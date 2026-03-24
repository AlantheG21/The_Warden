"""
mitigator.py — The Warden
iptables wrapper and self-healing ban manager.

Receives AlertEvents from the engine, issues iptables DROP rules for
offending IPs, and automatically lifts bans after a cooldown period.

Design:
  - Each ban is stored in a dict with its expiry timestamp.
  - A background thread (the "janitor") wakes every second and lifts
    any bans that have expired.
  - All iptables calls are wrapped in subprocess with error handling
    so a failed shell command never crashes The Warden.
  - A dry_run mode lets you test the full pipeline without actually
    modifying iptables — safe for development.
"""

import time
import logging
import threading
import subprocess
import os
from dataclasses import dataclass, field
from typing import Dict, Optional, Callable

logger = logging.getLogger("warden.mitigator")


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class BanRecord:
    """Represents a single active ban."""
    src_ip:     str
    protocol:   str
    pps:        float                        # PPS that triggered the ban
    banned_at:  float = field(default_factory=time.time)
    expires_at: float = 0.0                  # set after __init__
    ban_duration: float = 0.0

    def is_expired(self) -> bool:
        return time.time() >= self.expires_at

    def time_remaining(self) -> float:
        return max(0.0, self.expires_at - time.time())

    def __str__(self):
        ts = time.strftime("%H:%M:%S", time.localtime(self.banned_at))
        return (f"[{ts}] BAN {self.src_ip} | "
                f"{self.protocol} {self.pps:.1f} PPS | "
                f"{self.time_remaining():.0f}s remaining")


# ---------------------------------------------------------------------------
# Mitigator
# ---------------------------------------------------------------------------

class Mitigator:
    """
    The enforcement arm of The Warden.

    Usage:
        mitigator = Mitigator(ban_duration=60, dry_run=False)
        mitigator.start()    # starts the janitor thread

        # Pass mitigator.ban as the engine's alert_callback:
        engine = Engine(..., alert_callback=mitigator.ban)
    """

    def __init__(
        self,
        ban_duration:    float = 60.0,
        dry_run:         bool  = False,
        on_ban:          Optional[Callable[[BanRecord], None]] = None,
        on_unban:        Optional[Callable[[str], None]]       = None,
        log_path:        Optional[str] = None,
    ):
        """
        Args:
            ban_duration:  Seconds to keep an IP banned. Default 60s.
            dry_run:       If True, log bans but do NOT call iptables.
                           Use this for testing without root privileges.
            on_ban:        Optional callback fired when a ban is issued.
                           Signature: on_ban(record: BanRecord) -> None
            on_unban:      Optional callback fired when a ban is lifted.
                           Signature: on_unban(ip: str) -> None
            log_path:      Path to the ban log file. None = no file logging.
        """
        self.ban_duration = ban_duration
        self.dry_run      = dry_run
        self.on_ban       = on_ban
        self.on_unban     = on_unban
        self.log_path     = log_path

        # Active bans: ip -> BanRecord
        self._bans: Dict[str, BanRecord] = {}
        self._lock = threading.Lock()

        # Lifetime counters for the dashboard
        self.total_bans   = 0
        self.total_unbans = 0

        # Janitor thread — lifts expired bans
        self._janitor_running = False
        self._janitor_thread  = None

        if dry_run:
            logger.warning(
                "Mitigator running in DRY RUN mode — "
                "iptables will NOT be modified."
            )
        else:
            # Confirm we have root — iptables requires it
            if os.geteuid() != 0:
                logger.error(
                    "Mitigator requires root privileges for iptables. "
                    "Run The Warden with sudo."
                )

        logger.info(
            f"Mitigator initialized — ban duration: {ban_duration}s, "
            f"dry_run: {dry_run}"
        )

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def start(self):
        """Start the background janitor thread that lifts expired bans."""
        self._janitor_running = True
        self._janitor_thread = threading.Thread(
            target=self._janitor_loop,
            daemon=True,
            name="warden-janitor",
        )
        self._janitor_thread.start()
        logger.info("Janitor thread started.")

    def stop(self):
        """Stop the janitor and lift ALL active bans (clean shutdown)."""
        logger.info("Mitigator stopping — lifting all active bans.")
        self._janitor_running = False

        with self._lock:
            ips_to_unban = list(self._bans.keys())

        for ip in ips_to_unban:
            self._lift_ban(ip)

        logger.info("All bans lifted. Mitigator stopped.")

    def ban(self, event) -> None:
        """
        Issue a ban for the IP in an AlertEvent.
        Called by the engine's alert callback.
        Thread-safe — can be called from any thread.
        """
        src_ip = event.src_ip

        with self._lock:
            # Do not re-ban an already banned IP
            if src_ip in self._bans:
                logger.debug(f"IP {src_ip} already banned — skipping.")
                return

            record = BanRecord(
                src_ip=src_ip,
                protocol=event.protocol,
                pps=event.pps,
                ban_duration=self.ban_duration,
            )
            record.expires_at = record.banned_at + self.ban_duration
            self._bans[src_ip] = record
            self.total_bans += 1

        # Issue the iptables rule
        self._issue_ban(src_ip)

        # Write to log file
        self._write_log(f"BAN   {record}")

        logger.warning(f"Banned {src_ip} for {self.ban_duration}s "
                       f"({event.protocol} @ {event.pps:.1f} PPS)")

        # Fire the on_ban callback (for the UI)
        if self.on_ban:
            self.on_ban(record)

    def is_banned(self, ip: str) -> bool:
        """Return True if the IP currently has an active ban."""
        with self._lock:
            return ip in self._bans

    def get_active_bans(self) -> Dict[str, BanRecord]:
        """Return a snapshot of all currently active bans."""
        with self._lock:
            return dict(self._bans)

    def get_stats_snapshot(self) -> dict:
        """Return mitigator-level counters for the dashboard."""
        with self._lock:
            return {
                "active_bans":  len(self._bans),
                "total_bans":   self.total_bans,
                "total_unbans": self.total_unbans,
                "dry_run":      self.dry_run,
            }

    # ------------------------------------------------------------------
    # iptables wrappers
    # ------------------------------------------------------------------

    def _issue_ban(self, ip: str) -> bool:
        """
        Append a DROP rule for the given IP to the INPUT chain.
        Returns True on success, False on failure.
        """
        if self.dry_run:
            logger.info(f"[DRY RUN] Would run: iptables -I INPUT -s {ip} -j DROP")
            return True

        cmd = ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
        return self._run_iptables(cmd, f"ban {ip}")

    def _remove_ban(self, ip: str) -> bool:
        """
        Remove the DROP rule for the given IP from the INPUT chain.
        Returns True on success, False on failure.
        """
        if self.dry_run:
            logger.info(f"[DRY RUN] Would run: iptables -D INPUT -s {ip} -j DROP")
            return True

        cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
        return self._run_iptables(cmd, f"unban {ip}")

    def _run_iptables(self, cmd: list, description: str) -> bool:
        """
        Execute an iptables command safely.
        Wraps subprocess so a failure never crashes The Warden.
        """
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5,       # never hang on a frozen iptables
            )
            if result.returncode == 0:
                logger.info(f"iptables {description}: OK")
                return True
            else:
                logger.error(
                    f"iptables {description} failed "
                    f"(rc={result.returncode}): {result.stderr.strip()}"
                )
                return False
        except subprocess.TimeoutExpired:
            logger.error(f"iptables {description} timed out.")
            return False
        except FileNotFoundError:
            logger.error(
                "iptables not found. Is it installed? "
                "Run: sudo apt install iptables"
            )
            return False

    # ------------------------------------------------------------------
    # Janitor — lifts expired bans
    # ------------------------------------------------------------------

    def _janitor_loop(self):
        """
        Background loop that checks for expired bans every second.
        Wakes up, scans the ban dict, lifts anything past its expiry.
        """
        logger.debug("Janitor loop running.")
        while self._janitor_running:
            time.sleep(1)

            with self._lock:
                expired = [
                    ip for ip, record in self._bans.items()
                    if record.is_expired()
                ]

            for ip in expired:
                self._lift_ban(ip)

    def _lift_ban(self, ip: str) -> None:
        """Remove a ban — called by the janitor or during shutdown."""
        with self._lock:
            if ip not in self._bans:
                return
            del self._bans[ip]
            self.total_unbans += 1

        self._remove_ban(ip)
        self._write_log(f"UNBAN {ip}")
        logger.info(f"Ban lifted for {ip}")

        if self.on_unban:
            self.on_unban(ip)

    # ------------------------------------------------------------------
    # Log file writer
    # ------------------------------------------------------------------

    def _write_log(self, message: str) -> None:
        """Append a timestamped entry to the ban log file."""
        if not self.log_path:
            return
        try:
            ts = time.strftime("%Y-%m-%d %H:%M:%S")
            with open(self.log_path, "a") as f:
                f.write(f"{ts} | {message}\n")
        except OSError as e:
            logger.error(f"Could not write to log file: {e}")


# ---------------------------------------------------------------------------
# Standalone test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )
    warden_logger = logging.getLogger("warden")
    warden_logger.setLevel(logging.DEBUG)
    if not warden_logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        )
        warden_logger.addHandler(handler)
    warden_logger.propagate = False

    print("=" * 55)
    print("  Warden Mitigator — standalone test (DRY RUN)")
    print("  Tests ban, duplicate suppression, and auto-unban.")
    print("=" * 55)

    ban_events   = []
    unban_events = []

    def on_ban(record: BanRecord):
        ban_events.append(record)
        print(f"  [UI callback] New ban: {record}")

    def on_unban(ip: str):
        unban_events.append(ip)
        print(f"  [UI callback] Ban lifted: {ip}")

    mitigator = Mitigator(
        ban_duration=5,             # short duration for testing
        dry_run=True,               # do NOT touch iptables
        on_ban=on_ban,
        on_unban=on_unban,
        log_path="/tmp/warden_test_bans.log",
    )
    mitigator.start()

    # Simulate an AlertEvent without importing engine
    class FakeAlert:
        def __init__(self, ip, protocol="MQTT", pps=50.0):
            self.src_ip   = ip
            self.protocol = protocol
            self.pps      = pps

    print("\n[Test 1] Ban 192.168.10.90")
    mitigator.ban(FakeAlert("192.168.10.90", pps=50.0))

    print("\n[Test 2] Attempt duplicate ban (should be suppressed)")
    mitigator.ban(FakeAlert("192.168.10.90", pps=60.0))

    print("\n[Test 3] Ban a second IP")
    mitigator.ban(FakeAlert("192.168.10.91", protocol="CoAP", pps=30.0))

    print(f"\n[Status] Active bans: {list(mitigator.get_active_bans().keys())}")
    print(f"[Status] Stats: {mitigator.get_stats_snapshot()}")

    print(f"\n[Waiting] Auto-unban fires in ~5 seconds...")
    time.sleep(7)

    print(f"\n[Result] Active bans after cooldown: "
          f"{list(mitigator.get_active_bans().keys())}")
    print(f"[Result] Ban events fired:   {len(ban_events)}")
    print(f"[Result] Unban events fired: {len(unban_events)}")
    print(f"[Result] Stats: {mitigator.get_stats_snapshot()}")
    print(f"\nCheck log: cat /tmp/warden_test_bans.log")
    print("\nMitigator test complete.")