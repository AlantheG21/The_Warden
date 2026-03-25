#!/usr/bin/env python3
"""
main.py — The Warden
Entry point and orchestrator.

Wires together the sniffer, engine, mitigator, and UI into a single
running system. Handles startup, graceful shutdown, and signal handling.

Run with:
    sudo python3 main.py
    sudo python3 main.py --dry-run     # safe demo mode, no iptables
    sudo python3 main.py --config path/to/settings.yaml
"""

import os
import sys
import time
import signal
import logging
import argparse
import threading

import yaml

# ---------------------------------------------------------------------------
# Ensure src/ is on the path regardless of where main.py is invoked from
# ---------------------------------------------------------------------------
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR  = os.path.join(ROOT_DIR, "src")
sys.path.insert(0, SRC_DIR)

from sniffer   import Sniffer
from engine    import Engine
from mitigator import Mitigator
from ui        import Dashboard


# ---------------------------------------------------------------------------
# Logging setup — configured before any module imports log anything
# ---------------------------------------------------------------------------

def setup_logging(level: int = logging.WARNING) -> None:
    """
    Configure the warden logger hierarchy.
    Root logger stays at WARNING to suppress Scapy noise.
    All warden.* loggers write to stderr at the requested level.
    """
    logging.basicConfig(
        level=logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    )
    warden_logger = logging.getLogger("warden")
    warden_logger.setLevel(level)
    warden_logger.propagate = False

    if not warden_logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s — %(message)s"
        ))
        warden_logger.addHandler(handler)


logger = logging.getLogger("warden.main")


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------

def load_config(path: str) -> dict:
    """Load and return the YAML config. Raises on file not found."""
    with open(path, "r") as f:
        config = yaml.safe_load(f)
    logger.info(f"Config loaded from {path}")
    return config


# ---------------------------------------------------------------------------
# Warden orchestrator
# ---------------------------------------------------------------------------

class Warden:
    """
    Top-level orchestrator that owns all components and manages
    their lifecycle — startup, running, and graceful shutdown.
    """

    def __init__(self, config: dict, dry_run_override: bool = False):
        self.config = config

        # Extract config sections with safe defaults
        sniffer_cfg   = config.get("sniffer",   {})
        engine_cfg    = config.get("engine",    {})
        mitigator_cfg = config.get("mitigator", {})
        ui_cfg        = config.get("ui",        {})

        # dry_run: command-line --dry-run flag overrides the yaml setting
        dry_run = dry_run_override or mitigator_cfg.get("dry_run", False)

        # Ensure logs directory exists
        log_path = os.path.join(ROOT_DIR, mitigator_cfg.get("log_path", "logs/bans.log"))
        os.makedirs(os.path.dirname(log_path), exist_ok=True)

        # ------------------------------------------------------------------
        # Build the dashboard first so we can pass its callbacks downstream
        # ------------------------------------------------------------------
        # We pass placeholder None values here and assign real components
        # after they're constructed — the dashboard only calls methods on
        # them during run(), by which point everything is ready.
        self.dashboard = None   # assigned after all components exist

        # ------------------------------------------------------------------
        # Mitigator
        # ------------------------------------------------------------------
        self.mitigator = Mitigator(
            ban_duration = mitigator_cfg.get("ban_duration", 60.0),
            dry_run      = dry_run,
            log_path     = log_path,
            # Callbacks wired after dashboard is created (see below)
        )

        # ------------------------------------------------------------------
        # Engine
        # ------------------------------------------------------------------
        self.engine = Engine(
            threshold_pps    = engine_cfg.get("threshold_pps",    20.0),
            window_seconds   = engine_cfg.get("window_seconds",    5.0),
            cooldown_seconds = engine_cfg.get("cooldown_seconds", 10.0),
            whitelist        = engine_cfg.get("whitelist", ["192.168.10.1"]),
            alert_callback   = self._on_alert,
        )

        # ------------------------------------------------------------------
        # Sniffer
        # ------------------------------------------------------------------
        self.sniffer = Sniffer(
            interface = sniffer_cfg.get("interface", "any"),
            callback  = self.engine.ingest,
        )

        # ------------------------------------------------------------------
        # Dashboard — now all components exist
        # ------------------------------------------------------------------
        self.dashboard = Dashboard(
            engine       = self.engine,
            mitigator    = self.mitigator,
            sniffer      = self.sniffer,
            refresh_rate = ui_cfg.get("refresh_rate", 1.0),
        )

        # Wire dashboard event log into mitigator callbacks
        self.mitigator.on_ban   = self._on_ban
        self.mitigator.on_unban = self._on_unban

        # Thread handle for the sniffer
        self._sniffer_thread = None

        logger.info("Warden orchestrator initialized.")

    # ------------------------------------------------------------------
    # Callbacks — bridge between components and the dashboard event log
    # ------------------------------------------------------------------

    def _on_alert(self, event) -> None:
        """Fired by the engine when an IP exceeds the threshold."""
        msg = (f"ALERT {event.protocol} flood from {event.src_ip} "
               f"— {event.pps:.1f} PPS")
        logger.warning(msg)
        if self.dashboard:
            self.dashboard.log_event(msg)
        # Hand off to the mitigator for the actual ban
        self.mitigator.ban(event)

    def _on_ban(self, record) -> None:
        """Fired by the mitigator when a ban is issued."""
        msg = (f"BAN   {record.src_ip} issued for "
               f"{record.ban_duration:.0f}s "
               f"({record.protocol} @ {record.pps:.1f} PPS)")
        logger.warning(msg)
        if self.dashboard:
            self.dashboard.log_event(msg)
        # Tell the engine to reset stats so the IP gets a clean
        # slate when the ban expires — prevents immediate re-ban
        self.engine.reset_ip(record.src_ip)

    def _on_unban(self, ip: str) -> None:
        """Fired by the mitigator's janitor when a ban expires."""
        msg = f"UNBAN {ip} — ban expired"
        logger.info(msg)
        if self.dashboard:
            self.dashboard.log_event(msg)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """
        Start all components in the correct order:
          1. Mitigator janitor thread
          2. Sniffer thread (daemon)
          3. Dashboard (blocks main thread until Q is pressed)
        """
        logger.info("Starting The Warden...")

        # Log startup event to dashboard
        iface = self.config.get("sniffer", {}).get("interface", "any")
        threshold = self.config.get("engine", {}).get("threshold_pps", 20.0)
        dry = " [DRY RUN]" if self.mitigator.dry_run else ""
        self.dashboard.log_event(
            f"Warden started{dry} — interface: {iface}, "
            f"threshold: {threshold} PPS"
        )

        # 1. Start mitigator janitor
        self.mitigator.start()

        # 2. Start sniffer in a daemon thread
        self._sniffer_thread = threading.Thread(
            target  = self.sniffer.start,
            daemon  = True,
            name    = "warden-sniffer",
        )
        self._sniffer_thread.start()
        logger.info("Sniffer thread started.")

        # Small pause to let the sniffer initialize before the UI draws
        time.sleep(0.5)

        # 3. Run the dashboard — this BLOCKS until Q is pressed
        try:
            self.dashboard.run()
        finally:
            self.stop()

    def stop(self) -> None:
        """
        Graceful shutdown:
          1. Stop the sniffer
          2. Stop the mitigator (lifts all active bans)
          3. Log final stats
        """
        logger.info("Shutting down The Warden...")

        self.sniffer.stop()
        self.mitigator.stop()

        # Print final stats to stdout after curses releases the terminal
        sniffer_stats   = self.sniffer.get_stats()
        engine_stats    = self.engine.get_stats_snapshot()
        mitigator_stats = self.mitigator.get_stats_snapshot()

        print("\n" + "=" * 55)
        print("  THE WARDEN — Session Summary")
        print("=" * 55)
        print(f"  Packets captured : {sniffer_stats['total']:,}")
        print(f"    MQTT           : {sniffer_stats['mqtt']:,}")
        print(f"    CoAP           : {sniffer_stats['coap']:,}")
        print(f"  Alerts fired     : {engine_stats['total_alerts']:,}")
        print(f"  Bans issued      : {mitigator_stats['total_bans']:,}")
        print(f"  Bans lifted      : {mitigator_stats['total_unbans']:,}")
        print("=" * 55)
        print("  All bans lifted. Goodbye.\n")


# ---------------------------------------------------------------------------
# Signal handling — clean shutdown on Ctrl+C or kill
# ---------------------------------------------------------------------------

def install_signal_handlers(warden: Warden) -> None:
    """Install SIGINT and SIGTERM handlers for graceful shutdown."""
    def handler(signum, frame):
        logger.info(f"Signal {signum} received — shutting down.")
        warden.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT,  handler)
    signal.signal(signal.SIGTERM, handler)


# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="The Warden — Real-Time IPS for IoT Healthcare"
    )
    parser.add_argument(
        "--config",
        default=os.path.join(ROOT_DIR, "config", "settings.yaml"),
        help="Path to settings.yaml (default: config/settings.yaml)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run without modifying iptables (safe demo mode)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable verbose debug logging to stderr",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    args = parse_args()

    # Setup logging level
    log_level = logging.DEBUG if args.debug else logging.WARNING
    setup_logging(log_level)

    # Check for root unless dry-run mode
    if not args.dry_run and os.geteuid() != 0:
        print(
            "\n[ERROR] The Warden requires root privileges to modify iptables.\n"
            "Run with: sudo python3 main.py\n"
            "Or use:   sudo python3 main.py --dry-run  (safe demo mode)\n"
        )
        sys.exit(1)

    # Load config
    try:
        config = load_config(args.config)
    except FileNotFoundError:
        print(f"\n[ERROR] Config file not found: {args.config}")
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"\n[ERROR] Invalid YAML in config: {e}")
        sys.exit(1)

    # Build and start The Warden
    warden = Warden(config, dry_run_override=args.dry_run)
    install_signal_handlers(warden)
    warden.start()


if __name__ == "__main__":
    main()