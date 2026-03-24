"""
engine.py — The Warden
Moving Average detection engine.

Receives PacketRecord objects from the sniffer, tracks packets-per-second
(PPS) per source IP using a sliding time window, and fires an alert callback
when an IP exceeds the configured threshold.

Design:
  - One deque per source IP stores packet timestamps.
  - On every ingest(), stale timestamps outside the window are pruned.
  - PPS = len(deque) / window_size_in_seconds.
  - If PPS > threshold AND the IP is not already banned, fire alert callback.
"""

import time
import logging
import threading
from collections import deque, defaultdict
from dataclasses import dataclass, field
from typing import Callable, Dict, Optional

logger = logging.getLogger("warden.engine")


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class IPStats:
    """
    Sliding-window packet stats for a single source IP.
    The deque holds the timestamp of every packet seen within the window.
    maxlen is not used — we prune manually so the window is time-based,
    not count-based.
    """
    timestamps: deque = field(default_factory=deque)
    last_alert: float = 0.0          # epoch time of the last alert fired
    total_packets: int = 0           # lifetime counter for this IP


@dataclass
class AlertEvent:
    """
    Passed to the alert callback when an IP exceeds the threshold.
    The mitigator receives this and issues the iptables ban.
    """
    src_ip:     str
    protocol:   str
    msg_type:   str
    pps:        float                # packets per second at time of alert
    timestamp:  float = field(default_factory=time.time)

    def __str__(self):
        ts = time.strftime("%H:%M:%S", time.localtime(self.timestamp))
        return (f"[{ts}] ALERT {self.protocol} flood from {self.src_ip} "
                f"— {self.pps:.1f} PPS (msg: {self.msg_type})")


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class Engine:
    """
    The detection brain of The Warden.

    Usage:
        engine = Engine(
            threshold_pps=20,
            window_seconds=5,
            alert_callback=mitigator.ban,
            cooldown_seconds=10,
        )
        # Pass engine.ingest as the sniffer callback:
        sniffer = Sniffer(interface="any", callback=engine.ingest)
    """

    def __init__(
        self,
        threshold_pps:    float,
        window_seconds:   float,
        alert_callback:   Callable[[AlertEvent], None],
        cooldown_seconds: float = 10.0,
        whitelist:        Optional[list] = None,
    ):
        """
        Args:
            threshold_pps:    Packets per second above which an IP is flagged.
            window_seconds:   Sliding window size for PPS calculation.
            alert_callback:   Called with an AlertEvent when threshold breached.
                              Signature: callback(event: AlertEvent) -> None
            cooldown_seconds: Minimum seconds between repeated alerts for the
                              same IP (prevents alert storms).
            whitelist:        List of IPs to never flag (e.g. the broker itself).
        """
        self.threshold_pps    = threshold_pps
        self.window_seconds   = window_seconds
        self.alert_callback   = alert_callback
        self.cooldown_seconds = cooldown_seconds
        self.whitelist        = set(whitelist or [])

        # Per-IP stats — auto-creates an IPStats on first access
        self._stats: Dict[str, IPStats] = defaultdict(IPStats)

        # Thread lock — sniffer runs in its own thread, UI reads stats
        # from the main thread, so all mutations need protection
        self._lock = threading.Lock()

        # Engine-level counters for the dashboard
        self.total_ingested = 0
        self.total_alerts   = 0

        logger.info(
            f"Engine initialized — threshold: {threshold_pps} PPS, "
            f"window: {window_seconds}s, cooldown: {cooldown_seconds}s"
        )

    # ------------------------------------------------------------------
    # Core ingest — called by the sniffer for every packet
    # ------------------------------------------------------------------

    def ingest(self, record) -> None:
        """
        Process one PacketRecord from the sniffer.
        This runs in the sniffer's thread — keep it fast.
        """
        src_ip = record.src_ip

        # Never flag whitelisted IPs
        if src_ip in self.whitelist:
            return

        now = record.timestamp

        with self._lock:
            stats = self._stats[src_ip]
            stats.total_packets += 1
            stats.timestamps.append(now)
            self.total_ingested += 1

            # Prune timestamps outside the sliding window
            cutoff = now - self.window_seconds
            while stats.timestamps and stats.timestamps[0] < cutoff:
                stats.timestamps.popleft()

            # Calculate current PPS
            pps = len(stats.timestamps) / self.window_seconds

            # Fire alert if threshold exceeded and cooldown has elapsed
            if pps >= self.threshold_pps:
                time_since_last = now - stats.last_alert
                if time_since_last >= self.cooldown_seconds:
                    stats.last_alert = now
                    self.total_alerts += 1
                    event = AlertEvent(
                        src_ip=src_ip,
                        protocol=record.protocol,
                        msg_type=record.msg_type,
                        pps=pps,
                        timestamp=now,
                    )
                    logger.warning(event)
                    # Fire callback OUTSIDE the lock to prevent deadlock
                    # if the mitigator takes time to call iptables
                    threading.Thread(
                        target=self.alert_callback,
                        args=(event,),
                        daemon=True,
                    ).start()

    # ------------------------------------------------------------------
    # Read-only accessors for the dashboard (thread-safe)
    # ------------------------------------------------------------------

    def get_pps(self, src_ip: str) -> float:
        """Return the current PPS for a specific IP."""
        with self._lock:
            stats = self._stats.get(src_ip)
            if not stats:
                return 0.0
            now = time.time()
            cutoff = now - self.window_seconds
            # Count only timestamps within the window
            count = sum(1 for t in stats.timestamps if t >= cutoff)
            return count / self.window_seconds

    def get_all_pps(self) -> Dict[str, float]:
        """
        Return a snapshot of current PPS for every tracked IP.
        Used by the dashboard to display live metrics.
        """
        with self._lock:
            now = time.time()
            cutoff = now - self.window_seconds
            result = {}
            for ip, stats in self._stats.items():
                count = sum(1 for t in stats.timestamps if t >= cutoff)
                result[ip] = count / self.window_seconds
            return result

    def get_top_talkers(self, n: int = 5) -> list:
        """
        Return the top n IPs by current PPS, sorted descending.
        Returns a list of (ip, pps) tuples.
        """
        all_pps = self.get_all_pps()
        sorted_ips = sorted(all_pps.items(), key=lambda x: x[1], reverse=True)
        return sorted_ips[:n]

    def get_stats_snapshot(self) -> dict:
        """Return engine-level counters for the dashboard."""
        return {
            "total_ingested": self.total_ingested,
            "total_alerts":   self.total_alerts,
            "tracked_ips":    len(self._stats),
            "threshold_pps":  self.threshold_pps,
            "window_seconds": self.window_seconds,
        }

    def reset_ip(self, src_ip: str) -> None:
        """
        Clear all tracking data for an IP.
        Called by the mitigator after a ban expires — gives the IP
        a clean slate so it isn't immediately re-flagged.
        """
        with self._lock:
            if src_ip in self._stats:
                del self._stats[src_ip]
                logger.info(f"Engine reset stats for {src_ip}")


# ---------------------------------------------------------------------------
# Standalone test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import random

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
    print("  Warden Engine — standalone test")
    print("  Simulating normal traffic then a flood attack.")
    print("=" * 55)

    alerts_fired = []

    def mock_alert(event: AlertEvent):
        alerts_fired.append(event)
        print(f"\n  *** {event} ***\n")

    engine = Engine(
        threshold_pps=10,
        window_seconds=5,
        alert_callback=mock_alert,
        cooldown_seconds=5,
        whitelist=["192.168.10.1"],
    )

    # Simulate a PacketRecord without importing sniffer
    class FakeRecord:
        def __init__(self, src_ip, protocol="MQTT", msg_type="PUBLISH"):
            self.src_ip   = src_ip
            self.dst_ip   = "192.168.10.1"
            self.protocol = protocol
            self.msg_type = msg_type
            self.timestamp = time.time()

    print("\n[Phase 1] Normal traffic — 2 PPS from sensor (expect no alerts)")
    for _ in range(10):
        engine.ingest(FakeRecord("192.168.10.50"))
        time.sleep(0.5)   # 2 PPS — well below threshold
        pps = engine.get_pps("192.168.10.50")
        print(f"  192.168.10.50 PPS: {pps:.2f}")

    print("\n[Phase 2] Attack traffic — 50 PPS from attacker (expect alert)")
    for _ in range(60):
        engine.ingest(FakeRecord("192.168.10.90"))
        time.sleep(0.02)  # 50 PPS — way above threshold

    time.sleep(0.5)
    print(f"\n[Result] Total alerts fired: {len(alerts_fired)}")
    print(f"[Result] Engine stats: {engine.get_stats_snapshot()}")
    print(f"[Result] Top talkers: {engine.get_top_talkers()}")
    print("\nEngine test complete.")