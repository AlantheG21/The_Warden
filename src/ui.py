"""
ui.py — The Warden
Console-based live dashboard using Python's curses library.

Displays three panels:
  1. Live PPS metrics — per-IP packet rate with a visual bar
  2. ICU Network Health — overall status of the monitored network
  3. Active Bans — IPs currently blocked by iptables with countdown timers

Refreshes every second. Runs in the main thread while sniffer/engine/mitigator
run in daemon threads.
"""

import curses
import time
import logging
import threading
from typing import Callable

logger = logging.getLogger("warden.ui")


# ---------------------------------------------------------------------------
# Color pair IDs (defined once in init_colors)
# ---------------------------------------------------------------------------
COLOR_HEADER    = 1   # white on dark blue  — panel headers
COLOR_NORMAL    = 2   # green               — healthy / normal traffic
COLOR_WARNING   = 3   # yellow              — elevated traffic
COLOR_DANGER    = 4   # red                 — attack / banned
COLOR_MUTED     = 5   # dark gray           — secondary info
COLOR_HIGHLIGHT = 6   # black on green      — status badge SECURE
COLOR_ALERT     = 7   # black on red        — status badge UNDER ATTACK


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

class Dashboard:
    """
    Curses-based live dashboard for The Warden.

    Usage:
        dashboard = Dashboard(engine, mitigator, sniffer)
        dashboard.run()     # blocks — call from main thread
    """

    def __init__(self, engine, mitigator, sniffer, refresh_rate: float = 1.0):
        """
        Args:
            engine:       Engine instance — provides PPS data.
            mitigator:    Mitigator instance — provides ban data.
            sniffer:      Sniffer instance — provides packet counts.
            refresh_rate: Seconds between screen refreshes.
        """
        self.engine       = engine
        self.mitigator    = mitigator
        self.sniffer      = sniffer
        self.refresh_rate = refresh_rate

        # Event log — stores recent alert/ban messages for display
        self._event_log   = []
        self._event_lock  = threading.Lock()
        self._max_events  = 50

        # Flag to signal the dashboard to stop
        self._running = False

    # ------------------------------------------------------------------
    # Public event log API — called from engine/mitigator callbacks
    # ------------------------------------------------------------------

    def log_event(self, message: str) -> None:
        """Add a timestamped event to the dashboard event log."""
        ts = time.strftime("%H:%M:%S")
        entry = f"[{ts}] {message}"
        with self._event_lock:
            self._event_log.append(entry)
            if len(self._event_log) > self._max_events:
                self._event_log.pop(0)

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Start the dashboard. Blocks until the user presses 'q'."""
        self._running = True
        try:
            curses.wrapper(self._main_loop)
        except KeyboardInterrupt:
            pass
        finally:
            self._running = False

    # ------------------------------------------------------------------
    # Curses main loop
    # ------------------------------------------------------------------

    def _main_loop(self, stdscr) -> None:
        """Main curses loop — called by curses.wrapper."""
        self._init_colors()
        curses.curs_set(0)          # hide cursor
        stdscr.nodelay(True)        # non-blocking getch()
        stdscr.timeout(100)         # check for keypress every 100ms

        while self._running:
            stdscr.erase()
            height, width = stdscr.getmaxyx()

            try:
                self._draw_title_bar(stdscr, width)
                self._draw_pps_panel(stdscr, width)
                self._draw_health_panel(stdscr, width)
                self._draw_bans_panel(stdscr, width)
                self._draw_event_log(stdscr, width, height)
                self._draw_footer(stdscr, height, width)
            except curses.error:
                # Terminal too small — skip this frame
                pass

            stdscr.refresh()

            # Check for quit key
            elapsed = 0.0
            while elapsed < self.refresh_rate and self._running:
                key = stdscr.getch()
                if key in (ord('q'), ord('Q')):
                    self._running = False
                    return
                time.sleep(0.05)
                elapsed += 0.05
            # key = stdscr.getch()
            # if key in (ord('q'), ord('Q')):
            #     self._running = False
            #     break

            #time.sleep(self.refresh_rate)

    # ------------------------------------------------------------------
    # Drawing methods — each draws one panel
    # ------------------------------------------------------------------

    def _draw_title_bar(self, scr, width: int) -> None:
        """Top bar with title and current time."""
        title = " THE WARDEN — IoT Healthcare IPS "
        timestamp = time.strftime(" %Y-%m-%d %H:%M:%S ")
        scr.attron(curses.color_pair(COLOR_HEADER) | curses.A_BOLD)
        scr.addstr(0, 0, " " * width)
        scr.addstr(0, (width - len(title)) // 2, title)
        scr.addstr(0, width - len(timestamp) - 1, timestamp)
        scr.attroff(curses.color_pair(COLOR_HEADER) | curses.A_BOLD)

    def _draw_pps_panel(self, scr, width: int) -> None:
        """Panel 1 — Live packets-per-second per source IP."""
        row = 2
        self._draw_panel_header(scr, row, width, "[ LIVE TRAFFIC — Packets Per Second ]")
        row += 1

        top_talkers = self.engine.get_top_talkers(n=8)
        threshold   = self.engine.threshold_pps

        if not top_talkers:
            scr.addstr(row, 2, "  No traffic observed yet.", curses.color_pair(COLOR_MUTED))
            return

        col_ip    = 2
        col_pps   = 22
        col_bar   = 32
        bar_width = min(40, width - col_bar - 10)

        # Column headers
        scr.attron(curses.A_UNDERLINE)
        scr.addstr(row, col_ip,  "Source IP")
        scr.addstr(row, col_pps, "   PPS")
        scr.addstr(row, col_bar, "Rate")
        scr.attroff(curses.A_UNDERLINE)
        row += 1

        for ip, pps in top_talkers:
            if row >= curses.LINES - 10:
                break

            # Choose color based on PPS relative to threshold
            if pps >= threshold:
                color = curses.color_pair(COLOR_DANGER) | curses.A_BOLD
            elif pps >= threshold * 0.5:
                color = curses.color_pair(COLOR_WARNING)
            else:
                color = curses.color_pair(COLOR_NORMAL)

            # Build the bar
            filled = int(min(pps / max(threshold, 1), 1.0) * bar_width)
            bar    = "█" * filled + "░" * (bar_width - filled)

            banned_tag = " [BANNED]" if self.mitigator.is_banned(ip) else ""

            scr.addstr(row, col_ip,  f"  {ip:<18}", color)
            scr.addstr(row, col_pps, f"{pps:6.1f}", color)
            scr.addstr(row, col_bar, f" {bar}", color)
            if banned_tag:
                scr.addstr(row, col_bar + bar_width + 2,
                           banned_tag, curses.color_pair(COLOR_DANGER) | curses.A_BOLD)
            row += 1

    def _draw_health_panel(self, scr, width: int) -> None:
        """Panel 2 — Overall ICU network health status."""
        # Position below PPS panel (dynamic — find next blank row)
        top_talkers  = self.engine.get_top_talkers(n=8)
        panel_row    = 4 + min(len(top_talkers), 8) + 2

        self._draw_panel_header(
            scr, panel_row, width, "[ ICU NETWORK HEALTH ]"
        )
        panel_row += 1

        engine_stats    = self.engine.get_stats_snapshot()
        mitigator_stats = self.mitigator.get_stats_snapshot()
        sniffer_stats   = self.sniffer.get_stats()
        active_bans     = mitigator_stats["active_bans"]
        threshold       = engine_stats["threshold_pps"]

        # Determine overall health
        top_pps = top_talkers[0][1] if top_talkers else 0.0
        if active_bans > 0 or top_pps >= threshold:
            status_text  = " UNDER ATTACK "
            status_color = curses.color_pair(COLOR_ALERT) | curses.A_BOLD
        elif top_pps >= threshold * 0.5:
            status_text  = " ELEVATED     "
            status_color = curses.color_pair(COLOR_WARNING) | curses.A_BOLD
        else:
            status_text  = " SECURE       "
            status_color = curses.color_pair(COLOR_HIGHLIGHT) | curses.A_BOLD

        scr.addstr(panel_row, 2, "  Status: ")
        scr.addstr(panel_row, 12, status_text, status_color)

        panel_row += 1
        scr.addstr(panel_row, 2,
                   f"  Packets captured : {sniffer_stats['total']:,}   "
                   f"MQTT: {sniffer_stats['mqtt']:,}   "
                   f"CoAP: {sniffer_stats['coap']:,}",
                   curses.color_pair(COLOR_MUTED))

        panel_row += 1
        scr.addstr(panel_row, 2,
                   f"  Engine alerts    : {engine_stats['total_alerts']:,}   "
                   f"Tracked IPs: {engine_stats['tracked_ips']}   "
                   f"Threshold: {threshold} PPS",
                   curses.color_pair(COLOR_MUTED))

        panel_row += 1
        scr.addstr(panel_row, 2,
                   f"  Total bans issued: {mitigator_stats['total_bans']:,}   "
                   f"Lifted: {mitigator_stats['total_unbans']:,}   "
                   f"Active: {active_bans}",
                   curses.color_pair(COLOR_MUTED))

    def _draw_bans_panel(self, scr, width: int) -> None:
        """Panel 3 — Active bans with countdown timers."""
        top_talkers = self.engine.get_top_talkers(n=8)
        panel_row   = 4 + min(len(top_talkers), 8) + 7

        self._draw_panel_header(
            scr, panel_row, width, "[ ACTIVE BANS ]"
        )
        panel_row += 1

        active_bans = self.mitigator.get_active_bans()

        if not active_bans:
            scr.addstr(panel_row, 2,
                       "  No active bans — network is clean.",
                       curses.color_pair(COLOR_NORMAL))
            return

        for ip, record in active_bans.items():
            if panel_row >= curses.LINES - 8:
                break
            remaining = record.time_remaining()
            scr.addstr(
                panel_row, 2,
                f"  {ip:<18} {record.protocol:<6} "
                f"{record.pps:5.1f} PPS   "
                f"expires in {remaining:4.0f}s",
                curses.color_pair(COLOR_DANGER)
            )
            panel_row += 1

    def _draw_event_log(self, scr, width: int, height: int) -> None:
        """Bottom section — scrolling log of recent alert/ban events."""
        log_start = height - 9
        if log_start < 2:
            return

        self._draw_panel_header(
            scr, log_start, width, "[ EVENT LOG ]"
        )

        with self._event_lock:
            # Show the most recent events that fit
            visible_events = self._event_log[-(7):]

        for i, entry in enumerate(visible_events):
            row = log_start + 1 + i
            if row >= height - 1:
                break
            color = (curses.color_pair(COLOR_DANGER)
                     if "BAN" in entry or "ALERT" in entry
                     else curses.color_pair(COLOR_MUTED))
            scr.addstr(row, 2, f"  {entry[:width-4]}", color)

    def _draw_footer(self, scr, height: int, width: int) -> None:
        """Bottom bar with key bindings."""
        footer = " [Q] Quit "
        dry_run_tag = (
            " [DRY RUN — iptables inactive] "
            if self.mitigator.dry_run else ""
        )
        scr.attron(curses.color_pair(COLOR_HEADER))
        scr.addstr(height - 1, 0, " " * (width - 1))
        scr.addstr(height - 1, 1, footer)
        if dry_run_tag:
            scr.addstr(
                height - 1,
                width - len(dry_run_tag) - 1,
                dry_run_tag,
                curses.color_pair(COLOR_WARNING) | curses.A_BOLD
            )
        scr.attroff(curses.color_pair(COLOR_HEADER))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _draw_panel_header(self, scr, row: int, width: int, title: str) -> None:
        """Draw a full-width separator line with a centered title."""
        line = "─" * (width - 2)
        try:
            scr.addstr(row, 1, line, curses.color_pair(COLOR_MUTED))
            start_col = max(1, (width - len(title)) // 2)
            scr.addstr(row, start_col, title,
                       curses.color_pair(COLOR_HEADER) | curses.A_BOLD)
        except curses.error:
            pass

    def _init_colors(self) -> None:
        """Initialize all color pairs used by the dashboard."""
        curses.start_color()
        curses.use_default_colors()

        # Background color — use terminal default (-1)
        bg = -1

        curses.init_pair(COLOR_HEADER,    curses.COLOR_WHITE,  curses.COLOR_BLUE)
        curses.init_pair(COLOR_NORMAL,    curses.COLOR_GREEN,  bg)
        curses.init_pair(COLOR_WARNING,   curses.COLOR_YELLOW, bg)
        curses.init_pair(COLOR_DANGER,    curses.COLOR_RED,    bg)
        curses.init_pair(COLOR_MUTED,     curses.COLOR_WHITE,  bg)
        curses.init_pair(COLOR_HIGHLIGHT, curses.COLOR_BLACK,  curses.COLOR_GREEN)
        curses.init_pair(COLOR_ALERT,     curses.COLOR_WHITE,  curses.COLOR_RED)


# ---------------------------------------------------------------------------
# Standalone test — runs the dashboard with simulated data
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import random
    import sys

    logging.basicConfig(level=logging.WARNING)

    print("Starting dashboard with simulated data.")
    print("Press Q inside the dashboard to quit.\n")
    time.sleep(1)

    # --- Minimal stubs so we can test the UI without the real components ---

    class FakeSniffer:
        total_captured = 0
        total_mqtt     = 0
        total_coap     = 0
        def get_stats(self):
            self.total_captured += random.randint(1, 5)
            self.total_mqtt     += random.randint(1, 4)
            self.total_coap     += random.randint(0, 1)
            return {
                "total": self.total_captured,
                "mqtt":  self.total_mqtt,
                "coap":  self.total_coap,
            }

    class FakeEngine:
        threshold_pps = 20
        total_ingested = 1500
        total_alerts   = 3
        def get_top_talkers(self, n=8):
            return [
                ("192.168.10.50", random.uniform(0.5, 2.0)),
                ("192.168.10.51", random.uniform(0.3, 1.5)),
                ("192.168.10.90", random.uniform(35.0, 55.0)),
                ("192.168.10.91", random.uniform(5.0, 15.0)),
            ]
        def get_stats_snapshot(self):
            return {
                "total_ingested": self.total_ingested,
                "total_alerts":   self.total_alerts,
                "tracked_ips":    4,
                "threshold_pps":  self.threshold_pps,
                "window_seconds": 5,
            }

    class FakeMitigator:
        dry_run      = True
        total_bans   = 3
        total_unbans = 1
        def is_banned(self, ip):
            return ip == "192.168.10.90"
        def get_active_bans(self):
            from dataclasses import dataclass, field as f
            # Return a fake BanRecord
            class FakeBan:
                # src_ip   = "192.168.10.90"
                # protocol = "MQTT"
                # pps      = 47.3
                # def time_remaining(self): return random.uniform(10, 55)
                src_ip   = "192.168.10.90"
                protocol = "MQTT"
                pps      = 47.3
                _start   = time.time()                    # fixed reference point
                def time_remaining(self):
                    return max(0.0, 55.0 - (time.time() - self._start))
            return {"192.168.10.90": FakeBan()}
        def get_stats_snapshot(self):
            return {
                "active_bans":  1,
                "total_bans":   self.total_bans,
                "total_unbans": self.total_unbans,
                "dry_run":      self.dry_run,
            }

    dashboard = Dashboard(
        engine    = FakeEngine(),
        mitigator = FakeMitigator(),
        sniffer   = FakeSniffer(),
        refresh_rate = 1.0,
    )

    # Pre-populate the event log
    dashboard.log_event("ALERT MQTT flood from 192.168.10.90 — 47.3 PPS")
    dashboard.log_event("BAN   192.168.10.90 issued for 60s")
    dashboard.log_event("ALERT CoAP flood from 192.168.10.91 — 12.1 PPS")
    dashboard.log_event("System started — monitoring eth-icu")

    dashboard.run()
    print("Dashboard closed.")