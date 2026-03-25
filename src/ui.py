"""
ui.py — The Warden (Web Dashboard)
Replaces the curses terminal UI with a Flask + Server-Sent Events
web dashboard that auto-updates in real time.

The dashboard serves on http://localhost:5000 and pushes live data
to the browser every second via SSE — no websocket library needed.

Run The Warden then open http://localhost:5000 in any browser.
"""

import json
import time
import logging
import threading
from typing import Optional

logger = logging.getLogger("warden.ui")

try:
    from flask import Flask, Response, render_template_string
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    logger.error("Flask not installed. Run: pip3 install flask --break-system-packages")


# ---------------------------------------------------------------------------
# HTML Dashboard Template
# ---------------------------------------------------------------------------

DASHBOARD_HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>The Warden — IoT IPS</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');

  :root {
    --bg:        #080c10;
    --bg2:       #0d1117;
    --bg3:       #111820;
    --border:    #1e2d3d;
    --green:     #00ff88;
    --green-dim: #00994d;
    --red:       #ff3366;
    --red-dim:   #991f3d;
    --amber:     #ffaa00;
    --amber-dim: #996600;
    --blue:      #00aaff;
    --blue-dim:  #005580;
    --text:      #c8d8e8;
    --text-dim:  #4a6070;
    --mono:      'Share Tech Mono', monospace;
    --sans:      'Rajdhani', sans-serif;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--mono);
    font-size: 13px;
    min-height: 100vh;
    overflow-x: hidden;
  }

  body::before {
    content: '';
    position: fixed;
    inset: 0;
    background: repeating-linear-gradient(
      0deg, transparent, transparent 2px,
      rgba(0,255,136,0.015) 2px, rgba(0,255,136,0.015) 4px
    );
    pointer-events: none;
    z-index: 999;
  }

  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 14px 24px;
    background: var(--bg2);
    border-bottom: 1px solid var(--border);
    position: sticky;
    top: 0;
    z-index: 100;
  }

  .logo {
    font-family: var(--sans);
    font-size: 22px;
    font-weight: 700;
    letter-spacing: 4px;
    color: var(--green);
    text-shadow: 0 0 20px rgba(0,255,136,0.4);
  }

  .logo span {
    color: var(--text-dim);
    font-weight: 400;
    font-size: 13px;
    letter-spacing: 1px;
    margin-left: 12px;
  }

  .header-right { display: flex; align-items: center; gap: 20px; }

  #clock { font-size: 14px; color: var(--text-dim); letter-spacing: 2px; }

  .status-badge {
    font-family: var(--sans);
    font-size: 13px;
    font-weight: 700;
    letter-spacing: 3px;
    padding: 5px 14px;
    border-radius: 3px;
    transition: all 0.3s ease;
  }

  .status-secure   { background: rgba(0,255,136,0.1);  color: var(--green); border: 1px solid var(--green-dim); }
  .status-elevated { background: rgba(255,170,0,0.1);  color: var(--amber); border: 1px solid var(--amber-dim); }
  .status-attack   { background: rgba(255,51,102,0.15); color: var(--red);  border: 1px solid var(--red-dim);
                     animation: pulse-border 1s ease-in-out infinite; }

  @keyframes pulse-border {
    0%,100% { box-shadow: 0 0 0 0 rgba(255,51,102,0.4); }
    50%     { box-shadow: 0 0 0 6px rgba(255,51,102,0); }
  }

  .dry-run-tag {
    font-size: 11px; color: var(--amber);
    border: 1px solid var(--amber-dim);
    padding: 3px 8px; border-radius: 3px; letter-spacing: 1px;
  }

  .stats-row {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 1px;
    background: var(--border);
  }

  .stat-box { background: var(--bg2); padding: 16px 20px; text-align: center; }

  .stat-value {
    font-family: var(--sans);
    font-size: 32px;
    font-weight: 700;
    color: var(--green);
    line-height: 1;
    transition: color 0.3s;
  }

  .stat-value.danger { color: var(--red); }
  .stat-value.amber  { color: var(--amber); }
  .stat-value.blue   { color: var(--blue); }

  .stat-label {
    font-size: 11px; color: var(--text-dim);
    letter-spacing: 2px; margin-top: 6px;
    font-family: var(--sans); font-weight: 600;
  }

  .grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1px;
    background: var(--border);
    padding: 1px;
  }

  .panel { background: var(--bg2); overflow: hidden; }
  .panel-full { grid-column: 1 / -1; }

  .panel-header {
    display: flex; align-items: center; gap: 10px;
    padding: 10px 18px;
    background: var(--bg3);
    border-bottom: 1px solid var(--border);
    font-family: var(--sans); font-size: 12px;
    font-weight: 600; letter-spacing: 3px; color: var(--text-dim);
  }

  .dot { width: 6px; height: 6px; border-radius: 50%; }
  .dot.green { background: var(--green); box-shadow: 0 0 6px var(--green); }
  .dot.red   { background: var(--red);   box-shadow: 0 0 6px var(--red); }
  .dot.amber { background: var(--amber); box-shadow: 0 0 6px var(--amber); }
  .dot.blue  { background: var(--blue);  box-shadow: 0 0 6px var(--blue); }

  .panel-body { padding: 16px 18px; }

  .traffic-table, .bans-table { width: 100%; border-collapse: collapse; }

  .traffic-table th, .bans-table th {
    text-align: left; padding: 6px 10px;
    font-size: 10px; letter-spacing: 2px;
    color: var(--text-dim); border-bottom: 1px solid var(--border);
    font-family: var(--sans); font-weight: 600;
  }

  .traffic-table td, .bans-table td {
    padding: 7px 10px;
    border-bottom: 1px solid rgba(30,45,61,0.5);
    vertical-align: middle;
  }

  .row-normal td { color: var(--green); }
  .row-warning td { color: var(--amber); }
  .row-danger td  { color: var(--red); font-weight: bold; }
  .bans-table td  { color: var(--red); }

  .bar-track { height: 6px; background: rgba(255,255,255,0.05); border-radius: 3px; overflow: hidden; }
  .bar-fill  { height: 100%; border-radius: 3px; transition: width 0.5s ease; }
  .bar-green { background: var(--green); box-shadow: 0 0 8px rgba(0,255,136,0.5); }
  .bar-amber { background: var(--amber); box-shadow: 0 0 8px rgba(255,170,0,0.5); }
  .bar-red   { background: var(--red);   box-shadow: 0 0 8px rgba(255,51,102,0.5); }

  .banned-pill {
    display: inline-block; font-size: 9px; letter-spacing: 1px;
    padding: 2px 6px; background: rgba(255,51,102,0.15);
    color: var(--red); border: 1px solid var(--red-dim);
    border-radius: 2px; margin-left: 6px;
    font-family: var(--sans); font-weight: 600;
  }

  .timer-track { height: 4px; background: rgba(255,255,255,0.05); border-radius: 2px; overflow: hidden; width: 100px; }
  .timer-fill  { height: 100%; background: var(--red); border-radius: 2px;
                 box-shadow: 0 0 6px rgba(255,51,102,0.5); transition: width 1s linear; }

  .no-data { color: var(--green-dim); font-size: 12px; padding: 12px 10px; letter-spacing: 1px; }
  .empty   { color: var(--text-dim);  font-size: 12px; padding: 20px 0; text-align: center; letter-spacing: 1px; }

  .event-log { height: 200px; overflow-y: auto; font-size: 12px; line-height: 1.8; }
  .event-log::-webkit-scrollbar { width: 4px; }
  .event-log::-webkit-scrollbar-track { background: var(--bg3); }
  .event-log::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }

  .ev       { padding: 2px 0; border-bottom: 1px solid rgba(30,45,61,0.3); }
  .ev-time  { color: var(--text-dim); margin-right: 10px; }
  .ev-alert { color: var(--amber); }
  .ev-ban   { color: var(--red); }
  .ev-unban { color: var(--blue); }
  .ev-info  { color: var(--text-dim); }

  #conn-dot {
    display: inline-block; width: 8px; height: 8px;
    border-radius: 50%; background: var(--green);
    box-shadow: 0 0 8px var(--green); margin-right: 6px;
    animation: blink 2s ease-in-out infinite;
  }
  #conn-dot.offline { background: var(--red); box-shadow: 0 0 8px var(--red); animation: none; }

  @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.3} }
</style>
</head>
<body>

<header>
  <div class="logo">THE WARDEN <span>IoT Healthcare IPS</span></div>
  <div class="header-right">
    <span id="dry-tag" class="dry-run-tag" style="display:none">DRY RUN</span>
    <span id="badge" class="status-badge status-secure">SECURE</span>
    <span id="clock">--:--:--</span>
  </div>
</header>

<div class="stats-row">
  <div class="stat-box"><div class="stat-value blue" id="s-pkts">0</div><div class="stat-label">PACKETS CAPTURED</div></div>
  <div class="stat-box"><div class="stat-value" id="s-alerts">0</div><div class="stat-label">ALERTS FIRED</div></div>
  <div class="stat-box"><div class="stat-value" id="s-bans">0</div><div class="stat-label">TOTAL BANS</div></div>
  <div class="stat-box"><div class="stat-value" id="s-active">0</div><div class="stat-label">ACTIVE BANS</div></div>
</div>

<div class="grid">

  <div class="panel">
    <div class="panel-header"><span class="dot blue"></span>LIVE TRAFFIC</div>
    <div class="panel-body">
      <table class="traffic-table">
        <thead><tr><th>SOURCE IP</th><th>PPS</th><th style="width:40%">RATE</th></tr></thead>
        <tbody id="t-body"><tr><td colspan="3" class="empty">Waiting for traffic...</td></tr></tbody>
      </table>
    </div>
  </div>

  <div class="panel">
    <div class="panel-header"><span class="dot red"></span>ACTIVE BANS</div>
    <div class="panel-body">
      <table class="bans-table">
        <thead><tr><th>IP ADDRESS</th><th>PROTO</th><th>PPS</th><th>EXPIRES</th></tr></thead>
        <tbody id="b-body"><tr><td colspan="4" class="no-data">// No active bans</td></tr></tbody>
      </table>
    </div>
  </div>

  <div class="panel panel-full">
    <div class="panel-header">
      <span class="dot amber"></span>EVENT LOG
      <span style="margin-left:auto;font-size:11px"><span id="conn-dot"></span>LIVE</span>
    </div>
    <div class="panel-body">
      <div class="event-log" id="ev-log">
        <div class="ev ev-info"><span class="ev-time">--:--:--</span>Connecting to Warden...</div>
      </div>
    </div>
  </div>

</div>

<script>
  setInterval(() => {
    document.getElementById('clock').textContent =
      new Date().toTimeString().slice(0,8);
  }, 1000);

  const src = new EventSource('/stream');
  const dot = document.getElementById('conn-dot');
  src.onopen  = () => dot.classList.remove('offline');
  src.onerror = () => dot.classList.add('offline');

  src.onmessage = e => render(JSON.parse(e.data));

  function render(d) {
    // Stats
    document.getElementById('s-pkts').textContent   = d.sniffer.total.toLocaleString();
    document.getElementById('s-alerts').textContent = d.engine.total_alerts.toLocaleString();
    document.getElementById('s-bans').textContent   = d.mitigator.total_bans.toLocaleString();
    const act = d.mitigator.active_bans;
    const ae  = document.getElementById('s-active');
    ae.textContent = act;
    ae.className   = 'stat-value' + (act > 0 ? ' danger' : '');

    // Dry run
    document.getElementById('dry-tag').style.display = d.mitigator.dry_run ? 'inline-block' : 'none';

    // Badge
    const badge = document.getElementById('badge');
    const top   = d.top_talkers.length ? d.top_talkers[0][1] : 0;
    const thr   = d.engine.threshold_pps;
    if (act > 0 || top >= thr)       { badge.textContent = 'UNDER ATTACK'; badge.className = 'status-badge status-attack'; }
    else if (top >= thr * 0.5)       { badge.textContent = 'ELEVATED';     badge.className = 'status-badge status-elevated'; }
    else                             { badge.textContent = 'SECURE';       badge.className = 'status-badge status-secure'; }

    // Traffic table
    const tb = document.getElementById('t-body');
    if (!d.top_talkers.length) {
      tb.innerHTML = '<tr><td colspan="3" class="empty">Waiting for traffic...</td></tr>';
    } else {
      tb.innerHTML = d.top_talkers.map(([ip, pps]) => {
        const pct = Math.min(pps / Math.max(thr,1), 1) * 100;
        const banned = d.banned_ips.includes(ip);
        let rc = 'row-normal', bc = 'bar-green';
        if (pps >= thr)         { rc = 'row-danger';  bc = 'bar-red'; }
        else if (pps >= thr*.5) { rc = 'row-warning'; bc = 'bar-amber'; }
        return `<tr class="${rc}">
          <td>${ip}${banned?'<span class="banned-pill">BANNED</span>':''}</td>
          <td>${pps.toFixed(1)}</td>
          <td><div class="bar-track"><div class="bar-fill ${bc}" style="width:${pct}%"></div></div></td>
        </tr>`;
      }).join('');
    }

    // Bans table
    const bb = document.getElementById('b-body');
    if (!d.active_ban_list.length) {
      bb.innerHTML = '<tr><td colspan="4" class="no-data">// No active bans</td></tr>';
    } else {
      bb.innerHTML = d.active_ban_list.map(b => {
        const pct = Math.min(b.remaining / b.duration, 1) * 100;
        return `<tr>
          <td>${b.ip}</td><td>${b.protocol}</td><td>${b.pps.toFixed(1)}</td>
          <td style="display:flex;align-items:center;gap:8px">
            <span>${Math.ceil(b.remaining)}s</span>
            <div class="timer-track"><div class="timer-fill" style="width:${pct}%"></div></div>
          </td></tr>`;
      }).join('');
    }

    // Event log
    const el = document.getElementById('ev-log');
    if (!d.events.length) return;
    el.innerHTML = [...d.events].reverse().map(entry => {
      let cls = 'ev-info';
      if (entry.includes('ALERT'))                          cls = 'ev-alert';
      else if (entry.includes('BAN') && !entry.includes('UNBAN')) cls = 'ev-ban';
      else if (entry.includes('UNBAN'))                     cls = 'ev-unban';
      return `<div class="ev ${cls}"><span class="ev-time">${entry.slice(1,9)}</span>${entry.slice(11)}</div>`;
    }).join('');
  }
</script>
</body>
</html>'''


# ---------------------------------------------------------------------------
# Dashboard class
# ---------------------------------------------------------------------------

class Dashboard:
    """
    Web-based dashboard for The Warden.
    Serves on http://localhost:5000 and pushes live data via SSE.
    """

    def __init__(self, engine, mitigator, sniffer, refresh_rate: float = 1.0):
        self.engine       = engine
        self.mitigator    = mitigator
        self.sniffer      = sniffer
        self.refresh_rate = refresh_rate

        self._event_log  = []
        self._event_lock = threading.Lock()
        self._max_events = 100
        self._running    = False

        if not FLASK_AVAILABLE:
            raise RuntimeError(
                "Flask is required. "
                "Run: pip3 install flask --break-system-packages"
            )

        self._app = Flask(__name__)
        # Silence Flask/Werkzeug request logs so they don't corrupt output
        self._app.logger.setLevel(logging.ERROR)
        import logging as _log
        _log.getLogger('werkzeug').setLevel(_log.ERROR)
        self._register_routes()

    def log_event(self, message: str) -> None:
        """Add a timestamped event. Called by main.py callbacks."""
        ts    = time.strftime("%H:%M:%S")
        entry = f"[{ts}] {message}"
        with self._event_lock:
            self._event_log.append(entry)
            if len(self._event_log) > self._max_events:
                self._event_log.pop(0)

    def run(self) -> None:
        """Start the Flask server. Blocks until Ctrl+C."""
        self._running = True
        print("\n" + "=" * 55)
        print("  The Warden dashboard is running.")
        print("  Open your browser and go to:")
        print("  http://localhost:5000")
        print("  Press Ctrl+C to stop The Warden.")
        print("=" * 55 + "\n")
        self._app.run(
            host="0.0.0.0",
            port=5000,
            debug=False,
            threaded=True,
            use_reloader=False,
        )

    def _register_routes(self) -> None:
        app = self._app

        @app.route("/")
        def index():
            return render_template_string(DASHBOARD_HTML)

        @app.route("/stream")
        def stream():
            def gen():
                while True:
                    data = self._build_payload()
                    yield f"data: {json.dumps(data)}\n\n"
                    time.sleep(self.refresh_rate)
            return Response(
                gen(),
                mimetype="text/event-stream",
                headers={"Cache-Control": "no-cache",
                         "X-Accel-Buffering": "no"},
            )

    def _build_payload(self) -> dict:
        """Collect all live data into one JSON dict."""
        sniffer_stats   = self.sniffer.get_stats()
        engine_stats    = self.engine.get_stats_snapshot()
        mitigator_stats = self.mitigator.get_stats_snapshot()
        top_talkers     = self.engine.get_top_talkers(n=8)
        active_bans     = self.mitigator.get_active_bans()

        ban_list = [
            {
                "ip":        ip,
                "protocol":  r.protocol,
                "pps":       r.pps,
                "remaining": r.time_remaining(),
                "duration":  r.ban_duration,
            }
            for ip, r in active_bans.items()
        ]

        with self._event_lock:
            events = list(self._event_log)

        return {
            "sniffer":         sniffer_stats,
            "engine":          engine_stats,
            "mitigator":       mitigator_stats,
            "top_talkers":     top_talkers,
            "banned_ips":      list(active_bans.keys()),
            "active_ban_list": ban_list,
            "events":          events,
        }