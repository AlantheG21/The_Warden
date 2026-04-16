# The Warden — Real-Time Protocol-Aware IPS for IoT Healthcare

> A live, stateful Intrusion Prevention System designed for resource-constrained IoT healthcare environments. The Warden moves beyond passive detection by monitoring MQTT and CoAP protocol traffic in real time, detecting flood-based DoS attacks using a moving average threshold algorithm, and automatically issuing firewall bans via `iptables` — with self-healing cooldown timers to restore access once the threat subsides.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Flask](https://img.shields.io/badge/Dashboard-Flask-green)
![Platform](https://img.shields.io/badge/Platform-Linux-orange)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [What Works](#what-works)
- [Known Limitations](#known-limitations)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Running The Warden](#running-the-warden)
- [Running the Traffic Simulator](#running-the-traffic-simulator)
- [Project Structure](#project-structure)
- [Scholarly References](#scholarly-references)

---

## Overview

The Warden was built as an extension of the research presented in *"A Framework for Malicious Traffic Detection in IoT Healthcare Environment"* (Hussain et al., 2021). While the original paper focused on using machine learning to classify captured IoT traffic offline, The Warden implements the **active defense layer** that was missing — a live mitigation engine that detects and blocks attacks as they happen.

The system simulates a Smart ICU environment with normal sensor devices (heart rate monitor, oximeter, infusion pump, glucose monitor) alongside malicious attacker nodes, then protects the network in real time.

---

## Architecture

```
IoT Devices / Simulator
        │
        ▼
  [ sniffer.py ]  ←── Scapy captures MQTT (TCP/1883) and CoAP (UDP/5683)
        │
        ▼
  [ engine.py  ]  ←── Sliding window PPS calculation per source IP
        │                  Fires AlertEvent when threshold exceeded
        ▼
  [ mitigator.py] ←── Issues iptables DROP rule for offending IP
        │                  Janitor thread auto-lifts bans after cooldown
        ▼
  [ ui.py      ]  ←── Flask web dashboard on http://localhost:5000
                           Server-Sent Events push live data every second
```

All four modules are orchestrated by `main.py` and configured via `config/settings.yaml`.

---

## What Works

- **Live packet capture** — Scapy sniffs MQTT and CoAP traffic on configurable network interfaces using BPF kernel-level filtering for performance
- **Per-IP moving average detection** — sliding time window tracks packets-per-second per source IP; configurable threshold and window size
- **Automated iptables banning** — offending IPs receive a DROP rule inserted at the top of the INPUT chain (`-I` not `-A`) ensuring it takes priority
- **Self-healing cooldown** — a background janitor thread automatically lifts bans after a configurable duration, giving legitimate devices a clean slate
- **IP whitelisting** — broker and infrastructure IPs are never flagged regardless of traffic volume
- **Web dashboard** — live updating browser UI showing real-time PPS metrics, active bans with countdown timers, ICU network health status, and a scrolling event log
- **Dry run mode** — full pipeline runs without touching iptables, safe for demos and testing without root-level risk
- **Traffic simulator** — Python-based ICU traffic generator that assigns virtual IP aliases on loopback, replacing IoT-Flock for aarch64/ARM systems
- **Burst attack simulation** — configurable random attack patterns (attack for N seconds, pause for M seconds) for realistic demonstration

---

## Known Limitations

- **Linux only** — the mitigator uses `iptables` which is Linux-specific. Windows and macOS are not supported in the current version. A firewall backend abstraction layer is planned for a future release.
- **No dashboard authentication** — the Flask dashboard on port 5000 has no login protection. Do not expose this port to untrusted networks.
- **In-memory storage only** — ban history and event logs are lost if The Warden is restarted. SQLite persistence is planned for a future release.
- **Static thresholds** — the PPS threshold is manually configured in `settings.yaml`. Adaptive per-device baselining is not yet implemented.
- **No TLS support** — the sniffer monitors plaintext MQTT (port 1883) and CoAP (port 5683). Encrypted MQTT over TLS (port 8883) or CoAP over DTLS is not currently parsed.
- **Single broker assumption** — the system assumes one MQTT broker and one CoAP server. Multi-broker environments are not supported.
- **IoT-Flock incompatibility on ARM** — the IoT-Flock binaries are compiled for x86_64 and cannot run on aarch64/ARM systems. The included `simulator.py` is provided as a fully functional replacement.

---

## Requirements

### System
- Linux (Ubuntu 20.04+ recommended)
- Python 3.10+
- `sudo` / root access (required for Scapy raw sockets and iptables)
- `iptables` installed
- `iproute2` installed (for virtual IP aliases in the simulator)
- Mosquitto MQTT broker

### Python Dependencies
```
scapy>=2.7.0
flask>=3.1.0
pyyaml>=6.0
paho-mqtt>=2.0.0
```

---

## Installation

### 1. Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/the-warden.git
cd the-warden
```

### 2. Install system dependencies
```bash
sudo apt update
sudo apt install -y mosquitto mosquitto-clients python3-pip iptables iproute2
```

### 3. Install Python dependencies
```bash
sudo pip3 install scapy flask pyyaml paho-mqtt
```

### 4. Set up the virtual network interface
```bash
sudo modprobe dummy
sudo ip link add eth-icu type dummy
sudo ip addr add 192.168.10.1/24 dev eth-icu
sudo ip link set eth-icu up
```

To make the interface persistent across reboots, add these commands to `/etc/rc.local` or create a systemd service.

### 5. Configure and start Mosquitto
The repository includes a pre-configured Mosquitto config file. Start the broker with:
```bash
# Stop the default system Mosquitto instance first
sudo pkill mosquitto

# Start with The Warden's config
sudo mosquitto -c config/mosquitto_icu.conf
```

### 6. Verify the environment
```bash
# Confirm interface is up
ip addr show eth-icu

# Test broker is reachable
mosquitto_pub -h 192.168.10.1 -t test -m "hello" -p 1883

# Confirm Scapy is available
sudo python3 -c "from scapy.all import sniff; print('Scapy OK')"

# Confirm iptables is available
sudo iptables -L -n
```

All four checks should complete without errors before proceeding.

---

## Configuration

All settings are in `config/settings.yaml`. Edit this file to tune the system for your network:

```yaml
sniffer:
  interface: "any"          # "any" sniffs lo + eth-icu simultaneously

engine:
  threshold_pps: 20.0       # packets/sec that triggers an alert
  window_seconds: 5.0       # sliding window size for PPS calculation
  cooldown_seconds: 10.0    # minimum seconds between repeated alerts per IP
  whitelist:
    - "192.168.10.1"        # MQTT broker — never flagged or banned

mitigator:
  ban_duration: 60.0        # seconds an IP stays banned
  dry_run: false            # true = log bans but do NOT call iptables
  log_path: "logs/bans.log"

ui:
  refresh_rate: 1.0         # dashboard update interval in seconds
```

**Threshold tuning guide:**
- Normal ICU sensors: 0.5 – 2 PPS
- Elevated / suspicious: 10 – 15 PPS
- Active flood attack: 20 – 100+ PPS
- Recommended threshold for ICU networks: 15 – 25 PPS

---

## Running The Warden

### Safe demo mode (no iptables changes)
```bash
sudo python3 main.py --dry-run
```

### Full enforcement mode (live iptables banning)
```bash
sudo python3 main.py
```

### Additional flags
```bash
sudo python3 main.py --dry-run --debug        # verbose logging
sudo python3 main.py --config path/to/config  # custom config file
```

Once running, open your browser and navigate to:
```
http://localhost:5000
```

The dashboard updates automatically every second. Press `Ctrl+C` in the terminal to stop The Warden — all active bans are automatically lifted on shutdown.

---

## Running the Traffic Simulator

The included `simulator.py` replicates the IoT-Flock ICU use case by spawning virtual device threads that bind to specific source IPs, generating realistic MQTT and CoAP traffic patterns.

### Simulated devices

| IP | Device | Protocol | Rate |
|---|---|---|---|
| 192.168.10.50 | Heart Monitor | MQTT | 1 msg/sec |
| 192.168.10.51 | Oxymeter | MQTT | 1 msg/2sec |
| 192.168.10.52 | Infusion Pump | CoAP | 1 msg/30sec |
| 192.168.10.53 | Glucose Monitor | CoAP | 1 msg/120sec |
| 192.168.10.90 | MQTT Flood Attacker | MQTT | 50 msg/sec (burst) |
| 192.168.10.91 | CoAP Flood Attacker | CoAP | 20 msg/sec (burst) |

### Usage
```bash
# Full simulation — normal sensors + attackers (10 second delay before attack)
sudo python3 simulator.py --attack-delay 10

# Normal traffic only — baseline demonstration
sudo python3 simulator.py --normal-only

# Attack traffic only
sudo python3 simulator.py --attack-only

# Custom attack delay
sudo python3 simulator.py --attack-delay 30
```

### Recommended full demo sequence

**Terminal 1 — Start the broker:**
```bash
sudo mosquitto -c config/mosquitto_icu.conf
```

**Terminal 2 — Start The Warden:**
```bash
sudo python3 main.py --dry-run
```

**Terminal 3 — Start the simulator:**
```bash
sudo python3 simulator.py --attack-delay 15
```

Open `http://localhost:5000` in your browser. After 15 seconds you will observe:
1. Normal sensors appear in the Live Traffic panel at 1–2 PPS — status shows **SECURE**
2. Attacker IPs spike past 20 PPS — status flips to **UNDER ATTACK**
3. Bans are issued and appear in the Active Bans panel with countdown timers
4. After 60 seconds bans expire — status returns to **SECURE**
5. Attackers resume — the cycle repeats, building the event log

To test live iptables enforcement, run without `--dry-run` and verify bans with:
```bash
sudo iptables -L INPUT -n --line-numbers
```

---

## Project Structure

```
the-warden/
├── config/
│   ├── mosquitto_icu.conf      # Mosquitto broker config
│   └── settings.yaml           # All tunable parameters
├── logs/
│   └── bans.log                # Persistent ban history (auto-created)
├── src/
│   ├── __init__.py
│   ├── sniffer.py              # Scapy packet capture and parsing
│   ├── engine.py               # Moving average detection engine
│   ├── mitigator.py            # iptables wrapper and ban manager
│   └── ui.py                   # Flask web dashboard
├── simulator.py                # IoT ICU traffic simulator
├── main.py                     # Entry point and orchestrator
├── requirements.txt            # Python dependencies
└── README.md
```

---

## Scholarly References

### Foundational Paper (Prior Research)

**Koroniotis, N., Moustafa, N., Sitnikova, E., & Turnbull, B. (2019).** Towards the development of realistic botnet dataset in the Internet of Things for network forensic analytics: Bot-IoT dataset. *Future Generation Computer Systems, 100*, 779–796. https://doi.org/10.1016/j.future.2019.05.041

This paper established the Bot-IoT dataset — the first publicly available IoT dataset containing both normal and malicious traffic. It served as the direct motivation for the IoT-Flock framework, which this project builds upon. The authors identified the critical gap that existing IDS datasets did not reflect real IoT protocol behavior, a gap that The Warden's protocol-aware detection directly addresses.

### Contemporary Paper (Building on Current Work)

**Zahan, H., Hasan, M., & Islam, M. (2023).** IoT-AD: A framework to detect anomalies among interconnected IoT devices. *Sensors, 23*(4), 2373. https://doi.org/10.3390/s23042373

This paper advances the IoT security landscape by proposing anomaly detection across interconnected IoT device networks, extending the device-level detection approach of the IoT-Flock framework toward network-wide behavioral analysis. The Warden's per-IP sliding window engine reflects a compatible methodology — tracking behavioral rhythm deviations per device — while IoT-AD demonstrates how this approach can be extended to detect correlated multi-device anomalies. Together they represent the progression from single-device detection toward holistic IoT network defense.

---

## License

MIT License — see `LICENSE` for details.
