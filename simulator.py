#!/usr/bin/env python3
"""
simulator.py — The Warden
IoT traffic simulator to replace IoT-Flock on aarch64 systems.

Simulates the exact ICU use case defined in the project XML:
  Normal devices:
    192.168.10.50 — Heart Monitor    (MQTT, 1 msg/sec)
    192.168.10.51 — Oxymeter         (MQTT, 1 msg/every 2sec)
    192.168.10.52 — Infusion Pump    (CoAP, 1 msg/every 30sec)
    192.168.10.53 — Glucose Monitor  (CoAP, 1 msg/every 120sec)
  Attacking devices:
    192.168.10.90 — MQTT Flood       (MQTT, 50 msg/sec)
    192.168.10.91 — CoAP Flood       (CoAP, 20 msg/sec)

Each device binds a virtual IP alias on lo so packets appear
with the correct source IP to The Warden's sniffer.

Usage:
    sudo python3 simulator.py                  # normal + attack
    sudo python3 simulator.py --normal-only    # safe baseline only
    sudo python3 simulator.py --attack-only    # attack only
    sudo python3 simulator.py --attack-delay 15  # wait 15s before attack
"""

import os
import sys
import time
import random
import socket
import struct
import argparse
import threading
import subprocess
import logging

logger = logging.getLogger("simulator")

# ---------------------------------------------------------------------------
# Configuration — mirrors the project XML exactly
# ---------------------------------------------------------------------------

BROKER_IP   = "192.168.10.1"
BROKER_PORT = 1883
COAP_PORT   = 5683

NORMAL_DEVICES = [
    {
        "name":     "Heart Monitor",
        "ip":       "192.168.10.50",
        "protocol": "MQTT",
        "topic":    "icu/heartrate",
        "interval": 1.0,
        "payload":  lambda: f'{{"heart_rate": {random.randint(60, 100)}}}',
    },
    {
        "name":     "Oxymeter",
        "ip":       "192.168.10.51",
        "protocol": "MQTT",
        "topic":    "icu/spo2",
        "interval": 2.0,
        "payload":  lambda: f'{{"saturation": {random.randint(95, 100)}}}',
    },
    {
        "name":     "Infusion Pump",
        "ip":       "192.168.10.52",
        "protocol": "CoAP",
        "topic":    "coap://192.168.10.1/pump/status",
        "interval": 30.0,
        "payload":  lambda: f'{{"status": "infusing", "rate": "{random.randint(5,10)}mL/h"}}',
    },
    {
        "name":     "Glucose Monitor",
        "ip":       "192.168.10.53",
        "protocol": "CoAP",
        "topic":    "coap://192.168.10.1/glucose/status",
        "interval": 120.0,
        "payload":  lambda: f'{{"glucose_level": {random.randint(54, 180)}}}',
    },
]

ATTACK_DEVICES = [
    {
        "name":     "MQTT Flood Attacker",
        "ip":       "192.168.10.90",
        "protocol": "MQTT",
        "topic":    "icu/attack",
        "interval": 0.02,    # 50 msg/sec during attack
        "payload":  lambda: '{"flood": "ATTACK"}',
        "burst_duration": (5, 15),    # attack for 5-15 seconds
        "burst_pause":    (10, 30),   # rest for 10-30 seconds
    },
    {
        "name":     "CoAP Flood Attacker",
        "ip":       "192.168.10.91",
        "protocol": "CoAP",
        "topic":    "coap://192.168.10.1/attack",
        "interval": 0.05,    # 20 msg/sec during attack
        "payload":  lambda: '{"flood": "ATTACK"}',
        "burst_duration": (3, 10),
        "burst_pause":    (15, 40),
    },
]


# ---------------------------------------------------------------------------
# Virtual IP management
# ---------------------------------------------------------------------------

def add_virtual_ip(ip: str) -> bool:
    """
    Add an IP alias on the loopback interface so packets sent
    from this IP appear with the correct source to Scapy.
    """
    cmd = ["ip", "addr", "add", f"{ip}/32", "dev", "lo"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            logger.info(f"Added virtual IP: {ip}")
            return True
        elif "already exists" in result.stderr:
            logger.info(f"Virtual IP already exists: {ip}")
            return True
        else:
            logger.error(f"Failed to add {ip}: {result.stderr.strip()}")
            return False
    except Exception as e:
        logger.error(f"Error adding virtual IP {ip}: {e}")
        return False


def remove_virtual_ip(ip: str) -> None:
    """Remove a virtual IP alias from loopback."""
    cmd = ["ip", "addr", "del", f"{ip}/32", "dev", "lo"]
    try:
        subprocess.run(cmd, capture_output=True, text=True)
        logger.info(f"Removed virtual IP: {ip}")
    except Exception as e:
        logger.error(f"Error removing virtual IP {ip}: {e}")


def setup_all_virtual_ips(devices: list) -> list:
    """Add virtual IPs for all devices. Returns list of IPs added."""
    added = []
    for device in devices:
        if add_virtual_ip(device["ip"]):
            added.append(device["ip"])
    return added


def cleanup_all_virtual_ips(ips: list) -> None:
    """Remove all virtual IPs created by the simulator."""
    for ip in ips:
        remove_virtual_ip(ip)


# ---------------------------------------------------------------------------
# MQTT raw packet builder
# Builds a minimal MQTT PUBLISH packet without needing paho-mqtt
# so we can bind to a specific source IP via raw socket
# ---------------------------------------------------------------------------

def build_mqtt_connect() -> bytes:
    """Build a minimal MQTT CONNECT packet."""
    protocol_name   = b'\x00\x04MQTT'
    protocol_level  = b'\x04'           # MQTT 3.1.1
    connect_flags   = b'\x02'           # clean session
    keep_alive      = b'\x00\x3c'       # 60 seconds
    client_id       = b'\x00\x08WardSim'
    payload         = protocol_name + protocol_level + connect_flags + keep_alive + client_id
    remaining       = len(payload)
    return bytes([0x10, remaining]) + payload


def build_mqtt_publish(topic: str, payload: str) -> bytes:
    """Build a minimal MQTT PUBLISH packet."""
    topic_bytes     = topic.encode()
    payload_bytes   = payload.encode()
    topic_len       = struct.pack("!H", len(topic_bytes))
    msg             = topic_len + topic_bytes + payload_bytes
    remaining       = len(msg)
    # Encode remaining length (simple single-byte for packets < 128 bytes)
    if remaining < 128:
        return bytes([0x30, remaining]) + msg
    else:
        # Multi-byte remaining length encoding
        enc = []
        x = remaining
        while x > 0:
            digit = x % 128
            x //= 128
            if x > 0:
                digit |= 0x80
            enc.append(digit)
        return bytes([0x30] + enc) + msg


def build_mqtt_disconnect() -> bytes:
    """Build a minimal MQTT DISCONNECT packet."""
    return bytes([0xe0, 0x00])


# ---------------------------------------------------------------------------
# CoAP raw packet builder
# ---------------------------------------------------------------------------

def build_coap_get(path: str, msg_id: int = 1) -> bytes:
    """
    Build a minimal CoAP GET request.
    Header: Ver=1, Type=0 (CON), TKL=0, Code=0.01 (GET)
    """
    ver_type_tkl = 0x40        # Ver=1, Type=CON, TKL=0
    code         = 0x01        # GET
    header       = struct.pack("!BBH", ver_type_tkl, code, msg_id & 0xFFFF)
    # Uri-Path option (option number 11, delta 11)
    path_clean   = path.lstrip("/").encode()
    option       = bytes([0xb0 | len(path_clean)]) + path_clean
    return header + option


# ---------------------------------------------------------------------------
# Device thread — one thread per simulated device
# ---------------------------------------------------------------------------

class DeviceThread(threading.Thread):
    """
    Simulates one IoT device by sending MQTT or CoAP packets
    from its assigned virtual IP at the configured interval.
    """

    def __init__(self, device: dict, stop_event: threading.Event):
        super().__init__(name=f"sim-{device['name']}", daemon=True)
        self.device     = device
        self.stop_event = stop_event
        self.sent       = 0
        self._msg_id    = 1

    def run(self):
        name     = self.device["name"]
        src_ip   = self.device["ip"]
        protocol = self.device["protocol"]
        interval = self.device["interval"]

        # Check if this is a burst-mode attacker
        burst_dur   = self.device.get("burst_duration")
        burst_pause = self.device.get("burst_pause")

        logger.info(f"[{name}] Starting — {src_ip} {protocol}")

        while not self.stop_event.is_set():
            if burst_dur and burst_pause:
                # --- Burst mode ---
                attack_secs = random.uniform(*burst_dur)
                pause_secs  = random.uniform(*burst_pause)

                print(f"[{name}] Attacking for {attack_secs:.1f}s...")
                attack_end = time.time() + attack_secs

                while time.time() < attack_end and not self.stop_event.is_set():
                    try:
                        payload = self.device["payload"]()
                        if protocol == "MQTT":
                            self._send_mqtt(src_ip, payload)
                        elif protocol == "CoAP":
                            self._send_coap(src_ip, payload)
                        self.sent += 1
                    except Exception as e:
                        logger.error(f"[{name}] Send error: {e}")
                    self.stop_event.wait(interval)

                if not self.stop_event.is_set():
                    print(f"[{name}] Pausing for {pause_secs:.1f}s...")
                    self.stop_event.wait(pause_secs)
            else:
                # --- Continuous mode (normal sensors) ---
                try:
                    payload = self.device["payload"]()
                    if protocol == "MQTT":
                        self._send_mqtt(src_ip, payload)
                    elif protocol == "CoAP":
                        self._send_coap(src_ip, payload)
                    self.sent += 1
                except Exception as e:
                    logger.error(f"[{name}] Send error: {e}")
                self.stop_event.wait(interval)

        logger.info(f"[{name}] Stopped after {self.sent} packets.")

    def _send_mqtt(self, src_ip: str, payload: str) -> None:
        """
        Open a raw TCP connection from src_ip and send a complete
        MQTT CONNECT → PUBLISH → DISCONNECT sequence.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(2.0)
        try:
            # Bind to the virtual source IP before connecting
            sock.bind((src_ip, 0))
            sock.connect((BROKER_IP, BROKER_PORT))

            sock.sendall(build_mqtt_connect())
            # Wait for CONNACK (2 bytes)
            sock.recv(4)

            topic = self.device.get("topic", "icu/data")
            sock.sendall(build_mqtt_publish(topic, payload))
            sock.sendall(build_mqtt_disconnect())
        finally:
            sock.close()

    def _send_coap(self, src_ip: str, payload: str) -> None:
        """
        Send a CoAP GET request from src_ip over UDP.
        CoAP uses UDP so binding the source IP is straightforward.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        try:
            sock.bind((src_ip, 0))
            # Extract path from coap://host/path
            topic = self.device.get("topic", "coap://192.168.10.1/data")
            path  = "/" + "/".join(topic.split("/")[3:])
            pkt   = build_coap_get(path, self._msg_id)
            self._msg_id = (self._msg_id + 1) % 65536
            sock.sendto(pkt, (BROKER_IP, COAP_PORT))
        finally:
            sock.close()


# ---------------------------------------------------------------------------
# Simulator orchestrator
# ---------------------------------------------------------------------------

class Simulator:
    """
    Manages all device threads and virtual IP lifecycle.
    """

    def __init__(
        self,
        run_normal: bool = True,
        run_attack: bool = True,
        attack_delay: float = 10.0,
    ):
        self.run_normal   = run_normal
        self.run_attack   = run_attack
        self.attack_delay = attack_delay

        self._stop_event   = threading.Event()
        self._threads      = []
        self._virtual_ips  = []

    def start(self) -> None:
        """Set up virtual IPs and launch all device threads."""
        if os.geteuid() != 0:
            print("[ERROR] Simulator requires root to add virtual IPs.")
            print("Run with: sudo python3 simulator.py")
            sys.exit(1)

        devices_to_run = []
        if self.run_normal:
            devices_to_run.extend(NORMAL_DEVICES)
        if self.run_attack:
            devices_to_run.extend(ATTACK_DEVICES)

        # Add virtual IPs for all devices
        print("\n[*] Setting up virtual IP aliases on loopback...")
        self._virtual_ips = setup_all_virtual_ips(devices_to_run)
        print(f"[*] {len(self._virtual_ips)} virtual IPs configured.")

        # Start normal device threads immediately
        if self.run_normal:
            print("\n[*] Starting normal ICU sensor simulation...")
            for device in NORMAL_DEVICES:
                t = DeviceThread(device, self._stop_event)
                t.start()
                self._threads.append(t)
                print(f"    {device['ip']:<18} {device['name']}")

        # Start attack threads after delay
        if self.run_attack:
            if self.attack_delay > 0:
                print(f"\n[*] Attack begins in {self.attack_delay:.0f} seconds...")
                print("    Start The Warden now if not already running.\n")
                self._stop_event.wait(self.attack_delay)

            if not self._stop_event.is_set():
                print("\n[!] LAUNCHING ATTACK SIMULATION")
                for device in ATTACK_DEVICES:
                    t = DeviceThread(device, self._stop_event)
                    t.start()
                    self._threads.append(t)
                    print(f"    {device['ip']:<18} {device['name']} "
                          f"({1/device['interval']:.0f} pkt/s)")

        print("\n[*] Simulator running. Press Ctrl+C to stop.\n")

        try:
            while not self._stop_event.is_set():
                self._print_stats()
                time.sleep(5)
        except KeyboardInterrupt:
            self.stop()

    def stop(self) -> None:
        """Signal all threads to stop and clean up virtual IPs."""
        print("\n\n[*] Stopping simulator...")
        self._stop_event.set()

        for t in self._threads:
            t.join(timeout=3)

        print("[*] Cleaning up virtual IPs...")
        cleanup_all_virtual_ips(self._virtual_ips)

        print("\n[*] Simulator stopped.")
        self._print_stats()

    def _print_stats(self) -> None:
        """Print a one-line stats summary to stdout."""
        parts = []
        for t in self._threads:
            parts.append(f"{t.device['ip']} ({t.sent} sent)")
        print(f"[stats] {' | '.join(parts)}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="IoT ICU traffic simulator for The Warden testbed"
    )
    parser.add_argument(
        "--normal-only",
        action="store_true",
        help="Run only normal sensor traffic (no attack)",
    )
    parser.add_argument(
        "--attack-only",
        action="store_true",
        help="Run only attack traffic (no normal sensors)",
    )
    parser.add_argument(
        "--attack-delay",
        type=float,
        default=10.0,
        help="Seconds to wait before launching attack (default: 10)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )
    sim_logger = logging.getLogger("simulator")
    sim_logger.setLevel(logging.INFO)
    if not sim_logger.handlers:
        h = logging.StreamHandler()
        h.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        sim_logger.addHandler(h)
    sim_logger.propagate = False

    args = parse_args()

    run_normal = not args.attack_only
    run_attack = not args.normal_only

    sim = Simulator(
        run_normal   = run_normal,
        run_attack   = run_attack,
        attack_delay = args.attack_delay,
    )
    sim.start()