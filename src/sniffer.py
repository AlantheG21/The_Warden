"""
sniffer.py — The Warden
Scapy-based packet capture module.
Monitors eth-icu for MQTT (TCP/1883) and CoAP (UDP/5683) traffic,
extracts per-IP packet metadata, and feeds it to a callback for the engine.
"""

import time
import logging
import traceback
from scapy.all import sniff, IP, TCP, UDP, Raw

logger = logging.getLogger("warden.sniffer")


# ---------------------------------------------------------------------------
# Protocol helpers
# ---------------------------------------------------------------------------

MQTT_PORT = 1883
COAP_PORT = 5683

# MQTT control packet type names (upper nibble of first byte)
MQTT_MSG_TYPES = {
    1:  "CONNECT",
    2:  "CONNACK",
    3:  "PUBLISH",
    4:  "PUBACK",
    8:  "SUBSCRIBE",
    9:  "SUBACK",
    12: "PINGREQ",
    13: "PINGRESP",
    14: "DISCONNECT",
}

# CoAP method codes (first byte of CoAP header, lower nibble of second byte)
COAP_METHODS = {
    1: "GET",
    2: "POST",
    3: "PUT",
    4: "DELETE",
}


def _parse_mqtt_type(payload: bytes) -> str:
    """Extract the MQTT message type string from a raw TCP payload."""
    if len(payload) < 2:
        return "UNKNOWN"
    msg_type_nibble = (payload[0] >> 4) & 0x0F
    return MQTT_MSG_TYPES.get(msg_type_nibble, f"MQTT_TYPE_{msg_type_nibble}")


def _parse_coap_method(payload: bytes) -> str:
    """Extract the CoAP method string from a raw UDP payload."""
    if len(payload) < 4:
        return "UNKNOWN"
    # CoAP: byte 1 is the Code field. Upper 3 bits = class, lower 5 = detail.
    code = payload[1]
    code_class = (code >> 5) & 0x07
    code_detail = code & 0x1F
    if code_class == 0:
        return COAP_METHODS.get(code_detail, f"COAP_CODE_0.{code_detail:02d}")
    return f"COAP_{code_class}.{code_detail:02d}"


# ---------------------------------------------------------------------------
# Packet record
# ---------------------------------------------------------------------------

class PacketRecord:
    """
    Lightweight container for a single captured packet's metadata.
    The engine only needs these five fields — no raw bytes are passed up.
    """
    __slots__ = ("timestamp", "src_ip", "dst_ip", "protocol", "msg_type")

    def __init__(self, src_ip: str, dst_ip: str, protocol: str, msg_type: str):
        self.timestamp = time.time()
        self.src_ip   = src_ip
        self.dst_ip   = dst_ip
        self.protocol = protocol   # "MQTT" or "CoAP"
        self.msg_type = msg_type   # e.g. "PUBLISH", "GET"

    def __repr__(self):
        ts = time.strftime("%H:%M:%S", time.localtime(self.timestamp))
        return (f"[{ts}] {self.protocol:4s} {self.msg_type:12s} "
                f"{self.src_ip} → {self.dst_ip}")


# ---------------------------------------------------------------------------
# Sniffer class
# ---------------------------------------------------------------------------

class Sniffer:
    """
    Wraps Scapy's sniff() in a clean interface.

    Usage:
        sniffer = Sniffer(interface="eth-icu", callback=engine.ingest)
        sniffer.start()   # blocks — run in a thread
    """

    def __init__(self, interface: str, callback):
        """
        Args:
            interface:  Network interface to sniff on (e.g. "eth-icu").
            callback:   Function called with each PacketRecord.
                        Signature: callback(record: PacketRecord) -> None
        """
        # self.interface = interface
        # self.callback  = callback
        # self._running  = False

        # # Stats for the dashboard
        # self.total_captured = 0
        # self.total_mqtt     = 0
        # self.total_coap     = 0
        self.interface = interface
        self.callback  = callback
        self._running  = False

        # Deduplication: track (src_ip, dst_ip, protocol, msg_type) 
        # seen within the last 0.01 seconds to suppress loopback doubles
        self._seen     = {}
        self._dedup_window = 0.01   # 10ms window

        # Stats
        self.total_captured = 0
        self.total_mqtt     = 0
        self.total_coap     = 0


    # ------------------------------------------------------------------
    # Internal packet handler (called by Scapy for every packet)
    # ------------------------------------------------------------------

    def _handle_packet(self, pkt):
        """Parse one packet and fire the callback if it's MQTT or CoAP."""
        # Must have an IP layer
        if not pkt.haslayer(IP):
            return

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        record = None

        if pkt.haslayer(TCP) and pkt[TCP].dport == MQTT_PORT:
            if pkt.haslayer(Raw):
                msg_type = _parse_mqtt_type(bytes(pkt[Raw].load))
            else:
                msg_type = "TCP_CTRL"
            record = PacketRecord(src_ip, dst_ip, "MQTT", msg_type)
            self.total_mqtt += 1

        elif pkt.haslayer(UDP) and pkt[UDP].dport == COAP_PORT:
            if pkt.haslayer(Raw):
                msg_type = _parse_coap_method(bytes(pkt[Raw].load))
            else:
                msg_type = "UNKNOWN"
            record = PacketRecord(src_ip, dst_ip, "CoAP", msg_type)
            self.total_coap += 1

        if record is None:
            return

        # --- Deduplication ---
        # Packets seen on both lo and eth-icu get a unique key.
        # If the same key was seen within the dedup window, drop it.
        key = (record.src_ip, record.dst_ip, record.protocol, record.msg_type)
        now = record.timestamp
        last_seen = self._seen.get(key, 0)

        if (now - last_seen) < self._dedup_window:
            return   # duplicate — discard silently

        # Drop pure TCP control packets — no application payload to analyze
        if record.msg_type == "TCP_CTRL":
            return

        self._seen[key] = now
        self.total_captured += 1
        logger.debug(record)
        self.callback(record)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def start(self):
        """
        Begin sniffing. This call BLOCKS — run it in a daemon thread.
        BPF filter pre-filters at kernel level for efficiency:
        only TCP/1883 and UDP/5683 packets reach Python.
        """
        self._running = True
        bpf_filter = (
            f"(tcp and port {MQTT_PORT}) or "
            f"(udp and port {COAP_PORT})"
        )

        # Resolve interface list — sniff lo + eth-icu to catch both
        # local (loopback-routed) and external (IoT-Flock virtual IP) traffic
        if self.interface == "any":
            interfaces = ["lo", "eth-icu"]
        else:
            interfaces = self.interface

        logger.info(f"Sniffer starting on interfaces: {interfaces}")
        logger.info(f"BPF filter: {bpf_filter}")

        sniff(
            iface=interfaces,
            filter=bpf_filter,
            prn=self._handle_packet,
            store=False,
            stop_filter=lambda _: not self._running,
        )

    def stop(self):
        """Signal the sniffer to stop after the next packet arrives."""
        self._running = False
        logger.info("Sniffer stopping.")

    def get_stats(self) -> dict:
        """Return a snapshot of capture statistics for the dashboard."""
        return {
            "total":    self.total_captured,
            "mqtt":     self.total_mqtt,
            "coap":     self.total_coap,
        }


# ---------------------------------------------------------------------------
# Standalone test — run this file directly to verify sniffing works
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import threading

    # Configure only the warden logger — prevent Scapy from adding its own handler
    logging.basicConfig(
        level=logging.WARNING,          # suppress Scapy's own output
        format="%(asctime)s [%(levelname)s] %(message)s"
    )
    warden_logger = logging.getLogger("warden")
    warden_logger.setLevel(logging.DEBUG)

    # Ensure only one handler exists — clear any Scapy may have added
    if not warden_logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        warden_logger.addHandler(handler)

    warden_logger.propagate = False     # do NOT pass up to root logger

    print("=" * 55)
    print("  Warden Sniffer — standalone test")
    print("  Listening on eth-icu for MQTT and CoAP traffic.")
    print("  In another terminal run:")
    print("    mosquitto_pub -h 192.168.10.1 -t test -m hello")
    print("  Press Ctrl+C to stop.")
    print("=" * 55)

    def print_record(record: PacketRecord):
        pass #print(record)

    sniffer = Sniffer(interface="any", callback=print_record)

    # Run in a thread so we can catch KeyboardInterrupt cleanly
    t = threading.Thread(target=sniffer.start, daemon=True)
    t.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        sniffer.stop()
        print(f"\nStats: {sniffer.get_stats()}")
        print("Sniffer stopped.")