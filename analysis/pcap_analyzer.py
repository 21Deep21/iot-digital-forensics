
from pathlib import Path
from datetime import datetime
import csv

from scapy.all import rdpcap, IP, TCP, Raw

BASE_DIR = Path(__file__).resolve().parent.parent
PCAP_FILE = BASE_DIR / "captures" / "phishing_attack.pcapng"
REPORT_DIR = BASE_DIR / "reports"
OUTPUT_FILE = REPORT_DIR / "attack_timeline.csv"

EVENTS = {
    "/verify": "Phishing Link Accessed",
    "/payload": "Simulated Payload Requested",
    "/c2/checkin": "Simulated C2 Beacon",
}


def analyze_pcap():
    REPORT_DIR.mkdir(exist_ok=True)

    print("\n=== NETWORK FORENSIC ANALYSIS ===")

    packets = rdpcap(str(PCAP_FILE))
    print(f"Total packets captured: {len(packets)}")

    timeline = []

    for packet in packets:
        if not (packet.haslayer(IP) and packet.haslayer(TCP)):
            continue

        if not packet.haslayer(Raw):
            continue

        payload = bytes(packet[Raw].load)

        # Inspect HTTP request lines only.
        first_line = payload.split(b"\r\n", 1)[0]

        if not first_line.startswith(b"GET "):
            continue

        try:
            request_path = first_line.split(b" ")[1].decode("ascii")
        except (IndexError, UnicodeDecodeError):
            continue

        if request_path not in EVENTS:
            continue

        timestamp = datetime.fromtimestamp(
            float(packet.time)
        ).astimezone().isoformat(timespec="milliseconds")

        event = {
            "timestamp": timestamp,
            "source_ip": packet[IP].src,
            "destination_ip": packet[IP].dst,
            "source_port": packet[TCP].sport,
            "destination_port": packet[TCP].dport,
            "event": EVENTS[request_path],
            "request_path": request_path,
        }

        timeline.append(event)

    timeline.sort(key=lambda event: event["timestamp"])

    if not timeline:
        print("No matching simulation events found.")
        return

    with OUTPUT_FILE.open("w", newline="") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=list(timeline[0].keys())
        )
        writer.writeheader()
        writer.writerows(timeline)

    print("\n--- RECONSTRUCTED ATTACK TIMELINE ---")

    for event in timeline:
        print(
            f"{event['timestamp']} | "
            f"{event['event']} | "
            f"{event['source_ip']} -> "
            f"{event['destination_ip']}"
        )

    print(f"\nTotal detected events: {len(timeline)}")
    print(f"Timeline saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    analyze_pcap()
