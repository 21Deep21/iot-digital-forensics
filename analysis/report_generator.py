
from pathlib import Path
from datetime import datetime
import csv
import statistics
import hashlib

BASE_DIR = Path(__file__).resolve().parent.parent

TIMELINE_FILE = BASE_DIR / "reports" / "attack_timeline.csv"
PCAP_FILE = BASE_DIR / "captures" / "phishing_attack.pcapng"
REPORT_FILE = BASE_DIR / "reports" / "forensic_report.txt"


def calculate_sha256(path):
    digest = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(65536), b""):
            digest.update(chunk)

    return digest.hexdigest()


def generate_report():
    with TIMELINE_FILE.open(newline="") as file:
        events = list(csv.DictReader(file))

    if not events:
        print("No forensic events found.")
        return

    beacons = [
        event for event in events
        if event["request_path"] == "/c2/checkin"
    ]

    beacon_times = [
        datetime.fromisoformat(event["timestamp"])
        for event in beacons
    ]

    intervals = [
        (beacon_times[i] - beacon_times[i - 1]).total_seconds()
        for i in range(1, len(beacon_times))
    ]

    average_interval = (
        statistics.mean(intervals) if intervals else 0
    )

    interval_deviation = (
        statistics.pstdev(intervals) if intervals else 0
    )

    unique_connections = sorted({
        (
            event["destination_ip"],
            event["destination_port"]
        )
        for event in events
    })

    lines = [
        "=" * 55,
        "NETWORK TRAFFIC FORENSIC INVESTIGATION REPORT",
        "=" * 55,
        "",
        "1. CASE INFORMATION",
        "Project: Phishing-to-Compromise Reconstruction",
        "Environment: Fedora Linux - Controlled Local Lab",
        "Evidence: phishing_attack.pcapng",
        "",
        "2. EVIDENCE INTEGRITY",
        f"SHA-256: {calculate_sha256(PCAP_FILE)}",
        "",
        "3. INVESTIGATION SUMMARY",
        f"Total identified simulation events: {len(events)}",
        f"Simulated C2 requests: {len(beacons)}",
        f"First event: {events[0]['timestamp']}",
        f"Last event: {events[-1]['timestamp']}",
        "",
        "4. SIMULATED C2 BEACON ANALYSIS",
        f"Average beacon interval: {average_interval:.3f} seconds",
        f"Interval standard deviation: {interval_deviation:.3f} seconds",
        "Individual intervals: " +
        (", ".join(f"{x:.3f}s" for x in intervals)
         if intervals else "Insufficient data"),
        "",
        "5. OBSERVED NETWORK INDICATORS",
    ]

    for ip, port in unique_connections:
        lines.append(f"Destination: {ip}:{port}")

    lines.extend([
        "Observed request paths: /verify, /payload, /c2/checkin",
        "",
        "6. RECONSTRUCTED ATTACK TIMELINE",
    ])

    for index, event in enumerate(events, start=1):
        lines.append(
            f"{index}. {event['timestamp']} | "
            f"{event['event']} | "
            f"{event['request_path']}"
        )

    lines.extend([
        "",
        "7. CONCLUSION",
        "The captured network traffic demonstrates a controlled",
        "phishing-to-C2 simulation. HTTP requests were correlated",
        "using timestamps and predefined simulation endpoints.",
        "Five periodic C2-like requests were identified.",
        "",
        "The evidence does not establish a real malware infection.",
        "All identified indicators belong to the local simulation.",
        "",
        "=" * 55,
    ])

    REPORT_FILE.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8"
    )

    print("\n=== FORENSIC REPORT GENERATED ===")
    print(f"Events analyzed: {len(events)}")
    print(f"C2 beacons: {len(beacons)}")
    print(f"Average beacon interval: {average_interval:.3f}s")
    print(f"Report saved: {REPORT_FILE}")


if __name__ == "__main__":
    generate_report()
