
from pathlib import Path
from datetime import datetime, timezone
from uuid import uuid4
from collections import defaultdict
import csv
import hashlib
import json
import statistics
import subprocess

from flask import (
    Flask,
    render_template,
    request,
    send_file,
    abort,
)
from werkzeug.utils import secure_filename
from scapy.all import PcapReader, IP, TCP, Raw

from analysis.external_pcap_analyzer import analyze_external_pcap


# --------------------------------------------------
# PROJECT CONFIGURATION
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent

CAPTURES = BASE_DIR / "captures"
REPORTS = BASE_DIR / "reports"

SIMULATION_DIR = CAPTURES / "simulation"
EXTERNAL_DIR = CAPTURES / "external" / "uploads"

for directory in (
    CAPTURES,
    REPORTS,
    SIMULATION_DIR,
    EXTERNAL_DIR,
):
    directory.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)

app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024

ALLOWED_EXTENSIONS = {".pcap", ".pcapng"}

EVENTS = {
    "/verify": "Phishing Link Accessed",
    "/payload": "Simulated Payload Requested",
    "/c2/checkin": "Simulated C2 Beacon",
}


# --------------------------------------------------
# EVIDENCE MANAGEMENT
# --------------------------------------------------

def save_evidence(uploaded_file, folder):
    """
    Save evidence with a unique filename.
    Existing evidence is never overwritten.
    """

    original_name = secure_filename(
        uploaded_file.filename or ""
    )

    extension = Path(original_name).suffix.lower()

    if extension not in ALLOWED_EXTENSIONS:
        raise ValueError(
            "Only PCAP and PCAPNG files are supported."
        )

    timestamp = datetime.now(
        timezone.utc
    ).strftime("%Y%m%d_%H%M%S")

    unique_id = uuid4().hex[:12]

    filename = (
        f"{timestamp}_{unique_id}_{original_name}"
    )

    destination = folder / filename

    with destination.open("xb") as file:
        uploaded_file.save(file)

    return destination, unique_id


def calculate_sha256(path):
    digest = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(
            lambda: file.read(65536), b""
        ):
            digest.update(chunk)

    return digest.hexdigest()


def investigation_directory(investigation_id):
    path = REPORTS / investigation_id
    path.mkdir(parents=True, exist_ok=True)
    return path


# --------------------------------------------------
# SIMULATION PCAP ANALYSIS
# --------------------------------------------------

def analyze_simulation(path):
    timeline = []
    packet_count = 0

    with PcapReader(str(path)) as packets:
        for packet in packets:
            packet_count += 1

            if not (
                packet.haslayer(IP)
                and packet.haslayer(TCP)
                and packet.haslayer(Raw)
            ):
                continue

            payload = bytes(packet[Raw].load)
            first_line = payload.split(b"\r\n", 1)[0]

            if not first_line.startswith(b"GET "):
                continue

            parts = first_line.split(b" ")

            if len(parts) < 3:
                continue

            try:
                uri = parts[1].decode("ascii")
            except UnicodeDecodeError:
                continue

            if uri not in EVENTS:
                continue

            timestamp = datetime.fromtimestamp(
                float(packet.time),
                tz=timezone.utc
            ).astimezone()

            timeline.append({
                "timestamp": timestamp.isoformat(
                    timespec="milliseconds"
                ),
                "epoch": float(packet.time),
                "source_ip": packet[IP].src,
                "destination_ip": packet[IP].dst,
                "source_port": packet[TCP].sport,
                "destination_port": packet[TCP].dport,
                "event": EVENTS[uri],
                "request_path": uri,
            })

    timeline.sort(key=lambda item: item["epoch"])

    return packet_count, timeline


def generate_simulation_reports(
    evidence_path,
    investigation_id,
    packet_count,
    timeline,
):
    output_dir = investigation_directory(
        investigation_id
    )

    csv_path = output_dir / "attack_timeline.csv"
    report_path = output_dir / "forensic_report.txt"

    fields = [
        "timestamp",
        "source_ip",
        "destination_ip",
        "source_port",
        "destination_port",
        "event",
        "request_path",
    ]

    with csv_path.open(
        "w", newline="", encoding="utf-8"
    ) as file:
        writer = csv.DictWriter(
            file, fieldnames=fields
        )

        writer.writeheader()

        for event in timeline:
            writer.writerow({
                field: event[field]
                for field in fields
            })

    beacons = [
        event for event in timeline
        if event["request_path"] == "/c2/checkin"
    ]

    intervals = [
        beacons[i]["epoch"] - beacons[i - 1]["epoch"]
        for i in range(1, len(beacons))
    ]

    average = (
        statistics.mean(intervals)
        if intervals else 0
    )

    sha256 = calculate_sha256(evidence_path)

    lines = [
        "NETWORK TRAFFIC FORENSIC REPORT",
        "=" * 50,
        "",
        "CASE INFORMATION",
        f"Investigation ID: {investigation_id}",
        f"Evidence: {evidence_path.name}",
        f"SHA-256: {sha256}",
        "",
        "INVESTIGATION SUMMARY",
        f"Total packets: {packet_count}",
        f"Detected events: {len(timeline)}",
        f"Simulated C2 beacons: {len(beacons)}",
        f"Average beacon interval: {average:.3f}s",
        "",
        "RECONSTRUCTED TIMELINE",
        "-" * 50,
    ]

    for event in timeline:
        lines.append(
            f"{event['timestamp']} | "
            f"{event['event']} | "
            f"{event['request_path']}"
        )

    lines.extend([
        "",
        "CONCLUSION",
        "This investigation analyzes a controlled",
        "phishing-to-C2 simulation.",
        "Event labels correspond to predefined",
        "HTTP endpoints used in the laboratory.",
        "No actual malware execution is established.",
    ])

    report_path.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8"
    )

    return {
        "packets": packet_count,
        "events": len(timeline),
        "beacons": len(beacons),
        "average": round(average, 3),
        "sha256": sha256,
        "timeline": timeline,
        "investigation_id": investigation_id,
    }


# --------------------------------------------------
# SIMULATION DASHBOARD
# --------------------------------------------------

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    error = None

    if request.method == "POST":
        uploaded = request.files.get("pcap")

        if not uploaded or not uploaded.filename:
            error = "Please select a PCAP file."

        else:
            try:
                evidence_path, investigation_id = (
                    save_evidence(
                        uploaded,
                        SIMULATION_DIR
                    )
                )

                packet_count, timeline = (
                    analyze_simulation(evidence_path)
                )

                result = generate_simulation_reports(
                    evidence_path,
                    investigation_id,
                    packet_count,
                    timeline,
                )

            except Exception as exc:
                error = f"Analysis failed: {exc}"

    return render_template(
        "index.html",
        result=result,
        error=error,
    )


# --------------------------------------------------
# EXTERNAL PCAP DASHBOARD
# --------------------------------------------------

@app.route("/external", methods=["GET", "POST"])
def external_analysis():
    result = None
    error = None

    if request.method == "POST":
        uploaded = request.files.get("pcap")

        if not uploaded or not uploaded.filename:
            error = "Please select a PCAP file."

        else:
            try:
                evidence_path, investigation_id = (
                    save_evidence(
                        uploaded,
                        EXTERNAL_DIR
                    )
                )

                result = analyze_external_pcap(
                    evidence_path
                )

                result["investigation_id"] = (
                    investigation_id
                )

                output_dir = investigation_directory(
                    investigation_id
                )

                json_path = (
                    output_dir / "external_analysis.json"
                )

                json_path.write_text(
                    json.dumps(result, indent=2),
                    encoding="utf-8"
                )

            except Exception as exc:
                error = f"Analysis failed: {exc}"

    return render_template(
        "external.html",
        result=result,
        error=error,
    )


# --------------------------------------------------
# REPORT DOWNLOADS
# --------------------------------------------------

@app.route("/download/<investigation_id>/<report_type>")
def download_investigation(
    investigation_id,
    report_type,
):
    if (
        len(investigation_id) != 12
        or not all(
            character in "0123456789abcdef"
            for character in investigation_id
        )
    ):
        abort(404)

    filenames = {
        "csv": "attack_timeline.csv",
        "report": "forensic_report.txt",
        "external": "external_analysis.json",
    }

    filename = filenames.get(report_type)

    if not filename:
        abort(404)

    path = REPORTS / investigation_id / filename

    if not path.is_file():
        abort(404)

    return send_file(
        path,
        as_attachment=True,
        download_name=filename,
    )


# --------------------------------------------------
# APPLICATION START
# --------------------------------------------------

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=8000,
        debug=False,
    )
