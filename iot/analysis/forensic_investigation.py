
from pathlib import Path
from collections import Counter
from datetime import datetime, timezone
import csv
import hashlib
import statistics

BASE = Path(__file__).resolve().parent.parent
EVIDENCE = BASE / "evidence" / "labeled-conn.log"
REPORTS = BASE / "reports"

EXPECTED_HASH = (
    "0871016451ce1ebf8713bc0b117079c490615290cbff034b735d096b35722e82"
)

SUSPECT_IP = "192.168.1.115"
TARGET_IP = "41.108.179.197"
TARGET_PORT = "1177"


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for block in iter(lambda: file.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def read_zeek_log(path):
    fields = []
    records = []

    with path.open(encoding="utf-8") as file:
        for line_number, line in enumerate(file, 1):
            line = line.rstrip("\r\n")

            if line.startswith("#fields\t"):
                fields = line.split("\t")[1:]
                continue

            if not line or line.startswith("#"):
                continue

            if not fields:
                raise ValueError("Zeek field header not found")

            values = line.split("\t")

            if len(values) != len(fields):
                raise ValueError(
                    f"Invalid column count at line {line_number}: "
                    f"{len(values)} instead of {len(fields)}"
                )

            record = dict(zip(fields, values))
            record["evidence_line"] = line_number
            records.append(record)

    return records


def analyze():
    REPORTS.mkdir(parents=True, exist_ok=True)

    if not EVIDENCE.exists():
        raise FileNotFoundError(EVIDENCE)

    actual_hash = sha256_file(EVIDENCE)

    if actual_hash != EXPECTED_HASH:
        raise ValueError(
            "Evidence hash mismatch. Analysis stopped."
        )

    records = read_zeek_log(EVIDENCE)

    labels = Counter(
        record.get("label", "Unknown")
        for record in records
    )

    suspicious = [
        record for record in records
        if record.get("id.orig_h") == SUSPECT_IP
        and record.get("id.resp_h") == TARGET_IP
        and record.get("id.resp_p") == TARGET_PORT
        and record.get("proto") == "tcp"
    ]

    suspicious.sort(
        key=lambda record: float(record["ts"])
    )

    timestamps = [
        float(record["ts"])
        for record in suspicious
    ]

    intervals = [
        timestamps[i] - timestamps[i - 1]
        for i in range(1, len(timestamps))
    ]

    average_interval = (
        statistics.mean(intervals) if intervals else 0
    )

    states = Counter(
        record["conn_state"]
        for record in suspicious
    )

    timeline_path = REPORTS / "incident_timeline.csv"

    with timeline_path.open(
        "w", newline="", encoding="utf-8"
    ) as file:
        writer = csv.writer(file)

        writer.writerow([
            "Evidence Line",
            "Recorded Timestamp",
            "Source IP",
            "Source Port",
            "Destination IP",
            "Destination Port",
            "Protocol",
            "Connection State",
            "Published Label",
        ])

        for record in suspicious:
            writer.writerow([
                record["evidence_line"],
                record["ts"],
                record["id.orig_h"],
                record["id.orig_p"],
                record["id.resp_h"],
                record["id.resp_p"],
                record["proto"],
                record["conn_state"],
                record["label"],
            ])

    report_path = REPORTS / "forensic_case_report.txt"

    lines = [
        "NETWORK LOG FORENSIC INVESTIGATION",
        "=" * 55,
        "",
        "CASE INFORMATION",
        "Case ID: ADF-NJRAT-001",
        "Evidence: labeled-conn.log",
        "Source: Stratosphere IPS security-datasets-for-testing",
        "Scenario: CTU-Malware-Capture-Botnet-230-1",
        "Published malware association: NjRAT",
        "Dataset scope: First 1,000 log lines",
        "",
        "EVIDENCE INTEGRITY",
        f"SHA-256: {actual_hash}",
        "Integrity verification: PASSED",
        "",
        "DATASET EXAMINATION",
        f"Parsed connection records: {len(records)}",
        f"Background records: {labels['Background']}",
        f"Malicious-labeled records: {labels['Malicious']}",
        f"Benign records: {labels['Benign']}",
        "",
        "FINDING 01 - REPEATED TCP CONNECTION ATTEMPTS",
        f"Source: {SUSPECT_IP}",
        f"Destination: {TARGET_IP}:{TARGET_PORT}",
        f"Matching records: {len(suspicious)}",
        f"Connection states: {dict(states)}",
        f"Average interval: {average_interval:.3f} seconds",
        f"Minimum interval: {min(intervals):.3f} seconds"
        if intervals else "Minimum interval: N/A",
        f"Maximum interval: {max(intervals):.3f} seconds"
        if intervals else "Maximum interval: N/A",
        "",
        "FORENSIC INTERPRETATION",
        "Repeated TCP attempts were observed toward the same",
        "external destination. The published dataset labels",
        "these flows as malicious.",
        "S0 indicates that no response was observed.",
        "Successful C2 communication is not established.",
        "",
        "LIMITATIONS",
        "The source file is an excerpt, not a complete capture.",
        "The numeric timestamps are preserved as recorded.",
        "The log does not establish IoT-device provenance.",
        "No endpoint evidence confirms malware execution.",
        "",
        "CONCLUSION",
        "The evidence supports repeated, unanswered TCP",
        "connection attempts associated with a published",
        "NjRAT malware-traffic scenario.",
        "",
        "Timeline: incident_timeline.csv",
    ]

    report_path.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8"
    )

    print("\n=== NETWORK LOG FORENSIC INVESTIGATION ===")
    print("Evidence integrity: PASSED")
    print(f"Parsed records: {len(records)}")
    print(f"Labels: {dict(labels)}")
    print(f"Matching suspicious records: {len(suspicious)}")
    print(f"Connection states: {dict(states)}")
    print(f"Average interval: {average_interval:.3f}s")
    print(f"Timeline saved: {timeline_path}")
    print(f"Report saved: {report_path}")


if __name__ == "__main__":
    analyze()
