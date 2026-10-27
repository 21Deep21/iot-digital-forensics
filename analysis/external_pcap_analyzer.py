
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter
import subprocess
import csv
import hashlib
import json
import argparse

BASE = Path(__file__).resolve().parent.parent

DEFAULT_PCAP = (
    BASE / "captures" / "external"
    / "2026-10-01-traffic-analysis-exercise.pcap"
)

OUTPUT = BASE / "reports" / "external_analysis.json"

FIELDS_HTTP = [
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "tcp.stream",
    "http.request.method",
    "http.host",
    "http.request.uri",
    "http.response.code",
    "http.content_length",
    "http.request_in",
]

EXECUTABLE_EXTENSIONS = (
    ".exe", ".dll", ".msi", ".ps1",
    ".bat", ".cmd", ".scr"
)


def format_time(epoch):
    if not epoch:
        return ""

    return datetime.fromtimestamp(
        float(epoch), tz=timezone.utc
    ).astimezone().isoformat(timespec="milliseconds")


def run_tshark(pcap, display_filter, fields):
    command = [
        "tshark",
        "-r", str(pcap),
        "-Y", display_filter,
        "-T", "fields",
        "-E", "separator=/t",
        "-E", "occurrence=f",
    ]

    for field in fields:
        command.extend(["-e", field])

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=True,
        timeout=180,
    )

    rows = csv.reader(
        result.stdout.splitlines(),
        delimiter="\t"
    )

    return [
        dict(zip(fields, row))
        for row in rows
        if len(row) == len(fields)
    ]


def calculate_sha256(pcap):
    digest = hashlib.sha256()

    with pcap.open("rb") as file:
        for chunk in iter(
            lambda: file.read(65536), b""
        ):
            digest.update(chunk)

    return digest.hexdigest()


def extract_dns(pcap):
    fields = [
        "frame.number",
        "frame.time_epoch",
        "ip.src",
        "ip.dst",
        "dns.qry.name",
        "dns.qry.type",
    ]

    rows = run_tshark(
        pcap,
        "dns.flags.response == 0 && dns.qry.name",
        fields
    )

    return [
        {
            "frame": row["frame.number"],
            "timestamp": format_time(
                row["frame.time_epoch"]
            ),
            "source_ip": row["ip.src"],
            "destination_ip": row["ip.dst"],
            "domain": row["dns.qry.name"],
            "query_type": row["dns.qry.type"],
        }
        for row in rows
    ]


def extract_http(pcap):
    rows = run_tshark(
        pcap,
        "http.request || http.response",
        FIELDS_HTTP
    )

    events = []

    for row in rows:
        method = row["http.request.method"]
        uri = row["http.request.uri"]
        response = row["http.response.code"]

        is_request = bool(method)
        clean_uri = uri.lower().split("?", 1)[0]

        executable = (
            is_request
            and clean_uri.endswith(
                EXECUTABLE_EXTENSIONS
            )
        )

        events.append({
            "frame": row["frame.number"],
            "timestamp": format_time(
                row["frame.time_epoch"]
            ),
            "epoch": float(
                row["frame.time_epoch"]
            ),
            "source_ip": row["ip.src"],
            "destination_ip": row["ip.dst"],
            "tcp_stream": row["tcp.stream"],
            "type": (
                "request" if is_request
                else "response"
            ),
            "method": method,
            "host": row["http.host"],
            "uri": uri,
            "response_code": response,
            "content_length": row[
                "http.content_length"
            ],
            "request_frame": row["http.request_in"],
            "executable_indicator": executable,
        })

    return events


def extract_tls(pcap):
    fields = [
        "frame.number",
        "frame.time_epoch",
        "ip.src",
        "ip.dst",
        "tcp.stream",
        "tls.handshake.extensions_server_name",
    ]

    rows = run_tshark(
        pcap,
        "tls.handshake.extensions_server_name",
        fields
    )

    return [
        {
            "frame": row["frame.number"],
            "timestamp": format_time(
                row["frame.time_epoch"]
            ),
            "source_ip": row["ip.src"],
            "destination_ip": row["ip.dst"],
            "tcp_stream": row["tcp.stream"],
            "server_name": row[
                "tls.handshake.extensions_server_name"
            ],
        }
        for row in rows
    ]


def extract_tcp_connections(pcap):
    fields = [
        "frame.number",
        "frame.time_epoch",
        "ip.src",
        "ip.dst",
        "tcp.srcport",
        "tcp.dstport",
        "tcp.stream",
    ]

    rows = run_tshark(
        pcap,
        "tcp.flags.syn == 1 && tcp.flags.ack == 0 "
        "&& ip.src && ip.dst",
        fields
    )

    connections = []

    seen_streams = set()

    for row in rows:
        stream = row["tcp.stream"]

        if not stream or stream in seen_streams:
            continue

        seen_streams.add(stream)

        connections.append({
            "frame": row["frame.number"],
            "timestamp": format_time(
                row["frame.time_epoch"]
            ),
            "epoch": float(
                row["frame.time_epoch"]
            ),
            "source_ip": row["ip.src"],
            "destination_ip": row["ip.dst"],
            "source_port": row["tcp.srcport"],
            "destination_port": row["tcp.dstport"],
            "tcp_stream": stream,
        })

    return connections


def correlate_events(http, connections):
    findings = []

    downloads = [
        event for event in http
        if event["executable_indicator"]
    ]

    responses_by_request = {}

    for event in http:
        if (
            event["type"] == "response"
            and event["request_frame"]
        ):
            responses_by_request.setdefault(
                event["request_frame"], []
            ).append(event)

    for download in downloads:
        responses = responses_by_request.get(
            download["frame"], []
        )

        successful_responses = [
            response for response in responses
            if response["response_code"] == "200"
        ]

        if successful_responses:
            response = successful_responses[0]
            reference_time = response["epoch"]
            download_status = "HTTP 200 observed"
        else:
            response = None
            reference_time = download["epoch"]
            download_status = (
                "Successful response not confirmed"
            )

        subsequent = []

        for connection in connections:
            delta = (
                connection["epoch"] - reference_time
            )

            if not 0 < delta <= 60:
                continue

            if (
                connection["source_ip"]
                != download["source_ip"]
            ):
                continue

            if (
                connection["destination_ip"]
                == download["destination_ip"]
            ):
                continue

            subsequent.append({
                "frame": connection["frame"],
                "timestamp": connection["timestamp"],
                "destination_ip": connection[
                    "destination_ip"
                ],
                "destination_port": connection[
                    "destination_port"
                ],
                "tcp_stream": connection[
                    "tcp_stream"
                ],
                "seconds_after": round(delta, 3),
            })

        subsequent.sort(
            key=lambda item: item["seconds_after"]
        )

        findings.append({
            "finding": "Executable download indicator",
            "classification": "Requires investigation",
            "request_frame": download["frame"],
            "request_time": download["timestamp"],
            "source_ip": download["source_ip"],
            "destination_ip": download[
                "destination_ip"
            ],
            "requested_file": download["uri"],
            "http_status": download_status,
            "response_frame": (
                response["frame"] if response else None
            ),
            "declared_content_length": (
                response["content_length"]
                if response else None
            ),
            "subsequent_connections": subsequent,
            "note": (
                "Temporal correlation only. "
                "This does not establish malware "
                "execution, C2, or exfiltration."
            ),
        })

    return findings


def generate_summary(dns, http, tls, connections):
    executables = [
        event for event in http
        if event["executable_indicator"]
    ]

    domains = Counter(
        item["domain"] for item in dns
    )

    return {
        "dns_queries": len(dns),
        "unique_dns_names": len(domains),
        "http_events": len(http),
        "http_requests": sum(
            event["type"] == "request"
            for event in http
        ),
        "tls_sni_records": len(tls),
        "tcp_connections_observed": len(connections),
        "executable_requests": len(executables),
        "top_dns_names": domains.most_common(10),
    }

def analyze_external_pcap(pcap_path):
    """
    Analyze an external PCAP and return
    structured forensic results.
    """
    pcap = Path(pcap_path).resolve()

    if not pcap.is_file():
        raise FileNotFoundError(
            f"PCAP file not found: {pcap}"
        )

    dns = extract_dns(pcap)
    http = extract_http(pcap)
    tls = extract_tls(pcap)
    connections = extract_tcp_connections(pcap)

    findings = correlate_events(
        http, connections
    )

    summary = generate_summary(
        dns, http, tls, connections
    )

    return {
        "evidence_file": pcap.name,
        "sha256": calculate_sha256(pcap),
        "summary": summary,
        "dns_queries": dns,
        "http_events": http,
        "tls_server_names": tls,
        "tcp_connections": connections,
        "findings": findings,
    }


def main():
    parser = argparse.ArgumentParser(
        description="External PCAP forensic analyzer"
    )

    parser.add_argument(
        "pcap",
        nargs="?",
        type=Path,
        default=DEFAULT_PCAP,
        help="PCAP or PCAPNG file to analyze"
    )

    args = parser.parse_args()
    pcap = args.pcap.expanduser().resolve()

    if not pcap.is_file():
        print(f"PCAP not found: {pcap}")
        return

    if pcap.suffix.lower() not in (
        ".pcap", ".pcapng"
    ):
        print("Unsupported capture format.")
        return

    print("\n=== EXTERNAL PCAP FORENSIC ANALYSIS ===")

    try:
        print("[1/5] Extracting DNS...")
        dns = extract_dns(pcap)

        print("[2/5] Extracting HTTP...")
        http = extract_http(pcap)

        print("[3/5] Extracting TLS metadata...")
        tls = extract_tls(pcap)

        print("[4/5] Extracting TCP connections...")
        connections = extract_tcp_connections(pcap)

        print("[5/5] Correlating events...")
        findings = correlate_events(
            http, connections
        )

    except (
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired
    ) as error:
        print(f"TShark analysis failed: {error}")
        return

    summary = generate_summary(
        dns, http, tls, connections
    )

    report = {
        "evidence_file": pcap.name,
        "sha256": calculate_sha256(pcap),
        "summary": summary,
        "dns_queries": dns,
        "http_events": http,
        "tls_server_names": tls,
        "tcp_connections": connections,
        "findings": findings,
    }

    OUTPUT.parent.mkdir(
        parents=True, exist_ok=True
    )

    OUTPUT.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8"
    )

    print("\n--- ANALYSIS SUMMARY ---")

    for key, value in summary.items():
        if key != "top_dns_names":
            print(
                f"{key.replace('_', ' ').title()}: "
                f"{value}"
            )

    print("\n--- EXECUTABLE INDICATORS ---")

    for finding in findings:
        print(
            f"\nRequest frame: "
            f"{finding['request_frame']}"
        )
        print(
            f"File: {finding['requested_file']}"
        )
        print(
            f"Response: {finding['http_status']}"
        )
        print(
            "Subsequent TCP connections "
            f"(within 60s): "
            f"{len(finding['subsequent_connections'])}"
        )

        for connection in (
            finding["subsequent_connections"][:10]
        ):
            print(
                f"  Frame {connection['frame']} | "
                f"{connection['destination_ip']}:"
                f"{connection['destination_port']} | "
                f"Stream {connection['tcp_stream']} | "
                f"+{connection['seconds_after']}s"
            )

    print(f"\nReport saved: {OUTPUT}")
    print("\nAnalysis completed successfully.")


if __name__ == "__main__":
    main()
