## Unified Forensic Investigation Dashboard

The project provides a Flask-based interface for examining two complementary forms of network forensic evidence.

### Case Study 1 — PCAP Network Forensics

This investigation examines a published network capture containing 42,497 packets.

The forensic examination includes DNS queries, HTTP transactions, TLS metadata, TCP connections, and suspicious executable-download activity.

A notable finding is an HTTP request for `/wilow/runner_ilove.exe`, followed by several network connections requiring further investigation.

The PCAP analysis is accessible at `/external`.

### Case Study 2 — Zeek Network Log Forensics

This investigation examines a published Zeek connection-log excerpt associated with an NjRAT malware-traffic scenario.

The analysis identifies 237 malicious-labeled TCP connection attempts from `192.168.1.115` to `41.108.179.197:1177`.

All matching records have Zeek state `S0`, indicating that no response was observed.

The Zeek investigation is accessible at `/iot`.

### Dashboard Navigation

| Route | Purpose |
|---|---|
| `/` | Main forensic investigation homepage |
| `/external` | PCAP investigation |
| `/iot` | Zeek network-log investigation |
| `/simulation` | Supporting controlled simulation |

### Running the Unified Dashboard

Activate the Python environment and start Flask:

```bash
source .venv/bin/activate
python app.py
```

Open `http://127.0.0.1:8000` in your browser.

The dashboard presents both investigations, their supporting evidence, reconstructed timelines, and downloadable forensic reports.

**Scope:** The dashboard supports evidence examination and presentation. It does not independently confirm malware execution, successful command-and-control communication, or IoT-device compromise.