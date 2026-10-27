# Network Traffic Forensics: Phishing-to-Compromise Reconstruction

**Advanced Digital Forensics — Academic Project**

**Group:** L1ARS

## 1. Project Overview

This project demonstrates how network traffic evidence can be used to reconstruct a simulated phishing-to-compromise incident.

It combines a controlled phishing simulation with PCAP analysis to identify network events, reconstruct chronological timelines, investigate suspicious connections, and generate forensic reports.

The project also supports analysis of external PCAP files for broader network forensic investigation.

## 2. Objectives

- Simulate a phishing interaction in a controlled local environment.
- Capture network traffic using Wireshark.
- Analyze PCAP and PCAPNG evidence.
- Extract DNS, HTTP, TCP, and TLS metadata.
- Identify executable-download indicators.
- Examine simulated C2 beaconing behavior.
- Correlate network events chronologically.
- Generate forensic reports and SHA-256 evidence hashes.

## 3. Technologies Used

| Technology | Purpose |
|---|---|
| Python 3 | Core implementation |
| Flask | Web interface and simulation server |
| Scapy | Packet analysis |
| Wireshark | Packet capture and inspection |
| TShark | Protocol extraction and forensic analysis |
| Requests | Simulated HTTP requests |
| HTML/CSS | Dashboard interface |
| Fedora Linux | Development and execution environment |

## 4. Project Architecture

```text
Network Traffic Forensics
         |
         +-- Controlled Simulation
         |       |
         |       +-- Phishing interaction
         |       +-- Dummy payload retrieval
         |       +-- Simulated C2 beaconing
         |       +-- Wireshark packet capture
         |
         +-- Forensic Analysis
         |       |
         |       +-- Simulation PCAP analysis
         |       +-- External PCAP analysis
         |       +-- DNS, HTTP, TCP, TLS extraction
         |       +-- Event correlation
         |
         +-- Flask Dashboard
                 |
                 +-- Upload evidence
                 +-- View forensic findings
                 +-- Download reports
```

## 5. Features

### Controlled Simulation

A local Flask server simulates a phishing interaction, dummy payload retrieval, and periodic HTTP requests representing C2 communication.

All activity is harmless and runs on localhost.

### Network Traffic Capture

Wireshark/TShark captures the simulated network traffic and saves it in PCAPNG format.

### Simulation Analysis

The analyzer identifies predefined simulation endpoints and reconstructs their chronological sequence.

### External PCAP Analysis

The external analyzer extracts:

- DNS queries and queried domains
- HTTP requests and responses
- TLS Server Name Indication (SNI) metadata
- TCP connection initiation events
- Executable-download indicators
- Connections occurring shortly after suspicious downloads

### Evidence Integrity

SHA-256 hashes are calculated for uploaded captures.

Uploaded evidence is saved using unique filenames to prevent accidental overwriting.

### Forensic Reporting

Each investigation receives a unique identifier and its own reports.

## 6. Installation

### Requirements

- Fedora Linux or another compatible Linux distribution
- Python 3
- Wireshark and TShark

Install Wireshark on Fedora:

```bash
sudo dnf install wireshark wireshark-cli
```

Create a Python virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install Python dependencies:

```bash
python -m pip install -r requirements.txt
```

## 7. Running the Project

### Start the forensic dashboard

```bash
python app.py
```

Open:

`http://127.0.0.1:8000`

### Run the controlled simulation

In another terminal:

```bash
python simulation/phishing_server.py
```

In a separate terminal:

```bash
python simulation/attack_simulator.py
```

The simulator generates HTTP traffic representing the predefined attack sequence.

### Capture network traffic

On Fedora, capture loopback traffic using Wireshark or TShark.

Ensure packet capture permissions and output-directory permissions are configured appropriately.

### Analyze a capture

Open the dashboard and upload a PCAP or PCAPNG file.

Use the Simulation Analysis page for the controlled lab capture and External PCAP Analysis for general traffic investigation.

## 8. Experimental Results

### Controlled Simulation

| Metric | Result |
|---|---|
| Captured packets | 84 |
| Reconstructed events | 7 |
| Simulated C2 requests | 5 |
| Average beacon interval | 3.005 seconds |

### External Traffic Analysis

| Metric | Result |
|---|---|
| Captured packets | 42,497 |
| DNS queries | 170 |
| Unique DNS names | 71 |
| HTTP events | 32 |
| TLS SNI records | 92 |
| TCP connections observed | 184 |
| Executable-download indicators | 1 |

The external capture included an HTTP request for `runner_ilove.exe` and an HTTP 200 response.

Subsequent TCP connections were identified through temporal correlation. Their malicious nature has not been independently established.

## 9. Forensic Methodology

1. Acquire network evidence.
2. Preserve the original capture.
3. Calculate its SHA-256 hash.
4. Extract network protocol metadata.
5. Identify potentially relevant events.
6. Correlate events using timestamps and packet references.
7. Generate an investigation report.
8. Interpret findings while acknowledging evidentiary limitations.

## 10. Limitations

- The simulation uses predefined HTTP endpoints.
- The controlled experiment does not execute real malware.
- Malware execution cannot be established using network evidence alone.
- Suspicious connections are not automatically confirmed as C2.
- TLS analysis is limited to visible metadata.
- JA3/JA3S fingerprinting is not implemented.
- The current experiment does not use an isolated virtual machine.
- The application is intended for trusted local academic use, not public deployment.

## 11. Future Scope

- Automated detection of periodic communication patterns.
- More detailed TCP flow analysis.
- Advanced encrypted-traffic metadata analysis.
- Improved event correlation and classification.
- Optional isolated VM-based laboratory setup.

## 12. Conclusion

The project demonstrates how network traffic can be captured, examined, and correlated to reconstruct a controlled phishing-to-compromise scenario.

It also supports broader forensic investigation through analysis of external PCAP evidence.

The primary focus is evidence-based network investigation, chronological reconstruction, and reproducible forensic reporting.

---

**Disclaimer:** This project is developed strictly for educational and defensive digital forensics purposes.