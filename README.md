# Network Log Forensics and Incident Reconstruction Using Zeek Evidence

**Advanced Digital Forensics — Final Project**

## Project Overview

This project demonstrates a digital forensic investigation using publicly available Zeek network connection logs. It focuses on evidence acquisition, integrity verification, suspicious activity examination, incident timeline reconstruction, and forensic reporting.

Unlike a conventional network security application, the primary objective is to investigate recorded evidence and document findings that can be independently verified.

## Objectives

1. Acquire existing network forensic evidence from a documented public source.
2. Verify evidence integrity using SHA-256 hashing.
3. Examine network connections, protocols, IP addresses, ports, and connection states.
4. Identify and investigate suspicious communication patterns.
5. Reconstruct a chronological incident timeline.
6. Produce an evidence-backed forensic case report.

## Evidence Source

**Dataset:** CTU-Malware-Capture-Botnet-230-1  
**Scenario:** NjRAT malware-related network traffic  
**Provider:** Stratosphere Laboratory  
**Evidence:** `labeled-conn.log`

The evidence is a 1,000-line excerpt distributed through the Stratosphere IPS `security-datasets-for-testing` GitHub repository.

Source: https://github.com/stratosphereips/security-datasets-for-testing/tree/main/001-zeek-scenario-malicious

The current evidence does not establish that the investigated host is an IoT device. The case is therefore presented as network log forensics, not a verified IoT-device compromise.

## Forensic Methodology

**Acquisition → Preservation → Examination → Analysis → Reconstruction → Reporting**

The original log is preserved, and its SHA-256 hash is verified against the published Git LFS object hash.

The investigation script parses Zeek connection records, examines published labels, identifies repeated connections, calculates timing intervals, and exports a forensic timeline.

## Evidence Integrity

SHA-256:

`0871016451ce1ebf8713bc0b117079c490615290cbff034b735d096b35722e82`

The downloaded evidence matched the published hash during verification.

## Investigation Findings

| Parameter | Result |
|---|---|
| Parsed connection records | 992 |
| Background-labeled records | 739 |
| Malicious-labeled records | 244 |
| Benign-labeled records | 9 |
| Investigated source | 192.168.1.115 |
| Investigated destination | 41.108.179.197:1177 |
| Matching connection attempts | 237 |
| Connection state | S0 |
| Average interval | 11.566 seconds |
| Minimum interval | 8.985 seconds |
| Maximum interval | 17.002 seconds |

The investigated host repeatedly attempted TCP connections to the same destination.

All 237 matching records have Zeek state `S0`, indicating that no response was observed.

The published dataset labels these records as malicious. The observed timing suggests automated retry behavior, but the evidence does not establish a successful command-and-control session.

## Tools and Technologies

- Fedora Linux
- Python 3
- Zeek connection logs
- SHA-256 hashing
- CSV timeline generation
- Git and GitHub

The repository also retains an earlier PCAP analysis prototype using Flask, Scapy, Wireshark, and TShark. That prototype is supplementary to the primary log-forensic investigation.

## Project Structure

```text
iot/
├── analysis/
│   └── forensic_investigation.py
├── evidence/
│   └── labeled-conn.log
└── reports/
    ├── incident_timeline.csv
    └── forensic_case_report.txt
```

## Running the Investigation

Clone the repository:

```bash
git clone https://github.com/21Deep21/iot-digital-forensics.git
cd iot-digital-forensics
```

Run the forensic investigation:

```bash
python3 iot/analysis/forensic_investigation.py
```

The script verifies evidence integrity before processing the log.

The results are saved in `iot/reports/`.

No additional Python packages are required for this specific investigation script.

## Forensic Interpretation

The investigation identifies repeated unanswered TCP connection attempts associated with a published NjRAT malware-traffic scenario.

The analysis distinguishes the source dataset's malicious labels from observations independently derived from the connection records.

## Limitations

- The evidence is an excerpt rather than a complete capture.
- The source host's IoT-device identity is unverified.
- The numeric timestamps are preserved as recorded.
- The analysis does not establish successful malware execution or C2 communication.
- The published labels are not independently validated.
- The evidence hash verifies file consistency but does not establish a complete chain of custody.

## Conclusion

This project demonstrates a reproducible network log forensic investigation using existing evidence.

The primary contribution is the structured examination of network records, preservation of evidence integrity, reconstruction of suspicious activity, and documentation of findings with traceable evidence references.

**Purpose:** Educational and defensive digital forensic investigation.