# SentinelLog

### Offline Security Log Analyzer & Threat Detection Toolkit

SentinelLog is a Python-based cybersecurity learning project that analyzes security log files, identifies suspicious activity, extracts Indicators of Compromise (IOCs), maps alerts to MITRE ATT&CK, and generates incident reports.

The project is designed to help learners understand security event analysis, detection logic, and basic incident reporting using a lightweight, offline workflow.

> **Project status:** Version 1.0.0 — initial detection and reporting features implemented; further testing and improvements are ongoing.

## Features

* **SSH attack detection:** Detect repeated failed SSH logins and successful logins following multiple failures.
* **Account monitoring:** Identify Linux account creation and deletion events.
* **Multi-account failure detection:** Identify SSH authentication failures targeting multiple usernames from one source IP within a configured time window.
* **Windows event analysis:** Detect simulated event-log clearing and selected process-creation events.
* **Large outbound transfer detection:** Flag recorded outbound transfers exceeding the configured threshold.
* **USB insertion detection:** Identify USB insertion events in the supported sample-log format.
* **IOC extraction:** Extract IP addresses, usernames, ports, domains, URLs, and file hashes.
* **MITRE ATT&CK mapping:** Associate supported detections with relevant ATT&CK techniques.
* **Severity classification:** Assign severity levels to alerts.
* **Incident reporting:** Generate JSON and plain-text reports.
* **YAML rule configuration:** Store detection rule metadata in YAML files.

## Detection Scenarios

SentinelLog currently includes detection logic for these scenarios:

| Detection                   | Purpose                                                         |
| --------------------------- | --------------------------------------------------------------- |
| `SSH_BRUTE_FORCE`           | Identify repeated failed SSH authentication attempts            |
| `SSH_FAILURES_THEN_SUCCESS` | Identify successful SSH login after repeated failures           |
| `ACCOUNT_CREATED`           | Detect Linux account creation                                   |
| `ACCOUNT_DELETED`           | Detect Linux account deletion                                   |
| `MULTI_ACCOUNT_FAILURES`    | Detect failures targeting multiple usernames from one source IP |
| `EVENT_LOG_CLEARED`         | Detect supported event-log clearing records                     |
| `WHOAMI_EXECUTION`          | Detect supported `whoami.exe` process-creation records          |
| `POWERSHELL_EXECUTION`      | Detect supported PowerShell process-creation records            |
| `LARGE_DATA_EXFIL`          | Flag outbound transfers exceeding the configured byte threshold |
| `USB_INSERTION`             | Detect supported USB insertion records                          |

These detections currently operate against the project's supported log formats. Some Windows and network examples are simulated lab records rather than native event exports.

## Technology Stack

* Python 3
* PyYAML
* Regular expressions for log parsing and IOC extraction
* YAML for detection rule metadata
* JSON and plain text for incident reporting
* MITRE ATT&CK for detection context
* Kali Linux development environment

## Project Structure

```text
SentinelLog/
├── docs/
├── reports/
├── rules/
│   ├── authentication.yaml
│   └── ssh.yaml
├── sample_logs/
├── screenshots/
├── src/
│   ├── cli.py
│   ├── detector.py
│   ├── ioc.py
│   ├── mitre.py
│   ├── parser.py
│   ├── reporter.py
│   ├── rule_loader.py
│   └── severity.py
├── tests/
├── .gitignore
├── README.md
└── requirements.txt
```

## Installation

### Requirements

* Python 3
* pip
* A Linux terminal or another environment that supports Python 3

### 1. Clone the repository

After the project is published on GitHub:

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd SentinelLog
```

Replace `<YOUR_GITHUB_REPOSITORY_URL>` with your repository's actual URL.

### 2. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
python -m pip install -r requirements.txt
```

## Usage

Run these commands from the project's root directory.

### Display version

```bash
python src/cli.py version
```

### List detection rules

```bash
python src/cli.py rules
```

### Analyze a security log

```bash
python src/cli.py analyze sample_logs/auth_sample.log
```

### Analyze Windows event-log sample

```bash
python src/cli.py analyze sample_logs/windows_log_cleared.log
```

### Analyze a simulated large outbound transfer

```bash
python src/cli.py analyze sample_logs/large_data_transfer.log
```

### Analyze a USB insertion sample

```bash
python src/cli.py analyze sample_logs/usb_insertion.log
```

## Incident Reports

After analysis, SentinelLog generates:

```text
reports/incident_report.json
reports/incident_report.txt
```

The reports provide details about detected alerts, including available timestamps, source IP addresses, descriptions, severity levels, and MITRE ATT&CK mappings.

The IOC summary includes extracted IP addresses, usernames, ports, domains, URLs, and hashes.

Generated report files are excluded from Git by the current `.gitignore` configuration.

## Running the Existing Test Scripts

The project includes Python scripts for checking detection logic, parsing, IOC extraction, MITRE mappings, reporting, rule loading, and severity calculations.

Run the available scripts from the project root:

```bash
for test in src/test_*.py; do
    printf '\n===== Running %s =====\n' "$test"
    python "$test" || exit 1
done
```

These scripts provide useful development checks. Additional automated assertions and regression tests are planned to improve test coverage.

## Example Detection

A simulated SSH log containing four failed login attempts followed by a successful login can produce:

```text
Alert #1
Type       : SSH_BRUTE_FORCE
Severity   : MEDIUM
Source IP  : 192.168.56.10
MITRE ID   : T1110
Technique  : Brute Force
Tactic     : Credential Access
```

A separate high-severity alert may identify the successful login following repeated failures.

The generated alert depends on the input records and the configured detection thresholds.

## Limitations

* SentinelLog analyzes supplied log files; it does not currently provide live log collection or continuous monitoring.
* Windows process and event-log samples currently use simplified, simulated records. Native Windows Event Log formats and EVTX ingestion require additional work.
* The large-transfer rule identifies recorded transfers above a threshold; a large transfer does not, by itself, prove data exfiltration.
* Security alerts are indicators for investigation, not automatic proof of malicious activity.
* Detection coverage and IOC extraction are limited to the formats and patterns currently implemented.
* The YAML files describe detection rules, while the corresponding detection logic is implemented in Python.

## Future Improvements

* Add automated unit tests and regression tests.
* Improve support for native Windows security event exports.
* Expand log parsing and validation.
* Improve IOC classification and false-positive handling.
* Add configurable detection thresholds.
* Improve report detail and documentation.
* Add more Linux, Windows, and network security detections.

## Disclaimer

SentinelLog is an educational cybersecurity project intended for authorized defensive security analysis, learning, and testing.

Test with log files you own or have permission to analyze. Alerts require appropriate context and should be validated before making incident-response decisions.

## Author

**Shankar M**
Cybersecurity Learner

This project demonstrates practical learning in Python, log parsing, threat detection, IOC extraction, MITRE ATT&CK mapping, and incident reporting.
