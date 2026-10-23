import argparse

from parser import parse_log_line
from detector import (
    detect_ssh_bruteforce,
    detect_failure_then_success,
    detect_account_creation,
    detect_account_deletion,
    detect_multi_account_failures,
    detect_event_log_cleared,
    detect_whoami_execution,
    detect_powershell_execution,
    detect_large_data_exfiltration,
    detect_usb_insertion
)
from ioc import extract_iocs
from reporter import (
    save_json_report,
    save_text_report
)
from rule_loader import load_rules

VERSION = "1.0.0"


def load_log_file(log_file):
    """
    Read a log file and convert each line into a normalized event.
    """

    events = []

    with open(log_file, "r") as file:
        for line in file:
            if line.strip():
                events.append(parse_log_line(line))

    return events


def analyze_log(log_file):
    """
    Run the complete SentinelLog analysis pipeline.
    """

    print("\n========================================")
    print("           SENTINELLOG")
    print("       Security Log Analyzer")
    print("========================================\n")

    print(f"[+] Analyzing: {log_file}")

    # Parse log
    events = load_log_file(log_file)

    print(f"[+] Events parsed: {len(events)}")

    # Detect threats
    alerts = []

    alerts.extend(
        detect_ssh_bruteforce(events)
    )

    alerts.extend(
        detect_failure_then_success(events)
    )
    alerts.extend(detect_account_creation(events))
    alerts.extend(detect_account_deletion(events))
    alerts.extend(detect_multi_account_failures(events))
    alerts.extend(detect_event_log_cleared(events))
    alerts.extend(detect_whoami_execution(events))
    alerts.extend(detect_powershell_execution(events))
    alerts.extend(detect_large_data_exfiltration(events))
    alerts.extend(detect_usb_insertion(events))
    print(f"[+] Alerts detected: {len(alerts)}")

    # Extract IOCs
    iocs = extract_iocs(events)

    print(
        f"[+] IP addresses: "
        f"{len(iocs['ip_addresses'])}"
    )

    print(
        f"[+] Usernames: "
        f"{len(iocs['usernames'])}"
    )

    print(
        f"[+] Ports: "
        f"{len(iocs['ports'])}"
    )

    # Generate reports
    save_json_report(
        alerts,
        iocs,
        "reports/incident_report.json"
    )

    save_text_report(
        alerts,
        iocs,
        "reports/incident_report.txt"
    )

    print("\n[+] Analysis complete.")

    print(
        "[+] JSON report: "
        "reports/incident_report.json"
    )

    print(
        "[+] TXT report : "
        "reports/incident_report.txt"
    )


def show_version():
    print(f"SentinelLog version {VERSION}")


def show_rules():
    rules = load_rules("rules/authentication.yaml")

    print("\nAvailable Detection Rules")
    print("-------------------------")

    for number, rule in enumerate(rules, start=1):
        print(f"{number}. {rule['id']}")
        print(f"   Category : {rule.get('category', 'N/A')}")
        print(f"   Protocol : {rule.get('protocol', 'N/A')}")
        print(f"   Enabled  : {rule.get('enabled', False)}")
        print(f"   Description: {rule.get('description', 'N/A')}")
        print()


def main():

    parser = argparse.ArgumentParser(
        description="SentinelLog - Offline Security Log Analyzer"
    )

    subparsers = parser.add_subparsers(
        dest="command"
    )

    # Version command
    subparsers.add_parser(
        "version",
        help="Show SentinelLog version"
    )

    # Rules command
    subparsers.add_parser(
        "rules",
        help="Show available detection rules"
    )

    # Analyze command
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze a security log file"
    )

    analyze_parser.add_argument(
        "logfile",
        help="Path to the log file"
    )

    args = parser.parse_args()

    if args.command == "analyze":
        analyze_log(args.logfile)

    elif args.command == "version":
        show_version()

    elif args.command == "rules":
        show_rules()

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
