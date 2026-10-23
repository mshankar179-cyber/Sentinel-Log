from collections import defaultdict
from datetime import timedelta

try:
    from .severity import calculate_severity
    from .mitre import get_mitre_mapping
except ImportError:
    from severity import calculate_severity
    from mitre import get_mitre_mapping


def detect_ssh_bruteforce(events, threshold=4, window_minutes=5):
    failed_attempts = defaultdict(list)

    # Collect failed SSH attempts by source IP
    for event in events:
        if (
            event["service"] == "ssh"
            and event["event_type"] == "authentication_failure"
            and event["source_ip"]
            and event["timestamp"]
        ):
            failed_attempts[event["source_ip"]].append(event)

    alerts = []

    time_window = timedelta(minutes=window_minutes)

    # Analyze each source IP
    for ip, attempts in failed_attempts.items():

        # Sort events by timestamp
        attempts.sort(key=lambda event: event["timestamp"])

        for i in range(len(attempts)):

            window_start = attempts[i]["timestamp"]
            window_end = window_start + time_window

            window_events = [
                event
                for event in attempts[i:]
                if event["timestamp"] <= window_end
            ]

            if len(window_events) >= threshold:

                alerts.append({
                    "alert_type": "SSH_BRUTE_FORCE",
                    "severity": calculate_severity(
                       "SSH_BRUTE_FORCE",
                       len(window_events)
                     ),
                    "source_ip": ip,
                    "failed_attempts": len(window_events),
                    "window_minutes": window_minutes,
                    "first_seen": window_events[0]["timestamp"].isoformat(),
                    "last_seen": window_events[-1]["timestamp"].isoformat(),
                    "mitre_attack": get_mitre_mapping("SSH_BRUTE_FORCE"),
                    "description": (
                        f"Possible SSH brute-force activity detected from "
                        f"{ip}: {len(window_events)} failed attempts "
                        f"within {window_minutes} minutes"
                    )
                })

                break

    return alerts
def detect_failure_then_success(events, threshold=4, window_minutes=5):
    suspicious = {}

    # Group SSH events by source IP
    events_by_ip = defaultdict(list)

    for event in events:
        if (
            event["service"] == "ssh"
            and event["source_ip"]
            and event["timestamp"]
        ):
            events_by_ip[event["source_ip"]].append(event)

    time_window = timedelta(minutes=window_minutes)

    for ip, ip_events in events_by_ip.items():
        ip_events.sort(key=lambda event: event["timestamp"])

        for i, event in enumerate(ip_events):
            if event["event_type"] != "authentication_success":
                continue

            success_time = event["timestamp"]

            # Find failures before this successful login
            previous_events = [
                previous
                for previous in ip_events[:i]
                if (
                    previous["event_type"] == "authentication_failure"
                    and previous["timestamp"] >= success_time - time_window
                )
            ]

            if len(previous_events) >= threshold:
                suspicious[ip] = {
                    "alert_type": "SSH_FAILURES_THEN_SUCCESS",
                    "severity": calculate_severity(
                       "SSH_FAILURES_THEN_SUCCESS",
                        len(previous_events)
                     ),
                    "source_ip": ip,
                    "failed_attempts": len(previous_events),
                    "successful_username": event["username"],
                    "window_minutes": window_minutes,
                    "first_failure": previous_events[0]["timestamp"].isoformat(),
                    "success_time": success_time.isoformat(),
                    "mitre_attack": get_mitre_mapping(
                      "SSH_FAILURES_THEN_SUCCESS"
                       ),
                    "description": (
                    f"Successful SSH login from {ip} occurred after "
                    f"{len(previous_events)} failed attempts "
                    f"within {window_minutes} minutes"
                  )
                }
                break

    return list(suspicious.values())
def detect_account_creation(events):
    """
    Detect Linux account creation events.
    """

    alerts = []

    for event in events:
        if event.get("event_type") == "account_created":
            alerts.append({
                "alert_type": "ACCOUNT_CREATED",
                "severity": "MEDIUM",
                "username": event.get("username"),
                "timestamp": (
                    event["timestamp"].isoformat()
                    if event.get("timestamp")
                    else None
                ),
                "description": (
                    f"Linux account creation detected for user "
                    f"{event.get('username')}"
                ),
                "mitre_attack": {
                    "id": "T1136.001",
                    "name": "Create Account: Local Account",
                    "tactic": "Persistence"
                }
            })

    return alerts
def detect_account_deletion(events):
    """
    Detect Linux account deletion events.
    """

    alerts = []

    for event in events:
        if event.get("event_type") == "account_deleted":
            alerts.append({
                "alert_type": "ACCOUNT_DELETED",
                "severity": "MEDIUM",
                "username": event.get("username"),
                "timestamp": (
                    event["timestamp"].isoformat()
                    if event.get("timestamp")
                    else None
                ),
                "description": (
                    f"Linux account deletion detected for user "
                    f"{event.get('username')}"
                ),
                "mitre_attack": {
                    "id": "T1531",
                    "name": "Account Access Removal",
                    "tactic": "Impact"
                }
            })

    return alerts
def detect_multi_account_failures(events, threshold=3, window_minutes=5):
    """
    Detect SSH authentication failures against multiple usernames
    from the same source IP within a time window.
    """

    from collections import defaultdict
    from datetime import timedelta

    failures_by_ip = defaultdict(list)
    alerts = []

    for event in events:
        if (
            event.get("event_type") == "authentication_failure"
            and event.get("source_ip")
            and event.get("username")
            and event.get("timestamp")
        ):
            failures_by_ip[event["source_ip"]].append(event)

    for source_ip, failures in failures_by_ip.items():
        failures.sort(key=lambda event: event["timestamp"])

        for start_index, first_event in enumerate(failures):
            window_end = (
                first_event["timestamp"]
                + timedelta(minutes=window_minutes)
            )

            window_events = [
                event
                for event in failures[start_index:]
                if event["timestamp"] <= window_end
            ]

            usernames = sorted({
                event["username"]
                for event in window_events
            })

            if len(usernames) >= threshold:
                alerts.append({
                    "alert_type": "MULTI_ACCOUNT_FAILURES",
                    "severity": "MEDIUM",
                    "source_ip": source_ip,
                    "usernames": usernames,
                    "failed_attempts": len(window_events),
                    "window_minutes": window_minutes,
                    "mitre_attack": {
                        "id": "T1110",
                        "name": "Brute Force",
                        "tactic": "Credential Access"
                    },
                    "description": (
                        f"SSH authentication failures against "
                        f"{len(usernames)} usernames from {source_ip} "
                        f"within {window_minutes} minutes"
                    )
                })

                break

    return alerts

def detect_event_log_cleared(events):
    """
    Detect Windows Event Log clearing events.
    Event ID 104 indicates an event log was cleared.
    """
    alerts = []

    for event in events:
        if (
            event.get("event_type") == "event_log_cleared"
            and event.get("event_id") == 104
        ):
            alerts.append({
                "alert_type": "EVENT_LOG_CLEARED",
                "severity": "HIGH",
                "timestamp": (
                    event["timestamp"].isoformat()
                    if event.get("timestamp")
                    else None
                ),
                "description": (
                    "Windows event log clearing detected "
                    "(Event ID 104)"
                ),
                "mitre_attack": {
                    "id": "T1070.001",
                    "name": "Clear Windows Event Logs",
                    "tactic": "Defense Evasion"
                }
            })

    return alerts

def detect_whoami_execution(events):
    """
    Detect Windows whoami.exe process execution.
    """
    alerts = []

    for event in events:
        if (
            event.get("event_type") == "whoami_execution"
            and event.get("event_id") == 4688
            and event.get("process_name", "").lower() == "whoami.exe"
        ):
            alerts.append({
                "alert_type": "WHOAMI_EXECUTION",
                "severity": "LOW",
                "timestamp": (
                    event["timestamp"].isoformat()
                    if event.get("timestamp")
                    else None
                ),
                "description": (
                    "Execution of whoami.exe detected "
                    "(Windows Event ID 4688)"
                ),
                "mitre_attack": {
                    "id": "T1033",
                    "name": "System Owner/User Discovery",
                    "tactic": "Discovery"
                }
            })

    return alerts

def detect_powershell_execution(events):
    """
    Detect Windows PowerShell process execution.
    Event ID 4688 records process creation.
    """
    alerts = []

    for event in events:
        if (
            event.get("event_type") == "powershell_execution"
            and event.get("event_id") == 4688
            and event.get("process_name", "").lower()
            == "powershell.exe"
        ):
            alerts.append({
                "alert_type": "POWERSHELL_EXECUTION",
                "severity": "MEDIUM",
                "timestamp": (
                    event["timestamp"].isoformat()
                    if event.get("timestamp")
                    else None
                ),
                "description": (
                    "PowerShell process execution detected "
                    "(Windows Event ID 4688)"
                ),
                "mitre_attack": {
                    "id": "T1059.001",
                    "name": "PowerShell",
                    "tactic": "Execution"
                }
            })

    return alerts

def detect_large_data_exfiltration(events):
    alerts = []

    threshold = 25 * 1024 * 1024  # 25 MB

    for event in events:

        if event.get("event_type") != "large_data_transfer":
            continue

        bytes_sent = event.get("bytes_sent", 0)

        if bytes_sent > threshold:

            alerts.append({
                "alert_type": "LARGE_DATA_EXFIL",
                "severity": "HIGH",
                "source_ip": event.get("source_ip"),
                "destination_ip": event.get("destination_ip"),
                "bytes_sent": bytes_sent,
                "description": (
                    f"Outbound transfer exceeded 25 MB threshold "
                    f"({bytes_sent} bytes)"
                ),
                "mitre_attack": {
                    "id": "T1567",
                    "name": "Exfiltration Over Web Service",
                    "tactic": "Exfiltration"
                }
            })

    return alerts

def detect_usb_insertion(events):
    """
    Detect USB insertion events in parsed log records.
    """

    alerts = []

    for event in events:
        if event.get("event_type") == "usb_insertion":

            device_name = event.get(
                "device_name",
                "Unknown USB device"
            )

            alerts.append({
                "alert_type": "USB_INSERTION",
                "severity": "LOW",
                "timestamp": (
                    event["timestamp"].isoformat()
                    if event.get("timestamp")
                    else None
                ),
                "source_ip": event.get("source_ip"),
                "device_name": device_name,
                "description": (
                    f"USB storage device insertion detected: "
                    f"{device_name}"
                ),
                "mitre_attack": {
                    "id": "T1200",
                    "name": "Hardware Additions",
                    "tactic": "Initial Access"
                }
            })

    return alerts
