import re
from datetime import datetime


def parse_log_line(line):
    event = {
        "raw": line.strip(),
        "timestamp": None,
        "event_type": "unknown",
        "username": None,
        "source_ip": None,
        "port": None,
        "service": None,
    }

    # Extract timestamp
    timestamp_match = re.search(
        r"^([A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2})",
        line
    )

    if timestamp_match:
        timestamp_text = timestamp_match.group(1)

        current_year = datetime.now().year

        event["timestamp"] = datetime.strptime(
            f"{current_year} {timestamp_text}",
            "%Y %b %d %H:%M:%S"
        )

    # Detect SSH service
    if "sshd" in line:
        event["service"] = "ssh"

    # Detect failed SSH login
    failed_match = re.search(
        r"Failed password for (\S+) from ([0-9.]+) port (\d+)",
        line
    )

    if failed_match:
        event["event_type"] = "authentication_failure"
        event["username"] = failed_match.group(1)
        event["source_ip"] = failed_match.group(2)
        event["port"] = int(failed_match.group(3))
        return event

    # Detect successful SSH login
    success_match = re.search(
        r"Accepted password for (\S+) from ([0-9.]+) port (\d+)",
        line
    )

    if success_match:
        event["event_type"] = "authentication_success"
        event["username"] = success_match.group(1)
        event["source_ip"] = success_match.group(2)
        event["port"] = int(success_match.group(3))
        return event

    account_match = re.search(
        r"useradd.*new user: name=(\S+),",
        line
    )

    if account_match:
        event["event_type"] = "account_created"
        event["username"] = account_match.group(1)
        event["service"] = "user_management"
        return event


    deletion_match = re.search(
        r"userdel.*delete user ['\"]([^'\"]+)['\"]",
        line
    )

    if deletion_match:
        event["event_type"] = "account_deleted"
        event["username"] = deletion_match.group(1)
        event["service"] = "user_management"
        return event

    # Detect Windows Event Log cleared (Event ID 104)
    if re.search(r"Event ID 104\b", line):
        event["event_type"] = "event_log_cleared"
        event["service"] = "windows_eventlog"
        event["event_id"] = 104
        return event

    # Detect Windows whoami execution (Event ID 4688)
    if (
        re.search(r"Event ID 4688\b", line)
        and re.search(r"\bwhoami\.exe\b", line, re.IGNORECASE)
    ):
        event["event_type"] = "whoami_execution"
        event["service"] = "windows_process"
        event["event_id"] = 4688
        event["process_name"] = "whoami.exe"
        return event

    # Detect Windows PowerShell execution (Event ID 4688)
    if (
        re.search(r"Event ID 4688\b", line)
        and re.search(r"\bpowershell\.exe\b", line, re.IGNORECASE)
    ):
        event["event_type"] = "powershell_execution"
        event["service"] = "windows_process"
        event["event_id"] = 4688
        event["process_name"] = "powershell.exe"
        return event

        # Detect large outbound network transfer
    transfer_match = re.search(
        r"src_ip=([0-9.]+)\s+dest_ip=([0-9.]+)\s+bytes_sent=(\d+)",
        line
    )

    if transfer_match:
        event["event_type"] = "large_data_transfer"
        event["source_ip"] = transfer_match.group(1)
        event["destination_ip"] = transfer_match.group(2)
        event["bytes_sent"] = int(transfer_match.group(3))
        event["service"] = "network"
        return event

        # Detect USB device insertion
    if re.search(r"\bUSB_INSERTION\b", line, re.IGNORECASE):
        event["event_type"] = "usb_insertion"
        event["service"] = "windows_device"

        device_match = re.search(
            r"\bDevice=([^\s]+)",
            line,
            re.IGNORECASE
        )

        if device_match:
            event["device_name"] = device_match.group(1)

        event["device_type"] = "USB"
        return event

    return event
