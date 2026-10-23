import json
from pathlib import Path


def save_json_report(alerts, iocs, output_file):
    """
    Save security analysis results as a JSON report.
    """

    report = {
        "summary": {
            "alerts_detected": len(alerts),
            "ioc_count": (
                len(iocs.get("ip_addresses", []))
                + len(iocs.get("usernames", []))
                + len(iocs.get("ports", []))
                + len(iocs.get("domains", []))
                + len(iocs.get("urls", []))
                + len(iocs.get("hashes", []))
            )
        },
        "alerts": alerts,
        "iocs": iocs
    }

    output_path = Path(output_file)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(output_path, "w") as file:
        json.dump(
            report,
            file,
            indent=4,
            default=str
        )


def save_text_report(alerts, iocs, output_file):
    """
    Save security analysis results as a human-readable TXT report.
    """

    output_path = Path(output_file)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(output_path, "w") as file:

        file.write("========================================\n")
        file.write("        SENTINELLOG INCIDENT REPORT\n")
        file.write("========================================\n\n")

        file.write(
            f"Alerts detected: {len(alerts)}\n\n"
        )

        file.write("ALERTS\n")
        file.write("----------------------------------------\n")

        for number, alert in enumerate(alerts, start=1):

            file.write(f"\nAlert #{number}\n")
            file.write(
                f"Type       : {alert.get('alert_type')}\n"
            )
            file.write(
                f"Severity   : {alert.get('severity')}\n"
            )
            file.write(
                f"Source IP  : {alert.get('source_ip')}\n"
            )
            file.write(
                f"Description: {alert.get('description')}\n"
            )

            mitre = alert.get("mitre_attack", {})

            file.write(
                f"MITRE ID   : {mitre.get('id')}\n"
            )
            file.write(
                f"Technique  : {mitre.get('name')}\n"
            )
            file.write(
                f"Tactic     : {mitre.get('tactic')}\n"
            )

        file.write("\n")
        file.write("IOCs\n")
        file.write("----------------------------------------\n")

        file.write(
            f"IP Addresses: {iocs.get('ip_addresses', [])}\n"
        )

        file.write(
            f"Usernames   : {iocs.get('usernames', [])}\n"
        )

        file.write(
            f"Ports       : {iocs.get('ports', [])}\n"
        )

        file.write(
            f"Domains     : {iocs.get('domains', [])}\n"
        )

        file.write(
            f"URLs        : {iocs.get('urls', [])}\n"
        )

        file.write(
            f"Hashes      : {iocs.get('hashes', [])}\n"
        )
