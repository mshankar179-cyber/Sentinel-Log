from parser import parse_log_line
from detector import (
    detect_ssh_bruteforce,
    detect_failure_then_success
)


events = []

with open("sample_logs/auth_sample.log", "r") as file:
    for line in file:
        events.append(parse_log_line(line))


print("\n=== SSH BRUTE-FORCE DETECTION ===")

bruteforce_alerts = detect_ssh_bruteforce(events)

for alert in bruteforce_alerts:
    print(alert)


print("\n=== FAILED LOGINS FOLLOWED BY SUCCESS ===")

sequence_alerts = detect_failure_then_success(events)

for alert in sequence_alerts:
    print(alert)
