from parser import parse_log_line


with open("sample_logs/auth_sample.log", "r") as file:
    for line in file:
        event = parse_log_line(line)
        print(event)
