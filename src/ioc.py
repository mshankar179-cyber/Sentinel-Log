import re


def extract_iocs(events):
    ip_addresses = set()
    usernames = set()
    ports = set()
    domains = set()
    urls = set()
    hashes = set()

    for event in events:

        # Extract structured IP
        if event.get("source_ip"):
            ip_addresses.add(event["source_ip"])

        # Extract username
        if event.get("username"):
            usernames.add(event["username"])

        # Extract port
        if event.get("port"):
            ports.add(event["port"])

        # Analyze raw log line for additional IOCs
        raw = event.get("raw", "")

        # IPv4 addresses
        found_ips = re.findall(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            raw
        )

        for ip in found_ips:
            ip_addresses.add(ip)

        # URLs
        found_urls = re.findall(
            r"https?://[^\s]+",
            raw
        )

        for url in found_urls:
            urls.add(url)

        # Domain names
        found_domains = re.findall(
            r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
            raw
        )

        # Common file extensions that should not be classified as domains
        non_domain_extensions = {
            "exe", "dll", "sys", "bat", "cmd",
            "ps1", "psm1", "vbs", "js", "msi",
            "scr", "cpl", "drv", "ocx", "sh",
            "py", "jar", "log", "txt", "json",
            "xml", "yaml", "yml", "ini", "conf",
            "cfg", "dat", "zip", "rar", "pdf",
            "doc", "docx", "xls", "xlsx", "png",
            "jpg", "jpeg", "gif", "html", "css"
        }

        for domain in found_domains:
            extension = domain.rsplit(".", 1)[-1].lower()

            if extension not in non_domain_extensions:
                domains.add(domain)

        # MD5 / SHA1 / SHA256 hashes
        found_hashes = re.findall(
            r"\b[a-fA-F0-9]{32}\b|"
            r"\b[a-fA-F0-9]{40}\b|"
            r"\b[a-fA-F0-9]{64}\b",
            raw
        )

        for file_hash in found_hashes:
            hashes.add(file_hash)

    return {
        "ip_addresses": sorted(ip_addresses),
        "usernames": sorted(usernames),
        "ports": sorted(ports),
        "domains": sorted(domains),
        "urls": sorted(urls),
        "hashes": sorted(hashes),
    }
