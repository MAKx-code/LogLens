
import re
from collections import Counter


IP_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)


def extract_ip_addresses(entries):
    """Extract IP address candidates from log messages."""

    ip_counts = Counter()

    for entry in entries:
        message = entry["message"]

        matches = IP_PATTERN.findall(message)

        for ip in matches:
            octets = ip.split(".")

            if all(0 <= int(octet) <= 255 for octet in octets):
                ip_counts[ip] += 1

    return dict(ip_counts)


def detect_failed_logins(entries, threshold=3):
    """Detect IP addresses with repeated failed login attempts."""

    failed_attempts = Counter()

    for entry in entries:
        message = entry["message"]
        level = entry["level"]

        if level == "WARNING" and "Failed login" in message:
            matches = IP_PATTERN.findall(message)

            for ip in matches:
                octets = ip.split(".")

                if all(0 <= int(octet) <= 255 for octet in octets):
                    failed_attempts[ip] += 1

    suspicious_ips = {
        ip: count
        for ip, count in failed_attempts.items()
        if count >= threshold
    }

    return suspicious_ips
