
from collections import Counter


def analyze_logs(entries):
    """Analyze parsed log entries and return statistics."""

    level_counts = Counter()
    error_counts = Counter()

    for entry in entries:
        level = entry["level"]
        message = entry["message"]

        level_counts[level] += 1

        if level == "ERROR":
            error_counts[message] += 1

    return {
        "total_entries": len(entries),
        "level_counts": dict(level_counts),
        "error_counts": dict(error_counts)
    }
