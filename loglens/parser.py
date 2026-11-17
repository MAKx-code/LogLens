def parse_log_line(line):
    """Extract structured information from a log line."""
    parts = line.strip().split(maxsplit=3)

    if len(parts) != 4:
        return None

    date, time, level, message = parts

    valid_levels = {"INFO", "WARNING", "ERROR"}

    if level not in valid_levels:
        return None

    return {
        "date": date,
        "time": time,
        "level": level,
        "message": message
    }