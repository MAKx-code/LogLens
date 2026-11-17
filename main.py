
import argparse

from loglens.reader import read_log_file
from loglens.parser import parse_log_line
from loglens.analyzer import analyze_logs
from loglens.security import (
    extract_ip_addresses,
    detect_failed_logins
)
from loglens.reporter import export_csv, export_json


def run_loglens(input_file, threshold):
    """Run the complete LogLens analysis workflow."""

    lines = read_log_file(input_file)

    entries = []
    invalid_lines = []

    for line in lines:
        parsed = parse_log_line(line)

        if parsed is not None:
            entries.append(parsed)
        else:
            invalid_lines.append(line.strip())

    results = analyze_logs(entries)
    ip_counts = extract_ip_addresses(entries)
    suspicious_ips = detect_failed_logins(
        entries, threshold=threshold
    )

    report = {
        "total_lines": len(lines),
        "valid_entries": len(entries),
        "invalid_entries": len(invalid_lines),
        "log_levels": results["level_counts"],
        "error_counts": results["error_counts"],
        "ip_addresses": ip_counts,
        "suspicious_ips": suspicious_ips
    }

    print("\n========== LOGLENS REPORT ==========")

    print(f"Total lines: {len(lines)}")
    print(f"Valid entries: {len(entries)}")
    print(f"Invalid entries: {len(invalid_lines)}")

    if invalid_lines:
        print("\nInvalid log entries:")

        for line in invalid_lines:
            print(f"- {line}")

    print("\nLog level statistics:")

    for level, count in results["level_counts"].items():
        print(f"{level}: {count}")

    print("\nError statistics:")

    for message, count in results["error_counts"].items():
        print(f"{message}: {count}")

    print("\nIP address statistics:")

    for ip, count in ip_counts.items():
        print(f"{ip}: {count}")

    print("\nFailed login detection:")

    if suspicious_ips:
        for ip, count in suspicious_ips.items():
            print(f"{ip}: {count} failed attempts")
    else:
        print("No IP addresses reached the threshold.")

    export_csv(entries, "reports/log_report.csv")
    export_json(report, "reports/log_report.json")

    print("\nReports generated:")
    print("- reports/log_report.csv")
    print("- reports/log_report.json")

    print("====================================")


def main():
    parser = argparse.ArgumentParser(
        description="LogLens - Python Log Analyzer"
    )

    parser.add_argument(
        "--input",
        default="logs/sample.log",
        help="Path to the log file"
    )

    parser.add_argument(
        "--threshold",
        type=int,
        default=3,
        help="Failed login detection threshold"
    )

    args = parser.parse_args()

    if args.threshold < 1:
        parser.error("Threshold must be at least 1.")

    try:
        run_loglens(args.input, args.threshold)
    except (FileNotFoundError, ValueError, OSError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
