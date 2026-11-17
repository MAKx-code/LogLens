
import unittest
import tempfile
import json
import csv

from pathlib import Path

from loglens.reader import read_log_file
from loglens.parser import parse_log_line
from loglens.analyzer import analyze_logs
from loglens.security import (
    extract_ip_addresses,
    detect_failed_logins
)
from loglens.reporter import export_csv, export_json


class TestLogLens(unittest.TestCase):

    def test_reader(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "test.log"
            file_path.write_text(
                "First entry\nSecond entry\n",
                encoding="utf-8"
            )

            lines = read_log_file(file_path)

            self.assertEqual(len(lines), 2)

    def test_reader_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            read_log_file("missing_file.log")

    def test_parser_valid_entry(self):
        line = (
            "2026-11-18 09:10:12 "
            "ERROR Database connection failed"
        )

        result = parse_log_line(line)

        self.assertEqual(result["level"], "ERROR")
        self.assertEqual(
            result["message"],
            "Database connection failed"
        )

    def test_parser_invalid_entry(self):
        result = parse_log_line("INVALID LOG ENTRY")

        self.assertIsNone(result)

    def test_parser_multiple_spaces(self):
        line = (
             "2026-11-18   09:10:12    ERROR   "
            "Database connection failed"
        )
        result = parse_log_line(line)

        self.assertIsNotNone(result)
        self.assertEqual(result["level"], "ERROR")
        self.assertEqual(
            result["message"],
            "Database connection failed"
        )

    def test_analyzer(self):
        entries = [
            {"level": "INFO", "message": "User logged in"},
            {"level": "ERROR", "message": "Database failed"},
            {"level": "ERROR", "message": "Database failed"},
            {"level": "WARNING", "message": "High memory usage"}
        ]

        result = analyze_logs(entries)

        self.assertEqual(result["total_entries"], 4)
        self.assertEqual(result["level_counts"]["ERROR"], 2)
        self.assertEqual(result["error_counts"]["Database failed"], 2)

    def test_ip_extraction(self):
        entries = [
            {
                "level": "WARNING",
                "message": "Failed login from 192.168.1.10"
            },
            {
                "level": "WARNING",
                "message": "Failed login from 192.168.1.10"
            },
            {
                "level": "WARNING",
                "message": "Failed login from 999.999.1.10"
            }
        ]

        result = extract_ip_addresses(entries)

        self.assertEqual(result, {"192.168.1.10": 2})

    def test_failed_login_detection(self):
        entries = [
            {
                "level": "WARNING",
                "message": "Failed login from 192.168.1.10"
            },
            {
                "level": "WARNING",
                "message": "Failed login from 192.168.1.10"
            },
            {
                "level": "WARNING",
                "message": "Failed login from 192.168.1.10"
            }
        ]

        result = detect_failed_logins(entries, threshold=3)

        self.assertEqual(result, {"192.168.1.10": 3})

    def test_report_generation(self):
        entries = [
            {
                "date": "2026-11-18",
                "time": "09:10:12",
                "level": "INFO",
                "message": "User logged in"
            }
        ]

        report = {"total_entries": 1}

        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "report.csv"
            json_path = Path(temp_dir) / "report.json"

            export_csv(entries, csv_path)
            export_json(report, json_path)

            self.assertTrue(csv_path.exists())
            self.assertTrue(json_path.exists())

            with csv_path.open(encoding="utf-8") as file:
                rows = list(csv.DictReader(file))

            self.assertEqual(len(rows), 1)

            with json_path.open(encoding="utf-8") as file:
                data = json.load(file)

            self.assertEqual(data["total_entries"], 1)


if __name__ == "__main__":
    unittest.main()
