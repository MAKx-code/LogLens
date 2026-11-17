# LogLens — Python Log Analyzer

LogLens is a command-line log analysis tool built with Python. It reads log files, identifies valid and invalid entries, analyzes log levels, extracts IPv4 addresses, and detects repeated failed login attempts.

## Features

- Read and process log files.
- Parse structured log entries.
- Identify invalid log entries.
- Count INFO, WARNING, and ERROR messages.
- Identify frequently occurring error messages.
- Extract and count valid IPv4 addresses.
- Detect repeated failed login attempts using a configurable threshold.
- Export analysis results to CSV and JSON.
- Handle missing input files and invalid threshold values.

## Project Structure

```text
LogLens/
├── logs/
│   └── sample.log
├── loglens/
│   ├── __init__.py
│   ├── reader.py
│   ├── parser.py
│   ├── analyzer.py
│   ├── security.py
│   └── reporter.py
├── reports/
├── tests/
│   └── test_loglens.py
├── main.py
├── .gitignore
└── README.md
```

## Requirements

- Python 3.10 or later
- No external Python packages required.

## How to Run

Clone the repository:

```bash
git clone https://github.com/MAKx-code/LogLens.git
cd LogLens
```

Create and activate a virtual environment.

**Windows:**

```cmd
py -m venv .venv
.venv\Scripts\activate
```

Run LogLens:

```bash
python main.py
```

Specify a custom log file:

```bash
python main.py --input logs/sample.log
```

Set the failed login detection threshold:

```bash
python main.py --threshold 5
```

View available command-line options:

```bash
python main.py --help
```

## Running Tests

Run the automated test suite:

```bash
python -m unittest discover -s tests -v
```

## Generated Reports

LogLens generates:

- `reports/log_report.csv`
- `reports/log_report.json`

These files contain the processed log entries and analysis results.

## Current Limitations

- Supports INFO, WARNING, and ERROR log levels.
- Extracts IPv4 addresses only.
- Failed login detection uses a configurable occurrence threshold across the input file.
- Detection identifies suspicious patterns; it does not establish that an IP address is malicious.

## Technologies Used

- Python
- Regular Expressions
- CSV and JSON
- pathlib
- unittest
- argparse

## Project Status

Actively developed as a Python learning and portfolio project.