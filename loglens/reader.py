
from pathlib import Path

def read_log_file(file_path):
    """Read a log file and return its lines."""

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {file_path}")

    if not path.is_file():
        raise ValueError(f"Not a file: {file_path}")

    with path.open("r", encoding="utf-8") as file:
        return file.readlines()