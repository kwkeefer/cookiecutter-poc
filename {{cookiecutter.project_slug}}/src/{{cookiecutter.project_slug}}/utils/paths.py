"""
Path utilities for POC projects.
Provides consistent access to project directories.
"""

from pathlib import Path


# Project root directory (where pyproject.toml lives)
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent

# Common directories
LOGS_DIR = PROJECT_ROOT / "logs"
PAYLOADS_DIR = PROJECT_ROOT / "payloads"
SERVERS_DIR = PROJECT_ROOT / "servers"


def get_project_root():
    """Get the absolute path to the project root directory."""
    return PROJECT_ROOT


def get_logs_dir():
    """Get the absolute path to the logs directory."""
    return LOGS_DIR


def get_payloads_dir():
    """Get the absolute path to the payloads directory."""
    return PAYLOADS_DIR


def get_servers_dir():
    """Get the absolute path to the servers directory."""
    return SERVERS_DIR


def get_log_file(filename="server.ndjson"):
    """Get the absolute path to a log file."""
    return LOGS_DIR / filename


def ensure_dirs_exist():
    """Create all required directories if they don't exist."""
    LOGS_DIR.mkdir(exist_ok=True)
    PAYLOADS_DIR.mkdir(exist_ok=True)
    (PAYLOADS_DIR / "xss").mkdir(exist_ok=True)
    (PAYLOADS_DIR / "shells").mkdir(exist_ok=True)