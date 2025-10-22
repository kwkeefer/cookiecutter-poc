# {{ cookiecutter.project_name }}

**Target URL:** {{ cookiecutter.target_url }}

## Quick Start

```bash
# 1. Start HTTP callback server (terminal 1)
uv run {{ cookiecutter.project_slug }} --server

# 2. Run exploit (terminal 2)
uv run {{ cookiecutter.project_slug }} -t http://target.com
```

## Writing Your Exploit

Edit `src/{{ cookiecutter.project_slug }}/exploit.py`:

```python
from {{ cookiecutter.project_slug }}.utils.output import out
import requests

def run(args):
    target = args.target.rstrip('/')

    out.info(f"Testing {target}...")
    resp = requests.get(f"{target}/vulnerable-endpoint", verify=False)

    if "vulnerable" in resp.text:
        out.success("Target is vulnerable!")
        # Your exploit code here
    else:
        out.error("Not vulnerable")
```

## Available Utilities

This template includes utilities for common POC tasks:

- **Output** - Colored console messages (`out.success()`, `out.error()`, etc.)
- **Encoding** - Base64, URL, hex encoding/decoding
- **Reverse Shells** - Generate and catch shells directly in Python
- **XSS Helpers** - Cookie stealers and data exfiltration
- **XXE Helpers** - XML exploitation payloads
- **File Upload** - Upload with bypass techniques
- **Shell Catcher** - Interactive shell handler
- **Apache Hooks** - Read callbacks from Apache logs
- And more...

## Documentation

**Full API documentation and examples:**
https://cookiecutter-poc.readthedocs.io/en/latest/

- [Examples & Patterns](https://cookiecutter-poc.readthedocs.io/en/latest/examples.html)
- [API Reference](https://cookiecutter-poc.readthedocs.io/en/latest/api/index.html)
- [Workflows](https://cookiecutter-poc.readthedocs.io/en/latest/workflows.html)

## Project Structure

```
{{ cookiecutter.project_slug }}/
├── src/{{ cookiecutter.project_slug }}/
│   ├── exploit.py          # Your exploit code (edit this!)
│   ├── cli.py              # CLI interface
│   ├── utils/              # Helper utilities
│   └── servers/server.py   # HTTP callback server
├── payloads/               # Files to serve (XSS, shells, etc)
└── logs/                   # Server request logs
```

## CLI Options

```bash
{{ cookiecutter.project_slug }} --help

Options:
  -t, --target URL     Target URL (default: {{ cookiecutter.target_url }})
  -p, --proxy URL      HTTP proxy for requests
  --threads N          Number of threads
  -v, --verbose        Verbose output
  --server             Start HTTP callback server
  --lhost IP           Local host for server/callbacks (auto-detected)
  --lport N            Local port for server/callbacks (default: 8000)
```

---

Generated from: [cookiecutter-poc](https://github.com/kwkeefer/cookiecutter-poc)
