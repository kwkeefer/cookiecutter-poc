# Payloads Directory

Store your payloads here. They will be automatically served by the HTTP server.

## Directory Structure

```
payloads/
├── xss/           # XSS payloads
├── shells/        # Reverse shells, web shells
├── exploits/      # Compiled exploits
└── files/         # Miscellaneous files
```

## Access via HTTP Server

Files in this directory are accessible at:
- `http://[your-ip]:8000/payloads/[filename]`
- `http://[your-ip]:8000/static/[filename]` (alias)

## Examples

Place files here like:
- `payloads/xss/steal-cookie.js`
- `payloads/shells/reverse.py`
- `payloads/exploits/privesc.bin`

Then access them at:
- `http://your-server:8000/payloads/xss/steal-cookie.js`