#!/usr/bin/env python3
"""
Simple HTTP server for POC development.
Serves payloads and logs all requests.
"""

from http.server import SimpleHTTPRequestHandler, HTTPServer
import logging
from datetime import datetime
import json
import base64
from pathlib import Path
import argparse
from urllib.parse import parse_qs, urlparse
import os

# Setup paths
BASE_DIR = Path(__file__).parent.parent
LOGS_DIR = BASE_DIR / "logs"
PAYLOADS_DIR = BASE_DIR / "payloads"

# Create logs directory
LOGS_DIR.mkdir(exist_ok=True)

# Setup logger
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger('server')

# File logger for NDJSON
file_handler = logging.FileHandler(LOGS_DIR / 'server.ndjson')
file_handler.setFormatter(logging.Formatter('%(message)s'))


class POCHTTPHandler(SimpleHTTPRequestHandler):
    """HTTP handler that serves payloads and logs everything"""

    def __init__(self, *args, **kwargs):
        # Serve from payloads directory
        super().__init__(*args, directory=str(PAYLOADS_DIR), **kwargs)

    def do_GET(self):
        self.handle_request()
        super().do_GET()

    def do_POST(self):
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

    def handle_request(self):
        """Log request details"""
        parsed = urlparse(self.path)

        # Read body if POST
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length and self.command == 'POST' else b''

        # Create log entry
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'client': f"{self.client_address[0]}:{self.client_address[1]}",
            'method': self.command,
            'path': self.path,
            'query': parse_qs(parsed.query) if parsed.query else {},
            'headers': dict(self.headers),
            'body': base64.b64encode(body).decode() if body else ""
        }

        # Log to file
        with open(LOGS_DIR / 'server.ndjson', 'a') as f:
            f.write(json.dumps(log_entry) + '\n')

        # Console output (minimal)
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {self.command} {self.path} from {self.client_address[0]}")
        if parsed.query:
            print(f"  Query: {parsed.query}")
        if body:
            print(f"  Body: {body.decode('utf-8', errors='replace')[:100]}")

    def log_message(self, format, *args):
        # Suppress default logging
        pass

    def end_headers(self):
        # Add CORS to all responses
        self.send_header('Access-Control-Allow-Origin', '*')
        super().end_headers()


def main():
    parser = argparse.ArgumentParser(description='POC HTTP Server')
    parser.add_argument('-p', '--port', type=int, default=8000, help='Port (default: 8000)')
    parser.add_argument('-b', '--bind', default='0.0.0.0', help='Bind address (default: 0.0.0.0)')
    args = parser.parse_args()

    os.chdir(PAYLOADS_DIR)  # Serve from payloads directory

    print(f"\nPOC Server: http://{args.bind}:{args.port}")
    print(f"Serving: {PAYLOADS_DIR}")
    print(f"Logs: {LOGS_DIR}/server.ndjson\n")

    server = HTTPServer((args.bind, args.port), POCHTTPHandler)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()


if __name__ == '__main__':
    main()