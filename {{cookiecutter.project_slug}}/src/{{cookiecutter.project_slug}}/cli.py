#!/usr/bin/env python3
"""CLI for {{ cookiecutter.project_name }}"""

import argparse
import sys
import subprocess
import threading
import time
from pathlib import Path
from {{ cookiecutter.project_slug }} import __version__


def create_parser():
    """Create argument parser"""
    parser = argparse.ArgumentParser(
        prog="{{ cookiecutter.project_slug }}",
        description="{{ cookiecutter.poc_description }}",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    # Server mode
    parser.add_argument(
        "--no-server",
        action="store_true",
        help="Don't start background HTTP server",
    )

    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Server port (default: 8000)",
    )

    # Exploit options
    parser.add_argument(
        "--target",
        "-t",
        default="{{ cookiecutter.target_url }}",
        help="Target URL (default: {{ cookiecutter.target_url }})",
    )

    parser.add_argument(
        "--proxy",
        "-p",
        help="HTTP proxy (e.g., http://127.0.0.1:8080)",
    )

    parser.add_argument(
        "--threads",
        type=int,
        default=1,
        help="Number of threads (default: 1)",
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Verbose output",
    )

    return parser


def main():
    """Main entry point"""
    parser = create_parser()
    args = parser.parse_args()

    if args.server:
        # Start the HTTP server
        print(f"[*] Starting server on port {args.port}...")
        try:
            from {{ cookiecutter.project_slug }}.servers import server
            server_args = argparse.Namespace(port=args.port, bind='0.0.0.0')
            server.main_with_args(server_args)
        except KeyboardInterrupt:
            print("\n[*] Server stopped")
        sys.exit(0)

    # Run exploit
    print(f"[*] {{ cookiecutter.project_name }} - {{ cookiecutter.poc_description }}")
    print(f"[*] Target: {args.target}")

    if args.proxy:
        print(f"[*] Proxy: {args.proxy}")

    try:
        from {{ cookiecutter.project_slug }}.exploit import run
        run(args)
    except ImportError:
        print("[!] POC not implemented yet - add your code to src/{{ cookiecutter.project_slug }}/exploit.py")


if __name__ == "__main__":
    main()