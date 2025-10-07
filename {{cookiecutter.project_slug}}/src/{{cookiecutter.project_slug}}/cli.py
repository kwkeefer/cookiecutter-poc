#!/usr/bin/env python3
"""CLI for {{ cookiecutter.project_name }}"""

import argparse
import sys
import subprocess
import threading
import time
from pathlib import Path
from {{ cookiecutter.project_slug }} import __version__
from {{ cookiecutter.project_slug }}.utils.network import get_interfaces, get_callback_host
from {{ cookiecutter.project_slug }}.utils.output import out


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
        "--server",
        action="store_true",
        help="Start HTTP server for callbacks and payloads",
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
        "--lhost",
        type=str,
        default=None,
        help="Local host address for callbacks (defaults to tun0 if available)",
    )

    parser.add_argument(
        "--lport",
        type=str,
        default=None,
        help="Local port for callbacks (defaults to --port value)",
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
        out.info(f"Starting server on port {args.port}...")
        try:
            from {{ cookiecutter.project_slug }}.servers import server
            server_args = argparse.Namespace(port=args.port, bind='0.0.0.0')
            server.main_with_args(server_args)
        except KeyboardInterrupt:
            out.info("Server stopped")
        sys.exit(0)
    else:
        # Handle callback host/port defaults
        if args.lport is None:
            args.lport = str(args.port)
            out.warning(f"--lport not set, defaulting to --port value: {args.lport}")

        if args.lhost is None:
            args.lhost = get_callback_host()
            interfaces = get_interfaces()
            if 'tun0' in interfaces:
                out.warning(f"--lhost not set, defaulting to tun0 interface: {args.lhost}")
            else:
                out.warning(f"--lhost not set, defaulting to first available interface: {args.lhost}")


    # Run exploit
    out.info(f"{{ cookiecutter.project_name }} - {{ cookiecutter.poc_description }}")
    out.info(f"Target: {args.target}")

    if args.proxy:
        out.info(f"Proxy: {args.proxy}")

    from {{ cookiecutter.project_slug }}.exploit import run
    run(args)


if __name__ == "__main__":
    main()