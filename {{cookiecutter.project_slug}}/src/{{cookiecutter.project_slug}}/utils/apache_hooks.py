"""
Apache log parsing utilities.

Use this when you need to read callbacks from Apache logs instead of the built-in server.

Parses Apache access.log for both query and path parameters:

- Query parameters: ``/?cookie=data`` or ``/?exfil=data``
- Path parameters: ``/cookie/data`` or ``/exfil/data``

Works similarly to server_hooks.py but reads from log files.
"""

import re
import time
import base64
from pathlib import Path
from urllib.parse import parse_qs, unquote


def parse_apache_line(line: str) -> dict:
    """
    Parse Apache combined log format line.

    Example line:

    .. code-block:: text

        ::1 - - [13/Oct/2025:13:20:01 -0700] "GET /?cookies=test HTTP/1.1" 200 3454 "-" "Mozilla/5.0..."

    Returns:
        dict with: timestamp, method, path, query_params, path_params, status.
        Also extracts path-based parameters like ``/cookie/data`` or ``/exfil/data``
    """
    # Apache combined log format regex
    pattern = r'([^\s]+) - - \[([^\]]+)\] "(\w+) ([^\s]+) HTTP/[^"]+" (\d+) (\d+|-) "([^"]*)" "([^"]*)"'

    match = re.match(pattern, line)
    if not match:
        return None

    ip, timestamp, method, full_path, status, size, referer, user_agent = match.groups()

    # Split path and query string
    if '?' in full_path:
        path, query_string = full_path.split('?', 1)
        query_params = parse_qs(query_string)
    else:
        path = full_path
        query_params = {}

    # Check for path-based parameters (/cookie/data or /exfil/data)
    path_params = {}
    if path.startswith('/cookie/'):
        path_params['cookie'] = [unquote(path[8:])]  # Remove '/cookie/' prefix and decode
    elif path.startswith('/exfil/'):
        path_params['exfil'] = [unquote(path[7:])]  # Remove '/exfil/' prefix and decode

    return {
        'ip': ip,
        'timestamp': timestamp,
        'method': method,
        'path': path,
        'query': query_params,
        'path_params': path_params,
        'status': int(status),
        'size': int(size) if size != '-' else 0,
        'referer': referer,
        'user_agent': user_agent,
    }


def tail_log(log_file: str, start_pos: int = None) -> tuple:
    """
    Read new lines from log file since last position.

    Returns: (new_lines, new_position)
    """
    log_path = Path(log_file)

    if not log_path.exists():
        return [], 0

    with open(log_path, 'r') as f:
        if start_pos:
            f.seek(start_pos)

        lines = f.readlines()
        new_pos = f.tell()

    return lines, new_pos


def find_param_in_logs(log_file: str, param_name: str, timeout: int = 30) -> str:
    """
    Search Apache logs for a specific parameter (query or path-based).
    Returns the MOST RECENT occurrence (last match in file).

    Searches for both:

    - Query parameters: ``?param_name=value`` or ``&param_name=value``
    - Path parameters: ``/param_name/value``

    Args:
        log_file: Path to Apache access.log
        param_name: Parameter to search for (e.g., 'cookies', 'exfil', 'cookie')
        timeout: Max seconds to wait for log file to exist

    Returns:
        Parameter value (most recent) or None if not found
    """
    log_path = Path(log_file)

    # Wait for log file to exist
    start_time = time.time()
    while not log_path.exists():
        if time.time() - start_time >= timeout:
            return None
        time.sleep(0.5)

    # Read entire log file
    with open(log_file, 'r') as f:
        content = f.read()

    # Search for query parameters: ?param_name=value or &param_name=value
    query_pattern = rf'[?&]{re.escape(param_name)}=([^\s&"]+)'
    query_matches = re.findall(query_pattern, content)

    # Search for path parameters: /param_name/value
    # Match: "GET /param_name/value HTTP or "POST /param_name/value HTTP
    path_pattern = rf'"(?:GET|POST|PUT|DELETE) /{re.escape(param_name)}/([^\s"?]+)'
    path_matches = re.findall(path_pattern, content)

    # Combine all matches (query params come first in typical logs, so path params will be "more recent" if both exist)
    all_matches = query_matches + path_matches

    if all_matches:
        # Return the LAST occurrence (most recent)
        return all_matches[-1]

    return None


def get_cookie(log_file: str = '/var/log/apache2/access.log', timeout: int = 30) -> str:
    """
    Get cookie value from Apache logs.

    Supports both query and path parameters:

    - Query: ``/?cookies=value`` or ``/?cookie=value``
    - Path: ``/cookie/value``

    Args:
        log_file: Path to Apache access.log
        timeout: Max seconds to wait

    Returns:
        Cookie string (auto-decoded if base64) or None
    """
    # Try both 'cookies' and 'cookie' parameter names
    value = find_param_in_logs(log_file, 'cookies', timeout=timeout)

    if not value:
        value = find_param_in_logs(log_file, 'cookie', timeout=timeout)

    if not value:
        return None

    # Try to decode if it looks like base64
    try:
        decoded = base64.b64decode(unquote(value)).decode('utf-8', errors='replace')
        return decoded
    except:
        # Not base64 or failed to decode, return as-is
        return unquote(value)


def get_exfil(log_file: str = '/var/log/apache2/access.log', timeout: int = 30) -> str:
    """
    Get exfiltrated data from Apache logs.

    Supports both query and path parameters:

    - Query: ``/?exfil=value``
    - Path: ``/exfil/value``

    Args:
        log_file: Path to Apache access.log
        timeout: Max seconds to wait

    Returns:
        Exfiltrated data string or None
    """
    value = find_param_in_logs(log_file, 'exfil', timeout=timeout)

    if value:
        return unquote(value)

    return None


def get_param(param_name: str, log_file: str = '/var/log/apache2/access.log', timeout: int = 30) -> str:
    """
    Get any custom parameter from Apache logs.

    Args:
        param_name: Query parameter name to search for
        log_file: Path to Apache access.log
        timeout: Max seconds to wait

    Returns:
        Parameter value (URL-decoded) or None
    """
    value = find_param_in_logs(log_file, param_name, timeout=timeout)

    if value:
        return unquote(value)

    return None


def watch_log(log_file: str = '/var/log/apache2/access.log', params: list = None):
    """
    Watch Apache log in real-time and print interesting parameters.

    Monitors for both query and path parameters:

    - Query: ``/?param=value``
    - Path: ``/param/value``

    Args:
        log_file: Path to Apache access.log
        params: List of parameters to watch for (default: ['cookies', 'cookie', 'exfil'])
    """
    if params is None:
        params = ['cookies', 'cookie', 'exfil']

    log_path = Path(log_file)

    # Get initial file position (end of file)
    if log_path.exists():
        with open(log_path, 'r') as f:
            f.seek(0, 2)  # Seek to end
            file_pos = f.tell()
    else:
        print(f"[!] Log file not found: {log_file}")
        return

    print(f"[*] Watching {log_file} for parameters: {', '.join(params)}")
    print(f"[*] Press Ctrl+C to stop")

    try:
        while True:
            new_lines, file_pos = tail_log(log_file, file_pos)

            for line in new_lines:
                parsed = parse_apache_line(line.strip())
                if not parsed:
                    continue

                # Check for interesting parameters in query params
                for param in params:
                    if param in parsed['query']:
                        value = parsed['query'][param][-1]  # Last value

                        # Try to decode if base64
                        try:
                            decoded = base64.b64decode(unquote(value)).decode('utf-8', errors='replace')
                            print(f"[+] {param.upper()} (query): {decoded}")
                        except:
                            print(f"[+] {param.upper()} (query): {unquote(value)}")

                # Check for interesting parameters in path params
                for param in params:
                    if param in parsed['path_params']:
                        value = parsed['path_params'][param][0]  # First (and only) value

                        # Try to decode if base64
                        try:
                            decoded = base64.b64decode(value).decode('utf-8', errors='replace')
                            print(f"[+] {param.upper()} (path): {decoded}")
                        except:
                            print(f"[+] {param.upper()} (path): {value}")

            time.sleep(0.5)

    except KeyboardInterrupt:
        print("\n[*] Stopped watching log")


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == 'watch':
        # Watch mode: python apache_hooks.py watch [log_file] [param1] [param2] ...
        log_file = sys.argv[2] if len(sys.argv) > 2 else '/var/log/apache2/access.log'
        params = sys.argv[3:] if len(sys.argv) > 3 else None
        watch_log(log_file, params)
    else:
        # Test mode
        print("Testing Apache log parser...")

        # Test query parameter parsing
        print("\n1. Query parameter test:")
        test_line = '::1 - - [13/Oct/2025:13:20:01 -0700] "GET /?cookies=test123 HTTP/1.1" 200 3454 "-" "Mozilla/5.0"'
        parsed = parse_apache_line(test_line)
        print(f"   Query params: {parsed['query']}")
        print(f"   Path params: {parsed['path_params']}")

        # Test path parameter parsing
        print("\n2. Path parameter test:")
        test_line2 = '::1 - - [13/Oct/2025:13:20:02 -0700] "GET /cookie/session%3Dabc123 HTTP/1.1" 200 100 "-" "curl/7.68.0"'
        parsed2 = parse_apache_line(test_line2)
        print(f"   Query params: {parsed2['query']}")
        print(f"   Path params: {parsed2['path_params']}")

        print("\n3. Exfil path parameter test:")
        test_line3 = '::1 - - [13/Oct/2025:13:20:03 -0700] "GET /exfil/sensitive_data HTTP/1.1" 200 100 "-" "Python"'
        parsed3 = parse_apache_line(test_line3)
        print(f"   Query params: {parsed3['query']}")
        print(f"   Path params: {parsed3['path_params']}")

        print("\nTo watch logs in real-time:")
        print("  python apache_hooks.py watch")
        print("  python apache_hooks.py watch /var/log/apache2/access.log cookies exfil")
