"""
Simple utilities for interacting with the http server's event queue.
Use this from your exploit to get cookies and other events.
"""

import requests
import time


def get_event(server='http://localhost:8000', timeout=30, wait=False):
    """
    Pop next event from the server queue.

    Returns the event dict or None if timeout/empty.
    If wait=True, will poll until event arrives or timeout.
    """
    start_time = time.time()

    while True:
        try:
            r = requests.delete(f'{server}/queue', timeout=2)
            if r.status_code == 200:
                return r.json()
            elif r.status_code == 204 and not wait:
                return None
            # If 204 and wait=True, continue polling
        except (requests.Timeout, requests.ConnectionError):
            if not wait:
                return None
            # If wait=True, continue trying

        # Check if we've exceeded timeout
        if time.time() - start_time >= timeout:
            return None

        # Small delay before retrying
        if wait:
            time.sleep(0.5)


def get_cookie(server='http://localhost:8000', timeout=30):
    """
    Pop next cookie from server queue.

    Returns just the cookie data string or None if timeout/no cookie.
    Will wait up to timeout seconds for a cookie to arrive.
    """
    event = get_event(server, timeout, wait=True)
    if event and event.get('type') == 'cookie':
        return event.get('data')
    return None


def wait_for_callback(server='http://localhost:8000', timeout=30, param='cookie'):
    """
    Wait for a specific callback type to arrive.

    Examples:
        >>> # Send XSS payload
        >>> send_payload(xss)
        >>> # Wait for cookie to arrive
        >>> cookie = wait_for_callback(timeout=10)
        >>> if cookie:
        ...     print(f"Got cookie: {cookie}")
    """
    start_time = time.time()

    while time.time() - start_time < timeout:
        event = get_event(server, timeout=2, wait=False)  # Don't wait on each call
        if event and event.get('type') == param:
            return event.get('data')
        time.sleep(0.5)

    return None


def get_exfil(server='http://localhost:8000', timeout=30):
    """
    Pop next exfiltrated data from server queue (for XXE, SSRF, etc).

    Returns just the exfil data string or None if timeout/no data.
    Will wait up to timeout seconds for data to arrive.
    """
    event = get_event(server, timeout, wait=True)
    if event and event.get('type') == 'exfil':
        return event.get('data')
    return None


def drain_queue(server='http://localhost:8000'):
    """
    Clear all pending events from the queue.
    Useful for starting fresh before a new exploit attempt.
    """
    count = 0
    while get_event(server, timeout=1, wait=False):
        count += 1
    return count