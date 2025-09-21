"""
Simple utilities for interacting with the server's event queue.
Use this from your exploit to monitor/process incoming data.
"""

import json
import time
from pathlib import Path


def watch_events(callback, event_file=None):
    """
    Watch for new events from the server and call callback for each.

    Example:
        def handle_cookie(event):
            if event['type'] == 'cookie':
                print(f"Got cookie: {event['data']}")
                # Do something with the cookie...

        # Start watching in background
        import threading
        threading.Thread(target=watch_events, args=(handle_cookie,), daemon=True).start()

        # Or call directly (blocks)
        # watch_events(handle_cookie)
    """
    if event_file is None:
        event_file = Path(__file__).parent.parent.parent.parent / 'logs' / 'events.ndjson'

    # Track position in file
    last_pos = 0

    while True:
        try:
            if event_file.exists():
                with open(event_file, 'r') as f:
                    f.seek(last_pos)
                    for line in f:
                        if line.strip():
                            try:
                                event = json.loads(line)
                                callback(event)
                            except json.JSONDecodeError:
                                pass
                    last_pos = f.tell()
        except Exception as e:
            print(f"Error watching events: {e}")

        time.sleep(0.5)  # Check twice per second


def get_latest_cookie():
    """
    Quick helper to get the most recent cookie from events.
    Returns None if no cookies found.
    """
    event_file = Path(__file__).parent.parent.parent.parent / 'logs' / 'events.ndjson'

    if not event_file.exists():
        return None

    cookie = None
    with open(event_file, 'r') as f:
        for line in f:
            if line.strip():
                try:
                    event = json.loads(line)
                    if event.get('type') == 'cookie':
                        cookie = event.get('data')
                except:
                    pass

    return cookie


def wait_for_callback(timeout=30, param='cookie'):
    """
    Wait for a specific callback parameter to arrive.
    Returns the data or None if timeout.

    Example:
        # Send XSS payload
        send_payload(xss)

        # Wait for cookie to arrive
        cookie = wait_for_callback(timeout=10, param='cookie')
        if cookie:
            print(f"Got cookie: {cookie}")
    """
    event_file = Path(__file__).parent.parent.parent.parent / 'logs' / 'events.ndjson'
    start_time = time.time()
    last_pos = 0

    # Get initial position
    if event_file.exists():
        with open(event_file, 'r') as f:
            f.seek(0, 2)  # Go to end
            last_pos = f.tell()

    while time.time() - start_time < timeout:
        if event_file.exists():
            with open(event_file, 'r') as f:
                f.seek(last_pos)
                for line in f:
                    if line.strip():
                        try:
                            event = json.loads(line)
                            if event.get('type') == param:
                                return event.get('data')
                        except:
                            pass
                last_pos = f.tell()

        time.sleep(0.2)

    return None