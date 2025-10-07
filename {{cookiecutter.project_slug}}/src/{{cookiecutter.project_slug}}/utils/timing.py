#!/usr/bin/env python3
"""Time utilities for POCs - timestamp generation, timing attacks, etc."""

import time
from datetime import datetime, timedelta
from email.utils import parsedate_to_datetime


def time_ms():
    """Current time in milliseconds"""
    return round(time.time() * 1000)


def time_us():
    """Current time in microseconds"""
    return round(time.time() * 1000000)


def time_ns():
    """Current time in nanoseconds"""
    return time.time_ns()


def epoch_now():
    """Current epoch time in seconds. Use for second-precision timestamps."""
    return int(time.time())


def epoch_ms_now():
    """Current epoch time in milliseconds. Use for millisecond-precision timestamps."""
    return round(time.time() * 1000)


def epoch_range(start_date, end_date, step_minutes=1):
    """Generate range of epoch timestamps between two dates

    Args:
        start_date: String like '2024-01-01 00:00:00' or epoch timestamp (int/float)
        end_date: String like '2024-01-01 23:59:59' or epoch timestamp (int/float)
        step_minutes: Minutes between each timestamp

    Returns:
        List of epoch timestamps
    """
    # Handle epoch timestamps directly
    if isinstance(start_date, (int, float)):
        start = datetime.fromtimestamp(start_date)
    else:
        start = datetime.strptime(start_date, "%Y-%m-%d %H:%M:%S")

    if isinstance(end_date, (int, float)):
        end = datetime.fromtimestamp(end_date)
    else:
        end = datetime.strptime(end_date, "%Y-%m-%d %H:%M:%S")

    timestamps = []
    current = start
    step = timedelta(minutes=step_minutes)

    while current <= end:
        timestamps.append(int(current.timestamp()))
        current += step

    return timestamps


def epoch_range_ms(start_ms, end_ms):
    """Generate all millisecond timestamps between start and end

    Args:
        start_ms: Start timestamp in milliseconds (int)
        end_ms: End timestamp in milliseconds (int)

    Returns:
        List of all millisecond timestamps in range
    """
    return list(range(start_ms, end_ms + 1))


def measure_time(func, *args, **kwargs):
    """Measure execution time of a function in seconds

    Usage:
        duration = measure_time(requests.get, url, timeout=10)
    """
    start = time.time()
    result = func(*args, **kwargs)
    end = time.time()
    return end - start


def time_based_check(func, threshold=5.0, *args, **kwargs):
    """Check if function takes longer than threshold seconds

    Useful for blind time-based SQLi/XXE detection
    Returns duration if >= threshold, None otherwise
    """
    duration = measure_time(func, *args, **kwargs)
    return duration if duration >= threshold else None


def sleep_ms(milliseconds):
    """Sleep for specified milliseconds"""
    time.sleep(milliseconds / 1000)


def timestamp_to_date(timestamp, ms=False):
    """Convert epoch timestamp to readable date

    Args:
        timestamp: Epoch timestamp
        ms: True if timestamp is in milliseconds
    """
    if ms:
        timestamp = timestamp / 1000
    return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")


def date_to_timestamp(date_str, ms=False):
    """Convert date string to epoch timestamp

    Args:
        date_str: String like '2024-01-01 00:00:00'
        ms: True to return milliseconds
    """
    dt = datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
    ts = int(dt.timestamp())
    return ts * 1000 if ms else ts


def http_date_to_epoch_ms(http_date):
    """Convert HTTP Date header to epoch milliseconds

    Args:
        http_date: HTTP date string (RFC 2822 format)
                   e.g., 'Sun, 05 Oct 2025 02:43:25 GMT'

    Returns:
        Epoch timestamp in milliseconds
    """
    dt = parsedate_to_datetime(http_date)
    return int(dt.timestamp() * 1000)


def identify_timestamp(value):
    """Identify timestamp type and suggest generation function

    Args:
        value: Integer or string timestamp to identify

    Returns:
        Dict with type info and suggested function
    """
    # Convert to int if string
    if isinstance(value, str):
        value = int(value)

    # Current reference times
    now_s = int(time.time())
    now_ms = round(time.time() * 1000)
    now_us = round(time.time() * 1000000)
    now_ns = time.time_ns()

    # Reasonable time bounds (2000-01-01 to 2030-01-01)
    min_epoch = 946684800  # 2000-01-01
    max_epoch = 1893456000  # 2030-01-01

    result = {"value": value, "type": "unknown", "unit": "unknown", "function": None, "date": None, "explanation": ""}

    # Check if it's in seconds range
    if min_epoch <= value <= max_epoch:
        result["type"] = "epoch_seconds"
        result["unit"] = "seconds"
        result["function"] = "epoch_now() or int(time.time())"
        result["date"] = timestamp_to_date(value)
        result["explanation"] = f"Epoch timestamp in seconds (~{now_s})"

    # Check milliseconds range
    elif min_epoch * 1000 <= value <= max_epoch * 1000:
        result["type"] = "epoch_milliseconds"
        result["unit"] = "milliseconds"
        result["function"] = "time_ms() or round(time.time() * 1000)"
        result["date"] = timestamp_to_date(value, ms=True)
        result["explanation"] = f"Epoch timestamp in milliseconds (~{now_ms})"

    # Check microseconds range
    elif min_epoch * 1000000 <= value <= max_epoch * 1000000:
        result["type"] = "epoch_microseconds"
        result["unit"] = "microseconds"
        result["function"] = "time_us() or round(time.time() * 1000000)"
        result["date"] = timestamp_to_date(value / 1000000)
        result["explanation"] = f"Epoch timestamp in microseconds (~{now_us})"

    # Check nanoseconds range
    elif min_epoch * 1000000000 <= value <= max_epoch * 1000000000:
        result["type"] = "epoch_nanoseconds"
        result["unit"] = "nanoseconds"
        result["function"] = "time_ns()"
        result["date"] = timestamp_to_date(value / 1000000000)
        result["explanation"] = f"Epoch timestamp in nanoseconds (~{now_ns})"

    else:
        # Try to guess based on number of digits
        digits = len(str(value))
        if digits == 10:
            result["explanation"] = "Looks like seconds but outside reasonable date range"
        elif digits == 13:
            result["explanation"] = "Looks like milliseconds but outside reasonable date range"
        elif digits == 16:
            result["explanation"] = "Looks like microseconds but outside reasonable date range"
        elif digits == 19:
            result["explanation"] = "Looks like nanoseconds but outside reasonable date range"
        else:
            result["explanation"] = f"Unknown format ({digits} digits)"

    return result


if __name__ == "__main__":
    # Quick tests
    print(f"Current epoch:     {epoch_now()}")
    print(f"Current millis:    {time_ms()}")
    print(f"Current micros:    {time_us()}")

    # Test timestamp identification
    print("\n" + "=" * 50)
    print("Timestamp Identification:")
    print("=" * 50)

    test_timestamps = [
        epoch_now(),
        time_ms(),
        time_us(),
        time_ns(),
        1234567890,  # Old seconds timestamp
        1609459200000,  # Jan 1, 2021 in ms
    ]

    for ts in test_timestamps:
        info = identify_timestamp(ts)
        print(f"\nValue: {ts}")
        print(f"  Type: {info['type']}")
        print(f"  Unit: {info['unit']}")
        print(f"  Date: {info['date']}")
        print(f"  Generate with: {info['function']}")
        print(f"  Note: {info['explanation']}")
