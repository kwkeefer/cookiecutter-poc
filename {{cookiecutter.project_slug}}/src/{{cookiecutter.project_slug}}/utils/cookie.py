"""
Cookie parsing utilities for POCs.

This module provides functions for parsing and manipulating cookie strings,
making it easy to use stolen cookies in requests.
"""


def parse_cookie_string(cookie_string):
    """
    Parse a cookie string into a dict suitable for use with requests.

    Takes a cookie string (e.g., from document.cookie or Set-Cookie header)
    and converts it to a dictionary that can be passed to requests.

    Args:
        cookie_string: Cookie string in format "key1=value1; key2=value2"

    Returns:
        dict: Dictionary of cookie names to values

    Examples:
        .. code-block:: python

            cookie_str = "token=abc123; username=admin; session=xyz"
            cookies = parse_cookie_string(cookie_str)
            cookies
            {'token': 'abc123', 'username': 'admin', 'session': 'xyz'}
            
            # Use with requests:
            response = requests.get(url, cookies=cookies)
    """
    if not cookie_string:
        return {}

    cookies = {}
    for item in cookie_string.split(';'):
        item = item.strip()
        if '=' in item:
            key, value = item.split('=', 1)
            cookies[key.strip()] = value.strip()

    return cookies


def cookie_string_to_header(cookie_string):
    """
    Convert cookie string to a properly formatted Cookie header value.

    Parses the cookie string and reconstructs it as a clean Cookie header
    value, removing any extra whitespace or formatting issues.

    Args:
        cookie_string: Cookie string in any format

    Returns:
        str: Clean cookie string suitable for Cookie header

    Examples:
        .. code-block:: python

            cookie_str = "token=abc123; username=admin"
            header = cookie_string_to_header(cookie_str)
            header
            'token=abc123; username=admin'
            
            # Use with requests:
            headers = {'Cookie': header}
            response = requests.get(url, headers=headers)
    """
    # Parse and reconstruct to ensure clean formatting
    cookies = parse_cookie_string(cookie_string)
    return '; '.join(f'{k}={v}' for k, v in cookies.items())