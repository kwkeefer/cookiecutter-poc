"""
Cookie parsing utilities for POCs.
"""


def parse_cookie_string(cookie_string):
    """
    Parse a cookie string into a dict suitable for requests.

    Example:
        cookie_str = "token=abc123; username=admin; session=xyz"
        cookies = parse_cookie_string(cookie_str)
        # Returns: {'token': 'abc123', 'username': 'admin', 'session': 'xyz'}

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
    Convert cookie string to Cookie header value.

    Example:
        cookie_str = "token=abc123; username=admin"
        header = cookie_string_to_header(cookie_str)
        # Returns cleaned: "token=abc123; username=admin"

        # Use with requests:
        headers = {'Cookie': header}
        response = requests.get(url, headers=headers)
    """
    # Parse and reconstruct to ensure clean formatting
    cookies = parse_cookie_string(cookie_string)
    return '; '.join(f'{k}={v}' for k, v in cookies.items())