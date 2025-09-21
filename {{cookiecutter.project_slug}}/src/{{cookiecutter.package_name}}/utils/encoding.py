#!/usr/bin/env python3
"""Common encoding/decoding utilities for POCs"""

import base64
import urllib.parse
import html
import json


def base64_encode(data):
    """Base64 encode string or bytes"""
    if isinstance(data, str):
        data = data.encode()
    return base64.b64encode(data).decode()


def base64_decode(data):
    """Base64 decode string"""
    if isinstance(data, str):
        data = data.encode()
    return base64.b64decode(data).decode()


def url_encode(data):
    """URL encode string"""
    return urllib.parse.quote(data, safe='')


def url_decode(data):
    """URL decode string"""
    return urllib.parse.unquote(data)


def double_url_encode(data):
    """Double URL encode string"""
    return url_encode(url_encode(data))


def hex_encode(data):
    """Hex encode string or bytes"""
    if isinstance(data, str):
        data = data.encode()
    return data.hex()


def hex_decode(data):
    """Hex decode string"""
    return bytes.fromhex(data).decode()


def html_encode(data):
    """HTML entity encode string"""
    return html.escape(data)


def html_decode(data):
    """HTML entity decode string"""
    return html.unescape(data)


def json_encode(data):
    """JSON encode object"""
    return json.dumps(data)


def json_decode(data):
    """JSON decode string"""
    return json.loads(data)


def unicode_encode(data):
    """Unicode encode string for bypasses"""
    return ''.join([f'\\u{ord(c):04x}' for c in data])


def char_codes(data):
    """Convert to JavaScript char codes"""
    return ','.join([str(ord(c)) for c in data])


if __name__ == "__main__":
    # Quick tests
    test = "admin' OR '1'='1"
    print(f"Original:    {test}")
    print(f"Base64:      {base64_encode(test)}")
    print(f"URL:         {url_encode(test)}")
    print(f"Double URL:  {double_url_encode(test)}")
    print(f"Hex:         {hex_encode(test)}")
    print(f"HTML:        {html_encode(test)}")
    print(f"Unicode:     {unicode_encode(test)}")
    print(f"CharCodes:   {char_codes(test)}")