#!/usr/bin/env python3
"""Common encoding/decoding utilities for POCs.

Quick reference for encoding payloads, bypassing filters, and hashing credentials.

Example:
    .. code-block:: python

        from your_project.utils.encoding import base64_encode, url_encode, md5

        # Encode SQL injection payload
        payload = "admin' OR '1'='1"
        encoded = base64_encode(payload)  # For Authorization headers, etc.

        # Double encode for filter bypass
        from your_project.utils.encoding import double_url_encode
        bypass = double_url_encode("../../../etc/passwd")

        # Hash stolen password
        password_hash = md5("password123")
"""

import base64
import urllib.parse
import html
import json
import hashlib


def base64_encode(data):
    """Base64 encode string or bytes.

    Args:
        data: String or bytes to encode

    Returns:
        Base64 encoded string

    Example:
        ``base64_encode("admin:password")`` → ``"YWRtaW46cGFzc3dvcmQ="``
    """
    if isinstance(data, str):
        data = data.encode()
    return base64.b64encode(data).decode()


def base64_decode(data):
    """Base64 decode string.

    Args:
        data: Base64 encoded string or bytes

    Returns:
        Decoded string

    Example:
        ``base64_decode("YWRtaW46cGFzc3dvcmQ=")`` → ``"admin:password"``
    """
    if isinstance(data, str):
        data = data.encode()
    return base64.b64decode(data).decode()


def url_encode(data):
    """URL encode string (percent encoding).

    Args:
        data: String to encode

    Returns:
        URL encoded string

    Example:
        ``url_encode("../etc/passwd")`` → ``"..%2Fetc%2Fpasswd"``
    """
    return urllib.parse.quote(data, safe='')


def url_decode(data):
    """URL decode string.

    Args:
        data: URL encoded string

    Returns:
        Decoded string

    Example:
        ``url_decode("%3Cscript%3E")`` → ``"<script>"``
    """
    return urllib.parse.unquote(data)


def double_url_encode(data):
    """Double URL encode string for filter bypasses.

    Useful when the application decodes input once but processes it twice.

    Args:
        data: String to double encode

    Returns:
        Double URL encoded string

    Example:
        ``double_url_encode("../")`` → ``"%252E%252E%252F"``
    """
    return url_encode(url_encode(data))


def hex_encode(data):
    """Hex encode string or bytes.

    Args:
        data: String or bytes to encode

    Returns:
        Hexadecimal string

    Example:
        ``hex_encode("ABC")`` → ``"414243"``
    """
    if isinstance(data, str):
        data = data.encode()
    return data.hex()


def hex_decode(data):
    """Hex decode string.

    Args:
        data: Hexadecimal string

    Returns:
        Decoded string

    Example:
        ``hex_decode("414243")`` → ``"ABC"``
    """
    return bytes.fromhex(data).decode()


def html_encode(data):
    """HTML entity encode string for XSS prevention.

    Args:
        data: String to encode

    Returns:
        HTML entity encoded string

    Example:
        ``html_encode("<script>")`` → ``"&lt;script&gt;"``
    """
    return html.escape(data)


def html_decode(data):
    """HTML entity decode string.

    Args:
        data: HTML entity encoded string

    Returns:
        Decoded string

    Example:
        ``html_decode("&lt;script&gt;")`` → ``"<script>"``
    """
    return html.unescape(data)


def json_encode(data):
    """JSON encode object"""
    return json.dumps(data)


def json_decode(data):
    """JSON decode string"""
    return json.loads(data)


def unicode_encode(data):
    """Unicode encode string for filter bypasses.

    Converts string to JavaScript unicode escape sequences.

    Args:
        data: String to encode

    Returns:
        Unicode escaped string

    Example:
        ``unicode_encode("<script>")`` → ``"\\u003c\\u0073\\u0063\\u0072\\u0069\\u0070\\u0074\\u003e"``
    """
    return ''.join([f'\\u{ord(c):04x}' for c in data])


def char_codes(data):
    """Convert to JavaScript char codes.

    Useful for XSS payloads with String.fromCharCode().

    Args:
        data: String to convert

    Returns:
        Comma-separated character codes

    Example:
        ``char_codes("alert")`` → ``"97,108,101,114,116"``
    """
    return ','.join([str(ord(c)) for c in data])


def md5(data):
    """MD5 hash string or bytes.

    Common for older password hashes and checksums.

    Args:
        data: String or bytes to hash

    Returns:
        MD5 hex digest (32 characters)

    Example:
        ``md5("password123")`` → ``"482c811da5d5b4bc6d497ffa98491e38"``
    """
    if isinstance(data, str):
        data = data.encode()
    return hashlib.md5(data).hexdigest()


def sha1(data):
    """SHA1 hash string or bytes.

    Args:
        data: String or bytes to hash

    Returns:
        SHA1 hex digest (40 characters)

    Example:
        ``sha1("password123")`` → ``"aafdc23870ecbcd3d557b6423a8982134e17927e"``
    """
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha1(data).hexdigest()


def sha256(data):
    """SHA256 hash string or bytes.

    Modern standard for password hashing and signatures.

    Args:
        data: String or bytes to hash

    Returns:
        SHA256 hex digest (64 characters)

    Example:
        ``sha256("password123")`` → ``"ef92b778bafe771e8978...e5f29cb75"`` (truncated)
    """
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def sha512(data):
    """SHA512 hash string or bytes.

    Args:
        data: String or bytes to hash

    Returns:
        SHA512 hex digest (128 characters)
    """
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha512(data).hexdigest()


def ntlm(password):
    """NTLM hash (MD4 of UTF-16LE password)"""
    import hashlib
    pwd = password.encode('utf-16le')
    return hashlib.new('md4', pwd).hexdigest()


def hash_file(filepath, algorithm='sha256'):
    """Hash a file with specified algorithm"""
    h = hashlib.new(algorithm)
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


def hmac_sha256(key, data):
    """HMAC-SHA256 for API signatures"""
    import hmac
    if isinstance(key, str):
        key = key.encode()
    if isinstance(data, str):
        data = data.encode()
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def crc32(data):
    """CRC32 checksum"""
    import zlib
    if isinstance(data, str):
        data = data.encode()
    return format(zlib.crc32(data) & 0xffffffff, '08x')


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
    print(f"\nHashes for 'password123':")
    print(f"MD5:         {md5('password123')}")
    print(f"SHA1:        {sha1('password123')}")
    print(f"SHA256:      {sha256('password123')}")
    print(f"SHA512:      {sha512('password123')}")
    print(f"NTLM:        {ntlm('password123')}")
    print(f"CRC32:       {crc32('password123')}")