#!/usr/bin/env python3
"""Common encoding/decoding utilities for POCs"""

import base64
import urllib.parse
import html
import json
import hashlib


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


def md5(data):
    """MD5 hash string or bytes"""
    if isinstance(data, str):
        data = data.encode()
    return hashlib.md5(data).hexdigest()


def sha1(data):
    """SHA1 hash string or bytes"""
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha1(data).hexdigest()


def sha256(data):
    """SHA256 hash string or bytes"""
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def sha512(data):
    """SHA512 hash string or bytes"""
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