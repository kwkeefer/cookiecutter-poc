"""Batch request utility for sending multiple HTTP requests with different parameters."""

import asyncio
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterator, List, Optional, Union

import httpx
from httpx import Proxy

try:
    from .output import out
except ImportError:
    # Fallback if output module not available
    class out:
        @staticmethod
        def success(msg):
            print(f"[+] {msg}")

        @staticmethod
        def error(msg):
            print(f"[-] {msg}")

        @staticmethod
        def info(msg):
            print(f"[*] {msg}")


@dataclass
class BatchResult:
    """Result from a single request in the batch."""

    payload: Dict[str, Any]
    response: Optional[httpx.Response]
    matched: bool
    error: Optional[Exception] = None
    cookies: Optional[Dict[str, str]] = None


async def batch_request(
    base_request: httpx.Request,
    payloads: Iterator[Dict[str, Any]],
    validate: Callable[[httpx.Response], bool],
    concurrency: int = 10,
    timeout: float = 10.0,
    show_progress: bool = True,
    proxy: Optional[str] = None,
    filter_matched: bool = False,
    drop_response: bool = False,
    stop_on_match: bool = False,
    **client_kwargs,
) -> List[BatchResult]:
    """
    Send multiple HTTP requests using a base request as template.

    Args:
        base_request: Base httpx.Request to use as template
        payloads: Iterator of kwargs dicts to override the base request
        validate: Function to check if response matches criteria
        concurrency: Max concurrent requests (default: 10)
        timeout: Request timeout in seconds (default: 10.0)
        show_progress: Print successful matches (default: True)
        proxy: HTTP proxy URL (e.g., "http://127.0.0.1:8080")
        filter_matched: Only return results where validate() is True (default: False)
        drop_response: Don't store response object to save memory (default: False)
        stop_on_match: Stop sending requests after first match (default: False)
        **client_kwargs: Additional kwargs for httpx.AsyncClient

    Returns:
        List of BatchResult objects (only matched if filter_matched=True)

    Example:
        # Build base request with all common parameters
        client = httpx.Client()
        base = client.build_request(
            "POST",
            "http://target/api/login",
            json={"username": "test", "password": "test"},
            headers={"X-API-Key": "secret"}
        )

        # Fuzz just the username field
        results = await batch_request(
            base,
            payloads=[
                {"json": {"username": "admin", "password": "test"}},
                {"json": {"username": "root", "password": "test"}},
            ],
            validate=lambda r: r.status_code == 200,
            proxy="http://127.0.0.1:8080",  # Send through Burp
            filter_matched=True,  # Only return successful logins
            drop_response=True  # Save memory for large scans
        )
    """
    semaphore = asyncio.Semaphore(concurrency)
    results = []
    cancel_event = asyncio.Event()

    async def send_request(payload: Dict[str, Any], client_kwargs: Dict) -> Optional[BatchResult]:
        # Check if we should cancel before starting
        if cancel_event.is_set():
            return None

        async with semaphore:
            try:
                # Check again after acquiring semaphore
                if cancel_event.is_set():
                    return None

                # Create a new client for each request to isolate cookies
                async with httpx.AsyncClient(**client_kwargs) as client:
                    # Build new request from base, overriding with payload
                    # Remove Content-Length if we're changing the body
                    headers = dict(base_request.headers)
                    if "json" in payload or "data" in payload or "content" in payload:
                        headers.pop("Content-Length", None)
                        # Only set Content-Type if not explicitly provided in payload headers
                        payload_headers = payload.get("headers", {})
                        if "Content-Type" not in payload_headers:
                            if "json" in payload:
                                headers["Content-Type"] = "application/json"
                            elif "data" in payload:
                                headers["Content-Type"] = "application/x-www-form-urlencoded"
                    # Payload headers override everything
                    headers.update(payload.get("headers", {}))

                    request = client.build_request(
                        method=payload.get("method", base_request.method),
                        url=payload.get("url", base_request.url),
                        params=payload.get("params"),
                        headers=headers,
                        cookies=payload.get("cookies"),
                        json=payload.get("json"),
                        data=payload.get("data"),
                        content=payload.get(
                            "content", base_request.content if not payload.get("json") and not payload.get("data") else None
                        ),
                    )

                    response = await client.send(request)
                    matched = validate(response)

                    # Capture cookies from client as dict (includes session cookies)
                    cookies = dict(client.cookies)

                    if matched:
                        if show_progress:
                            payload_str = _format_payload(payload)
                            out.success(f"Match found: {payload_str}")

                        # Set cancel event if stop_on_match is enabled
                        if stop_on_match:
                            cancel_event.set()

                    # Drop response body if requested (saves memory)
                    if drop_response:
                        response = None

                    return BatchResult(payload, response, matched, cookies=cookies)
            except Exception as e:
                if show_progress:
                    out.error(f"Request failed: {str(e)[:100]}")
                return BatchResult(payload, None, False, error=e)

    # Set default client kwargs
    if "verify" not in client_kwargs:
        client_kwargs["verify"] = False

    # Configure proxy if provided (only if not already in client_kwargs)
    if proxy and "proxies" not in client_kwargs:
        client_kwargs["proxy"] = Proxy(url=proxy)

    # Add timeout to client kwargs
    client_kwargs["timeout"] = timeout

    # Create tasks with client kwargs
    tasks = [send_request(payload, client_kwargs) for payload in payloads]
    results = await asyncio.gather(*tasks)

    # Filter out None results (cancelled tasks)
    results = [r for r in results if r is not None]

    # Filter to only matched results if requested
    if filter_matched:
        return [r for r in results if r.matched]

    return results


def batch_request_sync(
    base_request: httpx.Request,
    payloads: Iterator[Dict[str, Any]],
    validate: Callable[[httpx.Response], bool],
    **kwargs,
) -> List[BatchResult]:
    """
    Synchronous wrapper for batch_request.

    Example:
        client = httpx.Client()
        base = client.build_request(
            "POST",
            "http://target/login",
            json={"username": "test", "password": "test"}
        )

        results = batch_request_sync(
            base,
            payloads=generate_json_payloads("username", ["admin", "root", "test"]),
            validate=lambda r: "dashboard" in r.text,
            proxy="http://127.0.0.1:8080"  # Optional: route through Burp
        )
    """
    import asyncio

    return asyncio.run(batch_request(base_request, payloads, validate, **kwargs))


def _format_payload(payload: Dict[str, Any]) -> str:
    """Format payload dict for display."""
    if "params" in payload:
        return f"params={payload['params']}"
    elif "data" in payload:
        return f"data={payload['data']}"
    elif "json" in payload:
        return f"json={payload['json']}"
    elif "headers" in payload:
        # Only show custom headers
        return f"headers={payload['headers']}"
    else:
        return str(payload)[:100]


# Helper functions to generate common payload patterns


def generate_param_payloads(name: str, values: List[Any], base_params: Optional[Dict] = None) -> List[Dict]:
    """
    Generate payloads for testing different URL parameter values.

    Example:
        client = httpx.Client()
        base = client.build_request("GET", "http://target/api", params={"page": 1})

        payloads = generate_param_payloads("id", range(1, 100))
        results = batch_request_sync(base, payloads, validate=lambda r: r.status_code == 200)
    """
    base_params = base_params or {}
    return [{"params": {**base_params, name: v}} for v in values]


def generate_json_payloads(field: str, values: List[Any], base_json: Optional[Dict] = None) -> List[Dict]:
    """
    Generate payloads for testing different JSON field values.

    Example:
        payloads = generate_json_payloads("username", ["admin", "root", "test"])
        payloads = generate_json_payloads("role", ["user", "admin"], base_json={"active": True})
    """
    base_json = base_json or {}
    return [{"json": {**base_json, field: v}} for v in values]


def generate_data_payloads(field: str, values: List[Any], base_data: Optional[Dict] = None) -> List[Dict]:
    """
    Generate payloads for testing different form data values.

    Example:
        payloads = generate_data_payloads("password", ["admin", "password", "123456"])
        payloads = generate_data_payloads("user", sqli_payloads, base_data={"pass": "test"})
    """
    base_data = base_data or {}
    return [{"data": {**base_data, field: v}} for v in values]


def generate_header_payloads(header: str, values: List[Any], base_headers: Optional[Dict] = None) -> List[Dict]:
    """
    Generate payloads for testing different header values.

    Example:
        payloads = generate_header_payloads("X-Forwarded-For", ["127.0.0.1", "localhost", "192.168.1.1"])
        payloads = generate_header_payloads("Authorization", [f"Bearer {token}" for token in tokens])
    """
    base_headers = base_headers or {}
    return [{"headers": {**base_headers, header: str(v)}} for v in values]


def generate_cookie_payloads(name: str, values: List[Any], base_cookies: Optional[Dict] = None) -> List[Dict]:
    """
    Generate payloads for testing different cookie values.

    Example:
        payloads = generate_cookie_payloads("session", ["admin", "guest", "' OR '1'='1"])
    """
    base_cookies = base_cookies or {}
    return [{"cookies": {**base_cookies, name: str(v)}} for v in values]


def generate_method_payloads(methods: List[str]) -> List[Dict]:
    """
    Generate payloads for testing different HTTP methods.

    Example:
        payloads = generate_method_payloads(["GET", "POST", "PUT", "DELETE", "OPTIONS"])
        results = batch_request_sync(
            base,
            payloads=payloads,
            validate=lambda r: r.status_code != 405
        )
    """
    return [{"method": method} for method in methods]


def generate_path_payloads(paths: List[str], base_url: Optional[str] = None) -> List[Dict]:
    """
    Generate payloads for testing different URL paths.

    Example:
        # Test different API endpoints
        payloads = generate_path_payloads([
            "/api/v1/users",
            "/api/v2/users",
            "/api/users",
            "/.git/config"
        ])

        # Or with base URL
        payloads = generate_path_payloads(
            ["1", "2", "999999", "../admin"],
            base_url="http://target/api/users/"
        )
    """
    if base_url:
        return [{"url": base_url.rstrip("/") + "/" + path.lstrip("/")} for path in paths]
    return [{"url": path} for path in paths]


def generate_multi_payloads(payloads_dict: Dict[str, List[Any]], base_kwargs: Optional[Dict] = None) -> List[Dict]:
    """
    Generate payloads for multiple positions (like Burp Pitchfork).

    Example:
        payloads = generate_multi_payloads({
            "data": [{"user": "admin", "pass": "admin"}, {"user": "root", "pass": "root"}],
            "headers": [{"X-Token": "abc"}, {"X-Token": "xyz"}]
        })
    """
    from itertools import product

    base_kwargs = base_kwargs or {}

    # Get all combinations
    keys = list(payloads_dict.keys())
    values = [payloads_dict[k] for k in keys]

    results = []
    for combo in product(*values):
        payload = dict(base_kwargs)
        for i, key in enumerate(keys):
            if key in payload:
                payload[key] = {**payload[key], **combo[i]}
            else:
                payload[key] = combo[i]
        results.append(payload)

    return results
