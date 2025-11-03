import requests
import urllib.parse
import socket
import ipaddress

def fetch_url(url: str):
    # Basic SSRF protections for demo: scheme allowlist + block private/loopback
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return "Invalid scheme", 400
        host = parsed.hostname
        if not host:
            return "Invalid host", 400
        try:
            ip = socket.gethostbyname(host)
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_loopback:
                return "Blocked internal address", 403
        except Exception:
            return "Unresolvable host", 400
        import requests
        r = requests.get(url, timeout=3)
        return r.text[:2000], r.status_code
    except Exception as e:
        return str(e), 502
