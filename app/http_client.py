import requests

def fetch_url(url: str):
    # INTENTIONALLY INSECURE: no validation (SSRF)
    try:
        r = requests.get(url, timeout=3)
        return r.text[:2000], r.status_code
    except Exception as e:
        return str(e), 502
