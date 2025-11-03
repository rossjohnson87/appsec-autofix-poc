import os, re, json, socket, ipaddress, urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DB_FILE = ROOT / "app" / "db.py"
HTTP_FILE = ROOT / "app" / "http_client.py"
TESTS_DIR = ROOT / "tests"
SEMGR_JSON = ROOT / "semgrep-latest.json"

def patch_db_sql_injection(fp: Path) -> bool:
    if not fp.exists():
        return False
    txt = fp.read_text(encoding="utf-8")

    # already parameterized?
    if "WHERE email = ?" in txt:
        return False

    # locate function block
    start = txt.find("def get_user_by_email")
    if start == -1:
        return False
    # find the end of the function: next 'def ' at col 0 or EOF
    m = re.search(r"\ndef\s+\w+\(", txt[start+1:])
    end = len(txt) if not m else start + 1 + m.start()

    safe_impl = (
        "def get_user_by_email(email: str):\n"
        "    q = \"SELECT id, email, name FROM users WHERE email = ?\"\n"
        "    conn = sqlite3.connect(DB_PATH)\n"
        "    cur = conn.cursor()\n"
        "    cur.execute(q, (email,))\n"
        "    row = cur.fetchone()\n"
        "    conn.close()\n"
        "    return row\n"
    )

    new = txt[:start] + safe_impl + txt[end:]
    fp.write_text(new, encoding="utf-8")
    print(f"[autofix] SQLi patched in {fp}")
    return True

def ensure_http_imports(txt: str) -> str:
    # ensure standard lib imports exist
    add = []
    if "import urllib.parse" not in txt:
        add.append("import urllib.parse")
    if "import socket" not in txt:
        add.append("import socket")
    if "import ipaddress" not in txt:
        add.append("import ipaddress")
    if not add:
        return txt
    # insert after 'import requests'
    lines = txt.splitlines()
    out = []
    inserted = False
    for line in lines:
        out.append(line)
        if not inserted and line.strip().startswith("import requests"):
            for a in add:
                out.append(a)
            inserted = True
    if not inserted:
        out = add + [""] + lines
    return "\n".join(out) + ("\n" if not txt.endswith("\n") else "")

def patch_http_ssrf(fp: Path) -> bool:
    if not fp.exists():
        return False
    txt = fp.read_text(encoding="utf-8")
    if "Blocked internal address" in txt or "Invalid scheme" in txt:
        return False  # already patched

    txt = ensure_http_imports(txt)

    start = txt.find("def fetch_url(")
    if start == -1:
        return False
    m = re.search(r"\ndef\s+\w+\(", txt[start+1:])
    end = len(txt) if not m else start + 1 + m.start()

    safe_impl = (
        "def fetch_url(url: str):\n"
        "    # Basic SSRF protections for demo: scheme allowlist + block private/loopback\n"
        "    try:\n"
        "        parsed = urllib.parse.urlparse(url)\n"
        "        if parsed.scheme not in (\"http\", \"https\"):\n"
        "            return \"Invalid scheme\", 400\n"
        "        host = parsed.hostname\n"
        "        if not host:\n"
        "            return \"Invalid host\", 400\n"
        "        try:\n"
        "            ip = socket.gethostbyname(host)\n"
        "            ip_obj = ipaddress.ip_address(ip)\n"
        "            if ip_obj.is_private or ip_obj.is_loopback:\n"
        "                return \"Blocked internal address\", 403\n"
        "        except Exception:\n"
        "            return \"Unresolvable host\", 400\n"
        "        # Fetch with short timeout\n"
        "        import requests\n"
        "        r = requests.get(url, timeout=3)\n"
        "        return r.text[:2000], r.status_code\n"
        "    except Exception as e:\n"
        "        return str(e), 502\n"
    )

    new = txt[:start] + safe_impl + txt[end:]
    fp.write_text(new, encoding="utf-8")
    print(f\"[autofix] SSRF mitigations added in {fp}\")
    return True

def write_tests(dirp: Path) -> bool:
    dirp.mkdir(exist_ok=True)
    test_path = dirp / "test_autofix.py"
    if test_path.exists():
        return False
    content = (
        "from app.db import init_db, get_user_by_email\n"
        "from app.http_client import fetch_url\n\n"
        "def test_sql_injection_blocked():\n"
        "    init_db()\n"
        "    r = get_user_by_email('alice@example.com')\n"
        "    assert r and r[1] == 'alice@example.com'\n"
        "    # classic injection payload should NOT match anything after fix\n"
        "    assert get_user_by_email(\"alice@example.com' OR '1'='1\") is None\n\n"
        "def test_ssrf_blocks_private():\n"
        "    content, status = fetch_url('http://127.0.0.1/')\n"
        "    assert status in (400, 403)\n"
    )
    test_path.write_text(content, encoding="utf-8")
    print(f\"[autofix] Added tests -> {test_path}\")
    return True

def semgrep_summary():
    if SEMGR_JSON.exists():
        try:
            data = json.loads(SEMGR_JSON.read_text(encoding=\"utf-8\"))
            ids = sorted({r.get(\"check_id\") for r in data.get(\"results\", [])})
            print(f\"[autofix] semgrep findings: {ids}\")
        except Exception:
            pass

def main():
    semgrep_summary()
    changed = False
    changed |= patch_db_sql_injection(DB_FILE)
    changed |= patch_http_ssrf(HTTP_FILE)
    changed |= write_tests(TESTS_DIR)
    if changed:
        print(\"[autofix] Changes applied; PR will be opened by the workflow.\")
    else:
        print(\"[autofix] No changes needed; nothing to commit.\")

if __name__ == \"__main__\":
    main()
