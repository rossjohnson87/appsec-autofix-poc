from app.db import init_db, get_user_by_email
from app.http_client import fetch_url

def test_sql_injection_blocked():
    init_db()
    r = get_user_by_email('alice@example.com')
    assert r and r[1] == 'alice@example.com'
    # classic injection payload should NOT match anything after fix
    assert get_user_by_email("alice@example.com' OR '1'='1") is None

def test_ssrf_blocks_private():
    content, status = fetch_url('http://127.0.0.1/')
    assert status in (400, 403)
