# AppSec Auto-Fix PR POC (Toy Service)

A tiny Flask app with **intentional vulnerabilities**:
- SQL injection in `app/db.py` (`get_user_by_email`)
- SSRF in `app/http_client.py` (`fetch_url`)

This repo will be used to demo a Semgrep → LLM → Auto-fix PR flow.

## Quick start (Windows)
```powershell
python -m venv .venv
.\.venv\Scripts\Activate
pip install -r requirements.txt
python -m app.server
# Then open:
# http://127.0.0.1:5000/user?email=alice@example.com
# http://127.0.0.1:5000/fetch?url=http://example.com
