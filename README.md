# OSINT Explorer — local educational project

A local-first educational OSINT dashboard inspired by public-data search tools. It runs real checks and does not generate mock findings.

## Features
- Username checks against a small, explicit list of public profile URL templates.
- Email syntax validation and XposedOrNot breach lookup.
- Domain DNS (A, AAAA, MX, NS, TXT), HTTPS response and TLS certificate checks.
- SQLite scan history, JSON report view, CSV export.
- Clear `found`, `not_found`, `inconclusive`, and `error` statuses.

## Requirements
- Python 3.11+ recommended
- Windows 10/11 and VS Code
- Internet connection for live checks

## Windows setup (PowerShell, in VS Code terminal)
```powershell
cd osint-explorer
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```
If PowerShell blocks activation, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in that terminal, then activate again.

Open http://127.0.0.1:8000. API documentation is at http://127.0.0.1:8000/docs.

## Email breach lookup
Email scans send the address to XposedOrNot's public endpoint (`/v1/check-email/`) for lookup. Its free API has per-IP rate limits; a `429` response is shown as rate-limited rather than as a finding. Non-200 responses are shown as lookup errors. A successful empty response means no matching records were returned; it does not prove the address was never exposed.

## Test
In a second terminal with the virtual environment active:
```powershell
python -m unittest discover -s tests -v
```
The tests exercise input validation and report helpers without making external network calls.

## Safe use and limits
- Use only on accounts you own or have permission to assess, and respect each platform's terms and rate limits.
- Username checks only request profile pages from the hard-coded allowlist in `main.py`. A `403`, `429`, challenge page, or timeout is `inconclusive`, not a match.
- Username availability is not identity proof. `found` means the URL returned a normal successful response, not that an account belongs to a particular person.
- Domain checks are for domains you own or are authorized to assess. The backend rejects localhost, private, loopback, link-local, reserved, and non-public IP resolutions to reduce SSRF risk. Redirects are not followed.
- This is a local educational prototype, not a production multi-user service. Do not expose it publicly without authentication, rate limiting, security review, and stronger isolation.
- Scan history stores targets and findings in `osint_history.db`. Delete that file to erase local history.
