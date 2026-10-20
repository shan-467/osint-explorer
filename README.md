# OSINT Explorer — local educational project

A local-first educational OSINT dashboard inspired by public-data search tools. It runs real checks and does not generate mock findings.

## Features
- Username checks against GitHub and GitLab official public APIs, plus evidence-limited public profile checks for Instagram, Reddit, LinkedIn, TikTok, and Keybase.
- Optional YouTube channel search using the official YouTube Data API; results are candidate channels, not exact username matches.
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

## GitHub Pages
GitHub Pages publishes the static dashboard from `static/` at the repository site root. To enable scans, sign in to Render and [deploy this repository as a Render Blueprint](https://render.com/deploy?repo=https://github.com/shan-467/osint-explorer), which uses the included `render.yaml`. Then enter the service's HTTPS URL in the dashboard's **Backend URL** field. The browser saves this URL locally. The Render service allows browser requests from this Pages origin only; CORS is not authentication, so the hosted API is still publicly callable by non-browser clients. The free Render service may sleep when idle, so its first request can take a minute; its temporary filesystem does not retain scan history across restarts or deployments. Use a persistent disk and set `DATABASE_PATH` to keep hosted history, or run the app locally for persistent SQLite history.

## Email breach lookup
Email scans send the address to XposedOrNot's public endpoint (`/v1/check-email/`) for lookup. Its free API has per-IP rate limits; a `429` response is shown as rate-limited rather than as a finding. Non-200 responses are shown as lookup errors. A successful empty response means no matching records were returned; it does not prove the address was never exposed.

## Optional username API configuration
- `GITHUB_TOKEN` is optional and only sent to GitHub's public Users API to increase its authenticated rate limit. Keep it in `.env`, never in frontend code or Git.
- `YOUTUBE_API_KEY` is optional. Enable YouTube Data API v3 in Google Cloud and set the key in `.env`. A username scan makes one channel-search API request when configured; check Google's current quota and restrict the key in Google Cloud Console.
- Instagram, LinkedIn, TikTok, Reddit, and Keybase checks use fixed public profile URLs. These pages may be generic, gated, or challenge pages; HTTP 200 is treated as inconclusive. A returned username match is not proof of identity.
- For a Render deployment, configure optional API keys in the Render service's environment settings; do not put them in the Pages frontend.

## Test
In a second terminal with the virtual environment active:
```powershell
python -m unittest discover -s tests -v
```
The tests exercise input validation and report helpers without making external network calls.

## Safe use and limits
- Use only on accounts you own or have permission to assess, and respect each platform's terms and rate limits.
- Username checks only contact fixed, documented API hosts and profile URL templates in `main.py`. A `403`, `429`, challenge page, generic page, or timeout is `inconclusive`, not a match.
- Username availability is not identity proof. `found` is reserved for exact public API username objects; YouTube search results and profile-page responses are not treated as identity matches.
- Domain checks are for domains you own or are authorized to assess. The backend rejects localhost, private, loopback, link-local, reserved, and non-public IP resolutions to reduce SSRF risk. Redirects are not followed.
- This is a local educational prototype, not a production multi-user service. Do not expose it publicly without authentication, rate limiting, security review, and stronger isolation.
- Scan history stores targets and findings in `osint_history.db`. Delete that file to erase local history.
