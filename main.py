from __future__ import annotations

import csv
import io
import json
import os
import re
import socket
import ssl
import sqlite3
import time
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path
from typing import Any
from urllib.parse import quote

import dns.resolver
import requests
from dotenv import load_dotenv
from email_validator import EmailNotValidError, validate_email
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")
DB_PATH = Path(os.getenv("DATABASE_PATH") or BASE_DIR / "osint_history.db")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "").strip()
YOUTUBE_API_KEY = os.getenv("YOUTUBE_API_KEY", "").strip()
CORS_ORIGINS = [
    origin.strip()
    for origin in os.getenv("CORS_ORIGINS", "").split(",")
    if origin.strip()
]

app = FastAPI(title="OSINT Explorer", version="1.0.0",
              description="Local educational OSINT checks; use only with authorization.")
if CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ORIGINS,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["Content-Type"],
    )
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

# Deliberately small, explicit allowlist. No arbitrary URL fetching.
PROFILE_SITES = {
    "Instagram": "https://www.instagram.com/{username}/",
    "Reddit": "https://www.reddit.com/user/{username}/",
    "LinkedIn": "https://www.linkedin.com/in/{username}/",
    "TikTok": "https://www.tiktok.com/@{username}",
    "Keybase": "https://keybase.io/{username}",
}
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,50}$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(?:\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))+$")

class ScanRequest(BaseModel):
    kind: str = Field(pattern="^(username|email|domain)$")
    target: str = Field(min_length=1, max_length=253)

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def db_connect():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    with db_connect() as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                result_json TEXT NOT NULL
            )
        """)

init_db()

def save_scan(kind: str, target: str, result: dict[str, Any]) -> dict[str, Any]:
    with db_connect() as con:
        cur = con.execute(
            "INSERT INTO scans(kind,target,status,created_at,result_json) VALUES(?,?,?,?,?)",
            (kind, target, result.get("status", "complete"), utc_now(),
             json.dumps(result, ensure_ascii=False))
        )
        scan_id = cur.lastrowid
    return {"id": scan_id, "kind": kind, "target": target,
            "created_at": utc_now(), "result": result}

def normalize_domain(raw: str) -> str:
    value = raw.strip().rstrip(".")
    if "://" in value or "/" in value or ":" in value or not DOMAIN_RE.fullmatch(value):
        raise ValueError("Enter a hostname only, e.g. example.com — no URL, path, or port.")
    value = value.lower()
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Invalid internationalized domain name.") from exc
    return value

def resolve_public_domain(domain: str) -> list[str]:
    try:
        answers = socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"DNS resolution failed: {exc}") from exc
    ips = sorted({item[4][0].split("%")[0] for item in answers})
    if not ips:
        raise ValueError("No A/AAAA addresses found.")
    for value in ips:
        ip = ip_address(value)
        if not ip.is_global:
            raise ValueError("Domain resolves to a non-public IP address; refusing to scan.")
    return ips

def dns_records(domain: str) -> dict[str, Any]:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 3.0
    result: dict[str, Any] = {}
    for record_type in ("A", "AAAA", "MX", "NS", "TXT"):
        try:
            answer = resolver.resolve(domain, record_type, raise_on_no_answer=False)
            if answer.rrset is None:
                result[record_type] = []
            elif record_type == "MX":
                result[record_type] = [str(r.exchange).rstrip(".") + f" (priority {r.preference})" for r in answer]
            elif record_type == "TXT":
                result[record_type] = [r.to_text() for r in answer]
            else:
                result[record_type] = [str(r).rstrip(".") for r in answer]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            result[record_type] = []
        except Exception as exc:
            result[record_type] = {"error": str(exc)}
    return result

def check_tls(domain: str) -> dict[str, Any]:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=domain) as conn:
                cert = conn.getpeercert()
                return {
                    "status": "valid",
                    "tls_version": conn.version(),
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "not_after": cert.get("notAfter"),
                    "subject_alt_names": [v for typ, v in cert.get("subjectAltName", []) if typ == "DNS"][:20],
                }
    except Exception as exc:
        return {"status": "error", "message": str(exc)}

def scan_domain(raw: str) -> dict[str, Any]:
    domain = normalize_domain(raw)
    ips = resolve_public_domain(domain)
    records = dns_records(domain)
    tls = check_tls(domain)
    https: dict[str, Any]
    try:
        # Redirects disabled so a public host cannot redirect the scanner to a private target.
        response = requests.get(f"https://{domain}/", timeout=7, allow_redirects=False,
                                headers={"User-Agent": "OSINT-Explorer-Educational/1.0"})
        https = {
            "status_code": response.status_code,
            "server_replied": True,
            "redirect_location": response.headers.get("Location"),
            "redirects_followed": False,
        }
    except requests.RequestException as exc:
        https = {"server_replied": False, "message": str(exc), "redirects_followed": False}
    return {
        "status": "complete",
        "summary": f"Completed DNS and HTTPS/TLS checks for {domain}.",
        "domain": domain,
        "resolved_ips": ips,
        "dns_records": records,
        "https": https,
        "tls": tls,
        "note": "A valid TLS certificate is one signal, not a full security audit.",
    }

def check_github(username: str) -> dict[str, Any]:
    profile_url = f"https://github.com/{quote(username, safe='')}"
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "OSINT-Explorer-Educational/1.0",
    }
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    try:
        response = requests.get(
            f"https://api.github.com/users/{quote(username, safe='')}",
            headers=headers,
            timeout=8,
        )
        if response.status_code == 200:
            user = response.json()
            if (
                isinstance(user, dict)
                and isinstance(user.get("login"), str)
                and user["login"].casefold() == username.casefold()
            ):
                return {
                    "source": "GitHub",
                    "url": profile_url,
                    "status": "found",
                    "http_status": response.status_code,
                    "method": "official_api",
                    "evidence": "GitHub public Users API returned an exact username match.",
                    "profile": {
                        "login": user.get("login"),
                        "name": user.get("name"),
                        "bio": user.get("bio"),
                        "public_repos": user.get("public_repos"),
                        "followers": user.get("followers"),
                        "created_at": user.get("created_at"),
                    },
                }
            return {
                "source": "GitHub",
                "url": profile_url,
                "status": "inconclusive",
                "http_status": response.status_code,
                "method": "official_api",
                "evidence": "GitHub API returned an unexpected or non-matching user object.",
            }
        if response.status_code == 404:
            status = "not_found"
            evidence = "GitHub API returned HTTP 404 for this username."
        else:
            status = "inconclusive"
            evidence = f"GitHub API returned HTTP {response.status_code}; access restrictions or rate limits may prevent a conclusion."
        return {
            "source": "GitHub",
            "url": profile_url,
            "status": status,
            "http_status": response.status_code,
            "method": "official_api",
            "evidence": evidence,
        }
    except (requests.RequestException, ValueError) as exc:
        return {
            "source": "GitHub",
            "url": profile_url,
            "status": "inconclusive",
            "method": "official_api",
            "evidence": str(exc),
        }

def check_gitlab(username: str) -> dict[str, Any]:
    profile_url = f"https://gitlab.com/{quote(username, safe='')}"
    try:
        response = requests.get(
            "https://gitlab.com/api/v4/users",
            params={"username": username},
            headers={"User-Agent": "OSINT-Explorer-Educational/1.0"},
            timeout=8,
        )
        if response.status_code == 200:
            users = response.json()
            if not isinstance(users, list):
                raise ValueError("GitLab returned an unexpected response.")
            match = next(
                (
                    user
                    for user in users
                    if isinstance(user, dict)
                    and isinstance(user.get("username"), str)
                    and user["username"].casefold() == username.casefold()
                ),
                None,
            )
            if match:
                return {
                    "source": "GitLab",
                    "url": profile_url,
                    "status": "found",
                    "http_status": response.status_code,
                    "method": "official_api",
                    "evidence": "GitLab public Users API returned an exact username match.",
                    "profile": {
                        "username": match.get("username"),
                        "name": match.get("name"),
                        "state": match.get("state"),
                        "avatar_url": match.get("avatar_url"),
                    },
                }
            return {
                "source": "GitLab",
                "url": profile_url,
                "status": "not_found",
                "http_status": response.status_code,
                "method": "official_api",
                "evidence": "GitLab API returned no exact username match.",
            }
        return {
            "source": "GitLab",
            "url": profile_url,
            "status": "inconclusive",
            "http_status": response.status_code,
            "method": "official_api",
            "evidence": f"GitLab API returned HTTP {response.status_code}.",
        }
    except (requests.RequestException, ValueError) as exc:
        return {
            "source": "GitLab",
            "url": profile_url,
            "status": "inconclusive",
            "method": "official_api",
            "evidence": str(exc),
        }

def check_youtube(username: str) -> dict[str, Any]:
    base = {
        "source": "YouTube",
        "url": "https://www.youtube.com/results?search_query=" + quote(username),
        "method": "official_api",
    }
    if not YOUTUBE_API_KEY:
        return {
            **base,
            "status": "inconclusive",
            "evidence": "YOUTUBE_API_KEY is not configured; YouTube search was not run.",
        }
    try:
        response = requests.get(
            "https://www.googleapis.com/youtube/v3/search",
            params={
                "part": "snippet",
                "type": "channel",
                "q": username,
                "maxResults": 10,
                "key": YOUTUBE_API_KEY,
            },
            timeout=10,
        )
        if response.status_code != 200:
            return {
                **base,
                "status": "inconclusive",
                "http_status": response.status_code,
                "evidence": f"YouTube API returned HTTP {response.status_code}; check the key, quota, and API enablement.",
            }
        data = response.json()
        if not isinstance(data, dict) or not isinstance(data.get("items", []), list):
            raise ValueError("YouTube API returned an unexpected response.")
        matches = []
        for item in data.get("items", []):
            if not isinstance(item, dict):
                continue
            channel = item.get("id")
            snippet = item.get("snippet", {})
            if (
                not isinstance(channel, dict)
                or not isinstance(snippet, dict)
                or not isinstance(channel.get("channelId"), str)
            ):
                continue
            channel_id = channel["channelId"]
            matches.append({
                "title": snippet.get("title"),
                "channel_id": channel_id,
                "url": f"https://www.youtube.com/channel/{quote(channel_id, safe='')}",
                "description": str(snippet.get("description", ""))[:300],
            })
        evidence = (
            "Search results are candidate channels, not proof of an exact username or account owner."
            if matches
            else "No channels were returned for this query; absence is not proof that an account does not exist."
        )
        return {
            **base,
            "status": "inconclusive",
            "http_status": response.status_code,
            "evidence": evidence,
            "matches": matches,
        }
    except requests.RequestException as exc:
        return {
            **base,
            "status": "inconclusive",
            "evidence": f"YouTube API request failed ({type(exc).__name__}).",
        }
    except ValueError:
        return {
            **base,
            "status": "inconclusive",
            "evidence": "YouTube API returned an invalid response.",
        }

def scan_username(raw: str) -> dict[str, Any]:
    username = raw.strip().lstrip("@")
    if not USERNAME_RE.fullmatch(username):
        raise ValueError("Use 1–50 letters, numbers, dots, underscores, or hyphens.")
    checks = [
        check_github(username),
        check_gitlab(username),
        check_youtube(username),
    ]
    for site, template in PROFILE_SITES.items():
        url = template.format(username=quote(username, safe="._-"))
        try:
            response = requests.get(url, timeout=6, allow_redirects=False,
                                    headers={"User-Agent": "OSINT-Explorer-Educational/1.0"})
            status = "not_found" if response.status_code == 404 else "inconclusive"
            detail = (
                "Public profile URL returned HTTP 404; this is a limited signal."
                if response.status_code == 404
                else f"HTTP {response.status_code}; public page checks cannot reliably confirm account existence."
            )
            checks.append({"source": site, "url": url, "status": status,
                           "http_status": response.status_code, "detail": detail,
                           "method": "public_url_check"})
        except requests.RequestException as exc:
            checks.append({"source": site, "url": url, "status": "inconclusive",
                           "detail": str(exc), "method": "public_url_check"})
    found = sum(c["status"] == "found" for c in checks)
    not_found = sum(c["status"] == "not_found" for c in checks)
    inconclusive = sum(c["status"] == "inconclusive" for c in checks)
    return {
        "status": "complete",
        "summary": f"Checked {len(checks)} sources for {username}: {found} found signal(s), {not_found} not-found signal(s), {inconclusive} inconclusive.",
        "username": username,
        "checks": checks,
        "note": "Official API matches and YouTube search results are public signals, not identity proof. YouTube results are candidates; generic profile pages and HTTP 200 responses are inconclusive.",
    }

def scan_email(raw: str) -> dict[str, Any]:
    try:
        email = validate_email(raw.strip(), check_deliverability=False).normalized
    except EmailNotValidError as exc:
        raise ValueError(f"Invalid email: {exc}") from exc

    url = "https://api.xposedornot.com/v1/check-email/" + quote(
        email, safe="@._+-"
    )
    result: dict[str, Any] = {
        "status": "complete",
        "email": email,
        "syntax_valid": True,
        "breach_source": "XposedOrNot",
        "privacy_notice": "The email is sent to XposedOrNot for lookup.",
    }
    try:
        response = requests.get(
            url,
            params={"details": "true"},
            headers={
                "User-Agent": "OSINT-Explorer-Educational/1.0",
                "Accept": "application/json",
            },
            timeout=10,
        )

        if response.status_code == 429:
            result["breach_lookup"] = {
                "status": "rate_limited",
                "message": "Free API limit reached. Try later.",
            }
            result["summary"] = "Lookup rate limited."
            return result

        if response.status_code != 200:
            result["breach_lookup"] = {
                "status": "error",
                "message": f"API returned HTTP {response.status_code}",
            }
            result["summary"] = "Lookup failed."
            return result

        data = response.json()
        if not isinstance(data, dict) or not isinstance(data.get("breaches", []), list):
            result["breach_lookup"] = {
                "status": "error",
                "message": "XposedOrNot returned an unexpected response.",
            }
            result["summary"] = "Lookup failed."
            return result

        names = [
            item
            for entry in data.get("breaches", [])
            for item in (entry if isinstance(entry, list) else [entry])
            if isinstance(item, str) and item.strip()
        ]

        names = list(dict.fromkeys(names))
        result["breach_lookup"] = {
            "status": "breaches_reported" if names else "no_breaches_returned",
            "count": len(names),
            "breaches": [{"name": name} for name in names],
            "message": (
                "Breach records returned by XposedOrNot."
                if names
                else "No matching records returned; this does not prove the email was never exposed."
            ),
        }
        result["summary"] = (
            f"{len(names)} breach name(s) returned."
            if names
            else "No matching breach records returned."
        )
    except requests.RequestException as exc:
        result["breach_lookup"] = {
            "status": "error",
            "message": str(exc),
        }
        result["summary"] = "Lookup failed."
    except ValueError as exc:
        result["breach_lookup"] = {
            "status": "error",
            "message": str(exc),
        }
        result["summary"] = "Lookup failed."
    return result

@app.get("/")
def home():
    return FileResponse(BASE_DIR / "static" / "index.html")

@app.get("/api/health")
def health():
    return {
        "ok": True,
        "breach_provider": "XposedOrNot",
        "github_token_configured": bool(GITHUB_TOKEN),
        "youtube_api_key_configured": bool(YOUTUBE_API_KEY),
        "time": utc_now(),
    }

@app.post("/api/scan")
def create_scan(payload: ScanRequest):
    target = payload.target.strip()
    try:
        if payload.kind == "username":
            result = scan_username(target)
        elif payload.kind == "email":
            result = scan_email(target)
        elif payload.kind == "domain":
            result = scan_domain(target)
        else:
            raise ValueError("Unsupported scan type.")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        # Keep unexpected errors explicit rather than manufacturing a finding.
        result = {"status": "error", "summary": "Scan failed.", "error": str(exc)}
    saved = save_scan(payload.kind, target, result)
    return saved

@app.get("/api/history")
def history(limit: int = 100):
    limit = max(1, min(limit, 250))
    with db_connect() as con:
        rows = con.execute(
            "SELECT id,kind,target,status,created_at FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(row) for row in rows]

@app.get("/api/reports/{scan_id}")
def get_report(scan_id: int):
    with db_connect() as con:
        row = con.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Report not found.")
    return {"id": row["id"], "kind": row["kind"], "target": row["target"],
            "status": row["status"], "created_at": row["created_at"],
            "result": json.loads(row["result_json"])}

@app.get("/api/reports/{scan_id}/csv")
def csv_report(scan_id: int):
    report = get_report(scan_id)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["scan_id", "kind", "target", "status", "created_at", "result_json"])
    writer.writerow([report["id"], report["kind"], report["target"], report["status"],
                     report["created_at"], json.dumps(report["result"], ensure_ascii=False)])
    output.seek(0)
    filename = f"osint-report-{scan_id}.csv"
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": f'attachment; filename="{filename}"'})

@app.delete("/api/history/{scan_id}")
def delete_history_item(scan_id: int):
    with db_connect() as con:
        cur = con.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="History item not found.")
    return {"deleted": True, "id": scan_id}
