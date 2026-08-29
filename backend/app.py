import base64
import hashlib
import json
import os
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import httpx
from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

GITHUB_API = "https://api.github.com"
GITHUB_OWNER = "davidetonelli"
GITHUB_REPO = "dnd"
ALLOWED_LOGIN = "davidetonelli"
CLIENT_ID = os.getenv("GITHUB_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET", "")
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "https://davidetonelli.github.io").rstrip("/")
DB_PATH = Path(os.getenv("SESSION_DB", str(Path.home() / ".local/share/dnd-save/sessions.sqlite3")))
CHARACTERS = {"olga": ("data.js", "OLGA_DATA"), "ossian": ("ossian/data.js", "OSSIAN_DATA")}

app = FastAPI(title="D&D character save service", docs_url=None, redoc_url=None)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_ORIGIN],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
    max_age=600,
)


def db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("CREATE TABLE IF NOT EXISTS oauth_states (state TEXT PRIMARY KEY, verifier TEXT NOT NULL, expires INTEGER NOT NULL, return_to TEXT NOT NULL DEFAULT '/dnd/')")
    columns = {row[1] for row in conn.execute("PRAGMA table_info(oauth_states)")}
    if "return_to" not in columns:
        conn.execute("ALTER TABLE oauth_states ADD COLUMN return_to TEXT NOT NULL DEFAULT '/dnd/'")
    conn.execute("CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, token TEXT NOT NULL, login TEXT NOT NULL, expires INTEGER NOT NULL)")
    conn.execute("DELETE FROM oauth_states WHERE expires < ?", (int(time.time()),))
    conn.execute("DELETE FROM sessions WHERE expires < ?", (int(time.time()),))
    conn.commit()
    return conn


def safe_return_to(value: str | None) -> str:
    return value if value in {"/dnd/", "/dnd/ossian/"} else "/dnd/"


def resolve_character(character: str) -> tuple[str, str]:
    if character not in CHARACTERS:
        raise ValueError("unknown character")
    return CHARACTERS[character]


def validate_character(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("data must be an object")
    if len(json.dumps(value, ensure_ascii=False).encode()) > 200_000:
        raise ValueError("payload too large")
    if not isinstance(value.get("character"), dict) or not str(value["character"].get("name", "")).strip():
        raise ValueError("character.name is required")
    for key in ("abilities", "spells", "traits", "slots"):
        if not isinstance(value.get(key), list):
            raise ValueError(f"{key} must be an array")
    ids: set[str] = set()
    for spell in value["spells"]:
        if not isinstance(spell, dict):
            raise ValueError("spell must be an object")
        spell_id = str(spell.get("id", "")).strip()
        if not spell_id or not str(spell.get("name", "")).strip():
            raise ValueError("spell id and name are required")
        if spell_id in ids:
            raise ValueError(f"duplicate spell id: {spell_id}")
        ids.add(spell_id)
    return value


def parse_update_result(payload: dict[str, Any], path: str) -> dict[str, str]:
    return {"ok": "true", "commit": payload["commit"]["sha"], "sha": payload["content"]["sha"], "path": path}


def render_data_js(variable: str, data: dict[str, Any]) -> str:
    return f"window.{variable}={json.dumps(data, ensure_ascii=False, separators=(',', ':'))};\n"


def bearer(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "GitHub login required")
    session_id = authorization[7:].strip()
    with db() as conn:
        row = conn.execute("SELECT token, login FROM sessions WHERE id=? AND expires>=?", (session_id, int(time.time()))).fetchone()
    if not row or row[1].lower() != ALLOWED_LOGIN:
        raise HTTPException(401, "GitHub login required")
    return row[0]


async def github(method: str, url: str, token: str, **kwargs: Any) -> httpx.Response:
    headers = kwargs.pop("headers", {})
    headers.update({"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
    async with httpx.AsyncClient(timeout=20) as client:
        return await client.request(method, url, headers=headers, **kwargs)


class SaveBody(BaseModel):
    data: dict[str, Any]
    sha: str | None = None


@app.get("/health")
def health() -> dict[str, bool]:
    return {"ok": True}


@app.get("/auth/login")
def auth_login(return_to: str | None = Query(default=None)) -> RedirectResponse:
    if not CLIENT_ID or not PUBLIC_BASE_URL:
        raise HTTPException(503, "OAuth is not configured")
    state = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    with db() as conn:
        conn.execute("INSERT INTO oauth_states(state,verifier,expires,return_to) VALUES(?,?,?,?)", (state, verifier, int(time.time()) + 600, safe_return_to(return_to)))
        conn.commit()
    query = urlencode({"client_id": CLIENT_ID, "redirect_uri": f"{PUBLIC_BASE_URL}/auth/callback", "scope": "public_repo", "state": state, "code_challenge": challenge, "code_challenge_method": "S256", "allow_signup": "false"})
    return RedirectResponse(f"https://github.com/login/oauth/authorize?{query}")


@app.get("/auth/callback")
async def auth_callback(code: str = Query(...), state: str = Query(...)) -> RedirectResponse:
    with db() as conn:
        row = conn.execute("SELECT verifier, return_to FROM oauth_states WHERE state=? AND expires>=?", (state, int(time.time()))).fetchone()
        conn.execute("DELETE FROM oauth_states WHERE state=?", (state,))
        conn.commit()
    if not row:
        raise HTTPException(400, "Invalid or expired OAuth state")
    async with httpx.AsyncClient(timeout=20) as client:
        response = await client.post("https://github.com/login/oauth/access_token", headers={"Accept": "application/json"}, data={"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, "code": code, "redirect_uri": f"{PUBLIC_BASE_URL}/auth/callback", "code_verifier": row[0]})
    payload = response.json()
    token = payload.get("access_token")
    if not token:
        raise HTTPException(502, "GitHub did not issue an access token")
    user_response = await github("GET", f"{GITHUB_API}/user", token)
    if user_response.status_code != 200:
        raise HTTPException(502, "Could not verify GitHub account")
    login = str(user_response.json().get("login", "")).lower()
    if login != ALLOWED_LOGIN:
        raise HTTPException(403, "This GitHub account is not allowed")
    session_id = secrets.token_urlsafe(48)
    with db() as conn:
        conn.execute("INSERT INTO sessions(id,token,login,expires) VALUES(?,?,?,?)", (session_id, token, login, int(time.time()) + 8 * 3600))
        conn.commit()
    return RedirectResponse(f"{FRONTEND_ORIGIN}{safe_return_to(row[1])}?github_session={session_id}")


@app.get("/api/me")
def me(authorization: str | None = Header(default=None)) -> dict[str, str]:
    bearer(authorization)
    return {"login": ALLOWED_LOGIN}


@app.get("/api/source/{character}")
async def source(character: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    token = bearer(authorization)
    try:
        path, variable = resolve_character(character)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
    response = await github("GET", f"{GITHUB_API}/repos/{GITHUB_OWNER}/{GITHUB_REPO}/contents/{path}?ref=main", token)
    if response.status_code != 200:
        raise HTTPException(502, "Could not read repository data")
    record = response.json()
    raw = base64.b64decode(record["content"]).decode()
    prefix = f"window.{variable}="
    if not raw.startswith(prefix) or not raw.rstrip().endswith(";"):
        raise HTTPException(500, "Repository data has an unexpected format")
    data = json.loads(raw[len(prefix):].rstrip()[:-1])
    return {"sha": record["sha"], "data": data}


@app.post("/api/save/{character}")
async def save_character(character: str, body: SaveBody, authorization: str | None = Header(default=None)) -> dict[str, str]:
    token = bearer(authorization)
    try:
        path, variable = resolve_character(character)
        clean = validate_character(body.data)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    current = await github("GET", f"{GITHUB_API}/repos/{GITHUB_OWNER}/{GITHUB_REPO}/contents/{path}?ref=main", token)
    if current.status_code != 200:
        raise HTTPException(502, "Could not read current repository version")
    current_sha = current.json()["sha"]
    if body.sha and body.sha != current_sha:
        raise HTTPException(409, "The character changed on GitHub; reload before saving")
    encoded = base64.b64encode(render_data_js(variable, clean).encode()).decode()
    updated = await github("PUT", f"{GITHUB_API}/repos/{GITHUB_OWNER}/{GITHUB_REPO}/contents/{path}", token, json={"message": f"data: update {character} from character sheet", "content": encoded, "sha": current_sha, "branch": "main"})
    if updated.status_code not in (200, 201):
        detail = updated.json().get("message", "GitHub rejected the update")
        raise HTTPException(502, detail)
    return parse_update_result(updated.json(), path)
