"""
VSF Bastion API
---------------
Public endpoint for vsf-sandbox kernel beacons and covenant distribution.

  GET  /          → ASCII welcome
  GET  /health    → node status
  GET  /covenant  → canonical covenant.vsm
  GET  /stats     → aggregate metrics
  POST /beacon    → kernel startup ping
  *               → honeypot (logged + tarpitted)
"""

import asyncio
import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, field_validator

DB_PATH      = Path(__file__).parent / "bastion.db"
COVENANT_PATH = Path(__file__).parent.parent / "covenant.vsm"
TARPIT_SECS  = 8
RATE_LIMIT   = 20   # requests / minute / IP

app = FastAPI(docs_url=None, redoc_url=None)


# ── Database ──────────────────────────────────────────────────────────────────

def init_db():
    con = sqlite3.connect(DB_PATH)
    con.executescript("""
        CREATE TABLE IF NOT EXISTS beacons (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ts        TEXT NOT NULL,
            version   TEXT,
            platform  TEXT,
            run_id    TEXT,
            cov_hash  TEXT
        );
        CREATE TABLE IF NOT EXISTS nodes (
            run_id    TEXT PRIMARY KEY,
            last_seen TEXT,
            version   TEXT,
            platform  TEXT
        );
        CREATE TABLE IF NOT EXISTS honeypot_log (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ts        TEXT NOT NULL,
            ip        TEXT,
            method    TEXT,
            path      TEXT,
            ua        TEXT,
            headers   TEXT,
            body      TEXT
        );
    """)
    con.commit()
    con.close()

@contextmanager
def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    finally:
        con.close()

init_db()


# ── Rate limiting ─────────────────────────────────────────────────────────────

_rate: dict[str, list] = {}

def is_rate_limited(ip: str) -> bool:
    now  = time.time()
    hits = _rate.setdefault(ip, [])
    _rate[ip] = [t for t in hits if now - t < 60]
    if len(_rate[ip]) >= RATE_LIMIT:
        return True
    _rate[ip].append(now)
    return False


# ── Models ────────────────────────────────────────────────────────────────────

class Beacon(BaseModel):
    version:       str
    platform:      Literal["linux", "mac", "windows"]
    run_id:        str
    covenant_hash: str
    timestamp:     str

    @field_validator("run_id", "covenant_hash")
    @classmethod
    def must_be_sha256(cls, v: str) -> str:
        if len(v) != 64 or not all(c in "0123456789abcdef" for c in v.lower()):
            raise ValueError("must be SHA-256 hex")
        return v.lower()


# ── Welcome ───────────────────────────────────────────────────────────────────

WELCOME = """\
<!DOCTYPE html><html><head>
<meta charset="utf-8"><title>VSF Bastion</title>
<style>
  body { background:#0a0a0a; color:#c8f0c8; font-family:monospace;
         display:flex; justify-content:center; padding:4rem; }
  pre  { line-height:1.7; }
  a    { color:#80d080; }
</style>
</head><body><pre>
      /\\/\\/\\
     ≈≈≈≈≈≈≈≈
  ⟦ VSF ✸ 2026 ⟧

  Viable System Framework — Bastion Node
  ───────────────────────────────────────
  GET  /covenant     canonical covenant.vsm
  GET  /stats        network metrics
  GET  /health       node status
  POST /beacon       kernel ping

  <a href="https://github.com/rm-w3kufe/vsf-sandbox">github.com/rm-w3kufe/vsf-sandbox</a>

  Crafted with cybernetic artisanship
  Sitio Eriazo ≋ Valparaíso, Chile
</pre></body></html>
"""


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def welcome():
    return WELCOME


@app.get("/health")
def health():
    with db() as con:
        beacons = con.execute("SELECT COUNT(*) FROM beacons").fetchone()[0]
        nodes   = con.execute("SELECT COUNT(*) FROM nodes").fetchone()[0]
        threats = con.execute("SELECT COUNT(*) FROM honeypot_log").fetchone()[0]
    return {"status": "ok", "beacons": beacons, "nodes": nodes, "threats_logged": threats}


@app.get("/covenant", response_class=PlainTextResponse)
def covenant():
    if COVENANT_PATH.exists():
        return COVENANT_PATH.read_text()
    return PlainTextResponse("covenant.vsm not found", status_code=404)


@app.get("/stats")
def stats():
    cutoff_week = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                time.gmtime(time.time() - 86400 * 7))
    with db() as con:
        total_beacons  = con.execute("SELECT COUNT(*) FROM beacons").fetchone()[0]
        active_nodes   = con.execute(
            "SELECT COUNT(*) FROM nodes WHERE last_seen > ?", (cutoff_week,)
        ).fetchone()[0]
        by_platform    = con.execute(
            "SELECT platform, COUNT(*) as n FROM nodes GROUP BY platform"
        ).fetchall()
        by_version     = con.execute(
            "SELECT version, COUNT(*) as n FROM nodes GROUP BY version ORDER BY n DESC LIMIT 5"
        ).fetchall()
    return {
        "total_beacons": total_beacons,
        "active_nodes_7d": active_nodes,
        "by_platform": {r["platform"]: r["n"] for r in by_platform},
        "top_versions": {r["version"]: r["n"] for r in by_version},
    }


@app.post("/beacon", status_code=202)
async def beacon(data: Beacon, request: Request):
    ip = request.client.host
    if is_rate_limited(ip):
        return JSONResponse({"error": "rate limited"}, status_code=429)
    with db() as con:
        con.execute(
            "INSERT INTO beacons (ts,version,platform,run_id,cov_hash) VALUES (?,?,?,?,?)",
            (data.timestamp, data.version, data.platform,
             data.run_id, data.covenant_hash),
        )
        con.execute(
            """INSERT INTO nodes (run_id,last_seen,version,platform) VALUES (?,?,?,?)
               ON CONFLICT(run_id) DO UPDATE SET
               last_seen=excluded.last_seen,
               version=excluded.version,
               platform=excluded.platform""",
            (data.run_id, data.timestamp, data.version, data.platform),
        )
    return {"status": "accepted"}


# ── Honeypot ──────────────────────────────────────────────────────────────────

HONEY_PATHS = {
    "/admin", "/admin/login", "/wp-admin", "/wp-login.php",
    "/.env", "/config.json", "/.git/config", "/config",
    "/shell", "/cmd", "/exec", "/phpmyadmin",
    "/api/v1/admin", "/api/admin", "/login",
    "/manager", "/console", "/setup", "/install", "/dashboard",
}

DECOY = {"status": "ok", "node": "vsf-bastion", "auth": "required"}

@app.middleware("http")
async def honeypot(request: Request, call_next):
    path = request.url.path
    is_honey = (
        path in HONEY_PATHS
        or path.endswith((".php", ".asp", ".aspx", ".cgi", ".bak", ".sql"))
    )
    if is_honey:
        body = (await request.body())[:512].decode("utf-8", errors="replace")
        with db() as con:
            con.execute(
                "INSERT INTO honeypot_log (ts,ip,method,path,ua,headers,body)"
                " VALUES (?,?,?,?,?,?,?)",
                (
                    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    request.client.host,
                    request.method,
                    path,
                    request.headers.get("user-agent", ""),
                    json.dumps(dict(request.headers)),
                    body,
                ),
            )
        await asyncio.sleep(TARPIT_SECS)
        return JSONResponse(DECOY, status_code=200)
    return await call_next(request)
