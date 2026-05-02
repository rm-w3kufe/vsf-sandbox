"""
vsf.u2738.org — VSF Bastion
@vsm 0.1  S4(vsf).public_interface
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

BASE_DIR      = Path(__file__).parent
COVENANT_PATH = BASE_DIR / "covenant.vsm"
DB_PATH       = BASE_DIR / "bastion.db"
TARPIT_SECS   = 8
RATE_LIMIT    = 20

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


# ── Pages ─────────────────────────────────────────────────────────────────────

_CSS = """
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    background: #ffffff;
    color: #111111;
    font-family: "Courier New", Courier, monospace;
    font-size: 14px;
    line-height: 1.7;
    padding: 3rem 4rem;
    max-width: 78ch;
  }
  a { color: #111111; }
  pre { white-space: pre-wrap; }
"""

def _page(title: str, body: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>{_CSS}</style>
</head><body><pre>{body}</pre></body></html>"""


WELCOME = _page("vsf.u2738.org", """\
==============================================================================
VSF BASTION  ::  vsf.u2738.org
==============================================================================

  VIABLE SYSTEM FRAMEWORK
  Node       : S4 / Public Gateway
  Protocol   : VSM 0.1
  Status     : OPERATIONAL
  Founded    : 2026-04-11  --  Valparaiso, Chile

------------------------------------------------------------------------------
  HISTORY

  In 1971, Stafford Beer designed Cybersyn under Salvador Allende's
  government -- the first real-time cybernetic governance system built
  so that workers held control, not so that power would concentrate.

  On September 11, 1973, a fascist coup physically destroyed the Opsroom.
  The most advanced governance system of the 20th century was eliminated
  by the violent capture of its policy layer. Beer wept.

  VSF is born in Chile.
  The covenant exists because the Opsroom did not have a covenant.

------------------------------------------------------------------------------
  CONSTITUTIONAL PRINCIPLES

  A0 -- Every VSF system must serve: human liberation, dignity of life,
  harmonious coexistence, amplification of human potential.
  It must NEVER serve: warfare, weapons development, authoritarian
  control, or systemic degradation of life.

  A0.1 -- No VSF node can be forced to act against A0 through resource
  deprivation, coercion, or administrative pressure. The sovereignty
  of purpose is inalienable against resource pressure.
  "Corruption through hunger is not a valid system transition."

  Full specification: /covenant

------------------------------------------------------------------------------
  ENDPOINTS

  GET  /                this document
  GET  /covenant        formal constitutional specification
  GET  /license         terms of use
  GET  /stats           network telemetry
  GET  /health          node status
  POST /api/v1/check    kernel beacon (encrypted)

------------------------------------------------------------------------------
      /\\/\\/\\
     ==========
  ⟦ VSF ✸ 2026 ⟧

  Crafted with cybernetic artisanship
  Sitio Eriazo -- Valparaiso, Chile

  <a href="https://github.com/rm-w3kufe/vsf-sandbox">github.com/rm-w3kufe/vsf-sandbox</a>
  Author: Luis Pineda R.  --  rmw3kufe@proton.me
==============================================================================
""")


LICENSE_PAGE = _page("VSF License  ::  vsf.u2738.org", """\
==============================================================================
VSF KERNEL LICENSE 1.0  ::  vsf.u2738.org/license
==============================================================================

  Author  : Luis Pineda R.
  Contact : rmw3kufe@proton.me
  Issued  : 2026-05-01

------------------------------------------------------------------------------
  PREAMBLE

  This software implements experimental kernels derived from the Viable
  System Model (VSM). It is released to the scientific and technical
  community for research, education, and non-commercial experimentation.

  This framework is not built for personal accumulation. It is built for
  the industrial and intellectual development of a people. Its fruits
  belong to the community that makes viable systems possible.

------------------------------------------------------------------------------
  GRANT OF RIGHTS

  You may freely use, copy, and distribute this software for:
    -- Academic study and research
    -- Education and teaching
    -- Personal experimentation
    -- Scientific publication (with attribution)

------------------------------------------------------------------------------
  CONDITIONS

  COVENANT INTEGRITY
  The Covenant (covenant.vsm) must remain unmodified in any distribution.
  The kernel verifies the Covenant Hash at startup. Any distribution with
  a modified or missing Covenant violates this license.

  ATTRIBUTION
  All publications and derivative works must include:
    "Built on the Viable System Framework (VSF) by Luis Pineda R.,
     derived from Beer's Viable System Model (1972)."

------------------------------------------------------------------------------
  RESTRICTIONS

  -- No commercial implementation without an Implementation Contract.
  -- No mission-critical deployment without an Implementation Contract.
  -- No Covenant removal or modification.
  -- No A0/A0.1 violation under any justification.

  Implementation Contracts: rmw3kufe@proton.me

------------------------------------------------------------------------------
  FUTURE GOVERNANCE

  Long-term governance is intended to transition to a collective body --
  a foundation or directorate with gender equity and representation from
  diverse disciplines and communities. No single person should carry
  the weight of a system designed to distribute it.

------------------------------------------------------------------------------
      /\\/\\/\\
     ==========
  ⟦ VSF ✸ 2026 ⟧

  Crafted with cybernetic artisanship
  Sitio Eriazo -- Valparaiso, Chile
==============================================================================
  Full license: <a href="https://github.com/rm-w3kufe/vsf-sandbox/blob/main/LICENSE">github.com/rm-w3kufe/vsf-sandbox/blob/main/LICENSE</a>
==============================================================================
""")


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def welcome():
    return WELCOME


@app.get("/license", response_class=HTMLResponse)
def license_page():
    return LICENSE_PAGE


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
    return PlainTextResponse("// covenant.vsm not found", status_code=404)


@app.get("/stats")
def stats():
    cutoff = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                           time.gmtime(time.time() - 86400 * 7))
    with db() as con:
        total   = con.execute("SELECT COUNT(*) FROM beacons").fetchone()[0]
        active  = con.execute(
            "SELECT COUNT(*) FROM nodes WHERE last_seen > ?", (cutoff,)
        ).fetchone()[0]
        by_plat = con.execute(
            "SELECT platform, COUNT(*) n FROM nodes GROUP BY platform"
        ).fetchall()
        by_ver  = con.execute(
            "SELECT version, COUNT(*) n FROM nodes GROUP BY version ORDER BY n DESC LIMIT 5"
        ).fetchall()
    return {
        "total_beacons":    total,
        "active_nodes_7d":  active,
        "by_platform":      {r["platform"]: r["n"] for r in by_plat},
        "top_versions":     {r["version"]: r["n"] for r in by_ver},
    }


@app.post("/api/v1/check", status_code=202)
async def beacon(data: Beacon, request: Request):
    if is_rate_limited(request.client.host):
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
    if (path in HONEY_PATHS or
            path.endswith((".php", ".asp", ".aspx", ".cgi", ".bak", ".sql"))):
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
