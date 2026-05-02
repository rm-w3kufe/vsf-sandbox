"""
vsf.u2738.org — VSF Bastion
@vsm 0.1  S4(vsf).public_interface
"""

import asyncio
import json
import logging
import os
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone

# fail2ban hook — writes HONEYPOT lines to /var/log/vsf-honeypot.log
_honeypot_log = logging.getLogger("vsf.honeypot")
_h = logging.FileHandler("/var/log/vsf-honeypot.log")
_h.setFormatter(logging.Formatter("%(asctime)s HONEYPOT %(message)s"))
_honeypot_log.addHandler(_h)
_honeypot_log.setLevel(logging.WARNING)
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, field_validator

BASE_DIR      = Path(__file__).parent
COVENANT_PATH = BASE_DIR / "covenant.vsm"
DB_PATH       = BASE_DIR / "bastion.db"
TARPIT_SECS   = 8
RATE_LIMIT    = 20
MONITOR_TOKEN = os.getenv("MONITOR_TOKEN", "")

_start_time = datetime.now(timezone.utc)

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
    line-height: 1.2;
    padding: 3rem 4rem;
    max-width: 93ch;
  }
  a { color: #111111; }
  pre { white-space: pre-wrap; }
"""

_W   = 93
_SEP = "=" * _W
_sep = "-" * _W


def _page(title: str, body: str, refresh: int = 0) -> str:
    refresh_tag = f'<meta http-equiv="refresh" content="{refresh}">\n' if refresh else ""
    return (
        "<!DOCTYPE html>\n<html lang=\"en\"><head>\n"
        "<meta charset=\"utf-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        + refresh_tag
        + f"<title>{title}</title>\n<style>{_CSS}</style>\n"
        "</head><body><pre>" + body + "</pre></body></html>"
    )


WELCOME = _page("vsf.u2738.org", f"""\
{_SEP}
VIABLE SYSTEM FRAMEWORK  ::  vsf.u2738.org
{_SEP}

  A formal implementation of Beer's Viable System Model (1972).

  VSF provides tools and protocols for designing systems that survive --
  systems that coordinate without losing autonomy, adapt without losing
  identity, and serve human purposes without surrendering to capture.

{_sep}
  HISTORY

  In 1971, Stafford Beer designed Project Cybersyn under Salvador Allende's
  government -- the first real-time cybernetic governance network in history,
  built so that workers held control, not so that power could concentrate.

  On September 11, 1973, a fascist coup physically destroyed the Opsroom.
  The most advanced governance system of the 20th century was eliminated
  by the violent capture of its policy layer. Beer wept.

  VSF is born in Chile.
  The covenant exists because the Opsroom did not have a covenant.

{_sep}
  THE KERNEL

  At the core of VSF is a formal kernel that makes viability computable.
  The kernel converges to a stable attractor under sustained operation --
  a measurable signature of systemic health that persists through thermal
  stress, long-run evolution, and perturbation.

  This is not simulation. The convergence is empirically measured.

{_sep}
  CONSTITUTIONAL PRINCIPLES

  A0   Every VSF system must serve human liberation, dignity of life,
       and the amplification of human potential. It must never serve
       warfare, authoritarian control, or the degradation of life.

  A0.1 No VSF node can be forced to act against A0 through resource
       deprivation, coercion, or administrative pressure.
       "Corruption through hunger is not a valid system transition."

  Full specification: <a href="/covenant">/covenant</a>

{_sep}
  DOCUMENTS

  <a href="/covenant">/covenant</a>     constitutional specification  (VSM 0.1)
  <a href="/license">/license</a>      terms of use  (VSF Kernel License 1.0)

  Research and source code:
  <a href="https://github.com/rm-w3kufe/vsf-sandbox">github.com/rm-w3kufe/vsf-sandbox</a>

  Contact and implementation inquiries:
  <a href="mailto:rmw3kufe@proton.me">rmw3kufe@proton.me</a>

{_sep}
  ⟦ VSF ✸ 2026 ⟧

  Luis Pineda R.
  Crafted with cybernetic artisanship
  Sitio Eriazo  --  Valparaíso, Chile
{_SEP}
""")


_LICENSE_FALLBACK = (
    f"{_SEP}\nVSF KERNEL LICENSE 1.0  ::  vsf.u2738.org/license\n{_SEP}\n\n"
    "  Full text: "
    "<a href=\"https://github.com/rm-w3kufe/vsf-sandbox/blob/main/LICENSE\">"
    "github.com/rm-w3kufe/vsf-sandbox/blob/main/LICENSE</a>\n\n"
    f"{_SEP}"
)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def welcome():
    return WELCOME


@app.get("/license", response_class=HTMLResponse)
def license_page():
    for candidate in (BASE_DIR / "LICENSE", BASE_DIR.parent / "LICENSE"):
        if candidate.exists():
            return _page("VSF License 1.0  ::  vsf.u2738.org", candidate.read_text())
    return _page("VSF License 1.0  ::  vsf.u2738.org", _LICENSE_FALLBACK)


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


def _fmt_uptime() -> str:
    delta = datetime.now(timezone.utc) - _start_time
    h, rem = divmod(int(delta.total_seconds()), 3600)
    m, s   = divmod(rem, 60)
    return f"{h}h {m:02d}m {s:02d}s"


@app.get("/monitor", response_class=HTMLResponse)
def monitor_page(t: str = ""):
    if not MONITOR_TOKEN or t != MONITOR_TOKEN:
        raise HTTPException(status_code=404)

    now    = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    cutoff = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 86400 * 7))

    with db() as con:
        total   = con.execute("SELECT COUNT(*) FROM beacons").fetchone()[0]
        active  = con.execute(
            "SELECT COUNT(*) FROM nodes WHERE last_seen > ?", (cutoff,)
        ).fetchone()[0]
        threats = con.execute("SELECT COUNT(*) FROM honeypot_log").fetchone()[0]
        by_plat = con.execute(
            "SELECT platform, COUNT(*) n FROM nodes GROUP BY platform"
        ).fetchall()
        by_ver  = con.execute(
            "SELECT version, COUNT(*) n FROM nodes GROUP BY version ORDER BY n DESC LIMIT 5"
        ).fetchall()
        recent  = con.execute(
            "SELECT ts, ip, method, path FROM honeypot_log ORDER BY id DESC LIMIT 10"
        ).fetchall()

    plat_str = "  ".join(f"{r['platform']}={r['n']}" for r in by_plat) or "—"
    ver_str  = "\n".join(f"  {r['version']:<20} {r['n']}" for r in by_ver) or "  —"

    threat_rows = "".join(
        f"  {r['ts'][:19]}  {r['ip']:<15}  {r['method']:<6}  {r['path']}\n"
        for r in recent
    ) or "  —\n"

    SEP  = _SEP
    sep2 = _sep
    # _COL: both right-side labels start at same column, line stays short
    _COL   = 27
    _ts    = f"  {now}"   # always 22 chars (ISO timestamp)
    header = _ts + " " * (_COL - len(_ts)) + "[auto‑refresh: 30s]"

    body = "\n".join([
        SEP,
        "VSF MONITOR  ::  vsf.u2738.org/monitor",
        SEP,
        header,
        sep2,
        "  NODE STATUS",
        "",
        f"  Uptime            :  {_fmt_uptime()}",
        "  Process           :  vsf-bastion  [ACTIVE]",
        "",
        sep2,
        "  NETWORK TELEMETRY",
        "",
        f"  Total beacons     :  {total}",
        f"  Active nodes (7d) :  {active}",
        f"  Threats captured  :  {threats}",
        "",
        "  By platform:",
        f"  {plat_str}",
        "",
        "  Top versions:",
        ver_str,
        "",
        sep2,
        "  RECENT THREATS" + " " * (_COL - 16) + "[last 10]",
        "",
        threat_rows.rstrip(),
        "",
        sep2,
        "  ⟦ VSF ✸ 2026 ⟧     INTERNAL USE ONLY",
        SEP,
    ])

    return _page("VSF Monitor", body, refresh=30)


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
        _honeypot_log.warning("%s %s %s", request.client.host, request.method, path)
        await asyncio.sleep(TARPIT_SECS)
        return JSONResponse(DECOY, status_code=200)
    return await call_next(request)
