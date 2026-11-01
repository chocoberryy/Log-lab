"""Halaman operator (R-05): login, sesi server-side, event, snapshot, dan dashboard.

Semua HTML dibuat di server; setiap teks dari database di-escape dengan html.escape.
Semua route data memerlukan sesi operator. Token ingest tidak berlaku sebagai sesi.
"""
from __future__ import annotations

import functools
import hashlib
import hmac
import html
import json
import re
import secrets
import sqlite3
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
from urllib.parse import parse_qs, urlencode

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from starlette.concurrency import run_in_threadpool

from .analysis import HEARTBEAT_STALE_SECONDS, iso_z, snapshot_id, window_start
from .config import Settings
from .db import connect
from .events import parse_utc
from .security import hash_password, token_hash, verify_password

COOKIE_NAME = "loglab_session"
SESSION_IDLE_SECONDS = 30 * 60
QUERY_LIMIT_PER_SECOND = 20
LOGIN_FAILURE_LIMIT = 5
LOGIN_WINDOW_SECONDS = 60
DEFAULT_RANGE = timedelta(hours=24)
MAX_RANGE = timedelta(days=7)
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 100
MAX_FILTER_LENGTH = 64
MAX_FORM_BYTES = 4096
_UUID_TEXT = re.compile(r"^[0-9a-f-]{1,36}$")
_NEW_SQLITE = sqlite3.sqlite_version_info >= (3, 42, 0)
# Urutan event memakai waktu yang di-parse SQLite (bukan perbandingan teks).
TS_EXPR = "unixepoch(occurred_at,'subsec')" if _NEW_SQLITE else "julianday(occurred_at)"

CSP = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
CSS = ("body{font-family:sans-serif;margin:1.2rem;max-width:72rem}table{border-collapse:collapse;width:100%}"
       "th,td{border:1px solid #bbb;padding:.3rem .5rem;text-align:left;font-size:.9rem;vertical-align:top}"
       ".bad{color:#a00}.ok{color:#060}.warn{color:#935000}nav a{margin-right:1rem}code,pre{word-break:break-all;white-space:pre-wrap}"
       "form.inline{display:inline}.note{background:#f3f3f3;padding:.5rem;margin:.5rem 0}")


def esc(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def ts_value(moment: datetime) -> float:
    return moment.timestamp() if _NEW_SQLITE else moment.timestamp() / 86400 + 2440587.5


@functools.lru_cache(maxsize=1)
def _dummy_hash() -> str:
    return hash_password("dummy-password-for-timing")


def _csrf_for(session_token: str) -> str:
    return hmac.new(session_token.encode(), b"loglab-csrf", hashlib.sha256).hexdigest()


def _utc(clock: Callable[[], float]) -> datetime:
    return datetime.fromtimestamp(clock(), timezone.utc)


class Console:
    def __init__(self, settings: Settings, model_status: Callable[[], dict[str, Any]], clock: Callable[[], float]):
        self.settings = settings
        self.db_path = settings.db_path
        self.model_status = model_status
        self.clock = clock
        self.query_hits: dict[str, deque[float]] = {}
        self.login_failures: dict[str, deque[float]] = {}

    # ------------------------------------------------------------- tampilan
    def page(self, title: str, body: str, *, status: int = 200, csrf: str | None = None,
             headers: dict[str, str] | None = None) -> HTMLResponse:
        nav = ""
        if csrf:
            nav = ('<nav><a href="/">Dashboard</a><a href="/events">Event</a><a href="/snapshots">Snapshot</a>'
                   '<form class="inline" method="post" action="/logout"><input type="hidden" name="csrf" value="%s">'
                   '<button type="submit">Logout</button></form></nav><hr>' % esc(csrf))
        document = ('<!doctype html><html lang="id"><head><meta charset="utf-8"><title>%s - LogLab Monitor</title>'
                    '<style>%s</style></head><body><h1>%s</h1>%s%s</body></html>' % (esc(title), CSS, esc(title), nav, body))
        response = HTMLResponse(document, status_code=status)
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        for key, value in (headers or {}).items():
            response.headers[key] = value
        return response

    def login_page(self, message: str = "", status: int = 200, headers: dict[str, str] | None = None) -> HTMLResponse:
        note = '<p class="bad">%s</p>' % esc(message) if message else ""
        body = (note + '<form method="post" action="/login"><p><label>Username <input name="username" maxlength="64" '
                'autocomplete="username"></label></p><p><label>Password <input name="password" type="password" '
                'maxlength="256" autocomplete="current-password"></label></p><button type="submit">Masuk</button></form>')
        return self.page("Login operator", body, status=status, headers=headers)

    # ----------------------------------------------------------------- sesi
    def load_session(self, request: Request) -> tuple[dict[str, Any], str] | None:
        token = request.cookies.get(COOKIE_NAME, "")
        if not token or len(token) > 128:
            return None
        now = self.clock()
        with connect(self.db_path) as db:
            row = db.execute("SELECT s.*, o.active FROM sessions s JOIN operators o ON o.username=s.username "
                             "WHERE s.token_hash=?", (token_hash(token),)).fetchone()
            if row is None:
                return None
            if row["expires_at"] <= now or not row["active"]:
                db.execute("DELETE FROM sessions WHERE token_hash=?", (row["token_hash"],))
                return None
            db.execute("UPDATE sessions SET expires_at=? WHERE token_hash=?", (now + SESSION_IDLE_SECONDS, row["token_hash"]))
        return dict(row), token

    def guard(self, request: Request) -> tuple[dict[str, Any] | None, Response | None]:
        """Pastikan ada sesi sah dan batas 20 request/detik per sesi tidak terlampaui."""
        loaded = self.load_session(request)
        if loaded is None:
            return None, RedirectResponse("/login", status_code=303)
        session, token = loaded
        now = self.clock()
        hits = self.query_hits.setdefault(session["token_hash"], deque())
        while hits and now - hits[0] >= 1.0:
            hits.popleft()
        if len(hits) >= QUERY_LIMIT_PER_SECOND:
            return None, self.page("Terlalu banyak permintaan", "<p>Batas 20 permintaan per detik. Coba lagi sebentar.</p>",
                                   status=429, headers={"Retry-After": "1"})
        hits.append(now)
        return {"username": session["username"], "csrf": _csrf_for(token), "csrf_hash": session["csrf_hash"],
                "token_hash": session["token_hash"]}, None

    def same_origin(self, request: Request) -> bool:
        origin = request.headers.get("origin")
        if origin is None:
            return True
        host = request.headers.get("host", "")
        return origin in (f"https://{host}", f"http://{host}")

    def check_csrf(self, request: Request, ctx: dict[str, Any], form: dict[str, list[str]]) -> bool:
        submitted = form.get("csrf", [""])[0]
        return self.same_origin(request) and hmac.compare_digest(token_hash(submitted), ctx["csrf_hash"])

    def retry_after(self, key: str) -> int:
        failures = self.login_failures.get(key)
        now = self.clock()
        if failures:
            while failures and now - failures[0] >= LOGIN_WINDOW_SECONDS:
                failures.popleft()
        if failures and len(failures) >= LOGIN_FAILURE_LIMIT:
            return max(1, int(LOGIN_WINDOW_SECONDS - (now - failures[0])) + 1)
        return 0

    def create_session(self, username: str) -> str:
        token = secrets.token_urlsafe(32)
        now = self.clock()
        with connect(self.db_path) as db:
            db.execute("DELETE FROM sessions WHERE expires_at<=?", (now,))
            db.execute("INSERT INTO sessions(token_hash, username, csrf_hash, created_at, expires_at) VALUES(?,?,?,?,?)",
                       (token_hash(token), username, token_hash(_csrf_for(token)), iso_z(_utc(self.clock)),
                        now + SESSION_IDLE_SECONDS))
        return token

    def check_login(self, username: str, password: str) -> bool:
        with connect(self.db_path) as db:
            row = db.execute("SELECT password_hash FROM operators WHERE username=? AND active=1", (username,)).fetchone()
        if row is None:
            verify_password(password, _dummy_hash())  # waktu kerja serupa agar username tidak bisa ditebak
            return False
        return verify_password(password, row["password_hash"])

    # --------------------------------------------------------------- filter
    def parse_filters(self, params: Any) -> tuple[dict[str, Any], list[str]]:
        errors: list[str] = []
        now = _utc(self.clock)

        def moment(name: str, default: datetime) -> datetime:
            raw = params.get(name)
            if not raw:
                return default
            try:
                return parse_utc(raw)
            except ValueError:
                errors.append("Parameter %s harus waktu UTC berformat 2026-01-01T00:00:00Z." % name)
                return default

        end = moment("to", now)
        start = moment("from", end - DEFAULT_RANGE)
        if not errors and start >= end:
            errors.append("Waktu awal (from) harus lebih awal dari waktu akhir (to).")
        elif not errors and end - start > MAX_RANGE:
            errors.append("Rentang waktu maksimal 7 hari; persempit from dan to.")
        values: dict[str, Any] = {"from": start, "to": end}
        for name in ("source", "account"):
            raw = params.get(name, "")
            if len(raw) > MAX_FILTER_LENGTH or not (raw.isascii() and raw.isprintable()):
                errors.append("Filter %s maksimal %d karakter ASCII yang dapat dicetak." % (name, MAX_FILTER_LENGTH))
                raw = ""
            values[name] = raw
        result = params.get("result", "")
        if result not in ("", "success", "failure"):
            errors.append("Filter result hanya boleh success atau failure.")
            result = ""
        values["result"] = result
        for name, default, low, high in (("page", 1, 1, 1_000_000), ("size", DEFAULT_PAGE_SIZE, 1, MAX_PAGE_SIZE)):
            raw = params.get(name)
            number = default
            if raw is not None:
                if raw.isdigit() and low <= int(raw) <= high:
                    number = int(raw)
                else:
                    errors.append("Parameter %s harus bilangan %d sampai %d." % (name, low, high))
            values[name] = number
        return values, errors

    # ----------------------------------------------------------- hasil analisis
    @staticmethod
    def result_text(row: sqlite3.Row | dict[str, Any]) -> str:
        """Label hanya tampil pada state succeeded; selain itu alasan, tidak pernah 'normal'."""
        if row["state"] == "succeeded":
            score = "" if row["score"] is None else " skor %.4f" % row["score"]
            return '<span class="%s">%s%s</span> <small>(%s)</small>' % (
                "bad" if row["label"] == "suspicious" else "ok", esc(row["label"]), esc(score), esc(row["reason"]))
        return '<span class="warn">%s: %s</span>' % (esc(row["state"]), esc(row["reason"]))


def register_console(app: FastAPI, settings: Settings, *, model_status: Callable[[], dict[str, Any]],
                     clock: Callable[[], float] = time.time) -> Console:
    console = Console(settings, model_status, clock)
    db_path = settings.db_path

    @app.get("/login")
    def login_form() -> Response:
        return console.login_page()

    @app.post("/login")
    async def login_submit(request: Request) -> Response:
        key = request.client.host if request.client else "unknown"
        wait = console.retry_after(key)
        if wait:
            return console.login_page("Terlalu banyak percobaan. Coba lagi nanti.", 429, {"Retry-After": str(wait)})
        body = await request.body()
        if len(body) > MAX_FORM_BYTES or not console.same_origin(request):
            return console.login_page("Permintaan ditolak.", 400)
        form = parse_qs(body.decode("utf-8", "replace"), keep_blank_values=True)
        username, password = form.get("username", [""])[0][:64], form.get("password", [""])[0][:256]
        if await run_in_threadpool(console.check_login, username, password):
            console.login_failures.pop(key, None)
            old = request.cookies.get(COOKIE_NAME)
            token = await run_in_threadpool(console.create_session, username)
            if old:  # rotasi: sesi lama dicabut
                with connect(db_path) as db:
                    db.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash(old),))
            response = RedirectResponse("/", status_code=303)
            response.set_cookie(COOKIE_NAME, token, httponly=True, secure=True, samesite="strict", path="/")
            return response
        console.login_failures.setdefault(key, deque()).append(clock())
        return console.login_page("Username atau password salah.", 401)

    @app.post("/logout")
    async def logout(request: Request) -> Response:
        ctx, denied = console.guard(request)
        if denied is not None:
            return denied
        form = parse_qs((await request.body())[:MAX_FORM_BYTES].decode("utf-8", "replace"))
        if not console.check_csrf(request, ctx, form):
            return console.page("Ditolak", "<p>Token CSRF tidak sah.</p>", status=403, csrf=ctx["csrf"])
        with connect(db_path) as db:
            db.execute("DELETE FROM sessions WHERE token_hash=?", (ctx["token_hash"],))
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie(COOKIE_NAME, path="/", secure=True, httponly=True, samesite="strict")
        return response

    # ------------------------------------------------------------ dashboard
    @app.get("/")
    def dashboard(request: Request) -> Response:
        ctx, denied = console.guard(request)
        if denied is not None:
            return denied
        now = _utc(clock)
        day_ago = iso_z(now - timedelta(hours=24))
        with connect(db_path) as db:
            sources = db.execute("SELECT * FROM source_status ORDER BY source_id, stream_id").fetchall()
            total = db.execute("SELECT COUNT(*) FROM monitor_events").fetchone()[0]
            recent = db.execute("SELECT COUNT(*) FROM monitor_events WHERE received_at>=?", (day_ago,)).fetchone()[0]
            rejected = db.execute("SELECT reason_code, COUNT(*) AS n FROM ingest_rejections WHERE received_at>=? "
                                  "GROUP BY reason_code ORDER BY reason_code", (day_ago,)).fetchall()
            quality = db.execute("SELECT quality, COUNT(*) AS n FROM snapshots s WHERE revision=(SELECT MAX(revision) "
                                 "FROM snapshots WHERE snapshot_id=s.snapshot_id) GROUP BY quality ORDER BY quality").fetchall()
            states = db.execute("SELECT result_kind, state, COUNT(*) AS n FROM analysis_results GROUP BY result_kind, state "
                                "ORDER BY result_kind, state").fetchall()
            latest = db.execute("SELECT snapshot_id, revision, window_start, quality, quality_reason FROM snapshots "
                                "ORDER BY window_start DESC, revision DESC LIMIT 5").fetchall()
        rows = []
        for src in sources:
            age = (now - parse_utc(src["received_at"])).total_seconds()
            if age > HEARTBEAT_STALE_SECONDS:
                state = '<span class="bad">STALE/offline (heartbeat %d detik lalu)</span>' % age
            elif src["acknowledged_sequence"] < src["committed_sequence"] or src["pending_count"] > 0:
                state = '<span class="warn">BACKLOG (menunggu ACK/pengiriman)</span>'
            else:
                state = '<span class="ok">sehat (idle atau aktif)</span>'
            rows.append("<tr><td>%s</td><td><code>%s</code></td><td>%s</td><td>%s / %s</td><td>%s</td><td>%s</td><td>%s ms</td>"
                        "<td>%s</td></tr>" % (esc(src["source_id"]), esc(src["stream_id"]), state, src["committed_sequence"],
                                              src["acknowledged_sequence"], src["pending_count"], src["held_count"],
                                              src["clock_offset_ms"], esc(src["received_at"])))
        source_table = ("<table><tr><th>Sumber</th><th>Stream</th><th>Keadaan</th><th>committed / ACK</th><th>pending</th>"
                        "<th>held</th><th>offset jam</th><th>heartbeat diterima (UTC)</th></tr>%s</table>" % "".join(rows)
                        if rows else '<p class="warn">Belum ada heartbeat: sumber offline atau belum pernah mengirim status.</p>')
        model = console.model_status()
        model_text = ('<span class="ok">dimuat</span>, versi %s, hash <code>%s</code>' % (esc(model.get("version")), esc(model.get("hash")))
                      if model.get("loaded") else '<span class="bad">tidak tersedia</span>: %s' % esc(model.get("error")))
        listing = "".join('<tr><td><a href="/snapshots/%s/%d">%s</a></td><td>%d</td><td>%s</td><td>%s</td></tr>' % (
            esc(r["snapshot_id"]), r["revision"], esc(r["window_start"]), r["revision"], esc(r["quality"]), esc(r["quality_reason"]))
            for r in latest)
        body = (
            '<p class="note">Diperbarui: %s UTC. Batas staleness heartbeat: %d detik. HTTP 200 pada /health hanya berarti proses '
            'hidup; itu bukan bukti delivery, analisis, atau restore.</p>' % (esc(iso_z(now)), HEARTBEAT_STALE_SECONDS)
            + "<h2>Sumber</h2>" + source_table
            + "<h2>Delivery</h2><p>Event tersimpan: %d total, %d diterima dalam 24 jam terakhir.</p>" % (total, recent)
            + "<p>Penolakan ingest 24 jam: %s</p>" % (", ".join("%s=%d" % (esc(r["reason_code"]), r["n"]) for r in rejected) or "tidak ada")
            + "<h2>Analisis</h2><p>Snapshot terbaru per kualitas: %s</p>" % (", ".join("%s=%d" % (esc(r["quality"]), r["n"]) for r in quality) or "belum ada")
            + "<p>Hasil per state: %s</p>" % (", ".join("%s/%s=%d" % (esc(r["result_kind"]), esc(r["state"]), r["n"]) for r in states) or "belum ada")
            + "<p>Model (eksperimental): %s</p>" % model_text
            + "<table><tr><th>Window (UTC)</th><th>Revisi</th><th>Kualitas</th><th>Alasan</th></tr>%s</table>" % listing)
        return console.page("Dashboard", body, csrf=ctx["csrf"])

    # --------------------------------------------------------------- event
    @app.get("/events")
    def event_list(request: Request) -> Response:
        ctx, denied = console.guard(request)
        if denied is not None:
            return denied
        filters, errors = console.parse_filters(request.query_params)
        if errors:
            items = "".join("<li>%s</li>" % esc(e) for e in errors)
            return console.page("Filter tidak valid", "<ul class=\"bad\">%s</ul><p><a href=\"/events\">Kembali ke daftar</a></p>" % items,
                                status=422, csrf=ctx["csrf"])
        where = ["%s >= ?" % TS_EXPR, "%s < ?" % TS_EXPR]
        args: list[Any] = [ts_value(filters["from"]), ts_value(filters["to"])]
        if filters["source"]:
            where.append("source_id=?"); args.append(filters["source"])
        if filters["account"]:
            where.append("account_token=?"); args.append(filters["account"])
        if filters["result"]:
            where.append("event_type=?"); args.append("login." + filters["result"])
        clause = " AND ".join(where)
        size, page_no = filters["size"], filters["page"]
        with connect(db_path) as db:
            total = db.execute("SELECT COUNT(*) FROM monitor_events WHERE " + clause, args).fetchone()[0]
            rows = db.execute("SELECT source_id, event_id, occurred_at, received_at, event_type, account_token, sequence "
                              "FROM monitor_events WHERE %s ORDER BY %s DESC, event_id DESC LIMIT ? OFFSET ?" % (clause, TS_EXPR),
                              (*args, size, (page_no - 1) * size)).fetchall()
        base = {"from": iso_z(filters["from"]), "to": iso_z(filters["to"]), "size": size}
        for name in ("source", "account", "result"):
            if filters[name]:
                base[name] = filters[name]
        links = []
        if page_no > 1:
            links.append('<a href="/events?%s">&laquo; sebelumnya</a>' % esc(urlencode(dict(base, page=page_no - 1))))
        if page_no * size < total:
            links.append('<a href="/events?%s">berikutnya &raquo;</a>' % esc(urlencode(dict(base, page=page_no + 1))))
        form = ('<form method="get" action="/events"><label>from <input name="from" value="%s" maxlength="40"></label> '
                '<label>to <input name="to" value="%s" maxlength="40"></label> <label>source <input name="source" value="%s" maxlength="64"></label> '
                '<label>account <input name="account" value="%s" maxlength="64"></label> <label>result <select name="result">'
                '<option value="">semua</option><option value="success"%s>success</option><option value="failure"%s>failure</option></select></label> '
                '<label>size <input name="size" value="%d" size="4"></label> <button type="submit">Cari</button></form>' % (
                    esc(base["from"]), esc(base["to"]), esc(filters["source"]), esc(filters["account"]),
                    " selected" if filters["result"] == "success" else "", " selected" if filters["result"] == "failure" else "", size))
        table = "".join('<tr><td>%s</td><td>%s</td><td>%s</td><td>%d</td><td><code>%s</code></td><td><a href="/events/%s">%s</a></td></tr>' % (
            esc(r["occurred_at"]), esc(r["received_at"]), esc(r["event_type"]), r["sequence"], esc(r["account_token"][:16]),
            esc(r["event_id"]), esc(r["event_id"])) for r in rows)
        first = (page_no - 1) * size + 1 if rows else 0
        body = (form + "<p>Waktu dalam UTC. Menampilkan %d-%d dari %d event.</p>" % (first, first + len(rows) - 1 if rows else 0, total)
                + "<table><tr><th>occurred_at (UTC)</th><th>received_at (UTC)</th><th>Jenis</th><th>Seq</th><th>Akun (pseudonim)</th><th>Event</th></tr>%s</table>" % table
                + "<p>%s</p>" % " | ".join(links))
        return console.page("Daftar event", body, csrf=ctx["csrf"])

    @app.get("/events/{event_id}")
    def event_detail(event_id: str, request: Request) -> Response:
        ctx, denied = console.guard(request)
        if denied is not None:
            return denied
        row = None
        if _UUID_TEXT.fullmatch(event_id):
            with connect(db_path) as db:
                row = db.execute("SELECT * FROM monitor_events WHERE event_id=? ORDER BY source_id LIMIT 1", (event_id,)).fetchone()
        if row is None:
            return console.page("Event tidak ditemukan", "<p>Event tidak ada.</p>", status=404, csrf=ctx["csrf"])
        start = window_start(parse_utc(row["occurred_at"]))
        sid = snapshot_id(row["source_id"], row["stream_id"], row["client_token"], iso_z(start))
        with connect(db_path) as db:
            revisions = db.execute("SELECT revision, quality FROM snapshots WHERE snapshot_id=? ORDER BY revision", (sid,)).fetchall()
        snap = " ".join('<a href="/snapshots/%s/%d">revisi %d (%s)</a>' % (esc(sid), r["revision"], r["revision"], esc(r["quality"]))
                        for r in revisions) or "belum ada snapshot untuk window ini"
        fields = [("event_id", row["event_id"]), ("source_id", row["source_id"]), ("stream_id", row["stream_id"]),
                  ("sequence", row["sequence"]), ("occurred_at (UTC)", row["occurred_at"]), ("received_at (UTC)", row["received_at"]),
                  ("jenis", row["event_type"]), ("alasan", row["reason_code"]), ("akun (pseudonim)", row["account_token"]),
                  ("client (pseudonim)", row["client_token"]), ("digest", row["event_digest"])]
        body = ("<table>%s</table>" % "".join("<tr><th>%s</th><td><code>%s</code></td></tr>" % (esc(k), esc(v)) for k, v in fields)
                + "<h2>Snapshot window ini</h2><p>%s</p>" % snap + "<h2>Payload tersimpan (teks)</h2><pre>%s</pre>" % esc(row["payload_json"])
                + '<p><a href="/events">Kembali</a></p>')
        return console.page("Detail event", body, csrf=ctx["csrf"])

    # ------------------------------------------------------------ snapshot
    @app.get("/snapshots")
    def snapshot_list(request: Request) -> Response:
        ctx, denied = console.guard(request)
        if denied is not None:
            return denied
        raw = request.query_params.get("page", "1")
        page_no = int(raw) if raw.isdigit() and 1 <= int(raw) <= 1_000_000 else 1
        with connect(db_path) as db:
            rows = db.execute("SELECT * FROM snapshots s WHERE revision=(SELECT MAX(revision) FROM snapshots WHERE snapshot_id=s.snapshot_id) "
                              "ORDER BY window_start DESC, snapshot_id LIMIT ? OFFSET ?",
                              (DEFAULT_PAGE_SIZE, (page_no - 1) * DEFAULT_PAGE_SIZE)).fetchall()
            lines = []
            for snap in rows:
                results = db.execute("SELECT result_kind, state, label, score, reason FROM analysis_results WHERE snapshot_id=? AND revision=? "
                                     "ORDER BY result_kind, model_hash", (snap["snapshot_id"], snap["revision"])).fetchall()
                cells = " ".join("%s: %s" % (esc(r["result_kind"]), console.result_text(r)) for r in results) or "belum ada hasil"
                lines.append('<tr><td><a href="/snapshots/%s/%d">%s</a></td><td>%d</td><td>%s (%s)</td><td>%s</td></tr>' % (
                    esc(snap["snapshot_id"]), snap["revision"], esc(snap["window_start"]), snap["revision"],
                    esc(snap["quality"]), esc(snap["quality_reason"]), cells))
        nav = ('<a href="/snapshots?page=%d">berikutnya &raquo;</a>' % (page_no + 1)) if len(rows) == DEFAULT_PAGE_SIZE else ""
        body = ("<p>Revisi terbaru per window. Waktu dalam UTC.</p><table><tr><th>Window mulai</th><th>Revisi</th><th>Kualitas</th>"
                "<th>Hasil</th></tr>%s</table><p>%s</p>" % ("".join(lines), nav))
        return console.page("Snapshot", body, csrf=ctx["csrf"])

    def snapshot_view(sid: str, revision: int | None, ctx: dict[str, Any]) -> Response:
        if not re.fullmatch(r"[0-9a-f]{1,64}", sid):
            return console.page("Tidak ditemukan", "<p>Snapshot tidak ada.</p>", status=404, csrf=ctx["csrf"])
        with connect(db_path) as db:
            revisions = db.execute("SELECT revision, quality, sealed_at FROM snapshots WHERE snapshot_id=? ORDER BY revision", (sid,)).fetchall()
            if not revisions:
                return console.page("Tidak ditemukan", "<p>Snapshot tidak ada.</p>", status=404, csrf=ctx["csrf"])
            newest = revisions[-1]["revision"]
            wanted = newest if revision is None else revision
            snap = db.execute("SELECT * FROM snapshots WHERE snapshot_id=? AND revision=?", (sid, wanted)).fetchone()
            if snap is None:
                return console.page("Tidak ditemukan", "<p>Revisi tidak ada.</p>", status=404, csrf=ctx["csrf"])
            results = db.execute("SELECT * FROM analysis_results WHERE snapshot_id=? AND revision=? ORDER BY result_kind, model_hash",
                                 (sid, wanted)).fetchall()
        features = json.loads(snap["features_json"])
        members = json.loads(snap["membership_json"])
        status = "terbaru" if wanted == newest else "superseded oleh revisi %d" % newest
        warn = ""
        if snap["quality"] != "READY":
            warn = '<p class="warn">Snapshot ini tidak layak (%s: %s). Tidak ada label normal untuk snapshot yang tidak READY.</p>' % (
                esc(snap["quality"]), esc(snap["quality_reason"]))
        rev_links = " ".join(('<a href="/snapshots/%s/%d">revisi %d</a>' % (esc(sid), r["revision"], r["revision"])) for r in revisions)
        result_rows = []
        for r in results:
            evidence = json.loads(r["evidence_json"] or "{}")
            version = esc(evidence.get("rules_version") or evidence.get("model_version") or r["model_hash"])
            note = " (eksperimental)" if r["result_kind"] == "ml" else ""
            support = evidence.get("supporting_event_ids") or []
            links = " ".join('<a href="/events/%s">%s</a>' % (esc(e), esc(e[:8])) for e in support[:50])
            result_rows.append("<tr><td>%s%s</td><td>%s</td><td><code>%s</code></td><td>%s</td><td>%s</td></tr>" % (
                esc(r["result_kind"]), note, version, esc(r["model_hash"][:16]), console.result_text(r), links))
        feature_rows = "".join("<tr><th>%s</th><td>%s</td></tr>" % (esc(k), esc(v)) for k, v in features["values"].items())
        event_links = " ".join('<a href="/events/%s">%s</a>' % (esc(e["event_id"]), esc(e["event_id"][:8])) for e in members["events"])
        body = (warn + "<p>Revisi %d dari %d (%s). Window %s sampai %s UTC. Disegel %s UTC.</p>" % (
                    wanted, newest, esc(status), esc(snap["window_start"]), esc(snap["window_end"]), esc(snap["sealed_at"]))
                + "<p>Kualitas: <b>%s</b> (%s). Input hash <code>%s</code>. Revisi lain: %s</p>" % (
                    esc(snap["quality"]), esc(snap["quality_reason"]), esc(snap["input_hash"]), rev_links)
                + "<h2>Fitur %s</h2><table>%s</table>" % (esc(features["version"]), feature_rows)
                + "<h2>Hasil</h2><table><tr><th>Jenis</th><th>Versi</th><th>Hash</th><th>State / label</th><th>Event pendukung</th></tr>%s</table>" % (
                    "".join(result_rows) or "<tr><td colspan=5>belum ada hasil</td></tr>")
                + "<h2>Event dalam window (%d)</h2><p>%s</p>" % (len(members["events"]), event_links))
        return console.page("Detail snapshot", body, csrf=ctx["csrf"])

    @app.get("/snapshots/{sid}")
    def snapshot_latest(sid: str, request: Request) -> Response:
        ctx, denied = console.guard(request)
        return denied if denied is not None else snapshot_view(sid, None, ctx)

    @app.get("/snapshots/{sid}/{revision}")
    def snapshot_revision(sid: str, revision: int, request: Request) -> Response:
        ctx, denied = console.guard(request)
        return denied if denied is not None else snapshot_view(sid, revision, ctx)

    return console
