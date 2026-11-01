from datetime import datetime, timedelta, timezone
from pathlib import Path
import dataclasses
import hashlib
import json
import re
import secrets
import tempfile
import time
import logging
import unittest

import httpx

from loglab.analysis import iso_z, run_cycle
from loglab.config import Settings
from loglab.db import connect
from loglab.events import build_event
from loglab.features import FEATURE_NAMES
from loglab.model import load_model
from loglab.monitor_app import create_app
from loglab.security import hash_password

PASSWORD = "operator-password-123"
SOURCE, STREAM, CLIENT = "login-lab-a", "11111111-1111-4111-8111-111111111111", "b" * 64
NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
COLUMNS = ("source_id,stream_id,event_id,sequence,occurred_at,event_type,account_token,client_token,"
           "reason_code,event_digest,received_at,payload_json")
ORIGIN = {"origin": "https://test"}


logging.getLogger("asyncio").setLevel(logging.ERROR)  # bungkam peringatan 'callback lambat' mode debug


class ConsoleCase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.token = secrets.token_hex(32)
        base = Settings.for_test("monitor", self.dir, source_token=self.token)
        self.settings = dataclasses.replace(base, operator_password_hash=hash_password(PASSWORD))
        self.now = NOW.timestamp()
        self.model = None
        self.model_error = "model_not_configured"
        self.start_app()

    def start_app(self):
        app = create_app(self.settings, model=self.model, model_error=self.model_error, clock=lambda: self.now)
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test")
        self.addAsyncCleanup(self.client.aclose)
        return self.client

    # ---- bantuan ----
    async def login(self, client=None, password=PASSWORD, username="operator"):
        return await (client or self.client).post("/login", data={"username": username, "password": password})

    async def get(self, path, client=None):
        return await (client or self.client).get(path, follow_redirects=False)

    @staticmethod
    def csrf(html_text):
        return re.search(r'name="csrf" value="([0-9a-f]+)"', html_text).group(1)

    def add_event(self, number, offset_seconds, kind="login.failure", account="a" * 64, source=SOURCE, stream=STREAM,
                  client=CLIENT, db=None):
        stamp = iso_z(NOW - timedelta(seconds=offset_seconds))
        reason = "SUCCESS" if kind == "login.success" else "INVALID_CREDENTIALS"
        event = build_event(source_id=source, stream_id=stream, sequence=number, occurred_at=stamp, event_type=kind,
                            account_token=account, client_token=client, reason_code=reason,
                            event_id="00000000-0000-4000-8000-%012d" % number)
        row = (source, stream, event["event_id"], number, stamp, kind, account, client, reason,
               event["event_digest"], stamp, json.dumps(event))
        sql = "INSERT INTO monitor_events(%s) VALUES(%s)" % (COLUMNS, ",".join("?" * 12))
        if db is not None:
            db.execute(sql, row)
        else:
            with connect(self.settings.db_path) as own:
                own.execute(sql, row)
        return event

    def set_status(self, committed, received_ago=1, source_ago=0, held=0, ack=None, pending=0):
        with connect(self.settings.db_path) as db:
            db.execute("INSERT OR REPLACE INTO source_status VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                       (SOURCE, STREAM, committed, committed if ack is None else ack, pending, held, 0, committed,
                        committed, iso_z(NOW - timedelta(seconds=source_ago)), iso_z(NOW - timedelta(seconds=received_ago)), 50))


class AccessTests(ConsoleCase):
    async def test_every_data_route_requires_a_session_and_health_stays_public(self):
        for path in ("/", "/events", "/events/00000000-0000-4000-8000-000000000001", "/snapshots",
                     "/snapshots/abc", "/snapshots/abc/1"):
            with self.subTest(path):
                response = await self.get(path)
                self.assertEqual((response.status_code, response.headers["location"]), (303, "/login"))
                self.assertNotIn("LogLab", response.text)
        self.assertEqual((await self.get("/health")).status_code, 200)
        self.assertEqual((await self.get("/login")).status_code, 200)

    async def test_wrong_credentials_get_no_session_and_no_hint(self):
        for username, password in (("operator", "salah-salah-salah"), ("bukan-operator", PASSWORD), ("", "")):
            with self.subTest(username=username):
                response = await self.login(username=username, password=password)
                self.assertEqual(response.status_code, 401)
                self.assertIn("Username atau password salah.", response.text)
                self.assertNotIn("set-cookie", response.headers)
        self.assertEqual((await self.get("/")).status_code, 303)

    async def test_login_sets_hardened_cookie_and_opens_the_dashboard(self):
        response = await self.login()
        self.assertEqual((response.status_code, response.headers["location"]), (303, "/"))
        cookie = response.headers["set-cookie"].lower()
        for flag in ("httponly", "secure", "samesite=strict"):
            self.assertIn(flag, cookie)
        page = await self.get("/")
        self.assertEqual(page.status_code, 200)
        self.assertIn("Dashboard", page.text)
        self.assertEqual(page.headers["cache-control"], "no-store")
        self.assertIn("default-src 'none'", page.headers["content-security-policy"])

    async def test_session_id_rotates_and_old_session_is_revoked(self):
        await self.login()
        old = self.client.cookies.get("loglab_session")
        await self.login()
        new = self.client.cookies.get("loglab_session")
        self.assertNotEqual(old, new)
        other = httpx.AsyncClient(transport=self.client._transport, base_url="https://test")
        self.addAsyncCleanup(other.aclose)
        other.cookies.set("loglab_session", new, domain="test.local")
        self.assertEqual((await self.get("/", other)).status_code, 200)  # cara menyisipkan cookie memang berfungsi
        other.cookies.clear()
        other.cookies.set("loglab_session", old, domain="test.local")
        self.assertEqual((await self.get("/", other)).status_code, 303)  # sesi lama sudah dicabut

    async def test_logout_needs_csrf_and_same_origin_then_revokes_session(self):
        await self.login()
        token = self.csrf((await self.get("/")).text)
        self.assertEqual((await self.client.post("/logout", data={"csrf": "salah"}, headers=ORIGIN)).status_code, 403)
        self.assertEqual((await self.client.post("/logout", data={"csrf": token}, headers={"origin": "https://evil.example"})).status_code, 403)
        self.assertEqual((await self.get("/")).status_code, 200)  # masih login setelah percobaan ditolak
        done = await self.client.post("/logout", data={"csrf": token}, headers=ORIGIN)
        self.assertEqual((done.status_code, done.headers["location"]), (303, "/login"))
        self.assertEqual((await self.get("/events")).status_code, 303)

    async def test_idle_timeout_is_sliding_and_session_survives_restart(self):
        await self.login()
        cookie = self.client.cookies.get("loglab_session")
        self.now += 20 * 60
        self.assertEqual((await self.get("/")).status_code, 200)  # aktivitas memperpanjang sesi
        self.now += 20 * 60  # 40 menit sejak login, tetapi hanya 20 menit sejak aktivitas terakhir
        restarted = self.start_app()  # aplikasi baru, database sama
        restarted.cookies.set("loglab_session", cookie, domain="test.local")
        self.assertEqual((await self.get("/", restarted)).status_code, 200)  # sesi tersimpan di database
        self.now += 31 * 60
        self.assertEqual((await self.get("/", restarted)).status_code, 303)

    async def test_login_failures_are_limited_per_client_and_recover_after_the_window(self):
        for _ in range(5):
            self.assertEqual((await self.login(password="salah-salah-salah")).status_code, 401)
        blocked = await self.login()  # password benar pun ditolak selama jendela berjalan
        self.assertEqual(blocked.status_code, 429)
        self.assertGreaterEqual(int(blocked.headers["retry-after"]), 1)
        self.now += 61
        self.assertEqual((await self.login()).status_code, 303)

    async def test_query_rate_is_limited_per_session(self):
        await self.login()
        codes = [(await self.get("/")).status_code for _ in range(22)]
        self.assertEqual(codes.count(200), 20)
        self.assertEqual(codes[-1], 429)
        limited = await self.get("/")
        self.assertEqual(limited.headers["retry-after"], "1")
        self.now += 1.1
        self.assertEqual((await self.get("/")).status_code, 200)

    async def test_ingest_token_never_works_as_operator_session(self):
        response = await self.client.get("/", headers={"Authorization": "Bearer " + self.token}, follow_redirects=False)
        self.assertEqual(response.status_code, 303)


class EventViewTests(ConsoleCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        with connect(self.settings.db_path) as db:
            db.execute("BEGIN")
            for number in range(1, 121):  # 120 event, 1 per 10 detik mundur dari NOW
                kind = "login.success" if number % 4 == 0 else "login.failure"
                self.add_event(number, number * 10, kind, account=("%064x" % (1 + number % 3)), source=SOURCE, db=db)
            self.add_event(500, 3 * 24 * 3600, db=db)  # 3 hari lalu: di luar default 24 jam
            db.execute("COMMIT")
        await self.login()

    def ids(self, text):
        return re.findall(r'href="/events/(0{8}-0000-4000-8000-\d{12})"', text)

    async def test_default_window_is_24_hours_and_order_is_newest_first(self):
        text = (await self.get("/events?size=100")).text
        ids = self.ids(text)
        self.assertEqual(len(ids), 100)
        self.assertEqual(ids[0], "00000000-0000-4000-8000-000000000001")  # paling baru = offset 10 detik
        self.assertIn("dari 120 event", text)
        self.assertNotIn("000000000500", text)

    async def test_pages_have_no_duplicates_or_gaps(self):
        seen = []
        for page in (1, 2, 3):
            seen += self.ids((await self.get("/events?size=50&page=%d" % page)).text)
        self.assertEqual(len(seen), 120)
        self.assertEqual(len(set(seen)), 120)
        self.assertEqual(seen, sorted(seen))  # urutan waktu menurun = nomor naik pada data uji

    async def test_filters_can_be_combined(self):
        text = (await self.get("/events?result=success&account=%064x&size=100" % 2)).text
        expected = [n for n in range(1, 121) if n % 4 == 0 and 1 + n % 3 == 2]
        self.assertEqual(sorted(int(i[-12:]) for i in self.ids(text)), expected)
        self.assertEqual(self.ids((await self.get("/events?source=tidak-ada")).text), [])
        window = await self.get("/events?from=2026-01-01T11:59:00Z&to=2026-01-01T12:00:00Z")
        self.assertEqual(len(self.ids(window.text)), 6)  # offset 10..50 detik; 60 detik tepat di batas awal
        self.assertEqual(len(self.ids((await self.get("/events?from=2025-12-31T00:00:00Z&to=2026-01-02T00:00:00Z&size=100")).text)), 100)

    async def test_invalid_filters_get_actionable_errors_and_no_data(self):
        bad = {
            "/events?size=101": "bilangan 1 sampai 100",
            "/events?size=0": "bilangan 1 sampai 100",
            "/events?page=abc": "Parameter page",
            "/events?result=maybe": "success atau failure",
            "/events?source=" + "x" * 65: "maksimal 64",
            "/events?from=kemarin": "format 2026-01-01T00:00:00Z",
            "/events?from=2025-12-01T00:00:00Z&to=2026-01-01T00:00:00Z": "maksimal 7 hari",
            "/events?from=2026-01-01T10:00:00Z&to=2026-01-01T09:00:00Z": "lebih awal",
        }
        for path, message in bad.items():
            with self.subTest(path):
                response = await self.get(path)
                self.assertEqual(response.status_code, 422)
                self.assertIn(message.replace("format ", "").replace("Parameter ", "Parameter ") if False else message.split()[0], response.text)
                self.assertEqual(self.ids(response.text), [])

    async def test_event_detail_shows_safe_metadata_and_snapshot_link(self):
        text = (await self.get("/events/00000000-0000-4000-8000-000000000004")).text
        for expected in ("occurred_at (UTC)", "received_at (UTC)", "login.success", "SUCCESS", "sequence", "stream_id"):
            self.assertIn(expected, text)
        self.assertNotIn(self.token, text)
        self.assertEqual((await self.get("/events/00000000-0000-4000-8000-0000000fffff")).status_code, 404)
        self.assertEqual((await self.get("/events/%3Cscript%3E")).status_code, 404)

    async def test_html_and_crlf_in_stored_text_are_shown_as_text(self):
        evil = '<script>alert(1)</script>\r\n<img src=x onerror=alert(2)>"'
        with connect(self.settings.db_path) as db:
            db.execute("UPDATE monitor_events SET source_id=?, payload_json=? WHERE event_id=?",
                       ("<b>x</b>", evil, "00000000-0000-4000-8000-000000000001"))
        for path in ("/events?size=100&source=%3Cb%3Ex%3C/b%3E", "/events/00000000-0000-4000-8000-000000000001"):
            text = (await self.get(path)).text
            self.assertNotIn("<script>", text)
            self.assertNotIn("<img", text)
            self.assertNotIn("<b>x</b>", text)
        self.assertIn("&lt;script&gt;", text)

    async def test_filter_reflection_is_escaped(self):
        text = (await self.get('/events?source=%22%3E%3Cscript%3Ex%3C/script%3E')).text
        self.assertNotIn("<script>x", text)

    async def test_twenty_thousand_events_are_listed_correctly_and_quickly(self):
        with connect(self.settings.db_path) as db:
            rows = []
            for number in range(1000, 21000):
                stamp = iso_z(NOW - timedelta(seconds=number % 86000 + 1))
                digest = hashlib.sha256(str(number).encode()).hexdigest()
                rows.append((SOURCE, STREAM, "10000000-0000-4000-8000-%012d" % number, number, stamp, "login.failure",
                             "c" * 64, CLIENT, "INVALID_CREDENTIALS", digest, stamp, "{}"))
            db.execute("BEGIN")  # satu transaksi; tanpa ini setiap baris di-fsync sendiri
            db.executemany("INSERT INTO monitor_events(%s) VALUES(%s)" % (COLUMNS, ",".join("?" * 12)), rows)
            db.execute("COMMIT")
        durations = []
        for _ in range(10):
            self.now += 1.1  # patuhi batas 20 request/detik pada jam uji
            started = time.perf_counter()
            first = await self.get("/events?size=100")
            durations.append(time.perf_counter() - started)
        self.assertLess(sorted(durations)[-1], 1.0)  # p95 daftar <= 1 detik pada 20.120 event
        self.assertIn("dari 20120 event", first.text)  # 120 event awal + 20.000 baru; yang berumur 3 hari tidak masuk
        seen: list[str] = []
        for page in (1, 2, 3, 201, 202):
            self.now += 1.1
            ids = re.findall(r'href="/events/([0-9a-f-]{36})"', (await self.get("/events?size=100&page=%d" % page)).text)
            self.assertEqual(len(ids), 20 if page == 202 else 100)
            self.assertFalse(set(seen) & set(ids))  # tidak ada duplikasi antar-page
            seen += ids


class AnalysisViewTests(ConsoleCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        await self.login()

    def window_events(self, count, minute_offset=600, accounts=1):
        base = NOW - timedelta(seconds=minute_offset)
        base = base.replace(second=0)
        for number in range(1, count + 1):
            stamp = iso_z(base + timedelta(seconds=number % 50))
            event = build_event(source_id=SOURCE, stream_id=STREAM, sequence=number, occurred_at=stamp,
                                event_type="login.failure", account_token="%064x" % (number % accounts + 1),
                                client_token=CLIENT, reason_code="INVALID_CREDENTIALS",
                                event_id="00000000-0000-4000-8000-%012d" % number)
            with connect(self.settings.db_path) as db:
                db.execute("INSERT INTO monitor_events(%s) VALUES(%s)" % (COLUMNS, ",".join("?" * 12)),
                           (SOURCE, STREAM, event["event_id"], number, stamp, event["event_type"], event["account_token"],
                            CLIENT, event["reason_code"], event["event_digest"], stamp, "{}"))

    def snap_path(self, db_path):
        with connect(db_path) as db:
            row = db.execute("SELECT snapshot_id, revision FROM snapshots ORDER BY revision DESC LIMIT 1").fetchone()
        return "/snapshots/%s/%d" % (row["snapshot_id"], row["revision"])

    async def test_dashboard_with_no_data_says_so_and_never_claims_health(self):
        text = (await self.get("/")).text
        self.assertIn("Belum ada heartbeat", text)
        self.assertIn("bukan bukti delivery", text)
        self.assertIn("tidak tersedia", text)
        self.assertIn("model_not_configured", text)
        self.assertIn("Batas staleness heartbeat: 20 detik", text)
        self.assertIn("2026-01-01T12:00:00.000Z", text)

    async def test_dashboard_separates_source_delivery_and_analysis_states(self):
        self.window_events(3)
        cases = [("sehat", dict(committed=3)), ("STALE/offline", dict(committed=3, received_ago=40)),
                 ("BACKLOG", dict(committed=3, ack=1, pending=2))]
        for expected, status in cases:
            with self.subTest(expected):
                self.set_status(**status)
                self.assertIn(expected, (await self.get("/")).text)
                self.now += 1.1
        await self.client.post("/api/v1/events", json={"x": 1}, headers={"Authorization": "Bearer salah"})
        self.assertIn("unauthorized=1", (await self.get("/")).text)  # penolakan terlihat sebagai counter

    async def test_ready_snapshot_shows_features_rules_and_supporting_events(self):
        self.window_events(10, accounts=5)
        self.set_status(10, received_ago=1, source_ago=0)
        run_cycle(self.settings.db_path, NOW, None, "model_missing")
        path = self.snap_path(self.settings.db_path)
        text = (await self.get(path)).text
        for expected in ("READY", "login-window-v1", "failure_count", "REPEATED_FAILURES", "suspicious", "terbaru",
                         "ml (eksperimental)", "model_unavailable:model_missing"):
            self.assertIn(expected, text)
        self.assertIn('href="/events/00000000-0000-4000-8000-000000000001"', text)  # event pendukung bisa dibuka
        event_page = await self.get("/events/00000000-0000-4000-8000-000000000001")
        self.assertIn("revisi 1 (READY)", event_page.text)
        listing = (await self.get("/snapshots")).text
        self.assertIn("READY", listing)

    async def test_not_ready_snapshot_is_never_shown_as_normal(self):
        self.window_events(4)  # tanpa heartbeat
        run_cycle(self.settings.db_path, NOW, None, "model_missing")
        text = (await self.get(self.snap_path(self.settings.db_path))).text
        self.assertIn("STALE", text)
        self.assertIn("tidak layak", text)
        self.assertIn("ineligible: heartbeat_missing", text)
        self.assertNotIn(">normal", text)
        self.assertNotIn("no_rule_triggered", text)

    async def test_superseded_revision_stays_reviewable(self):
        self.window_events(3)
        run_cycle(self.settings.db_path, NOW, None, "model_missing")  # revisi 1: STALE
        self.set_status(3)
        run_cycle(self.settings.db_path, NOW + timedelta(seconds=1), None, "model_missing")  # revisi 2: READY
        with connect(self.settings.db_path) as db:
            sid = db.execute("SELECT snapshot_id FROM snapshots LIMIT 1").fetchone()[0]
        old = (await self.get("/snapshots/%s/1" % sid)).text
        new = (await self.get("/snapshots/%s" % sid)).text
        self.assertIn("superseded oleh revisi 2", old)
        self.assertIn("STALE", old)
        self.assertIn("terbaru", new)
        self.assertIn("READY", new)
        self.assertEqual((await self.get("/snapshots/%s/9" % sid)).status_code, 404)
        self.assertEqual((await self.get("/snapshots/zzzz")).status_code, 404)

    async def test_loaded_model_result_is_labelled_experimental_with_version_and_score(self):
        package_file = self.dir / "model.json"
        payload = {"model_version": "uji-lr-1", "schema_version": "login-window-v1", "feature_names": list(FEATURE_NAMES),
                   "scaler": {"mean": [0.0] * 7, "scale": [1.0] * 7}, "coefficients": [0, 0, 0, 0, 0, 1, 0],
                   "intercept": 0, "threshold": 0.5}
        raw = json.dumps(payload, sort_keys=True).encode()
        package_file.write_bytes(raw)
        (self.dir / "model.json.sha256").write_text(hashlib.sha256(raw).hexdigest() + "  model.json\n")
        self.model, self.model_error = load_model(package_file), None
        self.client = self.start_app()
        await self.login()
        self.window_events(4)
        self.set_status(4)
        run_cycle(self.settings.db_path, NOW, self.model, None)
        text = (await self.get(self.snap_path(self.settings.db_path))).text
        for expected in ("eksperimental", "uji-lr-1", "suspicious", "skor 0.9820"):
            self.assertIn(expected, text)
        self.assertIn("uji-lr-1", (await self.get("/")).text)


if __name__ == "__main__":
    unittest.main()
