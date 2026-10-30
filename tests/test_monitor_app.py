from pathlib import Path
import json
import secrets
import tempfile
import unittest
 
from fastapi.testclient import TestClient
 
from loglab.config import Settings
from loglab.db import connect
from loglab.events import build_event
from loglab.monitor_app import create_app
from loglab.testing import fixture
 
EVENTS = "/api/v1/events"
STATUS = "/api/v1/source-status"
 
 
def make_event(**changes):
    """Buat event valid dari fixture, dengan beberapa field diganti (digest dihitung ulang)."""
    base = {k: v for k, v in fixture("login-success").items()
            if k not in ("event_digest", "schema_version")}
    base.update(changes)
    return build_event(**base)
 
 
class MonitorIngestTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.token = secrets.token_hex(32)
        self.settings = Settings.for_test("monitor", Path(tmp.name), source_token=self.token)
        self.client = TestClient(create_app(self.settings))
        self.auth = {"Authorization": "Bearer " + self.token}
 
    def query(self, sql, args=()):
        with connect(self.settings.db_path) as db:
            return [dict(row) for row in db.execute(sql, args)]
 
    def count(self, table):
        return self.query("SELECT COUNT(*) AS n FROM " + table)[0]["n"]
 
    def post(self, path, payload, headers=None):
        return self.client.post(path, json=payload, headers=self.auth if headers is None else headers)
 
    # ---- R3-01: event valid tersimpan dan receipt cocok ----
    def test_r3_01_valid_event_is_stored_and_receipt_matches(self):
        event = fixture("login-success")
        response = self.post(EVENTS, event)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), fixture("stored-receipt"))
        rows = self.query("SELECT * FROM monitor_events")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["event_id"], event["event_id"])
        self.assertEqual(rows[0]["event_digest"], event["event_digest"])
        self.assertEqual(json.loads(rows[0]["payload_json"]), event)
        self.assertTrue(rows[0]["received_at"].endswith("Z"))  # diisi Monitor, bukan Source
 
    # ---- R3-02: event identik dikirim ulang = satu record, receipt duplicate ----
    def test_r3_02_identical_event_is_duplicate_not_second_record(self):
        event = fixture("login-success")
        first = self.post(EVENTS, event)
        second = self.post(EVENTS, event)
        self.assertEqual(first.json()["status"], "stored")
        self.assertEqual(second.status_code, 200)
        self.assertEqual(second.json()["status"], "duplicate")
        self.assertEqual(second.json()["event_digest"], event["event_digest"])
        self.assertEqual(self.count("monitor_events"), 1)
 
    # ---- R3-03: ID/sequence konflik ditolak, data awal tidak berubah ----
    def test_r3_03_conflicts_are_rejected_and_original_is_kept(self):
        original = fixture("login-success")
        self.post(EVENTS, original)
        same_id_other_content = make_event(sequence=3)  # event_id sama, isi beda
        response = self.post(EVENTS, same_id_other_content)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json(), {"error": "event_conflict"})
        same_sequence_other_id = make_event(event_id="55555555-5555-4555-8555-555555555555")
        response = self.post(EVENTS, same_sequence_other_id)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json(), {"error": "sequence_conflict"})
        rows = self.query("SELECT * FROM monitor_events")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["event_digest"], original["event_digest"])
        self.assertEqual(rows[0]["sequence"], original["sequence"])
 
    # ---- R3-04: input salah ditolak pada kategori yang benar, tanpa membocorkan secret ----
    def test_r3_04_bad_requests_are_rejected_safely(self):
        event = fixture("login-success")
        bad_digest = dict(event, event_digest="0" * 64)
        extra_field = dict(event, password="rahasia")
        cases = [
            ("wrong token", dict(json=event, headers={"Authorization": "Bearer salah"}), 401, "unauthorized"),
            ("no token", dict(json=event, headers={}), 401, "unauthorized"),
            ("bad digest", dict(json=bad_digest, headers=self.auth), 422, "invalid_event"),
            ("extra field", dict(json=extra_field, headers=self.auth), 422, "invalid_event"),
            ("not an object", dict(json=[1, 2], headers=self.auth), 422, "invalid_event"),
            ("broken json", dict(content=b"{bukan json", headers=self.auth), 400, "invalid_json"),
            ("too large", dict(content=b"x" * 9000, headers=self.auth), 413, "request_too_large"),
            ("unknown source", dict(json=make_event(source_id="lab-lain"), headers=self.auth), 401, "unknown_source"),
        ]
        for name, kwargs, code, error in cases:
            with self.subTest(name):
                response = self.client.post(EVENTS, **kwargs)
                self.assertEqual(response.status_code, code)
                self.assertEqual(response.json(), {"error": error})
        self.assertEqual(self.count("monitor_events"), 0)
        rejections = self.query("SELECT * FROM ingest_rejections")
        self.assertEqual(len(rejections), len(cases))
        self.assertNotIn(self.token, json.dumps(rejections))
        self.assertNotIn("rahasia", json.dumps(rejections))
 
    # ---- R3-05: status sumber tidak menambah event login ----
    def test_r3_05_source_status_is_validated_and_is_not_an_event(self):
        status = fixture("source-status")
        response = self.post(STATUS, status)
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["status"], "accepted")
        self.assertEqual(body["source_id"], status["source_id"])
        self.assertIn("received_at", body)
        self.assertIsInstance(body["clock_offset_ms"], int)
        self.assertEqual(self.count("source_status"), 1)
        self.assertEqual(self.count("monitor_events"), 0)
        self.post(STATUS, dict(status, committed_sequence=5))  # kirim lagi: diperbarui, bukan dobel
        self.assertEqual(self.count("source_status"), 1)
        self.assertEqual(self.query("SELECT committed_sequence FROM source_status")[0]["committed_sequence"], 5)
        invalid = self.post(STATUS, dict(status, acknowledged_sequence=100))
        self.assertEqual(invalid.status_code, 422)
        self.assertEqual(invalid.json(), {"error": "invalid_source_status"})
        self.assertEqual(self.post(STATUS, status, headers={}).status_code, 401)
        self.assertEqual(self.count("monitor_events"), 0)
 
 
if __name__ == "__main__":
    unittest.main()
