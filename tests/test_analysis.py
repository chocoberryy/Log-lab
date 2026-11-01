from datetime import datetime, timedelta, timezone
from pathlib import Path
import json
import tempfile
import unittest

from loglab.analysis import (apply_rules, evaluate_quality, evaluate_rules, iso_z,
                             latest_revision, run_cycle, seal_due_snapshots, snapshot_id, window_end,
                             window_start)
from loglab.db import connect, initialize_monitor
from loglab.events import build_event, parse_utc

SOURCE = "login-lab-a"
STREAM = "11111111-1111-4111-8111-111111111111"
CLIENT = "b" * 64
ACCOUNT = "a" * 64
T0 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)  # awal window uji
COLUMNS = ("source_id,stream_id,event_id,sequence,occurred_at,event_type,account_token,client_token,"
           "reason_code,event_digest,received_at,payload_json")


def at(seconds):
    return T0 + timedelta(seconds=seconds)


class AnalysisCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db_path = Path(tmp.name) / "monitor.sqlite3"
        initialize_monitor(self.db_path)
        self.counter = 0

    # ---- bantuan data ----
    def add_event(self, second, kind="login.failure", account=ACCOUNT, stream=STREAM, client=CLIENT, sequence=None):
        self.counter += 1
        number = sequence or self.counter
        reason = "SUCCESS" if kind == "login.success" else "INVALID_CREDENTIALS"
        stamp = iso_z(at(second))
        event = build_event(
            source_id=SOURCE, stream_id=stream, sequence=number, occurred_at=stamp, event_type=kind,
            account_token=account, client_token=client, reason_code=reason,
            event_id="00000000-0000-4000-8000-%012d" % (number + (0 if stream == STREAM else 5000)))
        with connect(self.db_path) as db:
            db.execute("INSERT INTO monitor_events(%s) VALUES(%s)" % (COLUMNS, ",".join("?" * 12)),
                       (SOURCE, stream, event["event_id"], number, stamp, kind, account, client, reason,
                        event["event_digest"], stamp, json.dumps(event)))
        return event

    def set_status(self, committed, ack=None, held=0, source_second=71, received_second=72, offset=100, stream=STREAM):
        with connect(self.db_path) as db:
            db.execute(
                "INSERT OR REPLACE INTO source_status VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (SOURCE, stream, committed, committed if ack is None else ack, 0, held, 0, committed, committed,
                 iso_z(at(source_second)), iso_z(at(received_second)), offset))

    def snapshots(self):
        with connect(self.db_path) as db:
            return [dict(r) for r in db.execute("SELECT * FROM snapshots ORDER BY window_start, revision")]

    def results(self, kind="rules"):
        with connect(self.db_path) as db:
            return [dict(r) for r in db.execute(
                "SELECT * FROM analysis_results WHERE result_kind=? ORDER BY snapshot_id, revision", (kind,))]

    def ready_window(self, failures=3, successes=0):
        for i in range(failures):
            self.add_event(i * 2)
        for i in range(successes):
            self.add_event(50 + i, "login.success")
        self.set_status(failures + successes)


class WindowTests(unittest.TestCase):
    def test_tumbling_boundaries_are_half_open(self):
        self.assertEqual(window_start(parse_utc("2026-01-01T00:00:59.999Z")), T0)
        self.assertEqual(window_start(parse_utc("2026-01-01T00:01:00.000Z")), at(60))
        self.assertEqual(window_end(T0), at(60))
        self.assertEqual(window_start(parse_utc("2026-01-01T00:00:00Z")), T0)

    def test_snapshot_id_is_stable_and_depends_on_key(self):
        a = snapshot_id(SOURCE, STREAM, CLIENT, iso_z(T0))
        self.assertEqual(a, snapshot_id(SOURCE, STREAM, CLIENT, iso_z(T0)))
        self.assertNotEqual(a, snapshot_id(SOURCE, STREAM, "c" * 64, iso_z(T0)))
        self.assertNotEqual(a, snapshot_id(SOURCE, STREAM, CLIENT, iso_z(at(60))))


class QualityTests(unittest.TestCase):
    END = at(60)

    def status(self, **changes):
        base = {"committed_sequence": 5, "acknowledged_sequence": 5, "held_count": 0, "clock_offset_ms": 100,
                "source_time": iso_z(at(71)), "received_at": iso_z(at(72))}
        base.update(changes)
        return base

    def quality(self, now_second=75, status="default", stored=5):
        status = self.status() if status == "default" else status
        return evaluate_quality(end=self.END, now=at(now_second), status=status, stored_through_committed=stored)

    def test_each_state_and_reason(self):
        cases = [
            ("open before end+10", self.quality(now_second=69), ("OPEN", "window_open")),
            ("no heartbeat", self.quality(status=None), ("STALE", "heartbeat_missing")),
            ("old heartbeat", self.quality(now_second=93), ("STALE", "heartbeat_stale")),
            ("clock offset too large", self.quality(status=self.status(clock_offset_ms=2001)), ("INCOMPLETE", "clock_offset_exceeded")),
            ("negative offset too large", self.quality(status=self.status(clock_offset_ms=-2500)), ("INCOMPLETE", "clock_offset_exceeded")),
            ("offset unmeasured", self.quality(status=self.status(clock_offset_ms=None)), ("INCOMPLETE", "clock_offset_unmeasured")),
            ("held events", self.quality(status=self.status(held_count=1)), ("INCOMPLETE", "held_events")),
            ("source time before close", self.quality(status=self.status(source_time=iso_z(at(69)))), ("INCOMPLETE", "source_time_before_close")),
            ("ack behind", self.quality(status=self.status(acknowledged_sequence=4)), ("INCOMPLETE", "ack_behind_committed")),
            ("sequence gap", self.quality(stored=4), ("INCOMPLETE", "sequence_gap")),
            ("everything proven", self.quality(), ("READY", "all_conditions_met")),
            ("offset exactly 2s is ok", self.quality(status=self.status(clock_offset_ms=2000)), ("READY", "all_conditions_met")),
            ("exactly end+10 closes", self.quality(now_second=70), ("READY", "all_conditions_met")),
        ]
        for name, actual, expected in cases:
            with self.subTest(name):
                self.assertEqual(actual, expected)


class SnapshotTests(AnalysisCase):
    def test_ready_snapshot_has_features_membership_and_revision_one(self):
        self.ready_window(failures=3, successes=1)
        self.assertEqual(seal_due_snapshots(self.db_path, at(75)), 1)
        (snap,) = self.snapshots()
        self.assertEqual((snap["quality"], snap["quality_reason"], snap["revision"]), ("READY", "all_conditions_met", 1))
        self.assertEqual(snap["window_start"], iso_z(T0))
        self.assertEqual(snap["window_end"], iso_z(at(60)))
        values = json.loads(snap["features_json"])["values"]
        self.assertEqual((values["event_count"], values["failure_count"], values["success_count"]), (4, 3, 1))
        members = json.loads(snap["membership_json"])["events"]
        self.assertEqual(len(members), 4)
        self.assertEqual([m["event_id"] for m in members], sorted(m["event_id"] for m in members))  # waktu lalu id

    def test_open_window_is_not_sealed_and_empty_window_makes_no_snapshot(self):
        self.ready_window()
        self.assertEqual(seal_due_snapshots(self.db_path, at(69)), 0)  # belum end+10
        self.assertEqual(self.snapshots(), [])
        self.assertEqual(seal_due_snapshots(self.db_path, at(75) + timedelta(days=3)), 0)  # terlalu lama: di luar lookback
        empty = Path(tempfile.mkdtemp()) / "m.sqlite3"
        initialize_monitor(empty)
        self.assertEqual(seal_due_snapshots(empty, at(75)), 0)

    def test_same_input_does_not_add_a_revision(self):
        self.ready_window()
        seal_due_snapshots(self.db_path, at(75))
        self.assertEqual(seal_due_snapshots(self.db_path, at(80)), 0)
        self.assertEqual(len(self.snapshots()), 1)

    def test_heartbeat_refresh_without_class_change_adds_no_revision(self):
        self.ready_window()
        seal_due_snapshots(self.db_path, at(75))
        self.set_status(3, source_second=81, received_second=82)  # heartbeat rutin lebih baru
        self.assertEqual(seal_due_snapshots(self.db_path, at(85)), 0)

    def test_quality_class_change_creates_new_revision_and_keeps_old(self):
        for i in range(3):
            self.add_event(i * 2)
        seal_due_snapshots(self.db_path, at(75))  # belum ada heartbeat -> STALE
        self.assertEqual(self.snapshots()[0]["quality"], "STALE")
        self.set_status(3)  # heartbeat tiba -> READY
        self.assertEqual(seal_due_snapshots(self.db_path, at(76)), 1)
        first, second = self.snapshots()
        self.assertEqual((first["revision"], first["quality"]), (1, "STALE"))
        self.assertEqual((second["revision"], second["quality"]), (2, "READY"))
        self.assertNotEqual(first["input_hash"], second["input_hash"])
        with connect(self.db_path) as db:
            self.assertEqual(latest_revision(db, first["snapshot_id"]), 2)  # revisi 1 = superseded

    def test_late_event_creates_new_revision_with_new_membership(self):
        self.ready_window(failures=3)
        seal_due_snapshots(self.db_path, at(75))
        self.add_event(30)  # event terlambat, occurred_at masih di window pertama
        self.set_status(4)
        self.assertEqual(seal_due_snapshots(self.db_path, at(80)), 1)
        first, second = self.snapshots()
        self.assertEqual(len(json.loads(first["membership_json"])["events"]), 3)
        self.assertEqual(len(json.loads(second["membership_json"])["events"]), 4)

    def test_each_incomplete_cause_is_visible(self):
        cases = [
            ("gap", dict(), dict(committed=5, stored=(1, 2, 3, 5)), "sequence_gap"),
            ("offset", dict(offset=2500), dict(committed=3, stored=(1, 2, 3)), "clock_offset_exceeded"),
            ("held", dict(held=1), dict(committed=3, stored=(1, 2, 3)), "held_events"),
            ("ack", dict(ack=2), dict(committed=3, stored=(1, 2, 3)), "ack_behind_committed"),
        ]
        for name, status_args, data, reason in cases:
            with self.subTest(name):
                self.setUp()
                for number in data["stored"]:
                    self.add_event(number, sequence=number)
                self.set_status(data["committed"], **status_args)
                seal_due_snapshots(self.db_path, at(75))
                (snap,) = self.snapshots()
                self.assertEqual((snap["quality"], snap["quality_reason"]), ("INCOMPLETE", reason))

    def test_stale_heartbeat(self):
        self.ready_window()
        seal_due_snapshots(self.db_path, at(95))  # heartbeat diterima di detik 72, sekarang 95 (>20 detik)
        (snap,) = self.snapshots()
        self.assertEqual((snap["quality"], snap["quality_reason"]), ("STALE", "heartbeat_stale"))

    def test_membership_is_deterministic_across_arrival_order(self):
        events = [self.add_event(s) for s in (5, 20, 10)]
        self.set_status(3)
        seal_due_snapshots(self.db_path, at(75))
        hash_a = self.snapshots()[0]["input_hash"]
        self.setUp()  # database baru; event yang sama persis disisipkan dengan urutan terbalik
        for event in reversed(events):
            with connect(self.db_path) as db:
                db.execute("INSERT INTO monitor_events(%s) VALUES(%s)" % (COLUMNS, ",".join("?" * 12)),
                           (SOURCE, STREAM, event["event_id"], event["sequence"], event["occurred_at"],
                            event["event_type"], event["account_token"], CLIENT, event["reason_code"],
                            event["event_digest"], event["occurred_at"], json.dumps(event)))
        self.set_status(3)
        seal_due_snapshots(self.db_path, at(75))
        self.assertEqual(self.snapshots()[0]["input_hash"], hash_a)

    def test_boundary_events_and_separate_keys_make_separate_snapshots(self):
        self.add_event(59.999)
        self.add_event(60)  # tepat batas: masuk window berikutnya
        self.add_event(10, client="c" * 64)
        self.add_event(10, stream="22222222-2222-4222-8222-222222222222")
        self.set_status(2)
        self.set_status(1, stream="22222222-2222-4222-8222-222222222222")
        seal_due_snapshots(self.db_path, at(135))
        snaps = self.snapshots()
        self.assertEqual(len(snaps), 4)
        counts = sorted(json.loads(s["features_json"])["values"]["event_count"] for s in snaps)
        self.assertEqual(counts, [1, 1, 1, 1])
        self.assertEqual(len({s["snapshot_id"] for s in snaps}), 4)
        self.assertEqual(sorted(s["window_start"] for s in snaps).count(iso_z(T0)), 3)


class RulesTests(AnalysisCase):
    def triggered(self, failures, accounts):
        features = {"failure_count": failures, "distinct_accounts": accounts}
        return [t["rule"] for t in evaluate_rules(features)]

    def test_threshold_boundaries(self):
        self.assertEqual(self.triggered(9, 9), [])
        self.assertEqual(self.triggered(10, 1), ["REPEATED_FAILURES"])
        self.assertEqual(self.triggered(10, 4), ["REPEATED_FAILURES"])
        self.assertEqual(self.triggered(10, 5), ["REPEATED_FAILURES", "ACCOUNT_SWEEP"])
        self.assertEqual(self.triggered(9, 5), [])

    def window_with(self, failures, accounts):
        for i in range(failures):
            self.add_event(i, account=("%064x" % ((i % accounts) + 1)))
        self.set_status(failures)
        seal_due_snapshots(self.db_path, at(75))
        apply_rules(self.db_path, at(76))
        return self.results()[-1]

    def test_ten_failures_five_accounts_is_stored_with_evidence(self):
        result = self.window_with(10, 5)
        self.assertEqual((result["state"], result["label"]), ("succeeded", "suspicious"))
        self.assertEqual(result["model_hash"], "rules-v1")
        self.assertEqual(result["reason"], "rules_triggered:REPEATED_FAILURES,ACCOUNT_SWEEP")
        evidence = json.loads(result["evidence_json"])
        self.assertEqual(evidence["rules_version"], "rules-v1")
        self.assertEqual(evidence["revision"], 1)
        self.assertEqual(evidence["feature_values"]["failure_count"], 10)
        self.assertEqual([t["rule"] for t in evidence["triggered"]], ["REPEATED_FAILURES", "ACCOUNT_SWEEP"])
        self.assertEqual(len(evidence["supporting_event_ids"]), 10)

    def test_nine_failures_is_normal_but_only_when_ready(self):
        result = self.window_with(9, 5)
        self.assertEqual((result["state"], result["label"], result["reason"]), ("succeeded", "normal", "no_rule_triggered"))

    def test_not_ready_snapshot_never_gets_a_label(self):
        for i in range(12):
            self.add_event(i)  # tanpa heartbeat -> STALE
        seal_due_snapshots(self.db_path, at(75))
        apply_rules(self.db_path, at(76))
        result = self.results()[0]
        self.assertEqual((result["state"], result["label"], result["reason"]), ("ineligible", None, "heartbeat_missing"))

    def test_rules_are_idempotent_and_new_revision_gets_its_own_result(self):
        self.ready_window(failures=3)
        seal_due_snapshots(self.db_path, at(75))
        self.assertEqual(apply_rules(self.db_path, at(76)), 1)
        self.assertEqual(apply_rules(self.db_path, at(77)), 0)
        self.add_event(30)
        self.set_status(4)
        seal_due_snapshots(self.db_path, at(80))
        self.assertEqual(apply_rules(self.db_path, at(81)), 1)
        self.assertEqual([r["revision"] for r in self.results()], [1, 2])  # hasil lama tetap ada

    def test_run_cycle_without_model_marks_ready_ml_results_failed_not_normal(self):
        self.ready_window(failures=3)
        outcome = run_cycle(self.db_path, at(75), package=None, package_error="model_missing")
        self.assertEqual(outcome["sealed"], 1)
        (ml,) = self.results("ml")
        self.assertEqual((ml["state"], ml["label"], ml["reason"]), ("failed", None, "model_unavailable:model_missing"))


if __name__ == "__main__":
    unittest.main()
