from datetime import datetime, timedelta, timezone
from pathlib import Path
import hashlib
import json
import tempfile
import unittest

from loglab.analysis import iso_z, seal_due_snapshots
from loglab.db import connect, initialize_monitor
from loglab.events import build_event
from loglab.features import FEATURE_NAMES
from loglab.model import ModelError, infer_pending, load_model, predict, retry_failed

T0 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
NOW = datetime(2026, 1, 1, 0, 1, 20, tzinfo=timezone.utc)
SOURCE, STREAM, CLIENT, ACCOUNT = "login-lab-a", "11111111-1111-4111-8111-111111111111", "b" * 64, "a" * 64
FEATURES = {"event_count": 5, "failure_count": 4, "success_count": 1, "failure_ratio": 0.8,
            "distinct_accounts": 1, "max_consecutive_failures": 4, "active_span_seconds": 40.0}


def payload(**changes):
    base = {"model_version": "test-lr-1", "schema_version": "login-window-v1", "feature_names": list(FEATURE_NAMES),
            "scaler": {"mean": [0.0] * 7, "scale": [1.0] * 7}, "coefficients": [0, 0, 0, 2, 0, 0, 0],
            "intercept": -1, "threshold": 0.5}
    base.update(changes)
    return base


class PackageCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.model = self.dir / "model.json"

    def write(self, data, sidecar="auto"):
        raw = data if isinstance(data, bytes) else json.dumps(data, sort_keys=True).encode()
        self.model.write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest() if sidecar == "auto" else sidecar
        if digest is not None:
            (self.dir / "model.json.sha256").write_text(digest + "  model.json\n")
        return hashlib.sha256(raw).hexdigest()

    def code(self):
        with self.assertRaises(ModelError) as caught:
            load_model(self.model)
        return caught.exception.code


class LoaderTests(PackageCase):
    def test_valid_package_loads_and_identity_is_the_file_hash(self):
        digest = self.write(payload())
        package = load_model(self.model)
        self.assertEqual(package.model_hash, digest)
        self.assertEqual((package.model_version, package.threshold), ("test-lr-1", 0.5))

    def test_rejections_have_stable_codes(self):
        self.assertEqual(self.code(), "model_missing")
        self.write(payload(), sidecar=None)
        self.assertEqual(self.code(), "checksum_missing")
        self.write(payload(), sidecar="xyz")
        self.assertEqual(self.code(), "checksum_invalid_format")
        self.write(payload(), sidecar="0" * 64)
        self.assertEqual(self.code(), "hash_mismatch")
        self.write(b"{not json")
        self.assertEqual(self.code(), "invalid_json")
        self.write(b"[1,2,3]")
        self.assertEqual(self.code(), "invalid_schema")

    def test_schema_order_and_numbers_are_validated(self):
        names = list(FEATURE_NAMES)
        swapped = [names[1], names[0], *names[2:]]
        cases = {
            "feature order": (payload(feature_names=swapped), "feature_order_mismatch"),
            "schema version": (payload(schema_version="login-window-v2"), "invalid_schema"),
            "no version": (payload(model_version=""), "invalid_schema"),
            "short vector": (payload(coefficients=[0, 0, 0]), "invalid_schema"),
            "text number": (payload(intercept="1"), "invalid_number"),
            "bool number": (payload(intercept=True), "invalid_number"),
            "zero scale": (payload(scaler={"mean": [0.0] * 7, "scale": [1, 1, 1, 0, 1, 1, 1]}), "invalid_number"),
            "threshold 1": (payload(threshold=1.0), "invalid_number"),
            "no scaler": (payload(scaler=None), "invalid_schema"),
        }
        for name, (data, expected) in cases.items():
            with self.subTest(name):
                self.write(data)
                self.assertEqual(self.code(), expected)

    def test_nan_infinity_and_overflow_are_rejected(self):
        for name, raw in {
            "nan": b'{"model_version":"x","intercept":NaN}',
            "infinity": b'{"model_version":"x","intercept":Infinity}',
        }.items():
            with self.subTest(name):
                self.write(raw)
                self.assertEqual(self.code(), "invalid_number")
        good = json.dumps(payload(), sort_keys=True).replace('"intercept": -1', '"intercept": 1e999')
        self.write(good.encode())
        self.assertEqual(self.code(), "invalid_number")

    def test_package_changed_after_checksum_is_rejected(self):
        self.write(payload())
        self.model.write_bytes(self.model.read_bytes().replace(b"-1", b"-2"))
        self.assertEqual(self.code(), "hash_mismatch")


class PredictTests(PackageCase):
    def test_score_matches_hand_calculation(self):
        self.write(payload())
        result = predict(load_model(self.model), FEATURES)  # logit = -1 + 2*0.8 = 0.6
        self.assertAlmostEqual(result["score"], 0.6456563062257954, delta=1e-8)
        self.assertEqual(result["label"], "suspicious")

    def test_scaler_is_applied_per_feature(self):
        self.write(payload(scaler={"mean": [2, 1, 0, 0.5, 1, 1, 10], "scale": [3, 2, 1, 0.5, 2, 2, 20]},
                           coefficients=[0.5, 1.0, -0.5, 2.0, 0.25, 0.75, -0.1], intercept=-0.3))
        result = predict(load_model(self.model), FEATURES)  # logit 3.375, dihitung tangan
        self.assertAlmostEqual(result["score"], 0.9669140216112958, delta=1e-8)

    def test_threshold_decides_label_and_normal_is_possible(self):
        self.write(payload(threshold=0.9))
        self.assertEqual(predict(load_model(self.model), FEATURES)["label"], "normal")
        self.write(payload(intercept=-50, threshold=0.5))
        quiet = predict(load_model(self.model), dict(FEATURES, failure_ratio=0.0, failure_count=0,
                                                        success_count=5, max_consecutive_failures=0))
        self.assertEqual(quiet["label"], "normal")
        self.assertGreaterEqual(quiet["score"], 0.0)  # tidak overflow untuk logit sangat negatif

    def test_invalid_features_are_rejected_not_defaulted(self):
        self.write(payload())
        package = load_model(self.model)
        broken = dict(FEATURES)
        del broken["failure_ratio"]
        for bad in (broken, dict(FEATURES, failure_ratio=float("nan")), dict(FEATURES, extra=1)):
            with self.assertRaises(ValueError):
                predict(package, bad)


class InferenceTests(PackageCase):
    def setUp(self):
        super().setUp()
        self.db_path = self.dir / "monitor.sqlite3"
        initialize_monitor(self.db_path)

    def make_snapshot(self, ready=True):
        columns = ("source_id,stream_id,event_id,sequence,occurred_at,event_type,account_token,client_token,"
                   "reason_code,event_digest,received_at,payload_json")
        for number in range(1, 5):
            stamp = iso_z(T0 + timedelta(seconds=number * 5))
            event = build_event(source_id=SOURCE, stream_id=STREAM, sequence=number, occurred_at=stamp,
                                event_type="login.failure", account_token=ACCOUNT, client_token=CLIENT,
                                reason_code="INVALID_CREDENTIALS", event_id="00000000-0000-4000-8000-%012d" % number)
            with connect(self.db_path) as db:
                db.execute("INSERT INTO monitor_events(%s) VALUES(%s)" % (columns, ",".join("?" * 12)),
                           (SOURCE, STREAM, event["event_id"], number, stamp, event["event_type"], ACCOUNT, CLIENT,
                            event["reason_code"], event["event_digest"], stamp, "{}"))
        if ready:
            with connect(self.db_path) as db:
                db.execute("INSERT INTO source_status VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                           (SOURCE, STREAM, 4, 4, 0, 0, 0, 4, 4, iso_z(T0 + timedelta(seconds=71)),
                            iso_z(T0 + timedelta(seconds=72)), 100))
        seal_due_snapshots(self.db_path, NOW)

    def ml(self):
        with connect(self.db_path) as db:
            return [dict(r) for r in db.execute("SELECT * FROM analysis_results WHERE result_kind='ml' ORDER BY revision")]

    def test_ready_snapshot_gets_prediction_and_rerun_adds_nothing(self):
        self.write(payload(coefficients=[0, 0, 0, 0, 0, 1, 0], intercept=0, threshold=0.5))
        package = load_model(self.model)
        self.make_snapshot()
        self.assertEqual(infer_pending(self.db_path, package, None, NOW), 1)
        (row,) = self.ml()
        self.assertEqual((row["state"], row["label"], row["model_hash"]), ("succeeded", "suspicious", package.model_hash))
        self.assertAlmostEqual(row["score"], 0.9820137900379085, delta=1e-8)  # sigmoid(4), 4 gagal beruntun
        self.assertEqual(json.loads(row["evidence_json"])["model_version"], "test-lr-1")
        self.assertTrue(json.loads(row["evidence_json"])["experimental"])
        self.assertEqual(infer_pending(self.db_path, package, None, NOW), 0)
        self.assertEqual(len(self.ml()), 1)

    def test_not_ready_snapshot_is_ineligible_without_label(self):
        self.write(payload())
        package = load_model(self.model)
        self.make_snapshot(ready=False)
        infer_pending(self.db_path, package, None, NOW)
        (row,) = self.ml()
        self.assertEqual((row["state"], row["label"], row["score"], row["reason"]), ("ineligible", None, None, "heartbeat_missing"))

    def test_missing_package_gives_failed_with_visible_reason_never_normal(self):
        self.make_snapshot()
        infer_pending(self.db_path, None, "model_missing", NOW)
        (row,) = self.ml()
        self.assertEqual((row["state"], row["label"], row["model_hash"], row["reason"]),
                         ("failed", None, "unavailable", "model_unavailable:model_missing"))

    def test_crash_leaves_pending_and_next_start_resumes(self):
        self.write(payload())
        package = load_model(self.model)
        self.make_snapshot()
        with connect(self.db_path) as db:  # keadaan setelah crash: baris pending sudah dibuat
            db.execute("INSERT INTO analysis_results SELECT snapshot_id, revision, ?, 'ml', 'pending', NULL, NULL,"
                       " 'queued', '{}', ? FROM snapshots", (package.model_hash, iso_z(NOW)))
        self.assertEqual(infer_pending(self.db_path, package, None, NOW), 1)
        self.assertEqual(self.ml()[0]["state"], "succeeded")
        self.assertEqual(len(self.ml()), 1)

    def test_failed_can_be_retried_explicitly_after_fixing_the_cause(self):
        self.make_snapshot()
        infer_pending(self.db_path, None, "model_missing", NOW)
        self.assertEqual(infer_pending(self.db_path, None, "model_missing", NOW), 0)  # tidak mencoba ulang sendiri
        self.assertEqual(retry_failed(self.db_path, "unavailable"), 1)
        self.assertEqual(self.ml()[0]["state"], "pending")

    def test_new_package_gets_its_own_result_and_old_one_stays(self):
        self.make_snapshot()
        self.write(payload())
        first = load_model(self.model)
        infer_pending(self.db_path, first, None, NOW)
        self.write(payload(threshold=0.9))
        second = load_model(self.model)
        self.assertNotEqual(first.model_hash, second.model_hash)
        infer_pending(self.db_path, second, None, NOW)
        self.assertEqual(sorted(r["model_hash"] for r in self.ml()), sorted([first.model_hash, second.model_hash]))


if __name__ == "__main__":
    unittest.main()
