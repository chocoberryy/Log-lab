"""Window, kualitas snapshot, revisi immutable, dan rules (R-04).

Semua fungsi menerima `now` sebagai parameter supaya tes deterministik. Analisis berjalan
di luar transaksi ingest dan tidak pernah mengubah event yang sudah tersimpan.
"""
from __future__ import annotations

import calendar
import hashlib
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from .db import connect
from .events import canonical_json, parse_utc
from .features import FEATURE_VERSION, WINDOW_SECONDS, compute_features

CLOSE_DELAY_SECONDS = 10         # window dievaluasi paling cepat end + 10 detik
HEARTBEAT_STALE_SECONDS = 20     # heartbeat lebih tua dari ini dianggap stale
MAX_CLOCK_OFFSET_MS = 2000       # offset jam maksimal 2 detik
LOOKBACK_SECONDS = 24 * 3600     # window yang dievaluasi ulang: 24 jam terakhir
RULES_VERSION = "rules-v1"
RULES_RESULT_KIND = "rules"
FAILURE_THRESHOLD = 10
ACCOUNT_THRESHOLD = 5
QUALITY_STATES = ("OPEN", "STALE", "INCOMPLETE", "READY")


def iso_z(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def window_start(moment: datetime) -> datetime:
    """Awal window 60 detik (tumbling) yang memuat `moment`; interval [start, end)."""
    seconds = calendar.timegm(moment.astimezone(timezone.utc).utctimetuple())
    return datetime.fromtimestamp(seconds - seconds % WINDOW_SECONDS, timezone.utc)


def window_end(start: datetime) -> datetime:
    return start + timedelta(seconds=WINDOW_SECONDS)


def snapshot_id(source_id: str, stream_id: str, client_token: str, start_iso: str) -> str:
    raw = "\x1f".join((source_id, stream_id, client_token, start_iso, FEATURE_VERSION))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _json(value: Any) -> str:
    return canonical_json(value).decode("utf-8")


# ---------------------------------------------------------------- kualitas

def evaluate_quality(*, end: datetime, now: datetime, status: Mapping[str, Any] | None,
                     stored_through_committed: int) -> tuple[str, str]:
    """Kembalikan (state, alasan). Hanya READY yang boleh diberi label."""
    close_at = end + timedelta(seconds=CLOSE_DELAY_SECONDS)
    if now < close_at:
        return "OPEN", "window_open"
    if status is None:
        return "STALE", "heartbeat_missing"
    age = (now - parse_utc(status["received_at"])).total_seconds()
    if age > HEARTBEAT_STALE_SECONDS:
        return "STALE", "heartbeat_stale"
    offset = status.get("clock_offset_ms")
    if offset is None:
        return "INCOMPLETE", "clock_offset_unmeasured"
    if abs(offset) > MAX_CLOCK_OFFSET_MS:
        return "INCOMPLETE", "clock_offset_exceeded"
    if status["held_count"] > 0:
        return "INCOMPLETE", "held_events"
    if parse_utc(status["source_time"]) < close_at:
        return "INCOMPLETE", "source_time_before_close"
    if status["acknowledged_sequence"] != status["committed_sequence"]:
        return "INCOMPLETE", "ack_behind_committed"
    if stored_through_committed != status["committed_sequence"]:
        return "INCOMPLETE", "sequence_gap"
    return "READY", "all_conditions_met"


# ------------------------------------------------------------ snapshot/revisi

def _status_rows(db: sqlite3.Connection) -> dict[tuple[str, str], dict[str, Any]]:
    return {(r["source_id"], r["stream_id"]): dict(r) for r in db.execute("SELECT * FROM source_status")}


def seal_due_snapshots(db_path: Path | str, now: datetime, lookback_seconds: int = LOOKBACK_SECONDS) -> int:
    """Segel window yang sudah melewati end+10 detik. Mengembalikan jumlah revisi baru.

    Input identik tidak menambah revisi. Event terlambat atau perubahan kelas kualitas
    membuat revisi baru; revisi lama tetap tersimpan.
    """
    lower = now - timedelta(seconds=lookback_seconds + WINDOW_SECONDS)
    created = 0
    with connect(db_path) as db:
        rows = db.execute(
            "SELECT * FROM monitor_events WHERE occurred_at >= ? ORDER BY occurred_at, event_id",
            (iso_z(lower - timedelta(seconds=120)),)).fetchall()
        windows: dict[tuple[str, str, str, datetime], list[dict[str, Any]]] = {}
        for row in rows:
            moment = parse_utc(row["occurred_at"])
            start = window_start(moment)
            if start < window_start(lower):
                continue
            windows.setdefault((row["source_id"], row["stream_id"], row["client_token"], start), []).append(dict(row))
        statuses = _status_rows(db)
        stored_cache: dict[tuple[str, str, int], int] = {}
        for (source_id, stream_id, client_token, start), members in sorted(windows.items(), key=lambda i: i[0][3]):
            end = window_end(start)
            if now < end + timedelta(seconds=CLOSE_DELAY_SECONDS):
                continue  # masih OPEN: belum disegel
            status = statuses.get((source_id, stream_id))
            stored = 0
            if status is not None:
                key = (source_id, stream_id, status["committed_sequence"])
                if key not in stored_cache:
                    stored_cache[key] = db.execute(
                        "SELECT COUNT(*) FROM monitor_events WHERE source_id=? AND stream_id=? AND sequence<=?",
                        (source_id, stream_id, status["committed_sequence"])).fetchone()[0]
                stored = stored_cache[key]
            quality, reason = evaluate_quality(end=end, now=now, status=status, stored_through_committed=stored)
            features = compute_features(members)
            ordered = sorted(members, key=lambda e: (parse_utc(e["occurred_at"]), e["event_id"]))
            membership = [{"event_id": e["event_id"], "event_digest": e["event_digest"]} for e in ordered]
            input_hash = hashlib.sha256(canonical_json({
                "membership": membership, "feature_version": FEATURE_VERSION, "quality": quality})).hexdigest()
            sid = snapshot_id(source_id, stream_id, client_token, iso_z(start))
            db.execute("BEGIN IMMEDIATE")
            last = db.execute("SELECT revision, input_hash FROM snapshots WHERE snapshot_id=? ORDER BY revision DESC LIMIT 1",
                              (sid,)).fetchone()
            if last is not None and last["input_hash"] == input_hash:
                db.execute("COMMIT")
                continue
            revision = 1 if last is None else last["revision"] + 1
            evidence = None if status is None else {k: status[k] for k in (
                "committed_sequence", "acknowledged_sequence", "held_count", "source_time",
                "received_at", "clock_offset_ms")}
            db.execute(
                "INSERT INTO snapshots(snapshot_id, source_id, stream_id, client_token, window_start, window_end,"
                " revision, input_hash, quality, quality_reason, features_json, membership_json, sealed_at)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (sid, source_id, stream_id, client_token, iso_z(start), iso_z(end), revision, input_hash,
                 quality, reason, _json({"version": FEATURE_VERSION, "values": features}),
                 _json({"events": membership, "seal_evidence": evidence, "sealed_now": iso_z(now)}), iso_z(now)))
            db.execute("COMMIT")
            created += 1
    return created


def latest_revision(db: sqlite3.Connection, sid: str) -> int | None:
    row = db.execute("SELECT MAX(revision) FROM snapshots WHERE snapshot_id=?", (sid,)).fetchone()
    return row[0]


# --------------------------------------------------------------------- rules

def evaluate_rules(features: Mapping[str, Any]) -> list[dict[str, Any]]:
    """rules-v1. Mengembalikan daftar rule yang terpicu beserta ambang dan nilai yang diamati."""
    triggered: list[dict[str, Any]] = []
    failures, accounts = features["failure_count"], features["distinct_accounts"]
    if failures >= FAILURE_THRESHOLD:
        triggered.append({"rule": "REPEATED_FAILURES", "threshold": {"failure_count": FAILURE_THRESHOLD},
                          "observed": {"failure_count": failures}})
    if failures >= FAILURE_THRESHOLD and accounts >= ACCOUNT_THRESHOLD:
        triggered.append({"rule": "ACCOUNT_SWEEP",
                          "threshold": {"failure_count": FAILURE_THRESHOLD, "distinct_accounts": ACCOUNT_THRESHOLD},
                          "observed": {"failure_count": failures, "distinct_accounts": accounts}})
    return triggered


def apply_rules(db_path: Path | str, now: datetime) -> int:
    """Beri hasil rules pada setiap revisi yang belum punya. Idempotent."""
    written = 0
    with connect(db_path) as db:
        todo = db.execute(
            "SELECT s.* FROM snapshots s LEFT JOIN analysis_results r ON r.snapshot_id=s.snapshot_id"
            " AND r.revision=s.revision AND r.model_hash=? AND r.result_kind=?"
            " WHERE r.snapshot_id IS NULL ORDER BY s.window_start, s.revision",
            (RULES_VERSION, RULES_RESULT_KIND)).fetchall()
        for snap in todo:
            features = json.loads(snap["features_json"])["values"]
            member_ids = [m["event_id"] for m in json.loads(snap["membership_json"])["events"]]
            base = {"rules_version": RULES_VERSION, "snapshot_id": snap["snapshot_id"], "revision": snap["revision"],
                    "feature_version": FEATURE_VERSION}
            if snap["quality"] != "READY":
                state, label, reason = "ineligible", None, snap["quality_reason"]
                evidence = dict(base, quality=snap["quality"])
            else:
                triggered = evaluate_rules(features)
                failure_ids: list[str] = []
                if triggered and member_ids:
                    marks = ",".join("?" * len(member_ids))
                    failure_ids = [r[0] for r in db.execute(
                        "SELECT event_id FROM monitor_events WHERE source_id=? AND event_type='login.failure'"
                        " AND event_id IN (%s) ORDER BY occurred_at, event_id" % marks,
                        (snap["source_id"], *member_ids))]
                state = "succeeded"
                label = "suspicious" if triggered else "normal"
                reason = ("rules_triggered:" + ",".join(t["rule"] for t in triggered)) if triggered else "no_rule_triggered"
                evidence = dict(base, triggered=triggered, feature_values=features, supporting_event_ids=failure_ids)
            db.execute(
                "INSERT OR IGNORE INTO analysis_results(snapshot_id, revision, model_hash, result_kind, state, label,"
                " score, reason, evidence_json, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (snap["snapshot_id"], snap["revision"], RULES_VERSION, RULES_RESULT_KIND, state, label, None,
                 reason, _json(evidence), iso_z(now)))
            written += 1
    return written


def run_cycle(db_path: Path | str, now: datetime, package: Any = None, package_error: str | None = None) -> dict[str, int]:
    """Satu putaran analisis: segel snapshot, hitung rules, lalu inferensi model."""
    from .model import infer_pending  # impor lokal: model.py tidak mengimpor analysis.py
    sealed = seal_due_snapshots(db_path, now)
    ruled = apply_rules(db_path, now)
    inferred = infer_pending(db_path, package, package_error, now)
    return {"sealed": sealed, "rules": ruled, "ml": inferred}
