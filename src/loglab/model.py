"""Paket model numerik (data-only) dan inferensi Logistic Regression (R-05).

Paket tidak pernah dieksekusi atau di-unpickle: hanya JSON angka yang divalidasi.
Format `model.json` di bawah mengikuti SRS ML-05; nama field persisnya perlu dicocokkan
dengan paket dari integrator (F-05) sebelum dipakai sungguhan.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from .db import connect
from .events import canonical_json
from .features import FEATURE_NAMES, FEATURE_VERSION, feature_vector

RESULT_KIND = "ml"
UNAVAILABLE_HASH = "unavailable"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class ModelError(ValueError):
    """Kesalahan paket dengan kode stabil yang aman ditampilkan (tanpa isi file)."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ModelPackage:
    model_hash: str
    model_version: str
    schema_version: str
    mean: tuple[float, ...]
    scale: tuple[float, ...]
    coefficients: tuple[float, ...]
    intercept: float
    threshold: float


def _reject_constant(_: str) -> Any:
    raise ModelError("invalid_number")  # NaN / Infinity tidak diterima


def _numbers(value: Any, count: int) -> tuple[float, ...]:
    if not isinstance(value, list) or len(value) != count:
        raise ModelError("invalid_schema")
    out = []
    for item in value:
        if isinstance(item, bool) or not isinstance(item, (int, float)) or not math.isfinite(item):
            raise ModelError("invalid_number")
        out.append(float(item))
    return tuple(out)


def _number(value: Any) -> float:
    return _numbers([value], 1)[0]


def load_model(model_path: Path | str, checksum_path: Path | str | None = None) -> ModelPackage:
    """Baca dan verifikasi paket. Hash, schema, urutan fitur, atau angka salah ditolak."""
    model_path = Path(model_path)
    checksum_path = Path(checksum_path) if checksum_path else model_path.with_name(model_path.name + ".sha256")
    try:
        data = model_path.read_bytes()
    except OSError:
        raise ModelError("model_missing") from None
    try:
        sidecar = checksum_path.read_text(encoding="ascii").split()
    except (OSError, UnicodeDecodeError):
        raise ModelError("checksum_missing") from None
    if not sidecar or not _HEX64.fullmatch(sidecar[0]):
        raise ModelError("checksum_invalid_format")
    actual = hashlib.sha256(data).hexdigest()
    if not hmac.compare_digest(actual, sidecar[0]):
        raise ModelError("hash_mismatch")
    try:
        payload = json.loads(data.decode("utf-8"), parse_constant=_reject_constant)
    except (ValueError, UnicodeDecodeError) as exc:
        if isinstance(exc, ModelError):
            raise
        raise ModelError("invalid_json") from None
    if not isinstance(payload, dict):
        raise ModelError("invalid_schema")
    version, schema = payload.get("model_version"), payload.get("schema_version")
    if not isinstance(version, str) or not version or len(version) > 64:
        raise ModelError("invalid_schema")
    if schema != FEATURE_VERSION:
        raise ModelError("invalid_schema")
    if payload.get("feature_names") != list(FEATURE_NAMES):
        raise ModelError("feature_order_mismatch")
    scaler = payload.get("scaler")
    if not isinstance(scaler, dict):
        raise ModelError("invalid_schema")
    count = len(FEATURE_NAMES)
    mean, scale = _numbers(scaler.get("mean"), count), _numbers(scaler.get("scale"), count)
    coefficients = _numbers(payload.get("coefficients"), count)
    intercept, threshold = _number(payload.get("intercept")), _number(payload.get("threshold"))
    if any(s <= 0 for s in scale) or not 0 < threshold < 1:
        raise ModelError("invalid_number")
    return ModelPackage(actual, version, schema, mean, scale, coefficients, intercept, threshold)


def _sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


def predict(package: ModelPackage, features: Mapping[str, Any]) -> dict[str, Any]:
    """StandardScaler lalu Logistic Regression. Fitur tidak valid ditolak (ValueError)."""
    vector = feature_vector(features)
    logit = package.intercept + sum(
        c * ((x - m) / s) for c, x, m, s in zip(package.coefficients, vector, package.mean, package.scale))
    score = _sigmoid(logit)
    return {"score": score, "label": "suspicious" if score >= package.threshold else "normal",
            "threshold": package.threshold}


def _stamp(now: datetime) -> str:
    return now.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def infer_pending(db_path: Path | str, package: ModelPackage | None, package_error: str | None,
                  now: datetime) -> int:
    """Hitung hasil ML untuk revisi yang belum punya, di luar transaksi ingest.

    Identitas hasil: (snapshot_id, revision, model_hash). Baris `pending` dibuat dulu, lalu
    diselesaikan; jika proses mati di tengah, startup berikutnya melanjutkan baris pending.
    Label hanya ada pada state `succeeded`.
    """
    model_hash = package.model_hash if package else UNAVAILABLE_HASH
    with connect(db_path) as db:
        db.execute(
            "INSERT OR IGNORE INTO analysis_results(snapshot_id, revision, model_hash, result_kind, state, label,"
            " score, reason, evidence_json, updated_at)"
            " SELECT s.snapshot_id, s.revision, ?, ?, 'pending', NULL, NULL, 'queued', '{}', ? FROM snapshots s",
            (model_hash, RESULT_KIND, _stamp(now)))
        todo = db.execute(
            "SELECT s.snapshot_id, s.revision, s.quality, s.quality_reason, s.features_json FROM snapshots s"
            " JOIN analysis_results r ON r.snapshot_id=s.snapshot_id AND r.revision=s.revision"
            " WHERE r.model_hash=? AND r.result_kind=? AND r.state='pending' ORDER BY s.window_start, s.revision",
            (model_hash, RESULT_KIND)).fetchall()
    finished = 0
    for snap in todo:
        label = score = None
        evidence: dict[str, Any] = {"snapshot_id": snap["snapshot_id"], "revision": snap["revision"],
                                    "model_hash": model_hash, "experimental": True}
        if snap["quality"] != "READY":
            state, reason = "ineligible", snap["quality_reason"]
        elif package is None:
            state, reason = "failed", "model_unavailable:" + (package_error or "unknown")
        else:
            try:
                result = predict(package, json.loads(snap["features_json"])["values"])
            except (ValueError, KeyError, TypeError):
                state, reason = "failed", "inference_error"
            else:
                state, reason, label, score = "succeeded", "predicted", result["label"], result["score"]
                evidence.update(model_version=package.model_version, threshold=result["threshold"],
                                feature_version=FEATURE_VERSION)
        with connect(db_path) as db:  # transaksi pendek per hasil
            db.execute(
                "UPDATE analysis_results SET state=?, label=?, score=?, reason=?, evidence_json=?, updated_at=?"
                " WHERE snapshot_id=? AND revision=? AND model_hash=? AND result_kind=? AND state='pending'",
                (state, label, score, reason, canonical_json(evidence).decode("utf-8"), _stamp(now),
                 snap["snapshot_id"], snap["revision"], model_hash, RESULT_KIND))
        finished += 1
    return finished


def retry_failed(db_path: Path | str, model_hash: str) -> int:
    """Coba ulang hasil `failed` secara eksplisit setelah penyebabnya diperbaiki."""
    with connect(db_path) as db:
        cursor = db.execute(
            "UPDATE analysis_results SET state='pending', reason='retry_requested', label=NULL, score=NULL"
            " WHERE result_kind=? AND model_hash=? AND state='failed'", (RESULT_KIND, model_hash))
        return cursor.rowcount
