"""Tujuh fitur `login-window-v1` untuk satu window login (R-04).

Urutan FEATURE_NAMES adalah urutan kolom model. Training dan runtime wajib memakai
fungsi yang sama supaya angkanya tidak berbeda.
"""
from __future__ import annotations

import math
from typing import Any, Mapping, Sequence

from .events import parse_utc

FEATURE_VERSION = "login-window-v1"
WINDOW_SECONDS = 60
FEATURE_NAMES = (
    "event_count", "failure_count", "success_count", "failure_ratio",
    "distinct_accounts", "max_consecutive_failures", "active_span_seconds",
)
_INT_FEATURES = frozenset(FEATURE_NAMES) - {"failure_ratio", "active_span_seconds"}
_EVENT_TYPES = frozenset({"login.success", "login.failure"})


def sort_events(events: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    """Urutan event: waktu yang sudah di-parse, lalu event_id (bukan urutan string waktu)."""
    return sorted(events, key=lambda e: (parse_utc(e["occurred_at"]), e["event_id"]))


def _check_event(event: Mapping[str, Any]) -> None:
    if not isinstance(event, Mapping):
        raise ValueError("event must be an object")
    if not isinstance(event.get("event_id"), str) or not event["event_id"]:
        raise ValueError("event_id missing")
    if event.get("event_type") not in _EVENT_TYPES:
        raise ValueError("invalid event_type")
    if not isinstance(event.get("account_token"), str) or not event["account_token"]:
        raise ValueError("account_token missing")
    parse_utc(event.get("occurred_at"))


def compute_features(events: Sequence[Mapping[str, Any]]) -> dict[str, int | float]:
    """Hitung tujuh fitur dari event unik dalam satu window. Input kosong/rusak ditolak."""
    if not events:
        raise ValueError("window must contain at least one event")
    seen: set[str] = set()
    for event in events:
        _check_event(event)
        if event["event_id"] in seen:
            raise ValueError("duplicate event_id in window")
        seen.add(event["event_id"])
    ordered = sort_events(events)
    failures = successes = streak = longest = 0
    accounts: set[str] = set()
    for event in ordered:
        accounts.add(event["account_token"])
        if event["event_type"] == "login.failure":
            failures += 1
            streak += 1
            longest = max(longest, streak)
        else:
            successes += 1
            streak = 0
    span = (parse_utc(ordered[-1]["occurred_at"]) - parse_utc(ordered[0]["occurred_at"])).total_seconds()
    values: dict[str, int | float] = {
        "event_count": len(ordered),
        "failure_count": failures,
        "success_count": successes,
        "failure_ratio": failures / len(ordered),
        "distinct_accounts": len(accounts),
        "max_consecutive_failures": longest,
        "active_span_seconds": float(span),
    }
    validate_features(values)
    return values


def validate_features(values: Any) -> None:
    """Tolak field hilang, NaN, tipe salah, atau angka di luar jangkauan. Tidak ada nilai diganti nol."""
    if not isinstance(values, Mapping) or set(values) != set(FEATURE_NAMES):
        raise ValueError("feature fields do not match schema")
    for name in FEATURE_NAMES:
        value = values[name]
        if isinstance(value, bool):
            raise ValueError(f"invalid type for {name}")
        if name in _INT_FEATURES:
            if type(value) is not int:
                raise ValueError(f"invalid type for {name}")
        elif not isinstance(value, (int, float)) or not math.isfinite(value):
            raise ValueError(f"invalid number for {name}")
    if values["event_count"] < 1 or values["distinct_accounts"] < 1:
        raise ValueError("event_count and distinct_accounts must be at least 1")
    if values["failure_count"] < 0 or values["success_count"] < 0 or values["max_consecutive_failures"] < 0:
        raise ValueError("counts must not be negative")
    if values["failure_count"] + values["success_count"] != values["event_count"]:
        raise ValueError("success and failure counts must add up to event_count")
    if not 0 <= values["failure_ratio"] <= 1:
        raise ValueError("failure_ratio out of range")
    if values["max_consecutive_failures"] > values["failure_count"]:
        raise ValueError("max_consecutive_failures exceeds failure_count")
    if not 0 <= values["active_span_seconds"] < WINDOW_SECONDS:
        raise ValueError("active_span_seconds out of range")


def feature_vector(values: Mapping[str, Any]) -> list[float]:
    """Nilai fitur sebagai daftar angka dalam urutan kolom model."""
    validate_features(values)
    return [float(values[name]) for name in FEATURE_NAMES]
