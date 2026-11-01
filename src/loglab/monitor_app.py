"""Aplikasi Monitor: menerima event login dan status dari Source (R-03).

Urutan penting untuk setiap event: periksa -> simpan (commit) -> baru balas receipt.
"""
from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import logging
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from .analysis import run_cycle
from .config import Settings
from .console import register_console
from .db import connect, initialize_monitor
from .events import (build_receipt, event_json, parse_utc, utc_now,
                     validate_event, validate_source_status)

MAX_BODY_BYTES = 8 * 1024  # batas payload satu event: 8 KiB (EP-04)
ANALYSIS_INTERVAL_SECONDS = 5  # jeda antar putaran analisis (di luar transaksi ingest)
log = logging.getLogger("loglab.monitor")


def _error(status: int, code: str) -> JSONResponse:
    """Semua error berbentuk JSON dengan satu field: {'error': '<kode>'}."""
    return JSONResponse({"error": code}, status_code=status)


def _record_rejection(db_path: Path, source_id: str | None, reason: str) -> None:
    """Catat alasan penolakan. Isi request (body/token) TIDAK pernah dicatat."""
    try:
        with connect(db_path) as db:
            db.execute(
                "INSERT INTO ingest_rejections(received_at, source_id, reason_code) VALUES(?,?,?)",
                (utc_now(), source_id, reason),
            )
    except sqlite3.Error:
        pass  # gagal mencatat alasan tidak boleh mengubah jawaban ke Source


def _store_event(db_path: Path, event: dict[str, Any]) -> tuple[str | None, str | None]:
    """Simpan event dalam SATU transaksi.

    Mengembalikan (status, None) bila berhasil: 'stored' atau 'duplicate'.
    Mengembalikan (None, kode_error) bila konflik.
    Commit terjadi saat blok `with` selesai, sebelum fungsi ini kembali.
    """
    with connect(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        existing = db.execute(
            "SELECT event_digest FROM monitor_events WHERE source_id=? AND event_id=?",
            (event["source_id"], event["event_id"]),
        ).fetchone()
        if existing is not None:
            if existing["event_digest"] == event["event_digest"]:
                return "duplicate", None  # sama persis: sah, tidak ada record baru
            return None, "event_conflict"  # ID sama, isi beda
        taken = db.execute(
            "SELECT 1 FROM monitor_events WHERE source_id=? AND stream_id=? AND sequence=?",
            (event["source_id"], event["stream_id"], event["sequence"]),
        ).fetchone()
        if taken is not None:
            return None, "sequence_conflict"  # urutan sudah dipakai event lain
        db.execute(
            "INSERT INTO monitor_events(source_id, stream_id, event_id, sequence, occurred_at,"
            " event_type, account_token, client_token, reason_code, event_digest,"
            " received_at, payload_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (event["source_id"], event["stream_id"], event["event_id"], event["sequence"],
             event["occurred_at"], event["event_type"], event["account_token"],
             event["client_token"], event["reason_code"], event["event_digest"],
             utc_now(), event_json(event)),
        )
        return "stored", None


def _store_status(db_path: Path, status: dict[str, Any]) -> dict[str, Any]:
    """Simpan/perbarui status sumber. Status BUKAN event login."""
    received = utc_now()
    offset_ms = int((parse_utc(received) - parse_utc(status["source_time"])).total_seconds() * 1000)
    with connect(db_path) as db:
        db.execute(
            "INSERT INTO source_status(source_id, stream_id, committed_sequence,"
            " acknowledged_sequence, pending_count, held_count, rejected_count, offered_count,"
            " accepted_local_count, source_time, received_at, clock_offset_ms)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)"
            " ON CONFLICT(source_id, stream_id) DO UPDATE SET"
            " committed_sequence=excluded.committed_sequence,"
            " acknowledged_sequence=excluded.acknowledged_sequence,"
            " pending_count=excluded.pending_count, held_count=excluded.held_count,"
            " rejected_count=excluded.rejected_count, offered_count=excluded.offered_count,"
            " accepted_local_count=excluded.accepted_local_count,"
            " source_time=excluded.source_time, received_at=excluded.received_at,"
            " clock_offset_ms=excluded.clock_offset_ms",
            (status["source_id"], status["stream_id"], status["committed_sequence"],
             status["acknowledged_sequence"], status["pending_count"], status["held_count"],
             status["rejected_count"], status["offered_count"], status["accepted_local_count"],
             status["source_time"], received, offset_ms),
        )
    return {"status": "accepted", "source_id": status["source_id"],
            "received_at": received, "clock_offset_ms": offset_ms}


def _seed_operator(settings: Settings) -> None:
    """Salin akun operator dari konfigurasi ke database (hash sudah di-hash, bukan password mentah)."""
    if settings.operator_username and settings.operator_password_hash:
        with connect(settings.db_path) as db:
            db.execute(
                "INSERT INTO operators(username, password_hash, active) VALUES(?,?,1)"
                " ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash, active=1",
                (settings.operator_username, settings.operator_password_hash))


def create_app(settings: Settings, *, model: Any = None, model_error: str | None = None,
               start_analysis: bool = False, clock=time.time) -> FastAPI:
    """Membuat aplikasi Monitor dari satu objek Settings.

    `model` adalah paket hasil load_model() atau None; `model_error` adalah kode alasan bila gagal dimuat.
    `start_analysis=True` menyalakan loop analisis latar belakang (dipakai saat produksi).
    """
    initialize_monitor(settings.db_path)
    _seed_operator(settings)
    db_path = settings.db_path

    @contextlib.asynccontextmanager
    async def lifespan(_: FastAPI):
        task = None
        if start_analysis:
            async def analysis_loop() -> None:
                while True:
                    try:
                        now = datetime.fromtimestamp(clock(), timezone.utc)
                        await run_in_threadpool(run_cycle, db_path, now, model, model_error)
                    except Exception as exc:  # kegagalan analisis tidak boleh menjatuhkan penerimaan event
                        log.warning("siklus analisis gagal: %s", type(exc).__name__)
                    await asyncio.sleep(ANALYSIS_INTERVAL_SECONDS)
            task = asyncio.create_task(analysis_loop())
        try:
            yield
        finally:
            if task is not None:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task

    app = FastAPI(title="LogLab Monitor", lifespan=lifespan)

    def model_status() -> dict[str, Any]:
        if model is not None:
            return {"loaded": True, "version": model.model_version, "hash": model.model_hash}
        return {"loaded": False, "error": model_error or "model_not_configured"}

    @app.get("/health")
    def health() -> dict[str, str]:
        """Liveness publik minimal. HTTP 200 bukan bukti delivery, analisis, atau restore."""
        return {"service": "loglab-monitor", "state": "ready", "contract_version": settings.contract_version}

    register_console(app, settings, model_status=model_status, clock=clock)

    def authorized(request: Request) -> bool:
        header = request.headers.get("authorization", "")
        token = header[7:] if header.startswith("Bearer ") else ""
        # compare_digest membandingkan dalam waktu tetap supaya token tidak bisa ditebak
        return hmac.compare_digest(token.encode("utf-8"), settings.source_token.encode("utf-8"))

    async def read_json(request: Request) -> tuple[Any, JSONResponse | None, str | None]:
        """Baca body dengan batas ukuran, lalu parse JSON."""
        declared = request.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > MAX_BODY_BYTES:
            return None, _error(413, "request_too_large"), "request_too_large"
        body = await request.body()
        if len(body) > MAX_BODY_BYTES:
            return None, _error(413, "request_too_large"), "request_too_large"
        try:
            return json.loads(body), None, None
        except (ValueError, UnicodeDecodeError):
            return None, _error(400, "invalid_json"), "invalid_json"

    @app.post("/api/v1/events")
    async def ingest_event(request: Request) -> JSONResponse:
        if not authorized(request):
            await run_in_threadpool(_record_rejection, db_path, None, "unauthorized")
            return _error(401, "unauthorized")
        event, failure, reason = await read_json(request)
        if failure is not None:
            await run_in_threadpool(_record_rejection, db_path, None, reason)
            return failure
        try:
            validate_event(event)
        except ValueError:
            await run_in_threadpool(_record_rejection, db_path, None, "invalid_event")
            return _error(422, "invalid_event")
        if event["source_id"] != settings.source_id:
            await run_in_threadpool(_record_rejection, db_path, None, "unknown_source")
            return _error(401, "unknown_source")
        try:
            status, conflict = await run_in_threadpool(_store_event, db_path, event)
        except sqlite3.Error:
            return _error(503, "service_unavailable")
        if conflict is not None:
            await run_in_threadpool(_record_rejection, db_path, event["source_id"], conflict)
            return _error(409, conflict)
        # Sampai sini transaksi SUDAH commit; baru sekarang receipt dikirim.
        return JSONResponse(build_receipt(event, status), status_code=200)

    @app.post("/api/v1/source-status")
    async def ingest_status(request: Request) -> JSONResponse:
        if not authorized(request):
            await run_in_threadpool(_record_rejection, db_path, None, "unauthorized")
            return _error(401, "unauthorized")
        status, failure, reason = await read_json(request)
        if failure is not None:
            await run_in_threadpool(_record_rejection, db_path, None, reason)
            return failure
        try:
            validate_source_status(status)
        except ValueError:
            await run_in_threadpool(_record_rejection, db_path, None, "invalid_source_status")
            return _error(422, "invalid_source_status")
        if status["source_id"] != settings.source_id:
            await run_in_threadpool(_record_rejection, db_path, None, "unknown_source")
            return _error(401, "unknown_source")
        try:
            answer = await run_in_threadpool(_store_status, db_path, status)
        except sqlite3.Error:
            return _error(503, "service_unavailable")
        return JSONResponse(answer, status_code=200)

    return app
