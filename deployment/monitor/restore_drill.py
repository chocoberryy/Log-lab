"""Latihan restore Monitor (OP-03): periksa backup di folder terisolasi, tanpa menyentuh data aktif.

Pakai:  .venv/bin/python deployment/monitor/restore_drill.py [--backup BERKAS] [--live DB_AKTIF]
Keluaran: integrity_check, foreign_key_check, jumlah baris per tabel, dan model_hash yang tercatat.
Kode keluar 0 hanya bila backup utuh dan konsisten.
"""
from __future__ import annotations

import argparse
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

TABLES = ("monitor_events", "source_status", "ingest_rejections", "snapshots", "analysis_results", "operators")


def counts(path: Path) -> dict[str, int]:
    with sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True) as db:
        return {table: db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in TABLES}


def drill(backup: Path, live: Path | None) -> tuple[bool, list[str]]:
    lines: list[str] = []
    if not backup.is_file():
        return False, [f"GAGAL: backup tidak ditemukan: {backup}"]
    with tempfile.TemporaryDirectory(prefix="loglab-restore-") as folder:
        restored = Path(folder) / "restored.sqlite3"
        shutil.copyfile(backup, restored)  # bekerja pada salinan; backup asli tidak diubah
        restored.chmod(0o600)
        with sqlite3.connect(restored) as db:
            integrity = db.execute("PRAGMA integrity_check").fetchone()[0]
            foreign = db.execute("PRAGMA foreign_key_check").fetchall()
            version = db.execute("PRAGMA user_version").fetchone()[0]
            models = [r[0] for r in db.execute("SELECT DISTINCT model_hash FROM analysis_results ORDER BY model_hash")]
            duplicates = db.execute(
                "SELECT COUNT(*) FROM (SELECT source_id, stream_id, sequence FROM monitor_events "
                "GROUP BY 1,2,3 HAVING COUNT(*) > 1)").fetchone()[0]
        found = counts(restored)
    ok = integrity == "ok" and not foreign and duplicates == 0
    lines.append(f"integrity_check : {integrity}")
    lines.append(f"foreign_key_check: {'bersih' if not foreign else str(len(foreign)) + ' pelanggaran'}")
    lines.append(f"sequence ganda   : {duplicates}")
    lines.append(f"schema version   : {version}")
    for table in TABLES:
        lines.append(f"{table:<18}: {found[table]}")
    lines.append("model_hash tercatat: " + (", ".join(models) if models else "(belum ada hasil)"))
    if live is not None and live.is_file():
        now = counts(live)
        for table in ("monitor_events", "snapshots", "analysis_results"):
            lines.append(f"selisih {table:<17}: aktif {now[table]} vs backup {found[table]} (aktif boleh lebih banyak)")
            ok = ok and now[table] >= found[table]
    lines.append("HASIL: " + ("LULUS" if ok else "GAGAL"))
    return ok, lines


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backup", type=Path, default=Path("/var/backups/loglab/daily.sqlite3"))
    parser.add_argument("--live", type=Path, default=Path("/var/lib/loglab/monitor.sqlite3"))
    args = parser.parse_args()
    ok, lines = drill(args.backup, args.live)
    print("\n".join(lines))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
