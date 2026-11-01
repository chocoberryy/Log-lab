"""Kumpulkan bukti nyata untuk tabel "Catatan hasil" (R-07).

Pakai (dari ~/LogLab):  .venv/bin/python deployment/monitor/evidence.py
Skrip menjalankan tes dan pemeriksaan kontrak di mesin ini, mencatat commit yang diuji, lalu
mencetak baris tabel siap tempel. Output mentah lengkap disimpan PRIVAT di ~/loglab-evidence/
(di luar Git). Hanya ringkasan aman yang dicetak: tanpa token, password, atau isi database.
Pemeriksaan manual di VM (reboot, firewall, TLS di browser, restore) tidak bisa dijalankan skrip ini;
isi barisnya sendiri setelah benar-benar mencobanya.
"""
from __future__ import annotations

import io
import platform
import subprocess
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

# (label, modul tes, potongan nama tes atau None, tindakan, hasil yang diharapkan)
CASES = [
    ("R3-01 event valid", "tests.test_monitor_app", "test_r3_01", "unittest test_r3_01", "event tersimpan, receipt sama dengan fixture"),
    ("R3-02 duplikat", "tests.test_monitor_app", "test_r3_02", "unittest test_r3_02", "event sama dikirim dua kali: satu record, receipt kedua duplicate"),
    ("R3-03 konflik", "tests.test_monitor_app", "test_r3_03", "unittest test_r3_03", "ID/sequence konflik ditolak 409, data awal utuh"),
    ("R3-04 input salah", "tests.test_monitor_app", "test_r3_04", "unittest test_r3_04", "token/schema/digest/ukuran salah ditolak, tanpa secret di catatan"),
    ("R3-05 status sumber", "tests.test_monitor_app", "test_r3_05", "unittest test_r3_05", "status divalidasi dan bukan event login"),
    ("Startup dan /health", "tests.test_monitor_app", "EntrypointTests", "unittest EntrypointTests", "import tanpa efek samping, health publik minimal, ingest jalan tanpa model"),
    ("R-04 fitur login-window-v1", "tests.test_features", None, "unittest tests.test_features", "tujuh fitur sesuai contoh tangan; input rusak ditolak"),
    ("R-04 analisis: window, kualitas, revisi, rules", "tests.test_analysis", None, "unittest tests.test_analysis", "OPEN/STALE/INCOMPLETE/READY benar; revisi immutable; batas 9/10 gagal dan 4/5 akun"),
    ("R-05 model: loader dan inferensi", "tests.test_model", None, "unittest tests.test_model", "hash/schema/urutan fitur divalidasi; skor sama dengan hitungan tangan (1e-8)"),
    ("R-05 console operator", "tests.test_console", None, "unittest tests.test_console", "sesi, CSRF, rate limit, filter, pagination, escaping, state hasil benar"),
    ("R-06 konfigurasi deployment dan restore drill", "tests.test_deployment", None, "unittest tests.test_deployment", "unit, firewall, izin, setup konsisten dengan kontrak; restore drill lulus"),
]


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True).stdout.strip()


def run_group(module: str, needle: str | None) -> tuple[int, int, int, str]:
    suite = unittest.TestSuite()
    loaded = unittest.defaultTestLoader.loadTestsFromName(module)

    def flatten(item):
        for sub in item:
            if isinstance(sub, unittest.TestSuite):
                yield from flatten(sub)
            else:
                yield sub

    for test in flatten(loaded):
        if needle is None or needle in test.id():
            suite.addTest(test)
    stream = io.StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    return result.testsRun, len(result.failures), len(result.errors), stream.getvalue()


def make_check(target: str) -> tuple[bool, str]:
    done = subprocess.run(["make", target], cwd=ROOT, capture_output=True, text=True)
    return done.returncode == 0, done.stdout + done.stderr


def main() -> int:
    commit = git("rev-parse", "--short", "HEAD") or "tidak diketahui"
    dirty = bool(git("status", "--porcelain"))  # termasuk berkas baru yang belum di-add
    tag = commit + (" (+perubahan belum di-commit)" if dirty else "")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    private = Path.home() / "loglab-evidence"
    private.mkdir(mode=0o700, exist_ok=True)
    raw_path = private / f"arhasya-{stamp}.log"
    raw = [f"commit: {tag}", f"python: {platform.python_version()} {platform.platform()}", f"waktu: {stamp}", ""]
    rows, failed = [], False
    for label, module, needle, action, expected in CASES:
        run, bad, err, text = run_group(module, needle)
        ok = run > 0 and bad == 0 and err == 0
        failed = failed or not ok
        raw += [f"=== {label} ({module}, {needle})", text]
        actual = f"{run} tes dijalankan, {bad} gagal, {err} error"
        rows.append((label, tag, action, expected, actual, "Lulus" if ok else "GAGAL"))
    for target, expected in (("check-contract", "PASS: contract 1.0.0 ..."), ("test-contract", "semua tes kontrak OK")):
        ok, text = make_check(target)
        failed = failed or not ok
        raw += [f"=== make {target}", text]
        lines = [line for line in text.strip().splitlines() if line.strip()]
        last = next((line for line in lines if line.startswith(("PASS", "OK"))), lines[-1] if lines else "(tanpa output)")
        rows.append((f"make {target}", tag, f"make {target}", expected, last[:120], "Lulus" if ok else "GAGAL"))
    total = unittest.TestSuite(unittest.defaultTestLoader.discover(str(ROOT / "tests"), top_level_dir=str(ROOT / "tests")))
    stream = io.StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=0).run(total)
    full_ok = result.wasSuccessful()
    failed = failed or not full_ok
    raw += ["=== make test (discover)", stream.getvalue()]
    rows.append(("Seluruh tes proyek", tag, "make test", "semua tes lulus",
                 f"{result.testsRun} tes, {len(result.failures)} gagal, {len(result.errors)} error", "Lulus" if full_ok else "GAGAL"))
    raw_path.write_text("\n".join(raw), encoding="utf-8")
    raw_path.chmod(0o600)
    print("| Langkah atau case | Commit yang diuji | Perintah atau tindakan | Hasil yang diharapkan | Hasil nyata dan bukti aman | Status |")
    print("| --- | --- | --- | --- | --- | --- |")
    for row in rows:
        print("| " + " | ".join(row) + " |")
    print(f"\nOutput mentah privat: {raw_path} (jangan di-commit)")
    if dirty:
        print("PERINGATAN: ada perubahan belum di-commit. Commit dulu, lalu jalankan ulang agar commit yang dicatat benar-benar yang diuji.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
