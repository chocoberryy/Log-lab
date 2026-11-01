from pathlib import Path
import importlib.util
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

from loglab.analysis import run_cycle
from loglab.backup import create_atomic_backup
from loglab.db import connect, initialize_monitor
from loglab.events import build_event
from loglab.contract import ROOT

DEPLOY = ROOT / "deployment" / "monitor"
CONTRACT = json.loads((ROOT / "config" / "contract.json").read_text(encoding="utf-8"))
MONITOR = CONTRACT["roles"]["monitor"]
NETWORK = CONTRACT["network"]
SERVICE = (DEPLOY / "loglab-monitor.service").read_text()
NFT = (DEPLOY / "monitor.nft").read_text()
SETUP = (DEPLOY / "setup.sh").read_text()


def exec_start():
    return re.search(r"^ExecStart=(.*)$", SERVICE, re.M).group(1)


class ServiceUnitTests(unittest.TestCase):
    def test_unit_uses_contract_values(self):
        self.assertIn("User=loglab-svc", SERVICE)
        self.assertIn("EnvironmentFile=" + MONITOR["env_file"], SERVICE)
        self.assertIn("WorkingDirectory=" + CONTRACT["paths"]["project"], SERVICE)
        self.assertTrue(exec_start().startswith(CONTRACT["paths"]["venv"] + "/bin/python -m uvicorn " + MONITOR["entrypoint"] + " "))
        self.assertIn("ReadWritePaths=" + CONTRACT["paths"]["data"] + " " + CONTRACT["paths"]["backup"], SERVICE)
        self.assertIn("Restart=always", SERVICE)
        self.assertEqual(MONITOR["service"], "loglab-monitor.service")

    def test_bind_port_and_tls_come_from_env_not_hardcoded(self):
        command = exec_start()
        for variable in ("LOGLAB_BIND_HOST", "LOGLAB_PORT", "LOGLAB_TLS_KEY", "LOGLAB_TLS_CERT"):
            self.assertIn("${%s}" % variable, command)
        self.assertNotIn(MONITOR["ip"], command)
        self.assertNotIn(str(NETWORK["https_port"]), command)

    def test_unit_is_hardened_and_does_not_log_requests(self):
        for directive in ("NoNewPrivileges=true", "ProtectSystem=strict", "PrivateTmp=true", "ProtectHome=read-only"):
            self.assertIn(directive, SERVICE)
        for flag in ("--no-access-log", "--timeout-graceful-shutdown"):
            self.assertIn(flag, exec_start())

    def test_backup_units_use_contract_paths(self):
        backup = (DEPLOY / "loglab-monitor-backup.service").read_text()
        self.assertIn("--source " + MONITOR["db_file"], backup)
        self.assertIn("--destination " + CONTRACT["paths"]["backup_file"], backup)
        self.assertIn("User=loglab-svc", backup)
        self.assertIn("Persistent=true", (DEPLOY / "loglab-monitor-backup.timer").read_text())


class FirewallTests(unittest.TestCase):
    def rules(self):
        return [line.strip() for line in NFT.splitlines() if "accept" in line and not line.strip().startswith("#")]

    def test_every_contract_inbound_rule_is_present(self):
        for rule in NETWORK["inbound_tcp"]["monitor"]:
            ports = rule["ports"]
            wanted = ("tcp dport { %s }" % ", ".join(map(str, ports))) if len(ports) > 1 else "tcp dport %d" % ports[0]
            self.assertTrue(any("ip saddr %s %s accept" % (rule["from"], wanted) in r for r in self.rules()), rule)

    def test_default_deny_and_source_cannot_reach_ssh(self):
        chains = dict(re.findall(r"chain (\w+) \{\s*type filter hook \w+ priority filter; policy (\w+);", NFT))
        self.assertEqual(chains["input"], "drop")  # masuk: default-deny
        self.assertEqual(chains["forward"], "drop")
        source_rules = [r for r in self.rules() if "172.16.202.21" in r and "tcp dport" in r]
        self.assertEqual(len(source_rules), 1)
        self.assertNotIn("22", source_rules[0].split("dport")[1])
        for ip in set(re.findall(r"\b172\.16\.202\.\d+\b", NFT)):
            self.assertIn(ip, {NETWORK["host_ip"], "172.16.202.21"})

    def test_no_rule_opens_the_database_or_any_port_to_everyone(self):
        for rule in self.rules():
            if "tcp dport" in rule:
                self.assertIn("ip saddr", rule)
        self.assertNotIn("0.0.0.0/0", NFT)


class SetupScriptTests(unittest.TestCase):
    def test_syntax_is_valid(self):
        if shutil.which("bash") is None:
            self.skipTest("bash tidak tersedia")
        for name in ("setup.sh", "make-test-tls.sh"):
            result = subprocess.run(["bash", "-n", str(DEPLOY / name)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_permissions_follow_the_contract(self):
        self.assertRegex(SETUP, r"install -d -o root -g \"\$SERVICE_USER\" -m 0750 \"\$CONF_DIR\"")
        self.assertRegex(SETUP, r"install -d -o \"\$SERVICE_USER\" -g \"\$SERVICE_USER\" -m 0700 \"\$DATA_DIR\" \"\$BACKUP_DIR\"")
        self.assertIn("chmod 0600 \"$ENV_FILE\"", SETUP)
        self.assertIn("chmod 0640 \"${CONF_DIR}/tls.key\"", SETUP)
        self.assertEqual(MONITOR["env_file"], "/etc/loglab/monitor.env")
        self.assertIn('CONF_DIR="/etc/loglab"', SETUP)
        self.assertIn('DATA_DIR="/var/lib/loglab"', SETUP)

    def test_setup_validates_env_before_starting_and_never_overwrites_existing_secrets(self):
        self.assertLess(SETUP.index("validate_env\n    check_tls"), SETUP.index("start_service\n    health_check"))
        self.assertIn("scripts/check_contract.py\" --role monitor --env", SETUP)
        self.assertIn('if [ -e "$ENV_FILE" ]; then', SETUP)
        self.assertNotIn("777", SETUP)
        self.assertNotIn("chmod -R", SETUP)

    def test_setup_checks_service_account_access_and_ssh_isolation(self):
        self.assertIn("import loglab.monitor_main", SETUP)
        self.assertIn('.ssh', SETUP)
        self.assertIn("openssl verify -CAfile", SETUP)
        self.assertIn("IP Address:${MONITOR_IP}", SETUP)
        self.assertIn("nft -c -f", SETUP)  # sintaks diperiksa sebelum firewall lama diganti

    def test_test_tls_helper_makes_a_valid_chain_with_the_monitor_san_and_refuses_to_overwrite(self):
        if shutil.which("openssl") is None:
            self.skipTest("openssl tidak tersedia")
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "tls"
            first = subprocess.run(["bash", str(DEPLOY / "make-test-tls.sh"), str(out)], capture_output=True, text=True)
            self.assertEqual(first.returncode, 0, first.stderr)
            san = subprocess.run(["openssl", "x509", "-in", str(out / "tls.crt"), "-noout", "-ext", "subjectAltName"],
                                 capture_output=True, text=True).stdout
            self.assertIn("IP Address:" + MONITOR["ip"], san)
            verify = subprocess.run(["openssl", "verify", "-CAfile", str(out / "ca.crt"), str(out / "tls.crt")],
                                    capture_output=True, text=True)
            self.assertEqual(verify.returncode, 0, verify.stderr)
            self.assertEqual(oct((out / "tls.key").stat().st_mode & 0o777), "0o600")
            second = subprocess.run(["bash", str(DEPLOY / "make-test-tls.sh"), str(out)], capture_output=True, text=True)
            self.assertNotEqual(second.returncode, 0)


def load_drill():
    spec = importlib.util.spec_from_file_location("restore_drill", DEPLOY / "restore_drill.py")
    module = importlib.util.module_from_spec(spec)
    previous, sys.dont_write_bytecode = sys.dont_write_bytecode, True  # jangan buat __pycache__ di folder deployment
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


class RestoreDrillTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.live = self.dir / "monitor.sqlite3"
        self.backup = self.dir / "backup" / "daily.sqlite3"
        initialize_monitor(self.live)
        stamp = "2026-01-01T00:00:10.000Z"
        event = build_event(source_id="login-lab-a", stream_id="11111111-1111-4111-8111-111111111111", sequence=1,
                            occurred_at=stamp, event_type="login.failure", account_token="a" * 64, client_token="b" * 64,
                            reason_code="INVALID_CREDENTIALS", event_id="00000000-0000-4000-8000-000000000001")
        with connect(self.live) as db:
            db.execute("INSERT INTO monitor_events VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                       ("login-lab-a", event["stream_id"], event["event_id"], 1, stamp, event["event_type"], "a" * 64,
                        "b" * 64, event["reason_code"], event["event_digest"], stamp, "{}"))
        from datetime import datetime, timezone
        run_cycle(self.live, datetime(2026, 1, 1, 0, 5, tzinfo=timezone.utc))
        create_atomic_backup(self.live, self.backup)
        self.drill = load_drill()

    def test_good_backup_passes_and_reports_counts_and_recorded_models(self):
        ok, lines = self.drill.drill(self.backup, self.live)
        text = "\n".join(lines)
        self.assertTrue(ok, text)
        self.assertIn("integrity_check : ok", text)
        self.assertIn("monitor_events    : 1", text)
        self.assertIn("rules-v1", text)
        self.assertIn("HASIL: LULUS", text)

    def test_original_backup_is_untouched_and_live_may_have_more_rows(self):
        before = self.backup.read_bytes()
        with connect(self.live) as db:
            db.execute("INSERT INTO ingest_rejections(received_at, source_id, reason_code) VALUES('2026-01-01T00:06:00.000Z', NULL, 'x')")
        ok, _ = self.drill.drill(self.backup, self.live)
        self.assertTrue(ok)
        self.assertEqual(self.backup.read_bytes(), before)

    def test_corrupt_missing_or_shrunken_backup_fails(self):
        ok, lines = self.drill.drill(self.dir / "tidak-ada.sqlite3", None)
        self.assertFalse(ok)
        broken = self.dir / "rusak.sqlite3"
        data = bytearray(self.backup.read_bytes())
        data[100:200] = b"\x00" * 100
        broken.write_bytes(bytes(data))
        try:
            ok, lines = self.drill.drill(broken, None)
        except Exception:  # database rusak berat bisa gagal dibuka sama sekali
            ok = False
        self.assertFalse(ok)
        with connect(self.live) as db:  # data aktif lebih sedikit daripada backup = tidak konsisten
            db.execute("DELETE FROM analysis_results")
        ok, lines = self.drill.drill(self.backup, self.live)
        self.assertFalse(ok)
        self.assertIn("HASIL: GAGAL", "\n".join(lines))


if __name__ == "__main__":
    unittest.main()
