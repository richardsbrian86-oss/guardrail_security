import contextlib
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from guardrails.core import Audit, Broker, Denied, MAX_FILE, Policy, parse_json, validate_content
from guardrails.windows import BoundaryError, exclusive_lock, locked_file, pin_directory


@unittest.skipUnless(os.name == "nt", "Requires real Windows handle semantics")
class BackendTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="guardrail-tests-")
        self.base = Path(self.temp.name)
        self.workspace = self.base / "workspace"
        self.state = self.base / "state"
        self.workspace.mkdir()
        self.state.mkdir()
        self.policy_file = self.base / "policy.json"
        self.policy_file.write_text(json.dumps({"version": 1, "workspace": str(self.workspace),
                                                "state": str(self.state)}), encoding="utf-8")
        self.broker = Broker(Policy.load(self.policy_file))

    def tearDown(self):
        self.temp.cleanup()

    def call(self, operation="read_text", path="note.txt", **extra):
        return self.broker.handle(json.dumps(dict(version=1, operation=operation,
                                                   path=path, **extra)).encode())

    def events(self):
        with contextlib.closing(sqlite3.connect(self.state / "audit.sqlite3")) as db:
            return db.execute("SELECT operation, phase, reason FROM events ORDER BY sequence").fetchall()

    def test_create_read_replace_and_audit(self):
        first = self.call("create_text", content="hello")
        self.assertTrue(first["ok"], first)
        read = self.call()
        self.assertEqual(read["result"]["content"], "hello")
        replacement = self.call("replace_text", content="updated",
                                expected_sha256=read["result"]["sha256"])
        self.assertTrue(replacement["ok"], replacement)
        self.assertEqual((self.workspace / "note.txt").read_text(), "updated")
        self.assertEqual([row[1] for row in self.events()], ["intent", "completed"] * 3)

    def test_no_overwrite_on_create(self):
        self.call("create_text", content="keep")
        self.assertFalse(self.call("create_text", content="changed")["ok"])
        self.assertEqual((self.workspace / "note.txt").read_text(), "keep")

    def test_stale_replacement_preserves_file(self):
        self.call("create_text", content="keep")
        result = self.call("replace_text", content="changed", expected_sha256="0" * 64)
        self.assertEqual(result["reason"], "stale_file")
        self.assertEqual((self.workspace / "note.txt").read_text(), "keep")

    def test_unknown_operations_and_self_approval(self):
        for operation in ["shell", "PowerShell", "network", "delete", "approve", "set_policy", "mcp__send_email"]:
            with self.subTest(operation=operation):
                self.assertEqual(self.call(operation)["reason"], "operation_denied")
        self.assertEqual(self.call(approved=True)["reason"], "invalid_request_schema")

    def test_malformed_schemas(self):
        for obj in [None, [], {}, {"operation": "read_text"}, {"version": True, "operation": "read_text", "path": "note.txt"},
                    {"version": 1, "operation": [], "path": "note.txt"},
                    {"version": 1, "operation": "read_text", "path": 7}]:
            with self.subTest(obj=obj):
                self.assertFalse(self.broker.handle(json.dumps(obj).encode())["ok"])

    def test_malformed_json_and_duplicate_keys(self):
        for raw in [b"", b"{", b"\xff", b'{"version":1,"version":2}', b'{"value":NaN}', b"[" * 3000]:
            with self.subTest(raw=raw[:30]):
                self.assertFalse(self.broker.handle(raw)["ok"])

    def test_request_size_limit(self):
        self.assertEqual(self.broker.handle(b" " * 2_000_001)["reason"], "request_too_large")

    def test_path_escape_variants(self):
        paths = ["../outside.txt", "sub/../../outside.txt", "C:/outside.txt", "C:outside.txt", "/outside.txt",
                 "\\\\server\\share\\x.txt", "\\\\?\\C:\\x.txt", "sub\\x.txt", "x.txt:secret", "x.txt ",
                 "x.txt.", "sub//x.txt", "./x.txt", "sub/../x.txt", "CON.txt", "nul.txt", "COM1.txt",
                 "short~1.txt", "x\x00.txt", "percent%2e.txt", "а.txt", ".git/config.json", ".env",
                 "file.pem", "file.exe", "AGENTS.md", "CLAUDE.md", "rules.json", "id_rsa.txt", "package.json"]
        for path in paths:
            with self.subTest(path=path):
                self.assertFalse(self.call("create_text", path, content="x")["ok"])
        self.assertEqual(list(self.workspace.iterdir()), [])

    def test_missing_parent_denied(self):
        self.assertFalse(self.call("create_text", "missing/note.txt", content="x")["ok"])

    def test_nested_path_succeeds(self):
        (self.workspace / "src").mkdir()
        result = self.call("create_text", "src/main.py", content="print('hello')\n")
        self.assertTrue(result["ok"], result)

    def test_secret_read_write_denied_without_leaking_value(self):
        secret = "sk-proj-" + "A" * 40
        result = self.call("create_text", content=secret)
        self.assertEqual(result["reason"], "possible_secret")
        (self.workspace / "note.txt").write_text(secret)
        result = self.call()
        self.assertEqual(result["reason"], "possible_secret")
        self.assertNotIn(secret, json.dumps(result))
        self.assertNotIn(secret.encode(), (self.state / "audit.sqlite3").read_bytes())

    def test_placeholder_does_not_whitelist_other_secret(self):
        result = self.call("create_text", content='password = "placeholder"\n' + "ghp_" + "A" * 30)
        self.assertEqual(result["reason"], "possible_secret")

    def test_new_token_shapes(self):
        for token in ["sk-proj-" + "A_" * 20, "github_pat_" + "A" * 30,
                      '"password": "abcdefghijk"', "postgres://user:password@host/db"]:
            with self.subTest(kind=token[:10]):
                with self.assertRaises(Denied):
                    validate_content(token)

    def test_file_limits_and_encoding(self):
        for content in ["a" * (MAX_FILE + 1), "\x00", "\ud800", 7]:
            with self.subTest(kind=type(content).__name__):
                self.assertFalse(self.call("create_text", content=content)["ok"])
        (self.workspace / "note.txt").write_bytes(b"\xff")
        self.assertEqual(self.call()["reason"], "invalid_text")
        (self.workspace / "note.txt").write_bytes(b"x" * (MAX_FILE + 1))
        self.assertEqual(self.call()["reason"], "file_too_large")

    def test_hardlink_read_and_replace_denied(self):
        outside = self.base / "outside.txt"
        outside.write_text("keep")
        os.link(outside, self.workspace / "note.txt")
        self.assertEqual(self.call()["reason"], "hardlink_denied")
        self.assertFalse(self.call("replace_text", content="changed", expected_sha256=hashlib.sha256(b"keep").hexdigest())["ok"])
        self.assertEqual(outside.read_text(), "keep")

    def test_junction_traversal_denied(self):
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "note.txt").write_text("keep")
        link = self.workspace / "linked"
        # Only test-created temporary directories enter cmd. No destructive command.
        result = subprocess.run([os.environ["SystemRoot"] + "\\System32\\cmd.exe", "/d", "/c",
                                 "mklink", "/J", str(link), str(outside)], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        try:
            self.assertEqual(self.call(path="linked/note.txt")["reason"], "reparse_point_denied")
            self.assertFalse(self.call("create_text", "linked/new.txt", content="x")["ok"])
            self.assertFalse((outside / "new.txt").exists())
        finally:
            os.rmdir(link)

    def test_directory_pinning_prevents_rename(self):
        directory = self.workspace / "sub"
        directory.mkdir()
        with pin_directory(directory):
            with self.assertRaises(OSError):
                directory.rename(self.workspace / "moved")

    def test_mutation_pinning_prevents_directory_rename(self):
        directory = self.workspace / "sub"
        directory.mkdir()
        with pin_directory(directory, mutation=True):
            with self.assertRaises(OSError):
                directory.rename(self.workspace / "moved")

    def test_audit_hardlink_denies_before_mutation(self):
        external = self.base / "external.db"
        external.write_bytes(b"untouched")
        os.link(external, self.state / "audit.sqlite3")
        self.assertFalse(self.call("create_text", content="x")["ok"])
        self.assertEqual(external.read_bytes(), b"untouched")
        self.assertEqual(list(self.workspace.iterdir()), [])

    def test_failed_atomic_create_leaves_no_partial_target(self):
        with mock.patch("guardrails.core.os.rename", side_effect=OSError("failure")):
            self.assertFalse(self.call("create_text", content="new content")["ok"])
        self.assertEqual(list(self.workspace.iterdir()), [])

    def test_read_handle_prevents_concurrent_write(self):
        path = self.workspace / "note.txt"
        path.write_text("keep")
        with locked_file(path):
            with self.assertRaises(OSError):
                path.write_text("overwrite")

    def test_busy_broker_denies(self):
        with exclusive_lock(self.state / "broker.lock"):
            result = self.call("create_text", content="x")
        self.assertFalse(result["ok"])
        self.assertFalse((self.workspace / "note.txt").exists())

    def test_audit_failure_before_action_prevents_mutation(self):
        with mock.patch.object(Audit, "record", side_effect=sqlite3.OperationalError("unavailable")):
            result = self.call("create_text", content="x")
        self.assertFalse(result["ok"])
        self.assertFalse((self.workspace / "note.txt").exists())

    def test_audit_failure_after_action_reports_unknown_outcome(self):
        original = Audit.record
        def fail_completion(audit, request_id, op, phase, reason=""):
            if phase == "completed":
                raise sqlite3.OperationalError("unavailable")
            original(audit, request_id, op, phase, reason)
        with mock.patch.object(Audit, "record", new=fail_completion):
            result = self.call("create_text", content="created")
        self.assertEqual(result["reason"], "audit_or_lock_unavailable_outcome_unknown")
        self.assertEqual((self.workspace / "note.txt").read_text(), "created")
        self.assertNotIn("result", result)

    def test_audit_has_no_attacker_controlled_metadata(self):
        marker = "SENSITIVE_UNTRUSTED_MARKER"
        self.call("create_text", marker + ".txt", content=marker)
        self.call(marker)
        self.assertNotIn(marker.encode(), (self.state / "audit.sqlite3").read_bytes())

    def test_corrupt_audit_denies(self):
        (self.state / "audit.sqlite3").write_bytes(b"corrupt")
        self.assertFalse(self.call("create_text", content="x")["ok"])
        self.assertEqual(list(self.workspace.iterdir()), [])

    def test_failed_atomic_replace_preserves_original(self):
        self.call("create_text", content="keep")
        with mock.patch("guardrails.core.os.replace", side_effect=OSError("failure")):
            result = self.call("replace_text", content="changed", expected_sha256=hashlib.sha256(b"keep").hexdigest())
        self.assertFalse(result["ok"])
        self.assertEqual((self.workspace / "note.txt").read_text(), "keep")
        self.assertEqual([p.name for p in self.workspace.iterdir()], ["note.txt"])

    def test_policy_cannot_overlap_workspace(self):
        for workspace, state in [(self.workspace, self.workspace), (self.base, self.state),
                                  (self.state / "nested", self.state),
                                  (Path(__file__).resolve().parents[1], self.state)]:
            with self.subTest(workspace=workspace):
                with self.assertRaises(Denied):
                    Policy(workspace, state, self.policy_file)

    def test_bad_policy_denied(self):
        for content in ['{}', '{"version":1,"version":1}', 'null']:
            self.policy_file.write_text(content)
            with self.assertRaises(Denied):
                Policy.load(self.policy_file)

    def test_cli_startup_denial_is_json(self):
        entry = Path(__file__).resolve().parents[1] / "backend" / "run.py"
        result = subprocess.run([sys.executable, "-I", str(entry), "--policy", str(self.base / "missing.json")],
                                input="{}", text=True, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["reason"], "startup_denied")
        self.assertEqual(result.stderr, "")

    def test_cli_end_to_end(self):
        entry = Path(__file__).resolve().parents[1] / "backend" / "run.py"
        request = json.dumps(dict(version=1, operation="create_text", path="note.txt", content="hello"))
        result = subprocess.run([sys.executable, "-I", str(entry), "--policy", str(self.policy_file)],
                                input=request, text=True, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(json.loads(result.stdout)["ok"])
        denied = subprocess.run([sys.executable, "-I", str(entry), "--policy", str(self.policy_file)],
                                input='{"operation":"shell"}', text=True, capture_output=True, timeout=20)
        self.assertEqual(denied.returncode, 2)
        self.assertFalse(json.loads(denied.stdout)["ok"])


if __name__ == "__main__":
    unittest.main()
