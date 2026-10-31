"""Deny-by-default request validation, file capabilities, and metadata-only audit."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import time
import uuid

from .windows import BoundaryError, exclusive_lock, locked_file, pin_directory

MAX_REQUEST = 2_000_000
MAX_FILE = 262_144
OPERATIONS = frozenset({"read_text", "create_text", "replace_text"})
EXTENSIONS = frozenset({".txt", ".md", ".json", ".py", ".ps1", ".js", ".ts",
                        ".tsx", ".jsx", ".html", ".css", ".toml", ".yaml", ".yml"})
BLOCKED_NAMES = frozenset({"agents.md", "claude.md", "rules.json", "settings.json",
                           "settings.local.json", "credentials.json", "secrets.json",
                           "package.json", "package-lock.json", "pyproject.toml",
                           "requirements.txt", "cargo.toml", "go.mod", "gemfile",
                           "profile.ps1", "microsoft.powershell_profile.ps1"})
SECRETS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\b(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{20,}"),
    re.compile(r"\bsk-(?:proj-|ant-|svcacct-)?[A-Za-z0-9_-]{20,}"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}"),
    re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{20,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:[^\s@/]+@"),
    re.compile(r'''(?i)["']?\b(?:api[_-]?key|secret|password|passwd|token|client[_-]?secret|access[_-]?key)\b["']?\s*[:=]\s*["'][^"'\s]{8,}["']'''),
)


class Denied(Exception):
    pass


def parse_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise Denied("duplicate_json_key")
            result[key] = value
        return result
    try:
        if len(raw) > MAX_REQUEST:
            raise Denied("request_too_large")
        return json.loads(raw, object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(Denied("invalid_json")))
    except (ValueError, UnicodeError, RecursionError):
        raise Denied("invalid_json") from None


def validate_content(content):
    if type(content) is not str:
        raise Denied("text_required")
    try:
        encoded = content.encode("utf-8", errors="strict")
    except UnicodeError:
        raise Denied("invalid_text") from None
    if len(encoded) > MAX_FILE:
        raise Denied("file_too_large")
    if any(ord(c) < 32 and c not in "\t\r\n" for c in content):
        raise Denied("binary_content_denied")
    if any(pattern.search(content) for pattern in SECRETS):
        raise Denied("possible_secret")
    return encoded


def validate_path(value):
    if type(value) is not str or not 1 <= len(value) <= 180:
        raise Denied("invalid_path")
    # A deliberately small portable syntax: no drive, ADS, device, UNC, tilde,
    # escaping, Unicode confusables, dotfiles, trailing spaces, or dot segments.
    parts = value.split("/")
    for part in parts:
        if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,79}", part):
            raise Denied("invalid_path")
        if part.endswith(".") or part.casefold() in BLOCKED_NAMES:
            raise Denied("protected_path")
        if re.fullmatch(r"(?i)(?:secrets?|credentials?|tokens?|auth)\..+", part):
            raise Denied("protected_path")
        if re.fullmatch(r"(?i)(?:con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\..*)?", part):
            raise Denied("device_path_denied")
        if part.casefold().startswith(("id_rsa", "id_ed25519", "id_ecdsa", "id_dsa")):
            raise Denied("protected_path")
    if Path(parts[-1]).suffix.casefold() not in EXTENSIONS:
        raise Denied("file_type_denied")
    return parts


def validate_request(request):
    if type(request) is not dict:
        raise Denied("object_required")
    op = request.get("operation")
    if type(op) is not str or op not in OPERATIONS:
        raise Denied("operation_denied")
    fields = {"version", "operation", "path"}
    if op != "read_text":
        fields.add("content")
    if op == "replace_text":
        fields.add("expected_sha256")
    if set(request) != fields or type(request["version"]) is not int or request["version"] != 1:
        raise Denied("invalid_request_schema")
    parts = validate_path(request["path"])
    data = validate_content(request["content"]) if op != "read_text" else None
    if op == "replace_text" and (type(request["expected_sha256"]) is not str or
                                  not re.fullmatch(r"[0-9a-f]{64}", request["expected_sha256"])):
        raise Denied("invalid_expected_hash")
    return op, parts, data


def overlaps(left, right):
    return left == right or left in right.parents or right in left.parents


class Policy:
    def __init__(self, workspace, state, source):
        self.workspace, self.state, self.source = map(Path, (workspace, state, source))
        for path in (self.workspace, self.state, self.source):
            if not path.is_absolute() or ".." in path.parts or path.drive.startswith("\\"):
                raise Denied("invalid_policy_path")
        project = Path(__file__).resolve().parents[2]
        if (self.workspace == Path(self.workspace.anchor) or
                overlaps(self.workspace, self.state) or overlaps(self.workspace, project) or
                self.source == self.workspace or self.workspace in self.source.parents):
            raise Denied("policy_boundary_overlap")

    @classmethod
    def load(cls, path):
        path = Path(os.path.abspath(path))
        with pin_directory(path.parent), locked_file(path) as stream:
            config = parse_json(stream.read(MAX_REQUEST + 1))
        if (type(config) is not dict or set(config) != {"version", "workspace", "state"} or
                type(config["version"]) is not int or config["version"] != 1 or
                type(config["workspace"]) is not str or type(config["state"]) is not str):
            raise Denied("invalid_policy_schema")
        return cls(config["workspace"], config["state"], path)


class Audit:
    def __init__(self, directory):
        path = directory / "audit.sqlite3"
        # State is operator owned. Reject obvious linked pre-existing DB files.
        for candidate in directory.iterdir():
            if candidate.name.startswith("audit.sqlite3"):
                with locked_file(candidate):
                    pass
        self.db = sqlite3.connect(str(path), timeout=0)
        try:
            self.db.execute("PRAGMA journal_mode=DELETE")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("CREATE TABLE IF NOT EXISTS events (sequence INTEGER PRIMARY KEY, request_id TEXT NOT NULL, timestamp_ns INTEGER NOT NULL, operation TEXT NOT NULL, phase TEXT NOT NULL, reason TEXT NOT NULL)")
            self.db.commit()
        except BaseException:
            self.db.close()
            raise

    def record(self, request_id, op, phase, reason=""):
        self.db.execute("INSERT INTO events(request_id,timestamp_ns,operation,phase,reason) VALUES (?,?,?,?,?)",
                        (request_id, time.time_ns(), op, phase, reason))
        self.db.commit()

    def close(self):
        self.db.close()


def read_checked(path):
    with locked_file(path) as stream:
        raw = stream.read(MAX_FILE + 1)
    if len(raw) > MAX_FILE:
        raise Denied("file_too_large")
    try:
        content = raw.decode("utf-8", errors="strict")
    except UnicodeError:
        raise Denied("invalid_text") from None
    validate_content(content)
    return content, hashlib.sha256(raw).hexdigest()


class Broker:
    def __init__(self, policy):
        self.policy = policy

    def handle(self, raw):
        request_id = str(uuid.uuid4())
        # IDs and operation/reason enums are generated by the broker. No raw
        # request, file path, contents, prompt, command, or exception is logged.
        op = "unknown"
        response = {"version": 1, "request_id": request_id, "ok": False}
        try:
            with pin_directory(self.policy.state), exclusive_lock(self.policy.state / "broker.lock"):
                with contextlib.closing(Audit(self.policy.state)) as audit:
                    try:
                        request = parse_json(raw)
                        op, parts, data = validate_request(request)
                        target = self.policy.workspace.joinpath(*parts)
                        with pin_directory(target.parent, mutation=op != "read_text"):
                            audit.record(request_id, op, "intent")
                            result = self._execute(request_id, op, target, data, request)
                            audit.record(request_id, op, "completed")
                        response.update(ok=True, result=result)
                    except (Denied, BoundaryError) as error:
                        audit.record(request_id, op, "denied", str(error))
                        response["reason"] = str(error)
                    except (OSError, UnicodeError):
                        audit.record(request_id, op, "error", "io_failure")
                        response["reason"] = "io_failure"
        except (OSError, sqlite3.Error, BoundaryError):
            # If completion logging fails, a write may already have happened.
            # Never return content or claim a rollback in that case.
            response.update(ok=False, reason="audit_or_lock_unavailable_outcome_unknown")
            response.pop("result", None)
        return response

    def _execute(self, request_id, op, target, data, request):
        if op == "read_text":
            content, digest = read_checked(target)
            return {"content": content, "sha256": digest}
        if op == "replace_text":
            _, digest = read_checked(target)
            if digest != request["expected_sha256"]:
                raise Denied("stale_file")
        # Serialized broker operations + pinned ancestors + same-directory
        # atomic replacement. Direct external writers are excluded by deployment
        # ACLs; expected hashes are not a lock against another same-user process.
        staged = target.parent / ("guardrail-stage-" + request_id + ".tmp")
        created = False
        try:
            with locked_file(staged, create=True) as stream:
                created = True
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            if op == "create_text":
                # Windows rename fails if destination already exists.
                os.rename(staged, target)
            else:
                os.replace(staged, target)
        finally:
            if created and staged.exists():
                staged.unlink()
        return {"sha256": hashlib.sha256(data).hexdigest()}
