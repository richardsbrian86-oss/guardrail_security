# Guardrail backend for Windows

First working backend: strict JSON requests, bounded file operations, Windows
handle checks, atomic writes and metadata-only audit. Python 3.12+; standard library
only. No external package installation is required.

This is a tested development component, not yet installed as an enforced
Codex/Claude security boundary. See docs/SECURITY-BOUNDARY.md for assumptions and
the remaining deployment work.

## Build gate

From this directory, using a trusted Python interpreter:

```powershell
python -I verify.py
```

The gate requires Windows, parses backend source and runs the complete regression
suite. It fails when tests fail, required tests disappear, or tests are skipped.
Run after every backend change. Protected CI/release permissions are still needed
to make invocation mandatory outside this development workflow.

## Operator setup

Provision an empty local workspace and a separate state directory. The workspace
must not overlap this repository or state; keep policy outside the workspace.
Parents of requested files must already exist. Copy policy.example.json to an
operator-controlled location and set absolute paths. In deployment, keep runtime,
code, policy and audit state outside agent write access.

One process reads one JSON request from stdin and returns one JSON response:

```powershell
'{"version":1,"operation":"create_text","path":"note.txt","content":"hello"}' |
    python -I backend/run.py --policy C:\GuardrailConfig\policy.json
```

Read request:

```json
{"version":1,"operation":"read_text","path":"note.txt"}
```

Replacement uses the sha256 returned by the read:

```json
{"version":1,"operation":"replace_text","path":"note.txt","expected_sha256":"<64 lowercase hex characters returned by read_text>","content":"updated"}
```

Exit 0 means success; exit 2 means denial or an unavailable prerequisite. Unknown
operations and extra fields such as approved, command and policy are rejected.
There is no model self-approval route. The caller should bound process lifetime;
the one-request CLI waits for EOF and is not a multi-user server.

If the reason is audit_or_lock_unavailable_outcome_unknown, check the target before
retrying. A write may have succeeded before completion logging failed.

## Layout

- backend/run.py: local one-request CLI, no network listener.
- backend/guardrails/core.py: schema, paths, content checks, file operations, audit.
- backend/guardrails/windows.py: Windows handles.
- tests/test_backend.py: integration and failure-mode tests.
- verify.py: local build gate.
- docs/SECURITY-BOUNDARY.md: coverage, deployment assumptions, remaining gaps.
- hooks/ and claude/: preserved source snapshot, not loaded by this backend.

The imported regex policy is not an authorization source for the new backend.
