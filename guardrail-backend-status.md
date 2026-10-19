# Guardrail backend — first working build

The Windows backend is implemented and its local build gate passes: **31 tests,
zero failures, zero skips**, using Python 3.12.14 on Windows. The tests include
real file-handle locking, junction and hard-link rejection, JSON/schema denial,
atomic create/replace failures, stale edits, audit failures and CLI execution.

The editable project is in the guardrail-security folder alongside this outputs
directory. A portable source ZIP includes the backend, tests, setup example,
documentation and original Claude snapshot. Python's standard library is the only
runtime dependency.

## Working protections

- Deny unknown operations, malformed requests, extra fields and self-approval flags.
- Limit access to text files in one configured workspace.
- Reject traversal, drive/UNC paths, alternate streams, device names, hidden paths,
  protected configuration, pre-existing junctions and hard links.
- Scan reads and writes for recognized secret formats; never log raw request data.
- Use complete staged writes, prevent create-overwrite, and require the previous
  content hash for replacement.
- Record intent before action and completion before returning success; deny when
  audit/locking is unavailable, with honest unknown-outcome reporting after a write.
- Provide a repeatable Windows build-check command for ongoing development.

## What is not active yet

This is a local broker component. It does **not yet enforce every action in Codex
or Claude**. It runs under the launching account, and direct tools can bypass it.
The next deployment milestone is a separate execution identity or isolated VM,
protected policy/audit storage, and an authenticated connection with direct bypass
routes restricted. Arbitrary build commands, package installs, network actions,
deletions and deployments currently have no allowed backend operation.

Windows mutating operations still depend on access controls excluding external
writers; hostile concurrent reparse changes and direct writers need stronger
handle-relative protections or isolation. Secret detection is heuristic, and audit
storage needs rotation/export. The source documentation contains the complete
backlog and assumptions. No live settings or OS security configuration changed.

The current session's shell-sandbox startup error remains unresolved. Tests ran
through approved local execution; they do not verify the host sandbox.

The OpenAI Docs skill informed the integration boundary, using the official
[Windows sandbox documentation](https://learn.chatgpt.com/docs/windows/windows-sandbox).

## Continue development

From the project directory, run a trusted Python 3.12+ interpreter with:

```text
python -I verify.py
```

Read README.md for the broker CLI and policy setup, and
docs/SECURITY-BOUNDARY.md for enforcement assumptions and deployment work.
