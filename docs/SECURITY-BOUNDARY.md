# Security boundary and remaining work

Status: tested local development implementation, not an installed security service.

## Enforced inside the backend

Requests must match an exact JSON schema. Missing/unknown fields, duplicate keys,
invalid types and oversized input are denied. An agent cannot change policy,
supply an approval flag, or choose an executable. Only read_text, create_text
and replace_text exist. Shell, network, installation, deletion, database changes,
deployment, and arbitrary connector actions have no execution path.

Paths are relative to one operator-configured local workspace. The small ASCII
syntax rejects drives, UNC, alternate streams, device names, dot segments, hidden
paths, short aliases, keys, agent instructions and sensitive configuration names.
Only listed text extensions are accepted. Limits: 256 KiB per file and 2 MB per
request. All parent directories must already exist.

Windows handles reject existing reparse points and hard links before reading data.
Directory handles pin ancestry against rename/deletion during a request. Final
handle paths must match expected absolute paths; only fixed local drives are
accepted. Tests use real Windows junctions, hard links and concurrent file access.

Known secret patterns are checked on reads and writes with no whole-document
placeholder exemption. Detection is heuristic: unrecognized/encoded secrets can
pass, and benign examples can be blocked. Never put real credentials in the workspace.

Writes stage and flush a complete file before renaming in the same directory.
Windows creation cannot overwrite an existing file. Replacement requires the
previous read's SHA-256. This catches stale edits among serialized broker requests.
Failed renames preserve the original. Successful replacements are not backups;
preserve project history separately. Crashes may leave staging files for cleanup.

Audit intent is committed before acting and completion before returning results.
Audit failure before action blocks it. Failure after a write reports unknown
outcome, never a claimed rollback. Check the file before retrying. SQLite stores
only generated request IDs, timestamps, operation, phase and fixed reason codes.
It stores no paths, content, commands, prompts or raw requests. Exclusive state
locking serializes requests using the same state directory. Audit is not
cryptographically tamper-proof; storage access controls remain essential.

## Deployment assumptions and limits

Policy, runtime, code, state and workspace ancestors must be trusted. The operator
provisions directories. In an enforced deployment, the broker has workspace access;
the agent reaches it through an authenticated restricted transport. The agent must
not have direct write access to the workspace, broker, policy, state or ancestors.
An agent with a separate unrestricted shell can bypass this broker entirely.

This CLI runs as its launcher's Windows identity. It is not a separate identity,
authenticated service, installed Codex interception hook or OS sandbox. There is
no remote listener. Startup failures return generic JSON and exit 2; they may
happen before audit storage is available.

Windows mutation requires parent-directory write sharing. The directory handles
prevent rename, but **do not establish protection from every concurrent reparse
metadata change by a process with directory write access**. Expected hashes also
do not lock out direct external writers. Deployment ACLs must exclude these writers.
Use one state directory/broker per workspace. Stronger handle-relative mutations
and adversarial race tests remain work before use on a hostile shared host.

## Remaining work, in order

1. Provision a separate broker account or isolated VM; protect code, runtime,
   policy and state with OS access controls. Keep production secrets outside it.
2. Add authenticated transport with per-caller capabilities, quotas and timeouts.
   A connected tool by itself does not remove alternate filesystem/shell tools.
3. Restrict agent filesystem, direct tools and network access. Test every actual
   Codex/Claude entry point. Claude settings are not Codex settings.
4. Add sandboxed build/test execution. Allowlisting Python, PowerShell or Node
   executables alone does not make arbitrary scripts safe. They are denied here.
5. Implement network proxy rules and scoped credentials for permitted services.
6. Bind human approvals to caller, exact action digest, expiry and one-time use.
   Store approval authority outside agent access; no model self-approval route.
7. Add audit rotation, independent export, disk quotas and crash recovery for
   unmatched intents/staging files. Current audit storage needs operator maintenance.
8. Enforce artifact-specific independent review and the test gate in protected CI.
   The local verify command only gates builds that actually invoke it.

No live Claude/Codex settings, accounts, ACLs, services or firewall settings were
changed. This session's shell-sandbox startup error remains unresolved; passing
application tests does not establish that the host sandbox works.

## Imported gaps confirmed from source

- guard.ps1 passes empty/missing subjects despite its fail-closed comment.
- audit.ps1 logs command text, URLs and prompts, potentially including credentials.
- Whole-subject skip patterns can exempt dangerous content when an unrelated benign
  example appears elsewhere; whitespace flattening changes command boundaries.
- The stop gate marks a session before review and runs once. It is a reminder,
  not proof that the final artifact was reviewed.
- The source imported from disk differs from some staged code in the recording.
  The recorded 97 checks are not a result for this backend.

The imported files are preserved; fixes are implemented in the new backend.

## References

- [Microsoft CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [Microsoft handle information](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfileinformationbyhandle)
- [OpenAI Codex security](https://learn.chatgpt.com/docs/security)
- [OpenAI Windows sandbox](https://learn.chatgpt.com/docs/windows/windows-sandbox)

The OpenAI Docs skill informed the separation between tool checks and OS sandbox
enforcement. No Claude-style hook API is assumed to exist in Codex.
