# Hands-on testing evidence

## Purpose

This note records hands-on testing observations for the Guardrail backend. It separates repository-verifiable facts from author-observed results. It is not a claim that the project is an installed security boundary or that it prevents every possible direct filesystem bypass.

## Repository-verified context

The repository currently includes:

- A Windows-only build gate: `python -I verify.py`.
- A 31-test backend regression suite in `tests/test_backend.py`.
- A gate that denies non-Windows execution and fails when tests are missing, fail, or are skipped.
- Windows-specific tests for file handles, hard links, junction traversal, directory pinning, and concurrent access.

The repository documentation states that this is a local development implementation, not an installed Codex/Claude interceptor, OS sandbox, or separate security service.

## Author-observed testing

### Windows: primary development environment

The author observed the local 31-test regression suite run in the Windows development environment.

This is evidence that the project was exercised where its Windows-specific verification path is intended to run. The exact current pass/fail output is not included in this document; it should be captured and attached or linked in a future evidence update.

### Replit/Linux: limited smoke test

The author also performed a limited Replit/Linux smoke test and observed:

- Certain README-related text operations were allowed.
- Certain basic prohibited requests were denied.

This is author-observed evidence of limited allow/deny behavior. It is not evidence that the full Windows security suite ran in Linux, that all Windows handle protections were exercised, or that an AI agent could not bypass the backend through a separate unrestricted filesystem or shell path.

## Interpretation

The Linux observation suggests that some request-policy behavior can be exercised outside the primary Windows environment. The Windows build gate intentionally does not treat Linux execution as equivalent: it denies non-Windows runs because the suite requires real Windows handle semantics.

The appropriate conclusion is:

> Windows remains the primary verified development environment. Linux results are partial smoke-test observations and identify a future cross-platform testing opportunity.

## Remaining verification work

- Capture and retain the exact Windows build-gate output.
- Record which Linux requests were allowed or denied, with sanitized request and response examples.
- Verify audit records for denied operations.
- Test actual AI-tool entry points and direct-write bypass paths in a disposable workspace.
- Design Linux-specific tests before claiming comparable cross-platform enforcement.

## Evidence hygiene

Do not publish real credentials, local absolute paths, private audit data, or unredacted recordings. Any future screenshot or video should show the command, platform, test result, and relevant denial outcome while redacting unrelated windows and sensitive information.
