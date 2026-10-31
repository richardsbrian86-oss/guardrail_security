# Guardrail development

This file is development guidance, not a security boundary.

- Keep the imported hooks/ and claude/ snapshots unchanged for comparison.
- Use the backend's structured operations; do not add arbitrary shell execution.
- Any new capability needs an explicit schema, denial cases and a documented trust boundary.
- Run `python -I verify.py` after backend changes; a skipped Windows test is not a pass.
- Never log caller-supplied text, paths or secret values in the backend audit trail.
- Keep workspace, policy, runtime and audit ownership assumptions explicit.
- Update docs/SECURITY-BOUNDARY.md when enforcement or its assumptions change.
- Do not describe this development CLI as active OS or Codex enforcement.
