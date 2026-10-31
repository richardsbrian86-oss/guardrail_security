# Stop hook: before the session goes idle, require one security pass over the
# source files changed this session. Fires AT MOST ONCE per session (a marker
# file makes the second Stop a no-op), so it cannot loop.

$ErrorActionPreference = 'SilentlyContinue'

try { $payload = [Console]::In.ReadToEnd() | ConvertFrom-Json } catch { exit 0 }

$sid = 'unknown'
if ($payload.session_id) { $sid = ([string]$payload.session_id) -replace '[^A-Za-z0-9_-]', '' }

$dir     = Join-Path $env:LOCALAPPDATA 'claude-guardrails'
$touched = Join-Path $dir "$sid.touched"
$marker  = Join-Path $dir "$sid.gated"

if (-not (Test-Path $touched)) { exit 0 }   # nothing reviewable changed
if (Test-Path $marker)         { exit 0 }   # gate already fired this session

$files = Get-Content $touched | Where-Object { $_ } | Sort-Object -Unique
if (-not $files) { exit 0 }

Set-Content -Path $marker -Value (Get-Date -Format o) -Encoding utf8

$list = ($files | Select-Object -First 40) -join "`n  - "
$reason = @"
SECURITY GATE (fires once per session). You changed source files but have not run a security pass over them yet.

Before finishing, review these files for: injected/unsanitized input reaching a sink (SQL, shell, eval, file paths, HTML), missing or wrong authn/authz checks, hardcoded secrets or credentials, unsafe deserialization, SSRF, missing output encoding, weak crypto, and overly permissive CORS/permissions.

Use the security-review skill if it is available; otherwise read each file and report concretely.

Files changed:
  - $list

Report what you found (or state plainly that the review found nothing), then finish. Do not re-run this gate.
"@

@{ decision = 'block'; reason = $reason } | ConvertTo-Json -Compress -Depth 3
exit 0

