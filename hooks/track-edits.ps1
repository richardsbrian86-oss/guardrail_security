# PostToolUse on Write/Edit: record source files touched this session,
# so the Stop gate knows whether a security review is warranted.

$ErrorActionPreference = 'SilentlyContinue'

try { $payload = [Console]::In.ReadToEnd() | ConvertFrom-Json } catch { exit 0 }

$path = ''
if ($payload.tool_response -and $payload.tool_response.filePath) { $path = [string]$payload.tool_response.filePath }
if (-not $path -and $payload.tool_input -and $payload.tool_input.file_path) { $path = [string]$payload.tool_input.file_path }
if ([string]::IsNullOrWhiteSpace($path)) { exit 0 }

# Only code and infra files — prose and lockfiles don't need a security pass.
$reviewable = '(?i)(\.(ts|tsx|js|jsx|mjs|cjs|py|go|rs|java|kt|cs|rb|php|swift|sql|tf|ps1|sh|bash|vue|svelte|astro|graphql|prisma)$|(^|\\)dockerfile[^\\]*$|\\(docker-compose|\.github\\workflows\\[^\\]+)\.ya?ml$)'
if ($path -notmatch $reviewable) { exit 0 }

$sid = 'unknown'
if ($payload.session_id) { $sid = ([string]$payload.session_id) -replace '[^A-Za-z0-9_-]', '' }

$dir = Join-Path $env:LOCALAPPDATA 'claude-guardrails'
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

Add-Content -Path (Join-Path $dir "$sid.touched") -Value $path -Encoding utf8
exit 0
