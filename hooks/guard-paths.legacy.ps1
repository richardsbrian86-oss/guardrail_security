# PreToolUse guard for Write / Edit / NotebookEdit.
# Protects credential stores, system directories, and the guardrails themselves.

$ErrorActionPreference = 'Stop'

function Respond([string]$decision, [string]$reason) {
    $out = @{
        hookSpecificOutput = @{
            hookEventName            = 'PreToolUse'
            permissionDecision       = $decision
            permissionDecisionReason = $reason
        }
    }
    $out | ConvertTo-Json -Compress -Depth 5
    exit 0
}

try { $payload = [Console]::In.ReadToEnd() | ConvertFrom-Json } catch { exit 0 }

$path = ''
if ($payload.tool_input -and $payload.tool_input.file_path) { $path = [string]$payload.tool_input.file_path }
if ([string]::IsNullOrWhiteSpace($path)) { exit 0 }

$p = $path -replace '/', '\'

$deny = @(
    @{ p = '(?i)\\\.ssh\\';                               m = 'SSH key directory' }
    @{ p = '(?i)\\(id_rsa|id_ed25519|id_ecdsa|id_dsa)';   m = 'SSH private key' }
    @{ p = '(?i)\\\.aws\\credentials';                    m = 'AWS credentials file' }
    @{ p = '(?i)\\\.gnupg\\';                             m = 'GPG keyring' }
    @{ p = '(?i)\\\.credentials\.json$';                  m = 'stored auth credentials' }
    @{ p = '(?i)\.(pem|pfx|p12|jks|keystore)$';           m = 'private key / keystore file' }
    @{ p = '(?i)^[a-z]:\\windows\\';                      m = 'Windows system directory' }
    @{ p = '(?i)^[a-z]:\\program files';                  m = 'installed program directory' }
    @{ p = '(?i)\\\.git\\(config|hooks)\\?';              m = 'git config or git hooks (silent code execution path)' }
)

# Risky but sometimes legitimate during a build -> prompt instead of blocking.
$ask = @(
    @{ p = '(?i)\\\.env($|\.)';                           m = 'environment file that typically holds real secrets'; skip = '(?i)\\\.env\.(example|sample|template)$' }
    @{ p = '(?i)\\\.claude\\hooks\\';                     m = 'the security guardrail scripts themselves' }
    @{ p = '(?i)\\\.claude\\settings(\.local)?\.json$';   m = 'Claude Code settings (where the guardrails are wired up)' }
    @{ p = '(?i)\\\.claude\\CLAUDE\.md$';                 m = 'your global coding standards' }
    @{ p = '(?i)\\(\.npmrc|\.pypirc|\.netrc|_netrc)$';    m = 'registry auth file' }
    @{ p = '(?i)\\(secrets?|credentials?)\.(json|ya?ml|toml|ini)$'; m = 'a file named like a secret store' }
)

foreach ($r in $deny) {
    if ($p -match $r.p) {
        Respond 'deny' ("Blocked by security guardrail: {0} ({1}). Claude must not write here." -f $r.m, $path)
    }
}

foreach ($r in $ask) {
    if ($r.skip -and $p -match $r.skip) { continue }
    if ($p -match $r.p) {
        Respond 'ask' ("Security guardrail wants confirmation: writing to {0} ({1})." -f $r.m, $path)
    }
}

exit 0

