# PostToolUse audit trail. Appends one JSON line per noteworthy tool call so there
# is a record of what actually ran. Never logs file content or secret values -
# only the tool name and a truncated subject. Always exits 0: an audit failure
# must never break a turn.

$ErrorActionPreference = 'SilentlyContinue'

try {
    $payload = [Console]::In.ReadToEnd() | ConvertFrom-Json

    $tool = if ($payload.tool_name) { [string]$payload.tool_name } else { 'unknown' }
    $ti   = $payload.tool_input

    $subject = ''
    if ($ti) {
        if     ($ti.command)   { $subject = [string]$ti.command }
        elseif ($ti.file_path) { $subject = [string]$ti.file_path }
        elseif ($ti.url)       { $subject = [string]$ti.url }
        elseif ($ti.prompt)    { $subject = 'prompt:' + [string]$ti.prompt }
        else {
            # Serialize arguments but drop anything that could carry a secret body.
            $safe = @{}
            foreach ($p in $ti.PSObject.Properties) {
                if ($p.Name -in @('content', 'new_string', 'old_string', 'new_source', 'text', 'data')) {
                    $safe[$p.Name] = '<omitted>'
                } else {
                    $safe[$p.Name] = $p.Value
                }
            }
            $subject = ($safe | ConvertTo-Json -Compress -Depth 4)
        }
    }

    $subject = ($subject -replace '\s+', ' ').Trim()
    if ($subject.Length -gt 400) { $subject = $subject.Substring(0, 400) + '...' }

    $rec = [ordered]@{
        ts      = (Get-Date).ToString('o')
        session = if ($payload.session_id) { ([string]$payload.session_id) -replace '[^A-Za-z0-9_-]', '' } else { '' }
        cwd     = if ($payload.cwd) { [string]$payload.cwd } else { '' }
        tool    = $tool
        subject = $subject
    }

    $dir = Join-Path $env:USERPROFILE '.claude\logs'
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $file = Join-Path $dir ('audit-' + (Get-Date -Format 'yyyy-MM') + '.jsonl')

    Add-Content -LiteralPath $file -Value ($rec | ConvertTo-Json -Compress -Depth 4) -Encoding utf8
}
catch { }

exit 0

