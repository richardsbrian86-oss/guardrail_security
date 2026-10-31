# Shared PreToolUse guard. Patterns live in rules.json (data, not script) so that
# antivirus does not static-scan security signatures as malicious code - an earlier
# version embedded them inline, got blocked by AMSI, and silently failed OPEN.
#
#   -Section shell    -> tool_input.command                  (Bash | PowerShell)
#   -Section paths    -> tool_input.file_path                (Write | Edit | NotebookEdit)
#   -Section secrets  -> written content                     (Write | Edit | NotebookEdit)
#   -Section any      -> tool_name + serialized tool_input   (MCP, Artifact, Agent, Cron, ...)
#
# Fails CLOSED: if the ruleset or the payload cannot be read, the call is denied.

param([ValidateSet('shell', 'paths', 'secrets', 'any')][string]$Section = 'shell')

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

try {
    $payload   = [Console]::In.ReadToEnd() | ConvertFrom-Json
    $rulesFile = Join-Path $PSScriptRoot 'rules.json'
    $rules     = (Get-Content -LiteralPath $rulesFile -Raw -Encoding UTF8 | ConvertFrom-Json).$Section
    if (-not $rules -or -not ($rules.deny -or $rules.ask)) { throw "section '$Section' missing or empty in rules.json" }
}
catch {
    Respond 'deny' ("Security guardrail could not evaluate this call so it was DENIED (fail-closed): {0}. Check ~/.claude/hooks/rules.json." -f $_.Exception.Message)
}

try {
    $ti      = $payload.tool_input
    $subject = ''
    $label   = ''

    switch ($Section) {
        'shell' {
            if ($ti -and $ti.command) { $subject = (([string]$ti.command) -replace '\s+', ' ').Trim() }
            $label = $subject
        }
        'paths' {
            if ($ti -and $ti.file_path) { $subject = ([string]$ti.file_path) -replace '/', '\' }
            $label = $subject
        }
        'secrets' {
            $parts = @()
            foreach ($f in 'content', 'new_string', 'new_source') {
                if ($ti -and $ti.$f) { $parts += [string]$ti.$f }
            }
            $subject = $parts -join "`n"
            # Never echo the matched secret back into the transcript - name the file only.
            $label = if ($ti -and $ti.file_path) { [string]$ti.file_path } else { 'the written content' }
        }
        'any' {
            $name = if ($payload.tool_name) { [string]$payload.tool_name } else { '' }
            $args = ''
            if ($ti) { $args = ($ti | ConvertTo-Json -Compress -Depth 6) }
            $subject = ("{0} {1}" -f $name, $args).Trim()
            $label = $name
        }
    }

    # Nothing to inspect (a tool shape without the field) - let the normal
    # permission flow handle it rather than blocking blind.
    if ([string]::IsNullOrWhiteSpace($subject)) { exit 0 }

    $shown = $label
    if ($shown.Length -gt 160) { $shown = $shown.Substring(0, 160) + '...' }

    foreach ($r in $rules.deny) {
        if ($r.skip -and $subject -match $r.skip) { continue }
        if ($subject -match $r.p) {
            Respond 'deny' ("Blocked by security guardrail: {0}. [{1}] Claude cannot edit the guard scripts - do this yourself if it is genuinely intended." -f $r.m, $shown)
        }
    }

    foreach ($r in $rules.ask) {
        if ($r.skip -and $subject -match $r.skip) { continue }
        if ($subject -match $r.p) {
            if ($Section -eq 'secrets') {
                Respond 'ask' ("Security guardrail: this write looks like it contains a real secret ({0}) in {1}. Secrets belong in an environment variable or secret manager, not in source." -f $r.m, $shown)
            }
            Respond 'ask' ("Security guardrail wants confirmation: {0}. [{1}]" -f $r.m, $shown)
        }
    }
}
catch {
    Respond 'deny' ("Security guardrail errored while evaluating, so the call was DENIED (fail-closed): {0}" -f $_.Exception.Message)
}

exit 0

