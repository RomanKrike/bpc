$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/../cmd/bpc-agent/ui_status.ps1"

$runtime = @{ updated_at = 1000; handshake_at = 990 }
$transport = @{
    updated_at = 1000; endpoint = 'a:1'; reachable = 2; total = 3
    paths = @(
        @{ endpoint = 'a:1'; node = 'a'; reachable = $true },
        @{ endpoint = 'a:2'; node = 'a'; reachable = $true },
        @{ endpoint = 'b:1'; node = 'b'; reachable = $false }
    )
}
function Copy-Transport($overrides) {
    $copy = $transport.Clone()
    foreach ($key in $overrides.Keys) { $copy[$key] = $overrides[$key] }
    return $copy
}
$cases = @(
    @{ name = 'healthy'; service = 'running'; runtime = $runtime; transport = $transport; expected = 'Connected' },
    @{ name = 'user disconnected'; service = 'stopped'; runtime = $runtime; transport = $transport; expected = 'Disconnected' },
    @{ name = 'initial start'; service = 'running'; expected = 'Connecting' },
    @{ name = 'lost transport'; service = 'running'; runtime = $runtime; expected = 'Reconnecting' },
    @{ name = 'stale transport'; service = 'running'; runtime = $runtime; transport = (Copy-Transport @{ updated_at = 980 }); expected = 'Reconnecting' },
    @{ name = 'future transport'; service = 'running'; runtime = $runtime; transport = (Copy-Transport @{ updated_at = 1010 }); expected = 'Reconnecting' },
    @{ name = 'stale runtime'; service = 'running'; runtime = @{ updated_at = 980; handshake_at = 990 }; transport = $transport; expected = 'Reconnecting' },
    @{ name = 'stale handshake'; service = 'running'; runtime = @{ updated_at = 1000; handshake_at = 800 }; transport = $transport; expected = 'Reconnecting' },
    @{ name = 'no handshake'; service = 'running'; runtime = @{ updated_at = 1000; handshake_at = 0 }; transport = $transport; expected = 'Connecting' },
    @{ name = 'healthy alternate is not selected'; service = 'running'; runtime = $runtime; transport = (Copy-Transport @{ endpoint = 'b:1' }); expected = 'Reconnecting' },
    @{ name = 'switch completed'; service = 'running'; runtime = $runtime; transport = (Copy-Transport @{ endpoint = 'a:2' }); expected = 'Connected' }
    @{ name = 'gateway changed but old handshake'; service = 'running'; runtime = $runtime; transport = (Copy-Transport @{ node_changed_at = 995 }); expected = 'Reconnecting' },
    @{ name = 'gateway handshake recovered'; service = 'running'; runtime = @{ updated_at = 1000; handshake_at = 999 }; transport = (Copy-Transport @{ node_changed_at = 995 }); expected = 'Connected' }
)
foreach ($case in $cases) {
    $actual = Get-BpcConnectionState $case.service $case.runtime $case.transport 1000
    if ($actual -ne $case.expected) { throw "$($case.name): expected $($case.expected), got $actual" }
}
$summary = Get-BpcGatewaySummary $transport
if ($summary -ne 'Automatic - 1/2 gateways available') { throw "Ports counted as gateways: $summary" }
if ((Get-BpcGatewaySummary $null) -ne 'Automatic gateway selection') { throw 'Missing telemetry summary failed' }

# Parse the actual shipped script without launching a window or starting services.
$source = Get-Content "$PSScriptRoot/../cmd/bpc-agent/ui_windows.go" -Raw
$match = [regex]::Match($source, '(?s)const windowsUIScript = `(.*?)`')
if (-not $match.Success) { throw 'Embedded UI script not found' }
$scriptText = $match.Groups[1].Value.Replace('__BPC_STATUS_FUNCTIONS__',
    (Get-Content "$PSScriptRoot/../cmd/bpc-agent/ui_status.ps1" -Raw))
$parseErrors = $null
$tokens = $null
$null = [System.Management.Automation.Language.Parser]::ParseInput($scriptText, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
Write-Output "Windows UI: $($cases.Count + 2) state/summary checks and production script parsing passed"
