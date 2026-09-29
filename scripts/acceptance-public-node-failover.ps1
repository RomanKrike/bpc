#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$AgentPath = "$env:ProgramData\BPC\bpc-agent.exe",
    [string]$TransportStatusPath = "$env:ProgramData\BPC\ui-transport.json",
    [string]$Target = "10.253.0.1",
    [int]$DurationSeconds = 20,
    [int]$IntervalMilliseconds = 100,
    [int]$FaultAfterSeconds = 5,
    [int]$MaxSwitchMilliseconds = 1500,
    [string]$FaultSshHost = "",
    [string]$FaultSshUser = "root",
    [string]$FaultService = "bpc-agent-relay.service",
    [string]$ReportPath = ".\bpc-public-node-failover.json",
    [switch]$NoRestore
)

$ErrorActionPreference = "Stop"

if ($DurationSeconds -lt 5) {
    throw "DurationSeconds must be at least 5"
}
if ($IntervalMilliseconds -lt 50) {
    throw "IntervalMilliseconds must be at least 50"
}
if ($FaultAfterSeconds -lt 1 -or $FaultAfterSeconds -ge $DurationSeconds) {
    throw "FaultAfterSeconds must be within the measurement window"
}
if ($MaxSwitchMilliseconds -lt 100) {
    throw "MaxSwitchMilliseconds must be at least 100"
}
if (-not (Test-Path -LiteralPath $AgentPath)) {
    throw "BPC Agent was not found: $AgentPath"
}

function Read-AgentStatus {
    $raw = & $AgentPath status-json 2>$null
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($raw)) {
        return $null
    }
    try {
        return ($raw | ConvertFrom-Json)
    }
    catch {
        return $null
    }
}

function Read-TransportStatus {
    if (-not (Test-Path -LiteralPath $TransportStatusPath)) {
        return $null
    }
    try {
        return (Get-Content -LiteralPath $TransportStatusPath -Raw | ConvertFrom-Json)
    }
    catch {
        return $null
    }
}

function Get-SelectedNode($transport) {
    if ($null -eq $transport) {
        return ""
    }
    $endpoint = [string]$transport.endpoint
    foreach ($path in @($transport.paths)) {
        if ([string]$path.endpoint -eq $endpoint) {
            return [string]$path.node
        }
    }
    return ""
}

function Invoke-Fault([string]$hostName, [string]$userName, [string]$serviceName) {
    if ([string]::IsNullOrWhiteSpace($hostName)) {
        return $null
    }
    $destination = if ([string]::IsNullOrWhiteSpace($userName)) {
        $hostName
    }
    else {
        "$userName@$hostName"
    }
    $arguments = @(
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=5",
        $destination,
        "systemctl", "stop", $serviceName
    )
    return Start-Process -FilePath "ssh.exe" -ArgumentList $arguments -PassThru -WindowStyle Hidden
}

function Restore-Fault([string]$hostName, [string]$userName, [string]$serviceName) {
    if ([string]::IsNullOrWhiteSpace($hostName)) {
        return
    }
    $destination = if ([string]::IsNullOrWhiteSpace($userName)) {
        $hostName
    }
    else {
        "$userName@$hostName"
    }
    & ssh.exe -o BatchMode=yes -o ConnectTimeout=5 $destination systemctl start $serviceName | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to restore $serviceName on $destination"
    }
}

function Get-NormalizedRoutes($status) {
    if ($null -eq $status -or $null -eq $status.routes) {
        return @()
    }
    return @($status.routes | ForEach-Object { [string]$_ } | Sort-Object)
}

$before = Read-AgentStatus
if ($null -eq $before) {
    throw "Unable to read BPC Agent status-json"
}
$initialTransport = if ($null -ne $before.transport) {
    $before.transport
}
else {
    Read-TransportStatus
}
if ($null -eq $initialTransport) {
    throw "Transport telemetry is unavailable"
}

$initialEndpoint = [string]$initialTransport.endpoint
$initialNode = Get-SelectedNode $initialTransport
$initialTunnelAddress = [string]$before.tunnel_address
$initialRoutes = Get-NormalizedRoutes $before

$ping = New-Object System.Net.NetworkInformation.Ping
$samples = New-Object System.Collections.Generic.List[object]
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$faultMarkerMs = $null
$switchMs = $null
$switchEndpoint = ""
$switchNode = ""
$faultProcess = $null
$faultLaunched = $false
$lastSuccessMs = $null
$maxSuccessGapMs = 0.0
$successCount = 0
$failureCount = 0
$postSwitchRecovered = $false
$restoreError = ""

try {
    while ($stopwatch.Elapsed.TotalSeconds -lt $DurationSeconds) {
        $elapsedMs = [math]::Round($stopwatch.Elapsed.TotalMilliseconds, 3)

        if (-not $faultLaunched -and $elapsedMs -ge ($FaultAfterSeconds * 1000)) {
            $faultMarkerMs = $elapsedMs
            $faultLaunched = $true
            if (-not [string]::IsNullOrWhiteSpace($FaultSshHost)) {
                $faultProcess = Invoke-Fault $FaultSshHost $FaultSshUser $FaultService
            }
            else {
                Write-Host "FAULT MARKER reached. Trigger the active Public Node failure now." -ForegroundColor Yellow
            }
        }

        $transport = Read-TransportStatus
        $endpoint = if ($null -ne $transport) { [string]$transport.endpoint } else { "" }
        $node = Get-SelectedNode $transport

        if ($null -eq $switchMs -and $faultLaunched) {
            $nodeChanged = (
                -not [string]::IsNullOrWhiteSpace($initialNode) -and
                -not [string]::IsNullOrWhiteSpace($node) -and
                $node -ne $initialNode
            )
            $endpointChanged = (
                [string]::IsNullOrWhiteSpace($initialNode) -and
                -not [string]::IsNullOrWhiteSpace($endpoint) -and
                $endpoint -ne $initialEndpoint
            )
            if ($nodeChanged -or $endpointChanged) {
                $switchMs = $elapsedMs
                $switchEndpoint = $endpoint
                $switchNode = $node
            }
        }

        $pingOK = $false
        $rttMs = $null
        try {
            $reply = $ping.Send($Target, [math]::Max(50, $IntervalMilliseconds))
            if ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
                $pingOK = $true
                $rttMs = [double]$reply.RoundtripTime
                $successCount++
                if ($null -ne $lastSuccessMs) {
                    $gap = $elapsedMs - [double]$lastSuccessMs
                    if ($gap -gt $maxSuccessGapMs) {
                        $maxSuccessGapMs = $gap
                    }
                }
                $lastSuccessMs = $elapsedMs
                if ($null -ne $switchMs -and $elapsedMs -ge [double]$switchMs) {
                    $postSwitchRecovered = $true
                }
            }
            else {
                $failureCount++
            }
        }
        catch {
            $failureCount++
        }

        $samples.Add([ordered]@{
            elapsed_ms = $elapsedMs
            ping_ok = $pingOK
            rtt_ms = $rttMs
            endpoint = $endpoint
            node = $node
            transport_updated_at = if ($null -ne $transport) { $transport.updated_at } else { $null }
        })

        $remaining = $IntervalMilliseconds - [int]($stopwatch.Elapsed.TotalMilliseconds - $elapsedMs)
        if ($remaining -gt 0) {
            Start-Sleep -Milliseconds $remaining
        }
    }
}
finally {
    $stopwatch.Stop()
    $ping.Dispose()
    if ($null -ne $faultProcess) {
        try {
            $faultProcess.WaitForExit(7000) | Out-Null
        }
        catch {
        }
        $faultProcess.Dispose()
    }
    if (
        -not $NoRestore -and
        -not [string]::IsNullOrWhiteSpace($FaultSshHost) -and
        $faultLaunched
    ) {
        try {
            Restore-Fault $FaultSshHost $FaultSshUser $FaultService
        }
        catch {
            $restoreError = $_.Exception.Message
        }
    }
}

$after = Read-AgentStatus
$finalTunnelAddress = if ($null -ne $after) { [string]$after.tunnel_address } else { "" }
$finalRoutes = Get-NormalizedRoutes $after
$overlayUnchanged = (
    $initialTunnelAddress -eq $finalTunnelAddress -and
    (@($initialRoutes) -join "\n") -eq (@($finalRoutes) -join "\n")
)

$switchDelayMs = if ($null -ne $switchMs -and $null -ne $faultMarkerMs) {
    [math]::Round(([double]$switchMs - [double]$faultMarkerMs), 3)
}
else {
    $null
}

$automatedFault = -not [string]::IsNullOrWhiteSpace($FaultSshHost)
$passed = (
    $null -ne $switchDelayMs -and
    $switchDelayMs -ge 0 -and
    $switchDelayMs -le $MaxSwitchMilliseconds -and
    $overlayUnchanged -and
    $postSwitchRecovered -and
    [string]::IsNullOrWhiteSpace($restoreError)
)

$report = [ordered]@{
    version = 1
    generated_at = [DateTimeOffset]::UtcNow.ToString("o")
    automated_fault = $automatedFault
    fault = [ordered]@{
        marker_ms = $faultMarkerMs
        ssh_host = $FaultSshHost
        service = $FaultService
        restored = (-not $automatedFault -or [string]::IsNullOrWhiteSpace($restoreError))
        restore_error = $restoreError
    }
    selection = [ordered]@{
        initial_node = $initialNode
        initial_endpoint = $initialEndpoint
        final_node = $switchNode
        final_endpoint = $switchEndpoint
        switch_ms = $switchMs
        switch_delay_ms = $switchDelayMs
        maximum_allowed_ms = $MaxSwitchMilliseconds
    }
    overlay = [ordered]@{
        address_before = $initialTunnelAddress
        address_after = $finalTunnelAddress
        routes_before = @($initialRoutes)
        routes_after = @($finalRoutes)
        unchanged = $overlayUnchanged
    }
    traffic = [ordered]@{
        target = $Target
        successes = $successCount
        failures = $failureCount
        max_success_gap_ms = [math]::Round($maxSuccessGapMs, 3)
        post_switch_recovered = $postSwitchRecovered
    }
    passed = $passed
    before = $before
    after = $after
    samples = $samples
}

$reportDirectory = Split-Path -Parent $ReportPath
if (-not [string]::IsNullOrWhiteSpace($reportDirectory)) {
    New-Item -ItemType Directory -Force -Path $reportDirectory | Out-Null
}
$report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $ReportPath -Encoding UTF8

Write-Host "Initial: node=$initialNode endpoint=$initialEndpoint"
Write-Host "Final:   node=$switchNode endpoint=$switchEndpoint"
Write-Host "Switch delay: $switchDelayMs ms (limit $MaxSwitchMilliseconds ms)"
Write-Host "Ping: success=$successCount failure=$failureCount max-gap=$([math]::Round($maxSuccessGapMs, 3)) ms"
Write-Host "Overlay unchanged: $overlayUnchanged"
Write-Host "Report: $ReportPath"

if (-not $passed) {
    exit 2
}
