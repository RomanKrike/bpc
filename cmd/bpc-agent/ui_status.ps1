# Pure presentation logic; also exercised by scripts/test-windows-ui.ps1.
function Get-BpcConnectionState($service, $runtime, $transport, [Int64]$now) {
    if ($service -ne 'running') { return 'Disconnected' }
    $hadHandshake = $null -ne $runtime -and [Int64]$runtime.handshake_at -gt 0
    $waiting = 'Connecting'
    if ($hadHandshake) { $waiting = 'Reconnecting' }
    if ($null -eq $runtime -or $null -eq $transport) { return $waiting }
    $runtimeAge = $now - [Int64]$runtime.updated_at
    $transportAge = $now - [Int64]$transport.updated_at
    $handshakeAge = $now - [Int64]$runtime.handshake_at
    if ($runtimeAge -lt -5 -or $runtimeAge -gt 10 -or
        $transportAge -lt -5 -or $transportAge -gt 10 -or
        -not $hadHandshake -or $handshakeAge -lt -5 -or $handshakeAge -gt 180) {
        return $waiting
    }
    # Another healthy endpoint does not prove the selected path is working.
    $selected = @($transport.paths | Where-Object {
        $_.endpoint -eq $transport.endpoint -and $_.reachable -eq $true
    })
    if ($selected.Count -eq 0) { return $waiting }
    if ([Int64]$transport.node_changed_at -gt [Int64]$runtime.handshake_at) {
        return 'Reconnecting'
    }
    return 'Connected'
}

function Get-BpcGatewaySummary($transport) {
    if ($null -eq $transport) { return 'Automatic gateway selection' }
    $nodes = @($transport.paths | Where-Object { $_.node } |
        Group-Object -Property { $_.node })
    if ($nodes.Count -eq 0) { return 'Automatic gateway selection' }
    $available = @($nodes | Where-Object {
        @($_.Group | Where-Object { $_.reachable -eq $true }).Count -gt 0
    }).Count
    return "Automatic - $available/$($nodes.Count) gateways available"
}
