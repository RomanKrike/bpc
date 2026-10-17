$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this update script in PowerShell as Administrator.'
}
$source = Join-Path $PSScriptRoot 'BPC-Connect.exe'
$checksums = Get-Content (Join-Path $PSScriptRoot 'SHA256SUMS')
$entry = @($checksums | Where-Object { $_ -match '  BPC-Connect\.exe$' })
if ($entry.Count -ne 1) { throw 'Missing or duplicate executable checksum' }
$expected = ($entry[0] -split '\s+')[0]
if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -ne $expected) {
    throw 'Executable checksum mismatch'
}
$directory = Join-Path $env:ProgramData 'BPC'
$target = Join-Path $directory 'bpc-agent.exe'
if (-not (Test-Path (Join-Path $directory 'state.json')) -or
    -not (Test-Path $target) -or -not (Test-Path (Join-Path $directory 'wintun.dll'))) {
    throw 'An enrolled BPC installation is required. This update does not enroll a new Device.'
}
$service = Get-Service BPCAgent
$wasRunning = $service.Status -eq 'Running'
$backup = Join-Path $directory ('previous-' + (Get-Date -Format 'yyyyMMdd-HHmmss-ffff'))
$null = New-Item -ItemType Directory -Path $backup -ErrorAction Stop
Copy-Item -LiteralPath $target -Destination (Join-Path $backup 'bpc-agent.exe')
try {
    Stop-Service BPCAgent -ErrorAction Stop
    (Get-Service BPCAgent).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    $uiScript = Join-Path $env:LOCALAPPDATA 'BPC\bpc-ui.ps1'
    Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
        Where-Object { $_.CommandLine -and $_.CommandLine.Contains($uiScript) } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop }
    Copy-Item -LiteralPath $source -Destination $target -Force
    if ($wasRunning) {
        Start-Service BPCAgent -ErrorAction Stop
        (Get-Service BPCAgent).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
    }
    & $target install-ui
    if ($LASTEXITCODE -ne 0) { throw 'BPC UI registration failed' }
} catch {
    Stop-Service BPCAgent -ErrorAction SilentlyContinue
    Copy-Item -LiteralPath (Join-Path $backup 'bpc-agent.exe') -Destination $target -Force
    if ($wasRunning) { Start-Service BPCAgent -ErrorAction Continue }
    throw
}
Write-Output "Updated. Open BPC Connect in the Start menu. Previous executable: $backup"
