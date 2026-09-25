//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const uiTaskName = "BPC Agent UI"

const bpcConnectLogoPNGBase64 = "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"

const windowsUIScript = `Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$uiVersion = '__BPC_UI_VERSION__'
$created = $false
$mutex = [System.Threading.Mutex]::new($true, 'Local\BPCAgentUI', [ref]$created)
if (-not $created) { exit 0 }
$script:mutexReleased = $false

[System.Windows.Forms.Application]::EnableVisualStyles()
$exe = Join-Path $env:ProgramData 'BPC\bpc-agent.exe'
$statusPath = Join-Path $env:ProgramData 'BPC\ui-status.json'
$runtimePath = Join-Path $env:ProgramData 'BPC\ui-runtime.json'
$transportPath = Join-Path $env:ProgramData 'BPC\ui-transport.json'

$logoBytes = [Convert]::FromBase64String('__BPC_LOGO_PNG__')
$logoStream = New-Object System.IO.MemoryStream(,$logoBytes)
$logoImage = [System.Drawing.Image]::FromStream($logoStream)

$form = New-Object System.Windows.Forms.Form
$form.Text = 'BPC Connect'
$form.ClientSize = New-Object System.Drawing.Size(540, 453)
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false
$form.MinimizeBox = $true
$form.ShowInTaskbar = $true
$form.Font = New-Object System.Drawing.Font('Segoe UI', 9)

$logo = New-Object System.Windows.Forms.PictureBox
$logo.Image = $logoImage
$logo.SizeMode = 'Zoom'
$logo.Location = New-Object System.Drawing.Point(18, 10)
$logo.Size = New-Object System.Drawing.Size(50, 50)
$form.Controls.Add($logo)

$title = New-Object System.Windows.Forms.Label
$title.Text = 'Connect'
$title.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 19, [System.Drawing.FontStyle]::Regular)
$title.AutoSize = $true
$title.Location = New-Object System.Drawing.Point(78, 18)
$form.Controls.Add($title)

$versionValue = New-Object System.Windows.Forms.Label
$versionValue.Text = "v$uiVersion"
$versionValue.ForeColor = [System.Drawing.Color]::DimGray
$versionValue.Location = New-Object System.Drawing.Point(430, 24)
$versionValue.Size = New-Object System.Drawing.Size(90, 22)
$versionValue.TextAlign = 'MiddleRight'
$form.Controls.Add($versionValue)

$statusDot = New-Object System.Windows.Forms.Label
$statusDot.Text = [char]0x25CF
$statusDot.Font = New-Object System.Drawing.Font('Segoe UI', 14)
$statusDot.Location = New-Object System.Drawing.Point(20, 72)
$statusDot.Size = New-Object System.Drawing.Size(24, 25)
$form.Controls.Add($statusDot)

$statusValue = New-Object System.Windows.Forms.Label
$statusValue.Text = 'Checking...'
$statusValue.Font = New-Object System.Drawing.Font('Segoe UI', 11, [System.Drawing.FontStyle]::Bold)
$statusValue.Location = New-Object System.Drawing.Point(48, 75)
$statusValue.Size = New-Object System.Drawing.Size(180, 24)
$form.Controls.Add($statusValue)

function Add-Row([string]$caption, [int]$y) {
    $c = New-Object System.Windows.Forms.Label
    $c.Text = $caption
    $c.ForeColor = [System.Drawing.Color]::DimGray
    $c.Location = New-Object System.Drawing.Point(20, $y)
    $c.Size = New-Object System.Drawing.Size(120, 22)
    $form.Controls.Add($c)

    $v = New-Object System.Windows.Forms.Label
    $v.Text = '-'
    $v.Location = New-Object System.Drawing.Point(150, $y)
    $v.Size = New-Object System.Drawing.Size(365, 22)
    $form.Controls.Add($v)
    return $v
}

$deviceValue = Add-Row 'Device' 110
$ipValue = Add-Row 'Tunnel IP' 138
$relayValue = Add-Row 'UDP endpoint' 166
$portValue = Add-Row 'Port RTT' 194
$handshakeValue = Add-Row 'Last handshake' 222
$trafficValue = Add-Row 'Traffic' 250

$routesCaption = New-Object System.Windows.Forms.Label
$routesCaption.Text = 'Routes'
$routesCaption.ForeColor = [System.Drawing.Color]::DimGray
$routesCaption.Location = New-Object System.Drawing.Point(20, 280)
$routesCaption.Size = New-Object System.Drawing.Size(120, 22)
$form.Controls.Add($routesCaption)

$routesValue = New-Object System.Windows.Forms.TextBox
$routesValue.ReadOnly = $true
$routesValue.Multiline = $true
$routesValue.ScrollBars = 'Vertical'
$routesValue.BorderStyle = 'FixedSingle'
$routesValue.Location = New-Object System.Drawing.Point(150, 278)
$routesValue.Size = New-Object System.Drawing.Size(365, 90)
$routesValue.BackColor = [System.Drawing.SystemColors]::Window
$form.Controls.Add($routesValue)

$connect = New-Object System.Windows.Forms.Button
$connect.Text = 'Connect'
$connect.Location = New-Object System.Drawing.Point(150, 394)
$connect.Size = New-Object System.Drawing.Size(140, 36)
$form.Controls.Add($connect)

$disconnect = New-Object System.Windows.Forms.Button
$disconnect.Text = 'Disconnect'
$disconnect.Location = New-Object System.Drawing.Point(305, 394)
$disconnect.Size = New-Object System.Drawing.Size(140, 36)
$form.Controls.Add($disconnect)

$iconBitmap = New-Object System.Drawing.Bitmap 32, 32
$iconGraphics = [System.Drawing.Graphics]::FromImage($iconBitmap)
$iconGraphics.DrawImage($logoImage, 0, 0, 32, 32)
$iconGraphics.Dispose()
$iconHandle = $iconBitmap.GetHicon()
$clientIcon = [System.Drawing.Icon]::FromHandle($iconHandle)
$form.Icon = $clientIcon

$tray = New-Object System.Windows.Forms.NotifyIcon
$tray.Text = 'BPC Connect'
$tray.Icon = $clientIcon
$tray.Visible = $true

$menu = New-Object System.Windows.Forms.ContextMenuStrip
$openItem = $menu.Items.Add('Open BPC Connect')
$menu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator)) | Out-Null
$connectItem = $menu.Items.Add('Connect')
$disconnectItem = $menu.Items.Add('Disconnect')
$menu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator)) | Out-Null
$exitItem = $menu.Items.Add('Exit UI')
$tray.ContextMenuStrip = $menu

function Format-Bytes([UInt64]$value) {
    if ($value -ge 1GB) { return ('{0:N2} GB' -f ($value / 1GB)) }
    if ($value -ge 1MB) { return ('{0:N2} MB' -f ($value / 1MB)) }
    if ($value -ge 1KB) { return ('{0:N1} KB' -f ($value / 1KB)) }
    return "$value B"
}

function Format-Age([Int64]$seconds) {
    if ($seconds -lt 0) { $seconds = 0 }
    if ($seconds -lt 60) { return "$seconds sec ago" }
    $minutes = [math]::Floor($seconds / 60)
    $remain = $seconds % 60
    if ($minutes -lt 60) { return "$minutes min $remain sec ago" }
    $hours = [math]::Floor($minutes / 60)
    return "$hours h $($minutes % 60) min ago"
}

function Get-BpcStatus {
    try {
        if (-not (Test-Path -LiteralPath $statusPath)) { return $null }
        $s = Get-Content -LiteralPath $statusPath -Raw | ConvertFrom-Json
        $runtime = $null
        if (Test-Path -LiteralPath $runtimePath) {
            try { $runtime = Get-Content -LiteralPath $runtimePath -Raw | ConvertFrom-Json } catch {}
        }
        $transport = $null
        if (Test-Path -LiteralPath $transportPath) {
            try { $transport = Get-Content -LiteralPath $transportPath -Raw | ConvertFrom-Json } catch {}
        }

        $svc = Get-Service -Name BPCAgent -ErrorAction SilentlyContinue
        $service = 'missing'
        if ($null -ne $svc) {
            if ($svc.Status -eq 'Running') { $service = 'running' } else { $service = 'stopped' }
        }

        $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $connection = 'Disconnected'
        $handshakeAge = -1
        if ($service -eq 'running') {
            $connection = 'Connecting'
            if ($null -ne $runtime) {
                $runtimeAge = $now - [Int64]$runtime.updated_at
                if ($runtimeAge -ge -5 -and $runtimeAge -le 10 -and [Int64]$runtime.handshake_at -gt 0) {
                    $handshakeAge = $now - [Int64]$runtime.handshake_at
                    if ($handshakeAge -ge -5 -and $handshakeAge -le 180) {
                        $connection = 'Connected'
                    }
                }
            }
        }

        $s | Add-Member -NotePropertyName service -NotePropertyValue $service -Force
        $s | Add-Member -NotePropertyName connection -NotePropertyValue $connection -Force
        $s | Add-Member -NotePropertyName runtime -NotePropertyValue $runtime -Force
        $s | Add-Member -NotePropertyName transport -NotePropertyValue $transport -Force
        $s | Add-Member -NotePropertyName handshake_age -NotePropertyValue $handshakeAge -Force
        return $s
    } catch {
        return $null
    }
}

function Restart-BpcUI {
    if ($script:timer) { $script:timer.Stop() }
    $tray.Visible = $false
    $tray.Dispose()
    if (-not $script:mutexReleased) {
        $mutex.ReleaseMutex() | Out-Null
        $mutex.Dispose()
        $script:mutexReleased = $true
    }
    Start-Process -FilePath $exe -ArgumentList 'ui' -WindowStyle Hidden
    [System.Windows.Forms.Application]::Exit()
}

function Refresh-Bpc {
    $s = Get-BpcStatus
    if ($null -eq $s) {
        $statusValue.Text = 'Unavailable'
        $statusDot.ForeColor = [System.Drawing.Color]::DarkGray
        $deviceValue.Text = '-'
        $ipValue.Text = '-'
        $relayValue.Text = '-'
        $portValue.Text = '-'
        $handshakeValue.Text = '-'
        $trafficValue.Text = '-'
        $routesValue.Text = ''
        $connect.Enabled = $true
        $disconnect.Enabled = $false
        $connectItem.Enabled = $true
        $disconnectItem.Enabled = $false
        $tray.Text = 'BPC Connect - Unavailable'
        return
    }

    if ($s.version -and $s.version -ne $uiVersion) {
        Restart-BpcUI
        return
    }

    $versionValue.Text = "v$($s.version)"
    $deviceValue.Text = $s.device
    $ipValue.Text = $s.tunnel_address
    $routesValue.Text = ($s.routes -join [Environment]::NewLine)

    if ($null -ne $s.transport) {
        $relayValue.Text = $s.transport.endpoint
        if ([Int64]$s.transport.rtt_ms -gt 0) {
            $portValue.Text = "$($s.transport.rtt_ms) ms   $($s.transport.reachable)/$($s.transport.total) reachable"
        } else {
            $portValue.Text = "Testing...   $($s.transport.reachable)/$($s.transport.total) reachable"
        }
    } else {
        $relayValue.Text = $s.relay
        $poolCount = 1
        if ($null -ne $s.relay_pool -and $s.relay_pool.Count -gt 0) { $poolCount = $s.relay_pool.Count }
        $portValue.Text = "Waiting for probe   0/$poolCount reachable"
    }

    if ($null -ne $s.runtime) {
        if ($s.handshake_age -ge 0) {
            $handshakeValue.Text = Format-Age ([Int64]$s.handshake_age)
        } else {
            $handshakeValue.Text = 'Waiting for handshake'
        }
        $trafficValue.Text = "RX $(Format-Bytes ([UInt64]$s.runtime.rx_bytes))    TX $(Format-Bytes ([UInt64]$s.runtime.tx_bytes))"
    } else {
        $handshakeValue.Text = 'No tunnel telemetry'
        $trafficValue.Text = 'RX 0 B    TX 0 B'
    }

    switch ($s.connection) {
        'Connected' {
            $statusValue.Text = 'Connected'
            $statusDot.ForeColor = [System.Drawing.Color]::SeaGreen
            $tray.Text = 'BPC Connect - Connected'
        }
        'Connecting' {
            $statusValue.Text = 'Connecting...'
            $statusDot.ForeColor = [System.Drawing.Color]::DarkOrange
            $tray.Text = 'BPC Connect - Connecting'
        }
        default {
            $statusValue.Text = 'Disconnected'
            $statusDot.ForeColor = [System.Drawing.Color]::DarkGray
            $tray.Text = 'BPC Connect - Disconnected'
        }
    }

    $isRunning = $s.service -eq 'running'
    $connect.Enabled = -not $isRunning
    $disconnect.Enabled = $isRunning
    $connectItem.Enabled = -not $isRunning
    $disconnectItem.Enabled = $isRunning
}

$doConnect = {
    & $exe connect | Out-Null
    Start-Sleep -Milliseconds 400
    Refresh-Bpc
}
$doDisconnect = {
    & $exe disconnect | Out-Null
    Start-Sleep -Milliseconds 400
    Refresh-Bpc
}

$connect.Add_Click($doConnect)
$disconnect.Add_Click($doDisconnect)
$connectItem.Add_Click($doConnect)
$disconnectItem.Add_Click($doDisconnect)

$openAction = {
    if (-not $form.Visible) { $form.Show() }
    $form.WindowState = 'Normal'
    $form.Activate()
    Refresh-Bpc
}
$openItem.Add_Click($openAction)
$tray.Add_DoubleClick($openAction)

$exitItem.Add_Click({
    $tray.Visible = $false
    $form.Tag = 'exit'
    $form.Close()
    [System.Windows.Forms.Application]::Exit()
})

$form.Add_FormClosing({
    param($sender, $eventArgs)
    if ($form.Tag -ne 'exit') {
        $eventArgs.Cancel = $true
        $form.Hide()
    }
})

$script:timer = New-Object System.Windows.Forms.Timer
$script:timer.Interval = 2000
$script:timer.Add_Tick({ Refresh-Bpc })
$script:timer.Start()

Refresh-Bpc
$form.Show()
[System.Windows.Forms.Application]::Run()
$script:timer.Stop()
$tray.Visible = $false
$tray.Dispose()
$clientIcon.Dispose()
$iconBitmap.Dispose()
$logoImage.Dispose()
$logoStream.Dispose()
if (-not $script:mutexReleased) {
    $mutex.ReleaseMutex() | Out-Null
    $mutex.Dispose()
}
`

func installWindowsUI(exePath, dir string) error {
	// Terminate only the legacy 0.10.x PowerShell UI before removing its
	// ProgramData script. This lets the first 0.11.0 manual update replace the
	// already-running tray process instead of losing to its single-instance mutex.
	legacyScript := filepath.Join(dir, "bpc-ui.ps1")
	legacyCleanup := fmt.Sprintf(
		"$old='%s'; Get-CimInstance Win32_Process -Filter \"Name='powershell.exe'\" | "+
			"Where-Object { $_.CommandLine -and $_.CommandLine.Contains($old) } | "+
			"ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }",
		psQuote(legacyScript),
	)
	_, _ = runCommand(
		"powershell.exe",
		"-NoProfile",
		"-NonInteractive",
		"-Command",
		legacyCleanup,
	)

	// 0.11.0+ renders the UI script from the current EXE into the active
	// user's LocalAppData on each launch.
	_ = os.Remove(legacyScript)

	_, _ = runCommand("schtasks.exe", "/End", "/TN", uiTaskName)
	_, _ = runCommand("schtasks.exe", "/Delete", "/TN", uiTaskName, "/F")

	runValue := fmt.Sprintf("%q ui", exePath)
	out, err := runCommand(
		"reg.exe",
		"ADD",
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
		"/v",
		uiTaskName,
		"/t",
		"REG_SZ",
		"/d",
		runValue,
		"/f",
	)
	if err != nil {
		return fmt.Errorf("register UI logon launcher: %w: %s", err, out)
	}
	return nil
}

func startWindowsUI() error {
	return launchWindowsUI()
}

func removeWindowsUI() error {
	_, _ = runCommand("schtasks.exe", "/End", "/TN", uiTaskName)
	_, _ = runCommand("schtasks.exe", "/Delete", "/TN", uiTaskName, "/F")
	_, _ = runCommand(
		"reg.exe",
		"DELETE",
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
		"/v",
		uiTaskName,
		"/f",
	)

	dir, _, _, err := installPaths()
	if err == nil {
		_ = os.Remove(filepath.Join(dir, "bpc-ui.ps1"))
		_ = os.Remove(filepath.Join(dir, "ui-status.json"))
		_ = os.Remove(filepath.Join(dir, "ui-runtime.json"))
		_ = os.Remove(filepath.Join(dir, "ui-transport.json"))
	}
	if cacheDir, cacheErr := os.UserCacheDir(); cacheErr == nil {
		_ = os.RemoveAll(filepath.Join(cacheDir, "BPC"))
	}
	return nil
}

func launchWindowsUI() error {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return fmt.Errorf("resolve user cache directory: %w", err)
	}
	uiDir := filepath.Join(cacheDir, "BPC")
	if err := os.MkdirAll(uiDir, 0o700); err != nil {
		return fmt.Errorf("create user UI directory: %w", err)
	}
	script := filepath.Join(uiDir, "bpc-ui.ps1")
	body := strings.ReplaceAll(windowsUIScript, "__BPC_UI_VERSION__", version)
	body = strings.ReplaceAll(body, "__BPC_LOGO_PNG__", bpcConnectLogoPNGBase64)
	if err := os.WriteFile(script, []byte(body), 0o600); err != nil {
		return fmt.Errorf("write current BPC Connect UI: %w", err)
	}

	cmd := exec.Command(
		"powershell.exe",
		"-NoProfile",
		"-STA",
		"-WindowStyle",
		"Hidden",
		"-ExecutionPolicy",
		"Bypass",
		"-File",
		script,
	)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("launch BPC Connect UI: %w", err)
	}
	return nil
}
