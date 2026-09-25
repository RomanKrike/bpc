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

$form = New-Object System.Windows.Forms.Form
$form.Text = 'BPC Agent'
$form.ClientSize = New-Object System.Drawing.Size(540, 405)
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false
$form.MinimizeBox = $true
$form.ShowInTaskbar = $true
$form.Font = New-Object System.Drawing.Font('Segoe UI', 9)

$title = New-Object System.Windows.Forms.Label
$title.Text = 'BPC Agent'
$title.Font = New-Object System.Drawing.Font('Segoe UI', 17, [System.Drawing.FontStyle]::Bold)
$title.AutoSize = $true
$title.Location = New-Object System.Drawing.Point(18, 14)
$form.Controls.Add($title)

$versionValue = New-Object System.Windows.Forms.Label
$versionValue.Text = "v$uiVersion"
$versionValue.ForeColor = [System.Drawing.Color]::DimGray
$versionValue.Location = New-Object System.Drawing.Point(430, 22)
$versionValue.Size = New-Object System.Drawing.Size(90, 22)
$versionValue.TextAlign = 'MiddleRight'
$form.Controls.Add($versionValue)

$statusDot = New-Object System.Windows.Forms.Label
$statusDot.Text = [char]0x25CF
$statusDot.Font = New-Object System.Drawing.Font('Segoe UI', 14)
$statusDot.Location = New-Object System.Drawing.Point(20, 58)
$statusDot.Size = New-Object System.Drawing.Size(24, 25)
$form.Controls.Add($statusDot)

$statusValue = New-Object System.Windows.Forms.Label
$statusValue.Text = 'Checking...'
$statusValue.Font = New-Object System.Drawing.Font('Segoe UI', 11, [System.Drawing.FontStyle]::Bold)
$statusValue.Location = New-Object System.Drawing.Point(48, 61)
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

$deviceValue = Add-Row 'Device' 96
$ipValue = Add-Row 'Tunnel IP' 124
$relayValue = Add-Row 'Relay' 152
$handshakeValue = Add-Row 'Last handshake' 180
$trafficValue = Add-Row 'Traffic' 208

$routesCaption = New-Object System.Windows.Forms.Label
$routesCaption.Text = 'Routes'
$routesCaption.ForeColor = [System.Drawing.Color]::DimGray
$routesCaption.Location = New-Object System.Drawing.Point(20, 238)
$routesCaption.Size = New-Object System.Drawing.Size(120, 22)
$form.Controls.Add($routesCaption)

$routesValue = New-Object System.Windows.Forms.TextBox
$routesValue.ReadOnly = $true
$routesValue.Multiline = $true
$routesValue.ScrollBars = 'Vertical'
$routesValue.BorderStyle = 'FixedSingle'
$routesValue.Location = New-Object System.Drawing.Point(150, 236)
$routesValue.Size = New-Object System.Drawing.Size(365, 90)
$routesValue.BackColor = [System.Drawing.SystemColors]::Window
$form.Controls.Add($routesValue)

$connect = New-Object System.Windows.Forms.Button
$connect.Text = 'Connect'
$connect.Location = New-Object System.Drawing.Point(150, 348)
$connect.Size = New-Object System.Drawing.Size(140, 36)
$form.Controls.Add($connect)

$disconnect = New-Object System.Windows.Forms.Button
$disconnect.Text = 'Disconnect'
$disconnect.Location = New-Object System.Drawing.Point(305, 348)
$disconnect.Size = New-Object System.Drawing.Size(140, 36)
$form.Controls.Add($disconnect)

$tray = New-Object System.Windows.Forms.NotifyIcon
$tray.Text = 'BPC Agent'
$tray.Icon = [System.Drawing.SystemIcons]::Application
$tray.Visible = $true

$menu = New-Object System.Windows.Forms.ContextMenuStrip
$openItem = $menu.Items.Add('Open BPC Agent')
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
        $handshakeValue.Text = '-'
        $trafficValue.Text = '-'
        $routesValue.Text = ''
        $connect.Enabled = $true
        $disconnect.Enabled = $false
        $connectItem.Enabled = $true
        $disconnectItem.Enabled = $false
        $tray.Text = 'BPC Agent - Unavailable'
        return
    }

    if ($s.version -and $s.version -ne $uiVersion) {
        Restart-BpcUI
        return
    }

    $versionValue.Text = "v$($s.version)"
    $deviceValue.Text = $s.device
    $ipValue.Text = $s.tunnel_address
    $relayValue.Text = $s.relay
    $routesValue.Text = ($s.routes -join [Environment]::NewLine)

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
            $tray.Text = 'BPC Agent - Connected'
        }
        'Connecting' {
            $statusValue.Text = 'Connecting...'
            $statusDot.ForeColor = [System.Drawing.Color]::DarkOrange
            $tray.Text = 'BPC Agent - Connecting'
        }
        default {
            $statusValue.Text = 'Disconnected'
            $statusDot.ForeColor = [System.Drawing.Color]::DarkGray
            $tray.Text = 'BPC Agent - Disconnected'
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
if (-not $script:mutexReleased) {
    $mutex.ReleaseMutex() | Out-Null
    $mutex.Dispose()
}
`

func installWindowsUI(exePath, dir string) error {
	// 0.11.0+ renders the UI script from the current EXE into the active
	// user's LocalAppData on each launch. Remove the old ProgramData copy.
	_ = os.Remove(filepath.Join(dir, "bpc-ui.ps1"))

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
	if err := os.WriteFile(script, []byte(body), 0o600); err != nil {
		return fmt.Errorf("write current BPC Agent UI: %w", err)
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
		return fmt.Errorf("launch BPC Agent UI: %w", err)
	}
	return nil
}
