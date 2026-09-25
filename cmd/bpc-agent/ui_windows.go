//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const uiTaskName = "BPC Agent UI"

const windowsUIScript = `Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$created = $false
$mutex = [System.Threading.Mutex]::new($true, 'Local\BPCAgentUI', [ref]$created)
if (-not $created) { exit 0 }

[System.Windows.Forms.Application]::EnableVisualStyles()
$exe = Join-Path $env:ProgramData 'BPC\bpc-agent.exe'
$statusPath = Join-Path $env:ProgramData 'BPC\ui-status.json'

$form = New-Object System.Windows.Forms.Form
$form.Text = 'BPC Agent'
$form.ClientSize = New-Object System.Drawing.Size(430, 250)
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false
$form.MinimizeBox = $true
$form.ShowInTaskbar = $true

$title = New-Object System.Windows.Forms.Label
$title.Text = 'BPC Agent'
$title.Font = New-Object System.Drawing.Font('Segoe UI', 16, [System.Drawing.FontStyle]::Bold)
$title.AutoSize = $true
$title.Location = New-Object System.Drawing.Point(18, 16)
$form.Controls.Add($title)

$statusCaption = New-Object System.Windows.Forms.Label
$statusCaption.Text = 'Status'
$statusCaption.Location = New-Object System.Drawing.Point(20, 62)
$statusCaption.Size = New-Object System.Drawing.Size(90, 22)
$form.Controls.Add($statusCaption)

$statusValue = New-Object System.Windows.Forms.Label
$statusValue.Text = 'Checking...'
$statusValue.Font = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
$statusValue.Location = New-Object System.Drawing.Point(120, 62)
$statusValue.Size = New-Object System.Drawing.Size(280, 22)
$form.Controls.Add($statusValue)

$deviceCaption = New-Object System.Windows.Forms.Label
$deviceCaption.Text = 'Device'
$deviceCaption.Location = New-Object System.Drawing.Point(20, 92)
$deviceCaption.Size = New-Object System.Drawing.Size(90, 22)
$form.Controls.Add($deviceCaption)

$deviceValue = New-Object System.Windows.Forms.Label
$deviceValue.Text = '-'
$deviceValue.Location = New-Object System.Drawing.Point(120, 92)
$deviceValue.Size = New-Object System.Drawing.Size(280, 22)
$form.Controls.Add($deviceValue)

$relayCaption = New-Object System.Windows.Forms.Label
$relayCaption.Text = 'Relay'
$relayCaption.Location = New-Object System.Drawing.Point(20, 122)
$relayCaption.Size = New-Object System.Drawing.Size(90, 22)
$form.Controls.Add($relayCaption)

$relayValue = New-Object System.Windows.Forms.Label
$relayValue.Text = '-'
$relayValue.Location = New-Object System.Drawing.Point(120, 122)
$relayValue.Size = New-Object System.Drawing.Size(280, 22)
$form.Controls.Add($relayValue)

$routesCaption = New-Object System.Windows.Forms.Label
$routesCaption.Text = 'Routes'
$routesCaption.Location = New-Object System.Drawing.Point(20, 152)
$routesCaption.Size = New-Object System.Drawing.Size(90, 22)
$form.Controls.Add($routesCaption)

$routesValue = New-Object System.Windows.Forms.Label
$routesValue.Text = '-'
$routesValue.Location = New-Object System.Drawing.Point(120, 152)
$routesValue.Size = New-Object System.Drawing.Size(280, 40)
$form.Controls.Add($routesValue)

$connect = New-Object System.Windows.Forms.Button
$connect.Text = 'Connect'
$connect.Location = New-Object System.Drawing.Point(120, 202)
$connect.Size = New-Object System.Drawing.Size(120, 32)
$form.Controls.Add($connect)

$disconnect = New-Object System.Windows.Forms.Button
$disconnect.Text = 'Disconnect'
$disconnect.Location = New-Object System.Drawing.Point(252, 202)
$disconnect.Size = New-Object System.Drawing.Size(120, 32)
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

function Get-BpcStatus {
    try {
        if (-not (Test-Path -LiteralPath $statusPath)) { return $null }
        $s = Get-Content -LiteralPath $statusPath -Raw | ConvertFrom-Json
        $svc = Get-Service -Name BPCAgent -ErrorAction SilentlyContinue
        if ($null -eq $svc) {
            $s | Add-Member -NotePropertyName service -NotePropertyValue 'missing' -Force
        } elseif ($svc.Status -eq 'Running') {
            $s | Add-Member -NotePropertyName service -NotePropertyValue 'running' -Force
        } else {
            $s | Add-Member -NotePropertyName service -NotePropertyValue 'stopped' -Force
        }
        return $s
    } catch {
        return $null
    }
}

function Refresh-Bpc {
    $s = Get-BpcStatus
    if ($null -eq $s) {
        $statusValue.Text = 'Unavailable'
        $deviceValue.Text = '-'
        $relayValue.Text = '-'
        $routesValue.Text = '-'
        $connect.Enabled = $true
        $disconnect.Enabled = $false
        $connectItem.Enabled = $true
        $disconnectItem.Enabled = $false
        $tray.Text = 'BPC Agent - Unavailable'
        return
    }

    $deviceValue.Text = $s.device
    $relayValue.Text = $s.relay
    $routesValue.Text = ($s.routes -join ', ')

    if ($s.service -eq 'running') {
        $statusValue.Text = 'Connected'
        $connect.Enabled = $false
        $disconnect.Enabled = $true
        $connectItem.Enabled = $false
        $disconnectItem.Enabled = $true
        $tray.Text = 'BPC Agent - Connected'
    } else {
        $statusValue.Text = 'Disconnected'
        $connect.Enabled = $true
        $disconnect.Enabled = $false
        $connectItem.Enabled = $true
        $disconnectItem.Enabled = $false
        $tray.Text = 'BPC Agent - Disconnected'
    }
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

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 2000
$timer.Add_Tick({ Refresh-Bpc })
$timer.Start()

Refresh-Bpc
$form.Show()
[System.Windows.Forms.Application]::Run()
$timer.Stop()
$tray.Visible = $false
$tray.Dispose()
$mutex.ReleaseMutex() | Out-Null
$mutex.Dispose()
`

func installWindowsUI(exePath, dir string) error {
	uiPath := filepath.Join(dir, "bpc-ui.ps1")
	if err := os.WriteFile(uiPath, []byte(windowsUIScript), 0o600); err != nil {
		return err
	}

	// Remove the 0.10.6 task-based launcher. UI now starts in the current
	// interactive session and uses HKCU Run for logon autostart.
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
	}
	return nil
}

func launchWindowsUI() error {
	dir, _, _, err := installPaths()
	if err != nil {
		return err
	}
	script := filepath.Join(dir, "bpc-ui.ps1")
	if _, err := os.Stat(script); err != nil {
		return fmt.Errorf("BPC Agent UI is not installed: %w", err)
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
