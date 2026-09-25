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

$created = $false
$mutex = [System.Threading.Mutex]::new($true, 'Global\BPCAgentUI', [ref]$created)
if (-not $created) { exit 0 }

[System.Windows.Forms.Application]::EnableVisualStyles()
$exe = Join-Path $env:ProgramData 'BPC\bpc-agent.exe'

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
        $raw = (& $exe status-json 2>$null | Out-String).Trim()
        if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
        return $raw | ConvertFrom-Json
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
    Start-Service -Name BPCAgent -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 400
    Refresh-Bpc
}
$doDisconnect = {
    Stop-Service -Name BPCAgent -Force -ErrorAction SilentlyContinue
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

	userOut, err := runCommand(
		"powershell.exe",
		"-NoProfile",
		"-NonInteractive",
		"-Command",
		"[Security.Principal.WindowsIdentity]::GetCurrent().Name",
	)
	if err != nil {
		return fmt.Errorf("resolve UI task user: %w: %s", err, userOut)
	}
	user := strings.TrimSpace(userOut)
	if user == "" {
		return fmt.Errorf("resolve UI task user: empty identity")
	}

	ps := fmt.Sprintf(
		"$a=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument %s; "+
			"$t=New-ScheduledTaskTrigger -AtLogOn -User %s; "+
			"$p=New-ScheduledTaskPrincipal -UserId %s -LogonType Interactive -RunLevel Highest; "+
			"Register-ScheduledTask -TaskName %s -Action $a -Trigger $t -Principal $p -Force | Out-Null",
		psSingleQuote("-NoProfile -STA -WindowStyle Hidden -ExecutionPolicy Bypass -File "+uiPath),
		psSingleQuote(user),
		psSingleQuote(user),
		psSingleQuote(uiTaskName),
	)
	if out, err := runCommand("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps); err != nil {
		return fmt.Errorf("register UI task: %w: %s", err, out)
	}
	_ = exePath
	return nil
}

func startWindowsUI() error {
	out, err := runCommand("schtasks.exe", "/Run", "/TN", uiTaskName)
	if err != nil {
		return fmt.Errorf("start UI task: %w: %s", err, out)
	}
	return nil
}

func removeWindowsUI() error {
	_, _ = runCommand("schtasks.exe", "/End", "/TN", uiTaskName)
	_, _ = runCommand("schtasks.exe", "/Delete", "/TN", uiTaskName, "/F")
	dir, _, _, err := installPaths()
	if err == nil {
		_ = os.Remove(filepath.Join(dir, "bpc-ui.ps1"))
	}
	return nil
}

func launchWindowsUI() error {
	if !isAdministrator() {
		return elevate("ui")
	}
	if err := startWindowsUI(); err == nil {
		return nil
	}
	dir, _, _, err := installPaths()
	if err != nil {
		return err
	}
	script := filepath.Join(dir, "bpc-ui.ps1")
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
	return cmd.Start()
}

func psSingleQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}
