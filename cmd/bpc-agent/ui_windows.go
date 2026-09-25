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

$bg = [System.Drawing.Color]::FromArgb(247, 249, 251)
$card = [System.Drawing.Color]::White
$text = [System.Drawing.Color]::FromArgb(15, 23, 42)
$muted = [System.Drawing.Color]::FromArgb(100, 116, 139)
$line = [System.Drawing.Color]::FromArgb(226, 232, 240)
$green = [System.Drawing.Color]::FromArgb(22, 163, 74)
$greenSoft = [System.Drawing.Color]::FromArgb(236, 253, 245)
$orange = [System.Drawing.Color]::FromArgb(217, 119, 6)
$gray = [System.Drawing.Color]::FromArgb(148, 163, 184)
$red = [System.Drawing.Color]::FromArgb(220, 38, 38)
$redSoft = [System.Drawing.Color]::FromArgb(254, 242, 242)

function Set-RoundedRegion($control, [int]$radius) {
    $diameter = $radius * 2
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $path.StartFigure()
    $path.AddArc(0, 0, $diameter, $diameter, 180, 90)
    $path.AddArc($control.Width - $diameter - 1, 0, $diameter, $diameter, 270, 90)
    $path.AddArc($control.Width - $diameter - 1, $control.Height - $diameter - 1, $diameter, $diameter, 0, 90)
    $path.AddArc(0, $control.Height - $diameter - 1, $diameter, $diameter, 90, 90)
    $path.CloseFigure()
    $control.Region = New-Object System.Drawing.Region($path)
    $path.Dispose()
}

function New-Card([int]$x, [int]$y, [int]$w, [int]$h) {
    $panel = New-Object System.Windows.Forms.Panel
    $panel.Location = New-Object System.Drawing.Point($x, $y)
    $panel.Size = New-Object System.Drawing.Size($w, $h)
    $panel.BackColor = $card
    Set-RoundedRegion $panel 14
    return $panel
}

function New-Label([string]$value, [int]$x, [int]$y, [int]$w, [int]$h, [float]$size, [System.Drawing.FontStyle]$style, [System.Drawing.Color]$color) {
    $label = New-Object System.Windows.Forms.Label
    $label.Text = $value
    $label.Location = New-Object System.Drawing.Point($x, $y)
    $label.Size = New-Object System.Drawing.Size($w, $h)
    $label.Font = New-Object System.Drawing.Font('Segoe UI', $size, $style)
    $label.ForeColor = $color
    return $label
}

$form = New-Object System.Windows.Forms.Form
$form.Text = 'BPC Connect'
$form.ClientSize = New-Object System.Drawing.Size(520, 660)
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false
$form.MinimizeBox = $true
$form.ShowInTaskbar = $true
$form.BackColor = $bg
$form.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$form.AutoScaleMode = 'Dpi'

$logo = New-Object System.Windows.Forms.PictureBox
$logo.Image = $logoImage
$logo.SizeMode = 'Zoom'
$logo.Location = New-Object System.Drawing.Point(24, 18)
$logo.Size = New-Object System.Drawing.Size(48, 48)
$form.Controls.Add($logo)

$title = New-Label '' 84 22 220 38 20 ([System.Drawing.FontStyle]::Bold) $text
$title.Text = 'Connect'
$form.Controls.Add($title)

$settings = New-Object System.Windows.Forms.Button
$settings.Text = [char]0x2699
$settings.Font = New-Object System.Drawing.Font('Segoe UI Symbol', 17)
$settings.Location = New-Object System.Drawing.Point(448, 20)
$settings.Size = New-Object System.Drawing.Size(46, 46)
$settings.FlatStyle = 'Flat'
$settings.FlatAppearance.BorderSize = 0
$settings.BackColor = $card
$settings.ForeColor = $muted
$settings.Cursor = [System.Windows.Forms.Cursors]::Hand
Set-RoundedRegion $settings 12
$form.Controls.Add($settings)

$script:ringColor = $gray
$statusRing = New-Object System.Windows.Forms.Panel
$statusRing.Location = New-Object System.Drawing.Point(193, 86)
$statusRing.Size = New-Object System.Drawing.Size(134, 134)
$statusRing.BackColor = $bg
$statusRing.Add_Paint({
    param($sender, $eventArgs)
    $g = $eventArgs.Graphics
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $c = $script:ringColor

    $glow = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(28, $c))
    $g.FillEllipse($glow, 3, 3, 128, 128)
    $glow.Dispose()

    $ring = New-Object System.Drawing.Pen($c, 8)
    $g.DrawEllipse($ring, 20, 20, 94, 94)
    $ring.Dispose()

    $lockPen = New-Object System.Drawing.Pen($c, 5)
    $g.DrawArc($lockPen, 50, 42, 34, 34, 180, 180)
    $lockPen.Dispose()

    $lockBrush = New-Object System.Drawing.SolidBrush($c)
    $g.FillRectangle($lockBrush, 47, 61, 40, 34)
    $lockBrush.Dispose()

    $keyBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::White)
    $g.FillEllipse($keyBrush, 64, 72, 7, 7)
    $g.FillRectangle($keyBrush, 66, 77, 3, 8)
    $keyBrush.Dispose()
})
$form.Controls.Add($statusRing)

$statusValue = New-Label 'Checking...' 60 230 400 42 22 ([System.Drawing.FontStyle]::Bold) $text
$statusValue.TextAlign = 'MiddleCenter'
$form.Controls.Add($statusValue)

$statusSubtitle = New-Label 'Checking secure connection' 50 270 420 28 10.5 ([System.Drawing.FontStyle]::Regular) $muted
$statusSubtitle.TextAlign = 'MiddleCenter'
$form.Controls.Add($statusSubtitle)

$relayCard = New-Card 24 310 472 70
$form.Controls.Add($relayCard)

$relayDot = New-Label ([char]0x25CF) 18 17 28 28 15 ([System.Drawing.FontStyle]::Regular) $green
$relayCard.Controls.Add($relayDot)

$relayCaption = New-Label 'Relay' 54 11 270 26 10.5 ([System.Drawing.FontStyle]::Bold) $text
$relayCard.Controls.Add($relayCaption)

$relayValue = New-Label '-' 54 36 300 23 9.5 ([System.Drawing.FontStyle]::Regular) $muted
$relayCard.Controls.Add($relayValue)

$handshakeValue = New-Label '-' 338 24 112 24 9 ([System.Drawing.FontStyle]::Regular) $muted
$handshakeValue.TextAlign = 'MiddleRight'
$relayCard.Controls.Add($handshakeValue)

$latencyCard = New-Card 24 394 228 86
$form.Controls.Add($latencyCard)

$latencyCaption = New-Label 'LATENCY' 18 13 190 20 8.5 ([System.Drawing.FontStyle]::Bold) $muted
$latencyCard.Controls.Add($latencyCaption)

$latencyValue = New-Label ([char]0x2014) 18 37 190 35 20 ([System.Drawing.FontStyle]::Bold) $text
$latencyCard.Controls.Add($latencyValue)

$trafficCard = New-Card 268 394 228 86
$form.Controls.Add($trafficCard)

$trafficCaption = New-Label 'Traffic' 18 13 190 20 8.5 ([System.Drawing.FontStyle]::Bold) $muted
$trafficCard.Controls.Add($trafficCaption)

$trafficValue = New-Label 'RX 0 B   TX 0 B' 18 39 194 32 11 ([System.Drawing.FontStyle]::Bold) $text
$trafficCard.Controls.Add($trafficValue)

$deviceCard = New-Card 24 494 472 68
$form.Controls.Add($deviceCard)

$deviceCaption = New-Label 'Device' 22 11 185 20 8.5 ([System.Drawing.FontStyle]::Regular) $muted
$deviceCard.Controls.Add($deviceCaption)

$deviceValue = New-Label '-' 22 31 185 27 11 ([System.Drawing.FontStyle]::Bold) $text
$deviceCard.Controls.Add($deviceValue)

$divider = New-Object System.Windows.Forms.Panel
$divider.Location = New-Object System.Drawing.Point(234, 14)
$divider.Size = New-Object System.Drawing.Size(1, 40)
$divider.BackColor = $line
$deviceCard.Controls.Add($divider)

$ipCaption = New-Label 'Tunnel IP' 258 11 190 20 8.5 ([System.Drawing.FontStyle]::Regular) $muted
$deviceCard.Controls.Add($ipCaption)

$ipValue = New-Label '-' 258 31 190 27 11 ([System.Drawing.FontStyle]::Bold) $text
$deviceCard.Controls.Add($ipValue)

$connect = New-Object System.Windows.Forms.Button
$connect.Text = 'Connect'
$connect.Location = New-Object System.Drawing.Point(24, 582)
$connect.Size = New-Object System.Drawing.Size(472, 50)
$connect.FlatStyle = 'Flat'
$connect.FlatAppearance.BorderSize = 0
$connect.BackColor = $green
$connect.ForeColor = [System.Drawing.Color]::White
$connect.Font = New-Object System.Drawing.Font('Segoe UI', 11, [System.Drawing.FontStyle]::Bold)
$connect.Cursor = [System.Windows.Forms.Cursors]::Hand
Set-RoundedRegion $connect 13
$form.Controls.Add($connect)

$disconnect = New-Object System.Windows.Forms.Button
$disconnect.Text = 'Disconnect'
$disconnect.Location = New-Object System.Drawing.Point(24, 582)
$disconnect.Size = New-Object System.Drawing.Size(472, 50)
$disconnect.FlatStyle = 'Flat'
$disconnect.FlatAppearance.BorderSize = 1
$disconnect.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(254, 202, 202)
$disconnect.BackColor = $redSoft
$disconnect.ForeColor = $red
$disconnect.Font = New-Object System.Drawing.Font('Segoe UI', 11, [System.Drawing.FontStyle]::Bold)
$disconnect.Cursor = [System.Windows.Forms.Cursors]::Hand
Set-RoundedRegion $disconnect 13
$form.Controls.Add($disconnect)

$versionValue = New-Label "v$uiVersion" 24 637 472 18 8 ([System.Drawing.FontStyle]::Regular) $gray
$versionValue.TextAlign = 'MiddleCenter'
$form.Controls.Add($versionValue)

$routesValue = New-Object System.Windows.Forms.TextBox
$routesValue.ReadOnly = $true
$routesValue.Multiline = $true
$routesValue.Visible = $false
$form.Controls.Add($routesValue)

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
    if ($minutes -lt 60) { return "$minutes min ago" }
    $hours = [math]::Floor($minutes / 60)
    return "$hours h $($minutes % 60) min ago"
}

function Get-RelayHost([string]$relay) {
    $value = $relay.Trim()
    if ($value -match '^\[(.+)\]:(\d+)$') { return $Matches[1] }
    if ($value -match '^([^:]+):(\d+)$') { return $Matches[1] }
    return $value
}

$script:lastLatencyAt = [DateTime]::MinValue
$script:lastLatency = $null

function Update-Latency([string]$relay, [bool]$connected) {
    if (-not $connected) {
        $script:lastLatency = $null
        $latencyValue.Text = [string][char]0x2014
        return
    }

    $now = Get-Date
    if (($now - $script:lastLatencyAt).TotalSeconds -lt 4) {
        if ($null -eq $script:lastLatency) {
            $latencyValue.Text = [string][char]0x2014
        } else {
            $latencyValue.Text = "$($script:lastLatency) ms"
        }
        return
    }

    $script:lastLatencyAt = $now
    try {
        $hostName = Get-RelayHost $relay
        if ([string]::IsNullOrWhiteSpace($hostName)) { throw 'empty relay host' }
        $ping = New-Object System.Net.NetworkInformation.Ping
        try {
            $reply = $ping.Send($hostName, 650)
            if ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
                $script:lastLatency = [Int64]$reply.RoundtripTime
                $latencyValue.Text = "$($script:lastLatency) ms"
            } else {
                $script:lastLatency = $null
                $latencyValue.Text = [string][char]0x2014
            }
        } finally {
            $ping.Dispose()
        }
    } catch {
        $script:lastLatency = $null
        $latencyValue.Text = [string][char]0x2014
    }
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

function Set-ConnectionVisuals([string]$state) {
    switch ($state) {
        'Connected' {
            $statusValue.Text = 'Connected'
            $statusSubtitle.Text = 'Secure connection to your network'
            $script:ringColor = $green
            $relayDot.ForeColor = $green
            $tray.Text = 'BPC Connect - Connected'
        }
        'Connecting' {
            $statusValue.Text = 'Connecting...'
            $statusSubtitle.Text = 'Establishing secure connection'
            $script:ringColor = $orange
            $relayDot.ForeColor = $orange
            $tray.Text = 'BPC Connect - Connecting'
        }
        'Unavailable' {
            $statusValue.Text = 'Unavailable'
            $statusSubtitle.Text = 'Agent status is not available'
            $script:ringColor = $gray
            $relayDot.ForeColor = $gray
            $tray.Text = 'BPC Connect - Unavailable'
        }
        default {
            $statusValue.Text = 'Disconnected'
            $statusSubtitle.Text = 'Your secure network is offline'
            $script:ringColor = $gray
            $relayDot.ForeColor = $gray
            $tray.Text = 'BPC Connect - Disconnected'
        }
    }
    $statusRing.Invalidate()
}

function Refresh-Bpc {
    $s = Get-BpcStatus
    if ($null -eq $s) {
        Set-ConnectionVisuals 'Unavailable'
        $deviceValue.Text = '-'
        $ipValue.Text = '-'
        $relayCaption.Text = 'Relay'
        $relayValue.Text = '-'
        $handshakeValue.Text = '-'
        $trafficValue.Text = 'RX 0 B   TX 0 B'
        $routesValue.Text = ''
        $latencyValue.Text = [string][char]0x2014
        $connect.Enabled = $true
        $connect.Visible = $true
        $disconnect.Enabled = $false
        $disconnect.Visible = $false
        $connectItem.Enabled = $true
        $disconnectItem.Enabled = $false
        return
    }

    if ($s.version -and $s.version -ne $uiVersion) {
        Restart-BpcUI
        return
    }

    $script:lastStatus = $s
    $versionValue.Text = "v$($s.version)"
    $deviceValue.Text = $s.device
    $ipValue.Text = $s.tunnel_address
    $routesValue.Text = ($s.routes -join [Environment]::NewLine)

    if ($null -ne $s.transport) {
        $relayValue.Text = $s.transport.endpoint
        $relayCaption.Text = "Relay   $($s.transport.reachable)/$($s.transport.total) ports"
        if ([Int64]$s.transport.rtt_ms -gt 0) {
            $latencyValue.Text = "$($s.transport.rtt_ms) ms"
        } else {
            $latencyValue.Text = [string][char]0x2014
        }
    } else {
        $relayCaption.Text = 'Relay'
        $relayValue.Text = $s.relay
    }

    if ($null -ne $s.runtime) {
        if ($s.handshake_age -ge 0) {
            $handshakeValue.Text = Format-Age ([Int64]$s.handshake_age)
        } else {
            $handshakeValue.Text = 'No handshake'
        }
        $trafficValue.Text = "RX $(Format-Bytes ([UInt64]$s.runtime.rx_bytes))   TX $(Format-Bytes ([UInt64]$s.runtime.tx_bytes))"
    } else {
        $handshakeValue.Text = 'No telemetry'
        $trafficValue.Text = 'RX 0 B   TX 0 B'
    }

    Set-ConnectionVisuals $s.connection

    $isRunning = $s.service -eq 'running'
    $connect.Enabled = -not $isRunning
    $connect.Visible = -not $isRunning
    $disconnect.Enabled = $isRunning
    $disconnect.Visible = $isRunning
    $connectItem.Enabled = -not $isRunning
    $disconnectItem.Enabled = $isRunning

    if ($null -eq $s.transport) {
        Update-Latency $s.relay ($s.connection -eq 'Connected')
    } elseif ($s.connection -ne 'Connected') {
        $latencyValue.Text = [string][char]0x2014
    }
}

$doConnect = {
    $connect.Enabled = $false
    & $exe connect | Out-Null
    Start-Sleep -Milliseconds 400
    Refresh-Bpc
}

$doDisconnect = {
    $disconnect.Enabled = $false
    & $exe disconnect | Out-Null
    Start-Sleep -Milliseconds 400
    Refresh-Bpc
}

$connect.Add_Click($doConnect)
$disconnect.Add_Click($doDisconnect)
$connectItem.Add_Click($doConnect)
$disconnectItem.Add_Click($doDisconnect)

$settings.Add_Click({
    $details = New-Object System.Windows.Forms.Form
    $details.Text = 'Connect details'
    $details.ClientSize = New-Object System.Drawing.Size(440, 372)
    $details.StartPosition = 'CenterParent'
    $details.FormBorderStyle = 'FixedDialog'
    $details.MaximizeBox = $false
    $details.MinimizeBox = $false
    $details.BackColor = $bg
    $details.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $details.ShowInTaskbar = $false

    $heading = New-Label 'Connection details' 22 18 390 34 16 ([System.Drawing.FontStyle]::Bold) $text
    $details.Controls.Add($heading)

    $poolStatus = '-'
    if ($null -ne $script:lastStatus -and $null -ne $script:lastStatus.transport) {
        $poolStatus = "$($script:lastStatus.transport.reachable)/$($script:lastStatus.transport.total) reachable"
    }
    $rows = @(
        @('Device', $deviceValue.Text),
        @('Tunnel IP', $ipValue.Text),
        @('UDP endpoint', $relayValue.Text),
        @('Port pool', $poolStatus),
        @('Last handshake', $handshakeValue.Text),
        @('Version', $versionValue.Text)
    )

    $y = 66
    foreach ($row in $rows) {
        $caption = New-Label $row[0] 22 $y 130 24 9 ([System.Drawing.FontStyle]::Regular) $muted
        $value = New-Label $row[1] 156 $y 255 24 9 ([System.Drawing.FontStyle]::Bold) $text
        $details.Controls.Add($caption)
        $details.Controls.Add($value)
        $y += 31
    }

    $routesCaption = New-Label 'Routes' 22 255 130 24 9 ([System.Drawing.FontStyle]::Regular) $muted
    $details.Controls.Add($routesCaption)

    $routeBox = New-Object System.Windows.Forms.TextBox
    $routeBox.ReadOnly = $true
    $routeBox.Multiline = $true
    $routeBox.ScrollBars = 'Vertical'
    $routeBox.BorderStyle = 'FixedSingle'
    $routeBox.Location = New-Object System.Drawing.Point(156, 253)
    $routeBox.Size = New-Object System.Drawing.Size(255, 50)
    $routeBox.BackColor = $card
    $routeBox.Text = $routesValue.Text
    $details.Controls.Add($routeBox)

    $close = New-Object System.Windows.Forms.Button
    $close.Text = 'Close'
    $close.Location = New-Object System.Drawing.Point(316, 326)
    $close.Size = New-Object System.Drawing.Size(95, 30)
    $close.FlatStyle = 'Flat'
    $close.FlatAppearance.BorderColor = $line
    $close.BackColor = $card
    $close.Add_Click({ $details.Close() })
    $details.Controls.Add($close)

    [void]$details.ShowDialog($form)
    $details.Dispose()
})

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
