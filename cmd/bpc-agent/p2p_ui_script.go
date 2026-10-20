package main

// Embedded in the prepared Agent executable delivered by the existing HTTPS
// download link. Never execute UI input as PowerShell source or a command line.
const p2pUIScript = `Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
$exe = '__BPC_AGENT_PATH__'
$window = New-Object System.Windows.Forms.Form
$window.Text = 'BP Connect - Мои компьютеры'
$window.ClientSize = New-Object System.Drawing.Size(560, 420)
$window.StartPosition = 'CenterScreen'
$window.FormBorderStyle = 'FixedDialog'
$window.MaximizeBox = $false
$window.Font = New-Object System.Drawing.Font('Segoe UI', 10)
$note = New-Object System.Windows.Forms.Label
$note.Text = 'Войдите в один аккаунт на обоих компьютерах. Принимать приглашение на втором компьютере не нужно. Пилот: до 60 секунд.'
$note.Location = New-Object System.Drawing.Point(20, 16)
$note.Size = New-Object System.Drawing.Size(520, 64)
$window.Controls.Add($note)
$peers = New-Object System.Windows.Forms.ComboBox
$peers.DropDownStyle = 'DropDownList'
$peers.DisplayMember = 'Label'
$peers.Location = New-Object System.Drawing.Point(20, 176)
$peers.Size = New-Object System.Drawing.Size(520, 30)
$window.Controls.Add($peers)
$result = New-Object System.Windows.Forms.TextBox
$result.Multiline = $true
$result.ReadOnly = $true
$result.ScrollBars = 'Vertical'
$result.Location = New-Object System.Drawing.Point(20, 282)
$result.Size = New-Object System.Drawing.Size(520, 115)
$result.Text = 'Обновите список, выберите компьютер с Sunshine и подключитесь. Затем откройте Moonlight и добавьте показанный адрес.'
$window.Controls.Add($result)

function Invoke-Agent([string[]]$AgentArgs) {
    $runner = [powershell]::Create()
    try {
        $null = $runner.AddScript('param($Agent, $Arguments) $output = @(& $Agent @Arguments 2>&1); if ($LASTEXITCODE -ne 0) { throw ($output -join [Environment]::NewLine) }; $output -join [Environment]::NewLine')
        $null = $runner.AddArgument($exe)
        $null = $runner.AddArgument($AgentArgs)
        $pending = $runner.BeginInvoke()
        while (-not $pending.IsCompleted) {
            [System.Windows.Forms.Application]::DoEvents()
            [System.Threading.Thread]::Sleep(50)
        }
        $output = $runner.EndInvoke($pending)
        if ($runner.HadErrors) { throw ($runner.Streams.Error | Out-String) }
        return ($output -join [Environment]::NewLine)
    } finally { $runner.Dispose() }
}
function Invoke-Action([scriptblock]$Action) {
    $window.Enabled = $false
    $window.UseWaitCursor = $true
    $result.Text = 'Выполняется...'
    $window.Refresh()
    try { & $Action } catch { $result.Text = 'Не удалось выполнить действие: ' + $_.Exception.Message }
    finally { $window.UseWaitCursor = $false; $window.Enabled = $true }
}
function Add-Button([string]$Title, [int]$X, [int]$Y, [int]$Width, [scriptblock]$Action) {
    $button = New-Object System.Windows.Forms.Button
    $button.Text = $Title
    $button.Location = New-Object System.Drawing.Point($X, $Y)
    $button.Size = New-Object System.Drawing.Size($Width, 38)
    $button.Add_Click($Action)
    $window.Controls.Add($button)
}
Add-Button 'Включить на этом ПК' 20 90 250 {
    if ([System.Windows.Forms.MessageBox]::Show('Разрешить подключения между вашими компьютерами и перезапустить Agent? Текущее соединение BPC кратковременно прервётся.', 'BP Connect', 'OKCancel', 'Question') -ne 'OK') { return }
    Invoke-Action {
        $null = Invoke-Agent @('p2p', 'prepare')
        $null = Invoke-Agent @('p2p', 'consent', '--enabled=true')
        $result.Text = 'Этот компьютер подготовлен. После входа в тот же аккаунт на втором ПК обновите список.'
    }
}
Add-Button 'Обновить список' 290 90 250 {
    Invoke-Action {
        $items = @(ConvertFrom-Json -InputObject (Invoke-Agent @('p2p', 'peers-json')))
        $peers.Items.Clear()
        foreach ($item in $items) {
            if ($null -eq $item) { continue }
            $entry = [PSCustomObject]@{ ID = [string]$item.id; Address = [string]$item.address; Label = ([string]$item.name + ' - ' + [string]$item.address) }
            [void]$peers.Items.Add($entry)
        }
        if ($peers.Items.Count -gt 0) { $peers.SelectedIndex = 0 }
        $result.Text = 'Доступных компьютеров: ' + $peers.Items.Count + '. Список показывает разрешённые устройства; их доступность проверяется при подключении.'
    }
}
Add-Button 'Подключиться' 20 224 250 {
    if ($null -eq $peers.SelectedItem) { $result.Text = 'Сначала выберите компьютер.'; return }
    Invoke-Action {
        $null = Invoke-Agent @('p2p', 'connect', '--host', $peers.SelectedItem.ID)
        $result.Text = 'Запрос отправлен обоим компьютерам. Откройте Moonlight: ' + $peers.SelectedItem.Address + '. Это ещё не подтверждение соединения. Пилот завершится не позднее чем через 60 секунд.'
    }
}
Add-Button 'Отключить P2P на этом ПК' 290 224 250 {
    Invoke-Action {
        $null = Invoke-Agent @('p2p', 'consent', '--enabled=false')
        $result.Text = 'P2P на этом компьютере запрещён. Для новых подключений нажмите «Включить на этом ПК».'
    }
}
[void]$window.ShowDialog()
$window.Dispose()
`
