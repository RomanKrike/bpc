//go:build windows

package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

type loginDialogResult struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

const loginDialogPowerShell = `Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

[System.Windows.Forms.Application]::EnableVisualStyles()

$form = New-Object System.Windows.Forms.Form
$form.Text = 'BP Connect'
$form.ClientSize = New-Object System.Drawing.Size(420, 285)
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false
$form.MinimizeBox = $false
$form.ShowInTaskbar = $true
$form.TopMost = $true
$form.BackColor = [System.Drawing.Color]::FromArgb(247, 249, 251)
$form.Font = New-Object System.Drawing.Font('Segoe UI', 9)

$title = New-Object System.Windows.Forms.Label
$title.Text = 'Sign in to BP Connect'
$title.Location = New-Object System.Drawing.Point(28, 22)
$title.Size = New-Object System.Drawing.Size(360, 34)
$title.Font = New-Object System.Drawing.Font('Segoe UI', 18, [System.Drawing.FontStyle]::Bold)
$title.ForeColor = [System.Drawing.Color]::FromArgb(15, 23, 42)
$form.Controls.Add($title)

$subtitle = New-Object System.Windows.Forms.Label
$subtitle.Text = 'Use your BPC account to register this device.'
$subtitle.Location = New-Object System.Drawing.Point(30, 60)
$subtitle.Size = New-Object System.Drawing.Size(350, 24)
$subtitle.ForeColor = [System.Drawing.Color]::FromArgb(100, 116, 139)
$form.Controls.Add($subtitle)

$userLabel = New-Object System.Windows.Forms.Label
$userLabel.Text = 'Username'
$userLabel.Location = New-Object System.Drawing.Point(30, 98)
$userLabel.Size = New-Object System.Drawing.Size(360, 20)
$form.Controls.Add($userLabel)

$username = New-Object System.Windows.Forms.TextBox
$username.Location = New-Object System.Drawing.Point(30, 119)
$username.Size = New-Object System.Drawing.Size(360, 28)
$username.Font = New-Object System.Drawing.Font('Segoe UI', 10)
$form.Controls.Add($username)

$passwordLabel = New-Object System.Windows.Forms.Label
$passwordLabel.Text = 'Password'
$passwordLabel.Location = New-Object System.Drawing.Point(30, 158)
$passwordLabel.Size = New-Object System.Drawing.Size(360, 20)
$form.Controls.Add($passwordLabel)

$password = New-Object System.Windows.Forms.TextBox
$password.Location = New-Object System.Drawing.Point(30, 179)
$password.Size = New-Object System.Drawing.Size(360, 28)
$password.Font = New-Object System.Drawing.Font('Segoe UI', 10)
$password.UseSystemPasswordChar = $true
$form.Controls.Add($password)

$cancel = New-Object System.Windows.Forms.Button
$cancel.Text = 'Cancel'
$cancel.Location = New-Object System.Drawing.Point(214, 226)
$cancel.Size = New-Object System.Drawing.Size(84, 34)
$cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$form.Controls.Add($cancel)

$signIn = New-Object System.Windows.Forms.Button
$signIn.Text = 'Sign in'
$signIn.Location = New-Object System.Drawing.Point(306, 226)
$signIn.Size = New-Object System.Drawing.Size(84, 34)
$signIn.BackColor = [System.Drawing.Color]::FromArgb(22, 163, 74)
$signIn.ForeColor = [System.Drawing.Color]::White
$signIn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$signIn.FlatAppearance.BorderSize = 0
$signIn.Add_Click({
    if ([string]::IsNullOrWhiteSpace($username.Text)) {
        [System.Windows.Forms.MessageBox]::Show(
            'Enter your BPC username.',
            'BP Connect',
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null
        $username.Focus()
        return
    }
    if ([string]::IsNullOrEmpty($password.Text)) {
        [System.Windows.Forms.MessageBox]::Show(
            'Enter your BPC password.',
            'BP Connect',
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null
        $password.Focus()
        return
    }
    $form.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.Close()
})
$form.Controls.Add($signIn)

$form.AcceptButton = $signIn
$form.CancelButton = $cancel
$form.Add_Shown({ $username.Focus() })

$result = $form.ShowDialog()
if ($result -ne [System.Windows.Forms.DialogResult]::OK) {
    Write-Output '__BPC_LOGIN_CANCELLED__'
    exit 2
}

$value = @{
    username = $username.Text
    password = $password.Text
} | ConvertTo-Json -Compress
$raw = [System.Text.Encoding]::UTF8.GetBytes($value)
Write-Output ([Convert]::ToBase64String($raw))
`

func readLoginCredentialsPlatform() (string, string, error) {
	cmd := exec.Command(
		"powershell.exe",
		"-NoProfile",
		"-STA",
		"-ExecutionPolicy",
		"Bypass",
		"-Command",
		loginDialogPowerShell,
	)
	output, err := cmd.CombinedOutput()
	value := strings.TrimSpace(string(output))
	if strings.Contains(value, "__BPC_LOGIN_CANCELLED__") {
		return "", "", errors.New("BPC sign-in was cancelled")
	}
	if err != nil {
		if value != "" {
			return "", "", fmt.Errorf("open BPC sign-in window: %s", value)
		}
		return "", "", fmt.Errorf("open BPC sign-in window: %w", err)
	}

	lines := strings.Fields(value)
	if len(lines) == 0 {
		return "", "", errors.New("BPC sign-in window returned no credentials")
	}
	encoded := lines[len(lines)-1]
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", "", fmt.Errorf("decode BPC sign-in response: %w", err)
	}

	var result loginDialogResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return "", "", fmt.Errorf("parse BPC sign-in response: %w", err)
	}
	return result.Username, result.Password, nil
}
