param([Parameter(Mandatory=$true)][string]$Executable)
$ErrorActionPreference = 'Stop'
$path = (Resolve-Path -LiteralPath $Executable).Path
$bytes = [System.IO.File]::ReadAllBytes($path)
$pe = [BitConverter]::ToInt32($bytes, 0x3c)
if ([BitConverter]::ToUInt16($bytes, $pe + 24 + 68) -ne 2) {
    throw 'Expected a Windows GUI executable without a console window'
}
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class BpcResourceTest {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr LoadLibraryEx(string file, IntPtr reserved, uint flags);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr FindResource(IntPtr module, string name, IntPtr type);
    [DllImport("kernel32.dll")]
    public static extern bool FreeLibrary(IntPtr module);
}
'@
$module = [BpcResourceTest]::LoadLibraryEx($path, [IntPtr]::Zero, 2)
if ($module -eq [IntPtr]::Zero) { throw 'Cannot inspect EXE resources' }
try {
    $icon = [BpcResourceTest]::FindResource($module, 'APP', [IntPtr]14)
    if ($icon -eq [IntPtr]::Zero) { throw 'BPC application icon resource is missing' }
} finally {
    $null = [BpcResourceTest]::FreeLibrary($module)
}
Write-Output 'BPC icon resource and Windows GUI subsystem verified'
$source = Get-Content "$PSScriptRoot/../cmd/bpc-agent/ui_windows.go" -Raw
$identity = [regex]::Match($source, "(?s)Add-Type -TypeDefinition @'\r?\n(.*?)\r?\n'@")
if (-not $identity.Success) { throw 'Application identity declaration is missing' }
Add-Type -TypeDefinition $identity.Groups[1].Value
if ([BpcApplicationIdentity]::SetCurrentProcessExplicitAppUserModelID('BPC.Connect') -ne 0) {
    throw 'Windows rejected the BPC taskbar identity'
}
foreach ($name in @('windows-update-existing.ps1', 'test-windows-ui.ps1')) {
    $parseErrors = $null
    $tokens = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $PSScriptRoot $name), [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
}
Write-Output 'Taskbar identity accepted; update script syntax verified'
