<#
  Creates two Desktop shortcuts:
    "BTX Miner"        -> btx-miner-gui.ps1 (self-elevates, control panel)
    "Stop BTX Mining"  -> btx-kill.ps1 (instant kill: stop miner + shut down WSL)
  Run this once.
#>
$ErrorActionPreference = 'Stop'

$gui     = 'D:\BTX\btx-miner-gui.ps1'
$kill    = 'D:\BTX\btx-kill.ps1'
$icon    = 'D:\BTX\btx-miner.ico'
$desktop = [Environment]::GetFolderPath('Desktop')
$ps      = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
$ws      = New-Object -ComObject WScript.Shell

function New-Lnk {
    param($Path, $Target, $ArgLine, $Desc, $AdminBit, $WinStyle = 7)
    $sc = $ws.CreateShortcut($Path)
    $sc.TargetPath = $ps
    $sc.Arguments  = $ArgLine
    $sc.WorkingDirectory = 'D:\BTX'
    $sc.WindowStyle = $WinStyle
    $sc.Description = $Desc
    if (Test-Path $icon) { $sc.IconLocation = $icon } else { $sc.IconLocation = "$ps,0" }
    $sc.Save()
    if ($AdminBit) {
        $b = [System.IO.File]::ReadAllBytes($Path)
        $b[0x15] = $b[0x15] -bor 0x20   # "Run as administrator" flag
        [System.IO.File]::WriteAllBytes($Path, $b)
    }
}

if (-not (Test-Path $gui))  { throw "Not found: $gui" }
if (-not (Test-Path $kill)) { throw "Not found: $kill" }

New-Lnk (Join-Path $desktop 'BTX Miner.lnk') $ps `
    "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$gui`"" `
    'BTX Miner Control (admin -> WSL): start/stop, fine-tune, block chance' $true 7

New-Lnk (Join-Path $desktop 'Stop BTX Mining.lnk') $ps `
    "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$kill`"" `
    'Instantly stop BTX mining and free the GPU + RAM (shuts down WSL)' $false 7

Write-Host "Created two Desktop shortcuts:"
Write-Host "  * 'BTX Miner'       - open the control panel"
Write-Host "  * 'Stop BTX Mining' - one-click kill (frees the GPU)"
