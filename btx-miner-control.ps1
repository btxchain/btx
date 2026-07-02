# BTX Mining Control Panel
# One-click STOP (kills miner + frees WSL/GPU memory for gaming) or START mining.
# Runs as the current user, no admin needed. Launched hidden via btx-miner-control.vbs.
# CLI self-test: powershell -File btx-miner-control.ps1 status

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$ErrorActionPreference = 'SilentlyContinue'

$StartupVBS = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup\BTX-Pool.vbs'
$StartupDis = "$StartupVBS.disabled"
$Supervisor = 'D:\BTX\btx-pool-supervisor.ps1'

function Test-WslRunning {
    # Does NOT boot WSL (management command only) - safe to poll while stopped.
    $out = (& wsl.exe --list --running 2>$null | Out-String) -replace "`0", ""
    if ([string]::IsNullOrWhiteSpace($out)) { return $false }
    return ($out -notmatch 'no running distribution')
}

function Get-Status {
    $s = [ordered]@{ On = $false; Wsl = $false; Gpu = 'GPU  --'; Ram = 'WSL RAM  --' }
    $s.Wsl = Test-WslRunning
    if ($s.Wsl) {
        # only probe inside WSL when it's already up, so we never boot it just to check
        $r = (& wsl.exe -e bash -lc 'pgrep -x btx-gbt-solve >/dev/null 2>&1 && echo UP || echo DOWN' 2>$null | Out-String) -replace "`0", ""
        $s.On = ($r -match 'UP')
    }
    $g = (& nvidia-smi --query-gpu=utilization.gpu,power.draw --format=csv,noheader,nounits 2>$null | Out-String).Trim()
    if ($g) { $p = $g.Split(','); $s.Gpu = ('GPU  {0}%   {1} W' -f $p[0].Trim(), [int][double]$p[1].Trim()) }
    $vm = Get-Process -Name vmmemWSL, vmmem -ErrorAction SilentlyContinue | Sort-Object WorkingSet64 -Descending | Select-Object -First 1
    if ($vm) { $s.Ram = ('WSL RAM  {0:N1} GB' -f ($vm.WorkingSet64 / 1GB)) } else { $s.Ram = 'WSL RAM  0  (freed)' }
    return $s
}

function Invoke-StartMining {
    if (Test-Path $StartupDis) { Rename-Item -LiteralPath $StartupDis -NewName 'BTX-Pool.vbs' -Force }
    & wsl.exe -e bash -lc 'rm -f /tmp/btx-pool-guard.stop 2>/dev/null; rmdir /tmp/btx-pool-guard.lock 2>/dev/null; true' | Out-Null
    Start-Process cmd.exe -ArgumentList '/c', 'wsl -e bash -lc "exec env DEXBTX_NO_SOLVER_AUTOUPDATE=0 bash /mnt/d/BTX/btx-pool-guard.sh run"' -WindowStyle Hidden
    Start-Process powershell.exe -ArgumentList '-NoProfile', '-WindowStyle', 'Hidden', '-ExecutionPolicy', 'Bypass', '-File', $Supervisor -WindowStyle Hidden
}

function Invoke-StopMining {
    # 1) kill the Windows-side supervisor + its cmd->wsl anchor (so they don't relaunch)
    Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -like '*btx-pool-supervisor*' -and $_.ProcessId -ne $PID } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Get-CimInstance Win32_Process -Filter "Name='cmd.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -like '*btx-pool-guard*' } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    # 2) disable logon auto-start so a reboot mid-gaming won't relaunch mining
    if (Test-Path $StartupVBS) { Rename-Item -LiteralPath $StartupVBS -NewName 'BTX-Pool.vbs.disabled' -Force }
    # 3) shut down WSL entirely -> kills miner+solver+guard and returns ALL WSL RAM to Windows (safe: pool mode, no btxd node)
    & wsl.exe --shutdown
}

# ---- CLI mode (no GUI): status | start | stop  (same functions the buttons call) ----
if ($args.Count -ge 1 -and $args[0] -in @('status', 'start', 'stop')) {
    switch ($args[0]) {
        'start' { Invoke-StartMining; 'start command issued' }
        'stop'  { Invoke-StopMining;  'stop command issued' }
        default { $s = Get-Status; "On=$($s.On)  Wsl=$($s.Wsl)  |  $($s.Gpu)  |  $($s.Ram)" }
    }
    exit 0
}

# ---------- GUI ----------
$cAccent = [System.Drawing.Color]::FromArgb(76, 209, 121)
$cRed    = [System.Drawing.Color]::FromArgb(228, 86, 86)
$cYellow = [System.Drawing.Color]::FromArgb(236, 201, 92)
$cDark   = [System.Drawing.Color]::FromArgb(26, 28, 35)
$cGray   = [System.Drawing.Color]::FromArgb(168, 173, 184)

$form = New-Object System.Windows.Forms.Form
$form.Text = 'BTX Mining Control'
$form.ClientSize = New-Object System.Drawing.Size(380, 296)
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedSingle'
$form.MaximizeBox = $false
$form.BackColor = $cDark
$form.Font = New-Object System.Drawing.Font('Segoe UI', 9)

$lblStatus = New-Object System.Windows.Forms.Label
$lblStatus.SetBounds(20, 20, 340, 38)
$lblStatus.Font = New-Object System.Drawing.Font('Segoe UI', 18, [System.Drawing.FontStyle]::Bold)
$lblStatus.TextAlign = 'MiddleCenter'
$lblStatus.Text = 'Checking...'
$form.Controls.Add($lblStatus)

$lblDetail = New-Object System.Windows.Forms.Label
$lblDetail.SetBounds(20, 62, 340, 22)
$lblDetail.ForeColor = $cGray
$lblDetail.TextAlign = 'MiddleCenter'
$form.Controls.Add($lblDetail)

$btnStart = New-Object System.Windows.Forms.Button
$btnStart.SetBounds(26, 108, 152, 66)
$btnStart.Text = 'START MINING'
$btnStart.FlatStyle = 'Flat'
$btnStart.FlatAppearance.BorderSize = 0
$btnStart.BackColor = $cAccent
$btnStart.ForeColor = [System.Drawing.Color]::Black
$btnStart.Font = New-Object System.Drawing.Font('Segoe UI', 11, [System.Drawing.FontStyle]::Bold)
$btnStart.Cursor = 'Hand'
$form.Controls.Add($btnStart)

$btnStop = New-Object System.Windows.Forms.Button
$btnStop.SetBounds(202, 108, 152, 66)
$btnStop.Text = 'STOP + FREE RAM'
$btnStop.FlatStyle = 'Flat'
$btnStop.FlatAppearance.BorderSize = 0
$btnStop.BackColor = $cRed
$btnStop.ForeColor = [System.Drawing.Color]::White
$btnStop.Font = New-Object System.Drawing.Font('Segoe UI', 11, [System.Drawing.FontStyle]::Bold)
$btnStop.Cursor = 'Hand'
$form.Controls.Add($btnStop)

$btnRefresh = New-Object System.Windows.Forms.Button
$btnRefresh.SetBounds(130, 186, 120, 28)
$btnRefresh.Text = 'Refresh'
$btnRefresh.FlatStyle = 'Flat'
$btnRefresh.FlatAppearance.BorderColor = $cGray
$btnRefresh.BackColor = $cDark
$btnRefresh.ForeColor = $cGray
$btnRefresh.Cursor = 'Hand'
$form.Controls.Add($btnRefresh)

$lblAction = New-Object System.Windows.Forms.Label
$lblAction.SetBounds(16, 224, 348, 58)
$lblAction.ForeColor = $cGray
$lblAction.TextAlign = 'MiddleCenter'
$form.Controls.Add($lblAction)

$applyStatus = {
    param($s)
    if ($s.On) { $lblStatus.Text = 'MINING'; $lblStatus.ForeColor = $cAccent }
    elseif ($s.Wsl) { $lblStatus.Text = 'STARTING...'; $lblStatus.ForeColor = $cYellow }
    else { $lblStatus.Text = 'STOPPED'; $lblStatus.ForeColor = $cRed }
    $lblDetail.Text = ('{0}     |     {1}' -f $s.Gpu, $s.Ram)
}
$refresh = { & $applyStatus (Get-Status) }

$btnStart.Add_Click({
    $lblStatus.Text = 'STARTING...'; $lblStatus.ForeColor = $cYellow
    $lblAction.Text = 'Enabling auto-start, booting WSL, launching miner + solver...'
    $form.Refresh()
    Invoke-StartMining
    $lblAction.Text = 'Launched. The miner warms up over ~30-60s; status updates on its own.'
    & $refresh
})

$btnStop.Add_Click({
    $lblStatus.Text = 'STOPPING...'; $lblStatus.ForeColor = $cYellow
    $lblAction.Text = 'Stopping miner, disabling auto-start, shutting down WSL to free RAM...'
    $form.Refresh()
    Invoke-StopMining
    $lblAction.Text = "Stopped. GPU and WSL RAM freed. Click START MINING when you're done gaming."
    & $refresh
})

$btnRefresh.Add_Click({ $lblAction.Text = ''; & $refresh })

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 6000
$timer.Add_Tick({ & $refresh })
$timer.Start()

& $refresh
$form.Add_Shown({ $form.Activate() })
[System.Windows.Forms.Application]::Run($form)
