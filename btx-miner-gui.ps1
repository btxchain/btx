<#
  BTX Miner GUI  —  admin PowerShell -> WSL controller for dexbtx-miner / minebtx + solo.

  Flow: desktop shortcut -> this script self-elevates to Administrator -> boots WSL (Ubuntu)
        -> WinForms GUI drives the existing D:\BTX WSL scripts.

  Features:
    * START / STOP mining (pool = minebtx PPLNS, or solo to your own btxd)
    * Pool / Solo mode toggle
    * Fine-Tune panel (edits ~/.dexbtx-miner/config.yaml — the solver "key levers")
    * Block-Chance calculator (Poisson model: chance to find a block + expected BTX/day)
    * Live GPU / hashrate / mode status

  No Python-on-Windows dependency; everything runs through `wsl -d Ubuntu`.
  CLI self-test:  powershell -ExecutionPolicy Bypass -File btx-miner-gui.ps1 status
#>

# ----------------------------------------------------------------------------
# 0. Self-elevate to Administrator (skip for the `status` CLI self-test)
# ----------------------------------------------------------------------------
$cliMode = ($args.Count -ge 1 -and $args[0] -in @('status','start','stop'))
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and -not $cliMode) {
    $psi = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"") + $args
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $psi
    exit
}

# ----------------------------------------------------------------------------
# 1. Config / constants  (mirror btx-control.pyw)
# ----------------------------------------------------------------------------
$WSL_DIST   = 'Ubuntu'
$CFG_PATH   = '/home/eldian/.dexbtx-miner/config.yaml'
$MODE_SWITCH= '/mnt/d/BTX/btx-mining-mode.sh'
$MODE_CONF  = '/mnt/d/BTX/btx-mining-mode.conf'
$HASH_POOL  = '/mnt/d/BTX/btx-hashrate.sh'
$HASH_SOLO  = '/mnt/d/BTX/btx-solo-hashrate.sh'
$CLI        = '/home/eldian/btx-node/bin/btx-cli'
$DATADIR    = '/home/eldian/.btx'
$SOLO_STATS = '/mnt/d/BTX/btx-solo-stats.sh'
$RESTORE    = '/mnt/d/BTX/btx-restore-snapshot.sh'
$AUTOTUNE   = '/mnt/d/BTX/btx-autotune.sh'
$AUTOTUNE_LOG = '/mnt/d/BTX/btx-autotune.log'
$AUTOTUNE_STOP= '/tmp/btx-autotune.stop'
$PAYOUT     = 'btx1zkht84nwz8mxk2ln20krjr4lcn5e65gsmssk8m48qtlsl5m97awds6d9m35'
$EXPLORER   = 'https://explorer.minebtx.com/api/address/'
$BLOCK_TIME = 90.0      # BTX target spacing (seconds) -> 960 blocks/day
$NET_HS_DEFAULT = 156000000.0   # 156 MN/s fallback when node RPC is down (pool mode)

$ErrorActionPreference = 'SilentlyContinue'

# ----------------------------------------------------------------------------
# 2. WSL helpers
# ----------------------------------------------------------------------------
function Invoke-Wsl {
    param([string]$Cmd, [int]$TimeoutSec = 30)
    # Direct call (no per-call job) — far faster on the UI thread. Callers that
    # could boot a stopped WSL guard with Test-WslRunning first (Get-Status does).
    try { $o = (& wsl.exe -d $WSL_DIST -e bash -lc $Cmd 2>$null | Out-String) } catch { $o = '' }
    return ($o -replace "`0","")
}

function Parse-KV {
    param([string]$Text, [string]$Sep = '=')
    $h = @{}
    foreach ($line in ($Text -split "`n")) {
        if ($line -match "^\s*([A-Za-z0-9_]+)\s*$([regex]::Escape($Sep))\s*(.*?)\s*$") {
            $h[$matches[1]] = $matches[2]
        }
    }
    return $h
}

function Test-WslRunning {
    $out = (& wsl.exe --list --running 2>$null | Out-String) -replace "`0",""
    if ([string]::IsNullOrWhiteSpace($out)) { return $false }
    return ($out -match [regex]::Escape($WSL_DIST))
}

function Get-Mode {
    $c = Invoke-Wsl "cat $MODE_CONF 2>/dev/null" 5
    if ($c -match 'BTX_MINING_MODE\s*=\s*solo') { return 'solo' }
    return 'pool'
}

# ---- actions (reuse the existing mode-switch script) ----
# Boot WSL (Ubuntu) from a cold/stopped state and wait until it responds.
function Ensure-Wsl {
    & wsl.exe -d $WSL_DIST -e true 2>$null | Out-Null
    for ($i=0; $i -lt 12; $i++) {
        if ((& wsl.exe -d $WSL_DIST -e bash -lc 'echo ok' 2>$null | Out-String) -match 'ok') { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}
function Start-Mining { param($Mode) Invoke-Wsl "chmod +x $MODE_SWITCH; bash $MODE_SWITCH $Mode 2>&1" 120 }
function Stop-Mining  { Invoke-Wsl "chmod +x $MODE_SWITCH; bash $MODE_SWITCH stop 2>&1" 90 }
# Full kill: stop miner/guards, then shut down WSL so the GPU + RAM are freed.
# CRITICAL: stop btxd gracefully (btx-cli stop + wait) BEFORE wsl --shutdown. Hard-killing
# btxd mid-write is what corrupted the datadir and forced multi-hour resyncs. A clean stop
# means the chain state survives and the next start needs only seconds of catch-up.
function Kill-Mining {
    # Bash built from single-quoted pieces: PowerShell must never see bash's $( ) as its own.
    $bash = 'chmod +x ' + $MODE_SWITCH + ' /mnt/d/BTX/btx-smart-mine.sh 2>/dev/null; ' +
        'bash /mnt/d/BTX/btx-smart-mine.sh stop >/dev/null 2>&1; ' +
        'bash ' + $MODE_SWITCH + ' stop >/dev/null 2>&1; ' +
        'touch /tmp/btx-pool-guard.stop /tmp/btx-solo-guard.stop /tmp/btx-smart-mine.stop 2>/dev/null; ' +
        $CLI + ' -datadir=' + $DATADIR + ' -rpcclienttimeout=10 stop >/dev/null 2>&1; ' +
        'for i in $(seq 1 30); do pgrep -f "[b]txd" >/dev/null 2>&1 || break; sleep 1; done; true'
    Invoke-Wsl $bash 60 | Out-Null
    & wsl.exe --shutdown 2>$null | Out-Null
}
# Detect the "shielded state can't rebuild" corruption signature in the node log.
function Test-NodeCorrupt {
    $r = Invoke-Wsl "tail -200 /home/eldian/.btx/debug.log 2>/dev/null | grep -cE 'Failed to initialize shielded state database|RebuildShieldedState: replaying.*genesis|Refusing the destructive rebuild'" 8
    return ([int]("0"+($r.Trim())) -gt 0)
}
# Kill any leftover node/guard/sync processes so exactly ONE instance runs (kills the guard's
# duplicate-fast-sync pileup at the source). Called at the start of every solo START.
function Clean-NodeProcs {
    # [b]racketed patterns so pkill can never match (and kill) its own invoking shell.
    Invoke-Wsl ("pkill -9 -f '[b]tx-solo-guard|[b]tx-pool-guard|[b]tx-sync-fast|[b]tx-restore-snapshot|[f]aststart|[b]txd|[b]tx-smart-mine|[b]tx-mine.sh|[d]exbtx-miner' 2>/dev/null; " +
        "rmdir /tmp/btx-sync-fast.lock /tmp/btx-smart-mine.lock /tmp/btx-solo-guard.lock /tmp/btx-pool-guard.lock 2>/dev/null; " +
        "rm -f /tmp/btx-solo-guard.stop /tmp/btx-pool-guard.stop /tmp/btx-smart-mine.stop /tmp/btx-sync-fast.pid 2>/dev/null; sleep 2; true") 25 | Out-Null
}
# The single source of truth for starting a mode: guarantees ONE instance, auto-syncs, auto-mines.
# Solo uses btx-smart-mine.sh: pool-mines on the GPU while the node syncs (zero idle GPU),
# then hands the GPU to solo automatically at the tip. If the node is already synced it goes
# straight to solo, so a healthy datadir means instant solo starts.
function Invoke-StartMode {
    param($Mode)
    if ($Mode -eq 'solo') {
        Clean-NodeProcs             # one instance only
        # Synchronous launch — NOT Start-Process (which proved unreliable/silent here).
        # The launcher exits in seconds; its nohup'd children (sync, guard, miners)
        # live on inside the WSL VM. Output goes to a log so failures are visible.
        $out = Invoke-Wsl 'chmod +x /mnt/d/BTX/btx-smart-mine.sh /mnt/d/BTX/btx-mining-mode.sh; bash /mnt/d/BTX/btx-smart-mine.sh run 2>&1' 60
        Add-Content -Path 'D:\BTX\btx-gui-actions.log' -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] START solo -> $($out.Trim())" -ErrorAction SilentlyContinue
    } else {
        Start-Mining 'pool' | Out-Null
    }
}

# ---- balance (public minebtx explorer; works in pool mode with no local node) ----
function Get-Balance {
    try {
        $r = Invoke-RestMethod -Uri ($EXPLORER + $PAYOUT) -TimeoutSec 6 -Headers @{Accept='application/json'}
        $c = $r.chain_stats; $m = $r.mempool_stats
        $conf = [int64]$c.funded_txo_sum - [int64]$c.spent_txo_sum
        $mem  = [int64]$m.funded_txo_sum - [int64]$m.spent_txo_sum
        $txt = ('{0:N6} BTX' -f (($conf + $mem)/1e8))
        if ($mem -ne 0) { $txt += (' ({0:+0.######} pending)' -f ($mem/1e8)) }
        return $txt
    } catch { return 'unavailable (explorer offline)' }
}

# ---- blocks you personally mined (coinbase to payout addr; needs a local node) ----
function Get-BlocksFound {
    $kv = Parse-KV (Invoke-Wsl "chmod +x $SOLO_STATS; bash $SOLO_STATS 2>&1" 30)
    if ($kv.ContainsKey('solo_blocks_24h')) {
        $t = ('{0} (24h) / {1} (7d)' -f $kv.solo_blocks_24h, $kv.solo_blocks_7d)
        if ($kv.solo_last_win -and $kv.solo_last_win -ne 'none in window') { $t += "   last: $($kv.solo_last_win)" }
        return $t
    }
    return 'solo metric — pool pays via Balance (needs btxd for counts)'
}

# ---- node/pipeline state: names the exact phase on the road to mining, with a
# liveness heartbeat so a stall is visible. One combined WSL call per poll. ----
$script:hbMetric = -1; $script:hbTick = [Environment]::TickCount64
function Get-SyncStatus {
    $r = @{ Text='node off (pool mode — not needed)'; Pct=-1; Phase='—'; Metric=-1 }
    # [b]racket trick: the pattern must not match this probe shell's own command line.
    $probe = 'echo P_NODE=$(pgrep -f "[b]txd" >/dev/null 2>&1 && echo 1 || echo 0); ' +
        'echo P_SYNCF=$(pgrep -f "[b]tx-sync-fast.sh" >/dev/null 2>&1 && echo 1 || echo 0); ' +
        'echo P_FASTS=$(pgrep -f "[f]aststart.py" >/dev/null 2>&1 && echo 1 || echo 0); ' +
        'echo P_SGUARD=$(pgrep -f "[b]tx-solo-guard.sh" >/dev/null 2>&1 && echo 1 || echo 0); ' +
        'echo P_PGUARD=$(pgrep -f "[b]tx-pool-guard.sh" >/dev/null 2>&1 && echo 1 || echo 0); ' +
        'echo P_PMINER=$(pgrep -f "[d]exbtx-miner" >/dev/null 2>&1 && echo 1 || echo 0); ' +
        'echo P_SMINER=$(pgrep -f "[b]tx-mine.sh" >/dev/null 2>&1 && echo 1 || echo 0); ' +
        'echo LOCK=$([ -d /tmp/btx-sync-fast.lock ] && echo 1 || echo 0); ' +
        'echo SNAPSZ=$(stat -c %s /home/eldian/.btx/faststart/snapshot.dat 2>/dev/null || echo 0); ' +
        'DL=/mnt/d/BTX/btx-faststart-debug.log; [ /home/eldian/.btx/debug.log -nt $DL ] 2>/dev/null && DL=/home/eldian/.btx/debug.log; ' +
        'echo TIPH=$(grep -oE "height=[0-9]+" $DL 2>/dev/null | tail -1 | cut -d= -f2); ' +
        'echo TAGE=$(( $(date +%s) - $(stat -c %Y $DL 2>/dev/null || date +%s) )); ' +
        "$CLI -datadir=$DATADIR -rpcclienttimeout=5 getblockchaininfo 2>/dev/null; " +
        'echo ===LOG===; tail -n 25 /mnt/d/BTX/btx-sync-fast.log 2>/dev/null'
    $out = Invoke-Wsl $probe 15
    $parts = $out -split '===LOG==='
    $head  = $parts[0]
    $slog  = if ($parts.Count -gt 1) { $parts[1] } else { '' }
    $f = Parse-KV $head
    $tiph = [int64]("0"+($f.TIPH -replace '\D',''))
    $tage = [int64]("0"+($f.TAGE -replace '\D',''))

    # 1) RPC answers — authoritative.
    $ji = $head.IndexOf('{')
    if ($ji -ge 0) {
        try {
            $j = ($head.Substring($ji) | ConvertFrom-Json)
            $blocks=[int64]$j.blocks; $headers=[int64]$j.headers; $ibd=[bool]$j.initialblockdownload
            if (-not $ibd) {
                $r.Text=('Synced — tip {0:N0}' -f $blocks); $r.Pct=100.0; $r.Metric=$blocks
                $r.Phase = if ($f.P_SMINER -eq '1') {'⛏ MINING solo — node at tip, submitting blocks'}
                           elseif ($f.P_PMINER -eq '1') {'⛏ MINING pool — GPU on minebtx'}
                           else {'Synced — guard is starting the miner...'}
            } elseif ($blocks -eq 0 -and $headers -eq 0) {
                $r.Text='No chain yet'; $r.Pct=0.0; $r.Metric=0
                $r.Phase='Node up, empty chain — waiting for sync/snapshot'
            } else {
                $pct = if ($headers -gt 0) {[math]::Min(100.0,$blocks/$headers*100.0)} else {0.0}
                $r.Text=('Validating {0:N0}/{1:N0}' -f $blocks,$headers); $r.Pct=$pct; $r.Metric=$blocks
                $r.Phase=('Validating blocks — {0:N0} of {1:N0} (CPU, step 3/3)' -f $blocks,$headers)
                if ($f.P_PMINER -eq '1') { $r.Phase += ' · GPU pool-mining meanwhile' }
            }
            $r.Phase = Add-Heartbeat $r.Phase $r.Metric $tage
            return $r
        } catch {}
    }

    # 2) No RPC — read the sync pipeline's own signals.
    if ($f.LOCK -eq '1' -or $f.P_SYNCF -eq '1' -or $f.P_FASTS -eq '1') {
        $mm = [regex]::Matches($slog,'headers=(\d+)/(\d+)')
        $lastline = (($slog -split "`n") | Where-Object { $_ -match '\S' } | Select-Object -Last 1)
        if ($lastline -match 'downloading snapshot' -and [int64]$f.SNAPSZ -lt 440000000) {
            $mb=[math]::Round([int64]$f.SNAPSZ/1MB)
            $r.Text=('Downloading snapshot ({0} MB / 426 MB)' -f $mb); $r.Pct=[int64]$f.SNAPSZ/447000000.0*100.0; $r.Metric=[int64]$f.SNAPSZ
            $r.Phase=('Downloading snapshot - {0} MB of ~426 MB (step 1/3)' -f $mb)
        } elseif ($mm.Count -gt 0) {
            $g=$mm[$mm.Count-1].Groups; $h=[int64]$g[1].Value; $tg=[int64]$g[2].Value
            if ($h -ge $tg -and $tg -gt 0) {
                $r.Text='Loading snapshot into node...'; $r.Pct=-1; $r.Metric=$tiph
                $r.Phase='Loading snapshot into chainstate (step 2/3 — RPC silent here, normal)'
            } else {
                $r.Text=('Header sync {0:N0}/{1:N0}' -f $h,$tg); $r.Pct=($(if($tg -gt 0){$h/$tg*100.0}else{0})); $r.Metric=$h
                $r.Phase=('Header sync — {0:N0} of {1:N0} (step 1/3)' -f $h,$tg)
            }
        } else {
            $r.Text='Sync starting...'; $r.Pct=0.0; $r.Phase='Sync pipeline starting (resolving release/manifest)'
        }
        if ($f.P_PMINER -eq '1') { $r.Phase += ' · GPU pool-mining meanwhile' }
        $r.Phase = Add-Heartbeat $r.Phase $r.Metric $tage
        return $r
    }
    if ($f.P_NODE -eq '1') {
        if ($tiph -gt 0) {
            $r.Text='Node busy (RPC not answering)'; $r.Pct=-1; $r.Metric=$tiph
            $r.Phase=('Node busy - last validated height {0:N0}, log written {1}s ago' -f $tiph,$tage)
        } else {
            $r.Text='Node starting...'; $r.Pct=-1; $r.Metric=-1
            $r.Phase='Node starting — loading block index / shielded state'
        }
        $r.Phase = Add-Heartbeat $r.Phase $r.Metric $tage
        return $r
    }
    if ($f.P_PMINER -eq '1') { $r.Text='—'; $r.Phase='⛏ MINING pool — GPU on minebtx (no local node)'; return $r }
    if ($f.P_SGUARD -eq '1' -or $f.P_PGUARD -eq '1') { $r.Text='Guard waiting'; $r.Phase='Guard alive — waiting to start node/miner'; return $r }
    $r.Text='Nothing running'; $r.Phase='Stopped — no node, no sync, no miner'
    return $r
}
# Heartbeat: if the progress metric hasn't moved and the node log is stale, say so loudly.
function Add-Heartbeat {
    param([string]$Phase, [int64]$Metric, [int64]$LogAge)
    $now = [Environment]::TickCount64
    if ($Metric -ge 0 -and $Metric -ne $script:hbMetric) { $script:hbMetric=$Metric; $script:hbTick=$now; return "$Phase  ✓alive" }
    $stuckSec = [int](($now - $script:hbTick)/1000)
    if ($LogAge -lt 45) { return "$Phase  ✓alive" }   # log still being written = working
    if ($stuckSec -gt 150) { return "$Phase  ⚠ NO PROGRESS for $([int]($stuckSec/60))m" }
    return $Phase
}

# ----------------------------------------------------------------------------
# 3. Live status (GPU / hashrate / mode)
# ----------------------------------------------------------------------------
function Get-Status {
    $s = [ordered]@{ Wsl=$false; Mode='pool'; Mining=$false; Hashrate='--'; HsRaw=0.0; NetHs=0.0; EstDay=0.0; SyncText='WSL stopped'; SyncPct=-1; Phase='WSL stopped — press START'; Gpu='GPU  --' }
    # GPU probe uses the Windows nvidia-smi, so it works even while WSL is stopped.
    $g = (& nvidia-smi --query-gpu=utilization.gpu,temperature.gpu,power.draw --format=csv,noheader,nounits 2>$null | Out-String).Trim()
    if ($g) { $p = $g.Split(','); $s.Gpu = ('GPU  {0}%   {1}C   {2} W' -f $p[0].Trim(),$p[1].Trim(),[int][double]$p[2].Trim()) }
    $s.Wsl = Test-WslRunning
    if (-not $s.Wsl) { return $s }
    $s.Mode = Get-Mode

    if ($s.Mode -eq 'pool') {
        $kv = Parse-KV (Invoke-Wsl "chmod +x $HASH_POOL; bash $HASH_POOL 2>&1" 20)
        if ($kv.hashrate)    { $s.Hashrate = $kv.hashrate }
        if ($kv.hashrate_hs) { $s.HsRaw = [double]$kv.hashrate_hs }
        $r = Invoke-Wsl 'pgrep -f "[d]exbtx-miner" >/dev/null 2>&1 && echo UP || echo DOWN' 8
        $s.Mining = ($r -match 'UP')
    } else {
        $kv = Parse-KV (Invoke-Wsl "chmod +x $HASH_SOLO; bash $HASH_SOLO 2>&1" 20)
        if ($kv.solo_hashrate)    { $s.Hashrate = $kv.solo_hashrate }
        if ($kv.solo_hashrate_hs) { $s.HsRaw = [double]$kv.solo_hashrate_hs }
        if ($kv.network_hashps)   { $s.NetHs = [double]$kv.network_hashps }
        $r = Invoke-Wsl 'pgrep -f "[b]tx-mine\.sh" >/dev/null 2>&1 && echo UP || echo DOWN' 8
        $s.Mining = ($r -match 'UP')
    }
    # Estimated blocks/day = 960 * yourHs / netHs  (netHs falls back to 156 MN/s in pool mode)
    $net = if ($s.NetHs -gt 0) { $s.NetHs } else { $NET_HS_DEFAULT }
    if ($s.HsRaw -gt 0 -and $net -gt 0) { $s.EstDay = 960.0 * $s.HsRaw / $net }
    $sync = Get-SyncStatus
    $s.SyncText = $sync.Text; $s.SyncPct = $sync.Pct; $s.Phase = $sync.Phase
    return $s
}

# ----------------------------------------------------------------------------
# 4. CLI self-test mode
# ----------------------------------------------------------------------------
if ($cliMode) {
    switch ($args[0]) {
        'start' {
            [void](Ensure-Wsl); $m = Get-Mode
            Invoke-StartMode $m; "start issued (mode=$m; one instance, auto-sync, auto-mine)"
        }
        'stop'  { Kill-Mining; 'stop issued (killed miner + node + WSL)' }
        default { $s = Get-Status; "Wsl=$($s.Wsl) Mode=$($s.Mode) Mining=$($s.Mining) | $($s.Hashrate) | $($s.Gpu)`nActivity: $($s.Phase)`nSync: $($s.SyncText) ($([math]::Round($s.SyncPct,1))%)" }
    }
    exit 0
}

# ----------------------------------------------------------------------------
# 5. Boot WSL so the GUI is responsive immediately
# ----------------------------------------------------------------------------
# The launcher window is hidden, so a startup failure would otherwise be invisible —
# surface any terminating error in a dialog instead of dying silently.
trap {
    try { Add-Type -AssemblyName System.Windows.Forms } catch {}
    [System.Windows.Forms.MessageBox]::Show("BTX Miner failed to start:`n`n$($_.Exception.Message)",'BTX Miner') | Out-Null
    exit 1
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# NEWEST INSTANCE ALWAYS WINS: kill any GUI instance that is already open (it may be
# running stale code from before an edit), then take the singleton slot. This makes it
# impossible for a double-click to leave you looking at an outdated window.
Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.ProcessId -ne $PID -and $_.CommandLine -like '*btx-miner-gui.ps1*' } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
$script:guiMutex = New-Object System.Threading.Mutex($false, 'Global\BTXMinerGuiSingleton')
for ($i=0; $i -lt 10 -and -not $script:guiMutex.WaitOne(200,$false); $i++) { Start-Sleep -Milliseconds 200 }

# SELF-HEALING SHORTCUTS: recreate both desktop shortcuts on every launch, so they can
# never point at the wrong thing, lose the admin bit, or go missing.
try {
    $desk = [Environment]::GetFolderPath('Desktop')
    $psExe = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $wsh = New-Object -ComObject WScript.Shell
    foreach ($def in @(
        @{ Path=(Join-Path $desk 'BTX Miner.lnk');        File='D:\BTX\btx-miner-gui.ps1'; Admin=$true;  Desc='BTX Miner Control (auto-repaired on every launch)' },
        @{ Path=(Join-Path $desk 'Stop BTX Mining.lnk');  File='D:\BTX\btx-kill.ps1';      Admin=$false; Desc='Instantly stop BTX mining and free the GPU' })) {
        $sc = $wsh.CreateShortcut($def.Path)
        $sc.TargetPath = $psExe
        $sc.Arguments  = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$($def.File)`""
        $sc.WorkingDirectory = 'D:\BTX'
        $sc.WindowStyle = 7
        $sc.Description = $def.Desc
        if (Test-Path 'D:\BTX\btx-miner.ico') { $sc.IconLocation = 'D:\BTX\btx-miner.ico' } else { $sc.IconLocation = "$psExe,0" }
        $sc.Save()
        $b = [System.IO.File]::ReadAllBytes($def.Path)
        if ($def.Admin) { $b[0x15] = $b[0x15] -bor 0x20 } else { $b[0x15] = $b[0x15] -band (-bnot 0x20) }
        [System.IO.File]::WriteAllBytes($def.Path, $b)
    }
} catch {}

& wsl.exe -d $WSL_DIST -e true 2>$null | Out-Null

$cBg     = [System.Drawing.Color]::FromArgb(26,28,35)
$cPanel  = [System.Drawing.Color]::FromArgb(22,33,62)
$cAccent = [System.Drawing.Color]::FromArgb(76,209,121)
$cRed    = [System.Drawing.Color]::FromArgb(233,69,96)
$cYellow = [System.Drawing.Color]::FromArgb(236,201,92)
$cBlue   = [System.Drawing.Color]::FromArgb(15,52,96)
$cPurple = [System.Drawing.Color]::FromArgb(125,76,194)
$cGray   = [System.Drawing.Color]::FromArgb(168,173,184)
$fUI     = New-Object System.Drawing.Font('Segoe UI',9)

function New-FlatButton {
    param($Text,$X,$Y,$W,$H,$Back,$Fore)
    $b = New-Object System.Windows.Forms.Button
    $b.SetBounds($X,$Y,$W,$H); $b.Text=$Text; $b.FlatStyle='Flat'
    $b.FlatAppearance.BorderSize=0; $b.BackColor=$Back; $b.ForeColor=$Fore
    $b.Font = New-Object System.Drawing.Font('Segoe UI',10,[System.Drawing.FontStyle]::Bold)
    $b.Cursor='Hand'; return $b
}

# ============================================================================
#  FINE-TUNE dialog  (edits config.yaml — the solver key levers)
# ============================================================================
function Show-FineTune {
    $raw = Invoke-Wsl "cat $CFG_PATH 2>/dev/null" 8
    $cfg = Parse-KV $raw ':'
    if (-not $cfg.Keys.Count) {
        [System.Windows.Forms.MessageBox]::Show("Couldn't read $CFG_PATH in WSL.","Fine-Tune") | Out-Null; return
    }

    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text='BTX Fine-Tune  (solver config.yaml)'; $dlg.ClientSize=New-Object System.Drawing.Size(560,560)
    $dlg.StartPosition='CenterParent'; $dlg.FormBorderStyle='FixedDialog'; $dlg.MaximizeBox=$false
    $dlg.BackColor=$cBg; $dlg.Font=$fUI

    # field key, label, hint (canonical guidance from the miner --help)
    $fields = @(
        @('worker_name',          'Worker name',            'shows on the pool dashboard'),
        @('payout_address',       'Payout address',         'your btx1z... address'),
        @('pool_host',            'Pool host',              'pool.minebtx.com'),
        @('pool_port',            'Pool port',              '3333'),
        @('solver_threads',       'Solver threads',         'KEY LEVER — canonical 8'),
        @('solver_prepare_workers','Prepare workers',       'KEY LEVER — canonical 16; bump with threads if GPU <95%'),
        @('solver_batch_size',    'Batch size',             'canonical 128 (avoid 256 on some cards)'),
        @('solver_prefetch_depth','Prefetch depth',         'canonical 8'),
        @('gpu_inputs',           'GPU inputs',             'must be 1 (post-block-125000)'),
        @('nonces_per_slice',     'Nonces per slice',       'work chunk before re-checking for new job'),
        @('log_level',            'Log level',              'DEBUG / INFO / WARNING / ERROR')
    )
    $boxes = @{}
    $y = 16
    $hdr = New-Object System.Windows.Forms.Label
    $hdr.SetBounds(16,$y,528,20); $hdr.ForeColor=$cYellow
    $hdr.Text='Tune the GPU solver, then Save + Apply to restart the miner with new settings.'
    $dlg.Controls.Add($hdr); $y += 30

    foreach ($f in $fields) {
        $lbl = New-Object System.Windows.Forms.Label
        $lbl.SetBounds(16,$y+3,150,20); $lbl.Text=$f[1]; $lbl.ForeColor=[System.Drawing.Color]::White
        $dlg.Controls.Add($lbl)
        $tb = New-Object System.Windows.Forms.TextBox
        $tb.SetBounds(172,$y,150,22); $tb.BackColor=$cPanel; $tb.ForeColor=[System.Drawing.Color]::White
        $tb.BorderStyle='FixedSingle'
        $v = $cfg[$f[0]]; if ($v) { $tb.Text = $v }
        $dlg.Controls.Add($tb); $boxes[$f[0]] = $tb
        $hint = New-Object System.Windows.Forms.Label
        $hint.SetBounds(330,$y+3,214,32); $hint.Text=$f[2]; $hint.ForeColor=$cGray
        $hint.Font = New-Object System.Drawing.Font('Segoe UI',7.5)
        $dlg.Controls.Add($hint)
        $y += 40
    }

    $btnApply = New-FlatButton 'SAVE + APPLY' 16  ($y+6) 170 40 $cAccent ([System.Drawing.Color]::Black)
    $btnSave  = New-FlatButton 'Save only'    196 ($y+6) 130 40 $cBlue  ([System.Drawing.Color]::White)
    $btnReset = New-FlatButton 'Canonical'    336 ($y+6) 100 40 $cPurple ([System.Drawing.Color]::White)
    $btnCancel= New-FlatButton 'Cancel'       446 ($y+6) 98  40 $cRed   ([System.Drawing.Color]::White)
    $dlg.Controls.AddRange(@($btnApply,$btnSave,$btnReset,$btnCancel))

    $writeCfg = {
        # Rebuild config.yaml from current field values, preserving keys we don't edit.
        $out = @{}
        foreach ($k in $cfg.Keys) { $out[$k] = $cfg[$k] }          # keep untouched keys
        foreach ($k in $boxes.Keys) { $out[$k] = $boxes[$k].Text }  # override edited keys
        $sb = New-Object System.Text.StringBuilder
        foreach ($k in $out.Keys) { [void]$sb.AppendLine("${k}: $($out[$k])") }
        $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($sb.ToString()))
        Invoke-Wsl "echo $b64 | base64 -d > $CFG_PATH" 10 | Out-Null
    }

    $btnReset.Add_Click({
        $boxes['solver_threads'].Text='8'; $boxes['solver_prepare_workers'].Text='16'
        $boxes['solver_batch_size'].Text='128'; $boxes['solver_prefetch_depth'].Text='8'
        $boxes['gpu_inputs'].Text='1'
    })
    $btnSave.Add_Click({ & $writeCfg; $dlg.Tag='saved'; $dlg.Close() })
    $btnApply.Add_Click({ & $writeCfg; $dlg.Tag='apply'; $dlg.Close() })
    $btnCancel.Add_Click({ $dlg.Tag='cancel'; $dlg.Close() })

    $dlg.ShowDialog() | Out-Null
    if ($dlg.Tag -eq 'apply') {
        $mode = Get-Mode
        Stop-Mining | Out-Null
        Start-Mining $mode | Out-Null
        [System.Windows.Forms.MessageBox]::Show("Saved and restarted the $mode miner with new solver settings.","Fine-Tune") | Out-Null
    } elseif ($dlg.Tag -eq 'saved') {
        [System.Windows.Forms.MessageBox]::Show("Saved to config.yaml. Press STOP then START (or Save + Apply) to use it.","Fine-Tune") | Out-Null
    }
}

# ============================================================================
#  BLOCK-CHANCE calculator  (Poisson model)
# ============================================================================
function Show-BlockChance {
    $st = Get-Status
    $yourHs = if ($st.HsRaw -gt 0) { $st.HsRaw } else { 0.0 }
    $netHs  = if ($st.NetHs  -gt 0) { $st.NetHs } else { $NET_HS_DEFAULT }

    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text='BTX Block-Chance Calculator'; $dlg.ClientSize=New-Object System.Drawing.Size(470,470)
    $dlg.StartPosition='CenterParent'; $dlg.FormBorderStyle='FixedDialog'; $dlg.MaximizeBox=$false
    $dlg.BackColor=$cBg; $dlg.Font=$fUI

    $mkLabel = { param($t,$x,$y,$w) $l=New-Object System.Windows.Forms.Label; $l.SetBounds($x,$y,$w,20); $l.Text=$t; $l.ForeColor=[System.Drawing.Color]::White; $dlg.Controls.Add($l); $l }
    $mkInput = { param($v,$x,$y) $t=New-Object System.Windows.Forms.TextBox; $t.SetBounds($x,$y,150,22); $t.Text="$v"; $t.BackColor=$cPanel; $t.ForeColor=[System.Drawing.Color]::White; $t.BorderStyle='FixedSingle'; $dlg.Controls.Add($t); $t }

    & $mkLabel 'Your hashrate (H/s)'      16 18 170 | Out-Null; $inYou = & $mkInput ([math]::Round($yourHs)) 200 16
    & $mkLabel 'Network hashrate (H/s)'   16 50 170 | Out-Null; $inNet = & $mkInput ([math]::Round($netHs))  200 48
    & $mkLabel 'Block time (s)'           16 82 170 | Out-Null; $inBt  = & $mkInput $BLOCK_TIME               200 80
    & $mkLabel 'Block reward (BTX)'       16 114 170| Out-Null; $inRw  = & $mkInput '' 200 112
    & $mkLabel 'Pool fee (%)'             16 146 170| Out-Null; $inFee = & $mkInput '0' 200 144

    $note = & $mkLabel 'Blank reward = probability only. Live values auto-filled from the miner; edit to model "what if".' 16 172 440
    $note.ForeColor=$cGray; $note.Font=New-Object System.Drawing.Font('Segoe UI',7.5); $note.Height=30

    $out = New-Object System.Windows.Forms.TextBox
    $out.SetBounds(16,210,438,200); $out.Multiline=$true; $out.ReadOnly=$true; $out.BackColor=$cPanel
    $out.ForeColor=$cAccent; $out.Font=New-Object System.Drawing.Font('Consolas',9); $out.BorderStyle='FixedSingle'
    $dlg.Controls.Add($out)

    $btnCalc = New-FlatButton 'CALCULATE' 16 420 200 38 $cAccent ([System.Drawing.Color]::Black)
    $btnClose= New-FlatButton 'Close'     254 420 200 38 $cBlue ([System.Drawing.Color]::White)
    $dlg.Controls.AddRange(@($btnCalc,$btnClose))

    $doCalc = {
        $you=[double]$inYou.Text; $net=[double]$inNet.Text; $bt=[double]$inBt.Text
        if ($you -le 0 -or $net -le 0 -or $bt -le 0) { $out.Text='Enter positive hashrates and block time.'; return }
        $share = $you/$net
        $blocksDayNet = 86400.0/$bt
        $expDay = $blocksDayNet*$share
        $meanSec = if ($expDay -gt 0) { 86400.0/$expDay } else { [double]::PositiveInfinity }
        function P($tsec){ 1.0 - [math]::Exp(-$tsec/$meanSec) }
        function Human($sec){
            if ($sec -lt 3600) { '{0:N0} min' -f ($sec/60) }
            elseif ($sec -lt 86400) { '{0:N1} hours' -f ($sec/3600) }
            elseif ($sec -lt 86400*60) { '{0:N1} days' -f ($sec/86400) }
            else { '{0:N1} months' -f ($sec/86400/30) }
        }
        $L = @()
        $L += ('Your share of network : {0:P4}' -f $share)
        $L += ('Expected blocks / day  : {0:N4}' -f $expDay)
        $L += ('Mean time to a block   : {0}' -f (Human $meanSec))
        $L += ''
        $L += ('Chance of >=1 block in:')
        $L += ('   1 hour  : {0:P2}' -f (P 3600))
        $L += ('   24 hours: {0:P2}' -f (P 86400))
        $L += ('   7 days  : {0:P2}' -f (P (86400*7)))
        $L += ('   30 days : {0:P2}' -f (P (86400*30)))
        if ($inRw.Text -and [double]$inRw.Text -gt 0) {
            $rw=[double]$inRw.Text; $fee=[double]$inFee.Text/100.0
            $btcDay = $expDay*$rw*(1.0-$fee)
            $L += ''
            $L += ('Expected reward (reward={0} BTX, fee={1:P0}):' -f $rw,$fee)
            $L += ('   ~ {0:N4} BTX / day' -f $btcDay)
            $L += ('   ~ {0:N4} BTX / week' -f ($btcDay*7))
            $L += ('   ~ {0:N3} BTX / month' -f ($btcDay*30))
            $L += '(Pool pays this steadily; solo pays it in lumps of one full block.)'
        }
        $out.Text = ($L -join "`r`n")
    }
    $btnCalc.Add_Click($doCalc)
    $btnClose.Add_Click({ $dlg.Close() })
    & $doCalc
    $dlg.ShowDialog() | Out-Null
}

# ============================================================================
#  AUTO-TUNE dialog  (launches the WSL sweep, tails its progress)
# ============================================================================
function Show-AutoTune {
    if ((Get-Mode) -ne 'pool') {
        $ans = [System.Windows.Forms.MessageBox]::Show(
            "Auto-tune maximizes the POOL solver (config.yaml threads / prepare-workers). Switch to pool mode and start tuning now?",
            'Auto-Tune','YesNo','Question')
        if ($ans -ne 'Yes') { return }
        Start-Mining 'pool' | Out-Null
    }
    # bash-side nohup detach via a synchronous wsl call — Start-Process proved unreliable
    # here, while nohup'd children demonstrably survive the launching wsl.exe exiting.
    Invoke-Wsl "chmod +x $AUTOTUNE; rm -f $AUTOTUNE_STOP; nohup bash $AUTOTUNE >>/mnt/d/BTX/btx-autotune-launch.log 2>&1 </dev/null & echo launched" 15 | Out-Null

    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text='BTX Auto-Tune — maximizing hashrate'; $dlg.ClientSize=New-Object System.Drawing.Size(560,430)
    $dlg.StartPosition='CenterParent'; $dlg.FormBorderStyle='FixedDialog'; $dlg.MaximizeBox=$false
    $dlg.BackColor=$cBg; $dlg.Font=$fUI

    $info = New-Object System.Windows.Forms.Label
    $info.SetBounds(16,10,528,40); $info.ForeColor=$cYellow
    $info.Text='Sweeping solver threads / prepare-workers (~2 min per step, ~12 min total) and keeping the fastest. The GPU stays busy; you can keep using the PC. Closing this box does NOT stop tuning — it applies the best result on its own.'
    $dlg.Controls.Add($info)

    $box = New-Object System.Windows.Forms.TextBox
    $box.SetBounds(16,56,528,300); $box.Multiline=$true; $box.ReadOnly=$true; $box.ScrollBars='Vertical'
    $box.BackColor=$cPanel; $box.ForeColor=$cAccent; $box.Font=New-Object System.Drawing.Font('Consolas',9); $box.BorderStyle='FixedSingle'
    $dlg.Controls.Add($box)

    $btnStop  = New-FlatButton 'STOP TUNING' 16 366 200 46 $cRed  ([System.Drawing.Color]::White)
    $btnClose = New-FlatButton 'Close'       344 366 200 46 $cBlue ([System.Drawing.Color]::White)
    $dlg.Controls.AddRange(@($btnStop,$btnClose))

    $tick = {
        $t = Invoke-Wsl "tail -n 200 $AUTOTUNE_LOG 2>/dev/null" 8
        if ($t) { $box.Text = $t; $box.SelectionStart = $box.TextLength; $box.ScrollToCaret() }
        if ($t -match 'Auto-tune complete|ended without a winner') {
            $btnStop.Text='DONE'; $btnStop.BackColor=$cAccent; $btnStop.ForeColor=[System.Drawing.Color]::Black; $btnStop.Enabled=$false
        }
    }
    $atimer = New-Object System.Windows.Forms.Timer
    $atimer.Interval=3000; $atimer.Add_Tick($tick); $atimer.Start()
    $btnStop.Add_Click({ Invoke-Wsl "touch $AUTOTUNE_STOP" 5 | Out-Null; $btnStop.Text='STOPPING...' })
    $btnClose.Add_Click({ $atimer.Stop(); $dlg.Close() })
    & $tick
    $dlg.ShowDialog() | Out-Null
    $atimer.Stop()
}

# ============================================================================
#  MAIN window
# ============================================================================
$form = New-Object System.Windows.Forms.Form
$buildStamp = (Get-Item $PSCommandPath).LastWriteTime.ToString('MM-dd HH:mm')
$form.Text="BTX Miner Control (admin) - build $buildStamp"; $form.ClientSize=New-Object System.Drawing.Size(470,474)
$form.StartPosition='CenterScreen'; $form.FormBorderStyle='FixedSingle'; $form.MaximizeBox=$false
$form.BackColor=$cBg; $form.Font=$fUI

$lblStatus = New-Object System.Windows.Forms.Label
$lblStatus.SetBounds(20,14,430,36); $lblStatus.TextAlign='MiddleCenter'
$lblStatus.Font=New-Object System.Drawing.Font('Segoe UI',18,[System.Drawing.FontStyle]::Bold)
$lblStatus.Text='Checking...'; $form.Controls.Add($lblStatus)

$lblDetail = New-Object System.Windows.Forms.Label
$lblDetail.SetBounds(20,52,430,20); $lblDetail.TextAlign='MiddleCenter'; $lblDetail.ForeColor=$cGray
$form.Controls.Add($lblDetail)

$lblHash = New-Object System.Windows.Forms.Label
$lblHash.SetBounds(20,74,430,20); $lblHash.TextAlign='MiddleCenter'; $lblHash.ForeColor=$cAccent
$form.Controls.Add($lblHash)

# ---- info panel: balance / blocks found / est per-day / node sync ----
$panel = New-Object System.Windows.Forms.Panel
$panel.SetBounds(16,100,438,146); $panel.BackColor=$cPanel; $panel.BorderStyle='FixedSingle'
$form.Controls.Add($panel)
function New-Row {
    param($Label,$Y)
    $l = New-Object System.Windows.Forms.Label
    $l.SetBounds(12,$Y,108,20); $l.Text=$Label; $l.ForeColor=$cGray; $panel.Controls.Add($l)
    $v = New-Object System.Windows.Forms.Label
    $v.SetBounds(120,$Y,308,20); $v.Text='...'; $v.ForeColor=[System.Drawing.Color]::White
    $v.Font=New-Object System.Drawing.Font('Segoe UI',9,[System.Drawing.FontStyle]::Bold); $panel.Controls.Add($v)
    return $v
}
$valBal  = New-Row 'Balance'         6
$valBlk  = New-Row 'Blocks found'    28
$valEst  = New-Row 'Est. blocks/day' 50
$valSync = New-Row 'Node / Sync'     72
$valAct  = New-Row 'Activity'        94
$valAct.ForeColor = $cYellow
$valAct.Font = New-Object System.Drawing.Font('Segoe UI',8.5,[System.Drawing.FontStyle]::Bold)
$syncBar = New-Object System.Windows.Forms.ProgressBar
$syncBar.SetBounds(120,120,248,13); $syncBar.Minimum=0; $syncBar.Maximum=100; $syncBar.Style='Continuous'
$panel.Controls.Add($syncBar)
$lblPct = New-Object System.Windows.Forms.Label
$lblPct.SetBounds(372,118,56,16); $lblPct.TextAlign='MiddleRight'; $lblPct.ForeColor=$cAccent
$lblPct.Font=New-Object System.Drawing.Font('Segoe UI',9,[System.Drawing.FontStyle]::Bold)
$panel.Controls.Add($lblPct)

# mode selector
$lblMode = New-Object System.Windows.Forms.Label
$lblMode.SetBounds(20,258,50,24); $lblMode.Text='Mode:'; $lblMode.ForeColor=[System.Drawing.Color]::White
$form.Controls.Add($lblMode)
$cmbMode = New-Object System.Windows.Forms.ComboBox
$cmbMode.SetBounds(72,256,180,24); $cmbMode.DropDownStyle='DropDownList'
$cmbMode.Items.AddRange(@('pool (minebtx)','solo (own node)')) | Out-Null
$cmbMode.BackColor=$cPanel; $cmbMode.ForeColor=[System.Drawing.Color]::White
$form.Controls.Add($cmbMode)

$btnStart = New-FlatButton 'START'          26  290 205 56 $cAccent ([System.Drawing.Color]::Black)
$btnStop  = New-FlatButton 'STOP + FREE GPU' 247 290 197 56 $cRed   ([System.Drawing.Color]::White)
$form.Controls.AddRange(@($btnStart,$btnStop))

$btnTune  = New-FlatButton 'FINE-TUNE'   26  356 135 42 $cPurple ([System.Drawing.Color]::White)
$btnAuto  = New-FlatButton 'AUTO-TUNE'   167 356 135 42 $cAccent ([System.Drawing.Color]::Black)
$btnChance= New-FlatButton 'BLOCK CHANCE'308 356 136 42 $cBlue   ([System.Drawing.Color]::White)
$form.Controls.AddRange(@($btnTune,$btnAuto,$btnChance))

$lblAction = New-Object System.Windows.Forms.Label
$lblAction.SetBounds(16,408,438,58); $lblAction.TextAlign='MiddleCenter'; $lblAction.ForeColor=$cGray
$form.Controls.Add($lblAction)

$applyStatus = {
    param($s)
    if (-not $s.Wsl)                        { $lblStatus.Text='WSL OFF'; $lblStatus.ForeColor=$cRed }
    elseif ($s.Phase -match '^⛏|MINING')    { $lblStatus.Text='MINING';  $lblStatus.ForeColor=$cAccent }
    elseif ($s.Phase -match 'Stopped')      { $lblStatus.Text='STOPPED'; $lblStatus.ForeColor=$cRed }
    elseif ($s.Phase -match 'NO PROGRESS')  { $lblStatus.Text='STALLED?'; $lblStatus.ForeColor=$cRed }
    else                                    { $lblStatus.Text='WORKING'; $lblStatus.ForeColor=$cYellow }
    $valAct.Text = $s.Phase
    $valAct.ForeColor = if ($s.Phase -match 'NO PROGRESS') { $cRed } elseif ($s.Phase -match '^⛏') { $cAccent } else { $cYellow }
    $lblDetail.Text = $s.Gpu
    $lblHash.Text   = ('{0} mode   |   {1}' -f $s.Mode.ToUpper(), $s.Hashrate)
    if ($s.EstDay -gt 0) {
        $dpb = 1.0/$s.EstDay
        if ($dpb -lt 1)      { $per = '{0:N1} hours/block' -f ($dpb*24) }
        elseif ($dpb -lt 60) { $per = '{0:N1} days/block'  -f $dpb }
        else                 { $per = '{0:N1} months/block' -f ($dpb/30) }
        $valEst.Text = ('{0:N3}   (~{1})' -f $s.EstDay, $per)
    } elseif ($s.Wsl -and $s.Mining) { $valEst.Text = 'measuring hashrate...' }
    $valSync.Text = $s.SyncText
    if ($s.SyncPct -ge 0) {
        $syncBar.Visible = $true
        $syncBar.Value = [int][math]::Round([math]::Max(0.0,[math]::Min(100.0,$s.SyncPct)))
        $lblPct.Text = ('{0:N1}%' -f $s.SyncPct)
    } else { $syncBar.Visible = $false; $lblPct.Text = '' }
    if ($cmbMode.SelectedIndex -lt 0) { $cmbMode.SelectedIndex = if ($s.Mode -eq 'solo') {1} else {0} }
}
$refresh = { & $applyStatus (Get-Status) }

# Balance (HTTP) + blocks-found (WSL chain scan, can be slow) run in a detached
# job so they NEVER block the window. Self-contained: no access to outer funcs.
$slowBlock = {
    param($explorer,$payout,$dist,$soloStats)
    $bal = 'unavailable (explorer offline)'
    try {
        $r = Invoke-RestMethod -Uri ($explorer+$payout) -TimeoutSec 6 -Headers @{Accept='application/json'}
        $c=$r.chain_stats; $m=$r.mempool_stats
        $conf=[int64]$c.funded_txo_sum-[int64]$c.spent_txo_sum
        $mem =[int64]$m.funded_txo_sum-[int64]$m.spent_txo_sum
        $bal=('{0:N6} BTX' -f (($conf+$mem)/1e8)); if($mem -ne 0){$bal+=(' ({0:+0.######} pending)' -f ($mem/1e8))}
    } catch {}
    $blk = 'solo metric — pool pays via Balance (needs btxd for counts)'
    try {
        $run = (& wsl.exe --list --running 2>$null | Out-String) -replace "`0",""
        if ($run -match [regex]::Escape($dist)) {   # never boot a stopped WSL just to poll
            $o=(& wsl.exe -d $dist -e bash -lc "chmod +x $soloStats; bash $soloStats 2>&1" 2>$null | Out-String) -replace "`0",""
            $h=@{}; foreach($ln in ($o -split "`n")){ if($ln -match '^\s*([A-Za-z0-9_]+)\s*=\s*(.*?)\s*$'){$h[$matches[1]]=$matches[2]} }
            if($h.ContainsKey('solo_blocks_24h')){
                $blk=('{0} (24h) / {1} (7d)' -f $h['solo_blocks_24h'],$h['solo_blocks_7d'])
                if($h['solo_last_win'] -and $h['solo_last_win'] -ne 'none in window'){$blk+="   last: $($h['solo_last_win'])"}
            }
        }
    } catch {}
    "$bal|||$blk"
}
$script:slowJob = $null
$kickSlow = { if (-not $script:slowJob) { $script:slowJob = Start-Job -ScriptBlock $slowBlock -ArgumentList $EXPLORER,$PAYOUT,$WSL_DIST,$SOLO_STATS } }
$reapSlow = {
    if ($script:slowJob -and $script:slowJob.State -ne 'Running') {
        $res = Receive-Job $script:slowJob -ErrorAction SilentlyContinue
        Remove-Job $script:slowJob -Force; $script:slowJob = $null
        if ($res) { $pp = $res -split '\|\|\|',2; $valBal.Text=$pp[0]; if($pp.Count -gt 1){$valBlk.Text=$pp[1]} }
    }
}

$btnStart.Add_Click({
    $mode = if ($cmbMode.SelectedIndex -eq 1) {'solo'} else {'pool'}
    $btnStart.Enabled=$false; $btnStop.Enabled=$false
    $lblStatus.Text='STARTING...'; $lblStatus.ForeColor=$cYellow
    $lblAction.Text='Booting WSL...'; $form.Refresh()
    if (Ensure-Wsl) {
        if ($mode -eq 'solo') {
            $lblAction.Text='Ensuring ONE instance + auto-sync (node repairs/syncs itself, then mines)...'; $form.Refresh()
            Invoke-StartMode 'solo'
            $lblAction.Text='Running (one instance). Watch the Sync bar — mining begins automatically at the tip.'
        } else {
            $lblAction.Text='WSL up. Starting pool miner...'; $form.Refresh()
            Invoke-StartMode 'pool'
            $lblAction.Text='Started. Pool miner warming up (~30-60s).'
        }
    } else {
        $lblAction.Text='WSL failed to boot. Check `wsl --status`, then try START again.'
    }
    $btnStart.Enabled=$true; $btnStop.Enabled=$true
    & $refresh
})
$btnStop.Add_Click({
    $btnStart.Enabled=$false; $btnStop.Enabled=$false
    $lblStatus.Text='STOPPING...'; $lblStatus.ForeColor=$cYellow
    $lblAction.Text='Killing everything — miner, node, and WSL — to free the GPU + RAM...'; $form.Refresh()
    Kill-Mining
    $lblAction.Text='All stopped. GPU + RAM freed. Press START to bring it all back (WSL reboots on its own).'
    $btnStart.Enabled=$true; $btnStop.Enabled=$true
    & $refresh
})
$btnTune.Add_Click({ Show-FineTune; & $refresh })
$btnAuto.Add_Click({
    $lblAction.Text='Auto-tune launched — see the progress window. It applies the fastest settings automatically.'
    Show-AutoTune; & $refresh
})
$btnChance.Add_Click({ Show-BlockChance })

$script:lastSlow = 0
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 6000
$timer.Add_Tick({
    & $refresh
    & $reapSlow    # pick up finished balance/blocks result (instant; no wait)
    if (([Environment]::TickCount64 - $script:lastSlow) -gt 30000) {
        $script:lastSlow = [Environment]::TickCount64
        & $kickSlow
    }
})
$timer.Start()

& $refresh
& $kickSlow
$form.Add_Shown({ $form.Activate() })
$form.Add_FormClosing({
    param($s,$e)
    $ans = [System.Windows.Forms.MessageBox]::Show($form,
        ("Stop mining and free the GPU before closing?" + [Environment]::NewLine + [Environment]::NewLine +
         "Yes  =  stop miner + shut down WSL (frees GPU/RAM)" + [Environment]::NewLine +
         "No  =  keep mining in the background" + [Environment]::NewLine +
         "Cancel  =  don't close"),
        'Close BTX Miner', 'YesNoCancel', 'Question')
    if ($ans -eq 'Cancel') { $e.Cancel = $true; return }
    $timer.Stop()
    if ($script:slowJob) { Remove-Job $script:slowJob -Force -ErrorAction SilentlyContinue }
    if ($ans -eq 'Yes') {
        $lblStatus.Text='STOPPING...'; $lblStatus.ForeColor=$cYellow
        $lblAction.Text='Stopping miner and freeing the GPU...'; $form.Refresh()
        Kill-Mining
    }
})
[System.Windows.Forms.Application]::Run($form)
