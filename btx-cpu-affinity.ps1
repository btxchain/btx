# BTX / Fulgur CPU Affinity Keeper
# ---------------------------------
# i7-10700KF = 8 physical cores / 16 logical threads. The WSL VM that runs the
# single-threaded BTX GPU-feed is capped at 12 vCPUs and CANNOT be pinned
# directly (vmmemWSL is a protected process; its affinity reads as 0). So we pin
# the Fulgur CPU miner (brc-pow.exe) to logical cores 0-11, leaving cores 12-15
# (2 physical cores) free for the WSL VM to float its feed thread onto. This
# stops the two miners fighting and lifts BTX GPU util ~32% -> ~40%.
#
# (Freeing only 2 logical threads was too tight for the 12-vCPU VM to schedule;
#  2 physical cores / 4 logical is the sweet spot.)
#
# When BTX is NOT mining (WSL shut down, e.g. the gaming pause), Fulgur is
# released back to all 16 cores so the CPU miner isn't needlessly confined.
# Fulgur respawns workers per job, so we re-apply on a loop. No admin needed.

$ErrorActionPreference = 'SilentlyContinue'
try {
    $mtx = New-Object System.Threading.Mutex($false, 'Global\BTX_CPU_Affinity_Keeper')
    if (-not $mtx.WaitOne(0)) { exit }
} catch {}

$WHEN_MINING = [IntPtr]4095    # cores 0-11  (frees 12-15 for the BTX feed)
$WHEN_IDLE   = [IntPtr]65535   # all 16 cores (BTX not running -> Fulgur gets everything)

while ($true) {
    # vmmemWSL present == WSL/BTX is up. Checked on the Windows side so we never boot WSL.
    $btxUp = [bool](Get-Process vmmemWSL -ErrorAction SilentlyContinue)
    $mask = if ($btxUp) { $WHEN_MINING } else { $WHEN_IDLE }
    foreach ($p in (Get-Process brc-pow -ErrorAction SilentlyContinue)) {
        try { $p.ProcessorAffinity = $mask } catch {}
    }
    Start-Sleep -Seconds 5
}
