$limitPct = 90
for($i=0; $i -lt 280; $i++){
  $c = (Get-Counter "\Memory\% Committed Bytes In Use" -ErrorAction SilentlyContinue).CounterSamples[0].CookedValue
  if($c -gt $limitPct){
    wsl -e bash -lc "pkill -x btxd.real 2>/dev/null; pkill -f '[b]tx-faststart' 2>/dev/null; pkill -f '[b]tx-sync-fast' 2>/dev/null; true"
    "[{0}] WATCHDOG TRIPPED: commit {1:N1}% > {2}% -> killed BTX node sync to protect PC" -f (Get-Date -Format HH:mm:ss), $c, $limitPct | Out-File -FilePath "D:\BTX\btx-mem-watchdog.log" -Append -Encoding utf8
    break
  }
  Start-Sleep -Seconds 15
}
