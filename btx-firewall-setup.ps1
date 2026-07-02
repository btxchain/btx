# Elevated firewall setup for BTX P2P inbound (port 19335) with WSL mirrored networking.
$out = "D:\btx\btx-firewall-setup.log"
"=== $(Get-Date) ===" | Out-File $out
try {
    if (-not (Get-NetFirewallRule -DisplayName "BTX P2P 19335" -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName "BTX P2P 19335" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 19335 | Out-Null
        "host firewall rule created" | Out-File $out -Append
    } else {
        "host firewall rule already exists" | Out-File $out -Append
    }
} catch { "host rule FAILED: $_" | Out-File $out -Append }

# WSL VM creator GUID (fixed for WSL): inbound rule in the Hyper-V firewall,
# which governs traffic to the mirrored-mode VM.
try {
    $wslGuid = '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}'
    if (Get-Command New-NetFirewallHyperVRule -ErrorAction SilentlyContinue) {
        if (-not (Get-NetFirewallHyperVRule -Name "BTX-P2P" -ErrorAction SilentlyContinue)) {
            New-NetFirewallHyperVRule -Name "BTX-P2P" -DisplayName "BTX P2P 19335" -Direction Inbound -VMCreatorId $wslGuid -Protocol TCP -LocalPorts 19335 | Out-Null
            "hyperv firewall rule created" | Out-File $out -Append
        } else {
            "hyperv firewall rule already exists" | Out-File $out -Append
        }
    } else {
        "New-NetFirewallHyperVRule not available; skipping (older builds do not need it)" | Out-File $out -Append
    }
} catch { "hyperv rule FAILED: $_" | Out-File $out -Append }
"done" | Out-File $out -Append
