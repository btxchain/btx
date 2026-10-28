# Read-only ACL check. Prints icacls output, then any write grant to Everyone, Users or
# Authenticated Users, and exits.
# Never grants, denies, saves, restores, or rewrites the ACL.
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Path
)

$ErrorActionPreference = 'Continue'
if (Get-Variable -Name PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue) {
    $PSNativeCommandUseErrorActionPreference = $false
}

if (-not (Test-Path -LiteralPath $Path)) {
    Write-Output 'NOT_RUN'
    exit 2
}

$target = (Get-Item -LiteralPath $Path).FullName

$lines = @(& icacls.exe $target 2>&1 | ForEach-Object { "$_" })
$icaclsExit = $LASTEXITCODE
foreach ($line in $lines) {
    Write-Output $line
}

if ($lines.Count -eq 0 -or $icaclsExit -ne 0) {
    exit 1
}

# Decide on SIDs, not on the icacls text: account names are translated, and the console code
# page can garble them (the German NT AUTHORITY prefix under 65001). The rights match the icacls tokens F, M, W,
# WD, AD, WEA, WA, WDAC, WO, GA and GW. An allow rule grants; a deny rule does not.
$broad = @{
    'S-1-1-0'      = 'Everyone'
    'S-1-5-32-545' = 'BUILTIN\Users'
    'S-1-5-11'     = 'Authenticated Users'
}
$writeMask = 0x2 -bor 0x4 -bor 0x10 -bor 0x100 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000
try {
    $rules = (Get-Acl -LiteralPath $target).GetAccessRules(
        $true, $true, [System.Security.Principal.SecurityIdentifier])
} catch {
    Write-Output "Get-Acl failed: $($_.Exception.Message)"
    exit 1
}
$grantsWrite = $false
foreach ($rule in $rules) {
    $sid = $rule.IdentityReference.Value
    if ((-not $broad.ContainsKey($sid)) -or ("$($rule.AccessControlType)" -ne 'Allow')) {
        continue
    }
    if (([int]$rule.FileSystemRights -band $writeMask) -ne 0) {
        Write-Output ("write grant: {0} ({1}) {2}{3}" -f $broad[$sid], $sid, $rule.FileSystemRights,
            $(if ($rule.IsInherited) { ', inherited' } else { '' }))
        $grantsWrite = $true
    }
}

if ($grantsWrite) {
    exit 1
}
exit 0
