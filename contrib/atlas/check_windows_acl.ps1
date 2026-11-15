# Read-only ACL check. Prints icacls output, then any write or delete grant to a broad
# group (Everyone, Users, Authenticated Users, Interactive, Anonymous, Guests, Domain
# Users, Domain Guests) and an owner from such a group, and exits.
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
# D, DC, WD, AD, WEA, WA, WDAC, WO, GA and GW. An allow rule grants; a deny rule does not.
$broad = @{
    'S-1-1-0'      = 'Everyone'
    'S-1-5-32-545' = 'BUILTIN\Users'
    'S-1-5-11'     = 'Authenticated Users'
    'S-1-5-4'      = 'Interactive'
    'S-1-5-7'      = 'Anonymous Logon'
    'S-1-5-32-546' = 'BUILTIN\Guests'
}
function Get-BroadName([string]$sid) {
    if ($broad.ContainsKey($sid)) { return $broad[$sid] }
    if ($sid -match '^S-1-5-21-\d+-\d+-\d+-513$') { return 'Domain Users' }
    if ($sid -match '^S-1-5-21-\d+-\d+-\d+-514$') { return 'Domain Guests' }
    return $null
}
# 0x10000 is DELETE and 0x40 is DELETE_CHILD: either lets the file be removed and replaced.
$writeMask = 0x2 -bor 0x4 -bor 0x10 -bor 0x40 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000
try {
    $acl = Get-Acl -LiteralPath $target
    $rules = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
} catch {
    Write-Output "Get-Acl failed: $($_.Exception.Message)"
    exit 1
}
$grantsWrite = $false
# The owner can always rewrite the ACL (implicit WRITE_DAC), so a broad owner counts as a grant.
$ownerName = Get-BroadName $owner
if ($ownerName) {
    Write-Output ("owner: {0} ({1})" -f $ownerName, $owner)
    $grantsWrite = $true
}
foreach ($rule in $rules) {
    $sid = $rule.IdentityReference.Value
    $name = Get-BroadName $sid
    if ((-not $name) -or ("$($rule.AccessControlType)" -ne 'Allow')) {
        continue
    }
    if (([int]$rule.FileSystemRights -band $writeMask) -ne 0) {
        Write-Output ("write grant: {0} ({1}) {2}{3}" -f $name, $sid, $rule.FileSystemRights,
            $(if ($rule.IsInherited) { ', inherited' } else { '' }))
        $grantsWrite = $true
    }
}

if ($grantsWrite) {
    exit 1
}
exit 0
