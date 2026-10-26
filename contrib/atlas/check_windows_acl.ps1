# Read-only ACL check. Prints icacls output and exits.
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

function Test-RightsGrantWrite {
    param([string]$Rights)
    $deny = $false
    $write = $false
    $writeTokens = @(
        'F', 'M', 'W', 'GA', 'GW', 'WD', 'AD', 'WEA', 'WA', 'WDAC', 'WO'
    )
    foreach ($match in [regex]::Matches($Rights, '\(([^)]*)\)')) {
        $inner = $match.Groups[1].Value.Trim()
        if ($inner -match '^(?i:DENY)$') {
            $deny = $true
            continue
        }
        if ($inner -match '^(?i:OI|CI|IO|I|NP|GRANT)$') {
            continue
        }
        foreach ($token in ($inner -split ',')) {
            $name = $token.Trim().ToUpperInvariant()
            if ([string]::IsNullOrEmpty($name)) {
                continue
            }
            if ($writeTokens -contains $name) {
                $write = $true
                continue
            }
            if ($name -match '^[NFMRXWD]+$' -and $name -match '[FMW]') {
                $write = $true
            }
        }
    }
    if ($deny) {
        return $false
    }
    return $write
}

$lines = @(& icacls.exe $target 2>&1 | ForEach-Object { "$_" })
$icaclsExit = $LASTEXITCODE
foreach ($line in $lines) {
    Write-Output $line
}

if ($lines.Count -eq 0 -or $icaclsExit -ne 0) {
    exit 1
}

$acePattern = '(?i)(?:^|\s)(?<id>Everyone|BUILTIN\\Users|(?:[A-Za-z0-9 ._-]+\\)?Authenticated Users):(?<rights>(?:\([^)]*\))+)'
$identityPattern = '(?i)(?:^|\s)(?:Everyone|BUILTIN\\Users|(?:[A-Za-z0-9 ._-]+\\)?Authenticated Users):'
$grantsWrite = $false
$unparsed = $false

foreach ($line in $lines) {
    $parsed = $false
    foreach ($match in [regex]::Matches($line, $acePattern)) {
        $parsed = $true
        if (Test-RightsGrantWrite -Rights $match.Groups['rights'].Value) {
            $grantsWrite = $true
        }
    }
    if ((-not $parsed) -and ($line -match $identityPattern)) {
        $unparsed = $true
    }
    if ($line -match 'Failed processing\s+[1-9]') {
        $unparsed = $true
    }
}

if ($grantsWrite -or $unparsed) {
    exit 1
}
exit 0
