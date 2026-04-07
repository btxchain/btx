[CmdletBinding()]
param(
    [string]$SourceDir = "",
    [string]$BuildDir = "",
    [ValidateSet("Release", "RelWithDebInfo", "Debug")]
    [string]$Configuration = "Release",
    [switch]$InstallDependencies,
    [switch]$InstallCudaToolkit,
    [switch]$EnableCudaExperimental,
    [switch]$BuildGui,
    [switch]$BuildBench,
    [switch]$BuildTests,
    [switch]$UseStaticTriplet,
    [switch]$SkipSmokeTest,
    [switch]$Install,
    [string]$InstallDir = "",
    [string]$VcpkgRoot = "C:\btx-deps\vcpkg",
    [string]$VcpkgInstalledDir = "C:\btx-deps\vcpkg_installed\btx-node",
    [string]$VcpkgBuildtreesRoot = "C:\btx-deps\vcpkg-buildtrees",
    [string]$CudaToolkitRoot = "",
    [string]$CudaArchitectures = "120"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Write-Step {
    param([string]$Message)
    Write-Host "[btx-windows] $Message"
}

function Fail {
    param([string]$Message)
    throw $Message
}

function Resolve-NormalPath {
    param([string]$Path, [switch]$CreateDirectory)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ""
    }
    if ($CreateDirectory -and -not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
    if (Test-Path -LiteralPath $Path) {
        return (Resolve-Path -LiteralPath $Path).Path
    }
    return [System.IO.Path]::GetFullPath($Path)
}

function Get-CommandPath {
    param([string]$Name, [string[]]$Fallbacks = @())

    $cmd = Get-Command -Name $Name -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Source
    }
    foreach ($fallback in $Fallbacks) {
        if (Test-Path -LiteralPath $fallback) {
            return $fallback
        }
    }
    return $null
}

function Assert-Winget {
    $winget = Get-CommandPath -Name "winget.exe" -Fallbacks @(
        (Join-Path $env:LOCALAPPDATA "Microsoft\WindowsApps\winget.exe")
    )
    if (-not $winget) {
        Fail "winget is required for -InstallDependencies but was not found."
    }
    return $winget
}

function Install-WingetPackage {
    param(
        [string]$Winget,
        [string]$Id,
        [string]$Label,
        [string]$Override = ""
    )

    Write-Step "Installing $Label ($Id) via winget"
    $args = @(
        "install",
        "--id", $Id,
        "--exact",
        "--source", "winget",
        "--accept-package-agreements",
        "--accept-source-agreements"
    )
    if ($Override) {
        $args += @("--override", $Override)
    }
    & $Winget @args
    if ($LASTEXITCODE -ne 0) {
        Fail "winget install failed for $Id"
    }
}

function Get-VsWherePath {
    $fallback = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    return Get-CommandPath -Name "vswhere.exe" -Fallbacks @($fallback)
}

function Get-VsDevCmdPath {
    $vswhere = Get-VsWherePath
    if (-not $vswhere) {
        return $null
    }

    $installationPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($installationPath)) {
        return $null
    }

    $vsDevCmd = Join-Path $installationPath.Trim() "Common7\Tools\VsDevCmd.bat"
    if (Test-Path -LiteralPath $vsDevCmd) {
        return $vsDevCmd
    }
    return $null
}

function Ensure-CoreDependencies {
    param([switch]$NeedPython)

    $winget = $null
    if ($InstallDependencies) {
        $winget = Assert-Winget
    }

    $git = Get-CommandPath -Name "git.exe" -Fallbacks @(
        "C:\Program Files\Git\cmd\git.exe"
    )
    if (-not $git -and $InstallDependencies) {
        Install-WingetPackage -Winget $winget -Id "Git.Git" -Label "Git for Windows"
        $git = Get-CommandPath -Name "git.exe" -Fallbacks @("C:\Program Files\Git\cmd\git.exe")
    }
    if (-not $git) {
        Fail "Git for Windows is required. Install it or rerun with -InstallDependencies."
    }

    $cmake = Get-CommandPath -Name "cmake.exe" -Fallbacks @(
        "C:\Program Files\CMake\bin\cmake.exe"
    )
    if (-not $cmake -and $InstallDependencies) {
        Install-WingetPackage -Winget $winget -Id "Kitware.CMake" -Label "CMake"
        $cmake = Get-CommandPath -Name "cmake.exe" -Fallbacks @("C:\Program Files\CMake\bin\cmake.exe")
    }
    if (-not $cmake) {
        Fail "CMake is required. Install it or rerun with -InstallDependencies."
    }

    $vsDevCmd = Get-VsDevCmdPath
    if (-not $vsDevCmd -and $InstallDependencies) {
        $override = "--quiet --wait --norestart --nocache --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
        Install-WingetPackage -Winget $winget -Id "Microsoft.VisualStudio.2022.BuildTools" -Label "Visual Studio 2022 Build Tools" -Override $override
        $vsDevCmd = Get-VsDevCmdPath
    }
    if (-not $vsDevCmd) {
        Fail "Visual Studio 2022 Build Tools with Desktop C++ are required. Install them or rerun with -InstallDependencies."
    }

    $python = Get-CommandPath -Name "py.exe" -Fallbacks @(
        "C:\Windows\py.exe"
    )
    if ($NeedPython -and -not $python -and $InstallDependencies) {
        Install-WingetPackage -Winget $winget -Id "Python.Python.3.11" -Label "Python 3.11"
        $python = Get-CommandPath -Name "py.exe" -Fallbacks @("C:\Windows\py.exe")
    }
    if ($NeedPython -and -not $python) {
        Fail "Python 3.10+ is required for the requested test flow. Install it or rerun with -InstallDependencies."
    }

    return [pscustomobject]@{
        Git = $git
        CMake = $cmake
        VsDevCmd = $vsDevCmd
        PythonLauncher = $python
        Winget = $winget
    }
}

function Ensure-Vcpkg {
    param(
        [string]$Git,
        [string]$Root
    )

    $toolchain = Join-Path $Root "scripts\buildsystems\vcpkg.cmake"
    $bootstrap = Join-Path $Root "bootstrap-vcpkg.bat"
    $vcpkgExe = Join-Path $Root "vcpkg.exe"

    if (Test-Path -LiteralPath $Root) {
        $hasBootstrap = Test-Path -LiteralPath $bootstrap
        $hasGitDir = Test-Path -LiteralPath (Join-Path $Root ".git")
        if (-not $hasBootstrap -and -not $hasGitDir) {
            Write-Step "Removing incomplete vcpkg directory at $Root"
            Remove-Item -LiteralPath $Root -Recurse -Force
        }
    }

    if (-not (Test-Path -LiteralPath $Root)) {
        Write-Step "Cloning standalone vcpkg to $Root"
        & $Git clone https://github.com/microsoft/vcpkg.git $Root
        if ($LASTEXITCODE -ne 0) {
            Fail "Failed to clone vcpkg into $Root"
        }
    }

    if (-not (Test-Path -LiteralPath $bootstrap)) {
        Fail "vcpkg checkout at $Root is incomplete: missing bootstrap-vcpkg.bat"
    }

    if (-not (Test-Path -LiteralPath $vcpkgExe)) {
        Write-Step "Bootstrapping vcpkg"
        & cmd.exe /d /s /c "`"$bootstrap`" -disableMetrics"
        if ($LASTEXITCODE -ne 0) {
            Fail "vcpkg bootstrap failed"
        }
    }

    if (-not (Test-Path -LiteralPath $toolchain)) {
        Fail "Missing vcpkg toolchain file at $toolchain"
    }

    return [pscustomobject]@{
        Toolchain = $toolchain
        Exe = $vcpkgExe
    }
}

function Get-CudaRoot {
    param(
        $Tools,
        [string]$RequestedRoot
    )

    if ($RequestedRoot) {
        $candidate = Resolve-NormalPath -Path $RequestedRoot
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
        Fail "Requested CUDAToolkitRoot does not exist: $RequestedRoot"
    }

    if ($env:CUDA_PATH -and (Test-Path -LiteralPath $env:CUDA_PATH)) {
        return (Resolve-Path -LiteralPath $env:CUDA_PATH).Path
    }

    $nvcc = Get-CommandPath -Name "nvcc.exe"
    if ($nvcc) {
        return Split-Path -Parent (Split-Path -Parent $nvcc)
    }

    $candidates = Get-ChildItem -Path "C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA" -Directory -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending
    if ($candidates) {
        return $candidates[0].FullName
    }

    if ($InstallDependencies -and $InstallCudaToolkit) {
        $winget = $Tools.Winget
        if (-not $winget) {
            $winget = Assert-Winget
        }
        Install-WingetPackage -Winget $winget -Id "Nvidia.CUDA" -Label "NVIDIA CUDA Toolkit"
        $postInstall = Get-CudaRoot -Tools $Tools -RequestedRoot ""
        if ($postInstall) {
            return $postInstall
        }
    }

    return $null
}

function Invoke-BatchFile {
    param(
        [string[]]$Lines,
        [string]$Label
    )

    $tempFile = Join-Path $env:TEMP ("btx-windows-" + [System.Guid]::NewGuid().ToString("N") + ".cmd")
    try {
        Set-Content -LiteralPath $tempFile -Encoding Ascii -Value ($Lines -join "`r`n")
        Write-Step $Label
        & cmd.exe /d /s /c "`"$tempFile`""
        if ($LASTEXITCODE -ne 0) {
            Fail "$Label failed with exit code $LASTEXITCODE"
        }
    } finally {
        Remove-Item -LiteralPath $tempFile -ErrorAction SilentlyContinue
    }
}

function Get-BinaryPath {
    param(
        [string]$Root,
        [string]$Name
    )

    $candidates = @(
        (Join-Path $Root ("bin\" + $Name + ".exe")),
        (Join-Path $Root ("bin\Release\" + $Name + ".exe")),
        (Join-Path $Root ("bin\RelWithDebInfo\" + $Name + ".exe")),
        (Join-Path $Root ("bin\Debug\" + $Name + ".exe"))
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }
    Fail "Expected binary was not produced in $Root\bin for target $Name"
}

function Invoke-SmokeTest {
    param(
        [string]$BuildRoot
    )

    $daemon = Get-BinaryPath -Root $BuildRoot -Name "btxd"
    $cli = Get-BinaryPath -Root $BuildRoot -Name "btx-cli"

    $smokeDir = Join-Path $env:TEMP ("btx-windows-smoke-" + [System.Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $smokeDir -Force | Out-Null
    $nodeProcess = $null

    try {
        Write-Step "Running regtest smoke test in $smokeDir"
        $nodeProcess = Start-Process -FilePath $daemon -ArgumentList @(
            "-regtest",
            "-datadir=$smokeDir",
            "-fallbackfee=0.0001"
        ) -PassThru -WindowStyle Hidden

        $ready = $false
        for ($i = 0; $i -lt 60; $i++) {
            try {
                & $cli "-regtest" "-datadir=$smokeDir" getblockcount *> $null
                if ($LASTEXITCODE -eq 0) {
                    $ready = $true
                    break
                }
            } catch {
            }
            Start-Sleep -Seconds 1
        }
        if (-not $ready) {
            Fail "Regtest node did not become RPC-ready during smoke test"
        }

        & $cli "-regtest" "-datadir=$smokeDir" createwallet smoke | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Fail "createwallet failed during smoke test"
        }

        $address = (& $cli "-regtest" "-datadir=$smokeDir" "-rpcwallet=smoke" getnewaddress).Trim()
        if ([string]::IsNullOrWhiteSpace($address)) {
            Fail "Failed to create a smoke-test mining address"
        }

        & $cli "-regtest" "-datadir=$smokeDir" "-rpcwallet=smoke" generatetoaddress 1 $address | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Fail "generatetoaddress failed during smoke test"
        }

        $count = (& $cli "-regtest" "-datadir=$smokeDir" getblockcount).Trim()
        if ($count -ne "1") {
            Fail "Unexpected regtest block count after smoke test mining: $count"
        }

        Write-Step "Smoke test passed"
    } finally {
        try {
            & $cli "-regtest" "-datadir=$smokeDir" stop | Out-Null
        } catch {
        }
        if ($nodeProcess) {
            try {
                Wait-Process -Id $nodeProcess.Id -Timeout 10 -ErrorAction SilentlyContinue
            } catch {
            }
            if (-not $nodeProcess.HasExited) {
                Stop-Process -Id $nodeProcess.Id -Force -ErrorAction SilentlyContinue
            }
        }
        Start-Sleep -Seconds 2
        Remove-Item -LiteralPath $smokeDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ([string]::IsNullOrWhiteSpace($SourceDir)) {
    $SourceDir = Resolve-NormalPath -Path (Join-Path $PSScriptRoot "..\..")
} else {
    $SourceDir = Resolve-NormalPath -Path $SourceDir
}
if (-not (Test-Path -LiteralPath $SourceDir)) {
    Fail "SourceDir does not exist: $SourceDir"
}

if ([string]::IsNullOrWhiteSpace($BuildDir)) {
    $BuildDir = Join-Path $SourceDir "build-windows-msvc"
}
$BuildDir = Resolve-NormalPath -Path $BuildDir -CreateDirectory
$VcpkgRoot = Resolve-NormalPath -Path $VcpkgRoot -CreateDirectory
$VcpkgInstalledDir = Resolve-NormalPath -Path $VcpkgInstalledDir -CreateDirectory
$VcpkgBuildtreesRoot = Resolve-NormalPath -Path $VcpkgBuildtreesRoot -CreateDirectory

if ($SourceDir.Contains(" ")) {
    Write-Step "Source path contains spaces. The wrapper will keep vcpkg state on short paths, but cloning to a short path like C:\src\btx-node is still recommended."
}

$tools = Ensure-CoreDependencies -NeedPython:$BuildTests
$vcpkg = Ensure-Vcpkg -Git $tools.Git -Root $VcpkgRoot

$triplet = if ($UseStaticTriplet) { "x64-windows-static" } else { "x64-windows" }
$buildGuiValue = if ($BuildGui) { "ON" } else { "OFF" }
$buildBenchValue = if ($BuildBench) { "ON" } else { "OFF" }
$buildTestsValue = if ($BuildTests) { "ON" } else { "OFF" }
$cudaValue = if ($EnableCudaExperimental) { "ON" } else { "OFF" }
$features = New-Object System.Collections.Generic.List[string]
$features.Add("wallet")
if ($BuildTests) {
    $features.Add("tests")
}
if ($BuildGui) {
    $features.Add("qt5")
}
$manifestFeatures = ($features.ToArray() -join ";")

$cudaRoot = $null
$nvcc = $null
if ($EnableCudaExperimental) {
    $cudaRoot = Get-CudaRoot -Tools $tools -RequestedRoot $CudaToolkitRoot
    if (-not $cudaRoot) {
        Fail "CUDA was requested but no CUDA toolkit was found. Install it manually or rerun with -InstallDependencies -InstallCudaToolkit."
    }
    $nvcc = Join-Path $cudaRoot "bin\nvcc.exe"
    if (-not (Test-Path -LiteralPath $nvcc)) {
        Fail "CUDA toolkit root is missing nvcc.exe: $nvcc"
    }
}

$cmakeArgs = @(
    "cmake",
    "-S", "`"$SourceDir`"",
    "-B", "`"$BuildDir`"",
    "-G", "`"Visual Studio 17 2022`"",
    "-A", "x64",
    "-DCMAKE_TOOLCHAIN_FILE=`"$($vcpkg.Toolchain)`"",
    "-DVCPKG_TARGET_TRIPLET=$triplet",
    "-DVCPKG_INSTALLED_DIR=`"$VcpkgInstalledDir`"",
    "-DVCPKG_INSTALL_OPTIONS=--x-buildtrees-root=$VcpkgBuildtreesRoot",
    "-DVCPKG_MANIFEST_NO_DEFAULT_FEATURES=ON",
    "-DVCPKG_MANIFEST_FEATURES=$manifestFeatures",
    "-DBUILD_DAEMON=ON",
    "-DBUILD_CLI=ON",
    "-DBUILD_UTIL=ON",
    "-DBUILD_TX=ON",
    "-DBUILD_WALLET_TOOL=OFF",
    "-DBUILD_GUI=$buildGuiValue",
    "-DBUILD_BENCH=$buildBenchValue",
    "-DBUILD_TESTS=$buildTestsValue",
    "-DENABLE_WALLET=ON",
    "-DWITH_SQLITE=ON",
    "-DBTX_ENABLE_CUDA_EXPERIMENTAL=$cudaValue",
    "-DWARN_INCOMPATIBLE_BDB=OFF"
)

if ($EnableCudaExperimental) {
    $cmakeArgs += "-DBTX_CUDA_ARCHITECTURES=$CudaArchitectures"
    $cmakeArgs += "-DCUDAToolkit_ROOT=`"$cudaRoot`""
    $cmakeArgs += "-DCMAKE_CUDA_COMPILER=`"$nvcc`""
}

$configureLines = @(
    "@echo off",
    "setlocal enableextensions",
    "call `"$($tools.VsDevCmd)`" -arch=x64 -host_arch=x64 >nul || exit /b 1",
    "set `"VCPKG_ROOT=$VcpkgRoot`"",
    ($cmakeArgs -join " ")
)
Invoke-BatchFile -Lines $configureLines -Label "Configuring Windows build"

$buildLines = @(
    "@echo off",
    "setlocal enableextensions",
    "call `"$($tools.VsDevCmd)`" -arch=x64 -host_arch=x64 >nul || exit /b 1",
    "cmake --build `"$BuildDir`" --config $Configuration --parallel || exit /b 1"
)
if ($Install) {
    if ([string]::IsNullOrWhiteSpace($InstallDir)) {
        Fail "InstallDir must be supplied when -Install is used."
    }
    $InstallDir = Resolve-NormalPath -Path $InstallDir -CreateDirectory
    $buildLines += "cmake --install `"$BuildDir`" --config $Configuration --prefix `"$InstallDir`" || exit /b 1"
}
Invoke-BatchFile -Lines $buildLines -Label "Building BTX for Windows"

if (-not $SkipSmokeTest) {
    Invoke-SmokeTest -BuildRoot $BuildDir
}

$daemon = Get-BinaryPath -Root $BuildDir -Name "btxd"
$cli = Get-BinaryPath -Root $BuildDir -Name "btx-cli"

Write-Host ""
Write-Step "Build completed successfully"
Write-Host "  daemon: $daemon"
Write-Host "  cli:    $cli"
if (Test-Path -LiteralPath (Join-Path $BuildDir "bin\btx-wallet.exe")) {
    Write-Host "  wallet: $(Join-Path $BuildDir 'bin\btx-wallet.exe')"
}
if ($EnableCudaExperimental -and (Test-Path -LiteralPath (Join-Path $BuildDir "bin\btx-matmul-backend-info.exe"))) {
    Write-Host "  backend info: $(Join-Path $BuildDir 'bin\btx-matmul-backend-info.exe')"
}

Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Start the node: Start-Process -FilePath `"$daemon`""
Write-Host "  2. Create a mining wallet: `"$cli`" createwallet miningwallet"
Write-Host "  3. Create a payout address: `"$cli`" -rpcwallet=miningwallet getnewaddress"
Write-Host "  4. Wait for full sync, then begin solo mining with the Windows guide in doc\build-windows-msvc.md"
