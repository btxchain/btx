# BTX Windows 11 Compile Handbook

This handbook is the step-by-step Windows 11 path for people who want to
build BTX from source for the first time.

It is written for a normal Windows 11 x64 machine and aims to get you from:

- no local BTX build

to:

- a working `btxd.exe`
- a working `btx-cli.exe`
- a clean first node start
- a clear path toward wallet setup and mining

If you already know the BTX build flow and only want the shorter technical
version, see [build-windows-msvc.md](./build-windows-msvc.md).

## Precompiled Archive on This Branch

If you only want a generic precompiled Windows x64 CLI archive from this
branch, use:

- `contrib\prebuilt\windows\btx-29.4.0-generic-win64-x86_64-w64-mingw32.zip`
- `contrib\prebuilt\windows\btx-29.4.0-generic-win64-x86_64-w64-mingw32.zip.sha256`

## What This Handbook Recommends

For most public Windows users, the best path is:

1. install the required Windows tools
2. clone the repository
3. run the BTX PowerShell wrapper
4. let it build a headless wallet-enabled node
5. verify the binaries
6. start the node
7. create a wallet
8. wait for sync
9. begin mining only after the node is healthy and near tip

This handbook intentionally does **not** start with CUDA. First get the normal
Windows build working. Then add CUDA later if you want to experiment with the
experimental backend.

## Before You Start

### Supported target

- Windows 11 x64

### Recommended machine state

- at least `20-30 GB` free for source, build artifacts, and dependency caches
- much more free space if you plan to keep a full BTX node data directory
- a short source path with no spaces is best

Recommended clone path:

```text
C:\src\btx-node
```

Avoid very long or space-heavy paths if you can.

## Step 1: Install the Required Software

You need:

- Git for Windows
- Visual Studio 2022 Build Tools or Visual Studio 2022 Community
  - with `Desktop development with C++`
- CMake

Recommended:

- Python 3.11

Optional:

- NVIDIA CUDA Toolkit
- Nsight Compute

### One-command `winget` installs

Open PowerShell and run:

```powershell
winget install --id Git.Git --exact --source winget
winget install --id Kitware.CMake --exact --source winget
winget install --id Python.Python.3.11 --exact --source winget
winget install --id Microsoft.VisualStudio.2022.BuildTools --exact --source winget `
  --override "--quiet --wait --norestart --nocache --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
```

Optional CUDA tools:

```powershell
winget install --id Nvidia.CUDA --exact --source winget
winget install --id Nvidia.Nsight.Compute --exact --source winget
```

## Step 2: Download the BTX Source Code

Choose a short path and clone the repository:

```powershell
git clone https://github.com/btxchain/btx.git C:\src\btx
Set-Location C:\src\btx
```

If you already cloned the repo somewhere else, just change into that folder:

```powershell
Set-Location C:\path\to\btx-node
```

## Step 3: Run the Windows Build Wrapper

BTX includes a PowerShell wrapper that captures the Windows lessons we learned
from a real Windows 11 build.

Run:

```powershell
powershell -ExecutionPolicy Bypass -File .\contrib\devtools\build-btx-windows.ps1 `
  -InstallDependencies
```

### What this wrapper does

It will:

- verify Git, CMake, and Visual Studio C++ tools
- install missing pieces with `winget` when asked
- create a standalone `vcpkg` checkout under `C:\btx-deps\vcpkg`
- keep `vcpkg` state on short paths to reduce Windows path-length failures
- configure a wallet-enabled headless BTX build
- build the main node binaries
- run a regtest smoke test so you know the result is actually usable

### Why this is the recommended path

The older upstream-style Windows notes were inherited from Bitcoin Core and do
not match the public BTX build path well enough on their own. This wrapper is
the BTX-specific path.

## Step 4: Confirm the Build Output

With the default settings, the output goes under:

```text
.\build-windows-msvc\bin\Release\
```

The most important files are:

```text
.\build-windows-msvc\bin\Release\btxd.exe
.\build-windows-msvc\bin\Release\btx-cli.exe
```

If those exist, your core Windows build is in good shape.

## Step 5: Start the Node for the First Time

Create a minimal BTX config at:

```text
%APPDATA%\BTX\btx.conf
```

Suggested starting config:

```ini
server=1
listen=1
txindex=1
```

Then start the node:

```powershell
Start-Process -FilePath .\build-windows-msvc\bin\Release\btxd.exe
```

## Step 6: Check That the Node Is Alive

Use the CLI to talk to the node:

```powershell
.\build-windows-msvc\bin\Release\btx-cli.exe getblockchaininfo
.\build-windows-msvc\bin\Release\btx-cli.exe getnetworkinfo
.\build-windows-msvc\bin\Release\btx-cli.exe getmininginfo
```

You want to see:

- the RPC responding normally
- peers connecting
- blocks and headers progressing over time

## Step 7: Create a Wallet

Create a wallet for mining rewards or normal usage:

```powershell
.\build-windows-msvc\bin\Release\btx-cli.exe createwallet miningwallet
.\build-windows-msvc\bin\Release\btx-cli.exe -rpcwallet=miningwallet getnewaddress
```

That new address is where mining rewards can be sent later.

## Step 8: Back Up the Wallet

Back it up after creation, funding, or encryption:

```powershell
.\build-windows-msvc\bin\Release\btx-cli.exe -rpcwallet=miningwallet backupwallet "$HOME\\Desktop\\miningwallet-backup.dat"
```

For long-term safety, also keep copies of wallet metadata and any passphrases in
your own secure storage process.

## Step 9: Wait for Full Sync Before Mining

Do not start mining just because the node launches.

On BTX, the node should be:

- out of initial block download
- near tip
- not paused by the mining chain guard

Check:

```powershell
.\build-windows-msvc\bin\Release\btx-cli.exe getmininginfo
```

Important fields:

- `initialblockdownload`
- `chain_guard.should_pause_mining`
- peer and tip-health related values in `chain_guard`

Only begin mining when:

- `initialblockdownload` is `false`
- `chain_guard.should_pause_mining` is `false`

## Step 10: Start a Basic Solo-Mining Loop

For large-scale production mining, the correct path is still
`getblocktemplate` plus external workers.

If you want a simple local solo-mining loop from Windows PowerShell, you can
use:

```powershell
$Cli = Resolve-Path .\build-windows-msvc\bin\Release\btx-cli.exe
$Address = (& $Cli -rpcwallet=miningwallet getnewaddress).Trim()

while ($true) {
    $info = & $Cli getmininginfo | ConvertFrom-Json
    if (($info.initialblockdownload -eq $false) -and ($info.chain_guard.should_pause_mining -eq $false)) {
        & $Cli -rpcwallet=miningwallet generatetoaddress 1 $Address | Out-Null
    } else {
        Start-Sleep -Seconds 5
    }
}
```

That loop is intentionally conservative. It avoids mining while the node says it
should pause.

## Optional: Add Benchmarks or Tests to the Build

### Build with benchmark targets

```powershell
powershell -ExecutionPolicy Bypass -File .\contrib\devtools\build-btx-windows.ps1 `
  -InstallDependencies `
  -BuildBench
```

### Build with test targets

```powershell
powershell -ExecutionPolicy Bypass -File .\contrib\devtools\build-btx-windows.ps1 `
  -InstallDependencies `
  -BuildTests
```

## Optional: Enable the Experimental CUDA Backend

Only do this after the normal Windows build works.

```powershell
powershell -ExecutionPolicy Bypass -File .\contrib\devtools\build-btx-windows.ps1 `
  -InstallDependencies `
  -InstallCudaToolkit `
  -EnableCudaExperimental `
  -BuildBench
```

Then inspect the backend:

```powershell
.\build-windows-msvc\bin\Release\btx-matmul-backend-info.exe --backend cuda
```

This is optional and experimental. The public Windows build story should start
with the plain CPU-backed path first.

## Troubleshooting

### The build fails in `vcpkg`

Use the wrapper defaults. They are intentionally short:

- `C:\btx-deps\vcpkg`
- `C:\btx-deps\vcpkg_installed\btx-node`
- `C:\btx-deps\vcpkg-buildtrees`

These paths are there to reduce the most common Windows path-length problems.

### My repo path contains spaces

The wrapper helps, but a short path like `C:\src\btx-node` is still the best
choice.

### `btxd.exe` starts but mining does not

Check `getmininginfo` first. Most of the time the node is still syncing or the
chain guard is intentionally pausing mining.

### I want the GUI

Start with the default headless build. Only add `-BuildGui` once the headless
path is already working.

### I want CUDA

Get the normal Windows build working first. Then add CUDA later.

## The Short Version

If you want the minimum reliable public Windows flow, it is this:

```powershell
git clone https://github.com/btxchain/btx.git C:\src\btx
Set-Location C:\src\btx
powershell -ExecutionPolicy Bypass -File .\contrib\devtools\build-btx-windows.ps1 -InstallDependencies
Start-Process -FilePath .\build-windows-msvc\bin\Release\btxd.exe
.\build-windows-msvc\bin\Release\btx-cli.exe createwallet miningwallet
```

Then wait for sync, verify `getmininginfo`, and only mine when the node is
ready.
