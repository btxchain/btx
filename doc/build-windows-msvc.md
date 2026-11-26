# Windows / MSVC Build Guide

This guide describes how to build bitcoind, command-line utilities, and GUI on Windows using Microsoft Visual Studio.

For cross-compiling options, please see [`build-windows.md`](./build-windows.md).

## Preparation

### 1. Visual Studio

This guide relies on using CMake and vcpkg package manager provided with the Visual Studio installation.
Here are requirements for the Visual Studio installation:
1. Minimum required version: Visual Studio 2022 version 17.6.
2. Installed components:
- The "Desktop development with C++" workload.

The commands in this guide should be executed in "Developer PowerShell for VS 2022" or "Developer Command Prompt for VS 2022".
The former is assumed hereinafter.

### 2. Git

Download and install [Git for Windows](https://git-scm.com/download/win). Once installed, Git is available from PowerShell or the Command Prompt.

### 3. Clone Bitcoin Repository

Clone the Bitcoin Core repository to a directory. All build scripts and commands will run from this directory.
```
git clone https://github.com/bitcoin/bitcoin.git
```


## Triplets and Presets

The Bitcoin Core project supports the following vcpkg triplets:
- `x64-windows` (both CRT and library linkage is dynamic)
- `x64-windows-static` (both CRT and library linkage is static)

To facilitate build process, the Bitcoin Core project provides presets, which are used in this guide.

Available presets can be listed as follows:
```
cmake --list-presets
```

By default, all presets set `BUILD_GUI` to `ON`.

## Building

CMake will put the resulting object files, libraries, and executables into a dedicated build directory.

In the following instructions, the "Debug" configuration can be specified instead of the "Release" one.

### 4. Building with Static Linking with GUI

```
cmake -B build --preset vs2022-static          # It might take a while if the vcpkg binary cache is unpopulated or invalidated.
cmake --build build --config Release           # Append "-j N" for N parallel jobs.
ctest --test-dir build --build-config Release  # Append "-j N" for N parallel tests. Some tests are disabled if Python 3 is not available.
cmake --install build --config Release         # Optional.
```

### 5. Building with Dynamic Linking without GUI

```
cmake -B build --preset vs2022 -DBUILD_GUI=OFF # It might take a while if the vcpkg binary cache is unpopulated or invalidated.
cmake --build build --config Release           # Append "-j N" for N parallel jobs.
ctest --test-dir build --build-config Release  # Append "-j N" for N parallel tests. Some tests are disabled if Python 3 is not available.
```

### 6. Packaging a Generic Windows CLI Archive

For a generic Windows x64 archive from the BTX tree, use the
`windows-clangcl-static` preset. This path builds the daemon / CLI subset with
`clang-cl` plus Ninja, avoids machine-specific tuning, and produces the same
`windows-x86_64` archive shape used by the release helpers.

Make sure `clang-cl` and `ninja` are available on `PATH` before running the
commands below. One-time setup on a fresh Windows machine can be done with:

```powershell
choco install llvm ninja -y
```

Then configure, build, and package. If `nvcc` is on `PATH`, CMake turns the CUDA backend on and then stops because `BTX_CUDA_ARCHITECTURES` is empty. Pass `-DBTX_ENABLE_CUDA_EXPERIMENTAL=OFF` for a CPU build, or set the architectures for a CUDA build:

```powershell
cmake --preset windows-clangcl-static
cmake --build build --target btxd btx-cli
python scripts/release/package_release_archive.py --output-dir build\release --version <version> --platform-id windows-x86_64 --btxd build\bin\btxd.exe --btx-cli build\bin\btx-cli.exe
```

The resulting `build\release\btx-<version>-x86_64-w64-mingw32.zip` archive
contains `btxd.exe`, `btx-cli.exe`, and the helper files listed in
[`scripts/release/support_files.txt`](/scripts/release/support_files.txt).
This branch also includes a ready-made generic archive and checksum under
`contrib\prebuilt\windows\`.

### 7. vcpkg-specific Issues and Workarounds

vcpkg installation during the configuration step might fail for various reasons unrelated to Bitcoin Core.

If the failure is due to a "Buildtrees path … is too long" error, which is often encountered when building
with `BUILD_GUI=ON` and using the default vcpkg installation provided by Visual Studio, you can
specify a shorter path to store intermediate build files by using
the [`--x-buildtrees-root`](https://learn.microsoft.com/en-us/vcpkg/commands/common-options#buildtrees-root) option:

```powershell
cmake -B build --preset vs2022-static -DVCPKG_INSTALL_OPTIONS="--x-buildtrees-root=C:\vcpkg"
```

If vcpkg installation fails with the message "Paths with embedded space may be handled incorrectly", which
can occur if your local Bitcoin Core repository path contains spaces, you can override the vcpkg install directory
by setting the [`VCPKG_INSTALLED_DIR`](https://github.com/microsoft/vcpkg-docs/blob/main/vcpkg/users/buildsystems/cmake-integration.md#vcpkg_installed_dir) variable:

```powershell
cmake -B build --preset vs2022-static -DVCPKG_INSTALLED_DIR="C:\path_without_spaces"
```

## Performance Notes

### 8. vcpkg Manifest Default Features

One can skip vcpkg manifest default features to speedup the configuration step.
For example, the following invocation will skip all features except for "wallet" and "tests" and their dependencies:
```
cmake -B build --preset vs2022 -DVCPKG_MANIFEST_NO_DEFAULT_FEATURES=ON -DVCPKG_MANIFEST_FEATURES="wallet;tests" -DBUILD_GUI=OFF
```

Available features are listed in the [`vcpkg.json`](/vcpkg.json) file.

### 9. Antivirus Software

To improve the build process performance, one might add the Bitcoin repository directory to the Microsoft Defender Antivirus exclusions. A scanner can also quarantine `bitcoind.cpp.obj` as a miner. The link then fails with an undefined `main`, and the file has to be allowed before `btxd` will link.

## BTX on this tree

`contrib/devtools/build-btx-windows.ps1` is the Windows configure-and-build entry. SwapNet is part of the node, so the script installs Python 3.11 and the pin in `contrib/swapnet/requirements-tested-runtime.txt` when `-InstallDependencies` is set. That pin is `cryptography==46.0.4`.

The node links that Python. SwapNet's embedded interpreter does not read `PYTHONPATH` or the user site directory. It does load `cryptography` from the configure-time prefix's site-packages, so write access to that Python install is write access to the node. The Linux release archive is different: it points Python at the interpreter shipped under `lib/`.

ModelNet calls `find_package(OpenSSL)` and requires OpenSSL 3.5 or newer. The vcpkg baseline pinned by `vcpkg.json` does not ship that version. Pass `-OpenSSLRoot` to an OpenSSL 3.5 install you built or obtained yourself. The script forwards it as `-DOPENSSL_ROOT_DIR`. A ModelNet build without that prefix fails at configure. `-WithoutModelNet` passes `-DWITH_MODELNET=OFF` and skips the check.

This document does not record a Windows qualification. A Linux host cannot rerun the MSVC compile.
