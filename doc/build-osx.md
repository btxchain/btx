# macOS Build Guide

This guide covers the supported Apple Silicon build with Metal validation.

This guide describes how to build `btxd`, command-line utilities, and GUI on macOS.

## Preparation

The commands in this guide should be executed in a Terminal application.
macOS comes with a built-in Terminal located in:

```bash
/Applications/Utilities/Terminal.app
```

### 1. Xcode Command Line Tools

The Xcode Command Line Tools are a collection of build tools for macOS.
These tools must be installed in order to build BTX from source.

To install, run the following command from your terminal:

``` bash
xcode-select --install
```

Upon running the command, you should see a popup appear.
Click on `Install` to continue the installation process.

The Command Line Tools alone do not include the Metal compiler used by BTX.
Install full Xcode from the App Store, select it, and download the Metal
toolchain:

```bash
sudo xcode-select --switch /Applications/Xcode.app/Contents/Developer
xcodebuild -downloadComponent MetalToolchain
xcrun -f metal
```

The final command must print a path ending in `/usr/bin/metal`. If it reports
`missing Metal Toolchain`, rerun the `xcodebuild` download before configuring
BTX.

### 2. Homebrew Package Manager

Homebrew is a package manager for macOS that allows one to install packages from the command line easily.
While several package managers are available for macOS, this guide will focus on Homebrew as it is the most popular.
Since the examples in this guide which walk through the installation of a package will use Homebrew, it is recommended that you install it to follow along.
Otherwise, you can adapt the commands to your package manager of choice.

To install the Homebrew package manager, see: https://brew.sh

Note: If you run into issues while installing Homebrew or pulling packages, refer to [Homebrew's troubleshooting page](https://docs.brew.sh/Troubleshooting).

### 3. Install Required Dependencies

The first step is to download the required dependencies.
These dependencies represent the packages required to get a barebones installation up and running.

See [dependencies.md](dependencies.md) for a complete overview.

To install, run the following from your terminal:

```bash
brew install cmake ninja pkgconf boost@1.85 libevent zeromq libomp openssl@3
```

BTX currently uses Boost 1.85 for the macOS release build. Pass its include
directory explicitly during CMake configuration because versioned Homebrew
formulae are keg-only.

### 4. Clone the BTX repository

`git` should already be installed by default on your system.
Now that all the required dependencies are installed, clone BTX into a directory.
All build scripts and commands will run from this directory.

```bash
git clone https://github.com/btxchain/btx.git
cd btx
```

### 5. Install Optional Dependencies

#### Wallet Dependencies

It is not necessary to build wallet functionality to run `btxd` or `btx-qt`.

###### Descriptor Wallet Support

`sqlite` is required to support for descriptor wallets.

macOS ships with a useable `sqlite` package, meaning you don't need to
install anything.

###### Legacy Wallet Support

`berkeley-db@4` is only required to support for legacy wallets.
Skip if you don't intend to use legacy wallets.

``` bash
brew install berkeley-db@4
```
---

#### GUI Dependencies

###### Qt

BTX includes a GUI built with the cross-platform Qt Framework. To compile the GUI, install
Qt, libqrencode and pass `-DBUILD_GUI=ON`. Skip if you don't intend to use the GUI.

``` bash
brew install qt@5
```

Note: Building may fail if Qt 6 is installed (`qt` or `qt@6`)

Note: Building with Qt binaries downloaded from the Qt website is not officially supported.
See the upstream notes in [bitcoin/bitcoin#7714](https://github.com/bitcoin/bitcoin/issues/7714).

###### libqrencode

The GUI will be able to encode addresses in QR codes unless this feature is explicitly disabled. To install libqrencode, run:

``` bash
brew install qrencode
```

Otherwise, if you don't need QR encoding support, you can pass `-DWITH_QRENCODE=OFF` to disable this feature.

---

#### Port Mapping Dependencies

###### miniupnpc

miniupnpc may be used for UPnP port mapping.
Skip if you do not need this functionality.

``` bash
brew install miniupnpc
```

---

#### ZMQ Dependencies

ZMQ is **required** for every shipped `btxd` (`-DWITH_ZMQ=ON`, the CMake
default) and was installed in the required dependency step above. If it was
omitted, install it now:

``` bash
brew install zeromq
```

Apple Silicon Homebrew is not on CMake's default search path. Configure with:

``` bash
export PKG_CONFIG_PATH="/opt/homebrew/lib/pkgconfig"
cmake -B build -DCMAKE_PREFIX_PATH=/opt/homebrew -DWITH_ZMQ=ON
```

CMake prefers static `libzmq.a`, `libevent_*.a`, `libomp.a`, and (when
`WITH_MODELNET=ON`) `libssl.a` / `libcrypto.a` on macOS so the tarball has
no Homebrew load commands. After linking,
`otool -L build/bin/btxd` and `otool -L build/bin/btx-cli` must not list
`/opt/homebrew`, must not list `libzmq` or `libssl` as a dylib, and
`python3 scripts/release/verify_release_btxd.py build/bin/btxd build/bin/btx-cli`
must pass. `strings build/bin/btxd` must contain `Enable publish hash block`
— `-zmqpubhashblock` in the binary without that help text is the 0.33.4.2
silent-publish failure.

### Apple Silicon Metal Release (`macos-arm64-metal`)

ExactReplay, mining, and Native Model Network on Apple Silicon need a
**Metal** `btxd` plus OpenSSL 3.5+ for PQ1. Install:

```bash
brew install cmake ninja pkgconf boost@1.85 libevent zeromq libomp openssl@3 qt qrencode
```

Configure a Release tree (keep `-j1` or `-j2` if another `btxd` is already
using the GPU):

``` bash
export PATH="/opt/homebrew/bin:/usr/bin:$PATH"
export PKG_CONFIG_PATH="/opt/homebrew/lib/pkgconfig"
cmake -S . -B build-metal -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH=/opt/homebrew \
  -DBoost_INCLUDE_DIR="$(brew --prefix boost@1.85)/include" \
  -DWITH_ZMQ=ON \
  -DBTX_ENABLE_METAL=ON \
  -DWITH_MODELNET=ON \
  -DBUILD_GUI=ON -DWITH_QT_VERSION=6 \
  -DBUILD_BENCH=OFF
cmake --build build-metal --target btxd btx-cli btx-util btx-modeld \
  btx-modelcheck btx-open btx-matmul-backend-info btx-qt test_btx -j2
```

CMake precompiles `.metallib` kernels (including Metal 4 TensorOps when
`xcrun metal -std=metal4.0` works) so launchd `btxd` does not need
`MTLCompilerService`. Packaged archives copy those libraries to
`libexec/metal/` beside `btxd.real`. Stage-3 row-leaf and Fp3 LDE loaders
look there before falling back to inline source.

Apple's `/usr/bin/openssl` is LibreSSL and cannot mint ML-DSA-44
certificates. Native Model Network uses Homebrew `openssl@3` (or
`BTX_OPENSSL`) for those files. `otool -L` on `btxd` / `btx-modeld` still
must not list a Homebrew `libssl` dylib — the library is statically linked.

For more information on ZMQ, see: [zmq.md](zmq.md)

---

#### Test Suite Dependencies

There is an included test suite that is useful for testing code changes when developing.
To run the test suite (recommended), you will need to have Python 3 installed:

``` bash
brew install python
```

---

#### Deploy Dependencies

You can [deploy](#3-deploy-optional) a `.zip` containing the BTX application.
It is required that you have `python`, `libicns`, and `librsvg` installed.

``` bash
brew install libicns librsvg
```

Note: Deploying may fail if NPM png2icns is installed. You can remove it with:

``` bash
npm uninstall -g png2icns
```

## Building BTX

### 1. Configuration

There are many ways to configure BTX. Here are a few common examples:

##### Wallet (BDB + SQlite) Support, No GUI:

If `berkeley-db@4` or `sqlite` are not installed, this will throw an error.

``` bash
cmake -B build -DWITH_BDB=ON
```

##### Wallet (only SQlite) and GUI Support:

This enables the GUI.
If `sqlite` or `qt` are not installed, this will throw an error.

``` bash
cmake -B build -DBUILD_GUI=ON
```

##### No Wallet or GUI

``` bash
cmake -B build -DENABLE_WALLET=OFF
```

##### Further Configuration

You may want to dig deeper into the configuration options to achieve your desired behavior.
Examine the output of the following command for a full list of configuration options:

``` bash
cmake -B build -LH
```

### 2. Compile

After configuration, you are ready to compile.
Run the following in your terminal to compile BTX:

``` bash
cmake --build build     # Append "-j N" here for N parallel jobs.
ctest --test-dir build  # Append "-j N" for N parallel tests. Some tests are disabled if Python 3 is not available.
```

### 3. Deploy (optional)

You can also create a  `.zip` containing the `.app` bundle by running the following command:

``` bash
cmake --build build --target deploy
```

## Running BTX

The recommended Apple Silicon build above creates
`./build-metal/bin/btxd` and `./build-metal/bin/btx-cli`. If you configured the
generic `build` directory instead, replace `build-metal` with `build` below.
The optional GUI is `./build-metal/bin/btx-qt`.

The first time you run `btxd` or `btx-qt`, it will start downloading the blockchain.
This process could take many hours, or even days on slower than average systems.

By default, blockchain and wallet data files will be stored in:

``` bash
$HOME/Library/Application Support/BTX/
```

Before running, you may create an empty configuration file:

```shell
mkdir -p "$HOME/Library/Application Support/BTX"

touch "$HOME/Library/Application Support/BTX/btx.conf"

chmod 600 "$HOME/Library/Application Support/BTX/btx.conf"
```

You can monitor the download process by looking at the debug.log file:

```shell
tail -f "$HOME/Library/Application Support/BTX/debug.log"
```

## Troubleshooting

### `cannot execute tool 'metal' due to missing Metal Toolchain`

Full Xcode may be selected while the separately packaged compiler is still
missing. Install it and verify the path:

```bash
xcodebuild -downloadComponent MetalToolchain
xcrun -f metal
```

### Boost headers still come from unversioned Homebrew Boost

If an existing CMake cache still names `/opt/homebrew/opt/boost/include`,
configure a fresh build directory and pass the 1.85 include directory exactly
as shown in the Apple Silicon command above. Do not mix Boost header versions
inside one build directory.

### Linker reports `_pipe2` from `libevent_core.a`

This usually means the Homebrew archive was built against a newer macOS SDK
than the selected developer tools. First install the Command Line Tools update
shown by `softwareupdate --list`. Then rebuild libevent against the selected
SDK:

```bash
brew reinstall --build-from-source libevent
```

### Metal is built but runtime falls back to CPU

Check the selected backend:

```bash
./build-metal/bin/btx-cli getmininginfo
```

If `backend_selection_reason` reports that `MTLCompilerService` is unavailable,
stop the daemon cleanly and keep the process under shell job control instead of
using the daemon re-exec, so it retains access to the logged-in user's Metal
services:

```bash
./build-metal/bin/btx-cli stop
nohup ./build-metal/bin/btxd -server > /tmp/btxd-console.log 2>&1 &
```

## Other commands:

```shell
./build-metal/bin/btxd -daemon -server   # Start the BTX daemon.
./build-metal/bin/btx-cli getsetupstatus # Combined first-run and sync doctor.
./build-metal/bin/btx-cli getblockchaininfo
./build-metal/bin/btx-cli getmininginfo
./build-metal/bin/btx-cli stop            # Shut down cleanly.
./build-metal/bin/btx-cli --help          # List command-line options.
./build-metal/bin/btx-cli help            # List RPC commands while btxd is running.
./build-metal/bin/btx-qt -server          # Start the optional GUI in server mode.
```
