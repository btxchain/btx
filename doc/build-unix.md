UNIX BUILD NOTES
====================
Some notes on how to build Bitcoin Core in Unix.

(For BSD specific instructions, see `build-*bsd.md` in this directory.)

To Build
---------------------

```bash
cmake -B build
```
Run `cmake -B build -LH` to see the full list of available options.

```bash
cmake --build build    # Append "-j N" for N parallel jobs
cmake --install build  # Optional
```

See below for instructions on how to [install the dependencies on popular Linux
distributions](#linux-distribution-specific-instructions), or the
[dependencies](#dependencies) section for a complete overview.

## Optional: Enable the CUDA MatMul Backend

Linux builds can enable the NVIDIA CUDA MatMul mining backend explicitly.
This is opt-in and requires:

- An NVIDIA driver that supports your GPU
- A working CUDA toolkit / `nvcc`
- An explicit SM architecture list via `BTX_CUDA_ARCHITECTURES`

Example for a toolkit installed in `/usr/local/cuda`:

```bash
cmake -B build \
  -DBTX_ENABLE_CUDA_EXPERIMENTAL=ON \
  -DCUDAToolkit_ROOT=/usr/local/cuda \
  -DCMAKE_CUDA_COMPILER=/usr/local/cuda/bin/nvcc \
  -DBTX_CUDA_ARCHITECTURES=120

cmake --build build -j"$(nproc)"
```

CUDA development and validation for the Linux backend were performed against
CUDA Toolkit `13.2`, the current CUDA Toolkit documentation line as of April
2026, installed at `/usr/local/cuda`. On this workstation,
`/usr/local/cuda/bin/nvcc --version` reports `release 13.2, V13.2.51`.

Use the correct SM value for your GPU. `BTX_CUDA_ARCHITECTURES` also accepts a
semicolon-separated list.

After building, confirm that the backend is available on the local machine:

```bash
./build/bin/btx-matmul-backend-info --backend cuda
```

If CUDA runtime probing succeeds, the output will report:

- `"active_backend": "cuda"`
- `"reason": "ready"`

For current CUDA runtime defaults, pool behavior, and optimization notes, see
`btx-cuda-matmul-optimization-notes-2026-04-13.md`.

## Tuning the Metal MatMul accelerator (`BTX_MATMUL_*` environment variables)

On Apple Silicon, the MatMul mining / accelerated-solve paths are tuned by
environment variables rather than `btxd` command-line flags. They are read
directly inside `src/matmul/`, `src/metal/`, and `src/pow.cpp`; none appear
in `btxd -?`. Defaults work for most operators, but they are mostly
auto-tuned from backend and host heuristics rather than fixed constants. On
Apple Silicon, conservative hosts can still resolve to a single solver
thread by default, while higher-performance Macs fan out more aggressively.
This section lists the operationally relevant ones for the Metal backend; for
the complete inventory, search the source tree for `getenv("BTX_MATMUL_`.
CUDA-specific tuning knobs are documented separately.

These knobs affect mining throughput and accelerator diagnostics; consensus
Phase 2 validation still falls back to the CPU-canonical path. After setting
any variable, restart `btxd`. To inspect how the current tree would resolve a
backend request, use:

```bash
btx-matmul-backend-info --backend metal
```

### Backend selection

| Variable | Purpose | Default |
|---|---|---|
| `BTX_MATMUL_BACKEND` | Select accelerator backend: `cpu`, `metal`, `mlx`, or `cuda`. (`mlx` is an alias for `metal`.) | Platform default: `metal` on Apple, `cpu` elsewhere. |

On macOS source builds, MatMul and oracle Metal kernels are precompiled into build-tree `.metallib`
artifacts by default (`BTX_MATMUL_METAL_PRECOMPILE_KERNELS=ON`). The runtime loads those libraries first
and falls back to embedded source compilation only if the precompiled files are unavailable or the option
is disabled. This preserves the v0.30 developer path and avoids making normal local builds depend on
`MTLCompilerService` runtime source compilation.

### Mining throughput (`SolveMatMul`)

These govern how many in-flight matmul solves the daemon runs in parallel
during `generatetoaddress` / `getblocktemplate` mining. On current `main`,
the active Metal policy auto-tunes several of these when unset instead of
using fixed constants.

| Variable | Purpose | Default |
|---|---|---|
| `BTX_MATMUL_SOLVER_THREADS` | Number of parallel solver threads inside a single `SolveMatMul` call. Triggers the `SolveMatMulParallel` path in `src/pow.cpp` when `> 1`. | Auto-tuned by backend/host heuristics when unset. |
| `BTX_MATMUL_PREPARE_WORKERS` | Number of workers that prepare next-window inputs ahead of the solve. | Auto-tuned from host/backend heuristics when unset. |
| `BTX_MATMUL_PREPARE_PREFETCH_DEPTH` | How many windows ahead the prepare workers stage. Trades memory for steady-state throughput. | Backend-specific; usually small single digits. |
| `BTX_MATMUL_SOLVE_BATCH_SIZE` | Batch size submitted to the accelerated solver per call. | Backend-specific. |
| `BTX_MATMUL_NONCE_SEED_BATCH_SIZE` | Exact post-`nMatMulNonceSeedHeight` GPU nonce-seed batch size. Overrides backend auto sizing. | Backend-specific auto sizing when unset. |
| `BTX_MATMUL_NONCE_SEED_SCAN_MULTIPLIER` | Post-`nMatMulNonceSeedHeight` GPU prehash scan-window multiplier. Values are clamped to `1..8`. | `1` |
| `BTX_MATMUL_CUDA_NONCE_SEED_MEMORY_PERCENT` | Fraction of the first selected CUDA device's global memory used to cap CUDA nonce-seed auto batch sizing. | `25` |
| `BTX_MATMUL_PIPELINE_ASYNC` | Set to `1` to enable asynchronous pipelining of prepare and solve stages. | On for Metal when unset. |

A reasonable starting point on an Apple Silicon workstation with the Metal
backend active:

```bash
export BTX_MATMUL_SOLVER_THREADS=8
export BTX_MATMUL_PIPELINE_ASYNC=1
btxd -daemon
```

### Metal-specific knobs (Apple Silicon)

| Variable | Purpose | Default |
|---|---|---|
| `BTX_MATMUL_METAL_POOL_SLOTS` | Number of Metal command-buffer slots in the in-flight pool. Increase to overlap more solves on the GPU; decrease to cap GPU memory pressure. | Auto-tuned from solver-thread / Apple perf-level heuristics when unset. |
| `BTX_MATMUL_METAL_PIPELINE` | Select the Metal transcript pipeline mode (`auto`, `legacy`, `fused`). | Backend-default. |
| `BTX_MATMUL_METAL_FUNCTION_CONSTANTS` | Override Metal function-constant specialization for transcript kernels. | Backend-default. |
| `BTX_MATMUL_GPU_INPUTS` | Generate matmul inputs on the GPU instead of the CPU before the solve. Apple Metal auto-enables this for the production 512x16x8 mining shape; set `0` to force it off. | Backend-decided. |
| `BTX_MATMUL_APPLE_PERFLEVEL0_LOGICALCPU_OVERRIDE` | Override Apple Silicon perf-level-0 logical CPU count used in launch-rate tuning heuristics. Useful for benchmarking on machines whose reported perf-level partitions differ from the host's actual sustained-throughput core count. | Auto-detected. |

### Diagnostic / special-purpose knobs

Safe to leave unset. Useful when investigating a regression, comparing
backends, or changing guard-rail behavior on a dedicated mining host.

| Variable | Purpose | Default |
|---|---|---|
| `BTX_MATMUL_MEM_DIAG` | Logs per-solve memory and backend stats to `debug.log`. Verbose. | Off unless set. |
| `BTX_MATMUL_DIAG_COMPARE_CPU_METAL` | Cross-checks Metal results against a CPU recompute. Adds latency; useful for backend-correctness investigation. | Off unless set. |
| `BTX_MATMUL_CPU_CONFIRM` | Confirms an accelerated solve with a CPU recompute before accepting it. | On for Metal/CUDA when unset. |
| `BTX_MATMUL_AMX_EXPERIMENT` | Apple AMX experimental matrix path (opt-in for benchmarking). | Off unless set. |
| `BTX_MATMUL_BLOCKED_MULTIPLY_THREADS` | Threads for the blocked CPU matmul fallback. | Backend / host default when unset. |
| `BTX_MATMUL_NOISE_PARALLEL` | Parallelism in the noise-generation stage. | Backend / host default when unset. |
| `BTX_MATMUL_DIGEST_SLICE_SIZE` | Slice size for digest construction. | Backend default when unset. |
| `BTX_MATMUL_TIP_WATCHER` | Enables the tip watcher during long solves. | On when unset. |

## Initial Block Download

A new BTX node syncs the chain from peers via standard initial block download
(IBD). On a healthy connection with 8+ peers, IBD currently runs at roughly
100–200 blocks/min (varies with disk speed, CPU, and peer reachability), so a
fresh node reaches the current tip in a few hours.

### Snapshot loading (`loadtxoutset`)

The release publishes `snapshot.dat` alongside each binary release, intended as
a faster alternative to plain IBD via the `loadtxoutset` RPC. Use the latest
snapshot published for the release you are installing. Verify the release
checksum/signature artifacts first, start `btxd`, wait until the manifest's
base block hash is known in the local header chain, then load the snapshot:

```bash
SNAPSHOT_BLOCKHASH="$(jq -r .blockhash /path/to/snapshot.manifest.json)"
btx-cli getblockheader "$SNAPSHOT_BLOCKHASH" false
```

```bash
btx-cli -rpcclienttimeout=0 loadtxoutset /path/to/snapshot.dat
```

The `-rpcclienttimeout=0` flag prevents the CLI from giving up while the daemon
deserializes the snapshot (the load can take several minutes on large
chainstates). The base header is the readiness gate; the full snapshot base
block does not need to be downloaded before `loadtxoutset`.

For miner-oriented `btx.conf` settings and an end-to-end operator procedure,
see [Assumeutxo Usage](assumeutxo.md),
[BTX Download-and-Go Guide](btx-download-and-go.md), and
[BTX Mining Node Snapshot Runbook](btx-mining-node-snapshot-runbook.md).

## Memory Requirements

C++ compilers are memory-hungry. It is recommended to have at least 1.5 GB of
memory available when compiling Bitcoin Core. On systems with less, gcc can be
tuned to conserve memory with additional `CMAKE_CXX_FLAGS`:


    cmake -B build -DCMAKE_CXX_FLAGS="--param ggc-min-expand=1 --param ggc-min-heapsize=32768"

Alternatively, or in addition, debugging information can be skipped for compilation.
For the default build type `RelWithDebInfo`, the default compile flags are
`-O2 -g`, and can be changed with:

    cmake -B build -DCMAKE_CXX_FLAGS_RELWITHDEBINFO="-O2 -g0"

Finally, clang (often less resource hungry) can be used instead of gcc, which is used by default:

    cmake -B build -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_C_COMPILER=clang

## Linux Distribution Specific Instructions

### Ubuntu & Debian

#### Dependency Build Instructions

Build requirements:

    sudo apt-get install build-essential cmake pkgconf python3

Now, you can either build from self-compiled [depends](#dependencies) or install the required dependencies:

    sudo apt-get install libevent-dev libboost-dev

SQLite is required for the descriptor wallet:

    sudo apt install libsqlite3-dev

Berkeley DB is only required for the legacy wallet. Ubuntu and Debian have their own `libdb-dev` and `libdb++-dev` packages,
but these will install Berkeley DB 5.3 or later. This will break binary wallet compatibility with the distributed
executables, which are based on BerkeleyDB 4.8. Otherwise, you can build Berkeley DB [yourself](#berkeley-db).

To build Bitcoin Core without wallet, see [*Disable-wallet mode*](#disable-wallet-mode)

Optional port mapping library (see: `-DWITH_MINIUPNPC=ON`):

    sudo apt install libminiupnpc-dev

ZMQ-enabled binaries are compiled with `-DWITH_ZMQ=ON` and require the following dependency:

    sudo apt-get install libzmq3-dev

User-Space, Statically Defined Tracing (USDT) dependencies:

    sudo apt install systemtap-sdt-dev

GUI dependencies:

Bitcoin Core includes a GUI built with the cross-platform Qt Framework. To compile the GUI, we need to install
the necessary parts of Qt and some image processing tools, and pass `-DBUILD_GUI=ON` to cmake.
Skip if you don't intend to use the GUI.

    sudo apt-get install qtbase5-dev qttools5-dev qttools5-dev-tools librsvg2-bin imagemagick

Additionally, to support Wayland protocol for modern desktop environments:

    sudo apt install qtwayland5

The GUI will be able to encode addresses in QR codes unless this feature is explicitly disabled. To install libqrencode, run:

    sudo apt-get install libqrencode-dev

Otherwise, if you don't need QR encoding support, use the `-DWITH_QRENCODE=OFF` option to disable this feature in order to compile the GUI.

Note: You can also build with Qt 6 (instead of Qt 5) by passing `-DWITH_QT_VERSION=6` to cmake.


### Fedora

#### Dependency Build Instructions

Build requirements:

    sudo dnf install gcc-c++ cmake make python3

Now, you can either build from self-compiled [depends](#dependencies) or install the required dependencies:

    sudo dnf install libevent-devel boost-devel

SQLite is required for the descriptor wallet:

    sudo dnf install sqlite-devel

Berkeley DB is only required for the legacy wallet. Fedora releases have only `libdb-devel` and `libdb-cxx-devel` packages, but these will install
Berkeley DB 5.3 or later. This will break binary wallet compatibility with the distributed executables, which
are based on Berkeley DB 4.8. Otherwise, you can build Berkeley DB [yourself](#berkeley-db).

To build Bitcoin Core without wallet, see [*Disable-wallet mode*](#disable-wallet-mode)

Optional port mapping library (see: `-DWITH_MINIUPNPC=ON`):

    sudo dnf install miniupnpc-devel

ZMQ-enabled binaries are compiled with `-DWITH_ZMQ=ON` and require the following dependency:

    sudo dnf install zeromq-devel

User-Space, Statically Defined Tracing (USDT) dependencies:

    sudo dnf install systemtap-sdt-devel

GUI dependencies:

Bitcoin Core includes a GUI built with the cross-platform Qt Framework. To compile the GUI, we need to install
the necessary parts of Qt and some image processing tools, and pass `-DBUILD_GUI=ON` to cmake.
Skip if you don't intend to use the GUI.

    sudo dnf install qt5-qttools-devel qt5-qtbase-devel librsvg2-tools ImageMagick

Additionally, to support Wayland protocol for modern desktop environments:

    sudo dnf install qt5-qtwayland

The GUI will be able to encode addresses in QR codes unless this feature is explicitly disabled. To install libqrencode, run:

    sudo dnf install qrencode-devel

Otherwise, if you don't need QR encoding support, use the `-DWITH_QRENCODE=OFF` option to disable this feature in order to compile the GUI.

## Dependencies

See [dependencies.md](dependencies.md) for a complete overview, and
[depends](/depends/README.md) on how to compile them yourself, if you wish to
not use the packages of your Linux distribution.

### Berkeley DB

The legacy wallet uses Berkeley DB. To ensure backwards compatibility it is
recommended to use Berkeley DB 4.8. If you have to build it yourself, and don't
want to use any other libraries built in depends, you can do:
```bash
make -C depends NO_BOOST=1 NO_LIBEVENT=1 NO_QT=1 NO_SQLITE=1 NO_UPNP=1 NO_ZMQ=1 NO_USDT=1
...
to: /path/to/bitcoin/depends/x86_64-pc-linux-gnu
```
and configure using the following:
```bash
export BDB_PREFIX="/path/to/bitcoin/depends/x86_64-pc-linux-gnu"

cmake -B build -DBerkeleyDB_INCLUDE_DIR:PATH="${BDB_PREFIX}/include" -DWITH_BDB=ON
```

**Note**: Make sure that `BDB_PREFIX` is an absolute path.

**Note**: You only need Berkeley DB if the legacy wallet is enabled (see [*Disable-wallet mode*](#disable-wallet-mode)).

Disable-wallet mode
--------------------
When the intention is to only run a P2P node, without a wallet, Bitcoin Core can
be compiled in disable-wallet mode with:

    cmake -B build -DENABLE_WALLET=OFF

In this case there is no dependency on SQLite or Berkeley DB.

Mining is also possible in disable-wallet mode using the `getblocktemplate` RPC call.

Setup and Build Example: Arch Linux
-----------------------------------
This example lists the steps necessary to setup and build a command line only distribution of the latest changes on Arch Linux:

    pacman --sync --needed cmake boost gcc git libevent make python sqlite librsvg imagemagick
    git clone https://github.com/bitcoinknots/bitcoin.git
    cd bitcoin/
    cmake -B build
    cmake --build build
    ctest --test-dir build
    ./build/bin/btxd

If you intend to work with legacy Berkeley DB wallets, see [Berkeley DB](#berkeley-db) section.
