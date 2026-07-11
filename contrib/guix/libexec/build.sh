#!/usr/bin/env bash
# Copyright (c) 2019-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
export LC_ALL=C
set -e -o pipefail
export TZ=UTC

# Although Guix _does_ set umask when building its own packages (in our case,
# this is all packages in manifest.scm), it does not set it for `guix
# shell`. It does make sense for at least `guix shell --container`
# to set umask, so if that change gets merged upstream and we bump the
# time-machine to a commit which includes the aforementioned change, we can
# remove this line.
#
# This line should be placed before any commands which creates files.
umask 0022

if [ -n "$V" ]; then
    # Print both unexpanded (-v) and expanded (-x) forms of commands as they are
    # read from this file.
    set -vx
    # Set VERBOSE for CMake-based builds
    export VERBOSE="$V"
fi

# Check that required environment variables are set
cat << EOF
Required environment variables as seen inside the container:
    DIST_ARCHIVE_BASE: ${DIST_ARCHIVE_BASE:?not set}
    DISTNAME: ${DISTNAME:?not set}
    HOST: ${HOST:?not set}
    GUIX_LINUX_FLAVOR: ${GUIX_LINUX_FLAVOR:=cpu}
    SOURCE_DATE_EPOCH: ${SOURCE_DATE_EPOCH:?not set}
    JOBS: ${JOBS:?not set}
    DISTSRC: ${DISTSRC:?not set}
    OUTDIR: ${OUTDIR:?not set}
EOF

ACTUAL_OUTDIR="${OUTDIR}"
OUTDIR="${DISTSRC}/output"

#####################
# Environment Setup #
#####################

# The depends folder also serves as a base-prefix for depends packages for
# $HOSTs after successfully building.
BASEPREFIX="${PWD}/depends"

# Given a package name and an output name, return the path of that output in our
# current guix environment
store_path() {
    grep --extended-regexp "/[^-]{32}-${1}-[^-]+${2:+-${2}}" "${GUIX_ENVIRONMENT}/manifest" \
        | head --lines=1 \
        | sed --expression='s|\x29*$||' \
              --expression='s|^[[:space:]]*"||' \
              --expression='s|"[[:space:]]*$||'
}


# Set environment variables to point the NATIVE toolchain to the right
# includes/libs
NATIVE_GCC="$(store_path gcc-toolchain)"

unset LIBRARY_PATH
unset CPATH
unset C_INCLUDE_PATH
unset CPLUS_INCLUDE_PATH
unset OBJC_INCLUDE_PATH
unset OBJCPLUS_INCLUDE_PATH

export C_INCLUDE_PATH="${NATIVE_GCC}/include"
export CPLUS_INCLUDE_PATH="${NATIVE_GCC}/include/c++:${NATIVE_GCC}/include"

case "$HOST" in
    *darwin*) export LIBRARY_PATH="${NATIVE_GCC}/lib" ;; # Required for qt/qmake
    *mingw*) export LIBRARY_PATH="${NATIVE_GCC}/lib" ;;
    *)
        NATIVE_GCC_STATIC="$(store_path gcc-toolchain static)"
        export LIBRARY_PATH="${NATIVE_GCC}/lib:${NATIVE_GCC_STATIC}/lib"
        ;;
esac

# Set environment variables to point the CROSS toolchain to the right
# includes/libs for $HOST
case "$HOST" in
    *mingw*)
        # Determine output paths to use in CROSS_* environment variables
        CROSS_GLIBC="$(store_path "mingw-w64-x86_64-winpthreads")"
        CROSS_GCC="$(store_path "gcc-cross-${HOST}")"
        CROSS_GCC_LIB_STORE="$(store_path "gcc-cross-${HOST}" lib)"
        CROSS_GCC_LIBS=( "${CROSS_GCC_LIB_STORE}/lib/gcc/${HOST}"/* ) # This expands to an array of directories...
        CROSS_GCC_LIB="${CROSS_GCC_LIBS[0]}" # ...we just want the first one (there should only be one)

        # The search path ordering is generally:
        #    1. gcc-related search paths
        #    2. libc-related search paths
        #    2. kernel-header-related search paths (not applicable to mingw-w64 hosts)
        export CROSS_C_INCLUDE_PATH="${CROSS_GCC_LIB}/include:${CROSS_GCC_LIB}/include-fixed:${CROSS_GLIBC}/include"
        export CROSS_CPLUS_INCLUDE_PATH="${CROSS_GCC}/include/c++:${CROSS_GCC}/include/c++/${HOST}:${CROSS_GCC}/include/c++/backward:${CROSS_C_INCLUDE_PATH}"
        export CROSS_LIBRARY_PATH="${CROSS_GCC_LIB_STORE}/lib:${CROSS_GCC_LIB}:${CROSS_GLIBC}/lib"
        ;;
    *darwin*)
        # The CROSS toolchain for darwin uses the SDK and ignores environment variables.
        # See depends/hosts/darwin.mk for more details.
        ;;
    *linux*)
        CROSS_GLIBC="$(store_path "glibc-cross-${HOST}")"
        CROSS_GLIBC_STATIC="$(store_path "glibc-cross-${HOST}" static)"
        CROSS_KERNEL="$(store_path "linux-libre-headers-cross-${HOST}")"
        CROSS_GCC="$(store_path "gcc-cross-${HOST}")"
        CROSS_GCC_LIB_STORE="$(store_path "gcc-cross-${HOST}" lib)"
        CROSS_GCC_LIBS=( "${CROSS_GCC_LIB_STORE}/lib/gcc/${HOST}"/* ) # This expands to an array of directories...
        CROSS_GCC_LIB="${CROSS_GCC_LIBS[0]}" # ...we just want the first one (there should only be one)

        export CROSS_C_INCLUDE_PATH="${CROSS_GCC_LIB}/include:${CROSS_GCC_LIB}/include-fixed:${CROSS_GLIBC}/include:${CROSS_KERNEL}/include"
        export CROSS_CPLUS_INCLUDE_PATH="${CROSS_GCC}/include/c++:${CROSS_GCC}/include/c++/${HOST}:${CROSS_GCC}/include/c++/backward:${CROSS_C_INCLUDE_PATH}"
        export CROSS_LIBRARY_PATH="${CROSS_GCC_LIB_STORE}/lib:${CROSS_GCC_LIB}:${CROSS_GLIBC}/lib:${CROSS_GLIBC_STATIC}/lib"
        ;;
    *)
        exit 1 ;;
esac

# Sanity check CROSS_*_PATH directories
IFS=':' read -ra PATHS <<< "${CROSS_C_INCLUDE_PATH}:${CROSS_CPLUS_INCLUDE_PATH}:${CROSS_LIBRARY_PATH}"
for p in "${PATHS[@]}"; do
    if [ -n "$p" ] && [ ! -d "$p" ]; then
        echo "'$p' doesn't exist or isn't a directory... Aborting..."
        exit 1
    fi
done

# Disable Guix ld auto-rpath behavior
export GUIX_LD_WRAPPER_DISABLE_RPATH=yes

# Make /usr/bin if it doesn't exist
[ -e /usr/bin ] || mkdir -p /usr/bin

# Symlink file and env to a conventional path
[ -e /usr/bin/file ] || ln -s --no-dereference "$(command -v file)" /usr/bin/file
[ -e /usr/bin/env ]  || ln -s --no-dereference "$(command -v env)"  /usr/bin/env

ensure_cuda_tool_runtime_environment() {
    case "$HOST:$GUIX_LINUX_FLAVOR" in
        x86_64-linux-gnu:cuda12|x86_64-linux-gnu:cuda13) ;;
        *) return 0 ;;
    esac

    local native_loader fhs_loader
    native_loader="${NATIVE_GCC}/lib/ld-linux-x86-64.so.2"
    fhs_loader="/lib64/ld-linux-x86-64.so.2"

    if [ ! -x "$native_loader" ]; then
        echo "CUDA Guix build requires a native x86_64 dynamic loader at ${native_loader}" >&2
        exit 1
    fi

    [ -e /lib64 ] || mkdir -p /lib64
    if [ -L "$fhs_loader" ] && [ ! -e "$fhs_loader" ]; then
        rm "$fhs_loader"
    fi
    if [ ! -e "$fhs_loader" ]; then
        ln -s --no-dereference "$native_loader" "$fhs_loader"
    fi
    if [ ! -x "$fhs_loader" ]; then
        echo "CUDA Guix build could not create usable dynamic loader path: ${fhs_loader}" >&2
        exit 1
    fi
}

ensure_cuda_tool_runtime_environment

# Determine the correct value for -Wl,--dynamic-linker for the current $HOST
case "$HOST" in
    *linux*)
        glibc_dynamic_linker=$(
            case "$HOST" in
                x86_64-linux-gnu)      echo /lib64/ld-linux-x86-64.so.2 ;;
                arm-linux-gnueabihf)   echo /lib/ld-linux-armhf.so.3 ;;
                aarch64-linux-gnu)     echo /lib/ld-linux-aarch64.so.1 ;;
                riscv64-linux-gnu)     echo /lib/ld-linux-riscv64-lp64d.so.1 ;;
                powerpc64-linux-gnu)   echo /lib64/ld64.so.1;;
                powerpc64le-linux-gnu) echo /lib64/ld64.so.2;;
                *)                     exit 1 ;;
            esac
        )
        ;;
esac

# Environment variables for determinism
export TAR_OPTIONS="--owner=0 --group=0 --numeric-owner --mtime='@${SOURCE_DATE_EPOCH}' --sort=name"
export TZ="UTC"

####################
# Depends Building #
####################

# Build the depends tree, overriding variables that assume multilib gcc
make -C depends --jobs="$JOBS" HOST="$HOST" \
                                   ${V:+V=1} \
                                   ${SOURCES_PATH+SOURCES_PATH="$SOURCES_PATH"} \
                                   ${BASE_CACHE+BASE_CACHE="$BASE_CACHE"} \
                                   ${SDK_PATH+SDK_PATH="$SDK_PATH"} \
                                   x86_64_linux_CC=x86_64-linux-gnu-gcc \
                                   x86_64_linux_CXX=x86_64-linux-gnu-g++ \
                                   x86_64_linux_AR=x86_64-linux-gnu-gcc-ar \
                                   x86_64_linux_RANLIB=x86_64-linux-gnu-gcc-ranlib \
                                   x86_64_linux_NM=x86_64-linux-gnu-gcc-nm \
                                   x86_64_linux_STRIP=x86_64-linux-gnu-strip

case "$HOST" in
    *darwin*)
        # Unset now that Qt is built
        unset C_INCLUDE_PATH
        unset CPLUS_INCLUDE_PATH
        unset LIBRARY_PATH
        ;;
esac

###########################
# Source Tarball Building #
###########################

GIT_ARCHIVE="${DIST_ARCHIVE_BASE}/${DISTNAME}.tar.gz"
GIT_ARCHIVE_HEAD="${DIST_ARCHIVE_BASE}/${DISTNAME}.githead"
CURRENT_HEAD="$(git rev-parse HEAD)"

# Create the source tarball if needed. This uses `git archive HEAD`, so
# source-tree changes must be committed before a Guix rebuild can pick them up.
# When rerunning a build under the same VERSION label from a different commit,
# invalidate the cached archive automatically so the extracted distsrc matches
# the current HEAD.
cached_archive_head=""
if [ -e "$GIT_ARCHIVE_HEAD" ]; then
    cached_archive_head="$(cat "$GIT_ARCHIVE_HEAD")"
fi
if [ ! -e "$GIT_ARCHIVE" ] || [ ! -e "$GIT_ARCHIVE_HEAD" ] || [ "$cached_archive_head" != "$CURRENT_HEAD" ]; then
    mkdir -p "$(dirname "$GIT_ARCHIVE")"
    rm -f "$GIT_ARCHIVE" "$GIT_ARCHIVE_HEAD"
    REFERENCE_DATETIME="@${SOURCE_DATE_EPOCH}" \
    contrib/guix/libexec/make_release_tarball.sh "${GIT_ARCHIVE}" "${DISTNAME}"
    printf '%s\n' "$CURRENT_HEAD" > "$GIT_ARCHIVE_HEAD"
fi

mkdir -p "$OUTDIR"

###########################
# Binary Tarball Building #
###########################

# CONFIGFLAGS
BASE_CONFIGFLAGS="-DREDUCE_EXPORTS=ON -DBUILD_BENCH=OFF -DBUILD_GUI_TESTS=OFF -DBUILD_FUZZ_BINARY=OFF"
# Ship ZMQ notifications in release binaries. WITH_ZMQ defaults OFF in CMakeLists.txt,
# so without this flag the released btxd silently ignores -zmqpub* settings
# ("built without ZMQ support"). libzmq is already provided by the depends system
# (packages.mk: zmq_packages=zeromq, built by default unless NO_ZMQ is set).
BASE_CONFIGFLAGS="$BASE_CONFIGFLAGS -DWITH_ZMQ=ON"
BASE_CONFIGFLAGS="$BASE_CONFIGFLAGS -DCMAKE_SKIP_BUILD_RPATH=TRUE"  # check-symbols is fussy about rpath and we don't need it

make_cuda_host_compiler_wrapper() {
    local host_compiler wrapper_dir wrapper

    host_compiler="$1"
    wrapper_dir="${DISTSRC}/.guix-cuda-host-tools"
    wrapper="${wrapper_dir}/${HOST}-g++"
    mkdir -p "$wrapper_dir"
    {
        printf '%s\n' '#!/usr/bin/env bash'
        printf '%s\n' 'set -e'
        printf 'export CROSS_C_INCLUDE_PATH=%q\n' "$CROSS_C_INCLUDE_PATH"
        printf 'export CROSS_CPLUS_INCLUDE_PATH=%q\n' "$CROSS_CPLUS_INCLUDE_PATH"
        printf 'export CROSS_LIBRARY_PATH=%q\n' "$CROSS_LIBRARY_PATH"
        printf 'export GUIX_LD_WRAPPER_DISABLE_RPATH=%q\n' "$GUIX_LD_WRAPPER_DISABLE_RPATH"
        printf 'exec %q "$@"\n' "$host_compiler"
    } > "$wrapper"
    chmod +x "$wrapper"
    echo "$wrapper"
}

set_cuda_config_for_flavor() {
    local cuda_root cuda_host_compiler

    CUDA_COMPILER_FOR_CMAKE=""
    CUDA_HOST_COMPILER_FOR_CMAKE=""
    CUDA_TOOLKIT_ROOT_FOR_CMAKE=""
    CUDA_TOOL_LIBRARY_PATH=""
    CUDA_LIBRARY_CONFIGFLAGS=""
    CUDA_SMOKE_TEST_ARCH=""
    CUDA_CONFIGFLAGS=""
    CUDA_CMAKE_ENV=()
    CUDA_SYMBOL_CHECK_ENV=()

    case "$HOST:$GUIX_LINUX_FLAVOR" in
        *:default|*:cpu)
            CUDA_CONFIGFLAGS="-DBTX_ENABLE_CUDA_EXPERIMENTAL=OFF"
            ;;
        x86_64-linux-gnu:cuda12)
            cuda_root="$(store_path cuda-toolkit-12.9-btx)"
            cuda_host_compiler="$(command -v x86_64-linux-gnu-g++ || true)"
            if [ -z "$cuda_root" ] || [ ! -x "$cuda_root/bin/nvcc" ]; then
                echo "CUDA 12 Guix toolkit input is missing nvcc" >&2
                exit 1
            fi
            if [ -z "$cuda_host_compiler" ]; then
                echo "CUDA 12 Guix build requires x86_64-linux-gnu-g++ in PATH" >&2
                exit 1
            fi
            cuda_host_compiler="$(make_cuda_host_compiler_wrapper "$cuda_host_compiler")"
            CUDA_COMPILER_FOR_CMAKE="$cuda_root/bin/nvcc"
            CUDA_HOST_COMPILER_FOR_CMAKE="$cuda_host_compiler"
            CUDA_TOOLKIT_ROOT_FOR_CMAKE="$cuda_root"
            CUDA_TOOL_LIBRARY_PATH="$CUDA_TOOLKIT_ROOT_FOR_CMAKE/lib64:$CUDA_TOOLKIT_ROOT_FOR_CMAKE/lib:$CUDA_TOOLKIT_ROOT_FOR_CMAKE/nvvm/lib64:$NATIVE_GCC/lib"
            CUDA_LIBRARY_CONFIGFLAGS="-DCUDA_CUDART=$cuda_root/lib64/libcudart.so -DCUDA_cudart_static_LIBRARY=$cuda_root/lib64/libcudart_static.a -DCUDAToolkit_rt_LIBRARY=$CROSS_GLIBC/lib/librt.so"
            CUDA_SMOKE_TEST_ARCH="80"
            CUDA_CMAKE_ENV=(
                "CUDACXX=$CUDA_COMPILER_FOR_CMAKE"
                "CUDAHOSTCXX=$CUDA_HOST_COMPILER_FOR_CMAKE"
                "CUDA_PATH=$CUDA_TOOLKIT_ROOT_FOR_CMAKE"
                "CUDAToolkit_ROOT=$CUDA_TOOLKIT_ROOT_FOR_CMAKE"
                "LD_LIBRARY_PATH=$CUDA_TOOL_LIBRARY_PATH"
            )
            CUDA_SYMBOL_CHECK_ENV=("BTX_SYMBOL_CHECK_ALLOW_LIBRT=1")
            export LD_LIBRARY_PATH="$CUDA_TOOL_LIBRARY_PATH"
            CUDA_CONFIGFLAGS="-DBTX_ENABLE_CUDA_EXPERIMENTAL=ON -DBTX_CUDA_ARCHITECTURES=80-real;86-real;89-real;90-real;100-real;101-real;103-real;120-real;121-real;80-virtual;100-virtual;120-virtual -DCMAKE_CUDA_ARCHITECTURES=80-real;86-real;89-real;90-real;100-real;101-real;103-real;120-real;121-real;80-virtual;100-virtual;120-virtual -DCUDAToolkit_ROOT=$cuda_root -DCMAKE_CUDA_COMPILER=$CUDA_COMPILER_FOR_CMAKE -DCMAKE_CUDA_HOST_COMPILER=$CUDA_HOST_COMPILER_FOR_CMAKE $CUDA_LIBRARY_CONFIGFLAGS -DCMAKE_CUDA_RUNTIME_LIBRARY=Static -DBTX_CUDA_RUNTIME_LIBRARY=Static"
            ;;
        x86_64-linux-gnu:cuda13)
            cuda_root="$(store_path cuda-toolkit-13-btx)"
            cuda_host_compiler="$(command -v x86_64-linux-gnu-g++ || true)"
            if [ -z "$cuda_root" ] || [ ! -x "$cuda_root/bin/nvcc" ]; then
                echo "CUDA 13 Guix toolkit input is missing nvcc" >&2
                exit 1
            fi
            if [ -z "$cuda_host_compiler" ]; then
                echo "CUDA 13 Guix build requires x86_64-linux-gnu-g++ in PATH" >&2
                exit 1
            fi
            cuda_host_compiler="$(make_cuda_host_compiler_wrapper "$cuda_host_compiler")"
            CUDA_COMPILER_FOR_CMAKE="$cuda_root/bin/nvcc"
            CUDA_HOST_COMPILER_FOR_CMAKE="$cuda_host_compiler"
            CUDA_TOOLKIT_ROOT_FOR_CMAKE="$cuda_root"
            CUDA_TOOL_LIBRARY_PATH="$CUDA_TOOLKIT_ROOT_FOR_CMAKE/lib64:$CUDA_TOOLKIT_ROOT_FOR_CMAKE/lib:$CUDA_TOOLKIT_ROOT_FOR_CMAKE/nvvm/lib64:$NATIVE_GCC/lib"
            CUDA_LIBRARY_CONFIGFLAGS="-DCUDA_CUDART=$cuda_root/lib64/libcudart.so -DCUDA_cudart_static_LIBRARY=$cuda_root/lib64/libcudart_static.a -DCUDAToolkit_rt_LIBRARY=$CROSS_GLIBC/lib/librt.so"
            CUDA_SMOKE_TEST_ARCH="100"
            CUDA_CMAKE_ENV=(
                "CUDACXX=$CUDA_COMPILER_FOR_CMAKE"
                "CUDAHOSTCXX=$CUDA_HOST_COMPILER_FOR_CMAKE"
                "CUDA_PATH=$CUDA_TOOLKIT_ROOT_FOR_CMAKE"
                "CUDAToolkit_ROOT=$CUDA_TOOLKIT_ROOT_FOR_CMAKE"
                "LD_LIBRARY_PATH=$CUDA_TOOL_LIBRARY_PATH"
            )
            CUDA_SYMBOL_CHECK_ENV=("BTX_SYMBOL_CHECK_ALLOW_LIBRT=1")
            export LD_LIBRARY_PATH="$CUDA_TOOL_LIBRARY_PATH"
            CUDA_CONFIGFLAGS="-DBTX_ENABLE_CUDA_EXPERIMENTAL=ON -DBTX_CUDA_ARCHITECTURES=100-real;103-real;110-real;120-real;121-real;100-virtual;120-virtual -DCMAKE_CUDA_ARCHITECTURES=100-real;103-real;110-real;120-real;121-real;100-virtual;120-virtual -DCUDAToolkit_ROOT=$cuda_root -DCMAKE_CUDA_COMPILER=$CUDA_COMPILER_FOR_CMAKE -DCMAKE_CUDA_HOST_COMPILER=$CUDA_HOST_COMPILER_FOR_CMAKE $CUDA_LIBRARY_CONFIGFLAGS -DCMAKE_CUDA_RUNTIME_LIBRARY=Static -DBTX_CUDA_RUNTIME_LIBRARY=Static"
            ;;
        *)
            echo "Unsupported HOST/GUIX_LINUX_FLAVOR combination: $HOST/$GUIX_LINUX_FLAVOR" >&2
            exit 1
            ;;
    esac
}

run_cuda_compiler_smoke_test() {
    case "$HOST:$GUIX_LINUX_FLAVOR" in
        x86_64-linux-gnu:cuda12|x86_64-linux-gnu:cuda13) ;;
        *) return 0 ;;
    esac

    local probe_dir probe_src probe_bin
    probe_dir="${DISTSRC}/.guix-cuda-host-tools/probe"
    probe_src="${probe_dir}/cuda-link-probe.cu"
    probe_bin="${probe_dir}/cuda-link-probe"
    mkdir -p "$probe_dir"
    cat > "$probe_src" <<'EOF'
#include <cuda_runtime.h>

__global__ void btx_cuda_link_probe_kernel() {}

int main()
{
    btx_cuda_link_probe_kernel<<<1, 1>>>();
    return 0;
}
EOF

    echo "INFO: CUDA compiler: ${CUDA_COMPILER_FOR_CMAKE}"
    echo "INFO: CUDA host compiler wrapper: ${CUDA_HOST_COMPILER_FOR_CMAKE}"
    if ! "${CUDA_COMPILER_FOR_CMAKE}" \
            -ccbin "${CUDA_HOST_COMPILER_FOR_CMAKE}" \
            -arch="sm_${CUDA_SMOKE_TEST_ARCH}" \
            -cudart static \
            "$probe_src" \
            -o "$probe_bin"; then
        echo "CUDA nvcc smoke test failed; retrying with verbose compiler output" >&2
        "${CUDA_COMPILER_FOR_CMAKE}" \
            -ccbin "${CUDA_HOST_COMPILER_FOR_CMAKE}" \
            -arch="sm_${CUDA_SMOKE_TEST_ARCH}" \
            -cudart static \
            -v \
            "$probe_src" \
            -o "$probe_bin" >&2
        exit 1
    fi
}

linux_artifact_suffix_for_flavor() {
    case "$HOST:$GUIX_LINUX_FLAVOR" in
        x86_64-linux-gnu:cuda12) echo "-cuda12" ;;
        x86_64-linux-gnu:cuda13) echo "-cuda13" ;;
    esac
}

assert_no_dynamic_cuda_runtime_dependencies() {
    case "$HOST:$GUIX_LINUX_FLAVOR" in
        x86_64-linux-gnu:cuda12|x86_64-linux-gnu:cuda13) ;;
        *) return 0 ;;
    esac

    local readelf_bin
    readelf_bin="$(command -v readelf || true)"
    if [ -z "$readelf_bin" ]; then
        echo "CUDA release dependency check requires readelf in PATH" >&2
        exit 1
    fi

    local failed=0
    local binary
    local dynamic_section
    local needed
    while IFS= read -r -d '' binary; do
        if ! "$readelf_bin" -h "$binary" >/dev/null 2>&1; then
            continue
        fi
        dynamic_section="$("$readelf_bin" -d "$binary" 2>/dev/null || true)"
        needed="$(printf '%s\n' "$dynamic_section" | sed -n 's/.*Shared library: \[\(.*\)\].*/\1/p')"
        if printf '%s\n' "$needed" | grep --extended-regexp '^lib(cudart|cuda)\.so' >/dev/null; then
            echo "CUDA release binary has a dynamic NVIDIA runtime dependency: $binary" >&2
            printf '%s\n' "$needed" | grep --extended-regexp '^lib(cudart|cuda)\.so' >&2
            failed=1
        fi
        if printf '%s\n' "$dynamic_section" | grep --extended-regexp '\((RPATH|RUNPATH)\)' >/dev/null; then
            echo "CUDA release binary has RPATH/RUNPATH entries: $binary" >&2
            printf '%s\n' "$dynamic_section" | grep --extended-regexp '\((RPATH|RUNPATH)\)' >&2
            failed=1
        fi
    done < <(find "${DISTNAME}" -type f -perm /111 -print0)

    if [ "$failed" -ne 0 ]; then
        exit 1
    fi
}

CONSENSUS_CONFIGFLAGS="$BASE_CONFIGFLAGS -DBTX_ENABLE_CUDA_EXPERIMENTAL=OFF"
mkdir -p "$DISTSRC"
set_cuda_config_for_flavor
MAIN_CONFIGFLAGS="$BASE_CONFIGFLAGS $CUDA_CONFIGFLAGS"
LINUX_ARTIFACT_SUFFIX="$(linux_artifact_suffix_for_flavor)"

# CFLAGS
HOST_CFLAGS="-O2 -g"
HOST_CFLAGS+=$(find /gnu/store -maxdepth 1 -mindepth 1 -type d -exec echo -n " -ffile-prefix-map={}=/usr" \;)
case "$HOST" in
    *mingw*)  HOST_CFLAGS+=" -fno-ident" ;;
    *darwin*) unset HOST_CFLAGS ;;
esac

# CXXFLAGS
HOST_CXXFLAGS="$HOST_CFLAGS"

case "$HOST" in
    arm-linux-gnueabihf) HOST_CXXFLAGS="${HOST_CXXFLAGS} -Wno-psabi" ;;
esac

# LDFLAGS
case "$HOST" in
    *linux*)  HOST_LDFLAGS="-Wl,--as-needed -Wl,--dynamic-linker=$glibc_dynamic_linker -static-libstdc++ -Wl,-O2" ;;
    *mingw*)  HOST_LDFLAGS="-Wl,--no-insert-timestamp" ;;
esac

(
    cd "$DISTSRC"

    # Extract the source tarball
    tar --strip-components=1 -xf "${GIT_ARCHIVE}"
    run_cuda_compiler_smoke_test

    # First build libbitcoinconsensus
    # shellcheck disable=SC2086
    env CFLAGS="${HOST_CFLAGS}" CXXFLAGS="${HOST_CXXFLAGS}" LDFLAGS="${HOST_LDFLAGS}" \
    cmake -S . -B build_libbitcoinconsensus \
          --toolchain "${BASEPREFIX}/${HOST}/toolchain.cmake" \
          -DWITH_CCACHE=OFF \
          ${CONSENSUS_CONFIGFLAGS} \
          -DBUILD_BENCH=OFF \
          -DBUILD_CLI=OFF \
          -DBUILD_DAEMON=OFF \
          -DBUILD_FOR_FUZZING=OFF \
          -DBUILD_FUZZ_BINARY=OFF \
          -DBUILD_GUI=OFF \
          -DBUILD_GUI_TESTS=OFF \
          -DBUILD_KERNEL_LIB=OFF \
          -DBUILD_TESTS=OFF \
          -DBUILD_TX=OFF \
          -DBUILD_UTIL=OFF \
          -DBUILD_UTIL_CHAINSTATE=OFF \
          -DBUILD_WALLET_TOOL=OFF \
          -DBUILD_SHARED_LIBS=ON -DBUILD_BITCOINCONSENSUS_LIB=ON
    cmake --build build_libbitcoinconsensus -j "$JOBS" ${V:+--verbose}
    cmake --build build_libbitcoinconsensus -j 1 --target check-security ${V:+--verbose}
    cmake --build build_libbitcoinconsensus -j 1 --target check-symbols ${V:+--verbose}

    # Configure this DISTSRC for $HOST
    # shellcheck disable=SC2086
    env CFLAGS="${HOST_CFLAGS}" CXXFLAGS="${HOST_CXXFLAGS}" LDFLAGS="${HOST_LDFLAGS}" "${CUDA_CMAKE_ENV[@]}" \
    cmake -S . -B build \
          --toolchain "${BASEPREFIX}/${HOST}/toolchain.cmake" \
          -DWITH_CCACHE=OFF \
          ${MAIN_CONFIGFLAGS}

    # Build BTX
    cmake --build build -j "$JOBS" ${V:+--verbose}

    # Perform basic security checks on a series of executables.
    cmake --build build -j 1 --target check-security ${V:+--verbose}
    # Check that executables only contain allowed version symbols.
    env "${CUDA_SYMBOL_CHECK_ENV[@]}" cmake --build build -j 1 --target check-symbols ${V:+--verbose}

    mkdir -p "$OUTDIR"

    # Make the os-specific installers
    case "$HOST" in
        *mingw*)
            cmake --build build -j "$JOBS" -t deploy ${V:+--verbose}
            mv build/btx-win64-setup.exe "${OUTDIR}/${DISTNAME}-win64-setup-pgpverifiable.exe"
            ;;
    esac

    # Setup the directory where our BTX build for HOST will be
    # installed. This directory will also later serve as the input for our
    # binary tarballs.
    INSTALLPATH="${PWD}/installed/${DISTNAME}"
    mkdir -p "${INSTALLPATH}"
    # Install built BTX to $INSTALLPATH
    case "$HOST" in
        *darwin*)
            # This workaround can be dropped for CMake >= 3.27.
            # See the upstream commit 689616785f76acd844fd448c51c5b2a0711aafa2.
            find build* -name 'cmake_install.cmake' -exec sed -i 's| -u -r | |g' {} +

            cmake --install build_libbitcoinconsensus --strip --prefix "${INSTALLPATH}" ${V:+--verbose}
            cmake --install build --strip --prefix "${INSTALLPATH}" ${V:+--verbose}
            ;;
        *)
            cmake --install build_libbitcoinconsensus --prefix "${INSTALLPATH}" ${V:+--verbose}
            cmake --install build --prefix "${INSTALLPATH}" ${V:+--verbose}
            ;;
    esac

    (
        cd installed

        case "$HOST" in
            *darwin*) ;;
            *)
                # Split binaries from their debug symbols
                {
                    find "${DISTNAME}/bin" -type f -executable -print0
                    if test -d "${DISTNAME}/lib"; then
                        find "${DISTNAME}/lib" -type f -executable -print0
                    fi
                } | xargs -0 -P"$JOBS" -I{} "${DISTSRC}/build/split-debug.sh" {} {} {}.dbg
                ;;
        esac

        case "$HOST" in
            *mingw*)
                cp "${DISTSRC}/doc/README_windows.txt" "${DISTNAME}/readme.txt"
                ;;
            *linux*)
                cp "${DISTSRC}/README.md" "${DISTNAME}/"
                ;;
        esac

        # Copy over the example btx.conf file. If contrib/devtools/gen-bitcoin-conf.sh
        # has not been run before buildling, this file will be a stub
        cp "${DISTSRC}/share/examples/btx.conf" "${DISTNAME}/"

        cp -r "${DISTSRC}/share/rpcauth" "${DISTNAME}/share/"

        # Keep the official release archives aligned with the operator-facing
        # fast-start/mining toolchain that package_release_archive.py stages for
        # local testing and non-Guix packaging flows.
        while IFS= read -r relative_path; do
            [ -n "${relative_path}" ] || continue
            case "${relative_path}" in
                \#*) continue ;;
            esac
            relative_dir="${relative_path%/*}"
            mkdir -p "${DISTNAME}/${relative_dir}"
            cp "${DISTSRC}/${relative_path}" "${DISTNAME}/${relative_path}"
        done < "${DISTSRC}/scripts/release/support_files.txt"

        assert_no_dynamic_cuda_runtime_dependencies

        # Deterministically produce {non-,}debug binary tarballs ready
        # for release
        case "$HOST" in
            *mingw*)
                find "${DISTNAME}" -not -name "*.dbg" -print0 \
                    | xargs -0r touch --no-dereference --date="@${SOURCE_DATE_EPOCH}"
                find "${DISTNAME}" -not -name "*.dbg" \
                    | sort \
                    | zip -X@ "${OUTDIR}/${DISTNAME}-${HOST//x86_64-w64-mingw32/win64}-pgpverifiable.zip" \
                    || ( rm -f "${OUTDIR}/${DISTNAME}-${HOST//x86_64-w64-mingw32/win64}-pgpverifiable.zip" && exit 1 )
                find "${DISTNAME}" -name "*.dbg" -print0 \
                    | xargs -0r touch --no-dereference --date="@${SOURCE_DATE_EPOCH}"
                find "${DISTNAME}" -name "*.dbg" \
                    | sort \
                    | zip -X@ "${OUTDIR}/${DISTNAME}-${HOST//x86_64-w64-mingw32/win64}-debug.zip" \
                    || ( rm -f "${OUTDIR}/${DISTNAME}-${HOST//x86_64-w64-mingw32/win64}-debug.zip" && exit 1 )
                ;;
            *linux*)
                find "${DISTNAME}" -not -name "*.dbg" -print0 \
                    | sort --zero-terminated \
                    | tar --create --no-recursion --mode='u+rw,go+r-w,a+X' --null --files-from=- \
                    | gzip -9n > "${OUTDIR}/${DISTNAME}-${HOST}${LINUX_ARTIFACT_SUFFIX}.tar.gz" \
                    || ( rm -f "${OUTDIR}/${DISTNAME}-${HOST}${LINUX_ARTIFACT_SUFFIX}.tar.gz" && exit 1 )
                find "${DISTNAME}" -name "*.dbg" -print0 \
                    | sort --zero-terminated \
                    | tar --create --no-recursion --mode='u+rw,go+r-w,a+X' --null --files-from=- \
                    | gzip -9n > "${OUTDIR}/${DISTNAME}-${HOST}${LINUX_ARTIFACT_SUFFIX}-debug.tar.gz" \
                    || ( rm -f "${OUTDIR}/${DISTNAME}-${HOST}${LINUX_ARTIFACT_SUFFIX}-debug.tar.gz" && exit 1 )
                ;;
            *darwin*)
                find "${DISTNAME}" -print0 \
                    | sort --zero-terminated \
                    | tar --create --no-recursion --mode='u+rw,go+r-w,a+X' --null --files-from=- \
                    | gzip -9n > "${OUTDIR}/${DISTNAME}-${HOST}-unsigned.tar.gz" \
                    || ( rm -f "${OUTDIR}/${DISTNAME}-${HOST}-unsigned.tar.gz" && exit 1 )
                ;;
        esac
    )  # $DISTSRC/installed

    # Finally make tarballs for codesigning
    case "$HOST" in
        *mingw*)
            cp -rf --target-directory=. contrib/windeploy
            (
                cd ./windeploy
                mkdir -p unsigned
                cp --target-directory=unsigned/ "${OUTDIR}/${DISTNAME}-win64-setup-pgpverifiable.exe"
                cp -r --target-directory=unsigned/ "${INSTALLPATH}"
                find unsigned/ -name "*.dbg" -print0 \
                    | xargs -0r rm
                find . -print0 \
                    | sort --zero-terminated \
                    | tar --create --no-recursion --mode='u+rw,go+r-w,a+X' --null --files-from=- \
                    | gzip -9n > "${OUTDIR}/${DISTNAME}-win64-codesigning.tar.gz" \
                    || ( rm -f "${OUTDIR}/${DISTNAME}-win64-codesigning.tar.gz" && exit 1 )
            )
            ;;
        *darwin*)
            cmake --build build --target deploy ${V:+--verbose}
            mv build/dist/*.zip "${OUTDIR}/${DISTNAME}-${HOST}-unsigned.zip"
            mkdir -p "unsigned-app-${HOST}"
            cp  --target-directory="unsigned-app-${HOST}" \
                contrib/macdeploy/detached-sig-create.sh
            mv --target-directory="unsigned-app-${HOST}" build/dist
            cp -r --target-directory="unsigned-app-${HOST}" "${INSTALLPATH}"
            (
                cd "unsigned-app-${HOST}"
                find . -print0 \
                    | sort --zero-terminated \
                    | tar --create --no-recursion --mode='u+rw,go+r-w,a+X' --null --files-from=- \
                    | gzip -9n > "${OUTDIR}/${DISTNAME}-${HOST}-codesigning.tar.gz" \
                    || ( rm -f "${OUTDIR}/${DISTNAME}-${HOST}-codesigning.tar.gz" && exit 1 )
            )
            ;;
    esac
)  # $DISTSRC

rm -rf "$ACTUAL_OUTDIR"
mv --no-target-directory "$OUTDIR" "$ACTUAL_OUTDIR" \
    || ( rm -rf "$ACTUAL_OUTDIR" && exit 1 )

(
    cd /outdir-base
    {
        echo "$GIT_ARCHIVE"
        find "$ACTUAL_OUTDIR" -type f
    } | xargs realpath --relative-base="$PWD" \
      | xargs sha256sum \
      | sort -k2 \
      | sponge "$ACTUAL_OUTDIR"/SHA256SUMS.part
)
