cmake_minimum_required(VERSION 3.10)
project(libbitcoinpqc C ASM)

include(CheckCCompilerFlag)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Set version
set(BITCOINPQC_VERSION_MAJOR 0)
set(BITCOINPQC_VERSION_MINOR 1)
set(BITCOINPQC_VERSION_PATCH 0)

# Library output settings
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(SPHINCSPLUS_VARIANT "ref")
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(arm64|aarch64)$")
    # The optimized assembly path is known-good on Apple arm64 toolchains.
    # Linux toolchains in CI often lack support for required ARMv8.4-A
    # mnemonics (e.g. `bcax`), so keep Linux on the portable reference path.
    if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        check_c_compiler_flag("-march=armv8.4-a+sha3" COMPILER_SUPPORTS_ARMV84_SHA3)
        if(COMPILER_SUPPORTS_ARMV84_SHA3)
            set(SPHINCSPLUS_VARIANT "shake-a64")
        else()
            message(STATUS "Compiler does not support -march=armv8.4-a+sha3; using SPHINCS+ ref variant")
        endif()
    endif()
endif()

message(STATUS "Configuring libbitcoinpqc with SPHINCS+ variant: ${SPHINCSPLUS_VARIANT}")

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/dilithium/ref
    ${CMAKE_CURRENT_SOURCE_DIR}/sphincsplus/${SPHINCSPLUS_VARIANT}
)

# Custom randombytes implementation
set(CUSTOM_RANDOMBYTES
    dilithium/ref/randombytes_custom.c
    src/slh_dsa/randombytes_custom.c
)

# ML-DSA-44 (Dilithium) source files
set(ML_DSA_SOURCES
    dilithium/ref/sign.c
    dilithium/ref/packing.c
    dilithium/ref/polyvec.c
    dilithium/ref/poly.c
    dilithium/ref/ntt.c
    dilithium/ref/reduce.c
    dilithium/ref/rounding.c
    dilithium/ref/fips202.c
    dilithium/ref/symmetric-shake.c
)

# SLH-DSA-Shake-128s (SPHINCS+) source files
if(SPHINCSPLUS_VARIANT STREQUAL "ref")
    set(SLH_DSA_SOURCES
        sphincsplus/ref/address.c
        sphincsplus/ref/fors.c
        sphincsplus/ref/hash_shake.c
        sphincsplus/ref/merkle.c
        sphincsplus/ref/sign.c
        sphincsplus/ref/thash_shake_simple.c
        sphincsplus/ref/utils.c
        sphincsplus/ref/utilsx1.c
        sphincsplus/ref/wots.c
        sphincsplus/ref/wotsx1.c
        sphincsplus/ref/fips202.c
    )
elseif(SPHINCSPLUS_VARIANT STREQUAL "shake-a64")
    set(SLH_DSA_SOURCES
        sphincsplus/shake-a64/address.c
        sphincsplus/shake-a64/fors.c
        sphincsplus/shake-a64/hash_shake.c
        sphincsplus/shake-a64/hash_shakex2.c
        sphincsplus/shake-a64/merkle.c
        sphincsplus/shake-a64/sign.c
        sphincsplus/shake-a64/thash_shake_simplex2.c
        sphincsplus/shake-a64/utils.c
        sphincsplus/shake-a64/utilsx2.c
        sphincsplus/shake-a64/wots.c
        sphincsplus/shake-a64/fips202.c
        sphincsplus/shake-a64/fips202x2.c
        sphincsplus/shake-a64/f1600x2_const.c
        sphincsplus/shake-a64/f1600x2.s
    )
    set_source_files_properties(
        sphincsplus/shake-a64/f1600x2.s
        PROPERTIES COMPILE_OPTIONS "-march=armv8.4-a+sha3"
    )
else()
    message(FATAL_ERROR "Unknown SPHINCS+ variant: ${SPHINCSPLUS_VARIANT}")
endif()

# libbitcoinpqc source files
set(BITCOINPQC_SOURCES
    src/bitcoinpqc.c
    src/ml_dsa/utils.c
    src/ml_dsa/keygen.c
    src/ml_dsa/sign.c
    src/ml_dsa/verify.c
    src/slh_dsa/utils.c
    src/slh_dsa/keygen.c
    src/slh_dsa/sign.c
    src/slh_dsa/verify.c
)

# Define the main library target
add_library(bitcoinpqc STATIC
    ${BITCOINPQC_SOURCES}
    ${ML_DSA_SOURCES}
    ${SLH_DSA_SOURCES}
    ${CUSTOM_RANDOMBYTES}
)

# Set include directories for the library
target_include_directories(bitcoinpqc PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Set compile definitions for the library
target_compile_definitions(bitcoinpqc PRIVATE
    DILITHIUM_MODE=2  # ML-DSA-44 (Dilithium2)
    PARAMS=sphincs-shake-128s
    CUSTOM_RANDOMBYTES=1
)

if(SPHINCSPLUS_VARIANT STREQUAL "ref")
    target_compile_definitions(bitcoinpqc PRIVATE SPHINCSPLUS_VARIANT_REF=1)
elseif(SPHINCSPLUS_VARIANT STREQUAL "shake-a64")
    target_compile_definitions(bitcoinpqc PRIVATE SPHINCSPLUS_VARIANT_SHAKE_A64=1)
endif()

# PQ primitives are extremely compute-heavy; keep this target optimized even in
# debug builds to avoid CI timeouts and pathological wallet test runtimes.
if(NOT MSVC)
    target_compile_options(bitcoinpqc PRIVATE -O3)
endif()

# Configure install paths
install(TARGETS bitcoinpqc
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
    DESTINATION include
    FILES_MATCHING PATTERN "*.h"
)
