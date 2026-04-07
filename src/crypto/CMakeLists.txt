# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

set(ML_KEM_C_SOURCES
  ml-kem-768/cbd.c
  ml-kem-768/fips202.c
  ml-kem-768/indcpa.c
  ml-kem-768/kem.c
  ml-kem-768/ntt.c
  ml-kem-768/poly.c
  ml-kem-768/polyvec.c
  ml-kem-768/reduce.c
  ml-kem-768/symmetric-shake.c
  ml-kem-768/verify.c
)

add_library(bitcoin_crypto STATIC EXCLUDE_FROM_ALL
  aes.cpp
  chacha20.cpp
  chacha20poly1305.cpp
  ethash/lib/ethash/ethash.cpp
  ethash/lib/ethash/managed.cpp
  ethash/lib/ethash/primes.c
  ethash/lib/ethash/progpow.cpp
  ethash/lib/keccak/keccak.c
  ethash/lib/keccak/keccakf1600.c
  ethash/lib/keccak/keccakf800.c
  kawpow.cpp
  hex_base.cpp
  hkdf_sha256_32.cpp
  hmac_sha256.cpp
  hmac_sha512.cpp
  ${ML_KEM_C_SOURCES}
  ml_kem.cpp
  muhash.cpp
  poly1305.cpp
  ripemd160.cpp
  sha1.cpp
  sha256.cpp
  sha3.cpp
  sha512.cpp
  siphash.cpp
  ../support/cleanse.cpp
)

target_link_libraries(bitcoin_crypto
  PRIVATE
    core_interface
)

target_include_directories(bitcoin_crypto
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/ml-kem-768
)

# CVE-2024-36405 class hardening: force a constant-time-safe optimization
# profile for ML-KEM C sources under Clang toolchains.
if(CMAKE_C_COMPILER_ID MATCHES "Clang" AND NOT MSVC)
  set_property(SOURCE ${ML_KEM_C_SOURCES} APPEND PROPERTY COMPILE_OPTIONS -O2)
endif()

if(HAVE_SSE41)
  target_sources(bitcoin_crypto PRIVATE sha256_sse4.cpp)
  target_compile_definitions(bitcoin_crypto PRIVATE ENABLE_SSE41)
  target_sources(bitcoin_crypto PRIVATE sha256_sse41.cpp)
  set_property(SOURCE sha256_sse41.cpp PROPERTY
    COMPILE_OPTIONS ${SSE41_CXXFLAGS}
  )
endif()

if(HAVE_AVX2)
  target_compile_definitions(bitcoin_crypto PRIVATE ENABLE_AVX2)
  target_sources(bitcoin_crypto PRIVATE sha256_avx2.cpp)
  set_property(SOURCE sha256_avx2.cpp PROPERTY
    COMPILE_OPTIONS ${AVX2_CXXFLAGS}
  )
endif()

if(HAVE_SSE41 AND HAVE_X86_SHANI)
  target_compile_definitions(bitcoin_crypto PRIVATE ENABLE_SSE41 ENABLE_X86_SHANI)
  target_sources(bitcoin_crypto PRIVATE sha256_x86_shani.cpp)
  set_property(SOURCE sha256_x86_shani.cpp PROPERTY
    COMPILE_OPTIONS ${SSE41_CXXFLAGS} ${X86_SHANI_CXXFLAGS}
  )
endif()

if(HAVE_ARM_SHANI)
  target_compile_definitions(bitcoin_crypto PRIVATE ENABLE_ARM_SHANI)
  target_sources(bitcoin_crypto PRIVATE sha256_arm_shani.cpp)
  set_property(SOURCE sha256_arm_shani.cpp PROPERTY
    COMPILE_OPTIONS ${ARM_SHANI_CXXFLAGS}
  )
endif()

if(ENABLE_POWER8)
  target_compile_definitions(bitcoin_crypto PRIVATE
    ENABLE_POWER8
    $<IF:$<STREQUAL:${CMAKE_CXX_BYTE_ORDER},BIG_ENDIAN>,WORDS_BIGENDIAN,>
  )
  target_sources(bitcoin_crypto PRIVATE sha256_power8.cpp)
  set_property(SOURCE sha256_power8.cpp PROPERTY
    COMPILE_OPTIONS ${POWER8_CXXFLAGS}
  )
endif()
