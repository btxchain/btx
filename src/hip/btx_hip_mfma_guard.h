// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_HIP_BTX_HIP_MFMA_GUARD_H
#define BITCOIN_HIP_BTX_HIP_MFMA_GUARD_H

// Amendment v3 §1.D-MFMA — per-CDNA-generation int8 MFMA selection.
//
// Intrinsic is NOT one blanket CDNA path:
//   gfx908 / gfx90a (CDNA1/2): __builtin_amdgcn_mfma_i32_16x16x16i8  (K=16, i32 packs)
//   gfx940 / gfx941 / gfx942 / gfx950 (CDNA3/4): 
//       __builtin_amdgcn_mfma_i32_16x16x32_i8 (K=32, i64 packs of 8×i8)
//       K=16 int8 MFMA was REMOVED on these arches — compiling K=16 for MI300/MI355
//       is a build break / wrong path.
//   gfx1200+ (RDNA4): NO MFMA → scalar exact-INT8 (or future WMMA). Never emit MFMA.
//
// Include from HIP device TUs before any MFMA use. When neither K16 nor K32 is
// defined, callers MUST use the scalar twin and MUST NOT label the path MFMA.

#if defined(__HIP_DEVICE_COMPILE__)

#if defined(__gfx1200__) || defined(__gfx1201__) || defined(__gfx1230__) || \
    defined(__gfx1235__) || defined(__gfx1250__) || defined(__GFX12__)
#define BTX_HIP_IS_RDNA4_WMMA 1
#endif

// CDNA1/2 — K=16 int8 MFMA (4 packed i8 / lane pack).
#if defined(__gfx908__) || defined(__gfx90a__)
#define BTX_HIP_MFMA_I8_K16 1
#define BTX_HIP_HAVE_MFMA 1
#define BTX_HIP_BMX4C_HAVE_MFMA 1
#define BTX_HIP_MFMA_K_TILE 16
#endif

// CDNA3/4 — K=32 int8 MFMA (8 packed i8 → i64 packs). gfx940+.
#if defined(__gfx940__) || defined(__gfx941__) || defined(__gfx942__) || \
    defined(__gfx950__)
#define BTX_HIP_MFMA_I8_K32 1
#define BTX_HIP_HAVE_MFMA 1
#define BTX_HIP_BMX4C_HAVE_MFMA 1
#define BTX_HIP_MFMA_K_TILE 32
#endif

#if defined(BTX_HIP_MFMA_I8_K16) && defined(BTX_HIP_MFMA_I8_K32)
#error "BTX HIP MFMA guard: both K16 and K32 MFMA classes defined — arch fence broken"
#endif

#if (defined(BTX_HIP_MFMA_I8_K16) || defined(BTX_HIP_MFMA_I8_K32)) && \
    defined(BTX_HIP_IS_RDNA4_WMMA)
#error "BTX HIP MFMA guard: CDNA MFMA and RDNA4/WMMA both defined — arch fence broken"
#endif

#endif // __HIP_DEVICE_COMPILE__

#endif // BITCOIN_HIP_BTX_HIP_MFMA_GUARD_H
