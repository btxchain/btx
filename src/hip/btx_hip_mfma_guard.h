// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_HIP_BTX_HIP_MFMA_GUARD_H
#define BITCOIN_HIP_BTX_HIP_MFMA_GUARD_H

// Amendment v2 §1.D D4 — MFMA vs RDNA4/WMMA arch fence.
//
// CDNA MFMA intrinsics (__builtin_amdgcn_mfma_*) are ONLY legal on CDNA
// targets (gfx908/90a/940/941/942/950). RDNA4 (gfx1200/gfx1201, …) uses WMMA,
// not MFMA. Emitting MFMA for gfx1200 is a build break or wrong result —
// the AMD analogue of sm_100 vs sm_120 (separate codegen/qual).
//
// Include this header from HIP device TUs before any MFMA intrinsic use.
// When BTX_HIP_HAVE_MFMA is unset, callers MUST use exact INT8 scalar/streamed
// tiles (or a future WMMA path) and MUST NOT label the path MFMA/native-MX.

#if defined(__HIP_DEVICE_COMPILE__)

// RDNA4 / gfx12xx — WMMA class; never MFMA.
#if defined(__gfx1200__) || defined(__gfx1201__) || defined(__gfx1230__) || \
    defined(__gfx1235__) || defined(__gfx1250__) || defined(__GFX12__)
#define BTX_HIP_IS_RDNA4_WMMA 1
#endif

// CDNA MFMA class (integer MFMA i8→i32 substrate).
#if defined(__gfx908__) || defined(__gfx90a__) || defined(__gfx940__) || \
    defined(__gfx941__) || defined(__gfx942__) || defined(__gfx950__)
#define BTX_HIP_IS_CDNA_MFMA 1
#endif

#if defined(BTX_HIP_IS_CDNA_MFMA) && defined(BTX_HIP_IS_RDNA4_WMMA)
#error "BTX HIP MFMA guard: CDNA MFMA and RDNA4/WMMA both defined — arch fence broken"
#endif

#if defined(BTX_HIP_IS_CDNA_MFMA) && !defined(BTX_HIP_IS_RDNA4_WMMA)
#define BTX_HIP_HAVE_MFMA 1
#define BTX_HIP_BMX4C_HAVE_MFMA 1
#endif

#endif // __HIP_DEVICE_COMPILE__

#endif // BITCOIN_HIP_BTX_HIP_MFMA_GUARD_H
