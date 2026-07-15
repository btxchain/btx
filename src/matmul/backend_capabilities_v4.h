// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MATMUL_BACKEND_CAPABILITIES_V4_H
#define BTX_MATMUL_BACKEND_CAPABILITIES_V4_H

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

// MatMul v4 backend ELIGIBILITY detection (design spec
// doc/btx-matmul-v4-design-spec.md §S.1-§S.3, §B.6, §N.2, §N.3-v).
//
// v4's admissibility rule (§S.1) is stricter than v3's "backend compiled and
// runtime present" capability model (matmul/backend_capabilities.h): a backend
// may only MINE if it presents a genuine, bit-exact INT8 s8xs8->s32 integer
// tensor path. Concretely:
//
//   - CPU              : always admissible. The pure-integer CPU implementation
//                        (matmul_v4::ComputeDigest) IS the consensus definition
//                        (§N.3-v); AVX-512 VNNI etc. are internal details.
//   - CUDA             : admissible iff the device has IMMA integer tensor
//                        cores, i.e. compute capability >= 7.5 (Turing and
//                        later: sm_75/8x/9x/10x/12x). Volta (sm_70/72) tensor
//                        cores are FP16-multiply only -> verification-only.
//                        Pre-tensor parts (CMP 30HX/TU116-class, Pascal and
//                        older) are excluded outright (§S.4.2).
//   - HIP (ROCm)       : admissible iff the device is CDNA MFMA-capable
//                        (gfx908 / gfx90a / gfx94x / gfx95x - MI100..MI3xx).
//                        GCN (gfx900/gfx906) has no matrix cores; RDNA WMMA
//                        parts are verification-only until they pass the
//                        cross-vendor golden vectors (§B.6, Appendix C-3).
//   - METAL            : admissible iff the device is Apple M5-class, i.e. a
//                        GPU Neural Accelerator with Metal 4 INT8 TensorOps
//                        (s8xs8->s32, OS 26.4+). Pre-M5 GPUs and the ANE
//                        (which dequantizes INT8 to FP16) have no integer
//                        tensor path -> verification-only (§K.1, §O.1).
//
// FP-only paths (FP16/BF16/FP8, any floating accumulate) are NEVER admissible:
// floating accumulation rounds per partial sum and is not bit-reproducible
// (§B.1, §K.4). Admissibility is necessary but NOT sufficient for mining:
// per §N.3-v every non-CPU backend must additionally pass the determinism
// self-test / cross-backend harness (src/test/
// matmul_v4_backend_determinism_tests.cpp) bit-for-bit against the CPU
// reference before it may be flagged mining-capable
// (`Eligibility::self_test_required`).
//
// This header is consumed by the v4 dispatch layer (matmul/accel_v4.h,
// namespace matmul_v4::accel): accel_v4's ResolveBackend delegates the
// eligibility decision to ResolveBackend() below. `Kind` mirrors
// matmul_v4::accel::Kind member-for-member (CPU, CUDA, METAL, HIP) so the two
// enums convert by name; this header stays dependency-free of accel_v4.h so
// the include edge is one-way (accel_v4.h -> this header).

namespace matmul_v4::backend {

//! Mirrors matmul_v4::accel::Kind (same members, same order).
enum class Kind {
    CPU,
    CUDA,
    METAL,
    HIP,
};

struct Eligibility {
    //! Backend code is compiled into this binary (CMake:
    //! BTX_ENABLE_CUDA_EXPERIMENTAL / BTX_ENABLE_METAL / BTX_ENABLE_HIP).
    bool compiled{false};
    //! Runtime/driver present and a device is visible.
    bool available{false};
    //! §S.1 admissibility: device presents a bit-exact INT8 s8xs8->s32
    //! integer tensor path. Only admissible backends may mine.
    bool admissible{false};
    //! §N.3-v: backend must pass the determinism self-test (bit-for-bit
    //! digest+payload match vs the CPU reference) before mining. Always true
    //! for non-CPU backends; false for CPU, which is the reference itself.
    bool self_test_required{true};
    //! Machine-readable reason string (v3 backend_capabilities convention).
    std::string reason;
};

struct Selection {
    std::string requested_input;
    bool requested_known{true};
    Kind requested{Kind::CPU};
    Kind active{Kind::CPU};
    std::string reason;
};

std::string ToString(Kind kind);

//! Runtime eligibility for one backend of THIS binary (probes drivers/devices
//! for compiled-in backends; reports disabled_by_build otherwise).
Eligibility EligibilityFor(Kind kind);

//! Eligibility for every backend, in Kind declaration order.
std::vector<std::pair<Kind, Eligibility>> AllEligibility();

//! Resolve a user-requested backend string ("cpu", "cuda"/"nvidia",
//! "metal"/"mlx"/"apple", "hip"/"rocm"/"amd") against runtime eligibility.
//! Unknown, unavailable, or INADMISSIBLE (verification-only, §S.1) requests
//! fall back to CPU with a machine-readable reason. This is the hook
//! matmul_v4::accel::ResolveBackend delegates to.
Selection ResolveBackend(const std::string& requested);

// -- Pure classification rules (unit-testable without hardware) -------------
// Each classifier encodes the §S.1 admissibility rule for one vendor. The
// returned Eligibility has compiled/available preset to true (the caller has
// already probed a live device); only admissible/self_test_required/reason
// carry the classification. Backend probes MUST route their device identity
// through these functions so the eligibility rule is a single, tested,
// consensus-reviewed predicate rather than per-backend ad-hoc logic.

//! CUDA: admissible iff compute capability >= 7.5 (Turing IMMA). Volta
//! (7.0/7.2) is FP16-tensor-only; < 7.0 has no tensor cores.
Eligibility ClassifyCudaDevice(uint32_t cc_major, uint32_t cc_minor);

//! HIP/ROCm: admissible iff the gfx arch is CDNA MFMA-capable. Accepts full
//! target strings ("gfx90a:sramecc+:xnack-"); feature suffixes are ignored.
Eligibility ClassifyHipDevice(std::string_view gcn_arch_name);

//! Metal: admissible iff the device attests Metal 4 INT8 TensorOps
//! (M5-class GPU Neural Accelerator, s8xs8->s32). Pre-M5 / ANE-only devices
//! pass false and are verification-only.
Eligibility ClassifyMetalDevice(bool has_metal4_int8_tensor_ops);

} // namespace matmul_v4::backend

#endif // BTX_MATMUL_BACKEND_CAPABILITIES_V4_H
