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
//   - CUDA             : compute capability >= 7.5 is the candidate filter;
//                        mining additionally requires a cuBLASLt algorithm
//                        declaring native IMMA + signed-INT8 input + INT32
//                        accumulation and passing exact multi-shape self-qual.
//                        This rejects sm_75 products without a usable native
//                        Tensor Core route. Volta (sm_70/72) is FP16-only and
//                        Pascal and older have no tensor path (§S.4.2).
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
//   - ASCEND (昇腾)    : admissible iff CANN linked (BTX_HAVE_CANN), NPU present,
//                        Ascend 950-class SoC, AND ExactGemmS8S8 self-qual passed.
//                        Without CANN (default CI): fail-closed / disabled_by_build.
//
// Generic FP-only paths (FP16/BF16/FP8, unbounded floating accumulation) are
// NEVER admissible: floating accumulation rounds per partial sum and is not
// bit-reproducible (§B.1, §K.4). The separate LT-only TPU/Trainium provider
// splice is intentionally outside this registry: it may use BF16→FP32 only
// after proving every possible integer partial sum is within 2^24, attesting
// native tensor execution, and passing CPU parity. Admissibility here is
// necessary but NOT sufficient for mining:
// per §N.3-v every non-CPU backend must additionally pass the determinism
// self-test / cross-backend harness (src/test/
// matmul_v4_backend_determinism_tests.cpp) bit-for-bit against the CPU
// reference before it may be flagged mining-capable
// (`Eligibility::self_test_required`).
//
// This header is consumed by the v4 dispatch layer (matmul/accel_v4.h,
// namespace matmul_v4::accel): accel_v4's ResolveBackend delegates the
// eligibility decision to ResolveBackend() below. `Kind` mirrors
// matmul_v4::accel::Kind member-for-member (CPU, CUDA, METAL, HIP, ASCEND) so the two
// enums convert by name; this header stays dependency-free of accel_v4.h so
// the include edge is one-way (accel_v4.h -> this header).

namespace matmul_v4::backend {

//! Mirrors matmul_v4::accel::Kind (same members, same order).
enum class Kind {
    CPU,
    CUDA,
    METAL,
    HIP,
    ASCEND,
};

struct Eligibility {
    //! Backend code is compiled into this binary (CMake:
    //! BTX_ENABLE_CUDA_EXPERIMENTAL / BTX_ENABLE_METAL / BTX_ENABLE_HIP /
    //! BTX_ENABLE_ASCEND).
    bool compiled{false};
    //! Runtime/driver present and a device is visible.
    bool available{false};
    //! §S.1 registry admissibility: device presents a bit-exact INT8
    //! s8xs8->s32 integer tensor path. The bounded LT-only cloud provider is
    //! selected separately and does not make a full digest backend admissible.
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

//! Resolve a user-requested backend string against runtime eligibility:
//!   "auto" (or "") — pick the first §S.1-admissible device in platform order
//!     (Apple: Metal→CUDA→HIP→Ascend; else: CUDA→HIP→Ascend→Metal), else CPU
//!   "cpu", "cuda"/"nvidia", "metal"/"mlx"/"apple", "hip"/"rocm"/"amd",
//!     "ascend"/"huawei"/"npu" — explicit request
//! Unknown, unavailable, or INADMISSIBLE (verification-only, §S.1) requests
//! fall back to CPU with a machine-readable reason. This is the hook
//! matmul_v4::accel::ResolveBackend delegates to.
//! Non-CPU selections with `self_test_required` additionally require
//! HasPassedDeterminismSelfTest (fail-closed §N.3-v).
Selection ResolveBackend(const std::string& requested);

//! §N.3-v determinism / ExactGemm self-test latch. CPU is always true (it is
//! the reference). Non-CPU kinds return true only when EligibilityFor reports
//! admissible — device ExactGemm self-qual (IMMA / MFMA / TensorOps / Cube) is
//! folded into that predicate. RC mining ExactGemm inject is gated separately
//! by matmul::v4::rc::HasPassedRCSelfQual / ProbeRCSelfQual.
[[nodiscard]] bool HasPassedDeterminismSelfTest(Kind kind);

// -- Pure classification rules (unit-testable without hardware) -------------
// Each classifier encodes the §S.1 admissibility rule for one vendor. The
// returned Eligibility has compiled/available preset to true (the caller has
// already probed a live device); only admissible/self_test_required/reason
// carry the classification. Backend probes MUST route their device identity
// through these functions so the eligibility rule is a single, tested,
// consensus-reviewed predicate rather than per-backend ad-hoc logic.

//! CUDA candidate classification: compute capability >= 7.5. Runtime mining
//! eligibility additionally requires native-IMMA algorithm attestation and
//! exactness self-qualification in EligibilityFor(CUDA). Volta (7.0/7.2) is
//! FP16-tensor-only; < 7.0 has no tensor cores.
Eligibility ClassifyCudaDevice(uint32_t cc_major, uint32_t cc_minor);

//! HIP/ROCm: admissible iff the gfx arch is CDNA MFMA-capable. Accepts full
//! target strings ("gfx90a:sramecc+:xnack-"); feature suffixes are ignored.
Eligibility ClassifyHipDevice(std::string_view gcn_arch_name);

//! Metal: admissible iff the device attests Metal 4 INT8 TensorOps
//! (M5-class GPU Neural Accelerator, s8xs8->s32). Pre-M5 / ANE-only devices
//! pass false and are verification-only.
Eligibility ClassifyMetalDevice(bool has_metal4_int8_tensor_ops);

//! Ascend/CANN: candidate iff SoC indicates Ascend 950-class Cube INT8.
Eligibility ClassifyAscendDevice(std::string_view soc_name);

} // namespace matmul_v4::backend

#endif // BTX_MATMUL_BACKEND_CAPABILITIES_V4_H
