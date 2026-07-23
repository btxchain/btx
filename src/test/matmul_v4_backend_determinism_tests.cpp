// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// MatMul v4 CROSS-BACKEND DETERMINISM harness (design spec §B.6, §N.3-v,
// §S.1; the automated equivalent of the §B.6 / Appendix C-3 cross-vendor
// golden-vector check).
//
// Contract under test: for every backend compiled into this binary, the v4
// accelerated digest path must produce (digest, sketch payload) BYTE-IDENTICAL
// to the pure-integer CPU reference matmul_v4::ComputeDigest for a fixed set
// of (header, n) vectors. The CPU implementation is the consensus definition;
// a single differing bit on any backend is a chain split (risk register
// §N.3-v), so every cross-backend comparison below is a hard BOOST_REQUIRE —
// the suite FAILS, it does not warn, on divergence.
//
// Build topology:
//   - CPU-only build (CI containers): the harness self-tests CPU determinism
//     (twice-run byte-identity + VerifySketch round-trip) and emits a loud
//     BOOST_WARN for every GPU row that is skipped-pending-hardware.
//   - GPU builds: GPU rows are guarded by the SAME CMake defines the backends
//     use (BTX_ENABLE_CUDA_EXPERIMENTAL / BTX_ENABLE_METAL / BTX_ENABLE_HIP,
//     forwarded to this file by src/test/CMakeLists.txt) plus presence of the
//     dispatch header matmul/accel_v4.h. Run on real hardware per
//     doc/matmul-v4-gpu-backends.md; the pass criterion there is this suite
//     green with zero skipped rows for the backend under test.
//
// The vectors reuse the header constants of the pinned golden-vector table
// (matmul_v4_determinism_vectors.cpp) so hardware runs of this harness
// exercise exactly the points the release pins commit to.

#include <matmul/backend_capabilities_v4.h>
#include <matmul/int8_field.h>
#include <matmul/matmul_v4.h>
#include <matmul/pow_v4.h>

#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/strencodings.h>

// The dispatch layer (namespace matmul_v4::accel: Kind{CPU,CUDA,METAL,HIP},
// ComputeDigestDispatched, per-backend ComputeDigestAccel) lands separately;
// GPU rows activate automatically once it is present in the tree.
#if defined(__has_include)
#if __has_include(<matmul/accel_v4.h>)
#include <matmul/accel_v4.h>
#define BTX_V4_HAVE_ACCEL_DISPATCH 1
#endif
#endif

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

namespace {

uint256 ParseUint256(std::string_view hex)
{
    const auto parsed = uint256::FromHex(hex);
    BOOST_REQUIRE(parsed.has_value());
    return *parsed;
}

//! One cross-backend determinism vector (fixed, hand-written header fields —
//! no clocks, no OS randomness). n = 256/512 for suite speed; the mainnet
//! dimension n = 4096 is exercised by the same harness in the release-gate
//! hardware lane (doc/matmul-v4-gpu-backends.md).
struct DeterminismVector {
    std::string_view name;
    std::string_view prev_hash;
    std::string_view merkle_root;
    uint32_t time;
    uint32_t bits;
    uint64_t nonce;
    std::string_view seed_a;
    std::string_view seed_b;
    uint32_t n;
    uint32_t rounds;
};

constexpr DeterminismVector kVectors[] = {
    {
        .name = "V4-BD1-n256-r2-zero-seed",
        .prev_hash = "0000000000000000000000000000000000000000000000000000000000000000",
        .merkle_root = "0000000000000000000000000000000000000000000000000000000000000000",
        .time = 1'770'000'000,
        .bits = 0x207fffff,
        .nonce = 0,
        .seed_a = "0000000000000000000000000000000000000000000000000000000000000000",
        .seed_b = "0000000000000000000000000000000000000000000000000000000000000000",
        .n = 256,
        .rounds = 2,
    },
    {
        .name = "V4-BD2-n256-r3-structured-seed",
        .prev_hash = "1111111111111111111111111111111111111111111111111111111111111111",
        .merkle_root = "2222222222222222222222222222222222222222222222222222222222222222",
        .time = 1'770'000'090,
        .bits = 0x207fffff,
        .nonce = 42,
        .seed_a = "0000000000000000000000000000000000000000000000000000000000000000",
        .seed_b = "4504d44d861b69197db1d95e473442346c4f2bc1f5869996bdccd63cfbdbd150",
        .n = 256,
        .rounds = 3,
    },
    {
        .name = "V4-BD3-n512-r3",
        .prev_hash = "c6a811f7f75fe4e64be106a50351aed9c04403a74bfe7b4bbe59f7311722b735",
        .merkle_root = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
        .time = 1'770'000'180,
        .bits = 0x207fffff,
        .nonce = 7,
        .seed_a = "4504d44d861b69197db1d95e473442346c4f2bc1f5869996bdccd63cfbdbd150",
        .seed_b = "c6a811f7f75fe4e64be106a50351aed9c04403a74bfe7b4bbe59f7311722b735",
        .n = 512,
        .rounds = 3,
    },
};

CBlockHeader HeaderFromVector(const DeterminismVector& tv)
{
    CBlockHeader header;
    header.nVersion = 0x20000000;
    header.hashPrevBlock = ParseUint256(tv.prev_hash);
    header.hashMerkleRoot = ParseUint256(tv.merkle_root);
    header.nTime = tv.time;
    header.nBits = tv.bits;
    header.nNonce64 = tv.nonce;
    header.nNonce = static_cast<uint32_t>(tv.nonce);
    header.matmul_dim = static_cast<uint16_t>(tv.n);
    header.seed_a = ParseUint256(tv.seed_a);
    header.seed_b = ParseUint256(tv.seed_b);
    return header;
}

//! CPU reference bytes for one vector.
struct CpuReference {
    uint256 digest;
    std::vector<unsigned char> payload;
};

std::vector<CpuReference> ComputeCpuReferences()
{
    std::vector<CpuReference> refs;
    refs.reserve(std::size(kVectors));
    for (const DeterminismVector& tv : kVectors) {
        const CBlockHeader header = HeaderFromVector(tv);
        CpuReference ref;
        BOOST_REQUIRE_MESSAGE(
            matmul_v4::ComputeDigest(header, tv.n, tv.rounds, ref.digest, ref.payload),
            tv.name << ": CPU reference ComputeDigest failed");
        refs.push_back(std::move(ref));
    }
    return refs;
}

//! When BTX_REQUIRE_GPU_GOLDEN=1, skipped GPU rows hard-fail (certification
//! lane). Default CI WARN-skips so CPU-only containers stay green.
bool RequireGpuGolden()
{
    const char* v = std::getenv("BTX_REQUIRE_GPU_GOLDEN");
    return v != nullptr && std::string_view{v} == "1";
}

void SkipOrFailGpuRow(std::string_view msg)
{
    if (RequireGpuGolden()) {
        BOOST_REQUIRE_MESSAGE(false, msg << " [BTX_REQUIRE_GPU_GOLDEN=1]");
    } else {
        BOOST_WARN_MESSAGE(false, msg);
    }
}

#if defined(BTX_V4_HAVE_ACCEL_DISPATCH)
//! Run one compiled-in GPU backend over every vector and REQUIRE its
//! (digest, payload) to be byte-identical to the CPU reference. Loudly warns
//! (or fails under BTX_REQUIRE_GPU_GOLDEN=1) when the backend is compiled in
//! but no admissible device is present at runtime.
void RunBackendRowOrWarn(matmul_v4::accel::Kind accel_kind,
                         matmul_v4::backend::Kind backend_kind,
                         const std::vector<CpuReference>& refs)
{
    const std::string name = matmul_v4::backend::ToString(backend_kind);
    const auto eligibility = matmul_v4::backend::EligibilityFor(backend_kind);
    if (!eligibility.available || !eligibility.admissible) {
        SkipOrFailGpuRow(
            std::string("SKIPPED-PENDING-HARDWARE: v4 backend '") + name +
            "' compiled in but not runnable here (available=" +
            (eligibility.available ? "1" : "0") + ", admissible=" +
            (eligibility.admissible ? "1" : "0") + ", reason=" + eligibility.reason +
            "). Run this suite on real hardware per doc/matmul-v4-gpu-backends.md; "
            "the backend is NOT verified for mining until this row passes (§N.3-v).");
        return;
    }

    for (size_t i = 0; i < std::size(kVectors); ++i) {
        const DeterminismVector& tv = kVectors[i];
        const CBlockHeader header = HeaderFromVector(tv);

        uint256 digest;
        std::vector<unsigned char> payload;
        // Invoke the specific backend's device entry point (each lives in its
        // own matmul_v4::{cuda,metal,hip} namespace; the CPU reference is
        // matmul_v4::ComputeDigest). Dispatched by accel_kind so the row under
        // test exercises exactly one backend.
        const auto run_backend = [&]() -> bool {
            switch (accel_kind) {
                case matmul_v4::accel::Kind::CUDA:
                    return matmul_v4::cuda::ComputeDigestAccel(header, tv.n, tv.rounds, digest, payload);
                case matmul_v4::accel::Kind::METAL:
                    return matmul_v4::metal::ComputeDigestAccel(header, tv.n, tv.rounds, digest, payload);
                case matmul_v4::accel::Kind::HIP:
                    return matmul_v4::hip::ComputeDigestAccel(header, tv.n, tv.rounds, digest, payload);
                case matmul_v4::accel::Kind::ASCEND:
                    return matmul_v4::ascend::ComputeDigestAccel(header, tv.n, tv.rounds, digest, payload);
                case matmul_v4::accel::Kind::CPU:
                    return matmul_v4::ComputeDigest(header, tv.n, tv.rounds, digest, payload);
            }
            return false;
        };
        BOOST_REQUIRE_MESSAGE(
            run_backend(),
            tv.name << ": backend '" << name
                    << "' is admissible+available but ComputeDigestAccel failed — "
                       "backend may not silently skip the determinism check (§N.3-v)");

        // CONSENSUS-CRITICAL: byte-identical or chain split. One differing
        // bit here means this backend would mine/verify a different chain
        // than the CPU consensus reference (§B.6) — hard failure.
        BOOST_REQUIRE_MESSAGE(
            digest == refs[i].digest,
            "CONSENSUS SPLIT: v4 backend '" << name << "' digest mismatch on " << tv.name
                << " — backend=" << digest.GetHex()
                << " cpu=" << refs[i].digest.GetHex()
                << " (bit-exact s8xs8->s32 violated; backend MUST NOT mine, §B.6/§N.3-v)");
        BOOST_REQUIRE_MESSAGE(
            payload == refs[i].payload,
            "CONSENSUS SPLIT: v4 backend '" << name << "' sketch payload mismatch on " << tv.name
                << " — payload bytes differ from CPU reference (serialization order or "
                   "arithmetic divergence, §E.1/§B.6); backend MUST NOT mine");
    }

    BOOST_TEST_MESSAGE("v4 backend '" << name << "': " << std::size(kVectors)
                                      << " cross-backend vectors byte-identical to CPU reference");
}
#endif // BTX_V4_HAVE_ACCEL_DISPATCH

} // namespace

BOOST_FIXTURE_TEST_SUITE(matmul_v4_backend_determinism_tests, BasicTestingSetup)

// ---------------------------------------------------------------------------
// Eligibility detection (§S.1-§S.3): the admissibility rule is a pure,
// hardware-independent predicate — pin it exactly.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(cpu_backend_is_always_admissible_reference)
{
    const auto eligibility = matmul_v4::backend::EligibilityFor(matmul_v4::backend::Kind::CPU);
    BOOST_CHECK(eligibility.compiled);
    BOOST_CHECK(eligibility.available);
    BOOST_CHECK(eligibility.admissible);
    // The CPU path IS the consensus definition; it never self-tests against
    // itself (§N.3-v).
    BOOST_CHECK(!eligibility.self_test_required);
    BOOST_CHECK_EQUAL(eligibility.reason, "consensus_reference_always_available");
}

BOOST_AUTO_TEST_CASE(cuda_classifier_admits_imma_turing_plus_only)
{
    using matmul_v4::backend::ClassifyCudaDevice;

    // Pre-tensor (Pascal, CMP 30HX/TU116-class): excluded outright (§S.4.2).
    const auto pascal = ClassifyCudaDevice(6, 1);
    BOOST_CHECK(!pascal.admissible);
    BOOST_CHECK_EQUAL(pascal.reason, "pre_tensor_no_int8_mma:sm_61");

    // Volta: FP16-only tensor cores — verification-only (§S.4.2 "Tesla V100").
    const auto volta = ClassifyCudaDevice(7, 0);
    BOOST_CHECK(!volta.admissible);
    BOOST_CHECK_EQUAL(volta.reason, "volta_fp16_tensor_only_inadmissible:sm_70");
    BOOST_CHECK(!ClassifyCudaDevice(7, 2).admissible); // Xavier

    // Turing introduced IMMA s8xs8->s32; everything later keeps it (§B.6).
    const auto turing = ClassifyCudaDevice(7, 5);
    BOOST_CHECK(turing.admissible);
    BOOST_CHECK(turing.self_test_required);
    BOOST_CHECK_EQUAL(turing.reason, "imma_s8s8s32_tensor_path:sm_75");

    BOOST_CHECK(ClassifyCudaDevice(8, 0).admissible);  // A100
    BOOST_CHECK(ClassifyCudaDevice(8, 6).admissible);  // RTX 30-series
    BOOST_CHECK(ClassifyCudaDevice(8, 9).admissible);  // RTX 40-series (Ada)
    BOOST_CHECK(ClassifyCudaDevice(9, 0).admissible);  // H100/H200 (Hopper)
    BOOST_CHECK(ClassifyCudaDevice(10, 0).admissible); // B200 (Blackwell)
    BOOST_CHECK(ClassifyCudaDevice(12, 0).admissible); // RTX 50-series
}

BOOST_AUTO_TEST_CASE(hip_classifier_admits_cdna_mfma_only)
{
    using matmul_v4::backend::ClassifyHipDevice;

    // CDNA MFMA generations: admissible (pending self-test).
    for (const char* arch : {"gfx908", "gfx90a", "gfx940", "gfx941", "gfx942", "gfx950"}) {
        const auto e = ClassifyHipDevice(arch);
        BOOST_CHECK_MESSAGE(e.admissible, arch << " should be CDNA-MFMA admissible");
        BOOST_CHECK_MESSAGE(e.self_test_required, arch << " must still self-test (§N.3-v)");
    }

    // ROCm feature suffixes must not defeat classification.
    const auto suffixed = ClassifyHipDevice("gfx90a:sramecc+:xnack-");
    BOOST_CHECK(suffixed.admissible);
    BOOST_CHECK_EQUAL(suffixed.reason, "mfma_i8i8i32_tensor_path:gfx90a");

    // GCN/Vega: no matrix cores.
    const auto vega = ClassifyHipDevice("gfx906");
    BOOST_CHECK(!vega.admissible);
    BOOST_CHECK_EQUAL(vega.reason, "gcn_no_matrix_cores:gfx906");

    // RDNA consumer parts: WMMA is not the qualified CDNA MFMA path.
    for (const char* arch : {"gfx1030", "gfx1100", "gfx1201"}) {
        const auto e = ClassifyHipDevice(arch);
        BOOST_CHECK_MESSAGE(!e.admissible, arch << " must be verification-only");
        BOOST_CHECK_MESSAGE(e.reason.rfind("rdna_wmma_not_qualified_verification_only:", 0) == 0,
                            arch << " unexpected reason: " << e.reason);
    }

    BOOST_CHECK(!ClassifyHipDevice("").admissible);
    BOOST_CHECK(!ClassifyHipDevice("sm_90").admissible);
}

BOOST_AUTO_TEST_CASE(metal_classifier_admits_m5_int8_tensorops_only)
{
    using matmul_v4::backend::ClassifyMetalDevice;

    // Pre-M5 GPU / ANE-only: no exact integer tensor path (§K.1, §O.1).
    const auto pre_m5 = ClassifyMetalDevice(false);
    BOOST_CHECK(!pre_m5.admissible);
    BOOST_CHECK_EQUAL(pre_m5.reason, "no_integer_tensor_path_verification_only");

    // M5-class Metal 4 INT8 TensorOps: admissible, self-test still required.
    const auto m5 = ClassifyMetalDevice(true);
    BOOST_CHECK(m5.admissible);
    BOOST_CHECK(m5.self_test_required);
    BOOST_CHECK_EQUAL(m5.reason, "metal4_int8_tensorops_m5_class");
}

BOOST_AUTO_TEST_CASE(ascend_classifier_admits_950_cube_candidates)
{
    using matmul_v4::backend::ClassifyAscendDevice;
    BOOST_CHECK(ClassifyAscendDevice("dav-3510").admissible);
    BOOST_CHECK(ClassifyAscendDevice("Ascend950PR").admissible);
    BOOST_CHECK(!ClassifyAscendDevice("atlas-200").admissible);
}

BOOST_AUTO_TEST_CASE(resolve_backend_never_selects_inadmissible_backend)
{
    using matmul_v4::backend::Kind;
    using matmul_v4::backend::ResolveBackend;
    using matmul_v4::backend::ToString;

    // Unknown strings fall back to CPU.
    const auto unknown = ResolveBackend("not-a-backend");
    BOOST_CHECK(!unknown.requested_known);
    BOOST_CHECK_EQUAL(ToString(unknown.active), "cpu");
    BOOST_CHECK_EQUAL(unknown.reason, "unknown_backend_fallback_to_cpu");

    // CPU is always resolvable.
    const auto cpu = ResolveBackend("cpu");
    BOOST_CHECK(cpu.requested_known);
    BOOST_CHECK_EQUAL(ToString(cpu.active), "cpu");
    BOOST_CHECK_EQUAL(cpu.reason, "requested_backend_admissible");

    // Invariant: whatever this binary/hardware, a resolved-ACTIVE backend
    // must be compiled+available+admissible; anything else must have fallen
    // back to CPU with a machine-readable reason (§S.1 — inadmissible
    // devices are verification-only and must never mine).
    for (const char* name : {"cuda", "nvidia", "metal", "mlx", "apple", "hip", "rocm", "amd", "ascend", "huawei", "npu"}) {
        const auto selection = ResolveBackend(name);
        BOOST_CHECK_MESSAGE(selection.requested_known, name << " should parse");
        const auto eligibility = matmul_v4::backend::EligibilityFor(selection.active);
        BOOST_CHECK_MESSAGE(eligibility.compiled && eligibility.available && eligibility.admissible,
                            name << ": active backend " << ToString(selection.active)
                                 << " not eligible (" << eligibility.reason << ")");
        if (selection.active != selection.requested) {
            BOOST_CHECK_MESSAGE(selection.active == Kind::CPU,
                                name << ": fallback must land on CPU");
            BOOST_CHECK_MESSAGE(!selection.reason.empty(), name << ": fallback needs a reason");
        }
    }

    // Alias groups map to one backend.
    BOOST_CHECK(ResolveBackend("mlx").requested == Kind::METAL);
    BOOST_CHECK(ResolveBackend("rocm").requested == Kind::HIP);
    BOOST_CHECK(ResolveBackend("nvidia").requested == Kind::CUDA);
    BOOST_CHECK(ResolveBackend("ascend").requested == Kind::ASCEND);
    BOOST_CHECK(ResolveBackend("huawei").requested == Kind::ASCEND);

    // "auto" is a first-class request: known, picks an admissible device in
    // platform preference order (or CPU if none), never unknown_backend.
    {
        const auto auto_sel = ResolveBackend("auto");
        BOOST_CHECK(auto_sel.requested_known);
        BOOST_CHECK_EQUAL(auto_sel.requested_input, "auto");
        BOOST_CHECK(auto_sel.active == auto_sel.requested);
        const auto elig = matmul_v4::backend::EligibilityFor(auto_sel.active);
        BOOST_CHECK(elig.available && elig.admissible);
        if (auto_sel.active == Kind::CPU) {
            BOOST_CHECK_EQUAL(auto_sel.reason, "auto_no_admissible_device_fallback_to_cpu");
        } else {
            BOOST_CHECK_MESSAGE(auto_sel.reason.rfind("auto_selected_", 0) == 0,
                                "auto reason must be auto_selected_*: " << auto_sel.reason);
        }
        const auto empty_sel = ResolveBackend("");
        BOOST_CHECK(empty_sel.requested_known);
        BOOST_CHECK(empty_sel.active == auto_sel.active);
    }

    // AllEligibility covers every backend exactly once, CPU first.
    const auto all = matmul_v4::backend::AllEligibility();
    BOOST_REQUIRE_EQUAL(all.size(), 5U);
    BOOST_CHECK(all[0].first == Kind::CPU);
    for (const auto& [kind, eligibility] : all) {
        BOOST_CHECK_MESSAGE(!eligibility.reason.empty(),
                            ToString(kind) << ": eligibility reason must never be empty");
        if (eligibility.admissible) {
            BOOST_CHECK_MESSAGE(eligibility.compiled && eligibility.available,
                                ToString(kind) << ": admissible implies compiled+available");
        }
    }
}

// ---------------------------------------------------------------------------
// C7: runtime dispatch must consult the certification registry.
//
// The backend that actually RUNS (matmul_v4::accel::ResolveBackend, which the
// miner and ComputeDigest*Dispatched call) must be exactly the backend the v4
// admissibility/certification registry (matmul_v4::backend::ResolveBackend)
// admits for the same request -- NEVER an inadmissible / verification-only
// backend. Before the fix, accel::ResolveBackend consulted only the v3
// "compiled + device present" capability table, so it could dispatch to a
// backend the registry deems inadmissible. This pins the two in lock-step.
// ---------------------------------------------------------------------------

#if defined(BTX_V4_HAVE_ACCEL_DISPATCH)
namespace {
//! RAII guard for BTX_MATMUL_V4_BACKEND (the env the resolver reads).
class ScopedBackendEnv
{
public:
    explicit ScopedBackendEnv(const char* value)
    {
        if (const char* cur = std::getenv("BTX_MATMUL_V4_BACKEND")) {
            m_had_original = true;
            m_original = cur;
        }
        if (value != nullptr) {
            setenv("BTX_MATMUL_V4_BACKEND", value, 1);
        } else {
            unsetenv("BTX_MATMUL_V4_BACKEND");
        }
    }
    ~ScopedBackendEnv()
    {
        if (m_had_original) {
            setenv("BTX_MATMUL_V4_BACKEND", m_original.c_str(), 1);
        } else {
            unsetenv("BTX_MATMUL_V4_BACKEND");
        }
    }

private:
    bool m_had_original{false};
    std::string m_original;
};
} // namespace

BOOST_AUTO_TEST_CASE(runtime_dispatch_equals_certification_registry)
{
    using matmul_v4::accel::Kind;

    // For every explicit request, the accel dispatch layer must resolve to the
    // SAME active backend the certification registry resolves -- and whatever
    // ends up active must itself be registry-admissible+available (§S.1). An
    // inadmissible or unavailable request must fall back to CPU in BOTH.
    for (const char* req : {"cpu", "cuda", "nvidia", "metal", "mlx", "apple",
                            "hip", "rocm", "amd", "not-a-backend"}) {
        const ScopedBackendEnv env{req};

        const Kind active = matmul_v4::accel::ResolveBackend();
        const matmul_v4::backend::Selection sel = matmul_v4::backend::ResolveBackend(req);

        // The runtime-dispatched backend name equals the registry's active name.
        BOOST_CHECK_MESSAGE(
            matmul_v4::accel::ToString(active) == matmul_v4::backend::ToString(sel.active),
            "request '" << req << "': accel dispatch resolved to "
                        << matmul_v4::accel::ToString(active)
                        << " but the certification registry admits "
                        << matmul_v4::backend::ToString(sel.active));

        // C7 invariant: the backend that actually runs is registry-admissible.
        const auto elig = matmul_v4::backend::EligibilityFor(sel.active);
        BOOST_CHECK_MESSAGE(
            elig.available && elig.admissible,
            "request '" << req << "': dispatched-to backend "
                        << matmul_v4::backend::ToString(sel.active)
                        << " is NOT admissible+available (" << elig.reason
                        << ") -- runtime must never dispatch to an uncertified backend");
    }

    // Unset env: the default request must still resolve to an admissible backend
    // (CPU everywhere except Apple, where Metal may be admissible if present).
    {
        const ScopedBackendEnv env{nullptr};
        const Kind active = matmul_v4::accel::ResolveBackend();
        const auto backend_kind = [&]() {
            switch (active) {
            case Kind::CPU: return matmul_v4::backend::Kind::CPU;
            case Kind::CUDA: return matmul_v4::backend::Kind::CUDA;
            case Kind::METAL: return matmul_v4::backend::Kind::METAL;
            case Kind::HIP: return matmul_v4::backend::Kind::HIP;
            case Kind::ASCEND: return matmul_v4::backend::Kind::ASCEND;
            }
            return matmul_v4::backend::Kind::CPU;
        }();
        const auto elig = matmul_v4::backend::EligibilityFor(backend_kind);
        BOOST_CHECK_MESSAGE(elig.available && elig.admissible,
                            "default request resolved to a non-admissible backend ("
                                << elig.reason << ")");
    }
}
#endif // BTX_V4_HAVE_ACCEL_DISPATCH

// ---------------------------------------------------------------------------
// Cross-backend determinism harness (§B.6 / Appendix C-3 automated).
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(cross_backend_digest_determinism)
{
    // -- CPU reference + machine-local determinism self-test ---------------
    const std::vector<CpuReference> refs = ComputeCpuReferences();

    for (size_t i = 0; i < std::size(kVectors); ++i) {
        const DeterminismVector& tv = kVectors[i];
        const CBlockHeader header = HeaderFromVector(tv);

        // Twice-run byte-identity (machine-local half of §B.6).
        uint256 digest2;
        std::vector<unsigned char> payload2;
        BOOST_REQUIRE(matmul_v4::ComputeDigest(header, tv.n, tv.rounds, digest2, payload2));
        BOOST_REQUIRE_MESSAGE(digest2 == refs[i].digest,
                              tv.name << ": CPU digest not reproducible across runs");
        BOOST_REQUIRE_MESSAGE(payload2 == refs[i].payload,
                              tv.name << ": CPU sketch payload not reproducible across runs");

        // Payload shape pin: 8 * (n/b)^2 bytes (§E.1).
        const size_t m = tv.n / matmul_v4::kTileB;
        BOOST_CHECK_EQUAL(refs[i].payload.size(), 8 * m * m);

        // The emitted bytes must round-trip through the consensus verifier
        // against the SEALED header (miner writes the digest into
        // header.matmul_digest before broadcast; sigma binds every header
        // field except matmul_digest, so sealing does not change the proof —
        // and VerifySketch hard-requires the sealed digest to match).
        CBlockHeader sealed = header;
        sealed.matmul_digest = refs[i].digest;
        uint256 verified;
        BOOST_REQUIRE_MESSAGE(
            matmul_v4::VerifySketch(sealed, tv.n, tv.rounds, refs[i].payload, verified),
            tv.name << ": honest CPU proof failed VerifySketch");
        BOOST_REQUIRE_MESSAGE(verified == refs[i].digest,
                              tv.name << ": VerifySketch digest != miner digest");
    }

    // -- Dispatched-CPU row (dispatch layer must be a pure pass-through) ----
#if defined(BTX_V4_HAVE_ACCEL_DISPATCH)
    for (size_t i = 0; i < std::size(kVectors); ++i) {
        const DeterminismVector& tv = kVectors[i];
        const CBlockHeader header = HeaderFromVector(tv);

        uint256 digest;
        std::vector<unsigned char> payload;
        BOOST_REQUIRE_MESSAGE(
            matmul_v4::accel::ComputeDigestDispatched(header, tv.n, tv.rounds, digest, payload),
            tv.name << ": ComputeDigestDispatched failed");
        BOOST_REQUIRE_MESSAGE(digest == refs[i].digest,
                              "CONSENSUS SPLIT: dispatched digest != CPU reference on " << tv.name
                                  << " — dispatched=" << digest.GetHex()
                                  << " cpu=" << refs[i].digest.GetHex());
        BOOST_REQUIRE_MESSAGE(payload == refs[i].payload,
                              "CONSENSUS SPLIT: dispatched payload != CPU reference on " << tv.name);
    }
#else
    BOOST_TEST_MESSAGE(
        "matmul/accel_v4.h not present in this tree yet — dispatched-CPU row skipped; "
        "direct-CPU determinism verified above");
#endif

    // -- GPU rows, guarded by the backends' own CMake defines ---------------
    // Each row either RUNS (and then any single differing bit is a hard
    // failure — a chain split) or is skipped with a loud BOOST_WARN so a
    // green CPU-only run can never be mistaken for hardware verification.
    // Set BTX_REQUIRE_GPU_GOLDEN=1 to turn those skips into hard failures
    // (silicon certification lane).

#if defined(BTX_V4_HAVE_ACCEL_DISPATCH) && defined(BTX_ENABLE_CUDA_EXPERIMENTAL)
    RunBackendRowOrWarn(matmul_v4::accel::Kind::CUDA, matmul_v4::backend::Kind::CUDA, refs);
#else
    SkipOrFailGpuRow(
        "SKIPPED-PENDING-HARDWARE: CUDA v4 determinism row not compiled into this "
        "binary (needs -DBTX_ENABLE_CUDA_EXPERIMENTAL=ON + matmul/accel_v4.h + IMMA "
        "hardware, Turing+). CUDA is NOT verified for v4 mining by this run — see "
        "doc/matmul-v4-gpu-backends.md (§B.6/§N.3-v).");
#endif

#if defined(BTX_V4_HAVE_ACCEL_DISPATCH) && defined(BTX_ENABLE_METAL)
    RunBackendRowOrWarn(matmul_v4::accel::Kind::METAL, matmul_v4::backend::Kind::METAL, refs);
#else
    SkipOrFailGpuRow(
        "SKIPPED-PENDING-HARDWARE: Metal v4 determinism row not compiled into this "
        "binary (needs -DBTX_ENABLE_METAL=ON + matmul/accel_v4.h + Apple M5-class "
        "INT8 TensorOps hardware). Metal is NOT verified for v4 mining by this run — "
        "see doc/matmul-v4-gpu-backends.md (§O.1/§N.3-v).");
#endif

#if defined(BTX_V4_HAVE_ACCEL_DISPATCH) && defined(BTX_ENABLE_HIP)
    RunBackendRowOrWarn(matmul_v4::accel::Kind::HIP, matmul_v4::backend::Kind::HIP, refs);
#else
    SkipOrFailGpuRow(
        "SKIPPED-PENDING-HARDWARE: HIP/ROCm v4 determinism row not compiled into "
        "this binary (needs -DBTX_ENABLE_HIP=ON + matmul/accel_v4.h + CDNA MFMA "
        "hardware). HIP is NOT verified for v4 mining by this run — see "
        "doc/matmul-v4-gpu-backends.md (§S.1/§N.3-v).");
#endif

#if defined(BTX_V4_HAVE_ACCEL_DISPATCH) && defined(BTX_ENABLE_ASCEND) && defined(BTX_HAVE_CANN)
    RunBackendRowOrWarn(matmul_v4::accel::Kind::ASCEND, matmul_v4::backend::Kind::ASCEND, refs);
#else
    SkipOrFailGpuRow(
        "SKIPPED-PENDING-HARDWARE: Ascend v4 determinism row not compiled into "
        "this binary (needs -DBTX_ENABLE_ASCEND=ON + CANN + Ascend 950 ExactGemm "
        "self-qual). See doc/btx-matmul-v4.4-ascend-950-cann-backend.md.");
#endif
}

// ---------------------------------------------------------------------------
// C-1 ADVERSARIAL HIGH-MAGNITUDE ACCUMULATOR-REGIME VECTORS
// (multi-platform roadmap §4.1 / backlog C-1; companion
// doc/btx-matmul-v4-accumulator-eligibility.md).
//
// The v4 exactness argument (spec §B.6) requires every backend to accumulate
// its s8xs8->s32 GEMMs in a TRUE >= 32-bit integer accumulator
// (matmul::int8_field::kRequiredAccumulatorBits). Some AI accelerators (TPU
// v4-class MXUs) accumulate "INT8 matmuls" in an FP32-MANTISSA-bounded
// register that is exact only up to 2^24 = 16,777,216
// (int8_field::kFp32MantissaAccumulatorBound). The ordinary determinism
// vectors above CANNOT catch such a device: XOF-random operands concentrate
// every accumulated value around ~2^21 or below at every header dimension, so
// a mis-accumulating backend passes them by luck. The three high_magnitude_*
// cases below deliberately force accumulations into the (2^24, 2^31) danger
// regime for EVERY v4 GEMM stage — the base product C = A*B, the projections
// P = U*A and Q = B*V, and the Appendix C-13 limb-pair GEMMs (whose entries
// reach n*64^2 = EXACTLY 2^24 at the mainnet n = 4096 and 2^25 at n = 8192).
//
// On this CPU (true int32 accumulation) they pass BY CONSTRUCTION — every
// assertion is either an analytically-derived exact integer or byte-equality
// between two independent consensus-equivalent evaluation paths. Their
// purpose is to be the NORMATIVE adversarial golden-vector set (roadmap M-2):
// any backend onboarding MUST replay these operand-level vectors through its
// device GEMM kernels bit-for-bit before it may be flagged mining-capable; an
// FP32-mantissa accumulator FAILS them deterministically (it must round the
// odd-stepped partial sums past 2^24) instead of failing silently at some
// future block. contrib/matmul-v4/verify-backend.sh hard-FAILs unless these
// cases both RUN and PASS (§N.3-v).
//
// Nothing here changes consensus: q, n, b, the committed object, the digest
// and the Freivalds verifier are untouched — these are additive test vectors
// over the existing building blocks at magnitudes the spec already bounds
// (§B.4: |C|,|P|,|Q| <= 15,625*n; C-13: limb-pair <= n*64^2).
// ---------------------------------------------------------------------------

// VECTOR HM-A — base product C past the FP32-mantissa ceiling.
//
// Saturating balanced-s8 operands (every entry at the +/-125 rail — valid s8
// operand values any conforming GEMM unit must handle; the XOF would never
// emit them, which is exactly why this hand-built vector is needed) at
// n = 1088, the smallest b=4-compatible dimension with 15,625*n > 2^24:
// every C entry is +/-125*125*1088 = +/-17,000,000, strictly inside
// (2^24, 2^31). The accumulator's partial sums walk up in ODD steps of
// 15,625 and cross 2^24 at k = 1074, where FP32 spacing is 2 — an
// FP32-mantissa accumulator MUST round there and corrupts every entry of C,
// hence the sketch and the digest. (At the mainnet n = 4096 the same rail
// operands reach the spec's §B.4 peak 4096*125^2 = 6.4e7; n = 1088 keeps the
// Theta(n^3) reference product affordable in a unit test while landing in
// the identical rounding regime.)
BOOST_AUTO_TEST_CASE(high_magnitude_base_product_regime)
{
    using matmul::int8_field::kFp32MantissaAccumulatorBound;

    const uint32_t n = 1088;
    const uint32_t ms = 64; // building-block sketch width for this vector (the
                            // GEMM danger regime is set by n, not by m; the
                            // consensus m = n/b shape applies to the header
                            // path, which random operands cannot push past
                            // 2^24 — see the section banner).
    BOOST_REQUIRE(matmul::int8_field::CheckAccumulationBound(n));
    BOOST_REQUIRE(matmul::v4::CheckCombineLimbBound(n));

    const int32_t peak = 125 * 125 * static_cast<int32_t>(n); // 17,000,000
    BOOST_REQUIRE_EQUAL(peak, 17'000'000);
    BOOST_REQUIRE_GT(static_cast<int64_t>(peak), kFp32MantissaAccumulatorBound);
    BOOST_REQUIRE_LT(static_cast<int64_t>(peak), static_cast<int64_t>(1) << 31);

    // A: every entry +125. B: columns alternate -125 / +125 so both signs of
    // the danger regime are exercised in one product.
    std::vector<int8_t> A(static_cast<size_t>(n) * n, int8_t{125});
    std::vector<int8_t> B(static_cast<size_t>(n) * n);
    for (uint32_t k = 0; k < n; ++k) {
        for (uint32_t j = 0; j < n; ++j) {
            B[static_cast<size_t>(k) * n + j] = (j & 1) ? int8_t{125} : int8_t{-125};
        }
    }

    // Reference product: every entry must be EXACTLY +/-17,000,000 — any
    // accumulator that rounds past 2^24 cannot reproduce this matrix.
    const std::vector<int32_t> C = matmul::v4::ComputeExactProduct(A, B, n);
    size_t mismatches = 0;
    for (size_t idx = 0; idx < C.size(); ++idx) {
        const int32_t expected = ((idx % n) & 1) ? peak : -peak;
        mismatches += (C[idx] != expected) ? 1 : 0;
    }
    BOOST_REQUIRE_MESSAGE(mismatches == 0,
                          "HM-A: " << mismatches << " base-product entries diverged from the exact "
                                   << "+/-17,000,000 rail — int32 accumulation broken in the "
                                      "(2^24, 2^31) regime");

    // Projectors from the REAL ExpandProjector derivation (fixed seeds), then
    // the committed sketch through THREE independent consensus-equivalent
    // paths — full-C projection, direct P*Q mod q, and the C-13 limb-tensor
    // combine — which must agree byte-for-byte.
    const uint256 seed_u = ParseUint256("4504d44d861b69197db1d95e473442346c4f2bc1f5869996bdccd63cfbdbd150");
    const uint256 seed_v = ParseUint256("c6a811f7f75fe4e64be106a50351aed9c04403a74bfe7b4bbe59f7311722b735");
    const std::vector<int8_t> U = matmul::v4::ExpandProjector(seed_u, ms, n);
    const std::vector<int8_t> V = matmul::v4::ExpandProjector(seed_v, n, ms);

    const auto sketch_full = matmul::v4::ComputeSketch(U, C, V, n, ms);
    const std::vector<int32_t> P = matmul::v4::ComputeProjectedLeft(U, A, n, ms);
    const std::vector<int32_t> Q = matmul::v4::ComputeProjectedRight(B, V, n, ms);
    const auto sketch_direct = matmul::v4::ComputeCombineModQ(P, Q, n, ms);
    const auto sketch_limb = matmul::v4::ComputeCombineLimbTensor(P, Q, n, ms);
    BOOST_REQUIRE_MESSAGE(sketch_direct == sketch_full,
                          "HM-A: direct (U*A)(B*V) sketch != full-C sketch on high-magnitude C");
    BOOST_REQUIRE_MESSAGE(sketch_limb == sketch_full,
                          "HM-A: C-13 limb-tensor sketch != full-C sketch on high-magnitude C");

    // Serialization + committed-digest tie-in: identical residues must yield
    // identical payload bytes, a canonical ParseSketch round-trip, and one
    // digest under H(sigma || Chat).
    const std::vector<unsigned char> payload = matmul::v4::SerializeSketch(sketch_full);
    BOOST_REQUIRE_EQUAL(payload.size(), static_cast<size_t>(8) * ms * ms);
    BOOST_REQUIRE(matmul::v4::SerializeSketch(sketch_limb) == payload);
    std::vector<matmul::v4::Fq> reparsed;
    BOOST_REQUIRE(matmul::v4::ParseSketch(payload, ms, reparsed));
    BOOST_REQUIRE(reparsed == sketch_full);
    const uint256 sigma = ParseUint256("1111111111111111111111111111111111111111111111111111111111111111");
    BOOST_REQUIRE(matmul::v4::ComputeSketchDigest(sigma, payload) ==
                  matmul::v4::ComputeSketchDigest(sigma, matmul::v4::SerializeSketch(sketch_direct)));
}

// VECTOR HM-B — projected P = U*A and Q = B*V past 2^24 from the REAL XOF
// derivation, at the mainnet dimension n = 4096.
//
// A and B are genuine ExpandOperand matrices (fixed seeds). Random projectors
// cannot push P/Q past ~2^21, so the projector is built as a GRAM slice of
// the operand itself: U row r is column cols[r] of A (every entry a genuine
// balanced-s8 value, so U is a valid projector any backend GEMM must accept).
// Then P[r][cols[r]] = sum_i A[i][cols[r]]^2 — a length-4096 sum of squares
// with expected value 5,250*4,096 ~ 21.5e6 > 2^24, i.e. a REAL-OPERAND
// accumulation deep inside the danger regime, with generic (odd/even) partial
// sums that an FP32-mantissa accumulator must round. Symmetrically for
// Q = B*V with V columns taken from rows of B. The resulting high-magnitude
// P/Q (entries > 2^24) are then pushed through the C-13 limb combine, which
// exercises the top base-2^7 digit planes (d3 != 0) for the first time in
// this suite.
BOOST_AUTO_TEST_CASE(high_magnitude_projected_gram_regime)
{
    using matmul::int8_field::kFp32MantissaAccumulatorBound;

    const uint32_t n = 4096; // mainnet dimension
    const uint32_t ms = 8;   // Gram-slice width: 8 projected rows/cols suffice
                             // to land 8 independent accumulations past 2^24
                             // while keeping the reference O(ms * n^2).
    BOOST_REQUIRE(matmul::int8_field::CheckAccumulationBound(n));
    BOOST_REQUIRE(matmul::v4::CheckCombineLimbBound(n));

    const uint256 seed_a = ParseUint256("4504d44d861b69197db1d95e473442346c4f2bc1f5869996bdccd63cfbdbd150");
    const uint256 seed_b = ParseUint256("c6a811f7f75fe4e64be106a50351aed9c04403a74bfe7b4bbe59f7311722b735");
    const std::vector<int8_t> A = matmul::v4::ExpandOperand(seed_a, n);
    const std::vector<int8_t> B = matmul::v4::ExpandOperand(seed_b, n);

    // -- P = U*A with U rows = columns of A (Gram construction) -------------
    // The expected values are GOLDEN: generated 2026-07-16 from this exact
    // seed/XOF derivation on the true-int32 CPU reference and pinned forever.
    // Every one lies in (2^24, 2^30) — the regime an FP32-mantissa
    // accumulator cannot reproduce.
    const uint32_t cols[8] = {0, 1, 191, 1024, 2047, 2718, 3141, 4095};
    const int32_t kGramP[8] = {21'707'085, 21'770'049, 21'614'300, 21'170'086,
                               21'643'083, 21'543'048, 22'147'078, 21'749'154};
    std::vector<int8_t> U(static_cast<size_t>(ms) * n);
    for (uint32_t r = 0; r < ms; ++r) {
        for (uint32_t i = 0; i < n; ++i) {
            U[static_cast<size_t>(r) * n + i] = A[static_cast<size_t>(i) * n + cols[r]];
        }
    }
    const std::vector<int32_t> P = matmul::v4::ComputeProjectedLeft(U, A, n, ms);
    for (uint32_t r = 0; r < ms; ++r) {
        // Independent int64 recomputation pins the exact value and proves the
        // int32 path did not wrap; the range check pins the danger regime;
        // the golden constant pins the XOF derivation.
        int64_t ref = 0;
        for (uint32_t i = 0; i < n; ++i) {
            const int64_t a = A[static_cast<size_t>(i) * n + cols[r]];
            ref += a * a;
        }
        const int32_t got = P[static_cast<size_t>(r) * n + cols[r]];
        BOOST_REQUIRE_MESSAGE(static_cast<int64_t>(got) == ref,
                              "HM-B: P[" << r << "][" << cols[r] << "] = " << got
                                         << " != exact Gram value " << ref);
        BOOST_REQUIRE_MESSAGE(got == kGramP[r],
                              "HM-B: P[" << r << "][" << cols[r] << "] = " << got
                                         << " != pinned golden value " << kGramP[r]);
        BOOST_REQUIRE_MESSAGE(ref > kFp32MantissaAccumulatorBound,
                              "HM-B: Gram column " << cols[r] << " value " << ref
                                                   << " unexpectedly below 2^24 — vector no longer "
                                                      "exercises the danger regime");
        BOOST_REQUIRE_LT(ref, static_cast<int64_t>(1) << 30); // §B.4 envelope
    }

    // The same accumulation through the scalar consensus primitive.
    std::vector<int8_t> col0(n);
    for (uint32_t i = 0; i < n; ++i) col0[i] = A[static_cast<size_t>(i) * n + cols[0]];
    BOOST_REQUIRE_EQUAL(matmul::int8_field::ExactDot(col0.data(), col0.data(), n),
                        P[static_cast<size_t>(0) * n + cols[0]]);

    // -- Q = B*V with V columns = rows of B (Gram construction) -------------
    // Golden values: same derivation/pinning discipline as kGramP above.
    const uint32_t rows[8] = {0, 7, 512, 1023, 2048, 3000, 4000, 4095};
    const int32_t kGramQ[8] = {21'738'326, 21'743'142, 21'653'779, 21'133'642,
                               21'614'940, 21'416'532, 21'188'040, 21'513'072};
    std::vector<int8_t> V(static_cast<size_t>(n) * ms);
    for (uint32_t j = 0; j < n; ++j) {
        for (uint32_t c = 0; c < ms; ++c) {
            V[static_cast<size_t>(j) * ms + c] = B[static_cast<size_t>(rows[c]) * n + j];
        }
    }
    const std::vector<int32_t> Q = matmul::v4::ComputeProjectedRight(B, V, n, ms);
    for (uint32_t c = 0; c < ms; ++c) {
        int64_t ref = 0;
        for (uint32_t j = 0; j < n; ++j) {
            const int64_t b = B[static_cast<size_t>(rows[c]) * n + j];
            ref += b * b;
        }
        const int32_t got = Q[static_cast<size_t>(rows[c]) * ms + c];
        BOOST_REQUIRE_MESSAGE(static_cast<int64_t>(got) == ref,
                              "HM-B: Q[" << rows[c] << "][" << c << "] = " << got
                                         << " != exact Gram value " << ref);
        BOOST_REQUIRE_MESSAGE(got == kGramQ[c],
                              "HM-B: Q[" << rows[c] << "][" << c << "] = " << got
                                         << " != pinned golden value " << kGramQ[c]);
        BOOST_REQUIRE_MESSAGE(ref > kFp32MantissaAccumulatorBound,
                              "HM-B: Gram row " << rows[c] << " value " << ref
                                                << " unexpectedly below 2^24");
        BOOST_REQUIRE_LT(ref, static_cast<int64_t>(1) << 30);
    }

    // -- C-13 limb combine over REAL P/Q whose entries exceed 2^24 ----------
    // (combine INPUTS in (2^24, 2^27): the top digit plane d3 is nonzero, and
    // the direct mod-q path must match the limb-tensor path byte-for-byte).
    const auto direct = matmul::v4::ComputeCombineModQ(P, Q, n, ms);
    const auto limb = matmul::v4::ComputeCombineLimbTensor(P, Q, n, ms);
    BOOST_REQUIRE_MESSAGE(limb == direct,
                          "HM-B: limb-tensor combine != direct mod-q combine over "
                          "high-magnitude P/Q (top digit plane mis-handled)");
    const auto stacked = matmul::v4::ComputeCombineLimbTensorStacked(P, Q, n, ms, ms);
    BOOST_REQUIRE(stacked == direct);
}

// VECTOR HM-C — the C-13 limb-pair GEMM at and past its n*64^2 accumulator
// peak (the stage MOST exposed to an FP32-mantissa accumulator: the peak is
// EXACTLY 2^24 at the mainnet n = 4096 and 2^25 at n = 8192 — at/past the
// ceiling on precisely the spec's target dimension window; roadmap §4.1).
//
// Construction: an int32 entry x = 64 has balanced base-2^7 digits
// (d0, d1) = (-64, +1), so all-64 P/Q matrices drive the limb-pair GEMM
// S_00[a][c] = sum_k (-64)*(-64) = n*64^2 — the exact worst-case accumulator
// magnitude. Entries x = 65 give d0 = -63 so S_00 = n*3969 climbs in ODD
// steps: once the partial sum passes 2^24 (where FP32 spacing is 2) every odd
// step MUST round on an FP32-mantissa accumulator, making the divergence
// deterministic rather than data-dependent. Each sub-case asserts the exact
// analytic combine value AND byte-equality between the limb-tensor path and
// the direct mod-q path.
BOOST_AUTO_TEST_CASE(high_magnitude_limb_pair_boundary_regime)
{
    using matmul::int8_field::kFieldPrime;
    using matmul::int8_field::kFp32MantissaAccumulatorBound;
    using matmul::v4::Fq;

    // Pin the roadmap §4.1 arithmetic in code: n*64^2 == 2^24 at n = 4096.
    BOOST_REQUIRE_EQUAL(static_cast<int64_t>(4096) * 64 * 64, kFp32MantissaAccumulatorBound);

    const uint32_t ms = 4; // limb-pair GEMM width; the accumulator regime is
                           // set by the reduction length n, not by m.

    // One sub-case: constant-fill P (ms x n) and Q (n x ms), every output
    // entry n * pval * qval; limb path must equal direct path byte-for-byte
    // and both must equal the analytic canonical residue.
    const auto run_case = [&](uint32_t n, int32_t pval, int32_t qval, const char* label) {
        BOOST_REQUIRE(matmul::v4::CheckCombineLimbBound(n));
        const std::vector<int32_t> P(static_cast<size_t>(ms) * n, pval);
        const std::vector<int32_t> Q(static_cast<size_t>(n) * ms, qval);
        const auto direct = matmul::v4::ComputeCombineModQ(P, Q, n, ms);
        const auto limb = matmul::v4::ComputeCombineLimbTensor(P, Q, n, ms);
        BOOST_REQUIRE_MESSAGE(limb == direct,
                              "HM-C[" << label << "]: limb-tensor combine != direct mod-q combine");
        const int64_t exact = static_cast<int64_t>(n) * pval * qval; // |.| < 2^63 for all cases here
        const Fq expected = matmul::int8_field::FqFromSigned(exact);
        for (const Fq word : direct) {
            BOOST_REQUIRE_MESSAGE(word == expected,
                                  "HM-C[" << label << "]: combine entry " << word
                                          << " != analytic residue " << expected);
        }
        return direct;
    };

    // (a) EXACT boundary at mainnet n = 4096: digits of 64 are (-64, +1), so
    //     the S_00 limb-pair GEMM accumulates to 4096*64^2 = 2^24 exactly —
    //     the C-13 accumulator peak at the mainnet dimension. Output entries
    //     are also exactly 2^24 (canonical residue 2^24 < q).
    const auto boundary = run_case(4096, 64, 64, "n4096-boundary-2^24");
    for (const Fq word : boundary) {
        BOOST_REQUIRE_EQUAL(word, static_cast<Fq>(1) << 24);
    }

    // (b) n = 8192 (the spec's retarget dimension): S_00 = 8192*64^2 = 2^25,
    //     a full binade past the FP32-mantissa ceiling.
    const auto retarget = run_case(8192, 64, 64, "n8192-2^25");
    for (const Fq word : retarget) {
        BOOST_REQUIRE_EQUAL(word, static_cast<Fq>(1) << 25);
    }

    // (c) ODD-STEP climb past 2^24: entries 65 -> d0 = -63, so S_00 =
    //     4352*3969 = 17,273,088 > 2^24 accumulated in odd steps of 3,969 —
    //     an FP32-mantissa accumulator must round every odd partial sum past
    //     2^24. (n = 4352 is the smallest multiple of 128 with n*3969 > 2^24.)
    run_case(4352, 65, 65, "n4352-odd-steps");

    // (d) NEGATIVE side of the regime at the same magnitude: -64 has the
    //     single digit d0 = -64, so the combine value is -2^24 and the limb
    //     recombine must land on the canonical residue q - 2^24.
    const auto negative = run_case(4096, -64, 64, "n4096-negative-2^24");
    for (const Fq word : negative) {
        BOOST_REQUIRE_EQUAL(word, kFieldPrime - (static_cast<Fq>(1) << 24));
    }

    // (e) Combine INPUTS above 2^24 (as HM-B produces from real operands):
    //     P entries 16,777,301 (> 2^24, odd, inside the 15,625*n = 68e6
    //     envelope at n = 4352 and the 2^27 limb-decomposition range) force
    //     all four digit planes including d3 to be nonzero.
    run_case(4352, 16'777'301, 64, "n4352-input-past-2^24");

    // (f) STACKED combine (the §K.2b batched-miner GEMM shape): stacking a
    //     boundary block and an odd-step block must reproduce the single-nonce
    //     limb combine byte-for-byte per column block.
    {
        const uint32_t n = 4352;
        BOOST_REQUIRE(matmul::v4::CheckCombineLimbBound(n));
        const std::vector<int32_t> P65(static_cast<size_t>(ms) * n, 65);
        const std::vector<int32_t> Q64(static_cast<size_t>(n) * ms, 64);
        const std::vector<int32_t> Q65(static_cast<size_t>(n) * ms, 65);
        std::vector<int32_t> Qstack(static_cast<size_t>(n) * 2 * ms);
        for (uint32_t k = 0; k < n; ++k) {
            for (uint32_t c = 0; c < 2 * ms; ++c) {
                Qstack[static_cast<size_t>(k) * 2 * ms + c] = (c < ms) ? 64 : 65;
            }
        }
        const auto stacked = matmul::v4::ComputeCombineLimbTensorStacked(P65, Qstack, n, ms, 2 * ms);
        const auto block0 = matmul::v4::ComputeCombineLimbTensor(P65, Q64, n, ms);
        const auto block1 = matmul::v4::ComputeCombineLimbTensor(P65, Q65, n, ms);
        BOOST_REQUIRE_EQUAL(stacked.size(), static_cast<size_t>(ms) * 2 * ms);
        for (uint32_t a = 0; a < ms; ++a) {
            for (uint32_t c = 0; c < ms; ++c) {
                BOOST_REQUIRE_EQUAL(stacked[static_cast<size_t>(a) * 2 * ms + c],
                                    block0[static_cast<size_t>(a) * ms + c]);
                BOOST_REQUIRE_EQUAL(stacked[static_cast<size_t>(a) * 2 * ms + ms + c],
                                    block1[static_cast<size_t>(a) * ms + c]);
            }
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
