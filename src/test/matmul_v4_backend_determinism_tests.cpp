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

#if defined(BTX_V4_HAVE_ACCEL_DISPATCH)
//! Run one compiled-in GPU backend over every vector and REQUIRE its
//! (digest, payload) to be byte-identical to the CPU reference. Loudly warns
//! (never silently passes) when the backend is compiled in but no admissible
//! device is present at runtime.
void RunBackendRowOrWarn(matmul_v4::accel::Kind accel_kind,
                         matmul_v4::backend::Kind backend_kind,
                         const std::vector<CpuReference>& refs)
{
    const std::string name = matmul_v4::backend::ToString(backend_kind);
    const auto eligibility = matmul_v4::backend::EligibilityFor(backend_kind);
    if (!eligibility.available || !eligibility.admissible) {
        BOOST_WARN_MESSAGE(false,
                           "SKIPPED-PENDING-HARDWARE: v4 backend '" << name
                               << "' compiled in but not runnable here (available="
                               << eligibility.available << ", admissible=" << eligibility.admissible
                               << ", reason=" << eligibility.reason
                               << "). Run this suite on real hardware per doc/matmul-v4-gpu-backends.md; "
                                  "the backend is NOT verified for mining until this row passes (§N.3-v).");
        return;
    }

    for (size_t i = 0; i < std::size(kVectors); ++i) {
        const DeterminismVector& tv = kVectors[i];
        const CBlockHeader header = HeaderFromVector(tv);

        uint256 digest;
        std::vector<unsigned char> payload;
        BOOST_REQUIRE_MESSAGE(
            matmul_v4::accel::ComputeDigestAccel(accel_kind, header, tv.n, tv.rounds, digest, payload),
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
    for (const char* name : {"cuda", "nvidia", "metal", "mlx", "apple", "hip", "rocm", "amd"}) {
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

    // AllEligibility covers every backend exactly once, CPU first.
    const auto all = matmul_v4::backend::AllEligibility();
    BOOST_REQUIRE_EQUAL(all.size(), 4U);
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

#if defined(BTX_V4_HAVE_ACCEL_DISPATCH) && defined(BTX_ENABLE_CUDA_EXPERIMENTAL)
    RunBackendRowOrWarn(matmul_v4::accel::Kind::CUDA, matmul_v4::backend::Kind::CUDA, refs);
#else
    BOOST_WARN_MESSAGE(false,
                       "SKIPPED-PENDING-HARDWARE: CUDA v4 determinism row not compiled into this "
                       "binary (needs -DBTX_ENABLE_CUDA_EXPERIMENTAL=ON + matmul/accel_v4.h + IMMA "
                       "hardware, Turing+). CUDA is NOT verified for v4 mining by this run — see "
                       "doc/matmul-v4-gpu-backends.md (§B.6/§N.3-v).");
#endif

#if defined(BTX_V4_HAVE_ACCEL_DISPATCH) && defined(BTX_ENABLE_METAL)
    RunBackendRowOrWarn(matmul_v4::accel::Kind::METAL, matmul_v4::backend::Kind::METAL, refs);
#else
    BOOST_WARN_MESSAGE(false,
                       "SKIPPED-PENDING-HARDWARE: Metal v4 determinism row not compiled into this "
                       "binary (needs -DBTX_ENABLE_METAL=ON + matmul/accel_v4.h + Apple M5-class "
                       "INT8 TensorOps hardware). Metal is NOT verified for v4 mining by this run — "
                       "see doc/matmul-v4-gpu-backends.md (§O.1/§N.3-v).");
#endif

#if defined(BTX_V4_HAVE_ACCEL_DISPATCH) && defined(BTX_ENABLE_HIP)
    RunBackendRowOrWarn(matmul_v4::accel::Kind::HIP, matmul_v4::backend::Kind::HIP, refs);
#else
    BOOST_WARN_MESSAGE(false,
                       "SKIPPED-PENDING-HARDWARE: HIP/ROCm v4 determinism row not compiled into "
                       "this binary (needs -DBTX_ENABLE_HIP=ON + matmul/accel_v4.h + CDNA MFMA "
                       "hardware). HIP is NOT verified for v4 mining by this run — see "
                       "doc/matmul-v4-gpu-backends.md (§S.1/§N.3-v).");
#endif
}

BOOST_AUTO_TEST_SUITE_END()
