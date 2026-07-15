// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// MatMul v4 determinism GOLDEN-VECTOR harness (design spec §B.6, §N.3-v,
// and the TV1-TV6 test-vector discipline inherited from v3).
//
// Purpose: pin the exact consensus bytes — canonical digest and sketch
// payload — for a small fixed set of (header, n, R) inputs, so that ANY
// conforming backend (pure-integer CPU reference, CUDA IMMA, ROCm MFMA,
// Apple M5-class Metal TensorOps, AVX-512 VNNI) can be checked bit-for-bit
// against the same vectors. The pure-integer CPU implementation is the
// consensus definition; every tensor path must match it exactly (§N.3-v).
//
// Workflow:
//   1. UNPINNED vectors (expected fields empty) are computed and their
//      canonical values are printed to the test log. Once the reference
//      implementation is reviewed, paste the printed hex into the table —
//      the vectors are then PINNED and enforced with hard asserts.
//   2. Hardware backend slots (H100 / B200 / Apple M5) are declared below
//      as TODO placeholders: filling them requires running the miner
//      backend on physical hardware and confirming its digest/payload
//      bytes equal the pinned CPU values. Until then those entries only
//      document the procedure; they do not run.
//
// Every vector uses deterministic, hand-written header fields — no clocks,
// no OS randomness — so the table is reproducible on any machine.

#include <matmul/pow_v4.h>

#include <crypto/sha256.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>
#include <array>
#include <cstdint>
#include <span>
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

//! One golden determinism vector. `expected_digest_hex` and
//! `expected_payload_sha256_hex` empty => UNPINNED (harness prints the
//! canonical values to pin); non-empty => enforced bit-for-bit.
struct GoldenVector {
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
    std::string_view expected_digest_hex;         // uint256 GetHex() form
    std::string_view expected_payload_sha256_hex; // SHA256 of the raw sketch bytes
};

// Test dimensions are n = 256 / 512 for suite speed. Production runs
// n = 4096 (§0.7); mainnet-dimension vectors belong in the release-gate
// bench/QA lane, not the default unit suite (§D.5 verify budget).
constexpr GoldenVector kGoldenVectors[] = {
    {
        .name = "V4-TV1-n256-r2-zero-seed",
        .prev_hash = "0000000000000000000000000000000000000000000000000000000000000000",
        .merkle_root = "0000000000000000000000000000000000000000000000000000000000000000",
        .time = 1'770'000'000,
        .bits = 0x207fffff,
        .nonce = 0,
        .seed_a = "0000000000000000000000000000000000000000000000000000000000000000",
        .seed_b = "0000000000000000000000000000000000000000000000000000000000000000",
        .n = 256,
        .rounds = 2, // regtest round count (§G.2)
        // Pinned 2026-07-15 from the reviewed v4.1 batched-sketch reference
        // (b = 4, template-scoped A/U/V per §A.2 v4.1/I1'; supersedes every
        // earlier b = 8 / sigma-derived-projector value).
        .expected_digest_hex = "8d1b687fc7693f20d893326443cbff348d84a98a411113797ea9d03cbea8b519",
        .expected_payload_sha256_hex = "a4d30087ceadba54ca35551257a65a06377edd442ecb59bf666ca4ddf84b9af2",
    },
    {
        .name = "V4-TV2-n256-r3-structured-seed",
        .prev_hash = "1111111111111111111111111111111111111111111111111111111111111111",
        .merkle_root = "2222222222222222222222222222222222222222222222222222222222222222",
        .time = 1'770'000'090,
        .bits = 0x207fffff,
        .nonce = 42,
        .seed_a = "0000000000000000000000000000000000000000000000000000000000000000",
        .seed_b = "4504d44d861b69197db1d95e473442346c4f2bc1f5869996bdccd63cfbdbd150",
        .n = 256,
        .rounds = 3, // production round count (§0.7-(2))
        .expected_digest_hex = "338e64d0ba3d582c823593fe16dc7e35c2fbbe134584e378b25e9a6f269f1860",
        .expected_payload_sha256_hex = "f65a9b9f5ce8f5a6b932cc4fb924211da43889349078f09e08ba79631f41e6c1",
    },
    {
        .name = "V4-TV3-n256-r3-adjacent-nonce",
        // Identical to V4-TV2 except nNonce64: pins nonce-freshness of the
        // sigma/seed_B/challenge chain (§C-I1'; A/U/V are template-scoped
        // in v4.1, so only the B-side and the digest binding may differ).
        .prev_hash = "1111111111111111111111111111111111111111111111111111111111111111",
        .merkle_root = "2222222222222222222222222222222222222222222222222222222222222222",
        .time = 1'770'000'090,
        .bits = 0x207fffff,
        .nonce = 43,
        .seed_a = "0000000000000000000000000000000000000000000000000000000000000000",
        .seed_b = "4504d44d861b69197db1d95e473442346c4f2bc1f5869996bdccd63cfbdbd150",
        .n = 256,
        .rounds = 3,
        .expected_digest_hex = "1efae97b48b38b9d7399399cd84dae8d0ad345b19f3dc3282f6c58ba605c0d39",
        .expected_payload_sha256_hex = "66df2b82fc83e118dacae97d48e23ce1b96cbc607d5a7932cb4c58e02fcead80",
    },
    {
        .name = "V4-TV4-n512-r3",
        .prev_hash = "c6a811f7f75fe4e64be106a50351aed9c04403a74bfe7b4bbe59f7311722b735",
        .merkle_root = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
        .time = 1'770'000'180,
        .bits = 0x207fffff,
        .nonce = 7,
        .seed_a = "4504d44d861b69197db1d95e473442346c4f2bc1f5869996bdccd63cfbdbd150",
        .seed_b = "c6a811f7f75fe4e64be106a50351aed9c04403a74bfe7b4bbe59f7311722b735",
        .n = 512,
        .rounds = 3,
        .expected_digest_hex = "eae171c056ff30f7c1341d70f271afad2d235ea01eb0eb3a9bf0efcd81a81eb1",
        .expected_payload_sha256_hex = "b80502649893db648ba8393b8b60665c89ebfe93c7d0069afbc8208350a41493",
    },
};

// ---------------------------------------------------------------------------
// Hardware backend slots — REQUIRE PHYSICAL HARDWARE; placeholders only.
//
// The determinism claim of §B.6 is that s8 x s8 -> s32 MMA is exact and
// order-independent, so every backend must reproduce the pinned CPU bytes
// above EXACTLY. Each slot below is filled by running the corresponding
// miner backend over the same GoldenVector inputs on real silicon and
// recording (backend id, driver/library versions, digest, payload SHA256).
// A slot is complete only when its digest/payload hex equals the pinned
// CPU value for every vector; any divergence is a consensus-critical bug
// (risk register §N.3-v) and blocks that backend's mining eligibility.
//
// TODO(hardware, H100):  NVIDIA H100 (IMMA / cuBLASLt INT8) — pending access.
// TODO(hardware, B200):  NVIDIA B200 (IMMA / cuBLASLt INT8) — pending access.
// TODO(hardware, Apple): Apple M5-class Metal 4 TensorOps INT8 — pending
//                        access; pre-M5 Metal has no s8xs8->s32 path and is
//                        verification-only (§O.1), so no slot exists for it.
// TODO(hardware, AMD):   CDNA MFMA INT8 (optional at launch) — pending access.
//
// struct HardwareVector { std::string_view backend; std::string_view
//     driver_info; std::string_view vector_name; std::string_view
//     digest_hex; std::string_view payload_sha256_hex; };
// static constexpr HardwareVector kHardwareVectors[] = { /* pending */ };
// ---------------------------------------------------------------------------

CBlockHeader HeaderFromVector(const GoldenVector& tv)
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

std::string Sha256Hex(std::span<const unsigned char> bytes)
{
    std::array<unsigned char, CSHA256::OUTPUT_SIZE> out;
    CSHA256().Write(bytes.data(), bytes.size()).Finalize(out.data());
    return HexStr(out);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(matmul_v4_determinism_vectors, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(golden_vectors_are_reproducible_and_match_pins)
{
    for (const GoldenVector& tv : kGoldenVectors) {
        CBlockHeader header = HeaderFromVector(tv);

        uint256 digest;
        std::vector<unsigned char> payload;
        BOOST_REQUIRE_MESSAGE(
            matmul_v4::ComputeDigest(header, tv.n, tv.rounds, digest, payload),
            tv.name << ": ComputeDigest failed");

        // (1) Self-consistency: a second run must be byte-identical. This
        // is the machine-local half of the §B.6 determinism argument and
        // holds regardless of whether the vector is pinned yet.
        {
            uint256 digest2;
            std::vector<unsigned char> payload2;
            BOOST_REQUIRE(matmul_v4::ComputeDigest(header, tv.n, tv.rounds, digest2, payload2));
            BOOST_CHECK_MESSAGE(digest2 == digest, tv.name << ": digest not reproducible");
            BOOST_CHECK_MESSAGE(payload2 == payload, tv.name << ": payload not reproducible");
        }

        // (2) The emitted proof must verify under the same inputs. Seal the
        // mined digest into the header first, exactly as SolveMatMulV4 does
        // before finalizing a block: VerifySketch recomputes the digest from
        // the payload and requires it to equal header.matmul_digest (§0.7-(1)).
        {
            header.matmul_digest = digest;
            uint256 verified;
            BOOST_CHECK_MESSAGE(
                matmul_v4::VerifySketch(header, tv.n, tv.rounds, payload, verified),
                tv.name << ": honest proof failed VerifySketch");
            BOOST_CHECK_MESSAGE(verified == digest, tv.name << ": verify digest mismatch");
        }

        // (3) Shape pin: 8 * (n/b)^2 payload bytes (§E.1).
        {
            const size_t m = tv.n / matmul_v4::kTileB;
            BOOST_CHECK_MESSAGE(payload.size() == 8 * m * m,
                                tv.name << ": unexpected sketch payload size " << payload.size());
        }

        // (4) Golden pin: enforce when pinned, emit when not.
        const std::string digest_hex = digest.GetHex();
        const std::string payload_hex = Sha256Hex(payload);
        if (tv.expected_digest_hex.empty() || tv.expected_payload_sha256_hex.empty()) {
            // UNPINNED — print canonical values for pinning. Deliberately
            // loud (WARN, not MESSAGE) so unpinned vectors are visible in
            // default test output and cannot be forgotten at release time.
            BOOST_WARN_MESSAGE(false,
                               "UNPINNED golden vector " << tv.name
                                   << " — pin these values in matmul_v4_determinism_vectors.cpp:"
                                   << " digest=" << digest_hex
                                   << " payload_sha256=" << payload_hex);
        } else {
            BOOST_CHECK_MESSAGE(digest_hex == tv.expected_digest_hex,
                                tv.name << ": digest " << digest_hex
                                        << " != pinned " << tv.expected_digest_hex);
            BOOST_CHECK_MESSAGE(payload_hex == tv.expected_payload_sha256_hex,
                                tv.name << ": payload sha256 " << payload_hex
                                        << " != pinned " << tv.expected_payload_sha256_hex);
        }
    }
}

BOOST_AUTO_TEST_CASE(adjacent_nonce_vectors_diverge)
{
    // V4-TV2 vs V4-TV3 differ only in nNonce64; their digests and payloads
    // must be unrelated (nonce-fresh sigma/B chain, §C-I1'). Pinning both
    // makes this property part of the cross-backend contract.
    const GoldenVector& tv2 = kGoldenVectors[1];
    const GoldenVector& tv3 = kGoldenVectors[2];
    BOOST_REQUIRE_EQUAL(tv2.nonce + 1, tv3.nonce);

    uint256 d2, d3;
    std::vector<unsigned char> p2, p3;
    BOOST_REQUIRE(matmul_v4::ComputeDigest(HeaderFromVector(tv2), tv2.n, tv2.rounds, d2, p2));
    BOOST_REQUIRE(matmul_v4::ComputeDigest(HeaderFromVector(tv3), tv3.n, tv3.rounds, d3, p3));

    BOOST_CHECK(d2 != d3);
    BOOST_CHECK(p2 != p3);
}

BOOST_AUTO_TEST_CASE(hardware_backend_vectors_pending)
{
    // Placeholder gate for the real-hardware determinism matrix (see the
    // TODO(hardware, ...) block above). This test exists so the pending
    // work is tracked inside the suite itself; it intentionally asserts
    // nothing about hardware we cannot run in CI. When a hardware vector
    // set is recorded, add a HardwareVector table and compare each entry
    // against the pinned CPU values of kGoldenVectors bit-for-bit.
    BOOST_TEST_MESSAGE(
        "matmul v4 hardware determinism vectors pending: H100, B200, Apple M5 "
        "(requires physical hardware; CPU reference above is the consensus "
        "definition per spec §N.3-v)");
    BOOST_CHECK(true);
}

BOOST_AUTO_TEST_SUITE_END()
