// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// NON-CONSENSUS research-reference tests (ROUND-3 P0-2): ENC-BMX4C-D was REMOVED
// from the consensus state machine and was never deployed. These cases exercise
// ONLY the pure integer arithmetic retained as reference code in
// src/matmul/matmul_v4_bmx4.{h,cpp} (ComputeDigestBMX4D / VerifySketchBMX4D /
// ValidateDimsBMX4D and the D seed derivations). They do NOT touch any consensus
// dispatch, activation predicate, or chainparams -- there is no consensus D path
// to test any more. Kept solely to pin the reference arithmetic's determinism.
//
// ENC-BMX4C-D committed-object profile tests (MatMul v4.2-D; design
// doc/btx-matmul-v4.2-compute-bound-redesign.md). ENC-BMX4C-D is ENC-BMX4C with
// the sketch tile b = 4 -> 2 (m = n/2), committing 4x more of the product C to
// raise the enforced per-nonce tensor work ~3.6x at 4x sketch payload, while the
// verifier stays O(n^2) integer-exact and every accumulator / M-t24 bound is
// m-independent. This suite pins the D-profile CPU reference and the redesign's
// load-bearing invariants:
//
//   (a) SHORTCUT-CLOSURE / BYTE-IDENTITY: at the D rank m = n/2, the three miner
//       schedules a rational miner may run -- the optimal factored
//       (U*Ahat)(Bhat*V), the full-C U*(Ahat*Bhat)*V, and the tensor-landing
//       base-2^6 limb combine -- all produce the SAME committed m*m object,
//       byte-for-byte. The miner cannot avoid committing the larger sketch; its
//       only freedom is which tensor schedule (an L2 choice). This is the
//       machine-checked half of the "the enforced object cannot be produced for
//       less than the intended work" argument (the analytic half is in the
//       design doc).
//   (b) ENFORCED-WORK / PAYLOAD TRADEOFF: the D payload is exactly 4x the
//       C-profile payload (8*(n/2)^2 = 4 * 8*(n/4)^2), and the enforced marginal
//       tensor-MAC count (n^2*m + 16*n*m^2) is strictly larger at b=2 than b=4.
//   (c) DETERMINISM / M-t24 PRESERVATION: run-to-run byte identity; and every
//       accumulator bound (2304*n, 288*n, 1024*n) is m-independent, so the D
//       profile is byte-for-byte identical to C on the determinism axis.
//   (d) SOUNDNESS: an honest sketch passes VerifySketchBMX4D; a perturbed but
//       digest-consistent sketch fails it; a wrong dimension/rounds is rejected.
//   (e) PROFILE INDEPENDENCE: same header -> different C-profile vs D-profile
//       digest (distinct V4.2-D domain tags + different rank).
//   + GOLDEN vectors: pinned ENC-BMX4C-D digests at fixed headers.

#include <matmul/int8_field.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_bmx4.h>

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

using namespace matmul::v4;
namespace bx = matmul::v4::bmx4;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_bmx4d_tests, BasicTestingSetup)

namespace {

constexpr uint32_t kTestDim = 256; // b=2 -> m=128; 256 % 32 == 0, 128 % 32 == 0

uint256 ParseUint256(std::string_view hex)
{
    const auto parsed = uint256::FromHex(hex);
    BOOST_REQUIRE(parsed.has_value());
    return *parsed;
}

CBlockHeader MakeV4Header(uint64_t nonce, uint32_t n)
{
    CBlockHeader header;
    header.nVersion = 0x20000004;
    header.hashPrevBlock = ParseUint256("5151515151515151515151515151515151515151515151515151515151515151");
    header.hashMerkleRoot = ParseUint256("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3");
    header.nTime = 1'770'000'000;
    header.nBits = 0x207fffff;
    header.nNonce64 = nonce;
    header.nNonce = static_cast<uint32_t>(nonce);
    header.matmul_dim = static_cast<uint16_t>(n);
    header.seed_a = ParseUint256("1111111111111111111111111111111111111111111111111111111111111111");
    header.seed_b = ParseUint256("2222222222222222222222222222222222222222222222222222222222222222");
    return header;
}

std::string Sha256Hex(std::span<const unsigned char> bytes)
{
    std::array<unsigned char, CSHA256::OUTPUT_SIZE> out;
    CSHA256().Write(bytes.data(), bytes.size()).Finalize(out.data());
    return HexStr(out);
}

} // namespace

// --- (b) rank / payload / enforced-work tradeoff ---------------------------

BOOST_AUTO_TEST_CASE(d_profile_rank_and_payload_are_4x_c_profile)
{
    // The D tile is b=2 (m=n/2), exactly double the C tile's m=n/4.
    BOOST_CHECK_EQUAL(bx::kTileBMX4D, 2u);
    BOOST_CHECK_EQUAL(kTileB, 4u); // C-profile tile, for the ratio

    const uint32_t n = kTestDim;
    uint32_t m_d = 0, m_c = 0;
    BOOST_REQUIRE(bx::ValidateDimsBMX4D(n, m_d));
    BOOST_REQUIRE(matmul::v4::ValidateDims(n, kTileB, m_c));
    BOOST_CHECK_EQUAL(m_d, n / 2);
    BOOST_CHECK_EQUAL(m_c, n / 4);
    BOOST_CHECK_EQUAL(m_d, 2 * m_c);

    CBlockHeader header = MakeV4Header(7, n);
    uint256 digest_d, digest_c;
    std::vector<unsigned char> payload_d, payload_c;
    BOOST_REQUIRE(bx::ComputeDigestBMX4D(header, n, digest_d, payload_d));
    BOOST_REQUIRE(bx::ComputeDigestBMX4C(header, n, digest_c, payload_c));

    // Sketch payload is 8*m^2 bytes; D is exactly 4x C (m doubled).
    BOOST_CHECK_EQUAL(payload_d.size(), 8u * m_d * m_d);
    BOOST_CHECK_EQUAL(payload_c.size(), 8u * m_c * m_c);
    BOOST_CHECK_EQUAL(payload_d.size(), 4u * payload_c.size());

    // Enforced marginal tensor-MAC count n^2*m + 16*n*m^2 is strictly larger at
    // b=2. This is the quantified enforced-work lever (the combine term is
    // quadratic in m), pinned as a machine-checked invariant.
    auto enforced_macs = [n](uint64_t m) -> uint64_t {
        return static_cast<uint64_t>(n) * n * m + 16ull * n * m * m;
    };
    const uint64_t work_d = enforced_macs(m_d);
    const uint64_t work_c = enforced_macs(m_c);
    BOOST_CHECK_GT(work_d, work_c);
    // At m_d = 2*m_c the combine term (16 n m^2) quadruples and dominates, so
    // the total is > 3x the C-profile enforced work (3.6x in the n>>1 limit).
    BOOST_CHECK_GT(work_d, 3u * work_c);
}

// --- (c) M-t24 / determinism preservation ----------------------------------

BOOST_AUTO_TEST_CASE(d_profile_accumulator_bounds_are_m_independent)
{
    // The whole point that keeps M-t24 byte-identical: every accumulator bound
    // is a function of n only, NOT of the sketch rank m/tile b. The D profile
    // reuses the exact ENC-BMX4C constants; growing m spends payload, never
    // precision. This pins that the D construction touches no determinism bound.
    const uint32_t n = kTestDim;
    // |P|,|Q| <= 288*n gate is the same call for C and D.
    BOOST_CHECK(bx::CheckCombineLimbBoundBMX4C(n));
    // Base product |C| <= 2304*n and limb-pair |S| <= 1024*n stay < 2^24-region
    // exactly as in the C profile (m absent from all three).
    BOOST_CHECK_LT(static_cast<int64_t>(bx::kBaseProductPerMac) * n, (int64_t{1} << 31));
    BOOST_CHECK_LT(static_cast<int64_t>(bx::kProjPerMac) * n, bx::kCombineMaxAbs + 1);
    BOOST_CHECK_LT(static_cast<int64_t>(bx::kCombineLimbPairPerMac) * n, (int64_t{1} << 31));
}

BOOST_AUTO_TEST_CASE(d_profile_digest_is_deterministic)
{
    const uint32_t n = kTestDim;
    CBlockHeader header = MakeV4Header(1234, n);
    uint256 d1, d2;
    std::vector<unsigned char> p1, p2;
    BOOST_REQUIRE(bx::ComputeDigestBMX4D(header, n, d1, p1));
    BOOST_REQUIRE(bx::ComputeDigestBMX4D(header, n, d2, p2));
    BOOST_CHECK(d1 == d2);
    BOOST_CHECK(p1 == p2);
}

// --- (a) shortcut-closure: all miner schedules commit the SAME object -------

BOOST_AUTO_TEST_CASE(d_profile_all_schedules_are_byte_identical)
{
    // At the D rank m = n/2, regenerate the operands exactly as
    // ComputeDigestBMX4D does, then evaluate the sketch three ways:
    //   (1) optimal factored:   (U*Ahat)(Bhat*V) via ComputeCombineModQ
    //   (2) full-C reference:    U*(Ahat*Bhat)*V via ComputeExactProduct+Sketch
    //   (3) tensor-landing limb: the base-2^6 limb-tensor combine
    // All THREE must be byte-identical. This is the machine-checked shortcut-
    // closure invariant: whatever schedule the miner runs, it must commit the
    // same m*m = (n/2)^2 object -- there is no cheaper committed object.
    const uint32_t n = kTestDim;
    uint32_t m = 0;
    BOOST_REQUIRE(bx::ValidateDimsBMX4D(n, m));

    CBlockHeader header = MakeV4Header(99, n);
    const uint256 seed_a = bx::DeriveOperandSeedBMX4D(header, Operand::A);
    const uint256 seed_b = bx::DeriveOperandSeedBMX4D(header, Operand::B);
    const auto [seed_u, seed_v] = bx::DeriveProjectorSeedsBMX4D(header);
    const std::vector<int8_t> Ahat = bx::ExpandOperandA(seed_a, n);
    const std::vector<int8_t> Bhat = bx::ExpandOperandB(seed_b, n);
    const std::vector<int8_t> U = bx::ExpandProjectorBMX4C(seed_u, m, n);
    const std::vector<int8_t> V = bx::ExpandProjectorBMX4C(seed_v, n, m);

    const std::vector<int32_t> P = ComputeProjectedLeft(U, Ahat, n, m);
    const std::vector<int32_t> Q = ComputeProjectedRight(Bhat, V, n, m);

    // (1) optimal factored
    const std::vector<Fq> sketch_factored = ComputeCombineModQ(P, Q, n, m);
    // (2) full-C
    const std::vector<int32_t> C = ComputeExactProduct(Ahat, Bhat, n);
    const std::vector<Fq> sketch_fullc = ComputeSketch(U, C, V, n, m);
    // (3) tensor-landing base-2^6 limb combine
    const std::vector<Fq> sketch_limb = bx::ComputeCombineLimbTensorBMX4C(P, Q, n, m);

    BOOST_REQUIRE_EQUAL(sketch_factored.size(), static_cast<size_t>(m) * m);
    BOOST_CHECK(sketch_factored == sketch_fullc);
    BOOST_CHECK(sketch_factored == sketch_limb);

    // And the serialized payload matches ComputeDigestBMX4D's own output.
    uint256 digest;
    std::vector<unsigned char> payload;
    BOOST_REQUIRE(bx::ComputeDigestBMX4D(header, n, digest, payload));
    BOOST_CHECK(SerializeSketch(sketch_factored) == payload);
}

// --- (d) soundness ----------------------------------------------------------

BOOST_AUTO_TEST_CASE(d_profile_honest_proof_verifies_perturbed_fails)
{
    const uint32_t n = kTestDim;
    const uint32_t rounds = 3;
    CBlockHeader header = MakeV4Header(555, n);
    uint256 digest;
    std::vector<unsigned char> payload;
    BOOST_REQUIRE(bx::ComputeDigestBMX4D(header, n, digest, payload));

    header.matmul_digest = digest;
    uint256 verified;
    BOOST_CHECK(bx::VerifySketchBMX4D(header, n, rounds, payload, verified));
    BOOST_CHECK(verified == digest);

    // Wrong rounds (0) fails closed.
    BOOST_CHECK(!bx::VerifySketchBMX4D(header, n, 0, payload, verified));

    // Perturb one payload word and re-seal the digest so the digest check
    // passes but the Freivalds rounds must catch the wrong sketch.
    std::vector<unsigned char> bad_payload = payload;
    bad_payload[0] ^= 0x01;
    // Re-derive the digest over the tampered payload so the H(sigma||payload)
    // gate cannot be what rejects it -- only the O(n^2) Freivalds cascade can.
    const uint256 sigma = DeriveSigma(header);
    header.matmul_digest = ComputeSketchDigest(sigma, bad_payload);
    uint256 bad_verified;
    BOOST_CHECK(!bx::VerifySketchBMX4D(header, n, rounds, bad_payload, bad_verified));
}

// --- (e) profile independence ----------------------------------------------

BOOST_AUTO_TEST_CASE(d_profile_digest_differs_from_c_profile)
{
    const uint32_t n = kTestDim;
    CBlockHeader header = MakeV4Header(2026, n);
    uint256 dd, dc;
    std::vector<unsigned char> pd, pc;
    BOOST_REQUIRE(bx::ComputeDigestBMX4D(header, n, dd, pd));
    BOOST_REQUIRE(bx::ComputeDigestBMX4C(header, n, dc, pc));
    // Distinct rank AND distinct domain tags => unrelated commitments.
    BOOST_CHECK(dd != dc);
    BOOST_CHECK(pd.size() != pc.size()); // 4x
}

// --- GOLDEN vectors ---------------------------------------------------------

namespace {
struct GoldenD {
    std::string_view name;
    uint64_t nonce;
    uint32_t n;
    uint32_t rounds;
    std::string_view expected_digest_hex;
    std::string_view expected_payload_sha256_hex;
};

// Pinned 2026-07-16 from the reviewed ENC-BMX4C-D CPU reference (b=2, m=n/2,
// V4.2-D domain tags). Values printed by the harness below on first run.
constexpr GoldenD kGoldenD[] = {
    {"BMX4CD-TV1-n256-r3", 0, 256, 3,
     "a94c67a1a8290f25bd4003556645d326b927db07d878e7f1c5876df1a2c48aaa",
     "3a01c6bc5de6007079a161b99f924ddc49b779cf2ce7d67132d7bd6e6aaf7c57"},
    {"BMX4CD-TV2-n512-r3", 42, 512, 3,
     "4e8da00e51b184b709e0dfa08451bd3f461758e7272db41fb1ec91895418b343",
     "de3857e19c4cb5a1edffb1156335fe7cf2174d08a0e5e8ba20caef48b2e17e68"},
};
} // namespace

BOOST_AUTO_TEST_CASE(d_profile_golden_vectors)
{
    for (const GoldenD& tv : kGoldenD) {
        CBlockHeader header = MakeV4Header(tv.nonce, tv.n);
        uint256 digest;
        std::vector<unsigned char> payload;
        BOOST_REQUIRE_MESSAGE(bx::ComputeDigestBMX4D(header, tv.n, digest, payload),
                              tv.name << ": ComputeDigestBMX4D failed");

        // Self-consistency and honest-proof-verifies.
        header.matmul_digest = digest;
        uint256 verified;
        BOOST_CHECK_MESSAGE(bx::VerifySketchBMX4D(header, tv.n, tv.rounds, payload, verified),
                            tv.name << ": honest proof failed VerifySketchBMX4D");

        const std::string digest_hex = digest.GetHex();
        const std::string payload_hex = Sha256Hex(payload);
        const bool pinned = tv.expected_digest_hex.front() != '@';
        if (!pinned) {
            BOOST_WARN_MESSAGE(false, "UNPINNED ENC-BMX4C-D golden vector " << tv.name
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

BOOST_AUTO_TEST_SUITE_END()
