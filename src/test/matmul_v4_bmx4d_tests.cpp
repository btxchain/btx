// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// ENC-BMX4C-D CONSENSUS PROFILE tests (reinstated; solver-evolution Stage 1).
// ROUND-3 P0-2 removed D from the consensus state machine; the on-silicon
// per-card measurement reversed that, so D is a REAL consensus profile again
// (enum ENC_BMX4CD = 3, IsBMX4CDActive, verify/solve dispatch, per-profile
// construction asserts). These cases pin BOTH the D-profile CPU-reference
// arithmetic AND its consensus wiring: the profile selector, the per-profile
// MatMulProfileParams shape (C -> b4/m1024/8 MiB/segregated=false;
// D -> b2/m2048/32 MiB/segregated=true), and the b-parametric ValidateDimsBMX4.
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

#include <arith_uint256.h>
#include <consensus/amount.h>
#include <consensus/params.h>
#include <matmul/int8_field.h>
#include <matmul/matmul_proof_store.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_bmx4.h>
#include <pow.h>

#include <crypto/sha256.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstdint>
#include <limits>
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

// --- CONSENSUS WIRING: profile selector + per-profile params (design §4.1) ---

namespace {
// Minimal params exposing the three MatMul height gates the profile selector
// reads. GetMatMulEncodingProfile / GetMatMulProfileParams consult only these
// (no ASERT machinery), so a bare struct suffices. D forks strictly above C.
Consensus::Params ProfileLadderParams(int32_t c_height, int32_t d_height)
{
    Consensus::Params p{};
    p.nMatMulV4Height = c_height;      // unified v3 -> v4.2 flag day (v4 == C)
    p.nMatMulBMX4CHeight = c_height;
    p.nMatMulBMX4CDHeight = d_height;
    return p;
}
} // namespace

BOOST_AUTO_TEST_CASE(d_profile_selector_returns_enc_bmx4cd_when_active)
{
    // Ladder: v4/C at 100, D at 200. Below C -> S8 (meaningless, v3 rules);
    // [100,200) -> ENC_BMX4C; >=200 -> ENC_BMX4CD.
    const auto p = ProfileLadderParams(100, 200);

    BOOST_CHECK(!p.IsBMX4CDActive(199));
    BOOST_CHECK(p.IsBMX4CActive(199));
    BOOST_CHECK(p.GetMatMulEncodingProfile(199) ==
                Consensus::MatMulEncodingProfile::ENC_BMX4C);

    BOOST_CHECK(p.IsBMX4CDActive(200));
    BOOST_CHECK(p.IsBMX4CDActive(5000));
    BOOST_CHECK(p.GetMatMulEncodingProfile(200) ==
                Consensus::MatMulEncodingProfile::ENC_BMX4CD);

    // Disabled D (default INT32_MAX): selector never returns ENC_BMX4CD.
    const auto p_no_d = ProfileLadderParams(100, std::numeric_limits<int32_t>::max());
    BOOST_CHECK(!p_no_d.IsBMX4CDActive(1'000'000));
    BOOST_CHECK(p_no_d.GetMatMulEncodingProfile(1'000'000) ==
                Consensus::MatMulEncodingProfile::ENC_BMX4C);
}

BOOST_AUTO_TEST_CASE(get_matmul_profile_params_c_and_d_shapes)
{
    const auto p = ProfileLadderParams(100, 200);

    // C shape: b=4, m=1024, 8 MiB, in-block proof.
    const auto pc = p.GetMatMulProfileParams(150);
    BOOST_CHECK(pc.profile == Consensus::MatMulEncodingProfile::ENC_BMX4C);
    BOOST_CHECK_EQUAL(pc.tile_b, 4u);
    BOOST_CHECK_EQUAL(pc.sketch_rank_m, Consensus::BMX4C_SKETCH_RANK_M);
    BOOST_CHECK_EQUAL(pc.sketch_rank_m, 1024u);
    BOOST_CHECK_EQUAL(pc.sketch_payload_bytes, uint64_t{8} * 1024 * 1024); // 8 MiB
    BOOST_CHECK_EQUAL(pc.sketch_payload_bytes, 8u * 1024u * 1024u);
    BOOST_CHECK(!pc.proof_segregated);

    // D shape: b=2, m=2048, 32 MiB, segregated proof.
    const auto pd = p.GetMatMulProfileParams(200);
    BOOST_CHECK(pd.profile == Consensus::MatMulEncodingProfile::ENC_BMX4CD);
    BOOST_CHECK_EQUAL(pd.tile_b, 2u);
    BOOST_CHECK_EQUAL(pd.sketch_rank_m, Consensus::BMX4CD_SKETCH_RANK_M);
    BOOST_CHECK_EQUAL(pd.sketch_rank_m, 2048u);
    BOOST_CHECK_EQUAL(pd.sketch_payload_bytes, uint64_t{8} * 2048 * 2048); // 32 MiB
    BOOST_CHECK(pd.proof_segregated);

    // Payload accounting is exactly 8*m^2 for each profile, and D is 4x C.
    BOOST_CHECK_EQUAL(pc.sketch_payload_bytes,
                      uint64_t{8} * pc.sketch_rank_m * pc.sketch_rank_m);
    BOOST_CHECK_EQUAL(pd.sketch_payload_bytes,
                      uint64_t{8} * pd.sketch_rank_m * pd.sketch_rank_m);
    BOOST_CHECK_EQUAL(pd.sketch_payload_bytes, 4u * pc.sketch_payload_bytes);
    // The tile b matches the compile-time tiles the matmul layer uses.
    BOOST_CHECK_EQUAL(pd.tile_b, bx::kTileBMX4D);
    BOOST_CHECK_EQUAL(pc.tile_b, kTileB);
}

// --- b-PARAMETRIC VALIDATOR (design §4.2) -----------------------------------

BOOST_AUTO_TEST_CASE(validate_dims_bmx4_is_b_parametric)
{
    const uint32_t n = kTestDim; // 256, a multiple of 32 (and of both tiles)
    uint32_t m_b2 = 0, m_b4 = 0;

    // One routine, both tiles: m = n/b.
    BOOST_REQUIRE(bx::ValidateDimsBMX4(n, 2, m_b2));
    BOOST_REQUIRE(bx::ValidateDimsBMX4(n, 4, m_b4));
    BOOST_CHECK_EQUAL(m_b2, n / 2);
    BOOST_CHECK_EQUAL(m_b4, n / 4);

    // The thin C/D wrappers must agree with the unified routine at their tiles.
    uint32_t m_c = 0, m_d = 0;
    BOOST_REQUIRE(bx::ValidateDimsBMX4C(n, 4, m_c));
    BOOST_REQUIRE(bx::ValidateDimsBMX4D(n, m_d));
    BOOST_CHECK_EQUAL(m_c, m_b4);
    BOOST_CHECK_EQUAL(m_d, m_b2);

    // Structural gates are shared (only b differs): n % 32 != 0 fails for any b;
    // b that does not divide n fails.
    uint32_t dummy = 0;
    BOOST_CHECK(!bx::ValidateDimsBMX4(n + 1, 2, dummy)); // 257 % 32 != 0
    BOOST_CHECK(!bx::ValidateDimsBMX4(n, 3, dummy));     // 3 does not divide 256
    BOOST_CHECK(!bx::ValidateDimsBMX4(n, 0, dummy));     // b = 0 invalid
}

// --- SEGREGATED-PROOF CARRIAGE (solver-evolution Stage 2a; design §3) --------
//
// These pin the CONSENSUS CORE of the segregated proof: the height-gated block
// serialization change (the ~32 MiB sketch leaves the body), the local proof
// store, and the store-backed binding + Freivalds validation with the
// MUTATED/INCOMPLETE/CONSENSUS split. Everything runs single-process (no P2P).

namespace {

// A minimal but well-formed CBlock shell: a v4-D header + one coinbase-shaped tx
// so the SERIALIZE_METHODS payload region is exercised. Matrices left empty.
CBlock MakeBlockShell(uint32_t n, uint64_t nonce)
{
    CBlock block;
    static_cast<CBlockHeader&>(block) = MakeV4Header(nonce, n);
    CMutableTransaction cb;
    cb.vin.resize(1);
    cb.vin[0].prevout.SetNull();
    cb.vin[0].scriptSig = CScript() << OP_0 << OP_1; // 2 bytes, shape only
    cb.vout.resize(1);
    cb.vout[0].nValue = 50 * COIN;
    cb.vout[0].scriptPubKey = CScript() << OP_TRUE;
    block.vtx.push_back(MakeTransactionRef(std::move(cb)));
    return block;
}

std::vector<std::byte> SerializeBlock(const CBlock& block)
{
    DataStream ss{};
    ss << TX_WITH_WITNESS(block);
    return {ss.begin(), ss.end()};
}

// Mirror pow.cpp's PackMatMulV4SketchBytesToWords (the in-body word packing the
// solver uses) so a test can emulate an in-body sketch before offload.
std::vector<uint32_t> SketchBytesToWordsForTest(const std::vector<unsigned char>& bytes)
{
    std::vector<uint32_t> words((bytes.size() + 3) / 4, 0);
    for (size_t i = 0; i < bytes.size(); ++i) {
        words[i / 4] |= static_cast<uint32_t>(bytes[i]) << (8 * (i % 4));
    }
    return words;
}

// Params for the store-backed verify path: unified v4/C at 100, segregated D at
// 200, at a small D-valid dimension. powLimit is set wide so a handful of ground
// nonces land under target.
Consensus::Params SegregatedParams(uint32_t dim)
{
    Consensus::Params p{};
    p.nMatMulV4Height = 100;
    p.nMatMulBMX4CHeight = 100;
    p.nMatMulBMX4CDHeight = 200;
    p.nMatMulV4Dimension = dim;
    p.nMatMulV4FreivaldsRounds = 3;
    p.powLimit = *uint256::FromHex(
        "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    return p;
}

} // namespace

// (1) SERIALIZATION GATING (design §3.1/§3.6). At a segregated height the block
// body carries an EMPTY sketch, so the ~32 MiB proof is EXCLUDED from the wire
// by construction; round-trips are byte-identical.
BOOST_AUTO_TEST_CASE(segregated_block_serialization_excludes_sketch)
{
    const uint32_t n = kTestDim;
    CBlock block = MakeBlockShell(n, 0);
    BOOST_REQUIRE(block.matrix_c_data.empty());

    // Serialized with an empty body sketch: tiny, and FAR under the 24 MB ceiling.
    const std::vector<std::byte> wire_empty = SerializeBlock(block);
    BOOST_CHECK_LT(wire_empty.size(), 1024u);
    BOOST_CHECK_LT(wire_empty.size(), 24u * 1000 * 1000);

    // Round-trip: deserialize, then re-serialize -> byte-identical, and the
    // decoded block still has an empty sketch (no phantom trailing bytes).
    CBlock decoded;
    DataStream ss_in{wire_empty};
    ss_in >> TX_WITH_WITNESS(decoded);
    BOOST_CHECK(decoded.matrix_c_data.empty());
    BOOST_CHECK(decoded.matrix_a_data.empty());
    BOOST_CHECK(decoded.matrix_b_data.empty());
    const std::vector<std::byte> wire_reencoded = SerializeBlock(decoded);
    BOOST_CHECK(wire_empty == wire_reencoded);

    // Demonstrate EXCLUSION: the same block with the real D sketch inlined is
    // larger by exactly the sketch serialization; the segregated block omits it.
    uint256 digest;
    std::vector<unsigned char> payload;
    BOOST_REQUIRE(bx::ComputeDigestBMX4D(block, n, digest, payload));
    CBlock inlined = block;
    inlined.matrix_c_data = SketchBytesToWordsForTest(payload);
    const std::vector<std::byte> wire_inlined = SerializeBlock(inlined);
    BOOST_CHECK_GT(wire_inlined.size(), wire_empty.size());
    // The delta is the sketch payload words (4 bytes each) + its length prefix.
    BOOST_CHECK_GE(wire_inlined.size() - wire_empty.size(),
                   inlined.matrix_c_data.size() * sizeof(uint32_t));
}

// (2) PROOF STORE round-trip.
BOOST_AUTO_TEST_CASE(matmul_proof_store_roundtrip)
{
    matmul::MatMulProofStore store;
    const uint256 h1 = ParseUint256("1100000000000000000000000000000000000000000000000000000000000000");
    const uint256 h2 = ParseUint256("2200000000000000000000000000000000000000000000000000000000000000");
    const std::vector<unsigned char> a{1, 2, 3, 4};
    const std::vector<unsigned char> b{9, 8, 7};

    BOOST_CHECK(!store.Have(h1));
    std::vector<unsigned char> out;
    BOOST_CHECK(!store.Get(h1, out));

    store.Put(h1, a);
    store.Put(h2, b);
    BOOST_CHECK(store.Have(h1));
    BOOST_CHECK_EQUAL(store.Size(), 2u);
    BOOST_REQUIRE(store.Get(h1, out));
    BOOST_CHECK(out == a);
    BOOST_REQUIRE(store.Get(h2, out));
    BOOST_CHECK(out == b);

    store.Erase(h1);
    BOOST_CHECK(!store.Have(h1));
    BOOST_CHECK_EQUAL(store.Size(), 1u);
    store.Clear();
    BOOST_CHECK_EQUAL(store.Size(), 0u);
}

// (3) STORE-BACKED BINDING + FREIVALDS (design §3.3/§3.4). Drives every arm of
// the MUTATED / INCOMPLETE / CONSENSUS split through CheckMatMulV4SegregatedProof.
BOOST_AUTO_TEST_CASE(segregated_proof_binding_and_verify)
{
    const uint32_t n = 64; // b=2 -> m=32; 64 % 32 == 0, 32 % 32 == 0
    const Consensus::Params params = SegregatedParams(n);
    const int32_t d_height = 200;
    BOOST_REQUIRE(params.GetMatMulProfileParams(d_height).proof_segregated);

    const auto bnTarget = DeriveTarget(0x207fffff, params.powLimit);
    BOOST_REQUIRE(bnTarget.has_value());

    // Grind a nonce whose honest D digest lands at/under target (like the miner).
    CBlock block;
    uint256 digest;
    std::vector<unsigned char> payload;
    bool found = false;
    for (uint64_t nonce = 0; nonce < 4096 && !found; ++nonce) {
        block = MakeBlockShell(n, nonce);
        BOOST_REQUIRE(bx::ComputeDigestBMX4D(block, n, digest, payload));
        if (UintToArith256(digest) <= *bnTarget) found = true;
    }
    BOOST_REQUIRE_MESSAGE(found, "no ground nonce landed under target");
    block.matmul_digest = digest;
    const uint256 block_hash = block.GetHash();

    // Ensure a clean store for this block hash.
    matmul::GetLocalMatMulProofStore().Erase(block_hash);

    // INCOMPLETE: proof absent from the store.
    BOOST_CHECK(CheckMatMulV4SegregatedProof(block, params, d_height) ==
                MatMulSegregatedProofStatus::INCOMPLETE);

    // OK: honest proof present, binds to the digest, verifies, under target.
    matmul::PutMatMulProof(block_hash, payload);
    BOOST_CHECK(CheckMatMulV4SegregatedProof(block, params, d_height) ==
                MatMulSegregatedProofStatus::OK);

    // MUTATED (binding): a corrupted proof that no longer hashes to matmul_digest.
    {
        std::vector<unsigned char> corrupt = payload;
        corrupt[0] ^= 0x01;
        matmul::PutMatMulProof(block_hash, corrupt);
        BOOST_CHECK(CheckMatMulV4SegregatedProof(block, params, d_height) ==
                    MatMulSegregatedProofStatus::MUTATED);
    }

    // MUTATED (oversize): a blob past the §3.4 cap is rejected before any parse.
    {
        const uint64_t cap = params.GetMatMulProfileParams(d_height).sketch_payload_bytes +
                             MATMUL_SEGREGATED_PROOF_OVERHEAD;
        std::vector<unsigned char> oversize(cap + 1, 0);
        matmul::PutMatMulProof(block_hash, oversize);
        BOOST_CHECK(CheckMatMulV4SegregatedProof(block, params, d_height) ==
                    MatMulSegregatedProofStatus::MUTATED);
    }

    // Restore the honest proof -> OK again (idempotent, order-independent).
    matmul::PutMatMulProof(block_hash, payload);
    BOOST_CHECK(CheckMatMulV4SegregatedProof(block, params, d_height) ==
                MatMulSegregatedProofStatus::OK);

    // CONSENSUS_FAIL: perturb the sketch AND re-seal matmul_digest over it so the
    // §3.3 binding PASSES, leaving only the O(n^2) Freivalds cascade to reject it.
    // Re-sealing changes matmul_digest -> a new block hash; store under that key.
    {
        std::vector<unsigned char> bad = payload;
        bad[0] ^= 0x01;
        const uint256 sigma = DeriveSigma(block); // sigma excludes matmul_digest
        CBlock consensus_block = block;
        consensus_block.matmul_digest = ComputeSketchDigest(sigma, bad);
        const uint256 consensus_hash = consensus_block.GetHash();
        matmul::PutMatMulProof(consensus_hash, bad);
        BOOST_CHECK(CheckMatMulV4SegregatedProof(consensus_block, params, d_height) ==
                    MatMulSegregatedProofStatus::CONSENSUS_FAIL);
        matmul::GetLocalMatMulProofStore().Erase(consensus_hash);
    }

    // Teardown.
    matmul::GetLocalMatMulProofStore().Erase(block_hash);
}

// (4) MINER OFFLOAD (design §3.6): the handoff moves the solved sketch into the
// store and empties the body, keyed by the header hash (stable across the clear).
BOOST_AUTO_TEST_CASE(segregated_miner_offload_to_store)
{
    const uint32_t n = 64;
    CBlock block = MakeBlockShell(n, 7);
    uint256 digest;
    std::vector<unsigned char> payload;
    BOOST_REQUIRE(bx::ComputeDigestBMX4D(block, n, digest, payload));
    block.matmul_digest = digest;
    // Emulate the solver having attached the word-packed sketch in-body.
    block.matrix_c_data = SketchBytesToWordsForTest(payload);
    const uint256 block_hash = block.GetHash();
    matmul::GetLocalMatMulProofStore().Erase(block_hash);

    BOOST_REQUIRE(OffloadMatMulV4SegregatedProofToStore(block));
    // Body sketch cleared; hash unchanged (header-only); proof now in the store.
    BOOST_CHECK(block.matrix_c_data.empty());
    BOOST_CHECK(block.GetHash() == block_hash);
    std::vector<unsigned char> stored;
    BOOST_REQUIRE(matmul::GetMatMulProof(block_hash, stored));
    BOOST_CHECK(stored == payload);
    // Idempotent no-op once the body is already empty.
    BOOST_CHECK(!OffloadMatMulV4SegregatedProofToStore(block));

    matmul::GetLocalMatMulProofStore().Erase(block_hash);
}

BOOST_AUTO_TEST_SUITE_END()
