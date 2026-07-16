// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// ENC-BMX4C committed-object profile tests (MatMul v4.2 / BMX4-C; design
// doc/btx-matmul-v4.2-consolidated-design.md). This suite pins the bit-exact
// CPU reference every backend / golden vector mirrors:
//
//   (a) BYTE-IDENTITY: the optimal (U*Ahat)(Bhat*V) sketch == the full-C
//       reference ComputeSketch(U, Ahat*Bhat, V), byte-for-byte.
//   (b) COMBINE: the base-2^6 limb-tensor combine == the direct mod-q combine,
//       byte-for-byte, including the high-magnitude regime near 2^23 and the
//       corrected asymmetric-bound edge.
//   (c) SOUNDNESS: a correct sketch passes SketchFreivalds; a perturbed but
//       digest-consistent sketch fails it.
//   (d) DETERMINISM: run-to-run byte-identity of digest + payload.
//   (e) SAMPLER EXACTNESS: every sampled mantissa is in M11, every scale code
//       is a valid E8M0 exponent, and the E2M1 bijection holes are exact.
//   + GOLDEN vectors: pinned ENC-BMX4C digests at fixed headers, and the C-1'
//     accumulator boundary vectors (exact-2^t limb-pair pins, odd-step 2^14
//     crossings, E8M0 scale-exactness) so a rounding device fails loudly.

#include <matmul/int8_field.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_bmx4.h>
#include <matmul/pow_v4.h>

#include <primitives/block.h>
#include <random.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstdint>
#include <set>
#include <string>
#include <string_view>
#include <vector>

using namespace matmul::v4;
namespace bx = matmul::v4::bmx4;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_bmx4_tests, BasicTestingSetup)

namespace {

constexpr uint32_t kTestDim = 256; // fast unit dimension (b=4 -> m=64, /32 ok)

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

// True iff every element of `v` is a member of the pinned M11 alphabet.
bool AllInM11(const std::vector<int8_t>& v)
{
    static const std::set<int8_t> kM11{0, 1, -1, 2, -2, 3, -3, 4, -4, 6, -6};
    for (int8_t x : v) {
        if (kM11.find(x) == kM11.end()) return false;
    }
    return true;
}

} // namespace

// --- (e) SAMPLER EXACTNESS --------------------------------------------------

BOOST_AUTO_TEST_CASE(sampler_e2m1_bijection_holes_exact)
{
    // The 5 rejected nibble codes must be exactly {0.5,1.5,-0} = {1,3,8,9,11},
    // and the 11 accepted codes must map bijectively onto M11.
    std::set<int8_t> accepted_values;
    int accepted = 0;
    for (uint8_t nib = 0; nib < 16; ++nib) {
        bool ok = false;
        const int8_t mu = bx::SampleMantissaNibble(nib, ok);
        const bool is_hole = (nib == 1 || nib == 3 || nib == 8 || nib == 9 || nib == 11);
        BOOST_CHECK_EQUAL(ok, !is_hole);
        if (ok) {
            ++accepted;
            accepted_values.insert(mu);
            // never +-5 or any non-M11 magnitude
            const int a = mu < 0 ? -mu : mu;
            BOOST_CHECK(a == 0 || a == 1 || a == 2 || a == 3 || a == 4 || a == 6);
            BOOST_CHECK(a != 5);
        }
    }
    BOOST_CHECK_EQUAL(accepted, 11);
    const std::set<int8_t> kM11{0, 1, -1, 2, -2, 3, -3, 4, -4, 6, -6};
    BOOST_CHECK(accepted_values == kM11);
}

BOOST_AUTO_TEST_CASE(sampler_streams_are_valid)
{
    const uint256 seed = ParseUint256("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");

    // Mantissa stream: every element in M11.
    std::vector<int8_t> mant(10000);
    bx::ExpandMantissaStream(seed, mant.size(), mant.data());
    BOOST_CHECK(AllInM11(mant));

    // Scale stream: every code a valid E8M0 exponent in {0,1,2,3}.
    std::vector<uint8_t> scales(10000);
    bx::ExpandScaleStream(seed, scales.size(), scales.data());
    for (uint8_t e : scales) BOOST_CHECK(e <= bx::kScaleS);

    // Dequantized operands: exact integers with |.| <= E_max = 48.
    const auto Ahat = bx::ExpandOperandA(seed, kTestDim);
    const auto Bhat = bx::ExpandOperandB(seed, kTestDim);
    for (int8_t x : Ahat) BOOST_CHECK(x >= -bx::kEmax && x <= bx::kEmax);
    for (int8_t x : Bhat) BOOST_CHECK(x >= -bx::kEmax && x <= bx::kEmax);

    // Projectors: scale-free M11, |.| <= 6.
    const auto U = bx::ExpandProjectorBMX4C(seed, 8, kTestDim);
    BOOST_CHECK(AllInM11(U));
    for (int8_t x : U) BOOST_CHECK(x >= -bx::kMantissaMaxAbs && x <= bx::kMantissaMaxAbs);
}

BOOST_AUTO_TEST_CASE(pinned_constants)
{
    // The exact ENC-BMX4C constants (design §2.1/§2.4/§5.2).
    BOOST_CHECK_EQUAL(bx::kAlphabetSize, 11u);
    BOOST_CHECK_EQUAL(bx::kMantissaMaxAbs, 6);
    BOOST_CHECK_EQUAL(bx::kScaleS, 3u);
    BOOST_CHECK_EQUAL(bx::kBlockLen, 32u);
    BOOST_CHECK_EQUAL(bx::kEmax, 48);
    BOOST_CHECK_EQUAL(bx::kBaseProductPerMac, 2304);
    BOOST_CHECK_EQUAL(bx::kProjPerMac, 288);
    BOOST_CHECK_EQUAL(bx::kCombineLimbBase, 64);
    BOOST_CHECK_EQUAL(bx::kCombineLimbs, 4u);
    BOOST_CHECK_EQUAL(bx::kCombinePureBalancedPositiveExtreme, 8'255'455);
    BOOST_CHECK_EQUAL(bx::kCombineMaxAbs, 8'388'607); // 2^23 - 1

    // Corrected combine bound: 288*n <= 2^23-1 <=> n <= 29,127.
    BOOST_CHECK(bx::CheckCombineLimbBoundBMX4C(4096));
    BOOST_CHECK(bx::CheckCombineLimbBoundBMX4C(8192));
    BOOST_CHECK(bx::CheckCombineLimbBoundBMX4C(29127));
    BOOST_CHECK(!bx::CheckCombineLimbBoundBMX4C(29128));
}

// --- (a) BYTE-IDENTITY: optimal factoring == full-C reference ---------------

BOOST_AUTO_TEST_CASE(optimal_sketch_matches_full_c)
{
    const uint32_t n = kTestDim;
    uint32_t m = 0;
    BOOST_REQUIRE(bx::ValidateDimsBMX4C(n, kTileB, m));

    const uint256 sa = ParseUint256("00000000000000000000000000000000000000000000000000000000000000aa");
    const uint256 sb = ParseUint256("00000000000000000000000000000000000000000000000000000000000000bb");
    const uint256 su = ParseUint256("00000000000000000000000000000000000000000000000000000000000000cc");
    const uint256 sv = ParseUint256("00000000000000000000000000000000000000000000000000000000000000dd");

    const auto Ahat = bx::ExpandOperandA(sa, n);
    const auto Bhat = bx::ExpandOperandB(sb, n);
    const auto U = bx::ExpandProjectorBMX4C(su, m, n);
    const auto V = bx::ExpandProjectorBMX4C(sv, n, m);

    // Full-C reference: C = Ahat*Bhat (exact int32), Chat = U*C*V.
    const auto C = ComputeExactProduct(Ahat, Bhat, n);
    // Base product bound: |C| <= 2304*n.
    for (int32_t x : C) BOOST_REQUIRE(x <= 2304 * static_cast<int32_t>(n) &&
                                      x >= -2304 * static_cast<int32_t>(n));
    const auto full = ComputeSketch(U, C, V, n, m);

    // Optimal factoring: P = U*Ahat, Q = Bhat*V, Chat = P*Q mod q.
    const auto P = ComputeProjectedLeft(U, Ahat, n, m);
    const auto Q = ComputeProjectedRight(Bhat, V, n, m);
    for (int32_t x : P) BOOST_REQUIRE(x <= 288 * static_cast<int32_t>(n) &&
                                      x >= -288 * static_cast<int32_t>(n));
    const auto opt_direct = ComputeCombineModQ(P, Q, n, m);
    const auto opt_limb = bx::ComputeCombineLimbTensorBMX4C(P, Q, n, m);

    BOOST_CHECK(opt_direct == full);   // (U*A)(B*V) == U*(A*B)*V
    BOOST_CHECK(opt_limb == full);     // base-2^6 limb path == full-C
    // And byte-identical serialized payloads / digests.
    BOOST_CHECK(SerializeSketch(opt_limb) == SerializeSketch(full));
}

// --- (b) COMBINE: base-2^6 limb == direct mod-q -----------------------------

BOOST_AUTO_TEST_CASE(limb_combine_matches_direct_random)
{
    FastRandomContext rng{/*fDeterministic=*/true};
    const uint32_t n = 96; // multiple of 32
    const uint32_t m = 24;
    const int64_t bound = static_cast<int64_t>(bx::kProjPerMac) * n; // 288*n
    BOOST_REQUIRE(bx::CheckCombineLimbBoundBMX4C(n));

    std::vector<int32_t> P(static_cast<size_t>(m) * n);
    std::vector<int32_t> Q(static_cast<size_t>(n) * m);
    for (auto& x : P) x = static_cast<int32_t>(static_cast<int64_t>(rng.randrange(2 * bound + 1)) - bound);
    for (auto& x : Q) x = static_cast<int32_t>(static_cast<int64_t>(rng.randrange(2 * bound + 1)) - bound);

    const auto direct = ComputeCombineModQ(P, Q, n, m);
    const auto limb = bx::ComputeCombineLimbTensorBMX4C(P, Q, n, m);
    BOOST_CHECK(limb == direct);
}

BOOST_AUTO_TEST_CASE(limb_combine_matches_direct_high_magnitude_and_bound_edge)
{
    // Entries at the corrected-bound edges: the pure-balanced positive extreme
    // 8,255,455 and the remainder-top total bound 2^23-1 = 8,388,607, both
    // signs, plus small edges. n = 4 keeps the limb-pair accumulator in range
    // while the decomposition itself is exercised near 2^23. This is where a
    // "pure balanced only to 8,255,455" implementation would decompose WRONG;
    // the remainder-top rule keeps limb == direct.
    const uint32_t n = 4;
    const uint32_t m = 4;
    const int32_t E = static_cast<int32_t>(bx::kCombinePureBalancedPositiveExtreme); // 8,255,455
    const int32_t T = static_cast<int32_t>(bx::kCombineMaxAbs);                      // 8,388,607
    const int32_t edges[] = {0, 1, -1, 31, 32, -32, 33, -33, 63, 64, -64, 65,
                             4'194'304 /*2^22*/, -4'194'304, E, -E, T, -T};
    std::vector<int32_t> P(static_cast<size_t>(m) * n);
    std::vector<int32_t> Q(static_cast<size_t>(n) * m);
    for (size_t i = 0; i < P.size(); ++i) P[i] = edges[i % std::size(edges)];
    for (size_t i = 0; i < Q.size(); ++i) Q[i] = edges[(i * 5 + 2) % std::size(edges)];

    const auto direct = ComputeCombineModQ(P, Q, n, m);
    const auto limb = bx::ComputeCombineLimbTensorBMX4C(P, Q, n, m);
    BOOST_CHECK(limb == direct);
}

// --- GOLDEN / C-1' boundary vectors -----------------------------------------

BOOST_AUTO_TEST_CASE(boundary_e8m0_scale_exactness)
{
    // E8M0 dequant is a PURE power-of-two shift: mu * 2^e, exact, no mantissa
    // bit changes, |.| <= 48. A rounding / FP-mantissa device that mishandled
    // the block scale would diverge here.
    static const std::array<int8_t, 11> kM11{0, 1, -1, 2, -2, 3, -3, 4, -4, 6, -6};
    for (int8_t mu : kM11) {
        for (uint8_t e = 0; e <= bx::kScaleS; ++e) {
            const int32_t deq = static_cast<int32_t>(mu) * (1 << e);
            BOOST_CHECK_EQUAL(deq, static_cast<int32_t>(mu) << e); // pure shift for >=0
            BOOST_CHECK(deq >= -bx::kEmax && deq <= bx::kEmax);
        }
    }
    // Exact E_max: 6 * 2^3 == 48.
    BOOST_CHECK_EQUAL(6 * (1 << 3), bx::kEmax);
}

BOOST_AUTO_TEST_CASE(boundary_base_product_odd_step_crosses_2e14)
{
    // Odd-step base-product accumulation crossing 2^14 (catches a t~14
    // FP-mantissa accumulator, e.g. the DeepSeek/Hopper FP8 datapath). The
    // largest ODD per-MAC product on the committed path is mu=3 (e=0) times
    // mu=3 (e=0) = 9. A length-N rail dot climbs in odd steps of 9; at
    // N = 1824 it reaches 16,416 > 2^14 = 16,384, so a device exact only to
    // 2^14 (ULP >= 2 above it) MUST round while the int reference is exact.
    const uint32_t N = 1824; // 9*1824 = 16,416
    std::vector<int8_t> a(N, 3), b(N, 3); // dequant mu=3, e=0
    int64_t acc = 0;
    for (uint32_t k = 0; k < N; ++k) acc += static_cast<int64_t>(a[k]) * b[k];
    BOOST_CHECK_EQUAL(acc, static_cast<int64_t>(9) * N);
    BOOST_CHECK_EQUAL(acc, 16'416);
    BOOST_CHECK(acc > (1 << 14));               // crossed 2^14
    BOOST_CHECK_EQUAL(acc % 2, 0);              // 16416 even, but built by odd steps
    // Reference int8_field exact dot reproduces it bit-for-bit.
    BOOST_CHECK_EQUAL(matmul::int8_field::ExactDot(a.data(), b.data(), N), 16'416);
}

BOOST_AUTO_TEST_CASE(boundary_base_product_high_magnitude_real_gemm)
{
    // Real GEMM path in the high-magnitude regime: E_max rails (all dequant
    // = 48) push every C entry to exactly 2304*n, well past 2^14. Pushed
    // through all three consensus-equivalent sketch paths with byte-equality.
    const uint32_t n = 256; // 2304*256 = 589,824 ~ 2^19.2 (> 2^14)
    const uint32_t m = n / kTileB;
    std::vector<int8_t> Ahat(static_cast<size_t>(n) * n, 48);
    std::vector<int8_t> Bhat(static_cast<size_t>(n) * n, 48);
    const auto C = ComputeExactProduct(Ahat, Bhat, n);
    for (int32_t x : C) BOOST_REQUIRE_EQUAL(x, 2304 * static_cast<int32_t>(n));
    BOOST_CHECK_EQUAL(C[0], 589'824);

    // M11 projectors, then all three paths agree byte-for-byte.
    const auto U = bx::ExpandProjectorBMX4C(
        ParseUint256("00000000000000000000000000000000000000000000000000000000000000e1"), m, n);
    const auto V = bx::ExpandProjectorBMX4C(
        ParseUint256("00000000000000000000000000000000000000000000000000000000000000e2"), n, m);
    const auto full = ComputeSketch(U, C, V, n, m);
    const auto P = ComputeProjectedLeft(U, Ahat, n, m);
    const auto Q = ComputeProjectedRight(Bhat, V, n, m);
    BOOST_CHECK(ComputeCombineModQ(P, Q, n, m) == full);
    BOOST_CHECK(bx::ComputeCombineLimbTensorBMX4C(P, Q, n, m) == full);
}

BOOST_AUTO_TEST_CASE(boundary_limb_pair_exact_2e22_at_n4096)
{
    // The limb-pair GEMM accumulator peak is 1024*n = 2^22 at n = 4096
    // (design §2.4). Entries = 32 decompose to digit0 = -32, so S00 =
    // sum_k (-32)*(-32) = 1024*n hits EXACTLY 2^22. m is kept small so the
    // O(m^2 n) combine is cheap while n = 4096 is real.
    BOOST_CHECK_EQUAL(1024 * 4096, 1 << 22);
    const uint32_t n = 4096;
    const uint32_t m = 8;
    BOOST_REQUIRE(bx::CheckCombineLimbBoundBMX4C(n));
    std::vector<int32_t> P(static_cast<size_t>(m) * n, 32);
    std::vector<int32_t> Q(static_cast<size_t>(n) * m, 32);
    const auto direct = ComputeCombineModQ(P, Q, n, m);
    const auto limb = bx::ComputeCombineLimbTensorBMX4C(P, Q, n, m);
    BOOST_CHECK(limb == direct);
    // Chat[a][c] = sum_k 32*32 = 1024*4096 = 4,194,304 = 2^22 (< q, canonical).
    for (Fq v : direct) BOOST_CHECK_EQUAL(v, 4'194'304u);

    // At n = 8192 the same rails hit exactly 2^23.
    const uint32_t n8 = 8192;
    BOOST_REQUIRE(bx::CheckCombineLimbBoundBMX4C(n8));
    std::vector<int32_t> P8(static_cast<size_t>(m) * n8, 32);
    std::vector<int32_t> Q8(static_cast<size_t>(n8) * m, 32);
    const auto direct8 = ComputeCombineModQ(P8, Q8, n8, m);
    BOOST_CHECK(bx::ComputeCombineLimbTensorBMX4C(P8, Q8, n8, m) == direct8);
    for (Fq v : direct8) BOOST_CHECK_EQUAL(v, 8'388'608u); // 2^23
}

// --- (d) DETERMINISM --------------------------------------------------------

BOOST_AUTO_TEST_CASE(digest_determinism_run_to_run)
{
    const CBlockHeader header = MakeV4Header(0xdead'beef'0000'0001ULL, kTestDim);
    uint256 d1, d2;
    std::vector<unsigned char> p1, p2;
    BOOST_REQUIRE(bx::ComputeDigestBMX4C(header, kTestDim, d1, p1));
    BOOST_REQUIRE(bx::ComputeDigestBMX4C(header, kTestDim, d2, p2));
    BOOST_CHECK(d1 == d2);
    BOOST_CHECK(p1 == p2);
    BOOST_CHECK_EQUAL(p1.size(), 8u * (kTestDim / kTileB) * (kTestDim / kTileB));
}

// --- (c) SOUNDNESS ----------------------------------------------------------

BOOST_AUTO_TEST_CASE(verifier_accepts_correct_sketch)
{
    CBlockHeader header = MakeV4Header(0x1234'5678'0000'0009ULL, kTestDim);
    uint256 digest;
    std::vector<unsigned char> payload;
    BOOST_REQUIRE(bx::ComputeDigestBMX4C(header, kTestDim, digest, payload));
    header.matmul_digest = digest;

    uint256 vout;
    BOOST_CHECK(bx::VerifySketchBMX4C(header, kTestDim, matmul_v4::kFreivaldsRounds, payload, vout));
    BOOST_CHECK(vout == digest);
}

BOOST_AUTO_TEST_CASE(verifier_rejects_digest_mismatch)
{
    CBlockHeader header = MakeV4Header(0x1234'5678'0000'000aULL, kTestDim);
    uint256 digest;
    std::vector<unsigned char> payload;
    BOOST_REQUIRE(bx::ComputeDigestBMX4C(header, kTestDim, digest, payload));
    header.matmul_digest = digest;

    // Flip a byte in the payload: the recomputed digest no longer matches.
    payload[0] ^= 0x01;
    uint256 vout;
    BOOST_CHECK(!bx::VerifySketchBMX4C(header, kTestDim, matmul_v4::kFreivaldsRounds, payload, vout));
}

BOOST_AUTO_TEST_CASE(verifier_freivalds_rejects_wrong_but_consistent_sketch)
{
    // Isolate Freivalds soundness from the digest check: perturb ONE sketch
    // word, re-serialize, and re-commit the header to the perturbed digest so
    // the digest check passes -- the O(n^2) Freivalds identity must still fail.
    CBlockHeader header = MakeV4Header(0x1234'5678'0000'000bULL, kTestDim);
    uint256 digest;
    std::vector<unsigned char> payload;
    BOOST_REQUIRE(bx::ComputeDigestBMX4C(header, kTestDim, digest, payload));

    const uint32_t m = kTestDim / kTileB;
    std::vector<Fq> sketch;
    BOOST_REQUIRE(ParseSketch(payload, m, sketch));
    sketch[0] = matmul::int8_field::FqAdd(sketch[0], 1); // wrong, still canonical
    const auto bad_payload = SerializeSketch(sketch);

    const uint256 sigma = DeriveSigma(header);
    header.matmul_digest = ComputeSketchDigest(sigma, bad_payload); // consistent digest

    uint256 vout;
    BOOST_CHECK(!bx::VerifySketchBMX4C(header, kTestDim, matmul_v4::kFreivaldsRounds, bad_payload, vout));
}

// --- F-L3: verifiers fail-closed on rounds == 0 -----------------------------

BOOST_AUTO_TEST_CASE(verifier_bmx4c_rejects_zero_rounds)
{
    // A correct, digest-consistent ENC-BMX4C sketch that verifies at R = 3 MUST
    // be REJECTED when rounds == 0: SketchFreivalds returns true on an empty
    // round set, so the verifier must guard rounds == 0 itself (defense-in-depth
    // vs a misconfigured 0-round verify degrading to a no-op accept).
    CBlockHeader header = MakeV4Header(0x1234'5678'0000'00f0ULL, kTestDim);
    uint256 digest;
    std::vector<unsigned char> payload;
    BOOST_REQUIRE(bx::ComputeDigestBMX4C(header, kTestDim, digest, payload));
    header.matmul_digest = digest;

    uint256 vout;
    // Control: the honest R = 3 verify accepts.
    BOOST_CHECK(bx::VerifySketchBMX4C(header, kTestDim, matmul_v4::kFreivaldsRounds, payload, vout));
    // rounds == 0 fails closed (reject), even for the correct payload/digest.
    BOOST_CHECK(!bx::VerifySketchBMX4C(header, kTestDim, 0, payload, vout));
}

BOOST_AUTO_TEST_CASE(verifier_v4_encs8_rejects_zero_rounds)
{
    // Same fail-closed guard for the v4.1 ENC-S8 verifier (matmul_v4::VerifySketch):
    // a correct sketch that passes at R = 3 must be rejected at rounds == 0.
    CBlockHeader header = MakeV4Header(0x1234'5678'0000'00f1ULL, kTestDim);
    uint256 digest;
    std::vector<unsigned char> payload;
    BOOST_REQUIRE(matmul_v4::ComputeDigest(header, kTestDim, matmul_v4::kFreivaldsRounds,
                                           digest, payload));
    header.matmul_digest = digest;

    uint256 vout;
    BOOST_CHECK(matmul_v4::VerifySketch(header, kTestDim, matmul_v4::kFreivaldsRounds, payload, vout));
    BOOST_CHECK(!matmul_v4::VerifySketch(header, kTestDim, 0, payload, vout));
}

// --- GOLDEN digests (pinned by running this reference) ----------------------

namespace {
// Emit-or-assert helper: if `golden` is empty, print the freshly computed
// digest (first-generation pass); once pinned, assert byte-equality.
void CheckGolden(std::string_view label, const uint256& digest, std::string_view golden)
{
    if (golden.empty()) {
        BOOST_TEST_MESSAGE("GOLDEN " << label << " = " << digest.GetHex());
        return;
    }
    BOOST_CHECK_EQUAL(digest.GetHex(), std::string(golden));
}
} // namespace

BOOST_AUTO_TEST_CASE(golden_digests)
{
    struct Case { uint32_t n; uint64_t nonce; std::string_view golden; };
    const Case cases[] = {
        {128, 0x0000'0000'0000'0001ULL, "c94923800c8a5e344c88efdb2ec5ad07d80694c903af3dae1859ec14ade67b7c"},
        {256, 0x0000'0000'0000'0001ULL, "4e192d8b907ad2d1383600d6f9b794c3ebf6387d577ca82333e75f544f54a9f9"},
        {256, 0x0000'0000'0000'0002ULL, "91fe8b670ad84b6b37d6ce859133945f7d8181709f7dbdf8a64b8c7e25f4aeed"},
    };
    for (const auto& c : cases) {
        const CBlockHeader header = MakeV4Header(c.nonce, c.n);
        uint256 digest;
        std::vector<unsigned char> payload;
        BOOST_REQUIRE(bx::ComputeDigestBMX4C(header, c.n, digest, payload));
        // Self-verify each golden case end-to-end.
        CBlockHeader vheader = header;
        vheader.matmul_digest = digest;
        uint256 vout;
        BOOST_CHECK(bx::VerifySketchBMX4C(vheader, c.n, matmul_v4::kFreivaldsRounds, payload, vout));
        CheckGolden("n=" + std::to_string(c.n) + " nonce=" + std::to_string(c.nonce),
                    digest, c.golden);
    }
}

BOOST_AUTO_TEST_SUITE_END()
