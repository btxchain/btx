// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// MatMul v4 sketch-commitment tests (design spec §E / §0.7-(3)).
//
// The consensus payload is the compressed sketch C_hat = U * C * V in
// F_q^{m x m} (q = 2^61 - 1, m = n / b, b = kTileB = 4), with U, V dense
// template-derived balanced-s8 projectors (§A.2 v4.1, invariant I1') and
// the digest H(sigma || C_hat).
// The verifier never forms C: it checks x^T * C_hat * y against
// (U^T x)^T * A * (B * (V y)) per Freivalds round, catching any wrong
// sketch word with probability >= 1 - 2/q per round (§E.2), i.e. a forged
// sketch survives R = 3 rounds with probability <= (2/q)^3 = 2^-180.
//
// Tests run at n = 256 / 512 for speed (production n = 4096); soundness,
// canonicality, and Fiat-Shamir binding are dimension-independent.

#include <matmul/pow_v4.h>

#include <matmul/int8_field.h>
#include <matmul/matmul_v4.h>

#include <crypto/common.h>
#include <crypto/sha256.h>
#include <primitives/block.h>
#include <random.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

namespace {

constexpr uint64_t kMersenne61{(uint64_t{1} << 61) - 1};

//! Small test dimension: m = 256 / 8 = 32, payload 8 * 32^2 = 8,192 bytes.
constexpr uint32_t kTestDim{256};

uint256 ParseUint256(std::string_view hex)
{
    const auto parsed = uint256::FromHex(hex);
    BOOST_REQUIRE(parsed.has_value());
    return *parsed;
}

//! Deterministic v4 candidate header. All challenge material (seeds,
//! projectors U/V, Freivalds vectors) derives from these fields (§H.4/§C-I1':
//! A/U/V bind the template projection; sigma, B and the Fiat-Shamir
//! challenges additionally bind nNonce64).
CBlockHeader MakeV4Header(uint64_t nonce = 1, uint32_t n = kTestDim)
{
    CBlockHeader header;
    header.nVersion = 0x20000000;
    header.hashPrevBlock = ParseUint256("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
    header.hashMerkleRoot = ParseUint256("ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100");
    header.nTime = 1'770'000'000U;
    header.nBits = 0x207fffff;
    header.nNonce64 = nonce;
    header.nNonce = static_cast<uint32_t>(nonce);
    header.matmul_dim = static_cast<uint16_t>(n);
    header.seed_a = ParseUint256("0000000000000000000000000000000000000000000000000000000000000000");
    header.seed_b = ParseUint256("4504d44d861b69197db1d95e473442346c4f2bc1f5869996bdccd63cfbdbd150");
    return header;
}

size_t ExpectedSketchBytes(uint32_t n)
{
    const size_t m = n / matmul_v4::kTileB;
    return 8 * m * m; // one canonical mod-q word (8 bytes LE) per sketch entry (§E.1)
}

//! Draw one canonical F_q word (uniform enough for forgery trials).
uint64_t RandomCanonicalWord(FastRandomContext& rng)
{
    uint64_t x = rng.rand64();
    x = (x & kMersenne61) + (x >> 61);
    x = (x & kMersenne61) + (x >> 61);
    if (x >= kMersenne61) x -= kMersenne61;
    return x;
}

//! Overwrite the 8-byte word at word-index `idx` with a canonical value.
void SetPayloadWord(std::vector<unsigned char>& payload, size_t idx, uint64_t word)
{
    BOOST_REQUIRE_LE((idx + 1) * 8, payload.size());
    WriteLE64(payload.data() + idx * 8, word);
}

uint64_t GetPayloadWord(const std::vector<unsigned char>& payload, size_t idx)
{
    BOOST_REQUIRE_LE((idx + 1) * 8, payload.size());
    return ReadLE64(payload.data() + idx * 8);
}

struct HonestProof {
    CBlockHeader header;
    uint256 digest;
    std::vector<unsigned char> payload;
};

HonestProof ComputeHonestProof(uint64_t nonce = 1,
                               uint32_t n = kTestDim,
                               uint32_t rounds = matmul_v4::kFreivaldsRounds)
{
    HonestProof proof;
    proof.header = MakeV4Header(nonce, n);
    BOOST_REQUIRE(matmul_v4::ComputeDigest(proof.header, n, rounds, proof.digest, proof.payload));
    // Seal the mined digest into the header, exactly as SolveMatMulV4 does
    // before a block is finalized: VerifySketch recomputes the digest from the
    // payload and requires it to equal header.matmul_digest (§0.7-(1)). Honest
    // round-trips must carry the seal to verify; the mutation/forgery cases
    // below still fail because a tampered payload no longer hashes to it.
    proof.header.matmul_digest = proof.digest;
    return proof;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(matmul_v4_sketch_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(streaming_digest_uses_canonical_le64_image)
{
    const uint256 sigma = ParseUint256("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    const std::vector<matmul::int8_field::Fq> sketch{
        0,
        1,
        UINT64_C(0x0102030405060708),
        UINT64_C(0x0011223344556677),
        matmul::int8_field::kFieldPrime - 1,
    };

    // Pin the payload independently, byte by byte, so the fast contiguous
    // little-endian hash path cannot silently change the consensus image.
    const std::vector<unsigned char> payload = matmul::v4::SerializeSketch(sketch);
    BOOST_REQUIRE_EQUAL(payload.size(), sketch.size() * sizeof(uint64_t));
    for (size_t word = 0; word < sketch.size(); ++word) {
        for (size_t byte = 0; byte < sizeof(uint64_t); ++byte) {
            BOOST_CHECK_EQUAL(payload[word * sizeof(uint64_t) + byte],
                              static_cast<unsigned char>(sketch[word] >> (8 * byte)));
        }
    }
    BOOST_CHECK(matmul::v4::ComputeSketchDigestFromFq(sigma, sketch) ==
                matmul::v4::ComputeSketchDigest(sigma, payload));

    // Also cover the guarded empty-vector path (no null-pointer arithmetic).
    const std::vector<matmul::int8_field::Fq> empty;
    BOOST_CHECK(matmul::v4::ComputeSketchDigestFromFq(sigma, empty) ==
                matmul::v4::ComputeSketchDigest(sigma, {}));
}

// --- Wide counter-mode XOF (§A.2, Appendix C-12; PR #89 review fix) ---------

BOOST_AUTO_TEST_CASE(wide_xof_stream_matches_normative_construction)
{
    // Pin the normative operand XOF: keystream block j is
    //   SHA256( seed_le(32) || 's' (0x73) || LE64(j) )
    // and elements are the accepted (< 251) bytes in stream order, mapped to
    // [-125, 125]. Re-derive the stream here independently of int8_field.cpp
    // so any layout drift (domain byte, counter width/endianness, byte order,
    // rejection rule) breaks this test.
    const uint256 seed = ParseUint256("4504d44d861b69197db1d95e473442346c4f2bc1f5869996bdccd63cfbdbd150");
    constexpr size_t kCount = 10'000;

    std::vector<int8_t> got(kCount);
    matmul::int8_field::ExpandBalancedS8Stream(seed, kCount, got.data());

    uint8_t seed_le[32];
    for (size_t i = 0; i < 32; ++i) seed_le[i] = seed.data()[31 - i];

    std::vector<int8_t> want;
    want.reserve(kCount);
    uint64_t hashes = 0;
    for (uint64_t block = 0; want.size() < kCount; ++block) {
        CSHA256 hasher;
        hasher.Write(seed_le, sizeof(seed_le));
        const uint8_t domain = 0x73; // 's'
        hasher.Write(&domain, 1);
        uint8_t block_le[8];
        WriteLE64(block_le, block);
        hasher.Write(block_le, sizeof(block_le));
        uint8_t hash[CSHA256::OUTPUT_SIZE];
        hasher.Finalize(hash);
        ++hashes;
        for (size_t i = 0; i < CSHA256::OUTPUT_SIZE && want.size() < kCount; ++i) {
            if (hash[i] < 251) {
                want.push_back(static_cast<int8_t>(static_cast<int32_t>(hash[i]) - 125));
            }
        }
    }
    BOOST_CHECK(got == want);

    // Width property (the load-bearing fix): ~31.4 elements per compression,
    // i.e. hash count must be a small fraction of the element count — never
    // the >= 1 hash/element of the retired per-element oracle.
    BOOST_CHECK_LT(hashes, kCount / 25);

    // Canonical balanced range.
    for (const int8_t v : got) {
        BOOST_CHECK_LE(static_cast<int32_t>(v), 125);
        BOOST_CHECK_GE(static_cast<int32_t>(v), -125);
    }
}

BOOST_AUTO_TEST_CASE(wide_xof_fq_stream_matches_normative_construction)
{
    // Same pin for the F_q challenge stream: block j is
    //   SHA256( seed_le(32) || 'q' (0x71) || LE64(j) )
    // -> four LE64 words, each masked to 61 bits, rejecting only the value q.
    const uint256 seed = ParseUint256("c6a811f7f75fe4e64be106a50351aed9c04403a74bfe7b4bbe59f7311722b735");
    constexpr size_t kCount = 4'096;
    constexpr uint64_t q = kMersenne61;

    std::vector<matmul::int8_field::Fq> got(kCount);
    matmul::int8_field::ExpandFqStream(seed, kCount, got.data());

    uint8_t seed_le[32];
    for (size_t i = 0; i < 32; ++i) seed_le[i] = seed.data()[31 - i];

    std::vector<uint64_t> want;
    want.reserve(kCount);
    for (uint64_t block = 0; want.size() < kCount; ++block) {
        CSHA256 hasher;
        hasher.Write(seed_le, sizeof(seed_le));
        const uint8_t domain = 0x71; // 'q'
        hasher.Write(&domain, 1);
        uint8_t block_le[8];
        WriteLE64(block_le, block);
        hasher.Write(block_le, sizeof(block_le));
        uint8_t hash[CSHA256::OUTPUT_SIZE];
        hasher.Finalize(hash);
        for (size_t w = 0; w < CSHA256::OUTPUT_SIZE / 8 && want.size() < kCount; ++w) {
            const uint64_t candidate = ReadLE64(hash + w * 8) & q;
            if (candidate < q) want.push_back(candidate);
        }
    }
    BOOST_CHECK(std::vector<uint64_t>(got.begin(), got.end()) == want);
    for (const uint64_t v : got) BOOST_CHECK_LT(v, q);
}

// --- Optimal-vs-reference sketch equivalence --------------------------------

BOOST_AUTO_TEST_CASE(optimal_sketch_matches_full_c_reference)
{
    // The miner path (ComputeDigest) uses ComputeSketchOptimal, which evaluates
    // Chat = (U*A)(B*V) without forming C. It MUST equal the full-C reference
    // ComputeSketch(U, ComputeExactProduct(A,B), V) word-for-word: by
    // integer-matrix associativity (U*A)(B*V) == U*(A*B)*V == U*C*V, every m*m
    // entry is the same integer and thus the same canonical F_q residue. This
    // is what makes the SerializeSketch payload and the digest byte-identical.
    for (const uint32_t n : {kTestDim, uint32_t{512}}) {
        uint32_t m = 0;
        BOOST_REQUIRE(matmul::v4::ValidateDims(n, matmul_v4::kTileB, m));

        // Exercise several distinct nonces (fresh operands + projectors each).
        for (uint64_t nonce : {uint64_t{1}, uint64_t{7}, uint64_t{4242}}) {
            const CBlockHeader header = MakeV4Header(nonce, n);

            const uint256 sigma = matmul::v4::DeriveSigma(header);
            const uint256 seed_a = matmul::v4::DeriveOperandSeed(header, matmul::v4::Operand::A);
            const uint256 seed_b = matmul::v4::DeriveOperandSeed(header, matmul::v4::Operand::B);
            const auto [seed_u, seed_v] = matmul::v4::DeriveProjectorSeeds(header);

            const std::vector<int8_t> A = matmul::v4::ExpandOperand(seed_a, n);
            const std::vector<int8_t> B = matmul::v4::ExpandOperand(seed_b, n);
            const std::vector<int8_t> U = matmul::v4::ExpandProjector(seed_u, m, n);
            const std::vector<int8_t> V = matmul::v4::ExpandProjector(seed_v, n, m);

            const std::vector<int32_t> C = matmul::v4::ComputeExactProduct(A, B, n);
            const std::vector<matmul::v4::Fq> reference = matmul::v4::ComputeSketch(U, C, V, n, m);
            const std::vector<matmul::v4::Fq> optimal = matmul::v4::ComputeSketchOptimal(U, A, B, V, n, m);

            BOOST_REQUIRE_EQUAL(reference.size(), static_cast<size_t>(m) * m);
            BOOST_REQUIRE_EQUAL(optimal.size(), reference.size());
            BOOST_CHECK_MESSAGE(optimal == reference,
                                "ComputeSketchOptimal != full-C ComputeSketch at n=" << n
                                    << " nonce=" << nonce);

            // And therefore the serialized payloads are byte-identical.
            BOOST_CHECK(matmul::v4::SerializeSketch(optimal) == matmul::v4::SerializeSketch(reference));
        }
    }
}

// --- Honest round-trips -----------------------------------------------------

BOOST_AUTO_TEST_CASE(honest_sketch_roundtrip_accepts)
{
    const auto proof = ComputeHonestProof();

    uint256 verified_digest;
    BOOST_CHECK(matmul_v4::VerifySketch(proof.header, kTestDim, matmul_v4::kFreivaldsRounds,
                                        proof.payload, verified_digest));
    BOOST_CHECK_EQUAL(verified_digest, proof.digest);
}

BOOST_AUTO_TEST_CASE(honest_sketch_roundtrip_accepts_regtest_rounds)
{
    // R = 2 is the regtest round count (§0.7-(2)).
    const auto proof = ComputeHonestProof(/*nonce=*/2, kTestDim, /*rounds=*/2);

    uint256 verified_digest;
    BOOST_CHECK(matmul_v4::VerifySketch(proof.header, kTestDim, /*rounds=*/2,
                                        proof.payload, verified_digest));
    BOOST_CHECK_EQUAL(verified_digest, proof.digest);
}

BOOST_AUTO_TEST_CASE(honest_sketch_roundtrip_accepts_n512)
{
    const auto proof = ComputeHonestProof(/*nonce=*/3, /*n=*/512);

    uint256 verified_digest;
    BOOST_CHECK(matmul_v4::VerifySketch(proof.header, 512, matmul_v4::kFreivaldsRounds,
                                        proof.payload, verified_digest));
    BOOST_CHECK_EQUAL(verified_digest, proof.digest);
}

BOOST_AUTO_TEST_CASE(sketch_payload_has_normative_shape)
{
    // §E.1: the payload is exactly 8 * m^2 bytes, m = n / b — quadratically
    // smaller than the 4 * n^2 bytes of a full-C payload. This is also the
    // structural evidence that verification input never includes C.
    for (const uint32_t n : {kTestDim, uint32_t{512}}) {
        const auto proof = ComputeHonestProof(/*nonce=*/4, n);
        BOOST_CHECK_EQUAL(proof.payload.size(), ExpectedSketchBytes(n));
        BOOST_CHECK_LT(proof.payload.size(), static_cast<size_t>(4) * n * n);
    }
}

BOOST_AUTO_TEST_CASE(sketch_payload_words_are_canonical_mod_q)
{
    // Every 8-byte word must be a canonical residue < q; anything else is
    // non-canonical and consensus-invalid (§E.1, §I.2 step 2).
    const auto proof = ComputeHonestProof();
    BOOST_REQUIRE_EQUAL(proof.payload.size() % 8, 0U);
    for (size_t idx = 0; idx < proof.payload.size() / 8; ++idx) {
        BOOST_CHECK_LT(GetPayloadWord(proof.payload, idx), kMersenne61);
    }
}

// --- Mutations are rejected -------------------------------------------------

BOOST_AUTO_TEST_CASE(single_bit_flips_are_rejected)
{
    const auto proof = ComputeHonestProof();

    const size_t positions[] = {0, proof.payload.size() / 3, proof.payload.size() / 2,
                                proof.payload.size() - 1};
    const unsigned char masks[] = {0x01, 0x80};
    for (const size_t pos : positions) {
        for (const unsigned char mask : masks) {
            auto mutated = proof.payload;
            mutated[pos] ^= mask;
            uint256 digest;
            BOOST_CHECK_MESSAGE(
                !matmul_v4::VerifySketch(proof.header, kTestDim, matmul_v4::kFreivaldsRounds,
                                         mutated, digest),
                "bit flip at byte " << pos << " mask " << static_cast<int>(mask)
                                    << " must be rejected");
        }
    }
}

BOOST_AUTO_TEST_CASE(single_word_replacement_is_rejected)
{
    // Replacing one sketch word with a different *canonical* residue is the
    // minimal wrong-C_hat forgery; each Freivalds round catches it with
    // probability >= 1 - 2/q (§E.2).
    const auto proof = ComputeHonestProof();
    const size_t num_words = proof.payload.size() / 8;

    FastRandomContext rng{true};
    for (int trial = 0; trial < 32; ++trial) {
        const size_t idx = static_cast<size_t>(rng.randrange(num_words));
        uint64_t replacement = RandomCanonicalWord(rng);
        if (replacement == GetPayloadWord(proof.payload, idx)) {
            replacement = (replacement + 1) % kMersenne61;
        }
        auto mutated = proof.payload;
        SetPayloadWord(mutated, idx, replacement);
        uint256 digest;
        BOOST_CHECK(!matmul_v4::VerifySketch(proof.header, kTestDim, matmul_v4::kFreivaldsRounds,
                                             mutated, digest));
    }
}

BOOST_AUTO_TEST_CASE(off_by_one_word_is_rejected)
{
    // C_hat differing from U*C*V in exactly one word by exactly one is the
    // hardest honest-adjacent forgery; the exact-integer lift guarantees it
    // cannot alias mod q (§D.3).
    const auto proof = ComputeHonestProof();
    auto mutated = proof.payload;
    const uint64_t w = GetPayloadWord(mutated, 0);
    SetPayloadWord(mutated, 0, (w + 1) % kMersenne61);
    uint256 digest;
    BOOST_CHECK(!matmul_v4::VerifySketch(proof.header, kTestDim, matmul_v4::kFreivaldsRounds,
                                         mutated, digest));
}

BOOST_AUTO_TEST_CASE(non_canonical_word_is_rejected)
{
    // A word >= q (here: all-ones) is non-canonical even when it denotes the
    // same residue class — serialization is canonical-form-only (§B.1-(3)).
    const auto proof = ComputeHonestProof();
    auto mutated = proof.payload;
    SetPayloadWord(mutated, 0, ~uint64_t{0});
    uint256 digest;
    BOOST_CHECK(!matmul_v4::VerifySketch(proof.header, kTestDim, matmul_v4::kFreivaldsRounds,
                                         mutated, digest));

    // The dual representation of the same residue (w + q) must likewise be
    // rejected wherever it stays inside 64 bits.
    auto dual = proof.payload;
    const uint64_t w = GetPayloadWord(dual, 1);
    SetPayloadWord(dual, 1, w + kMersenne61); // w < q so w + q < 2^62, representable
    BOOST_CHECK(!matmul_v4::VerifySketch(proof.header, kTestDim, matmul_v4::kFreivaldsRounds,
                                         dual, digest));
}

BOOST_AUTO_TEST_CASE(wrong_shape_payloads_are_rejected)
{
    const auto proof = ComputeHonestProof();
    uint256 digest;

    std::vector<unsigned char> empty;
    BOOST_CHECK(!matmul_v4::VerifySketch(proof.header, kTestDim, matmul_v4::kFreivaldsRounds,
                                         empty, digest));

    auto truncated = proof.payload;
    truncated.resize(truncated.size() - 8);
    BOOST_CHECK(!matmul_v4::VerifySketch(proof.header, kTestDim, matmul_v4::kFreivaldsRounds,
                                         truncated, digest));

    auto extended = proof.payload;
    extended.insert(extended.end(), 8, 0x00);
    BOOST_CHECK(!matmul_v4::VerifySketch(proof.header, kTestDim, matmul_v4::kFreivaldsRounds,
                                         extended, digest));

    auto misaligned = proof.payload;
    misaligned.push_back(0x00);
    BOOST_CHECK(!matmul_v4::VerifySketch(proof.header, kTestDim, matmul_v4::kFreivaldsRounds,
                                         misaligned, digest));

    std::vector<unsigned char> zeros(proof.payload.size(), 0x00);
    BOOST_CHECK(!matmul_v4::VerifySketch(proof.header, kTestDim, matmul_v4::kFreivaldsRounds,
                                         zeros, digest));
}

BOOST_AUTO_TEST_CASE(payload_for_another_header_is_rejected)
{
    // The sketch commits to *this* header's product: operand B, sigma and
    // the Fiat-Shamir challenges are nonce-fresh (§C-I1'), so an honestly
    // computed payload for a sibling nonce is a wrong C for this header.
    const auto proof_a = ComputeHonestProof(/*nonce=*/10);
    const auto proof_b = ComputeHonestProof(/*nonce=*/11);
    BOOST_REQUIRE(proof_a.payload != proof_b.payload);

    uint256 digest;
    BOOST_CHECK(!matmul_v4::VerifySketch(proof_a.header, kTestDim, matmul_v4::kFreivaldsRounds,
                                         proof_b.payload, digest));
    BOOST_CHECK(!matmul_v4::VerifySketch(proof_b.header, kTestDim, matmul_v4::kFreivaldsRounds,
                                         proof_a.payload, digest));
}

// --- Statistical soundness spot-check ---------------------------------------

BOOST_AUTO_TEST_CASE(forged_sketches_never_pass_statistical_spot_check)
{
    // A forged sketch passes R rounds with probability <= (2/q)^R = 2^-180
    // at R = 3 (§E.2) — cryptographically negligible. Any acceptance among
    // these fixed-seed forgeries therefore indicates an implementation bug
    // (e.g. challenges not bound to the payload, or a degenerate projector),
    // not bad luck.
    const auto proof = ComputeHonestProof();
    const size_t num_words = proof.payload.size() / 8;
    FastRandomContext rng{true};

    // (a) Fully random canonical sketches.
    for (int trial = 0; trial < 64; ++trial) {
        std::vector<unsigned char> forged(proof.payload.size());
        for (size_t idx = 0; idx < num_words; ++idx) {
            SetPayloadWord(forged, idx, RandomCanonicalWord(rng));
        }
        uint256 digest;
        BOOST_CHECK(!matmul_v4::VerifySketch(proof.header, kTestDim, matmul_v4::kFreivaldsRounds,
                                             forged, digest));
    }

    // (b) Honest sketch with a sparse random perturbation (1..4 words).
    for (int trial = 0; trial < 64; ++trial) {
        auto forged = proof.payload;
        const size_t flips = 1 + static_cast<size_t>(rng.randrange(4));
        for (size_t f = 0; f < flips; ++f) {
            const size_t idx = static_cast<size_t>(rng.randrange(num_words));
            uint64_t replacement = RandomCanonicalWord(rng);
            if (replacement == GetPayloadWord(proof.payload, idx)) {
                replacement = (replacement + 1) % kMersenne61;
            }
            SetPayloadWord(forged, idx, replacement);
        }
        if (forged == proof.payload) continue; // theoretically unreachable
        uint256 digest;
        BOOST_CHECK(!matmul_v4::VerifySketch(proof.header, kTestDim, matmul_v4::kFreivaldsRounds,
                                             forged, digest));
    }
}

BOOST_AUTO_TEST_CASE(forged_sketches_rejected_even_at_regtest_rounds)
{
    // R = 2 still gives <= (2/q)^2 = 2^-120 — spot-check the regtest
    // configuration as well.
    const auto proof = ComputeHonestProof(/*nonce=*/20, kTestDim, /*rounds=*/2);
    const size_t num_words = proof.payload.size() / 8;
    FastRandomContext rng{true};

    for (int trial = 0; trial < 32; ++trial) {
        auto forged = proof.payload;
        const size_t idx = static_cast<size_t>(rng.randrange(num_words));
        uint64_t replacement = RandomCanonicalWord(rng);
        if (replacement == GetPayloadWord(proof.payload, idx)) {
            replacement = (replacement + 1) % kMersenne61;
        }
        SetPayloadWord(forged, idx, replacement);
        uint256 digest;
        BOOST_CHECK(!matmul_v4::VerifySketch(proof.header, kTestDim, /*rounds=*/2, forged, digest));
    }
}

BOOST_AUTO_TEST_SUITE_END()
