// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// MatMul v4.4 ENC-DR ("digest-only, re-derivable") consensus tests
// (doc/btx-matmul-v4.4-tension-resolution.md §4). These cases pin:
//
//   (a) PROFILE WIRING: at v4 heights GetMatMulProfileParams selects the
//       DIGEST_RECOMPUTE carriage (zero consensus proof bytes); the legacy
//       FLAT_SKETCH_INBLOCK carriage is reachable only via the regtest-only
//       fMatMulV4FlatSketchReplay differential switch.
//   (b) RECOMPUTE == MINE, BY SHARED CODE (the §4.1 determinism invariant and
//       the R1 CPU-reference anchor): the verify-side reference recompute
//       (RecomputeMatMulV4SketchReference) is byte-identical — digest AND
//       sketch bytes — to the miner's CPU reference (ComputeDigestBMX4C, the
//       same routine SolveMatMulV4BMX4C reseals winners with), and to the
//       digest the v4.3 Freivalds verifier recomputes over the payload. The
//       mine-side reference itself is anchored by the pinned ENC-BMX4C golden
//       vectors in matmul_v4_bmx4 tests, so this transitively pins the
//       verify-side recompute to the same goldens.
//   (c) BOTH EVALUATION STRATEGIES ACCEPT an honest digest-only block: the
//       exact recompute path (epsilon = 0, cold cache) and the cache-assisted
//       Freivalds path (epsilon <= 2^-180, warm cache) decide the identical
//       predicate (§4.2).
//   (d) REJECTION by the CPU-reference recompute: a crafted block whose header
//       digest != H(sigma||Chat_true) — including a digest lifted from a
//       DIFFERENT nonce's true sketch — MUST be rejected (the §5-2 adversarial
//       vector for the exact-equality clause).
//   (e) GARBAGE-CACHE ISOLATION (§4.2-a): a tampered cache entry fails the
//       one-hash authentication, is dropped, and the block still ACCEPTS via
//       recompute — a cache failure is never evidence about the block.
//   (f) The sketch cache itself: bounded FIFO, capacity 0 = disabled.

#include <arith_uint256.h>
#include <consensus/params.h>
#include <matmul/matmul_sketch_cache.h>
#include <matmul/matmul_v4_bmx4.h>
#include <matmul/pow_v4.h>
#include <pow.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <vector>

namespace bx = matmul::v4::bmx4;

BOOST_FIXTURE_TEST_SUITE(matmul_encdr_tests, BasicTestingSetup)

namespace {

//! Smallest legal ENC-BMX4C dim (64 % 32 == 0, b = 4 | 64) => m = 16, sketch
//! 8·m² = 2048 bytes: fast enough to recompute many times per test.
constexpr uint32_t kTestDim = 64;
constexpr int32_t kActivation = 100;
constexpr int32_t kHeight = 150;

Consensus::Params MakeEncDrParams()
{
    Consensus::Params p{};
    p.fMatMulPOW = true;
    p.fSkipMatMulValidation = false;
    // Max target so the first nonce's digest wins (single digest evaluation).
    p.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
    // Single flag day (tension-resolution §5-1): v4 and ENC-BMX4C together.
    p.nMatMulV4Height = kActivation;
    p.nMatMulBMX4CHeight = kActivation;
    p.nMatMulV4Dimension = kTestDim;
    p.nMatMulV4FreivaldsRounds = 2; // regtest rounds
    return p;
}

CBlockHeader MakeHeader(const Consensus::Params& params, uint64_t nonce)
{
    CBlockHeader header{};
    header.nVersion = 0x20000004;
    header.hashPrevBlock = uint256{"5151515151515151515151515151515151515151515151515151515151515151"};
    header.hashMerkleRoot = uint256{"a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"};
    header.nTime = 1'780'000'020U;
    header.nBits = UintToArith256(params.powLimit).GetCompact();
    header.nNonce64 = nonce;
    header.nNonce = static_cast<uint32_t>(nonce);
    header.matmul_dim = static_cast<uint16_t>(kTestDim);
    // The ENC-DR predicate (CheckMatMulProofOfWork_V4EncDr) requires non-null
    // seeds but does not itself pin their derivation (that is
    // ContextualCheckBlockHeader's "bad-matmul-seeds" recompute-and-compare,
    // covered by pow_tests); fixed seeds keep these cases deterministic.
    header.seed_a = uint256{"1111111111111111111111111111111111111111111111111111111111111111"};
    header.seed_b = uint256{"2222222222222222222222222222222222222222222222222222222222222222"};
    return header;
}

//! Mine a digest-only ENC-DR block the way the real miner does at its core:
//! seal header.matmul_digest with the CPU reference (ComputeDigestBMX4C — the
//! routine SolveMatMulV4BMX4C reseals every winning candidate through). At max
//! target the first nonce wins. Returns the block plus the miner's 8·m² sketch
//! bytes (what OffloadMatMulV4SketchToCache would hand the cache).
CBlock MineDigestOnlyBlock(const Consensus::Params& params,
                           std::vector<unsigned char>& sketch_out,
                           uint64_t nonce = 7)
{
    CBlockHeader header = MakeHeader(params, nonce);
    uint256 digest;
    BOOST_REQUIRE(bx::ComputeDigestBMX4C(header, kTestDim, digest, sketch_out));
    BOOST_REQUIRE(UintToArith256(digest) <=
                  UintToArith256(params.powLimit)); // max target: always wins
    header.matmul_digest = digest;
    CBlock block;
    static_cast<CBlockHeader&>(block) = header;
    // Digest-only body (§4.1 clause 2): every payload channel empty.
    BOOST_REQUIRE(block.matrix_a_data.empty());
    BOOST_REQUIRE(block.matrix_b_data.empty());
    BOOST_REQUIRE(block.matrix_c_data.empty());
    return block;
}

struct SketchCacheReset {
    SketchCacheReset()
    {
        matmul::GetMatMulSketchCache().Clear();
        matmul::GetMatMulSketchCache().SetCapacity(8);
    }
    ~SketchCacheReset()
    {
        matmul::GetMatMulSketchCache().Clear();
        matmul::GetMatMulSketchCache().SetCapacity(8);
    }
};

} // namespace

// --- (a) profile wiring -----------------------------------------------------

BOOST_AUTO_TEST_CASE(encdr_profile_selects_digest_recompute_at_v4_heights)
{
    Consensus::Params p = MakeEncDrParams();

    BOOST_CHECK(p.IsMatMulV4Active(kHeight));
    BOOST_CHECK(p.IsMatMulEncDrActive(kHeight));

    const Consensus::MatMulProfileParams profile = p.GetMatMulProfileParams(kHeight);
    BOOST_CHECK(profile.commitment == Consensus::MatMulCommitmentScheme::DIGEST_RECOMPUTE);
    BOOST_CHECK(profile.profile == Consensus::MatMulEncodingProfile::ENC_BMX4C);
    BOOST_CHECK_EQUAL(profile.tile_b, 4U);
    BOOST_CHECK_EQUAL(profile.sketch_rank_m, Consensus::BMX4C_SKETCH_RANK_M);
    // The 8·m² quantity survives only as the sketch-cache size bound.
    BOOST_CHECK_EQUAL(profile.SketchCacheBytes(),
                      uint64_t{8} * profile.sketch_rank_m * profile.sketch_rank_m);

    // The legacy in-block carriage exists only behind the regtest replay switch.
    Consensus::Params replay = p;
    replay.fMatMulV4FlatSketchReplay = true;
    BOOST_CHECK(!replay.IsMatMulEncDrActive(kHeight));
    BOOST_CHECK(replay.GetMatMulProfileParams(kHeight).commitment ==
                Consensus::MatMulCommitmentScheme::FLAT_SKETCH_INBLOCK);
}

// --- (b) recompute == mine, by shared code ----------------------------------

BOOST_AUTO_TEST_CASE(encdr_verify_recompute_is_byte_identical_to_mine_reference)
{
    SketchCacheReset guard;
    const Consensus::Params p = MakeEncDrParams();

    const CBlockHeader header = MakeHeader(p, /*nonce=*/42);

    // Mine-side CPU reference (what SolveMatMulV4BMX4C seals winners with).
    uint256 mine_digest;
    std::vector<unsigned char> mine_sketch;
    BOOST_REQUIRE(bx::ComputeDigestBMX4C(header, kTestDim, mine_digest, mine_sketch));

    // Verify-side reference recompute (the ENC-DR consensus definition). Must
    // be byte-identical: digest AND every sketch byte.
    uint256 verify_digest;
    std::vector<unsigned char> verify_sketch;
    BOOST_REQUIRE(RecomputeMatMulV4SketchReference(header, p, kHeight, verify_digest, verify_sketch));
    BOOST_CHECK_EQUAL(verify_digest, mine_digest);
    BOOST_CHECK(verify_sketch == mine_sketch);

    // Determinism: a second recompute reproduces the identical bytes.
    uint256 again_digest;
    std::vector<unsigned char> again_sketch;
    BOOST_REQUIRE(RecomputeMatMulV4SketchReference(header, p, kHeight, again_digest, again_sketch));
    BOOST_CHECK_EQUAL(again_digest, verify_digest);
    BOOST_CHECK(again_sketch == verify_sketch);

    // Cross-check against the third independent path: the v4.3 Freivalds
    // verifier recomputes the digest from the payload bytes; all three agree.
    CBlockHeader sealed = header;
    sealed.matmul_digest = mine_digest;
    uint256 freivalds_digest;
    BOOST_CHECK(bx::VerifySketchBMX4C(sealed, kTestDim, p.nMatMulV4FreivaldsRounds,
                                      mine_sketch, freivalds_digest));
    BOOST_CHECK_EQUAL(freivalds_digest, mine_digest);
}

// --- (c) both evaluation strategies accept an honest digest-only block ------

BOOST_AUTO_TEST_CASE(encdr_digest_only_block_validates_via_recompute_and_cache)
{
    SketchCacheReset guard;
    const Consensus::Params p = MakeEncDrParams();

    std::vector<unsigned char> miner_sketch;
    const CBlock block = MineDigestOnlyBlock(p, miner_sketch);
    const uint256 hash = block.GetHash();

    // RECOMPUTE path (cold cache): the consensus definition, epsilon = 0.
    BOOST_REQUIRE(!matmul::GetMatMulSketchCache().Have(hash));
    BOOST_CHECK(CheckMatMulProofOfWork_V4EncDr(block, p, kHeight));
    // Accepting by recompute materialized the bytes: this node can now serve
    // peers (tension-resolution §3.1-vi-c) — and they are the miner's bytes.
    std::vector<unsigned char> cached;
    BOOST_REQUIRE(matmul::GetMatMulSketchCache().Get(hash, cached));
    BOOST_CHECK(cached == miner_sketch);

    // CACHE path (warm cache, e.g. an authenticated mmsketch delivery): the
    // v4.3 Freivalds verifier over the untrusted bytes decides the identical
    // predicate. Seed the cache explicitly with the miner handoff bytes.
    matmul::GetMatMulSketchCache().Clear();
    matmul::GetMatMulSketchCache().Put(hash, miner_sketch);
    BOOST_CHECK(CheckMatMulProofOfWork_V4EncDr(block, p, kHeight));
    BOOST_CHECK(matmul::GetMatMulSketchCache().Have(hash));
}

// --- (d) rejection by the CPU-reference recompute ---------------------------

BOOST_AUTO_TEST_CASE(encdr_wrong_digest_rejected_by_reference_recompute)
{
    SketchCacheReset guard;
    const Consensus::Params p = MakeEncDrParams();

    std::vector<unsigned char> miner_sketch;
    const CBlock good = MineDigestOnlyBlock(p, miner_sketch);

    // (d-1) Arbitrary wrong digest: header digest != H(sigma||Chat_true).
    {
        CBlock bad = good;
        bad.matmul_digest = uint256{"00000000000000000000000000000000000000000000000000000000000000ff"};
        BOOST_CHECK(!CheckMatMulProofOfWork_V4EncDr(bad, p, kHeight));
    }

    // (d-2) The §5-2 crafted vector: a digest that IS a true H(sigma'||Chat')
    // for a DIFFERENT nonce's header, spliced onto this header. Under SHA
    // collision resistance no bytes can authenticate it against THIS header's
    // sigma, and the CPU-reference recompute (the sole arbiter of invalidity,
    // R1) must reject it by exact inequality.
    {
        CBlockHeader other = MakeHeader(p, /*nonce=*/8);
        uint256 other_digest;
        std::vector<unsigned char> other_sketch;
        BOOST_REQUIRE(bx::ComputeDigestBMX4C(other, kTestDim, other_digest, other_sketch));
        BOOST_REQUIRE(other_digest != good.matmul_digest);

        CBlock spliced = good;
        spliced.matmul_digest = other_digest;
        BOOST_CHECK(!CheckMatMulProofOfWork_V4EncDr(spliced, p, kHeight));

        // Even with the OTHER nonce's true sketch planted in the cache, the
        // one-hash authentication fails (sigma differs), the entry is dropped,
        // and the recompute verdict stands: rejected.
        matmul::GetMatMulSketchCache().Put(spliced.GetHash(), other_sketch);
        BOOST_CHECK(!CheckMatMulProofOfWork_V4EncDr(spliced, p, kHeight));
        BOOST_CHECK(!matmul::GetMatMulSketchCache().Have(spliced.GetHash()));
    }

    // (d-3) Null / structural failures.
    {
        CBlock bad = good;
        bad.seed_a.SetNull();
        BOOST_CHECK(!CheckMatMulProofOfWork_V4EncDr(bad, p, kHeight));
        CBlock bad_dim = good;
        bad_dim.matmul_dim = static_cast<uint16_t>(kTestDim * 2);
        BOOST_CHECK(!CheckMatMulProofOfWork_V4EncDr(bad_dim, p, kHeight));
    }

    // Below the activation height the ENC-DR predicate is undefined => false.
    BOOST_CHECK(!CheckMatMulProofOfWork_V4EncDr(good, p, kActivation - 1));
}

// --- (e) garbage-cache isolation -------------------------------------------

BOOST_AUTO_TEST_CASE(encdr_tampered_cache_falls_back_to_recompute_and_accepts)
{
    SketchCacheReset guard;
    const Consensus::Params p = MakeEncDrParams();

    std::vector<unsigned char> miner_sketch;
    const CBlock block = MineDigestOnlyBlock(p, miner_sketch);
    const uint256 hash = block.GetHash();

    // Plant a TAMPERED cache entry (one flipped byte): fails the one-hash
    // H(sigma||bytes)==matmul_digest authentication, must be dropped, and the
    // block must still ACCEPT via the reference recompute — a cache failure is
    // NEVER evidence about the block (§4.2-a).
    std::vector<unsigned char> tampered = miner_sketch;
    tampered[0] ^= 0x01;
    matmul::GetMatMulSketchCache().Put(hash, tampered);

    BOOST_CHECK(CheckMatMulProofOfWork_V4EncDr(block, p, kHeight));
    // The garbage entry was replaced by the recompute's true bytes.
    std::vector<unsigned char> cached;
    BOOST_REQUIRE(matmul::GetMatMulSketchCache().Get(hash, cached));
    BOOST_CHECK(cached == miner_sketch);

    // Truncated / oversized garbage behaves identically.
    matmul::GetMatMulSketchCache().Clear();
    std::vector<unsigned char> truncated(miner_sketch.begin(), miner_sketch.end() - 8);
    matmul::GetMatMulSketchCache().Put(hash, truncated);
    BOOST_CHECK(CheckMatMulProofOfWork_V4EncDr(block, p, kHeight));
}

// --- miner handoff ----------------------------------------------------------

BOOST_AUTO_TEST_CASE(encdr_miner_offload_empties_body_and_feeds_cache)
{
    SketchCacheReset guard;
    const Consensus::Params p = MakeEncDrParams();

    std::vector<unsigned char> miner_sketch;
    CBlock block = MineDigestOnlyBlock(p, miner_sketch);
    // Reconstruct the solver's in-body word-packed state (what
    // freivalds_payload_out produces before the offload).
    CBlock with_payload = block;
    with_payload.matrix_c_data.resize(miner_sketch.size() / 4);
    for (size_t i = 0; i < with_payload.matrix_c_data.size(); ++i) {
        uint32_t w = 0;
        for (int b = 0; b < 4; ++b) w |= uint32_t{miner_sketch[4 * i + b]} << (8 * b);
        with_payload.matrix_c_data[i] = w;
    }

    BOOST_CHECK(OffloadMatMulV4SketchToCache(with_payload));
    // §4.1 clause 2: the block now serializes digest-only...
    BOOST_CHECK(with_payload.matrix_c_data.empty());
    // ...and the winner holds the bytes to serve via getmmsketch.
    std::vector<unsigned char> cached;
    BOOST_REQUIRE(matmul::GetMatMulSketchCache().Get(with_payload.GetHash(), cached));
    BOOST_CHECK(cached == miner_sketch);
    // Idempotent no-op on an already-empty body.
    BOOST_CHECK(!OffloadMatMulV4SketchToCache(with_payload));
}

// --- (f) the cache itself ---------------------------------------------------

BOOST_AUTO_TEST_CASE(sketch_cache_bounded_fifo_and_disable)
{
    SketchCacheReset guard;
    matmul::MatMulSketchCache cache;
    cache.SetCapacity(2);

    constexpr uint256 h1{"0000000000000000000000000000000000000000000000000000000000000001"};
    constexpr uint256 h2{"0000000000000000000000000000000000000000000000000000000000000002"};
    constexpr uint256 h3{"0000000000000000000000000000000000000000000000000000000000000003"};

    cache.Put(h1, {1});
    cache.Put(h2, {2});
    BOOST_CHECK_EQUAL(cache.Size(), 2U);
    cache.Put(h3, {3});             // FIFO-evicts h1
    BOOST_CHECK_EQUAL(cache.Size(), 2U);
    BOOST_CHECK(!cache.Have(h1));
    BOOST_CHECK(cache.Have(h2));
    BOOST_CHECK(cache.Have(h3));

    std::vector<unsigned char> out;
    BOOST_REQUIRE(cache.Get(h2, out));
    BOOST_CHECK_EQUAL(out.size(), 1U);
    BOOST_CHECK_EQUAL(out[0], 2);

    cache.Erase(h2);
    BOOST_CHECK(!cache.Have(h2));
    BOOST_CHECK_EQUAL(cache.Size(), 1U);

    // Capacity 0 disables: existing entries dropped, Put becomes a no-op.
    cache.SetCapacity(0);
    BOOST_CHECK_EQUAL(cache.Size(), 0U);
    cache.Put(h1, {1});
    BOOST_CHECK(!cache.Have(h1));
    BOOST_CHECK_EQUAL(cache.Capacity(), 0U);
}

BOOST_AUTO_TEST_SUITE_END()
