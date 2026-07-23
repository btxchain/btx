// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// SUBLINEAR Freivalds-sampled episode verifier (matmul_v4_rc_freivalds_sampled).
// Fiat–Shamir-sampled per-layer checking with random-projection (Freivalds)
// GEMM verification + O(log N) tile-tree openings, replacing the O(N) full
// re-execution. ADDITIVE / shadow-gated: arbiter OFF, heights INT32_MAX, never
// consensus. Composes against the frozen Fable FreivaldsCheckGemm.
//
// Coverage mirrors the frvsampled_selfcheck (a)-(f):
//  (a) honest episode proof -> wires-mode AND carrier-mode accept
//  (b) tamper a SAMPLED layer (Y / A / extract_out) -> reject at the right stage
//  (c) wrong tile-tree opening -> reject
//  (d) FS-sample determinism + unbiasability
//  (e) SUBLINEARITY: verifier touches only lambda layers, flat as layers grow
//  (f) RESIDUAL honesty: an UNSAMPLED tampered layer passes (deterrence boundary)

#include <arith_uint256.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_freivalds.h>
#include <matmul/matmul_v4_rc_freivalds_sampled.h>
#include <matmul/matmul_v4_rc_gkr.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <limits>
#include <string>
#include <vector>

namespace rc = matmul::v4::rc;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_freivalds_sampled_tests, BasicTestingSetup)

namespace {

constexpr uint32_t kLambda = 3; // small so toy episodes retain unsampled layers

CBlockHeader MakeRCHeader(uint64_t nonce)
{
    CBlockHeader header;
    header.nVersion = 0x20000004;
    header.nTime = 1'770'000'000;
    header.nBits = 0x207fffff;
    header.nNonce64 = nonce;
    header.nNonce = static_cast<uint32_t>(nonce);
    for (int i = 0; i < 32; ++i) {
        header.hashPrevBlock.data()[i] = 0x51;
        header.hashMerkleRoot.data()[i] = 0xa3;
        header.seed_a.data()[i] = 0x11;
        header.seed_b.data()[i] = 0x22;
    }
    return header;
}

arith_uint256 MaxTarget()
{
    arith_uint256 t;
    t = ~t;
    return t;
}

bool LayerInStream(rc::RCGkrLayerKind k)
{
    return k == rc::RCGkrLayerKind::GemmPhase1SV || k == rc::RCGkrLayerKind::GemmPhase2Fwd ||
           k == rc::RCGkrLayerKind::GemmPhase2Bwd || k == rc::RCGkrLayerKind::GemmPhase2Wgrad;
}

std::vector<uint32_t> SampledLayerIndices(const rc::RCGkrProofV7& proof, const CBlockHeader& h,
                                          const arith_uint256& target, uint32_t lambda)
{
    const auto prov = rc::RCGkrEpisodeLayerProvenance(h, proof.episode, proof.round_roots);
    const uint256 base = rc::RCGkrFsSeedV7(h, proof.height, proof.episode, target,
                                           proof.claimed_digest, proof.episode_sigma,
                                           proof.round_roots);
    std::vector<uint32_t> sampleable;
    for (uint32_t i = 0; i < prov.size(); ++i)
        if (LayerInStream(prov[i].kind)) sampleable.push_back(i);
    const auto units = rc::FreivaldsSampleLayers(base, static_cast<uint32_t>(sampleable.size()),
                                                 lambda);
    std::vector<uint32_t> out;
    for (uint32_t u : units) out.push_back(sampleable[u]);
    return out;
}

struct Fixture {
    CBlockHeader h;
    rc::RCEpisodeParams params;
    rc::RCGkrProofV7 proof;
    arith_uint256 target;
    bool ok{false};
};

Fixture MakeFixture(const rc::RCEpisodeParams& params, uint64_t nonce)
{
    Fixture f;
    f.params = params;
    f.target = MaxTarget();
    const auto base = MakeRCHeader(nonce);
    const uint256 real_dig = rc::RecomputeResidentCurriculumReference(base, params, 0);
    f.h = base;
    f.h.matmul_digest = real_dig;
    auto res = rc::ProveWinnerEpisodeV7(f.h, params, 0, f.target, real_dig);
    f.ok = res.timing.ok;
    f.proof = std::move(res.proof);
    return f;
}

bool StartsWith(const std::string& s, const char* p) { return s.rfind(p, 0) == 0; }

} // namespace

// Discipline invariants: never consensus.
BOOST_AUTO_TEST_CASE(frvs_never_consensus)
{
    BOOST_CHECK_EQUAL(Consensus::Params{}.nMatMulRCHeight, std::numeric_limits<int32_t>::max());
    BOOST_CHECK(!rc::EnvRCGkrArbiterEnabled());
}

// (a) honest acceptance — wires-mode and carrier-mode.
BOOST_AUTO_TEST_CASE(frvs_honest_accepts)
{
    Fixture f = MakeFixture(rc::MakeToyRCEpisodeParams(), 42);
    BOOST_REQUIRE(f.ok);

    std::string why;
    rc::RCFreivaldsSampledTiming tmg;
    BOOST_REQUIRE_MESSAGE(
        rc::VerifyEpisodeFreivaldsSampled(f.proof, f.h, 0, f.target, &why, &tmg, kLambda), why);
    BOOST_CHECK_EQUAL(tmg.n_layers_checked, kLambda);
    BOOST_CHECK_EQUAL(tmg.n_freivalds_calls, kLambda);
    BOOST_CHECK_GT(tmg.n_units_total, kLambda);      // more sampleable than sampled
    BOOST_CHECK_GT(tmg.n_merkle_openings, 0u);

    rc::RCFreivaldsSampledCarrier carrier;
    std::string bwhy;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildFreivaldsSampledCarrier(f.proof, f.h, 0, f.target, carrier, &bwhy, kLambda), bwhy);
    BOOST_CHECK_EQUAL(carrier.sampled.size(), kLambda);
    std::string cwhy;
    rc::RCFreivaldsSampledTiming ctmg;
    BOOST_REQUIRE_MESSAGE(
        rc::VerifyEpisodeFreivaldsSampledCarrier(carrier, f.h, 0, f.target, &cwhy, &ctmg), cwhy);
    BOOST_CHECK_EQUAL(ctmg.n_layers_checked, tmg.n_layers_checked);
}

// (b) tamper a SAMPLED layer -> reject at the right stage.
BOOST_AUTO_TEST_CASE(frvs_tamper_sampled_layer_rejects)
{
    Fixture f = MakeFixture(rc::MakeToyRCEpisodeParams(), 42);
    BOOST_REQUIRE(f.ok);
    const auto sampled = SampledLayerIndices(f.proof, f.h, f.target, kLambda);
    BOOST_REQUIRE(!sampled.empty());
    const uint32_t li = sampled.front();

    {   // Tamper Y -> Freivalds catches (A*B != Y).
        rc::RCGkrProofV7 p = f.proof;
        p.wires[li].Y[0] += 1;
        std::string why;
        BOOST_CHECK(!rc::VerifyEpisodeFreivaldsSampled(p, f.h, 0, f.target, &why, nullptr, kLambda));
        BOOST_CHECK_MESSAGE(StartsWith(why, "v7fs:freivalds"), why);
    }
    {   // Tamper A -> Freivalds catches.
        rc::RCGkrProofV7 p = f.proof;
        p.wires[li].A[0] = static_cast<int8_t>(p.wires[li].A[0] ^ 0x7f);
        std::string why;
        BOOST_CHECK(!rc::VerifyEpisodeFreivaldsSampled(p, f.h, 0, f.target, &why, nullptr, kLambda));
        BOOST_CHECK_MESSAGE(StartsWith(why, "v7fs:freivalds"), why);
    }
    {   // Tamper extract_out -> native Extract re-exec catches.
        rc::RCGkrProofV7 p = f.proof;
        p.wires[li].extract_out[0] = static_cast<int8_t>(p.wires[li].extract_out[0] ^ 0x1);
        std::string why;
        BOOST_CHECK(!rc::VerifyEpisodeFreivaldsSampled(p, f.h, 0, f.target, &why, nullptr, kLambda));
        BOOST_CHECK_MESSAGE(StartsWith(why, "v7fs:extract_air"), why);
    }
}

// (c) wrong tile-tree opening -> reject.
BOOST_AUTO_TEST_CASE(frvs_wrong_tiletree_opening_rejects)
{
    Fixture f = MakeFixture(rc::MakeToyRCEpisodeParams(), 42);
    BOOST_REQUIRE(f.ok);
    rc::RCFreivaldsSampledCarrier carrier;
    std::string bwhy;
    BOOST_REQUIRE(
        rc::BuildFreivaldsSampledCarrier(f.proof, f.h, 0, f.target, carrier, &bwhy, kLambda));
    BOOST_REQUIRE(!carrier.sampled.empty());
    BOOST_REQUIRE(!carrier.sampled[0].tiles.empty());

    {   // Corrupt a Merkle sibling of the first sampled tile's opening.
        rc::RCFreivaldsSampledCarrier c = carrier;
        auto& tile = c.sampled[0].tiles[0];
        BOOST_REQUIRE(!tile.leaf_proofs.empty());
        BOOST_REQUIRE(!tile.leaf_proofs[0].siblings.empty());
        tile.leaf_proofs[0].siblings[0].data()[0] ^= 0xff;
        std::string why;
        BOOST_CHECK(!rc::VerifyEpisodeFreivaldsSampledCarrier(c, f.h, 0, f.target, &why, nullptr));
        BOOST_CHECK_MESSAGE(StartsWith(why, "v7fs:tiletree"), why);
    }
    {   // Corrupt a leaf byte -> leaf hash changes -> path no longer folds to root.
        rc::RCFreivaldsSampledCarrier c = carrier;
        auto& tile = c.sampled[0].tiles[0];
        BOOST_REQUIRE(!tile.leaf_bytes.empty());
        auto& lb = tile.leaf_bytes.back();
        BOOST_REQUIRE(!lb.empty());
        lb.back() ^= 0xff;
        std::string why;
        BOOST_CHECK(!rc::VerifyEpisodeFreivaldsSampledCarrier(c, f.h, 0, f.target, &why, nullptr));
        BOOST_CHECK_MESSAGE(StartsWith(why, "v7fs:tiletree"), why);
    }
    {   // Corrupt the opened extract_out block -> leaf-overlap byte check fails.
        rc::RCFreivaldsSampledCarrier c = carrier;
        auto& tile = c.sampled[0].tiles[0];
        BOOST_REQUIRE(!tile.extract_out.empty());
        tile.extract_out[0] ^= 0x1;
        std::string why;
        BOOST_CHECK(!rc::VerifyEpisodeFreivaldsSampledCarrier(c, f.h, 0, f.target, &why, nullptr));
    }
}

// (d) FS-sample determinism + unbiasability.
BOOST_AUTO_TEST_CASE(frvs_fs_sample_determinism)
{
    Fixture f = MakeFixture(rc::MakeToyRCEpisodeParams(), 42);
    BOOST_REQUIRE(f.ok);
    const uint256 base = rc::RCGkrFsSeedV7(f.h, 0, f.params, f.target, f.proof.claimed_digest,
                                           f.proof.episode_sigma, f.proof.round_roots);
    const auto s1 = rc::FreivaldsSampleLayers(base, 7, kLambda);
    const auto s2 = rc::FreivaldsSampleLayers(base, 7, kLambda);
    BOOST_CHECK(s1 == s2);              // deterministic
    BOOST_CHECK_EQUAL(s1.size(), kLambda);
    for (size_t i = 0; i < s1.size(); ++i)   // distinct
        for (size_t j = i + 1; j < s1.size(); ++j) BOOST_CHECK(s1[i] != s1[j]);

    auto roots2 = f.proof.round_roots;
    roots2[0].data()[0] ^= 0xff;
    const uint256 base2 = rc::RCGkrFsSeedV7(f.h, 0, f.params, f.target, f.proof.claimed_digest,
                                            f.proof.episode_sigma, roots2);
    BOOST_CHECK(rc::FreivaldsSampleLayers(base2, 7, kLambda) != s1); // moving roots moves the set

    uint256 dig2 = f.proof.claimed_digest;
    dig2.data()[0] ^= 0xff;
    const uint256 base3 = rc::RCGkrFsSeedV7(f.h, 0, f.params, f.target, dig2, f.proof.episode_sigma,
                                            f.proof.round_roots);
    BOOST_CHECK(rc::FreivaldsSampleLayers(base3, 7, kLambda) != s1); // moving digest moves the set
}

// (e) SUBLINEARITY: touches exactly lambda layers, flat as total layers grow.
BOOST_AUTO_TEST_CASE(frvs_sublinearity_flat_in_layers)
{
    Fixture fs = MakeFixture(rc::MakeToyRCEpisodeParams(), 42); // 8 layers, 7 sampleable
    rc::RCEpisodeParams big = rc::MakeToyRCEpisodeParams();
    big.L_lyr = 8; // 26 layers, 25 sampleable
    Fixture fb = MakeFixture(big, 7);
    BOOST_REQUIRE(fs.ok);
    BOOST_REQUIRE(fb.ok);

    std::string w1, w2;
    rc::RCFreivaldsSampledTiming t1, t2;
    BOOST_REQUIRE(rc::VerifyEpisodeFreivaldsSampled(fs.proof, fs.h, 0, fs.target, &w1, &t1, kLambda));
    BOOST_REQUIRE(rc::VerifyEpisodeFreivaldsSampled(fb.proof, fb.h, 0, fb.target, &w2, &t2, kLambda));

    BOOST_CHECK_GT(t2.n_units_total, t1.n_units_total);  // big episode has MORE layers
    // The instrumentation counter is FLAT: exactly lambda layers touched in both.
    BOOST_CHECK_EQUAL(t1.n_layers_checked, kLambda);
    BOOST_CHECK_EQUAL(t2.n_layers_checked, kLambda);
    BOOST_CHECK_EQUAL(t1.n_freivalds_calls, t2.n_freivalds_calls);
}

// (f) RESIDUAL honesty: an UNSAMPLED tampered layer PASSES (deterrence boundary,
// not a bug). This is the rho* ~ ln(kappa)/lambda cheatable residual.
BOOST_AUTO_TEST_CASE(frvs_residual_unsampled_tamper_passes)
{
    Fixture f = MakeFixture(rc::MakeToyRCEpisodeParams(), 42);
    BOOST_REQUIRE(f.ok);
    const auto sampled = SampledLayerIndices(f.proof, f.h, f.target, kLambda);
    const auto prov = rc::RCGkrEpisodeLayerProvenance(f.h, f.params, f.proof.round_roots);

    int victim = -1;
    for (uint32_t i = 0; i < prov.size(); ++i) {
        if (!LayerInStream(prov[i].kind)) continue;
        bool is_sampled = false;
        for (uint32_t s : sampled) if (s == i) is_sampled = true;
        if (!is_sampled) { victim = static_cast<int>(i); break; }
    }
    BOOST_REQUIRE_GE(victim, 0);

    rc::RCGkrProofV7 p = f.proof;
    p.wires[victim].Y[0] += 1; // fake an UNSAMPLED layer's GEMM output
    std::string why;
    // Documented residual: the sampled verifier does NOT detect this (unsampled).
    BOOST_CHECK(rc::VerifyEpisodeFreivaldsSampled(p, f.h, 0, f.target, &why, nullptr, kLambda));
}

// ===========================================================================
// SEGMENT-FREIVALDS: the primitive + the segment CARRIER (bounded per-layer
// relay, datacenter relay-ceiling fit). matmul_v4_rc_freivalds.h + the segment
// carrier in matmul_v4_rc_freivalds_sampled.{h,cpp}.
// ===========================================================================

// (g) FreivaldsCheckGemmSegments primitive: completeness EXACT over the segmented
//     contraction; a wrong claim caught (soundness ≤ 2^(−63·reps)); the segment
//     partials compose (Σ_p A_p·B_p == Y under one projection).
BOOST_AUTO_TEST_CASE(frvs_check_gemm_segments_primitive)
{
    // Deterministic pseudo-random int8 A (m×k), B (k×n); split k into segments.
    const uint32_t m = 3, n = 32, k = 200;
    auto mix = [](uint32_t x) { x ^= x >> 15; x *= 0x2c1b3c6dU; x ^= x >> 12; return x; };
    std::vector<int8_t> A(static_cast<size_t>(m) * k), B(static_cast<size_t>(k) * n);
    for (uint32_t i = 0; i < A.size(); ++i) A[i] = static_cast<int8_t>((mix(i + 1) % 97) - 48);
    for (uint32_t i = 0; i < B.size(); ++i) B[i] = static_cast<int8_t>((mix(i + 7919) % 97) - 48);
    // True product Y = A·B (int64).
    std::vector<int64_t> Y(static_cast<size_t>(m) * n, 0);
    for (uint32_t i = 0; i < m; ++i)
        for (uint32_t t = 0; t < k; ++t)
            for (uint32_t j = 0; j < n; ++j)
                Y[i * n + j] += static_cast<int64_t>(A[i * k + t]) * static_cast<int64_t>(B[t * n + j]);

    // Split k into 3 segments (64,64,72) and slice A,B accordingly.
    const uint32_t offs[] = {0, 64, 128};
    const uint32_t lens[] = {64, 64, 72};
    std::vector<rc::FreivaldsSegmentOperand> segs;
    for (int s = 0; s < 3; ++s) {
        rc::FreivaldsSegmentOperand fo;
        fo.k_p = lens[s];
        fo.A_slice.resize(static_cast<size_t>(m) * lens[s]);
        for (uint32_t i = 0; i < m; ++i)
            for (uint32_t t = 0; t < lens[s]; ++t)
                fo.A_slice[i * lens[s] + t] = A[i * k + offs[s] + t];
        fo.B_slice.resize(static_cast<size_t>(lens[s]) * n);
        for (uint32_t t = 0; t < lens[s]; ++t)
            for (uint32_t j = 0; j < n; ++j)
                fo.B_slice[t * n + j] = B[(offs[s] + t) * n + j];
        segs.push_back(std::move(fo));
    }
    const uint256 seed = uint256::ONE;
    std::string why;
    // Completeness: the segmented sum equals Y exactly.
    BOOST_CHECK_MESSAGE(rc::FreivaldsCheckGemmSegments(segs, Y, m, n, seed, 2, &why), why);
    // Soundness: any single wrong output entry is caught.
    std::vector<int64_t> Ybad = Y;
    Ybad[0] += 1;
    BOOST_CHECK(!rc::FreivaldsCheckGemmSegments(segs, Ybad, m, n, seed, 2, &why));
    // Dropping a segment (partial contraction) no longer equals the FULL Y — the
    // exact identity fails, which is exactly why partial coverage is deterrence.
    std::vector<rc::FreivaldsSegmentOperand> partial(segs.begin(), segs.begin() + 2);
    BOOST_CHECK(!rc::FreivaldsCheckGemmSegments(partial, Y, m, n, seed, 2, &why));
    // Tampering a segment operand byte is caught against the true Y.
    auto segs_t = segs;
    segs_t[1].A_slice[0] ^= 0x40;
    BOOST_CHECK(!rc::FreivaldsCheckGemmSegments(segs_t, Y, m, n, seed, 2, &why));
}

// (h) Segment CARRIER honest verify + tamper rejection (toy dims are full-cover,
//     so the tile GEMM is verified EXACTLY and any tamper is caught).
BOOST_AUTO_TEST_CASE(frvs_segment_carrier_honest_and_tamper)
{
    Fixture f = MakeFixture(rc::MakeToyRCEpisodeParams(), 42);
    BOOST_REQUIRE(f.ok);
    rc::RCFreivaldsSampledCarrier carrier;
    std::string bwhy;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildFreivaldsSampledCarrier(f.proof, f.h, 0, f.target, carrier, &bwhy, kLambda), bwhy);
    BOOST_REQUIRE_EQUAL(carrier.sampled.size(), kLambda);
    BOOST_REQUIRE(!carrier.sampled[0].tiles.empty());
    // Toy contraction is fully covered by the sampled window.
    BOOST_CHECK(carrier.sampled[0].tiles[0].full_cover);

    std::string why;
    rc::RCFreivaldsSampledTiming tmg;
    BOOST_REQUIRE_MESSAGE(
        rc::VerifyEpisodeFreivaldsSampledCarrier(carrier, f.h, 0, f.target, &why, &tmg), why);
    BOOST_CHECK_EQUAL(tmg.n_layers_checked, kLambda);
    BOOST_CHECK_GT(tmg.n_freivalds_calls, 0u);     // one per opened tile
    BOOST_CHECK_GT(tmg.n_merkle_openings, 0u);

    {   // Tamper a tile Y output -> segment-Freivalds (full cover) OR Extract catches.
        rc::RCFreivaldsSampledCarrier c = carrier;
        c.sampled[0].tiles[0].Y[0] += 1;
        BOOST_CHECK(!rc::VerifyEpisodeFreivaldsSampledCarrier(c, f.h, 0, f.target, &why, nullptr));
    }
    {   // Tamper a contraction-segment operand byte -> exact-cover Freivalds catches.
        rc::RCFreivaldsSampledCarrier c = carrier;
        BOOST_REQUIRE(!c.sampled[0].tiles[0].segments.empty());
        c.sampled[0].tiles[0].segments[0].A_seg[0] ^= 0x40;
        BOOST_CHECK(
            !rc::VerifyEpisodeFreivaldsSampledCarrier(c, f.h, 0, f.target, &why, nullptr));
        BOOST_CHECK_MESSAGE(StartsWith(why, "v7fs:freivalds_seg"), why);
    }
    {   // Tamper extract_out -> Extract re-exec out-binding catches.
        rc::RCFreivaldsSampledCarrier c = carrier;
        c.sampled[0].tiles[0].extract_out[0] ^= 0x1;
        BOOST_CHECK(!rc::VerifyEpisodeFreivaldsSampledCarrier(c, f.h, 0, f.target, &why, nullptr));
    }
}

BOOST_AUTO_TEST_SUITE_END()
