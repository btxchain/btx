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

    {   // Corrupt a Merkle sibling.
        rc::RCFreivaldsSampledCarrier c = carrier;
        BOOST_REQUIRE(!c.sampled[0].leaf_proofs.empty());
        BOOST_REQUIRE(!c.sampled[0].leaf_proofs[0].siblings.empty());
        c.sampled[0].leaf_proofs[0].siblings[0].data()[0] ^= 0xff;
        std::string why;
        BOOST_CHECK(!rc::VerifyEpisodeFreivaldsSampledCarrier(c, f.h, 0, f.target, &why, nullptr));
        BOOST_CHECK_MESSAGE(StartsWith(why, "v7fs:tiletree"), why);
    }
    {   // Corrupt a leaf byte -> leaf hash changes -> path no longer folds to root.
        rc::RCFreivaldsSampledCarrier c = carrier;
        BOOST_REQUIRE(!c.sampled[0].leaf_bytes.empty());
        auto& lb = c.sampled[0].leaf_bytes.back();
        BOOST_REQUIRE(!lb.empty());
        lb.back() ^= 0xff;
        std::string why;
        BOOST_CHECK(!rc::VerifyEpisodeFreivaldsSampledCarrier(c, f.h, 0, f.target, &why, nullptr));
        BOOST_CHECK_MESSAGE(StartsWith(why, "v7fs:tiletree"), why);
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

BOOST_AUTO_TEST_SUITE_END()
