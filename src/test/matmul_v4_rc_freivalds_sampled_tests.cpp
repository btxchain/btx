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
//  (d) FS-sample determinism + commitment-binding (moving roots/digest moves the set)
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

#include <cstdint>
#include <cstdlib>
#include <limits>
#include <optional>
#include <string>
#include <vector>

namespace rc = matmul::v4::rc;

namespace matmul::v4::rc::test {
bool FreivaldsSampleCandidateAcceptedForTesting(uint64_t candidate, uint64_t bound, uint64_t& out);
}

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
    return k == rc::RCGkrLayerKind::GemmPhase1SV ||
           k == rc::RCGkrLayerKind::GemmPhase2Fwd;
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

class EnvVarGuard
{
public:
    explicit EnvVarGuard(const char* name) : m_name{name}
    {
        if (const char* v = std::getenv(name)) {
            m_old = v;
        }
    }
    ~EnvVarGuard()
    {
        if (m_old) {
            setenv(m_name, m_old->c_str(), /*overwrite=*/1);
        } else {
            unsetenv(m_name);
        }
    }
private:
    const char* m_name;
    std::optional<std::string> m_old;
};

} // namespace

// Discipline invariants: public RC activation remains height-gated; profile-2
// uses the sampled authority only once that consensus height is made finite.
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
    BOOST_CHECK_GE(tmg.n_units_total, kLambda);
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

// (d) FS-sample determinism + commitment-binding. This exercises that the sample
// coin is a deterministic function of the committed roots/digest and that moving
// either moves the sampled set (no cheap re-bias without a fresh PoW grind). It is
// NOT a proof of cryptographic unbiasability — that external audit remains OPEN.
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
    for (uint32_t s : s1) BOOST_CHECK_LT(s, 7u); // in range
    for (size_t i = 0; i < s1.size(); ++i)       // distinct
        for (size_t j = i + 1; j < s1.size(); ++j) BOOST_CHECK(s1[i] != s1[j]);

    const auto all = rc::FreivaldsSampleLayers(base, 7, 99);
    BOOST_CHECK_EQUAL(all.size(), 7u);
    for (size_t i = 0; i < all.size(); ++i) {
        BOOST_CHECK_LT(all[i], 7u);
        for (size_t j = i + 1; j < all.size(); ++j) BOOST_CHECK(all[i] != all[j]);
    }

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

BOOST_AUTO_TEST_CASE(frvs_carrier_tile_schedule_deterministic_in_range)
{
    Fixture f = MakeFixture(rc::MakeToyRCEpisodeParams(), 42);
    BOOST_REQUIRE(f.ok);

    rc::RCFreivaldsSampledCarrier c1;
    rc::RCFreivaldsSampledCarrier c2;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildFreivaldsSampledCarrier(f.proof, f.h, 0, f.target, c1, &why, kLambda), why);
    why.clear();
    BOOST_REQUIRE_MESSAGE(
        rc::BuildFreivaldsSampledCarrier(f.proof, f.h, 0, f.target, c2, &why, kLambda), why);

    BOOST_REQUIRE_EQUAL(c1.sampled.size(), c2.sampled.size());
    bool saw_tile = false;
    for (size_t li = 0; li < c1.sampled.size(); ++li) {
        const auto& a = c1.sampled[li];
        const auto& b = c2.sampled[li];
        BOOST_CHECK_EQUAL(a.layer_index, b.layer_index);
        BOOST_CHECK_EQUAL(a.round, b.round);
        BOOST_CHECK_EQUAL(static_cast<uint32_t>(a.kind), static_cast<uint32_t>(b.kind));
        BOOST_CHECK_EQUAL(a.m, b.m);
        BOOST_CHECK_EQUAL(a.n, b.n);
        BOOST_REQUIRE_EQUAL(a.tiles.size(), b.tiles.size());
        for (size_t ti = 0; ti < a.tiles.size(); ++ti) {
            const auto& ta = a.tiles[ti];
            const auto& tb = b.tiles[ti];
            saw_tile = true;
            BOOST_CHECK_EQUAL(ta.row, tb.row);
            BOOST_CHECK_EQUAL(ta.bcol, tb.bcol);
            BOOST_CHECK_LT(ta.row, a.m);
            BOOST_CHECK_LT(ta.bcol, a.n / rc::kRCMxBlockLen);
            for (size_t prev = 0; prev < ti; ++prev) {
                BOOST_CHECK(ta.row != a.tiles[prev].row || ta.bcol != a.tiles[prev].bcol);
            }
        }
    }
    BOOST_CHECK(saw_tile);
}

BOOST_AUTO_TEST_CASE(frvs_bounded_rejection_sampler_rejects_modulo_tail)
{
    const uint64_t bound = (uint64_t{1} << 63) + 1;
    const uint64_t reject_below = (uint64_t{0} - bound) % bound;
    BOOST_REQUIRE_EQUAL(reject_below, (uint64_t{1} << 63) - 1);

    uint64_t out = 0;
    BOOST_CHECK(!matmul::v4::rc::test::FreivaldsSampleCandidateAcceptedForTesting(
        reject_below - 1, bound, out));
    BOOST_CHECK(matmul::v4::rc::test::FreivaldsSampleCandidateAcceptedForTesting(
        reject_below, bound, out));
    BOOST_CHECK_EQUAL(out, reject_below);
    BOOST_CHECK(matmul::v4::rc::test::FreivaldsSampleCandidateAcceptedForTesting(
        std::numeric_limits<uint64_t>::max(), bound, out));
    BOOST_CHECK_EQUAL(out, (uint64_t{1} << 63) - 2);
}

// (e) SUBLINEARITY: touches exactly lambda layers, flat as total layers grow.
BOOST_AUTO_TEST_CASE(frvs_sublinearity_flat_in_layers)
{
    Fixture fs = MakeFixture(rc::MakeToyRCEpisodeParams(), 42); // 8 layers, 7 sampleable
    rc::RCEpisodeParams big = rc::MakeToyRCEpisodeParams();
    big.L_lyr = 8; // 18 layers, 9 sampleable under fused FFN
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
    rc::RCEpisodeParams params = rc::MakeToyRCEpisodeParams();
    params.L_lyr = 8; // enough streamed units to leave at least one unsampled layer
    Fixture f = MakeFixture(params, 42);
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
// FreivaldsCheckGemmSegments PRIMITIVE (frozen Fable, matmul_v4_rc_freivalds.h) +
// the v3 ANCHORED per-tile CARRIER (bounded per-layer relay, datacenter relay-
// ceiling fit) in matmul_v4_rc_freivalds_sampled.{h,cpp}. NOTE: the carrier itself
// no longer runs segment-Freivalds — it exact-recomputes each opened tile from
// anchored operands (v3). The segments primitive below is still exercised on its
// own; it is not the carrier's verification path.
// ===========================================================================

// (g) FreivaldsCheckGemmSegments primitive (standalone; NOT the carrier path):
//     completeness EXACT over the segmented contraction; a wrong claim caught
//     (soundness ≤ 2^(−63·reps)); the segment partials compose (Σ_p A_p·B_p == Y
//     under one projection).
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

// (h) Anchored CARRIER honest verify + tamper rejection. Carrier v3 no longer
//     relays Y/segments; it opens the committed extract_out tile plus the
//     anchored A-row, and the verifier recomputes H/Y from PRF weights.
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

    std::string why;
    rc::RCFreivaldsSampledTiming tmg;
    BOOST_REQUIRE_MESSAGE(
        rc::VerifyEpisodeFreivaldsSampledCarrier(carrier, f.h, 0, f.target, &why, &tmg), why);
    BOOST_CHECK_EQUAL(tmg.n_layers_checked, kLambda);
    BOOST_CHECK_GT(tmg.n_freivalds_calls, 0u);     // one anchored recompute per opened tile
    BOOST_CHECK_GT(tmg.n_merkle_openings, 0u);

    {   // Tamper the relayed output tile: anchored recompute or committed-leaf binding catches.
        rc::RCFreivaldsSampledCarrier c = carrier;
        BOOST_REQUIRE(!c.sampled[0].tiles[0].extract_out.empty());
        c.sampled[0].tiles[0].extract_out[0] ^= 0x1;
        BOOST_CHECK(!rc::VerifyEpisodeFreivaldsSampledCarrier(c, f.h, 0, f.target, &why, nullptr));
    }
    {   // Tamper exact accumulator evidence while leaving committed int8 bytes intact.
        rc::RCFreivaldsSampledCarrier c = carrier;
        c.sampled[0].tiles[0].acc_tag.data()[0] ^= 0x1;
        BOOST_CHECK(!rc::VerifyEpisodeFreivaldsSampledCarrier(c, f.h, 0, f.target, &why, nullptr));
        BOOST_CHECK_EQUAL(why, "v7fs:acc_tag");
    }
    {   // Tamper the anchored A-row leaf when a non-PRF source row is sampled.
        rc::RCFreivaldsSampledCarrier c = carrier;
        bool tampered = false;
        for (auto& layer : c.sampled) {
            for (auto& tile : layer.tiles) {
                if (!tile.a_prf_regen && !tile.a_row_leaf.empty()) {
                    tile.a_row_leaf[0] ^= 0x1;
                    tampered = true;
                    break;
                }
            }
            if (tampered) break;
        }
        BOOST_REQUIRE(tampered);
        BOOST_CHECK(!rc::VerifyEpisodeFreivaldsSampledCarrier(c, f.h, 0, f.target, &why, nullptr));
    }
}

BOOST_AUTO_TEST_CASE(frvs_carrier_parallel_verdict_and_reason_are_thread_invariant)
{
    EnvVarGuard guard{"BTX_RC_CARRIER_VERIFY_THREADS"};
    Fixture f = MakeFixture(rc::MakeToyRCEpisodeParams(), 42);
    BOOST_REQUIRE(f.ok);
    rc::RCFreivaldsSampledCarrier carrier;
    std::string bwhy;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildFreivaldsSampledCarrier(f.proof, f.h, 0, f.target, carrier, &bwhy, kLambda), bwhy);

    setenv("BTX_RC_CARRIER_VERIFY_THREADS", "1", /*overwrite=*/1);
    std::string why1;
    rc::RCFreivaldsSampledTiming t1;
    const bool ok1 = rc::VerifyEpisodeFreivaldsSampledCarrier(carrier, f.h, 0, f.target, &why1, &t1);

    setenv("BTX_RC_CARRIER_VERIFY_THREADS", "8", /*overwrite=*/1);
    std::string why8;
    rc::RCFreivaldsSampledTiming t8;
    const bool ok8 = rc::VerifyEpisodeFreivaldsSampledCarrier(carrier, f.h, 0, f.target, &why8, &t8);

    BOOST_CHECK(ok1);
    BOOST_CHECK_EQUAL(ok1, ok8);
    BOOST_CHECK_EQUAL(why1, why8);
    BOOST_CHECK_EQUAL(t1.verify_threads, 1u);
    BOOST_CHECK_GT(t8.verify_threads, 1u);

    rc::RCFreivaldsSampledCarrier bad = carrier;
    BOOST_REQUIRE(!bad.sampled.empty());
    BOOST_REQUIRE(!bad.sampled[0].tiles.empty());
    BOOST_REQUIRE(!bad.sampled[0].tiles[0].extract_out.empty());
    bad.sampled[0].tiles[0].extract_out[0] ^= 0x01;

    setenv("BTX_RC_CARRIER_VERIFY_THREADS", "1", /*overwrite=*/1);
    std::string bad_why1;
    rc::RCFreivaldsSampledTiming bad_t1;
    const bool bad_ok1 =
        rc::VerifyEpisodeFreivaldsSampledCarrier(bad, f.h, 0, f.target, &bad_why1, &bad_t1);

    setenv("BTX_RC_CARRIER_VERIFY_THREADS", "8", /*overwrite=*/1);
    std::string bad_why8;
    rc::RCFreivaldsSampledTiming bad_t8;
    const bool bad_ok8 =
        rc::VerifyEpisodeFreivaldsSampledCarrier(bad, f.h, 0, f.target, &bad_why8, &bad_t8);

    BOOST_CHECK(!bad_ok1);
    BOOST_CHECK_EQUAL(bad_ok1, bad_ok8);
    BOOST_CHECK_EQUAL(bad_why1, bad_why8);
    BOOST_CHECK_EQUAL(bad_why1, "v7fs:recompute_mismatch");
}

// (i) #101 REGRESSION LOCK — the profile-2 carrier verifier ENFORCES the fused-FFN
//     matmul, targeted at the FFN layer specifically (the other tamper tests hit
//     sampled[0], which may be an attention/SV layer). GemmPhase2Fwd is the streamed
//     DOWN projection X[l+1]=Extract(H·W_down+X[l]); H=Extract(X·W_up) is the INTERNAL
//     UP projection the verifier recomputes on the fly when a Fwd tile is checked. So
//     when a Fwd layer is sampled, the anchored recompute exercises BOTH FFN matmuls
//     (W_up internal + W_down streamed) and the result is bound to the committed output
//     opened against round_roots. A verifier that merely trusted the committed FFN
//     output (the #101 break) would accept a forged Fwd tile; this asserts it does not.
BOOST_AUTO_TEST_CASE(frvs_ffn_matmul_is_enforced_101)
{
    Fixture f = MakeFixture(rc::MakeToyRCEpisodeParams(), 101);
    BOOST_REQUIRE(f.ok);

    // λ ≥ the sampleable-layer count ⇒ FreivaldsSampleLayers (without replacement)
    // covers every layer, so every fused-FFN DOWN layer is in the sample set.
    constexpr uint32_t kFfnLambda = 64;
    rc::RCFreivaldsSampledCarrier carrier;
    std::string bwhy;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildFreivaldsSampledCarrier(f.proof, f.h, 0, f.target, carrier, &bwhy, kFfnLambda), bwhy);

    // Non-vacuous: the honest carrier actually SAMPLES a fused-FFN DOWN layer with a
    // committed output tile, so the FFN matmul path is genuinely exercised. This
    // directly refutes the premise of #101 ("verifier does not enforce FFN matmul").
    int ffn_idx = -1;
    for (size_t i = 0; i < carrier.sampled.size(); ++i) {
        if (carrier.sampled[i].kind == rc::RCGkrLayerKind::GemmPhase2Fwd &&
            !carrier.sampled[i].tiles.empty() &&
            !carrier.sampled[i].tiles[0].extract_out.empty()) {
            ffn_idx = static_cast<int>(i);
            break;
        }
    }
    BOOST_REQUIRE_MESSAGE(ffn_idx >= 0, "toy episode must sample a fused-FFN DOWN layer");

    // Honest carrier verifies, and the sampled FFN layer is counted as checked.
    std::string why;
    rc::RCFreivaldsSampledTiming tmg;
    BOOST_REQUIRE_MESSAGE(
        rc::VerifyEpisodeFreivaldsSampledCarrier(carrier, f.h, 0, f.target, &why, &tmg), why);
    BOOST_CHECK_GT(tmg.n_freivalds_calls, 0u);

    // Forge the fused-FFN layer's committed output. The verifier recomputes
    // H=Extract(X·W_up) from the anchored input + PRF W_up, then Extract(H·W_down+X)
    // from PRF W_down, and binds the result to the committed tile — so the forgery is
    // caught by the FFN recompute (v7fs:recompute_mismatch), NOT merely the leaf
    // opening. A miner cannot substitute a self-consistent fake FFN output.
    rc::RCFreivaldsSampledCarrier forged = carrier;
    forged.sampled[ffn_idx].tiles[0].extract_out[0] ^= 0x1;
    std::string bad_why;
    BOOST_CHECK(
        !rc::VerifyEpisodeFreivaldsSampledCarrier(forged, f.h, 0, f.target, &bad_why, nullptr));
    BOOST_CHECK_EQUAL(bad_why, "v7fs:recompute_mismatch");
}

// ===========================================================================
// R-01 T-BIND: fixed-length Merkle openings. The verifier derives the canonical
// tile-tree geometry (depth + real-leaf count) from consensus-pinned episode
// params and MUST reject any opening that does not match it — closing the shallow-
// tree / high-bit-alias / padding-leaf aliases the bare `cur == root` fold admits.
// ===========================================================================

// (j) Geometry-bound VerifyMerkleProof primitive: each adversarial opening shape
//     REJECTS; an honest full-depth opening ACCEPTS. Also demonstrates the exact
//     bare-fold vulnerabilities T-BIND closes (padding leaf + high-bit alias).
BOOST_AUTO_TEST_CASE(frvs_tbind_merkle_geometry)
{
    const uint32_t t_leaf = 64;
    const size_t logical = 5 * t_leaf + 13;  // 6 real leaves (last one partial)
    std::vector<int8_t> stream(logical);
    for (size_t i = 0; i < logical; ++i) stream[i] = static_cast<int8_t>((i * 37 + 11) & 0x7f);

    const std::vector<uint256> leaves = rc::BuildTileTreeLeaves(stream, t_leaf);
    const uint256 root = rc::BuildTileTreeRoot(stream, t_leaf);
    const uint32_t real_leaves = static_cast<uint32_t>((logical + t_leaf - 1) / t_leaf);  // 6
    uint32_t depth = 0;
    while ((size_t{1} << depth) < leaves.size()) ++depth;  // log2(8) = 3
    BOOST_REQUIRE_EQUAL(leaves.size(), 8u);   // next_pow2(6)
    BOOST_REQUIRE_EQUAL(real_leaves, 6u);
    BOOST_REQUIRE_EQUAL(depth, 3u);

    const uint32_t idx = 2;  // a real leaf
    const rc::RCMerkleProof proof = rc::OpenMerkleProof(leaves, idx);
    const uint256& leaf = leaves[idx];

    // Honest full-depth opening ACCEPTS (bare fold AND geometry-checked).
    BOOST_CHECK(rc::VerifyMerkleProof(leaf, idx, proof, root));
    BOOST_CHECK(rc::VerifyMerkleProof(leaf, idx, proof, root, depth, real_leaves));

    // (1) EMPTY sibling path -> depth mismatch -> REJECT.
    BOOST_CHECK(!rc::VerifyMerkleProof(leaf, idx, rc::RCMerkleProof{}, root, depth, real_leaves));
    // (2) TRUNCATED path (a shallow tree presented for the full vector) -> REJECT.
    {
        rc::RCMerkleProof p = proof;
        p.siblings.pop_back();
        BOOST_CHECK(!rc::VerifyMerkleProof(leaf, idx, p, root, depth, real_leaves));
    }
    // (3) EXTENDED path -> REJECT.
    {
        rc::RCMerkleProof p = proof;
        p.siblings.push_back(uint256::ONE);
        BOOST_CHECK(!rc::VerifyMerkleProof(leaf, idx, p, root, depth, real_leaves));
    }
    // (4) HIGH-BIT ALIAS: index idx and idx+2^depth share the low `depth` bits, so
    //     the honest siblings fold identically. The bare fold now consumes the high
    //     bit (idx != 0) AND the geometry range check both REJECT the alias.
    const uint32_t alias = idx + (1u << depth);  // 2 + 8 = 10
    BOOST_CHECK(!rc::VerifyMerkleProof(leaf, alias, proof, root));                       // idx!=0 after fold
    BOOST_CHECK(!rc::VerifyMerkleProof(leaf, alias, proof, root, depth, real_leaves));   // + range
    // (5) PADDING LEAF (index in [real_leaves, padded)) folds to root, so the bare
    //     fold ACCEPTS it (the vulnerability); T-BIND range check REJECTS it.
    const uint32_t pad_idx = 7;  // in [6, 8)
    const rc::RCMerkleProof pad_proof = rc::OpenMerkleProof(leaves, pad_idx);
    BOOST_CHECK(rc::VerifyMerkleProof(leaves[pad_idx], pad_idx, pad_proof, root));  // bare fold accepts
    BOOST_CHECK(!rc::VerifyMerkleProof(leaves[pad_idx], pad_idx, pad_proof, root, depth, real_leaves));
    // (6) index >= real_leaves at the real depth (out of range) -> REJECT.
    BOOST_CHECK(!rc::VerifyMerkleProof(leaf, real_leaves, proof, root, depth, real_leaves));

    // (7) WRONG length / cross-shape: a genuinely SHALLOW tree over a shorter stream
    //     folds to its own shallow root with fewer siblings; it verifies on its OWN
    //     root but is REJECTED when presented under the full vector's geometry.
    std::vector<int8_t> shortstream(2 * t_leaf);  // 2 leaves -> depth 1
    for (size_t i = 0; i < shortstream.size(); ++i) shortstream[i] = static_cast<int8_t>(i & 0x7f);
    const std::vector<uint256> sleaves = rc::BuildTileTreeLeaves(shortstream, t_leaf);
    const uint256 sroot = rc::BuildTileTreeRoot(shortstream, t_leaf);
    const rc::RCMerkleProof sproof = rc::OpenMerkleProof(sleaves, 0);
    BOOST_CHECK(rc::VerifyMerkleProof(sleaves[0], 0, sproof, sroot));                    // honest on own root
    BOOST_CHECK(!rc::VerifyMerkleProof(sleaves[0], 0, sproof, sroot, depth, real_leaves));  // wrong geometry
}

// (k) T-BIND wired into the carrier verifier: geometry is derived from the carried
//     (consensus-pinned) episode, so a wrong-DEPTH sibling path on a carried opening
//     REJECTS with a tile-tree depth reason. An honest carrier still ACCEPTS.
BOOST_AUTO_TEST_CASE(frvs_tbind_carrier_depth_rejects)
{
    Fixture f = MakeFixture(rc::MakeToyRCEpisodeParams(), 42);
    BOOST_REQUIRE(f.ok);
    rc::RCFreivaldsSampledCarrier carrier;
    std::string bwhy;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildFreivaldsSampledCarrier(f.proof, f.h, 0, f.target, carrier, &bwhy, kLambda), bwhy);
    BOOST_REQUIRE(!carrier.sampled.empty());
    BOOST_REQUIRE(!carrier.sampled[0].tiles.empty());
    BOOST_REQUIRE(!carrier.sampled[0].tiles[0].leaf_proofs.empty());
    BOOST_REQUIRE(!carrier.sampled[0].tiles[0].leaf_proofs[0].siblings.empty());

    // Honest carrier ACCEPTS (unchanged behavior — no honest opening is rejected).
    {
        std::string why;
        BOOST_REQUIRE_MESSAGE(
            rc::VerifyEpisodeFreivaldsSampledCarrier(carrier, f.h, 0, f.target, &why, nullptr), why);
    }
    auto expect_depth_reject = [&](const rc::RCFreivaldsSampledCarrier& c) {
        std::string why;
        BOOST_CHECK(!rc::VerifyEpisodeFreivaldsSampledCarrier(c, f.h, 0, f.target, &why, nullptr));
        BOOST_CHECK_MESSAGE(StartsWith(why, "v7fs:tiletree:depth"), why);
    };
    {   // TRUNCATED (shallow) extract_out path.
        rc::RCFreivaldsSampledCarrier c = carrier;
        c.sampled[0].tiles[0].leaf_proofs[0].siblings.pop_back();
        expect_depth_reject(c);
    }
    {   // EXTENDED extract_out path.
        rc::RCFreivaldsSampledCarrier c = carrier;
        c.sampled[0].tiles[0].leaf_proofs[0].siblings.push_back(uint256::ONE);
        expect_depth_reject(c);
    }
    {   // EMPTIED extract_out path.
        rc::RCFreivaldsSampledCarrier c = carrier;
        c.sampled[0].tiles[0].leaf_proofs[0].siblings.clear();
        expect_depth_reject(c);
    }
    {   // A committed A-row opening (if any sampled DOWN tile carries one) with a
        // wrong-depth path also REJECTS on the tile-tree depth bind.
        rc::RCFreivaldsSampledCarrier c = carrier;
        bool tampered = false;
        for (auto& layer : c.sampled) {
            for (auto& tile : layer.tiles) {
                if (!tile.a_prf_regen && !tile.a_row_proof.siblings.empty()) {
                    tile.a_row_proof.siblings.pop_back();
                    tampered = true;
                    break;
                }
            }
            if (tampered) break;
        }
        if (tampered) expect_depth_reject(c);
    }
}

BOOST_AUTO_TEST_SUITE_END()
