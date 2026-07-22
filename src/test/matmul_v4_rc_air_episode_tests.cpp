// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// COMPACT (VERIFIER-SUBLINEAR) v7 episode grounding — correctness + measure.
//
// The compact path (VerifyWinnerProofV7Compact) replaces the O(N)
// GroundEpisodeInCircuit row scan with the episode AIR constraint-quotient
// (O(Q) per shard) + the bounded direct tile-tree SHA closure. These tests
// assert the two paths AGREE on accept/reject:
//   1. honest episode → compact ACCEPTS (and the full verifier accepts);
//   2. every §9 fabricated-witness episode forgery that the row scan rejects
//      is ALSO rejected by the compact verifier — ARITHMETICALLY, at the
//      Q = 128 query points (quotient identity C(y) != Q(y)·Z_H(y)), except
//      UnrelatedLayerRoots which correctly dies at the (non-arithmetized)
//      direct tile-tree closure;
//   3. an over-degree quotient is rejected by the structural degree-bound
//      check before any query work.
// Plus the measurement the construction exists for: wall-time of the row
// scan vs the compact verify (toy dims in CI; medium behind
// BTX_RC_AIR_EPISODE_MEASURE_MEDIUM=1).
//
// HARD RULES: arbiter OFF, heights INT32_MAX, int64 reference immutable,
// VerifyWinnerProofV7 unchanged (the compact path is additive).

#include <arith_uint256.h>
#include <consensus/params.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_air_episode.h>
#include <matmul/matmul_v4_rc_air_quotient.h>
#include <matmul/matmul_v4_rc_gkr.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <cstdlib>
#include <limits>
#include <string>
#include <vector>

namespace rc = matmul::v4::rc;
namespace ae = matmul::v4::rc::air_episode;
namespace aq = matmul::v4::rc::air_quotient;
namespace gf = matmul::v4::rc::gkr_field;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_air_episode_tests, BasicTestingSetup)

namespace {

CBlockHeader MakeRCHeader(uint64_t nonce)
{
    CBlockHeader header;
    header.nVersion = 0x20000004;
    header.nTime = 1'770'000'000;
    header.nBits = 0x207fffff;
    header.nNonce64 = nonce;
    header.nNonce = static_cast<uint32_t>(nonce);
    for (int i = 0; i < 32; ++i) {
        header.hashPrevBlock.data()[i] = static_cast<unsigned char>(0x51);
        header.hashMerkleRoot.data()[i] = static_cast<unsigned char>(0xa3);
        header.seed_a.data()[i] = static_cast<unsigned char>(0x11);
        header.seed_b.data()[i] = static_cast<unsigned char>(0x22);
    }
    return header;
}

arith_uint256 MaxTarget()
{
    arith_uint256 t;
    t = ~t;
    return t;
}

bool Contains(const std::string& s, const char* needle)
{
    return s.find(needle) != std::string::npos;
}

struct HonestV7 {
    CBlockHeader header;
    rc::RCEpisodeParams params;
    rc::RCGkrProveResultV7 prove;
};

HonestV7 MakeHonestToy(uint64_t nonce)
{
    HonestV7 h;
    h.header = MakeRCHeader(nonce);
    h.params = rc::MakeToyRCEpisodeParams();
    const uint256 dig = rc::RecomputeResidentCurriculumReference(h.header, h.params, 0);
    h.header.matmul_digest = dig;
    h.prove = rc::ProveWinnerEpisodeV7(h.header, h.params, 0, MaxTarget(), dig);
    return h;
}

void ReportTimings(const char* tag, const rc::RCGkrGroundScanMeasureV7& scan,
                   const rc::RCGkrCompactTimingV7& ct, double air_prove_s)
{
    BOOST_TEST_MESSAGE("=== " << tag << " measurement ===");
    BOOST_TEST_MESSAGE("  (a) GroundEpisodeInCircuit row scan: " << scan.scan_s << " s"
                       << " (tiles=" << scan.n_tiles << " mxexpand_sha=" << scan.n_mxexpand_sha
                       << " tiletree_sha=" << scan.n_tiletree_sha << ")");
    BOOST_TEST_MESSAGE("  (b) compact verify total:            " << ct.total_s << " s"
                       << " (speedup x" << (ct.total_s > 0 ? scan.scan_s / ct.total_s : 0));
    BOOST_TEST_MESSAGE("      gates=" << ct.gates_s << " colbind=" << ct.colbind_s
                       << " fri=" << ct.fri_s << " layers=" << ct.layers_s);
    BOOST_TEST_MESSAGE("      air_preprocess=" << ct.air_preprocess_s
                       << " air_quotient=" << ct.air_quotient_s << " (shards=" << ct.air_shards
                       << " rows=" << ct.air_rows << ")");
    BOOST_TEST_MESSAGE("      chain=" << ct.chain_s << " tiletree=" << ct.tiletree_s
                       << " (n_tiletree_sha=" << ct.n_tiletree_sha << ")");
    BOOST_TEST_MESSAGE("  episode AIR prove (prover-side): " << air_prove_s << " s");
}

} // namespace

// The degree-2 factorization of the acceptance rule used by the episode AIR
// ((1−b2)·inner == 0) must agree with the degree-4 AirAcceptPoly selector on
// all 16 E2M1 codes.
BOOST_AUTO_TEST_CASE(accept_factorization_matches_accept_poly)
{
    for (uint32_t n = 0; n < 16; ++n) {
        const uint32_t b0 = n & 1u, b1 = (n >> 1) & 1u, b2 = (n >> 2) & 1u, b3 = (n >> 3) & 1u;
        const gf::Fp3 accept = aq::AirAcceptPoly<gf::Fp3>(
            gf::Fp3::FromFp(b0), gf::Fp3::FromFp(b1), gf::Fp3::FromFp(b2), gf::Fp3::FromFp(b3));
        const uint32_t inner = b3 ? (1u - b1 + b1 * b0) : b0;
        const uint32_t rejected = (1u - b2) * inner;
        // accept == 1 ⇔ (1−b2)·inner == 0 — the exact factorization.
        BOOST_CHECK_EQUAL(gf::Eq(accept, gf::Fp3::One()), rejected == 0);
        BOOST_CHECK(gf::Eq(accept, gf::Fp3::FromFp(gf::FromU64(1u - rejected))));
    }
}

// Honest episode: the compact verifier ACCEPTS, agrees with the full verifier,
// and the AIR division is exact on every shard. Also the toy measurement.
BOOST_AUTO_TEST_CASE(honest_compact_accepts_and_measures_toy)
{
    BOOST_CHECK_EQUAL(Consensus::Params{}.nMatMulRCHeight, std::numeric_limits<int32_t>::max());
    BOOST_CHECK(!rc::EnvRCGkrArbiterEnabled());

    const HonestV7 h = MakeHonestToy(42);
    BOOST_REQUIRE_MESSAGE(h.prove.timing.ok, h.prove.timing.note);

    // Full (row-scan) verifier accepts — agreement baseline.
    std::string full_why;
    BOOST_REQUIRE_MESSAGE(
        rc::VerifyWinnerProofV7(h.prove.proof, h.header, 0, MaxTarget(), &full_why), full_why);

    // Episode AIR prove: honest witness → exact division, no force needed.
    const rc::RCGkrEpisodeAirProveResultV7 air =
        rc::ProveEpisodeAirForProofV7(h.prove.proof, h.header, 0, MaxTarget());
    BOOST_REQUIRE_MESSAGE(air.ok, air.note);
    BOOST_CHECK(air.division_exact);

    // Compact verifier accepts.
    std::string why;
    rc::RCGkrCompactTimingV7 ct;
    BOOST_CHECK_MESSAGE(
        rc::VerifyWinnerProofV7Compact(h.prove.proof, air.proof, h.header, 0, MaxTarget(), &why,
                                       &ct),
        why);
    BOOST_TEST_MESSAGE("compact why: " << why);

    // (a) vs (b): the measurement the construction exists for.
    const rc::RCGkrGroundScanMeasureV7 scan =
        rc::MeasureGroundEpisodeScanV7(h.prove.proof, h.header);
    BOOST_REQUIRE_MESSAGE(scan.ok, scan.failure);
    ReportTimings("toy", scan, ct, air.prove_s);

    // The O(N) row scan is gone from the compact verifier: its residual SHA
    // work is ONLY the direct tile-tree closure (no MxExpand / sampler scan).
    BOOST_CHECK_EQUAL(ct.n_tiletree_sha, scan.n_tiletree_sha);

    // FS binding: the AIR proof does not verify under a different header seed.
    CBlockHeader other = h.header;
    other.nNonce64 ^= 0xdeadbeef;
    std::string w2;
    BOOST_CHECK(!rc::VerifyWinnerProofV7Compact(h.prove.proof, air.proof, other, 0, MaxTarget(),
                                                &w2, nullptr));
}

// §9 fabricated-witness forgeries: everything the row scan rejects, the
// compact verifier rejects too — the witness kinds ARITHMETICALLY at the
// query points, UnrelatedLayerRoots at the direct tile-tree closure.
BOOST_AUTO_TEST_CASE(section9_forgeries_rejected_by_compact)
{
    const auto base_header = MakeRCHeader(42);
    const auto params = rc::MakeToyRCEpisodeParams();
    const uint256 real_dig = rc::RecomputeResidentCurriculumReference(base_header, params, 0);
    const arith_uint256 target = MaxTarget();

    struct Case {
        rc::RCGkrIndepMaliciousKind kind;
        const char* name;
        bool expect_air_reject;   // else: tile-tree closure
        bool expect_inexact;      // AIR division must be inexact (forced commit)
    };
    const Case cases[] = {
        {rc::RCGkrIndepMaliciousKind::ArbitraryAbFactorization, "ArbitraryAbFactorization",
         true, true},
        {rc::RCGkrIndepMaliciousKind::FabricatedTraceWires, "FabricatedTraceWires", true, true},
        {rc::RCGkrIndepMaliciousKind::IdenticalFabricatedLookup, "IdenticalFabricatedLookup",
         true, true},
        {rc::RCGkrIndepMaliciousKind::FabricatedExtractIO, "FabricatedExtractIO", true, true},
        {rc::RCGkrIndepMaliciousKind::UnrelatedLayerRoots, "UnrelatedLayerRoots", false, false},
    };

    for (const Case& c : cases) {
        const auto forged =
            rc::ProveMaliciousEpisodeV7ForTest(base_header, params, 0, target, real_dig, c.kind);
        BOOST_REQUIRE_MESSAGE(forged.timing.ok,
                              std::string(c.name) + ": forgery prover failed: " +
                                  forged.timing.note);
        CBlockHeader h = base_header;
        h.matmul_digest = forged.proof.claimed_digest;

        // Row-scan baseline: the full verifier rejects (agreement).
        std::string full_why;
        BOOST_REQUIRE_MESSAGE(!rc::VerifyWinnerProofV7(forged.proof, h, 0, target, &full_why),
                              std::string(c.name) + ": full verifier ACCEPTED a forgery");

        // The forging prover must FORCE-commit: the honest AIR prover refuses
        // to commit a trace that violates a constraint.
        ae::EpisodeAirProveOptions opt;
        opt.force_commit_on_violation = true;
        const rc::RCGkrEpisodeAirProveResultV7 air =
            rc::ProveEpisodeAirForProofV7(forged.proof, h, 0, target, opt);
        BOOST_REQUIRE_MESSAGE(air.ok, std::string(c.name) + ": " + air.note);
        BOOST_CHECK_MESSAGE(air.division_exact == !c.expect_inexact,
                            std::string(c.name) + ": unexpected division_exact=" +
                                (air.division_exact ? "1" : "0"));

        std::string why;
        const bool ok =
            rc::VerifyWinnerProofV7Compact(forged.proof, air.proof, h, 0, target, &why, nullptr);
        BOOST_TEST_MESSAGE(std::string("[") + c.name + "] compact why=\"" + why + "\"");
        BOOST_CHECK_MESSAGE(!ok, std::string("SOUNDNESS BUG: compact verifier ACCEPTED ") +
                                     c.name);
        if (c.expect_air_reject) {
            // Arithmetic rejection at the Q = 128 query points.
            BOOST_CHECK_MESSAGE(Contains(why, "v7c:air:"),
                                std::string(c.name) + ": expected AIR rejection, got \"" + why +
                                    "\"");
            BOOST_CHECK_MESSAGE(Contains(why, "quotient identity"),
                                std::string(c.name) +
                                    ": expected query-point quotient-identity rejection, got \"" +
                                    why + "\"");
        } else {
            BOOST_CHECK_MESSAGE(Contains(why, "v7c:tiletree:"),
                                std::string(c.name) + ": expected tile-tree rejection, got \"" +
                                    why + "\"");
        }
    }
}

// An over-degree quotient (committed longer than the declared bound) is
// rejected by the structural degree-bound check before any query work.
BOOST_AUTO_TEST_CASE(overdegree_quotient_rejected)
{
    const HonestV7 h = MakeHonestToy(43);
    BOOST_REQUIRE_MESSAGE(h.prove.timing.ok, h.prove.timing.note);

    ae::EpisodeAirProveOptions opt;
    opt.quotient_len_override = ae::kEpisodeAirMaxShardRows + 8;  // declared bound is N−1
    const rc::RCGkrEpisodeAirProveResultV7 air =
        rc::ProveEpisodeAirForProofV7(h.prove.proof, h.header, 0, MaxTarget(), opt);
    BOOST_REQUIRE_MESSAGE(air.ok, air.note);
    BOOST_CHECK(air.division_exact);  // the trace is honest; only the bound lies

    std::string why;
    BOOST_CHECK(!rc::VerifyWinnerProofV7Compact(h.prove.proof, air.proof, h.header, 0,
                                                MaxTarget(), &why, nullptr));
    BOOST_TEST_MESSAGE("overdegree why: " << why);
    BOOST_CHECK_MESSAGE(Contains(why, "quotient degree bound mismatch"), why);
}

// Medium-dims measurement (off-CI: BTX_RC_AIR_EPISODE_MEASURE_MEDIUM=1).
BOOST_AUTO_TEST_CASE(measure_medium_dims)
{
    const char* env = std::getenv("BTX_RC_AIR_EPISODE_MEASURE_MEDIUM");
    if (env == nullptr || std::string(env) != "1") {
        BOOST_TEST_MESSAGE("measure_medium_dims skipped (BTX_RC_AIR_EPISODE_MEASURE_MEDIUM!=1)");
        return;
    }
    CBlockHeader header = MakeRCHeader(7);
    const auto params = rc::MakeMediumRCEpisodeParams();
    const uint256 dig = rc::RecomputeResidentCurriculumReference(header, params, 0);
    header.matmul_digest = dig;
    const auto prove = rc::ProveWinnerEpisodeV7(header, params, 0, MaxTarget(), dig);
    BOOST_REQUIRE_MESSAGE(prove.timing.ok, prove.timing.note);
    BOOST_TEST_MESSAGE("medium v7 prove_s=" << prove.timing.prove_s);

    const rc::RCGkrEpisodeAirProveResultV7 air =
        rc::ProveEpisodeAirForProofV7(prove.proof, header, 0, MaxTarget());
    BOOST_REQUIRE_MESSAGE(air.ok, air.note);
    BOOST_CHECK(air.division_exact);

    std::string why;
    rc::RCGkrCompactTimingV7 ct;
    BOOST_REQUIRE_MESSAGE(rc::VerifyWinnerProofV7Compact(prove.proof, air.proof, header, 0,
                                                         MaxTarget(), &why, &ct),
                          why);
    const rc::RCGkrGroundScanMeasureV7 scan = rc::MeasureGroundEpisodeScanV7(prove.proof, header);
    BOOST_REQUIRE_MESSAGE(scan.ok, scan.failure);
    ReportTimings("medium", scan, ct, air.prove_s);
}

BOOST_AUTO_TEST_SUITE_END()
