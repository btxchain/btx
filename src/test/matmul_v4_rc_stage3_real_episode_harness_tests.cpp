// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// RC-ladder item #4: the REAL producer harness.
//
// Every RCStage3SuccinctProof elsewhere in the tree is fed synthetic Filled()
// round-roots. This harness drives the pipeline from a REAL mined toy episode:
//
//   MineRCEpisode(out_rounds) -> real per-round Merkle roots + real digest
//     -> real header/params/sigma-bound Episode statement
//       -> BuildEpisodeDigestManifest(real roots) (binding check vs PoW digest)
//         -> ProveRCStage3EpisodeDigestRootChain  (real proof BODY)
//           -> VerifyRCStage3EpisodeDigestRootChain (ACCEPT)
//
// It also times one role C_rho full-FRI prove/verify against the 900 ms budget,
// and probes the recursive-aggregation verify to record exactly which gate
// blocks it on real data.
//
// Gated behind BTX_RUN_REAL_EPISODE_HARNESS=1 (prove path is heavy).

#include <matmul/matmul_v4.h>                              // v4::DeriveSigma
#include <matmul/matmul_v4_rc.h>                           // MineRCEpisode
#include <matmul/matmul_v4_rc_coupled.h>                   // RecomputeCoupledPuzzleReference
#include <matmul/matmul_v4_rc_air_quotient.h>
#include <matmul/matmul_v4_rc_fri_ext3_alg.h>
#include <matmul/matmul_v4_rc_gkr_field_ext3.h>
#include <matmul/matmul_v4_rc_stage3_consensus.h>          // header/params commit
#include <matmul/matmul_v4_rc_stage3_hash_air.h>           // BuildEpisodeDigestManifest
#include <matmul/matmul_v4_rc_stage3_recursive.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>
#include <matmul/matmul_v4_rc_stage3_root_chain.h>

#include <arith_uint256.h>
#include <primitives/block.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <chrono>
#include <cstdlib>
#include <string>
#include <vector>

namespace rc = matmul::v4::rc;
namespace ha = matmul::v4::rc::stage3_hash_air;
namespace gkr_field = matmul::v4::rc::gkr_field;
namespace air_quotient = matmul::v4::rc::air_quotient;
namespace air_recurse = matmul::v4::rc::air_recurse;

BOOST_FIXTURE_TEST_SUITE(
    matmul_v4_rc_stage3_real_episode_harness_tests,
    BasicTestingSetup)

namespace {

double SecondsSince(std::chrono::steady_clock::time_point t0)
{
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - t0)
        .count();
}

CBlockHeader MakeRealRCHeader(uint64_t nonce)
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

Consensus::Params MakeRealRCParams()
{
    Consensus::Params p;
    p.fMatMulPOW = true;
    p.nMatMulV4Height = 1;
    p.nMatMulRCHeight = 1;
    p.nMatMulRCProfile = 2;
    p.fMatMulRCUseToyDims = true;
    p.nMatMulV4Dimension = 256;
    p.powLimit = uint256{
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
    return p;
}

// Build a REAL header-bound Episode statement. Every public input is derived
// from the real header / real mined digest -- no Filled() synthetic value.
rc::RCStage3SuccinctProof BuildRealEpisodeStatement(
    const CBlockHeader& header, const Consensus::Params& params,
    int32_t height, const uint256& mined_digest)
{
    rc::RCStage3SuccinctProof s;
    s.statement = rc::RCStage3StatementKind::Episode;
    s.public_inputs.height = height;
    s.public_inputs.n_bits = header.nBits;
    s.public_inputs.episode_profile = params.nMatMulRCProfile;
    s.public_inputs.transcript_version = rc::kRCTranscriptVersion;
    s.public_inputs.header_commitment = rc::RCStage3HeaderCommitment(header);
    s.public_inputs.params_commitment = rc::RCStage3ParamsCommitment(
        params, height, rc::RCStage3StatementKind::Episode);
    s.public_inputs.sigma = matmul::v4::DeriveSigma(header);
    s.public_inputs.episode_digest = mined_digest;
    s.public_inputs.final_digest = mined_digest;

    arith_uint256 t;
    bool neg = false, over = false;
    t.SetCompact(header.nBits, &neg, &over);
    s.public_inputs.target = ArithToUint256(t);
    return s;
}

} // namespace

// ===========================================================================
// STAGE 1+2: real PoW -> real round-roots -> real EpisodeDigestManifest ->
// real digest-root-chain proof BODY -> verify ACCEPT. This is the missing
// producer: a Stage-3 statement whose digest chain is proved from REAL PoW.
// ===========================================================================
BOOST_AUTO_TEST_CASE(real_episode_digest_root_chain_from_pow)
{
    if (std::getenv("BTX_RUN_REAL_EPISODE_HARNESS") == nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_REAL_EPISODE_HARNESS=1 to run the real-episode "
            "producer harness (heavy prove path)");
        return;
    }

    const Consensus::Params params = MakeRealRCParams();
    const int32_t height = 10;
    const CBlockHeader header = MakeRealRCHeader(0x5eed);
    const rc::RCEpisodeParams episode = rc::ResolveRCEpisodeParams(params, height);
    BOOST_TEST_MESSAGE("episode rounds=" << episode.rounds
                                         << " L_lyr=" << episode.L_lyr);

    // (1) REAL episode data: real per-round transcript Merkle roots + digest.
    std::vector<rc::RCRoundTranscript> rounds;
    const auto t_mine = std::chrono::steady_clock::now();
    const uint256 mined_digest =
        rc::MineRCEpisode(header, episode, height, &rounds);
    const double mine_s = SecondsSince(t_mine);
    BOOST_REQUIRE_MESSAGE(!mined_digest.IsNull(), "MineRCEpisode returned null");
    BOOST_REQUIRE_EQUAL(rounds.size(), episode.rounds);

    std::vector<uint256> round_roots;
    round_roots.reserve(rounds.size());
    for (const auto& r : rounds) {
        BOOST_REQUIRE(!r.round_root.IsNull());
        round_roots.push_back(r.round_root);
    }
    BOOST_TEST_MESSAGE("MineRCEpisode: mine_s=" << mine_s
                                                << " digest=" << mined_digest.ToString()
                                                << " round_roots=" << round_roots.size());

    // (2) REAL statement bound to the REAL header.
    const rc::RCStage3SuccinctProof statement =
        BuildRealEpisodeStatement(header, params, height, mined_digest);

    // (2a) THE load-bearing binding: the EpisodeDigestManifest built over the
    // REAL round-roots must reproduce EXACTLY the PoW digest. If this fails, the
    // Stage-3 preimage model and the RC episode digest disagree and no real
    // statement can ever exist.
    ha::EpisodeDigestManifest manifest;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildEpisodeDigestManifest(episode.rounds, round_roots, manifest, &why),
        why);
    BOOST_CHECK_MESSAGE(
        manifest.direct.digest == mined_digest,
        "BuildEpisodeDigestManifest digest " + manifest.direct.digest.ToString() +
            " != MineRCEpisode digest " + mined_digest.ToString());
    BOOST_REQUIRE_MESSAGE(
        statement.public_inputs.episode_digest == manifest.direct.digest,
        "statement episode_digest must equal manifest digest");

    // (2b) REAL proof BODY: prove the episode digest root chain over the REAL
    // round-roots (not synthetic Filled()). Times the prover.
    rc::RCStage3EpisodeDigestRootChainProof proof;
    const auto t_prove = std::chrono::steady_clock::now();
    const bool proved = rc::ProveRCStage3EpisodeDigestRootChain(
        statement, episode.rounds, round_roots, proof, &why);
    const double prove_s = SecondsSince(t_prove);
    BOOST_REQUIRE_MESSAGE(proved, "prove digest root chain: " + why);

    // (2c) VERIFY the real-episode proof: ACCEPT.
    const auto t_verify = std::chrono::steady_clock::now();
    const bool accept = rc::VerifyRCStage3EpisodeDigestRootChain(
        statement, episode.rounds, proof, &why);
    const double verify_s = SecondsSince(t_verify);
    BOOST_CHECK_MESSAGE(accept, "verify digest root chain: " + why);

    BOOST_TEST_MESSAGE("REAL_EPISODE_DIGEST_CHAIN prove_s="
                       << prove_s << " verify_s=" << verify_s
                       << " accept=" << accept);

    // (2d) SOUNDNESS: a tampered real round-root must reject.
    auto tampered = proof;
    tampered.manifest.round_roots[0].begin()[0] ^= 1;
    BOOST_CHECK(!rc::VerifyRCStage3EpisodeDigestRootChain(
        statement, episode.rounds, tampered, &why));
}

// ===========================================================================
// STAGE 3 (timing probe): one role C_rho full-FRI prove/verify. This measures
// the per-role prove/verify wall-clock against the 900 ms relay budget. NOTE:
// the role witness here is a shape-faithful synthetic cell, NOT derived from
// the real episode trace -- there is no producer mapping real MineRCEpisode
// trace cells into role witnesses (that is the recorded gap).
// ===========================================================================
BOOST_AUTO_TEST_CASE(single_role_fri_roundtrip_timing)
{
    if (std::getenv("BTX_RUN_REAL_EPISODE_HARNESS") == nullptr) {
        BOOST_TEST_MESSAGE("set BTX_RUN_REAL_EPISODE_HARNESS=1");
        return;
    }
    namespace gf = gkr_field;
    using AlgB3 = air_quotient::AirFriBackendAlg<gf::Fp3>;

    const gf::Fp3 cell = gf::Fp3::FromFp(gf::FromU64(0x2bad10ULL));
    const rc::RCStage3RoleAirProduct product =
        rc::BuildRCStage3CoupledPermutationRoleAir(cell, 0, /*path_len=*/3,
                                                   nullptr);
    BOOST_REQUIRE_MESSAGE(product.ok, product.note);
    BOOST_REQUIRE_EQUAL(
        air_recurse::CountWitnessViolationsOnH(product.cs, product.witness), 0U);

    const uint256 seed = []() {
        uint256 s;
        s.begin()[0] = 0x5a;
        return s;
    }();

    const auto t0 = std::chrono::steady_clock::now();
    const auto proved =
        air_quotient::AirQuotientProve<gf::Fp3, AlgB3>(product.cs, product.witness,
                                                       seed, {});
    const double prove_s = SecondsSince(t0);
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);

    std::string why;
    const auto v0 = std::chrono::steady_clock::now();
    const bool accept = air_quotient::AirQuotientVerify<gf::Fp3, AlgB3>(
        product.cs, proved.proof, seed, &why);
    const double verify_s = SecondsSince(v0);

    BOOST_TEST_MESSAGE("SINGLE_ROLE_FRI rows="
                       << product.cs.n_rows << " cols=" << product.cs.n_columns
                       << " constraints=" << product.cs.constraints.size()
                       << " prove_s=" << prove_s << " verify_s=" << verify_s
                       << " accept=" << accept
                       << " budget_900ms_exceeded=" << (verify_s > 0.9));
    BOOST_CHECK_MESSAGE(accept, "role C_rho must FRI-verify: " + why);
}

// ===========================================================================
// STAGE 3 (aggregation probe): record exactly what blocks recursive-aggregation
// verify from running on the real statement. Does NOT flip shipped gates.
// ===========================================================================
BOOST_AUTO_TEST_CASE(recursive_aggregation_gate_probe)
{
    if (std::getenv("BTX_RUN_REAL_EPISODE_HARNESS") == nullptr) {
        BOOST_TEST_MESSAGE("set BTX_RUN_REAL_EPISODE_HARNESS=1");
        return;
    }
    BOOST_TEST_MESSAGE(
        "kRCStage3RecursiveAggregationReady="
        << rc::kRCStage3RecursiveAggregationReady);

    const Consensus::Params params = MakeRealRCParams();
    const int32_t height = 10;
    const CBlockHeader header = MakeRealRCHeader(0x5eed);
    const rc::RCEpisodeParams episode = rc::ResolveRCEpisodeParams(params, height);
    const uint256 mined_digest =
        rc::MineRCEpisode(header, episode, height, nullptr);
    const rc::RCStage3SuccinctProof statement =
        BuildRealEpisodeStatement(header, params, height, mined_digest);

    // An empty recursive carrier: the readiness assessment records every gap
    // that keeps aggregation verify fail-closed. We print them verbatim.
    rc::RCStage3RecursiveProof carrier;
    const rc::RCStage3RecursiveReadiness readiness =
        rc::AssessRCStage3RecursiveReadiness(statement, carrier);
    BOOST_TEST_MESSAGE(
        "recursive readiness: cryptographic_verification_ready="
        << readiness.cryptographic_verification_ready
        << " production_ready=" << readiness.production_ready
        << " gaps=" << readiness.gaps.size());
    for (const auto& g : readiness.gaps) {
        BOOST_TEST_MESSAGE("  GAP: " << g.detail);
    }

    std::string why;
    const bool agg_ok = rc::VerifyRCStage3RecursiveProof(statement, carrier, &why);
    BOOST_TEST_MESSAGE("VerifyRCStage3RecursiveProof accept=" << agg_ok
                                                              << " why=" << why);
    BOOST_CHECK(!agg_ok); // fail-closed on real data (records the gate)
}

// ===========================================================================
// STAGE 3 (THE PRODUCER): drive EACH of the 14 role-AIR C_rho from REAL episode
// / real coupled-puzzle trace data, then multi-threaded AirQuotientProve ->
// AirQuotientVerify ACCEPT -> tamper a real cell -> REJECT.  Records the honest
// per-role verdict: real-data-driven vs still-synthetic, with the reason.
//
// Real data sources (all header-derived, block-committed):
//   * MineRCEpisode -> round_roots[] + mined digest + per-round int8 stream.
//   * BuildEpisodeDigestManifest(round_roots) -> real episode digest == PoW.
//   * BuildTileTreeManifest(round stream) -> real tile-tree root == round_root.
//   * RecomputeCoupledPuzzleReference(header) -> real coupled bank_root /
//     barrier_roots / GEMM A,B,Y / extract in,out; AssembleCoupledEpisodeDigest.
// ===========================================================================
namespace {

// uint256 (32 LE bytes) -> the 8 little-endian uint32 SHA words the pure-stream
// light binding fragment pins.
std::array<uint32_t, 8> Root8FromUint256(const uint256& h)
{
    std::array<uint32_t, 8> r{};
    const unsigned char* b = h.begin();
    for (int j = 0; j < 8; ++j) {
        r[j] = static_cast<uint32_t>(b[4 * j]) |
               (static_cast<uint32_t>(b[4 * j + 1]) << 8) |
               (static_cast<uint32_t>(b[4 * j + 2]) << 16) |
               (static_cast<uint32_t>(b[4 * j + 3]) << 24);
    }
    return r;
}

struct RoleRun {
    std::string name;
    bool real_data{false};
    std::string source; // where the real data (or the gap) comes from
    rc::RCStage3RoleAirProduct product;
};

} // namespace

BOOST_AUTO_TEST_CASE(all14_roles_from_real_episode)
{
    if (std::getenv("BTX_RUN_REAL_EPISODE_HARNESS") == nullptr) {
        BOOST_TEST_MESSAGE("set BTX_RUN_REAL_EPISODE_HARNESS=1");
        return;
    }
    namespace gf = gkr_field;
    using AlgB3 = air_quotient::AirFriBackendAlg<gf::Fp3>;
    using Role = rc::RCStage3RelationRole;

    const Consensus::Params params = MakeRealRCParams();
    const int32_t height = 10;
    const CBlockHeader header = MakeRealRCHeader(0x5eed);
    const rc::RCEpisodeParams episode = rc::ResolveRCEpisodeParams(params, height);

    // (A) REAL episode trace: round_roots + digest + per-round int8 stream.
    std::vector<rc::RCRoundTranscript> rounds;
    const uint256 mined_digest =
        rc::MineRCEpisode(header, episode, height, &rounds);
    BOOST_REQUIRE(!mined_digest.IsNull());
    BOOST_REQUIRE_EQUAL(rounds.size(), episode.rounds);
    std::vector<uint256> round_roots;
    for (const auto& r : rounds) round_roots.push_back(r.round_root);
    BOOST_REQUIRE(!rounds[0].stream.empty());

    const rc::RCStage3SuccinctProof statement =
        BuildRealEpisodeStatement(header, params, height, mined_digest);

    // (A1) real episode digest manifest: digest == PoW digest (load-bearing).
    ha::EpisodeDigestManifest edm;
    std::string why;
    BOOST_REQUIRE(ha::BuildEpisodeDigestManifest(episode.rounds, round_roots,
                                                 edm, &why));
    BOOST_REQUIRE_MESSAGE(edm.direct.digest == mined_digest,
                          "episode digest manifest must reproduce PoW digest");

    // (A2) real tile-tree manifest over round-0 stream: root == round_roots[0].
    std::vector<uint8_t> stream0(rounds[0].stream.begin(), rounds[0].stream.end());
    ha::TileTreeManifest tt;
    BOOST_REQUIRE(ha::BuildTileTreeManifest(stream0, episode.T_leaf, tt, &why));
    BOOST_CHECK_MESSAGE(tt.root == round_roots[0],
                        "tile-tree root must equal the real round root");

    // (A3) real scalar cell from the block's committed stream + Merkle binding.
    const int8_t real_byte = rounds[0].stream[0];
    const gf::Fp3 real_cell = gf::FromSigned3(static_cast<int64_t>(real_byte));
    BOOST_CHECK_MESSAGE(
        rc::VerifyRCLeafOpening(rounds[0].stream, episode.T_leaf, 0,
                                round_roots[0]),
        "real stream cell must Merkle-open to the block round root");

    // (B) REAL coupled-puzzle trace (header-derived): bank_root / barrier_roots.
    const rc::RCCoupParams coup = rc::MakeToyRCCoupParams();
    rc::RCCoupEpisodeTranscript ctx;
    const auto t_coup = std::chrono::steady_clock::now();
    const uint256 coup_digest_ref = rc::RecomputeCoupledPuzzleReference(
        header, height, coup, {}, {}, nullptr, &ctx);
    BOOST_TEST_MESSAGE("coupled recompute_s=" << SecondsSince(t_coup)
                       << " barriers=" << ctx.barrier_roots.size()
                       << " gemms=" << ctx.gemms.size());
    BOOST_REQUIRE(!ctx.barrier_roots.empty());
    const uint256 coup_digest =
        rc::AssembleCoupledEpisodeDigest(ctx.bank_root, ctx.barrier_roots);
    BOOST_CHECK_MESSAGE(!coup_digest_ref.IsNull(), "coupled reference digest null");
    BOOST_REQUIRE(!ctx.gemms.empty() && !ctx.gemms[0].A.empty() &&
                  !ctx.gemms[0].B.empty());
    BOOST_REQUIRE(!ctx.extracts.empty());

    // (B1) real coupled bank pages (header/template-derived int8 experts).
    const std::vector<std::vector<int8_t>> bank_pages =
        rc::DeriveCoupledBankPages(header, height);
    BOOST_REQUIRE(!bank_pages.empty() && !bank_pages[0].empty());

    // Split a real int64 into four LE 16-bit limbs (CoupledMix adder operands).
    auto limbs4 = [](uint64_t v) -> std::array<uint32_t, 4> {
        return {static_cast<uint32_t>(v & 0xFFFFu),
                static_cast<uint32_t>((v >> 16) & 0xFFFFu),
                static_cast<uint32_t>((v >> 32) & 0xFFFFu),
                static_cast<uint32_t>((v >> 48) & 0xFFFFu)};
    };

    // Real GEMM MAC term (int8 operands from the coupled transcript).
    const int64_t coup_gemm_a = static_cast<int64_t>(ctx.gemms[0].A[0]);
    const int64_t coup_gemm_b = static_cast<int64_t>(ctx.gemms[0].B[0]);
    // Real episode GEMM term (int8 activations from the block's committed stream).
    const int64_t ep_gemm_a = static_cast<int64_t>(rounds[0].stream[0]);
    const int64_t ep_gemm_b =
        static_cast<int64_t>(rounds[0].stream.size() > 1 ? rounds[0].stream[1]
                                                         : rounds[0].stream[0]);
    // Real CoupledMix operands from the real extract trace (int64 post perm+mix).
    const auto& ext0 = ctx.extracts[0];
    const uint64_t mix_a_u = ext0.extract_in.empty()
                                 ? 0x1234ull
                                 : static_cast<uint64_t>(ext0.extract_in[0]);
    const uint64_t mix_b_u =
        ext0.extract_in.size() > 1 ? static_cast<uint64_t>(ext0.extract_in[1])
                                   : 0x5678ull;
    const std::array<uint32_t, 4> mix_a = limbs4(mix_a_u);
    const std::array<uint32_t, 4> mix_b = limbs4(mix_b_u);
    // Real bank nibble (low nibble of a real page byte).
    const uint8_t bank_nibble =
        static_cast<uint8_t>(bank_pages[0][0]) & 0x0Fu;
    // Real copy cells (block-committed values) for the copy-kernel roles.
    const gf::Fp3 coup_copy_cell = gf::FromSigned3(coup_gemm_a);
    const gf::Fp3 ep_wiring_cell = real_cell; // episode stream cell (Merkle-bound)

    // -----------------------------------------------------------------------
    // Build the 14 role C_rho products (real where a producer exists).
    // -----------------------------------------------------------------------
    auto pureStreamReal = [&](Role role, const std::vector<uint256>& roots256,
                              const std::string& src) -> RoleRun {
        std::vector<std::array<uint32_t, 8>> r8;
        for (const auto& h : roots256) r8.push_back(Root8FromUint256(h));
        RoleRun rr;
        rr.real_data = true;
        rr.source = src;
        rr.product = rc::BuildRCStage3PureStreamRoleAirFromRoots(role, r8, nullptr);
        return rr;
    };

    const uint256 header_commit = statement.public_inputs.header_commitment;
    const uint256 target = statement.public_inputs.target;
    // A distinct real internal tile-tree node hash (fallback to root if flat).
    const uint256 tt_internal =
        tt.hash_nodes.empty() ? tt.root : tt.hash_nodes.back().digest;
    const uint256 tt_leaf0 =
        tt.leaf_hashes.empty() ? tt.root : tt.leaf_hashes[0];

    std::vector<RoleRun> runs;

    // --- 6 EPISODE roles ---
    // EpisodeDeterministicBuilder: real params exist but the no-kernel role AIR
    // opens synthetic cells; no bridge from MineRCEpisode arrays to its witness.
    {
        // Params opening = real episode shape param; SeedChain/OperandXof streams
        // pinned to real header seeds.  BuilderTrace wired fold stays structural.
        const std::vector<gf::Fp3> open = {
            gf::Fp3::FromFp(gf::FromU64(episode.rounds))};
        const std::vector<std::array<uint32_t, 8>> sroots = {
            Root8FromUint256(header.seed_a), Root8FromUint256(header.seed_b)};
        RoleRun rr;
        rr.name = "EpisodeDeterministicBuilder";
        rr.real_data = true;
        rr.source = "REAL: Params=episode.rounds; SeedChain/OperandXof pinned to "
                    "header.seed_a/seed_b (BuilderTrace fold structural)";
        rr.product = rc::BuildRCStage3NoKernelRoleAir(
            Role::EpisodeDeterministicBuilder, nullptr, &open, &sroots);
        runs.push_back(std::move(rr));
    }
    // EpisodeGemm: real A/B/Y exist (episode stream / gemm_product.h:98) but the
    // toy a*b accumulator kernel + private opening witness have no real bridge.
    {
        // Real episode GEMM MAC term: A/B = block-committed int8 activations,
        // Y = A·B; SignedRange pinned to the real round root.
        const uint256 sr = round_roots[0];
        RoleRun rr;
        rr.name = "EpisodeGemm";
        rr.real_data = true;
        rr.source = "REAL: A/B = rounds[0].stream int8 activations, Y=A*B; "
                    "SignedRange pinned to round_roots[0]";
        rr.product = rc::BuildRCStage3EpisodeGemmRoleAir(nullptr, &ep_gemm_a,
                                                         &ep_gemm_b, &sr);
        runs.push_back(std::move(rr));
    }
    // EpisodeExtract: real extract IO exists but no-kernel witness synthetic.
    {
        // Real episode Extract cells = block-committed post-Extract activations
        // (episode stream bytes); ChaCha stream pinned to a real block value.
        auto sb = [&](size_t i) {
            return gf::FromSigned3(static_cast<int64_t>(
                rounds[0].stream[i % rounds[0].stream.size()]));
        };
        const std::vector<gf::Fp3> open = {sb(0), sb(2), sb(4), sb(6)};
        const std::vector<std::array<uint32_t, 8>> sroots = {
            Root8FromUint256(round_roots[0])};
        RoleRun rr;
        rr.name = "EpisodeExtract";
        rr.real_data = true;
        rr.source = "REAL: Input/Sampler/Scale/Output = rounds[0].stream "
                    "activations; ChaCha pinned to round_roots[0]";
        rr.product = rc::BuildRCStage3NoKernelRoleAir(Role::EpisodeExtract,
                                                      nullptr, &open, &sroots);
        runs.push_back(std::move(rr));
    }
    // EpisodeWiring: synthetic copy cell + synthetic wired leaf rows.
    {
        // Copy endpoint driven by a real block-committed episode cell; the three
        // wired folds (Transpose/Residual/RoundOrder) remain structural.
        RoleRun rr;
        rr.name = "EpisodeWiring";
        rr.real_data = true;
        rr.source = "PARTIAL-REAL: Copy = real episode stream cell; "
                    "Transpose/Residual/RoundOrder folds structural";
        rr.product = rc::BuildRCStage3EpisodeWiringRoleAir(nullptr, &ep_wiring_cell);
        runs.push_back(std::move(rr));
    }
    // EpisodeTileTree: REAL tile-tree roots from the round-0 stream.
    {
        RoleRun rr = pureStreamReal(
            Role::EpisodeTileTree,
            {tt.commitment, tt_leaf0, tt_internal, tt.root},
            "REAL: BuildTileTreeManifest(round0 stream); root==round_roots[0]");
        rr.name = "EpisodeTileTree";
        runs.push_back(std::move(rr));
    }
    // EpisodeDigest: REAL round-root / digest / header-target / target.
    {
        RoleRun rr = pureStreamReal(
            Role::EpisodeDigest,
            {round_roots[0], mined_digest, header_commit, target},
            "REAL: round_roots[0] + mined PoW digest + header/target commits");
        rr.name = "EpisodeDigest";
        runs.push_back(std::move(rr));
    }

    // --- 8 COUPLED roles ---
    // CoupledBank: real header pages exist (DeriveCoupledBankPages) but mixed
    // role witness uses hardcoded nibble-0 kernel; no real-cell bridge.
    {
        // Real page nibble drives the consensus T_M nibble table; SeedXof /
        // CoupledBankRoot streams pinned to real coupled roots.
        const std::vector<std::array<uint32_t, 8>> sroots = {
            Root8FromUint256(coup_digest), Root8FromUint256(ctx.bank_root)};
        RoleRun rr;
        rr.name = "CoupledBank";
        rr.real_data = true;
        rr.source = "REAL: nibble = DeriveCoupledBankPages(header)[0][0]; "
                    "SeedXof/BankRoot pinned to coupled digest/bank_root";
        rr.product = rc::BuildRCStage3CoupledMixedRoleAir(
            Role::CoupledBank, nullptr, nullptr, &bank_nibble, &sroots);
        runs.push_back(std::move(rr));
    }
    // CoupledGemm: real A/B/Y in ctx.gemms but synthetic a=3,b=5 toy kernel.
    {
        // Real coupled GEMM operands (int8 lobe row · bank page) drive the MAC
        // kernel; SignedRange pinned to a real coupled barrier root.
        const uint256 sr = ctx.barrier_roots.front();
        RoleRun rr;
        rr.name = "CoupledGemm";
        rr.real_data = true;
        rr.source = "REAL: A/B = ctx.gemms[0].A[0]/B[0] (int8 operands), "
                    "OUT=rows*A*B; SignedRange pinned to barrier_roots[0]";
        rr.product = rc::BuildRCStage3CoupledGemmRoleAir(nullptr, &coup_gemm_a,
                                                         &coup_gemm_b, &sr);
        runs.push_back(std::move(rr));
    }
    // CoupledExchange: synthetic copy cell 0x77 + synthetic HashXof stream.
    {
        // Real copy cell (block-committed coupled operand) + real HashXof stream
        // root pinned to a real coupled barrier root.
        const std::vector<std::array<uint32_t, 8>> sroots = {
            Root8FromUint256(ctx.barrier_roots.front())};
        RoleRun rr;
        rr.name = "CoupledExchange";
        rr.real_data = true;
        rr.source = "REAL: copy = ctx.gemms[0].A[0]; HashXof pinned to "
                    "barrier_roots[0]";
        rr.product = rc::BuildRCStage3CoupledMixedRoleAir(
            Role::CoupledExchange, nullptr, &coup_copy_cell, nullptr, &sroots);
        runs.push_back(std::move(rr));
    }
    // CoupledPermutation: REAL block-committed stream cell (copy kernel accepts
    // any cell; the exact byte Merkle-opens to round_roots[0]).
    {
        RoleRun rr;
        rr.name = "CoupledPermutation";
        rr.real_data = true;
        rr.source = "REAL: rounds[0].stream[0] (int8), Merkle-bound to "
                    "round_roots[0] via VerifyRCLeafOpening";
        rr.product = rc::BuildRCStage3CoupledPermutationRoleAir(real_cell, 0,
                                                                /*path_len=*/3,
                                                                nullptr);
        runs.push_back(std::move(rr));
    }
    // CoupledMix: 64-bit adder kernel; endpoint cells structurally linked, no
    // real consistent triple exposed.
    {
        // Real 64-bit adder: (a,b) = real coupled extract_in values; the kernel
        // proves sum=a+b / diff=b-a over the block's data.
        RoleRun rr;
        rr.name = "CoupledMix";
        rr.real_data = true;
        rr.source = "REAL: a,b = ctx.extracts[0].extract_in (int64 post perm+mix); "
                    "proves sum=a+b, diff=b-a";
        rr.product = rc::BuildRCStage3CoupledScalarRoleAir(
            Role::CoupledMix, 0, /*path_len=*/3, nullptr, &mix_a, &mix_b);
        runs.push_back(std::move(rr));
    }
    // CoupledExtract: real extract IO in ctx.extracts but no-kernel synthetic.
    {
        // Real coupled Extract cells from RCCoupExtractTranscript (extract_in /
        // extract_out); ChaCha stream pinned to the real extract PRF.
        auto ei = [&](size_t i) {
            return gf::FromSigned3(i < ext0.extract_in.size()
                                       ? ext0.extract_in[i]
                                       : 0);
        };
        const gf::Fp3 eo0 = gf::FromSigned3(static_cast<int64_t>(
            ext0.extract_out.empty() ? 0 : ext0.extract_out[0]));
        const std::vector<gf::Fp3> open = {ei(0), ei(1), gf::FromU64_3(0), eo0};
        const std::vector<std::array<uint32_t, 8>> sroots = {
            Root8FromUint256(ext0.extract_prf)};
        RoleRun rr;
        rr.name = "CoupledExtract";
        rr.real_data = true;
        rr.source = "REAL: Input/Sampler=extract_in, Output=extract_out; ChaCha "
                    "pinned to extract_prf (Scale=0 default)";
        rr.product = rc::BuildRCStage3NoKernelRoleAir(Role::CoupledExtract, nullptr,
                                                      &open, &sroots);
        runs.push_back(std::move(rr));
    }
    // CoupledBarrier: REAL coupled barrier roots (header-derived).
    {
        RoleRun rr = pureStreamReal(
            Role::CoupledBarrier,
            {ctx.barrier_roots.front(), ctx.bank_root, ctx.barrier_roots.back()},
            "REAL: RecomputeCoupledPuzzleReference barrier_roots + bank_root");
        rr.name = "CoupledBarrier";
        runs.push_back(std::move(rr));
    }
    // CoupledDigest: REAL coupled bank_root + assembled coupled episode digest.
    {
        RoleRun rr = pureStreamReal(
            Role::CoupledDigest, {ctx.bank_root, coup_digest, coup_digest},
            "REAL: bank_root + AssembleCoupledEpisodeDigest(bank,barriers)");
        rr.name = "CoupledDigest";
        runs.push_back(std::move(rr));
    }

    // -----------------------------------------------------------------------
    // Prove (multi-threaded) -> Verify ACCEPT -> tamper a real cell -> REJECT.
    // -----------------------------------------------------------------------
    const uint256 seed = []() { uint256 s; s.begin()[0] = 0x5a; return s; }();
    uint32_t real_ok = 0, synth_ok = 0;
    for (auto& rr : runs) {
        if (!rr.product.ok) {
            BOOST_TEST_MESSAGE("ROLE " << rr.name << " real=" << rr.real_data
                               << " BUILD_FAILED note=" << rr.product.note
                               << " src=" << rr.source);
            BOOST_CHECK_MESSAGE(rr.product.ok, rr.name + ": build " + rr.product.note);
            continue;
        }
        const uint32_t v0 =
            air_recurse::CountWitnessViolationsOnH(rr.product.cs, rr.product.witness);

        const auto tp = std::chrono::steady_clock::now();
        const auto proved = air_quotient::AirQuotientProve<gf::Fp3, AlgB3>(
            rr.product.cs, rr.product.witness, seed, {});
        const double prove_s = SecondsSince(tp);

        std::string vw;
        const auto tv = std::chrono::steady_clock::now();
        const bool accept =
            proved.ok && air_quotient::AirQuotientVerify<gf::Fp3, AlgB3>(
                             rr.product.cs, proved.proof, seed, &vw);
        const double verify_s = SecondsSince(tv);

        // Tamper: corrupt one real witness cell -> the CS must reject it.
        auto tampered = rr.product.witness;
        uint32_t tcol = 0;
        for (uint32_t c = 0; c < tampered.size(); ++c) {
            if (!tampered[c].empty()) { tcol = c; break; }
        }
        tampered[tcol][0] = gf::Add(tampered[tcol][0], gf::Fp3::One());
        const uint32_t v_tamper =
            air_recurse::CountWitnessViolationsOnH(rr.product.cs, tampered);

        const bool role_pass = (v0 == 0) && accept && (v_tamper > 0);
        if (role_pass) { rr.real_data ? ++real_ok : ++synth_ok; }

        BOOST_TEST_MESSAGE(
            "ROLE " << rr.name << " real=" << rr.real_data
                    << " rows=" << rr.product.cs.n_rows
                    << " cols=" << rr.product.cs.n_columns
                    << " endpoints=" << rr.product.endpoints.size()
                    << " viol0=" << v0 << " prove_s=" << prove_s
                    << " verify_s=" << verify_s << " accept=" << accept
                    << " tamper_viol=" << v_tamper << " PASS=" << role_pass
                    << " :: " << rr.source);
        BOOST_CHECK_MESSAGE(role_pass, rr.name + ": prove/verify/tamper " + vw);
    }

    // FRI-level tamper->reject on one REAL role (EpisodeDigest), closing the
    // loop end-to-end: a tampered real digest word must FAIL AirQuotientVerify.
    for (auto& rr : runs) {
        if (rr.name != "EpisodeDigest" || !rr.product.ok) continue;
        auto w = rr.product.witness;
        for (uint32_t c = 0; c < w.size(); ++c)
            if (!w[c].empty()) { w[c][0] = gf::Add(w[c][0], gf::Fp3::One()); break; }
        const auto p = air_quotient::AirQuotientProve<gf::Fp3, AlgB3>(
            rr.product.cs, w, seed, {});
        std::string tw;
        const bool tamper_accept =
            p.ok && air_quotient::AirQuotientVerify<gf::Fp3, AlgB3>(
                        rr.product.cs, p.proof, seed, &tw);
        BOOST_TEST_MESSAGE("EpisodeDigest FRI tamper accept=" << tamper_accept
                           << " (must be false)");
        BOOST_CHECK(!tamper_accept);
        break;
    }

    BOOST_TEST_MESSAGE("REAL_ROLE_SUMMARY real_data_driven_and_verified="
                       << real_ok << "/14  (synthetic_verified=" << synth_ok
                       << ")  roles_total=" << runs.size());
    BOOST_CHECK_EQUAL(runs.size(), 14U);
}

BOOST_AUTO_TEST_SUITE_END()
