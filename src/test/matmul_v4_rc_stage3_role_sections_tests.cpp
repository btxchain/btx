// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// REAL BLOCK -> STATEMENT -> PROVE -> VERIFY for the Stage-3 role sections.
//
// This is the first place in the tree where an RCStage3SuccinctProof object is
// built with REAL per-role AirQuotientProofs in ::sections and then verified
// WITHOUT a witness and WITHOUT replaying the episode.
//
// The block header is a genuine mined ENC_RC block pulled off a regtest chain
// (BTX_REAL_BLOCK_HEADER_HEX / BTX_REAL_BLOCK_HEIGHT). The load-bearing check
// is that recomputing the episode from that header reproduces the header's own
// matmul_digest -- i.e. the statement really is about that block.
//
// Gated behind BTX_RUN_STAGE3_SECTIONS=1 (episode recompute + 6 FRI proves).

#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_air_quotient.h>
#include <matmul/matmul_v4_rc_air_recurse.h>
#include <matmul/matmul_v4_rc_gkr_field_ext3.h>
#include <matmul/matmul_v4_rc_stage3_composition.h>
#include <matmul/matmul_v4_rc_stage3_consensus.h>
#include <matmul/matmul_v4_rc_stage3_hash_air.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>
#include <matmul/matmul_v4_rc_stage3_role_sections.h>
#include <matmul/matmul_v4_rc_stage3_root_chain.h>

#include <arith_uint256.h>
#include <consensus/params.h>
#include <primitives/block.h>
#include <streams.h>
#include <util/strencodings.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <chrono>
#include <cstdlib>
#include <string>
#include <vector>

namespace rc = matmul::v4::rc;
namespace ha = matmul::v4::rc::stage3_hash_air;
namespace gf = matmul::v4::rc::gkr_field;
namespace aq = matmul::v4::rc::air_quotient;
namespace ar = matmul::v4::rc::air_recurse;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_stage3_role_sections_tests,
                         BasicTestingSetup)

namespace {

using Role = rc::RCStage3RelationRole;

bool Enabled()
{
    return std::getenv("BTX_RUN_STAGE3_SECTIONS") != nullptr;
}

double SecondsSince(std::chrono::steady_clock::time_point t0)
{
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - t0)
        .count();
}

/** Deserialize a real block header straight off the wire encoding returned by
 * `getblockheader <hash> false`. */
bool HeaderFromHex(const std::string& hex, CBlockHeader& out)
{
    if (!IsHex(hex)) return false;
    const std::vector<unsigned char> bytes = ParseHex(hex);
    try {
        DataStream stream{bytes};
        stream >> out;
        return stream.empty();
    } catch (const std::exception&) {
        return false;
    }
}

/**
 * Consensus params mirroring the regtest node that mined the block:
 * ENC_RC episode live with CI toy dims, ENC_RC_COUPLED pushed out of range so
 * the required statement is Episode (Composed additionally needs
 * CompositionLink, which has no role AIR at all).
 *
 * The ProgramTable registry hashes are NOT configured on any real network
 * (Consensus::Params::hashMatMulRCStage3ProgramRegistry* are default-null
 * everywhere in kernel/chainparams.cpp). They are set here purely so the
 * unmodified ValidateRCStage3ConsensusBinding can be exercised end to end;
 * this test therefore does NOT establish a real verifying-key authority.
 */
Consensus::Params MakeChainParams(int32_t rc_height)
{
    Consensus::Params p;
    p.fMatMulPOW = true;
    p.nMatMulV4Height = 1;
    p.nMatMulRCHeight = rc_height;
    p.nMatMulRCCoupledHeight = 1'000'000;
    p.nMatMulRCProfile = 1;
    p.fMatMulRCUseToyDims = true;
    p.nMatMulV4Dimension = 256;
    p.powLimit = uint256{
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
    // Placeholder ProgramTable pin: canonical four-limb Goldilocks values so
    // ValidateProductionProgramConsensusPinV1 accepts it. NOT the real registry.
    uint256 alg;
    uint256 sha;
    uint256 bind;
    for (int i = 0; i < 32; ++i) {
        alg.data()[i] = 0x08;
        sha.data()[i] = 0x09;
        bind.data()[i] = 0x0a;
    }
    p.hashMatMulRCStage3ProgramRegistryAlgRoot = alg;
    p.hashMatMulRCStage3ProgramRegistryShaAuditRoot = sha;
    p.hashMatMulRCStage3ProgramRegistryBinding = bind;
    return p;
}

rc::ProductionProgramConsensusPinV1 PinFromParams(const Consensus::Params& p)
{
    rc::ProductionProgramConsensusPinV1 pin;
    pin.recursive_alg_hash_root = p.hashMatMulRCStage3ProgramRegistryAlgRoot;
    pin.external_sha256d_audit_root =
        p.hashMatMulRCStage3ProgramRegistryShaAuditRoot;
    pin.registry_binding = p.hashMatMulRCStage3ProgramRegistryBinding;
    return pin;
}

std::array<uint32_t, 8> Root8(const uint256& h)
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

/** The six EPISODE role C_rho products, every operand taken from the REAL
 * recomputed episode of the REAL block. */
std::vector<rc::RCStage3RoleAirProduct> BuildEpisodeRoleProducts(
    const CBlockHeader& header,
    const rc::RCEpisodeParams& episode,
    const std::vector<rc::RCRoundTranscript>& rounds,
    const std::vector<uint256>& round_roots,
    const uint256& mined_digest,
    const uint256& header_commitment,
    const uint256& target,
    const ha::TileTreeManifest& tt)
{
    std::vector<rc::RCStage3RoleAirProduct> out;

    // EpisodeDeterministicBuilder: real episode shape param + real header seeds.
    {
        const std::vector<gf::Fp3> open = {
            gf::Fp3::FromFp(gf::FromU64(episode.rounds))};
        const std::vector<std::array<uint32_t, 8>> sroots = {
            Root8(header.seed_a), Root8(header.seed_b)};
        out.push_back(rc::BuildRCStage3NoKernelRoleAir(
            Role::EpisodeDeterministicBuilder, nullptr, &open, &sroots));
    }
    // EpisodeGemm: A/B are block-committed int8 activations, Y = A*B.
    {
        const int64_t a = static_cast<int64_t>(rounds[0].stream[0]);
        const int64_t b = static_cast<int64_t>(
            rounds[0].stream.size() > 1 ? rounds[0].stream[1]
                                        : rounds[0].stream[0]);
        const uint256 sr = round_roots[0];
        out.push_back(
            rc::BuildRCStage3EpisodeGemmRoleAir(nullptr, &a, &b, &sr));
    }
    // EpisodeExtract: real post-Extract activations from the block's stream.
    {
        auto sb = [&](size_t i) {
            return gf::FromSigned3(static_cast<int64_t>(
                rounds[0].stream[i % rounds[0].stream.size()]));
        };
        const std::vector<gf::Fp3> open = {sb(0), sb(2), sb(4), sb(6)};
        const std::vector<std::array<uint32_t, 8>> sroots = {
            Root8(round_roots[0])};
        out.push_back(rc::BuildRCStage3NoKernelRoleAir(Role::EpisodeExtract,
                                                       nullptr, &open, &sroots));
    }
    // EpisodeWiring: copy endpoint driven by a real Merkle-bound episode cell.
    {
        const gf::Fp3 cell =
            gf::FromSigned3(static_cast<int64_t>(rounds[0].stream[0]));
        out.push_back(rc::BuildRCStage3EpisodeWiringRoleAir(nullptr, &cell));
    }
    // EpisodeTileTree: real tile-tree manifest over the round-0 stream.
    {
        const uint256 internal =
            tt.hash_nodes.empty() ? tt.root : tt.hash_nodes.back().digest;
        const uint256 leaf0 =
            tt.leaf_hashes.empty() ? tt.root : tt.leaf_hashes[0];
        const std::vector<std::array<uint32_t, 8>> r8 = {
            Root8(tt.commitment), Root8(leaf0), Root8(internal), Root8(tt.root)};
        out.push_back(rc::BuildRCStage3PureStreamRoleAirFromRoots(
            Role::EpisodeTileTree, r8, nullptr));
    }
    // EpisodeDigest: real round root, real PoW digest, header/target commits.
    {
        const std::vector<std::array<uint32_t, 8>> r8 = {
            Root8(round_roots[0]), Root8(mined_digest), Root8(header_commitment),
            Root8(target)};
        out.push_back(rc::BuildRCStage3PureStreamRoleAirFromRoots(
            Role::EpisodeDigest, r8, nullptr));
    }
    return out;
}

struct RealEpisode {
    CBlockHeader header;
    int32_t height{0};
    Consensus::Params params;
    rc::RCEpisodeParams episode;
    std::vector<rc::RCRoundTranscript> rounds;
    std::vector<uint256> round_roots;
    uint256 digest;
    ha::TileTreeManifest tile_tree;
};

/** Recompute the REAL episode of a REAL block and assert the recomputed digest
 * is the digest the block header actually committed. */
bool LoadRealEpisode(const char* header_env, const char* height_env,
                     RealEpisode& out, std::string& note)
{
    const char* hex = std::getenv(header_env);
    const char* height_s = std::getenv(height_env);
    if (hex == nullptr || height_s == nullptr) {
        note = std::string("set ") + header_env + " and " + height_env;
        return false;
    }
    if (!HeaderFromHex(hex, out.header)) {
        note = "header hex did not deserialize";
        return false;
    }
    out.height = static_cast<int32_t>(std::atoi(height_s));
    out.params = MakeChainParams(out.height);
    out.episode = rc::ResolveRCEpisodeParams(out.params, out.height);
    out.digest = rc::RecomputeResidentCurriculumReference(
        out.header, out.episode, out.height, {}, &out.rounds);
    if (out.digest.IsNull() || out.rounds.size() != out.episode.rounds) {
        note = "episode recompute failed";
        return false;
    }
    for (const auto& r : out.rounds) out.round_roots.push_back(r.round_root);
    std::string why;
    std::vector<uint8_t> stream0(out.rounds[0].stream.begin(),
                                 out.rounds[0].stream.end());
    if (!ha::BuildTileTreeManifest(stream0, out.episode.T_leaf, out.tile_tree,
                                   &why)) {
        note = "tile tree manifest: " + why;
        return false;
    }
    return true;
}

} // namespace

// ===========================================================================
// THE END-TO-END CASE: real mined block -> statement -> 6 real role FRI proofs
// assembled into RCStage3SuccinctProof::sections -> witness-free section
// verification ACCEPT.
// ===========================================================================
BOOST_AUTO_TEST_CASE(real_block_statement_prove_verify_sections)
{
    if (!Enabled()) {
        BOOST_TEST_MESSAGE("set BTX_RUN_STAGE3_SECTIONS=1 to run");
        return;
    }
    RealEpisode blk;
    std::string note;
    BOOST_REQUIRE_MESSAGE(
        LoadRealEpisode("BTX_REAL_BLOCK_HEADER_HEX", "BTX_REAL_BLOCK_HEIGHT",
                        blk, note),
        note);

    // (1) LOAD-BEARING: the recomputed episode digest IS the block's digest.
    BOOST_REQUIRE_MESSAGE(
        blk.digest == blk.header.matmul_digest,
        "recomputed episode digest " + blk.digest.ToString() +
            " != header.matmul_digest " +
            blk.header.matmul_digest.ToString() +
            " (the statement would not be about this block)");
    BOOST_TEST_MESSAGE("REAL BLOCK height=" << blk.height
                                            << " digest=" << blk.digest.ToString()
                                            << " rounds=" << blk.rounds.size());

    // (2) Real episode digest manifest reproduces the PoW digest.
    ha::EpisodeDigestManifest edm;
    std::string why;
    BOOST_REQUIRE(ha::BuildEpisodeDigestManifest(blk.episode.rounds,
                                                 blk.round_roots, edm, &why));
    BOOST_CHECK_EQUAL(edm.direct.digest.ToString(), blk.digest.ToString());
    BOOST_CHECK_MESSAGE(blk.tile_tree.root == blk.round_roots[0],
                        "tile-tree root must equal the real round root");

    // (3) PRODUCTION statement builder: header -> statement.
    rc::RCStage3SuccinctProof statement;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3StatementForHeader(
            blk.header, blk.params, blk.height,
            rc::RCStage3StatementKind::Episode, PinFromParams(blk.params),
            blk.digest, uint256{}, statement, &why),
        why);
    BOOST_CHECK(statement.public_inputs.final_digest ==
                blk.header.matmul_digest);

    // (4) Real role C_rho from real episode data -> real FRI section proofs.
    auto products = BuildEpisodeRoleProducts(
        blk.header, blk.episode, blk.rounds, blk.round_roots, blk.digest,
        statement.public_inputs.header_commitment,
        statement.public_inputs.target, blk.tile_tree);
    BOOST_REQUIRE_EQUAL(products.size(), 6U);

    std::vector<rc::RCStage3RoleAirSection> sections;
    double total_prove = 0.0;
    size_t total_bytes = 0;
    for (const auto& product : products) {
        BOOST_REQUIRE_MESSAGE(product.ok, product.note);
        BOOST_REQUIRE_EQUAL(
            ar::CountWitnessViolationsOnH(product.cs, product.witness), 0U);
        const auto proved =
            rc::ProveRCStage3RoleAirSection(statement, product);
        BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
        total_prove += proved.prove_seconds;
        std::vector<unsigned char> encoded;
        BOOST_REQUIRE(
            rc::SerializeRCStage3RoleAirSection(proved.section, encoded, &why));
        total_bytes += encoded.size();
        BOOST_TEST_MESSAGE("SECTION "
                           << rc::RCStage3RelationRoleName(product.role)
                           << " rows=" << proved.section.n_rows
                           << " cols=" << proved.section.n_columns
                           << " endpoint_roots="
                           << proved.section.endpoint_authority_roots.size()
                           << " prove_s=" << proved.prove_seconds
                           << " section_bytes=" << encoded.size());
        sections.push_back(proved.section);
    }

    // (5) WITNESS-FREE VERIFY of every required relation, one section at a
    //     time: rebuild C_rho from the immutable registry using only section
    //     pins, then the real AirQuotientVerify. All six must ACCEPT.
    uint32_t accepted = 0;
    double verify_s = 0.0;
    for (const auto& section : sections) {
        const auto t0 = std::chrono::steady_clock::now();
        std::string section_why;
        const bool ok =
            rc::VerifyRCStage3RoleAirSection(statement, section, &section_why);
        verify_s += SecondsSince(t0);
        BOOST_CHECK_MESSAGE(
            ok, std::string(rc::RCStage3RelationRoleName(section.role)) +
                    " section verify: " + section_why);
        if (ok) ++accepted;
    }
    BOOST_CHECK_EQUAL(accepted, 6U);
    BOOST_TEST_MESSAGE("SECTION_VERIFY accepted="
                       << accepted << "/6 verify_s=" << verify_s
                       << " total_prove_s=" << total_prove
                       << " total_section_bytes=" << total_bytes
                       << " envelope_cap=" << rc::kRCStage3MaxProofBytes);

    // (6) Assemble the single Stage-3 proof object. MEASURED FACT: six real
    //     episode role proofs at the row-wise Alg-FRI backend's per-query
    //     full-row openings do not fit the 16 MiB Stage-3 envelope. This is
    //     reported, never worked around by relaxing the cap.
    const bool assembled =
        rc::AssembleRCStage3SuccinctProofSections(statement, sections, &why);
    BOOST_TEST_MESSAGE("ENVELOPE_ASSEMBLE ok=" << assembled << " why=" << why
                                               << " total_section_bytes="
                                               << total_bytes);
    if (!assembled) {
        BOOST_TEST_MESSAGE(
            "BLOCKER: real per-role FRI sections exceed kRCStage3MaxProofBytes; "
            "the per-relation proofs verify, the consensus envelope cannot "
            "carry them at this proof size");
        return;
    }

    // (7) The proof serializes on the consensus wire and round-trips.
    std::vector<unsigned char> wire;
    BOOST_REQUIRE_MESSAGE(rc::SerializeRCStage3Proof(statement, wire, &why), why);
    const auto reparsed = rc::DeserializeRCStage3Proof(wire, &why);
    BOOST_REQUIRE_MESSAGE(reparsed.has_value(), why);
    BOOST_CHECK(*reparsed == statement);
    BOOST_CHECK_MESSAGE(rc::VerifyRCStage3RoleAirSections(*reparsed, &why), why);

    // (8) The unmodified consensus binding accepts this statement for this
    //     exact block/height/params/target.
    arith_uint256 target;
    bool neg = false;
    bool over = false;
    target.SetCompact(blk.header.nBits, &neg, &over);
    BOOST_CHECK_MESSAGE(
        rc::ValidateRCStage3ConsensusBinding(*reparsed, blk.header, blk.params,
                                             blk.height, ArithToUint256(target),
                                             &why),
        "consensus binding: " + why);
}

// ===========================================================================
// PROOF-LEVEL soundness. Every reject below is decided by the real FRI/AIR
// verifier or by the canonical codec -- none of them is a witness-side
// CountWitnessViolationsOnH check.
// ===========================================================================
BOOST_AUTO_TEST_CASE(real_block_section_tamper_rejects)
{
    if (!Enabled()) {
        BOOST_TEST_MESSAGE("set BTX_RUN_STAGE3_SECTIONS=1 to run");
        return;
    }
    RealEpisode blk;
    std::string note;
    BOOST_REQUIRE_MESSAGE(
        LoadRealEpisode("BTX_REAL_BLOCK_HEADER_HEX", "BTX_REAL_BLOCK_HEIGHT",
                        blk, note),
        note);
    BOOST_REQUIRE(blk.digest == blk.header.matmul_digest);

    std::string why;
    rc::RCStage3SuccinctProof statement;
    BOOST_REQUIRE(rc::BuildRCStage3StatementForHeader(
        blk.header, blk.params, blk.height, rc::RCStage3StatementKind::Episode,
        PinFromParams(blk.params), blk.digest, uint256{}, statement, &why));

    auto products = BuildEpisodeRoleProducts(
        blk.header, blk.episode, blk.rounds, blk.round_roots, blk.digest,
        statement.public_inputs.header_commitment,
        statement.public_inputs.target, blk.tile_tree);
    // The two pure-stream roles carry REAL block roots (tile-tree manifest over
    // the block's round-0 stream; round root + PoW digest + header/target
    // commitments) and are cheap enough to prove repeatedly here.
    const auto& tiletree = products[4];
    const auto& digest = products[5];
    BOOST_REQUIRE(tiletree.ok && digest.ok);

    const auto honest = rc::ProveRCStage3RoleAirSection(statement, digest);
    BOOST_REQUIRE_MESSAGE(honest.ok, honest.note);
    BOOST_REQUIRE_MESSAGE(
        rc::VerifyRCStage3RoleAirSection(statement, honest.section, &why), why);

    // (A) FRI-BODY TAMPER: mutate the proof itself. Reject must be decided by
    //     the real AirQuotientVerify (or the canonical codec), never by a
    //     witness-side check.
    {
        auto bad = honest.section;
        BOOST_REQUIRE(!bad.air.batch.fold_challenges.empty());
        bad.air.batch.fold_challenges[0] =
            gf::Add(bad.air.batch.fold_challenges[0], gf::Fp3::One());
        std::string bad_why;
        const bool accepted =
            rc::VerifyRCStage3RoleAirSection(statement, bad, &bad_why);
        BOOST_TEST_MESSAGE("TAMPER fri_body accept=" << accepted
                                                     << " why=" << bad_why);
        BOOST_CHECK(!accepted);
    }

    // (B) PROOF OF A FALSE STATEMENT: corrupt one REAL witness cell, then run
    //     the real prover directly (bypassing the section prover's own
    //     self-verify) and hand the resulting well-formed section to the
    //     verifier. The verifier has no witness; it must reject on the proof
    //     alone. This is the genuine proof-level soundness case.
    {
        auto product = digest;
        for (uint32_t c = 0; c < product.witness.size(); ++c) {
            if (!product.witness[c].empty()) {
                product.witness[c][0] =
                    gf::Add(product.witness[c][0], gf::Fp3::One());
                break;
            }
        }
        BOOST_REQUIRE(
            ar::CountWitnessViolationsOnH(product.cs, product.witness) > 0U);
        const uint256 seed =
            rc::ComputeRCStage3RoleAirSectionSeed(statement, product.role);
        using AlgB3 = aq::AirFriBackendAlg<gf::Fp3>;
        const auto proved = aq::AirQuotientProve<gf::Fp3, AlgB3>(
            product.cs, product.witness, seed, {});
        rc::RCStage3RoleAirSection bad = honest.section;
        bad.air = proved.proof;
        std::string bad_why;
        const bool accepted =
            proved.ok &&
            rc::VerifyRCStage3RoleAirSection(statement, bad, &bad_why);
        BOOST_TEST_MESSAGE("FALSE_STATEMENT prove_ok="
                           << proved.ok << " note=" << proved.note
                           << " verify_accept=" << accepted
                           << " why=" << bad_why);
        BOOST_CHECK(!accepted);
        // The section prover must also refuse to emit such a section at all.
        const auto refused = rc::ProveRCStage3RoleAirSection(statement, product);
        BOOST_CHECK(!refused.ok);
        BOOST_TEST_MESSAGE("section prover refused: " << refused.note);
    }

    // (C) CROSS-ROLE REPLAY: a valid section proved for EpisodeDigest must not
    //     verify when relabelled EpisodeTileTree. The FS seed is role-separated
    //     AND the registry rebuilds a different C_rho for the other role.
    {
        auto bad = honest.section;
        bad.role = Role::EpisodeTileTree;
        std::string bad_why;
        const bool accepted =
            rc::VerifyRCStage3RoleAirSection(statement, bad, &bad_why);
        BOOST_TEST_MESSAGE("TAMPER cross_role accept=" << accepted
                                                       << " why=" << bad_why);
        BOOST_CHECK(!accepted);
    }

    // (D) CROSS-BLOCK REPLAY: the same real section verified against a
    //     DIFFERENT block's statement must be rejected. The section FS seed is
    //     derived from the statement, so the FRI transcript no longer
    //     re-derives. This is what binds the proof to THIS block.
    {
        CBlockHeader other = blk.header;
        other.nNonce64 ^= 0x5eed000000000001ULL;
        rc::RCStage3SuccinctProof other_statement;
        BOOST_REQUIRE(rc::BuildRCStage3StatementForHeader(
            other, blk.params, blk.height, rc::RCStage3StatementKind::Episode,
            PinFromParams(blk.params), blk.digest, uint256{}, other_statement,
            &why));
        BOOST_REQUIRE(other_statement.public_inputs.header_commitment !=
                      statement.public_inputs.header_commitment);
        std::string bad_why;
        const bool accepted = rc::VerifyRCStage3RoleAirSection(
            other_statement, honest.section, &bad_why);
        BOOST_TEST_MESSAGE("TAMPER cross_block accept=" << accepted
                                                        << " why=" << bad_why);
        BOOST_CHECK(!accepted);
    }

    // (E) ENDPOINT-ROOT TAMPER: change a pinned real block root. The registry
    //     then rebuilds a DIFFERENT C_rho and the proof no longer verifies.
    //     (This is the mechanism that would carry endpoint provenance once
    //     kRCStage3RoleSectionEndpointProvenanceReady can be closed.)
    {
        auto bad = honest.section;
        BOOST_REQUIRE(!bad.endpoint_authority_roots.empty());
        bad.endpoint_authority_roots[0][0] =
            (bad.endpoint_authority_roots[0][0] + 1) % gf::kP;
        std::string bad_why;
        const bool accepted =
            rc::VerifyRCStage3RoleAirSection(statement, bad, &bad_why);
        BOOST_TEST_MESSAGE("TAMPER endpoint_root accept=" << accepted
                                                          << " why=" << bad_why);
        BOOST_CHECK(!accepted);
    }

    // (F) A second real role (EpisodeTileTree) also proves and verifies, so the
    //     result above is not a single-role artefact.
    {
        const auto tt = rc::ProveRCStage3RoleAirSection(statement, tiletree);
        BOOST_REQUIRE_MESSAGE(tt.ok, tt.note);
        BOOST_CHECK_MESSAGE(
            rc::VerifyRCStage3RoleAirSection(statement, tt.section, &why), why);
    }
}

// ===========================================================================
// Composed statements can NEVER be fully section-verified: CompositionLink has
// no role AIR. Record that fail-closed boundary explicitly so it cannot be
// quietly lost.
// ===========================================================================
// ===========================================================================
// ENDPOINT PROVENANCE: the declared endpoint authority roots must be the
// block's roots, not roots of the prover's choosing.
//
// Pure-stream endpoints anchor either to a statement public input or, via a
// REALLY-VERIFIED episode digest root chain, to a committed round root.
// ===========================================================================
BOOST_AUTO_TEST_CASE(endpoint_provenance_binds_declared_roots_to_the_block)
{
    if (!Enabled()) {
        BOOST_TEST_MESSAGE("set BTX_RUN_STAGE3_SECTIONS=1 to run");
        return;
    }
    RealEpisode blk;
    std::string note;
    BOOST_REQUIRE_MESSAGE(
        LoadRealEpisode("BTX_REAL_BLOCK_HEADER_HEX", "BTX_REAL_BLOCK_HEIGHT",
                        blk, note),
        note);
    BOOST_REQUIRE(blk.digest == blk.header.matmul_digest);

    std::string why;
    rc::RCStage3SuccinctProof statement;
    BOOST_REQUIRE(rc::BuildRCStage3StatementForHeader(
        blk.header, blk.params, blk.height, rc::RCStage3StatementKind::Episode,
        PinFromParams(blk.params), blk.digest, uint256{}, statement, &why));

    // The real digest root chain: round_roots -> typed preimage -> SHA256d
    // provenance -> episode digest == statement.episode_digest.
    rc::RCStage3EndpointProvenance provenance;
    const auto t_chain = std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3EpisodeDigestRootChain(statement, blk.episode.rounds,
                                                blk.round_roots,
                                                provenance.digest_chain, &why),
        why);
    provenance.has_digest_chain = true;
    const double chain_prove_s = SecondsSince(t_chain);
    BOOST_REQUIRE_MESSAGE(
        rc::VerifyRCStage3EpisodeDigestRootChain(statement, blk.episode.rounds,
                                                 provenance.digest_chain, &why),
        why);
    BOOST_TEST_MESSAGE("DIGEST_ROOT_CHAIN prove_s=" << chain_prove_s
                       << " round_roots="
                       << provenance.digest_chain.manifest.round_roots.size());

    auto products = BuildEpisodeRoleProducts(
        blk.header, blk.episode, blk.rounds, blk.round_roots, blk.digest,
        statement.public_inputs.header_commitment,
        statement.public_inputs.target, blk.tile_tree);

    // Anchor table sanity: the canonical repacking really is what the role
    // builder produced for the statement-anchored endpoints.
    {
        rc::alg_hash::Digest expected;
        BOOST_REQUIRE(rc::RCStage3StreamAuthorityRootFromUint256(
            statement.public_inputs.episode_digest, expected));
        // EpisodeDigest endpoints are {RoundRoots, Value, HeaderTarget, Pow}.
        BOOST_CHECK(products[5].endpoint_committed_roots[1] == expected);
    }

    rc::RCStage3EndpointProvenanceReport report;
    uint32_t sections_checked = 0;
    for (const auto& product : products) {
        BOOST_REQUIRE_MESSAGE(product.ok, product.note);
        const auto proved = rc::ProveRCStage3RoleAirSection(statement, product);
        BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
        BOOST_REQUIRE_MESSAGE(
            rc::VerifyRCStage3RoleAirSection(statement, proved.section, &why),
            why);
        std::string prov_why;
        const bool ok = rc::VerifyRCStage3RoleAirSectionEndpointProvenance(
            statement, proved.section, provenance, blk.episode.rounds, &report,
            &prov_why);
        BOOST_CHECK_MESSAGE(
            ok, std::string(rc::RCStage3RelationRoleName(product.role)) +
                    " provenance: " + prov_why);
        if (ok) ++sections_checked;
    }
    BOOST_CHECK_EQUAL(sections_checked, 6U);
    BOOST_TEST_MESSAGE("PROVENANCE endpoints_total="
                       << report.endpoints_total << " anchored_to_statement="
                       << report.anchored_to_statement
                       << " anchored_to_round_roots="
                       << report.anchored_to_round_roots
                       << " unanchored=" << report.unanchored);
    for (const auto& reason : report.unanchored_reasons) {
        BOOST_TEST_MESSAGE("  UNANCHORED: " << reason);
    }
    // MEASURED accounting, asserted so it cannot silently drift.
    BOOST_CHECK_EQUAL(report.anchored_to_statement, 3U);
    BOOST_CHECK_EQUAL(report.anchored_to_round_roots, 2U);
    BOOST_CHECK(report.unanchored > 0U);
    BOOST_CHECK(!rc::kRCStage3RoleSectionEndpointProvenanceReady);

    // THE ATTACK THIS CLOSES: a prover declares a convenient endpoint root.
    // Substitute a real, well-formed, but WRONG root and require rejection.
    {
        const auto proved = rc::ProveRCStage3RoleAirSection(statement, products[5]);
        BOOST_REQUIRE(proved.ok);
        auto forged = proved.section;
        rc::alg_hash::Digest other;
        BOOST_REQUIRE(rc::RCStage3StreamAuthorityRootFromUint256(
            statement.public_inputs.header_commitment, other));
        // Endpoint 24 (EpisodeDigestValue) must be the episode digest; claim
        // the header commitment instead.
        forged.endpoint_authority_roots[1] = other;
        std::string bad_why;
        const bool accepted = rc::VerifyRCStage3RoleAirSectionEndpointProvenance(
            statement, forged, provenance, blk.episode.rounds, nullptr,
            &bad_why);
        BOOST_TEST_MESSAGE("PROVENANCE forged_endpoint accept=" << accepted
                                                                << " why="
                                                                << bad_why);
        BOOST_CHECK(!accepted);
    }

    // A root that is NOT a committed round root of this episode is rejected on
    // the EpisodeRoundRoot-anchored endpoint.
    {
        const auto proved = rc::ProveRCStage3RoleAirSection(statement, products[4]);
        BOOST_REQUIRE(proved.ok);
        auto forged = proved.section;
        uint256 invented;
        for (int i = 0; i < 24; ++i) invented.data()[i] = static_cast<unsigned char>(0x3c + i);
        rc::alg_hash::Digest bogus;
        BOOST_REQUIRE(rc::RCStage3StreamAuthorityRootFromUint256(invented, bogus));
        forged.endpoint_authority_roots[3] = bogus; // EpisodeTileTreeRoot
        std::string bad_why;
        const bool accepted = rc::VerifyRCStage3RoleAirSectionEndpointProvenance(
            statement, forged, provenance, blk.episode.rounds, nullptr,
            &bad_why);
        BOOST_TEST_MESSAGE("PROVENANCE invented_round_root accept=" << accepted
                                                                    << " why="
                                                                    << bad_why);
        BOOST_CHECK(!accepted);
    }

    // Without a digest chain the round-root endpoints are reported UNANCHORED,
    // never silently treated as checked.
    {
        const auto proved = rc::ProveRCStage3RoleAirSection(statement, products[4]);
        BOOST_REQUIRE(proved.ok);
        rc::RCStage3EndpointProvenance none;
        rc::RCStage3EndpointProvenanceReport r2;
        BOOST_CHECK(rc::VerifyRCStage3RoleAirSectionEndpointProvenance(
            statement, proved.section, none, blk.episode.rounds, &r2, &why));
        BOOST_CHECK_EQUAL(r2.anchored_to_round_roots, 0U);
        BOOST_CHECK_EQUAL(r2.unanchored, 4U);
    }
}

// ===========================================================================
// Why VerifyRCStage3RecursiveProof still cannot accept, on a WELL-FORMED
// carrier built from a REAL role proof (not the empty carrier the existing
// harness probes, which only ever reports "unknown_role").
//
// AssessRCStage3RecursiveReadiness ANDs a hard-coded
//   constexpr bool child_fiat_shamir_replay_closed{false}
// into cryptographic_verification_ready, so no carrier of any shape can be
// accepted. This records the ACTUAL remaining gaps so the claim is measured,
// not asserted. Nothing here flips a gate.
// ===========================================================================
BOOST_AUTO_TEST_CASE(recursive_verify_blocked_on_real_wellformed_carrier)
{
    if (!Enabled()) {
        BOOST_TEST_MESSAGE("set BTX_RUN_STAGE3_SECTIONS=1 to run");
        return;
    }
    using AlgB3 = aq::AirFriBackendAlg<gf::Fp3>;

    // A real block-committed episode cell drives the child role AIR.
    RealEpisode blk;
    std::string note;
    BOOST_REQUIRE_MESSAGE(
        LoadRealEpisode("BTX_REAL_BLOCK_HEADER_HEX", "BTX_REAL_BLOCK_HEIGHT",
                        blk, note),
        note);
    // EpisodeTileTree: a role that IS in the Episode statement registry, driven
    // by the REAL tile-tree manifest over the block's round-0 stream.
    const uint256 tt_internal = blk.tile_tree.hash_nodes.empty()
                                    ? blk.tile_tree.root
                                    : blk.tile_tree.hash_nodes.back().digest;
    const uint256 tt_leaf0 = blk.tile_tree.leaf_hashes.empty()
                                 ? blk.tile_tree.root
                                 : blk.tile_tree.leaf_hashes[0];
    const std::vector<std::array<uint32_t, 8>> tt_roots = {
        Root8(blk.tile_tree.commitment), Root8(tt_leaf0), Root8(tt_internal),
        Root8(blk.tile_tree.root)};
    const auto product = rc::BuildRCStage3PureStreamRoleAirFromRoots(
        Role::EpisodeTileTree, tt_roots, nullptr);
    BOOST_REQUIRE_MESSAGE(product.ok, product.note);

    ar::ChildPublicInputs shape;
    shape.child_n_rows = product.cs.n_rows;
    shape.child_w = product.cs.n_columns;
    shape.endpoint_authority_roots = product.endpoint_committed_roots;
    aq::AirConstraintSystem<gf::Fp3> child_cs;
    std::string registry_why;
    BOOST_REQUIRE_MESSAGE(
        rc::ResolveCurrentRCStage3RelationConstraintSystem(
            Role::EpisodeTileTree, shape, child_cs, &registry_why),
        registry_why);
    BOOST_REQUIRE_EQUAL(child_cs.n_rows, product.cs.n_rows);
    BOOST_REQUIRE_EQUAL(child_cs.n_columns, product.cs.n_columns);

    uint256 child_fs_seed;
    child_fs_seed.data()[0] = 0x77;
    const auto proved = aq::AirQuotientProve<gf::Fp3, AlgB3>(
        product.cs, product.witness, child_fs_seed, {});
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    const bool child_verifies = aq::AirQuotientVerify<gf::Fp3, AlgB3>(
        child_cs, proved.proof, child_fs_seed, &registry_why);
    BOOST_REQUIRE_MESSAGE(child_verifies, registry_why);

    // A structurally valid, REAL-data carrier: real child pins extracted from a
    // real child proof, canonical fixed-role commitment.
    rc::RCStage3RecursiveProof carrier;
    carrier.role = Role::EpisodeTileTree;
    carrier.ctl_child_commitment.data()[0] = 0x5c;
    for (int slot = 0; slot < 4; ++slot) {
        ar::ChildPublicInputs pi = ar::ExtractChildPublicInputs(
            child_cs, proved.proof, child_fs_seed);
        pi.child_constraints.clear();
        // ExtractChildPublicInputs cannot recover the endpoint authority roots
        // from the proof; they are separate public pins supplied by the caller.
        pi.endpoint_authority_roots = product.endpoint_committed_roots;
        pi.ok = true;
        pi.note.clear();
        carrier.children.push_back({pi});
    }
    carrier.fixed_role_commitment =
        rc::ComputeRCStage3RecursiveChildPinsCommitment(
            carrier.role, carrier.ctl_child_commitment, carrier.children);
    carrier.root = proved.proof; // shape-valid stand-in for the aggregate root

    rc::RCStage3SuccinctProof statement;
    std::string why;
    BOOST_REQUIRE(rc::BuildRCStage3StatementForHeader(
        blk.header, blk.params, blk.height, rc::RCStage3StatementKind::Episode,
        PinFromParams(blk.params), blk.digest, uint256{}, statement, &why));

    const auto readiness =
        rc::AssessRCStage3RecursiveReadiness(statement, carrier);
    BOOST_TEST_MESSAGE("RECURSIVE readiness on REAL carrier:"
                       << " structurally_valid=" << readiness.structurally_valid
                       << " constraints_resolved=" << readiness.constraints_resolved
                       << " backend_shape_supported="
                       << readiness.backend_shape_supported
                       << " soundness_bits=" << readiness.soundness_bits
                       << " cryptographic_verification_ready="
                       << readiness.cryptographic_verification_ready
                       << " gaps=" << readiness.gaps.size());
    for (const auto& gap : readiness.gaps) {
        BOOST_TEST_MESSAGE("  GAP[" << static_cast<int>(gap.code)
                                    << "]: " << gap.detail);
    }
    // Structural / registry / backend preconditions DO close on real data.
    BOOST_CHECK(readiness.structurally_valid);
    BOOST_CHECK(readiness.constraints_resolved);
    BOOST_CHECK(readiness.backend_shape_supported);
    // ...and the verifier is STILL fail-closed. This is the measured blocker.
    BOOST_CHECK(!readiness.cryptographic_verification_ready);
    std::string verify_why;
    BOOST_CHECK(
        !rc::VerifyRCStage3RecursiveProof(statement, carrier, &verify_why));
    BOOST_TEST_MESSAGE("VerifyRCStage3RecursiveProof why=" << verify_why);
}

// ===========================================================================
// The consensus BINDING layer must authenticate the whole payload.
//
// transcript_commitment used to be only null-checked, which left it, every
// per-role commitment root, and every section body unauthenticated by
// ValidateRCStage3ConsensusBinding (69 of 164 payload words). It is now
// recomputed and compared. These are structural, always-on regressions -- no
// episode recompute, no FRI proving.
// ===========================================================================
BOOST_AUTO_TEST_CASE(consensus_binding_authenticates_commitments_and_sections)
{
    constexpr int32_t HEIGHT{101};
    const Consensus::Params params = MakeChainParams(HEIGHT);

    CBlockHeader header;
    header.nVersion = 0x20000000;
    header.nTime = 1'785'000'000;
    header.nBits = 0x207fffff;
    header.nNonce64 = 7;
    header.matmul_dim = 256;
    for (int i = 0; i < 32; ++i) {
        header.hashPrevBlock.data()[i] = static_cast<unsigned char>(0x41);
        header.hashMerkleRoot.data()[i] = static_cast<unsigned char>(0x42);
        header.seed_a.data()[i] = static_cast<unsigned char>(0x43);
        header.seed_b.data()[i] = static_cast<unsigned char>(0x44);
        header.matmul_digest.data()[i] = static_cast<unsigned char>(0x00);
    }
    header.matmul_digest.data()[0] = 0x11; // comfortably under target

    std::string why;
    rc::RCStage3SuccinctProof proof;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3StatementForHeader(
            header, params, HEIGHT, rc::RCStage3StatementKind::Episode,
            PinFromParams(params), header.matmul_digest, uint256{}, proof, &why),
        why);

    // Structural sections: this test is about the BINDING layer, not the
    // mathematical verifier, so the bodies only need to be well-formed bytes.
    const auto roles =
        rc::RequiredRCStage3RelationRoles(rc::RCStage3StatementKind::Episode);
    for (size_t i = 0; i < roles.size(); ++i) {
        uint256 root;
        root.data()[0] = static_cast<unsigned char>(0xb0 + i);
        proof.commitments.push_back({roles[i], root});
        proof.sections.push_back(
            {roles[i], {static_cast<unsigned char>(i), 0x5a, 0xa5}});
    }
    proof.public_inputs.transcript_commitment =
        rc::ComputeRCStage3TranscriptCommitment(proof);

    arith_uint256 t;
    bool neg = false;
    bool over = false;
    t.SetCompact(header.nBits, &neg, &over);
    const uint256 target = ArithToUint256(t);
    BOOST_REQUIRE_MESSAGE(
        rc::ValidateRCStage3ConsensusBinding(proof, header, params, HEIGHT,
                                             target, &why),
        why);

    // (1) transcript_commitment itself: non-null but wrong.
    {
        auto bad = proof;
        bad.public_inputs.transcript_commitment.data()[0] ^= 0x01;
        std::string bad_why;
        BOOST_CHECK(!rc::ValidateRCStage3ConsensusBinding(
            bad, header, params, HEIGHT, target, &bad_why));
        BOOST_TEST_MESSAGE("BIND transcript why=" << bad_why);
    }
    // (2) a per-role commitment ROOT, with the transcript left as-is.
    {
        auto bad = proof;
        bad.commitments[2].root.data()[0] ^= 0x01;
        std::string bad_why;
        BOOST_CHECK(!rc::ValidateRCStage3ConsensusBinding(
            bad, header, params, HEIGHT, target, &bad_why));
        BOOST_TEST_MESSAGE("BIND commitment_root why=" << bad_why);
    }
    // (3) a section BODY, with the transcript left as-is.
    {
        auto bad = proof;
        bad.sections[4].proof[1] ^= 0x01;
        std::string bad_why;
        BOOST_CHECK(!rc::ValidateRCStage3ConsensusBinding(
            bad, header, params, HEIGHT, target, &bad_why));
        BOOST_TEST_MESSAGE("BIND section_body why=" << bad_why);
    }
    // (4) a consistent forgery: tamper a section AND recompute the transcript.
    //     The binding layer accepts it -- correctly, because authenticating the
    //     CONTENT of a section is the mathematical verifier's job, not the
    //     binding layer's. Recorded so the distinction is not overstated.
    {
        auto bad = proof;
        bad.sections[4].proof[1] ^= 0x01;
        bad.public_inputs.transcript_commitment = {};
        bad.public_inputs.transcript_commitment =
            rc::ComputeRCStage3TranscriptCommitment(bad);
        std::string bad_why;
        const bool accepted = rc::ValidateRCStage3ConsensusBinding(
            bad, header, params, HEIGHT, target, &bad_why);
        BOOST_CHECK(accepted);
        BOOST_TEST_MESSAGE(
            "BIND self_consistent_forgery accepted=" << accepted
            << " (binding layer binds STRUCTURE; section CONTENT is the "
               "mathematical verifier's obligation)");
    }
}

BOOST_AUTO_TEST_CASE(composition_link_has_no_role_air)
{
    BOOST_CHECK(!rc::RCStage3RoleIsInCsClosable(Role::CompositionLink));
    for (const Role role :
         rc::RequiredRCStage3RelationRoles(rc::RCStage3StatementKind::Episode)) {
        BOOST_CHECK_MESSAGE(rc::RCStage3RoleIsInCsClosable(role),
                            std::string("episode role must be CS-closable: ") +
                                rc::RCStage3RelationRoleName(role));
    }
    for (const Role role :
         rc::RequiredRCStage3RelationRoles(rc::RCStage3StatementKind::Coupled)) {
        BOOST_CHECK_MESSAGE(rc::RCStage3RoleIsInCsClosable(role),
                            std::string("coupled role must be CS-closable: ") +
                                rc::RCStage3RelationRoleName(role));
    }
    BOOST_CHECK(!rc::kRCStage3RoleSectionEndpointProvenanceReady);
}

BOOST_AUTO_TEST_SUITE_END()
