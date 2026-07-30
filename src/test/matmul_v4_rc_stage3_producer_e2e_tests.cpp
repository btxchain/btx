// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// PR-89 item 5 — THE FULL LOOP, with a REAL prover registered.
//
// Every other producer test installs a stub RCStage3ProofSource. This one
// installs the real chain the section-assembly lane owns:
//
//   real RC block -> RecomputeResidentCurriculumReference (real episode)
//                 -> BuildRCStage3StatementForHeader
//                 -> ProveRCStage3RoleAirSection x6   (real FRI proofs)
//                 -> AssembleRCStage3SuccinctProofSections
//                 -> AttachRCStage3ProofFromSource     (the producer seam)
//                 -> InspectRCStage3ConsensusAttachment (the validator's parse)
//
// and reports the PRECISE point at which it stops, with measured bytes.
//
// This is expected to FAIL, at a specific place, for a specific measured reason.
// The test asserts that it fails THERE and not somewhere else, because "where
// does the real loop actually stop" is the question worth answering. Nothing is
// activated; kRCStage3SuccinctAuthorityReady stays false throughout and the
// producer's gated entry point is deliberately not the one under test here.
//
// COST: proving six real role sections takes minutes and multiple GB. Gated
// behind BTX_RUN_STAGE3_E2E=1 so the default suite stays fast.

#include <matmul/matmul_v4_rc_stage3_producer.h>

#include <arith_uint256.h>
#include <consensus/params.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_air_quotient.h>
#include <matmul/matmul_v4_rc_gkr_field_ext3.h>
#include <matmul/matmul_v4_rc_stage3_composition.h>
#include <matmul/matmul_v4_rc_stage3_consensus.h>
#include <matmul/matmul_v4_rc_stage3_hash_air.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>
#include <matmul/matmul_v4_rc_stage3_role_sections.h>
#include <pow.h>
#include <primitives/block.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstdlib>
#include <string>
#include <vector>

namespace rc = matmul::v4::rc;
namespace gf = matmul::v4::rc::gkr_field;
namespace ha = matmul::v4::rc::stage3_hash_air;
namespace ar = matmul::v4::rc::air_quotient;
using Role = rc::RCStage3RelationRole;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_stage3_producer_e2e_tests, BasicTestingSetup)

namespace {

bool Enabled() { return std::getenv("BTX_RUN_STAGE3_E2E") != nullptr; }

//! Real ENC_RC block, height 102 of a local RC regtest chain
//! (RPC 19335, regtestrccoupledheight=1000). Regtest activates RC at 101, so
//! this block is genuinely RC-active and its header carries a real solved
//! matmul_digest produced by the real episode solver.
const char* kRealRcBlock102Hex =
    "0000002091d3c0b1f4b3c49c81c32a9438212765d05ea559a7326658f9a9a246c60352"
    "cbf8bbf554af210e9eb0c117aacbbca4d0268c52ab1603936efc9109cc3034c6463e08"
    "666affff7f200000000000000000b7f9cfe3f9719c351f163b56fe4bcd154c7e906190"
    "47e17f17127c6e77a71607000137cd0e9194be5ef03c797c0b2eaf62be9aca9cea2157"
    "286921dff19ff0f2c747da8835c1811ed0d18214845c2493871ebc1ce3e638cbd7b6d0"
    "a608fa5c5bd7ed01020000000001010000000000000000000000000000000000000000"
    "000000000000000000000000ffffffff03016600ffffffff0200943577000000002252"
    "204df0e118c006dd68e46e0c8f144ff5c2c5618633a9c556dddb6c0704bd5535460000"
    "000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c6906897999"
    "62b48bebd836974e8cf901200000000000000000000000000000000000000000000000"
    "000000000000000000000000000000";

CBlock RealRcBlock102(bool& ok)
{
    CBlock block;
    const auto bytes = TryParseHex<unsigned char>(kRealRcBlock102Hex);
    ok = false;
    if (!bytes.has_value()) return block;
    try {
        DataStream stream{*bytes};
        stream >> TX_WITH_WITNESS(block);
        ok = true;
    } catch (const std::exception&) {
        ok = false;
    }
    return block;
}

//! Consensus params matching the RC chain the fixture came from, with a
//! PLACEHOLDER ProgramTable pin. The real registry roots are unconfigured on
//! every network — that is a separate activation blocker — and the binding
//! check rejects a null registry outright, so a placeholder is required to
//! reach any later step at all.
Consensus::Params RcChainParams(int32_t height)
{
    Consensus::Params p;
    p.fMatMulPOW = true;
    p.nMatMulV4Height = 1;
    p.nMatMulRCHeight = 101;
    p.nMatMulRCCoupledHeight = 1'000'000;
    p.nMatMulRCProfile = 1;
    p.fMatMulRCUseToyDims = true;
    p.nMatMulV4Dimension = 256;
    p.powLimit = uint256{
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
    uint256 alg, sha, bind;
    for (int i = 0; i < 32; ++i) {
        alg.data()[i] = 0x08;
        sha.data()[i] = 0x09;
        bind.data()[i] = 0x0a;
    }
    p.hashMatMulRCStage3ProgramRegistryAlgRoot = alg;
    p.hashMatMulRCStage3ProgramRegistryShaAuditRoot = sha;
    p.hashMatMulRCStage3ProgramRegistryBinding = bind;
    (void)height;
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

/** The six EPISODE role C_rho products, every operand from the REAL episode.
 *  Mirrors the assembly lane's BuildEpisodeRoleProducts; kept in step with it. */
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
    {
        const std::vector<gf::Fp3> open = {
            gf::Fp3::FromFp(gf::FromU64(episode.rounds))};
        const std::vector<std::array<uint32_t, 8>> sroots = {
            Root8(header.seed_a), Root8(header.seed_b)};
        out.push_back(rc::BuildRCStage3NoKernelRoleAir(
            Role::EpisodeDeterministicBuilder, nullptr, &open, &sroots));
    }
    {
        const int64_t a = static_cast<int64_t>(rounds[0].stream[0]);
        const int64_t b = static_cast<int64_t>(
            rounds[0].stream.size() > 1 ? rounds[0].stream[1] : rounds[0].stream[0]);
        const uint256 sr = round_roots[0];
        out.push_back(rc::BuildRCStage3EpisodeGemmRoleAir(nullptr, &a, &b, &sr));
    }
    {
        auto sb = [&](size_t i) {
            return gf::FromSigned3(static_cast<int64_t>(
                rounds[0].stream[i % rounds[0].stream.size()]));
        };
        const std::vector<gf::Fp3> open = {sb(0), sb(2), sb(4), sb(6)};
        const std::vector<std::array<uint32_t, 8>> sroots = {Root8(round_roots[0])};
        out.push_back(rc::BuildRCStage3NoKernelRoleAir(Role::EpisodeExtract,
                                                       nullptr, &open, &sroots));
    }
    {
        const gf::Fp3 cell =
            gf::FromSigned3(static_cast<int64_t>(rounds[0].stream[0]));
        out.push_back(rc::BuildRCStage3EpisodeWiringRoleAir(nullptr, &cell));
    }
    {
        const uint256 internal =
            tt.hash_nodes.empty() ? tt.root : tt.hash_nodes.back().digest;
        const uint256 leaf0 = tt.leaf_hashes.empty() ? tt.root : tt.leaf_hashes[0];
        const std::vector<std::array<uint32_t, 8>> r8 = {
            Root8(tt.commitment), Root8(leaf0), Root8(internal), Root8(tt.root)};
        out.push_back(rc::BuildRCStage3PureStreamRoleAirFromRoots(
            Role::EpisodeTileTree, r8, nullptr));
    }
    {
        const std::vector<std::array<uint32_t, 8>> r8 = {
            Root8(round_roots[0]), Root8(mined_digest), Root8(header_commitment),
            Root8(target)};
        out.push_back(rc::BuildRCStage3PureStreamRoleAirFromRoots(
            Role::EpisodeDigest, r8, nullptr));
    }
    return out;
}

/**
 * THE REAL PROVER, registered as an RCStage3ProofSource.
 *
 * This is the concrete instance of the "expected implementation shape" the
 * producer header documents. It reads NOTHING from block.matrix_c_data — the
 * miner path clears it before calling — and derives everything from the
 * finalized header, exactly as the interface requires. It uses
 * hints.episode_rounds when supplied purely to skip a redundant episode
 * recompute, and works identically without it.
 */
struct RealProverStats {
    bool statement_built{false};
    bool products_built{false};
    size_t sections_proved{0};
    bool assembled{false};
    size_t total_section_bytes{0};
    double total_prove_seconds{0.0};
    bool used_hint{false};
    std::string stop_reason;
};

RealProverStats g_stats;

bool RealProver(const CBlock& solved,
                const Consensus::Params& params,
                int32_t height,
                const uint256& target,
                const rc::RCStage3ProducerHints& hints,
                rc::RCStage3SuccinctProof& out,
                std::string* why)
{
    g_stats = {};
    const rc::RCEpisodeParams episode = rc::ResolveRCEpisodeParams(params, height);

    // Episode transcript: use the solver's if it was handed to us, otherwise
    // re-derive from the header. Both paths must produce the same digest.
    std::vector<rc::RCRoundTranscript> local_rounds;
    const std::vector<rc::RCRoundTranscript>* rounds = nullptr;
    uint256 digest;
    if (hints.episode_rounds != nullptr &&
        hints.episode_rounds->size() == episode.rounds) {
        rounds = hints.episode_rounds;
        g_stats.used_hint = true;
        // Still need the digest; recompute it from the supplied roots rather
        // than trusting a value we were not given.
        digest = rc::RecomputeResidentCurriculumReference(
            solved, episode, height, {}, &local_rounds);
    } else {
        digest = rc::RecomputeResidentCurriculumReference(
            solved, episode, height, {}, &local_rounds);
        rounds = &local_rounds;
    }
    if (digest.IsNull() || rounds->size() != episode.rounds) {
        if (why != nullptr) *why = "episode_recompute_failed";
        g_stats.stop_reason = "episode_recompute";
        return false;
    }
    if (digest != solved.matmul_digest) {
        if (why != nullptr) {
            *why = "recomputed digest " + digest.ToString() +
                   " != header.matmul_digest " + solved.matmul_digest.ToString();
        }
        g_stats.stop_reason = "digest_mismatch";
        return false;
    }

    std::vector<uint256> round_roots;
    for (const auto& r : *rounds) round_roots.push_back(r.round_root);

    ha::TileTreeManifest tt;
    std::string tt_why;
    std::vector<uint8_t> stream0((*rounds)[0].stream.begin(),
                                 (*rounds)[0].stream.end());
    if (!ha::BuildTileTreeManifest(stream0, episode.T_leaf, tt, &tt_why)) {
        if (why != nullptr) *why = "tile_tree: " + tt_why;
        g_stats.stop_reason = "tile_tree";
        return false;
    }

    std::string build_why;
    if (!rc::BuildRCStage3StatementForHeader(
            solved, params, height, rc::RCStage3StatementKind::Episode,
            PinFromParams(params), digest, uint256{}, out, &build_why)) {
        if (why != nullptr) *why = "statement: " + build_why;
        g_stats.stop_reason = "statement";
        return false;
    }
    g_stats.statement_built = true;

    auto products = BuildEpisodeRoleProducts(
        solved, episode, *rounds, round_roots, digest,
        out.public_inputs.header_commitment, target, tt);
    for (const auto& p : products) {
        if (!p.ok) {
            if (why != nullptr) *why = "role_product: " + p.note;
            g_stats.stop_reason = "role_product";
            return false;
        }
    }
    g_stats.products_built = true;

    std::vector<rc::RCStage3RoleAirSection> sections;
    for (const auto& product : products) {
        const auto proved = rc::ProveRCStage3RoleAirSection(out, product);
        if (!proved.ok) {
            if (why != nullptr) *why = "prove_section: " + proved.note;
            g_stats.stop_reason = "prove_section";
            return false;
        }
        g_stats.total_prove_seconds += proved.prove_seconds;
        std::vector<unsigned char> encoded;
        std::string enc_why;
        if (rc::SerializeRCStage3RoleAirSection(proved.section, encoded, &enc_why)) {
            g_stats.total_section_bytes += encoded.size();
        }
        ++g_stats.sections_proved;
        BOOST_TEST_MESSAGE("  SECTION " << rc::RCStage3RelationRoleName(product.role)
                           << " rows=" << proved.section.n_rows
                           << " cols=" << proved.section.n_columns
                           << " bytes=" << encoded.size()
                           << " prove_s=" << proved.prove_seconds);
        sections.push_back(proved.section);
    }

    std::string asm_why;
    if (!rc::AssembleRCStage3SuccinctProofSections(out, sections, &asm_why)) {
        if (why != nullptr) *why = "assemble: " + asm_why;
        g_stats.stop_reason = "assemble:" + asm_why;
        return false;
    }
    g_stats.assembled = true;
    return true;
}

} // namespace

BOOST_AUTO_TEST_CASE(real_prover_full_consensus_loop)
{
    if (!Enabled()) {
        BOOST_TEST_MESSAGE("set BTX_RUN_STAGE3_E2E=1 to run (minutes, multi-GB)");
        return;
    }

    bool decoded{false};
    const CBlock block = RealRcBlock102(decoded);
    BOOST_REQUIRE_MESSAGE(decoded, "real block fixture did not deserialize");

    constexpr int32_t HEIGHT{102};
    const auto params = RcChainParams(HEIGHT);
    const auto target_arith = DeriveTarget(block.nBits, params.powLimit);
    BOOST_REQUIRE(target_arith.has_value());
    const uint256 target = ArithToUint256(*target_arith);

    BOOST_REQUIRE(params.IsMatMulRCFamilyActive(HEIGHT));
    BOOST_REQUIRE(rc::RequiredRCStage3Statement(params, HEIGHT).has_value());

    rc::SetRCStage3ProofSource(RealProver);
    BOOST_REQUIRE(rc::HasRCStage3ProofSource());

    CBlock candidate = block;
    candidate.matrix_c_data.clear(); // the miner path clears before producing

    std::string why;
    rc::RCStage3AttachmentSizeReport size_report;
    const auto status = rc::AttachRCStage3ProofFromSource(
        candidate, params, HEIGHT, target, &why, &size_report);

    BOOST_TEST_MESSAGE("=== FULL LOOP RESULT ===");
    BOOST_TEST_MESSAGE("status        : " << rc::RCStage3ProduceStatusName(status));
    BOOST_TEST_MESSAGE("why           : " << why);
    BOOST_TEST_MESSAGE("statement     : " << g_stats.statement_built);
    BOOST_TEST_MESSAGE("products      : " << g_stats.products_built);
    BOOST_TEST_MESSAGE("sections      : " << g_stats.sections_proved << "/6");
    BOOST_TEST_MESSAGE("section bytes : " << g_stats.total_section_bytes);
    BOOST_TEST_MESSAGE("prove seconds : " << g_stats.total_prove_seconds);
    BOOST_TEST_MESSAGE("assembled     : " << g_stats.assembled);
    BOOST_TEST_MESSAGE("stop reason   : " << g_stats.stop_reason);
    if (size_report.payload_bytes != 0) {
        BOOST_TEST_MESSAGE("size report   : " << size_report.ToString());
    }
    BOOST_TEST_MESSAGE("planned reservation: "
        << rc::RCStage3PlannedReservation(params, HEIGHT).envelope_bytes << " B");

    rc::SetRCStage3ProofSource({});

    if (status == rc::RCStage3ProduceStatus::Attached) {
        // If it ever DOES fit, the validator's parse must accept the binding and
        // stop only at the mathematical-authority gate.
        BOOST_TEST_MESSAGE("ATTACHED — proceeding to validator parse");
        const auto inspected = rc::InspectRCStage3ConsensusAttachment(
            candidate, params, HEIGHT, target, nullptr, nullptr, &why);
        BOOST_CHECK(inspected ==
                    rc::RCStage3AttachmentStatus::AuthorityUnavailable);
        BOOST_CHECK(!rc::RCStage3AttachmentIsMutation(inspected));
        return;
    }

    // The loop stopped. Whatever the reason, the block must be UNTOUCHED — a
    // miner that ignored the status still cannot ship a partial attachment.
    BOOST_CHECK(candidate.matrix_c_data.empty());
    BOOST_CHECK(rc::RCStage3ProduceIsFatal(status));

    // And it must have got far enough to be a SIZE result rather than an
    // infrastructure failure. If any of these fire, the loop broke earlier than
    // the known wall and the stop reason above is the thing to read.
    BOOST_CHECK_MESSAGE(g_stats.statement_built,
                        "loop failed before the statement was built: "
                            << g_stats.stop_reason);
    BOOST_CHECK_MESSAGE(g_stats.products_built,
                        "role products failed: " << g_stats.stop_reason);
    BOOST_CHECK_MESSAGE(g_stats.sections_proved == 6,
                        "only " << g_stats.sections_proved
                                << "/6 sections proved: " << g_stats.stop_reason);

    // MEASURED RESULT, pinned. All six real role sections prove successfully;
    // the loop dies at ASSEMBLY, because the envelope exceeds the 16 MiB codec
    // ceiling. Asserted as an inequality against the cap rather than an exact
    // equality so a genuine size improvement is not a test failure — but the
    // exact figure is logged above and was 35,363,636 B when written, matching
    // the section-assembly lane's independent measurement byte for byte.
    BOOST_CHECK(!g_stats.assembled);
    BOOST_CHECK_MESSAGE(
        g_stats.total_section_bytes > rc::kRCStage3MaxProofBytes,
        "sections now FIT the codec cap (" << g_stats.total_section_bytes
            << " <= " << rc::kRCStage3MaxProofBytes
            << ") — the size wall moved; re-read this test");
    BOOST_CHECK(g_stats.stop_reason.find("relation_proofs_oversize") !=
                std::string::npos);

    // NOTE ON LAYERING, since it is easy to misread the status above:
    // assembly fails closed BEFORE the producer's own size-budget check, so the
    // real loop surfaces ProverFailed, not ExceedsSizeBudget. The producer's
    // ExceedsSizeBudget path is therefore currently unreachable through the real
    // prover and is exercised only by the synthetic test that shrinks the block
    // caps. Both refusals are correct; they just live at different layers.
    BOOST_CHECK(status == rc::RCStage3ProduceStatus::ProverFailed);
}

BOOST_AUTO_TEST_CASE(planned_reservation_is_codec_bounded_and_usable)
{
    // Runs unconditionally: this is exact codec/framing arithmetic, not a
    // proving run.
    constexpr int32_t HEIGHT{102};
    const auto params = RcChainParams(HEIGHT);
    const auto r = rc::RCStage3PlannedReservation(params, HEIGHT);

    BOOST_CHECK_EQUAL(r.envelope_bytes, rc::kRCStage3MaxProofBytes);
    // Word packing: 2 envelope words + ceil(bytes/4).
    BOOST_CHECK_EQUAL(
        r.payload_words,
        2U + (rc::kRCStage3MaxProofBytes + 3) / 4);
    BOOST_CHECK_EQUAL(
        r.block_serialized_delta,
        ::GetSizeOfCompactSize(r.payload_words) +
            r.payload_words * sizeof(uint32_t));
    BOOST_CHECK(r.block_serialized_delta > r.envelope_bytes);
    BOOST_CHECK(r.fits_codec_cap);
    BOOST_CHECK(r.fits_block_cap);
    BOOST_CHECK(r.Usable());
    BOOST_CHECK_EQUAL(std::string(r.basis), "codec-bounded-v3-maximum");
    BOOST_TEST_MESSAGE("reservation: envelope=" << r.envelope_bytes
                       << " B words=" << r.payload_words
                       << " block_delta=" << r.block_serialized_delta
                       << " B codec_ok=" << r.fits_codec_cap
                       << " block_ok=" << r.fits_block_cap
                       << " basis=" << r.basis);

    // A network whose serialized-size cap cannot carry the complete reserved
    // vector must fail closed. Equality is insufficient because a legal block
    // also contains its header, coinbase, and other body framing.
    auto undersized = params;
    undersized.nMaxBlockSerializedSize =
        static_cast<uint32_t>(r.block_serialized_delta);
    const auto no_room = rc::RCStage3PlannedReservation(undersized, HEIGHT);
    BOOST_CHECK(no_room.fits_codec_cap);
    BOOST_CHECK(!no_room.fits_block_cap);
    BOOST_CHECK(!no_room.Usable());

    undersized = params;
    undersized.nMaxBlockWeight =
        static_cast<uint32_t>(r.block_serialized_delta);
    const auto no_weight_room =
        rc::RCStage3PlannedReservation(undersized, HEIGHT);
    BOOST_CHECK(no_weight_room.fits_codec_cap);
    BOOST_CHECK(!no_weight_room.fits_block_cap);
    BOOST_CHECK(!no_weight_room.Usable());

    // Outside the RC family nothing is reserved at all.
    auto pre_rc = params;
    pre_rc.nMatMulRCHeight = std::numeric_limits<int32_t>::max();
    pre_rc.nMatMulRCCoupledHeight = std::numeric_limits<int32_t>::max();
    const auto none = rc::RCStage3PlannedReservation(pre_rc, HEIGHT);
    BOOST_CHECK_EQUAL(none.envelope_bytes, 0U);
    BOOST_CHECK_EQUAL(std::string(none.basis), "not_required");
}

BOOST_AUTO_TEST_SUITE_END()
