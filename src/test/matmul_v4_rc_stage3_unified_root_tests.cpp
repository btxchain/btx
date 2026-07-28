// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_composition.h>
#include <matmul/matmul_v4_rc_stage3_soundness_scenarios.h>
#include <matmul/matmul_v4_rc_stage3_unified_root.h>

#include <algorithm>
#include <string>
#include <vector>

namespace {

using namespace matmul::v4::rc;

uint256 Filled(unsigned char value)
{
    uint256 out;
    std::fill(out.begin(), out.end(), value);
    return out;
}

RCStage3SuccinctProof ComposedStatement()
{
    RCStage3SuccinctProof statement;
    statement.statement = RCStage3StatementKind::Composed;
    auto& p = statement.public_inputs;
    p.height = 91;
    p.n_bits = 0x1d00ffff;
    p.episode_profile = 2;
    p.coupled_profile = 1;
    p.transcript_version = 7;
    p.header_commitment = Filled(1);
    p.params_commitment = Filled(2);
    // The proof envelope requires a canonical program-consensus pin.  Keep
    // this fixture self-contained while making the AlgHash limb encoding
    // canonical in Goldilocks (each repeated-byte u64 is strictly below p).
    p.program_consensus_pin.recursive_alg_hash_root = Filled(8);
    p.program_consensus_pin.external_sha256d_audit_root = Filled(9);
    p.program_consensus_pin.registry_binding = Filled(10);
    p.target = Filled(3);
    p.sigma = Filled(4);
    p.episode_digest = Filled(5);
    p.coupled_digest = Filled(6);

    unsigned char value = 10;
    for (const auto role :
         RequiredRCStage3RelationRoles(statement.statement)) {
        statement.commitments.push_back({role, Filled(value++)});
        statement.sections.push_back({role, {value++, value++}});
    }
    p.final_digest = ComputeRCStage3FinalDigest(statement);
    p.transcript_commitment =
        ComputeRCStage3TranscriptCommitment(statement);
    return statement;
}

RCStage3UnifiedRootPublicPin PublicPin(
    const RCStage3SuccinctProof& statement)
{
    RCStage3UnifiedRootPublicPin pin;
    pin.statement_commitment =
        ComputeRCStage3UnifiedStatementCommitment(statement);
    pin.final_digest = statement.public_inputs.final_digest;
    pin.ctl_manifest.bus_id = 77;
    pin.ctl_manifest.transcript_seed = pin.statement_commitment;
    const auto& order = RCStage3UnifiedRoleOrder();
    for (size_t i = 0; i < order.size(); ++i) {
        RCStage3CtlParticipantSpec participant;
        participant.role = order[i];
        participant.event_count = 2;
        participant.send_count = 1;
        participant.receive_count = 1;
        participant.schedule_commitment =
            Filled(static_cast<unsigned char>(40 + i));
        pin.ctl_manifest.participants.push_back(participant);

        RCStage3CtlChildPin child;
        child.role = order[i];
        child.bus_id = pin.ctl_manifest.bus_id;
        child.event_count = participant.event_count;
        child.send_count = participant.send_count;
        child.receive_count = participant.receive_count;
        child.schedule_commitment = participant.schedule_commitment;
        child.trace_commitment =
            Filled(static_cast<unsigned char>(60 + i));
        pin.ctl_children.push_back(child);
    }
    RCStage3CtlChallenges challenges;
    BOOST_REQUIRE(DeriveRCStage3CtlChallenges(
        pin.ctl_manifest, pin.ctl_children, challenges));
    const uint256 challenge_commitment =
        CommitRCStage3CtlChallenges(challenges);
    for (size_t i = 0; i < order.size(); ++i) {
        auto& child = pin.ctl_children[i];
        child.auxiliary_commitment =
            Filled(static_cast<unsigned char>(80 + i));
        child.challenge_commitment = challenge_commitment;
        pin.roles.push_back(
            {order[i], statement.commitments[i].root,
             CommitRCStage3CtlChildPin(child)});
    }
    pin.composition_link_commitment =
        statement.commitments.back().root;
    pin.ctl_composition_commitment =
        CommitRCStage3CtlComposition(
            pin.ctl_manifest, pin.ctl_children);
    pin.soundness_manifest_commitment =
        ComputeRCStage3UnifiedSoundnessManifestCommitment();
    pin.production_site_manifest_commitment =
        ComputeRCStage3UnifiedProductionSiteManifestCommitment();
    pin.production_aggregation_schedule_commitment =
        ComputeRCStage3UnifiedProductionAggregationScheduleCommitment();
    pin.normalized_leaf_tree_commitment =
        ComputeRCStage3UnifiedNormalizedLeafTreeCommitment(pin);
    pin.recursive_proof = {1, 2, 3, 4, 5};
    pin.normalized_recursive_root_commitment =
        CommitRCStage3UnifiedRecursiveProof(pin.recursive_proof);
    return pin;
}

struct ExecutableUnifiedCtlFixture {
    RCStage3SuccinctProof statement{ComposedStatement()};
    RCStage3UnifiedRootPublicPin pin;
    RCStage3UnifiedCtlProofBundle bundle;

    ExecutableUnifiedCtlFixture()
    {
        pin.statement_commitment =
            ComputeRCStage3UnifiedStatementCommitment(statement);
        pin.final_digest = statement.public_inputs.final_digest;
        pin.ctl_manifest.bus_id = 177;
        pin.ctl_manifest.transcript_seed = pin.statement_commitment;

        const auto& order = RCStage3UnifiedRoleOrder();
        const gkr_field::Fp3 value{19, 23, 29};
        std::vector<RCStage3CtlSchedule> schedules;
        schedules.reserve(order.size());
        pin.ctl_children.resize(order.size());
        for (size_t i = 0; i < order.size(); ++i) {
            const int8_t multiplicity = (i % 2 == 0) ? 1 : -1;
            RCStage3CtlSchedule schedule;
            schedule.events.push_back(
                {901, 7, 33, multiplicity});
            schedules.push_back(schedule);

            RCStage3CtlParticipantSpec participant;
            participant.role = order[i];
            participant.event_count = 1;
            participant.send_count = multiplicity == 1 ? 1 : 0;
            participant.receive_count = multiplicity == -1 ? 1 : 0;
            participant.schedule_commitment =
                CommitRCStage3CtlSchedule(schedule);
            pin.ctl_manifest.participants.push_back(participant);

            auto& child = pin.ctl_children[i];
            child.role = order[i];
            child.bus_id = pin.ctl_manifest.bus_id;
            child.event_count = 1;
            child.send_count = participant.send_count;
            child.receive_count = participant.receive_count;
            child.schedule_commitment =
                participant.schedule_commitment;
            child.trace_commitment =
                ComputeRCStage3CtlPrechallengeTraceCommitment(
                    schedule, {value});
            BOOST_REQUIRE(!child.trace_commitment.IsNull());
        }

        RCStage3CtlChallenges challenges;
        BOOST_REQUIRE(DeriveRCStage3CtlChallenges(
            pin.ctl_manifest, pin.ctl_children, challenges));
        const uint256 challenge_commitment =
            CommitRCStage3CtlChallenges(challenges);
        bundle.children.reserve(order.size());
        for (size_t i = 0; i < order.size(); ++i) {
            const auto witness = BuildRCStage3CtlWitness(
                schedules[i], {value}, challenges);
            BOOST_REQUIRE_MESSAGE(witness.ok, witness.note);
            auto& child = pin.ctl_children[i];
            child.challenge_commitment = challenge_commitment;
            child.terminal = witness.terminal;
            const uint256 seed =
                ComputeRCStage3CtlAirSeed(pin.ctl_manifest, child);
            const auto cs = BuildRCStage3CtlConstraintSystem(
                {schedules[i], challenges, witness.terminal});
            const auto proved =
                air_quotient::AirQuotientProve<gkr_field::Fp3>(
                    cs, witness.columns, seed);
            BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
            child.auxiliary_commitment =
                ComputeRCStage3CtlAuxiliaryCommitment(proved.proof);
            BOOST_REQUIRE(!child.auxiliary_commitment.IsNull());
            pin.roles.push_back(
                {order[i], statement.commitments[i].root,
                 CommitRCStage3CtlChildPin(child)});
            RCStage3CtlRelationExportPin relation_export;
            relation_export.role = order[i];
            relation_export.bus_id = child.bus_id;
            relation_export.event_count = child.event_count;
            relation_export.relation_commitment =
                statement.commitments[i].root;
            relation_export.schedule_commitment =
                child.schedule_commitment;
            relation_export.n_rows =
                proved.proof.batch.column_len[
                    stage3_ctl_col::NAMESPACE];
            relation_export.n_coeffs =
                proved.proof.batch.n_coeffs;
            for (uint32_t column = stage3_ctl_col::NAMESPACE;
                 column <= stage3_ctl_col::MULTIPLICITY;
                 ++column) {
                relation_export.prechallenge_column_roots[column] =
                    proved.proof.batch.columns[column].root;
            }
            bundle.children.push_back(
                {order[i], relation_export, schedules[i], proved.proof});
        }

        pin.composition_link_commitment =
            statement.commitments.back().root;
        pin.ctl_composition_commitment =
            CommitRCStage3CtlComposition(
                pin.ctl_manifest, pin.ctl_children);
        BOOST_REQUIRE(!pin.ctl_composition_commitment.IsNull());
        pin.soundness_manifest_commitment =
            ComputeRCStage3UnifiedSoundnessManifestCommitment();
        pin.production_site_manifest_commitment =
            ComputeRCStage3UnifiedProductionSiteManifestCommitment();
        pin.production_aggregation_schedule_commitment =
            ComputeRCStage3UnifiedProductionAggregationScheduleCommitment();
        pin.normalized_leaf_tree_commitment =
            ComputeRCStage3UnifiedNormalizedLeafTreeCommitment(pin);
        pin.recursive_proof = {9, 8, 7};
        pin.normalized_recursive_root_commitment =
            CommitRCStage3UnifiedRecursiveProof(pin.recursive_proof);

        bundle.root_seed = ComputeRCStage3UnifiedRootSeed(pin);
        bundle.ctl_composition_commitment =
            pin.ctl_composition_commitment;
        BOOST_REQUIRE(!bundle.root_seed.IsNull());
    }
};

} // namespace

BOOST_AUTO_TEST_SUITE(matmul_v4_rc_stage3_unified_root_tests)

BOOST_AUTO_TEST_CASE(canonical_parameters_cover_exact_registry_and_soundness)
{
    const auto parameters = CanonicalRCStage3UnifiedRootParameters();
    BOOST_CHECK(parameters.topology ==
                RCStage3UnifiedTopology::NormalizedBinary16);
    BOOST_CHECK_EQUAL(parameters.aggregation_arity, 2U);
    BOOST_CHECK_EQUAL(parameters.aggregation_depth, 4U);
    BOOST_CHECK_EQUAL(parameters.role_leaf_count, 14U);
    BOOST_CHECK_EQUAL(parameters.normalized_leaf_count, 16U);
    BOOST_CHECK_EQUAL(parameters.fri_queries, kRCFri3AlgNumQueries);
    BOOST_CHECK_EQUAL(parameters.fri_repetition_lanes,
                      kRCFri3AlgDualNumLanes);
    BOOST_CHECK(
        parameters.fri_batching_mode ==
        RCStage3UnifiedFriBatchingMode::IndependentCoefficients);
    BOOST_CHECK(
        parameters.fri_commitment_scenario ==
        Fri3AlgDualCommitmentScenario::SharedMasterDerivedChildren);
    BOOST_CHECK_EQUAL(parameters.fri_queries_per_lane,
                      kRCFri3AlgDualQueriesPerLane);
    BOOST_CHECK_EQUAL(parameters.grinding_bits, kRCFriGrindingBits);
    BOOST_CHECK_EQUAL(parameters.target_soundness_bits,
                      kRCStage3UnifiedV1SecurityClassBits);
    BOOST_CHECK_EQUAL(parameters.target_soundness_bits, 64U);
    BOOST_CHECK_LT(parameters.target_soundness_bits,
                   kRCFri3AlgTargetSoundnessBits);
    BOOST_CHECK_EQUAL(parameters.soundness_union_bound_instances,
                      kRCStage3UnifiedMaxTotalProofSites);
    const auto selected_manifest =
        soundness_scenarios::BuildProductionProofSiteManifest(
            soundness_scenarios::
                SelectedProductionProofSitePolicy());
    BOOST_REQUIRE(!selected_manifest.commitment.IsNull());
    BOOST_CHECK_EQUAL(
        parameters.soundness_union_bound_instances,
        selected_manifest.union_bound_cap);
    BOOST_CHECK_EQUAL(parameters.max_recursive_air_columns, 16'384U);
    BOOST_CHECK_EQUAL(RCStage3UnifiedRootSoundnessBits(parameters), 109U);
    BOOST_CHECK_GE(RCStage3UnifiedRootSoundnessBits(parameters),
                   parameters.target_soundness_bits);

    const auto& roles = RCStage3UnifiedRoleOrder();
    BOOST_REQUIRE_EQUAL(roles.size(), 14U);
    BOOST_CHECK(roles.front() ==
                RCStage3RelationRole::EpisodeDeterministicBuilder);
    BOOST_CHECK(roles[5] == RCStage3RelationRole::EpisodeDigest);
    BOOST_CHECK(roles[6] == RCStage3RelationRole::CoupledBank);
    BOOST_CHECK(roles.back() == RCStage3RelationRole::CoupledDigest);
    BOOST_CHECK(std::find(roles.begin(), roles.end(),
                          RCStage3RelationRole::CompositionLink) ==
                roles.end());

    const auto& sites = RCStage3UnifiedSoundnessSiteManifest();
    BOOST_REQUIRE_EQUAL(sites.size(), 29U);
    for (size_t i = 0; i < 14; ++i) {
        BOOST_CHECK(
            sites[i].kind ==
            RCStage3UnifiedSoundnessSiteKind::RelationLeaf);
        BOOST_CHECK_EQUAL(sites[i].tree_level, 0U);
        BOOST_CHECK_EQUAL(sites[i].tree_index, i);
        BOOST_CHECK(sites[i].role == roles[i]);
        BOOST_CHECK_EQUAL(sites[i].fri_queries,
                          kRCFri3AlgNumQueries);
    }
    const std::array<uint16_t, 4> nodes_per_level{{8, 4, 2, 1}};
    size_t cursor = 14;
    for (uint8_t level = 1; level <= 4; ++level) {
        for (uint16_t index = 0; index < nodes_per_level[level - 1];
             ++index, ++cursor) {
            BOOST_CHECK(
                sites[cursor].kind ==
                RCStage3UnifiedSoundnessSiteKind::AggregationNode);
            BOOST_CHECK_EQUAL(sites[cursor].tree_level, level);
            BOOST_CHECK_EQUAL(sites[cursor].tree_index, index);
            BOOST_CHECK_EQUAL(sites[cursor].fri_queries,
                              kRCFri3AlgNumQueries);
        }
    }
    BOOST_CHECK_EQUAL(cursor, 29U);
    BOOST_CHECK(
        !ComputeRCStage3UnifiedSoundnessManifestCommitment().IsNull());
}

BOOST_AUTO_TEST_CASE(canonical_bounded_codec_roundtrip)
{
    const auto statement = ComposedStatement();
    const auto pin = PublicPin(statement);
    std::vector<unsigned char> encoded;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        SerializeRCStage3UnifiedRootPublicPin(pin, encoded, &why), why);
    const auto decoded =
        DeserializeRCStage3UnifiedRootPublicPin(encoded, &why);
    BOOST_REQUIRE_MESSAGE(decoded.has_value(), why);
    BOOST_CHECK(*decoded == pin);

    std::vector<unsigned char> reencoded;
    BOOST_REQUIRE(SerializeRCStage3UnifiedRootPublicPin(
        *decoded, reencoded, &why));
    BOOST_CHECK(reencoded == encoded);
    BOOST_CHECK(ValidateRCStage3UnifiedRootPublicBinding(
        statement, *decoded, &why));
    BOOST_CHECK(
        !pin.production_site_manifest_commitment.IsNull());
    BOOST_CHECK(
        !pin.production_aggregation_schedule_commitment.IsNull());

    auto changed_manifest = pin;
    changed_manifest.production_site_manifest_commitment =
        Filled(199);
    BOOST_CHECK(!ValidateRCStage3UnifiedRootStructure(
        changed_manifest, &why));
    BOOST_CHECK(
        why.find("production_site_manifest_mismatch") !=
        std::string::npos);

    auto changed_schedule = pin;
    changed_schedule.production_aggregation_schedule_commitment =
        Filled(200);
    BOOST_CHECK(!ValidateRCStage3UnifiedRootStructure(
        changed_schedule, &why));
    BOOST_CHECK(
        why.find("production_aggregation_schedule_mismatch") !=
        std::string::npos);
}

BOOST_AUTO_TEST_CASE(codec_rejects_omission_reorder_and_malformed_bytes)
{
    const auto statement = ComposedStatement();
    const auto canonical = PublicPin(statement);
    std::string why;
    std::vector<unsigned char> ignored;

    auto omitted = canonical;
    omitted.roles.pop_back();
    BOOST_CHECK(!SerializeRCStage3UnifiedRootPublicPin(
        omitted, ignored, &why));

    auto reordered = canonical;
    std::swap(reordered.roles[2], reordered.roles[3]);
    BOOST_CHECK(!SerializeRCStage3UnifiedRootPublicPin(
        reordered, ignored, &why));

    auto duplicate = canonical;
    duplicate.roles[3] = duplicate.roles[2];
    BOOST_CHECK(!SerializeRCStage3UnifiedRootPublicPin(
        duplicate, ignored, &why));

    std::vector<unsigned char> encoded;
    BOOST_REQUIRE(SerializeRCStage3UnifiedRootPublicPin(
        canonical, encoded, &why));

    auto bad_magic = encoded;
    bad_magic[0] ^= 1;
    BOOST_CHECK(!DeserializeRCStage3UnifiedRootPublicPin(
                     bad_magic, &why)
                     .has_value());

    auto reserved = encoded;
    reserved[11] = 1;
    BOOST_CHECK(!DeserializeRCStage3UnifiedRootPublicPin(
                     reserved, &why)
                     .has_value());

    auto truncated = encoded;
    truncated.pop_back();
    BOOST_CHECK(!DeserializeRCStage3UnifiedRootPublicPin(
                     truncated, &why)
                     .has_value());

    auto trailing = encoded;
    trailing.push_back(0);
    BOOST_CHECK(!DeserializeRCStage3UnifiedRootPublicPin(
                     trailing, &why)
                     .has_value());

    auto huge_proof = encoded;
    const size_t proof_size_offset =
        huge_proof.size() - canonical.recursive_proof.size() - 4;
    BOOST_REQUIRE_LE(proof_size_offset + 4, huge_proof.size());
    std::fill(huge_proof.begin() + proof_size_offset,
              huge_proof.begin() + proof_size_offset + 4, 0xff);
    BOOST_CHECK(!DeserializeRCStage3UnifiedRootPublicPin(
                     huge_proof, &why)
                     .has_value());
}

BOOST_AUTO_TEST_CASE(public_binding_rejects_every_statement_root_mutation)
{
    const auto statement = ComposedStatement();
    const auto canonical = PublicPin(statement);
    std::string why;
    BOOST_REQUIRE(ValidateRCStage3UnifiedRootPublicBinding(
        statement, canonical, &why));

    for (size_t i = 0; i < canonical.roles.size(); ++i) {
        auto changed = canonical;
        changed.roles[i].relation_commitment =
            Filled(static_cast<unsigned char>(160 + i));
        changed.normalized_leaf_tree_commitment =
            ComputeRCStage3UnifiedNormalizedLeafTreeCommitment(changed);
        BOOST_CHECK(!ValidateRCStage3UnifiedRootPublicBinding(
            statement, changed, &why));
        BOOST_CHECK(why.find("relation_commitment_mismatch") !=
                    std::string::npos);
    }

    auto link = canonical;
    link.composition_link_commitment = Filled(200);
    link.normalized_leaf_tree_commitment =
        ComputeRCStage3UnifiedNormalizedLeafTreeCommitment(link);
    BOOST_CHECK(!ValidateRCStage3UnifiedRootPublicBinding(
        statement, link, &why));
    BOOST_CHECK(why.find("composition_link_commitment_mismatch") !=
                std::string::npos);

    auto final_digest = canonical;
    final_digest.final_digest = Filled(201);
    final_digest.normalized_leaf_tree_commitment =
        ComputeRCStage3UnifiedNormalizedLeafTreeCommitment(final_digest);
    BOOST_CHECK(!ValidateRCStage3UnifiedRootPublicBinding(
        statement, final_digest, &why));
    BOOST_CHECK(why.find("final_digest_mismatch") != std::string::npos);

    auto public_input = statement;
    ++public_input.public_inputs.n_bits;
    public_input.public_inputs.transcript_commitment =
        ComputeRCStage3TranscriptCommitment(public_input);
    BOOST_CHECK(!ValidateRCStage3UnifiedRootPublicBinding(
        public_input, canonical, &why));
    BOOST_CHECK(why.find("statement_commitment_mismatch") !=
                std::string::npos);

    auto transcript = statement;
    transcript.public_inputs.transcript_commitment = Filled(202);
    BOOST_CHECK(!ValidateRCStage3UnifiedRootPublicBinding(
        transcript, canonical, &why));
    BOOST_CHECK(why.find("invalid_composition") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(seed_binds_all_public_pins_without_proof_cycle)
{
    const auto statement = ComposedStatement();
    const auto canonical = PublicPin(statement);
    const uint256 seed = ComputeRCStage3UnifiedRootSeed(canonical);

    auto parameters = canonical;
    ++parameters.parameters.fri_queries;
    BOOST_CHECK(seed != ComputeRCStage3UnifiedRootSeed(parameters));
    parameters = canonical;
    ++parameters.parameters.fri_repetition_lanes;
    BOOST_CHECK(seed != ComputeRCStage3UnifiedRootSeed(parameters));
    parameters = canonical;
    --parameters.parameters.fri_queries_per_lane;
    BOOST_CHECK(seed != ComputeRCStage3UnifiedRootSeed(parameters));
    parameters = canonical;
    parameters.parameters.fri_batching_mode =
        RCStage3UnifiedFriBatchingMode::SinglePowerChallenge;
    BOOST_CHECK(seed != ComputeRCStage3UnifiedRootSeed(parameters));
    parameters = canonical;
    parameters.parameters.fri_commitment_scenario =
        Fri3AlgDualCommitmentScenario::
            FullyDuplicatedLaneCommitments;
    BOOST_CHECK(seed != ComputeRCStage3UnifiedRootSeed(parameters));

    auto relation = canonical;
    relation.roles[4].relation_commitment = Filled(210);
    BOOST_CHECK(seed != ComputeRCStage3UnifiedRootSeed(relation));

    auto ctl_child = canonical;
    ctl_child.roles[9].ctl_child_commitment = Filled(211);
    BOOST_CHECK(seed != ComputeRCStage3UnifiedRootSeed(ctl_child));

    auto link = canonical;
    link.composition_link_commitment = Filled(212);
    BOOST_CHECK(seed != ComputeRCStage3UnifiedRootSeed(link));

    auto ctl_composition = canonical;
    ctl_composition.ctl_composition_commitment = Filled(213);
    BOOST_CHECK(seed != ComputeRCStage3UnifiedRootSeed(ctl_composition));

    auto final_digest = canonical;
    final_digest.final_digest = Filled(214);
    BOOST_CHECK(seed != ComputeRCStage3UnifiedRootSeed(final_digest));

    auto production_sites = canonical;
    production_sites.production_site_manifest_commitment = Filled(216);
    BOOST_CHECK(
        seed != ComputeRCStage3UnifiedRootSeed(production_sites));

    auto production_schedule = canonical;
    production_schedule.production_aggregation_schedule_commitment =
        Filled(217);
    BOOST_CHECK(
        seed != ComputeRCStage3UnifiedRootSeed(production_schedule));

    auto root = canonical;
    root.normalized_recursive_root_commitment = Filled(215);
    BOOST_CHECK(seed == ComputeRCStage3UnifiedRootSeed(root));

    auto proof = canonical;
    proof.recursive_proof[0] ^= 0xff;
    BOOST_CHECK(seed == ComputeRCStage3UnifiedRootSeed(proof));
    BOOST_CHECK(!ValidateRCStage3UnifiedRootStructure(proof));
}

BOOST_AUTO_TEST_CASE(exact_ctl_pins_reject_omission_reorder_substitution_and_terminal_mismatch)
{
    const auto statement = ComposedStatement();
    const auto canonical = PublicPin(statement);
    std::string why;
    BOOST_REQUIRE(ValidateRCStage3UnifiedRootStructure(canonical, &why));

    auto omitted = canonical;
    omitted.ctl_children.pop_back();
    BOOST_CHECK(!ValidateRCStage3UnifiedRootStructure(omitted, &why));
    BOOST_CHECK(why.find("ctl_participant_count") != std::string::npos);

    auto reordered = canonical;
    std::swap(reordered.ctl_children[3], reordered.ctl_children[4]);
    BOOST_CHECK(!ValidateRCStage3UnifiedRootStructure(reordered, &why));
    BOOST_CHECK(why.find("ctl_role_order") != std::string::npos);

    auto substituted = canonical;
    substituted.ctl_children[7].trace_commitment = Filled(0xe1);
    substituted.roles[7].ctl_child_commitment =
        CommitRCStage3CtlChildPin(substituted.ctl_children[7]);
    BOOST_CHECK(!ValidateRCStage3UnifiedRootStructure(substituted, &why));
    BOOST_CHECK(why.find("challenge_binding") != std::string::npos);

    auto terminal = canonical;
    terminal.ctl_children[6].terminal.alpha1_sum =
        gkr_field::Fp3::One();
    terminal.roles[6].ctl_child_commitment =
        CommitRCStage3CtlChildPin(terminal.ctl_children[6]);
    BOOST_CHECK(!ValidateRCStage3UnifiedRootStructure(terminal, &why));
    BOOST_CHECK(why.find("nonzero_terminal") != std::string::npos);

    // A fully re-bound prechallenge substitution is structurally well formed,
    // but necessarily changes the root seed and normalized leaf tree.
    auto rebound = canonical;
    rebound.ctl_children[7].trace_commitment = Filled(0xe2);
    RCStage3CtlChallenges challenges;
    BOOST_REQUIRE(DeriveRCStage3CtlChallenges(
        rebound.ctl_manifest, rebound.ctl_children, challenges, &why));
    const uint256 challenge_commitment =
        CommitRCStage3CtlChallenges(challenges);
    for (size_t i = 0; i < rebound.ctl_children.size(); ++i) {
        rebound.ctl_children[i].challenge_commitment =
            challenge_commitment;
        rebound.roles[i].ctl_child_commitment =
            CommitRCStage3CtlChildPin(rebound.ctl_children[i]);
    }
    rebound.ctl_composition_commitment =
        CommitRCStage3CtlComposition(
            rebound.ctl_manifest, rebound.ctl_children);
    rebound.normalized_leaf_tree_commitment =
        ComputeRCStage3UnifiedNormalizedLeafTreeCommitment(rebound);
    BOOST_REQUIRE(ValidateRCStage3UnifiedRootStructure(rebound, &why));
    BOOST_CHECK(
        rebound.normalized_leaf_tree_commitment !=
        canonical.normalized_leaf_tree_commitment);
    BOOST_CHECK(ComputeRCStage3UnifiedRootSeed(rebound) !=
                ComputeRCStage3UnifiedRootSeed(canonical));
}

BOOST_AUTO_TEST_CASE(normalized_tree_and_node_seeds_bind_order_and_position)
{
    const auto canonical = PublicPin(ComposedStatement());
    const uint256 root_seed =
        ComputeRCStage3UnifiedRootSeed(canonical);
    const uint256 left =
        ComputeRCStage3UnifiedRoleLeafCommitment(canonical.roles[0]);
    const uint256 right =
        ComputeRCStage3UnifiedRoleLeafCommitment(canonical.roles[1]);
    const uint256 seed = ComputeRCStage3UnifiedAggregationNodeSeed(
        root_seed, 1, 0, left, right);
    BOOST_CHECK(!seed.IsNull());
    BOOST_CHECK(seed != ComputeRCStage3UnifiedAggregationNodeSeed(
                            root_seed, 1, 0, right, left));
    BOOST_CHECK(seed != ComputeRCStage3UnifiedAggregationNodeSeed(
                            root_seed, 1, 1, left, right));
    BOOST_CHECK(seed != ComputeRCStage3UnifiedAggregationNodeSeed(
                            Filled(0xf0), 1, 0, left, right));
    BOOST_CHECK(
        ComputeRCStage3UnifiedAggregationNodeSeed(
            root_seed, 0, 0, left, right)
            .IsNull());
}

BOOST_AUTO_TEST_CASE(global_soundness_ledger_never_certifies_unaccounted_terms)
{
    const auto canonical = PublicPin(ComposedStatement());
    const auto ledger =
        AssessRCStage3UnifiedGlobalSoundness(canonical);
    BOOST_REQUIRE_EQUAL(ledger.terms.size(), 10U);
    BOOST_CHECK_EQUAL(ledger.provisional_known_term_bits, 102U);
    BOOST_CHECK_EQUAL(ledger.certified_bits, 0U);
    BOOST_CHECK(!ledger.theorem_complete);
    BOOST_CHECK(!ledger.authority_eligible);
    // Gate 3 flipped (single-lane rbr/BCS reduction machine-checked); the
    // unified ledger still certifies 0 because other terms remain incomplete.
    BOOST_CHECK(kRCFri3AlgFormalSoundnessReady);

    auto find = [&](RCStage3UnifiedSoundnessTermKind kind)
        -> const RCStage3UnifiedSoundnessTerm* {
        const auto it = std::find_if(
            ledger.terms.begin(), ledger.terms.end(),
            [&](const RCStage3UnifiedSoundnessTerm& term) {
                return term.kind == kind;
            });
        return it == ledger.terms.end() ? nullptr : &*it;
    };
    const auto* fri = find(
        RCStage3UnifiedSoundnessTermKind::FriProximityAndGrinding);
    BOOST_REQUIRE(fri != nullptr);
    BOOST_CHECK_EQUAL(fri->charged_instances,
                      kRCStage3UnifiedMaxTotalProofSites);
    BOOST_CHECK_EQUAL(fri->conservative_bits, 109U);
    BOOST_CHECK(fri->quantitatively_accounted);
    BOOST_CHECK(fri->reduction_complete);

    const auto* fri_field = find(
        RCStage3UnifiedSoundnessTermKind::FriFieldDomain);
    BOOST_REQUIRE(fri_field != nullptr);
    BOOST_CHECK_EQUAL(fri_field->conservative_bits, 102U);
    BOOST_CHECK(fri_field->quantitatively_accounted);
    BOOST_CHECK(!fri_field->reduction_complete);
    BOOST_CHECK(
        fri_field->detail.find("Definition-2") != std::string::npos);

    for (const auto kind :
         {RCStage3UnifiedSoundnessTermKind::Fp3ConstraintBatching,
          RCStage3UnifiedSoundnessTermKind::FiatShamirModel}) {
        const auto* missing = find(kind);
        BOOST_REQUIRE(missing != nullptr);
        BOOST_CHECK(!missing->quantitatively_accounted);
        BOOST_CHECK(!missing->reduction_complete);
        BOOST_CHECK_EQUAL(missing->conservative_bits, 0U);
    }
    const auto* hash = find(
        RCStage3UnifiedSoundnessTermKind::HashCollision);
    BOOST_REQUIRE(hash != nullptr);
    BOOST_CHECK_EQUAL(hash->conservative_bits, 102U);
    BOOST_CHECK(!hash->quantitatively_accounted);
    BOOST_CHECK(!hash->reduction_complete);
    const auto* pow = find(
        RCStage3UnifiedSoundnessTermKind::PowGrindingComposition);
    BOOST_REQUIRE(pow != nullptr);
    BOOST_CHECK(!pow->reduction_complete);
    const auto* global_union = find(
        RCStage3UnifiedSoundnessTermKind::GlobalFalseAcceptUnion);
    BOOST_REQUIRE(global_union != nullptr);
    BOOST_CHECK_EQUAL(global_union->conservative_bits, 0U);
    BOOST_CHECK(!global_union->quantitatively_accounted);
    BOOST_CHECK(!global_union->reduction_complete);
    BOOST_CHECK(
        global_union->detail.find("smallest individual exponent") !=
        std::string::npos);

    const auto* ctl = find(
        RCStage3UnifiedSoundnessTermKind::CtlTupleCompression);
    BOOST_REQUIRE(ctl != nullptr);
    BOOST_CHECK_EQUAL(ctl->charged_instances, 1U);
    BOOST_CHECK_EQUAL(ctl->conservative_bits, 324U);
    BOOST_CHECK(ctl->quantitatively_accounted);
    BOOST_CHECK(!ctl->reduction_complete);
    BOOST_CHECK(
        ctl->detail.find("rational-numerator") != std::string::npos);

    const auto* ctl_completeness = find(
        RCStage3UnifiedSoundnessTermKind::CtlDenominatorPoles);
    BOOST_REQUIRE(ctl_completeness != nullptr);
    BOOST_CHECK_EQUAL(ctl_completeness->charged_instances, 28U);
    BOOST_CHECK_EQUAL(ctl_completeness->conservative_bits, 142U);
    BOOST_CHECK(ctl_completeness->quantitatively_accounted);
    BOOST_CHECK(!ctl_completeness->reduction_complete);
    BOOST_CHECK(
        ctl_completeness->detail.find("not false-accept") !=
        std::string::npos);
}

BOOST_AUTO_TEST_CASE(verifier_is_explicitly_fail_closed)
{
    const auto statement = ComposedStatement();
    const auto canonical = PublicPin(statement);
    std::string why;
    BOOST_CHECK(!VerifyRCStage3UnifiedRootProof(
        statement, canonical, &why));
    BOOST_CHECK_EQUAL(
        why, "stage3:unified_root:soundness_theorem_incomplete");
    BOOST_CHECK(!kRCStage3UnifiedRootExecutable);
    BOOST_CHECK(!kRCStage3UnifiedRootAuthorityReady);
}

BOOST_AUTO_TEST_CASE(native_ctl_bundle_consumes_all_ordered_child_air_proofs)
{
    ExecutableUnifiedCtlFixture fixture;
    std::string why;
    BOOST_REQUIRE(VerifyRCStage3UnifiedCtlProofBundle(
        fixture.pin, fixture.bundle, &why));
    BOOST_CHECK(
        why.find("recursive_consumption_pending") != std::string::npos);
    BOOST_CHECK(kRCStage3UnifiedCtlNativeProofBridgeExecutable);
    BOOST_CHECK(
        kRCStage3UnifiedCtlRelationExportCommitmentBridgeExecutable);
    BOOST_CHECK(!kRCStage3UnifiedCtlRelationWitnessBindingReady);
    BOOST_CHECK(!kRCStage3UnifiedCtlRecursiveConsumptionReady);

    std::vector<unsigned char> encoded;
    BOOST_REQUIRE(SerializeRCStage3UnifiedCtlProofBundle(
        fixture.bundle, encoded, &why));
    BOOST_CHECK_LE(encoded.size(), kRCStage3UnifiedCtlBundleMaxBytes);
    const auto decoded =
        DeserializeRCStage3UnifiedCtlProofBundle(encoded, &why);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_REQUIRE(VerifyRCStage3UnifiedCtlProofBundle(
        fixture.pin, *decoded, &why));
    BOOST_CHECK(
        !CommitRCStage3UnifiedCtlProofBundle(fixture.bundle).IsNull());
}

BOOST_AUTO_TEST_CASE(native_ctl_bundle_rejects_omission_reorder_and_mutation)
{
    ExecutableUnifiedCtlFixture fixture;
    std::string why;

    auto omitted = fixture.bundle;
    omitted.children.pop_back();
    BOOST_CHECK(!VerifyRCStage3UnifiedCtlProofBundle(
        fixture.pin, omitted, &why));
    BOOST_CHECK(why.find("child_count") != std::string::npos);

    auto reordered = fixture.bundle;
    std::swap(reordered.children[0], reordered.children[1]);
    BOOST_CHECK(!VerifyRCStage3UnifiedCtlProofBundle(
        fixture.pin, reordered, &why));
    BOOST_CHECK(why.find("role_order") != std::string::npos);

    auto bad_schedule = fixture.bundle;
    ++bad_schedule.children[0].schedule.events[0].address;
    BOOST_CHECK(!VerifyRCStage3UnifiedCtlProofBundle(
        fixture.pin, bad_schedule, &why));
    BOOST_CHECK(
        why.find("manifest_pin_proof_binding") != std::string::npos);

    auto relabelled_export = fixture.bundle;
    relabelled_export.children[0].relation_export.role =
        RCStage3RelationRole::EpisodeGemm;
    BOOST_CHECK(!VerifyRCStage3UnifiedCtlProofBundle(
        fixture.pin, relabelled_export, &why));
    BOOST_CHECK(why.find("role_order") != std::string::npos);

    auto substituted_relation = fixture.bundle;
    substituted_relation.children[0]
        .relation_export.relation_commitment = Filled(0xac);
    BOOST_CHECK(!VerifyRCStage3UnifiedCtlProofBundle(
        fixture.pin, substituted_relation, &why));
    BOOST_CHECK(
        why.find("relation_export") != std::string::npos);

    auto substituted_value_root = fixture.bundle;
    substituted_value_root.children[0]
        .relation_export
        .prechallenge_column_roots[stage3_ctl_col::VALUE] =
        Filled(0xad);
    BOOST_CHECK(!VerifyRCStage3UnifiedCtlProofBundle(
        fixture.pin, substituted_value_root, &why));
    BOOST_CHECK(
        why.find("column_root") != std::string::npos);

    auto bad_proof = fixture.bundle;
    bad_proof.children[0].proof.next_openings[0][0].leaf.c0 ^=
        uint64_t{1};
    BOOST_CHECK(!VerifyRCStage3UnifiedCtlProofBundle(
        fixture.pin, bad_proof, &why));
    BOOST_CHECK(why.find("proof:") != std::string::npos);

    auto wrong_root = fixture.bundle;
    wrong_root.root_seed = Filled(0xee);
    BOOST_CHECK(!VerifyRCStage3UnifiedCtlProofBundle(
        fixture.pin, wrong_root, &why));
    BOOST_CHECK(why.find("root_seed_binding") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(native_ctl_bundle_codec_rejects_count_and_trailing_bytes)
{
    ExecutableUnifiedCtlFixture fixture;
    std::string why;
    std::vector<unsigned char> encoded;
    BOOST_REQUIRE(SerializeRCStage3UnifiedCtlProofBundle(
        fixture.bundle, encoded, &why));

    // Header child_count starts after magic/version/registry and two hashes.
    constexpr size_t child_count_offset = 4 + 2 + 2 + 32 + 32;
    auto wrong_count = encoded;
    wrong_count[child_count_offset] =
        static_cast<unsigned char>(kRCStage3UnifiedRoleCount - 1);
    BOOST_CHECK(!DeserializeRCStage3UnifiedCtlProofBundle(
                     wrong_count, &why)
                     .has_value());

    auto trailing = encoded;
    trailing.push_back(0);
    BOOST_CHECK(!DeserializeRCStage3UnifiedCtlProofBundle(
                     trailing, &why)
                     .has_value());

    auto truncated = encoded;
    truncated.pop_back();
    BOOST_CHECK(!DeserializeRCStage3UnifiedCtlProofBundle(
                     truncated, &why)
                     .has_value());

    // The first schedule count follows the bundle header, child count, role,
    // and fixed-size relation-export pin.
    // A maximum in-protocol count cannot fit in this tiny mutated envelope and
    // must be rejected from remaining bytes before allocating its event vector.
    constexpr size_t first_schedule_count_offset =
        child_count_offset + 2 + 2 +
        kRCStage3CtlRelationExportBytes;
    auto allocation_bomb = encoded;
    const uint32_t impossible_count = kRCStage3CtlMaxEvents;
    for (size_t byte = 0; byte < sizeof(impossible_count); ++byte) {
        allocation_bomb[first_schedule_count_offset + byte] =
            static_cast<unsigned char>(impossible_count >> (8 * byte));
    }
    BOOST_CHECK(!DeserializeRCStage3UnifiedCtlProofBundle(
                     allocation_bomb, &why)
                     .has_value());
}

BOOST_AUTO_TEST_SUITE_END()
