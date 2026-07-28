// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_air_quotient.h>
#include <matmul/matmul_v4_rc_air_recurse.h>
#include <matmul/matmul_v4_rc_gkr_air.h>
#include <matmul/matmul_v4_rc_stage3_recursive.h>
#include <matmul/matmul_v4_rc_stage3_composition.h>
#include <matmul/matmul_v4_rc_stage3_episode_builder_params.h>
#include <matmul/matmul_v4_rc_stage3_coupled_bank_root_binding.h>
#include <matmul/matmul_v4_rc_stage3_coupled_signed_range_binding.h>
#include <matmul/matmul_v4_rc_stage3_episode_builder_trace.h>
#include <matmul/matmul_v4_rc_stage3_episode_builder_trace_binding.h>
#include <matmul/matmul_v4_rc_stage3_episode_extract_product.h>
#include <matmul/matmul_v4_rc_stage3_episode_relation_product.h>
#include <matmul/matmul_v4_rc_stage3_episode_wiring_binding.h>
#include <matmul/matmul_v4_rc_stage3_episode_wiring_product.h>
#include <matmul/matmul_v4_rc_stage3_gemm_sumcheck_binding.h>
#include <matmul/matmul_v4_rc_stage3_extract_stream_ctl.h>
#include <matmul/matmul_v4_rc_stage3_seed_chain_binding.h>
#include <matmul/matmul_v4_rc_stage3_hash_air.h>
#include <matmul/matmul_v4_rc_stage3_production_family_programs.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>
#include <matmul/matmul_v4_rc_stage3_role_bytecode.h>
#include <matmul/matmul_v4_rc_stage3_stream_endpoint.h>

#include <hash.h>

#include <algorithm>

namespace {

using namespace matmul::v4::rc;

uint256 Filled(unsigned char value)
{
    uint256 out;
    std::fill(out.begin(), out.end(), value);
    return out;
}

RCStage3SuccinctProof Statement()
{
    RCStage3SuccinctProof statement;
    statement.statement = RCStage3StatementKind::Composed;
    auto& p = statement.public_inputs;
    p.height = 707;
    p.n_bits = 0x1d00ffff;
    p.episode_profile = 2;
    p.coupled_profile = 1;
    p.transcript_version = 7;
    p.header_commitment = Filled(1);
    p.params_commitment = Filled(2);
    p.target = Filled(3);
    p.sigma = Filled(4);
    p.episode_digest = Filled(5);
    p.coupled_digest = Filled(6);
    p.program_consensus_pin.recursive_alg_hash_root = Filled(0x08);
    p.program_consensus_pin.external_sha256d_audit_root = Filled(0x09);
    p.program_consensus_pin.registry_binding = Filled(0x0a);
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

struct Fixture {
    RCStage3SuccinctProof statement{Statement()};
    RCStage3UnifiedRootPublicPin root;
    RCStage3UnifiedCtlProofBundle ctl_bundle;
    RCStage3RelationClosureV1 closure;

    Fixture()
    {
        root.statement_commitment =
            ComputeRCStage3UnifiedStatementCommitment(statement);
        root.final_digest = statement.public_inputs.final_digest;
        root.ctl_manifest.bus_id = 407;
        root.ctl_manifest.transcript_seed = root.statement_commitment;

        const auto& order = RCStage3UnifiedRoleOrder();
        const gkr_field::Fp3 value{31, 37, 41};
        std::vector<RCStage3CtlSchedule> schedules(order.size());
        root.ctl_children.resize(order.size());
        for (size_t i = 0; i < order.size(); ++i) {
            const int8_t multiplicity = (i % 2 == 0) ? 1 : -1;
            schedules[i].events.push_back({1701, 11, 53, multiplicity});
            RCStage3CtlParticipantSpec participant;
            participant.role = order[i];
            participant.event_count = 1;
            participant.send_count = multiplicity == 1 ? 1 : 0;
            participant.receive_count = multiplicity == -1 ? 1 : 0;
            participant.schedule_commitment =
                CommitRCStage3CtlSchedule(schedules[i]);
            root.ctl_manifest.participants.push_back(participant);

            auto& child = root.ctl_children[i];
            child.role = order[i];
            child.bus_id = root.ctl_manifest.bus_id;
            child.event_count = 1;
            child.send_count = participant.send_count;
            child.receive_count = participant.receive_count;
            child.schedule_commitment = participant.schedule_commitment;
            child.trace_commitment =
                ComputeRCStage3CtlPrechallengeTraceCommitment(
                    schedules[i], {value});
            BOOST_REQUIRE(!child.trace_commitment.IsNull());
        }

        RCStage3CtlChallenges challenges;
        BOOST_REQUIRE(DeriveRCStage3CtlChallenges(
            root.ctl_manifest, root.ctl_children, challenges));
        const uint256 challenge_commitment =
            CommitRCStage3CtlChallenges(challenges);
        ctl_bundle.children.reserve(order.size());
        for (size_t i = 0; i < order.size(); ++i) {
            const auto witness =
                BuildRCStage3CtlWitness(schedules[i], {value}, challenges);
            BOOST_REQUIRE_MESSAGE(witness.ok, witness.note);
            auto& child = root.ctl_children[i];
            child.challenge_commitment = challenge_commitment;
            child.terminal = witness.terminal;
            const auto constraints = BuildRCStage3CtlConstraintSystem(
                {schedules[i], challenges, witness.terminal});
            const auto proved =
                air_quotient::AirQuotientProve<gkr_field::Fp3>(
                    constraints, witness.columns,
                    ComputeRCStage3CtlAirSeed(root.ctl_manifest, child));
            BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
            child.auxiliary_commitment =
                ComputeRCStage3CtlAuxiliaryCommitment(proved.proof);
            root.roles.push_back(
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
                proved.proof.batch.column_len[stage3_ctl_col::NAMESPACE];
            relation_export.n_coeffs = proved.proof.batch.n_coeffs;
            for (uint32_t column = stage3_ctl_col::NAMESPACE;
                 column <= stage3_ctl_col::MULTIPLICITY; ++column) {
                relation_export.prechallenge_column_roots[column] =
                    proved.proof.batch.columns[column].root;
            }
            ctl_bundle.children.push_back(
                {order[i], relation_export, schedules[i], proved.proof});
        }

        root.composition_link_commitment =
            statement.commitments.back().root;
        root.ctl_composition_commitment =
            CommitRCStage3CtlComposition(
                root.ctl_manifest, root.ctl_children);
        root.soundness_manifest_commitment =
            ComputeRCStage3UnifiedSoundnessManifestCommitment();
        root.production_site_manifest_commitment =
            ComputeRCStage3UnifiedProductionSiteManifestCommitment();
        root.production_aggregation_schedule_commitment =
            ComputeRCStage3UnifiedProductionAggregationScheduleCommitment();
        root.normalized_leaf_tree_commitment =
            ComputeRCStage3UnifiedNormalizedLeafTreeCommitment(root);
        root.recursive_proof = {4, 3, 2, 1};
        root.normalized_recursive_root_commitment =
            CommitRCStage3UnifiedRecursiveProof(root.recursive_proof);

        ctl_bundle.root_seed = ComputeRCStage3UnifiedRootSeed(root);
        ctl_bundle.ctl_composition_commitment =
            root.ctl_composition_commitment;

        closure.unified_root_seed = ctl_bundle.root_seed;
        closure.statement_commitment = root.statement_commitment;
        closure.ctl_proof_bundle_commitment =
            CommitRCStage3UnifiedCtlProofBundle(ctl_bundle);
        for (size_t i = 0; i < order.size(); ++i) {
            RCStage3RelationRoleClosure role;
            role.role = order[i];
            role.relation_commitment = root.roles[i].relation_commitment;
            role.relation_statement_root =
                Filled(static_cast<unsigned char>(80 + i));
            const uint256 fused_role_child =
                Filled(static_cast<unsigned char>(110 + i));
            const auto& required =
                RequiredRCStage3RelationEndpoints(role.role);
            for (size_t j = 0; j < required.size(); ++j) {
                RCStage3RelationEndpointPin endpoint;
                endpoint.endpoint = required[j];
                endpoint.instance_count = j + 1;
                endpoint.manifest_root =
                    Filled(static_cast<unsigned char>(10 + j));
                endpoint.proof_root =
                    Filled(static_cast<unsigned char>(30 + j));
                endpoint.semantic_root =
                    Filled(static_cast<unsigned char>(50 + j));
                endpoint.proof_column_root =
                    Filled(static_cast<unsigned char>(70 + j));
                // A role-local fused child may discharge several compatible
                // endpoints; the exact endpoint manifest remains explicit.
                endpoint.recursive_child_commitment = fused_role_child;
                role.endpoints.push_back(endpoint);
            }
            const auto exported = RCStage3RelationCtlExportEndpoint(role.role);
            auto it = std::find_if(
                role.endpoints.begin(), role.endpoints.end(),
                [exported](const auto& endpoint) {
                    return endpoint.endpoint == exported;
                });
            BOOST_REQUIRE(it != role.endpoints.end());
            it->proof_column_root =
                ctl_bundle.children[i].relation_export
                    .prechallenge_column_roots[stage3_ctl_col::VALUE];
            if (role.role == RCStage3RelationRole::EpisodeDigest) {
                it->semantic_root = statement.public_inputs.episode_digest;
            } else if (
                role.role == RCStage3RelationRole::CoupledDigest) {
                it->semantic_root = statement.public_inputs.coupled_digest;
            }
            role.endpoint_multiproof_root =
                ComputeRCStage3RelationRoleMultiproofRoot(role);
            closure.roles.push_back(role);
        }
        closure.composition_link_commitment =
            root.composition_link_commitment;
        closure.final_digest_manifest_root = Filled(201);
        closure.final_digest_proof_root = Filled(202);
        closure.final_digest_semantic_root =
            statement.public_inputs.final_digest;
        closure.final_digest_recursive_child_commitment = Filled(203);
        closure.closure_commitment =
            ComputeRCStage3RelationClosureCommitment(closure);
    }
};

} // namespace

BOOST_AUTO_TEST_SUITE(matmul_v4_rc_stage3_relation_closure_tests)

BOOST_AUTO_TEST_CASE(strategy_screen_selects_hash_bound_multiproof_v1)
{
    const auto assessments = AssessRCStage3RelationClosureStrategies();
    BOOST_REQUIRE_EQUAL(assessments.size(), 3U);
    BOOST_CHECK(
        assessments[0].strategy ==
        RCStage3RelationClosureStrategy::OneProofPerRole);
    BOOST_CHECK(assessments[0].compatible_with_current_heterogeneous_airs);
    BOOST_CHECK(
        assessments[1].strategy ==
        RCStage3RelationClosureStrategy::FusedCompatibleAir);
    BOOST_CHECK(
        !assessments[1].compatible_with_current_heterogeneous_airs);
    BOOST_CHECK(
        assessments[2].strategy ==
        RCStage3RelationClosureStrategy::HashBoundMultiproof);
    BOOST_CHECK(assessments[2].proof_derived_root_binding_possible);
    for (const auto& assessment : assessments) {
        BOOST_CHECK_EQUAL(assessment.registered_roles, 14U);
        BOOST_CHECK_EQUAL(assessment.registered_endpoints, 52U);
        BOOST_CHECK(!assessment.recursive_execution_complete);
    }
    BOOST_CHECK(kRCStage3RelationClosureRegistryComplete);
    BOOST_CHECK(kRCStage3RelationClosureCtlValueBindingExecutable);
    BOOST_CHECK(!kRCStage3RelationClosureRecursiveChildrenExecutable);
    BOOST_CHECK(!kRCStage3RelationClosureAuthorityReady);

    const auto audit = CurrentRCStage3RelationClosureRoleAudit();
    BOOST_REQUIRE_EQUAL(audit.size(), 14U);
    uint16_t endpoints = 0;
    uint16_t proof_derived_ctl = 0;
    for (size_t i = 0; i < audit.size(); ++i) {
        BOOST_CHECK(audit[i].role == RCStage3UnifiedRoleOrder()[i]);
        BOOST_CHECK(!audit[i].recursive_ctl_consumption);
        BOOST_CHECK(!audit[i].role_complete);
        endpoints += audit[i].required_endpoints;
        proof_derived_ctl += audit[i].proof_derived_ctl_endpoints;
    }
    BOOST_CHECK_EQUAL(endpoints, 52U);
    BOOST_CHECK_EQUAL(proof_derived_ctl, 28U);

    const auto cells = CurrentRCStage3RelationEndpointCellAudit();
    BOOST_REQUIRE_EQUAL(cells.size(), 52U);
    uint16_t relation_cells = 0;
    uint16_t same_trace_aliases = 0;
    uint16_t semantic_complete = 0;
    uint16_t producer_complete = 0;
    uint16_t strict_transitive_complete = 0;
    uint16_t recursively_consumed = 0;
    for (const auto& cell : cells) {
        relation_cells += cell.relation_air_cell;
        same_trace_aliases += cell.same_trace_ctl_alias;
        semantic_complete += cell.semantic_relation_complete;
        producer_complete += cell.producer_provenance_complete;
        strict_transitive_complete +=
            cell.strict_transitive_complete;
        recursively_consumed += cell.recursive_child_consumed;
        BOOST_CHECK(!cell.remaining.empty());
    }
    BOOST_CHECK_EQUAL(relation_cells, 28U);
    BOOST_CHECK_EQUAL(same_trace_aliases, 28U);
    // Blocker A COMPLETE: 28 (four builder-program exports + 23 scalar-cell
    // exports, including all four canonical ExtractCore producer lanes, plus
    // signed range) + 19
    // stream/digest §4 pins + 3 value-vector openings (BuilderParams,
    // ExtractInput, ExtractScale) + 8 wired sibling bindings (BuilderTrace,
    // GemmSumcheck, SeedChain, Wiring{Transpose,Residual,RoundOrder}, BankRoot,
    // CoupledGemmSignedRange) => 52/52.
    BOOST_CHECK_EQUAL(semantic_complete, 52U);
    BOOST_CHECK_EQUAL(RCStage3CommitmentOpeningEndpointCount(), 21U);
    BOOST_CHECK_EQUAL(RCStage3StreamOpeningEndpointCount(), 19U);
    BOOST_CHECK_EQUAL(RCStage3VectorOpeningEndpointCount(), 3U);
    BOOST_CHECK_EQUAL(RCStage3WiredBindingEndpointCount(), 8U);
    // 52/52 is local relation/opening coverage, not transitive episode
    // computation closure.  Only the two verifier-regenerated public anchors
    // terminate without another producer relation.
    BOOST_CHECK_EQUAL(producer_complete, 2U);
    BOOST_CHECK_EQUAL(strict_transitive_complete, 2U);
    BOOST_CHECK_EQUAL(recursively_consumed, 0U);
    // Every one of the 52 endpoints now has an opening/binding.
    BOOST_CHECK_EQUAL(21U + 19U + 3U + 8U + 1U, 52U);
    BOOST_CHECK(kRCStage3RelationClosureSameTraceCtlAliasExecutable);
    // Recursive-child consumption remains a separate fail-closed gate.
    BOOST_CHECK(!kRCStage3RelationClosureRecursiveChildrenExecutable);
    BOOST_CHECK(!kRCStage3RelationClosureAuthorityReady);
}

BOOST_AUTO_TEST_CASE(
    episode_gemm_cell_and_ctl_value_are_one_proved_trace_not_opaque_roots)
{
    namespace aq = air_quotient;
    namespace gf = gkr_field;
    constexpr uint32_t N = 8;
    const auto statement = Statement();

    std::vector<std::vector<gf::Fp3>> relation_columns(
        3, std::vector<gf::Fp3>(N));
    const gf::Fp3 a = gf::Fp3::FromFp(2);
    const gf::Fp3 b = gf::Fp3::FromFp(3);
    const gf::Fp3 product = gf::Mul(a, b);
    for (uint32_t row = 0; row < N; ++row) {
        relation_columns[0][row] = product;
        relation_columns[1][row] = a;
        relation_columns[2][row] = b;
    }

    RCStage3CtlSchedule send_schedule;
    RCStage3CtlSchedule receive_schedule;
    std::vector<gf::Fp3> values(N, product);
    for (uint32_t row = 0; row < N; ++row) {
        send_schedule.events.push_back({901, 7, row, 1});
        receive_schedule.events.push_back({901, 7, row, -1});
    }

    RCStage3CtlManifest manifest;
    manifest.bus_id = 909;
    manifest.transcript_seed =
        RCStage3EpisodeStatementCommitment(statement);
    manifest.participants = {
        {RCStage3RelationRole::EpisodeGemm, N, N, 0,
         CommitRCStage3CtlSchedule(send_schedule)},
        {RCStage3RelationRole::CompositionLink, N, 0, N,
         CommitRCStage3CtlSchedule(receive_schedule)},
    };
    std::vector<RCStage3CtlChildPin> pins(2);
    pins[0].role = RCStage3RelationRole::EpisodeGemm;
    pins[1].role = RCStage3RelationRole::CompositionLink;
    for (size_t i = 0; i < pins.size(); ++i) {
        auto& pin = pins[i];
        const auto& participant = manifest.participants[i];
        const auto& schedule =
            i == 0 ? send_schedule : receive_schedule;
        pin.bus_id = manifest.bus_id;
        pin.event_count = participant.event_count;
        pin.send_count = participant.send_count;
        pin.receive_count = participant.receive_count;
        pin.schedule_commitment = participant.schedule_commitment;
        pin.trace_commitment =
            ComputeRCStage3CtlPrechallengeTraceCommitment(
                schedule, values);
        BOOST_REQUIRE(!pin.trace_commitment.IsNull());
    }
    RCStage3CtlChallenges challenges;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        DeriveRCStage3CtlChallenges(manifest, pins, challenges, &why), why);
    const auto send =
        BuildRCStage3CtlWitness(send_schedule, values, challenges);
    const auto receive =
        BuildRCStage3CtlWitness(receive_schedule, values, challenges);
    BOOST_REQUIRE_MESSAGE(send.ok, send.note);
    BOOST_REQUIRE_MESSAGE(receive.ok, receive.note);
    pins[0].terminal = send.terminal;
    pins[1].terminal = receive.terminal;
    const uint256 challenge_commitment =
        CommitRCStage3CtlChallenges(challenges);
    pins[0].challenge_commitment = challenge_commitment;
    pins[1].challenge_commitment = challenge_commitment;
    // Derivation only consumes epoch-one roots. The participant placeholder
    // is replaced by the shared proof's exact postchallenge commitment below.
    pins[0].auxiliary_commitment = Filled(0xd1);
    pins[1].auxiliary_commitment = Filled(0xd2);
    BOOST_CHECK(gf::IsZero(gf::Add(
        pins[0].terminal.alpha1_sum, pins[1].terminal.alpha1_sum)));
    BOOST_CHECK(gf::IsZero(gf::Add(
        pins[0].terminal.alpha2_sum, pins[1].terminal.alpha2_sum)));

    RCStage3EpisodeAirPublicPin episode_pin;
    episode_pin.role = RCStage3RelationRole::EpisodeGemm;
    episode_pin.family =
        RCStage3EpisodeAirFamily::GemmEndpointFp3V1;
    episode_pin.statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    episode_pin.shard_count = 1;
    episode_pin.logical_rows = N;
    episode_pin.n_rows = N;
    episode_pin.n_coeffs = N;
    episode_pin.column_roots = {{0, Filled(1)},
                                {1, Filled(2)},
                                {2, Filled(3)}};

    aq::AirConstraintSystem<gf::Fp3> relation_cs;
    BOOST_REQUIRE_MESSAGE(
        ResolveRCStage3EpisodeAirConstraintSystem(
            statement, episode_pin, relation_cs, &why),
        why);
    RCStage3CtlAirSpec ctl_spec{
        send_schedule, challenges, send.terminal};
    aq::AirConstraintSystem<gf::Fp3> combined;
    RCStage3RelationCtlDirectAliasLayout layout;
    BOOST_REQUIRE_MESSAGE(
        BuildRCStage3RelationCtlDirectAliasConstraintSystem(
            relation_cs, ctl_spec, 0, combined, &layout, &why),
        why);
    BOOST_CHECK(layout.same_trace);
    BOOST_CHECK(layout.direct_alias);
    BOOST_CHECK_EQUAL(layout.relation_columns, 3U);
    BOOST_CHECK_EQUAL(layout.ctl_column_base, 3U);
    BOOST_CHECK_EQUAL(layout.total_columns,
                      3U + stage3_ctl_col::NUM_COLUMNS);
    BOOST_CHECK_EQUAL(combined.constraints.size(), 14U);
    BOOST_CHECK_EQUAL(combined.QuotientLen(), 21U);

    const uint32_t product_coeffs =
        FriNextPow2(std::max(combined.n_rows, combined.QuotientLen()));
    for (uint32_t column = 0; column < relation_columns.size(); ++column) {
        episode_pin.column_roots[column].root =
            aq::AirCommittedValuesRoot<gf::Fp3>(
                relation_columns[column], product_coeffs);
        relation_cs.preprocessed_roots[column].second =
            episode_pin.column_roots[column].root;
    }
    BOOST_REQUIRE_MESSAGE(
        BuildRCStage3RelationCtlDirectAliasConstraintSystem(
            relation_cs, ctl_spec, 0, combined, &layout, &why),
        why);
    std::vector<std::vector<gf::Fp3>> combined_columns;
    BOOST_REQUIRE_MESSAGE(
        BuildRCStage3RelationCtlDirectAliasWitness(
            layout, relation_columns, send, combined_columns, &why),
        why);
    const uint256 relation_seed =
        ComputeRCStage3EpisodeAirSeed(statement, episode_pin);
    const uint256 seed =
        ComputeRCStage3RelationCtlDirectAliasSeed(
            RCStage3RelationEndpoint::EpisodeGemmOutputY,
            relation_seed, send_schedule, challenges,
            send.terminal, 0);
    BOOST_REQUIRE(!seed.IsNull());
    const auto proved =
        aq::AirQuotientProve<gf::Fp3>(
            combined, combined_columns, seed);
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_REQUIRE(proved.division_exact);
    BOOST_CHECK_EQUAL(proved.proof.batch.n_coeffs, 32U);
    BOOST_CHECK_EQUAL(proved.proof.batch.columns.size(), 13U);
    pins[0].auxiliary_commitment =
        ComputeRCStage3RelationCtlDirectAliasAuxiliaryCommitment(
            proved.proof, layout);
    BOOST_REQUIRE(!pins[0].auxiliary_commitment.IsNull());
    BOOST_REQUIRE_MESSAGE(
        VerifyRCStage3EpisodeEndpointCtlDirectAliasProof(
            statement,
            RCStage3RelationEndpoint::EpisodeGemmOutputY,
            episode_pin, manifest, pins, 0, send_schedule,
            proved.proof, &why),
        why);
    BOOST_CHECK(why.find("same_trace_ctl_value") != std::string::npos);
    BOOST_CHECK(static_cast<bool>(
        proved.proof.batch.columns[layout.source_column].root ==
        proved.proof.batch.columns[layout.ctl_value_column].root));

    auto detached_auxiliary = pins;
    detached_auxiliary[0].auxiliary_commitment = Filled(0xd1);
    BOOST_CHECK(!VerifyRCStage3EpisodeEndpointCtlDirectAliasProof(
        statement,
        RCStage3RelationEndpoint::EpisodeGemmOutputY,
        episode_pin, manifest, detached_auxiliary, 0,
        send_schedule, proved.proof, &why));
    BOOST_CHECK(
        why.find("ctl_auxiliary_commitment") !=
        std::string::npos);

    auto detached = relation_columns;
    detached[0][3] = gf::Add(detached[0][3], gf::Fp3::One());
    BOOST_CHECK(!BuildRCStage3RelationCtlDirectAliasWitness(
        layout, detached, send, combined_columns, &why));
    BOOST_CHECK(why.find("value_mismatch") != std::string::npos);

    auto wrong_endpoint = RCStage3RelationEndpoint::EpisodeGemmOperandA;
    BOOST_CHECK(!VerifyRCStage3EpisodeEndpointCtlDirectAliasProof(
        statement, wrong_endpoint, episode_pin, manifest, pins, 0,
        send_schedule, proved.proof, &why));
    BOOST_CHECK(why.find("source_value_root") != std::string::npos);

    auto root_substitution = episode_pin;
    root_substitution.column_roots[0].root = Filled(0xe1);
    BOOST_CHECK(!VerifyRCStage3EpisodeEndpointCtlDirectAliasProof(
        statement,
        RCStage3RelationEndpoint::EpisodeGemmOutputY,
        root_substitution, manifest, pins, 0, send_schedule,
        proved.proof, &why));
    BOOST_CHECK(why.find("relation_column_root") !=
                std::string::npos);

    auto trace_substitution = pins;
    trace_substitution[0].trace_commitment = Filled(0xe2);
    BOOST_CHECK(!VerifyRCStage3EpisodeEndpointCtlDirectAliasProof(
        statement,
        RCStage3RelationEndpoint::EpisodeGemmOutputY,
        episode_pin, manifest, trace_substitution, 0, send_schedule,
        proved.proof, &why));
    BOOST_CHECK(why.find("challenge") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(
    canonical_builder_program_exports_all_four_endpoints_to_same_trace_ctl)
{
    namespace aq = air_quotient;
    namespace cb = constraint_bytecode;
    namespace gf = gkr_field;
    namespace pf = universal_topology;
    namespace sites = soundness_scenarios;
    constexpr uint32_t N = 8;

    cb::ProgramTable table;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        pf::BuildCanonicalProductionFamilyProgramTableV1(
            sites::ProductionProofSiteKind::
                EpisodeBuilderCounterXof,
            RCStage3RelationRole::EpisodeDeterministicBuilder,
            table, &why),
        why);
    BOOST_REQUIRE_EQUAL(table.current_width, 21U);
    BOOST_REQUIRE_EQUAL(table.challenge_width, 0U);

    std::vector<std::vector<gf::Fp3>> relation_columns(
        table.current_width,
        std::vector<gf::Fp3>(N, gf::Fp3::Zero()));
    for (uint32_t row = 0; row < N; ++row) {
        relation_columns[0][row] = gf::FromSigned3(-7);
        relation_columns[1][row] = gf::FromU64_3(2);
        relation_columns[2][row] = gf::Fp3::Zero();
        relation_columns[3][row] = gf::Fp3::One();
        relation_columns[4][row] = gf::FromU64_3(4);
        relation_columns[5][row] = gf::FromSigned3(-28);
        for (const auto [base, value] : {
                 std::pair{6U, 11U},
                 std::pair{11U, 17U},
                 std::pair{16U, 23U}}) {
            relation_columns[base][row] = gf::Fp3::One();
            relation_columns[base + 2][row] =
                gf::FromU64_3(value);
            relation_columns[base + 3][row] =
                gf::FromU64_3(value);
            relation_columns[base + 4][row] =
                gf::FromU64_3(value);
        }
    }

    RCStage3BuilderProgramAirPublicPinV1 pin;
    pin.statement_commitment =
        RCStage3EpisodeStatementCommitment(Statement());
    pin.n_rows = N;
    const auto keys =
        cb::CommitProgramTableForExternalAndRecursiveUse(table);
    BOOST_REQUIRE(keys.same_canonical_serialization);
    pin.program_external_sha256d = keys.external_sha256d;
    pin.program_recursive_alg_hash = keys.recursive_alg_hash;
    pin.relation_column_roots.resize(table.current_width);
    const uint32_t n_coeffs =
        FriNextPow2(3 * N - 3);
    for (uint32_t column = 0;
         column < relation_columns.size(); ++column) {
        pin.relation_column_roots[column] =
            aq::AirCommittedValuesRoot<gf::Fp3>(
                relation_columns[column], n_coeffs);
    }

    const std::array<RCStage3RelationEndpoint, 4> endpoints{
        RCStage3RelationEndpoint::EpisodeBuilderParams,
        RCStage3RelationEndpoint::EpisodeBuilderSeedChain,
        RCStage3RelationEndpoint::EpisodeBuilderOperandXof,
        RCStage3RelationEndpoint::EpisodeBuilderTrace,
    };
    const std::array<uint32_t, 4> source_columns{
        pf::production_family_col_v1::EpisodeBuilderParams,
        pf::production_family_col_v1::EpisodeBuilderSeedChain,
        pf::production_family_col_v1::EpisodeBuilderOperandXof,
        pf::production_family_col_v1::EpisodeBuilderTrace,
    };
    std::array<RCStage3BuilderProgramCtlLaneV1, 4> lanes;
    std::array<RCStage3CtlWitness, 4> witnesses;
    for (uint32_t lane_index = 0;
         lane_index < lanes.size(); ++lane_index) {
        auto& lane = lanes[lane_index];
        lane.endpoint = endpoints[lane_index];
        RCStage3CtlSchedule receive_schedule;
        const std::vector<gf::Fp3> values(
            relation_columns[source_columns[lane_index]].begin(),
            relation_columns[source_columns[lane_index]].end());
        for (uint32_t row = 0; row < N; ++row) {
            lane.schedule.events.push_back(
                {2200U + lane_index, 17, row, 1});
            receive_schedule.events.push_back(
                {2200U + lane_index, 17, row, -1});
        }
        lane.manifest.bus_id = 2300U + lane_index;
        lane.manifest.transcript_seed =
            pin.statement_commitment;
        lane.manifest.participants = {
            {RCStage3RelationRole::EpisodeDeterministicBuilder,
             N, N, 0,
             CommitRCStage3CtlSchedule(lane.schedule)},
            {RCStage3RelationRole::CompositionLink,
             N, 0, N,
             CommitRCStage3CtlSchedule(receive_schedule)},
        };
        lane.pins.resize(2);
        for (uint32_t participant_index = 0;
             participant_index < 2;
             ++participant_index) {
            auto& child = lane.pins[participant_index];
            const auto& participant =
                lane.manifest.participants[participant_index];
            const auto& schedule =
                participant_index == 0
                ? lane.schedule
                : receive_schedule;
            child.role = participant.role;
            child.bus_id = lane.manifest.bus_id;
            child.event_count = participant.event_count;
            child.send_count = participant.send_count;
            child.receive_count = participant.receive_count;
            child.schedule_commitment =
                participant.schedule_commitment;
            child.trace_commitment =
                ComputeRCStage3CtlPrechallengeTraceCommitment(
                    schedule, values);
            BOOST_REQUIRE(!child.trace_commitment.IsNull());
        }
        RCStage3CtlChallenges challenges;
        BOOST_REQUIRE_MESSAGE(
            DeriveRCStage3CtlChallenges(
                lane.manifest, lane.pins,
                challenges, &why),
            why);
        witnesses[lane_index] =
            BuildRCStage3CtlWitness(
                lane.schedule, values, challenges);
        const auto receive =
            BuildRCStage3CtlWitness(
                receive_schedule, values, challenges);
        BOOST_REQUIRE_MESSAGE(
            witnesses[lane_index].ok,
            witnesses[lane_index].note);
        BOOST_REQUIRE_MESSAGE(receive.ok, receive.note);
        const uint256 challenge_commitment =
            CommitRCStage3CtlChallenges(challenges);
        lane.pins[0].terminal =
            witnesses[lane_index].terminal;
        lane.pins[1].terminal = receive.terminal;
        lane.pins[0].challenge_commitment =
            challenge_commitment;
        lane.pins[1].challenge_commitment =
            challenge_commitment;
        lane.pins[0].auxiliary_commitment =
            Filled(static_cast<unsigned char>(
                0xc0 + lane_index));
        lane.pins[1].auxiliary_commitment =
            Filled(static_cast<unsigned char>(
                0xd0 + lane_index));
    }

    aq::AirConstraintSystem<gf::Fp3> cs;
    RCStage3BuilderProgramCtlDirectAliasLayoutV1 layout;
    BOOST_REQUIRE_MESSAGE(
        BuildRCStage3BuilderProgramCtlDirectAliasConstraintSystemV1(
            pin, lanes, cs, &layout, &why),
        why);
    BOOST_CHECK(layout.canonical_program_selected);
    BOOST_CHECK(layout.all_four_same_trace);
    BOOST_CHECK_EQUAL(layout.relation_columns, 21U);
    BOOST_CHECK_EQUAL(layout.total_columns, 57U);
    std::vector<std::vector<gf::Fp3>> columns;
    BOOST_REQUIRE_MESSAGE(
        BuildRCStage3BuilderProgramCtlDirectAliasWitnessV1(
            layout, relation_columns, witnesses,
            columns, &why),
        why);
    const uint256 seed =
        ComputeRCStage3BuilderProgramCtlDirectAliasSeedV1(
            pin, lanes);
    BOOST_REQUIRE(!seed.IsNull());
    const auto proved =
        aq::AirQuotientProve<gf::Fp3>(
            cs, columns, seed);
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_REQUIRE(proved.division_exact);
    for (uint32_t lane_index = 0;
         lane_index < lanes.size(); ++lane_index) {
        lanes[lane_index].pins[0].auxiliary_commitment =
            ComputeRCStage3RelationCtlDirectAliasAuxiliaryCommitment(
                proved.proof, layout.lanes[lane_index]);
        BOOST_REQUIRE(
            !lanes[lane_index]
                 .pins[0]
                 .auxiliary_commitment.IsNull());
    }
    BOOST_REQUIRE_MESSAGE(
        VerifyRCStage3BuilderProgramCtlDirectAliasProofV1(
            pin, lanes, proved.proof, &why),
        why);
    BOOST_TEST_MESSAGE(
        "PROOF-LEVEL builder four-endpoint same-trace accept: rows="
        << cs.n_rows << " cols=" << cs.n_columns
        << " constraints=" << cs.constraints.size()
        << " n_coeffs=" << proved.proof.batch.n_coeffs);

    auto detached_aux = lanes;
    detached_aux[2].pins[0].auxiliary_commitment =
        Filled(0xe1);
    BOOST_CHECK(
        !VerifyRCStage3BuilderProgramCtlDirectAliasProofV1(
            pin, detached_aux, proved.proof, &why));
    BOOST_CHECK(
        why.find("ctl_auxiliary_commitment") !=
        std::string::npos);

    auto forged_columns = columns;
    forged_columns[
        layout.lanes[1].ctl_value_column][3] =
        gf::Add(
            forged_columns[
                layout.lanes[1].ctl_value_column][3],
            gf::Fp3::One());
    aq::AirProveOptions adversarial;
    adversarial.force_commit_on_inexact = true;
    const auto forged =
        aq::AirQuotientProve<gf::Fp3>(
            cs, forged_columns, seed, adversarial);
    BOOST_REQUIRE_MESSAGE(forged.ok, forged.note);
    BOOST_CHECK(!forged.division_exact);
    BOOST_CHECK(
        !aq::AirQuotientVerify<gf::Fp3>(
            cs, forged.proof, seed, &why));
    BOOST_TEST_MESSAGE(
        "PROOF-LEVEL forged BuilderSeedChain CTL VALUE rejected: "
        << why);
}

BOOST_AUTO_TEST_CASE(
    canonical_gemm_and_range_programs_build_four_dual_port_bus_relations)
{
    namespace aq = air_quotient;
    namespace cb = constraint_bytecode;
    namespace gf = gkr_field;
    namespace pf = universal_topology;
    namespace sites = soundness_scenarios;

    RCEpisodeParams params;
    params.rounds = 1;
    params.d_head = 32;
    params.n_q = 32;
    params.n_ctx = 32;
    params.L_lyr = 1;
    params.d_model = 32;
    params.d_ff = 32;
    params.b_seq = 32;
    params.T_leaf = 32;
    const auto trace_layout = RCGkrTraceLayout(params);
    std::vector<RCStage3GemmExtractLayerBindings> bindings(
        trace_layout.layers.size());
    for (uint32_t layer = 0;
         layer < bindings.size(); ++layer) {
        auto& binding = bindings[layer];
        binding.extract_prf = Filled(0x11 + layer);
        binding.operand_a_root = Filled(0x21 + layer);
        binding.operand_b_root = Filled(0x31 + layer);
        binding.gemm_y_root = Filled(0x41 + layer);
        binding.extract_input_root = Filled(0x51 + layer);
        binding.extract_output_root = Filled(0x61 + layer);
        binding.gemm_proof_root = Filled(0x71 + layer);
        binding.extract_recursive_root = Filled(0x81 + layer);
        binding.scale_schedule_root = Filled(0x91 + layer);
        binding.ctl_terminal_root = Filled(0xa1 + layer);
    }
    std::string why;
    const uint256 statement_commitment =
        RCStage3EpisodeStatementCommitment(Statement());
    const auto built_manifest =
        BuildRCStage3GemmExtractManifest(
            params, statement_commitment,
            bindings, &why);
    BOOST_REQUIRE_MESSAGE(
        built_manifest.has_value(), why);
    const auto& manifest = *built_manifest;
    auto range_pin =
        MakeRCStage3SignedRangePin(
            manifest, 0, 0, &why);
    BOOST_REQUIRE_MESSAGE(range_pin.has_value(), why);
    const uint32_t N = range_pin->n_rows;
    BOOST_REQUIRE_EQUAL(N, 1024U);

    std::vector<int64_t> signed_values(
        range_pin->logical_rows);
    for (uint32_t row = 0;
         row < signed_values.size(); ++row) {
        const int64_t magnitude =
            static_cast<int64_t>(
                row % (range_pin->max_abs + 1));
        signed_values[row] =
            row % 3 == 0 ? -magnitude : magnitude;
    }
    std::vector<std::vector<gf::Fp3>> range_columns;
    BOOST_REQUIRE_MESSAGE(
        BuildRCStage3SignedRangeColumns(
            *range_pin, signed_values,
            range_columns, &why),
        why);
    constexpr uint32_t RANGE_MAX_ABS =
        kRCStage3SignedRangeColumns;
    constexpr uint32_t RANGE_MAX_BITS =
        RANGE_MAX_ABS + 1;
    constexpr uint32_t RANGE_LOGICAL_ROWS =
        RANGE_MAX_BITS + kRCStage3SignedRangeBits;
    range_columns.resize(
        RANGE_LOGICAL_ROWS + 1,
        std::vector<gf::Fp3>(
            N, gf::Fp3::Zero()));
    for (uint32_t row = 0; row < N; ++row) {
        range_columns[RANGE_MAX_ABS][row] =
            gf::FromU64_3(range_pin->max_abs);
        range_columns[RANGE_LOGICAL_ROWS][row] =
            gf::FromU64_3(range_pin->logical_rows);
        for (uint32_t bit = 0;
             bit < kRCStage3SignedRangeBits;
             ++bit) {
            range_columns[RANGE_MAX_BITS + bit][row] =
                gf::FromU64_3(
                    (range_pin->max_abs >> bit) & 1U);
        }
    }

    std::vector<std::vector<gf::Fp3>> gemm_columns(
        3, std::vector<gf::Fp3>(
               N, gf::Fp3::Zero()));
    for (uint32_t row = 0; row < N; ++row) {
        gemm_columns[1][row] = gf::FromU64_3(3);
        gemm_columns[2][row] = gf::FromU64_3(5);
        gemm_columns[0][row] = gf::FromU64_3(15);
    }
    const uint32_t n_coeffs =
        FriNextPow2(3 * N - 3);
    for (uint32_t column = 0;
         column < kRCStage3SignedRangeColumns;
         ++column) {
        range_pin->column_roots[column].root =
            aq::AirCommittedValuesRoot<gf::Fp3>(
                range_columns[column], n_coeffs);
    }

    cb::ProgramTable gemm_table;
    cb::ProgramTable range_table;
    BOOST_REQUIRE_MESSAGE(
        pf::BuildCanonicalProductionFamilyProgramTableV1(
            sites::ProductionProofSiteKind::
                EpisodeGemmSumcheck,
            RCStage3RelationRole::EpisodeGemm,
            gemm_table, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        pf::BuildCanonicalProductionFamilyProgramTableV1(
            sites::ProductionProofSiteKind::
                EpisodeSignedRange,
            RCStage3RelationRole::EpisodeGemm,
            range_table, &why),
        why);
    RCStage3EpisodeGemmProgramAirPublicPinV1 pin;
    pin.statement_commitment = statement_commitment;
    pin.n_rows = N;
    pin.layer_ordinal = 0;
    const auto gemm_keys =
        cb::CommitProgramTableForExternalAndRecursiveUse(
            gemm_table);
    const auto range_keys =
        cb::CommitProgramTableForExternalAndRecursiveUse(
            range_table);
    BOOST_REQUIRE(gemm_keys.same_canonical_serialization);
    BOOST_REQUIRE(range_keys.same_canonical_serialization);
    pin.gemm_program_external_sha256d =
        gemm_keys.external_sha256d;
    pin.gemm_program_recursive_alg_hash =
        gemm_keys.recursive_alg_hash;
    pin.range_program_external_sha256d =
        range_keys.external_sha256d;
    pin.range_program_recursive_alg_hash =
        range_keys.recursive_alg_hash;
    for (uint32_t column = 0; column < 3; ++column) {
        pin.gemm_column_roots[column] =
            aq::AirCommittedValuesRoot<gf::Fp3>(
                gemm_columns[column], n_coeffs);
    }

    const std::array<RCStage3RelationEndpoint, 4> endpoints{
        RCStage3RelationEndpoint::EpisodeGemmOperandA,
        RCStage3RelationEndpoint::EpisodeGemmOperandB,
        RCStage3RelationEndpoint::EpisodeGemmOutputY,
        RCStage3RelationEndpoint::EpisodeGemmSignedRange,
    };
    const std::array<uint32_t, 4> source_columns{
        1, 2, 0,
        3 + kRCStage3RangeValue,
    };
    std::vector<std::vector<gf::Fp3>> relation_columns =
        gemm_columns;
    relation_columns.insert(
        relation_columns.end(),
        range_columns.begin(), range_columns.end());
    std::array<RCStage3EpisodeGemmProgramCtlLaneV1, 4>
        lanes;
    std::array<RCStage3CtlWitness, 4> producer_witnesses;
    std::array<RCStage3CtlWitness, 4> consumer_witnesses;
    const uint32_t shard_ordinal =
        RCStage3SignedRangeGlobalShardOrdinal(
            manifest, *range_pin);
    BOOST_REQUIRE_NE(
        shard_ordinal,
        std::numeric_limits<uint32_t>::max());
    for (uint32_t lane_index = 0;
         lane_index < lanes.size(); ++lane_index) {
        auto& lane = lanes[lane_index];
        lane.endpoint = endpoints[lane_index];
        const auto producer =
            BuildRCStage3EpisodeGemmProgramCtlScheduleV1(
                manifest, *range_pin,
                lane.endpoint, true);
        const auto consumer =
            BuildRCStage3EpisodeGemmProgramCtlScheduleV1(
                manifest, *range_pin,
                lane.endpoint, false);
        BOOST_REQUIRE(!producer.events.empty());
        BOOST_REQUIRE_EQUAL(
            producer.events.size(),
            consumer.events.size());
        lane.manifest.bus_id =
            kRCStage3EpisodeGemmProgramBatchBusBaseV1 +
            shard_ordinal * lanes.size() + lane_index;
        lane.manifest.transcript_seed =
            ComputeRCStage3EpisodeGemmProgramCtlTranscriptSeedV1(
                manifest, *range_pin, lane.endpoint);
        lane.manifest.participants = {
            {RCStage3RelationRole::EpisodeGemm,
             producer.events.size(),
             producer.events.size(), 0,
             CommitRCStage3CtlSchedule(producer)},
            {RCStage3RelationRole::CompositionLink,
             consumer.events.size(), 0,
             consumer.events.size(),
             CommitRCStage3CtlSchedule(consumer)},
        };
        const std::vector<gf::Fp3> values(
            relation_columns[source_columns[lane_index]].begin(),
            relation_columns[source_columns[lane_index]].begin() +
                producer.events.size());
        for (uint32_t participant_index = 0;
             participant_index < 2;
             ++participant_index) {
            const auto& participant =
                lane.manifest.participants[
                    participant_index];
            auto& child = lane.pins[participant_index];
            child.role = participant.role;
            child.bus_id = lane.manifest.bus_id;
            child.event_count = participant.event_count;
            child.send_count = participant.send_count;
            child.receive_count =
                participant.receive_count;
            child.schedule_commitment =
                participant.schedule_commitment;
            child.trace_commitment =
                ComputeRCStage3CtlPrechallengeTraceCommitment(
                    participant_index == 0
                        ? producer : consumer,
                    values);
            BOOST_REQUIRE(!child.trace_commitment.IsNull());
        }
        RCStage3CtlChallenges challenges;
        BOOST_REQUIRE_MESSAGE(
            DeriveRCStage3CtlChallenges(
                lane.manifest,
                {lane.pins[0], lane.pins[1]},
                challenges, &why),
            why);
        producer_witnesses[lane_index] =
            BuildRCStage3CtlWitness(
                producer, values, challenges);
        consumer_witnesses[lane_index] =
            BuildRCStage3CtlWitness(
                consumer, values, challenges);
        BOOST_REQUIRE_MESSAGE(
            producer_witnesses[lane_index].ok,
            producer_witnesses[lane_index].note);
        BOOST_REQUIRE_MESSAGE(
            consumer_witnesses[lane_index].ok,
            consumer_witnesses[lane_index].note);
        lane.pins[0].terminal =
            producer_witnesses[lane_index].terminal;
        lane.pins[1].terminal =
            consumer_witnesses[lane_index].terminal;
        const uint256 challenge_commitment =
            CommitRCStage3CtlChallenges(challenges);
        lane.pins[0].challenge_commitment =
            challenge_commitment;
        lane.pins[1].challenge_commitment =
            challenge_commitment;
        lane.pins[0].auxiliary_commitment =
            Filled(0xc0 + lane_index);
        lane.pins[1].auxiliary_commitment =
            Filled(0xd0 + lane_index);
    }
    // Commit-then-challenge ordering: both sides of one equality link absorb
    // the same two prechallenge trace commitments and therefore share exactly
    // one Fp3 challenge tuple.  The endpoint-tagged transcript seed differs
    // across links, so no A/B/Y/range challenge tuple is reused.
    for (uint32_t lane = 0; lane < lanes.size(); ++lane) {
        BOOST_CHECK(
            lanes[lane].pins[0].challenge_commitment ==
            lanes[lane].pins[1].challenge_commitment);
    }
    for (uint32_t left = 0; left < lanes.size(); ++left) {
        for (uint32_t right = left + 1;
             right < lanes.size(); ++right) {
            BOOST_CHECK(
                lanes[left].pins[0].challenge_commitment !=
                lanes[right].pins[0].challenge_commitment);
        }
    }

    aq::AirConstraintSystem<gf::Fp3> cs;
    RCStage3EpisodeGemmProgramCtlDirectAliasLayoutV1 layout;
    BOOST_REQUIRE_MESSAGE(
        BuildRCStage3EpisodeGemmProgramCtlDirectAliasConstraintSystemV1(
            manifest, *range_pin, pin, lanes,
            cs, &layout, &why),
        why);
    BOOST_CHECK(layout.canonical_programs_selected);
    BOOST_CHECK(layout.manifest_context_bound);
    BOOST_CHECK(layout.all_four_dual_port_bus_relations);
    BOOST_CHECK(!layout.consumer_relation_programs_included);
    BOOST_CHECK(!layout.consumer_arithmetic_owned);
    BOOST_CHECK(!layout.recursive_children_consumed);
    BOOST_CHECK(!layout.semantic_closure);
    BOOST_CHECK_EQUAL(layout.relation_columns, 105U);
    BOOST_CHECK_EQUAL(layout.total_columns, 177U);
    BOOST_CHECK_EQUAL(cs.QuotientLen(), 3 * N - 3);
    std::vector<std::vector<gf::Fp3>> columns;
    BOOST_REQUIRE_MESSAGE(
        BuildRCStage3EpisodeGemmProgramCtlDirectAliasWitnessV1(
            layout, gemm_columns, range_columns,
            producer_witnesses, consumer_witnesses,
            columns, &why),
        why);
    const uint256 seed =
        ComputeRCStage3EpisodeGemmProgramCtlDirectAliasSeedV1(
            manifest, *range_pin, pin, lanes);
    BOOST_REQUIRE(!seed.IsNull());
    const auto proved =
        aq::AirQuotientProve<gf::Fp3>(
            cs, columns, seed);
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_REQUIRE(proved.division_exact);
    for (uint32_t lane_index = 0;
         lane_index < lanes.size(); ++lane_index) {
        lanes[lane_index].pins[0].auxiliary_commitment =
            ComputeRCStage3RelationCtlDirectAliasAuxiliaryCommitment(
                proved.proof,
                layout.producer_lanes[lane_index]);
        BOOST_REQUIRE(
            !lanes[lane_index]
                 .pins[0]
                 .auxiliary_commitment.IsNull());
        lanes[lane_index].pins[1].auxiliary_commitment =
            ComputeRCStage3RelationCtlDirectAliasAuxiliaryCommitment(
                proved.proof,
                layout.consumer_lanes[lane_index]);
        BOOST_REQUIRE(
            !lanes[lane_index]
                 .pins[1]
                 .auxiliary_commitment.IsNull());
    }
    BOOST_REQUIRE_MESSAGE(
        VerifyRCStage3EpisodeGemmProgramCtlDirectAliasProofV1(
            manifest, *range_pin, pin, lanes,
            proved.proof, &why),
        why);
    BOOST_TEST_MESSAGE(
        "PROOF-LEVEL GEMM A/B/Y/range dual-port same-trace accept: rows="
        << cs.n_rows << " cols=" << cs.n_columns
        << " constraints=" << cs.constraints.size()
        << " n_coeffs=" << proved.proof.batch.n_coeffs);

    // RESIDUAL, exhibited rather than hidden: the opposite CTL accumulator is
    // proof-owned, but an independent consumer relation is not an input to
    // this product.  Changing such an unattached relation claim therefore
    // cannot change verification.  This acceptance is intentional evidence
    // that the construction is a dual-port bus relation only and MUST NOT
    // increment consumer-semantic or recursive-closure accounting.
    std::array<std::vector<gf::Fp3>, 4>
        unattached_consumer_relation_values;
    for (uint32_t lane_index = 0;
         lane_index < lanes.size(); ++lane_index) {
        const auto& source =
            relation_columns[source_columns[lane_index]];
        unattached_consumer_relation_values[lane_index].assign(
            source.begin(), source.end());
    }
    unattached_consumer_relation_values[2][17] =
        gf::Add(
            unattached_consumer_relation_values[2][17],
            gf::Fp3::One());
    BOOST_CHECK(
        !gf::Eq(
            unattached_consumer_relation_values[2][17],
            relation_columns[source_columns[2]][17]));
    BOOST_CHECK_MESSAGE(
        VerifyRCStage3EpisodeGemmProgramCtlDirectAliasProofV1(
            manifest, *range_pin, pin, lanes,
            proved.proof, &why),
        why);
    BOOST_TEST_MESSAGE(
        "EVIDENCE-ONLY residual: unattached consumer arithmetic is outside "
        "the dual-port bus proof; semantic_closure remains false");

    auto detached_aux = lanes;
    detached_aux[0].pins[1].auxiliary_commitment =
        Filled(0xee);
    BOOST_CHECK(
        !VerifyRCStage3EpisodeGemmProgramCtlDirectAliasProofV1(
            manifest, *range_pin, pin, detached_aux,
            proved.proof, &why));
    BOOST_CHECK(
        why.find("ctl_auxiliary_commitment") !=
        std::string::npos);

    auto forged_columns = columns;
    forged_columns[
        layout.consumer_lanes[2].ctl_value_column][17] =
        gf::Add(
            forged_columns[
                layout.consumer_lanes[2].ctl_value_column][17],
            gf::Fp3::One());
    aq::AirProveOptions adversarial;
    adversarial.force_commit_on_inexact = true;
    const auto forged =
        aq::AirQuotientProve<gf::Fp3>(
            cs, forged_columns, seed, adversarial);
    BOOST_REQUIRE_MESSAGE(forged.ok, forged.note);
    BOOST_CHECK(!forged.division_exact);
    BOOST_CHECK(
        !aq::AirQuotientVerify<gf::Fp3>(
            cs, forged.proof, seed, &why));
    BOOST_TEST_MESSAGE(
        "PROOF-LEVEL forged GEMM-Y consumer CTL VALUE rejected: "
        << why);
}

BOOST_AUTO_TEST_CASE(
    canonical_extract_program_proves_four_producer_bus_relations)
{
    namespace aq = air_quotient;
    namespace air = gkr_air;
    namespace cb = constraint_bytecode;
    namespace gf = gkr_field;

    const auto statement = Statement();
    air::TilePublic tile_public;
    std::array<uint8_t, 32> prf_bytes{};
    for (uint32_t i = 0; i < prf_bytes.size(); ++i) {
        prf_bytes[i] =
            static_cast<uint8_t>(17U * 7U + i * 31U + 1U);
    }
    tile_public.prf_key = uint256{
        Span<const unsigned char>{
            prf_bytes.data(), prf_bytes.size()}};
    tile_public.i = 0;
    tile_public.bj = 0;
    std::array<int64_t, kRCMxBlockLen> input{};
    for (uint32_t i = 0; i < input.size(); ++i) {
        const int64_t value =
            1000 + static_cast<int64_t>(i) * 977;
        input[i] = i % 3 == 0 ? -value : value;
    }
    input[5] = int64_t{1} << 40;
    input[9] = -(int64_t{1} << 45);
    const air::TileWitness tile =
        air::TraceTile(tile_public, input);
    const auto next_power_of_two = [](uint32_t value) {
        uint32_t out = 1;
        while (out < value) out <<= 1;
        return out;
    };
    const uint32_t N = next_power_of_two(
        std::max<uint32_t>(
            static_cast<uint32_t>(tile.cands.size()),
            kRCMxBlockLen + 1));

    RCStage3EpisodeExtractProgramAirPublicPinV1 pin;
    auto& episode = pin.episode_air;
    episode.role = RCStage3RelationRole::EpisodeExtract;
    episode.family =
        RCStage3EpisodeAirFamily::ExtractSamplerCoreFp3V1;
    episode.statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    episode.shard_index = 0;
    episode.shard_count = 1;
    episode.logical_rows =
        static_cast<uint32_t>(tile.cands.size());
    episode.n_rows = N;
    episode.n_coeffs =
        next_power_of_two(3 * N - 3);
    episode.extract_scale_e = tile.scale_e;
    for (uint32_t column = 0;
         column < aq::kRcSamplerNumCols;
         ++column) {
        episode.column_roots.push_back(
            {column,
             Filled(static_cast<unsigned char>(
                 0x20U + column))});
    }
    const uint256 episode_seed =
        ComputeRCStage3EpisodeAirSeed(
            statement, episode);
    BOOST_REQUIRE(!episode_seed.IsNull());
    const air::TableTM tm;
    const auto instance =
        aq::BuildRcSamplerInstance<gf::Fp3>(
            tile, tm, episode_seed);
    BOOST_REQUIRE_MESSAGE(instance.ok, instance.note);
    BOOST_REQUIRE_EQUAL(instance.n_rows, N);
    BOOST_REQUIRE_EQUAL(
        instance.columns.size(),
        aq::kRcSamplerNumCols);
    BOOST_REQUIRE_EQUAL(
        instance.cs.QuotientLen(), 3 * N - 3);
    for (uint32_t column = 0;
         column < aq::kRcSamplerNumCols;
         ++column) {
        episode.column_roots[column].root =
            aq::AirCommittedValuesRoot<gf::Fp3>(
                instance.columns[column],
                episode.n_coeffs);
    }
    BOOST_REQUIRE(
        ComputeRCStage3EpisodeAirSeed(
            statement, episode) == episode_seed);

    cb::ProgramTable table;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        BuildRCStage3EpisodeExtractLocalKernelProgramTable(
            episode.extract_scale_e, table, &why),
        why);
    const auto keys =
        cb::CommitProgramTableForExternalAndRecursiveUse(
            table);
    BOOST_REQUIRE(keys.same_canonical_serialization);
    pin.program_external_sha256d =
        keys.external_sha256d;
    pin.program_recursive_alg_hash =
        keys.recursive_alg_hash;

    const std::array<RCStage3RelationEndpoint, 4>
        endpoints{
            RCStage3RelationEndpoint::EpisodeExtractInput,
            RCStage3RelationEndpoint::EpisodeExtractSampler,
            RCStage3RelationEndpoint::EpisodeExtractScale,
            RCStage3RelationEndpoint::EpisodeExtractOutput,
        };
    const std::array<uint32_t, 4> source_columns{
        aq::kColUMix,
        aq::kColMixed,
        aq::kColE0,
        aq::kColOut,
    };
    std::array<RCStage3EpisodeExtractProgramCtlLaneV1, 4>
        lanes;
    std::array<RCStage3CtlWitness, 4>
        producer_witnesses;
    for (uint32_t lane_index = 0;
         lane_index < lanes.size(); ++lane_index) {
        auto& lane = lanes[lane_index];
        lane.endpoint = endpoints[lane_index];
        const auto producer =
            BuildRCStage3EpisodeExtractProgramCtlScheduleV1(
                pin, lane.endpoint, true);
        const auto counterparty =
            BuildRCStage3EpisodeExtractProgramCtlScheduleV1(
                pin, lane.endpoint, false);
        BOOST_REQUIRE_EQUAL(producer.events.size(), N);
        BOOST_REQUIRE_EQUAL(
            counterparty.events.size(), N);
        lane.manifest.bus_id =
            kRCStage3EpisodeExtractProgramBatchBusBaseV1 +
            episode.shard_index * lanes.size() +
            lane_index;
        lane.manifest.transcript_seed =
            ComputeRCStage3EpisodeExtractProgramCtlTranscriptSeedV1(
                pin, lane.endpoint);
        lane.manifest.participants = {
            {RCStage3RelationRole::EpisodeExtract,
             producer.events.size(),
             producer.events.size(), 0,
             CommitRCStage3CtlSchedule(producer)},
            {RCStage3RelationRole::CompositionLink,
             counterparty.events.size(), 0,
             counterparty.events.size(),
             CommitRCStage3CtlSchedule(counterparty)},
        };
        const auto& values =
            instance.columns[source_columns[lane_index]];
        for (uint32_t participant_index = 0;
             participant_index < lane.pins.size();
             ++participant_index) {
            const auto& participant =
                lane.manifest.participants[
                    participant_index];
            auto& child =
                lane.pins[participant_index];
            child.role = participant.role;
            child.bus_id = lane.manifest.bus_id;
            child.event_count = participant.event_count;
            child.send_count = participant.send_count;
            child.receive_count =
                participant.receive_count;
            child.schedule_commitment =
                participant.schedule_commitment;
            child.trace_commitment =
                ComputeRCStage3CtlPrechallengeTraceCommitment(
                    participant_index == 0
                        ? producer : counterparty,
                    values);
            BOOST_REQUIRE(!child.trace_commitment.IsNull());
        }
        RCStage3CtlChallenges challenges;
        BOOST_REQUIRE_MESSAGE(
            DeriveRCStage3CtlChallenges(
                lane.manifest,
                {lane.pins[0], lane.pins[1]},
                challenges, &why),
            why);
        producer_witnesses[lane_index] =
            BuildRCStage3CtlWitness(
                producer, values, challenges);
        const auto counterparty_witness =
            BuildRCStage3CtlWitness(
                counterparty, values, challenges);
        BOOST_REQUIRE_MESSAGE(
            producer_witnesses[lane_index].ok,
            producer_witnesses[lane_index].note);
        BOOST_REQUIRE_MESSAGE(
            counterparty_witness.ok,
            counterparty_witness.note);
        lane.pins[0].terminal =
            producer_witnesses[lane_index].terminal;
        lane.pins[1].terminal =
            counterparty_witness.terminal;
        const uint256 challenge_commitment =
            CommitRCStage3CtlChallenges(challenges);
        lane.pins[0].challenge_commitment =
            challenge_commitment;
        lane.pins[1].challenge_commitment =
            challenge_commitment;
        lane.pins[0].auxiliary_commitment =
            Filled(static_cast<unsigned char>(
                0xc0U + lane_index));
        // Counterparty postchallenge columns are intentionally outside this
        // producer proof. This is a prechallenge pin, not a fake consumer
        // accumulator or a semantic-closure claim.
        lane.pins[1].auxiliary_commitment =
            Filled(static_cast<unsigned char>(
                0xd0U + lane_index));
    }
    for (uint32_t left = 0;
         left < lanes.size(); ++left) {
        BOOST_CHECK(
            lanes[left].pins[0].challenge_commitment ==
            lanes[left].pins[1].challenge_commitment);
        for (uint32_t right = left + 1;
             right < lanes.size(); ++right) {
            BOOST_CHECK(
                lanes[left].pins[0].challenge_commitment !=
                lanes[right].pins[0].challenge_commitment);
        }
    }

    aq::AirConstraintSystem<gf::Fp3> cs;
    RCStage3EpisodeExtractProgramCtlDirectAliasLayoutV1
        layout;
    BOOST_REQUIRE_MESSAGE(
        BuildRCStage3EpisodeExtractProgramCtlDirectAliasConstraintSystemV1(
            statement, pin, lanes, cs, &layout, &why),
        why);
    BOOST_CHECK(layout.canonical_program_selected);
    BOOST_CHECK(layout.verifier_scale_bound);
    BOOST_CHECK(layout.all_four_producer_same_trace);
    BOOST_CHECK(!layout.chacha_provenance_included);
    BOOST_CHECK(!layout.recursive_children_consumed);
    BOOST_CHECK(!layout.role_complete);
    BOOST_CHECK_EQUAL(
        layout.relation_columns,
        aq::kRcSamplerNumCols);
    BOOST_CHECK_EQUAL(
        layout.total_columns,
        aq::kRcSamplerNumCols +
            4 * stage3_ctl_col::NUM_COLUMNS);
    BOOST_CHECK_EQUAL(
        cs.QuotientLen(), 3 * N - 3);
    std::vector<std::vector<gf::Fp3>> columns;
    BOOST_REQUIRE_MESSAGE(
        BuildRCStage3EpisodeExtractProgramCtlDirectAliasWitnessV1(
            layout, instance.columns,
            producer_witnesses, columns, &why),
        why);
    const uint256 seed =
        ComputeRCStage3EpisodeExtractProgramCtlDirectAliasSeedV1(
            statement, pin, lanes);
    BOOST_REQUIRE(!seed.IsNull());
    const auto proved =
        aq::AirQuotientProve<gf::Fp3>(
            cs, columns, seed);
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_REQUIRE(proved.division_exact);
    for (uint32_t lane_index = 0;
         lane_index < lanes.size(); ++lane_index) {
        lanes[lane_index]
            .pins[0]
            .auxiliary_commitment =
            ComputeRCStage3RelationCtlDirectAliasAuxiliaryCommitment(
                proved.proof,
                layout.producer_lanes[lane_index]);
        BOOST_REQUIRE(
            !lanes[lane_index]
                 .pins[0]
                 .auxiliary_commitment.IsNull());
    }
    BOOST_REQUIRE_MESSAGE(
        VerifyRCStage3EpisodeExtractProgramCtlDirectAliasProofV1(
            statement, pin, lanes,
            proved.proof, &why),
        why);
    BOOST_TEST_MESSAGE(
        "PROOF-LEVEL Extract Input/Sampler/Scale/Output producer accept: "
        "rows=" << cs.n_rows
        << " cols=" << cs.n_columns
        << " constraints=" << cs.constraints.size()
        << " n_coeffs=" << proved.proof.batch.n_coeffs);

    // The opposite side contributes only its prechallenge trace commitment.
    // Its postchallenge auxiliary receipt is deliberately not claimed by
    // this producer product, so changing that detached field must not be
    // misreported as consumer execution or role closure.
    auto unattached_counterparty_aux = lanes;
    unattached_counterparty_aux[0]
        .pins[1]
        .auxiliary_commitment = Filled(0xec);
    BOOST_CHECK_MESSAGE(
        VerifyRCStage3EpisodeExtractProgramCtlDirectAliasProofV1(
            statement, pin, unattached_counterparty_aux,
            proved.proof, &why),
        why);
    BOOST_TEST_MESSAGE(
        "EVIDENCE-ONLY residual: counterparty postchallenge receipt is "
        "outside the Extract producer proof; role_complete remains false");

    auto detached_aux = lanes;
    detached_aux[0].pins[0].auxiliary_commitment =
        Filled(0xee);
    BOOST_CHECK(
        !VerifyRCStage3EpisodeExtractProgramCtlDirectAliasProofV1(
            statement, pin, detached_aux,
            proved.proof, &why));
    BOOST_CHECK(
        why.find("ctl_auxiliary_commitment") !=
        std::string::npos);

    auto forged_columns = columns;
    forged_columns[
        layout.producer_lanes[2].ctl_value_column][17] =
        gf::Add(
            forged_columns[
                layout.producer_lanes[2]
                    .ctl_value_column][17],
            gf::Fp3::One());
    aq::AirProveOptions adversarial;
    adversarial.force_commit_on_inexact = true;
    const auto forged =
        aq::AirQuotientProve<gf::Fp3>(
            cs, forged_columns, seed, adversarial);
    BOOST_REQUIRE_MESSAGE(forged.ok, forged.note);
    BOOST_CHECK(!forged.division_exact);
    BOOST_CHECK(
        !aq::AirQuotientVerify<gf::Fp3>(
            cs, forged.proof, seed, &why));
    BOOST_TEST_MESSAGE(
        "PROOF-LEVEL forged Extract Scale CTL VALUE rejected: "
        << why);

    auto wrong_scale = pin;
    wrong_scale.episode_air.extract_scale_e =
        static_cast<uint8_t>(
            (episode.extract_scale_e + 1U) & 3U);
    BOOST_CHECK(
        !BuildRCStage3EpisodeExtractProgramCtlDirectAliasConstraintSystemV1(
            statement, wrong_scale, lanes,
            cs, nullptr, &why));
    BOOST_CHECK(
        why.find("program_key_scale_or_shape") !=
        std::string::npos);
    cb::ProgramTable wrong_scale_table;
    BOOST_REQUIRE(
        BuildRCStage3EpisodeExtractLocalKernelProgramTable(
            wrong_scale.episode_air.extract_scale_e,
            wrong_scale_table, &why));
    const auto wrong_scale_keys =
        cb::CommitProgramTableForExternalAndRecursiveUse(
            wrong_scale_table);
    wrong_scale.program_external_sha256d =
        wrong_scale_keys.external_sha256d;
    wrong_scale.program_recursive_alg_hash =
        wrong_scale_keys.recursive_alg_hash;
    BOOST_CHECK(
        !BuildRCStage3EpisodeExtractProgramCtlDirectAliasConstraintSystemV1(
            statement, wrong_scale, lanes,
            cs, nullptr, &why));
    BOOST_CHECK(
        why.find("canonical_lane") !=
        std::string::npos);

    auto wrong_domain = lanes;
    wrong_domain[1].manifest.transcript_seed =
        Filled(0xed);
    BOOST_CHECK(
        !BuildRCStage3EpisodeExtractProgramCtlDirectAliasConstraintSystemV1(
            statement, pin, wrong_domain,
            cs, nullptr, &why));
    BOOST_CHECK(
        why.find("canonical_lane") !=
        std::string::npos);
    auto wrong_endpoint = lanes;
    wrong_endpoint[1].endpoint =
        RCStage3RelationEndpoint::EpisodeExtractInput;
    BOOST_CHECK(
        !BuildRCStage3EpisodeExtractProgramCtlDirectAliasConstraintSystemV1(
            statement, pin, wrong_endpoint,
            cs, nullptr, &why));
    BOOST_CHECK(
        why.find("canonical_lane") !=
        std::string::npos);
    auto omitted = lanes;
    omitted[3] = {};
    BOOST_CHECK(
        !BuildRCStage3EpisodeExtractProgramCtlDirectAliasConstraintSystemV1(
            statement, pin, omitted,
            cs, nullptr, &why));
    BOOST_CHECK(
        why.find("canonical_lane") !=
        std::string::npos);
    auto reordered = lanes;
    std::swap(reordered[0], reordered[1]);
    BOOST_CHECK(
        !BuildRCStage3EpisodeExtractProgramCtlDirectAliasConstraintSystemV1(
            statement, pin, reordered,
            cs, nullptr, &why));
    BOOST_CHECK(
        why.find("canonical_lane") !=
        std::string::npos);

    auto aliased_relation = instance.columns;
    BOOST_REQUIRE_LE(
        aliased_relation[aq::kColE0][0].c0,
        std::numeric_limits<uint32_t>::max());
    aliased_relation[aq::kColE0][0].c0 +=
        gf::kP;
    BOOST_CHECK(
        !BuildRCStage3EpisodeExtractProgramCtlDirectAliasWitnessV1(
            layout, aliased_relation,
            producer_witnesses, columns, &why));
    BOOST_CHECK(
        why.find("noncanonical_relation_cell") !=
        std::string::npos);
    auto aliased_ctl = producer_witnesses;
    BOOST_REQUIRE_LT(
        aliased_ctl[0]
            .columns[stage3_ctl_col::NAMESPACE][0]
            .c0,
        gf::kP);
    aliased_ctl[0]
        .columns[stage3_ctl_col::NAMESPACE][0]
        .c0 += gf::kP;
    BOOST_CHECK(
        !BuildRCStage3EpisodeExtractProgramCtlDirectAliasWitnessV1(
            layout, instance.columns,
            aliased_ctl, columns, &why));
    BOOST_CHECK(
        why.find("noncanonical_ctl_cell") !=
        std::string::npos);

    // Upgrade endpoint 14 only: append the exact selected-row producer CTL
    // under the challenge of an EXECUTED endpoint-19 semantic-memory receiver.
    // The other three producer lanes remain explicit residuals.
    RCEpisodeParams params;
    params.rounds = 1;
    params.d_head = 32;
    params.n_q = 32;
    params.n_ctx = 32;
    params.L_lyr = 1;
    params.d_model = 32;
    params.d_ff = 32;
    params.b_seq = 32;
    params.T_leaf = 64;
    const auto trace_layout = RCGkrTraceLayout(params);
    std::vector<RCStage3GemmExtractLayerBindings> bindings(
        trace_layout.layers.size());
    for (uint32_t layer_index = 0;
         layer_index < bindings.size(); ++layer_index) {
        auto& binding = bindings[layer_index];
        binding.extract_prf = tile_public.prf_key;
        binding.operand_a_root =
            Filled(0x20 + layer_index);
        binding.operand_b_root =
            Filled(0x30 + layer_index);
        binding.gemm_y_root =
            Filled(0x40 + layer_index);
        binding.extract_input_root =
            Filled(0x50 + layer_index);
        binding.extract_output_root =
            Filled(0x60 + layer_index);
        binding.gemm_proof_root =
            Filled(0x70 + layer_index);
        binding.extract_recursive_root =
            Filled(0x80 + layer_index);
        binding.scale_schedule_root =
            Filled(0x90 + layer_index);
        binding.ctl_terminal_root =
            Filled(0xa0 + layer_index);
    }
    const auto built_manifest =
        BuildRCStage3GemmExtractManifest(
            params,
            RCStage3EpisodeStatementCommitment(statement),
            bindings, &why);
    BOOST_REQUIRE_MESSAGE(
        built_manifest.has_value(), why);
    const auto streamed = std::find_if(
        built_manifest->layers.begin(),
        built_manifest->layers.end(),
        [](const auto& layer) {
            return RCStage3EpisodeLayerIsStreamed(
                layer.kind);
        });
    BOOST_REQUIRE(streamed !=
        built_manifest->layers.end());
    const uint32_t streamed_layer =
        static_cast<uint32_t>(
            streamed - built_manifest->layers.begin());

    RCStage3EpisodeExtractTileProduct extract_tile;
    extract_tile.global_tile = 0;
    extract_tile.layer_ordinal = streamed_layer;
    extract_tile.layer_tile_index = 0;
    extract_tile.input = input;
    extract_tile.sampler_pin = episode;
    RCStage3EpisodeExtractProduct extract_product;
    extract_product.collection_commitment =
        Filled(0xa1);
    extract_product.tiles.push_back(extract_tile);

    RCStage3EpisodeTileStreamProduct stream_product;
    stream_product.collection_commitment =
        Filled(0xa2);
    RCStage3EpisodeTileStreamShard stream_tile;
    stream_tile.global_stream_tile = 0;
    stream_tile.layer_ordinal = streamed_layer;
    stream_tile.layer_tile_index = 0;
    stream_tile.stream_byte_begin = 0;
    stream_tile.pin = episode;
    stream_product.tiles.push_back(stream_tile);
    stream_product.rounds.resize(1);
    stream_product.rounds[0].round_index = 0;
    auto& stream_bytes =
        stream_product.rounds[0]
            .tree.tree_manifest.stream;
    std::vector<gf::Fp3> memory_values;
    for (int8_t value : tile.out) {
        stream_bytes.push_back(
            static_cast<uint8_t>(value));
        memory_values.push_back(
            gf::Fp3::FromFp(
                gf::FromSigned(value)));
    }
    const auto memory_root =
        ComputeRCStage3EpisodeSemanticValueRoot(
            memory_values, kRCMxBlockLen,
            kRCMxBlockLen, &why);
    BOOST_REQUIRE_MESSAGE(
        memory_root.has_value(), why);
    const auto memory_manifest =
        BuildRCStage3EpisodeSemanticMemoryManifest(
            RCStage3RelationEndpoint::
                EpisodeTileTreeStream,
            episode.statement_commitment,
            kRCMxBlockLen, kRCMxBlockLen,
            UINT64_C(0x4553000000000000), 1,
            *memory_root, &why);
    BOOST_REQUIRE_MESSAGE(
        memory_manifest.has_value(), why);
    RCStage3EpisodeSemanticMemoryShard memory_shard;
    memory_shard.manifest = *memory_manifest;
    stream_product.rounds[0]
        .stream_memory.shards.push_back(
            memory_shard);

    RCStage3ExtractStreamCtlTileProof receiver;
    BOOST_REQUIRE_MESSAGE(
        ProveRCStage3ExtractStreamCtlTile(
            statement, *built_manifest,
            extract_product, stream_product,
            0, receiver, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        VerifyRCStage3ExtractStreamCtlTile(
            statement, *built_manifest,
            extract_product, stream_product,
            0, receiver, &why),
        why);

    aq::AirConstraintSystem<gf::Fp3> receiver_cs;
    RCStage3EpisodeExtractOutputReceiverLayoutV1
        receiver_layout;
    BOOST_REQUIRE_MESSAGE(
        BuildRCStage3EpisodeExtractOutputReceiverConstraintSystemV1(
            statement, pin, lanes,
            *built_manifest, extract_product,
            stream_product, 0, receiver,
            receiver_cs, &receiver_layout, &why),
        why);
    BOOST_CHECK(
        receiver_layout.receiver_proof_executed);
    BOOST_CHECK(
        receiver_layout.exact_selected_schedule);
    BOOST_CHECK(
        receiver_layout.output_source_same_trace);
    BOOST_CHECK(
        receiver_layout.shared_dual_fp3_challenges);
    BOOST_CHECK(
        receiver_layout.opposing_terminals);
    BOOST_CHECK_EQUAL(
        receiver_layout.total_columns,
        layout.total_columns + 6);
    std::vector<std::vector<gf::Fp3>>
        receiver_columns;
    BOOST_REQUIRE_MESSAGE(
        BuildRCStage3EpisodeExtractOutputReceiverWitnessV1(
            receiver_layout, instance.columns,
            producer_witnesses, receiver,
            receiver_columns, &why),
        why);
    const uint256 receiver_seed =
        ComputeRCStage3EpisodeExtractOutputReceiverSeedV1(
            statement, pin, lanes, receiver);
    BOOST_REQUIRE(!receiver_seed.IsNull());
    const auto receiver_proved =
        aq::AirQuotientProve<gf::Fp3>(
            receiver_cs, receiver_columns,
            receiver_seed);
    BOOST_REQUIRE_MESSAGE(
        receiver_proved.ok,
        receiver_proved.note);
    BOOST_REQUIRE(receiver_proved.division_exact);
    for (uint32_t lane_index = 0;
         lane_index < lanes.size(); ++lane_index) {
        lanes[lane_index]
            .pins[0]
            .auxiliary_commitment =
            ComputeRCStage3RelationCtlDirectAliasAuxiliaryCommitment(
                receiver_proved.proof,
                receiver_layout.producer
                    .producer_lanes[lane_index]);
    }
    RCStage3EpisodeExtractOutputReceiverAuditV1
        receiver_audit;
    BOOST_REQUIRE_MESSAGE(
        VerifyRCStage3EpisodeExtractOutputReceiverProofV1(
            statement, pin, lanes,
            *built_manifest, extract_product,
            stream_product, 0, receiver,
            receiver_proved.proof,
            &receiver_audit, &why),
        why);
    BOOST_CHECK_EQUAL(
        receiver_audit.producer_endpoint_families,
        4U);
    BOOST_CHECK_EQUAL(
        receiver_audit.strictly_transitive_endpoint_families,
        1U);
    BOOST_CHECK(
        receiver_audit.producer_endpoint ==
        RCStage3RelationEndpoint::EpisodeExtractOutput);
    BOOST_CHECK(
        receiver_audit.receiver_endpoint ==
        RCStage3RelationEndpoint::EpisodeTileTreeStream);
    BOOST_CHECK(
        receiver_audit.producer_alias_product_verified);
    BOOST_CHECK(
        receiver_audit.authoritative_receiver_product_verified);
    BOOST_CHECK(
        receiver_audit.sampler_output_root_equal);
    BOOST_CHECK(
        receiver_audit.semantic_value_root_bound);
    BOOST_CHECK(
        receiver_audit.semantic_export_root_bound);
    BOOST_CHECK(
        receiver_audit.exact_selected_schedule);
    BOOST_CHECK(
        receiver_audit.shared_dual_fp3_challenges);
    BOOST_CHECK(
        receiver_audit.opposing_terminals);
    BOOST_CHECK(
        !receiver_audit.chacha_output_proof_owned);
    BOOST_CHECK(
        !receiver_audit.scale_output_proof_owned);
    BOOST_CHECK(
        !receiver_audit.recursive_children_consumed);
    BOOST_CHECK(!receiver_audit.role_complete);
    BOOST_TEST_MESSAGE(
        "PROOF-LEVEL strict transitive Extract endpoint 14 -> "
        "TileTreeStream endpoint 19 accept: rows="
        << receiver_cs.n_rows
        << " cols=" << receiver_cs.n_columns
        << " constraints="
        << receiver_cs.constraints.size());

    // A receiver proof that is valid for the original source cannot be
    // detached and paired with a substituted producer root.
    auto detached_pin = pin;
    detached_pin.episode_air
        .column_roots[aq::kColOut].root =
        Filled(0xe1);
    BOOST_CHECK(
        !VerifyRCStage3EpisodeExtractOutputReceiverProofV1(
            statement, detached_pin, lanes,
            *built_manifest, extract_product,
            stream_product, 0, receiver,
            receiver_proved.proof, nullptr,
            &why));

    auto detached_receiver_aux = receiver;
    detached_receiver_aux.pins[1]
        .auxiliary_commitment = Filled(0xe2);
    BOOST_CHECK(
        !VerifyRCStage3EpisodeExtractOutputReceiverProofV1(
            statement, pin, lanes,
            *built_manifest, extract_product,
            stream_product, 0,
            detached_receiver_aux,
            receiver_proved.proof, nullptr,
            &why));
    auto wrong_interval = receiver;
    ++wrong_interval.memory_row_begin;
    BOOST_CHECK(
        !VerifyRCStage3EpisodeExtractOutputReceiverProofV1(
            statement, pin, lanes,
            *built_manifest, extract_product,
            stream_product, 0, wrong_interval,
            receiver_proved.proof, nullptr,
            &why));
    auto wrong_cardinality = receiver;
    --wrong_cardinality.manifest
        .participants[1].event_count;
    BOOST_CHECK(
        !VerifyRCStage3EpisodeExtractOutputReceiverProofV1(
            statement, pin, lanes,
            *built_manifest, extract_product,
            stream_product, 0,
            wrong_cardinality,
            receiver_proved.proof, nullptr,
            &why));
    auto root_substitution = receiver;
    root_substitution.memory_value_root =
        Filled(0xe3);
    BOOST_CHECK(
        !VerifyRCStage3EpisodeExtractOutputReceiverProofV1(
            statement, pin, lanes,
            *built_manifest, extract_product,
            stream_product, 0,
            root_substitution,
            receiver_proved.proof, nullptr,
            &why));
    auto challenge_mismatch = receiver;
    challenge_mismatch.pins[1]
        .challenge_commitment = Filled(0xe4);
    BOOST_CHECK(
        !VerifyRCStage3EpisodeExtractOutputReceiverProofV1(
            statement, pin, lanes,
            *built_manifest, extract_product,
            stream_product, 0,
            challenge_mismatch,
            receiver_proved.proof, nullptr,
            &why));
    auto omitted_receiver = receiver;
    omitted_receiver.pins.pop_back();
    BOOST_CHECK(
        !VerifyRCStage3EpisodeExtractOutputReceiverProofV1(
            statement, pin, lanes,
            *built_manifest, extract_product,
            stream_product, 0,
            omitted_receiver,
            receiver_proved.proof, nullptr,
            &why));
    auto omitted_schedule = receiver;
    omitted_schedule.manifest.participants.pop_back();
    BOOST_CHECK(
        !VerifyRCStage3EpisodeExtractOutputReceiverProofV1(
            statement, pin, lanes,
            *built_manifest, extract_product,
            stream_product, 0,
            omitted_schedule,
            receiver_proved.proof, nullptr,
            &why));
    auto duplicated_schedule = receiver;
    duplicated_schedule.manifest
        .participants[1].schedule_commitment =
        duplicated_schedule.manifest
            .participants[0].schedule_commitment;
    BOOST_CHECK(
        !VerifyRCStage3EpisodeExtractOutputReceiverProofV1(
            statement, pin, lanes,
            *built_manifest, extract_product,
            stream_product, 0,
            duplicated_schedule,
            receiver_proved.proof, nullptr,
            &why));
    auto reordered_schedule = receiver;
    std::swap(
        reordered_schedule.manifest.participants[0],
        reordered_schedule.manifest.participants[1]);
    BOOST_CHECK(
        !VerifyRCStage3EpisodeExtractOutputReceiverProofV1(
            statement, pin, lanes,
            *built_manifest, extract_product,
            stream_product, 0,
            reordered_schedule,
            receiver_proved.proof, nullptr,
            &why));
    auto reordered_receiver = receiver;
    std::swap(
        reordered_receiver.pins[0],
        reordered_receiver.pins[1]);
    BOOST_CHECK(
        !VerifyRCStage3EpisodeExtractOutputReceiverProofV1(
            statement, pin, lanes,
            *built_manifest, extract_product,
            stream_product, 0,
            reordered_receiver,
            receiver_proved.proof, nullptr,
            &why));
    auto noncanonical_receiver = receiver;
    noncanonical_receiver.pins[0]
        .terminal.alpha1_sum.c0 = gf::kP;
    BOOST_CHECK(
        !VerifyRCStage3EpisodeExtractOutputReceiverProofV1(
            statement, pin, lanes,
            *built_manifest, extract_product,
            stream_product, 0,
            noncanonical_receiver,
            receiver_proved.proof, nullptr,
            &why));
    BOOST_TEST_MESSAGE(
        "PROOF-LEVEL receiver attacks rejected: detached/rebuilt "
        "pairing, aux, interval/cardinality, root/challenge, "
        "schedule omission/duplication/reorder, raw x+p representative");
}

BOOST_AUTO_TEST_CASE(
    degree2_direct_alias_preserves_relation_root_and_rejects_detach)
{
    namespace aq = air_quotient;
    namespace gf = gkr_field;
    constexpr uint32_t N = 8;
    std::vector<gf::Fp3> values(N);
    for (uint32_t row = 0; row < N; ++row) {
        values[row] = gf::Fp3::FromFp(row + 17);
    }
    RCStage3CtlSchedule send_schedule;
    RCStage3CtlSchedule receive_schedule;
    for (uint32_t row = 0; row < N; ++row) {
        send_schedule.events.push_back(
            {0x44543231U, 24, row, 1});
        receive_schedule.events.push_back(
            {0x44543231U, 24, row, -1});
    }
    RCStage3CtlManifest manifest;
    manifest.bus_id = 0x44543231U;
    manifest.transcript_seed = Filled(0xd3);
    manifest.participants = {
        {RCStage3RelationRole::EpisodeDigest,
         N, N, 0,
         CommitRCStage3CtlSchedule(send_schedule)},
        {RCStage3RelationRole::CompositionLink,
         N, 0, N,
         CommitRCStage3CtlSchedule(receive_schedule)},
    };
    std::vector<RCStage3CtlChildPin> pins(2);
    for (size_t i = 0; i < pins.size(); ++i) {
        const auto& participant = manifest.participants[i];
        pins[i].role = participant.role;
        pins[i].bus_id = manifest.bus_id;
        pins[i].event_count = participant.event_count;
        pins[i].send_count = participant.send_count;
        pins[i].receive_count = participant.receive_count;
        pins[i].schedule_commitment =
            participant.schedule_commitment;
        pins[i].trace_commitment =
            ComputeRCStage3CtlDegree2PrechallengeTraceCommitment(
                i == 0 ? send_schedule : receive_schedule,
                values);
    }
    std::string why;
    RCStage3CtlChallenges challenges;
    BOOST_REQUIRE_MESSAGE(
        DeriveRCStage3CtlChallenges(
            manifest, pins, challenges, &why),
        why);
    const auto send =
        BuildRCStage3CtlDegree2Witness(
            send_schedule, values, challenges);
    const auto receive =
        BuildRCStage3CtlDegree2Witness(
            receive_schedule, values, challenges);
    BOOST_REQUIRE_MESSAGE(send.ok, send.note);
    BOOST_REQUIRE_MESSAGE(receive.ok, receive.note);
    BOOST_CHECK(gf::IsZero(gf::Add(
        send.terminal.alpha1_sum,
        receive.terminal.alpha1_sum)));
    BOOST_CHECK(gf::IsZero(gf::Add(
        send.terminal.alpha2_sum,
        receive.terminal.alpha2_sum)));

    aq::AirConstraintSystem<gf::Fp3> relation;
    relation.n_rows = N;
    relation.n_columns = 1;
    aq::AirConstraint<gf::Fp3> identity;
    identity.name = "test.degree2_relation_identity";
    identity.kind = aq::AirKind::kEverywhere;
    identity.alg_degree = 1;
    identity.eval = [](
                        const std::vector<gf::Fp3>& row,
                        const std::vector<gf::Fp3>&) {
        return gf::Sub(row[0], row[0]);
    };
    relation.constraints.push_back(std::move(identity));

    aq::AirConstraintSystem<gf::Fp3> combined;
    RCStage3RelationCtlDegree2DirectAliasLayout layout;
    BOOST_REQUIRE_MESSAGE(
        BuildRCStage3RelationCtlDegree2DirectAliasConstraintSystem(
            relation,
            {kRCStage3CtlDegree2Version,
             send_schedule,
             challenges,
             send.terminal},
            0, combined, &layout, &why),
        why);
    BOOST_CHECK(layout.exact_row_degree_two);
    BOOST_CHECK(layout.same_trace);
    BOOST_CHECK(layout.direct_alias);
    BOOST_CHECK_LE(combined.QuotientLen(), N);
    std::vector<std::vector<gf::Fp3>> product_columns;
    BOOST_REQUIRE_MESSAGE(
        BuildRCStage3RelationCtlDegree2DirectAliasWitness(
            layout, {values}, send,
            product_columns, &why),
        why);
    const auto proved = aq::AirQuotientProve<gf::Fp3>(
        combined, product_columns, Filled(0xd4));
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_REQUIRE(proved.division_exact);
    BOOST_CHECK_EQUAL(proved.proof.batch.n_coeffs, N);
    const uint256 relation_root =
        aq::AirCommittedValuesRoot<gf::Fp3>(values, N);
    BOOST_CHECK(
        proved.proof.batch.columns[
            layout.source_column].root ==
        relation_root);
    BOOST_CHECK(
        proved.proof.batch.columns[
            layout.ctl_value_column].root ==
        relation_root);

    std::array<uint256, 5> roots{};
    for (uint32_t column =
             stage3_ctl_degree2_col::NAMESPACE;
         column <=
             stage3_ctl_degree2_col::MULTIPLICITY;
         ++column) {
        roots[column] =
            proved.proof.batch.columns[
                layout.ctl_column_base + column].root;
    }
    BOOST_CHECK(
        ComputeRCStage3CtlDegree2PrechallengeTraceCommitmentFromRoots(
            send_schedule, N, N, roots) ==
        pins[0].trace_commitment);

    auto detached = values;
    detached[3] = gf::Add(
        detached[3], gf::Fp3::One());
    BOOST_CHECK(
        !BuildRCStage3RelationCtlDegree2DirectAliasWitness(
            layout, {detached}, send,
            product_columns, &why));
    BOOST_CHECK(
        why.find("value_mismatch") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(
    fixed_hash_boundary_mask_exports_real_word_cells_without_fixture)
{
    namespace hash_air = stage3_hash_air;
    namespace gf = gkr_field;
    const auto program = hash_air::BuildCanonicalProgram(
        hash_air::ProgramKind::Sha256Compression);
    BOOST_REQUIRE(
        hash_air::ValidateCanonicalProgram(program));
    std::vector<uint32_t> external(
        program.external_address_count, 0);
    hash_air::ProgramWitness program_witness;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        hash_air::BuildProgramWitness(
            program, external, program_witness, &why),
        why);
    const auto final_words = program_witness.final_words;

    const auto provenance =
        hash_air::BuildFixedProgramProvenanceInstance(
            program, program_witness, external, final_words,
            Filled(0xc1));
    BOOST_REQUIRE_MESSAGE(provenance.valid, provenance.note);
    const auto& hash_cs = provenance.cs;
    const auto& hash_columns = provenance.columns;
    BOOST_CHECK_EQUAL(
        hash_cs.n_columns,
        hash_air::kFixedProgramProvenanceColumns);
    BOOST_CHECK_EQUAL(hash_cs.n_columns, 171U);
    BOOST_CHECK_EQUAL(hash_cs.n_rows, 1024U);

    const uint32_t source_column = hash_air::ValueColumn(0);
    const uint32_t mask_column =
        hash_air::kFixedProgramBoundaryMaskBase;
    std::vector<gf::Fp3> export_values(hash_cs.n_rows);
    size_t first_live = hash_cs.n_rows;
    for (uint32_t row = 0; row < hash_cs.n_rows; ++row) {
        export_values[row] = gf::Mul(
            hash_columns[mask_column][row],
            hash_columns[source_column][row]);
        if (first_live == hash_cs.n_rows &&
            gf::Eq(hash_columns[mask_column][row],
                   gf::Fp3::One())) {
            first_live = row;
        }
    }
    BOOST_REQUIRE_LT(first_live, hash_cs.n_rows);

    RCStage3CtlSchedule schedule;
    for (uint32_t row = 0; row < hash_cs.n_rows; ++row) {
        schedule.events.push_back({1301, 1, row, 1});
    }
    const RCStage3CtlChallenges challenges{
        {2, 3, 4}, {5, 6, 7}, {101, 103, 107}, {109, 113, 127}};
    const auto ctl_witness =
        BuildRCStage3CtlWitness(schedule, export_values, challenges);
    BOOST_REQUIRE_MESSAGE(ctl_witness.ok, ctl_witness.note);
    const RCStage3CtlAirSpec ctl_spec{
        schedule, challenges, ctl_witness.terminal};
    air_quotient::AirConstraintSystem<gf::Fp3> combined;
    RCStage3RelationCtlMaskedAliasLayout layout;
    BOOST_REQUIRE_MESSAGE(
        BuildRCStage3RelationCtlMaskedAliasConstraintSystem(
            hash_cs, ctl_spec, {{source_column, mask_column}},
            combined, &layout, &why),
        why);
    BOOST_CHECK(layout.preprocessed_masks);
    BOOST_CHECK(layout.masks_boolean_and_disjoint);
    BOOST_CHECK(layout.same_trace);
    BOOST_CHECK_EQUAL(
        combined.n_columns,
        hash_air::kFixedProgramProvenanceColumns +
            stage3_ctl_col::NUM_COLUMNS);
    BOOST_CHECK_EQUAL(combined.n_columns, 180U);
    BOOST_CHECK_EQUAL(
        combined.constraints.size(),
        hash_cs.constraints.size() + 13U);

    std::vector<std::vector<gf::Fp3>> combined_columns;
    BOOST_REQUIRE_MESSAGE(
        BuildRCStage3RelationCtlMaskedAliasWitness(
            layout, hash_columns, ctl_witness,
            combined_columns, &why),
        why);
    BOOST_CHECK_EQUAL(combined_columns.size(), 180U);

    auto detached = hash_columns;
    detached[source_column][first_live] = gf::Add(
        detached[source_column][first_live], gf::Fp3::One());
    BOOST_CHECK(!BuildRCStage3RelationCtlMaskedAliasWitness(
        layout, detached, ctl_witness, combined_columns, &why));
    BOOST_CHECK(why.find("value_mismatch") != std::string::npos);

    BOOST_CHECK(
        !BuildRCStage3RelationCtlMaskedAliasConstraintSystem(
            hash_cs, ctl_spec,
            {{source_column, mask_column},
             {hash_air::ValueColumn(1), mask_column}},
            combined, &layout, &why));
    BOOST_CHECK(why.find("duplicate_mask") != std::string::npos);

    // Width feasibility for the next builder step: four provenance lanes plus
    // four scalar CTL traces per lane remain below the 1,092-column cap. The
    // current tree has a packed boundary builder, not yet a packed provenance
    // builder, so this is deliberately not marked executable.
    constexpr uint32_t four_lane_provenance_ctl_columns =
        hash_air::kFixedProgramPackedLanes *
            hash_air::kFixedProgramProvenanceColumns +
        hash_air::kFixedProgramPackedLanes * 4U *
            stage3_ctl_col::NUM_COLUMNS;
    static_assert(four_lane_provenance_ctl_columns == 828);
    static_assert(
        four_lane_provenance_ctl_columns <
        hash_air::kFixedProgramRecursiveWidthCap);
}

BOOST_AUTO_TEST_CASE(
    coupled_gemm_local_kernel_cell_is_proved_in_the_ctl_trace)
{
    namespace aq = air_quotient;
    namespace col = coupled_air_col;
    namespace gf = gkr_field;
    const auto statement = Statement();

    RCStage3CoupledEndpointAirPublicPin public_pin;
    public_pin.endpoint =
        RCStage3RelationEndpoint::CoupledGemmOperandA;
    public_pin.request.role = RCStage3RelationRole::CoupledGemm;
    public_pin.request.shape = MakeRCStage3CoupledShape(
        MakeMediumV3RCCoupParams(), MakeMediumV4RCCoupOptions());
    public_pin.request.gamma = gf::Fp3::One();
    public_pin.request.alpha = gf::Fp3::One();
    public_pin.statement_commitment =
        CommitRCStage3CoupledStatement(statement.public_inputs);
    public_pin.shape_commitment =
        CommitRCStage3CoupledShape(public_pin.request.shape);

    RCStage3CoupledAirEntry entry;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        ResolveRCStage3CoupledAir(
            public_pin.request, entry, &why),
        why);
    BOOST_REQUIRE(entry.constraint_system_available);
    const uint32_t N = entry.constraints.n_rows;
    BOOST_CHECK_EQUAL(N, 64U);
    std::vector<std::vector<gf::Fp3>> relation_columns(
        entry.constraints.n_columns,
        std::vector<gf::Fp3>(N, gf::Fp3::Zero()));
    gf::Fp3 accumulator = gf::Fp3::Zero();
    for (uint32_t row = 0; row < N; ++row) {
        relation_columns[col::GEMM_A][row] =
            gf::Fp3::FromFp(2);
        relation_columns[col::GEMM_B][row] =
            gf::Fp3::FromFp(3);
        relation_columns[col::GEMM_ACTIVE][row] =
            gf::Fp3::One();
        accumulator = gf::Add(
            accumulator, gf::Fp3::FromFp(6));
        relation_columns[col::GEMM_ACC][row] = accumulator;
    }
    for (uint32_t row = 0; row < N; ++row) {
        relation_columns[col::GEMM_OUT][row] = accumulator;
    }

    RCStage3CtlSchedule send_schedule;
    RCStage3CtlSchedule receive_schedule;
    const auto& values = relation_columns[col::GEMM_A];
    for (uint32_t row = 0; row < N; ++row) {
        send_schedule.events.push_back({1401, 3, row, 1});
        receive_schedule.events.push_back({1401, 3, row, -1});
    }
    RCStage3CtlManifest manifest;
    manifest.bus_id = 1409;
    manifest.transcript_seed = public_pin.statement_commitment;
    manifest.participants = {
        {RCStage3RelationRole::CoupledGemm, N, N, 0,
         CommitRCStage3CtlSchedule(send_schedule)},
        {RCStage3RelationRole::CompositionLink, N, 0, N,
         CommitRCStage3CtlSchedule(receive_schedule)},
    };
    std::vector<RCStage3CtlChildPin> pins(2);
    pins[0].role = RCStage3RelationRole::CoupledGemm;
    pins[1].role = RCStage3RelationRole::CompositionLink;
    for (size_t i = 0; i < pins.size(); ++i) {
        auto& child = pins[i];
        const auto& participant = manifest.participants[i];
        const auto& schedule =
            i == 0 ? send_schedule : receive_schedule;
        child.bus_id = manifest.bus_id;
        child.event_count = participant.event_count;
        child.send_count = participant.send_count;
        child.receive_count = participant.receive_count;
        child.schedule_commitment =
            participant.schedule_commitment;
        child.trace_commitment =
            ComputeRCStage3CtlPrechallengeTraceCommitment(
                schedule, values);
    }
    RCStage3CtlChallenges challenges;
    BOOST_REQUIRE_MESSAGE(
        DeriveRCStage3CtlChallenges(
            manifest, pins, challenges, &why),
        why);
    const auto send =
        BuildRCStage3CtlWitness(
            send_schedule, values, challenges);
    const auto receive =
        BuildRCStage3CtlWitness(
            receive_schedule, values, challenges);
    BOOST_REQUIRE_MESSAGE(send.ok, send.note);
    BOOST_REQUIRE_MESSAGE(receive.ok, receive.note);
    const uint256 challenge_commitment =
        CommitRCStage3CtlChallenges(challenges);
    pins[0].terminal = send.terminal;
    pins[1].terminal = receive.terminal;
    for (size_t i = 0; i < pins.size(); ++i) {
        pins[i].challenge_commitment = challenge_commitment;
        pins[i].auxiliary_commitment =
            Filled(static_cast<unsigned char>(0xd5 + i));
    }

    const RCStage3CtlAirSpec ctl_spec{
        send_schedule, challenges, send.terminal};
    aq::AirConstraintSystem<gf::Fp3> combined;
    RCStage3RelationCtlDirectAliasLayout layout;
    BOOST_REQUIRE_MESSAGE(
        BuildRCStage3RelationCtlDirectAliasConstraintSystem(
            entry.constraints, ctl_spec, col::GEMM_A,
            combined, &layout, &why),
        why);
    const uint32_t product_coeffs =
        FriNextPow2(std::max(combined.n_rows, combined.QuotientLen()));
    public_pin.relation_column_roots.resize(
        relation_columns.size());
    for (uint32_t column = 0;
         column < relation_columns.size(); ++column) {
        public_pin.relation_column_roots[column] =
            aq::AirCommittedValuesRoot<gf::Fp3>(
                relation_columns[column], product_coeffs);
        entry.constraints.preprocessed_roots.emplace_back(
            column, public_pin.relation_column_roots[column]);
    }
    BOOST_REQUIRE_MESSAGE(
        BuildRCStage3RelationCtlDirectAliasConstraintSystem(
            entry.constraints, ctl_spec, col::GEMM_A,
            combined, &layout, &why),
        why);
    std::vector<std::vector<gf::Fp3>> combined_columns;
    BOOST_REQUIRE_MESSAGE(
        BuildRCStage3RelationCtlDirectAliasWitness(
            layout, relation_columns, send,
            combined_columns, &why),
        why);
    const uint256 relation_seed =
        ComputeRCStage3CoupledEndpointAirSeed(
            statement, public_pin);
    const uint256 seed =
        ComputeRCStage3RelationCtlDirectAliasSeed(
            public_pin.endpoint, relation_seed, send_schedule,
            challenges, send.terminal, col::GEMM_A);
    const auto proved =
        aq::AirQuotientProve<gf::Fp3>(
            combined, combined_columns, seed);
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_REQUIRE(proved.division_exact);
    pins[0].auxiliary_commitment =
        ComputeRCStage3RelationCtlDirectAliasAuxiliaryCommitment(
            proved.proof, layout);
    BOOST_REQUIRE(!pins[0].auxiliary_commitment.IsNull());
    BOOST_REQUIRE_MESSAGE(
        VerifyRCStage3CoupledEndpointCtlDirectAliasProof(
            statement, public_pin, manifest, pins, 0,
            send_schedule, proved.proof, &why),
        why);
    BOOST_CHECK(
        why.find("coupled_local_kernel_cell") !=
        std::string::npos);

    auto detached_auxiliary = pins;
    detached_auxiliary[0].auxiliary_commitment = Filled(0xd5);
    BOOST_CHECK(
        !VerifyRCStage3CoupledEndpointCtlDirectAliasProof(
            statement, public_pin, manifest, detached_auxiliary, 0,
            send_schedule, proved.proof, &why));
    BOOST_CHECK(
        why.find("ctl_auxiliary_commitment") !=
        std::string::npos);

    auto relabelled = public_pin;
    relabelled.endpoint =
        RCStage3RelationEndpoint::CoupledExchangeInput;
    BOOST_CHECK(
        !VerifyRCStage3CoupledEndpointCtlDirectAliasProof(
            statement, relabelled, manifest, pins, 0,
            send_schedule, proved.proof, &why));
    BOOST_CHECK(why.find("unregistered_endpoint") !=
                std::string::npos);

    auto substituted = public_pin;
    substituted.relation_column_roots[col::GEMM_A] =
        Filled(0xe8);
    BOOST_CHECK(
        !VerifyRCStage3CoupledEndpointCtlDirectAliasProof(
            statement, substituted, manifest, pins, 0,
            send_schedule, proved.proof, &why));
    BOOST_CHECK(why.find("relation_column_root") !=
                    std::string::npos ||
                why.find("air:") != std::string::npos);

    BOOST_CHECK(
        !VerifyRCStage3CoupledEndpointCtlDirectAliasProof(
            statement, public_pin, manifest, pins, 0,
            send_schedule,
            [&] {
                auto mutated = proved.proof;
                mutated.batch.columns[layout.source_column].root =
                    Filled(0xe9);
                return mutated;
            }(),
            &why));
}

BOOST_AUTO_TEST_CASE(all_registered_endpoints_bind_to_executed_ctl_values)
{
    Fixture fixture;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        VerifyRCStage3RelationClosureV1(
            fixture.statement, fixture.root, fixture.ctl_bundle,
            fixture.closure, &why),
        why);
    size_t endpoint_total = 0;
    for (const auto& role : fixture.closure.roles) {
        endpoint_total += role.endpoints.size();
    }
    BOOST_CHECK_EQUAL(endpoint_total, 52U);
    BOOST_CHECK_EQUAL(
        fixture.closure.roles.size(),
        kRCStage3RelationClosureRoleCount);
}

BOOST_AUTO_TEST_CASE(omission_substitution_and_relabelling_fail_closed)
{
    Fixture fixture;
    std::string why;

    auto omitted_role = fixture.closure;
    omitted_role.roles.pop_back();
    omitted_role.closure_commitment =
        ComputeRCStage3RelationClosureCommitment(omitted_role);
    BOOST_CHECK(!VerifyRCStage3RelationClosureV1(
        fixture.statement, fixture.root, fixture.ctl_bundle,
        omitted_role, &why));
    BOOST_CHECK(why.find("role_count") != std::string::npos);

    auto omitted_endpoint = fixture.closure;
    omitted_endpoint.roles[1].endpoints.pop_back();
    omitted_endpoint.roles[1].endpoint_multiproof_root =
        ComputeRCStage3RelationRoleMultiproofRoot(
            omitted_endpoint.roles[1]);
    omitted_endpoint.closure_commitment =
        ComputeRCStage3RelationClosureCommitment(omitted_endpoint);
    BOOST_CHECK(!VerifyRCStage3RelationClosureV1(
        fixture.statement, fixture.root, fixture.ctl_bundle,
        omitted_endpoint, &why));
    BOOST_CHECK(why.find("endpoint_count") != std::string::npos);

    auto substituted = fixture.closure;
    const auto exported = RCStage3RelationCtlExportEndpoint(
        substituted.roles[2].role);
    auto it = std::find_if(
        substituted.roles[2].endpoints.begin(),
        substituted.roles[2].endpoints.end(),
        [exported](const auto& endpoint) {
            return endpoint.endpoint == exported;
        });
    BOOST_REQUIRE(it != substituted.roles[2].endpoints.end());
    it->proof_column_root = Filled(240);
    substituted.roles[2].endpoint_multiproof_root =
        ComputeRCStage3RelationRoleMultiproofRoot(substituted.roles[2]);
    substituted.closure_commitment =
        ComputeRCStage3RelationClosureCommitment(substituted);
    BOOST_CHECK(!VerifyRCStage3RelationClosureV1(
        fixture.statement, fixture.root, fixture.ctl_bundle,
        substituted, &why));
    BOOST_CHECK(why.find("proof_to_ctl_value_root") !=
                std::string::npos);

    auto relabelled = fixture.closure;
    relabelled.roles[3].endpoints[0].endpoint =
        relabelled.roles[3].endpoints[1].endpoint;
    relabelled.roles[3].endpoint_multiproof_root =
        ComputeRCStage3RelationRoleMultiproofRoot(relabelled.roles[3]);
    relabelled.closure_commitment =
        ComputeRCStage3RelationClosureCommitment(relabelled);
    BOOST_CHECK(!VerifyRCStage3RelationClosureV1(
        fixture.statement, fixture.root, fixture.ctl_bundle,
        relabelled, &why));
    BOOST_CHECK(why.find("endpoint_order") != std::string::npos);

    auto digest = fixture.closure;
    digest.roles[5].endpoints[1].semantic_root = Filled(241);
    digest.roles[5].endpoint_multiproof_root =
        ComputeRCStage3RelationRoleMultiproofRoot(digest.roles[5]);
    digest.closure_commitment =
        ComputeRCStage3RelationClosureCommitment(digest);
    BOOST_CHECK(!VerifyRCStage3RelationClosureV1(
        fixture.statement, fixture.root, fixture.ctl_bundle,
        digest, &why));
    BOOST_CHECK(why.find("episode_digest") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(opaque_recursive_child_metadata_is_not_misreported_as_proof)
{
    Fixture fixture;
    std::string why;

    // The ledger binds these values but cannot verify an opaque recursive
    // child.  Replacing both and recomputing the public ledger is therefore
    // still structurally valid.  This attack remains pinned in the suite so
    // nobody can promote closure validation to consensus authority before the
    // normalized recursive verifier executes the child.
    auto opaque = fixture.closure;
    opaque.roles[0].endpoints[0].proof_root = Filled(242);
    opaque.roles[0].endpoints[0].recursive_child_commitment = Filled(243);
    opaque.roles[0].endpoint_multiproof_root =
        ComputeRCStage3RelationRoleMultiproofRoot(opaque.roles[0]);
    opaque.closure_commitment =
        ComputeRCStage3RelationClosureCommitment(opaque);
    BOOST_CHECK(VerifyRCStage3RelationClosureV1(
        fixture.statement, fixture.root, fixture.ctl_bundle, opaque, &why));
    BOOST_CHECK(why.find("recursive_children_open") != std::string::npos);
    BOOST_CHECK(!kRCStage3RelationClosureRecursiveChildrenExecutable);
    BOOST_CHECK(!kRCStage3RelationClosureAuthorityReady);
}

// Blocker A: every opened endpoint's relation cell PROVES, through the standard
// batched-FRI backend (AirQuotientProve + AirQuotientVerify) — not a native
// constraint scan — that it opens its committed manifest root (LeafHash +
// AlgHash Merkle path, spliced in-circuit) and is bound to the CTL VALUE column
// at the public leaf index.  Honest opening divides exactly and verifies;
// tampering the CTL value drives the proof inexact and verification fails.
BOOST_AUTO_TEST_CASE(commitment_opening_proves_cell_opens_manifest_root_per_endpoint)
{
    namespace gf = gkr_field;

    // Enumerate exactly the endpoints reported as carrying an opening.
    std::vector<RCStage3RelationEndpoint> opened;
    for (const auto& cell : CurrentRCStage3RelationEndpointCellAudit()) {
        if (RCStage3EndpointHasCommitmentOpening(cell.endpoint)) {
            BOOST_CHECK(cell.semantic_relation_complete);
            opened.push_back(cell.endpoint);
        }
    }
    BOOST_REQUIRE_EQUAL(opened.size(), 21U);
    BOOST_CHECK_EQUAL(RCStage3CommitmentOpeningEndpointCount(), 21U);

    uint32_t proved_open = 0;
    for (const RCStage3RelationEndpoint endpoint : opened) {
        // A distinct committed cell/value per endpoint.
        const gf::Fp3 cell = gf::Fp3::FromFp(
            gf::FromU64(0x51D3ULL + static_cast<uint64_t>(endpoint) * 131ULL));
        const uint32_t index = static_cast<uint32_t>(endpoint) + 3U;
        const auto manifest = BuildRCStage3CanonicalManifest(
            endpoint, cell, index, kRCStage3OpeningPathLen);

        std::string why;
        // (1) Honest opening: PROVED honest acceptance.
        const auto honest =
            OpenRCStage3EndpointCommitment(endpoint, cell, cell, manifest, &why);
        BOOST_CHECK_MESSAGE(honest.opens, RCStage3RelationEndpointName(endpoint)
                                              << ": " << why);
        BOOST_CHECK(honest.division_exact);
        BOOST_CHECK(honest.verified);
        BOOST_CHECK(honest.ctl_value_bound);
        BOOST_CHECK(honest.leaf_consistent);
        BOOST_CHECK(honest.root_matches_manifest);
        BOOST_CHECK_EQUAL(honest.path_len, kRCStage3OpeningPathLen);
        if (honest.opens) ++proved_open;

        // (2) Tamper: a CTL value that is not the committed cell — the value
        // bind is violated, so the quotient is inexact and verify rejects.
        const gf::Fp3 wrong_value = gf::Add(cell, gf::Fp3::One());
        const auto bad_ctl = OpenRCStage3EndpointCommitment(
            endpoint, cell, wrong_value, manifest, &why);
        BOOST_CHECK(!bad_ctl.opens);
        BOOST_CHECK(!bad_ctl.division_exact);
        BOOST_CHECK(!bad_ctl.verified);
    }
    BOOST_CHECK_EQUAL(proved_open, 21U);

    // Endpoints without an exported scalar relation cell have no opening.
    BOOST_CHECK(!RCStage3EndpointHasCommitmentOpening(
        RCStage3RelationEndpoint::EpisodeBuilderParams));
    BOOST_CHECK(!RCStage3EndpointHasCommitmentOpening(
        RCStage3RelationEndpoint::CoupledBarrierHash));
}

// Full tamper battery on one representative endpoint: cell, sibling, direction
// and committed-root substitutions each make the PROVED opening inexact and
// unverifiable.
BOOST_AUTO_TEST_CASE(commitment_opening_proved_tamper_battery)
{
    namespace gf = gkr_field;
    const auto endpoint = RCStage3RelationEndpoint::CoupledGemmOutputY;
    const gf::Fp3 cell = gf::Fp3::FromFp(gf::FromU64(0xC0FFEEULL));
    const uint32_t index = 5U;
    const auto manifest =
        BuildRCStage3CanonicalManifest(endpoint, cell, index, kRCStage3OpeningPathLen);
    std::string why;

    const auto honest =
        OpenRCStage3EndpointCommitment(endpoint, cell, cell, manifest, &why);
    BOOST_CHECK_MESSAGE(honest.opens, why);
    BOOST_CHECK(honest.verified);

    // Wrong cell (not the manifest-committed value): folded root diverges.
    const gf::Fp3 wrong_cell = gf::Add(cell, gf::Fp3::One());
    const auto bad_cell =
        OpenRCStage3EndpointCommitment(endpoint, wrong_cell, wrong_cell, manifest, &why);
    BOOST_CHECK(!bad_cell.opens);
    BOOST_CHECK(!bad_cell.verified);

    // Substituted sibling on the authentication path.
    auto bad_sib = manifest;
    bad_sib.siblings[1][0] = gf::Add(bad_sib.siblings[1][0], gkr_field::Fp{1});
    const auto sib_res =
        OpenRCStage3EndpointCommitment(endpoint, cell, cell, bad_sib, &why);
    BOOST_CHECK(!sib_res.opens);
    BOOST_CHECK(!sib_res.verified);

    // Flipped direction bit (breaks the public-position pin).
    auto bad_dir = manifest;
    bad_dir.directions[0] = !bad_dir.directions[0];
    const auto dir_res =
        OpenRCStage3EndpointCommitment(endpoint, cell, cell, bad_dir, &why);
    BOOST_CHECK(!dir_res.opens);
    BOOST_CHECK(!dir_res.verified);

    // Substituted committed root.
    auto bad_root = manifest;
    bad_root.committed_root[0] = gf::Add(bad_root.committed_root[0], gkr_field::Fp{1});
    const auto root_res =
        OpenRCStage3EndpointCommitment(endpoint, cell, cell, bad_root, &why);
    BOOST_CHECK(!root_res.opens);
    BOOST_CHECK(!root_res.verified);
    BOOST_CHECK(!root_res.root_matches_manifest);
}

// Blocker A (stream/digest facet): every stream endpoint's committed hash/
// stream column is pinned to its §4 SHA256d manifest-binding stream_column_root
// (the real Build/Verify*ManifestRecursiveBinding machinery), honest pins and
// binding/root tampers are rejected.  OperandXof additionally exports a scalar
// cell from the canonical builder proof; the root pin and same-trace CTL are
// complementary rather than mutually exclusive.
BOOST_AUTO_TEST_CASE(stream_endpoints_pin_to_section4_manifest_binding_root)
{
    std::vector<RCStage3RelationEndpoint> stream_eps;
    for (const auto& cell : CurrentRCStage3RelationEndpointCellAudit()) {
        if (RCStage3EndpointHasStreamOpening(cell.endpoint)) {
            BOOST_CHECK(cell.semantic_relation_complete);
            BOOST_CHECK(
                cell.relation_air_cell ==
                (cell.endpoint ==
                 RCStage3RelationEndpoint::
                     EpisodeBuilderOperandXof));
            stream_eps.push_back(cell.endpoint);
        }
    }
    BOOST_REQUIRE_EQUAL(stream_eps.size(), 19U);
    BOOST_CHECK_EQUAL(RCStage3StreamOpeningEndpointCount(), 19U);

    uint32_t pinned = 0;
    for (const RCStage3RelationEndpoint endpoint : stream_eps) {
        std::string why;
        // Honest: the §4 binding verifies and the endpoint root pins to it.
        const auto honest = OpenRCStage3StreamEndpointCommitment(
            endpoint, /*tamper_stream=*/false, /*substitute_root=*/false, &why);
        BOOST_CHECK_MESSAGE(honest.opens, RCStage3RelationEndpointName(endpoint)
                                              << ": " << why);
        BOOST_CHECK(honest.binding_built);
        BOOST_CHECK(honest.binding_verified);
        BOOST_CHECK(honest.root_pinned);
        BOOST_CHECK(honest.family != RCStage3StreamManifestFamily::None);
        BOOST_CHECK(!honest.stream_column_root.IsNull());
        if (honest.opens) ++pinned;

        // Tamper: corrupted binding fails §4 verification.
        const auto bad_bind = OpenRCStage3StreamEndpointCommitment(
            endpoint, /*tamper_stream=*/true, /*substitute_root=*/false, &why);
        BOOST_CHECK(!bad_bind.opens);
        BOOST_CHECK(!bad_bind.binding_verified);

        // Tamper: a substituted endpoint root does not pin to stream_column_root.
        const auto bad_root = OpenRCStage3StreamEndpointCommitment(
            endpoint, /*tamper_stream=*/false, /*substitute_root=*/true, &why);
        BOOST_CHECK(!bad_root.opens);
        BOOST_CHECK(!bad_root.root_pinned);
    }
    BOOST_CHECK_EQUAL(pinned, 19U);

    // Endpoints with neither a scalar cell nor a §4 stream binding cannot close.
    for (const auto ep : {RCStage3RelationEndpoint::EpisodeBuilderParams,
                          RCStage3RelationEndpoint::EpisodeGemmSumcheck,
                          RCStage3RelationEndpoint::EpisodeWiringResidual,
                          RCStage3RelationEndpoint::CoupledGemmSignedRange}) {
        BOOST_CHECK(!RCStage3EndpointHasStreamOpening(ep));
        BOOST_CHECK(!RCStage3EndpointHasCommitmentOpening(ep));
        std::string why;
        const auto none = OpenRCStage3StreamEndpointCommitment(ep, false, false, &why);
        BOOST_CHECK(!none.opens);
        BOOST_CHECK(none.family == RCStage3StreamManifestFamily::None);
    }
}

// Recommendation #5: DirectSha256d residual relation families map 1:1 onto the
// stream-endpoint closer's residual RCStage3StreamFamily values (not the
// generic DirectSha256d fallback), so each keeps a distinct FamilyDomain.
BOOST_AUTO_TEST_CASE(
    direct_sha256d_residual_families_map_one_to_one_onto_stream_family)
{
    using Manifest = RCStage3StreamManifestFamily;
    using Stream = RCStage3StreamFamily;

    const struct {
        RCStage3RelationEndpoint endpoint;
        Manifest manifest;
        Stream stream;
    } cases[] = {
        {RCStage3RelationEndpoint::EpisodeDigestValue,
         Manifest::DirectSha256dEpisodeDigest,
         Stream::DirectSha256dEpisodeDigest},
        {RCStage3RelationEndpoint::EpisodeDigestPow,
         Manifest::DirectSha256dEpisodeDigest,
         Stream::DirectSha256dEpisodeDigest},
        {RCStage3RelationEndpoint::CoupledBarrierHash,
         Manifest::DirectSha256dCoupledBarrier,
         Stream::DirectSha256dCoupledBarrier},
        {RCStage3RelationEndpoint::CoupledBarrierOutput,
         Manifest::DirectSha256dCoupledBarrier,
         Stream::DirectSha256dCoupledBarrier},
        {RCStage3RelationEndpoint::CoupledDigestHash,
         Manifest::DirectSha256dCoupledDigest,
         Stream::DirectSha256dCoupledDigest},
        {RCStage3RelationEndpoint::CoupledDigestValue,
         Manifest::DirectSha256dCoupledDigest,
         Stream::DirectSha256dCoupledDigest},
    };

    for (const auto& c : cases) {
        BOOST_CHECK(RCStage3StreamEndpointManifestFamily(c.endpoint) ==
                    c.manifest);
        BOOST_CHECK(RCStage3StreamFamilyForEndpoint(c.endpoint) == c.stream);
        BOOST_CHECK(RCStage3StreamFamilyForEndpoint(c.endpoint) !=
                    Stream::DirectSha256d);
    }

    // Cross-family domain separation: identical stream_value / path under the
    // three residual families must produce three distinct committed roots.
    constexpr uint32_t kPathLen = 3;
    std::array<uint32_t, 8> stream_value{};
    for (uint32_t j = 0; j < 8; ++j) stream_value[j] = 0xA5u + 17u * j;
    const Stream residuals[] = {
        Stream::DirectSha256dEpisodeDigest,
        Stream::DirectSha256dCoupledBarrier,
        Stream::DirectSha256dCoupledDigest,
    };
    std::array<std::array<uint32_t, 8>, 3> roots{};
    for (uint32_t i = 0; i < 3; ++i) {
        const auto manifest = BuildRCStage3StreamEndpointCanonicalManifest(
            residuals[i], stream_value, /*leaf_index=*/0, kPathLen);
        std::string why;
        BOOST_REQUIRE(RCStage3StreamEndpointCommittedRoot(
            residuals[i], manifest, roots[i], &why));
    }
    BOOST_CHECK(roots[0] != roots[1]);
    BOOST_CHECK(roots[0] != roots[2]);
    BOOST_CHECK(roots[1] != roots[2]);
}

// Blocker A (value-vector facet): EpisodeBuilderParams opens a cell of the
// verifier-recomputed 9-cell consensus-params VALUE column against the
// re-anchored VectorRootAlg (Poseidon) root, proved by the same in-AIR opening.
BOOST_AUTO_TEST_CASE(builder_params_cell_opens_reanchored_vector_root)
{
    namespace gf = gkr_field;
    const auto endpoint = RCStage3RelationEndpoint::EpisodeBuilderParams;
    BOOST_REQUIRE(RCStage3EndpointHasVectorOpening(endpoint));
    // BuilderParams + ExtractInput + ExtractScale.
    BOOST_CHECK_EQUAL(RCStage3VectorOpeningEndpointCount(), 3U);

    // The 9 real consensus-params cells the verifier regenerates (never read
    // from the manifest).
    const auto params = DefaultConsensusRCEpisodeParams();
    const std::vector<gf::Fp3> values =
        CanonicalRCStage3EpisodeBuilderParamValues(params);
    BOOST_REQUIRE_EQUAL(values.size(), kRCStage3EpisodeBuilderParamsCells);

    // Open several distinct param cells; each must divide exactly and verify.
    uint32_t opened = 0;
    for (uint32_t index : {0U, 3U, 8U}) {
        const auto manifest = BuildRCStage3VectorManifest(endpoint, values, index);
        std::string why;
        const auto honest = OpenRCStage3EndpointCommitment(
            endpoint, values[index], values[index], manifest, &why);
        BOOST_CHECK_MESSAGE(honest.opens, "index " << index << ": " << why);
        BOOST_CHECK(honest.division_exact);
        BOOST_CHECK(honest.verified);
        BOOST_CHECK(honest.root_matches_manifest);
        if (honest.opens) ++opened;

        // Tamper: a value that is not the committed cell fails the opening.
        const auto wrong = gf::Add(values[index], gf::Fp3::One());
        const auto bad = OpenRCStage3EndpointCommitment(
            endpoint, wrong, wrong, manifest, &why);
        BOOST_CHECK(!bad.opens);
        BOOST_CHECK(!bad.verified);
    }
    BOOST_CHECK_EQUAL(opened, 3U);

    // The committed root is the Poseidon VectorRootAlg over the real cells, and
    // it is independent of cell ordering only through the index-bound leaves:
    // a reordered vector yields a different root.
    auto reordered = values;
    std::swap(reordered[0], reordered[1]);
    const auto m0 = BuildRCStage3VectorManifest(endpoint, values, 0);
    const auto m1 = BuildRCStage3VectorManifest(endpoint, reordered, 0);
    BOOST_CHECK(!(m0.committed_root == m1.committed_root));
}

// Blocker A (wired sibling bindings): drive the sibling lanes' REAL binding
// builders/verifiers (not stubs), confirm the wire helper yields
// semantic_relation_complete for an honest binding and rejects a tamper, and
// confirm the registry flips the endpoint.
namespace {
uint256 WireSeed(uint64_t s)
{
    HashWriter h;
    h << "BTX_PR89_BINDING_TEST_SEED" << s;
    return h.GetHash();
}
RCStage3SuccinctProof CoupledStatement()
{
    RCStage3SuccinctProof statement;
    statement.statement = RCStage3StatementKind::Composed;
    statement.public_inputs.height = 17;
    statement.public_inputs.episode_profile = 2;
    statement.public_inputs.coupled_profile = 4;
    statement.public_inputs.transcript_version = ENC_RC_V4;
    statement.public_inputs.header_commitment = Filled(0x11);
    statement.public_inputs.params_commitment = Filled(0x22);
    statement.public_inputs.sigma = Filled(0x33);
    statement.public_inputs.coupled_digest = Filled(0x44);
    return statement;
}
} // namespace

// Blocker A (extract value columns): EpisodeExtractInput (kColUMix) and
// EpisodeExtractScale (kColE0) open a cell of the REAL sampler value column
// (produced by tracing a real extract tile) against the re-anchored VectorRootAlg
// root, proved by the same in-AIR opening.
BOOST_AUTO_TEST_CASE(extract_input_and_scale_cells_open_reanchored_vector_root)
{
    namespace gf = gkr_field;
    namespace aq = air_quotient;
    namespace ga = gkr_air;

    BOOST_CHECK(RCStage3EndpointHasVectorOpening(
        RCStage3RelationEndpoint::EpisodeExtractInput));
    BOOST_CHECK(RCStage3EndpointHasVectorOpening(
        RCStage3RelationEndpoint::EpisodeExtractScale));

    // Trace one real extract tile and build the genuine sampler columns.
    std::array<int64_t, kRCMxBlockLen> input{};
    for (uint32_t i = 0; i < input.size(); ++i) input[i] = static_cast<int64_t>(i) - 16;
    const ga::TilePublic tile_public{Filled(0x7e), 0, 0};
    const ga::TileWitness witness = ga::TraceTile(tile_public, input);
    BOOST_REQUIRE(!witness.cands.empty());
    const ga::TableTM table;
    HashWriter sh;
    sh << "BTX_RC_STAGE3_EXTRACT_SAMPLER_TEST" << uint64_t{1};
    const auto sampler = aq::BuildRcSamplerInstance<gf::Fp3>(witness, table, sh.GetHash());
    BOOST_REQUIRE_MESSAGE(sampler.ok, sampler.note);

    struct Case {
        RCStage3RelationEndpoint endpoint;
        uint32_t column;
    };
    const Case cases[] = {
        {RCStage3RelationEndpoint::EpisodeExtractInput, aq::kColUMix},
        {RCStage3RelationEndpoint::EpisodeExtractScale, aq::kColE0},
    };
    for (const auto& c : cases) {
        const std::vector<gf::Fp3>& col = sampler.columns[c.column];
        BOOST_REQUIRE(!col.empty());
        // Commit a real prefix (fixed T-BIND depth <= 7 keeps the tree cheap).
        const std::vector<gf::Fp3> values(
            col.begin(), col.begin() + std::min<size_t>(col.size(), 64));
        const uint32_t index = static_cast<uint32_t>(values.size() / 2);
        const auto manifest = BuildRCStage3VectorManifest(c.endpoint, values, index);
        std::string why;
        const auto honest = OpenRCStage3EndpointCommitment(
            c.endpoint, values[index], values[index], manifest, &why);
        BOOST_CHECK_MESSAGE(honest.opens, RCStage3RelationEndpointName(c.endpoint)
                                              << ": " << why);
        BOOST_CHECK(honest.division_exact);
        BOOST_CHECK(honest.verified);
        BOOST_CHECK(honest.root_matches_manifest);

        // Tamper: a value not committed at that index fails the opening.
        const auto wrong = gf::Add(values[index], gf::Fp3::One());
        const auto bad = OpenRCStage3EndpointCommitment(
            c.endpoint, wrong, wrong, manifest, &why);
        BOOST_CHECK(!bad.opens);
        BOOST_CHECK(!bad.verified);

        // Registry endpoint is flipped.
        for (const auto& cell : CurrentRCStage3RelationEndpointCellAudit()) {
            if (cell.endpoint == c.endpoint)
                BOOST_CHECK(cell.semantic_relation_complete);
        }
    }
}

// Blocker A (the 5 sibling-lane bindings, wired): drive each REAL binding
// engine with a real fixture, confirm the wire helper yields a complete pin,
// and confirm a tamper rejects — mirroring the sibling's verified suite.
// Registration swap: the Poseidon VectorRootAlg root the registry stores in
// RCStage3GemmExtractLayerBindings::*_root_alg (authority) is byte-identical to
// the root the commitment opening authenticates — so the registry assembles
// C_ρ against the exact root the opening proves; the SHA256d root is transport.
BOOST_AUTO_TEST_CASE(registration_swap_authority_root_matches_opening_root)
{
    namespace gf = gkr_field;
    // A power-of-two value column so the authority commitment and the opening
    // tree pad identically.
    std::vector<gf::Fp3> values(8);
    for (uint32_t i = 0; i < values.size(); ++i)
        values[i] = gf::Fp3::FromFp(gf::FromU64(0x9E37ULL * (i + 1)));

    const uint256 authority = RCStage3VectorRootAlgCommitment(values);
    BOOST_CHECK(!authority.IsNull());

    // The registry stores it as the Poseidon authority; the SHA root is transport.
    RCStage3GemmExtractLayerBindings b;
    b.operand_a_root = Filled(0xAA);       // SHA256d transport / audit
    b.operand_a_root_alg = authority;      // Poseidon VectorRootAlg authority
    BOOST_CHECK(b.operand_a_root_alg == authority);
    BOOST_CHECK(!(b.operand_a_root == b.operand_a_root_alg));

    // The opening authenticates the SAME VectorRootAlg tree: its committed root,
    // packed identically, equals the stored authority.
    const auto endpoint = RCStage3RelationEndpoint::EpisodeGemmOperandA;
    const uint32_t index = 3;
    const auto manifest = BuildRCStage3VectorManifest(endpoint, values, index);
    const alg_hash::Digest opened_root =
        RCStage3ComputeVectorRootAlg(values); // == manifest.committed_root tree
    for (uint32_t j = 0; j < alg_hash::kAlgHashDigestLen; ++j) {
        BOOST_CHECK_EQUAL(gf::Canonical(opened_root[j]),
                          gf::Canonical(manifest.committed_root[j]));
    }
    std::string why;
    const auto honest = OpenRCStage3EndpointCommitment(
        endpoint, values[index], values[index], manifest, &why);
    BOOST_CHECK_MESSAGE(honest.opens, why);
    // The opened root packs to the registered authority.
    BOOST_CHECK(RCStage3VectorRootAlgCommitment(values) == authority);

    // Determinism + reorder sensitivity of the authority commitment.
    auto reordered = values;
    std::swap(reordered[0], reordered[1]);
    BOOST_CHECK(!(RCStage3VectorRootAlgCommitment(reordered) == authority));
}

BOOST_AUTO_TEST_CASE(coupled_bank_root_semantic_pin_wires_into_registry)
{
    const auto statement = CoupledStatement();
    const auto shape = MakeRCStage3CoupledShape(MakeToyRCCoupParams(), MakeV4RCCoupOptions());
    const uint64_t n = uint64_t{shape.bank_pages} * shape.lobe_width * shape.lobe_width;
    std::vector<uint8_t> pages(n);
    for (uint64_t i = 0; i < n; ++i) pages[i] = static_cast<uint8_t>(17 * i + 3);

    RCStage3CoupledBankRootManifest manifest;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        BuildRCStage3CoupledBankRootManifest(statement, shape, pages, manifest, &why), why);
    RCStage3CoupledBankRootAlgBinding committed;
    BOOST_REQUIRE_MESSAGE(
        ComputeRCStage3CoupledBankRootAlgBinding(manifest, committed, &why), why);

    RCStage3CoupledBankRootBindingResult r;
    BOOST_REQUIRE_MESSAGE(
        VerifyRCStage3CoupledBankRootAlgBinding(manifest, committed, manifest.bank_root, r, &why),
        why);
    BOOST_CHECK(r.binding_complete);
    BOOST_CHECK(RCStage3CoupledBankRootWireSemanticPin(r).semantic_relation_complete);

    // Tamper: a single page byte -> §4 binding rejects.
    auto tampered = pages;
    tampered[tampered.size() / 2] ^= 0x01;
    RCStage3CoupledBankRootManifest m2;
    BOOST_REQUIRE(BuildRCStage3CoupledBankRootManifest(statement, shape, tampered, m2, &why));
    RCStage3CoupledBankRootBindingResult bad;
    BOOST_CHECK(!VerifyRCStage3CoupledBankRootAlgBinding(m2, committed, manifest.bank_root, bad, nullptr));
    BOOST_CHECK(!RCStage3CoupledBankRootWireSemanticPin(bad).semantic_relation_complete);
}

BOOST_AUTO_TEST_CASE(seed_chain_semantic_pin_wires_into_registry)
{
    namespace ha = stage3_hash_air;
    auto params = MakeToyRCEpisodeParams();
    params.rounds = 2;
    std::vector<uint256> roots{Filled(0x61), Filled(0x62)};
    ha::EpisodeDigestManifest digest;
    std::string why;
    BOOST_REQUIRE_MESSAGE(ha::BuildEpisodeDigestManifest(roots.size(), roots, digest, &why), why);
    RCStage3SuccinctProof statement;
    statement.statement = RCStage3StatementKind::Episode;
    statement.public_inputs.height = 17;
    statement.public_inputs.episode_profile = 2;
    statement.public_inputs.transcript_version = ENC_RC_V4;
    statement.public_inputs.header_commitment = Filled(0x11);
    statement.public_inputs.params_commitment = Filled(0x22);
    statement.public_inputs.sigma = Filled(0x33);
    statement.public_inputs.episode_digest = digest.direct.digest;
    RCStage3EpisodeBuilderSeedChainProduct product;
    BOOST_REQUIRE_MESSAGE(
        ProveRCStage3EpisodeBuilderSeedChainProduct(statement, params, digest, product, &why), why);

    RCStage3SeedChainAlgBinding committed;
    BOOST_REQUIRE_MESSAGE(ComputeRCStage3SeedChainAlgBinding(product, committed, &why), why);
    RCStage3SeedChainBindingResult r;
    BOOST_REQUIRE_MESSAGE(VerifyRCStage3SeedChainAlgBinding(statement, product, committed, r, &why), why);
    BOOST_CHECK(r.binding_complete);
    BOOST_CHECK(RCStage3SeedChainWireSemanticPin(r).semantic_relation_complete);

    // Tamper: wrong σ anchor -> chain edge rejects.
    auto s2 = statement;
    s2.public_inputs.sigma = Filled(0xAB);
    RCStage3SeedChainBindingResult bad;
    BOOST_CHECK(!VerifyRCStage3SeedChainAlgBinding(s2, product, committed, bad, nullptr));
    BOOST_CHECK(!RCStage3SeedChainWireSemanticPin(bad).semantic_relation_complete);
}

BOOST_AUTO_TEST_CASE(coupled_signed_range_semantic_pin_wires_into_registry)
{
    namespace aq = air_quotient;
    namespace gf = gkr_field;
    const auto statement = CoupledStatement();
    const auto shape = MakeRCStage3CoupledShape(MakeToyRCCoupParams(), MakeV4RCCoupOptions());
    RCStage3CoupledSignedRangeManifest manifest;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        BuildRCStage3CoupledSignedRangeManifest(statement, shape, manifest, &why), why);

    RCStage3SignedRangePin pin;
    BOOST_REQUIRE(MakeRCStage3CoupledSignedRangePin(manifest, 0, pin, &why));
    std::vector<int64_t> values(pin.logical_rows);
    for (uint32_t row = 0; row < values.size(); ++row) {
        int64_t v = static_cast<int64_t>(row % (pin.max_abs + 1));
        values[row] = (row % 2 == 0) ? v : -v;
    }
    std::vector<std::vector<gf::Fp3>> columns;
    BOOST_REQUIRE(BuildRCStage3SignedRangeColumns(pin, values, columns, &why));
    pin.column_roots[kRCStage3RangeValue].root =
        aq::AirCommittedValuesRoot<gf::Fp3>(columns[kRCStage3RangeValue], pin.n_rows);
    RCStage3SignedRangeShardEntry s0;
    s0.pin = pin;
    s0.y_interval_root = pin.column_roots[kRCStage3RangeValue].root;

    std::vector<RCStage3SignedRangeShardEntry> one{s0};
    RCStage3SignedRangeAlgBinding committed;
    BOOST_REQUIRE_MESSAGE(ComputeRCStage3SignedRangeAlgBinding(one, committed, &why), why);
    RCStage3SignedRangeBindingResult r;
    BOOST_REQUIRE_MESSAGE(VerifyRCStage3SignedRangeAlgBinding(one, committed, r, &why), why);
    BOOST_CHECK(r.binding_complete);
    BOOST_CHECK(r.y_interval_equal);
    BOOST_CHECK(RCStage3SignedRangeWireSemanticPin(r).semantic_relation_complete);

    // Tamper: mismatched CoupledGemmOutputY interval root -> equality rejects.
    auto bad_entry = s0;
    bad_entry.y_interval_root = Filled(0x5A);
    std::vector<RCStage3SignedRangeShardEntry> mism{bad_entry};
    RCStage3SignedRangeAlgBinding cb;
    BOOST_REQUIRE(ComputeRCStage3SignedRangeAlgBinding(mism, cb, &why));
    RCStage3SignedRangeBindingResult bad;
    BOOST_CHECK(!VerifyRCStage3SignedRangeAlgBinding(mism, cb, bad, nullptr));
    BOOST_CHECK(!bad.y_interval_equal);
    BOOST_CHECK(!RCStage3SignedRangeWireSemanticPin(bad).semantic_relation_complete);
}

BOOST_AUTO_TEST_CASE(episode_wiring_semantic_pins_wire_into_registry)
{
    namespace aq = air_quotient;
    namespace gf = gkr_field;
    RCStage3SuccinctProof statement;
    statement.statement = RCStage3StatementKind::Episode;
    statement.public_inputs.height = 183;
    statement.public_inputs.n_bits = 0x207fffffU;
    statement.public_inputs.episode_profile = 2;
    statement.public_inputs.transcript_version = ENC_RC_V4;
    statement.public_inputs.header_commitment = Filled(0x11);
    statement.public_inputs.params_commitment = Filled(0x22);
    statement.public_inputs.sigma = Filled(0x33);
    statement.public_inputs.target = Filled(0xff);
    statement.public_inputs.episode_digest = Filled(0x44);
    statement.public_inputs.final_digest = Filled(0x44);

    RCEpisodeParams params;
    params.rounds = 1; params.d_head = 32; params.n_q = 32; params.n_ctx = 32;
    params.L_lyr = 1; params.d_model = 32; params.d_ff = 32; params.b_seq = 32;
    params.T_leaf = 64;
    const uint256 sc = RCStage3EpisodeStatementCommitment(statement);
    const auto layout = RCGkrTraceLayout(params);
    std::vector<RCStage3GemmExtractLayerBindings> bindings(layout.layers.size());
    for (uint32_t i = 0; i < bindings.size(); ++i) {
        auto& b = bindings[i];
        b.extract_prf = Filled(0x10 + i); b.operand_a_root = Filled(0x20 + i);
        b.operand_b_root = Filled(0x30 + i); b.gemm_y_root = Filled(0x40 + i);
        b.extract_input_root = Filled(0x50 + i); b.extract_output_root = Filled(0x60 + i);
        b.gemm_proof_root = Filled(0x70 + i); b.extract_recursive_root = Filled(0x80 + i);
        b.scale_schedule_root = Filled(0x90 + i); b.ctl_terminal_root = Filled(0xa0 + i);
    }
    std::string why;
    const auto built = BuildRCStage3GemmExtractManifest(params, sc, bindings, &why);
    BOOST_REQUIRE_MESSAGE(built.has_value(), why);
    RCStage3GemmExtractManifest manifest = *built;

    auto wiringRoot = [&](uint32_t first_column, uint32_t n_chunks, uint64_t count) {
        const auto root = ComputeRCStage3EpisodeWiringVectorRootFromValues(
            sc, first_column, n_chunks, std::vector<gf::Fp3>(count, gf::Fp3::Zero()), &why);
        return root.has_value() ? *root : uint256{};
    };

    RCStage3EpisodeGemmProduct gemm;
    gemm.statement_commitment = sc;
    gemm.layers.resize(manifest.layers.size());
    for (uint32_t i = 0; i < manifest.layers.size(); ++i) {
        auto& spec = manifest.layers[i];
        auto& layer = gemm.layers[i];
        layer.layer_ordinal = i;
        layer.operand_a.assign(static_cast<uint64_t>(spec.m) * spec.k, 0);
        layer.operand_b.assign(static_cast<uint64_t>(spec.k) * spec.n, 0);
        layer.gemm_y.assign(spec.gemm_cell_count, 0);
        if (spec.residual_first_column >= 0) layer.residual.assign(spec.gemm_cell_count, 0);
        spec.bindings.operand_a_root = wiringRoot(spec.a.first_column, spec.a.n_chunks, layer.operand_a.size());
        spec.bindings.operand_b_root = wiringRoot(spec.b.first_column, spec.b.n_chunks, layer.operand_b.size());
        spec.bindings.gemm_y_root = wiringRoot(spec.y_first_column, spec.y_chunks, layer.gemm_y.size());
    }
    gemm.manifest_commitment = ComputeRCStage3GemmExtractManifestCommitment(manifest);
    gemm.collection_commitment = Filled(0xc1);

    RCStage3EpisodeExtractProduct extract;
    extract.statement_commitment = sc;
    extract.manifest_commitment = gemm.manifest_commitment;
    extract.expected_tiles = manifest.total_extract_tiles;
    const uint256 zero_out_root = aq::AirCommittedValuesRoot<gf::Fp3>(
        std::vector<gf::Fp3>(kRCMxBlockLen, gf::Fp3::Zero()), kRCMxBlockLen);
    for (uint32_t lo = 0; lo < manifest.layers.size(); ++lo) {
        const auto& spec = manifest.layers[lo];
        for (uint64_t local = 0; local < spec.extract_tile_count; ++local) {
            RCStage3EpisodeExtractTileProduct tile;
            tile.global_tile = extract.tiles.size();
            tile.layer_ordinal = lo;
            tile.layer_tile_index = local;
            tile.sampler_pin.logical_rows = kRCMxBlockLen;
            tile.sampler_pin.n_rows = kRCMxBlockLen;
            tile.sampler_pin.n_coeffs = kRCMxBlockLen;
            tile.sampler_pin.column_roots.resize(aq::kRcSamplerNumCols);
            for (uint32_t col = 0; col < aq::kRcSamplerNumCols; ++col)
                tile.sampler_pin.column_roots[col] = {col, Filled(static_cast<unsigned char>(1 + ((col + lo) % 250)))};
            tile.sampler_pin.column_roots[aq::kColOut].root = zero_out_root;
            extract.tiles.push_back(std::move(tile));
        }
    }
    extract.collection_commitment = Filled(0xc2);

    RCStage3EpisodeWiringProduct wiring;
    BOOST_REQUIRE_MESSAGE(
        BuildRCStage3EpisodeWiringProduct(statement, manifest, gemm, extract, wiring, &why), why);

    const auto committed = ComputeRCStage3WiringLedgerRoots(wiring);
    RCStage3WiringBindingResult r;
    BOOST_REQUIRE_MESSAGE(
        VerifyRCStage3WiringLedgerBinding(manifest, wiring, committed, r, &why), why);
    BOOST_CHECK(r.binding_complete);
    const auto pin = RCStage3WiringWireSemanticPin(r);
    BOOST_CHECK(pin.transpose_complete);
    BOOST_CHECK(pin.residual_complete);
    BOOST_CHECK(pin.round_order_complete);

    // Tamper: substitute a transpose output root -> rejects.
    auto p = wiring;
    p.transpose_edges[0].transposed_vector_root = Filled(0xE2);
    RCStage3WiringBindingResult bad;
    BOOST_CHECK(!VerifyRCStage3WiringLedgerBinding(manifest, p, committed, bad, nullptr));
    BOOST_CHECK(!RCStage3WiringWireSemanticPin(bad).transpose_complete);

    // All three wiring endpoints are flipped in the registry.
    for (const auto& cell : CurrentRCStage3RelationEndpointCellAudit()) {
        if (cell.endpoint == RCStage3RelationEndpoint::EpisodeWiringTranspose ||
            cell.endpoint == RCStage3RelationEndpoint::EpisodeWiringResidual ||
            cell.endpoint == RCStage3RelationEndpoint::EpisodeWiringRoundOrder)
            BOOST_CHECK(cell.semantic_relation_complete);
    }
}

BOOST_AUTO_TEST_CASE(gemm_sumcheck_semantic_pin_wires_into_registry)
{
    namespace gf = gkr_field;
    const auto endpoint = RCStage3RelationEndpoint::EpisodeGemmSumcheck;
    BOOST_CHECK(RCStage3EndpointIsWiredBinding(endpoint));

    // Honest Thaler product-sumcheck transcript (real builder), K = 8.
    const auto t = BuildRCStage3HonestGemmSumcheckLayerTranscript(2, 3, 0xBEEF);
    const uint256 root = ComputeRCStage3GemmSumcheckRoot(t);
    RCStage3GemmSumcheckAlgBindingResult r;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        VerifyRCStage3GemmSumcheckAlgBinding(t, t.initial_claim, root, r, &why), why);
    BOOST_CHECK(r.binding_complete);
    BOOST_CHECK(r.air_proved);
    BOOST_CHECK(r.air_verified);
    const auto pin = RCStage3GemmSumcheckWireSemanticPin(r);
    BOOST_CHECK(pin.semantic_relation_complete);
    BOOST_CHECK(pin.sumcheck_root == root);

    // Tamper: a wrong initial claim (not the endpoint-7 MLE(Y)) rejects.
    RCStage3GemmSumcheckAlgBindingResult bad;
    const bool ok = VerifyRCStage3GemmSumcheckAlgBinding(
        t, gf::Add(t.initial_claim, gf::Fp3::One()), root, bad, nullptr);
    BOOST_CHECK(!ok);
    BOOST_CHECK(!RCStage3GemmSumcheckWireSemanticPin(bad).semantic_relation_complete);

    // The registry endpoint is flipped from the wired pin.
    for (const auto& cell : CurrentRCStage3RelationEndpointCellAudit()) {
        if (cell.endpoint == endpoint) BOOST_CHECK(cell.semantic_relation_complete);
    }
}

BOOST_AUTO_TEST_CASE(builder_trace_semantic_pin_wires_into_registry)
{
    const auto endpoint = RCStage3RelationEndpoint::EpisodeBuilderTrace;
    BOOST_CHECK(RCStage3EndpointIsWiredBinding(endpoint));

    // A real (synthetic-but-genuine) builder-trace product: two expansions each
    // with two dequant shards, three trace columns whose wiring_vector_root is
    // computed by the production ComputeRCStage3EpisodeWiringVectorRoot (= the
    // root endpoints 5/6 open, composing with the re-anchor).
    RCStage3EpisodeBuilderTraceProduct p;
    p.statement_commitment = WireSeed(0x5747);
    p.root_memory.endpoint = endpoint;
    std::vector<uint256> ep3;
    for (uint32_t j = 0; j < 2; ++j) {
        RCStage3EpisodeBuilderTraceExpansion e;
        e.expansion_index = j;
        e.kind = (j == 0) ? RCStage3EpisodeOperandKind::Q
                          : RCStage3EpisodeOperandKind::WUp;
        e.round_index = j;
        e.layer_index = 0;
        e.rows = 16;
        e.cols = 8;
        e.operand_xof_indices = {j * 2u, j * 2u + 1u};
        e.source_link_root = WireSeed(0x3000 + j);
        ep3.push_back(e.source_link_root);
        for (uint32_t s = 0; s < 2; ++s) {
            RCStage3EpisodeBuilderTraceAirShard sh;
            sh.shard_index = s;
            sh.output_root = WireSeed(0x4000 + j * 16 + s);
            e.shards.push_back(sh);
        }
        p.expansions.push_back(e);
    }
    for (uint32_t i = 0; i < 3; ++i) {
        RCStage3EpisodeBuilderTraceColumn c;
        c.trace_index = i;
        c.tensor = RCGkrTensor::Q;
        c.round_index = i;
        c.layer_index = 0;
        c.rows = 16;
        c.cols = 8;
        c.first_column = i * 8;
        c.n_chunks = 4;
        c.expansion_index = i % 2;
        std::vector<uint256> shard_roots;
        for (const auto& sh : p.expansions[c.expansion_index].shards)
            shard_roots.push_back(sh.output_root);
        c.wiring_vector_root = ComputeRCStage3EpisodeWiringVectorRoot(
            p.statement_commitment, c.first_column, c.n_chunks,
            static_cast<uint64_t>(c.n_chunks) * 8, shard_roots);
        p.trace_columns.push_back(c);
    }

    const auto roots = ComputeRCStage3BuilderTraceAlgRoots(p);
    RCStage3BuilderTraceAlgBindingResult r;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        VerifyRCStage3BuilderTraceAlgBinding(
            p, roots.expansion_ledger_root, roots.builder_trace_root, ep3, r, &why),
        why);
    BOOST_CHECK(r.binding_complete);
    const auto pin = RCStage3BuilderTraceWireSemanticPin(r);
    BOOST_CHECK(pin.semantic_relation_complete);
    BOOST_CHECK(pin.builder_trace_root == roots.builder_trace_root);
    BOOST_CHECK_EQUAL(pin.wiring_vector_roots.size(), p.trace_columns.size());

    // Tamper: a substituted committed builder_trace_root rejects.
    RCStage3BuilderTraceAlgBindingResult bad;
    uint256 wrong = roots.builder_trace_root;
    wrong.begin()[0] ^= 0x01;
    const bool ok = VerifyRCStage3BuilderTraceAlgBinding(
        p, roots.expansion_ledger_root, wrong, ep3, bad, nullptr);
    BOOST_CHECK(!ok);
    BOOST_CHECK(!RCStage3BuilderTraceWireSemanticPin(bad).semantic_relation_complete);

    for (const auto& cell : CurrentRCStage3RelationEndpointCellAudit()) {
        if (cell.endpoint == endpoint) BOOST_CHECK(cell.semantic_relation_complete);
    }
}

// ---------------------------------------------------------------------------
// C_rho assembly core: CoupledPermutation role AIR as the column-shifted direct
// product of the copy kernel + one alg_hash opening block per required scalar
// endpoint, boundary-aliased. Verified at the constraint-system level with
// air_recurse::CountWitnessViolationsOnH (no FRI): honest joint witness -> 0
// violations (completeness), any child/opening tamper -> > 0 (soundness).
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(coupled_permutation_role_air_assembles_and_rejects_tamper)
{
    namespace ar = air_recurse;
    namespace gf = gkr_field;

    const gf::Fp3 cell = gf::Fp3::FromFp(gf::FromU64(0x1234567ULL));
    const uint32_t leaf_index = 0;
    const uint32_t path_len = 3; // rows = 4 (power of two T-BIND)

    std::string why;
    const RCStage3RoleAirProduct product =
        BuildRCStage3CoupledPermutationRoleAir(cell, leaf_index, path_len, &why);
    BOOST_REQUIRE_MESSAGE(product.ok, why);
    BOOST_CHECK(product.role == RCStage3RelationRole::CoupledPermutation);

    // Shape: 2-col copy kernel + two 271-col opening blocks; 4 rows.
    BOOST_CHECK_EQUAL(product.cs.n_rows, path_len + 1);
    BOOST_CHECK_EQUAL(product.fragment_columns, 2U);
    BOOST_CHECK_EQUAL(product.opening_blocks, 2U);
    BOOST_CHECK_EQUAL(product.cs.n_columns,
                      2U + 2U * kRCStage3OpeningWidth);
    BOOST_REQUIRE_EQUAL(product.endpoints.size(), 2U);
    BOOST_CHECK(product.endpoints[0] ==
                RCStage3RelationEndpoint::CoupledPermutationInput);
    BOOST_CHECK(product.endpoints[1] ==
                RCStage3RelationEndpoint::CoupledPermutationOutput);

    // Every required endpoint of the role is covered by an opening block.
    const auto& required =
        RequiredRCStage3RelationEndpoints(RCStage3RelationRole::CoupledPermutation);
    BOOST_CHECK_EQUAL(required.size(), product.endpoints.size());

    // NF (no free cells): the witness partitions the product columns exactly,
    // every column has n_rows values, and the endpoint value columns sit in the
    // opening blocks (fragment-determined | endpoint-opened provenance).
    BOOST_REQUIRE_EQUAL(product.witness.size(), product.cs.n_columns);
    for (const auto& col : product.witness) {
        BOOST_CHECK_EQUAL(col.size(), product.cs.n_rows);
    }
    BOOST_REQUIRE_EQUAL(product.endpoint_value_columns.size(), 2U);
    BOOST_CHECK_EQUAL(product.endpoint_value_columns[0],
                      2U + kRCStage3OpeningValueColumn);
    BOOST_CHECK_EQUAL(product.endpoint_value_columns[1],
                      2U + kRCStage3OpeningWidth + kRCStage3OpeningValueColumn);

    // Completeness: honest joint witness satisfies every constraint on H.
    uint32_t first_row = 0;
    std::string first_name;
    const uint32_t honest = ar::CountWitnessViolationsOnH(
        product.cs, product.witness, &first_row, &first_name);
    BOOST_CHECK_MESSAGE(honest == 0,
                        "honest witness violated " + first_name + " at row " +
                            std::to_string(first_row));

    // Soundness A: tamper a child cell (kernel COPY_INPUT). Breaks the copy
    // relation and the endpoint boundary alias.
    {
        auto w = product.witness;
        w[coupled_air_col::COPY_INPUT][0] =
            gf::Add(w[coupled_air_col::COPY_INPUT][0], gf::Fp3::One());
        BOOST_CHECK(ar::CountWitnessViolationsOnH(product.cs, w) > 0);
    }

    // Soundness B: tamper an opening value column (breaks the leaf CTL-value
    // bind and the boundary alias to the kernel cell).
    {
        auto w = product.witness;
        const uint32_t v = product.endpoint_value_columns[1];
        w[v][0] = gf::Add(w[v][0], gf::Fp3::One());
        BOOST_CHECK(ar::CountWitnessViolationsOnH(product.cs, w) > 0);
    }

    // Soundness C: tamper an opening authentication sibling (folds to a root
    // that mismatches the pinned committed manifest root).
    {
        auto w = product.witness;
        // Opening block 0 sibling lane base = fragment(2) + kGlueSibBase(266).
        const uint32_t sib = 2U + 266U;
        w[sib][0] = gf::Add(w[sib][0], gf::Fp3::One());
        BOOST_CHECK(ar::CountWitnessViolationsOnH(product.cs, w) > 0);
    }

    // RC (pure-shape resolvable): deterministic from (role, cell, index,
    // path_len) alone — a second assembly is byte-identical in shape/constraints.
    const RCStage3RoleAirProduct again =
        BuildRCStage3CoupledPermutationRoleAir(cell, leaf_index, path_len, nullptr);
    BOOST_REQUIRE(again.ok);
    BOOST_CHECK_EQUAL(again.cs.n_columns, product.cs.n_columns);
    BOOST_CHECK_EQUAL(again.cs.n_rows, product.cs.n_rows);
    BOOST_CHECK_EQUAL(again.cs.constraints.size(),
                      product.cs.constraints.size());
    BOOST_CHECK_EQUAL(
        ar::CountWitnessViolationsOnH(again.cs, again.witness), 0U);

    // FS (proof-independent role seed): ComputeRCStage3RecursiveRoleSeed takes no
    // proof and is deterministic; distinct roles derive distinct bases.
    const RCStage3SuccinctProof statement = Statement();
    const uint256 commit = Filled(0x5a);
    const uint256 seed_a = ComputeRCStage3RecursiveRoleSeed(
        statement, RCStage3RelationRole::CoupledPermutation, commit);
    const uint256 seed_b = ComputeRCStage3RecursiveRoleSeed(
        statement, RCStage3RelationRole::CoupledPermutation, commit);
    const uint256 seed_c = ComputeRCStage3RecursiveRoleSeed(
        statement, RCStage3RelationRole::CoupledMix, commit);
    BOOST_CHECK(seed_a == seed_b);
    BOOST_CHECK(seed_a != seed_c);
}

// Faithful wired-closer core: the multi-permutation sponge CS reproduces
// alg_hash::LeafHashRow (the wired ledger-fold leaf hash) and rejects any tamper.
BOOST_AUTO_TEST_CASE(leafhashrow_sponge_cs_reproduces_and_rejects_tamper)
{
    namespace ar = air_recurse;
    namespace gf = gkr_field;
    namespace ah = alg_hash;

    std::vector<gf::Fp3> row; // 13-lane row like a SignedRange shard leaf
    for (uint32_t i = 0; i < 13; ++i)
        row.push_back(gf::Fp3::FromFp(gf::FromU64(1000 + i * 7)));
    const uint32_t index = 3;

    const RCStage3SpongeProduct sp =
        BuildRCStage3LeafHashRowSpongeProduct(row, index);
    BOOST_REQUIRE_MESSAGE(sp.ok, sp.note);
    // The in-circuit digest equals the real primitive.
    BOOST_CHECK(sp.digest == ah::LeafHashRow(row, index));
    BOOST_CHECK_EQUAL(sp.cs.n_columns, kRCStage3SpongeRowWidth);

    // Honest sponge witness satisfies every constraint on H.
    uint32_t fr = 0;
    std::string fn;
    BOOST_CHECK_MESSAGE(
        ar::CountWitnessViolationsOnH(sp.cs, sp.witness, &fr, &fn) == 0,
        "sponge honest violated " + fn + " row " + std::to_string(fr));

    // Tamper a rate-message lane -> row-0 absorb + downstream digest fail.
    {
        auto w = sp.witness;
        w[130][0] = gf::Add(w[130][0], gf::Fp3::One());
        BOOST_CHECK(ar::CountWitnessViolationsOnH(sp.cs, w) > 0);
    }
    // Tamper a permutation S-box cell -> its degree-7 identity fails.
    {
        auto w = sp.witness;
        w[20][0] = gf::Add(w[20][0], gf::Fp3::One());
        BOOST_CHECK(ar::CountWitnessViolationsOnH(sp.cs, w) > 0);
    }
    // A different committed row pins a different digest -> the original honest
    // sponge witness violates that CS's terminal squeeze.
    {
        std::vector<gf::Fp3> row2 = row;
        row2[5] = gf::Add(row2[5], gf::Fp3::One());
        const RCStage3SpongeProduct sp2 =
            BuildRCStage3LeafHashRowSpongeProduct(row2, index);
        BOOST_REQUIRE(sp2.ok);
        BOOST_CHECK(!(sp2.digest == sp.digest));
        BOOST_CHECK(ar::CountWitnessViolationsOnH(sp2.cs, sp.witness) > 0);
    }
}

// Faithful SignedRange wired ledger-fold closer: sponge over the real ShardLeaf
// row + broadcast-column Y-root equality bus. Cross-checked against the real
// ComputeRCStage3SignedRangeLedgerFold; every tamper rejects.
BOOST_AUTO_TEST_CASE(signed_range_wired_closer_matches_real_fold_and_rejects_tamper)
{
    namespace ar = air_recurse;
    namespace gf = gkr_field;
    namespace ah = alg_hash;

    const uint64_t cell_begin = 100, max_abs = 255;
    const uint32_t logical_rows = 7, n_rows_meta = 8, shard = 0;
    const uint256 rv = Filled(0x11);

    auto pack = [](const ah::Digest& d) {
        uint256 o;
        unsigned char* p = o.begin();
        for (uint32_t i = 0; i < ah::kAlgHashDigestLen; ++i) {
            const uint64_t l = static_cast<uint64_t>(gf::Canonical(d[i]));
            for (uint32_t b = 0; b < 8; ++b)
                p[i * 8 + b] = static_cast<unsigned char>((l >> (8 * b)) & 0xFF);
        }
        return o;
    };
    auto real_fold = [&](const uint256& rvr, const uint256& yr) {
        RCStage3SignedRangePin pin;
        pin.shard_index = shard;
        pin.cell_begin = cell_begin;
        pin.logical_rows = logical_rows;
        pin.n_rows = n_rows_meta;
        pin.max_abs = max_abs;
        pin.column_roots.resize(kRCStage3SignedRangeColumns);
        for (uint32_t c = 0; c < kRCStage3SignedRangeColumns; ++c)
            pin.column_roots[c].column = c;
        pin.column_roots[kRCStage3RangeValue].root = rvr;
        RCStage3SignedRangeShardEntry e{pin, yr};
        return ComputeRCStage3SignedRangeLedgerFold({e});
    };

    // Honest binding: RANGE_VALUE root == Y interval root.
    const RCStage3WiredCloserProduct c =
        BuildRCStage3SignedRangeWiredCloserProduct(
            shard, cell_begin, logical_rows, n_rows_meta, max_abs, rv, rv);
    BOOST_REQUIRE_MESSAGE(c.ok, c.note);
    BOOST_CHECK_EQUAL(c.root_equality_gadgets, 4U);
    // Faithful: the in-circuit committed digest == the REAL ledger fold.
    BOOST_CHECK(pack(c.committed_digest) == real_fold(rv, rv));
    // Honest ledger-fold witness satisfies every constraint on H.
    uint32_t fr = 0;
    std::string fn;
    BOOST_CHECK_MESSAGE(
        ar::CountWitnessViolationsOnH(c.cs, c.witness, &fr, &fn) == 0,
        "wired honest violated " + fn + " row " + std::to_string(fr));

    // Tamper: RANGE_VALUE root != Y interval root -> the sponge still hashes a
    // valid message, but the broadcast equality bus rejects.
    {
        const RCStage3WiredCloserProduct bad =
            BuildRCStage3SignedRangeWiredCloserProduct(
                shard, cell_begin, logical_rows, n_rows_meta, max_abs, rv,
                Filled(0x22));
        BOOST_REQUIRE(bad.ok);
        BOOST_CHECK(ar::CountWitnessViolationsOnH(bad.cs, bad.witness) > 0);
    }
    // Tamper a leaf permutation cell -> S-box identity fails.
    {
        auto w = c.witness;
        w[20][0] = gf::Add(w[20][0], gf::Fp3::One());
        BOOST_CHECK(ar::CountWitnessViolationsOnH(c.cs, w) > 0);
    }
    // Tamper the committed authority root: a closer over a different shard meta
    // pins a different fold root; the original honest witness violates it.
    {
        const RCStage3WiredCloserProduct other =
            BuildRCStage3SignedRangeWiredCloserProduct(
                shard, cell_begin + 1, logical_rows, n_rows_meta, max_abs, rv,
                rv);
        BOOST_REQUIRE(other.ok);
        BOOST_CHECK(!(pack(other.committed_digest) == pack(c.committed_digest)));
        BOOST_CHECK(ar::CountWitnessViolationsOnH(other.cs, c.witness) > 0);
    }
}

// First MIXED scalar+wired role C_ρ: CoupledGemm = a·b kernel ⊕ A/B/Y scalar
// openings ⊕ SignedRange wired ledger-fold closer, on 8 shared rows.
BOOST_AUTO_TEST_CASE(coupled_gemm_mixed_role_air_assembles_and_rejects_tamper)
{
    namespace ar = air_recurse;
    namespace gf = gkr_field;

    const RCStage3RoleAirProduct p = BuildRCStage3CoupledGemmRoleAir();
    BOOST_REQUIRE_MESSAGE(p.ok, p.note);
    BOOST_CHECK(p.role == RCStage3RelationRole::CoupledGemm);
    BOOST_CHECK_EQUAL(p.cs.n_rows, 8U);
    // 4 required endpoints: A/B/Y scalar + SignedRange wired.
    BOOST_REQUIRE_EQUAL(p.endpoints.size(), 4U);
    BOOST_CHECK(p.endpoints[3] ==
                RCStage3RelationEndpoint::CoupledGemmSignedRange);
    // 3 scalar opening blocks present.
    BOOST_CHECK_EQUAL(RCStage3CountInCsOpeningBlocks(p.cs), 3U);
    BOOST_REQUIRE_EQUAL(p.witness.size(), p.cs.n_columns);

    // Completeness: the honest composed witness satisfies every constraint.
    uint32_t fr = 0;
    std::string fn;
    BOOST_CHECK_MESSAGE(
        ar::CountWitnessViolationsOnH(p.cs, p.witness, &fr, &fn) == 0,
        "gemm honest violated " + fn + " row " + std::to_string(fr));

    // Tamper the GEMM operand A cell -> accumulator + opening alias fail.
    {
        auto w = p.witness;
        w[coupled_air_col::GEMM_A][0] =
            gf::Add(w[coupled_air_col::GEMM_A][0], gf::Fp3::One());
        BOOST_CHECK(ar::CountWitnessViolationsOnH(p.cs, w) > 0);
    }
    // Tamper an A-opening value column -> leaf bind + alias fail.
    {
        auto w = p.witness;
        const uint32_t v = p.endpoint_value_columns[0];
        w[v][0] = gf::Add(w[v][0], gf::Fp3::One());
        BOOST_CHECK(ar::CountWitnessViolationsOnH(p.cs, w) > 0);
    }
    // Tamper the SignedRange wired closer's leaf permutation -> sponge fails.
    {
        auto w = p.witness;
        const uint32_t wired_base = p.endpoint_value_columns[3];
        w[wired_base + 20][0] = gf::Add(w[wired_base + 20][0], gf::Fp3::One());
        BOOST_CHECK(ar::CountWitnessViolationsOnH(p.cs, w) > 0);
    }
}

// Rigor cross-check: each equality-free wired closer's in-circuit committed
// digest == the REAL fold-root function for the matching real entry, driven
// through the production function (not a stub) — matching SignedRange's bar.
BOOST_AUTO_TEST_CASE(wired_closers_match_real_fold_roots)
{
    namespace ar = air_recurse;
    namespace gf = gkr_field;
    namespace ah = alg_hash;

    auto pack = [](const ah::Digest& d) {
        uint256 o;
        unsigned char* p = o.begin();
        for (uint32_t i = 0; i < ah::kAlgHashDigestLen; ++i) {
            const uint64_t l = static_cast<uint64_t>(gf::Canonical(d[i]));
            for (uint32_t b = 0; b < 8; ++b)
                p[i * 8 + b] = static_cast<unsigned char>((l >> (8 * b)) & 0xFF);
        }
        return o;
    };
    auto root_of = [](unsigned char v) {
        uint256 r;
        std::fill(r.begin(), r.end(), v);
        return r;
    };
    auto push_root = [](std::vector<gf::Fp3>& row, const uint256& root) {
        const unsigned char* p = root.begin();
        for (uint32_t i = 0; i < 4; ++i) {
            uint64_t limb = 0;
            for (uint32_t b = 0; b < 8; ++b)
                limb |= static_cast<uint64_t>(p[i * 8 + b]) << (8 * b);
            row.push_back(gf::FromU64_3(limb));
        }
    };
    auto verify_ok = [](const RCStage3SpongeProduct& sp) {
        return sp.ok &&
               ar::CountWitnessViolationsOnH(sp.cs, sp.witness) == 0;
    };

    // --- Sumcheck (RoundLeaf fold) ---
    {
        std::vector<gf::Fp3> row = {gf::FromU64_3(2), gf::FromU64_3(1),
                                    gf::FromU64_3(7), gf::FromU64_3(11),
                                    gf::FromU64_3(13), gf::FromU64_3(17)};
        const RCStage3SpongeProduct sp =
            BuildRCStage3LeafHashRowSpongeProduct(row, 1, 8);
        BOOST_REQUIRE(verify_ok(sp));
        RCStage3GemmSumcheckLayerTranscript t;
        t.layer_ordinal = 2;
        t.rounds.push_back({gf::FromU64_3(7), gf::FromU64_3(11),
                            gf::FromU64_3(13), gf::FromU64_3(17)});
        BOOST_CHECK(pack(sp.digest) == ComputeRCStage3GemmSumcheckRoot(t));
    }

    // --- Wiring: Transpose / Residual / RoundOrder (edge-ledger folds) ---
    {
        std::vector<gf::Fp3> row = {gf::FromU64_3(0), gf::FromU64_3(5),
                                    gf::FromU64_3(2), gf::FromU64_3(1),
                                    gf::FromU64_3(0), gf::FromU64_3(4),
                                    gf::FromU64_3(8), gf::FromU64_3(8),
                                    gf::FromU64_3(64)};
        push_root(row, root_of(0x21));
        push_root(row, root_of(0x22));
        push_root(row, root_of(0x23));
        const RCStage3SpongeProduct sp =
            BuildRCStage3LeafHashRowSpongeProduct(row, 0, 16);
        BOOST_REQUIRE(verify_ok(sp));
        RCStage3EpisodeWiringProduct product;
        RCStage3EpisodeWiringTransposeEdge e;
        e.schedule.schedule_index = 5;
        e.schedule.layer_ordinal = 2;
        e.schedule.slot = RCStage3EpisodeWiringOperandSlot::A;
        e.schedule.first_column = 0;
        e.schedule.n_chunks = 4;
        e.schedule.source_rows = 8;
        e.schedule.source_cols = 8;
        e.schedule.value_count = 64;
        e.schedule.registered_source_root = root_of(0x21);
        e.pin.pin_commitment = root_of(0x22);
        e.transposed_vector_root = root_of(0x23);
        product.transpose_edges.push_back(e);
        BOOST_CHECK(pack(sp.digest) ==
                    ComputeRCStage3WiringLedgerRoots(product).transpose_proof_root);
    }
    {
        std::vector<gf::Fp3> row = {gf::FromU64_3(0), gf::FromU64_3(5),
                                    gf::FromU64_3(2), gf::FromU64_3(0),
                                    gf::FromU64_3(4), gf::FromU64_3(64)};
        push_root(row, root_of(0x31));
        push_root(row, root_of(0x32));
        push_root(row, root_of(0x33));
        const RCStage3SpongeProduct sp =
            BuildRCStage3LeafHashRowSpongeProduct(row, 0, 16);
        BOOST_REQUIRE(verify_ok(sp));
        RCStage3EpisodeWiringProduct product;
        RCStage3EpisodeWiringResidualEdge e;
        e.schedule.schedule_index = 5;
        e.schedule.layer_ordinal = 2;
        e.schedule.residual_first_column = 0;
        e.schedule.residual_n_chunks = 4;
        e.schedule.value_count = 64;
        e.schedule.registered_y_root = root_of(0x31);
        e.schedule.registered_residual_root = root_of(0x32);
        e.pin.pin_commitment = root_of(0x33);
        product.residual_edges.push_back(e);
        BOOST_CHECK(pack(sp.digest) ==
                    ComputeRCStage3WiringLedgerRoots(product).residual_proof_root);
    }
    {
        std::vector<gf::Fp3> row = {gf::FromU64_3(0), gf::FromU64_3(5),
                                    gf::FromU64_3(1), gf::FromU64_3(2),
                                    gf::FromU64_3(3), gf::FromU64_3(0),
                                    gf::FromU64_3(4), gf::FromU64_3(64)};
        push_root(row, root_of(0x41));
        push_root(row, root_of(0x42));
        const RCStage3SpongeProduct sp =
            BuildRCStage3LeafHashRowSpongeProduct(row, 0, 16);
        BOOST_REQUIRE(verify_ok(sp));
        RCStage3EpisodeWiringProduct product;
        RCStage3EpisodeWiringRoundOrderEdge e;
        e.schedule.schedule_index = 5;
        e.schedule.producer_layer_ordinal = 1;
        e.schedule.consumer_layer_ordinal = 2;
        e.schedule.round_index = 3;
        e.schedule.first_column = 0;
        e.schedule.n_chunks = 4;
        e.schedule.value_count = 64;
        e.schedule.registered_consumer_root = root_of(0x41);
        e.pin.pin_commitment = root_of(0x42);
        product.round_order_edges.push_back(e);
        BOOST_CHECK(pack(sp.digest) ==
                    ComputeRCStage3WiringLedgerRoots(product)
                        .round_order_proof_root);
    }

    // --- BuilderTrace (TraceColumnLeaf fold -> builder_trace_root) ---
    {
        std::vector<gf::Fp3> row = {gf::FromU64_3(0), gf::FromU64_3(1),
                                    gf::FromU64_3(2), gf::FromU64_3(3),
                                    gf::FromU64_3(8), gf::FromU64_3(8),
                                    gf::FromU64_3(0), gf::FromU64_3(4),
                                    gf::FromU64_3(0)};
        push_root(row, root_of(0x5b));
        const RCStage3SpongeProduct sp =
            BuildRCStage3LeafHashRowSpongeProduct(row, 0, 8);
        BOOST_REQUIRE(verify_ok(sp));
        RCStage3EpisodeBuilderTraceProduct product;
        RCStage3EpisodeBuilderTraceColumn c;
        c.trace_index = 0;
        c.tensor = static_cast<RCGkrTensor>(1);
        c.round_index = 2;
        c.layer_index = 3;
        c.rows = 8;
        c.cols = 8;
        c.first_column = 0;
        c.n_chunks = 4;
        c.expansion_index = 0;
        c.wiring_vector_root = root_of(0x5b);
        product.trace_columns.push_back(c);
        BOOST_CHECK(pack(sp.digest) ==
                    ComputeRCStage3BuilderTraceAlgRoots(product).builder_trace_root);
    }
}

BOOST_AUTO_TEST_CASE(
    no_kernel_real_stream_manifests_bind_root_and_ctl_value_together)
{
    namespace gf = gkr_field;
    const std::array<uint32_t, 8> seed_a{
        0x10U, 0x11U, 0x12U, 0x13U,
        0x14U, 0x15U, 0x16U, 0x17U};
    const std::array<uint32_t, 8> seed_b{
        0x20U, 0x21U, 0x22U, 0x23U,
        0x24U, 0x25U, 0x26U, 0x27U};
    const std::vector<RCStage3StreamEndpointManifest>
        manifests{
            BuildRCStage3StreamEndpointCanonicalManifest(
                RCStage3StreamFamilyForEndpoint(
                    RCStage3RelationEndpoint::
                        EpisodeBuilderSeedChain),
                seed_a, 0, 3),
            BuildRCStage3StreamEndpointCanonicalManifest(
                RCStage3StreamFamilyForEndpoint(
                    RCStage3RelationEndpoint::
                        EpisodeBuilderOperandXof),
                seed_b, 0, 3),
        };
    const std::vector<gf::Fp3> openings{
        gf::FromU64_3(7)};
    std::string why;
    const auto role =
        BuildRCStage3NoKernelRoleAir(
            RCStage3RelationRole::
                EpisodeDeterministicBuilder,
            &why, &openings, nullptr, &manifests);
    BOOST_REQUIRE_MESSAGE(role.ok, why);
    BOOST_REQUIRE_EQUAL(role.endpoints.size(), 4U);
    BOOST_REQUIRE_EQUAL(
        role.endpoint_value_columns.size(), 4U);
    BOOST_REQUIRE_EQUAL(
        role.endpoint_committed_roots.size(), 4U);

    for (uint32_t stream = 0; stream < 2; ++stream) {
        const uint32_t endpoint_index = 1U + stream;
        std::array<uint32_t, 8> root{};
        BOOST_REQUIRE(
            RCStage3StreamEndpointCommittedRoot(
                RCStage3StreamFamilyForEndpoint(
                    role.endpoints[endpoint_index]),
                manifests[stream], root, &why));
        for (uint32_t limb = 0; limb < 4; ++limb) {
            const uint64_t packed =
                uint64_t{root[2U * limb]} |
                (uint64_t{root[2U * limb + 1U]}
                 << 32);
            BOOST_CHECK_EQUAL(
                role.endpoint_committed_roots[
                    endpoint_index][limb],
                packed);
        }
        const uint32_t value_column =
            role.endpoint_value_columns[
                endpoint_index];
        BOOST_REQUIRE_LT(
            value_column, role.witness.size());
        BOOST_CHECK(gf::Eq(
            role.witness[value_column][0],
            RCStage3StreamEndpointCtlValue(
                manifests[stream])));
    }

    std::vector<std::array<uint32_t, 8>>
        substituted_roots(2);
    BOOST_REQUIRE(
        RCStage3StreamEndpointCommittedRoot(
            RCStage3StreamFamilyForEndpoint(
                RCStage3RelationEndpoint::
                    EpisodeBuilderSeedChain),
            manifests[0], substituted_roots[0],
            &why));
    BOOST_REQUIRE(
        RCStage3StreamEndpointCommittedRoot(
            RCStage3StreamFamilyForEndpoint(
                RCStage3RelationEndpoint::
                    EpisodeBuilderOperandXof),
            manifests[1], substituted_roots[1],
            &why));
    ++substituted_roots[0][0];
    const auto rejected =
        BuildRCStage3NoKernelRoleAir(
            RCStage3RelationRole::
                EpisodeDeterministicBuilder,
            &why, &openings, &substituted_roots,
            &manifests);
    BOOST_CHECK(!rejected.ok);
    BOOST_CHECK(
        why.find("stream_root_manifest_mismatch") !=
        std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()
