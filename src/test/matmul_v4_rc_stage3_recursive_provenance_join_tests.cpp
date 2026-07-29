// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_air_quotient_codec.h>
#include <matmul/matmul_v4_rc_stage3_recursive_provenance_join.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <vector>

namespace rpj =
    matmul::v4::rc::recursive_provenance_join;
namespace rc = matmul::v4::rc;
namespace gf = matmul::v4::rc::gkr_field;

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_recursive_provenance_join_tests)

namespace {

uint256 Root(uint32_t value)
{
    uint256 out;
    for (uint32_t i = 0; i < out.size(); ++i) {
        out.begin()[i] =
            static_cast<unsigned char>(
                (value + 37U * i) & 0xffU);
    }
    if (out.IsNull()) out.begin()[0] = 1;
    return out;
}

rpj::RecursiveProvenanceShapeV1 Shape(
    uint32_t exchange_rounds = 3)
{
    rpj::RecursiveProvenanceShapeV1 out;
    out.episode_round_roots = 4;
    out.coupled_barriers = 3;
    out.coupled_lobes = 2;
    out.coupled_exchange_rounds = exchange_rounds;
    out.episode_builder_params_root = Root(1);
    out.episode_header_target_root = Root(25);
    return out;
}

rpj::RecursiveProvenanceWitnessV1 Witness(
    const rpj::RecursiveProvenanceShapeV1& shape)
{
    rpj::RecursiveProvenanceWitnessV1 out;
    uint32_t root_id = 100;
    for (const auto role :
         rpj::CanonicalRecursiveProvenanceRoleOrderV1()) {
        const uint256 root = Root(root_id++);
        out.roles.push_back({role, root, root, true});
    }
    for (const auto& endpoint :
         rc::CurrentRCStage3RelationEndpointCellAudit()) {
        uint256 root = Root(root_id++);
        if (endpoint.endpoint ==
            rc::RCStage3RelationEndpoint::
                EpisodeBuilderParams) {
            root = shape.episode_builder_params_root;
        } else if (
            endpoint.endpoint ==
            rc::RCStage3RelationEndpoint::
                EpisodeDigestHeaderTarget) {
            root = shape.episode_header_target_root;
        }
        out.endpoints.push_back({
            endpoint.endpoint, endpoint.role,
            root, root, true});
    }
    std::vector<rpj::RecursiveProvenanceEventKeyV1>
        events;
    BOOST_REQUIRE(
        rpj::BuildCanonicalRecursiveProvenanceEventScheduleV1(
            shape, events, nullptr));
    for (const auto& key : events) {
        const uint256 root = Root(root_id++);
        out.events.push_back({
            key, root, root, true, true});
    }
    return out;
}

struct ParentAliasFixture {
    rpj::RecursiveProvenanceShapeV1 shape;
    rpj::RecursiveProvenanceParentAliasRefsV1 refs;
    rpj::aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    uint256 fixed_offset_schedule_commitment{};
};

ParentAliasFixture ParentAliases()
{
    ParentAliasFixture out;
    out.shape = Shape();
    out.cs.n_rows = 256;
    out.cs.n_columns = 16;
    out.columns.assign(
        out.cs.n_columns,
        std::vector<gf::Fp3>(
            out.cs.n_rows, gf::Fp3::Zero()));
    out.refs.parent_rows = out.cs.n_rows;
    out.refs.parent_original_columns = out.cs.n_columns;
    uint32_t row = 0;
    const auto install =
        [&](const uint256& root,
            rpj::RecursiveProvenanceParentRootAliasV1&
                alias) {
            BOOST_REQUIRE_LT(row, out.cs.n_rows);
            for (uint32_t limb = 0; limb < 8; ++limb) {
                const uint32_t offset = 4 * limb;
                const uint32_t value =
                    static_cast<uint32_t>(
                        root.begin()[offset]) |
                    (static_cast<uint32_t>(
                         root.begin()[offset + 1])
                     << 8) |
                    (static_cast<uint32_t>(
                         root.begin()[offset + 2])
                     << 16) |
                    (static_cast<uint32_t>(
                         root.begin()[offset + 3])
                     << 24);
                out.columns[limb][row] =
                    gf::Fp3::FromFp(
                        gf::FromU64(value));
                out.columns[8 + limb][row] =
                    out.columns[limb][row];
                alias.verifier_output.limb[limb] =
                    {limb, row};
                alias.named_consumer.limb[limb] =
                    {8 + limb, row};
            }
            ++row;
        };
    uint32_t id = 0x1000;
    const auto& role_order =
        rpj::CanonicalRecursiveProvenanceRoleOrderV1();
    for (uint32_t role = 0;
         role < out.refs.roles.size(); ++role) {
        out.refs.roles[role].role = role_order[role];
        install(
            Root(id++),
            out.refs.roles[role].root);
    }
    const auto endpoint_audit =
        rc::CurrentRCStage3RelationEndpointCellAudit();
    BOOST_REQUIRE_EQUAL(endpoint_audit.size(), 52U);
    for (uint32_t endpoint = 0;
         endpoint < out.refs.endpoints.size();
         ++endpoint) {
        uint256 root = Root(id++);
        if (endpoint == 0) {
            root =
                out.shape.episode_builder_params_root;
        } else if (endpoint == 24) {
            root =
                out.shape.episode_header_target_root;
        }
        out.refs.endpoints[endpoint].endpoint =
            endpoint_audit[endpoint].endpoint;
        out.refs.endpoints[endpoint].role =
            endpoint_audit[endpoint].role;
        install(
            root,
            out.refs.endpoints[endpoint].root);
    }
    std::vector<rpj::RecursiveProvenanceEventKeyV1>
        events;
    BOOST_REQUIRE(
        rpj::BuildCanonicalRecursiveProvenanceEventScheduleV1(
            out.shape, events, nullptr));
    for (const auto& key : events) {
        rpj::RecursiveProvenanceParentEventAliasV1 event;
        event.key = key;
        install(Root(id++), event.root);
        out.refs.events.push_back(std::move(event));
    }
    BOOST_REQUIRE_LT(row, out.cs.n_rows);
    out.fixed_offset_schedule_commitment =
        rpj::
            ComputeRecursiveProvenanceParentAliasScheduleCommitmentV1(
                out.shape, out.refs);
    BOOST_REQUIRE(
        !out.fixed_offset_schedule_commitment.IsNull());
    return out;
}

} // namespace

BOOST_AUTO_TEST_CASE(
    exact_52_endpoint_14_role_schedule_and_temporal_cells)
{
    const auto shape = Shape();
    const auto witness = Witness(shape);
    const auto product =
        rpj::BuildRecursiveProvenanceJoinV1(
            shape, witness);
    BOOST_REQUIRE_MESSAGE(product.valid, product.note);
    BOOST_CHECK_EQUAL(witness.roles.size(), 14U);
    BOOST_CHECK_EQUAL(witness.endpoints.size(), 52U);
    BOOST_CHECK_GT(product.graph_named_root_events, 0U);
    BOOST_CHECK_GT(product.temporal_events, 0U);
    BOOST_CHECK_EQUAL(product.violations, 0U);
    BOOST_CHECK(product.exact_role_order);
    BOOST_CHECK(product.exact_endpoint_order);
    BOOST_CHECK(product.exact_event_order);
    BOOST_CHECK(product.public_anchors_1_and_25_pinned);
    BOOST_CHECK(
        product.
            every_supplied_cell_host_reported_locally_verified);
    BOOST_CHECK(product.values_are_ordinary_witness_columns);
    BOOST_CHECK(product.selectors_and_positions_preprocessed);
    BOOST_CHECK(product.temporal_edges_explicit);
    BOOST_CHECK(!product.same_parent_child_verifier_owned);
    BOOST_CHECK(!product.recursive_authority);
    BOOST_CHECK(!product.production_complete);

    const auto temporal_chain = std::count_if(
        witness.events.begin(), witness.events.end(),
        [](const auto& event) {
            return event.key.kind ==
                rpj::RecursiveProvenanceEventKindV1::
                    CoupledMaterialRoundChain;
        });
    BOOST_CHECK_EQUAL(
        temporal_chain,
        shape.coupled_barriers *
            (shape.coupled_exchange_rounds - 1U));
}

BOOST_AUTO_TEST_CASE(
    omission_duplicate_relabel_reorder_and_round_shift_reject)
{
    const auto shape = Shape();
    const auto honest = Witness(shape);

    auto omitted = honest;
    omitted.endpoints.erase(omitted.endpoints.begin() + 7);
    BOOST_CHECK(
        !rpj::BuildRecursiveProvenanceJoinV1(
             shape, omitted).valid);

    auto duplicate = honest;
    duplicate.events.push_back(duplicate.events.back());
    BOOST_CHECK(
        !rpj::BuildRecursiveProvenanceJoinV1(
             shape, duplicate).valid);

    auto relabelled = honest;
    relabelled.endpoints[5].endpoint =
        rc::RCStage3RelationEndpoint::EpisodeGemmOperandA;
    BOOST_CHECK(
        !rpj::BuildRecursiveProvenanceJoinV1(
             shape, relabelled).valid);

    auto reordered = honest;
    std::swap(reordered.roles[2], reordered.roles[3]);
    BOOST_CHECK(
        !rpj::BuildRecursiveProvenanceJoinV1(
             shape, reordered).valid);

    auto shifted = honest;
    const auto it = std::find_if(
        shifted.events.begin(), shifted.events.end(),
        [](const auto& event) {
            return event.key.kind ==
                rpj::RecursiveProvenanceEventKindV1::
                    CoupledMaterialRoundChain;
        });
    BOOST_REQUIRE(it != shifted.events.end());
    ++it->key.consumer_position;
    BOOST_CHECK(
        !rpj::BuildRecursiveProvenanceJoinV1(
             shape, shifted).valid);
}

BOOST_AUTO_TEST_CASE(
    root_substitution_and_public_anchor_attacks_hit_air)
{
    const auto shape = Shape();
    const auto honest = Witness(shape);

    auto event_substitution = honest;
    event_substitution.events[3].
        consumer_named_input_root = Root(0x9000);
    const auto bad_event =
        rpj::BuildRecursiveProvenanceJoinV1(
            shape, event_substitution);
    BOOST_CHECK_GT(bad_event.violations, 0U);
    BOOST_CHECK(!bad_event.valid);

    auto endpoint_substitution = honest;
    endpoint_substitution.endpoints[30].
        named_endpoint_root = Root(0x9001);
    const auto bad_endpoint =
        rpj::BuildRecursiveProvenanceJoinV1(
            shape, endpoint_substitution);
    BOOST_CHECK_GT(bad_endpoint.violations, 0U);
    BOOST_CHECK(!bad_endpoint.valid);

    auto role_substitution = honest;
    role_substitution.roles[9].named_role_root =
        Root(0x9002);
    const auto bad_role =
        rpj::BuildRecursiveProvenanceJoinV1(
            shape, role_substitution);
    BOOST_CHECK_GT(bad_role.violations, 0U);
    BOOST_CHECK(!bad_role.valid);

    auto anchor_substitution = honest;
    anchor_substitution.endpoints[0].
        locally_verified_child_output_root = Root(0x9003);
    anchor_substitution.endpoints[0].
        named_endpoint_root = Root(0x9003);
    const auto bad_anchor =
        rpj::BuildRecursiveProvenanceJoinV1(
            shape, anchor_substitution);
    BOOST_CHECK_GT(bad_anchor.violations, 0U);
    BOOST_CHECK(!bad_anchor.valid);
}

BOOST_AUTO_TEST_CASE(
    zero_material_round_path_is_explicit_and_exclusive)
{
    const auto shape = Shape(0);
    const auto witness = Witness(shape);
    const auto product =
        rpj::BuildRecursiveProvenanceJoinV1(
            shape, witness);
    BOOST_REQUIRE_MESSAGE(product.valid, product.note);
    const uint32_t zero_round = std::count_if(
        witness.events.begin(), witness.events.end(),
        [](const auto& event) {
            return event.key.kind ==
                rpj::RecursiveProvenanceEventKindV1::
                    CoupledZeroRoundMixToExtract;
        });
    const uint32_t final_round = std::count_if(
        witness.events.begin(), witness.events.end(),
        [](const auto& event) {
            return event.key.kind ==
                rpj::RecursiveProvenanceEventKindV1::
                    CoupledFinalMaterialToExtract;
        });
    BOOST_CHECK_EQUAL(zero_round, shape.coupled_barriers);
    BOOST_CHECK_EQUAL(final_round, 0U);
}

BOOST_AUTO_TEST_CASE(
    air_quotient_roundtrip_and_targeted_proof_level_rejects)
{
    const auto shape = Shape();
    const auto product =
        rpj::BuildRecursiveProvenanceJoinV1(
            shape, Witness(shape));
    BOOST_REQUIRE_MESSAGE(product.valid, product.note);
    BOOST_REQUIRE_EQUAL(product.cs.n_rows, 256U);

    const auto proof =
        rpj::ProveRecursiveProvenanceJoinV1(product);
    BOOST_REQUIRE_MESSAGE(proof.valid, proof.note);
    BOOST_CHECK(proof.quotient_division_exact);
    BOOST_CHECK(proof.locally_verified);
    BOOST_CHECK(proof.canonical_codec);
    BOOST_CHECK(!proof.canonical_proof_bytes.empty());
    BOOST_CHECK(!proof.same_parent_child_verifier_owned);
    BOOST_CHECK(!proof.recursive_authority);
    BOOST_CHECK(!proof.production_complete);

    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rpj::VerifyRecursiveProvenanceJoinProofV1(
            shape, proof, &why),
        why);
    BOOST_TEST_MESSAGE(
        "RECURSIVE_PROVENANCE_PROOF measured_bytes="
        << proof.canonical_proof_bytes.size()
        << " prove_us=" << proof.prove_micros
        << " verify_us=" << proof.verify_micros
        << " rows=" << product.cs.n_rows
        << " cols=" << product.cs.n_columns
        << " events=" << product.graph_named_root_events +
                           product.temporal_events);

    const auto reject_column =
        [&](uint32_t column, const char* attack) {
            auto tampered = proof;
            BOOST_REQUIRE(
                !tampered.proof.batch.queries.empty());
            BOOST_REQUIRE_GT(
                tampered.proof.batch.queries[0].
                    row.values.size(),
                column);
            tampered.proof.batch.queries[0].
                row.values[column] =
                gf::Add(
                    tampered.proof.batch.queries[0].
                        row.values[column],
                    gf::Fp3::One());
            std::string reject_why;
            const bool accepted =
                rpj::VerifyRecursiveProvenanceJoinProofV1(
                    shape, tampered, &reject_why);
            BOOST_CHECK_MESSAGE(
                !accepted,
                attack << " proof tamper accepted");
            BOOST_TEST_MESSAGE(
                "RECURSIVE_PROVENANCE_PROOF_REJECT "
                << attack << " why=\"" << reject_why << "\"");
        };

    // These are proof-query mutations.  Rejection is decided by
    // AirQuotientVerifyRows (Merkle/FRI), not Count...Violations.
    reject_column(
        product.layout.left_root[0],
        "producer_root");
    reject_column(
        product.layout.right_root[0],
        "consumer_root");
    reject_column(
        product.layout.claimed_endpoint,
        "endpoint_relabel");
    reject_column(
        product.layout.claimed_consumer_position,
        "event_position_shift");
    reject_column(
        product.layout.right_root[7],
        "public_anchor_root");
}

BOOST_AUTO_TEST_CASE(
    all_66_and_temporal_literal_parent_aliases_execute)
{
    auto fixture = ParentAliases();
    rpj::RecursiveProvenanceParentAliasAttachmentV1
        attachment;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rpj::AppendRecursiveProvenanceParentAliasesV1(
            fixture.cs, fixture.columns,
            fixture.shape, fixture.refs,
            fixture.fixed_offset_schedule_commitment,
            attachment, &why),
        why);
    BOOST_CHECK(attachment.valid);
    BOOST_CHECK_EQUAL(
        attachment.role_root_aliases, 14U);
    BOOST_CHECK_EQUAL(
        attachment.endpoint_root_aliases, 52U);
    BOOST_CHECK_EQUAL(
        attachment.temporal_root_aliases,
        fixture.refs.events.size());
    BOOST_CHECK_EQUAL(
        attachment.limb_equalities,
        (14U + 52U + fixture.refs.events.size()) *
            8U);
    BOOST_CHECK_EQUAL(
        attachment.public_anchor_equalities, 16U);
    BOOST_CHECK_EQUAL(
        attachment.selector_columns,
        14U + 52U + fixture.refs.events.size());
    BOOST_CHECK_EQUAL(attachment.carrier_columns, 0U);
    BOOST_CHECK(attachment.all_66_root_aliases_literal);
    BOOST_CHECK(attachment.every_temporal_alias_literal);
    BOOST_CHECK(
        attachment.aliased_values_are_ordinary_columns);
    BOOST_CHECK(
        attachment.source_and_sink_cells_disjoint);
    BOOST_CHECK(
        attachment.semantic_export_cells_distinct);
    BOOST_CHECK(
        attachment.selectors_only_new_preprocessing);
    BOOST_CHECK(
        attachment.cross_row_transport_constrained);
    BOOST_CHECK(attachment.parent_witness_shape_exact);
    BOOST_CHECK(attachment.fixed_offset_schedule_bound);
    BOOST_CHECK(
        attachment.fixed_offset_schedule_commitment ==
        fixture.fixed_offset_schedule_commitment);
    BOOST_CHECK(attachment.no_child_tape_hash_required);
    BOOST_CHECK(
        attachment.parent_trace_commitment_binding_model);
    BOOST_CHECK_EQUAL(attachment.violations, 0U);
    BOOST_CHECK(
        !attachment.verifier_output_semantics_constrained);
    BOOST_CHECK(
        !attachment.named_consumer_semantics_constrained);
    BOOST_CHECK(
        !attachment.complete_child_acceptance_in_same_parent);
    BOOST_CHECK(
        !attachment.same_parent_child_verifier_owned);
    BOOST_CHECK(!attachment.recursive_authority);
    BOOST_CHECK_EQUAL(attachment.residuals.size(), 5U);
}

BOOST_AUTO_TEST_CASE(
    parent_alias_shape_schedule_relabel_and_reorder_attacks_reject)
{
    const auto rejects =
        [](ParentAliasFixture fixture,
           const char* expected) {
            rpj::RecursiveProvenanceParentAliasAttachmentV1
                attachment;
            std::string why;
            BOOST_CHECK(
                !rpj::AppendRecursiveProvenanceParentAliasesV1(
                    fixture.cs, fixture.columns,
                    fixture.shape, fixture.refs,
                    fixture.fixed_offset_schedule_commitment,
                    attachment, &why));
            BOOST_CHECK_NE(
                why.find(expected),
                std::string::npos);
            BOOST_CHECK(!attachment.recursive_authority);
        };
    {
        auto fixture = ParentAliases();
        ++fixture.refs.parent_rows;
        rejects(std::move(fixture), "fixed_offset_schedule");
    }
    {
        auto fixture = ParentAliases();
        ++fixture.refs.roles[0].root.
            verifier_output.limb[0].row;
        rejects(std::move(fixture), "fixed_offset_schedule");
    }
    {
        auto fixture = ParentAliases();
        fixture.refs.roles[0].role =
            fixture.refs.roles[1].role;
        rejects(std::move(fixture), "fixed_offset_schedule");
    }
    {
        auto fixture = ParentAliases();
        std::swap(
            fixture.refs.endpoints[2],
            fixture.refs.endpoints[3]);
        rejects(std::move(fixture), "fixed_offset_schedule");
    }
    {
        auto fixture = ParentAliases();
        fixture.fixed_offset_schedule_commitment.begin()[0] ^=
            1U;
        rejects(std::move(fixture), "fixed_offset_schedule");
    }
}

BOOST_AUTO_TEST_CASE(
    parent_alias_preprocessed_collapsed_non_u32_and_value_attacks_reject)
{
    {
        auto fixture = ParentAliases();
        fixture.cs.preprocessed.emplace_back(
            0, fixture.columns[0]);
        rpj::RecursiveProvenanceParentAliasAttachmentV1
            attachment;
        std::string why;
        BOOST_CHECK(
            !rpj::AppendRecursiveProvenanceParentAliasesV1(
                fixture.cs, fixture.columns,
                fixture.shape, fixture.refs,
                fixture.fixed_offset_schedule_commitment,
                attachment, &why));
        BOOST_CHECK_NE(
            why.find("preprocessed"),
            std::string::npos);
    }
    {
        auto fixture = ParentAliases();
        fixture.refs.roles[1].root.verifier_output =
            fixture.refs.roles[0].root.verifier_output;
        fixture.fixed_offset_schedule_commitment =
            rpj::
                ComputeRecursiveProvenanceParentAliasScheduleCommitmentV1(
                    fixture.shape, fixture.refs);
        BOOST_REQUIRE(
            !fixture.fixed_offset_schedule_commitment.IsNull());
        rpj::RecursiveProvenanceParentAliasAttachmentV1
            attachment;
        std::string why;
        BOOST_CHECK(
            !rpj::AppendRecursiveProvenanceParentAliasesV1(
                fixture.cs, fixture.columns,
                fixture.shape, fixture.refs,
                fixture.fixed_offset_schedule_commitment,
                attachment, &why));
        BOOST_CHECK_NE(
            why.find("collapsed"),
            std::string::npos);
    }
    {
        auto fixture = ParentAliases();
        const auto ref =
            fixture.refs.roles[0].root.
                verifier_output.limb[0];
        fixture.columns[ref.column][ref.row].c1 =
            gf::FromU64(1);
        rpj::RecursiveProvenanceParentAliasAttachmentV1
            attachment;
        std::string why;
        BOOST_CHECK(
            !rpj::AppendRecursiveProvenanceParentAliasesV1(
                fixture.cs, fixture.columns,
                fixture.shape, fixture.refs,
                fixture.fixed_offset_schedule_commitment,
                attachment, &why));
    }
    {
        auto fixture = ParentAliases();
        const auto ref =
            fixture.refs.endpoints[30].root.
                named_consumer.limb[3];
        fixture.columns[ref.column][ref.row] =
            gf::Add(
                fixture.columns[ref.column][ref.row],
                gf::Fp3::One());
        rpj::RecursiveProvenanceParentAliasAttachmentV1
            attachment;
        std::string why;
        BOOST_CHECK(
            !rpj::AppendRecursiveProvenanceParentAliasesV1(
                fixture.cs, fixture.columns,
                fixture.shape, fixture.refs,
                fixture.fixed_offset_schedule_commitment,
                attachment, &why));
        BOOST_CHECK_GT(attachment.violations, 0U);
    }
}

BOOST_AUTO_TEST_CASE(
    parent_alias_cross_row_carrier_is_constrained)
{
    auto fixture = ParentAliases();
    constexpr uint32_t kSinkRow = 220;
    for (uint32_t limb = 0;
         limb < rpj::kRecursiveProvenanceRootLimbsV1;
         ++limb) {
        const auto old_ref =
            fixture.refs.roles[0].root.
                named_consumer.limb[limb];
        fixture.columns[old_ref.column][kSinkRow] =
            fixture.columns[old_ref.column][old_ref.row];
        fixture.refs.roles[0].root.
            named_consumer.limb[limb].row = kSinkRow;
    }
    fixture.fixed_offset_schedule_commitment =
        rpj::
            ComputeRecursiveProvenanceParentAliasScheduleCommitmentV1(
                fixture.shape, fixture.refs);
    BOOST_REQUIRE(
        !fixture.fixed_offset_schedule_commitment.IsNull());

    rpj::RecursiveProvenanceParentAliasAttachmentV1
        attachment;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rpj::AppendRecursiveProvenanceParentAliasesV1(
            fixture.cs, fixture.columns,
            fixture.shape, fixture.refs,
            fixture.fixed_offset_schedule_commitment,
            attachment, &why),
        why);
    BOOST_CHECK_EQUAL(attachment.cross_row_equalities, 8U);
    BOOST_CHECK_EQUAL(attachment.carrier_columns, 8U);
    BOOST_CHECK(attachment.cross_row_transport_constrained);
    BOOST_CHECK_EQUAL(attachment.violations, 0U);

    // The first carrier is created at the original width.  Changing an
    // interior carried value must violate its transition constraint; it is
    // not a free equality witness.
    fixture.columns[attachment.original_columns][100] =
        gf::Add(
            fixture.columns[attachment.original_columns][100],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        rpj::CountRecursiveProvenanceJoinViolationsV1(
            fixture.cs, fixture.columns),
        0U);
}

BOOST_AUTO_TEST_CASE(
    parent_alias_air_proof_roundtrip_and_proof_level_rejects)
{
    auto fixture = ParentAliases();
    rpj::RecursiveProvenanceParentAliasAttachmentV1
        attachment;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rpj::AppendRecursiveProvenanceParentAliasesV1(
            fixture.cs, fixture.columns,
            fixture.shape, fixture.refs,
            fixture.fixed_offset_schedule_commitment,
            attachment, &why),
        why);
    const uint256 seed =
        rpj::ComputeRecursiveProvenanceParentAliasFsSeedV1(
            fixture.shape,
            fixture.fixed_offset_schedule_commitment);
    BOOST_REQUIRE(!seed.IsNull());
    const auto prove_begin =
        std::chrono::steady_clock::now();
    const auto proved =
        rpj::aq::AirQuotientProveRows(
            fixture.cs, fixture.columns, seed);
    const auto prove_end =
        std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_REQUIRE(proved.division_exact);
    const auto verify_begin =
        std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(
        rpj::aq::AirQuotientVerifyRows(
            fixture.cs, proved.proof, seed, &why),
        why);
    const auto verify_end =
        std::chrono::steady_clock::now();

    matmul::v4::rc::AirQuotientProofAlg canonical;
    canonical.batch = proved.proof.batch;
    canonical.next_openings =
        proved.proof.next_openings;
    canonical.trace_commit =
        proved.proof.trace_commit;
    std::vector<unsigned char> bytes;
    BOOST_REQUIRE_MESSAGE(
        matmul::v4::rc::SerializeAirQuotientProofAlg(
            canonical, bytes, &why),
        why);
    BOOST_TEST_MESSAGE(
        "RECURSIVE_PROVENANCE_PARENT_ALIAS_PROOF "
        "measured_bytes="
        << bytes.size()
        << " prove_us="
        << std::chrono::duration_cast<
               std::chrono::microseconds>(
               prove_end - prove_begin).count()
        << " verify_us="
        << std::chrono::duration_cast<
               std::chrono::microseconds>(
               verify_end - verify_begin).count()
        << " rows=" << fixture.cs.n_rows
        << " cols=" << fixture.cs.n_columns
        << " aliases="
        << attachment.role_root_aliases +
               attachment.endpoint_root_aliases +
               attachment.temporal_root_aliases);

    const auto proof_reject =
        [&](uint32_t column, const char* attack) {
            auto tampered = proved.proof;
            BOOST_REQUIRE(
                !tampered.batch.queries.empty());
            BOOST_REQUIRE_GT(
                tampered.batch.queries[0].
                    row.values.size(),
                column);
            tampered.batch.queries[0].
                row.values[column] =
                gf::Add(
                    tampered.batch.queries[0].
                        row.values[column],
                    gf::Fp3::One());
            std::string reject_why;
            BOOST_CHECK_MESSAGE(
                !rpj::aq::AirQuotientVerifyRows(
                    fixture.cs, tampered, seed,
                    &reject_why),
                attack << " proof tamper accepted");
            BOOST_TEST_MESSAGE(
                "RECURSIVE_PROVENANCE_PARENT_ALIAS_REJECT "
                << attack << " why=\""
                << reject_why << "\"");
        };
    proof_reject(
        fixture.refs.roles[0].root.
            verifier_output.limb[0].column,
        "role_verifier_output");
    proof_reject(
        fixture.refs.endpoints[30].root.
            named_consumer.limb[3].column,
        "endpoint_named_consumer");
    proof_reject(
        fixture.refs.events[4].
            root.verifier_output.limb[7].column,
        "temporal_producer");
}

BOOST_AUTO_TEST_SUITE_END()
