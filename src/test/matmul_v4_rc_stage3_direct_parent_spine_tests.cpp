// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_air_quotient_alg.h>
#include <matmul/matmul_v4_rc_air_recurse.h>
#include <matmul/matmul_v4_rc_stage3_direct_parent_spine.h>

#include <algorithm>

namespace ar = matmul::v4::rc::air_recurse;
namespace aq = matmul::v4::rc::air_quotient;
namespace dps = matmul::v4::rc::direct_parent_spine;
namespace gf = matmul::v4::rc::gkr_field;
namespace rpj =
    matmul::v4::rc::recursive_provenance_join;

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_direct_parent_spine_tests)

namespace {

uint256 Root(unsigned char value)
{
    uint256 out;
    std::fill(out.begin(), out.end(), value);
    return out;
}

gf::Fp3 F(uint64_t value)
{
    return gf::Fp3::FromFp(gf::FromU64(value));
}

dps::DirectParentStatementV1 Statement()
{
    dps::DirectParentStatementV1 out;
    out.total_program_ordinals = 6;
    out.source_identity = Root(0x11);
    out.query_schedule = Root(0x22);
    out.exact_set_manifest_root = Root(0x33);
    out.query_indices = {17, 4, 91};
    out.source_parent_q = {F(13), F(23), F(37)};

    out.receipts[0].receipt_ordinal = 0;
    out.receipts[0].source_identity = out.source_identity;
    out.receipts[0].query_schedule = out.query_schedule;
    out.receipts[0].exact_set_manifest_root =
        out.exact_set_manifest_root;
    out.receipts[0].statement_root = Root(0x40);
    out.receipts[0].receipt_root = Root(0x50);
    out.receipts[0].query_indices = out.query_indices;
    out.receipts[0].source_parent_q = out.source_parent_q;
    out.receipts[0].local_q_per_query = {F(5), F(7), F(11)};
    out.receipts[0].program_ordinals = {0, 2, 5};

    out.receipts[1].receipt_ordinal = 1;
    out.receipts[1].source_identity = out.source_identity;
    out.receipts[1].query_schedule = out.query_schedule;
    out.receipts[1].exact_set_manifest_root =
        out.exact_set_manifest_root;
    out.receipts[1].statement_root = Root(0x41);
    out.receipts[1].receipt_root = Root(0x51);
    out.receipts[1].query_indices = out.query_indices;
    out.receipts[1].source_parent_q = out.source_parent_q;
    out.receipts[1].local_q_per_query = {F(8), F(16), F(26)};
    out.receipts[1].program_ordinals = {1, 3, 4};
    return out;
}

dps::DirectParentTerminalExportsV1 Exports(
    const dps::DirectParentStatementV1& statement)
{
    dps::DirectParentTerminalExportsV1 out;
    out.source_identity = statement.source_identity;
    out.query_schedule = statement.query_schedule;
    out.exact_set_manifest_root =
        statement.exact_set_manifest_root;
    out.query_indices = statement.query_indices;
    out.source_parent_q = statement.source_parent_q;
    out.receipts = statement.receipts;
    return out;
}

struct Built {
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    dps::DirectParentSpineAppendV1 append;
};

Built Build(
    const dps::DirectParentStatementV1& statement,
    const dps::DirectParentTerminalExportsV1& exports)
{
    Built out;
    out.cs.n_rows = 16;
    out.cs.n_columns = 1;
    out.columns.assign(
        1, std::vector<gf::Fp3>(
               out.cs.n_rows, gf::Fp3::Zero()));
    aq::AirConstraint<gf::Fp3> base;
    base.name = "stage3.direct_parent.test.base_zero";
    base.kind = aq::AirKind::kEverywhere;
    base.alg_degree = 1;
    base.eval =
        [](const std::vector<gf::Fp3>& current,
           const std::vector<gf::Fp3>&) {
            return current[0];
        };
    out.cs.constraints.push_back(std::move(base));
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        dps::AppendDirectParentSpineV1(
            out.cs, out.columns, statement, exports,
            out.append, nullptr, &why),
        why);
    return out;
}

uint32_t Violations(const Built& built)
{
    return ar::CountWitnessViolationsOnH(
        built.cs, built.columns);
}

struct ConsumerFixture {
    rpj::RecursiveProvenanceShapeV1 shape;
    rpj::RecursiveProvenanceParentAliasRefsV1 sources;
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
};

void SetSourceRoot(
    ConsumerFixture& fixture,
    uint32_t row,
    const uint256& root,
    rpj::RecursiveProvenanceParentRootAliasV1& alias)
{
    BOOST_REQUIRE_LT(row, fixture.cs.n_rows);
    for (uint32_t word = 0; word < 8; ++word) {
        const uint32_t offset = 4U * word;
        const uint32_t value =
            static_cast<uint32_t>(root.begin()[offset]) |
            (static_cast<uint32_t>(
                 root.begin()[offset + 1]) << 8U) |
            (static_cast<uint32_t>(
                 root.begin()[offset + 2]) << 16U) |
            (static_cast<uint32_t>(
                 root.begin()[offset + 3]) << 24U);
        fixture.columns[word][row] = F(value);
        alias.verifier_output.limb[word] = {word, row};
    }
}

ConsumerFixture CanonicalConsumerFixture()
{
    ConsumerFixture out;
    out.shape.episode_round_roots = 4;
    out.shape.coupled_barriers = 3;
    out.shape.coupled_lobes = 2;
    out.shape.coupled_exchange_rounds = 3;
    out.shape.episode_builder_params_root = Root(0xa1);
    out.shape.episode_header_target_root = Root(0xa2);
    out.cs.n_rows = 256;
    out.cs.n_columns = 8;
    out.columns.assign(
        out.cs.n_columns,
        std::vector<gf::Fp3>(
            out.cs.n_rows, gf::Fp3::Zero()));
    out.sources.parent_rows = out.cs.n_rows;
    out.sources.parent_original_columns =
        out.cs.n_columns;

    uint32_t row = 0;
    uint32_t root_id = 1;
    const auto& roles =
        rpj::CanonicalRecursiveProvenanceRoleOrderV1();
    for (uint32_t i = 0; i < out.sources.roles.size(); ++i) {
        out.sources.roles[i].role = roles[i];
        SetSourceRoot(
            out, row++, Root(root_id++),
            out.sources.roles[i].root);
    }
    const auto endpoints =
        matmul::v4::rc::
            CurrentRCStage3RelationEndpointCellAudit();
    BOOST_REQUIRE_EQUAL(endpoints.size(), 52U);
    for (uint32_t i = 0; i < out.sources.endpoints.size(); ++i) {
        out.sources.endpoints[i].endpoint =
            endpoints[i].endpoint;
        out.sources.endpoints[i].role =
            endpoints[i].role;
        uint256 root = Root(root_id++);
        if (i == 0) {
            root = out.shape.episode_builder_params_root;
        } else if (i == 24) {
            root = out.shape.episode_header_target_root;
        }
        SetSourceRoot(
            out, row++, root,
            out.sources.endpoints[i].root);
    }
    std::vector<rpj::RecursiveProvenanceEventKeyV1> events;
    BOOST_REQUIRE(
        rpj::BuildCanonicalRecursiveProvenanceEventScheduleV1(
            out.shape, events, nullptr));
    for (const auto& key : events) {
        rpj::RecursiveProvenanceParentEventAliasV1 event;
        event.key = key;
        SetSourceRoot(
            out, row++, Root(root_id++), event.root);
        out.sources.events.push_back(std::move(event));
    }
    BOOST_REQUIRE_LT(row, out.cs.n_rows);
    return out;
}

} // namespace

BOOST_AUTO_TEST_CASE(
    honest_exact_set_and_q_partition_are_appendable)
{
    const auto statement = Statement();
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        dps::ValidateDirectParentStatementV1(
            statement, &why),
        why);
    const auto built = Build(statement, Exports(statement));
    BOOST_CHECK(built.append.valid);
    BOOST_CHECK(built.append.statement_exact_set);
    BOOST_CHECK(built.append.statement_q_partition);
    BOOST_CHECK(
        built.append.terminal_row_equality_constrained);
    BOOST_CHECK(
        built.append.ordered_receipt_coverage_constrained);
    BOOST_CHECK(built.append.source_identity_constrained);
    BOOST_CHECK(built.append.query_schedule_constrained);
    BOOST_CHECK(built.append.source_q_constrained);
    BOOST_CHECK(built.append.local_q_join_constrained);
    BOOST_CHECK(built.append.padding_zero_constrained);
    BOOST_CHECK(built.append.preprocessed_fallback);
    BOOST_CHECK(
        built.append.all_actual_inputs_verifier_owned);
    BOOST_CHECK(
        built.append.no_free_binding_or_q_witness);
    BOOST_CHECK(built.append.direct_alias_capable);
    BOOST_CHECK(!built.append.direct_child_aliases);
    BOOST_CHECK(!built.append.recursively_consumed);
    BOOST_CHECK_EQUAL(Violations(built), 0U);
}

BOOST_AUTO_TEST_CASE(
    compensated_local_q_and_source_q_substitution_are_rejected)
{
    const auto statement = Statement();
    auto compensated = Build(statement, Exports(statement));
    const auto row = 1U;
    const auto delta = F(9);
    const auto left =
        compensated.append.layout.actual.receipts[0].local_q;
    const auto right =
        compensated.append.layout.actual.receipts[1].local_q;
    compensated.columns[left][row] =
        gf::Add(compensated.columns[left][row], delta);
    compensated.columns[right][row] =
        gf::Sub(compensated.columns[right][row], delta);
    // The naked q_left+q_right equation still holds.  Equality to each
    // verifier-owned receipt q terminal is what rejects this attack.
    BOOST_CHECK_GT(Violations(compensated), 0U);

    auto source_substitution =
        Build(statement, Exports(statement));
    const auto source_q =
        source_substitution.append.layout.actual.source.parent_q;
    source_substitution.columns[source_q][0] =
        gf::Add(
            source_substitution.columns[source_q][0], F(1));
    BOOST_CHECK_GT(Violations(source_substitution), 0U);
}

BOOST_AUTO_TEST_CASE(
    receipt_omission_duplicate_reorder_and_overlap_are_rejected)
{
    const auto statement = Statement();

    auto omission = Build(statement, Exports(statement));
    const uint32_t first_manifest =
        omission.append.layout.query_rows;
    const auto left_present =
        omission.append.layout.actual.receipts[0]
            .manifest_present;
    omission.columns[left_present][first_manifest] =
        gf::Fp3::Zero();
    BOOST_CHECK_GT(Violations(omission), 0U);

    auto duplicate = Build(statement, Exports(statement));
    const auto left_program =
        duplicate.append.layout.actual.receipts[0]
            .program_ordinal;
    duplicate.columns[left_program][first_manifest + 1] =
        duplicate.columns[left_program][first_manifest];
    BOOST_CHECK_GT(Violations(duplicate), 0U);

    auto cross_receipt_overlap =
        Build(statement, Exports(statement));
    // Reassign ordinal 5 from receipt 0 to ordinal 4, which is already owned
    // by receipt 1.  Total row count is unchanged.
    cross_receipt_overlap.columns[left_program]
        [first_manifest + 2] = F(4);
    BOOST_CHECK_GT(
        Violations(cross_receipt_overlap), 0U);

    auto reordered = Build(statement, Exports(statement));
    const auto left_slot =
        reordered.append.layout.actual.receipts[0]
            .receipt_ordinal;
    reordered.columns[left_slot][first_manifest] =
        gf::Fp3::One();
    BOOST_CHECK_GT(Violations(reordered), 0U);

    // A count-preserving ordinal reassignment (duplicate 4, omit 5) cannot
    // become a new verifier statement: exact-set validation rejects it.
    auto overlap = statement;
    overlap.receipts[0].program_ordinals.back() = 4;
    BOOST_CHECK(
        !dps::ValidateDirectParentStatementV1(
            overlap, nullptr));
}

BOOST_AUTO_TEST_CASE(
    source_splice_query_swap_and_padding_smuggling_are_rejected)
{
    const auto statement = Statement();

    auto source_splice = Build(statement, Exports(statement));
    const auto right_source_limb =
        source_splice.append.layout.actual.receipts[1]
            .source_identity.limb[0];
    source_splice.columns[right_source_limb][0] =
        F(0xdeadbeefU);
    BOOST_CHECK_GT(Violations(source_splice), 0U);

    auto query_swap = Build(statement, Exports(statement));
    const auto right_query =
        query_swap.append.layout.actual.receipts[1]
            .query_index;
    std::swap(
        query_swap.columns[right_query][0],
        query_swap.columns[right_query][1]);
    BOOST_CHECK_GT(Violations(query_swap), 0U);

    auto padding = Build(statement, Exports(statement));
    const uint32_t first_padding =
        padding.append.layout.query_rows +
        padding.append.layout.manifest_rows;
    BOOST_REQUIRE_LT(
        first_padding, padding.append.layout.terminal_rows);
    const auto smuggled_q =
        padding.append.layout.actual.receipts[0].local_q;
    padding.columns[smuggled_q][first_padding] = F(7);
    BOOST_CHECK_GT(Violations(padding), 0U);
}

BOOST_AUTO_TEST_CASE(
    existing_parent_columns_can_be_reused_without_claiming_integration)
{
    const auto statement = Statement();
    const auto fallback =
        Build(statement, Exports(statement));

    Built direct;
    direct.cs.n_rows = fallback.cs.n_rows;
    direct.cs.n_columns =
        fallback.append.layout.expected.common.row_kind;
    direct.columns.assign(
        fallback.columns.begin(),
        fallback.columns.begin() + direct.cs.n_columns);
    aq::AirConstraint<gf::Fp3> base;
    base.name = "stage3.direct_parent.test.base_zero";
    base.kind = aq::AirKind::kEverywhere;
    base.alg_degree = 1;
    base.eval =
        [](const std::vector<gf::Fp3>& current,
           const std::vector<gf::Fp3>&) {
            return current[0];
        };
    direct.cs.constraints.push_back(std::move(base));
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        dps::AppendDirectParentSpineV1(
            direct.cs, direct.columns,
            statement, Exports(statement),
            direct.append,
            &fallback.append.layout.actual, &why),
        why);
    BOOST_CHECK(direct.append.actual_columns_reused);
    BOOST_CHECK(!direct.append.preprocessed_fallback);
    BOOST_CHECK(!direct.append.direct_child_aliases);
    BOOST_CHECK(!direct.append.recursively_consumed);
    BOOST_CHECK(
        !direct.append.all_actual_inputs_verifier_owned);
    BOOST_CHECK(
        !direct.append.no_free_binding_or_q_witness);
    BOOST_CHECK_EQUAL(Violations(direct), 0U);
}

BOOST_AUTO_TEST_CASE(
    direct_parent_refs_reject_preprocessed_and_raw_field_aliases)
{
    const auto statement = Statement();
    const auto fallback =
        Build(statement, Exports(statement));

    const auto attempt =
        [&](bool preprocessed, bool raw_alias) {
            Built direct;
            direct.cs.n_rows = fallback.cs.n_rows;
            direct.cs.n_columns =
                fallback.append.layout.expected.common.row_kind;
            direct.columns.assign(
                fallback.columns.begin(),
                fallback.columns.begin() +
                    direct.cs.n_columns);
            const auto& refs =
                fallback.append.layout.actual;
            const uint32_t target =
                refs.source.source_identity.limb[0];
            if (preprocessed) {
                direct.cs.preprocessed.push_back(
                    {target, direct.columns[target]});
            }
            if (raw_alias) {
                direct.columns[target][0] =
                    gf::Fp3{gf::kP + 1U, 0, 0};
            }
            std::string why;
            BOOST_CHECK(
                !dps::AppendDirectParentSpineV1(
                    direct.cs, direct.columns,
                    statement, Exports(statement),
                    direct.append, &refs, &why));
        };
    attempt(true, false);
    attempt(false, true);
}

BOOST_AUTO_TEST_CASE(
    canonical_consumer_program_owns_all_named_cells_fail_closed)
{
    auto fixture = CanonicalConsumerFixture();
    const auto plan =
        dps::BuildCanonicalProvenanceConsumerPlanV1(
            fixture.shape, fixture.sources);
    BOOST_REQUIRE(plan.valid);
    BOOST_CHECK_EQUAL(plan.role_rows, 14U);
    BOOST_CHECK_EQUAL(plan.endpoint_rows, 52U);
    BOOST_CHECK_GT(plan.temporal_rows, 0U);
    BOOST_CHECK_EQUAL(
        plan.active_rows,
        14U + 52U + plan.temporal_rows);
    BOOST_CHECK(plan.canonical_program_table);
    BOOST_CHECK(!plan.bytecode_program_root.IsNull());
    BOOST_CHECK(!plan.consumer_schedule_root.IsNull());
    BOOST_CHECK(
        !plan.fixed_alias_schedule_commitment.IsNull());

    dps::CanonicalProvenanceConsumerAttachmentV1
        attachment;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        dps::AppendCanonicalProvenanceConsumerSpineV1(
            fixture.cs, fixture.columns,
            fixture.shape, fixture.sources,
            plan, attachment, &why),
        why);
    BOOST_CHECK(attachment.valid);
    BOOST_CHECK(
        attachment.independently_pinned_plan_match);
    BOOST_CHECK(
        attachment.root_words_are_canonical_u32);
    BOOST_CHECK(
        attachment.root_words_bit_constrained);
    BOOST_CHECK(
        attachment.all_consumer_addresses_program_allocated);
    BOOST_CHECK(
        attachment.temporal_event_schedule_bound);
    BOOST_CHECK(
        attachment.no_free_consumer_root_witness);
    BOOST_CHECK(
        attachment.named_consumer_semantics_constrained);
    BOOST_CHECK(
        !attachment.
            underlying_relation_program_semantics_complete);
    BOOST_CHECK(
        !attachment.verifier_output_semantics_constrained);
    BOOST_CHECK(
        !attachment.
            complete_child_acceptance_in_same_parent);
    BOOST_CHECK(!attachment.recursive_authority);
    BOOST_CHECK_EQUAL(attachment.violations, 0U);
    BOOST_CHECK_EQUAL(attachment.alias.role_root_aliases, 14U);
    BOOST_CHECK_EQUAL(
        attachment.alias.endpoint_root_aliases, 52U);
    BOOST_CHECK_EQUAL(
        attachment.alias.temporal_root_aliases,
        plan.temporal_rows);
}

BOOST_AUTO_TEST_CASE(
    canonical_consumer_plan_rejects_relabel_reorder_and_omission)
{
    const auto honest = CanonicalConsumerFixture();
    const auto expected =
        dps::BuildCanonicalProvenanceConsumerPlanV1(
            honest.shape, honest.sources);
    BOOST_REQUIRE(expected.valid);

    const auto rejects =
        [&](ConsumerFixture fixture) {
            const auto plan =
                dps::BuildCanonicalProvenanceConsumerPlanV1(
                    fixture.shape, fixture.sources);
            BOOST_CHECK(!plan.valid);
            dps::CanonicalProvenanceConsumerAttachmentV1
                attachment;
            BOOST_CHECK(
                !dps::AppendCanonicalProvenanceConsumerSpineV1(
                    fixture.cs, fixture.columns,
                    fixture.shape, fixture.sources,
                    expected, attachment, nullptr));
            BOOST_CHECK(!attachment.recursive_authority);
        };
    {
        auto fixture = honest;
        fixture.sources.roles[0].role =
            fixture.sources.roles[1].role;
        rejects(std::move(fixture));
    }
    {
        auto fixture = honest;
        std::swap(
            fixture.sources.endpoints[2],
            fixture.sources.endpoints[3]);
        rejects(std::move(fixture));
    }
    {
        auto fixture = honest;
        fixture.sources.events.pop_back();
        rejects(std::move(fixture));
    }
    {
        auto fixture = honest;
        std::swap(
            fixture.sources.events[1],
            fixture.sources.events[2]);
        rejects(std::move(fixture));
    }
}

BOOST_AUTO_TEST_CASE(
    canonical_consumer_rejects_unpinned_program_and_schedule_roots)
{
    const auto honest = CanonicalConsumerFixture();
    const auto plan =
        dps::BuildCanonicalProvenanceConsumerPlanV1(
            honest.shape, honest.sources);
    BOOST_REQUIRE(plan.valid);

    const auto rejects =
        [&](dps::CanonicalProvenanceConsumerPlanV1 expected) {
            auto fixture = honest;
            dps::CanonicalProvenanceConsumerAttachmentV1
                attachment;
            BOOST_CHECK(
                !dps::AppendCanonicalProvenanceConsumerSpineV1(
                    fixture.cs, fixture.columns,
                    fixture.shape, fixture.sources,
                    expected, attachment, nullptr));
            BOOST_CHECK(
                !attachment.independently_pinned_plan_match);
            BOOST_CHECK(!attachment.recursive_authority);
        };
    {
        auto expected = plan;
        expected.bytecode_program_root.begin()[0] ^= 1U;
        rejects(std::move(expected));
    }
    {
        auto expected = plan;
        expected.bytecode_program_alg_root[0] ^= 1U;
        rejects(std::move(expected));
    }
    {
        auto expected = plan;
        expected.consumer_schedule_root.begin()[0] ^= 1U;
        rejects(std::move(expected));
    }
    {
        auto expected = plan;
        expected.fixed_alias_schedule_commitment.begin()[0] ^= 1U;
        rejects(std::move(expected));
    }
}

BOOST_AUTO_TEST_CASE(
    canonical_consumer_rejects_x_plus_p_preprocessed_and_free_witness)
{
    const auto honest = CanonicalConsumerFixture();
    const auto plan =
        dps::BuildCanonicalProvenanceConsumerPlanV1(
            honest.shape, honest.sources);
    BOOST_REQUIRE(plan.valid);

    {
        auto fixture = honest;
        fixture.columns[0][0] =
            gf::Fp3{gf::kP + 1U, 0, 0};
        dps::CanonicalProvenanceConsumerAttachmentV1
            attachment;
        BOOST_CHECK(
            !dps::AppendCanonicalProvenanceConsumerSpineV1(
                fixture.cs, fixture.columns,
                fixture.shape, fixture.sources,
                plan, attachment, nullptr));
    }
    {
        auto fixture = honest;
        fixture.cs.preprocessed.push_back(
            {0, fixture.columns[0]});
        dps::CanonicalProvenanceConsumerAttachmentV1
            attachment;
        BOOST_CHECK(
            !dps::AppendCanonicalProvenanceConsumerSpineV1(
                fixture.cs, fixture.columns,
                fixture.shape, fixture.sources,
                plan, attachment, nullptr));
    }
    {
        auto fixture = honest;
        dps::CanonicalProvenanceConsumerAttachmentV1
            attachment;
        BOOST_REQUIRE(
            dps::AppendCanonicalProvenanceConsumerSpineV1(
                fixture.cs, fixture.columns,
                fixture.shape, fixture.sources,
                plan, attachment, nullptr));
        const uint32_t row = 4;
        const uint32_t root_column =
            attachment.plan.layout.root_word[0];
        const uint32_t bit_column =
            attachment.plan.layout.root_bits_base;
        const bool low_bit =
            gf::Canonical(
                fixture.columns[bit_column][row].c0) != 0;
        fixture.columns[root_column][row] =
            low_bit
                ? gf::Sub(
                    fixture.columns[root_column][row],
                    gf::Fp3::One())
                : gf::Add(
                    fixture.columns[root_column][row],
                    gf::Fp3::One());
        fixture.columns[bit_column][row] =
            low_bit
                ? gf::Fp3::Zero()
                : gf::Fp3::One();
        BOOST_CHECK_GT(
            rpj::CountRecursiveProvenanceJoinViolationsV1(
                fixture.cs, fixture.columns),
            0U);
    }
}

BOOST_AUTO_TEST_CASE(
    real_fri_air_verifier_rejects_compensated_q_proof)
{
    using AlgB3 = aq::AirFriBackendAlg<gf::Fp3>;
    const auto statement = Statement();
    const auto honest = Build(statement, Exports(statement));
    const uint256 seed = Root(0x71);
    const auto proved =
        aq::AirQuotientProve<gf::Fp3, AlgB3>(
            honest.cs, honest.columns, seed, {});
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_REQUIRE(proved.division_exact);
    std::string why;
    BOOST_CHECK_MESSAGE(
        (aq::AirQuotientVerify<gf::Fp3, AlgB3>(
            honest.cs, proved.proof, seed, &why)),
        why);

    auto compensated = honest;
    const auto delta = F(9);
    const auto left =
        compensated.append.layout.actual.receipts[0].local_q;
    const auto right =
        compensated.append.layout.actual.receipts[1].local_q;
    compensated.columns[left][0] =
        gf::Add(compensated.columns[left][0], delta);
    compensated.columns[right][0] =
        gf::Sub(compensated.columns[right][0], delta);
    BOOST_REQUIRE_GT(Violations(compensated), 0U);
    aq::AirProveOptions adversarial;
    adversarial.force_commit_on_inexact = true;
    const auto forged =
        aq::AirQuotientProve<gf::Fp3, AlgB3>(
            compensated.cs, compensated.columns,
            seed, adversarial);
    BOOST_REQUIRE_MESSAGE(forged.ok, forged.note);
    BOOST_CHECK(!forged.division_exact);
    BOOST_CHECK(
        !(aq::AirQuotientVerify<gf::Fp3, AlgB3>(
            compensated.cs, forged.proof, seed, &why)));
}

BOOST_AUTO_TEST_SUITE_END()
