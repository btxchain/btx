// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_v13_terminal_fold_parent.h>
#include <matmul/matmul_v4_rc_stage3_air_quotient_codec.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <numeric>

namespace terminal =
    matmul::v4::rc::stage3_v13_terminal_fold_parent;
namespace proofabi =
    matmul::v4::rc::stage3_multirow_v11_proof_abi;
namespace aq = matmul::v4::rc::air_quotient;
namespace composer =
    matmul::v4::rc::stage3_air_parent_composer;
namespace gf = matmul::v4::rc::gkr_field;
using CanaryBackend =
    aq::AirFriBackendAlg<gf::Fp3>;
namespace tape =
    matmul::v4::rc::stage3_multirow_v13_proof_tape_air;
namespace rc = matmul::v4::rc;

namespace {

uint256 Root(uint8_t byte)
{
    uint256 out;
    std::fill(out.begin(), out.end(), byte);
    return out;
}

tape::PublicShapeV1 ToyShape()
{
    tape::PublicShapeV1 out;
    out.trace_rows = 2;
    out.trace_columns = 2;
    out.quotient_len = 2;
    out.n_coeffs = 2;
    out.base_column_indices = {0};
    return out;
}

tape::PublicBindingV1 Binding()
{
    tape::PublicBindingV1 out;
    out.program_root = Root(0x11);
    out.statement_root = Root(0x22);
    out.public_fs_seed = Root(0x33);
    out.proof_wire_root = Root(0x44);
    out.tape_root = {1, 2, 3, 4};
    return out;
}

size_t SemanticRecord(uint32_t address)
{
    return tape::kPublicPrefixRecordsV1 +
        tape::kHeaderRecordsV1 + address;
}

std::vector<uint32_t> CanonicalWords(
    const tape::ScheduleV1& schedule)
{
    std::vector<uint32_t> out(
        tape::kHeaderRecordsV1 +
            size_t{schedule.source_records} * 2);
    for (uint32_t header = 0;
         header < tape::kHeaderRecordsV1;
         ++header) {
        out[header] =
            schedule.records[
                tape::kPublicPrefixRecordsV1 +
                header].expected_value;
    }
    for (uint32_t address = 0;
         address < schedule.source_records;
         ++address) {
        const auto& record =
            schedule.records[
                SemanticRecord(address)];
        const size_t offset =
            tape::kHeaderRecordsV1 +
            size_t{address} * 2;
        out[offset] = record.expected_address;
        out[offset + 1] =
            record.fixed_value
            ? record.expected_value
            : schedule.semantic_sources[address]
                  .value;
    }
    return out;
}

size_t SourceValueWord(uint32_t address)
{
    return tape::kHeaderRecordsV1 +
        size_t{address} * 2 + 1;
}

std::optional<uint32_t> FindAddress(
    const tape::ScheduleV1& schedule,
    proofabi::FieldKindV1 kind,
    uint32_t a,
    uint32_t d,
    uint8_t limb)
{
    for (const auto& source :
         schedule.semantic_sources) {
        if (source.key.kind == kind &&
            source.key.a == a &&
            source.key.d == d &&
            source.key.limb == limb) {
            return source.address;
        }
    }
    return std::nullopt;
}

rc::Fri3AlgDigest TerminalRoot(
    const gf::Fp3& final_value)
{
    std::vector<rc::Fri3AlgDigest> level;
    level.reserve(rc::kRCFriBlowup);
    for (uint32_t index = 0;
         index < rc::kRCFriBlowup;
         ++index) {
        rc::alg_hash::State input{};
        input[0] = gf::Canonical(final_value.c0);
        input[1] = gf::Canonical(final_value.c1);
        input[2] = gf::Canonical(final_value.c2);
        input[3] = gf::FromU64(index);
        input[4] =
            rc::alg_hash::GetAlgHashConstants()
                .leaf_domain;
        rc::alg_hash::Permute(input);
        level.push_back({
            input[0], input[1],
            input[2], input[3]});
    }
    while (level.size() > 1) {
        std::vector<rc::Fri3AlgDigest> next;
        next.reserve(level.size() / 2);
        for (uint32_t node = 0;
             node < level.size();
             node += 2) {
            rc::alg_hash::State input{};
            for (uint32_t coordinate = 0;
                 coordinate < 4;
                 ++coordinate) {
                input[coordinate] =
                    level[node][coordinate];
                input[4 + coordinate] =
                    level[node + 1][coordinate];
            }
            input[8] =
                rc::alg_hash::
                    GetAlgHashConstants()
                    .node_domain;
            rc::alg_hash::Permute(input);
            next.push_back({
                input[0], input[1],
                input[2], input[3]});
        }
        level = std::move(next);
    }
    return level.front();
}

void SetField(
    std::vector<uint32_t>& words,
    const tape::ScheduleV1& schedule,
    proofabi::FieldKindV1 kind,
    uint32_t a,
    const std::array<uint64_t, 4>& value,
    uint32_t coordinates)
{
    for (uint32_t coordinate = 0;
         coordinate < coordinates;
         ++coordinate) {
        for (uint32_t limb = 0;
             limb < 2;
             ++limb) {
            const auto address =
                FindAddress(
                    schedule, kind, a,
                    coordinate,
                    static_cast<uint8_t>(
                        limb));
            BOOST_REQUIRE(address.has_value());
            words[SourceValueWord(*address)] =
                static_cast<uint32_t>(
                    value[coordinate] >>
                    (32 * limb));
        }
    }
}

struct Fixture {
    tape::PublicShapeV1 shape{ToyShape()};
    tape::PublicBindingV1 binding{Binding()};
    tape::ScheduleV1 schedule{};
    std::vector<uint32_t> words;
    proofabi::DecodedV1 decoded{};
    tape::ProductV1 tape_product{};
    terminal::PublicPlanV1 plan{};
    terminal::ProductV1 terminal_product{};

    Fixture()
    {
        schedule =
            tape::BuildScheduleV1(
                shape, binding);
        BOOST_REQUIRE_MESSAGE(
            schedule.valid, schedule.note);
        words = CanonicalWords(schedule);
        const gf::Fp3 final_value{
            gf::FromU64(9),
            gf::FromU64(17),
            gf::FromU64(25)};
        SetField(
            words, schedule,
            proofabi::FieldKindV1::FinalValue,
            0,
            {gf::Canonical(final_value.c0),
             gf::Canonical(final_value.c1),
             gf::Canonical(final_value.c2),
             0},
            3);
        const auto terminal_root =
            TerminalRoot(final_value);
        SetField(
            words, schedule,
            proofabi::FieldKindV1::FoldRoot,
            1,
            {gf::Canonical(terminal_root[0]),
             gf::Canonical(terminal_root[1]),
             gf::Canonical(terminal_root[2]),
             gf::Canonical(terminal_root[3])},
            4);
        std::string why;
        const auto decoded_optional =
            proofabi::DecodeCanonicalSafeV13(
                words, &why);
        BOOST_REQUIRE_MESSAGE(
            decoded_optional.has_value(), why);
        decoded = *decoded_optional;
        binding.tape_root =
            tape::ComputeTapeRootV1(
                shape, binding, words, &why);
        BOOST_REQUIRE_MESSAGE(
            binding.tape_root !=
                rc::alg_hash::Digest{},
            why);
        tape_product =
            tape::BuildProductV1(
                shape, binding, words);
        BOOST_REQUIRE_MESSAGE(
            tape_product.valid,
            tape_product.note);
        plan =
            terminal::BuildPublicPlanV1(
                shape);
        BOOST_REQUIRE_MESSAGE(
            plan.valid, plan.note);
        terminal_product =
            terminal::BuildProductV1(
                plan, decoded);
        BOOST_REQUIRE_MESSAGE(
            terminal_product.valid,
            terminal_product.note);
    }
};

struct Parent {
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>>
        columns;
    composer::ChildAttachmentV1 tape;
    composer::ChildAttachmentV1 terminal;
    terminal::ParentAliasAttachmentV1
        aliases;
};

Parent Compose(
    const tape::ProductV1& tape_product,
    const terminal::ProductV1& terminal_product,
    bool expect_alias_success)
{
    Parent out;
    const uint32_t rows =
        std::max(
            tape_product.cs.n_rows,
            terminal_product.cs.n_rows);
    std::string why;
    const auto append =
        [&](const auto& child_cs,
            const auto& child_columns,
            uint32_t ordinal,
            composer::ChildAttachmentV1& attachment) {
            return child_cs.n_rows == rows
                ? composer::AppendChildV1(
                      out.cs, out.columns,
                      child_cs, child_columns,
                      ordinal, attachment, &why)
                : composer::AppendChildLiftedV1(
                      out.cs, out.columns,
                      child_cs, child_columns,
                      rows, ordinal,
                      attachment, &why);
        };
    BOOST_REQUIRE_MESSAGE(
        append(
            tape_product.cs,
            tape_product.columns,
            0, out.tape),
        why);
    BOOST_REQUIRE_MESSAGE(
        append(
            terminal_product.cs,
            terminal_product.columns,
            1, out.terminal),
        why);
    const bool alias_ok =
        terminal::AppendProofTapeAliasesV1(
            out.cs, out.columns,
            tape_product, out.tape,
            terminal_product,
            out.terminal,
            out.aliases, &why);
    BOOST_CHECK_EQUAL(
        alias_ok, expect_alias_success);
    return out;
}

uint256 Seed()
{
    return Root(0x71);
}

struct AliasCanary {
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>>
        columns;
    terminal::LiteralAliasAttachmentV1
        attachment;
    bool appended{false};
};

AliasCanary BuildAliasCanary(
    const gf::Fp3& source,
    const gf::Fp3& sink)
{
    AliasCanary out;
    out.cs.n_rows = 2;
    out.cs.n_columns = 2;
    out.columns.assign(
        2,
        std::vector<gf::Fp3>(
            2, gf::Fp3::Zero()));
    out.columns[0][0] = source;
    out.columns[1][1] = sink;
    std::string why;
    out.appended =
        terminal::AppendLiteralAliasesV1(
            out.cs, out.columns,
            {{{0, 0}, {1, 1}}},
            out.attachment, &why);
    // The bounded canary uses the row-wise Alg backend directly. Its two
    // source/sink selector columns are verifier-owned and dual-OOD pinned;
    // the production parent instead folds the same selectors into global R0.
    out.cs.preprocessed_pin_ood = true;
    return out;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_v13_terminal_fold_parent_tests)

BOOST_AUTO_TEST_CASE(
    actual_v13_tape_cells_bind_terminal_tree_full_inventory)
{
    Fixture fixture;
    Parent parent =
        Compose(
            fixture.tape_product,
            fixture.terminal_product,
            true);
    BOOST_REQUIRE(parent.aliases.valid);
    BOOST_CHECK_EQUAL(
        parent.aliases.literal_aliases,
        terminal::kFinalValueLimbsV1 +
            terminal::kTerminalRootLimbsV1);
    BOOST_CHECK(
        parent.aliases
            .actual_tape_value_cells_referenced);
    BOOST_CHECK(
        parent.aliases
            .actual_terminal_cells_referenced);
    BOOST_CHECK(
        parent.aliases
            .cross_row_transport_constrained);
    BOOST_CHECK_EQUAL(
        parent.aliases.violations,
        0U);

}

BOOST_AUTO_TEST_CASE(
    literal_alias_has_bounded_proof_level_accept_and_reject)
{
    Fixture fixture;
    const auto honest_source =
        fixture.tape_product.source_cells.end();
    const auto root_address =
        FindAddress(
            fixture.schedule,
            proofabi::FieldKindV1::FoldRoot,
            fixture.plan.fold_count,
            0, 0);
    BOOST_REQUIRE(root_address.has_value());
    const auto source_cell =
        std::find_if(
            fixture.tape_product
                .source_cells.begin(),
            fixture.tape_product
                .source_cells.end(),
            [address = *root_address](
                const auto& cell) {
                return cell.address ==
                    address;
            });
    BOOST_REQUIRE(
        source_cell != honest_source);
    const auto sink_ref =
        fixture.terminal_product
            .abi_consumers
            .terminal_root[0];
    const gf::Fp3 sink_value =
        fixture.terminal_product
            .columns[sink_ref.column]
                    [sink_ref.row];
    const gf::Fp3 source_value =
        fixture.tape_product
            .columns[
                source_cell->value_column]
                    [source_cell->row];
    AliasCanary honest =
        BuildAliasCanary(
            source_value, sink_value);
    BOOST_REQUIRE(
        honest.appended);
    BOOST_REQUIRE_EQUAL(
        honest.attachment.violations,
        0U);
    const auto honest_proof =
        aq::AirQuotientProve<
            gf::Fp3, CanaryBackend>(
            honest.cs, honest.columns,
            Seed());
    BOOST_REQUIRE_MESSAGE(
        honest_proof.ok,
        honest_proof.note);
    BOOST_REQUIRE(
        honest_proof.division_exact);
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        (aq::AirQuotientVerify<
            gf::Fp3, CanaryBackend>(
            honest.cs,
            honest_proof.proof,
            Seed(), &why)),
        why);
    std::vector<unsigned char> honest_wire;
    BOOST_REQUIRE_MESSAGE(
        rc::SerializeAirQuotientProofAlg(
            honest_proof.proof,
            honest_wire, &why),
        why);
    BOOST_REQUIRE(
        !honest_wire.empty());
    BOOST_TEST_MESSAGE(
        "bounded terminal alias proof bytes="
        << honest_wire.size());

    std::vector<uint32_t> forged_words =
        fixture.words;
    const auto address =
        FindAddress(
            fixture.schedule,
            proofabi::FieldKindV1::FoldRoot,
            fixture.plan.fold_count,
            0, 0);
    BOOST_REQUIRE(address.has_value());
    forged_words[
        SourceValueWord(*address)] ^= 1U;

    auto forged_binding = fixture.binding;
    forged_binding.tape_root =
        tape::ComputeTapeRootV1(
            fixture.shape, forged_binding,
            forged_words, &why);
    BOOST_REQUIRE_MESSAGE(
        forged_binding.tape_root !=
            rc::alg_hash::Digest{},
        why);
    const auto forged_tape =
        tape::BuildProductV1(
            fixture.shape, forged_binding,
            forged_words);
    BOOST_REQUIRE_MESSAGE(
        forged_tape.valid,
        forged_tape.note);

    // Both child products are independently satisfiable.  Their exact
    // physical terminal-root cells disagree, so only the new same-parent
    // alias relation is violated.
    BOOST_REQUIRE_EQUAL(
        forged_tape.violations, 0U);
    BOOST_REQUIRE_EQUAL(
        fixture.terminal_product.violations,
        0U);
    const auto forged_source_cell =
        std::find_if(
            forged_tape.source_cells.begin(),
            forged_tape.source_cells.end(),
            [address = *root_address](
                const auto& cell) {
                return cell.address ==
                    address;
            });
    BOOST_REQUIRE(
        forged_source_cell !=
            forged_tape.source_cells.end());
    const gf::Fp3 forged_source =
        forged_tape.columns[
            forged_source_cell
                ->value_column]
            [forged_source_cell->row];
    AliasCanary forged =
        BuildAliasCanary(
            forged_source,
            sink_value);
    BOOST_REQUIRE(
        !forged.appended);
    BOOST_REQUIRE(
        terminal::CountViolationsV1(
            forged.cs,
            forged.columns) > 0);

    aq::AirProveOptions force;
    force.force_commit_on_inexact = true;
    const auto forged_proof =
        aq::AirQuotientProve<
            gf::Fp3, CanaryBackend>(
            forged.cs, forged.columns,
            Seed(), force);
    BOOST_REQUIRE_MESSAGE(
        forged_proof.ok,
        forged_proof.note);
    BOOST_REQUIRE(
        !forged_proof.division_exact);
    BOOST_CHECK(
        (!aq::AirQuotientVerify<
            gf::Fp3, CanaryBackend>(
            forged.cs,
            forged_proof.proof,
            Seed(), &why)));

    // A coordinate swap is not an alternate encoding of the same root:
    // lane ownership is exact and the same proof-level quotient check rejects.
    const auto lane1_address =
        FindAddress(
            fixture.schedule,
            proofabi::FieldKindV1::FoldRoot,
            fixture.plan.fold_count,
            1, 0);
    BOOST_REQUIRE(
        lane1_address.has_value());
    const auto lane1_cell =
        std::find_if(
            fixture.tape_product
                .source_cells.begin(),
            fixture.tape_product
                .source_cells.end(),
            [address = *lane1_address](
                const auto& cell) {
                return cell.address ==
                    address;
            });
    BOOST_REQUIRE(
        lane1_cell !=
            fixture.tape_product
                .source_cells.end());
    AliasCanary swapped =
        BuildAliasCanary(
            fixture.tape_product
                .columns[
                    lane1_cell
                        ->value_column]
                        [lane1_cell->row],
            sink_value);
    BOOST_REQUIRE(
        !swapped.appended);
    const auto swapped_proof =
        aq::AirQuotientProve<
            gf::Fp3, CanaryBackend>(
            swapped.cs,
            swapped.columns,
            Seed(), force);
    BOOST_REQUIRE(
        swapped_proof.ok);
    BOOST_REQUIRE(
        !swapped_proof.division_exact);
    BOOST_CHECK(
        (!aq::AirQuotientVerify<
            gf::Fp3, CanaryBackend>(
            swapped.cs,
            swapped_proof.proof,
            Seed(), &why)));
}

BOOST_AUTO_TEST_SUITE_END()
