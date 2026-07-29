// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_coupled_winner_parent_air.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <numeric>

namespace {

namespace parent =
    matmul::v4::rc::coupled_winner_parent_air;
namespace aq = matmul::v4::rc::air_quotient;
namespace gf = matmul::v4::rc::gkr_field;
namespace rc = matmul::v4::rc;

uint256 H(uint8_t value)
{
    std::array<unsigned char, 32> bytes{};
    bytes.fill(value);
    return uint256{
        Span<const unsigned char>{
            bytes.data(), bytes.size()}};
}

struct BuiltApplication {
    aq::AirConstraintSystem<gf::Fp3> cs;
    parent::LayoutV1 layout;
    std::vector<std::vector<gf::Fp3>> columns;
    aq::AirQuotientFixedTracePinV3 fixed_trace;
    aq::AirQuotientTwoEpochBaseRowSession r0;
};

BuiltApplication BuildApplication(
    const std::vector<parent::TerminalCellV1>& cells)
{
    BuiltApplication out;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        parent::BuildConstraintSystemV1(
            cells.size(), out.cs,
            &out.layout, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        parent::BuildWitnessV1(
            cells, out.layout,
            out.cs.n_rows,
            out.columns, &why),
        why);
    out.fixed_trace.ordered_columns.resize(
        out.layout.phase0_end);
    std::iota(
        out.fixed_trace.ordered_columns.begin(),
        out.fixed_trace.ordered_columns.end(), 0);
    out.r0 =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            out.cs, out.columns,
            out.fixed_trace.ordered_columns);
    BOOST_REQUIRE(out.r0.valid);
    out.fixed_trace.row_root =
        out.r0.base_row_commitment;
    return out;
}

std::vector<parent::TerminalCellV1> Cells()
{
    using Family = parent::TerminalFamilyV1;
    using Kind = parent::TerminalKindV1;
    return {
        {Family::Binding, Kind::StatementRoot,
         0, 0, H(0x11)},
        {Family::Gemm, Kind::PinRoot,
         3, 0, H(0x22)},
        {Family::Gemm, Kind::TraceRoot,
         3, 0, H(0x33)},
        {Family::RootVector, Kind::TerminalRoot,
         7, 1, H(0x44)},
    };
}

rc::RCStage3CoupledWinnerChildBindingV1 Binding()
{
    rc::RCStage3CoupledWinnerChildBindingV1 out;
    out.finalized_header_hash = H(0x01);
    out.statement_commitment = H(0x02);
    out.coupled_shape_commitment = H(0x03);
    out.winner_receipt_commitment = H(0x04);
    out.scheduled_page_instances = 1;
    out.accumulation_links = 2;
    out.stage_boundary_links = 3;
    out.barrier_links = 4;
    out.initial_state_binding = H(0x05);
    out.scheduled_page_binding = H(0x06);
    out.accumulation_binding = H(0x07);
    out.stage_boundary_binding = H(0x08);
    out.bank_hash_binding = H(0x09);
    out.barrier_digest_binding = H(0x0a);
    out.representative_cell_binding = H(0x0b);
    out.child_proof_family_binding = H(0x0c);
    out.product_commitment =
        rc::CommitRCStage3CoupledWinnerChildBindingV1(
            out);
    return out;
}

rc::RCStage3BoundedCoupledSemanticComposition
MinimalChildren()
{
    rc::RCStage3BoundedCoupledSemanticComposition out;
    out.bank.product_commitment = H(0x21);
    out.bank_root.manifest.commitment = H(0x22);
    out.bank_root.bank_bytes.semantic_memory_root = H(0x23);
    out.bank_root.bank_digest.semantic_memory_root = H(0x24);
    out.initial_state.product_commitment = H(0x25);
    out.gemm.product_commitment = H(0x26);
    out.signed_range.value_roots_commitment = H(0x27);
    out.exchange_permutation.product_commitment = H(0x28);
    out.mix.product_commitment = H(0x29);
    out.extract.product_commitment = H(0x2a);
    out.extract.output_to_barrier.pin.link_commitment = H(0x2b);
    out.root_chain.barrier_inputs_pin.pin_commitment = H(0x2c);
    out.root_chain.digest_value_pin.pin_commitment = H(0x2d);

    out.mix.arithmetic_pin.statement_commitment = H(0x31);
    out.mix.arithmetic_pin.pin_commitment = H(0x32);
    out.mix.arithmetic_proof.trace_commit = H(0x33);

    const std::array<uint256, 4> pin{
        H(0x41), H(0x42), H(0x43), H(0x44)};
    const std::array<uint256, 4> trace{
        H(0x51), H(0x52), H(0x53), H(0x54)};
    std::array<rc::RCStage3RootChainVectorProof*, 4>
        proofs{
            &out.root_chain.barrier_inputs_proof,
            &out.root_chain.barrier_outputs_proof,
            &out.root_chain.digest_inputs_proof,
            &out.root_chain.digest_value_proof,
        };
    for (uint32_t i = 0; i < proofs.size(); ++i) {
        proofs[i]->pin_commitment = pin[i];
        proofs[i]->quotient.trace_commit = trace[i];
    }
    return out;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_coupled_winner_parent_air_tests)

BOOST_AUTO_TEST_CASE(
    canonical_terminal_table_executes_safe_fixed_parent)
{
    const auto cells = Cells();
    auto application = BuildApplication(cells);
    const uint256 seed = H(0x71);
    const auto proved =
        aq::AirQuotientProveRowsSplitRapSafeFixedV3(
            application.cs,
            application.columns,
            application.fixed_trace,
            seed, {}, &application.r0);
    BOOST_REQUIRE_MESSAGE(
        proved.ok, proved.note);
    BOOST_REQUIRE(proved.division_exact);
    std::string why;
    BOOST_CHECK_MESSAGE(
        aq::AirQuotientVerifyRowsSplitRapSafeFixedV3(
            application.cs, proved.proof,
            application.fixed_trace,
            seed, &why),
        why);
    BOOST_CHECK_EQUAL(
        application.layout.phase0_end,
        23U);
    BOOST_CHECK_EQUAL(
        application.layout.n_columns,
        31U);
    BOOST_CHECK(
        !parent::CommitTerminalCellsV1(
             cells).IsNull());

    parent::ParentProofV1 envelope;
    envelope.terminal_cells =
        static_cast<uint32_t>(cells.size());
    envelope.trace_rows =
        application.cs.n_rows;
    envelope.terminal_table_commitment =
        parent::CommitTerminalCellsV1(cells);
    envelope.r0_row_group_root =
        application.fixed_trace.row_root;
    envelope.proof = proved.proof;
    std::vector<unsigned char> bytes;
    BOOST_REQUIRE_NE(
        parent::SerializeParentProofV1(
            envelope, bytes, &why),
        0U);
    const auto decoded =
        parent::DeserializeParentProofV1(
            bytes, &why);
    BOOST_REQUIRE_MESSAGE(
        decoded.has_value(), why);
    BOOST_CHECK_EQUAL(
        decoded->terminal_cells,
        envelope.terminal_cells);
    BOOST_CHECK_EQUAL(
        decoded->trace_rows,
        envelope.trace_rows);
    BOOST_CHECK(
        decoded->terminal_table_commitment ==
        envelope.terminal_table_commitment);
    BOOST_CHECK(
        decoded->r0_row_group_root ==
        envelope.r0_row_group_root);
    BOOST_CHECK_MESSAGE(
        aq::AirQuotientVerifyRowsSplitRapSafeFixedV3(
            application.cs, decoded->proof,
            application.fixed_trace,
            seed, &why),
        why);

    auto noncanonical = bytes;
    noncanonical[6] = 1;
    BOOST_CHECK(
        !parent::DeserializeParentProofV1(
             noncanonical, &why).has_value());
    noncanonical = bytes;
    noncanonical.push_back(0);
    BOOST_CHECK(
        !parent::DeserializeParentProofV1(
             noncanonical, &why).has_value());
}

BOOST_AUTO_TEST_CASE(
    independently_committed_alternate_terminal_table_rejects)
{
    const auto honest_cells = Cells();
    auto alternate_cells = honest_cells;
    alternate_cells[2].value = H(0x99);
    auto honest =
        BuildApplication(honest_cells);
    auto alternate =
        BuildApplication(alternate_cells);
    BOOST_REQUIRE(
        honest.fixed_trace.row_root !=
        alternate.fixed_trace.row_root);

    const uint256 seed = H(0x72);
    const auto honest_proof =
        aq::AirQuotientProveRowsSplitRapSafeFixedV3(
            honest.cs, honest.columns,
            honest.fixed_trace, seed, {},
            &honest.r0);
    BOOST_REQUIRE_MESSAGE(
        honest_proof.ok, honest_proof.note);
    const auto alternate_proof =
        aq::AirQuotientProveRowsSplitRapSafeFixedV3(
            alternate.cs, alternate.columns,
            alternate.fixed_trace, seed, {},
            &alternate.r0);
    BOOST_REQUIRE_MESSAGE(
        alternate_proof.ok,
        alternate_proof.note);
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        aq::AirQuotientVerifyRowsSplitRapSafeFixedV3(
            alternate.cs,
            alternate_proof.proof,
            alternate.fixed_trace,
            seed, &why),
        why);
    BOOST_CHECK(
        !aq::AirQuotientVerifyRowsSplitRapSafeFixedV3(
            honest.cs,
            alternate_proof.proof,
            honest.fixed_trace,
            seed, &why));
}

BOOST_AUTO_TEST_CASE(
    collector_rejects_stale_binding_commitment)
{
    auto binding = Binding();
    binding.product_commitment = H(0xff);

    const auto children = MinimalChildren();
    std::vector<parent::TerminalCellV1> cells;
    std::string why;
    BOOST_CHECK(
        !parent::CollectTerminalCellsV1(
            binding, children, cells, &why));
    BOOST_CHECK(
        why.find("binding_commitment") !=
        std::string::npos);
}

BOOST_AUTO_TEST_CASE(
    every_mapped_child_root_changes_the_parent_table)
{
    const auto binding = Binding();
    const auto honest = MinimalChildren();
    std::vector<parent::TerminalCellV1>
        honest_cells;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        parent::CollectTerminalCellsV1(
            binding, honest,
            honest_cells, &why),
        why);
    BOOST_CHECK_EQUAL(
        honest_cells.size(), 42U);
    BOOST_CHECK(
        std::any_of(
            honest_cells.begin(),
            honest_cells.end(),
            [](const auto& cell) {
                return
                    cell.family ==
                        parent::TerminalFamilyV1::
                            Binding &&
                    cell.kind ==
                        parent::TerminalKindV1::
                            TerminalRoot &&
                    cell.value == H(0x0b);
            }));
    BOOST_CHECK(
        std::any_of(
            honest_cells.begin(),
            honest_cells.end(),
            [](const auto& cell) {
                return
                    cell.family ==
                        parent::TerminalFamilyV1::
                            RootVector &&
                    cell.kind ==
                        parent::TerminalKindV1::
                            TraceRoot &&
                    cell.value == H(0x51);
            }));

    auto alternate = honest;
    alternate.root_chain
        .barrier_inputs_proof
        .quotient.trace_commit = H(0xe1);
    std::vector<parent::TerminalCellV1>
        alternate_cells;
    BOOST_REQUIRE_MESSAGE(
        parent::CollectTerminalCellsV1(
            binding, alternate,
            alternate_cells, &why),
        why);
    BOOST_CHECK(
        parent::CommitTerminalCellsV1(
            honest_cells) !=
        parent::CommitTerminalCellsV1(
            alternate_cells));
}

BOOST_AUTO_TEST_SUITE_END()
