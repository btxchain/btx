// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_receipt_public_statement.h>

#include <algorithm>
#include <array>
#include <vector>

namespace aq = matmul::v4::rc::air_quotient;
namespace gf = matmul::v4::rc::gkr_field;
namespace rps =
    matmul::v4::rc::receipt_public_statement;

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_receipt_public_statement_tests)

namespace {

uint256 Root(unsigned char byte)
{
    uint256 out;
    std::fill(out.begin(), out.end(), byte);
    return out;
}

rps::ReceiptPublicStatementTupleV1 Statement(uint32_t slot = 0)
{
    rps::ReceiptPublicStatementTupleV1 out;
    out.child_slot = slot;
    out.program_root = Root(0x11);
    out.exact_set_manifest_root = Root(0x22);
    out.source_identity = Root(0x33);
    out.statement_root = Root(0x44);
    return out;
}

aq::AirConstraintSystem<gf::Fp3> ToyCs()
{
    aq::AirConstraintSystem<gf::Fp3> cs;
    cs.n_rows = 8;
    cs.n_columns = 2;
    aq::AirConstraint<gf::Fp3> zero;
    zero.name =
        "stage3.receipt_public_statement.test.zero";
    zero.kind = aq::AirKind::kEverywhere;
    zero.alg_degree = 1;
    zero.eval =
        [](const std::vector<gf::Fp3>& cur,
           const std::vector<gf::Fp3>&) {
            return gf::Sub(cur[0], cur[0]);
        };
    cs.constraints.push_back(std::move(zero));
    return cs;
}

std::vector<std::vector<gf::Fp3>> ToyColumns()
{
    std::vector<std::vector<gf::Fp3>> out(
        2, std::vector<gf::Fp3>(8));
    for (uint32_t column = 0; column < out.size(); ++column) {
        for (uint32_t row = 0; row < out[column].size(); ++row) {
            out[column][row] = gf::Fp3{
                gf::FromU64(1 + 7 * column + 11 * row),
                gf::FromU64(3 + 5 * column + 13 * row),
                gf::FromU64(9 + 17 * column + 19 * row)};
        }
    }
    return out;
}

} // namespace

BOOST_AUTO_TEST_CASE(
    ordered_tuple_commitment_rejects_null_relabel_and_reorder)
{
    const auto statement = Statement();
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rps::ValidateReceiptPublicStatementTupleV1(
            statement, &why),
        why);
    const uint256 commitment =
        rps::CommitReceiptPublicStatementTupleV1(statement);
    BOOST_REQUIRE(!commitment.IsNull());

    auto relabelled = statement;
    relabelled.child_slot = 1;
    BOOST_CHECK(
        rps::CommitReceiptPublicStatementTupleV1(relabelled) !=
        commitment);

    auto reordered = statement;
    std::swap(
        reordered.program_root,
        reordered.exact_set_manifest_root);
    BOOST_CHECK(
        rps::CommitReceiptPublicStatementTupleV1(reordered) !=
        commitment);

    const std::array<uint256 rps::ReceiptPublicStatementTupleV1::*, 4>
        roots{
            &rps::ReceiptPublicStatementTupleV1::program_root,
            &rps::ReceiptPublicStatementTupleV1::
                exact_set_manifest_root,
            &rps::ReceiptPublicStatementTupleV1::source_identity,
            &rps::ReceiptPublicStatementTupleV1::statement_root};
    for (const auto root : roots) {
        auto null_root = statement;
        (null_root.*root).SetNull();
        BOOST_CHECK(
            !rps::ValidateReceiptPublicStatementTupleV1(
                null_root, &why));
        BOOST_CHECK(
            rps::CommitReceiptPublicStatementTupleV1(
                null_root).IsNull());
    }
    auto bad_slot = statement;
    bad_slot.child_slot = 2;
    BOOST_CHECK(
        !rps::ValidateReceiptPublicStatementTupleV1(
            bad_slot, &why));
}

BOOST_AUTO_TEST_CASE(
    air_child_relation_seed_binding_and_parent_cell_exports)
{
    const auto cs = ToyCs();
    const auto columns = ToyColumns();
    const auto statement = Statement();
    const uint256 base_seed = Root(0x55);
    const auto proof =
        rps::ProveStatementBoundChildRelationV1(
            cs, columns, statement, base_seed);
    BOOST_REQUIRE_MESSAGE(proof.valid, proof.note);
    BOOST_CHECK(proof.relation_proved);
    BOOST_CHECK(proof.relation_locally_verified);
    BOOST_CHECK(proof.tuple_bound_before_first_commitment);
    BOOST_CHECK(proof.canonical_alg_proof);
    BOOST_CHECK(!proof.same_parent_verifier_consumed);
    BOOST_CHECK(!proof.recursive_authority);

    rps::VerifiedReceiptPublicCellsV1 cells;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rps::VerifyStatementBoundChildRelationV1(
            cs, proof, statement, base_seed, &cells, &why),
        why);
    BOOST_CHECK(cells.tuple_canonical);
    BOOST_CHECK(cells.child_proof_verified);
    BOOST_CHECK(cells.fs_seed_recomputed_by_verifier);
    BOOST_CHECK(cells.cells_exported_after_verification);
    BOOST_CHECK(!cells.same_parent_verifier_consumed);
    BOOST_CHECK(!cells.recursive_authority);
    BOOST_CHECK_EQUAL(cells.child_slot, 0U);

    const std::array<uint256 rps::ReceiptPublicStatementTupleV1::*, 4>
        roots{
            &rps::ReceiptPublicStatementTupleV1::program_root,
            &rps::ReceiptPublicStatementTupleV1::
                exact_set_manifest_root,
            &rps::ReceiptPublicStatementTupleV1::source_identity,
            &rps::ReceiptPublicStatementTupleV1::statement_root};
    for (uint32_t i = 0; i < roots.size(); ++i) {
        auto substituted = statement;
        substituted.*roots[i] = Root(
            static_cast<unsigned char>(0x70 + i));
        BOOST_CHECK(
            !rps::VerifyStatementBoundChildRelationV1(
                cs, proof, substituted, base_seed,
                nullptr, nullptr));
    }

    auto relabelled = statement;
    relabelled.child_slot = 1;
    BOOST_CHECK(
        !rps::VerifyStatementBoundChildRelationV1(
            cs, proof, relabelled, base_seed,
            nullptr, nullptr));

    auto reordered = statement;
    std::swap(
        reordered.program_root,
        reordered.exact_set_manifest_root);
    BOOST_CHECK(
        !rps::VerifyStatementBoundChildRelationV1(
            cs, proof, reordered, base_seed,
            nullptr, nullptr));
    BOOST_CHECK(
        !rps::VerifyStatementBoundChildRelationV1(
            cs, proof, statement, Root(0x56),
            nullptr, nullptr));

    auto tampered = proof;
    BOOST_REQUIRE(!tampered.proof.batch.queries.empty());
    BOOST_REQUIRE(
        !tampered.proof.batch.queries[0].row.values.empty());
    tampered.proof.batch.queries[0].row.values[0] =
        gf::Add(
            tampered.proof.batch.queries[0].row.values[0],
            gf::Fp3::One());
    // PROOF-LEVEL rejection, not a host witness comparison.
    BOOST_CHECK(
        !rps::VerifyStatementBoundChildRelationV1(
            cs, tampered, statement, base_seed,
            nullptr, nullptr));
}

BOOST_AUTO_TEST_CASE(
    v10_tuple_seed_canary_rejects_substitution_relabel_and_opening_tamper)
{
    const auto statement = Statement();
    const uint256 base_seed = Root(0x66);
    const auto proof =
        rps::ProveStatementBoundV10TraceCanaryV1(
            ToyColumns(), statement, base_seed);
    BOOST_REQUIRE_MESSAGE(proof.valid, proof.note);
    BOOST_CHECK(proof.v10_trace_low_degree_proved);
    BOOST_CHECK(proof.tuple_bound_before_first_commitment);
    BOOST_CHECK(!proof.air_quotient_relation_proved);
    BOOST_CHECK(!proof.same_trace_join_with_child_air);
    BOOST_CHECK(!proof.recursive_authority);

    rps::VerifiedReceiptPublicCellsV1 cells;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rps::VerifyStatementBoundV10TraceCanaryV1(
            proof, statement, base_seed, &cells, &why),
        why);

    auto substituted = statement;
    substituted.source_identity = Root(0x77);
    BOOST_CHECK(
        !rps::VerifyStatementBoundV10TraceCanaryV1(
            proof, substituted, base_seed, nullptr, nullptr));
    auto relabelled = statement;
    relabelled.child_slot = 1;
    BOOST_CHECK(
        !rps::VerifyStatementBoundV10TraceCanaryV1(
            proof, relabelled, base_seed, nullptr, nullptr));
    auto reordered = statement;
    std::swap(
        reordered.program_root,
        reordered.statement_root);
    BOOST_CHECK(
        !rps::VerifyStatementBoundV10TraceCanaryV1(
            proof, reordered, base_seed, nullptr, nullptr));

    auto tampered = proof;
    BOOST_REQUIRE(!tampered.proof.queries.empty());
    BOOST_REQUIRE(!tampered.proof.queries[0].row.values.empty());
    tampered.proof.queries[0].row.values[0] =
        gf::Add(
            tampered.proof.queries[0].row.values[0],
            gf::Fp3::One());
    BOOST_CHECK(
        !rps::VerifyStatementBoundV10TraceCanaryV1(
            tampered, statement, base_seed,
            nullptr, nullptr));
}

BOOST_AUTO_TEST_SUITE_END()
