// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_multirow_v11_q96_child_verifier_bridge.h>

namespace matmul::v4::rc::
    stage3_multirow_v11_q96_child_verifier_bridge {
namespace {

uint256 Root(uint32_t tag)
{
    return Fri3AlgDigestToUint256(
        alg_hash::SpongeHashFp({
            gf::FromU64(0x31544f4fU),
            gf::FromU64(0x36395643U),
            gf::FromU64(tag)}));
}

std::array<
    q96::rv::ShardReceiptV1,
    q96::base::kQ96QueryShardsV1>
Receipts()
{
    std::array<
        q96::rv::ShardReceiptV1,
        q96::base::kQ96QueryShardsV1> out{};
    const auto ranges =
        q96::base::CanonicalQ96QueryRangesV1();
    for (uint32_t shard = 0;
         shard < out.size();
         ++shard) {
        auto& receipt = out[shard];
        receipt.range = ranges[shard];
        receipt.child_abi_root = Root(1);
        receipt.child_wire_root = Root(2);
        receipt.child_statement_root = Root(3);
        receipt.full_q192_transcript_root = Root(4);
        receipt.public_fs_seed = Root(5);
        receipt.program_root = {
            gf::FromU64(1), gf::FromU64(2),
            gf::FromU64(3), gf::FromU64(4)};
        receipt.parent_join_r0_root = Root(7);
        receipt.merkle_hash_r0_root =
            Root(10 + 5 * shard);
        receipt.merkle_fold_r0_root =
            Root(11 + 5 * shard);
        receipt.deep_vm_r0_root =
            Root(12 + 5 * shard);
        receipt.decoder_join_r0_root =
            Root(13 + 5 * shard);
        receipt.merkle_hash_rows = 1U << 19;
        receipt.merkle_hash_columns = 500;
        receipt.merkle_fold_rows = 1U << 13;
        receipt.merkle_fold_columns = 16;
        receipt.deep_vm_rows = 1U << 19;
        receipt.deep_vm_columns = 53;
        receipt.decoder_join_rows = 1U << 15;
        receipt.decoder_join_columns = 21;
        receipt.materialized_trace_cells =
            uint64_t{shard + 1} *
            1000000001ULL;
        receipt.measured_unaggregated_wire_bytes =
            uint64_t{shard + 1} *
            100003ULL;
        receipt.receipt_root =
            q96::rv::ComputeShardReceiptRootV1(
                receipt);
    }
    return out;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_multirow_v11_q96_child_verifier_bridge_tests)

BOOST_AUTO_TEST_CASE(
    exact_q96_child_verifier_capacity_is_bounded_but_not_static)
{
    const auto statement =
        q96::BuildStatementV1(Receipts());
    const auto audit = AuditCapacityV1(statement);
    BOOST_REQUIRE_MESSAGE(audit.valid, audit.note);
    BOOST_CHECK(audit.exact_q96_child_shape);
    BOOST_CHECK(audit.canonical_split_rap_program);
    BOOST_CHECK(audit.quotient_cap_audit_complete);
    BOOST_CHECK(audit.trace_cap_fits);
    BOOST_CHECK(audit.lde_cap_fits);
    BOOST_CHECK_EQUAL(
        audit.verifier_queries,
        kRCFri3AlgNumQueries);
    BOOST_CHECK_LE(
        audit.verifier_trace_rows,
        kTraceRowsCapV1);
    BOOST_CHECK_LE(
        audit.verifier_lde_rows,
        kLdeRowsCapV1);
    BOOST_CHECK_EQUAL(
        audit.verifier_max_constraint_degree, 3U);
    BOOST_CHECK_EQUAL(
        audit.verifier_quotient_len, 1048574U);
    BOOST_CHECK_EQUAL(
        audit.verifier_commitment_coefficients,
        1048576U);
    BOOST_CHECK_EQUAL(
        audit.verifier_lde_rows, kLdeRowsCapV1);

    BOOST_TEST_MESSAGE(
        "V11_Q96_CHILD_VERIFIER_CAP"
        << " child_rows=" << audit.child_rows
        << " child_cols=" << audit.child_columns
        << " child_constraints="
        << audit.child_constraints
        << " child_quotient="
        << audit.child_quotient_len
        << " active_rows="
        << audit.verifier_active_rows
        << " trace_rows="
        << audit.verifier_trace_rows
        << " degree="
        << audit.verifier_max_constraint_degree
        << " quotient="
        << audit.verifier_quotient_len
        << " coefficients="
        << audit.verifier_commitment_coefficients
        << " lde_rows="
        << audit.verifier_lde_rows
        << " poseidon_rows="
        << audit.verifier_poseidon_rows
        << " merkle_depth="
        << audit.verifier_merkle_depth
        << " folds=" << audit.verifier_fold_count
        << " static_cs=0"
        << " verifier_excludes_child_proof=0"
        << " authority=0");
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace matmul::v4::rc::stage3_multirow_v11_q96_child_verifier_bridge
