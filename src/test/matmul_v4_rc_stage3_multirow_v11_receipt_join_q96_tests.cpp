// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v11_receipt_join_q96.h>

#include <chrono>

namespace matmul::v4::rc::stage3_multirow_v11_receipt_join_q96 {
namespace {

uint256 Root(uint32_t tag)
{
    return Fri3AlgDigestToUint256(
        alg_hash::SpongeHashFp({
            gf::FromU64(0x31544f4fU),
            gf::FromU64(0x36395152U),
            gf::FromU64(tag)}));
}

std::array<
    rv::ShardReceiptV1,
    base::kQ96QueryShardsV1>
Receipts()
{
    std::array<
        rv::ShardReceiptV1,
        base::kQ96QueryShardsV1> out{};
    const auto ranges =
        base::CanonicalQ96QueryRangesV1();
    const uint256 child_abi = Root(1);
    const uint256 child_wire = Root(2);
    const uint256 child_statement = Root(3);
    const uint256 transcript = Root(4);
    const uint256 fs_seed = Root(5);
    const alg_hash::Digest program{
        gf::FromU64(1), gf::FromU64(2),
        gf::FromU64(3), gf::FromU64(4)};
    const uint256 parent = Root(7);
    for (uint32_t shard = 0;
         shard < out.size();
         ++shard) {
        auto& receipt = out[shard];
        receipt.range = ranges[shard];
        receipt.child_abi_root = child_abi;
        receipt.child_wire_root = child_wire;
        receipt.child_statement_root =
            child_statement;
        receipt.full_q192_transcript_root =
            transcript;
        receipt.public_fs_seed = fs_seed;
        receipt.program_root = program;
        receipt.parent_join_r0_root = parent;
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
            rv::ComputeShardReceiptRootV1(
                receipt);
    }
    return out;
}

bool Different(const uint256& lhs, const uint256& rhs)
{
    return lhs.GetHex() != rhs.GetHex();
}

void RequireInexactProofRejected(
    const StatementV1& statement)
{
    const auto product =
        BuildProductV1(statement);
    BOOST_REQUIRE(!product.valid);
    BOOST_REQUIRE_GT(product.violations, 0U);
    aq::AirProveOptions options;
    options.force_commit_on_inexact = true;
    const auto forced =
        aq::AirQuotientProveRowsSplitRap(
            product.cs, product.columns,
            product.preprocessed_columns,
            uint256::ONE, options);
    BOOST_REQUIRE_MESSAGE(forced.ok, forced.note);
    BOOST_CHECK(!forced.division_exact);
    std::string why;
    BOOST_CHECK(
        !aq::AirQuotientVerifyRowsSplitRap(
             product.cs, forced.proof,
             product.preprocessed_columns,
             uint256::ONE, &why));
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_multirow_v11_receipt_join_q96_tests)

BOOST_AUTO_TEST_CASE(
    exact_q96_join_closes_at_32_rows)
{
    const auto statement =
        BuildStatementV1(Receipts());
    const auto product =
        BuildProductV1(statement);
    BOOST_REQUIRE_MESSAGE(
        product.valid, product.note);
    BOOST_CHECK_EQUAL(product.trace_rows, 32U);
    BOOST_CHECK_EQUAL(product.trace_columns, 778U);
    BOOST_CHECK_EQUAL(product.constraints, 772U);
    BOOST_CHECK_EQUAL(
        product.max_constraint_degree, 2U);
    BOOST_CHECK_EQUAL(product.quotient_len, 32U);
    BOOST_CHECK_EQUAL(
        product.materialized_trace_cells,
        24896U);
    BOOST_CHECK_EQUAL(product.violations, 0U);
    BOOST_CHECK(product.exact_single_q192_partition);
    BOOST_CHECK(product.exact_common_child_identity);
    BOOST_CHECK(
        product.all_leaf_receipt_roots_recomputed);
    BOOST_CHECK(
        product.ordered_receipt_set_root_recomputed);
    BOOST_CHECK(product.root_export_constrained);
    BOOST_CHECK(
        product.canonical_u32_absorb_encoding);
    BOOST_CHECK(
        product.preprocessed_values_root_pinned);
    BOOST_CHECK(product.quadratic_poseidon_air);
    BOOST_CHECK(
        !product.child_receipt_proofs_verified_in_air);
    BOOST_CHECK(!product.recursive_authority_ready);
    BOOST_CHECK(
        product.computed_receipt_set_root ==
        statement.expected_receipt_set_root);

    const auto root =
        Fri3AlgDigestFromUint256(
            product.computed_receipt_set_root);
    BOOST_REQUIRE(root.has_value());
    BOOST_CHECK(gf::Eq(
        product.columns[
            product.layout.last_block]
            [kRootExportRowV1],
        gf::Fp3::One()));
    for (uint32_t limb = 0;
         limb < alg_hash::kAlgHashDigestLen;
         ++limb) {
        BOOST_CHECK(gf::Eq(
            product.columns[
                product.layout.ExpectedDigest(
                    limb)]
                [kRootExportRowV1],
            gf::Fp3::FromFp((*root)[limb])));
    }
}

BOOST_AUTO_TEST_CASE(
    malformed_partition_identity_and_x_plus_p_reject_at_proof_level)
{
    const auto receipts = Receipts();
    const auto honest =
        BuildStatementV1(receipts);

    auto omitted = receipts;
    omitted[1].range.query_count = 0;
    omitted[1].receipt_root =
        rv::ComputeShardReceiptRootV1(
            omitted[1]);
    const auto omitted_statement =
        BuildStatementV1(omitted);
    BOOST_CHECK(Different(
        honest.expected_receipt_set_root,
        omitted_statement.expected_receipt_set_root));
    RequireInexactProofRejected(
        omitted_statement);

    auto reordered = receipts;
    std::swap(reordered[0], reordered[1]);
    const auto reordered_statement =
        BuildStatementV1(reordered);
    BOOST_CHECK(Different(
        honest.expected_receipt_set_root,
        reordered_statement.expected_receipt_set_root));
    RequireInexactProofRejected(
        reordered_statement);

    auto split_transcript = receipts;
    split_transcript[1]
        .full_q192_transcript_root = Root(90);
    split_transcript[1].receipt_root =
        rv::ComputeShardReceiptRootV1(
            split_transcript[1]);
    RequireInexactProofRejected(
        BuildStatementV1(split_transcript));

    auto alias = receipts;
    const uint256 before =
        alias[0].receipt_root;
    alias[0].materialized_trace_cells +=
        gf::kP;
    const uint256 after =
        rv::ComputeShardReceiptRootV1(
            alias[0]);
    BOOST_CHECK(Different(before, after));
    // Retaining the old receipt root is the actual x/x+p
    // substitution attack.
    RequireInexactProofRejected(
        BuildStatementV1(alias));
}

BOOST_AUTO_TEST_CASE(
    split_rap_proof_accepts_and_committed_root_tamper_rejects)
{
    const auto statement =
        BuildStatementV1(Receipts());
    const auto prove_start =
        std::chrono::steady_clock::now();
    const auto proved =
        ProveV1(statement, uint256::ONE);
    const auto prove_ms =
        std::chrono::duration_cast<
            std::chrono::milliseconds>(
            std::chrono::steady_clock::now() -
            prove_start).count();
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_REQUIRE_LT(
        proved.proof_wire_bytes,
        kRCStage3MaxProofBytes);

    const auto verify_start =
        std::chrono::steady_clock::now();
    const auto verified =
        VerifyV1(
            statement, proved.proof,
            uint256::ONE);
    const auto verify_us =
        std::chrono::duration_cast<
            std::chrono::microseconds>(
            std::chrono::steady_clock::now() -
            verify_start).count();
    BOOST_REQUIRE_MESSAGE(
        verified.valid, verified.note);
    BOOST_CHECK(
        verified.split_rap_quotient_fri_verified);
    BOOST_CHECK(
        !verified.child_receipt_proofs_verified_in_air);
    BOOST_CHECK(!verified.recursive_authority_ready);

    auto root_tamper = proved.proof;
    BOOST_REQUIRE_EQUAL(
        root_tamper.batch.groups.size(), 3U);
    root_tamper.batch.groups[0]
        .row_commit.root[0] =
        gf::Add(
            root_tamper.batch.groups[0]
                .row_commit.root[0],
            gf::FromU64(1));
    BOOST_CHECK(
        !VerifyV1(
             statement, root_tamper,
             uint256::ONE).valid);

    BOOST_TEST_MESSAGE(
        "V11_Q96_RECEIPT_JOIN"
        << " rows=" << proved.trace_rows
        << " cols=" << proved.trace_columns
        << " constraints=" << proved.constraints
        << " degree="
        << proved.max_constraint_degree
        << " quotient_len="
        << proved.quotient_len
        << " proof_bytes="
        << proved.proof_wire_bytes
        << " prove_ms=" << prove_ms
        << " verify_us=" << verify_us
        << " one_q192_transcript=1"
        << " independent_lanes=0"
        << " proof_root_reject=1"
        << " omission_reject=1"
        << " reorder_reject=1"
        << " common_root_reject=1"
        << " x_plus_p_reject=1");
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace matmul::v4::rc::stage3_multirow_v11_receipt_join_q96
