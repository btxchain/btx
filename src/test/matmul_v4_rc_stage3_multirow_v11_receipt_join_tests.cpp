// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v11_receipt_join.h>

#include <chrono>

namespace matmul::v4::rc::stage3_multirow_v11_receipt_join {
namespace {

uint256 Root(uint32_t tag)
{
    return Fri3AlgDigestToUint256(
        alg_hash::SpongeHashFp({
            gf::FromU64(0x31544f4fU),
            gf::FromU64(0x524e494aU),
            gf::FromU64(tag)}));
}

std::array<rv::ShardReceiptV1, rv::kQueryShardsV1>
Receipts()
{
    std::array<
        rv::ShardReceiptV1,
        rv::kQueryShardsV1> out{};
    const auto ranges =
        rv::CanonicalQueryRangesV1();
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

std::array<
    rv::ShardReceiptV1,
    kQ96QueryShardsV1>
Q96Receipts()
{
    const auto q64 = Receipts();
    std::array<
        rv::ShardReceiptV1,
        kQ96QueryShardsV1> out{
            q64[0], q64[1]};
    const auto ranges =
        CanonicalQ96QueryRangesV1();
    for (uint32_t shard = 0;
         shard < out.size();
         ++shard) {
        out[shard].range = ranges[shard];
        out[shard].receipt_root =
            rv::ComputeShardReceiptRootV1(
                out[shard]);
    }
    return out;
}

bool Different(const uint256& a, const uint256& b)
{
    return a.GetHex() != b.GetHex();
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
    matmul_v4_rc_stage3_multirow_v11_receipt_join_tests)

BOOST_AUTO_TEST_CASE(
    q96_two_shard_capacity_is_exact_but_inventory_conditional)
{
    const auto audit =
        AuditQ96TwoShardV1(
            1298, 1276, 5, 6);
    BOOST_REQUIRE_MESSAGE(
        audit.valid_as_capacity_evaluation,
        audit.note);
    BOOST_CHECK_EQUAL(
        audit.rows_per_query, 7680U);
    BOOST_CHECK_EQUAL(
        audit.raw_rows_per_shard, 737280U);
    BOOST_CHECK_EQUAL(
        audit.rounded_trace_rows, 1048576U);
    BOOST_CHECK_EQUAL(
        audit.lde_rows, 16777216U);
    BOOST_CHECK_EQUAL(
        audit.maximum_rows_per_query, 10922U);
    BOOST_CHECK_EQUAL(
        audit.rows_per_query_headroom, 3242U);
    BOOST_CHECK_EQUAL(
        audit.q64_parent_leaf_receipts, 18U);
    BOOST_CHECK_EQUAL(
        audit.q96_parent_leaf_receipts, 12U);
    BOOST_CHECK(
        audit.exact_single_q192_partition);
    BOOST_CHECK(!audit.independent_query_lanes);
    BOOST_CHECK(audit.fits_trace_cap);
    BOOST_CHECK(audit.fits_lde_cap);
    BOOST_CHECK(
        !audit
             .executable_program_inventory_measured);
    BOOST_TEST_MESSAGE(
        "V11_Q96_CAP"
        << " rows_per_query="
        << audit.rows_per_query
        << " raw_rows="
        << audit.raw_rows_per_shard
        << " trace_rows="
        << audit.rounded_trace_rows
        << " lde_rows=" << audit.lde_rows
        << " headroom_rows_per_query="
        << audit.rows_per_query_headroom
        << " leaf_receipts="
        << audit.q64_parent_leaf_receipts
        << "->"
        << audit.q96_parent_leaf_receipts
        << " one_q192_transcript=1"
        << " independent_lanes=0"
        << " inventory_conditional=1");

    BOOST_CHECK(
        !AuditQ96TwoShardV1(
             0, 1276, 5, 6)
             .valid_as_capacity_evaluation);
    BOOST_CHECK(
        !AuditQ96TwoShardV1(
             UINT32_MAX, UINT32_MAX,
             UINT32_MAX, 6)
             .valid_as_capacity_evaluation);
}

BOOST_AUTO_TEST_CASE(
    q96_binding_profile_binds_partition_order_and_common_identity)
{
    const auto receipts = Q96Receipts();
    const auto profile =
        BuildQ96ReceiptSetV1(receipts);
    BOOST_REQUIRE_MESSAGE(
        profile.valid_as_binding_profile,
        profile.note);
    BOOST_CHECK(
        profile.exact_single_q192_partition);
    BOOST_CHECK(profile.common_child_identity);
    BOOST_CHECK(profile.leaf_roots_recomputed);
    BOOST_CHECK(profile.canonical_alg_hash_root);
    BOOST_CHECK(!profile.executable_join_air);
    BOOST_CHECK(
        !profile.recursive_authority_ready);
    BOOST_TEST_MESSAGE(
        "V11_Q96_RECEIPT_SET"
        << " ranges=[0,96),[96,192)"
        << " root="
        << profile.receipt_set_root.GetHex()
        << " executable_join_air=0"
        << " authority=0");

    auto omitted = receipts;
    omitted[1].range.query_count = 0;
    omitted[1].receipt_root =
        rv::ComputeShardReceiptRootV1(
            omitted[1]);
    const auto omitted_profile =
        BuildQ96ReceiptSetV1(omitted);
    BOOST_CHECK(
        !omitted_profile
             .valid_as_binding_profile);
    BOOST_CHECK(
        !omitted_profile
             .exact_single_q192_partition);
    BOOST_CHECK(Different(
        profile.receipt_set_root,
        omitted_profile.receipt_set_root));

    auto reordered = receipts;
    std::swap(reordered[0], reordered[1]);
    const auto reordered_profile =
        BuildQ96ReceiptSetV1(reordered);
    BOOST_CHECK(
        !reordered_profile
             .valid_as_binding_profile);
    BOOST_CHECK(
        !reordered_profile
             .exact_single_q192_partition);
    BOOST_CHECK(Different(
        profile.receipt_set_root,
        reordered_profile.receipt_set_root));

    auto split_transcript = receipts;
    split_transcript[1]
        .full_q192_transcript_root = Root(201);
    split_transcript[1].receipt_root =
        rv::ComputeShardReceiptRootV1(
            split_transcript[1]);
    const auto split_profile =
        BuildQ96ReceiptSetV1(
            split_transcript);
    BOOST_CHECK(
        !split_profile
             .valid_as_binding_profile);
    BOOST_CHECK(
        !split_profile.common_child_identity);

    auto alias = receipts;
    const uint256 old_leaf =
        alias[0].receipt_root;
    alias[0].materialized_trace_cells +=
        gf::kP;
    const uint256 new_leaf =
        rv::ComputeShardReceiptRootV1(
            alias[0]);
    BOOST_CHECK(Different(old_leaf, new_leaf));
    const auto alias_profile =
        BuildQ96ReceiptSetV1(alias);
    BOOST_CHECK(
        !alias_profile.valid_as_binding_profile);
    BOOST_CHECK(
        !alias_profile.leaf_roots_recomputed);
}

BOOST_AUTO_TEST_CASE(
    exact_receipt_codec_and_binary_air_shape_close)
{
    const auto receipts = Receipts();
    for (const auto& receipt : receipts) {
        const auto preimage =
            BuildReceiptPreimageV1(receipt);
        BOOST_REQUIRE_EQUAL(
            preimage.size(),
            kReceiptPreimageLanesV1);
        BOOST_CHECK(
            Fri3AlgDigestToUint256(
                alg_hash::SpongeHashFp(
                    preimage)) ==
            receipt.receipt_root);
    }

    const auto statement =
        BuildStatementV1(receipts);
    BOOST_REQUIRE(
        Fri3AlgDigestFromUint256(
            statement
                .expected_shard_set_root)
            .has_value());
    BOOST_REQUIRE(
        Fri3AlgDigestFromUint256(
            statement.expected_binary_root)
            .has_value());
    const auto product =
        BuildProductV1(statement);
    BOOST_REQUIRE_MESSAGE(
        product.valid, product.note);
    BOOST_CHECK_EQUAL(
        product.trace_rows, 64U);
    BOOST_CHECK_EQUAL(
        product.trace_columns, 778U);
    BOOST_CHECK_EQUAL(
        product.constraints, 772U);
    BOOST_CHECK_EQUAL(
        product.max_constraint_degree, 2U);
    BOOST_CHECK_EQUAL(
        product.quotient_len, 64U);
    BOOST_CHECK_EQUAL(
        product.materialized_trace_cells,
        49792U);
    BOOST_CHECK_EQUAL(product.violations, 0U);
    BOOST_CHECK(product.exact_q192_partition);
    BOOST_CHECK(
        product.exact_common_child_identity);
    BOOST_CHECK(
        product.all_leaf_receipt_roots_recomputed);
    BOOST_CHECK(
        product.direct_shard_set_root_recomputed);
    BOOST_CHECK(
        product.ordered_binary_tree_recomputed);
    BOOST_CHECK(
        product.binary_root_export_constrained);
    const auto binary_digest =
        Fri3AlgDigestFromUint256(
            product.computed_binary_root);
    BOOST_REQUIRE(binary_digest.has_value());
    BOOST_CHECK(gf::Eq(
        product.columns[
            product.layout.last_block]
            [kBinaryRootExportRowV1],
        gf::Fp3::One()));
    for (uint32_t limb = 0;
         limb < alg_hash::kAlgHashDigestLen;
         ++limb) {
        BOOST_CHECK(gf::Eq(
            product.columns[
                product.layout
                    .ExpectedDigest(limb)]
                [kBinaryRootExportRowV1],
            gf::Fp3::FromFp(
                (*binary_digest)[limb])));
    }
    BOOST_CHECK(
        product.canonical_u32_absorb_encoding);
    BOOST_CHECK(
        product.preprocessed_values_root_pinned);
    BOOST_CHECK(
        product.quadratic_poseidon_air);
    BOOST_CHECK(
        !product
             .child_receipt_proofs_verified_in_air);
    BOOST_CHECK(
        !product.recursive_authority_ready);
}

BOOST_AUTO_TEST_CASE(
    relation_rejects_omission_reorder_common_root_and_x_plus_p)
{
    const auto receipts = Receipts();
    const auto honest =
        BuildStatementV1(receipts);

    auto omitted_receipts = receipts;
    omitted_receipts[2].range.query_count = 0;
    omitted_receipts[2].receipt_root =
        rv::ComputeShardReceiptRootV1(
            omitted_receipts[2]);
    const auto omitted =
        BuildStatementV1(omitted_receipts);
    const auto omitted_product =
        BuildProductV1(omitted);
    BOOST_CHECK(!omitted_product.valid);
    BOOST_CHECK(
        !omitted_product.exact_q192_partition);
    BOOST_CHECK_GT(
        omitted_product.violations, 0U);
    RequireInexactProofRejected(omitted);

    auto reordered_receipts = receipts;
    std::swap(
        reordered_receipts[0],
        reordered_receipts[1]);
    const auto reordered =
        BuildStatementV1(reordered_receipts);
    const auto reordered_product =
        BuildProductV1(reordered);
    BOOST_CHECK(!reordered_product.valid);
    BOOST_CHECK(
        !reordered_product.exact_q192_partition);
    BOOST_CHECK_GT(
        reordered_product.violations, 0U);
    RequireInexactProofRejected(reordered);

    auto split_identity_receipts = receipts;
    split_identity_receipts[1]
        .full_q192_transcript_root = Root(90);
    split_identity_receipts[1].receipt_root =
        rv::ComputeShardReceiptRootV1(
            split_identity_receipts[1]);
    const auto split_identity =
        BuildStatementV1(
            split_identity_receipts);
    const auto split_product =
        BuildProductV1(split_identity);
    BOOST_CHECK(!split_product.valid);
    BOOST_CHECK(
        !split_product.exact_common_child_identity);
    BOOST_CHECK_GT(
        split_product.violations, 0U);
    RequireInexactProofRejected(split_identity);

    auto alias_receipts = receipts;
    const uint256 before =
        alias_receipts[0].receipt_root;
    alias_receipts[0]
        .materialized_trace_cells += gf::kP;
    const uint256 after =
        rv::ComputeShardReceiptRootV1(
            alias_receipts[0]);
    BOOST_CHECK(Different(before, after));
    // Leaving the old root is the actual x/x+p substitution attack.
    const auto alias_attack =
        BuildStatementV1(alias_receipts);
    const auto alias_product =
        BuildProductV1(alias_attack);
    BOOST_CHECK(!alias_product.valid);
    BOOST_CHECK(
        !alias_product
             .all_leaf_receipt_roots_recomputed);
    BOOST_CHECK_GT(alias_product.violations, 0U);
    RequireInexactProofRejected(alias_attack);

    auto noncanonical_program = receipts;
    for (auto& receipt : noncanonical_program) {
        receipt.program_root[0] = gf::kP + 1;
        // The native field hash aliases this to 1. The statement decoder,
        // not the field arithmetic, must therefore reject it.
        receipt.receipt_root =
            rv::ComputeShardReceiptRootV1(receipt);
    }
    BOOST_CHECK(
        noncanonical_program[0].receipt_root ==
        receipts[0].receipt_root);
    const auto noncanonical_product =
        BuildProductV1(
            BuildStatementV1(
                noncanonical_program));
    BOOST_CHECK(!noncanonical_product.valid);
    BOOST_CHECK(
        !noncanonical_product
             .exact_common_child_identity);

    BOOST_CHECK(Different(
        honest.expected_binary_root,
        omitted.expected_binary_root));
    BOOST_CHECK(Different(
        honest.expected_binary_root,
        reordered.expected_binary_root));
}

BOOST_AUTO_TEST_CASE(
    split_rap_proof_accepts_and_proof_level_substitutions_reject)
{
    const auto receipts = Receipts();
    const auto statement =
        BuildStatementV1(receipts);
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
        verified
            .split_rap_quotient_fri_verified);
    BOOST_CHECK(
        !verified
             .child_receipt_proofs_verified_in_air);
    BOOST_CHECK(
        !verified.recursive_authority_ready);

    auto proof_root_substitution = proved.proof;
    BOOST_REQUIRE_EQUAL(
        proof_root_substitution.batch.groups.size(),
        3U);
    proof_root_substitution.batch.groups[0]
        .row_commit.root[0] =
        gf::Add(
            proof_root_substitution.batch
                .groups[0].row_commit.root[0],
            gf::FromU64(1));
    BOOST_CHECK(
        !VerifyV1(
             statement,
             proof_root_substitution,
             uint256::ONE).valid);

    auto omitted_receipts = receipts;
    omitted_receipts[2].range.query_count = 0;
    omitted_receipts[2].receipt_root =
        rv::ComputeShardReceiptRootV1(
            omitted_receipts[2]);
    BOOST_CHECK(
        !VerifyV1(
             BuildStatementV1(
                 omitted_receipts),
             proved.proof,
             uint256::ONE).valid);

    auto reordered_receipts = receipts;
    std::swap(
        reordered_receipts[0],
        reordered_receipts[1]);
    BOOST_CHECK(
        !VerifyV1(
             BuildStatementV1(
                 reordered_receipts),
             proved.proof,
             uint256::ONE).valid);

    auto common_root_substitution = receipts;
    common_root_substitution[1]
        .full_q192_transcript_root = Root(91);
    common_root_substitution[1].receipt_root =
        rv::ComputeShardReceiptRootV1(
            common_root_substitution[1]);
    BOOST_CHECK(
        !VerifyV1(
             BuildStatementV1(
                 common_root_substitution),
             proved.proof,
             uint256::ONE).valid);

    auto alias_substitution = receipts;
    alias_substitution[0]
        .materialized_trace_cells += gf::kP;
    BOOST_CHECK(
        !VerifyV1(
             BuildStatementV1(
                 alias_substitution),
             proved.proof,
             uint256::ONE).valid);

    BOOST_TEST_MESSAGE(
        "V11_RECEIPT_JOIN"
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
        << " proof_root_reject=1"
        << " omission_reject=1"
        << " reorder_reject=1"
        << " common_root_reject=1"
        << " x_plus_p_reject=1");
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace matmul::v4::rc::stage3_multirow_v11_receipt_join
