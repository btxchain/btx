// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_multirow_v11_recursive_verifier.h>
#include <matmul/matmul_v4_rc_stage3_multirow_p2_consumer_bridge.h>

#include <hash.h>

namespace matmul::v4::rc::stage3_multirow_v11_recursive_verifier {
namespace {

uint256 H(uint32_t tag)
{
    HashWriter hash;
    hash << uint64_t{0x31545345'54525652ULL};
    hash << tag;
    return hash.GetHash();
}

bool Different(const uint256& a, const uint256& b)
{
    return a.GetHex() != b.GetHex();
}

air_quotient::AirConstraintSystem<gf::Fp3> TransitionAir()
{
    air_quotient::AirConstraintSystem<gf::Fp3> cs;
    cs.n_rows = 256;
    cs.n_columns = 2;
    cs.constraints.push_back({
        "counter_step", air_quotient::AirKind::kTransition, 1,
        [](const auto& current, const auto& next) {
            return gf::Sub(
                gf::Sub(next[0], current[0]),
                gf::Fp3::One());
        }});
    cs.constraints.push_back({
        "double_counter", air_quotient::AirKind::kEverywhere, 1,
        [](const auto& current, const auto&) {
            return gf::Sub(
                current[1],
                gf::Mul(current[0], gf::Fp3::FromFp(2)));
        }});
    return cs;
}

std::vector<std::vector<gf::Fp3>> TransitionTrace()
{
    std::vector<std::vector<gf::Fp3>> out(
        2, std::vector<gf::Fp3>(256));
    for (uint32_t row = 0; row < 256; ++row) {
        out[0][row] = gf::Fp3::FromFp(row + 11);
        out[1][row] =
            gf::Mul(out[0][row], gf::Fp3::FromFp(2));
    }
    return out;
}

cb::Instruction Load(cb::Opcode opcode, uint32_t column)
{
    cb::Instruction out;
    out.opcode = opcode;
    out.lhs = column;
    return out;
}

cb::Instruction Constant(uint64_t value)
{
    cb::Instruction out;
    out.opcode = cb::Opcode::Constant;
    out.constant = gf::Fp3::FromFp(value);
    return out;
}

cb::Instruction Binary(
    cb::Opcode opcode, uint32_t lhs, uint32_t rhs)
{
    cb::Instruction out;
    out.opcode = opcode;
    out.lhs = lhs;
    out.rhs = rhs;
    return out;
}

cb::ProgramTable TransitionPrograms()
{
    cb::Program step;
    step.role = RCStage3RelationRole::EpisodeGemm;
    step.constraint_ordinal = 0;
    step.kind = air_quotient::AirKind::kTransition;
    step.declared_degree = 1;
    step.current_width = 2;
    step.next_width = 2;
    step.instructions = {
        Load(cb::Opcode::Next, 0),
        Load(cb::Opcode::Current, 0),
        Binary(cb::Opcode::Sub, 0, 1),
        Constant(1),
        Binary(cb::Opcode::Sub, 2, 3),
    };

    cb::Program twice;
    twice.role = RCStage3RelationRole::EpisodeGemm;
    twice.constraint_ordinal = 1;
    twice.kind = air_quotient::AirKind::kEverywhere;
    twice.declared_degree = 1;
    twice.current_width = 2;
    twice.next_width = 2;
    twice.instructions = {
        Load(cb::Opcode::Current, 1),
        Load(cb::Opcode::Current, 0),
        Constant(2),
        Binary(cb::Opcode::Mul, 1, 2),
        Binary(cb::Opcode::Sub, 0, 3),
    };

    cb::ProgramTable out;
    out.role = RCStage3RelationRole::EpisodeGemm;
    out.current_width = 2;
    out.next_width = 2;
    out.programs = {step, twice};
    return out;
}

tp::StatementV1 StatementFromProof(
    const backend::ProofV1& proof)
{
    tp::StatementV1 out;
    const auto& envelope = proof.envelope;
    const auto& split = envelope.split;
    const auto& batch = split.batch;
    for (uint32_t word = 0;
         word < envelope.public_fs_seed.size(); ++word) {
        for (uint32_t byte = 0; byte < 4; ++byte) {
            out.public_fs_seed.data()[4 * word + byte] =
                static_cast<unsigned char>(
                    envelope.public_fs_seed[word] >>
                    (8 * byte));
        }
    }
    out.pow_grind_nonce = batch.pow_grind_nonce;
    out.trace_rows = split.trace_rows;
    out.trace_columns = envelope.trace_columns;
    out.quotient_len = envelope.quotient_len;
    out.n_coeffs = batch.n_coeffs;
    out.blowup = batch.blowup;
    out.base_column_indices = split.base_column_indices;
    for (uint32_t group = 0; group < out.groups.size(); ++group) {
        out.groups[group] = {
            batch.groups[group].role,
            batch.groups[group].first_column,
            batch.groups[group].column_count,
            batch.groups[group].row_commit.n_leaves,
            batch.groups[group].row_commit.root};
    }
    out.column_len = batch.column_len;
    out.evals_z1 = batch.evals_z1;
    out.evals_z2 = batch.evals_z2;
    for (const auto& fold : batch.fold_layers) {
        out.folds.push_back({fold.n_leaves, fold.root});
    }
    out.final_value = batch.final_value;
    return out;
}

InputV1 ActualInput()
{
    InputV1 out;
    const auto cs = TransitionAir();
    const auto proved = backend::ProveAirQuotientV1(
        cs, TransitionTrace(), {0}, H(100));
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    out.proof = proved.proximity.proof;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        backend::VerifyV1(out.proof, &out.transcript, &why),
        why);
    out.child_program = TransitionPrograms();
    BOOST_REQUIRE_MESSAGE(
        cb::ValidateProgramTable(out.child_program, &why), why);
    out.expected_child_program_root =
        cb::CommitProgramTableAlgHash(out.child_program);
    out.expected_child_statement_root = H(101);

    std::vector<uint32_t> words;
    BOOST_REQUIRE_MESSAGE(
        abi::EncodeCanonicalV1(
            out.proof.envelope, words, nullptr, &why),
        why);
    const auto decoded = abi::DecodeCanonicalV1(words, &why);
    BOOST_REQUIRE_MESSAGE(decoded.has_value(), why);
    const auto replay =
        tp::BuildProductV1(StatementFromProof(out.proof));
    BOOST_REQUIRE_MESSAGE(replay.valid, replay.note);
    const auto consumer =
        stage3_multirow_p2_consumer_bridge::BuildProductV1(
            replay);
    BOOST_REQUIRE_MESSAGE(consumer.valid, consumer.note);
    uint32_t parent_column = 100;
    for (const auto& source : decoded->sources) {
        if (source.ownership ==
            abi::OwnershipClassV1::PublicStatement) {
            out.parent_public.push_back({
                source.key, parent_column++, source.value});
        }
    }
    out.parent_join = pj::BuildProductV1(
        *decoded, out.parent_public, replay, consumer);
    BOOST_REQUIRE_MESSAGE(
        out.parent_join.valid, out.parent_join.note);
    return out;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_multirow_v11_recursive_verifier_tests)

BOOST_AUTO_TEST_CASE(
    canonical_q64_partition_is_exact_disjoint_and_complete)
{
    constexpr auto ranges = CanonicalQueryRangesV1();
    uint32_t next = 0;
    uint32_t total = 0;
    for (uint32_t i = 0; i < ranges.size(); ++i) {
        BOOST_CHECK_EQUAL(ranges[i].ordinal, i);
        BOOST_CHECK_EQUAL(ranges[i].first_query, next);
        BOOST_CHECK_EQUAL(
            ranges[i].query_count, kQueriesPerShardV1);
        next += ranges[i].query_count;
        total += ranges[i].query_count;
    }
    BOOST_CHECK_EQUAL(total, abi::kQueryCountV11);

    // Omission, overlap and reordering attacks cannot equal the canonical
    // schedule.
    auto omitted = ranges;
    --omitted[2].query_count;
    BOOST_CHECK(omitted != ranges);
    auto overlapped = ranges;
    --overlapped[1].first_query;
    BOOST_CHECK(overlapped != ranges);
    auto reordered = ranges;
    std::swap(reordered[0], reordered[1]);
    BOOST_CHECK(reordered != ranges);
}

BOOST_AUTO_TEST_CASE(
    direct_parent_vm_trace_audit_fails_closed_without_quotient_degree)
{
    // Measured published parent-join shape. Five instructions/constraint is
    // deliberately optimistic: if even this lower estimate fails, the wide
    // direct route cannot be rescued by interpreter tuning.  This overload
    // has no CS, so it may not certify the Q64 LDE.
    const auto audit =
        AuditDirectAndQ64RowsV1(1298, 1276, 5);
    BOOST_CHECK(!audit.valid);
    BOOST_CHECK_EQUAL(
        audit.direct_q192_vm_rows, 1474560U);
    BOOST_CHECK_EQUAL(audit.q64_vm_rows, 491520U);
    BOOST_CHECK_EQUAL(audit.q64_trace_rows, 524288U);
    BOOST_CHECK_EQUAL(audit.q64_lde_rows, 0U);
    BOOST_CHECK(audit.direct_exceeds_trace_cap);
    BOOST_CHECK(audit.q64_fits_trace_cap);
    BOOST_CHECK(!audit.q64_fits_lde_cap);
    BOOST_CHECK_EQUAL(
        audit.note,
        "stage3:v11_recursive_verifier:cap:"
        "trace_only_quotient_degree_required");
}

BOOST_AUTO_TEST_CASE(cap_audit_fails_closed_on_invalid_or_overflow_shape)
{
    BOOST_CHECK(!AuditDirectAndQ64RowsV1(0, 1276, 5).valid);
    BOOST_CHECK(!AuditDirectAndQ64RowsV1(1298, 0, 5).valid);
    BOOST_CHECK(!AuditDirectAndQ64RowsV1(1298, 1276, 0).valid);
    const auto too_large =
        AuditDirectAndQ64RowsV1(
            UINT32_MAX, UINT32_MAX, UINT32_MAX);
    BOOST_CHECK(!too_large.valid);
}

BOOST_AUTO_TEST_CASE(
    receipt_root_binds_range_child_program_and_every_chip_root)
{
    ShardReceiptV1 honest;
    honest.range = CanonicalQueryRangesV1()[0];
    honest.child_abi_root = uint256::ONE;
    honest.child_wire_root = H(2);
    honest.child_statement_root = H(17);
    honest.full_q192_transcript_root = H(18);
    honest.public_fs_seed = H(3);
    honest.program_root = {
        gf::FromU64(4), gf::FromU64(5),
        gf::FromU64(6), gf::FromU64(7)};
    honest.parent_join_r0_root = H(8);
    honest.merkle_hash_r0_root = H(9);
    honest.merkle_fold_r0_root = H(10);
    honest.deep_vm_r0_root = H(11);
    honest.decoder_join_r0_root = H(12);
    honest.merkle_hash_rows = 1U << 14;
    honest.merkle_hash_columns = 500;
    honest.merkle_fold_rows = 1U << 11;
    honest.merkle_fold_columns = 16;
    honest.deep_vm_rows = 1U << 19;
    honest.deep_vm_columns = 48;
    honest.decoder_join_rows = 1U << 15;
    honest.decoder_join_columns = 19;
    honest.materialized_trace_cells =
        uint64_t{honest.merkle_hash_rows} *
            honest.merkle_hash_columns +
        uint64_t{honest.merkle_fold_rows} *
            honest.merkle_fold_columns +
        uint64_t{honest.deep_vm_rows} *
            honest.deep_vm_columns +
        uint64_t{honest.decoder_join_rows} *
            honest.decoder_join_columns;
    honest.receipt_root = ComputeShardReceiptRootV1(honest);
    BOOST_REQUIRE(!honest.receipt_root.IsNull());
    BOOST_REQUIRE(
        Fri3AlgDigestFromUint256(
            honest.receipt_root).has_value());

    auto attack = honest;
    attack.range.first_query ^= 1U;
    BOOST_CHECK(Different(
        ComputeShardReceiptRootV1(attack),
        honest.receipt_root));
    attack = honest;
    attack.child_abi_root = H(13);
    BOOST_CHECK(Different(
        ComputeShardReceiptRootV1(attack),
        honest.receipt_root));
    attack = honest;
    attack.child_statement_root = H(19);
    BOOST_CHECK(Different(
        ComputeShardReceiptRootV1(attack),
        honest.receipt_root));
    attack = honest;
    attack.full_q192_transcript_root = H(20);
    BOOST_CHECK(Different(
        ComputeShardReceiptRootV1(attack),
        honest.receipt_root));
    attack = honest;
    attack.program_root[0] ^= 1U;
    BOOST_CHECK(Different(
        ComputeShardReceiptRootV1(attack),
        honest.receipt_root));
    attack = honest;
    attack.merkle_hash_r0_root = H(14);
    BOOST_CHECK(Different(
        ComputeShardReceiptRootV1(attack),
        honest.receipt_root));
    attack = honest;
    attack.deep_vm_r0_root = H(15);
    BOOST_CHECK(Different(
        ComputeShardReceiptRootV1(attack),
        honest.receipt_root));
    attack = honest;
    attack.decoder_join_r0_root = H(16);
    BOOST_CHECK(Different(
        ComputeShardReceiptRootV1(attack),
        honest.receipt_root));
    // Regression for the Goldilocks x / x+p alias: arbitrary u64 fields are
    // committed as two u32 limbs, so adding p cannot preserve the root.
    attack = honest;
    attack.materialized_trace_cells += gf::kP;
    BOOST_CHECK(Different(
        ComputeShardReceiptRootV1(attack),
        honest.receipt_root));
}

BOOST_AUTO_TEST_CASE(
    actual_backend_child_one_query_materializes_and_substitutions_reject)
{
    const auto input = ActualInput();
    const QueryRangeV1 one{0, 0, 1};
    const auto product =
        BuildSingleShardAuditV1(input, one);
    BOOST_REQUIRE_MESSAGE(product.valid, product.note);
    BOOST_CHECK(product.exact_query_range);
    BOOST_CHECK(product.merkle_and_fold_air_executable);
    BOOST_CHECK(product.deep_quotient_vm_air_executable);
    BOOST_CHECK(product.proof_owned_roots_recomputed);
    BOOST_CHECK(!product.recursive_receipt_verified_in_air);
    BOOST_CHECK_EQUAL(product.receipt.range.query_count, 1U);
    BOOST_CHECK_GT(product.receipt.merkle_hash_rows, 0U);
    BOOST_CHECK_EQUAL(product.receipt.merkle_hash_columns, 500U);
    BOOST_CHECK_GT(product.receipt.deep_vm_rows, 0U);
    BOOST_CHECK_GT(product.receipt.materialized_trace_cells, 0U);
    BOOST_CHECK_EQUAL(
        product.receipt.measured_unaggregated_wire_bytes, 0U);
    BOOST_CHECK(
        Fri3AlgDigestFromUint256(
            product.receipt.child_abi_root).has_value());
    BOOST_CHECK(
        Fri3AlgDigestFromUint256(
            product.receipt.child_wire_root).has_value());
    BOOST_CHECK(
        Fri3AlgDigestFromUint256(
            product.receipt.full_q192_transcript_root).has_value());
    BOOST_CHECK(
        Fri3AlgDigestFromUint256(
            product.receipt.receipt_root).has_value());
    BOOST_TEST_MESSAGE(
        "V11_RECURSIVE_SHARD q=1 hash="
        << product.receipt.merkle_hash_rows << "x"
        << product.receipt.merkle_hash_columns
        << " fold=" << product.receipt.merkle_fold_rows
        << "x" << product.receipt.merkle_fold_columns
        << " deep=" << product.receipt.deep_vm_rows
        << "x" << product.receipt.deep_vm_columns
        << " decoder=" << product.receipt.decoder_join_rows
        << "x" << product.receipt.decoder_join_columns
        << " cells=" << product.receipt.materialized_trace_cells);

    auto proof_cell = input;
    proof_cell.proof.envelope.split.batch.queries[0]
        .group_rows[0].values[0].c0 ^= 1U;
    BOOST_CHECK(!BuildSingleShardAuditV1(
        proof_cell, one).valid);

    auto program_root = input;
    program_root.expected_child_program_root[0] ^= 1U;
    BOOST_CHECK(!BuildSingleShardAuditV1(
        program_root, one).valid);

    auto omitted = one;
    omitted.query_count = 0;
    BOOST_CHECK(!BuildSingleShardAuditV1(
        input, omitted).valid);

    auto out_of_range = one;
    out_of_range.first_query = abi::kQueryCountV11;
    BOOST_CHECK(!BuildSingleShardAuditV1(
        input, out_of_range).valid);
}

BOOST_AUTO_TEST_CASE(
    shard_set_alg_hash_binds_all_receipts_and_order)
{
    std::array<ShardReceiptV1, kQueryShardsV1> receipts{};
    for (uint32_t shard = 0; shard < receipts.size(); ++shard) {
        receipts[shard].range = CanonicalQueryRangesV1()[shard];
        receipts[shard].receipt_root = H(500 + shard);
    }
    const uint256 honest = ComputeShardSetRootV1(receipts);
    BOOST_REQUIRE(!honest.IsNull());
    BOOST_REQUIRE(
        Fri3AlgDigestFromUint256(honest).has_value());

    auto substituted = receipts;
    substituted[1].receipt_root = H(600);
    BOOST_CHECK(Different(
        ComputeShardSetRootV1(substituted), honest));

    auto reordered = receipts;
    std::swap(
        reordered[0].receipt_root,
        reordered[1].receipt_root);
    BOOST_CHECK(Different(
        ComputeShardSetRootV1(reordered), honest));
}

BOOST_AUTO_TEST_CASE(readiness_is_exact_and_fail_closed)
{
    constexpr auto readiness = CurrentReadinessV1();
    BOOST_CHECK(readiness.exact_q192_query_partition_executable);
    BOOST_CHECK(readiness.bounded_q64_merkle_fold_air_executable);
    BOOST_CHECK(readiness.bounded_q64_deep_vm_air_executable);
    BOOST_CHECK(readiness.decoder_ownership_join_executable);
    BOOST_CHECK(!readiness.same_parent_r0_alias_executable);
    BOOST_CHECK(!readiness.recursive_receipt_verifier_executable);
    BOOST_CHECK(!readiness.canonical_verifier_program_executable);
    BOOST_CHECK(!readiness.binary_receipt_tree_executable);
    BOOST_CHECK(!readiness.recursive_authority_ready);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace matmul::v4::rc::stage3_multirow_v11_recursive_verifier
