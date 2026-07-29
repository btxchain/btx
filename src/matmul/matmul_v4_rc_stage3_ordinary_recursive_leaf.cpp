// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_ordinary_recursive_leaf.h>
#include <matmul/matmul_v4_rc_stage3_air_quotient_codec.h>

#include <hash.h>

#include <algorithm>
#include <limits>
#include <utility>

namespace matmul::v4::rc::stage3_ordinary_recursive_leaf {
namespace {

using AirCS = aq::AirConstraintSystem<gf::Fp3>;
using Fp3 = gf::Fp3;
namespace hierarchy = recursive_hierarchy;
namespace narrow = narrow_recurse;

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why =
            "stage3:ordinary_recursive_leaf:" +
            detail;
    }
    return false;
}

uint256 CommitProofBytes(
    const std::vector<unsigned char>& proof_bytes)
{
    if (proof_bytes.empty()) return {};
    HashWriter hash;
    // This exact domain is frozen by
    // ValidateNarrowRecursiveProofReceiptV1.
    hash <<
        "BTX_RC_STAGE3_MULTI_CHILD_L2_PARENT_PROOF_V1";
    hash << static_cast<uint64_t>(
        proof_bytes.size());
    hash << proof_bytes;
    return hash.GetHash();
}

uint32_t ProofLdeSize(const AirCS& cs)
{
    if (cs.n_rows < 2 ||
        cs.n_columns == 0 ||
        cs.constraints.empty()) {
        return 0;
    }
    const uint32_t coefficient_floor =
        std::max(cs.n_rows, cs.QuotientLen());
    if (coefficient_floor == 0) return 0;
    const uint32_t n_coeffs =
        FriNextPow2(coefficient_floor);
    if (n_coeffs == 0 ||
        n_coeffs >
            std::numeric_limits<uint32_t>::max() /
                kRCFriBlowup) {
        return 0;
    }
    return n_coeffs * kRCFriBlowup;
}

bool RejectProofTamper(
    const AirCS& cs,
    const fixedpoint::AlgAirProof& proof,
    const uint256& fs_seed)
{
    auto tampered = proof;
    if (!tampered.batch.queries.empty() &&
        !tampered.batch.queries[0]
             .row.values.empty()) {
        auto& value =
            tampered.batch.queries[0]
                .row.values[0];
        value = gf::Add(value, Fp3::One());
    } else if (
        !tampered.batch.queries.empty() &&
        !tampered.batch.queries[0]
             .steps.empty()) {
        auto& value =
            tampered.batch.queries[0]
                .steps[0].even;
        value = gf::Add(value, Fp3::One());
    } else {
        return false;
    }
    std::string why;
    return !aq::AirQuotientVerify<
        Fp3, aq::AirFriBackendAlg<Fp3>>(
            cs, tampered, fs_seed, &why);
}

} // namespace

uint256 CommitPublicBindingV1(
    const PublicBindingV1& binding,
    const uint256& constraint_system_commitment)
{
    if (binding.version != kVersionV1 ||
        binding.node_binding.IsNull() ||
        binding.program_binding.IsNull() ||
        binding.proof_context_binding.IsNull() ||
        binding.public_statement_binding.IsNull() ||
        binding.fs_seed.IsNull() ||
        constraint_system_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_ORDINARY_RECURSIVE_LEAF_STATEMENT_V1";
    hash << binding.version;
    hash << binding.node_binding;
    hash << binding.program_binding;
    hash << binding.proof_context_binding;
    hash << binding.public_statement_binding;
    hash << binding.fs_seed;
    hash << constraint_system_commitment;
    return hash.GetHash();
}

fixedpoint::NarrowRecursiveProofExpectedBindingV2
BuildExpectedRecursiveBindingV2(
    const AirCS& expected_cs,
    const PublicBindingV1& expected_binding)
{
    fixedpoint::NarrowRecursiveProofExpectedBindingV2 out;
    const uint256 cs_commitment =
        hierarchy::
            ComputeHierarchyConstraintSystemCommitmentV1(
                expected_cs);
    out.node_binding =
        expected_binding.node_binding;
    out.program_binding =
        expected_binding.program_binding;
    out.proof_context_binding =
        expected_binding.proof_context_binding;
    out.statement_commitment =
        CommitPublicBindingV1(
            expected_binding, cs_commitment);
    out.fs_seed = expected_binding.fs_seed;
    out.active_rows = expected_cs.n_rows;
    out.n_lde = ProofLdeSize(expected_cs);

    // The receipt carries the exact AIR row count as its recursive schedule
    // charge.  Never search for a smaller schedule class that happens to
    // produce the same power-of-two FRI domain.
    const auto shape =
        narrow::AssessNarrowNodeFriShape(
            out.active_rows);
    // `shape.n_lde` is the degree-two normalized-parent estimate.  Ordinary
    // children may have a larger algebraic degree, so their authenticated
    // domain is ProofLdeSize(expected_cs), not that estimate.  Enforce the
    // same hard cap without rewriting the child's proof statement.
    const bool proof_domain_representable =
        uint64_t{out.n_lde} >=
            uint64_t{kRCFriBlowup} *
                expected_cs.n_rows &&
        (out.n_lde & (out.n_lde - 1U)) == 0 &&
        shape.lde_log2_cap < 32 &&
        uint64_t{out.n_lde} <=
            (uint64_t{1} << shape.lde_log2_cap);
    if (cs_commitment.IsNull() ||
        out.statement_commitment.IsNull() ||
        !shape.representable ||
        shape.trace_rows != expected_cs.n_rows ||
        !proof_domain_representable) {
        return {};
    }
    return out;
}

ProofV1 RetainProofV1(
    const AirCS& expected_cs,
    const aq::AirQuotientRowsProof&
        streaming_proof,
    const PublicBindingV1& binding)
{
    ProofV1 out;
    out.binding = binding;
    const uint256 cs_commitment =
        hierarchy::
            ComputeHierarchyConstraintSystemCommitmentV1(
                expected_cs);
    const uint256 statement_commitment =
        CommitPublicBindingV1(
            binding, cs_commitment);
    const auto expected =
        BuildExpectedRecursiveBindingV2(
            expected_cs, binding);
    const uint32_t n_lde = expected.n_lde;
    const uint64_t active_rows =
        expected.active_rows;
    if (cs_commitment.IsNull() ||
        statement_commitment.IsNull() ||
        expected.statement_commitment !=
            statement_commitment ||
        n_lde == 0 ||
        active_rows == 0) {
        out.note =
            "stage3:ordinary_recursive_leaf:"
            "invalid_public_input";
        return out;
    }

    std::string why;
    out.native_streaming_proof_verified =
        aq::AirQuotientVerifyRows(
            expected_cs, streaming_proof,
            binding.fs_seed, &why);
    if (!out.native_streaming_proof_verified) {
        out.note =
            "stage3:ordinary_recursive_leaf:"
            "native_verify:" + why;
        return out;
    }

    fixedpoint::AlgAirProof ordinary;
    ordinary.batch = streaming_proof.batch;
    ordinary.trace_commit =
        streaming_proof.trace_commit;
    ordinary.next_openings =
        streaming_proof.next_openings;
    std::vector<unsigned char> proof_bytes;
    if (!SerializeAirQuotientProofAlg(
            ordinary, proof_bytes, &why) ||
        proof_bytes.empty()) {
        out.note =
            "stage3:ordinary_recursive_leaf:"
            "serialize:" + why;
        return out;
    }
    const auto decoded =
        DeserializeAirQuotientProofAlg(
            proof_bytes, &why);
    std::vector<unsigned char> canonical;
    out.ordinary_reentry_verified =
        decoded.has_value() &&
        SerializeAirQuotientProofAlg(
            *decoded, canonical, &why) &&
        canonical == proof_bytes &&
        aq::AirQuotientVerify<
            Fp3, aq::AirFriBackendAlg<Fp3>>(
                expected_cs, *decoded,
                binding.fs_seed, &why);
    if (!out.ordinary_reentry_verified) {
        out.note =
            "stage3:ordinary_recursive_leaf:"
            "ordinary_reentry:" + why;
        return out;
    }

    auto& receipt = out.receipt;
    receipt.node_binding =
        binding.node_binding;
    receipt.program_binding =
        binding.program_binding;
    receipt.proof_context_binding =
        binding.proof_context_binding;
    receipt.n_rows = expected_cs.n_rows;
    receipt.n_columns =
        expected_cs.n_columns;
    receipt.n_constraints =
        static_cast<uint32_t>(
            expected_cs.constraints.size());
    receipt.active_rows = active_rows;
    receipt.n_lde = n_lde;
    receipt.constraint_system_commitment =
        cs_commitment;
    receipt.fs_seed = binding.fs_seed;
    receipt.proof_commitment =
        CommitProofBytes(proof_bytes);
    receipt.statement_commitment =
        statement_commitment;
    receipt.constraint_system =
        expected_cs;
    receipt.proof = *decoded;
    receipt.proof_bytes =
        std::move(proof_bytes);
    receipt.serialize_within_fri_budget =
        receipt.proof_bytes.size() <=
            kRCFriMaxProofBytesHard;
    receipt.receipt_commitment =
        fixedpoint::
            CommitNarrowRecursiveProofReceiptV1(
                receipt);
    receipt.valid =
        !receipt.receipt_commitment.IsNull() &&
        fixedpoint::
            ValidateNarrowRecursiveProofReceiptV2(
                receipt, expected_cs,
                expected, &why);
    receipt.note = receipt.valid
        ? "stage3:ordinary_recursive_leaf:"
          "receipt_valid"
        : "stage3:ordinary_recursive_leaf:"
          "receipt_invalid:" + why;
    out.proof_tamper_rejected =
        receipt.valid &&
        RejectProofTamper(
            expected_cs, receipt.proof,
            binding.fs_seed);
    out.valid =
        receipt.valid &&
        out.proof_tamper_rejected;
    if (out.valid) {
        out.note =
            "stage3:ordinary_recursive_leaf:valid";
    } else if (!receipt.valid) {
        out.note =
            "stage3:ordinary_recursive_leaf:"
            "invalid_receipt:" + receipt.note;
    } else {
        out.note =
            "stage3:ordinary_recursive_leaf:"
            "proof_tamper_canary_failed";
    }
    return out;
}

ProofV1 ProveV1(
    const AirCS& expected_cs,
    const std::vector<std::vector<Fp3>>&
        columns,
    const PublicBindingV1& binding)
{
    ProofV1 out;
    if (columns.size() !=
            expected_cs.n_columns) {
        out.note =
            "stage3:ordinary_recursive_leaf:"
            "column_count";
        return out;
    }
    for (const auto& column : columns) {
        if (column.size() !=
            expected_cs.n_rows) {
            out.note =
                "stage3:ordinary_recursive_leaf:"
                "column_length";
            return out;
        }
    }
    const auto proved =
        aq::AirQuotientProveRows(
            expected_cs, columns,
            binding.fs_seed, {});
    if (!proved.ok || !proved.division_exact) {
        out.note =
            "stage3:ordinary_recursive_leaf:"
            "prove:" + proved.note;
        return out;
    }
    return RetainProofV1(
        expected_cs, proved.proof, binding);
}

bool VerifyV1(
    const ProofV1& proof,
    const AirCS& expected_cs,
    const PublicBindingV1& expected_binding,
    std::string* why)
{
    const uint256 cs_commitment =
        hierarchy::
            ComputeHierarchyConstraintSystemCommitmentV1(
                expected_cs);
    const auto expected_recursive =
        BuildExpectedRecursiveBindingV2(
            expected_cs, expected_binding);
    if (proof.binding != expected_binding ||
        proof.receipt.proof_context_binding !=
            expected_binding
                .proof_context_binding ||
        proof.receipt.fs_seed !=
            expected_binding.fs_seed ||
        proof.receipt.statement_commitment !=
            CommitPublicBindingV1(
                expected_binding,
                cs_commitment)) {
        return Fail(why, "public_binding");
    }
    std::string receipt_why;
    if (!fixedpoint::
            ValidateNarrowRecursiveProofReceiptV2(
                proof.receipt, expected_cs,
                expected_recursive, &receipt_why)) {
        return Fail(
            why, "receipt:" + receipt_why);
    }
    if (!RejectProofTamper(
            expected_cs, proof.receipt.proof,
            expected_binding.fs_seed)) {
        return Fail(
            why, "proof_tamper_not_rejected");
    }
    if (why != nullptr) {
        *why =
            "stage3:ordinary_recursive_leaf:"
            "verified";
    }
    return true;
}

PublicBindingV1 BuildTapeShardPublicBindingV1(
    const tape::ShardStatementV2& statement,
    const std::array<Fp3, 2>& source_terminal)
{
    PublicBindingV1 out;
    out.program_binding =
        statement.binding.program_root;
    out.fs_seed =
        tape::DeriveShardPublicFsSeedV3(
            statement, source_terminal);
    if (out.program_binding.IsNull() ||
        out.fs_seed.IsNull() ||
        statement.binding.statement_root.IsNull() ||
        statement.binding.proof_wire_root.IsNull() ||
        statement.source_inventory_root.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_V13_TAPE_SHARD_RECURSIVE_STATEMENT_V1";
    hash << statement.plan.shard_index;
    hash << statement.plan.shard_count;
    hash << statement.plan.row_begin;
    hash << statement.plan.trace_rows;
    hash << statement.plan.record_begin;
    hash << statement.plan.record_count;
    hash << statement.plan.active_records;
    hash << statement.plan.total_trace_rows;
    hash << statement.plan.total_records;
    hash << statement.plan.total_active_records;
    hash << statement.binding.program_root;
    hash << statement.binding.statement_root;
    hash << statement.binding.proof_wire_root;
    hash << statement.source_inventory_root;
    for (const auto lane :
         statement.binding.tape_root) {
        hash << static_cast<uint64_t>(lane);
    }
    for (const auto lane :
         statement.start_state) {
        hash << static_cast<uint64_t>(lane);
    }
    for (const auto lane :
         statement.end_state) {
        hash << static_cast<uint64_t>(lane);
    }
    for (const Fp3& terminal :
         source_terminal) {
        hash << static_cast<uint64_t>(
            terminal.c0);
        hash << static_cast<uint64_t>(
            terminal.c1);
        hash << static_cast<uint64_t>(
            terminal.c2);
    }
    hash << out.fs_seed;
    out.public_statement_binding =
        hash.GetHash();
    if (out.public_statement_binding.IsNull()) {
        return {};
    }
    // The canonical recursive position is the complete shard statement.
    out.node_binding =
        out.public_statement_binding;
    HashWriter context;
    context <<
        "BTX_RC_STAGE3_V13_TAPE_SHARD_RECURSIVE_CONTEXT_V1";
    context << statement.binding.proof_wire_root;
    context << statement.plan.shard_index;
    context << out.public_statement_binding;
    context << out.fs_seed;
    out.proof_context_binding =
        context.GetHash();
    if (out.proof_context_binding.IsNull()) {
        return {};
    }
    return out;
}

TapeShardReceiptV1 RetainTapeShardProofV1(
    const tape::ShardStatementV2& statement,
    const tape::ShardProofV3& proof)
{
    TapeShardReceiptV1 out;
    out.shard_index = proof.shard_index;
    out.source_terminal =
        proof.source_terminal;
    std::string why;
    out.native_tape_verifier_accepted =
        tape::VerifyShardPublicV3(
            statement, proof, &why);
    if (!out.native_tape_verifier_accepted) {
        out.note =
            "stage3:ordinary_recursive_leaf:"
            "tape_native_verify:" + why;
        return out;
    }
    AirCS cs;
    if (!tape::
            BuildShardFinalConstraintSystemV3(
                statement,
                proof.source_terminal,
                cs, nullptr, &why)) {
        out.note =
            "stage3:ordinary_recursive_leaf:"
            "tape_final_cs:" + why;
        return out;
    }
    const PublicBindingV1 binding =
        BuildTapeShardPublicBindingV1(
            statement, proof.source_terminal);
    out.ordinary =
        RetainProofV1(
            cs, proof.proof, binding);
    if (!out.ordinary.valid) {
        out.note =
            "stage3:ordinary_recursive_leaf:"
            "tape_ordinary:" +
            out.ordinary.note;
        return out;
    }

    std::vector<unsigned char> tape_bytes;
    const auto canonical =
        tape::CanonicalShardPublicAlgProofV3(
            proof, &tape_bytes, &why);
    out.canonical_payload_equal =
        canonical.has_value() &&
        tape_bytes ==
            out.ordinary.receipt.proof_bytes;
    out.valid =
        out.native_tape_verifier_accepted &&
        out.canonical_payload_equal &&
        out.ordinary.valid;
    out.note = out.valid
        ? "stage3:ordinary_recursive_leaf:"
          "tape_receipt_valid"
        : "stage3:ordinary_recursive_leaf:"
          "tape_receipt_payload_mismatch";
    return out;
}

bool VerifyTapeShardReceiptV1(
    const TapeShardReceiptV1& receipt,
    const tape::ShardStatementV2&
        expected_statement,
    std::string* why)
{
    if (receipt.version != kVersionV1 ||
        receipt.shard_index !=
            expected_statement
                .plan.shard_index) {
        return Fail(why, "tape_envelope");
    }
    tape::ShardProofV3 tape_proof;
    tape_proof.shard_index =
        receipt.shard_index;
    tape_proof.source_terminal =
        receipt.source_terminal;
    tape_proof.proof.batch =
        receipt.ordinary.receipt.proof.batch;
    tape_proof.proof.trace_commit =
        receipt.ordinary.receipt
            .proof.trace_commit;
    tape_proof.proof.next_openings =
        receipt.ordinary.receipt
            .proof.next_openings;
    std::string tape_why;
    if (!tape::VerifyShardPublicV3(
            expected_statement, tape_proof,
            &tape_why)) {
        return Fail(
            why, "tape_native_verify:" +
                     tape_why);
    }
    AirCS expected_cs;
    if (!tape::
            BuildShardFinalConstraintSystemV3(
                expected_statement,
                receipt.source_terminal,
                expected_cs, nullptr,
                &tape_why)) {
        return Fail(
            why, "tape_final_cs:" +
                     tape_why);
    }
    const PublicBindingV1 expected_binding =
        BuildTapeShardPublicBindingV1(
            expected_statement,
            receipt.source_terminal);
    if (!VerifyV1(
            receipt.ordinary, expected_cs,
            expected_binding, &tape_why)) {
        return Fail(
            why, "tape_ordinary:" +
                     tape_why);
    }
    std::vector<unsigned char> canonical;
    if (!tape::
            CanonicalShardPublicAlgProofV3(
                tape_proof, &canonical,
                &tape_why)
             .has_value() ||
        canonical !=
            receipt.ordinary
                .receipt.proof_bytes) {
        return Fail(
            why, "tape_payload_mismatch");
    }
    if (why != nullptr) {
        *why =
            "stage3:ordinary_recursive_leaf:"
            "tape_receipt_verified";
    }
    return true;
}

} // namespace matmul::v4::rc::stage3_ordinary_recursive_leaf
