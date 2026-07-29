// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_receipt_public_statement.h>

#include <hash.h>

#include <algorithm>
#include <utility>

namespace matmul::v4::rc::receipt_public_statement {
namespace {

constexpr char kTupleDomain[] =
    "BTX_RC_STAGE3_RECEIPT_PUBLIC_STATEMENT_TUPLE_V1";
constexpr char kSeedDomain[] =
    "BTX_RC_STAGE3_RECEIPT_PUBLIC_STATEMENT_FS_V1";

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:receipt_public_statement:" + detail;
    }
    return false;
}

RootU32CellsV1 RootCells(const uint256& root)
{
    RootU32CellsV1 out;
    for (uint32_t limb = 0; limb < out.limb.size(); ++limb) {
        const uint32_t offset = 4U * limb;
        out.limb[limb] =
            static_cast<uint32_t>(root.begin()[offset]) |
            (static_cast<uint32_t>(root.begin()[offset + 1]) << 8) |
            (static_cast<uint32_t>(root.begin()[offset + 2]) << 16) |
            (static_cast<uint32_t>(root.begin()[offset + 3]) << 24);
    }
    return out;
}

fp::AlgAirProof ToCanonicalAlgProof(aq::AirQuotientRowsProof proof)
{
    fp::AlgAirProof out;
    out.batch = std::move(proof.batch);
    out.next_openings = std::move(proof.next_openings);
    out.trace_commit = proof.trace_commit;
    return out;
}

bool FillVerifiedCells(
    const ReceiptPublicStatementTupleV1& statement,
    const uint256& tuple_commitment,
    const uint256& bound_fs_seed,
    VerifiedReceiptPublicCellsV1& out)
{
    if (!ValidateReceiptPublicStatementTupleV1(statement, nullptr) ||
        tuple_commitment.IsNull() ||
        bound_fs_seed.IsNull()) {
        return false;
    }
    out = {};
    out.child_slot = statement.child_slot;
    out.program_root = RootCells(statement.program_root);
    out.exact_set_manifest_root =
        RootCells(statement.exact_set_manifest_root);
    out.source_identity = RootCells(statement.source_identity);
    out.statement_root = RootCells(statement.statement_root);
    out.tuple_commitment = RootCells(tuple_commitment);
    out.bound_fs_seed = RootCells(bound_fs_seed);
    out.tuple_canonical = true;
    out.child_proof_verified = true;
    out.fs_seed_recomputed_by_verifier = true;
    out.cells_exported_after_verification = true;
    out.same_parent_verifier_consumed = false;
    out.recursive_authority = false;
    out.note =
        "stage3:receipt_public_statement:"
        "local_verifier_owned_cells;"
        "same_parent_transcript_join_open";
    return true;
}

bool SameStatement(
    const ReceiptPublicStatementTupleV1& lhs,
    const ReceiptPublicStatementTupleV1& rhs)
{
    return lhs == rhs;
}

} // namespace

bool ValidateReceiptPublicStatementTupleV1(
    const ReceiptPublicStatementTupleV1& statement,
    std::string* why)
{
    if (statement.version != kReceiptPublicStatementVersionV1) {
        return Fail(why, "version");
    }
    if (statement.child_slot >=
        kReceiptPublicStatementMaxChildrenV1) {
        return Fail(why, "child_slot");
    }
    if (statement.program_root.IsNull() ||
        statement.exact_set_manifest_root.IsNull() ||
        statement.source_identity.IsNull() ||
        statement.statement_root.IsNull()) {
        return Fail(why, "null_root");
    }
    return true;
}

bool BuildReceiptPublicStatementTupleFromV2(
    const rr2::ShardSourceTerminalBindingV2& binding,
    const uint256& exact_set_manifest_root,
    uint32_t child_slot,
    ReceiptPublicStatementTupleV1& out,
    std::string* why)
{
    out = {};
    if (!binding.valid ||
        binding.version != rr2::kShardReceiptVersionV2 ||
        binding.local.program_commitment.IsNull() ||
        binding.source_proof_commitment.IsNull() ||
        binding.statement_commitment.IsNull()) {
        return Fail(why, "v2_binding");
    }
    out.child_slot = child_slot;
    out.program_root = binding.local.program_commitment;
    out.exact_set_manifest_root = exact_set_manifest_root;
    out.source_identity = binding.source_proof_commitment;
    out.statement_root = binding.statement_commitment;
    return ValidateReceiptPublicStatementTupleV1(out, why);
}

uint256 CommitReceiptPublicStatementTupleV1(
    const ReceiptPublicStatementTupleV1& statement)
{
    if (!ValidateReceiptPublicStatementTupleV1(statement, nullptr)) return {};
    HashWriter hash;
    hash << kTupleDomain
         << statement.version
         << statement.child_slot
         << statement.program_root
         << statement.exact_set_manifest_root
         << statement.source_identity
         << statement.statement_root;
    return hash.GetHash();
}

uint256 ComputeStatementBoundReceiptFsSeedV1(
    const ReceiptPublicStatementTupleV1& statement,
    const uint256& base_v2_seed)
{
    const uint256 tuple_commitment =
        CommitReceiptPublicStatementTupleV1(statement);
    if (base_v2_seed.IsNull() || tuple_commitment.IsNull()) return {};
    HashWriter hash;
    hash << kSeedDomain
         << kReceiptPublicStatementVersionV1
         << base_v2_seed
         << tuple_commitment;
    return hash.GetHash();
}

StatementBoundChildProofV1
ProveStatementBoundChildRelationV1(
    const aq::AirConstraintSystem<gf::Fp3>& child_cs,
    const std::vector<std::vector<gf::Fp3>>& child_columns,
    const ReceiptPublicStatementTupleV1& statement,
    const uint256& base_v2_seed,
    const aq::AirProveOptions& options)
{
    StatementBoundChildProofV1 out;
    out.statement = statement;
    out.base_v2_seed = base_v2_seed;
    if (!ValidateReceiptPublicStatementTupleV1(statement, nullptr) ||
        base_v2_seed.IsNull()) {
        out.note =
            "stage3:receipt_public_statement:prove:statement";
        return out;
    }
    out.tuple_commitment =
        CommitReceiptPublicStatementTupleV1(statement);
    out.bound_fs_seed =
        ComputeStatementBoundReceiptFsSeedV1(
            statement, base_v2_seed);
    if (out.tuple_commitment.IsNull() ||
        out.bound_fs_seed.IsNull()) {
        out.note =
            "stage3:receipt_public_statement:prove:seed";
        return out;
    }
    // This call creates the first trace commitment.  Supplying the already
    // tuple-bound seed here is the load-bearing transcript-order property.
    auto proved = aq::AirQuotientProveRows(
        child_cs, child_columns, out.bound_fs_seed, options);
    out.relation_proved = proved.ok && proved.division_exact;
    if (!out.relation_proved) {
        out.note =
            "stage3:receipt_public_statement:prove:" +
            proved.note;
        return out;
    }
    std::string verify_why;
    out.relation_locally_verified =
        aq::AirQuotientVerifyRows(
            child_cs, proved.proof,
            out.bound_fs_seed, &verify_why);
    if (!out.relation_locally_verified) {
        out.note =
            "stage3:receipt_public_statement:prove_verify:" +
            verify_why;
        return out;
    }
    out.proof = ToCanonicalAlgProof(std::move(proved.proof));
    out.proof_commitment =
        fp::ComputeNormalizedAlgAirProofCommitment(out.proof);
    out.canonical_alg_proof = !out.proof_commitment.IsNull();
    out.tuple_bound_before_first_commitment = true;
    out.same_parent_verifier_consumed = false;
    out.recursive_authority = false;
    out.valid =
        out.relation_proved &&
        out.relation_locally_verified &&
        out.tuple_bound_before_first_commitment &&
        out.canonical_alg_proof;
    out.note = out.valid
        ? "stage3:receipt_public_statement:"
          "relation_proved_under_precommit_tuple_seed"
        : "stage3:receipt_public_statement:proof_commitment";
    return out;
}

bool VerifyStatementBoundChildRelationV1(
    const aq::AirConstraintSystem<gf::Fp3>& child_cs,
    const StatementBoundChildProofV1& proof,
    const ReceiptPublicStatementTupleV1& expected_statement,
    const uint256& expected_base_v2_seed,
    VerifiedReceiptPublicCellsV1* cells,
    std::string* why)
{
    if (proof.version != kReceiptPublicStatementVersionV1 ||
        !proof.valid ||
        !ValidateReceiptPublicStatementTupleV1(
            expected_statement, nullptr) ||
        expected_base_v2_seed.IsNull() ||
        !SameStatement(proof.statement, expected_statement)) {
        return Fail(why, "verify_statement");
    }
    const uint256 tuple_commitment =
        CommitReceiptPublicStatementTupleV1(expected_statement);
    const uint256 bound_seed =
        ComputeStatementBoundReceiptFsSeedV1(
            expected_statement, expected_base_v2_seed);
    if (tuple_commitment.IsNull() ||
        bound_seed.IsNull() ||
        proof.tuple_commitment != tuple_commitment ||
        proof.base_v2_seed != expected_base_v2_seed ||
        proof.bound_fs_seed != bound_seed ||
        proof.proof_commitment.IsNull() ||
        proof.proof_commitment !=
            fp::ComputeNormalizedAlgAirProofCommitment(proof.proof)) {
        return Fail(why, "verify_binding");
    }
    std::string verify_why;
    if (!aq::AirQuotientVerify<
            gf::Fp3, aq::AirFriBackendAlg<gf::Fp3>>(
            child_cs, proof.proof, bound_seed, &verify_why)) {
        return Fail(why, "verify_proof:" + verify_why);
    }
    if (cells != nullptr &&
        !FillVerifiedCells(
            expected_statement, tuple_commitment,
            bound_seed, *cells)) {
        return Fail(why, "verify_cells");
    }
    if (why != nullptr) {
        *why =
            "stage3:receipt_public_statement:verify_ok";
    }
    return true;
}

StatementBoundV10TraceCanaryV1
ProveStatementBoundV10TraceCanaryV1(
    const std::vector<std::vector<gf::Fp3>>& coefficient_columns,
    const ReceiptPublicStatementTupleV1& statement,
    const uint256& base_v2_seed,
    uint64_t pow_grind_nonce)
{
    StatementBoundV10TraceCanaryV1 out;
    out.statement = statement;
    out.base_v2_seed = base_v2_seed;
    if (!ValidateReceiptPublicStatementTupleV1(statement, nullptr) ||
        base_v2_seed.IsNull()) {
        out.note =
            "stage3:receipt_public_statement:v10:statement";
        return out;
    }
    out.tuple_commitment =
        CommitReceiptPublicStatementTupleV1(statement);
    out.bound_fs_seed =
        ComputeStatementBoundReceiptFsSeedV1(
            statement, base_v2_seed);
    if (out.tuple_commitment.IsNull() ||
        out.bound_fs_seed.IsNull()) {
        out.note =
            "stage3:receipt_public_statement:v10:seed";
        return out;
    }
    const auto committed =
        Fri3AlgP2Q192K2V10BatchCommit(
            coefficient_columns, out.bound_fs_seed,
            pow_grind_nonce);
    if (!committed.ok) {
        out.note =
            "stage3:receipt_public_statement:v10:" +
            committed.note;
        return out;
    }
    std::string verify_why;
    if (!Fri3AlgP2Q192K2V10BatchVerify(
            committed.proof, out.bound_fs_seed,
            &verify_why)) {
        out.note =
            "stage3:receipt_public_statement:v10_verify:" +
            verify_why;
        return out;
    }
    out.proof = committed.proof;
    out.v10_trace_low_degree_proved = true;
    out.tuple_bound_before_first_commitment = true;
    out.air_quotient_relation_proved = false;
    out.same_trace_join_with_child_air = false;
    out.recursive_authority = false;
    out.valid = true;
    out.note =
        "stage3:receipt_public_statement:"
        "v10_tuple_seed_trace_canary;"
        "air_quotient_backend_and_same_trace_join_open";
    return out;
}

bool VerifyStatementBoundV10TraceCanaryV1(
    const StatementBoundV10TraceCanaryV1& proof,
    const ReceiptPublicStatementTupleV1& expected_statement,
    const uint256& expected_base_v2_seed,
    VerifiedReceiptPublicCellsV1* cells,
    std::string* why)
{
    if (proof.version != kReceiptPublicStatementVersionV1 ||
        !proof.valid ||
        !ValidateReceiptPublicStatementTupleV1(
            expected_statement, nullptr) ||
        expected_base_v2_seed.IsNull() ||
        !SameStatement(proof.statement, expected_statement)) {
        return Fail(why, "v10_verify_statement");
    }
    const uint256 tuple_commitment =
        CommitReceiptPublicStatementTupleV1(expected_statement);
    const uint256 bound_seed =
        ComputeStatementBoundReceiptFsSeedV1(
            expected_statement, expected_base_v2_seed);
    if (proof.tuple_commitment != tuple_commitment ||
        proof.base_v2_seed != expected_base_v2_seed ||
        proof.bound_fs_seed != bound_seed) {
        return Fail(why, "v10_verify_binding");
    }
    std::string verify_why;
    if (!Fri3AlgP2Q192K2V10BatchVerify(
            proof.proof, bound_seed, &verify_why)) {
        return Fail(why, "v10_verify_proof:" + verify_why);
    }
    if (cells != nullptr &&
        !FillVerifiedCells(
            expected_statement, tuple_commitment,
            bound_seed, *cells)) {
        return Fail(why, "v10_verify_cells");
    }
    if (why != nullptr) {
        *why =
            "stage3:receipt_public_statement:v10_verify_ok";
    }
    return true;
}

} // namespace matmul::v4::rc::receipt_public_statement
