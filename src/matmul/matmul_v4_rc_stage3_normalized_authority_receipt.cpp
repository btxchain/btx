// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_normalized_authority_receipt.h>

#include <hash.h>
#include <matmul/matmul_v4_rc_stage3_composition.h>

#include <algorithm>
#include <array>
#include <limits>

namespace matmul::v4::rc::normalized_authority {
namespace {

constexpr char kEndpointDomainV3[] =
    "BTX_RC_STAGE3_NORMALIZED_AUTHORITY_ENDPOINT_V3";
constexpr char kRoleEndpointsDomainV3[] =
    "BTX_RC_STAGE3_NORMALIZED_AUTHORITY_ROLE_ENDPOINTS_V3";
constexpr char kRoleStatementDomainV3[] =
    "BTX_RC_STAGE3_NORMALIZED_AUTHORITY_ROLE_STATEMENT_V3";
constexpr char kRoleManifestDomainV3[] =
    "BTX_RC_STAGE3_NORMALIZED_AUTHORITY_ROLE_MANIFEST_V3";
constexpr char kDirectOuterStatementDomainV3[] =
    "BTX_RC_STAGE3_NORMALIZED_AUTHORITY_DIRECT_OUTER_STATEMENT_V3";
constexpr char kFixedTraceDomainV3[] =
    "BTX_RC_STAGE3_NORMALIZED_AUTHORITY_FIXED_TRACE_V3";
constexpr char kParentStatementDomainV3[] =
    "BTX_RC_STAGE3_NORMALIZED_AUTHORITY_PARENT_STATEMENT_V3";
constexpr char kParentFsDomainV3[] =
    "BTX_RC_STAGE3_NORMALIZED_AUTHORITY_PARENT_FS_V3";
constexpr char kParentProofDomainV3[] =
    "BTX_RC_STAGE3_NORMALIZED_AUTHORITY_PARENT_PROOF_V3";
constexpr char kReceiptDomainV3[] =
    "BTX_RC_STAGE3_NORMALIZED_AUTHORITY_RECEIPT_V3";

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:normalized_authority_v3:" + detail;
    }
    return false;
}

bool IsPowerOfTwo(uint32_t value)
{
    return value >= 2 && (value & (value - 1)) == 0;
}

bool NonNull(const uint256& value)
{
    return !value.IsNull();
}

RCStage3PublicInputs ToLegacyPublicInputs(
    const ComposedPublicStatementV3& statement)
{
    RCStage3PublicInputs out;
    out.height = statement.height;
    out.n_bits = statement.n_bits;
    out.episode_profile = statement.episode_profile;
    out.coupled_profile = statement.coupled_profile;
    out.transcript_version = statement.transcript_version;
    out.program_consensus_pin =
        statement.program_consensus_pin;
    out.header_commitment = statement.header_commitment;
    out.params_commitment = statement.params_commitment;
    out.target = statement.target;
    out.sigma = statement.sigma;
    out.episode_digest = statement.episode_digest;
    out.coupled_digest = statement.coupled_digest;
    out.final_digest = statement.final_digest;
    return out;
}

bool CanonicalPublicStatement(
    const ComposedPublicStatementV3& statement,
    std::string* why)
{
    std::string pin_why;
    if (statement.height < 0 ||
        statement.n_bits == 0 ||
        statement.episode_profile == 0 ||
        statement.coupled_profile == 0 ||
        statement.transcript_version == 0 ||
        !ValidateProductionProgramConsensusPinV1(
            statement.program_consensus_pin,
            &pin_why) ||
        !NonNull(statement.header_commitment) ||
        !NonNull(statement.params_commitment) ||
        !NonNull(statement.target) ||
        !NonNull(statement.sigma) ||
        !NonNull(statement.episode_digest) ||
        !NonNull(statement.coupled_digest) ||
        !NonNull(statement.final_digest)) {
        return Fail(
            why,
            pin_why.empty()
                ? "public_statement"
                : "public_statement_program_pin:" +
                      pin_why);
    }
    RCStage3SuccinctProof statement_probe;
    statement_probe.statement =
        RCStage3StatementKind::Composed;
    statement_probe.public_inputs =
        ToLegacyPublicInputs(statement);
    if (ComputeRCStage3FinalDigest(statement_probe) !=
        statement.final_digest) {
        return Fail(why, "public_statement_final_digest");
    }
    return true;
}

bool CanonicalShape(const ParentShapeV3& shape)
{
    if (!IsPowerOfTwo(shape.trace_rows) ||
        shape.semantic_columns == 0 ||
        shape.proof_columns == 0 ||
        shape.semantic_columns > shape.proof_columns ||
        shape.proof_columns >= kRCFri3AlgBatchMaxColumns ||
        shape.constraints == 0 ||
        shape.max_constraint_degree == 0 ||
        shape.quotient_rows == 0 ||
        !IsPowerOfTwo(shape.fri_n_coeffs) ||
        shape.fri_n_coeffs < shape.trace_rows ||
        shape.fri_n_coeffs < shape.quotient_rows) {
        return false;
    }
    const uint64_t lde_rows =
        static_cast<uint64_t>(shape.fri_n_coeffs) *
        kRCFriBlowup;
    return lde_rows <= std::numeric_limits<uint32_t>::max() &&
        shape.lde_rows == lde_rows;
}

bool CanonicalFixedColumns(
    const std::vector<uint32_t>& columns,
    uint32_t proof_columns)
{
    if (columns.empty() ||
        columns.size() >= proof_columns ||
        columns.size() >= kRCFri3AlgBatchMaxColumns) {
        return false;
    }
    uint32_t previous = 0;
    for (size_t i = 0; i < columns.size(); ++i) {
        if (columns[i] >= proof_columns ||
            (i != 0 && columns[i] <= previous)) {
            return false;
        }
        previous = columns[i];
    }
    return true;
}

bool CanonicalRoles(
    const std::vector<RolePinV3>& roles,
    std::string* why)
{
    if (roles.size() != kRoleCountV3) {
        return Fail(why, "role_count");
    }
    const auto& order = RCStage3UnifiedRoleOrder();
    uint32_t endpoints = 0;
    for (size_t role_index = 0;
         role_index < roles.size();
         ++role_index) {
        const RolePinV3& role = roles[role_index];
        if (role.role != order[role_index]) {
            return Fail(why, "role_order");
        }
        if (!NonNull(role.program_root) ||
            !NonNull(role.relation_statement_root)) {
            return Fail(why, "role_public_root");
        }
        const auto& required =
            RequiredRCStage3RelationEndpoints(role.role);
        if (role.endpoints.size() != required.size()) {
            return Fail(why, "endpoint_count");
        }
        for (size_t endpoint_index = 0;
             endpoint_index < required.size();
             ++endpoint_index) {
            const EndpointPinV3& endpoint =
                role.endpoints[endpoint_index];
            if (endpoint.endpoint !=
                    required[endpoint_index] ||
                endpoint.instance_count == 0 ||
                !NonNull(endpoint.manifest_root) ||
                !NonNull(endpoint.relation_proof_root) ||
                !NonNull(endpoint.semantic_root) ||
                !NonNull(endpoint.ctl_terminal_root) ||
                !NonNull(
                    endpoint.recursive_child_statement_root)) {
                return Fail(why, "endpoint_pin");
            }
        }
        endpoints += role.endpoints.size();
        if (role.endpoint_manifest_root !=
                ComputeRoleEndpointManifestRootV3(role) ||
            role.role_statement_root !=
                ComputeRoleStatementRootV3(role)) {
            return Fail(why, "role_derived_root");
        }
    }
    if (endpoints != kEndpointCountV3) {
        return Fail(why, "endpoint_total");
    }
    return true;
}

RebuiltVerifierInputsV3 ToVerifierInputs(
    const NormalizedAuthorityReceiptV3& receipt)
{
    RebuiltVerifierInputsV3 out;
    out.outer_binding_kind = receipt.outer_binding_kind;
    out.public_statement = receipt.public_statement;
    out.outer_statement_root = receipt.outer_statement_root;
    out.program_registry_root = receipt.program_registry_root;
    out.topology_manifest_root = receipt.topology_manifest_root;
    out.aggregation_schedule_root =
        receipt.aggregation_schedule_root;
    out.occurrence_manifest_root =
        receipt.occurrence_manifest_root;
    out.verifier_program_root = receipt.verifier_program_root;
    out.abi_plan_root = receipt.abi_plan_root;
    out.selection_plan_root = receipt.selection_plan_root;
    out.derived_hash_plan_root = receipt.derived_hash_plan_root;
    out.fixed_trace_columns = receipt.fixed_trace_columns;
    out.fixed_trace_row_root = receipt.fixed_trace_row_root;
    out.roles = receipt.roles;
    out.parent_shape = receipt.parent_shape;
    out.parent_node_binding = receipt.parent_node_binding;
    out.parent_context_binding = receipt.parent_context_binding;
    out.parent_program_root = receipt.parent_program_root;
    out.parent_cs_commitment = receipt.parent_cs_commitment;
    return out;
}

bool DecodeAndCheckParentProof(
    const NormalizedAuthorityReceiptV3& receipt,
    aq::AirQuotientSplitRapRowsProof& proof,
    std::string* why)
{
    const auto decoded =
        aq::DeserializeAirQuotientSplitRapRowsProof(
            receipt.parent_proof_bytes);
    if (!decoded.has_value()) {
        return Fail(why, "parent_proof_codec");
    }
    proof = *decoded;
    std::vector<unsigned char> canonical;
    if (aq::SerializeAirQuotientSplitRapRowsProof(
            proof, canonical) !=
            receipt.parent_proof_bytes.size() ||
        canonical != receipt.parent_proof_bytes) {
        return Fail(why, "parent_proof_noncanonical");
    }
    if (proof.version != kOuterProofVersionV3 ||
        proof.batch.version != kSafeBackendVersionV3 ||
        proof.trace_rows !=
            receipt.parent_shape.trace_rows ||
        proof.base_column_indices !=
            receipt.fixed_trace_columns ||
        proof.batch.blowup != kRCFriBlowup ||
        proof.batch.n_coeffs !=
            receipt.parent_shape.fri_n_coeffs ||
        proof.batch.column_len.size() !=
            static_cast<size_t>(
                receipt.parent_shape.proof_columns) + 1 ||
        proof.batch.column_len.back() !=
            receipt.parent_shape.quotient_rows ||
        proof.batch.queries.size() != kFriQueriesV3) {
        return Fail(why, "parent_proof_statement");
    }
    for (uint32_t column = 0;
         column < receipt.parent_shape.proof_columns;
         ++column) {
        if (proof.batch.column_len[column] !=
            receipt.parent_shape.trace_rows) {
            return Fail(why, "parent_proof_column_length");
        }
    }
    return true;
}

void WriteU16(std::vector<unsigned char>& out, uint16_t value)
{
    out.push_back(static_cast<unsigned char>(value));
    out.push_back(static_cast<unsigned char>(value >> 8));
}

void WriteU32(std::vector<unsigned char>& out, uint32_t value)
{
    for (uint32_t i = 0; i < 4; ++i) {
        out.push_back(
            static_cast<unsigned char>(value >> (8U * i)));
    }
}

void WriteU64(std::vector<unsigned char>& out, uint64_t value)
{
    for (uint32_t i = 0; i < 8; ++i) {
        out.push_back(
            static_cast<unsigned char>(value >> (8U * i)));
    }
}

void WriteHash(std::vector<unsigned char>& out, const uint256& value)
{
    out.insert(out.end(), value.begin(), value.end());
}

void WriteShape(
    std::vector<unsigned char>& out,
    const ParentShapeV3& shape)
{
    WriteU32(out, shape.trace_rows);
    WriteU32(out, shape.semantic_columns);
    WriteU32(out, shape.proof_columns);
    WriteU32(out, shape.constraints);
    WriteU32(out, shape.max_constraint_degree);
    WriteU32(out, shape.quotient_rows);
    WriteU32(out, shape.fri_n_coeffs);
    WriteU32(out, shape.lde_rows);
}

void WritePublicStatement(
    std::vector<unsigned char>& out,
    const ComposedPublicStatementV3& statement)
{
    WriteU32(
        out, static_cast<uint32_t>(statement.height));
    WriteU32(out, statement.n_bits);
    WriteU32(out, statement.episode_profile);
    WriteU32(out, statement.coupled_profile);
    WriteU32(out, statement.transcript_version);
    WriteU16(
        out, statement.program_consensus_pin.version);
    WriteHash(
        out,
        statement.program_consensus_pin
            .recursive_alg_hash_root);
    WriteHash(
        out,
        statement.program_consensus_pin
            .external_sha256d_audit_root);
    WriteHash(
        out,
        statement.program_consensus_pin
            .registry_binding);
    WriteHash(out, statement.header_commitment);
    WriteHash(out, statement.params_commitment);
    WriteHash(out, statement.target);
    WriteHash(out, statement.sigma);
    WriteHash(out, statement.episode_digest);
    WriteHash(out, statement.coupled_digest);
    WriteHash(out, statement.final_digest);
}

class Reader {
public:
    explicit Reader(const std::vector<unsigned char>& bytes)
        : m_bytes(bytes)
    {
    }

    bool U16(uint16_t& out)
    {
        if (Remaining() < 2) return false;
        out = static_cast<uint16_t>(m_bytes[m_pos]) |
            static_cast<uint16_t>(m_bytes[m_pos + 1]) << 8;
        m_pos += 2;
        return true;
    }

    bool U32(uint32_t& out)
    {
        if (Remaining() < 4) return false;
        out = 0;
        for (uint32_t i = 0; i < 4; ++i) {
            out |=
                static_cast<uint32_t>(m_bytes[m_pos + i])
                << (8U * i);
        }
        m_pos += 4;
        return true;
    }

    bool U64(uint64_t& out)
    {
        if (Remaining() < 8) return false;
        out = 0;
        for (uint32_t i = 0; i < 8; ++i) {
            out |=
                static_cast<uint64_t>(m_bytes[m_pos + i])
                << (8U * i);
        }
        m_pos += 8;
        return true;
    }

    bool Hash(uint256& out)
    {
        if (Remaining() < out.size()) return false;
        std::copy_n(
            m_bytes.begin() +
                static_cast<ptrdiff_t>(m_pos),
            out.size(), out.begin());
        m_pos += out.size();
        return true;
    }

    bool Bytes(
        size_t count,
        std::vector<unsigned char>& out)
    {
        if (Remaining() < count) return false;
        out.assign(
            m_bytes.begin() +
                static_cast<ptrdiff_t>(m_pos),
            m_bytes.begin() +
                static_cast<ptrdiff_t>(m_pos + count));
        m_pos += count;
        return true;
    }

    size_t Remaining() const
    {
        return m_bytes.size() - m_pos;
    }

private:
    const std::vector<unsigned char>& m_bytes;
    size_t m_pos{0};
};

bool ReadShape(Reader& reader, ParentShapeV3& shape)
{
    return reader.U32(shape.trace_rows) &&
        reader.U32(shape.semantic_columns) &&
        reader.U32(shape.proof_columns) &&
        reader.U32(shape.constraints) &&
        reader.U32(shape.max_constraint_degree) &&
        reader.U32(shape.quotient_rows) &&
        reader.U32(shape.fri_n_coeffs) &&
        reader.U32(shape.lde_rows);
}

bool ReadPublicStatement(
    Reader& reader,
    ComposedPublicStatementV3& statement)
{
    uint32_t height = 0;
    if (!reader.U32(height) ||
        height >
            static_cast<uint32_t>(
                std::numeric_limits<int32_t>::max()) ||
        !reader.U32(statement.n_bits) ||
        !reader.U32(statement.episode_profile) ||
        !reader.U32(statement.coupled_profile) ||
        !reader.U32(statement.transcript_version) ||
        !reader.U16(
            statement.program_consensus_pin.version) ||
        !reader.Hash(
            statement.program_consensus_pin
                .recursive_alg_hash_root) ||
        !reader.Hash(
            statement.program_consensus_pin
                .external_sha256d_audit_root) ||
        !reader.Hash(
            statement.program_consensus_pin
                .registry_binding) ||
        !reader.Hash(statement.header_commitment) ||
        !reader.Hash(statement.params_commitment) ||
        !reader.Hash(statement.target) ||
        !reader.Hash(statement.sigma) ||
        !reader.Hash(statement.episode_digest) ||
        !reader.Hash(statement.coupled_digest) ||
        !reader.Hash(statement.final_digest)) {
        return false;
    }
    statement.height = static_cast<int32_t>(height);
    return true;
}

} // namespace

uint256 ComputeEndpointPinRootV3(
    const EndpointPinV3& endpoint)
{
    HashWriter hash;
    hash << kEndpointDomainV3;
    hash << kReceiptVersionV3;
    hash << static_cast<uint16_t>(endpoint.endpoint);
    hash << endpoint.instance_count;
    hash << endpoint.manifest_root;
    hash << endpoint.relation_proof_root;
    hash << endpoint.semantic_root;
    hash << endpoint.ctl_terminal_root;
    hash << endpoint.recursive_child_statement_root;
    return hash.GetHash();
}

uint256 ComputeRoleEndpointManifestRootV3(
    const RolePinV3& role)
{
    HashWriter hash;
    hash << kRoleEndpointsDomainV3;
    hash << kReceiptVersionV3;
    hash << static_cast<uint16_t>(role.role);
    hash << static_cast<uint16_t>(role.endpoints.size());
    for (const EndpointPinV3& endpoint : role.endpoints) {
        hash << ComputeEndpointPinRootV3(endpoint);
    }
    return hash.GetHash();
}

uint256 ComputeRoleStatementRootV3(
    const RolePinV3& role)
{
    HashWriter hash;
    hash << kRoleStatementDomainV3;
    hash << kReceiptVersionV3;
    hash << static_cast<uint16_t>(role.role);
    hash << role.program_root;
    hash << role.relation_statement_root;
    hash << role.endpoint_manifest_root;
    return hash.GetHash();
}

uint256 ComputeRoleManifestRootV3(
    const std::vector<RolePinV3>& roles)
{
    HashWriter hash;
    hash << kRoleManifestDomainV3;
    hash << kReceiptVersionV3;
    hash << static_cast<uint16_t>(roles.size());
    for (const RolePinV3& role : roles) {
        hash << static_cast<uint16_t>(role.role);
        hash << role.role_statement_root;
    }
    return hash.GetHash();
}

uint256 ComputeDirectOuterStatementRootV3(
    const ComposedPublicStatementV3& statement,
    const std::vector<RolePinV3>& roles)
{
    HashWriter hash;
    hash << kDirectOuterStatementDomainV3;
    hash << kReceiptVersionV3;
    hash << statement.height;
    hash << statement.n_bits;
    hash << statement.episode_profile;
    hash << statement.coupled_profile;
    hash << statement.transcript_version;
    hash << statement.program_consensus_pin.version;
    hash << statement.program_consensus_pin
                .recursive_alg_hash_root;
    hash << statement.program_consensus_pin
                .external_sha256d_audit_root;
    hash << statement.program_consensus_pin
                .registry_binding;
    hash << statement.header_commitment;
    hash << statement.params_commitment;
    hash << statement.target;
    hash << statement.sigma;
    hash << statement.episode_digest;
    hash << statement.coupled_digest;
    hash << statement.final_digest;
    hash << ComputeRoleManifestRootV3(roles);
    return hash.GetHash();
}

uint256 ComputeFixedTraceManifestRootV3(
    const ParentShapeV3& shape,
    const std::vector<uint32_t>& ordered_columns,
    const uint256& row_root)
{
    HashWriter hash;
    hash << kFixedTraceDomainV3;
    hash << kReceiptVersionV3;
    hash << shape.trace_rows;
    hash << shape.proof_columns;
    hash << static_cast<uint32_t>(ordered_columns.size());
    for (uint32_t column : ordered_columns) {
        hash << column;
    }
    hash << row_root;
    return hash.GetHash();
}

uint256 ComputeParentStatementRootV3(
    const RebuiltVerifierInputsV3& inputs)
{
    HashWriter hash;
    hash << kParentStatementDomainV3;
    hash << kReceiptVersionV3;
    hash << kFpExtensionDegreeV3;
    hash << kFriQueriesV3;
    hash << kOodCandidatesV3;
    hash << kSafeBackendVersionV3;
    hash << kOuterProofVersionV3;
    hash << static_cast<uint8_t>(
        inputs.outer_binding_kind);
    hash << ComputeDirectOuterStatementRootV3(
        inputs.public_statement, inputs.roles);
    hash << inputs.outer_statement_root;
    hash << inputs.program_registry_root;
    hash << inputs.topology_manifest_root;
    hash << inputs.aggregation_schedule_root;
    hash << inputs.occurrence_manifest_root;
    hash << inputs.verifier_program_root;
    hash << inputs.abi_plan_root;
    hash << inputs.selection_plan_root;
    hash << inputs.derived_hash_plan_root;
    hash << ComputeFixedTraceManifestRootV3(
        inputs.parent_shape,
        inputs.fixed_trace_columns,
        inputs.fixed_trace_row_root);
    hash << ComputeRoleManifestRootV3(inputs.roles);
    hash << inputs.parent_shape.trace_rows;
    hash << inputs.parent_shape.semantic_columns;
    hash << inputs.parent_shape.proof_columns;
    hash << inputs.parent_shape.constraints;
    hash << inputs.parent_shape.max_constraint_degree;
    hash << inputs.parent_shape.quotient_rows;
    hash << inputs.parent_shape.fri_n_coeffs;
    hash << inputs.parent_shape.lde_rows;
    hash << inputs.parent_node_binding;
    hash << inputs.parent_context_binding;
    hash << inputs.parent_program_root;
    hash << inputs.parent_cs_commitment;
    return hash.GetHash();
}

uint256 DeriveParentFsSeedV3(
    const uint256& parent_statement_root)
{
    HashWriter hash;
    hash << kParentFsDomainV3;
    hash << kReceiptVersionV3;
    hash << parent_statement_root;
    return hash.GetHash();
}

uint256 ComputeParentProofRootV3(
    const std::vector<unsigned char>& proof_bytes)
{
    HashWriter hash;
    hash << kParentProofDomainV3;
    hash << kReceiptVersionV3;
    hash << static_cast<uint64_t>(proof_bytes.size());
    hash << proof_bytes;
    return hash.GetHash();
}

uint256 ComputeReceiptRootV3(
    const NormalizedAuthorityReceiptV3& receipt)
{
    HashWriter hash;
    hash << kReceiptDomainV3;
    hash << receipt.magic;
    hash << receipt.version;
    hash << receipt.fp_extension_degree;
    hash << receipt.fri_queries;
    hash << receipt.ood_candidates;
    hash << receipt.safe_backend_version;
    hash << receipt.outer_proof_version;
    hash << static_cast<uint8_t>(
        receipt.outer_binding_kind);
    hash << ComputeDirectOuterStatementRootV3(
        receipt.public_statement, receipt.roles);
    hash << receipt.parent_statement_root;
    hash << receipt.parent_fs_seed;
    hash << receipt.parent_proof_root;
    hash << static_cast<uint64_t>(
        receipt.parent_proof_bytes.size());
    return hash.GetHash();
}

bool ValidateNormalizedAuthorityReceiptV3(
    const NormalizedAuthorityReceiptV3& receipt,
    std::string* why)
{
    if (receipt.magic != kReceiptMagicV3 ||
        receipt.version != kReceiptVersionV3 ||
        receipt.fp_extension_degree !=
            kFpExtensionDegreeV3 ||
        receipt.fri_queries != kFriQueriesV3 ||
        receipt.ood_candidates != kOodCandidatesV3 ||
        receipt.safe_backend_version !=
            kSafeBackendVersionV3 ||
        receipt.outer_proof_version !=
            kOuterProofVersionV3) {
        return Fail(why, "protocol_header");
    }
    if (receipt.outer_binding_kind !=
            OuterBindingKindV3::DirectBlockReceipt &&
        receipt.outer_binding_kind !=
            OuterBindingKindV3::LegacyCompositionEnvelope) {
        return Fail(why, "outer_binding_kind");
    }
    if (!CanonicalPublicStatement(
            receipt.public_statement, why)) {
        return false;
    }
    if (!NonNull(receipt.outer_statement_root) ||
        !NonNull(receipt.program_registry_root) ||
        !NonNull(receipt.topology_manifest_root) ||
        !NonNull(receipt.aggregation_schedule_root) ||
        !NonNull(receipt.occurrence_manifest_root) ||
        !NonNull(receipt.verifier_program_root) ||
        !NonNull(receipt.abi_plan_root) ||
        !NonNull(receipt.selection_plan_root) ||
        !NonNull(receipt.derived_hash_plan_root) ||
        !NonNull(receipt.fixed_trace_row_root) ||
        !NonNull(receipt.parent_node_binding) ||
        !NonNull(receipt.parent_context_binding) ||
        !NonNull(receipt.parent_program_root) ||
        !NonNull(receipt.parent_cs_commitment)) {
        return Fail(why, "missing_public_root");
    }
    if (!CanonicalShape(receipt.parent_shape)) {
        return Fail(why, "parent_shape");
    }
    if (!CanonicalFixedColumns(
            receipt.fixed_trace_columns,
            receipt.parent_shape.proof_columns)) {
        return Fail(why, "fixed_trace_columns");
    }
    if (receipt.fixed_trace_manifest_root !=
        ComputeFixedTraceManifestRootV3(
            receipt.parent_shape,
            receipt.fixed_trace_columns,
            receipt.fixed_trace_row_root)) {
        return Fail(why, "fixed_trace_manifest_root");
    }
    if (!CanonicalRoles(receipt.roles, why)) {
        return false;
    }
    if (receipt.role_manifest_root !=
        ComputeRoleManifestRootV3(receipt.roles)) {
        return Fail(why, "role_manifest_root");
    }
    if (receipt.program_registry_root !=
        receipt.public_statement.program_consensus_pin
            .recursive_alg_hash_root) {
        return Fail(why, "program_registry_statement");
    }
    if (receipt.outer_binding_kind ==
            OuterBindingKindV3::DirectBlockReceipt &&
        receipt.outer_statement_root !=
            ComputeDirectOuterStatementRootV3(
                receipt.public_statement,
                receipt.roles)) {
        return Fail(why, "direct_outer_statement_root");
    }
    const RebuiltVerifierInputsV3 inputs =
        ToVerifierInputs(receipt);
    if (receipt.parent_statement_root !=
        ComputeParentStatementRootV3(inputs)) {
        return Fail(why, "parent_statement_root");
    }
    if (receipt.parent_fs_seed !=
        DeriveParentFsSeedV3(
            receipt.parent_statement_root)) {
        return Fail(why, "parent_fs_seed");
    }
    if (receipt.parent_proof_bytes.empty() ||
        receipt.parent_proof_bytes.size() >
            kRCStage3MaxProofBytes ||
        receipt.parent_proof_bytes.size() >
            aq::kAirQuotientSplitRapRowsMaxProofBytesHard) {
        return Fail(why, "parent_proof_size");
    }
    if (receipt.parent_proof_root !=
        ComputeParentProofRootV3(
            receipt.parent_proof_bytes)) {
        return Fail(why, "parent_proof_root");
    }
    aq::AirQuotientSplitRapRowsProof decoded;
    if (!DecodeAndCheckParentProof(
            receipt, decoded, why)) {
        return false;
    }
    if (receipt.receipt_root !=
        ComputeReceiptRootV3(receipt)) {
        return Fail(why, "receipt_root");
    }
    if (why != nullptr) {
        *why =
            "stage3:normalized_authority_v3:"
            "canonical_not_executed";
    }
    return true;
}

bool ValidateAndDecodeVerifierInputsV3(
    const NormalizedAuthorityReceiptV3& receipt,
    const RebuiltVerifierInputsV3& rebuilt,
    aq::AirQuotientSplitRapRowsProof& decoded_parent_proof,
    aq::AirQuotientFixedTracePinV3& fixed_trace,
    std::string* why)
{
    if (!ValidateNormalizedAuthorityReceiptV3(
            receipt, why)) {
        return false;
    }
    if (!NonNull(rebuilt.parent_cs_commitment) ||
        !CanonicalShape(rebuilt.parent_shape) ||
        !CanonicalFixedColumns(
            rebuilt.fixed_trace_columns,
            rebuilt.parent_shape.proof_columns) ||
        !CanonicalRoles(rebuilt.roles, why)) {
        return Fail(why, "rebuilt_parent_cs");
    }
    if (rebuilt != ToVerifierInputs(receipt)) {
        return Fail(why, "verifier_input_substitution");
    }
    if (receipt.fixed_trace_manifest_root !=
            ComputeFixedTraceManifestRootV3(
                rebuilt.parent_shape,
                rebuilt.fixed_trace_columns,
                rebuilt.fixed_trace_row_root) ||
        receipt.role_manifest_root !=
            ComputeRoleManifestRootV3(rebuilt.roles) ||
        receipt.parent_statement_root !=
            ComputeParentStatementRootV3(rebuilt)) {
        return Fail(why, "verifier_rebuilt_root");
    }
    if (!DecodeAndCheckParentProof(
            receipt, decoded_parent_proof, why)) {
        return false;
    }
    fixed_trace.version = 1;
    fixed_trace.ordered_columns =
        rebuilt.fixed_trace_columns;
    fixed_trace.row_root =
        rebuilt.fixed_trace_row_root;
    if (why != nullptr) {
        *why =
            "stage3:normalized_authority_v3:"
            "verifier_inputs_bound_parent_verify_required";
    }
    return true;
}

size_t SerializeNormalizedAuthorityReceiptV3(
    const NormalizedAuthorityReceiptV3& receipt,
    std::vector<unsigned char>& out)
{
    out.clear();
    if (!ValidateNormalizedAuthorityReceiptV3(
            receipt, nullptr) ||
        receipt.parent_proof_bytes.size() >
            std::numeric_limits<uint32_t>::max()) {
        return 0;
    }
    WriteU32(out, receipt.magic);
    WriteU16(out, receipt.version);
    WriteU16(out, receipt.fp_extension_degree);
    WriteU16(out, receipt.fri_queries);
    WriteU16(out, receipt.ood_candidates);
    WriteU16(out, receipt.safe_backend_version);
    WriteU16(out, receipt.outer_proof_version);

    WriteU16(
        out,
        static_cast<uint16_t>(
            receipt.outer_binding_kind));
    WritePublicStatement(
        out, receipt.public_statement);
    WriteHash(out, receipt.outer_statement_root);
    WriteHash(out, receipt.program_registry_root);
    WriteHash(out, receipt.topology_manifest_root);
    WriteHash(out, receipt.aggregation_schedule_root);
    WriteHash(out, receipt.occurrence_manifest_root);
    WriteHash(out, receipt.verifier_program_root);
    WriteHash(out, receipt.abi_plan_root);
    WriteHash(out, receipt.selection_plan_root);
    WriteHash(out, receipt.derived_hash_plan_root);

    WriteU32(
        out,
        static_cast<uint32_t>(
            receipt.fixed_trace_columns.size()));
    for (uint32_t column : receipt.fixed_trace_columns) {
        WriteU32(out, column);
    }
    WriteHash(out, receipt.fixed_trace_row_root);
    WriteHash(out, receipt.fixed_trace_manifest_root);

    WriteU16(
        out,
        static_cast<uint16_t>(receipt.roles.size()));
    for (const RolePinV3& role : receipt.roles) {
        WriteU16(out, static_cast<uint16_t>(role.role));
        WriteHash(out, role.program_root);
        WriteHash(out, role.relation_statement_root);
        WriteU16(
            out,
            static_cast<uint16_t>(role.endpoints.size()));
        for (const EndpointPinV3& endpoint :
             role.endpoints) {
            WriteU16(
                out,
                static_cast<uint16_t>(endpoint.endpoint));
            WriteU64(out, endpoint.instance_count);
            WriteHash(out, endpoint.manifest_root);
            WriteHash(out, endpoint.relation_proof_root);
            WriteHash(out, endpoint.semantic_root);
            WriteHash(out, endpoint.ctl_terminal_root);
            WriteHash(
                out,
                endpoint.recursive_child_statement_root);
        }
        WriteHash(out, role.endpoint_manifest_root);
        WriteHash(out, role.role_statement_root);
    }
    WriteHash(out, receipt.role_manifest_root);

    WriteShape(out, receipt.parent_shape);
    WriteHash(out, receipt.parent_node_binding);
    WriteHash(out, receipt.parent_context_binding);
    WriteHash(out, receipt.parent_program_root);
    WriteHash(out, receipt.parent_cs_commitment);
    WriteHash(out, receipt.parent_statement_root);
    WriteHash(out, receipt.parent_fs_seed);

    WriteU32(
        out,
        static_cast<uint32_t>(
            receipt.parent_proof_bytes.size()));
    out.insert(
        out.end(),
        receipt.parent_proof_bytes.begin(),
        receipt.parent_proof_bytes.end());
    WriteHash(out, receipt.parent_proof_root);
    WriteHash(out, receipt.receipt_root);
    if (out.size() > kRCStage3MaxProofBytes) {
        out.clear();
        return 0;
    }
    return out.size();
}

std::optional<NormalizedAuthorityReceiptV3>
DeserializeNormalizedAuthorityReceiptV3(
    const std::vector<unsigned char>& bytes,
    std::string* why)
{
    const auto fail =
        [&](const std::string& detail)
            -> std::optional<NormalizedAuthorityReceiptV3> {
        Fail(why, "decode_" + detail);
        return std::nullopt;
    };
    if (bytes.empty() ||
        bytes.size() > kRCStage3MaxProofBytes) {
        return fail("size");
    }
    Reader reader(bytes);
    NormalizedAuthorityReceiptV3 out;
    uint16_t outer_binding_kind = 0;
    if (!reader.U32(out.magic) ||
        !reader.U16(out.version) ||
        !reader.U16(out.fp_extension_degree) ||
        !reader.U16(out.fri_queries) ||
        !reader.U16(out.ood_candidates) ||
        !reader.U16(out.safe_backend_version) ||
        !reader.U16(out.outer_proof_version) ||
        out.magic != kReceiptMagicV3 ||
        out.version != kReceiptVersionV3 ||
        out.fp_extension_degree !=
            kFpExtensionDegreeV3 ||
        out.fri_queries != kFriQueriesV3 ||
        out.ood_candidates != kOodCandidatesV3 ||
        out.safe_backend_version !=
            kSafeBackendVersionV3 ||
        out.outer_proof_version !=
            kOuterProofVersionV3) {
        return fail("header");
    }
    if (!reader.U16(outer_binding_kind) ||
        (outer_binding_kind !=
             static_cast<uint16_t>(
                 OuterBindingKindV3::
                     DirectBlockReceipt) &&
         outer_binding_kind !=
             static_cast<uint16_t>(
                 OuterBindingKindV3::
                     LegacyCompositionEnvelope)) ||
        !ReadPublicStatement(
            reader, out.public_statement) ||
        !reader.Hash(out.outer_statement_root) ||
        !reader.Hash(out.program_registry_root) ||
        !reader.Hash(out.topology_manifest_root) ||
        !reader.Hash(out.aggregation_schedule_root) ||
        !reader.Hash(out.occurrence_manifest_root) ||
        !reader.Hash(out.verifier_program_root) ||
        !reader.Hash(out.abi_plan_root) ||
        !reader.Hash(out.selection_plan_root) ||
        !reader.Hash(out.derived_hash_plan_root)) {
        return fail("public_roots");
    }
    out.outer_binding_kind =
        static_cast<OuterBindingKindV3>(
            outer_binding_kind);
    uint32_t fixed_count = 0;
    if (!reader.U32(fixed_count) ||
        fixed_count == 0 ||
        fixed_count >= kRCFri3AlgBatchMaxColumns ||
        reader.Remaining() <
            static_cast<uint64_t>(fixed_count) * 4 + 64) {
        return fail("fixed_count");
    }
    out.fixed_trace_columns.resize(fixed_count);
    for (uint32_t& column : out.fixed_trace_columns) {
        if (!reader.U32(column)) {
            return fail("fixed_columns");
        }
    }
    if (!reader.Hash(out.fixed_trace_row_root) ||
        !reader.Hash(out.fixed_trace_manifest_root)) {
        return fail("fixed_roots");
    }

    uint16_t role_count = 0;
    if (!reader.U16(role_count) ||
        role_count != kRoleCountV3) {
        return fail("role_count");
    }
    out.roles.resize(role_count);
    uint32_t endpoint_total = 0;
    for (RolePinV3& role : out.roles) {
        uint16_t role_id = 0;
        uint16_t endpoint_count = 0;
        if (!reader.U16(role_id) ||
            !reader.Hash(role.program_root) ||
            !reader.Hash(role.relation_statement_root) ||
            !reader.U16(endpoint_count) ||
            endpoint_count > kEndpointCountV3) {
            return fail("role");
        }
        role.role =
            static_cast<RCStage3RelationRole>(role_id);
        endpoint_total += endpoint_count;
        if (endpoint_total > kEndpointCountV3) {
            return fail("endpoint_total");
        }
        role.endpoints.resize(endpoint_count);
        for (EndpointPinV3& endpoint : role.endpoints) {
            uint16_t endpoint_id = 0;
            if (!reader.U16(endpoint_id) ||
                !reader.U64(endpoint.instance_count) ||
                !reader.Hash(endpoint.manifest_root) ||
                !reader.Hash(endpoint.relation_proof_root) ||
                !reader.Hash(endpoint.semantic_root) ||
                !reader.Hash(endpoint.ctl_terminal_root) ||
                !reader.Hash(
                    endpoint.recursive_child_statement_root)) {
                return fail("endpoint");
            }
            endpoint.endpoint =
                static_cast<RCStage3RelationEndpoint>(
                    endpoint_id);
        }
        if (!reader.Hash(role.endpoint_manifest_root) ||
            !reader.Hash(role.role_statement_root)) {
            return fail("role_roots");
        }
    }
    if (endpoint_total != kEndpointCountV3 ||
        !reader.Hash(out.role_manifest_root) ||
        !ReadShape(reader, out.parent_shape) ||
        !reader.Hash(out.parent_node_binding) ||
        !reader.Hash(out.parent_context_binding) ||
        !reader.Hash(out.parent_program_root) ||
        !reader.Hash(out.parent_cs_commitment) ||
        !reader.Hash(out.parent_statement_root) ||
        !reader.Hash(out.parent_fs_seed)) {
        return fail("parent_statement");
    }

    uint32_t proof_size = 0;
    if (!reader.U32(proof_size) ||
        proof_size == 0 ||
        proof_size > kRCStage3MaxProofBytes ||
        proof_size >
            aq::kAirQuotientSplitRapRowsMaxProofBytesHard ||
        !reader.Bytes(
            proof_size, out.parent_proof_bytes) ||
        !reader.Hash(out.parent_proof_root) ||
        !reader.Hash(out.receipt_root) ||
        reader.Remaining() != 0) {
        return fail("proof_payload");
    }
    if (!ValidateNormalizedAuthorityReceiptV3(
            out, why)) {
        return std::nullopt;
    }
    std::vector<unsigned char> canonical;
    if (SerializeNormalizedAuthorityReceiptV3(
            out, canonical) != bytes.size() ||
        canonical != bytes) {
        return fail("noncanonical");
    }
    if (why != nullptr) {
        *why =
            "stage3:normalized_authority_v3:"
            "decode_canonical_not_executed";
    }
    return out;
}

} // namespace matmul::v4::rc::normalized_authority
