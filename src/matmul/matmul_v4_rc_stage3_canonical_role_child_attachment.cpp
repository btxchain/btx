// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/MIT.

#include <matmul/matmul_v4_rc_stage3_canonical_role_child_attachment.h>

#include <consensus/params.h>
#include <hash.h>
#include <matmul/matmul_v4_rc_stage3_recursive_fixedpoint.h>
#include <primitives/block.h>

#include <algorithm>
#include <array>
#include <limits>

namespace matmul::v4::rc::canonical_role_child_attachment {
namespace {

constexpr std::array<unsigned char, 8> kMagic{
    'B', 'T', 'X', 'C', 'R', 'C', '1', 0};
constexpr size_t kFixedHeaderBytes =
    kMagic.size() + 2 + 2 + 32;
constexpr size_t kChildHeaderBytes =
    2 + 2 + 32 + 32 + 32 + 32 + 32 + 4;

bool Fail(std::string* why, const std::string& message)
{
    if (why != nullptr) {
        *why =
            "stage3:canonical_role_child_attachment:" +
            message;
    }
    return false;
}

uint256 RegistryAuthorityRoot(
    const aqc::FrozenSpecAssessmentV1& assessment)
{
    return universal_topology::
        BuildProductionProgramConsensusPinV1(
            assessment.registry.diagnostic_registry)
        .recursive_alg_hash_root;
}

void PutU16(std::vector<unsigned char>& out, uint16_t value)
{
    out.push_back(static_cast<unsigned char>(value));
    out.push_back(static_cast<unsigned char>(value >> 8));
}

void PutU32(std::vector<unsigned char>& out, uint32_t value)
{
    for (uint32_t byte = 0; byte < 4; ++byte) {
        out.push_back(static_cast<unsigned char>(
            value >> (8U * byte)));
    }
}

class Reader {
public:
    explicit Reader(const std::vector<unsigned char>& bytes)
        : bytes_(bytes)
    {
    }

    bool Bytes(unsigned char* out, size_t count)
    {
        if (count > bytes_.size() - offset_) return false;
        std::copy_n(bytes_.data() + offset_, count, out);
        offset_ += count;
        return true;
    }

    bool Slice(size_t count, std::vector<unsigned char>& out)
    {
        if (count > bytes_.size() - offset_) return false;
        out.assign(
            bytes_.begin() + offset_,
            bytes_.begin() + offset_ + count);
        offset_ += count;
        return true;
    }

    bool U16(uint16_t& out)
    {
        unsigned char bytes[2];
        if (!Bytes(bytes, sizeof(bytes))) return false;
        out = uint16_t{bytes[0]} |
            (uint16_t{bytes[1]} << 8);
        return true;
    }

    bool U32(uint32_t& out)
    {
        unsigned char bytes[4];
        if (!Bytes(bytes, sizeof(bytes))) return false;
        out = uint32_t{bytes[0]} |
            (uint32_t{bytes[1]} << 8) |
            (uint32_t{bytes[2]} << 16) |
            (uint32_t{bytes[3]} << 24);
        return true;
    }

    bool Done() const { return offset_ == bytes_.size(); }

private:
    const std::vector<unsigned char>& bytes_;
    size_t offset_{0};
};

bool AssessmentCanSelectChildren(
    const aqc::FrozenSpecAssessmentV1& assessment,
    std::string* why)
{
    if (!assessment.block_dimensions_canonical ||
        !assessment.manifest_canonical ||
        !assessment.aggregation_schedule_canonical ||
        !assessment.registry_rebuilt_from_canonical_sources ||
        !assessment.consensus_registry_pin_matches ||
        !assessment.exact_endpoint_order ||
        !assessment.exact_endpoint_occurrence_schedule ||
        !assessment.exact_role_program_schedule ||
        !assessment.role_half_programs_available ||
        !assessment.role_half_shapes_available ||
        !assessment.public_output_abi_available ||
        !assessment.role_half_r0_schedules_available ||
        assessment.diagnostic_child_r0_base_columns[0]
            .empty() ||
        assessment.diagnostic_child_r0_base_columns[1]
            .empty() ||
        assessment.diagnostic_child_phase_commitment[0]
            .IsNull() ||
        assessment.diagnostic_child_phase_commitment[1]
            .IsNull() ||
        !aqc::ValidateDiagnosticRoleHalfAdapterV1(
            assessment,
            assessment.diagnostic_frozen_spec,
            why)) {
        return Fail(why, "assessment_not_canonical");
    }
    return true;
}

bool BuildEnvelopes(
    const aqc::FrozenSpecAssessmentV1& assessment,
    const std::array<
        aq::AirQuotientSplitRapRowsProof,
        kChildCountV1>& proofs,
    std::array<ChildEnvelopeV1, kChildCountV1>& out,
    std::string* why)
{
    for (uint16_t child = 0;
         child < kChildCountV1; ++child) {
        auto& envelope = out[child];
        envelope.version = kVersionV1;
        envelope.child_index = child;
        envelope.program_root =
            assessment.diagnostic_frozen_spec
                .child_registry[child].program_root;
        envelope.shape_commitment =
            u2::CommitPublicShapeV1(
                assessment.diagnostic_frozen_spec
                    .child_shape[child]);
        envelope.phase_commitment =
            assessment
                .diagnostic_child_phase_commitment[child];
        envelope.r0_base_column_indices =
            assessment
                .diagnostic_child_r0_base_columns[child];
        envelope.child_identity =
            ComputeChildIdentityV1(
                child, envelope.program_root,
                envelope.shape_commitment,
                envelope.phase_commitment,
                envelope.r0_base_column_indices);
        envelope.proof = proofs[child];
        if (envelope.program_root.IsNull() ||
            envelope.shape_commitment.IsNull() ||
            envelope.phase_commitment.IsNull() ||
            envelope.child_identity.IsNull() ||
            proofs[child].version !=
                aq::kAirQuotientSplitRapRowsSafeProofVersionV2 ||
            proofs[child].trace_rows !=
                assessment.diagnostic_frozen_spec
                    .child_shape[child].child_rows ||
            proofs[child].base_column_indices !=
                envelope.r0_base_column_indices ||
            aq::SerializeAirQuotientSplitRapRowsProof(
                proofs[child],
                envelope.proof_bytes) == 0) {
            return Fail(why, "proof_encode");
        }
        envelope.proof_root =
            ComputeChildProofRootV1(
                child, envelope.child_identity,
                envelope.proof_bytes);
        if (envelope.proof_root.IsNull()) {
            return Fail(why, "proof_root");
        }
    }
    return true;
}

bool SerializeEnvelopes(
    const uint256& registry_root,
    const std::array<ChildEnvelopeV1, kChildCountV1>& child,
    std::vector<unsigned char>& out,
    std::string* why)
{
    out.clear();
    const uint256 pair_root =
        ComputePairRootV1(registry_root, child);
    if (registry_root.IsNull() || pair_root.IsNull()) {
        return Fail(why, "pair_header");
    }
    uint64_t bytes =
        kFixedHeaderBytes + 32;
    for (const auto& envelope : child) {
        bytes += kChildHeaderBytes +
            envelope.proof_bytes.size();
    }
    if (bytes > kMaxAttachmentBytesV1 ||
        bytes > std::numeric_limits<uint32_t>::max()) {
        return Fail(why, "attachment_oversize");
    }
    out.reserve(static_cast<size_t>(bytes));
    out.insert(out.end(), kMagic.begin(), kMagic.end());
    PutU16(out, kVersionV1);
    PutU16(out, kChildCountV1);
    out.insert(
        out.end(),
        registry_root.begin(),
        registry_root.end());
    for (const auto& envelope : child) {
        if (envelope.version != kVersionV1 ||
            envelope.child_index >= kChildCountV1 ||
            envelope.program_root.IsNull() ||
            envelope.shape_commitment.IsNull() ||
            envelope.phase_commitment.IsNull() ||
            envelope.child_identity.IsNull() ||
            envelope.proof_root.IsNull() ||
            envelope.proof_bytes.empty() ||
            envelope.proof_bytes.size() >
                std::numeric_limits<uint32_t>::max()) {
            out.clear();
            return Fail(why, "child_header");
        }
        PutU16(out, envelope.child_index);
        PutU16(out, 0);
        out.insert(
            out.end(),
            envelope.program_root.begin(),
            envelope.program_root.end());
        out.insert(
            out.end(),
            envelope.shape_commitment.begin(),
            envelope.shape_commitment.end());
        out.insert(
            out.end(),
            envelope.phase_commitment.begin(),
            envelope.phase_commitment.end());
        out.insert(
            out.end(),
            envelope.child_identity.begin(),
            envelope.child_identity.end());
        out.insert(
            out.end(),
            envelope.proof_root.begin(),
            envelope.proof_root.end());
        PutU32(
            out,
            static_cast<uint32_t>(
                envelope.proof_bytes.size()));
        out.insert(
            out.end(),
            envelope.proof_bytes.begin(),
            envelope.proof_bytes.end());
    }
    out.insert(
        out.end(), pair_root.begin(), pair_root.end());
    return out.size() == bytes;
}

} // namespace

uint256 ComputeChildProofRootV1(
    uint16_t child_index,
    const uint256& child_identity,
    const std::vector<unsigned char>& canonical_proof_bytes)
{
    if (child_index >= kChildCountV1 ||
        child_identity.IsNull() ||
        canonical_proof_bytes.empty()) {
        return {};
    }
    HashWriter hash;
    hash << "BTX_RC_STAGE3_CANONICAL_ROLE_CHILD_PROOF_V1";
    hash << kVersionV1;
    hash << child_index;
    hash << child_identity;
    hash << canonical_proof_bytes;
    return hash.GetHash();
}

uint256 ComputeChildIdentityV1(
    uint16_t child_index,
    const uint256& program_root,
    const uint256& shape_commitment,
    const uint256& phase_commitment,
    const std::vector<uint32_t>&
        r0_base_column_indices)
{
    if (child_index >= kChildCountV1 ||
        program_root.IsNull() ||
        shape_commitment.IsNull() ||
        phase_commitment.IsNull() ||
        r0_base_column_indices.empty()) {
        return {};
    }
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_CANONICAL_ROLE_CHILD_IDENTITY_V2";
    hash << kVersionV1;
    hash << child_index;
    hash << program_root;
    hash << shape_commitment;
    hash << phase_commitment;
    hash << static_cast<uint32_t>(
        r0_base_column_indices.size());
    for (const uint32_t column :
         r0_base_column_indices) {
        hash << column;
    }
    return hash.GetHash();
}

uint256 ComputePairRootV1(
    const uint256& consensus_registry_root,
    const std::array<ChildEnvelopeV1, kChildCountV1>& child)
{
    if (consensus_registry_root.IsNull()) return {};
    HashWriter hash;
    hash << "BTX_RC_STAGE3_CANONICAL_ROLE_CHILD_PAIR_V1";
    hash << kVersionV1;
    hash << kChildCountV1;
    hash << consensus_registry_root;
    for (uint16_t index = 0;
         index < kChildCountV1; ++index) {
        const auto& envelope = child[index];
        if (envelope.version != kVersionV1 ||
            envelope.child_index != index ||
            envelope.program_root.IsNull() ||
            envelope.shape_commitment.IsNull() ||
            envelope.phase_commitment.IsNull() ||
            envelope.child_identity.IsNull() ||
            envelope.proof_root.IsNull()) {
            return {};
        }
        hash << envelope.child_index;
        hash << envelope.program_root;
        hash << envelope.shape_commitment;
        hash << envelope.phase_commitment;
        hash << envelope.child_identity;
        hash << envelope.proof_root;
    }
    return hash.GetHash();
}

bool SerializeAgainstAssessmentV1(
    const aqc::FrozenSpecAssessmentV1& assessment,
    const std::array<
        aq::AirQuotientSplitRapRowsProof,
        kChildCountV1>& proofs,
    std::vector<unsigned char>& out,
    std::string* why)
{
    out.clear();
    if (!AssessmentCanSelectChildren(assessment, why)) {
        return false;
    }
    std::array<ChildEnvelopeV1, kChildCountV1> child;
    if (!BuildEnvelopes(
            assessment, proofs, child, why)) {
        return false;
    }
    return SerializeEnvelopes(
        RegistryAuthorityRoot(assessment),
        child, out, why);
}

bool DecodeAgainstAssessmentV1(
    const aqc::FrozenSpecAssessmentV1& assessment,
    const std::vector<unsigned char>& encoded,
    ValidatedPairV1& out,
    std::string* why)
{
    out = {};
    if (encoded.size() > kMaxAttachmentBytesV1 ||
        encoded.size() <
            kFixedHeaderBytes +
            kChildCountV1 * kChildHeaderBytes +
            32 ||
        !AssessmentCanSelectChildren(
            assessment, why)) {
        return Fail(why, "decode_prerequisites");
    }
    Reader reader(encoded);
    std::array<unsigned char, kMagic.size()> magic{};
    uint16_t version = 0;
    uint16_t count = 0;
    if (!reader.Bytes(magic.data(), magic.size()) ||
        magic != kMagic ||
        !reader.U16(version) ||
        version != kVersionV1 ||
        !reader.U16(count) ||
        count != kChildCountV1 ||
        !reader.Bytes(
            out.consensus_registry_root.data(),
            out.consensus_registry_root.size())) {
        return Fail(why, "decode_header");
    }
    out.exact_child_count = true;
    const uint256 expected_registry =
        RegistryAuthorityRoot(assessment);
    if (out.consensus_registry_root.IsNull() ||
        out.consensus_registry_root != expected_registry) {
        out = {};
        return Fail(why, "registry_root_substitution");
    }
    out.registry_root_verified = true;

    for (uint16_t expected = 0;
         expected < kChildCountV1; ++expected) {
        ChildEnvelopeV1 envelope;
        uint16_t reserved = 0;
        uint32_t proof_len = 0;
        if (!reader.U16(envelope.child_index) ||
            !reader.U16(reserved) ||
            reserved != 0 ||
            envelope.child_index != expected ||
            !reader.Bytes(
                envelope.program_root.data(),
                envelope.program_root.size()) ||
            !reader.Bytes(
                envelope.shape_commitment.data(),
                envelope.shape_commitment.size()) ||
            !reader.Bytes(
                envelope.phase_commitment.data(),
                envelope.phase_commitment.size()) ||
            !reader.Bytes(
                envelope.child_identity.data(),
                envelope.child_identity.size()) ||
            !reader.Bytes(
                envelope.proof_root.data(),
                envelope.proof_root.size()) ||
            !reader.U32(proof_len) ||
            proof_len == 0 ||
            proof_len >
                aq::kAirQuotientSplitRapRowsMaxProofBytesHard ||
            !reader.Slice(
                proof_len,
                envelope.proof_bytes)) {
            out = {};
            return Fail(why, "decode_child");
        }
        envelope.version = kVersionV1;
        const uint256 expected_program =
            assessment.diagnostic_frozen_spec
                .child_registry[expected].program_root;
        const uint256 expected_shape =
            u2::CommitPublicShapeV1(
                assessment.diagnostic_frozen_spec
                    .child_shape[expected]);
        const uint256 expected_phase =
            assessment
                .diagnostic_child_phase_commitment[expected];
        envelope.r0_base_column_indices =
            assessment
                .diagnostic_child_r0_base_columns[expected];
        const uint256 expected_identity =
            ComputeChildIdentityV1(
                expected, expected_program,
                expected_shape, expected_phase,
                envelope.r0_base_column_indices);
        if (envelope.program_root != expected_program ||
            envelope.shape_commitment != expected_shape ||
            envelope.phase_commitment != expected_phase ||
            envelope.child_identity != expected_identity) {
            out = {};
            return Fail(why, "child_spec_substitution");
        }
        const uint256 expected_proof_root =
            ComputeChildProofRootV1(
                expected, expected_identity,
                envelope.proof_bytes);
        if (envelope.proof_root.IsNull() ||
            envelope.proof_root != expected_proof_root) {
            out = {};
            return Fail(why, "child_proof_root");
        }
        auto proof =
            aq::DeserializeAirQuotientSplitRapRowsProof(
                envelope.proof_bytes);
        if (!proof.has_value()) {
            out = {};
            return Fail(why, "child_proof_codec");
        }
        std::vector<unsigned char> canonical;
        if (aq::SerializeAirQuotientSplitRapRowsProof(
                *proof, canonical) == 0 ||
            canonical != envelope.proof_bytes) {
            out = {};
            return Fail(
                why, "child_proof_noncanonical");
        }
        if (proof->version !=
                aq::kAirQuotientSplitRapRowsSafeProofVersionV2 ||
            proof->trace_rows !=
                assessment.diagnostic_frozen_spec
                    .child_shape[expected].child_rows ||
            proof->base_column_indices !=
                envelope.r0_base_column_indices) {
            out = {};
            return Fail(
                why, "child_r0_schedule_substitution");
        }
        envelope.proof = std::move(*proof);
        out.child[expected] = std::move(envelope);
    }
    uint256 encoded_pair_root;
    if (!reader.Bytes(
            encoded_pair_root.data(),
            encoded_pair_root.size()) ||
        !reader.Done()) {
        out = {};
        return Fail(why, "trailing_or_truncated");
    }
    out.pair_root =
        ComputePairRootV1(
            out.consensus_registry_root,
            out.child);
    if (out.pair_root.IsNull() ||
        encoded_pair_root != out.pair_root) {
        out = {};
        return Fail(why, "pair_root");
    }

    out.version = kVersionV1;
    out.assessment = assessment;
    out.frozen_spec =
        assessment.diagnostic_frozen_spec;
    out.canonical_child_order = true;
    out.program_roots_reconstructed = true;
    out.shapes_reconstructed = true;
    out.r0_schedules_reconstructed = true;
    out.phase_commitments_verified = true;
    out.child_identities_verified = true;
    out.proof_codecs_canonical = true;
    out.proof_roots_verified = true;
    out.pair_root_verified = true;
    // The transport now carries the right SAFE Split-RAP V2 proof type and
    // binds its manifest-derived phase split. Native child verification still
    // belongs to the parent because only that layer owns the statement-derived
    // child seed and complete public-output vector.
    out.native_child_proofs_verified = false;
    out.parent_consumption_compatible = false;
    out.valid = true;
    out.note =
        "stage3:canonical_role_child_attachment:"
        "canonical_pair_valid;"
        "native_acceptance_open:"
        "native_acceptance_requires_parent_child_seed_and_output_binding";
    if (why != nullptr) *why = out.note;
    return true;
}

bool VerifyNativeChildProofV1(
    const constraint_bytecode::ProgramTable& program,
    uint32_t expected_trace_rows,
    const std::vector<uint32_t>&
        expected_r0_base_column_indices,
    const uint256& expected_public_fs_seed,
    const aq::AirQuotientSplitRapRowsProof& proof,
    std::string* why)
{
    namespace rfp = recursive_fixedpoint;
    if (expected_trace_rows < 2 ||
        expected_r0_base_column_indices.empty() ||
        expected_public_fs_seed.IsNull() ||
        proof.version !=
            aq::kAirQuotientSplitRapRowsSafeProofVersionV2 ||
        proof.trace_rows != expected_trace_rows ||
        proof.base_column_indices !=
            expected_r0_base_column_indices ||
        constraint_bytecode::CommitProgramTable(program)
            .IsNull()) {
        return Fail(why, "native_child_prerequisites");
    }
    rfp::BytecodeChallengeTranscriptV1 transcript;
    if (!rfp::BuildBytecodeChallengeTranscriptV1(
            program, proof,
            expected_r0_base_column_indices,
            expected_public_fs_seed,
            transcript, why) ||
        !transcript.valid ||
        !transcript.safe_split_rap_statement_verified ||
        !transcript.exact_p2_replay ||
        transcript.public_fs_seed !=
            expected_public_fs_seed ||
        transcript.program_commitment !=
            constraint_bytecode::CommitProgramTable(program) ||
        transcript.base_column_indices !=
            expected_r0_base_column_indices) {
        return Fail(why, "native_child_verify");
    }
    if (why != nullptr) {
        *why =
            "stage3:canonical_role_child_attachment:"
            "native_safe_v2_child_verified";
    }
    return true;
}

bool VerifyNativeChildPairV1(
    const aqc::FrozenSpecAssessmentV1& assessment,
    const std::array<uint256, kChildCountV1>&
        expected_child_fs_seed,
    ValidatedPairV1& pair,
    std::string* why)
{
    pair.native_child_proofs_verified = false;
    pair.parent_consumption_compatible = false;
    if (!pair.valid ||
        !pair.registry_root_verified ||
        !pair.program_roots_reconstructed ||
        !pair.shapes_reconstructed ||
        !pair.r0_schedules_reconstructed ||
        !pair.phase_commitments_verified ||
        !pair.child_identities_verified ||
        !pair.proof_codecs_canonical ||
        !pair.proof_roots_verified ||
        !pair.pair_root_verified ||
        !AssessmentCanSelectChildren(
            assessment, why) ||
        expected_child_fs_seed[0].IsNull() ||
        expected_child_fs_seed[1].IsNull() ||
        pair.consensus_registry_root !=
            RegistryAuthorityRoot(assessment)) {
        return Fail(why, "native_pair_prerequisites");
    }
    for (uint16_t child = 0;
         child < kChildCountV1; ++child) {
        const auto& expected_program =
            assessment.diagnostic_frozen_spec
                .child_registry[child]
                .child_relation_program;
        const uint256 expected_program_root =
            assessment.diagnostic_frozen_spec
                .child_registry[child].program_root;
        const uint256 expected_shape =
            u2::CommitPublicShapeV1(
                assessment.diagnostic_frozen_spec
                    .child_shape[child]);
        const uint256 expected_phase =
            assessment
                .diagnostic_child_phase_commitment[child];
        const auto& expected_r0 =
            assessment
                .diagnostic_child_r0_base_columns[child];
        auto& envelope = pair.child[child];
        const uint256 expected_identity =
            ComputeChildIdentityV1(
                child, expected_program_root,
                expected_shape, expected_phase,
                expected_r0);
        std::vector<unsigned char> canonical_proof;
        if (envelope.version != kVersionV1 ||
            envelope.child_index != child ||
            envelope.program_root !=
                expected_program_root ||
            constraint_bytecode::CommitProgramTable(
                expected_program) !=
                expected_program_root ||
            envelope.shape_commitment !=
                expected_shape ||
            envelope.phase_commitment !=
                expected_phase ||
            envelope.r0_base_column_indices !=
                expected_r0 ||
            envelope.child_identity !=
                expected_identity ||
            aq::SerializeAirQuotientSplitRapRowsProof(
                envelope.proof,
                canonical_proof) == 0 ||
            canonical_proof != envelope.proof_bytes ||
            envelope.proof_root !=
                ComputeChildProofRootV1(
                    child, expected_identity,
                    canonical_proof) ||
            !VerifyNativeChildProofV1(
                expected_program,
                assessment.diagnostic_frozen_spec
                    .child_shape[child].child_rows,
                expected_r0,
                expected_child_fs_seed[child],
                envelope.proof, why)) {
            return Fail(
                why, "native_pair_child_" +
                    std::to_string(child));
        }
    }
    pair.native_child_proofs_verified = true;
    pair.note =
        "stage3:canonical_role_child_attachment:"
        "native_safe_v2_pair_verified;"
        "parent_consumption_open";
    if (why != nullptr) *why = pair.note;
    return true;
}

bool DecodeAndValidateV1(
    const CBlock& block,
    const Consensus::Params& params,
    int32_t height,
    const std::vector<unsigned char>& encoded,
    ValidatedPairV1& out,
    std::string* why)
{
    const aqc::FrozenSpecAssessmentV1 assessment =
        aqc::AssessFrozenBinaryParentSpecV1(
            block, params, height);
    return DecodeAgainstAssessmentV1(
        assessment, encoded, out, why);
}

} // namespace matmul::v4::rc::canonical_role_child_attachment
