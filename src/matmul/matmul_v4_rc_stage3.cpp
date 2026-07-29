// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3.h>

#include <algorithm>
#include <array>
#include <limits>

namespace matmul::v4::rc {
namespace {

constexpr std::array<RCStage3RelationRole, 6> EPISODE_ROLES{
    RCStage3RelationRole::EpisodeDeterministicBuilder,
    RCStage3RelationRole::EpisodeGemm,
    RCStage3RelationRole::EpisodeExtract,
    RCStage3RelationRole::EpisodeWiring,
    RCStage3RelationRole::EpisodeTileTree,
    RCStage3RelationRole::EpisodeDigest,
};

constexpr std::array<RCStage3RelationRole, 8> COUPLED_ROLES{
    RCStage3RelationRole::CoupledBank,
    RCStage3RelationRole::CoupledGemm,
    RCStage3RelationRole::CoupledExchange,
    RCStage3RelationRole::CoupledPermutation,
    RCStage3RelationRole::CoupledMix,
    RCStage3RelationRole::CoupledExtract,
    RCStage3RelationRole::CoupledBarrier,
    RCStage3RelationRole::CoupledDigest,
};

bool Fail(std::string* why, const std::string& message)
{
    if (why != nullptr) *why = "stage3:" + message;
    return false;
}

void WriteU8(std::vector<unsigned char>& out, uint8_t v) { out.push_back(v); }

void WriteU16(std::vector<unsigned char>& out, uint16_t v)
{
    out.push_back(static_cast<unsigned char>(v));
    out.push_back(static_cast<unsigned char>(v >> 8));
}

void WriteU32(std::vector<unsigned char>& out, uint32_t v)
{
    for (unsigned i = 0; i < 4; ++i) out.push_back(static_cast<unsigned char>(v >> (8 * i)));
}

void WriteUint256(std::vector<unsigned char>& out, const uint256& v)
{
    out.insert(out.end(), v.data(), v.data() + v.size());
}

class Reader {
public:
    explicit Reader(const std::vector<unsigned char>& bytes) : m_bytes(bytes) {}

    bool ReadU8(uint8_t& out)
    {
        if (Remaining() < 1) return false;
        out = m_bytes[m_pos++];
        return true;
    }

    bool ReadU16(uint16_t& out)
    {
        if (Remaining() < 2) return false;
        out = static_cast<uint16_t>(m_bytes[m_pos]) |
              (static_cast<uint16_t>(m_bytes[m_pos + 1]) << 8);
        m_pos += 2;
        return true;
    }

    bool ReadU32(uint32_t& out)
    {
        if (Remaining() < 4) return false;
        out = 0;
        for (unsigned i = 0; i < 4; ++i) {
            out |= static_cast<uint32_t>(m_bytes[m_pos + i]) << (8 * i);
        }
        m_pos += 4;
        return true;
    }

    bool ReadUint256(uint256& out)
    {
        if (Remaining() < out.size()) return false;
        std::copy_n(m_bytes.data() + m_pos, out.size(), out.data());
        m_pos += out.size();
        return true;
    }

    bool ReadBytes(size_t count, std::vector<unsigned char>& out)
    {
        if (count > Remaining()) return false;
        out.assign(m_bytes.begin() + m_pos, m_bytes.begin() + m_pos + count);
        m_pos += count;
        return true;
    }

    [[nodiscard]] size_t Remaining() const { return m_bytes.size() - m_pos; }

private:
    const std::vector<unsigned char>& m_bytes;
    size_t m_pos{0};
};

bool KnownAuthority(RCProofAuthority authority)
{
    return authority == RCProofAuthority::ExactReplay ||
           authority == RCProofAuthority::SampledPrefilter ||
           authority == RCProofAuthority::SuccinctV1;
}

bool KnownStatement(RCStage3StatementKind statement)
{
    return statement == RCStage3StatementKind::Episode ||
           statement == RCStage3StatementKind::Coupled ||
           statement == RCStage3StatementKind::Composed;
}

bool KnownRole(RCStage3RelationRole role)
{
    const auto all = RequiredRCStage3RelationRoles(RCStage3StatementKind::Composed);
    return std::find(all.begin(), all.end(), role) != all.end();
}

bool IsCanonicalProgramAlgHashRoot(const uint256& root)
{
    // Four canonical little-endian Goldilocks limbs. Keep the constant local
    // to the consensus codec so this foundational envelope does not depend on
    // a particular prover implementation.
    static constexpr uint64_t GOLDILOCKS_P{0xFFFFFFFF00000001ULL};
    if (root.IsNull()) return false;
    for (size_t limb_index = 0; limb_index < 4; ++limb_index) {
        uint64_t limb{0};
        for (size_t byte_index = 0; byte_index < 8; ++byte_index) {
            limb |= static_cast<uint64_t>(
                        root.data()[8 * limb_index + byte_index])
                    << (8 * byte_index);
        }
        if (limb >= GOLDILOCKS_P) return false;
    }
    return true;
}

} // namespace

std::vector<RCStage3RelationRole>
RequiredRCStage3RelationRoles(RCStage3StatementKind statement)
{
    std::vector<RCStage3RelationRole> out;
    if (statement == RCStage3StatementKind::Episode ||
        statement == RCStage3StatementKind::Composed) {
        out.insert(out.end(), EPISODE_ROLES.begin(), EPISODE_ROLES.end());
    }
    if (statement == RCStage3StatementKind::Coupled ||
        statement == RCStage3StatementKind::Composed) {
        out.insert(out.end(), COUPLED_ROLES.begin(), COUPLED_ROLES.end());
    }
    if (statement == RCStage3StatementKind::Composed) {
        out.push_back(RCStage3RelationRole::CompositionLink);
    }
    return out;
}

const char* RCStage3RelationRoleName(RCStage3RelationRole role)
{
    switch (role) {
    case RCStage3RelationRole::EpisodeDeterministicBuilder: return "episode:builder";
    case RCStage3RelationRole::EpisodeGemm: return "episode:gemm";
    case RCStage3RelationRole::EpisodeExtract: return "episode:extract";
    case RCStage3RelationRole::EpisodeWiring: return "episode:wiring";
    case RCStage3RelationRole::EpisodeTileTree: return "episode:tiletree";
    case RCStage3RelationRole::EpisodeDigest: return "episode:digest";
    case RCStage3RelationRole::CoupledBank: return "coupled:bank";
    case RCStage3RelationRole::CoupledGemm: return "coupled:gemm";
    case RCStage3RelationRole::CoupledExchange: return "coupled:exchange";
    case RCStage3RelationRole::CoupledPermutation: return "coupled:permutation";
    case RCStage3RelationRole::CoupledMix: return "coupled:mix";
    case RCStage3RelationRole::CoupledExtract: return "coupled:extract";
    case RCStage3RelationRole::CoupledBarrier: return "coupled:barrier";
    case RCStage3RelationRole::CoupledDigest: return "coupled:digest";
    case RCStage3RelationRole::CompositionLink: return "composition:link";
    }
    return "unknown";
}

bool ValidateProductionProgramConsensusPinV1(
    const ProductionProgramConsensusPinV1& pin,
    std::string* why)
{
    if (pin.version != kProductionProgramConsensusPinVersionV1) {
        return Fail(why, "program_pin_version");
    }
    if (!IsCanonicalProgramAlgHashRoot(pin.recursive_alg_hash_root)) {
        return Fail(why, "program_pin_alg_hash_root");
    }
    if (pin.external_sha256d_audit_root.IsNull()) {
        return Fail(why, "program_pin_sha256d_audit_root");
    }
    if (pin.registry_binding.IsNull()) {
        return Fail(why, "program_pin_registry_binding");
    }
    return true;
}

bool ValidateRCStage3ProofStructure(const RCStage3SuccinctProof& proof, std::string* why)
{
    if (proof.magic != kRCStage3ProofMagic) return Fail(why, "bad_magic");
    if (proof.version != kRCStage3ProofVersion) return Fail(why, "bad_version");
    if (!KnownAuthority(proof.authority)) return Fail(why, "unknown_authority");
    if (proof.authority != RCProofAuthority::SuccinctV1) {
        return Fail(why, "non_succinct_authority");
    }
    if (!KnownStatement(proof.statement)) return Fail(why, "unknown_statement");

    const auto& p = proof.public_inputs;
    if (p.height < 0) return Fail(why, "negative_height");
    if (p.n_bits == 0) return Fail(why, "zero_nbits");
    if (p.header_commitment.IsNull()) return Fail(why, "null_header_commitment");
    if (p.params_commitment.IsNull()) return Fail(why, "null_params_commitment");
    if (!ValidateProductionProgramConsensusPinV1(
            p.program_consensus_pin, why)) return false;
    if (p.target.IsNull()) return Fail(why, "null_target");
    if (p.sigma.IsNull()) return Fail(why, "null_sigma");
    if (p.final_digest.IsNull()) return Fail(why, "null_final_digest");
    if (p.transcript_commitment.IsNull()) return Fail(why, "null_transcript_commitment");

    if (proof.statement == RCStage3StatementKind::Episode) {
        if (p.episode_profile == 0 || p.episode_digest.IsNull()) {
            return Fail(why, "missing_episode_public_input");
        }
        if (p.coupled_profile != 0 || !p.coupled_digest.IsNull()) {
            return Fail(why, "unexpected_coupled_public_input");
        }
    } else if (proof.statement == RCStage3StatementKind::Coupled) {
        if (p.coupled_profile == 0 || p.coupled_digest.IsNull()) {
            return Fail(why, "missing_coupled_public_input");
        }
        if (p.episode_profile != 0 || !p.episode_digest.IsNull()) {
            return Fail(why, "unexpected_episode_public_input");
        }
    } else {
        if (p.episode_profile == 0 || p.coupled_profile == 0 ||
            p.episode_digest.IsNull() || p.coupled_digest.IsNull()) {
            return Fail(why, "missing_composed_public_input");
        }
    }

    const auto required = RequiredRCStage3RelationRoles(proof.statement);
    if (required.empty() || required.size() > kRCStage3MaxRelationSections) {
        return Fail(why, "bad_required_role_registry");
    }
    if (proof.commitments.size() != required.size()) {
        return Fail(why, "commitment_role_count");
    }
    if (proof.sections.size() != required.size()) return Fail(why, "section_role_count");

    size_t proof_bytes = 0;
    for (size_t i = 0; i < required.size(); ++i) {
        if (!KnownRole(proof.commitments[i].role) ||
            proof.commitments[i].role != required[i]) {
            return Fail(why, "commitment_role_order");
        }
        if (proof.commitments[i].root.IsNull()) return Fail(why, "null_commitment_root");
        if (!KnownRole(proof.sections[i].role) || proof.sections[i].role != required[i]) {
            return Fail(why, "section_role_order");
        }
        if (proof.sections[i].proof.empty()) return Fail(why, "empty_relation_proof");
        if (proof.sections[i].proof.size() > kRCStage3MaxProofBytes - proof_bytes) {
            return Fail(why, "relation_proofs_oversize");
        }
        proof_bytes += proof.sections[i].proof.size();
    }
    return true;
}

bool SerializeRCStage3Proof(const RCStage3SuccinctProof& proof,
                            std::vector<unsigned char>& out,
                            std::string* why)
{
    out.clear();
    if (!ValidateRCStage3ProofStructure(proof, why)) return false;

    WriteU32(out, proof.magic);
    WriteU16(out, proof.version);
    WriteU8(out, static_cast<uint8_t>(proof.authority));
    WriteU8(out, static_cast<uint8_t>(proof.statement));

    const auto& p = proof.public_inputs;
    WriteU32(out, static_cast<uint32_t>(p.height));
    WriteU32(out, p.n_bits);
    WriteU32(out, p.episode_profile);
    WriteU32(out, p.coupled_profile);
    WriteU32(out, p.transcript_version);
    WriteU16(out, p.program_consensus_pin.version);
    WriteU16(out, 0); // reserved, must remain zero
    WriteUint256(out, p.program_consensus_pin.recursive_alg_hash_root);
    WriteUint256(out, p.program_consensus_pin.external_sha256d_audit_root);
    WriteUint256(out, p.program_consensus_pin.registry_binding);
    WriteUint256(out, p.header_commitment);
    WriteUint256(out, p.params_commitment);
    WriteUint256(out, p.target);
    WriteUint256(out, p.sigma);
    WriteUint256(out, p.episode_digest);
    WriteUint256(out, p.coupled_digest);
    WriteUint256(out, p.final_digest);
    WriteUint256(out, p.transcript_commitment);

    WriteU16(out, static_cast<uint16_t>(proof.commitments.size()));
    for (const auto& commitment : proof.commitments) {
        WriteU16(out, static_cast<uint16_t>(commitment.role));
        WriteUint256(out, commitment.root);
    }

    WriteU16(out, static_cast<uint16_t>(proof.sections.size()));
    for (const auto& section : proof.sections) {
        WriteU16(out, static_cast<uint16_t>(section.role));
        WriteU32(out, static_cast<uint32_t>(section.proof.size()));
        out.insert(out.end(), section.proof.begin(), section.proof.end());
    }

    if (out.size() > kRCStage3MaxProofBytes) {
        out.clear();
        return Fail(why, "serialized_oversize");
    }
    return true;
}

std::optional<RCStage3SuccinctProof>
DeserializeRCStage3Proof(const std::vector<unsigned char>& bytes, std::string* why)
{
    if (bytes.empty()) {
        Fail(why, "empty");
        return std::nullopt;
    }
    if (bytes.size() > kRCStage3MaxProofBytes) {
        Fail(why, "serialized_oversize");
        return std::nullopt;
    }

    Reader r(bytes);
    RCStage3SuccinctProof proof;
    uint8_t authority{0};
    uint8_t statement{0};
    uint32_t height{0};
    if (!r.ReadU32(proof.magic) || !r.ReadU16(proof.version) ||
        !r.ReadU8(authority) || !r.ReadU8(statement) || !r.ReadU32(height) ||
        !r.ReadU32(proof.public_inputs.n_bits) ||
        !r.ReadU32(proof.public_inputs.episode_profile) ||
        !r.ReadU32(proof.public_inputs.coupled_profile) ||
        !r.ReadU32(proof.public_inputs.transcript_version)) {
        Fail(why, "truncated_header");
        return std::nullopt;
    }
    if (height > static_cast<uint32_t>(std::numeric_limits<int32_t>::max())) {
        Fail(why, "height_overflow");
        return std::nullopt;
    }
    proof.public_inputs.height = static_cast<int32_t>(height);
    proof.authority = static_cast<RCProofAuthority>(authority);
    proof.statement = static_cast<RCStage3StatementKind>(statement);
    if (proof.version != kRCStage3ProofVersion) {
        Fail(why, "bad_version");
        return std::nullopt;
    }
    if (!KnownAuthority(proof.authority) || !KnownStatement(proof.statement)) {
        Fail(why, "unknown_enum");
        return std::nullopt;
    }

    auto& p = proof.public_inputs;
    uint16_t program_pin_reserved{0};
    if (!r.ReadU16(p.program_consensus_pin.version) ||
        !r.ReadU16(program_pin_reserved) ||
        !r.ReadUint256(p.program_consensus_pin.recursive_alg_hash_root) ||
        !r.ReadUint256(p.program_consensus_pin.external_sha256d_audit_root) ||
        !r.ReadUint256(p.program_consensus_pin.registry_binding)) {
        Fail(why, "truncated_program_pin");
        return std::nullopt;
    }
    if (program_pin_reserved != 0) {
        Fail(why, "nonzero_program_pin_reserved");
        return std::nullopt;
    }
    if (!r.ReadUint256(p.header_commitment) || !r.ReadUint256(p.params_commitment) ||
        !r.ReadUint256(p.target) || !r.ReadUint256(p.sigma) ||
        !r.ReadUint256(p.episode_digest) || !r.ReadUint256(p.coupled_digest) ||
        !r.ReadUint256(p.final_digest) || !r.ReadUint256(p.transcript_commitment)) {
        Fail(why, "truncated_public_inputs");
        return std::nullopt;
    }

    uint16_t n_commitments{0};
    if (!r.ReadU16(n_commitments) || n_commitments == 0 ||
        n_commitments > kRCStage3MaxRelationSections) {
        Fail(why, "bad_commitment_count");
        return std::nullopt;
    }
    proof.commitments.reserve(n_commitments);
    for (uint16_t i = 0; i < n_commitments; ++i) {
        uint16_t raw_role{0};
        RCStage3Commitment commitment;
        if (!r.ReadU16(raw_role) || !r.ReadUint256(commitment.root)) {
            Fail(why, "truncated_commitment");
            return std::nullopt;
        }
        commitment.role = static_cast<RCStage3RelationRole>(raw_role);
        if (!KnownRole(commitment.role)) {
            Fail(why, "unknown_commitment_role");
            return std::nullopt;
        }
        proof.commitments.push_back(std::move(commitment));
    }

    uint16_t n_sections{0};
    if (!r.ReadU16(n_sections) || n_sections == 0 ||
        n_sections > kRCStage3MaxRelationSections) {
        Fail(why, "bad_section_count");
        return std::nullopt;
    }
    proof.sections.reserve(n_sections);
    size_t relation_bytes{0};
    for (uint16_t i = 0; i < n_sections; ++i) {
        uint16_t raw_role{0};
        uint32_t section_size{0};
        RCStage3ProofSection section;
        if (!r.ReadU16(raw_role) || !r.ReadU32(section_size)) {
            Fail(why, "truncated_section_header");
            return std::nullopt;
        }
        section.role = static_cast<RCStage3RelationRole>(raw_role);
        if (!KnownRole(section.role)) {
            Fail(why, "unknown_section_role");
            return std::nullopt;
        }
        if (section_size == 0 || section_size > kRCStage3MaxProofBytes - relation_bytes) {
            Fail(why, "bad_section_size");
            return std::nullopt;
        }
        if (!r.ReadBytes(section_size, section.proof)) {
            Fail(why, "truncated_section");
            return std::nullopt;
        }
        relation_bytes += section_size;
        proof.sections.push_back(std::move(section));
    }

    if (r.Remaining() != 0) {
        Fail(why, "trailing_bytes");
        return std::nullopt;
    }
    if (!ValidateRCStage3ProofStructure(proof, why)) return std::nullopt;
    return proof;
}

bool PackRCStage3ProofWords(const RCStage3SuccinctProof& proof,
                            std::vector<uint32_t>& out,
                            std::string* why)
{
    std::vector<unsigned char> bytes;
    if (!SerializeRCStage3Proof(proof, bytes, why)) {
        out.clear();
        return false;
    }
    if (bytes.size() > std::numeric_limits<uint32_t>::max()) {
        out.clear();
        return Fail(why, "word_length_overflow");
    }

    const size_t payload_words = (bytes.size() + 3) / 4;
    out.assign(2 + payload_words, 0);
    out[0] = kRCStage3BlockPayloadMagic;
    out[1] = static_cast<uint32_t>(bytes.size());
    for (size_t i = 0; i < bytes.size(); ++i) {
        out[2 + i / 4] |= static_cast<uint32_t>(bytes[i]) << (8 * (i % 4));
    }
    return true;
}

std::optional<RCStage3SuccinctProof>
UnpackRCStage3ProofWords(const std::vector<uint32_t>& words, std::string* why)
{
    if (words.size() < 3 || words[0] != kRCStage3BlockPayloadMagic) {
        Fail(why, "bad_word_envelope");
        return std::nullopt;
    }
    const size_t byte_len = words[1];
    if (byte_len == 0 || byte_len > kRCStage3MaxProofBytes) {
        Fail(why, "bad_word_byte_length");
        return std::nullopt;
    }
    const size_t expected_words = 2 + (byte_len + 3) / 4;
    if (words.size() != expected_words) {
        Fail(why, "noncanonical_word_count");
        return std::nullopt;
    }

    std::vector<unsigned char> bytes(byte_len);
    for (size_t i = 0; i < byte_len; ++i) {
        bytes[i] = static_cast<unsigned char>(words[2 + i / 4] >> (8 * (i % 4)));
    }
    const size_t used_last_bytes = byte_len % 4;
    if (used_last_bytes != 0) {
        const uint32_t used_mask = (uint32_t{1} << (8 * used_last_bytes)) - 1;
        if ((words.back() & ~used_mask) != 0) {
            Fail(why, "nonzero_word_padding");
            return std::nullopt;
        }
    }
    return DeserializeRCStage3Proof(bytes, why);
}

bool IsRCStage3ProofWords(const std::vector<uint32_t>& words)
{
    return words.size() >= 3 && words[0] == kRCStage3BlockPayloadMagic;
}

} // namespace matmul::v4::rc
