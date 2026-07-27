// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_coupled.h>

#include <crypto/sha256.h>
#include <matmul/matmul_v4_rc_stage3_recursive.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>

namespace matmul::v4::rc {
namespace {

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
    if (why != nullptr) *why = "stage3:coupled:" + message;
    return false;
}

template <typename T>
std::optional<T> FailOptional(std::string* why, const std::string& message)
{
    Fail(why, message);
    return std::nullopt;
}

bool IsCoupledRole(RCStage3RelationRole role)
{
    return std::find(COUPLED_ROLES.begin(), COUPLED_ROLES.end(), role) !=
           COUPLED_ROLES.end();
}

bool CheckedMul(uint64_t a, uint64_t b, uint64_t& out)
{
    if (a != 0 && b > std::numeric_limits<uint64_t>::max() / a) return false;
    out = a * b;
    return true;
}

bool CheckedAdd(uint64_t a, uint64_t b, uint64_t& out)
{
    if (b > std::numeric_limits<uint64_t>::max() - a) return false;
    out = a + b;
    return true;
}

void WriteU8(std::vector<unsigned char>& out, uint8_t value)
{
    out.push_back(value);
}

void WriteU16(std::vector<unsigned char>& out, uint16_t value)
{
    out.push_back(static_cast<unsigned char>(value));
    out.push_back(static_cast<unsigned char>(value >> 8));
}

void WriteU32(std::vector<unsigned char>& out, uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i) {
        out.push_back(static_cast<unsigned char>(value >> (8 * i)));
    }
}

void WriteU64(std::vector<unsigned char>& out, uint64_t value)
{
    for (unsigned i = 0; i < 8; ++i) {
        out.push_back(static_cast<unsigned char>(value >> (8 * i)));
    }
}

void WriteUint256(std::vector<unsigned char>& out, const uint256& value)
{
    out.insert(out.end(), value.begin(), value.end());
}

void WriteShape(std::vector<unsigned char>& out, const RCStage3CoupledShape& shape)
{
    WriteU32(out, shape.barriers);
    WriteU32(out, shape.lobes);
    WriteU32(out, shape.lobe_width);
    WriteU32(out, shape.bank_pages);
    WriteU32(out, shape.rows_per_lobe);
    WriteU32(out, shape.pages_per_barrier_lobe);
    WriteU32(out, shape.transcript_version);
    WriteU8(out, shape.full_bank_schedule ? 1 : 0);
    WriteU8(out, shape.material_exchange ? 1 : 0);
    WriteU8(out, shape.force_signed_mix ? 1 : 0);
    WriteU8(out, 0); // reserved; canonical zero
    WriteU32(out, shape.exchange_rows);
    WriteU32(out, shape.exchange_rounds);
}

uint256 Sha256d(const std::vector<unsigned char>& bytes)
{
    uint8_t first[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(bytes.data(), bytes.size()).Finalize(first);
    uint8_t second[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(first, sizeof(first)).Finalize(second);
    uint256 result;
    std::memcpy(result.data(), second, result.size());
    return result;
}

void WriteDomain(std::vector<unsigned char>& out, const char* domain)
{
    out.insert(out.end(), reinterpret_cast<const unsigned char*>(domain),
               reinterpret_cast<const unsigned char*>(domain) + std::strlen(domain));
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

    bool ReadBool(bool& out)
    {
        uint8_t value{0};
        if (!ReadU8(value) || value > 1) return false;
        out = value != 0;
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

    bool ReadU64(uint64_t& out)
    {
        if (Remaining() < 8) return false;
        out = 0;
        for (unsigned i = 0; i < 8; ++i) {
            out |= static_cast<uint64_t>(m_bytes[m_pos + i]) << (8 * i);
        }
        m_pos += 8;
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

bool ReadShape(Reader& reader, RCStage3CoupledShape& shape)
{
    uint8_t reserved{0};
    return reader.ReadU32(shape.barriers) && reader.ReadU32(shape.lobes) &&
           reader.ReadU32(shape.lobe_width) && reader.ReadU32(shape.bank_pages) &&
           reader.ReadU32(shape.rows_per_lobe) &&
           reader.ReadU32(shape.pages_per_barrier_lobe) &&
           reader.ReadU32(shape.transcript_version) &&
           reader.ReadBool(shape.full_bank_schedule) &&
           reader.ReadBool(shape.material_exchange) &&
           reader.ReadBool(shape.force_signed_mix) && reader.ReadU8(reserved) &&
           reserved == 0 && reader.ReadU32(shape.exchange_rows) &&
           reader.ReadU32(shape.exchange_rounds);
}

bool ValidateShape(const RCStage3CoupledShape& shape, std::string* why)
{
    uint64_t state_bytes{0};
    if (!CheckedMul(shape.lobes, shape.rows_per_lobe, state_bytes) ||
        !CheckedMul(state_bytes, shape.lobe_width, state_bytes) ||
        state_bytes > std::numeric_limits<uint32_t>::max()) {
        return Fail(why, "shape:state_bytes_overflow");
    }
    RCCoupParams params;
    params.barriers = shape.barriers;
    params.lobes = shape.lobes;
    params.lobe_width = shape.lobe_width;
    params.bank_pages = shape.bank_pages;
    params.rows_per_lobe = shape.rows_per_lobe;
    params.pages_per_barrier_lobe = shape.pages_per_barrier_lobe;
    if (!ValidateRCCoupParams(params)) return Fail(why, "shape:params_invalid");
    if (!shape.full_bank_schedule) return Fail(why, "shape:partial_bank_schedule");
    if (!RCCoupUsesProofFriendlyPermutation(shape.transcript_version)) {
        return Fail(why, "shape:permutation_not_proof_friendly");
    }
    if (shape.force_signed_mix) return Fail(why, "shape:test_mix_override");
    if (shape.material_exchange && shape.exchange_rows == 0) {
        return Fail(why, "shape:zero_exchange_rows");
    }
    if (!shape.material_exchange && shape.exchange_rounds != 0) {
        return Fail(why, "shape:exchange_rounds_without_exchange");
    }
    return true;
}

bool ValidateReceiptStructure(const RCStage3CoupledRelationReceipt& receipt,
                              std::string* why)
{
    if (receipt.magic != kRCStage3CoupledReceiptMagic) return Fail(why, "receipt:bad_magic");
    if (receipt.version != kRCStage3CoupledReceiptVersion) {
        return Fail(why, "receipt:bad_version");
    }
    if (!IsCoupledRole(receipt.role)) return Fail(why, "receipt:bad_role");
    if (receipt.engine != RCStage3CoupledProofEngine::ProofOnlyV1) {
        return Fail(why, "receipt:unknown_engine");
    }
    if (!ValidateShape(receipt.shape, why)) return false;
    if (receipt.statement_commitment.IsNull() || receipt.params_commitment.IsNull() ||
        receipt.coupled_shape_commitment.IsNull() || receipt.sigma.IsNull() ||
        receipt.input_root.IsNull() || receipt.output_root.IsNull() ||
        receipt.trace_root.IsNull() || receipt.aggregate_root.IsNull()) {
        return Fail(why, "receipt:null_binding");
    }
    if (receipt.engine_receipt.empty()) return Fail(why, "receipt:empty_engine_proof");
    if (receipt.engine_receipt.size() > kRCStage3CoupledMaxEngineReceiptBytes) {
        return Fail(why, "receipt:engine_proof_oversize");
    }
    return true;
}

bool VerifyProofOnlyEngine(const RCStage3SuccinctProof& statement,
                           const RCStage3CoupledRelationReceipt& receipt,
                           std::string* why)
{
    // Do not substitute VerifyWinnerCoupledV7 here: it calls BuildCoupledWires
    // and natively re-derives the coupled witness. ProofOnlyV1 is the recursive
    // aggregate carrier; its local registry still fails closed until each of
    // the eight complete immutable AIR/PCS relations exists.
    std::string recursive_why;
    const auto recursive =
        DeserializeRCStage3RecursiveProof(receipt.engine_receipt, &recursive_why);
    if (!recursive.has_value()) {
        return Fail(why, std::string(RCStage3RelationRoleName(receipt.role)) +
                             ":recursive_decode:" + recursive_why);
    }
    if (recursive->role != receipt.role) {
        return Fail(why, std::string(RCStage3RelationRoleName(receipt.role)) +
                             ":recursive_role");
    }
    if (!VerifyRCStage3RecursiveProof(statement, *recursive, &recursive_why)) {
        return Fail(why, std::string(RCStage3RelationRoleName(receipt.role)) +
                             ":recursive_verify:" + recursive_why);
    }
    return true;
}

} // namespace

RCStage3CoupledShape MakeRCStage3CoupledShape(const RCCoupParams& params,
                                             const RCCoupOptions& options)
{
    RCStage3CoupledShape shape;
    shape.barriers = params.barriers;
    shape.lobes = params.lobes;
    shape.lobe_width = params.lobe_width;
    shape.bank_pages = params.bank_pages;
    shape.rows_per_lobe = params.rows_per_lobe;
    shape.pages_per_barrier_lobe = params.pages_per_barrier_lobe;
    shape.transcript_version = options.transcript_version;
    shape.full_bank_schedule = options.full_bank_schedule;
    shape.material_exchange = options.material_exchange;
    shape.exchange_rows = options.exchange_rows;
    shape.exchange_rounds = options.exchange_rounds;
    shape.force_signed_mix = options.force_signed_mix;
    return shape;
}

uint256 CommitRCStage3CoupledStatement(const RCStage3PublicInputs& public_inputs)
{
    std::vector<unsigned char> bytes;
    WriteDomain(bytes, "BTX_RC_STAGE3_COUPLED_STATEMENT_V2");
    WriteU32(bytes, static_cast<uint32_t>(public_inputs.height));
    WriteU32(bytes, public_inputs.n_bits);
    WriteU32(bytes, public_inputs.episode_profile);
    WriteU32(bytes, public_inputs.coupled_profile);
    WriteU32(bytes, public_inputs.transcript_version);
    WriteU16(bytes, public_inputs.program_consensus_pin.version);
    WriteUint256(
        bytes,
        public_inputs.program_consensus_pin.recursive_alg_hash_root);
    WriteUint256(
        bytes,
        public_inputs.program_consensus_pin.external_sha256d_audit_root);
    WriteUint256(
        bytes,
        public_inputs.program_consensus_pin.registry_binding);
    WriteUint256(bytes, public_inputs.header_commitment);
    WriteUint256(bytes, public_inputs.params_commitment);
    WriteUint256(bytes, public_inputs.target);
    WriteUint256(bytes, public_inputs.sigma);
    WriteUint256(bytes, public_inputs.episode_digest);
    WriteUint256(bytes, public_inputs.coupled_digest);
    WriteUint256(bytes, public_inputs.final_digest);
    return Sha256d(bytes);
}

uint256 CommitRCStage3CoupledShape(const RCStage3CoupledShape& shape)
{
    std::vector<unsigned char> bytes;
    WriteDomain(bytes, "BTX_RC_STAGE3_COUPLED_SHAPE_V1");
    WriteShape(bytes, shape);
    return Sha256d(bytes);
}

uint256 CommitRCStage3CoupledRelationAggregate(
    const RCStage3CoupledRelationReceipt& receipt)
{
    std::vector<unsigned char> bytes;
    WriteDomain(bytes, "BTX_RC_STAGE3_COUPLED_RELATION_V1");
    WriteU16(bytes, static_cast<uint16_t>(receipt.role));
    WriteU16(bytes, static_cast<uint16_t>(receipt.engine));
    WriteShape(bytes, receipt.shape);
    WriteUint256(bytes, receipt.statement_commitment);
    WriteUint256(bytes, receipt.params_commitment);
    WriteUint256(bytes, receipt.coupled_shape_commitment);
    WriteUint256(bytes, receipt.sigma);
    WriteUint256(bytes, receipt.input_root);
    WriteUint256(bytes, receipt.output_root);
    WriteUint256(bytes, receipt.trace_root);
    WriteU64(bytes, receipt.primary_count);
    WriteU64(bytes, receipt.secondary_count);
    WriteU32(bytes, static_cast<uint32_t>(receipt.engine_receipt.size()));
    bytes.insert(bytes.end(), receipt.engine_receipt.begin(), receipt.engine_receipt.end());
    return Sha256d(bytes);
}

uint256 CommitRCStage3CoupledSection(const std::vector<unsigned char>& section)
{
    std::vector<unsigned char> bytes;
    WriteDomain(bytes, "BTX_RC_STAGE3_COUPLED_SECTION_V1");
    WriteU32(bytes, static_cast<uint32_t>(section.size()));
    bytes.insert(bytes.end(), section.begin(), section.end());
    return Sha256d(bytes);
}

std::optional<RCStage3CoupledRelationCounts>
ExpectedRCStage3CoupledRelationCounts(RCStage3RelationRole role,
                                      const RCStage3CoupledShape& shape,
                                      std::string* why)
{
    if (!IsCoupledRole(role)) {
        return FailOptional<RCStage3CoupledRelationCounts>(why, "counts:bad_role");
    }
    if (!ValidateShape(shape, why)) return std::nullopt;

    uint64_t barrier_lobes{0};
    uint64_t state_bytes{0};
    uint64_t scheduled_pages{0};
    if (!CheckedMul(shape.barriers, shape.lobes, barrier_lobes) ||
        !CheckedMul(shape.lobes, shape.rows_per_lobe, state_bytes) ||
        !CheckedMul(state_bytes, shape.lobe_width, state_bytes) ||
        !CheckedMul(barrier_lobes, shape.pages_per_barrier_lobe, scheduled_pages)) {
        return FailOptional<RCStage3CoupledRelationCounts>(why, "counts:overflow");
    }
    uint64_t all_state_cells{0};
    if (!CheckedMul(shape.barriers, state_bytes, all_state_cells)) {
        return FailOptional<RCStage3CoupledRelationCounts>(why, "counts:overflow");
    }

    RCStage3CoupledRelationCounts counts;
    switch (role) {
    case RCStage3RelationRole::CoupledBank:
        counts = {shape.bank_pages, scheduled_pages};
        break;
    case RCStage3RelationRole::CoupledGemm:
        counts = {scheduled_pages, barrier_lobes};
        break;
    case RCStage3RelationRole::CoupledExchange: {
        uint64_t exchange_stages{0};
        uint64_t material_stages{0};
        if (!CheckedMul(shape.barriers, shape.exchange_rounds, material_stages) ||
            !CheckedAdd(barrier_lobes, material_stages, exchange_stages)) {
            return FailOptional<RCStage3CoupledRelationCounts>(why, "counts:overflow");
        }
        counts = {exchange_stages, all_state_cells};
        break;
    }
    case RCStage3RelationRole::CoupledPermutation:
        counts = {shape.barriers, all_state_cells};
        break;
    case RCStage3RelationRole::CoupledMix: {
        uint64_t stages_per_barrier{0};
        for (uint64_t width = state_bytes; width > 1; width >>= 1) {
            ++stages_per_barrier;
        }
        uint64_t mix_stages{0};
        if (!CheckedMul(shape.barriers, stages_per_barrier, mix_stages)) {
            return FailOptional<RCStage3CoupledRelationCounts>(why, "counts:overflow");
        }
        counts = {mix_stages, all_state_cells};
        break;
    }
    case RCStage3RelationRole::CoupledExtract:
        if ((state_bytes % kRCMxBlockLen) != 0) {
            return FailOptional<RCStage3CoupledRelationCounts>(why, "counts:extract_geometry");
        }
        counts = {all_state_cells / kRCMxBlockLen, all_state_cells};
        break;
    case RCStage3RelationRole::CoupledBarrier:
        counts = {shape.barriers, all_state_cells};
        break;
    case RCStage3RelationRole::CoupledDigest:
        counts = {1, static_cast<uint64_t>(shape.barriers) + 1};
        break;
    default:
        return FailOptional<RCStage3CoupledRelationCounts>(why, "counts:bad_role");
    }
    if (counts.primary == 0 || counts.secondary == 0) {
        return FailOptional<RCStage3CoupledRelationCounts>(why, "counts:zero");
    }
    return counts;
}

bool SerializeRCStage3CoupledRelationReceipt(
    const RCStage3CoupledRelationReceipt& receipt,
    std::vector<unsigned char>& out,
    std::string* why)
{
    out.clear();
    if (!ValidateReceiptStructure(receipt, why)) return false;

    WriteU32(out, receipt.magic);
    WriteU16(out, receipt.version);
    WriteU16(out, static_cast<uint16_t>(receipt.role));
    WriteU16(out, static_cast<uint16_t>(receipt.engine));
    WriteU16(out, 0); // reserved
    WriteShape(out, receipt.shape);
    WriteUint256(out, receipt.statement_commitment);
    WriteUint256(out, receipt.params_commitment);
    WriteUint256(out, receipt.coupled_shape_commitment);
    WriteUint256(out, receipt.sigma);
    WriteUint256(out, receipt.input_root);
    WriteUint256(out, receipt.output_root);
    WriteUint256(out, receipt.trace_root);
    WriteUint256(out, receipt.aggregate_root);
    WriteU64(out, receipt.primary_count);
    WriteU64(out, receipt.secondary_count);
    WriteU32(out, static_cast<uint32_t>(receipt.engine_receipt.size()));
    out.insert(out.end(), receipt.engine_receipt.begin(), receipt.engine_receipt.end());
    return true;
}

std::optional<RCStage3CoupledRelationReceipt>
DeserializeRCStage3CoupledRelationReceipt(const std::vector<unsigned char>& bytes,
                                          std::string* why)
{
    if (bytes.empty()) {
        return FailOptional<RCStage3CoupledRelationReceipt>(why, "receipt:empty");
    }
    if (bytes.size() > kRCStage3CoupledMaxEngineReceiptBytes + 512U) {
        return FailOptional<RCStage3CoupledRelationReceipt>(why, "receipt:oversize");
    }

    Reader reader(bytes);
    RCStage3CoupledRelationReceipt receipt;
    uint16_t role{0};
    uint16_t engine{0};
    uint16_t reserved{0};
    uint32_t engine_size{0};
    if (!reader.ReadU32(receipt.magic) || !reader.ReadU16(receipt.version) ||
        !reader.ReadU16(role) || !reader.ReadU16(engine) ||
        !reader.ReadU16(reserved) || reserved != 0 ||
        !ReadShape(reader, receipt.shape) ||
        !reader.ReadUint256(receipt.statement_commitment) ||
        !reader.ReadUint256(receipt.params_commitment) ||
        !reader.ReadUint256(receipt.coupled_shape_commitment) ||
        !reader.ReadUint256(receipt.sigma) ||
        !reader.ReadUint256(receipt.input_root) ||
        !reader.ReadUint256(receipt.output_root) ||
        !reader.ReadUint256(receipt.trace_root) ||
        !reader.ReadUint256(receipt.aggregate_root) ||
        !reader.ReadU64(receipt.primary_count) ||
        !reader.ReadU64(receipt.secondary_count) ||
        !reader.ReadU32(engine_size)) {
        return FailOptional<RCStage3CoupledRelationReceipt>(why, "receipt:truncated");
    }
    if (engine_size == 0 || engine_size > kRCStage3CoupledMaxEngineReceiptBytes ||
        engine_size != reader.Remaining() ||
        !reader.ReadBytes(engine_size, receipt.engine_receipt) ||
        reader.Remaining() != 0) {
        return FailOptional<RCStage3CoupledRelationReceipt>(why, "receipt:engine_length");
    }
    receipt.role = static_cast<RCStage3RelationRole>(role);
    receipt.engine = static_cast<RCStage3CoupledProofEngine>(engine);
    if (!ValidateReceiptStructure(receipt, why)) return std::nullopt;
    return receipt;
}

bool VerifyRCStage3CoupledRelations(const RCStage3SuccinctProof& proof, std::string* why)
{
    if (!ValidateRCStage3ProofStructure(proof, why)) return false;
    if (proof.statement == RCStage3StatementKind::Episode) {
        return Fail(why, "episode_only_statement");
    }
    if (proof.public_inputs.coupled_profile == 0 ||
        proof.public_inputs.coupled_digest.IsNull()) {
        return Fail(why, "missing_public_input");
    }

    const uint256 statement_commitment =
        CommitRCStage3CoupledStatement(proof.public_inputs);
    std::vector<RCStage3CoupledRelationReceipt> receipts;
    receipts.reserve(COUPLED_ROLES.size());

    for (RCStage3RelationRole role : COUPLED_ROLES) {
        const auto section_it =
            std::find_if(proof.sections.begin(), proof.sections.end(),
                         [role](const RCStage3ProofSection& section) {
                             return section.role == role;
                         });
        const auto commitment_it =
            std::find_if(proof.commitments.begin(), proof.commitments.end(),
                         [role](const RCStage3Commitment& commitment) {
                             return commitment.role == role;
                         });
        if (section_it == proof.sections.end() ||
            commitment_it == proof.commitments.end()) {
            return Fail(why, std::string(RCStage3RelationRoleName(role)) + ":missing");
        }
        if (commitment_it->root != CommitRCStage3CoupledSection(section_it->proof)) {
            return Fail(why, std::string(RCStage3RelationRoleName(role)) +
                                 ":section_commitment");
        }
        auto receipt = DeserializeRCStage3CoupledRelationReceipt(section_it->proof, why);
        if (!receipt.has_value()) return false;
        if (receipt->role != role) {
            return Fail(why, std::string(RCStage3RelationRoleName(role)) + ":role");
        }
        receipts.push_back(std::move(*receipt));
    }

    // Validate the entire graph before dispatching any proof engine. This makes
    // later-relation mutations observable even while every engine remains OFF.
    const RCStage3CoupledShape shape = receipts.front().shape;
    const uint256 coupled_shape_commitment = CommitRCStage3CoupledShape(shape);
    uint256 expected_input = proof.public_inputs.header_commitment;
    for (size_t i = 0; i < receipts.size(); ++i) {
        const auto& receipt = receipts[i];
        const RCStage3RelationRole role = COUPLED_ROLES[i];
        if (!(receipt.shape == shape)) {
            return Fail(why, std::string(RCStage3RelationRoleName(role)) + ":shape");
        }
        if (receipt.shape.transcript_version != proof.public_inputs.transcript_version) {
            return Fail(why, std::string(RCStage3RelationRoleName(role)) +
                                 ":transcript_version");
        }
        if (receipt.statement_commitment != statement_commitment ||
            receipt.params_commitment != proof.public_inputs.params_commitment ||
            receipt.coupled_shape_commitment != coupled_shape_commitment ||
            receipt.sigma != proof.public_inputs.sigma) {
            return Fail(why, std::string(RCStage3RelationRoleName(role)) +
                                 ":public_binding");
        }
        const auto counts = ExpectedRCStage3CoupledRelationCounts(role, shape, why);
        if (!counts.has_value()) return false;
        if (receipt.primary_count != counts->primary ||
            receipt.secondary_count != counts->secondary) {
            return Fail(why, std::string(RCStage3RelationRoleName(role)) + ":coverage");
        }
        if (receipt.input_root != expected_input) {
            return Fail(why, std::string(RCStage3RelationRoleName(role)) + ":input_root");
        }
        if (receipt.aggregate_root !=
            CommitRCStage3CoupledRelationAggregate(receipt)) {
            return Fail(why, std::string(RCStage3RelationRoleName(role)) +
                                 ":aggregate_root");
        }
        expected_input = receipt.output_root;
    }
    if (receipts.back().output_root != proof.public_inputs.coupled_digest) {
        return Fail(why, "coupled:digest:public_digest");
    }

    for (const auto& receipt : receipts) {
        if (!VerifyProofOnlyEngine(proof, receipt, why)) return false;
    }
    return true;
}

bool RCStage3CoupledRelationEnginesReady(std::string* why)
{
    static_assert(!kRCStage3CoupledRelationEnginesReady,
                  "Do not enable without all eight proof-only engines");
    return Fail(why,
                "proof_engines_missing:bank,gemm,exchange,permutation,mix,"
                "extract,barrier,digest");
}

} // namespace matmul::v4::rc
