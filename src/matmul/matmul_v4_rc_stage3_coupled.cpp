// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_coupled.h>

#include <crypto/sha256.h>
#include <hash.h>
#include <matmul/matmul_v4_rc_air_quotient_alg.h>
#include <matmul/matmul_v4_rc_fri_ext3.h>
#include <matmul/matmul_v4_rc_gkr_field_ext3.h>
#include <matmul/matmul_v4_rc_stage3_coupled_bank_product.h>
#include <matmul/matmul_v4_rc_stage3_coupled_bank_stream.h>
#include <matmul/matmul_v4_rc_stage3_coupled_gemm_product.h>
#include <matmul/matmul_v4_rc_stage3_hash_semantic.h>
#include <matmul/matmul_v4_rc_stage3_recursive.h>

#include <streams.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <set>

namespace matmul::v4::rc {
namespace {

namespace aq = air_quotient;
using gkr_field::Fp3;

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
    if (receipt.engine != RCStage3CoupledProofEngine::ProofOnlyV1 &&
        receipt.engine != RCStage3CoupledProofEngine::BankDequantPagesV1 &&
        receipt.engine != RCStage3CoupledProofEngine::GemmDotTilesV1 &&
        receipt.engine != RCStage3CoupledProofEngine::BankSeedXofV1 &&
        receipt.engine != RCStage3CoupledProofEngine::BankPageInclusionV1) {
        return Fail(why, "receipt:unknown_engine");
    }
    if (receipt.engine == RCStage3CoupledProofEngine::BankDequantPagesV1 &&
        receipt.role != RCStage3RelationRole::CoupledBank) {
        return Fail(why, "receipt:bank_dequant_engine_wrong_role");
    }
    if (receipt.engine == RCStage3CoupledProofEngine::GemmDotTilesV1 &&
        receipt.role != RCStage3RelationRole::CoupledGemm) {
        return Fail(why, "receipt:gemm_dot_engine_wrong_role");
    }
    if ((receipt.engine == RCStage3CoupledProofEngine::BankSeedXofV1 ||
         receipt.engine == RCStage3CoupledProofEngine::BankPageInclusionV1) &&
        receipt.role != RCStage3RelationRole::CoupledBank) {
        return Fail(why, "receipt:bank_provenance_engine_wrong_role");
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

constexpr uint32_t kBankDequantEngineMagic = 0x31514442U; // "BDQ1"
constexpr uint16_t kBankDequantEngineVersion = 1;

const std::vector<uint32_t>& BankDequantBaseColumns()
{
    static const std::vector<uint32_t> columns{0, 1, 2, 3, 4, 5};
    return columns;
}

void SerializeBankDequantPin(const RCStage3CoupledBankDequantPin& pin,
                             std::vector<unsigned char>& out)
{
    WriteU16(out, pin.version);
    WriteUint256(out, pin.statement_commitment);
    WriteUint256(out, pin.shape_commitment);
    WriteUint256(out, pin.sigma);
    WriteU32(out, pin.page_index);
    WriteU32(out, pin.logical_rows);
    WriteU32(out, pin.n_rows);
    WriteU32(out, pin.n_coeffs);
    WriteUint256(out, pin.r0_row_group_root);
    WriteUint256(out, pin.pin_commitment);
}

bool ReadBankDequantPin(Reader& reader, RCStage3CoupledBankDequantPin& pin)
{
    return reader.ReadU16(pin.version) &&
           reader.ReadUint256(pin.statement_commitment) &&
           reader.ReadUint256(pin.shape_commitment) &&
           reader.ReadUint256(pin.sigma) &&
           reader.ReadU32(pin.page_index) &&
           reader.ReadU32(pin.logical_rows) &&
           reader.ReadU32(pin.n_rows) &&
           reader.ReadU32(pin.n_coeffs) &&
           reader.ReadUint256(pin.r0_row_group_root) &&
           reader.ReadUint256(pin.pin_commitment);
}

uint256 ComputeBankDequantEngineTraceRoot(const std::vector<uint256>& page_roots)
{
    std::vector<unsigned char> bytes;
    WriteDomain(bytes, "BTX_RC_STAGE3_COUPLED_BANK_DEQUANT_ENGINE_TRACE_V1");
    WriteU64(bytes, static_cast<uint64_t>(page_roots.size()));
    for (const uint256& root : page_roots) WriteUint256(bytes, root);
    return Sha256d(bytes);
}

bool BankDequantLogicalRows(const RCStage3CoupledShape& shape, uint32_t& out,
                            std::string* why)
{
    uint64_t logical{0};
    if (!CheckedMul(shape.lobe_width, shape.lobe_width, logical) || logical < 2 ||
        (logical & (logical - 1)) != 0 ||
        logical > std::numeric_limits<uint32_t>::max()) {
        return Fail(why, "bank_dequant_engine:logical_rows");
    }
    out = static_cast<uint32_t>(logical);
    return true;
}

} // namespace

bool BuildRCStage3CoupledBankDequantEngineReceipt(
    const RCStage3CoupledShape& shape,
    const uint256& statement_commitment,
    const uint256& coupled_shape_commitment,
    const uint256& sigma,
    const std::vector<RCStage3CoupledBankDequantPageWitness>& pages,
    std::vector<unsigned char>& out_engine_receipt,
    uint256& out_trace_root,
    std::string* why)
{
    out_engine_receipt.clear();
    out_trace_root.SetNull();
    uint32_t logical{0};
    if (!BankDequantLogicalRows(shape, logical, why)) return false;
    if (pages.empty() || pages.size() != shape.bank_pages) {
        return Fail(why, "bank_dequant_engine:page_count");
    }

    std::vector<unsigned char> body;
    WriteU32(body, kBankDequantEngineMagic);
    WriteU16(body, kBankDequantEngineVersion);
    WriteU32(body, static_cast<uint32_t>(pages.size()));

    std::vector<uint256> page_roots;
    page_roots.reserve(pages.size());
    for (uint32_t i = 0; i < pages.size(); ++i) {
        const RCStage3CoupledBankDequantPageWitness& page = pages[i];
        if (page.mantissa.size() != logical || page.scale.size() != logical) {
            return Fail(why, "bank_dequant_engine:page_shape:" + std::to_string(i));
        }
        std::vector<std::vector<Fp3>> columns(
            static_cast<size_t>(kRCStage3CoupledBankDequantColumns) + 1,
            std::vector<Fp3>(logical, Fp3::Zero()));
        for (uint32_t cell = 0; cell < logical; ++cell) {
            const uint8_t scale = page.scale[cell];
            if (scale > 3) {
                return Fail(why, "bank_dequant_engine:scale_range:" + std::to_string(i));
            }
            const uint8_t bit0 = scale & 1U;
            const uint8_t bit1 = (scale >> 1) & 1U;
            const int64_t factor = int64_t{1} << scale;
            const int64_t mantissa = page.mantissa[cell];
            columns[kRCStage3CoupledBankMantissa][cell] = gkr_field::FromSigned3(mantissa);
            columns[kRCStage3CoupledBankRepeatedScale][cell] = gkr_field::FromU64_3(scale);
            columns[kRCStage3CoupledBankScaleBit0][cell] = gkr_field::FromU64_3(bit0);
            columns[kRCStage3CoupledBankScaleBit1][cell] = gkr_field::FromU64_3(bit1);
            columns[kRCStage3CoupledBankScaleFactor][cell] =
                gkr_field::FromU64_3(static_cast<uint64_t>(factor));
            columns[kRCStage3CoupledBankOutput][cell] =
                gkr_field::FromSigned3(mantissa * factor);
        }

        RCStage3CoupledBankDequantPin pin;
        pin.version = kRCStage3CoupledBankProductVersion;
        pin.statement_commitment = statement_commitment;
        pin.shape_commitment = coupled_shape_commitment;
        pin.sigma = sigma;
        pin.page_index = i;
        pin.logical_rows = logical;
        pin.n_rows = logical;
        pin.n_coeffs = logical;

        aq::AirConstraintSystem<Fp3> row_shape;
        row_shape.n_rows = logical;
        row_shape.n_columns = static_cast<uint32_t>(columns.size());
        const auto r0 = aq::AirQuotientBuildTwoEpochBaseRowSession(
            row_shape, columns, BankDequantBaseColumns());
        if (!r0.valid) {
            return Fail(why, "bank_dequant_engine:r0:" + std::to_string(i));
        }
        pin.r0_row_group_root = r0.base_row_commitment;
        pin.pin_commitment = ComputeRCStage3CoupledBankDequantPinCommitment(pin);
        if (pin.pin_commitment.IsNull()) {
            return Fail(why, "bank_dequant_engine:pin:" + std::to_string(i));
        }

        aq::AirConstraintSystem<Fp3> cs;
        if (!BuildRCStage3CoupledBankDequantConstraintSystem(pin, cs, why)) return false;

        auto proved = aq::AirQuotientProveRowsSplitRap(
            cs, columns, BankDequantBaseColumns(),
            ComputeRCStage3CoupledBankDequantSeed(pin), {}, &r0);
        if (!proved.ok || !proved.division_exact) {
            return Fail(why, "bank_dequant_engine:prove:" + std::to_string(i) + ":" +
                                 proved.note);
        }
        if (!VerifyRCStage3CoupledBankDequantProof(pin, proved.proof, why)) return false;

        std::vector<unsigned char> proof_bytes;
        if (aq::SerializeAirQuotientSplitRapRowsProof(proved.proof, proof_bytes) == 0) {
            return Fail(why, "bank_dequant_engine:proof_codec:" + std::to_string(i));
        }
        WriteU32(body, i);
        SerializeBankDequantPin(pin, body);
        WriteU32(body, static_cast<uint32_t>(proof_bytes.size()));
        body.insert(body.end(), proof_bytes.begin(), proof_bytes.end());
        page_roots.push_back(pin.r0_row_group_root);
    }

    out_trace_root = ComputeBankDequantEngineTraceRoot(page_roots);
    out_engine_receipt = std::move(body);
    return true;
}

bool VerifyRCStage3CoupledBankDequantEngineReceipt(
    const RCStage3CoupledShape& shape,
    const uint256& statement_commitment,
    const uint256& coupled_shape_commitment,
    const uint256& sigma,
    const std::vector<unsigned char>& engine_receipt,
    uint256& out_trace_root,
    std::string* why)
{
    out_trace_root.SetNull();
    uint32_t logical{0};
    if (!BankDequantLogicalRows(shape, logical, why)) return false;

    Reader reader(engine_receipt);
    uint32_t magic{0};
    uint16_t version{0};
    uint32_t page_count{0};
    if (!reader.ReadU32(magic) || magic != kBankDequantEngineMagic ||
        !reader.ReadU16(version) || version != kBankDequantEngineVersion ||
        !reader.ReadU32(page_count) || page_count == 0 ||
        page_count != shape.bank_pages) {
        return Fail(why, "bank_dequant_engine:header");
    }

    std::vector<uint256> page_roots;
    page_roots.reserve(page_count);
    for (uint32_t i = 0; i < page_count; ++i) {
        uint32_t page_index{0};
        RCStage3CoupledBankDequantPin pin;
        uint32_t proof_len{0};
        std::vector<unsigned char> proof_bytes;
        if (!reader.ReadU32(page_index) || page_index != i ||
            !ReadBankDequantPin(reader, pin) || !reader.ReadU32(proof_len) ||
            proof_len == 0 || !reader.ReadBytes(proof_len, proof_bytes)) {
            return Fail(why, "bank_dequant_engine:page_decode:" + std::to_string(i));
        }
        if (pin.statement_commitment != statement_commitment ||
            pin.shape_commitment != coupled_shape_commitment || pin.sigma != sigma ||
            pin.page_index != i || pin.logical_rows != logical ||
            pin.n_rows != logical || pin.n_coeffs != logical ||
            pin.pin_commitment.IsNull() ||
            pin.pin_commitment != ComputeRCStage3CoupledBankDequantPinCommitment(pin)) {
            return Fail(why, "bank_dequant_engine:page_binding:" + std::to_string(i));
        }
        const auto proof = aq::DeserializeAirQuotientSplitRapRowsProof(proof_bytes);
        if (!proof.has_value()) {
            return Fail(why, "bank_dequant_engine:proof_codec:" + std::to_string(i));
        }
        std::string page_why;
        if (!VerifyRCStage3CoupledBankDequantProof(pin, *proof, &page_why)) {
            return Fail(why, "bank_dequant_engine:page_verify:" + std::to_string(i) + ":" +
                                 page_why);
        }
        page_roots.push_back(pin.r0_row_group_root);
    }
    if (reader.Remaining() != 0) {
        return Fail(why, "bank_dequant_engine:trailing_bytes");
    }
    out_trace_root = ComputeBankDequantEngineTraceRoot(page_roots);
    return true;
}

namespace {

constexpr uint32_t kGemmDotEngineMagic = 0x31544447U; // "GDT1"
constexpr uint16_t kGemmDotEngineVersion = 1;
constexpr char kGemmScheduleDomain[] = "BTX_RC_STAGE3_COUPLED_GEMM_SCHEDULE_V1";
constexpr uint32_t kFri3AirQuotientMagic = 0x31514146U; // "FAQ1"

bool WriteFp3(std::vector<unsigned char>& out, const Fp3& value)
{
    WriteU64(out, gkr_field::Canonical(value.c0));
    WriteU64(out, gkr_field::Canonical(value.c1));
    WriteU64(out, gkr_field::Canonical(value.c2));
    return true;
}

bool ReadFp3(Reader& reader, Fp3& value)
{
    uint64_t c0{0}, c1{0}, c2{0};
    if (!reader.ReadU64(c0) || !reader.ReadU64(c1) || !reader.ReadU64(c2) ||
        c0 >= gkr_field::kP || c1 >= gkr_field::kP || c2 >= gkr_field::kP) {
        return false;
    }
    value = {c0, c1, c2};
    return true;
}

bool SerializeFri3AirQuotientProof(const aq::AirQuotientProof<Fp3>& proof,
                                   std::vector<unsigned char>& out)
{
    out.clear();
    std::vector<unsigned char> batch;
    if (SerializeFri3BatchProof(proof.batch, batch) == 0 || batch.empty() ||
        batch.size() > kRCFriMaxProofBytesHard ||
        proof.next_openings.size() > kRCFriMaxQueriesHard) {
        return false;
    }
    uint64_t exact = 4 + 2 + 4 + batch.size() + 32 + 4;
    for (const auto& paths : proof.next_openings) {
        if (paths.size() > kRCFriBatchMaxColumns) return false;
        exact += 4;
        for (const auto& path : paths) {
            if (path.siblings.size() > kRCFriMaxFoldLayersHard) return false;
            exact += 4 + 24 + 4 + uint64_t{path.siblings.size()} * 32;
        }
    }
    if (exact > kRCStage3CoupledMaxEngineReceiptBytes ||
        exact > std::numeric_limits<size_t>::max()) {
        return false;
    }
    out.reserve(static_cast<size_t>(exact));
    WriteU32(out, kFri3AirQuotientMagic);
    WriteU16(out, 1);
    WriteU32(out, static_cast<uint32_t>(batch.size()));
    out.insert(out.end(), batch.begin(), batch.end());
    WriteUint256(out, proof.trace_commit);
    WriteU32(out, static_cast<uint32_t>(proof.next_openings.size()));
    for (const auto& paths : proof.next_openings) {
        WriteU32(out, static_cast<uint32_t>(paths.size()));
        for (const auto& path : paths) {
            WriteU32(out, path.index);
            WriteFp3(out, path.leaf);
            WriteU32(out, static_cast<uint32_t>(path.siblings.size()));
            for (const uint256& sibling : path.siblings) WriteUint256(out, sibling);
        }
    }
    return out.size() == exact;
}

bool DeserializeFri3AirQuotientProof(const std::vector<unsigned char>& bytes,
                                     aq::AirQuotientProof<Fp3>& out)
{
    out = {};
    Reader reader(bytes);
    uint32_t magic{0};
    uint16_t version{0};
    uint32_t batch_len{0};
    std::vector<unsigned char> batch_bytes;
    if (!reader.ReadU32(magic) || magic != kFri3AirQuotientMagic ||
        !reader.ReadU16(version) || version != 1 || !reader.ReadU32(batch_len) ||
        batch_len == 0 || batch_len > kRCFriMaxProofBytesHard ||
        !reader.ReadBytes(batch_len, batch_bytes)) {
        return false;
    }
    const auto batch = DeserializeFri3BatchProof(batch_bytes);
    if (!batch.has_value()) return false;
    std::vector<unsigned char> canonical;
    if (SerializeFri3BatchProof(*batch, canonical) != batch_bytes.size() ||
        canonical != batch_bytes) {
        return false;
    }
    out.batch = *batch;
    uint32_t query_count{0};
    if (!reader.ReadUint256(out.trace_commit) || !reader.ReadU32(query_count) ||
        query_count > kRCFriMaxQueriesHard) {
        return false;
    }
    out.next_openings.resize(query_count);
    for (auto& paths : out.next_openings) {
        uint32_t path_count{0};
        if (!reader.ReadU32(path_count) || path_count > kRCFriBatchMaxColumns) {
            return false;
        }
        paths.resize(path_count);
        for (auto& path : paths) {
            uint32_t sibling_count{0};
            if (!reader.ReadU32(path.index) || !ReadFp3(reader, path.leaf) ||
                !reader.ReadU32(sibling_count) ||
                sibling_count > kRCFriMaxFoldLayersHard) {
                return false;
            }
            path.siblings.resize(sibling_count);
            for (uint256& sibling : path.siblings) {
                if (!reader.ReadUint256(sibling)) return false;
            }
        }
    }
    return reader.Remaining() == 0;
}

void SerializeGemmDotPin(const RCStage3CoupledGemmDotPin& pin,
                         std::vector<unsigned char>& out)
{
    WriteU16(out, pin.version);
    WriteUint256(out, pin.statement_commitment);
    WriteUint256(out, pin.shape_commitment);
    WriteUint256(out, pin.schedule_commitment);
    WriteU64(out, pin.schedule_index);
    WriteU64(out, pin.output_tile_index);
    WriteU32(out, pin.contraction_size);
    WriteU32(out, pin.logical_rows);
    WriteU32(out, pin.n_rows);
    WriteU32(out, pin.n_coeffs);
    WriteU32(out, static_cast<uint32_t>(pin.column_roots.size()));
    for (const auto& root : pin.column_roots) {
        WriteU32(out, root.column);
        WriteUint256(out, root.root);
    }
    WriteUint256(out, pin.pin_commitment);
}

bool ReadGemmDotPin(Reader& reader, RCStage3CoupledGemmDotPin& pin)
{
    uint32_t root_count{0};
    if (!reader.ReadU16(pin.version) ||
        !reader.ReadUint256(pin.statement_commitment) ||
        !reader.ReadUint256(pin.shape_commitment) ||
        !reader.ReadUint256(pin.schedule_commitment) ||
        !reader.ReadU64(pin.schedule_index) ||
        !reader.ReadU64(pin.output_tile_index) ||
        !reader.ReadU32(pin.contraction_size) ||
        !reader.ReadU32(pin.logical_rows) || !reader.ReadU32(pin.n_rows) ||
        !reader.ReadU32(pin.n_coeffs) || !reader.ReadU32(root_count) ||
        root_count > kRCStage3CoupledGemmColumns + 1) {
        return false;
    }
    pin.column_roots.resize(root_count);
    for (auto& root : pin.column_roots) {
        if (!reader.ReadU32(root.column) || !reader.ReadUint256(root.root)) {
            return false;
        }
    }
    return reader.ReadUint256(pin.pin_commitment);
}

uint256 ComputeGemmDotEngineTraceRoot(const std::vector<uint256>& pin_commitments)
{
    std::vector<unsigned char> bytes;
    WriteDomain(bytes, "BTX_RC_STAGE3_COUPLED_GEMM_DOT_ENGINE_TRACE_V1");
    WriteU64(bytes, static_cast<uint64_t>(pin_commitments.size()));
    for (const uint256& root : pin_commitments) WriteUint256(bytes, root);
    return Sha256d(bytes);
}

bool RebuildGemmSchedule(const RCStage3CoupledShape& shape,
                         const uint256& statement_commitment,
                         const uint256& sigma,
                         std::vector<RCStage3CoupledGemmScheduleEntry>& out,
                         uint256& schedule_commitment,
                         std::string* why)
{
    out.clear();
    schedule_commitment.SetNull();
    const auto counts =
        ExpectedRCStage3CoupledRelationCounts(RCStage3RelationRole::CoupledGemm,
                                              shape, why);
    if (sigma.IsNull() || statement_commitment.IsNull() || !counts.has_value()) {
        return Fail(why, "gemm_dot_engine:schedule_public");
    }
    RCCoupParams params;
    params.barriers = shape.barriers;
    params.lobes = shape.lobes;
    params.lobe_width = shape.lobe_width;
    params.bank_pages = shape.bank_pages;
    params.rows_per_lobe = shape.rows_per_lobe;
    params.pages_per_barrier_lobe = shape.pages_per_barrier_lobe;
    out.reserve(counts->primary);
    for (uint32_t barrier = 0; barrier < shape.barriers; ++barrier) {
        for (uint32_t lobe = 0; lobe < shape.lobes; ++lobe) {
            const auto pages = SelectCoupledBankPageIds(
                barrier, lobe, params, sigma, shape.full_bank_schedule,
                shape.transcript_version);
            if (pages.size() != shape.pages_per_barrier_lobe) {
                return Fail(why, "gemm_dot_engine:schedule_page_count");
            }
            for (uint32_t slot = 0; slot < pages.size(); ++slot) {
                if (pages[slot] >= shape.bank_pages) {
                    return Fail(why, "gemm_dot_engine:schedule_page_id");
                }
                out.push_back({out.size(), barrier, lobe, slot, pages[slot]});
            }
        }
    }
    if (out.size() != counts->primary) {
        return Fail(why, "gemm_dot_engine:schedule_count");
    }
    HashWriter hash;
    hash << kGemmScheduleDomain;
    hash << kRCStage3CoupledGemmProductVersion;
    hash << statement_commitment;
    hash << CommitRCStage3CoupledShape(shape);
    hash << sigma;
    hash << static_cast<uint64_t>(out.size());
    for (const auto& entry : out) {
        hash << entry.schedule_index << entry.barrier << entry.lobe
             << entry.page_slot << entry.page_id;
    }
    schedule_commitment = hash.GetHash();
    return !schedule_commitment.IsNull() ||
           Fail(why, "gemm_dot_engine:schedule_commitment");
}

} // namespace

bool BuildRCStage3CoupledGemmDotEngineReceipt(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const std::vector<RCStage3CoupledGemmDotOpening>& openings,
    std::vector<unsigned char>& out_engine_receipt,
    uint256& out_trace_root,
    std::string* why)
{
    out_engine_receipt.clear();
    out_trace_root.SetNull();
    std::vector<RCStage3CoupledGemmOpening> product_openings;
    product_openings.reserve(openings.size());
    for (const auto& opening : openings) {
        product_openings.push_back(
            {opening.operand_a, opening.operand_b, opening.output_y});
    }
    RCStage3CoupledGemmProduct product;
    if (!ProveRCStage3CoupledGemmProduct(statement, shape, product_openings,
                                         product, why)) {
        return false;
    }

    std::vector<unsigned char> body;
    WriteU32(body, kGemmDotEngineMagic);
    WriteU16(body, kGemmDotEngineVersion);
    WriteUint256(body, product.schedule_commitment);
    WriteU64(body, product.expected_gemms);
    WriteU64(body, product.expected_output_tiles);

    std::vector<uint256> pin_commitments;
    pin_commitments.reserve(product.expected_output_tiles);
    uint64_t tiles_written{0};
    for (const auto& gemm : product.gemms) {
        for (const auto& tile : gemm.tiles) {
            std::vector<unsigned char> proof_bytes;
            if (!SerializeFri3AirQuotientProof(tile.proof, proof_bytes) ||
                proof_bytes.empty()) {
                return Fail(why, "gemm_dot_engine:proof_codec");
            }
            WriteU64(body, tile.pin.schedule_index);
            WriteU64(body, tile.output_tile_index);
            SerializeGemmDotPin(tile.pin, body);
            WriteU32(body, static_cast<uint32_t>(proof_bytes.size()));
            body.insert(body.end(), proof_bytes.begin(), proof_bytes.end());
            pin_commitments.push_back(tile.pin.pin_commitment);
            ++tiles_written;
        }
    }
    if (tiles_written != product.expected_output_tiles ||
        body.size() > kRCStage3CoupledMaxEngineReceiptBytes) {
        return Fail(why, "gemm_dot_engine:tile_count_or_oversize");
    }
    out_trace_root = ComputeGemmDotEngineTraceRoot(pin_commitments);
    out_engine_receipt = std::move(body);
    return true;
}

bool VerifyRCStage3CoupledGemmDotEngineReceipt(
    const RCStage3CoupledShape& shape,
    const uint256& statement_commitment,
    const uint256& coupled_shape_commitment,
    const uint256& sigma,
    const std::vector<unsigned char>& engine_receipt,
    uint256& out_trace_root,
    std::string* why)
{
    out_trace_root.SetNull();
    std::vector<RCStage3CoupledGemmScheduleEntry> schedule;
    uint256 expected_schedule_commitment;
    if (!RebuildGemmSchedule(shape, statement_commitment, sigma, schedule,
                             expected_schedule_commitment, why)) {
        return false;
    }
    const uint64_t tiles_per_gemm =
        uint64_t{shape.rows_per_lobe} * (shape.lobe_width / kRCMxBlockLen);
    if (tiles_per_gemm == 0 || shape.lobe_width % kRCMxBlockLen != 0) {
        return Fail(why, "gemm_dot_engine:tile_geometry");
    }
    const uint64_t expected_tiles = tiles_per_gemm * schedule.size();

    Reader reader(engine_receipt);
    uint32_t magic{0};
    uint16_t version{0};
    uint256 schedule_commitment;
    uint64_t expected_gemms{0};
    uint64_t expected_output_tiles{0};
    if (!reader.ReadU32(magic) || magic != kGemmDotEngineMagic ||
        !reader.ReadU16(version) || version != kGemmDotEngineVersion ||
        !reader.ReadUint256(schedule_commitment) ||
        !reader.ReadU64(expected_gemms) || !reader.ReadU64(expected_output_tiles) ||
        schedule_commitment != expected_schedule_commitment ||
        expected_gemms != schedule.size() ||
        expected_output_tiles != expected_tiles) {
        return Fail(why, "gemm_dot_engine:header");
    }

    std::vector<uint256> pin_commitments;
    pin_commitments.reserve(expected_tiles);
    for (uint64_t tile_ordinal = 0; tile_ordinal < expected_tiles; ++tile_ordinal) {
        const uint64_t schedule_index = tile_ordinal / tiles_per_gemm;
        const uint64_t output_tile_index = tile_ordinal % tiles_per_gemm;
        uint64_t wire_schedule{0};
        uint64_t wire_tile{0};
        RCStage3CoupledGemmDotPin pin;
        uint32_t proof_len{0};
        std::vector<unsigned char> proof_bytes;
        if (!reader.ReadU64(wire_schedule) || wire_schedule != schedule_index ||
            !reader.ReadU64(wire_tile) || wire_tile != output_tile_index ||
            !ReadGemmDotPin(reader, pin) || !reader.ReadU32(proof_len) ||
            proof_len == 0 || !reader.ReadBytes(proof_len, proof_bytes)) {
            return Fail(why, "gemm_dot_engine:tile_decode:" +
                                 std::to_string(tile_ordinal));
        }
        if (pin.statement_commitment != statement_commitment ||
            pin.shape_commitment != coupled_shape_commitment ||
            pin.schedule_commitment != schedule_commitment ||
            pin.schedule_index != schedule_index ||
            pin.output_tile_index != output_tile_index ||
            pin.contraction_size != shape.lobe_width ||
            pin.logical_rows != shape.lobe_width * kRCMxBlockLen ||
            pin.n_rows == 0 || pin.n_coeffs != pin.n_rows ||
            pin.pin_commitment.IsNull() ||
            pin.pin_commitment != ComputeRCStage3CoupledGemmDotPinCommitment(pin)) {
            return Fail(why, "gemm_dot_engine:tile_binding:" +
                                 std::to_string(tile_ordinal));
        }
        aq::AirQuotientProof<Fp3> proof;
        if (!DeserializeFri3AirQuotientProof(proof_bytes, proof)) {
            return Fail(why, "gemm_dot_engine:proof_codec:" +
                                 std::to_string(tile_ordinal));
        }
        std::string tile_why;
        if (!VerifyRCStage3CoupledGemmDotProof(pin, proof, &tile_why)) {
            return Fail(why, "gemm_dot_engine:tile_verify:" +
                                 std::to_string(tile_ordinal) + ":" + tile_why);
        }
        pin_commitments.push_back(pin.pin_commitment);
    }
    if (reader.Remaining() != 0) {
        return Fail(why, "gemm_dot_engine:trailing_bytes");
    }
    out_trace_root = ComputeGemmDotEngineTraceRoot(pin_commitments);
    return true;
}

namespace {

constexpr uint32_t kBankSeedXofEngineMagic = 0x31585342U; // "BSX1"
constexpr uint16_t kBankSeedXofEngineVersion = 1;
constexpr uint32_t kBankPageInclusionEngineMagic = 0x31495042U; // "BPI1"
constexpr uint16_t kBankPageInclusionEngineVersion = 1;
constexpr char kBankPageInclusionScheduleDomain[] =
    "BTX_RC_STAGE3_COUPLED_BANK_PAGE_INCLUSION_SCHEDULE_V1";
constexpr char kBankPageInclusionTraceDomain[] =
    "BTX_RC_STAGE3_COUPLED_BANK_PAGE_INCLUSION_TRACE_V1";
constexpr char kBankSeedXofTraceDomain[] =
    "BTX_RC_STAGE3_COUPLED_BANK_SEED_XOF_TRACE_V1";

namespace hs = stage3_hash_semantic;
namespace ha = stage3_hash_air;

bool SerializeProvenanceAirProof(const ha::FixedProgramProvenanceAirProof& proof,
                                 std::vector<unsigned char>& out)
{
    out.clear();
    std::vector<unsigned char> quotient;
    if (!proof.valid || !SerializeFri3AirQuotientProof(proof.quotient, quotient) ||
        quotient.empty()) {
        return false;
    }
    WriteU16(out, proof.version);
    WriteUint256(out, proof.boundary_statement);
    WriteUint256(out, proof.challenge_commitment);
    WriteU32(out, static_cast<uint32_t>(quotient.size()));
    out.insert(out.end(), quotient.begin(), quotient.end());
    return true;
}

bool DeserializeProvenanceAirProof(Reader& reader,
                                   ha::FixedProgramProvenanceAirProof& out)
{
    out = {};
    uint32_t quotient_len{0};
    std::vector<unsigned char> quotient_bytes;
    if (!reader.ReadU16(out.version) || !reader.ReadUint256(out.boundary_statement) ||
        !reader.ReadUint256(out.challenge_commitment) || !reader.ReadU32(quotient_len) ||
        quotient_len == 0 || !reader.ReadBytes(quotient_len, quotient_bytes) ||
        !DeserializeFri3AirQuotientProof(quotient_bytes, out.quotient)) {
        return false;
    }
    out.valid = true;
    return true;
}

bool SerializeFlatBoundaryBundleProofs(
    const hs::FlatBoundaryProofBundle& bundle, std::vector<unsigned char>& body)
{
    if (bundle.proofs.size() > hs::kMaxFlatBoundaryProofs) return false;
    WriteU32(body, static_cast<uint32_t>(bundle.proofs.size()));
    for (const auto& proof : bundle.proofs) {
        std::vector<unsigned char> proof_bytes;
        if (!SerializeProvenanceAirProof(proof, proof_bytes) || proof_bytes.empty()) {
            return false;
        }
        WriteU32(body, static_cast<uint32_t>(proof_bytes.size()));
        body.insert(body.end(), proof_bytes.begin(), proof_bytes.end());
    }
    return true;
}

bool ReadFlatBoundaryBundleProofs(Reader& reader, hs::FlatBoundaryProofBundle& bundle)
{
    uint32_t count{0};
    if (!reader.ReadU32(count) || count == 0 || count > hs::kMaxFlatBoundaryProofs) {
        return false;
    }
    bundle.proofs.clear();
    bundle.proofs.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t proof_len{0};
        std::vector<unsigned char> proof_bytes;
        if (!reader.ReadU32(proof_len) || proof_len == 0 ||
            !reader.ReadBytes(proof_len, proof_bytes)) {
            return false;
        }
        Reader proof_reader(proof_bytes);
        ha::FixedProgramProvenanceAirProof proof;
        if (!DeserializeProvenanceAirProof(proof_reader, proof) ||
            proof_reader.Remaining() != 0) {
            return false;
        }
        bundle.proofs.push_back(std::move(proof));
    }
    return true;
}

uint256 ComputeBankSeedXofEngineTraceRoot(const RCStage3CoupledBankProduct& product)
{
    std::vector<unsigned char> bytes;
    WriteDomain(bytes, kBankSeedXofTraceDomain);
    WriteUint256(bytes, product.seed_xof_endpoint_root);
    WriteUint256(bytes, product.bank_root_seed.manifest.commitment);
    WriteU64(bytes, static_cast<uint64_t>(product.pages.size()));
    for (const auto& page : product.pages) {
        WriteU32(bytes, page.page_index);
        WriteUint256(bytes, page.page_seed.manifest.commitment);
        WriteUint256(bytes, page.mantissa.commitment);
        WriteUint256(bytes, page.scale.commitment);
    }
    return Sha256d(bytes);
}

bool VerifyBankSeedXofBundles(const RCStage3CoupledBankProduct& product,
                              std::string* why)
{
    if (!hs::VerifyShaManifestBundle(RCStage3RelationEndpoint::CoupledBankSeedXof,
                                     product.bank_root_seed.manifest,
                                     product.bank_root_seed.proof, why)) {
        return Fail(why, "bank_seed_xof_engine:root_seed");
    }
    for (uint32_t i = 0; i < product.pages.size(); ++i) {
        const auto& page = product.pages[i];
        if (!hs::VerifyShaManifestBundle(RCStage3RelationEndpoint::CoupledBankSeedXof,
                                         page.page_seed.manifest, page.page_seed.proof,
                                         why) ||
            !hs::VerifyCounterXofManifestBundle(
                RCStage3RelationEndpoint::CoupledBankSeedXof, page.mantissa,
                page.mantissa_proof, why) ||
            !hs::VerifyCounterXofManifestBundle(
                RCStage3RelationEndpoint::CoupledBankSeedXof, page.scale,
                page.scale_proof, why)) {
            return Fail(why, "bank_seed_xof_engine:page:" + std::to_string(i));
        }
    }
    return true;
}

struct BankPageInclusionScheduleEntry {
    uint64_t schedule_index{0};
    uint32_t barrier{0};
    uint32_t lobe{0};
    uint32_t page_slot{0};
    uint32_t page_id{0};

    bool operator==(const BankPageInclusionScheduleEntry&) const = default;
};

bool BuildBankPageInclusionSchedule(const RCStage3CoupledShape& shape,
                                    const uint256& sigma,
                                    std::vector<BankPageInclusionScheduleEntry>& out,
                                    uint256& schedule_commitment,
                                    std::string* why)
{
    out.clear();
    schedule_commitment.SetNull();
    RCCoupParams params;
    params.barriers = shape.barriers;
    params.lobes = shape.lobes;
    params.lobe_width = shape.lobe_width;
    params.bank_pages = shape.bank_pages;
    params.rows_per_lobe = shape.rows_per_lobe;
    params.pages_per_barrier_lobe = shape.pages_per_barrier_lobe;
    if (!ValidateRCCoupParams(params)) {
        return Fail(why, "bank_page_inclusion_engine:schedule_public");
    }
    uint64_t ordinal{0};
    for (uint32_t barrier = 0; barrier < shape.barriers; ++barrier) {
        for (uint32_t lobe = 0; lobe < shape.lobes; ++lobe) {
            const auto pages = SelectCoupledBankPageIds(
                barrier, lobe, params, sigma, shape.full_bank_schedule,
                shape.transcript_version);
            if (pages.size() != shape.pages_per_barrier_lobe) {
                return Fail(why, "bank_page_inclusion_engine:schedule_page_count");
            }
            for (uint32_t slot = 0; slot < pages.size(); ++slot) {
                if (pages[slot] >= shape.bank_pages) {
                    return Fail(why, "bank_page_inclusion_engine:schedule_page_id");
                }
                BankPageInclusionScheduleEntry entry;
                entry.schedule_index = ordinal++;
                entry.barrier = barrier;
                entry.lobe = lobe;
                entry.page_slot = slot;
                entry.page_id = pages[slot];
                out.push_back(entry);
            }
        }
    }
    const auto counts =
        ExpectedRCStage3CoupledRelationCounts(RCStage3RelationRole::CoupledBank, shape, why);
    if (!counts.has_value() || counts->secondary != out.size()) {
        return Fail(why, "bank_page_inclusion_engine:schedule_count");
    }
    HashWriter hash;
    hash << kBankPageInclusionScheduleDomain;
    hash << CommitRCStage3CoupledShape(shape);
    hash << sigma;
    hash << static_cast<uint64_t>(out.size());
    for (const auto& entry : out) {
        hash << entry.schedule_index << entry.barrier << entry.lobe << entry.page_slot
             << entry.page_id;
    }
    schedule_commitment = hash.GetHash();
    return !schedule_commitment.IsNull() ||
           Fail(why, "bank_page_inclusion_engine:schedule_commitment");
}

uint256 ComputeBankPageInclusionTraceRoot(const uint256& schedule_commitment,
                                          const uint256& bank_page_byte_root,
                                          const std::vector<uint256>& page_roots)
{
    std::vector<unsigned char> bytes;
    WriteDomain(bytes, kBankPageInclusionTraceDomain);
    WriteUint256(bytes, schedule_commitment);
    WriteUint256(bytes, bank_page_byte_root);
    WriteU64(bytes, static_cast<uint64_t>(page_roots.size()));
    for (const uint256& root : page_roots) WriteUint256(bytes, root);
    return Sha256d(bytes);
}

} // namespace

bool BuildRCStage3CoupledBankSeedXofEngineReceipt(
    const RCStage3SuccinctProof& statement,
    const CBlockHeader& header,
    const RCStage3CoupledShape& shape,
    std::vector<unsigned char>& out_engine_receipt,
    uint256& out_trace_root,
    std::string* why)
{
    out_engine_receipt.clear();
    out_trace_root.SetNull();
    if (RCStage3HeaderCommitment(header) != statement.public_inputs.header_commitment) {
        return Fail(why, "bank_seed_xof_engine:header_commitment");
    }
    RCStage3CoupledBankProduct product;
    if (!ProveRCStage3CoupledBankProduct(statement, header, shape, product, why)) {
        return Fail(why, "bank_seed_xof_engine:prove");
    }
    if (!VerifyBankSeedXofBundles(product, why)) return false;

    DataStream header_ss{};
    header_ss << header;
    std::vector<unsigned char> body;
    WriteU32(body, kBankSeedXofEngineMagic);
    WriteU16(body, kBankSeedXofEngineVersion);
    WriteU32(body, static_cast<uint32_t>(header_ss.size()));
    for (std::byte b : header_ss) {
        body.push_back(static_cast<unsigned char>(b));
    }
    WriteU32(body, static_cast<uint32_t>(product.pages.size()));
    WriteUint256(body, product.seed_xof_endpoint_root);
    if (!SerializeFlatBoundaryBundleProofs(product.bank_root_seed.proof, body)) {
        return Fail(why, "bank_seed_xof_engine:root_codec");
    }
    for (const auto& page : product.pages) {
        WriteU32(body, page.page_index);
        if (!SerializeFlatBoundaryBundleProofs(page.page_seed.proof, body) ||
            !SerializeFlatBoundaryBundleProofs(page.mantissa_proof, body) ||
            !SerializeFlatBoundaryBundleProofs(page.scale_proof, body)) {
            return Fail(why, "bank_seed_xof_engine:page_codec");
        }
    }
    if (body.size() > kRCStage3CoupledMaxEngineReceiptBytes) {
        return Fail(why, "bank_seed_xof_engine:oversize");
    }
    out_trace_root = ComputeBankSeedXofEngineTraceRoot(product);
    out_engine_receipt = std::move(body);
    return true;
}

bool VerifyRCStage3CoupledBankSeedXofEngineReceipt(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const std::vector<unsigned char>& engine_receipt,
    uint256& out_trace_root,
    std::string* why)
{
    out_trace_root.SetNull();
    Reader reader(engine_receipt);
    uint32_t magic{0};
    uint16_t version{0};
    uint32_t header_len{0};
    std::vector<unsigned char> header_bytes;
    if (!reader.ReadU32(magic) || magic != kBankSeedXofEngineMagic ||
        !reader.ReadU16(version) || version != kBankSeedXofEngineVersion ||
        !reader.ReadU32(header_len) || header_len == 0 ||
        !reader.ReadBytes(header_len, header_bytes)) {
        return Fail(why, "bank_seed_xof_engine:header_prefix");
    }
    CBlockHeader header;
    try {
        DataStream ss{header_bytes};
        ss >> header;
        if (!ss.empty()) return Fail(why, "bank_seed_xof_engine:header_trailing");
    } catch (...) {
        return Fail(why, "bank_seed_xof_engine:header_decode");
    }
    if (RCStage3HeaderCommitment(header) != statement.public_inputs.header_commitment) {
        return Fail(why, "bank_seed_xof_engine:header_commitment");
    }

    RCStage3CoupledBankProduct product;
    if (!BuildRCStage3CoupledBankProduct(statement, header, shape, product, why)) {
        return Fail(why, "bank_seed_xof_engine:rebuild");
    }

    uint32_t page_count{0};
    uint256 seed_xof_endpoint_root;
    if (!reader.ReadU32(page_count) || page_count != product.pages.size() ||
        !reader.ReadUint256(seed_xof_endpoint_root) ||
        seed_xof_endpoint_root != product.seed_xof_endpoint_root) {
        return Fail(why, "bank_seed_xof_engine:header");
    }
    if (!ReadFlatBoundaryBundleProofs(reader, product.bank_root_seed.proof)) {
        return Fail(why, "bank_seed_xof_engine:root_decode");
    }
    product.bank_root_seed.proof.endpoint = RCStage3RelationEndpoint::CoupledBankSeedXof;
    product.bank_root_seed.proof.statement_commitment = product.statement_commitment;
    product.bank_root_seed.proof.manifest_commitment =
        product.bank_root_seed.manifest.commitment;
    for (uint32_t i = 0; i < page_count; ++i) {
        uint32_t page_index{0};
        if (!reader.ReadU32(page_index) || page_index != i ||
            !ReadFlatBoundaryBundleProofs(reader, product.pages[i].page_seed.proof) ||
            !ReadFlatBoundaryBundleProofs(reader, product.pages[i].mantissa_proof) ||
            !ReadFlatBoundaryBundleProofs(reader, product.pages[i].scale_proof)) {
            return Fail(why, "bank_seed_xof_engine:page_decode:" + std::to_string(i));
        }
        auto& page = product.pages[i];
        page.page_seed.proof.endpoint = RCStage3RelationEndpoint::CoupledBankSeedXof;
        page.page_seed.proof.statement_commitment = product.statement_commitment;
        page.page_seed.proof.manifest_commitment = page.page_seed.manifest.commitment;
        page.mantissa_proof.endpoint = RCStage3RelationEndpoint::CoupledBankSeedXof;
        page.mantissa_proof.statement_commitment = product.statement_commitment;
        page.mantissa_proof.manifest_commitment = page.mantissa.commitment;
        page.scale_proof.endpoint = RCStage3RelationEndpoint::CoupledBankSeedXof;
        page.scale_proof.statement_commitment = product.statement_commitment;
        page.scale_proof.manifest_commitment = page.scale.commitment;
    }
    if (reader.Remaining() != 0) {
        return Fail(why, "bank_seed_xof_engine:trailing_bytes");
    }
    if (!ValidateRCStage3CoupledBankProductSchedule(statement, header, shape, product,
                                                    why) ||
        !VerifyBankSeedXofBundles(product, why)) {
        return false;
    }
    out_trace_root = ComputeBankSeedXofEngineTraceRoot(product);
    return true;
}

bool BuildRCStage3CoupledBankPageInclusionEngineReceipt(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const uint256& sigma,
    const std::vector<std::vector<int8_t>>& pages,
    std::vector<unsigned char>& out_engine_receipt,
    uint256& out_trace_root,
    std::string* why)
{
    out_engine_receipt.clear();
    out_trace_root.SetNull();
    const uint256 statement_commitment =
        CommitRCStage3CoupledStatement(statement.public_inputs);
    const uint256 shape_commitment = CommitRCStage3CoupledShape(shape);
    if (statement_commitment.IsNull() || shape_commitment.IsNull() || sigma.IsNull() ||
        pages.size() != shape.bank_pages) {
        return Fail(why, "bank_page_inclusion_engine:public");
    }
    const uint64_t page_cells = uint64_t{shape.lobe_width} * shape.lobe_width;
    std::vector<uint8_t> flat;
    flat.reserve(static_cast<size_t>(page_cells) * pages.size());
    std::vector<uint256> page_roots;
    page_roots.reserve(pages.size());
    for (uint32_t i = 0; i < pages.size(); ++i) {
        if (pages[i].size() != page_cells) {
            return Fail(why, "bank_page_inclusion_engine:page_shape");
        }
        HashWriter page_hash;
        page_hash << std::string{"BTX_RC_STAGE3_COUPLED_BANK_PAGE_BYTES_V1"};
        page_hash << i;
        page_hash << static_cast<uint64_t>(pages[i].size());
        for (int8_t value : pages[i]) {
            const auto byte = static_cast<uint8_t>(value);
            flat.push_back(byte);
            page_hash << byte;
        }
        page_roots.push_back(page_hash.GetHash());
    }

    uint256 bank_page_byte_root;
    RCStage3CoupledBankSourceOpening probe;
    if (!BuildRCStage3CoupledBankSourceOpeningForTest(flat, 0, bank_page_byte_root, probe,
                                                     why)) {
        return Fail(why, "bank_page_inclusion_engine:source_root");
    }

    std::vector<BankPageInclusionScheduleEntry> schedule;
    uint256 schedule_commitment;
    if (!BuildBankPageInclusionSchedule(shape, sigma, schedule, schedule_commitment, why)) {
        return false;
    }
    std::set<uint32_t> scheduled_pages;
    for (const auto& entry : schedule) scheduled_pages.insert(entry.page_id);
    if (scheduled_pages.empty()) {
        return Fail(why, "bank_page_inclusion_engine:empty_schedule");
    }
    for (uint32_t page_id : scheduled_pages) {
        if (page_id >= pages.size()) {
            return Fail(why, "bank_page_inclusion_engine:page_id");
        }
    }

    std::vector<unsigned char> body;
    WriteU32(body, kBankPageInclusionEngineMagic);
    WriteU16(body, kBankPageInclusionEngineVersion);
    WriteUint256(body, statement_commitment);
    WriteUint256(body, shape_commitment);
    WriteUint256(body, sigma);
    WriteUint256(body, schedule_commitment);
    WriteUint256(body, bank_page_byte_root);
    WriteU32(body, static_cast<uint32_t>(pages.size()));
    for (uint32_t i = 0; i < pages.size(); ++i) {
        WriteUint256(body, page_roots[i]);
        WriteU32(body, static_cast<uint32_t>(pages[i].size()));
        for (int8_t value : pages[i]) WriteU8(body, static_cast<uint8_t>(value));
    }
    WriteU64(body, static_cast<uint64_t>(schedule.size()));
    for (const auto& entry : schedule) {
        WriteU64(body, entry.schedule_index);
        WriteU32(body, entry.barrier);
        WriteU32(body, entry.lobe);
        WriteU32(body, entry.page_slot);
        WriteU32(body, entry.page_id);
    }
    WriteU32(body, static_cast<uint32_t>(scheduled_pages.size()));
    for (uint32_t page_id : scheduled_pages) WriteU32(body, page_id);

    if (body.size() > kRCStage3CoupledMaxEngineReceiptBytes) {
        return Fail(why, "bank_page_inclusion_engine:oversize");
    }
    out_trace_root =
        ComputeBankPageInclusionTraceRoot(schedule_commitment, bank_page_byte_root, page_roots);
    out_engine_receipt = std::move(body);
    return true;
}

bool VerifyRCStage3CoupledBankPageInclusionEngineReceipt(
    const RCStage3CoupledShape& shape,
    const uint256& statement_commitment,
    const uint256& coupled_shape_commitment,
    const uint256& sigma,
    const std::vector<unsigned char>& engine_receipt,
    uint256& out_trace_root,
    std::string* why)
{
    out_trace_root.SetNull();
    Reader reader(engine_receipt);
    uint32_t magic{0};
    uint16_t version{0};
    uint256 got_statement;
    uint256 got_shape;
    uint256 got_sigma;
    uint256 schedule_commitment;
    uint256 bank_page_byte_root;
    uint32_t page_count{0};
    if (!reader.ReadU32(magic) || magic != kBankPageInclusionEngineMagic ||
        !reader.ReadU16(version) || version != kBankPageInclusionEngineVersion ||
        !reader.ReadUint256(got_statement) || got_statement != statement_commitment ||
        !reader.ReadUint256(got_shape) || got_shape != coupled_shape_commitment ||
        !reader.ReadUint256(got_sigma) || got_sigma != sigma ||
        !reader.ReadUint256(schedule_commitment) ||
        !reader.ReadUint256(bank_page_byte_root) || !reader.ReadU32(page_count) ||
        page_count != shape.bank_pages) {
        return Fail(why, "bank_page_inclusion_engine:header");
    }

    const uint64_t page_cells = uint64_t{shape.lobe_width} * shape.lobe_width;
    std::vector<uint8_t> flat;
    std::vector<uint256> page_roots(page_count);
    for (uint32_t i = 0; i < page_count; ++i) {
        uint32_t nbytes{0};
        std::vector<unsigned char> page_bytes;
        if (!reader.ReadUint256(page_roots[i]) || page_roots[i].IsNull() ||
            !reader.ReadU32(nbytes) || nbytes != page_cells ||
            !reader.ReadBytes(nbytes, page_bytes)) {
            return Fail(why, "bank_page_inclusion_engine:page_bytes");
        }
        HashWriter page_hash;
        page_hash << std::string{"BTX_RC_STAGE3_COUPLED_BANK_PAGE_BYTES_V1"};
        page_hash << i;
        page_hash << static_cast<uint64_t>(page_bytes.size());
        for (unsigned char byte : page_bytes) {
            flat.push_back(byte);
            page_hash << byte;
        }
        if (page_hash.GetHash() != page_roots[i]) {
            return Fail(why, "bank_page_inclusion_engine:page_root_mismatch");
        }
    }

    uint256 rebuilt_root;
    RCStage3CoupledBankSourceOpening probe;
    if (!BuildRCStage3CoupledBankSourceOpeningForTest(flat, 0, rebuilt_root, probe, why) ||
        rebuilt_root != bank_page_byte_root) {
        return Fail(why, "bank_page_inclusion_engine:bank_root");
    }

    std::vector<BankPageInclusionScheduleEntry> expected;
    uint256 expected_schedule;
    if (!BuildBankPageInclusionSchedule(shape, sigma, expected, expected_schedule, why) ||
        expected_schedule != schedule_commitment) {
        return Fail(why, "bank_page_inclusion_engine:schedule_mismatch");
    }
    uint64_t schedule_len{0};
    if (!reader.ReadU64(schedule_len) || schedule_len != expected.size()) {
        return Fail(why, "bank_page_inclusion_engine:schedule_len");
    }
    for (uint64_t i = 0; i < schedule_len; ++i) {
        BankPageInclusionScheduleEntry entry;
        if (!reader.ReadU64(entry.schedule_index) || !reader.ReadU32(entry.barrier) ||
            !reader.ReadU32(entry.lobe) || !reader.ReadU32(entry.page_slot) ||
            !reader.ReadU32(entry.page_id) ||
            !(entry == expected[static_cast<size_t>(i)])) {
            return Fail(why, "bank_page_inclusion_engine:schedule_entry");
        }
    }

    std::set<uint32_t> expected_pages;
    for (const auto& entry : expected) expected_pages.insert(entry.page_id);
    uint32_t scheduled_page_count{0};
    if (!reader.ReadU32(scheduled_page_count) ||
        scheduled_page_count != expected_pages.size()) {
        return Fail(why, "bank_page_inclusion_engine:scheduled_pages");
    }
    for (uint32_t i = 0; i < scheduled_page_count; ++i) {
        uint32_t page_id{0};
        if (!reader.ReadU32(page_id) || expected_pages.count(page_id) == 0) {
            return Fail(why, "bank_page_inclusion_engine:scheduled_page_id");
        }
        expected_pages.erase(page_id);
    }
    if (!expected_pages.empty() || reader.Remaining() != 0) {
        return Fail(why, "bank_page_inclusion_engine:trailing");
    }
    out_trace_root =
        ComputeBankPageInclusionTraceRoot(schedule_commitment, bank_page_byte_root, page_roots);
    return true;
}


namespace {

bool VerifyProofOnlyEngine(const RCStage3SuccinctProof& statement,
                           const RCStage3CoupledRelationReceipt& receipt,
                           std::string* why)
{
    if (receipt.engine == RCStage3CoupledProofEngine::BankDequantPagesV1) {
        if (receipt.role != RCStage3RelationRole::CoupledBank) {
            return Fail(why, std::string(RCStage3RelationRoleName(receipt.role)) +
                                 ":bank_dequant_engine_wrong_role");
        }
        uint256 trace_root;
        if (!VerifyRCStage3CoupledBankDequantEngineReceipt(
                receipt.shape, receipt.statement_commitment,
                receipt.coupled_shape_commitment, receipt.sigma, receipt.engine_receipt,
                trace_root, why)) {
            return false;
        }
        if (trace_root != receipt.trace_root) {
            return Fail(why, "coupled:bank:bank_dequant_engine_trace_root");
        }
        return true;
    }
    if (receipt.engine == RCStage3CoupledProofEngine::GemmDotTilesV1) {
        if (receipt.role != RCStage3RelationRole::CoupledGemm) {
            return Fail(why, std::string(RCStage3RelationRoleName(receipt.role)) +
                                 ":gemm_dot_engine_wrong_role");
        }
        uint256 trace_root;
        if (!VerifyRCStage3CoupledGemmDotEngineReceipt(
                receipt.shape, receipt.statement_commitment,
                receipt.coupled_shape_commitment, receipt.sigma, receipt.engine_receipt,
                trace_root, why)) {
            return false;
        }
        if (trace_root != receipt.trace_root) {
            return Fail(why, "coupled:gemm:gemm_dot_engine_trace_root");
        }
        return true;
    }
    if (receipt.engine == RCStage3CoupledProofEngine::BankSeedXofV1) {
        if (receipt.role != RCStage3RelationRole::CoupledBank) {
            return Fail(why, std::string(RCStage3RelationRoleName(receipt.role)) +
                                 ":bank_seed_xof_engine_wrong_role");
        }
        uint256 trace_root;
        if (!VerifyRCStage3CoupledBankSeedXofEngineReceipt(
                statement, receipt.shape, receipt.engine_receipt, trace_root, why)) {
            return false;
        }
        if (trace_root != receipt.trace_root) {
            return Fail(why, "coupled:bank:bank_seed_xof_engine_trace_root");
        }
        return true;
    }
    if (receipt.engine == RCStage3CoupledProofEngine::BankPageInclusionV1) {
        if (receipt.role != RCStage3RelationRole::CoupledBank) {
            return Fail(why, std::string(RCStage3RelationRoleName(receipt.role)) +
                                 ":bank_page_inclusion_engine_wrong_role");
        }
        uint256 trace_root;
        if (!VerifyRCStage3CoupledBankPageInclusionEngineReceipt(
                receipt.shape, receipt.statement_commitment,
                receipt.coupled_shape_commitment, receipt.sigma, receipt.engine_receipt,
                trace_root, why)) {
            return false;
        }
        if (trace_root != receipt.trace_root) {
            return Fail(why, "coupled:bank:bank_page_inclusion_engine_trace_root");
        }
        return true;
    }

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
    // BankDequantPagesV1 + GemmDotTilesV1 + BankSeedXofV1 + BankPageInclusionV1
    // are real local engines (BankSeedXof/BankPageInclusion AirGaps cleared via
    // measured prototypes). Exchange/Permutation/Mix/Extract still fail closed
    // on ProofOnlyV1 recursive stubs; Barrier/Digest lack immutable AIRs;
    // CommitmentOpeningBridge + RecursiveAggregation remain on every role.
    return Fail(why,
                "proof_engines_missing:exchange,permutation,mix,extract,"
                "barrier,digest");
}

} // namespace matmul::v4::rc
