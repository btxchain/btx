// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_episode_air.h>

#include <crypto/sha256.h>
#include <matmul/matmul_v4_rc_gkr_field_ext3.h>
#include <matmul/matmul_v4_rc_stage3_role_bytecode.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>

namespace matmul::v4::rc {
namespace {

using air_quotient::AirConstraintSystem;
using air_quotient::AirKind;
using gkr_field::Fp3;
namespace gf = gkr_field;
namespace cb = constraint_bytecode;

constexpr uint32_t GEMM_COL_GF = 0;
constexpr uint32_t GEMM_COL_A = 1;
constexpr uint32_t GEMM_COL_B = 2;
constexpr uint32_t GEMM_COLUMNS = 3;
constexpr uint32_t WIRING_COL_U = 0;
constexpr uint32_t WIRING_COL_V = 1;
constexpr uint32_t WIRING_COLUMNS = 2;

constexpr uint64_t Bit(RCStage3EpisodeObligation obligation)
{
    return static_cast<uint64_t>(obligation);
}

constexpr uint64_t GEMM_LOCAL =
    Bit(RCStage3EpisodeObligation::GemmSumcheck);
constexpr uint64_t WIRING_LOCAL =
    Bit(RCStage3EpisodeObligation::WiringCopies);

bool Fail(std::string* why, const std::string& message)
{
    if (why != nullptr) *why = "stage3:episode_air:" + message;
    return false;
}

template <typename T>
std::optional<T> FailOptional(std::string* why, const std::string& message)
{
    Fail(why, message);
    return std::nullopt;
}

bool IsPowerOfTwo(uint32_t value)
{
    return value >= 2 && (value & (value - 1)) == 0;
}

uint32_t ExpectedColumns(RCStage3EpisodeAirFamily family)
{
    switch (family) {
    case RCStage3EpisodeAirFamily::GemmEndpointFp3V1:
        return GEMM_COLUMNS;
    case RCStage3EpisodeAirFamily::ExtractSamplerCoreFp3V1:
        return air_quotient::kRcSamplerNumCols;
    case RCStage3EpisodeAirFamily::WiringEqualityFp3V1:
        return WIRING_COLUMNS;
    }
    return 0;
}

uint32_t NextPowerOfTwo(uint64_t value)
{
    if (value == 0 || value > uint64_t{1} << 31) return 0;
    uint64_t out = 1;
    while (out < value) out <<= 1;
    return static_cast<uint32_t>(out);
}

uint32_t ExpectedCoefficients(RCStage3EpisodeAirFamily family,
                              uint32_t n_rows)
{
    switch (family) {
    case RCStage3EpisodeAirFamily::GemmEndpointFp3V1:
    case RCStage3EpisodeAirFamily::WiringEqualityFp3V1:
        return n_rows;
    case RCStage3EpisodeAirFamily::ExtractSamplerCoreFp3V1:
        // RcSampler's degree-4 everywhere acceptance polynomial gives
        // quotient length 3*(N-1); FRI commits the next power of two of the
        // maximum trace/quotient coefficient length.
        if (n_rows >
            (std::numeric_limits<uint32_t>::max() + uint64_t{3}) / 3) {
            return 0;
        }
        return NextPowerOfTwo(3 * uint64_t{n_rows} - 3);
    }
    return 0;
}

bool FamilyMatchesRole(RCStage3EpisodeAirFamily family,
                       RCStage3RelationRole role)
{
    switch (family) {
    case RCStage3EpisodeAirFamily::GemmEndpointFp3V1:
        return role == RCStage3RelationRole::EpisodeGemm;
    case RCStage3EpisodeAirFamily::ExtractSamplerCoreFp3V1:
        return role == RCStage3RelationRole::EpisodeExtract;
    case RCStage3EpisodeAirFamily::WiringEqualityFp3V1:
        return role == RCStage3RelationRole::EpisodeWiring;
    }
    return false;
}

uint64_t LocalObligations(RCStage3EpisodeAirFamily family)
{
    switch (family) {
    case RCStage3EpisodeAirFamily::GemmEndpointFp3V1:
        return GEMM_LOCAL;
    case RCStage3EpisodeAirFamily::ExtractSamplerCoreFp3V1:
        // The RcSampler core is a real proof-only relation, but none of the
        // broad Stage-3 Extract obligation names is fully discharged: its
        // ChaCha binding and signed-int embedding are explicit residuals and
        // this adapter has no all-tile shard manifest.
        return 0;
    case RCStage3EpisodeAirFamily::WiringEqualityFp3V1:
        return WIRING_LOCAL;
    }
    return 0;
}

bool ValidatePin(const RCStage3EpisodeAirPublicPin& pin, std::string* why)
{
    if (pin.magic != kRCStage3EpisodeAirPinMagic) {
        return Fail(why, "bad_pin_magic");
    }
    if (pin.version != kRCStage3EpisodeAirPinVersion) {
        return Fail(why, "bad_pin_version");
    }
    if (pin.registry_version != kRCStage3EpisodeAirRegistryVersion) {
        return Fail(why, "bad_registry_version");
    }
    if (!IsRCStage3EpisodeRole(pin.role) ||
        !FamilyMatchesRole(pin.family, pin.role)) {
        return Fail(why, "family_role_mismatch");
    }
    if (pin.statement_commitment.IsNull()) {
        return Fail(why, "null_statement_commitment");
    }
    if (pin.shard_count == 0 ||
        pin.shard_count > kRCStage3EpisodeAirMaxShards ||
        pin.shard_index >= pin.shard_count) {
        return Fail(why, "bad_shard_position");
    }
    if (!IsPowerOfTwo(pin.n_rows) ||
        pin.n_rows > kRCFriMaxCoeffsHard ||
        pin.logical_rows == 0 ||
        pin.logical_rows > pin.n_rows) {
        return Fail(why, "bad_row_shape");
    }
    const uint32_t expected_coeffs =
        ExpectedCoefficients(pin.family, pin.n_rows);
    if (expected_coeffs == 0 ||
        expected_coeffs > kRCFriMaxCoeffsHard ||
        pin.n_coeffs != expected_coeffs) {
        return Fail(why, "noncanonical_n_coeffs");
    }
    if (pin.family == RCStage3EpisodeAirFamily::ExtractSamplerCoreFp3V1) {
        if (pin.extract_scale_e > 3) return Fail(why, "bad_extract_scale");
    } else if (pin.extract_scale_e != 0) {
        return Fail(why, "nonzero_unused_extract_scale");
    }
    const uint32_t expected = ExpectedColumns(pin.family);
    if (expected == 0 || expected > kRCStage3EpisodeAirMaxPinnedColumns ||
        pin.column_roots.size() != expected) {
        return Fail(why, "bad_column_root_count");
    }
    for (uint32_t i = 0; i < expected; ++i) {
        if (pin.column_roots[i].column != i) {
            return Fail(why, "noncanonical_column_order");
        }
        if (pin.column_roots[i].root.IsNull()) {
            return Fail(why, "null_column_root");
        }
    }
    return true;
}

class Writer {
public:
    void U8(uint8_t value) { m_bytes.push_back(value); }
    void U16(uint16_t value)
    {
        for (unsigned i = 0; i < 2; ++i) U8(value >> (8 * i));
    }
    void U32(uint32_t value)
    {
        for (unsigned i = 0; i < 4; ++i) U8(value >> (8 * i));
    }
    void Uint256(const uint256& value)
    {
        m_bytes.insert(m_bytes.end(), value.data(), value.data() + value.size());
    }
    std::vector<unsigned char> Take() { return std::move(m_bytes); }

private:
    std::vector<unsigned char> m_bytes;
};

class Reader {
public:
    explicit Reader(const std::vector<unsigned char>& bytes)
        : m_pos(bytes.data()), m_end(bytes.data() + bytes.size())
    {
    }

    bool U8(uint8_t& value)
    {
        if (Remaining() < 1) return false;
        value = *m_pos++;
        return true;
    }
    bool U16(uint16_t& value)
    {
        if (Remaining() < 2) return false;
        value = static_cast<uint16_t>(m_pos[0]) |
                (static_cast<uint16_t>(m_pos[1]) << 8);
        m_pos += 2;
        return true;
    }
    bool U32(uint32_t& value)
    {
        if (Remaining() < 4) return false;
        value = 0;
        for (unsigned i = 0; i < 4; ++i) {
            value |= static_cast<uint32_t>(m_pos[i]) << (8 * i);
        }
        m_pos += 4;
        return true;
    }
    bool Uint256(uint256& value)
    {
        if (Remaining() < value.size()) return false;
        std::copy_n(m_pos, value.size(), value.data());
        m_pos += value.size();
        return true;
    }
    size_t Remaining() const
    {
        return static_cast<size_t>(m_end - m_pos);
    }

private:
    const unsigned char* m_pos;
    const unsigned char* m_end;
};

uint256 Sha256d(const std::vector<unsigned char>& bytes)
{
    unsigned char first[CSHA256::OUTPUT_SIZE];
    uint256 out;
    CSHA256().Write(bytes.data(), bytes.size()).Finalize(first);
    CSHA256().Write(first, sizeof(first)).Finalize(out.data());
    return out;
}

uint256 TaggedHash(const char* domain,
                   const std::vector<unsigned char>& payload)
{
    std::vector<unsigned char> bytes;
    bytes.insert(bytes.end(), domain, domain + std::strlen(domain));
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return Sha256d(bytes);
}

std::vector<uint256> Roots(const RCStage3EpisodeAirPublicPin& pin,
                           uint32_t begin, uint32_t end)
{
    std::vector<uint256> roots;
    roots.reserve(end - begin);
    for (uint32_t i = begin; i < end; ++i) {
        roots.push_back(pin.column_roots[i].root);
    }
    return roots;
}

void PinAllRoots(const RCStage3EpisodeAirPublicPin& pin,
                 AirConstraintSystem<Fp3>& cs)
{
    cs.preprocessed_roots.clear();
    cs.preprocessed_roots.reserve(pin.column_roots.size());
    for (const auto& root : pin.column_roots) {
        cs.preprocessed_roots.emplace_back(root.column, root.root);
    }
}

AirConstraintSystem<Fp3> BuildGemmEndpoint(
    const RCStage3EpisodeAirPublicPin& pin)
{
    cb::ProgramTable table;
    AirConstraintSystem<Fp3> cs;
    if (!BuildRCStage3EpisodeLocalKernelProgramTable(
            RCStage3EpisodeAirFamily::GemmEndpointFp3V1,
            table) ||
        !cb::BuildAirConstraintSystemFromProgramTable(
            table, pin.n_rows, cs)) {
        return {};
    }
    PinAllRoots(pin, cs);
    return cs;
}

AirConstraintSystem<Fp3> BuildWiringEquality(
    const RCStage3EpisodeAirPublicPin& pin)
{
    cb::ProgramTable table;
    AirConstraintSystem<Fp3> cs;
    if (!BuildRCStage3EpisodeLocalKernelProgramTable(
            RCStage3EpisodeAirFamily::WiringEqualityFp3V1,
            table) ||
        !cb::BuildAirConstraintSystemFromProgramTable(
            table, pin.n_rows, cs)) {
        return {};
    }
    PinAllRoots(pin, cs);
    return cs;
}

Fp3 RcSamplerChallenge(const uint256& seed, const char* label,
                       const std::vector<uint256>& base_roots,
                       uint32_t n_rows, uint32_t n_coeffs)
{
    const uint256 digest = air_quotient::AirChallengeDigest(
        seed, label, base_roots, {n_rows, n_coeffs});
    return gf::FromChallengeBytes3(digest.data());
}

const RCStage3EpisodeAirCapability* FindCapability(
    RCStage3RelationRole role, RCStage3EpisodeAirFamily family)
{
    static const std::array<RCStage3EpisodeAirCapability, 3> CAPS{{
        {RCStage3RelationRole::EpisodeGemm,
         RCStage3EpisodeAirFamily::GemmEndpointFp3V1,
         GEMM_LOCAL, true, false,
         "proof-only gf=a*b endpoint; no every-layer manifest, operand "
         "openings, or signed accumulator range proof"},
        {RCStage3RelationRole::EpisodeExtract,
         RCStage3EpisodeAirFamily::ExtractSamplerCoreFp3V1,
         0, true, false,
         "proof-only RcSampler low-degree core; ChaCha binding, signed-int "
         "embedding, scale provenance, and all-tile closure remain open"},
        {RCStage3RelationRole::EpisodeWiring,
         RCStage3EpisodeAirFamily::WiringEqualityFp3V1,
         WIRING_LOCAL, true, false,
         "proof-only direct equality; transpose, residual, order, and "
         "all-edge manifest remain open"},
    }};
    const auto it = std::find_if(
        CAPS.begin(), CAPS.end(), [&](const auto& cap) {
            return cap.role == role && cap.family == family;
        });
    return it == CAPS.end() ? nullptr : &*it;
}

} // namespace

const char* RCStage3EpisodeAirFamilyName(RCStage3EpisodeAirFamily family)
{
    switch (family) {
    case RCStage3EpisodeAirFamily::GemmEndpointFp3V1:
        return "gemm_endpoint_fp3_v1";
    case RCStage3EpisodeAirFamily::ExtractSamplerCoreFp3V1:
        return "extract_sampler_core_fp3_v1";
    case RCStage3EpisodeAirFamily::WiringEqualityFp3V1:
        return "wiring_equality_fp3_v1";
    }
    return "unknown";
}

std::vector<RCStage3EpisodeAirCapability>
CurrentRCStage3EpisodeAirCapabilities()
{
    std::vector<RCStage3EpisodeAirCapability> out;
    for (const auto family : {
             RCStage3EpisodeAirFamily::GemmEndpointFp3V1,
             RCStage3EpisodeAirFamily::ExtractSamplerCoreFp3V1,
             RCStage3EpisodeAirFamily::WiringEqualityFp3V1}) {
        RCStage3RelationRole role{};
        switch (family) {
        case RCStage3EpisodeAirFamily::GemmEndpointFp3V1:
            role = RCStage3RelationRole::EpisodeGemm;
            break;
        case RCStage3EpisodeAirFamily::ExtractSamplerCoreFp3V1:
            role = RCStage3RelationRole::EpisodeExtract;
            break;
        case RCStage3EpisodeAirFamily::WiringEqualityFp3V1:
            role = RCStage3RelationRole::EpisodeWiring;
            break;
        }
        out.push_back(*FindCapability(role, family));
    }
    return out;
}

bool BuildRCStage3EpisodeLocalKernelProgramTable(
    RCStage3EpisodeAirFamily family,
    cb::ProgramTable& out,
    std::string* why)
{
    out = {};
    cb::Program program;
    program.kind = AirKind::kEverywhere;
    program.constraint_ordinal = 0;
    switch (family) {
    case RCStage3EpisodeAirFamily::GemmEndpointFp3V1:
        program.role = RCStage3RelationRole::EpisodeGemm;
        program.declared_degree = 2;
        program.current_width = GEMM_COLUMNS;
        program.next_width = GEMM_COLUMNS;
        program.instructions = {
            {cb::Opcode::Current, GEMM_COL_GF, 0, Fp3::Zero()},
            {cb::Opcode::Current, GEMM_COL_A, 0, Fp3::Zero()},
            {cb::Opcode::Current, GEMM_COL_B, 0, Fp3::Zero()},
            {cb::Opcode::Mul, 1, 2, Fp3::Zero()},
            {cb::Opcode::Sub, 0, 3, Fp3::Zero()},
        };
        break;
    case RCStage3EpisodeAirFamily::WiringEqualityFp3V1:
        program.role = RCStage3RelationRole::EpisodeWiring;
        program.declared_degree = 1;
        program.current_width = WIRING_COLUMNS;
        program.next_width = WIRING_COLUMNS;
        program.instructions = {
            {cb::Opcode::Current, WIRING_COL_U, 0, Fp3::Zero()},
            {cb::Opcode::Current, WIRING_COL_V, 0, Fp3::Zero()},
            {cb::Opcode::Sub, 0, 1, Fp3::Zero()},
        };
        break;
    case RCStage3EpisodeAirFamily::ExtractSamplerCoreFp3V1:
        // Full RcSampler local kernel as bytecode, committed under the
        // EpisodeExtract role. scale_e=0 is the canonical wired default; the
        // C_rho-assembling lane calls the scale_e-parameterized builder
        // directly for other public exponents (as on the coupled side).
        return BuildRCStage3EpisodeExtractLocalKernelProgramTable(
            0, out, why);
    default:
        return Fail(why, "bytecode_family");
    }
    out.role = program.role;
    out.current_width = program.current_width;
    out.next_width = program.next_width;
    out.programs.push_back(std::move(program));
    return cb::ValidateProgramTable(out, why);
}

bool SerializeRCStage3EpisodeAirPublicPin(
    const RCStage3EpisodeAirPublicPin& pin,
    std::vector<unsigned char>& out,
    std::string* why)
{
    out.clear();
    if (!ValidatePin(pin, why)) return false;
    Writer writer;
    writer.U32(pin.magic);
    writer.U16(pin.version);
    writer.U16(pin.registry_version);
    writer.U16(static_cast<uint16_t>(pin.role));
    writer.U8(static_cast<uint8_t>(pin.family));
    writer.U8(0);
    writer.Uint256(pin.statement_commitment);
    writer.U32(pin.shard_index);
    writer.U32(pin.shard_count);
    writer.U32(pin.logical_rows);
    writer.U32(pin.n_rows);
    writer.U32(pin.n_coeffs);
    writer.U8(pin.extract_scale_e);
    writer.U8(0);
    writer.U8(0);
    writer.U8(0);
    writer.U32(static_cast<uint32_t>(pin.column_roots.size()));
    for (const auto& root : pin.column_roots) {
        writer.U32(root.column);
        writer.Uint256(root.root);
    }
    out = writer.Take();
    return true;
}

std::optional<RCStage3EpisodeAirPublicPin>
DeserializeRCStage3EpisodeAirPublicPin(
    const std::vector<unsigned char>& bytes,
    std::string* why)
{
    // Fixed header (72) plus at most 64 (column,root) records.
    constexpr size_t HEADER_BYTES = 72;
    constexpr size_t ROOT_BYTES = 36;
    if (bytes.size() < HEADER_BYTES ||
        bytes.size() > HEADER_BYTES +
                           kRCStage3EpisodeAirMaxPinnedColumns * ROOT_BYTES) {
        return FailOptional<RCStage3EpisodeAirPublicPin>(why, "pin_size");
    }
    Reader reader(bytes);
    RCStage3EpisodeAirPublicPin pin;
    uint16_t role{0};
    uint8_t family{0};
    uint8_t reserved{0};
    uint8_t reserved_scale[3]{};
    uint32_t roots{0};
    if (!reader.U32(pin.magic) || !reader.U16(pin.version) ||
        !reader.U16(pin.registry_version) || !reader.U16(role) ||
        !reader.U8(family) || !reader.U8(reserved) ||
        !reader.Uint256(pin.statement_commitment) ||
        !reader.U32(pin.shard_index) || !reader.U32(pin.shard_count) ||
        !reader.U32(pin.logical_rows) || !reader.U32(pin.n_rows) ||
        !reader.U32(pin.n_coeffs) || !reader.U8(pin.extract_scale_e) ||
        !reader.U8(reserved_scale[0]) || !reader.U8(reserved_scale[1]) ||
        !reader.U8(reserved_scale[2]) || !reader.U32(roots)) {
        return FailOptional<RCStage3EpisodeAirPublicPin>(why, "truncated_pin");
    }
    if (reserved != 0 || reserved_scale[0] != 0 ||
        reserved_scale[1] != 0 || reserved_scale[2] != 0) {
        return FailOptional<RCStage3EpisodeAirPublicPin>(why, "nonzero_reserved");
    }
    if (roots > kRCStage3EpisodeAirMaxPinnedColumns ||
        roots > reader.Remaining() / ROOT_BYTES ||
        reader.Remaining() != static_cast<size_t>(roots) * ROOT_BYTES) {
        return FailOptional<RCStage3EpisodeAirPublicPin>(
            why, "noncanonical_root_length");
    }
    pin.role = static_cast<RCStage3RelationRole>(role);
    pin.family = static_cast<RCStage3EpisodeAirFamily>(family);
    pin.column_roots.resize(roots);
    for (auto& root : pin.column_roots) {
        if (!reader.U32(root.column) || !reader.Uint256(root.root)) {
            return FailOptional<RCStage3EpisodeAirPublicPin>(
                why, "truncated_root");
        }
    }
    if (reader.Remaining() != 0 || !ValidatePin(pin, why)) {
        return std::nullopt;
    }
    std::vector<unsigned char> canonical;
    if (!SerializeRCStage3EpisodeAirPublicPin(pin, canonical, why) ||
        canonical != bytes) {
        return FailOptional<RCStage3EpisodeAirPublicPin>(
            why, "noncanonical_pin");
    }
    return pin;
}

uint256 ComputeRCStage3EpisodeAirPinCommitment(
    const RCStage3EpisodeAirPublicPin& pin)
{
    std::vector<unsigned char> bytes;
    if (!SerializeRCStage3EpisodeAirPublicPin(pin, bytes, nullptr)) {
        return {};
    }
    return TaggedHash("BTX_RC_STAGE3_EPISODE_AIR_PIN_V1", bytes);
}

uint256 ComputeRCStage3EpisodeAirSeed(
    const RCStage3SuccinctProof& statement,
    const RCStage3EpisodeAirPublicPin& pin)
{
    if (!ValidatePin(pin, nullptr)) return {};
    if (pin.statement_commitment !=
        RCStage3EpisodeStatementCommitment(statement)) {
        return {};
    }
    // Two-epoch discipline: do not absorb trace roots here. In the Extract
    // family, epoch-2 LogUp roots depend on gamma/alpha, which are themselves
    // derived from this seed plus the epoch-1 base roots. Hashing the finished
    // pin here would create an unprovable fixed point. The complete pin is
    // still outer-committed by ComputeRCStage3EpisodeAirPinCommitment.
    Writer writer;
    writer.U32(pin.magic);
    writer.U16(pin.version);
    writer.U16(pin.registry_version);
    writer.U16(static_cast<uint16_t>(pin.role));
    writer.U8(static_cast<uint8_t>(pin.family));
    writer.U8(0);
    const uint256 statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    writer.Uint256(statement_commitment);
    writer.U32(pin.shard_index);
    writer.U32(pin.shard_count);
    writer.U32(pin.logical_rows);
    writer.U32(pin.n_rows);
    writer.U32(pin.n_coeffs);
    writer.U8(pin.extract_scale_e);
    writer.U8(0);
    writer.U8(0);
    writer.U8(0);
    writer.U32(ExpectedColumns(pin.family));
    return TaggedHash("BTX_RC_STAGE3_EPISODE_AIR_SEED_V1",
                      writer.Take());
}

bool ResolveRCStage3EpisodeAirConstraintSystem(
    const RCStage3SuccinctProof& statement,
    const RCStage3EpisodeAirPublicPin& pin,
    AirConstraintSystem<Fp3>& out,
    std::string* why)
{
    out = {};
    if (!ValidatePin(pin, why)) return false;
    if (statement.statement == RCStage3StatementKind::Coupled) {
        return Fail(why, "coupled_only_statement");
    }
    if (pin.statement_commitment !=
        RCStage3EpisodeStatementCommitment(statement)) {
        return Fail(why, "statement_commitment_mismatch");
    }
    if (FindCapability(pin.role, pin.family) == nullptr) {
        return Fail(why, "unregistered_family");
    }
    const uint256 seed = ComputeRCStage3EpisodeAirSeed(statement, pin);
    if (seed.IsNull()) return Fail(why, "seed");

    switch (pin.family) {
    case RCStage3EpisodeAirFamily::GemmEndpointFp3V1:
        out = BuildGemmEndpoint(pin);
        break;
    case RCStage3EpisodeAirFamily::ExtractSamplerCoreFp3V1: {
        const std::vector<uint256> base_roots =
            Roots(pin, 0, air_quotient::kRcSamplerBaseCols);
        const Fp3 gamma = RcSamplerChallenge(
            seed, "airq_gamma", base_roots, pin.n_rows, pin.n_coeffs);
        const Fp3 alpha = RcSamplerChallenge(
            seed, "airq_alpha", base_roots, pin.n_rows, pin.n_coeffs);
        const gkr_air::TableTM tm;
        out = air_quotient::BuildRcSamplerConstraintSystem<Fp3>(
            pin.n_rows, gamma, alpha, pin.extract_scale_e, tm);
        PinAllRoots(pin, out);
        break;
    }
    case RCStage3EpisodeAirFamily::WiringEqualityFp3V1:
        out = BuildWiringEquality(pin);
        break;
    }
    if (out.n_rows != pin.n_rows ||
        out.n_columns != ExpectedColumns(pin.family) ||
        out.QuotientLen() > pin.n_coeffs ||
        out.constraints.empty()) {
        out = {};
        return Fail(why, "registry_shape");
    }
    return true;
}

RCStage3EpisodeAirReadiness AssessRCStage3EpisodeAirReadiness(
    const RCStage3SuccinctProof& statement,
    const RCStage3EpisodeAirPublicPin& pin)
{
    RCStage3EpisodeAirReadiness out;
    std::string why;
    if (!ValidatePin(pin, &why)) {
        out.gaps.push_back(why);
        return out;
    }
    out.structurally_valid = true;
    AirConstraintSystem<Fp3> cs;
    out.constraint_system_resolved =
        ResolveRCStage3EpisodeAirConstraintSystem(statement, pin, cs, &why);
    if (!out.constraint_system_resolved) {
        out.gaps.push_back(why);
        return out;
    }
    out.locally_enforced_obligations = LocalObligations(pin.family);
    out.missing_obligations =
        RequiredRCStage3EpisodeCoverage(pin.role) &
        ~out.locally_enforced_obligations;
    if (out.missing_obligations != 0) {
        out.gaps.push_back("registered_role_obligations_missing");
    }
    out.gaps.push_back("no_canonical_air_proof_payload_codec");
    out.gaps.push_back("no_complete_all_shard_manifest_or_recursive_root");
    if (pin.family ==
        RCStage3EpisodeAirFamily::ExtractSamplerCoreFp3V1) {
        out.gaps.push_back(
            "extract_chacha_signed_embedding_scale_provenance_and_all_tile_"
            "closure_missing");
        out.gaps.push_back(
            "extract_table_preprocessing_is_verifier_linear_without_"
            "recursive_provenance");
    }
    out.role_complete = false;
    return out;
}

bool VerifyRCStage3EpisodeAirShard(
    const RCStage3SuccinctProof& statement,
    const RCStage3EpisodeAirPublicPin& pin,
    const air_quotient::AirQuotientProof<Fp3>& proof,
    std::string* why)
{
    AirConstraintSystem<Fp3> cs;
    std::string resolve_why;
    if (!ResolveRCStage3EpisodeAirConstraintSystem(
            statement, pin, cs, &resolve_why)) {
        return Fail(why, "resolve:" + resolve_why);
    }
    if (proof.batch.columns.size() != pin.column_roots.size() + 1 ||
        proof.batch.column_len.size() != pin.column_roots.size() + 1 ||
        proof.batch.n_coeffs != pin.n_coeffs) {
        return Fail(why, "proof_shape");
    }
    for (size_t i = 0; i < pin.column_roots.size(); ++i) {
        if (proof.batch.columns[i].root != pin.column_roots[i].root) {
            return Fail(why, "column_root_mismatch");
        }
    }
    const uint256 seed = ComputeRCStage3EpisodeAirSeed(statement, pin);
    std::string air_why;
    if (!air_quotient::AirQuotientVerify<Fp3>(
            cs, proof, seed, &air_why)) {
        return Fail(why, "air:" + air_why);
    }
    if (why != nullptr) *why = "stage3:episode_air:shard_ok_role_incomplete";
    return true;
}

std::vector<RCStage3EpisodeAirRoleGap>
CurrentRCStage3EpisodeAirRoleGaps()
{
    std::vector<RCStage3EpisodeAirRoleGap> gaps;
    const auto roles =
        RequiredRCStage3RelationRoles(RCStage3StatementKind::Episode);
    gaps.reserve(roles.size());
    for (const RCStage3RelationRole role : roles) {
        uint64_t local = 0;
        std::string reason;
        switch (role) {
        case RCStage3RelationRole::EpisodeDeterministicBuilder:
            reason = "no proof-only header/params/seed/XOF builder AIR";
            break;
        case RCStage3RelationRole::EpisodeGemm:
            local = GEMM_LOCAL;
            reason = "endpoint AIR plus a sibling exact every-layer manifest "
                     "and signed-accumulator range AIR exist; exact A/B/Y "
                     "opening/sumcheck/CTL obligations are now pinned, but "
                     "their recursive child proof engines remain";
            break;
        case RCStage3RelationRole::EpisodeExtract:
            reason = "RcSampler low-degree core and a sibling exact all-tile "
                     "interval/root manifest exist; range-to-Extract CTL pins "
                     "and public scale schedules are exact, but the recursive "
                     "roots/hash AIR and ChaCha proof are not executed";
            break;
        case RCStage3RelationRole::EpisodeWiring:
            local = WIRING_LOCAL;
            reason = "direct equality AIR only; transpose, residual, order, "
                     "and all-edge manifest remain";
            break;
        case RCStage3RelationRole::EpisodeTileTree:
            reason = "no proof-only full-stream SHA tile-tree AIR";
            break;
        case RCStage3RelationRole::EpisodeDigest:
            reason = "no proof-only round-root/episode/header/target/PoW "
                     "digest composition AIR";
            break;
        default:
            reason = "non_episode_role";
            break;
        }
        gaps.push_back(
            {role, local,
             RequiredRCStage3EpisodeCoverage(role) & ~local,
             std::move(reason)});
    }
    return gaps;
}

} // namespace matmul::v4::rc
