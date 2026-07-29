// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_episode_header_target.h>
#include <matmul/matmul_v4_rc_stage3_role_bytecode.h>

#include <hash.h>

#include <algorithm>
#include <array>

namespace matmul::v4::rc {
namespace {

namespace aq = air_quotient;
namespace gf = gkr_field;
using gf::Fp3;

constexpr char PIN_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_HEADER_TARGET_PIN_V1";
constexpr char PROOF_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_HEADER_TARGET_PROOF_V1";

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:episode_header_target:" + detail;
    }
    return false;
}

bool DecodeCompactTarget(
    uint32_t n_bits,
    std::array<uint8_t, 32>& out,
    std::string* why)
{
    out.fill(0);
    const uint32_t size = n_bits >> 24;
    uint32_t word = n_bits & 0x007fffffU;
    const bool negative =
        word != 0 && (n_bits & 0x00800000U) != 0;
    const bool overflow =
        word != 0 &&
        (size > 34 ||
         (word > 0xffU && size > 33) ||
         (word > 0xffffU && size > 32));
    if (word == 0 || negative || overflow) {
        return Fail(why, "invalid_compact");
    }
    if (size <= 3) {
        word >>= 8U * (3U - size);
        for (uint32_t i = 0; i < 4; ++i) {
            out[i] = static_cast<uint8_t>(word >> (8U * i));
        }
        return true;
    }
    const uint32_t offset = size - 3;
    for (uint32_t i = 0; i < 3; ++i) {
        const uint8_t byte =
            static_cast<uint8_t>(word >> (8U * i));
        if (offset + i >= out.size()) {
            if (byte != 0) {
                return Fail(why, "compact_overflow");
            }
            continue;
        }
        out[offset + i] = byte;
    }
    return true;
}

uint256 CommitPin(const RCStage3EpisodeHeaderTargetPin& pin)
{
    if (pin.version != kRCStage3EpisodeHeaderTargetVersion ||
        pin.statement_commitment.IsNull() ||
        pin.header_commitment.IsNull() ||
        pin.target.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << PIN_DOMAIN;
    hash << pin.version;
    hash << pin.statement_commitment;
    hash << pin.header_commitment;
    hash << pin.n_bits;
    hash << pin.target;
    return hash.GetHash();
}

uint256 ProofSeed(const RCStage3EpisodeHeaderTargetPin& pin)
{
    if (pin.pin_commitment != CommitPin(pin)) return {};
    HashWriter hash;
    hash << PROOF_DOMAIN;
    hash << pin.pin_commitment;
    return hash.GetHash();
}

std::vector<Fp3> PublicValues(
    const RCStage3EpisodeHeaderTargetPin& pin)
{
    std::vector<Fp3> out;
    out.reserve(kRCStage3EpisodeHeaderTargetPublicCells);
    for (uint32_t i = 0; i < 4; ++i) {
        out.push_back(Fp3::FromFp(
            static_cast<uint8_t>(pin.n_bits >> (8U * i))));
    }
    for (uint8_t byte : pin.header_commitment) {
        out.push_back(Fp3::FromFp(byte));
    }
    for (uint8_t byte : pin.target) {
        out.push_back(Fp3::FromFp(byte));
    }
    return out;
}

} // namespace

bool BuildRCStage3EpisodeHeaderTargetPin(
    const RCStage3SuccinctProof& statement,
    RCStage3EpisodeHeaderTargetPin& out,
    std::string* why)
{
    out = {};
    if (statement.statement != RCStage3StatementKind::Episode &&
        statement.statement != RCStage3StatementKind::Composed) {
        return Fail(why, "statement_kind");
    }
    const auto& public_inputs = statement.public_inputs;
    const uint256 statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    std::array<uint8_t, 32> decoded{};
    if (statement_commitment.IsNull() ||
        public_inputs.header_commitment.IsNull() ||
        public_inputs.target.IsNull() ||
        !DecodeCompactTarget(public_inputs.n_bits, decoded, why) ||
        !std::equal(
            decoded.begin(), decoded.end(),
            public_inputs.target.begin())) {
        return Fail(why, "public_target_projection");
    }
    out.version = kRCStage3EpisodeHeaderTargetVersion;
    out.statement_commitment = statement_commitment;
    out.header_commitment = public_inputs.header_commitment;
    out.n_bits = public_inputs.n_bits;
    out.target = public_inputs.target;
    out.pin_commitment = CommitPin(out);
    return !out.pin_commitment.IsNull() ||
        Fail(why, "pin_commitment");
}

bool BuildRCStage3EpisodeHeaderTargetConstraintSystem(
    const RCStage3EpisodeHeaderTargetPin& pin,
    aq::AirConstraintSystem<Fp3>& out,
    std::string* why)
{
    std::array<uint8_t, 32> expected{};
    if (pin.pin_commitment != CommitPin(pin) ||
        !DecodeCompactTarget(pin.n_bits, expected, why) ||
        !std::equal(
            expected.begin(), expected.end(),
            pin.target.begin())) {
        return Fail(why, "pin");
    }
    out = {};
    out.n_rows = kRCStage3EpisodeHeaderTargetRows;
    out.n_columns = kRCStage3EpisodeHeaderTargetColumns;
    std::vector<Fp3> expected_column(out.n_rows);
    for (uint32_t row = 0; row < out.n_rows; ++row) {
        expected_column[row] = Fp3::FromFp(expected[row]);
    }
    out.preprocessed.emplace_back(
        kRCStage3EpisodeHeaderTargetExpectedByte,
        std::move(expected_column));
    constraint_bytecode::Program program;
    if (!BuildRCStage3EpisodeHeaderTargetConstraintProgram(
            pin, program, why)) {
        return false;
    }
    aq::AirConstraint<Fp3> equality;
    equality.name = "header_target.compact_byte";
    equality.kind = program.kind;
    equality.alg_degree = program.declared_degree;
    equality.eval = [program = std::move(program)](
        const std::vector<Fp3>& current,
        const std::vector<Fp3>& next) {
        Fp3 result = Fp3::Zero();
        if (!constraint_bytecode::EvaluateProgram(
                program, current, next, result)) {
            return Fp3::One();
        }
        return result;
    };
    out.constraints.push_back(std::move(equality));
    return true;
}

uint256 ComputeRCStage3EpisodeHeaderTargetSeed(
    const RCStage3EpisodeHeaderTargetPin& pin)
{
    return ProofSeed(pin);
}

bool BuildRCStage3EpisodeHeaderTargetConstraintProgram(
    const RCStage3EpisodeHeaderTargetPin& pin,
    constraint_bytecode::Program& out,
    std::string* why)
{
    std::array<uint8_t, 32> expected{};
    if (pin.pin_commitment != CommitPin(pin) ||
        !DecodeCompactTarget(pin.n_bits, expected, why) ||
        !std::equal(
            expected.begin(), expected.end(),
            pin.target.begin())) {
        return Fail(why, "bytecode_pin");
    }
    constraint_bytecode::ProgramTable table;
    if (!BuildRCStage3EpisodeHeaderTargetEqualityProgramTable(
            table, why) ||
        table.current_width !=
            kRCStage3EpisodeHeaderTargetColumns ||
        table.programs.size() != 1) {
        return Fail(why, "canonical_bytecode_shape");
    }
    out = std::move(table.programs.front());
    return true;
}

bool BuildRCStage3EpisodeHeaderTargetProgramTable(
    const RCStage3EpisodeHeaderTargetPin& pin,
    constraint_bytecode::ProgramTable& out,
    std::string* why)
{
    constraint_bytecode::Program program;
    if (!BuildRCStage3EpisodeHeaderTargetConstraintProgram(
            pin, program, why)) {
        return false;
    }
    out = {};
    out.role = program.role;
    out.current_width = program.current_width;
    out.next_width = program.next_width;
    out.programs.push_back(std::move(program));
    return constraint_bytecode::ValidateProgramTable(
        out, why);
}

bool ProveRCStage3EpisodeHeaderTargetProduct(
    const RCStage3SuccinctProof& statement,
    RCStage3EpisodeHeaderTargetProduct& out,
    std::string* why)
{
    out = {};
    RCStage3EpisodeHeaderTargetPin pin;
    aq::AirConstraintSystem<Fp3> cs;
    if (!BuildRCStage3EpisodeHeaderTargetPin(
            statement, pin, why) ||
        !BuildRCStage3EpisodeHeaderTargetConstraintSystem(
            pin, cs, why)) {
        return false;
    }
    std::vector<std::vector<Fp3>> columns(
        cs.n_columns,
        std::vector<Fp3>(cs.n_rows, Fp3::Zero()));
    for (const auto& [column, values] : cs.preprocessed) {
        columns[column] = values;
    }
    for (uint32_t row = 0; row < cs.n_rows; ++row) {
        columns[kRCStage3EpisodeHeaderTargetByte][row] =
            Fp3::FromFp(pin.target.data()[row]);
    }
    const auto compact = aq::AirQuotientProve<Fp3>(
        cs, columns, ProofSeed(pin));
    if (!compact.ok || !compact.division_exact) {
        return Fail(why, "compact_prove:" + compact.note);
    }

    const auto public_values = PublicValues(pin);
    const auto public_root =
        ComputeRCStage3EpisodeSemanticValueRoot(
            public_values, kRCStage3EpisodeHeaderTargetPublicCells,
            128, why);
    if (!public_root.has_value()) return false;
    const auto manifest =
        BuildRCStage3EpisodeSemanticMemoryManifest(
            RCStage3RelationEndpoint::EpisodeDigestHeaderTarget,
            pin.statement_commitment,
            kRCStage3EpisodeHeaderTargetPublicCells,
            kRCStage3EpisodeHeaderTargetPublicCells,
            0, 1, *public_root, why);
    if (!manifest.has_value()) return false;

    out.version = kRCStage3EpisodeHeaderTargetVersion;
    out.pin = pin;
    out.compact_target_proof = compact.proof;
    out.public_memory_manifest = *manifest;
    return ProveRCStage3EpisodeSemanticMemory(
        *manifest, public_values, out.public_memory_proof, why);
}

bool VerifyRCStage3EpisodeHeaderTargetProduct(
    const RCStage3SuccinctProof& statement,
    const uint256& expected_header_commitment,
    uint32_t expected_n_bits,
    const uint256& expected_target,
    const RCStage3EpisodeHeaderTargetProduct& product,
    std::string* why)
{
    RCStage3EpisodeHeaderTargetPin expected_pin;
    if (product.version !=
            kRCStage3EpisodeHeaderTargetVersion ||
        expected_header_commitment.IsNull() ||
        expected_target.IsNull() ||
        statement.public_inputs.header_commitment !=
            expected_header_commitment ||
        statement.public_inputs.n_bits != expected_n_bits ||
        statement.public_inputs.target != expected_target ||
        !BuildRCStage3EpisodeHeaderTargetPin(
            statement, expected_pin, why) ||
        product.pin != expected_pin) {
        return Fail(why, "consensus_public_pin");
    }
    aq::AirConstraintSystem<Fp3> cs;
    std::string air_why;
    if (!BuildRCStage3EpisodeHeaderTargetConstraintSystem(
            expected_pin, cs, why) ||
        !aq::AirQuotientVerify<Fp3>(
            cs, product.compact_target_proof,
            ProofSeed(expected_pin), &air_why)) {
        return Fail(why, "compact_verify:" + air_why);
    }
    const auto values = PublicValues(expected_pin);
    const auto root = ComputeRCStage3EpisodeSemanticValueRoot(
        values, kRCStage3EpisodeHeaderTargetPublicCells,
        128, why);
    const auto& manifest = product.public_memory_manifest;
    if (!root.has_value() ||
        manifest.endpoint !=
            RCStage3RelationEndpoint::EpisodeDigestHeaderTarget ||
        manifest.statement_commitment !=
            expected_pin.statement_commitment ||
        manifest.instance_count !=
            kRCStage3EpisodeHeaderTargetPublicCells ||
        manifest.logical_rows !=
            kRCStage3EpisodeHeaderTargetPublicCells ||
        manifest.n_rows != 128 ||
        manifest.address_begin != 0 ||
        manifest.address_stride != 1 ||
        manifest.canonical_value_root != *root ||
        !VerifyRCStage3EpisodeSemanticMemory(
            expected_pin.statement_commitment, manifest,
            product.public_memory_proof, why)) {
        return Fail(why, "public_memory");
    }
    if (why != nullptr) {
        *why =
            "stage3:episode_header_target:compact_target_and_"
            "public_header_vector_proved";
    }
    return true;
}

RCStage3EpisodeHeaderTargetAudit
CurrentRCStage3EpisodeHeaderTargetAudit()
{
    RCStage3EpisodeHeaderTargetAudit out;
    out.consensus_public_inputs_required = true;
    out.compact_target_relation_executable = true;
    out.exact_public_vector_proved = true;
    out.local_relation_complete = true;
    out.producer_provenance_complete = true;
    out.semantic_complete = true;
    out.recursively_consumed =
        kRCStage3EpisodeHeaderTargetRecursivelyConsumed;
    out.remaining =
        "normalized recursive child consumption remains";
    return out;
}

static_assert(
    kRCStage3EpisodeHeaderTargetProductExecutable);
static_assert(
    !kRCStage3EpisodeHeaderTargetRecursivelyConsumed);

} // namespace matmul::v4::rc
