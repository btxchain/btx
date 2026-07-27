// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_constraint_bytecode.h>

#include <hash.h>

#include <algorithm>
#include <array>
#include <limits>

namespace matmul::v4::rc::constraint_bytecode {
namespace {

namespace gf = gkr_field;
namespace ah = alg_hash;

constexpr char PROGRAM_TABLE_ALG_HASH_DOMAIN[] =
    "BTX_RC_STAGE3_CONSTRAINT_BYTECODE_TABLE_ALGHASH_V1";

bool Fail(std::string* why, const char* detail)
{
    if (why != nullptr) {
        *why = std::string{"stage3:constraint_bytecode:"} +
            detail;
    }
    return false;
}

bool IsCanonicalZero(const Fp3& value)
{
    return gf::IsZero(value);
}

void AppendU32PackedBytes(
    std::vector<gf::Fp>& out,
    const unsigned char* bytes,
    size_t size)
{
    out.push_back(gf::FromU64(size));
    for (size_t offset = 0; offset < size; offset += 4) {
        uint32_t word = 0;
        const size_t take = std::min<size_t>(4, size - offset);
        for (size_t byte = 0; byte < take; ++byte) {
            word |= uint32_t{bytes[offset + byte]} << (8 * byte);
        }
        out.push_back(gf::FromU64(word));
    }
}

void PutU16(std::vector<unsigned char>& out, uint16_t value)
{
    out.push_back(value & 0xffU);
    out.push_back((value >> 8) & 0xffU);
}

void PutU32(std::vector<unsigned char>& out, uint32_t value)
{
    for (uint32_t i = 0; i < 4; ++i) {
        out.push_back((value >> (8 * i)) & 0xffU);
    }
}

void PutU64(std::vector<unsigned char>& out, uint64_t value)
{
    for (uint32_t i = 0; i < 8; ++i) {
        out.push_back((value >> (8 * i)) & 0xffU);
    }
}

bool GetU16(const std::vector<unsigned char>& in,
            size_t& cursor,
            uint16_t& value)
{
    if (cursor > in.size() || in.size() - cursor < 2) {
        return false;
    }
    value = uint16_t{in[cursor]} |
        (uint16_t{in[cursor + 1]} << 8);
    cursor += 2;
    return true;
}

bool GetU32(const std::vector<unsigned char>& in,
            size_t& cursor,
            uint32_t& value)
{
    if (cursor > in.size() || in.size() - cursor < 4) {
        return false;
    }
    value = 0;
    for (uint32_t i = 0; i < 4; ++i) {
        value |= uint32_t{in[cursor + i]} << (8 * i);
    }
    cursor += 4;
    return true;
}

bool GetU64(const std::vector<unsigned char>& in,
            size_t& cursor,
            uint64_t& value)
{
    if (cursor > in.size() || in.size() - cursor < 8) {
        return false;
    }
    value = 0;
    for (uint32_t i = 0; i < 8; ++i) {
        value |= uint64_t{in[cursor + i]} << (8 * i);
    }
    cursor += 8;
    return true;
}

void PutFp3(std::vector<unsigned char>& out, const Fp3& value)
{
    PutU64(out, gf::Canonical(value.c0));
    PutU64(out, gf::Canonical(value.c1));
    PutU64(out, gf::Canonical(value.c2));
}

bool GetFp3(const std::vector<unsigned char>& in,
            size_t& cursor,
            Fp3& value)
{
    uint64_t c0 = 0;
    uint64_t c1 = 0;
    uint64_t c2 = 0;
    if (!GetU64(in, cursor, c0) ||
        !GetU64(in, cursor, c1) ||
        !GetU64(in, cursor, c2) ||
        c0 >= gf::kP ||
        c1 >= gf::kP ||
        c2 >= gf::kP) {
        return false;
    }
    value = Fp3{c0, c1, c2};
    return true;
}

bool IsRoleValue(uint16_t value)
{
    switch (static_cast<RCStage3RelationRole>(value)) {
    case RCStage3RelationRole::EpisodeDeterministicBuilder:
    case RCStage3RelationRole::EpisodeGemm:
    case RCStage3RelationRole::EpisodeExtract:
    case RCStage3RelationRole::EpisodeWiring:
    case RCStage3RelationRole::EpisodeTileTree:
    case RCStage3RelationRole::EpisodeDigest:
    case RCStage3RelationRole::CoupledBank:
    case RCStage3RelationRole::CoupledGemm:
    case RCStage3RelationRole::CoupledExchange:
    case RCStage3RelationRole::CoupledPermutation:
    case RCStage3RelationRole::CoupledMix:
    case RCStage3RelationRole::CoupledExtract:
    case RCStage3RelationRole::CoupledBarrier:
    case RCStage3RelationRole::CoupledDigest:
    case RCStage3RelationRole::CompositionLink:
        return true;
    }
    return false;
}

} // namespace

bool ValidateProgram(const Program& program, std::string* why)
{
    if (program.version != kConstraintBytecodeVersion) {
        return Fail(why, "version");
    }
    if (!IsRoleValue(static_cast<uint16_t>(program.role))) {
        return Fail(why, "role");
    }
    if (program.kind != air_quotient::AirKind::kEverywhere &&
        program.kind != air_quotient::AirKind::kTransition &&
        program.kind != air_quotient::AirKind::kFirstRow &&
        program.kind != air_quotient::AirKind::kLastRow) {
        return Fail(why, "kind");
    }
    if (program.declared_degree == 0 ||
        program.current_width == 0 ||
        program.next_width > program.current_width ||
        program.challenge_width >
            kConstraintBytecodeMaxInstructions ||
        program.instructions.empty() ||
        program.instructions.size() >
            kConstraintBytecodeMaxInstructions) {
        return Fail(why, "shape");
    }
    std::vector<uint32_t> reads(
        program.instructions.size(), 0);
    std::vector<uint32_t> degrees;
    degrees.reserve(program.instructions.size());
    for (uint32_t index = 0;
         index < program.instructions.size(); ++index) {
        const Instruction& instruction =
            program.instructions[index];
        switch (instruction.opcode) {
        case Opcode::Current:
            if (instruction.lhs >= program.current_width ||
                instruction.rhs != 0 ||
                !IsCanonicalZero(instruction.constant)) {
                return Fail(why, "current");
            }
            degrees.push_back(1);
            break;
        case Opcode::Next:
            if (instruction.lhs >= program.next_width ||
                instruction.rhs != 0 ||
                !IsCanonicalZero(instruction.constant)) {
                return Fail(why, "next");
            }
            degrees.push_back(1);
            break;
        case Opcode::Challenge:
            // Verifier-owned post-challenge column load. It carries no baked
            // value (constant is zero) so the committed table is
            // challenge-independent, and it counts as algebraic degree 1 so a
            // LogUp lane written over it is honestly degree 3, never 2.
            if (instruction.lhs >= program.challenge_width ||
                instruction.rhs != 0 ||
                !IsCanonicalZero(instruction.constant)) {
                return Fail(why, "challenge");
            }
            degrees.push_back(1);
            break;
        case Opcode::Constant:
            if (instruction.lhs != 0 ||
                instruction.rhs != 0) {
                return Fail(why, "constant");
            }
            degrees.push_back(0);
            break;
        case Opcode::Add:
        case Opcode::Sub:
        case Opcode::Mul:
            if (instruction.lhs >= index ||
                instruction.rhs >= index ||
                !IsCanonicalZero(instruction.constant)) {
                return Fail(why, "binary");
            }
            ++reads[instruction.lhs];
            ++reads[instruction.rhs];
            if (instruction.opcode == Opcode::Mul) {
                const uint64_t degree =
                    uint64_t{degrees[instruction.lhs]} +
                    degrees[instruction.rhs];
                if (degree >
                    std::numeric_limits<uint32_t>::max()) {
                    return Fail(why, "degree_overflow");
                }
                degrees.push_back(
                    static_cast<uint32_t>(degree));
            } else {
                degrees.push_back(std::max(
                    degrees[instruction.lhs],
                    degrees[instruction.rhs]));
            }
            break;
        default:
            return Fail(why, "opcode");
        }
    }
    // Canonical programs contain no dead prefix. The final instruction is the
    // sole result and is checked against zero by the interpreter.
    for (uint32_t index = 0;
         index + 1 < reads.size(); ++index) {
        if (reads[index] == 0) {
            return Fail(why, "dead_register");
        }
    }
    if (degrees.back() != program.declared_degree) {
        return Fail(why, "declared_degree");
    }
    return true;
}

bool SerializeProgram(const Program& program,
                      std::vector<unsigned char>& out,
                      std::string* why)
{
    if (!ValidateProgram(program, why)) return false;
    out.clear();
    out.reserve(32 + 33 * program.instructions.size());
    PutU16(out, program.version);
    PutU16(out, static_cast<uint16_t>(program.role));
    PutU32(out, program.constraint_ordinal);
    out.push_back(static_cast<uint8_t>(program.kind));
    PutU32(out, program.declared_degree);
    PutU32(out, program.current_width);
    PutU32(out, program.next_width);
    PutU32(out, program.challenge_width);
    PutU32(
        out,
        static_cast<uint32_t>(program.instructions.size()));
    for (const Instruction& instruction :
         program.instructions) {
        out.push_back(
            static_cast<uint8_t>(instruction.opcode));
        PutU32(out, instruction.lhs);
        PutU32(out, instruction.rhs);
        PutFp3(out, instruction.constant);
    }
    return true;
}

bool DeserializeProgram(const std::vector<unsigned char>& bytes,
                        Program& out,
                        std::string* why)
{
    out = {};
    size_t cursor = 0;
    uint16_t role = 0;
    uint32_t count = 0;
    if (!GetU16(bytes, cursor, out.version) ||
        !GetU16(bytes, cursor, role) ||
        !GetU32(bytes, cursor, out.constraint_ordinal) ||
        cursor >= bytes.size()) {
        return Fail(why, "truncated_header");
    }
    out.role = static_cast<RCStage3RelationRole>(role);
    out.kind =
        static_cast<air_quotient::AirKind>(bytes[cursor++]);
    if (!GetU32(bytes, cursor, out.declared_degree) ||
        !GetU32(bytes, cursor, out.current_width) ||
        !GetU32(bytes, cursor, out.next_width) ||
        !GetU32(bytes, cursor, out.challenge_width) ||
        !GetU32(bytes, cursor, count) ||
        count > kConstraintBytecodeMaxInstructions) {
        return Fail(why, "truncated_shape");
    }
    out.instructions.resize(count);
    for (Instruction& instruction : out.instructions) {
        if (cursor >= bytes.size()) {
            return Fail(why, "truncated_instruction");
        }
        instruction.opcode =
            static_cast<Opcode>(bytes[cursor++]);
        if (!GetU32(bytes, cursor, instruction.lhs) ||
            !GetU32(bytes, cursor, instruction.rhs) ||
            !GetFp3(bytes, cursor, instruction.constant)) {
            return Fail(why, "truncated_instruction");
        }
    }
    if (cursor != bytes.size()) {
        return Fail(why, "trailing_bytes");
    }
    return ValidateProgram(out, why);
}

uint256 CommitProgram(const Program& program)
{
    std::vector<unsigned char> bytes;
    if (!SerializeProgram(program, bytes)) return {};
    HashWriter hash;
    hash << "BTX_RC_STAGE3_CONSTRAINT_BYTECODE_V1";
    hash << bytes;
    return hash.GetHash();
}

bool ValidateProgramTable(const ProgramTable& table,
                          std::string* why)
{
    if (table.version != kConstraintBytecodeVersion ||
        table.programs.empty() ||
        table.programs.size() >
            kConstraintBytecodeMaxInstructions ||
        table.current_width == 0 ||
        table.next_width > table.current_width) {
        return Fail(why, "table_shape");
    }
    for (uint32_t ordinal = 0;
         ordinal < table.programs.size(); ++ordinal) {
        const Program& program = table.programs[ordinal];
        if (!ValidateProgram(program, why) ||
            program.role != table.role ||
            program.constraint_ordinal != ordinal ||
            program.current_width != table.current_width ||
            program.next_width != table.next_width ||
            program.challenge_width != table.challenge_width) {
            return Fail(why, "table_program");
        }
    }
    return true;
}

bool SerializeProgramTable(const ProgramTable& table,
                           std::vector<unsigned char>& out,
                           std::string* why)
{
    if (!ValidateProgramTable(table, why)) return false;
    out.clear();
    PutU16(out, table.version);
    PutU16(out, static_cast<uint16_t>(table.role));
    PutU32(out, table.current_width);
    PutU32(out, table.next_width);
    PutU32(out, table.challenge_width);
    PutU32(
        out,
        static_cast<uint32_t>(table.programs.size()));
    for (const Program& program : table.programs) {
        std::vector<unsigned char> encoded;
        if (!SerializeProgram(program, encoded, why) ||
            encoded.size() >
                std::numeric_limits<uint32_t>::max()) {
            return Fail(why, "table_encode_program");
        }
        PutU32(
            out, static_cast<uint32_t>(encoded.size()));
        out.insert(out.end(), encoded.begin(), encoded.end());
    }
    return true;
}

bool DeserializeProgramTable(
    const std::vector<unsigned char>& bytes,
    ProgramTable& out,
    std::string* why)
{
    out = {};
    size_t cursor = 0;
    uint16_t role = 0;
    uint32_t count = 0;
    if (!GetU16(bytes, cursor, out.version) ||
        !GetU16(bytes, cursor, role) ||
        !GetU32(bytes, cursor, out.current_width) ||
        !GetU32(bytes, cursor, out.next_width) ||
        !GetU32(bytes, cursor, out.challenge_width) ||
        !GetU32(bytes, cursor, count) ||
        count == 0 ||
        count > kConstraintBytecodeMaxInstructions) {
        return Fail(why, "table_header");
    }
    out.role = static_cast<RCStage3RelationRole>(role);
    out.programs.reserve(count);
    for (uint32_t index = 0; index < count; ++index) {
        uint32_t size = 0;
        if (!GetU32(bytes, cursor, size) ||
            cursor > bytes.size() ||
            size > bytes.size() - cursor) {
            return Fail(why, "table_program_size");
        }
        std::vector<unsigned char> encoded(
            bytes.begin() + cursor,
            bytes.begin() + cursor + size);
        cursor += size;
        Program program;
        if (!DeserializeProgram(encoded, program, why)) {
            return false;
        }
        out.programs.push_back(std::move(program));
    }
    if (cursor != bytes.size()) {
        return Fail(why, "table_trailing_bytes");
    }
    return ValidateProgramTable(out, why);
}

uint256 CommitProgramTable(const ProgramTable& table)
{
    std::vector<unsigned char> bytes;
    if (!SerializeProgramTable(table, bytes)) return {};
    HashWriter hash;
    hash << "BTX_RC_STAGE3_CONSTRAINT_BYTECODE_TABLE_V1";
    hash << bytes;
    return hash.GetHash();
}

alg_hash::Digest CommitProgramTableAlgHash(
    const ProgramTable& table)
{
    std::vector<gf::Fp> preimage;
    if (!BuildProgramTableAlgHashPreimage(
            table, preimage)) {
        return {};
    }
    return ah::SpongeHashFp(preimage);
}

bool BuildProgramTableAlgHashPreimage(
    const ProgramTable& table,
    std::vector<gf::Fp>& out,
    std::string* why)
{
    out.clear();
    std::vector<unsigned char> bytes;
    if (!SerializeProgramTable(
            table, bytes, why)) {
        return false;
    }
    const size_t domain_size =
        sizeof(PROGRAM_TABLE_ALG_HASH_DOMAIN) - 1;
    out.reserve(
        2 + (domain_size + 3) / 4 +
        (bytes.size() + 3) / 4);
    AppendU32PackedBytes(
        out,
        reinterpret_cast<const unsigned char*>(
            PROGRAM_TABLE_ALG_HASH_DOMAIN),
        domain_size);
    AppendU32PackedBytes(
        out, bytes.data(), bytes.size());
    return !out.empty();
}

ProgramTableCommitmentPair
CommitProgramTableForExternalAndRecursiveUse(
    const ProgramTable& table)
{
    ProgramTableCommitmentPair out;
    std::vector<unsigned char> bytes;
    if (!SerializeProgramTable(table, bytes)) return out;
    out.external_sha256d = CommitProgramTable(table);
    out.recursive_alg_hash =
        CommitProgramTableAlgHash(table);
    out.same_canonical_serialization =
        !out.external_sha256d.IsNull();
    out.cross_hash_collision_binding_proved = false;
    return out;
}

namespace {

// A valid equality relation on the three tables {honest, ext, rec} induces a
// partition; its complement (the three "differs" flags) must be one of the
// five realizable patterns. A lone "differs" (exactly one true) violates
// transitivity of equality and is therefore an inconsistent witness.
bool DiffersTripleConsistent(bool ext_h, bool rec_h, bool ext_rec)
{
    const int count = int{ext_h} + int{rec_h} + int{ext_rec};
    // 000 all equal; 111 all distinct; 110/101/011 exactly one pair equal.
    return count != 1;
}

} // namespace

CrossHashClassification
ClassifyCrossHashChannels(const CrossHashFacts& facts)
{
    CrossHashClassification out;
    out.facts_consistent =
        facts.inputs_valid &&
        DiffersTripleConsistent(
            facts.ext_differs_from_honest,
            facts.rec_differs_from_honest,
            facts.ext_differs_from_rec);

    // A SHA256d collision is a distinct byte string that reaches S*; an
    // AlgHash collision is a distinct field preimage that reaches A*.
    out.sha256d_collision_extracted =
        facts.inputs_valid &&
        facts.ext_differs_from_honest &&
        facts.ext_sha_matches_honest;
    out.alg_hash_collision_extracted =
        facts.inputs_valid &&
        facts.rec_differs_from_honest &&
        facts.rec_alg_matches_honest;

    // The stored pair fails to bind if any channel accepts a table != T*.
    out.pair_binding_failure =
        out.facts_consistent &&
        (out.sha256d_collision_extracted ||
         out.alg_hash_collision_extracted);

    // The cross-channel case: two DISTINCT tables each accepted on its own
    // channel under the single stored pair. Require consistent facts so a
    // malformed witness cannot assert a disagreement.
    out.cross_channel_disagreement =
        out.facts_consistent &&
        facts.ext_differs_from_rec &&
        facts.ext_sha_matches_honest &&
        facts.rec_alg_matches_honest;

    // The hybrid lemma: on consistent facts a cross-channel disagreement forces
    // a collision in at least one primitive. (If neither collided then
    // ext == honest and rec == honest, so ext == rec, contradicting
    // ext_differs_from_rec.) For non-disagreements the implication is vacuous.
    out.reduction_lemma_holds =
        !out.cross_channel_disagreement ||
        out.sha256d_collision_extracted ||
        out.alg_hash_collision_extracted;

    if (out.sha256d_collision_extracted &&
        out.alg_hash_collision_extracted) {
        out.channel = CrossHashCollisionChannel::Both;
    } else if (out.sha256d_collision_extracted) {
        out.channel = CrossHashCollisionChannel::Sha256d;
    } else if (out.alg_hash_collision_extracted) {
        out.channel = CrossHashCollisionChannel::AlgHash;
    } else {
        out.channel = CrossHashCollisionChannel::None;
    }
    out.certified_floor_bits =
        (out.channel == CrossHashCollisionChannel::None)
            ? 0U
            : kCrossHashBindingFloorBits;
    return out;
}

CrossHashClassification
ExtractCrossHashCollision(const CrossHashCollisionWitness& witness)
{
    CrossHashFacts facts;

    std::vector<unsigned char> honest_bytes;
    std::vector<unsigned char> ext_bytes;
    std::vector<unsigned char> rec_bytes;
    std::vector<gf::Fp> honest_pre;
    std::vector<gf::Fp> ext_pre;
    std::vector<gf::Fp> rec_pre;
    const bool serialized =
        SerializeProgramTable(witness.honest, honest_bytes) &&
        SerializeProgramTable(
            witness.external_candidate, ext_bytes) &&
        SerializeProgramTable(
            witness.recursive_candidate, rec_bytes) &&
        BuildProgramTableAlgHashPreimage(
            witness.honest, honest_pre) &&
        BuildProgramTableAlgHashPreimage(
            witness.external_candidate, ext_pre) &&
        BuildProgramTableAlgHashPreimage(
            witness.recursive_candidate, rec_pre);
    facts.inputs_valid = serialized;
    if (!serialized) {
        return ClassifyCrossHashChannels(facts);
    }

    // Canonical serialization is injective on valid tables, so byte inequality
    // is exactly table inequality. The SHA256d channel commits these bytes and
    // the AlgHash channel commits an injective field packing of the SAME bytes
    // (explicit length prefixes), so distinct tables give distinct preimages on
    // both channels.
    facts.ext_differs_from_honest = ext_bytes != honest_bytes;
    facts.rec_differs_from_honest = rec_bytes != honest_bytes;
    facts.ext_differs_from_rec = ext_bytes != rec_bytes;

    facts.ext_sha_matches_honest =
        CommitProgramTable(witness.external_candidate) ==
        CommitProgramTable(witness.honest);

    const ah::Digest honest_alg =
        CommitProgramTableAlgHash(witness.honest);
    const ah::Digest rec_alg =
        CommitProgramTableAlgHash(witness.recursive_candidate);
    bool alg_equal = true;
    for (uint32_t lane = 0; lane < ah::kAlgHashDigestLen; ++lane) {
        if (gf::Canonical(rec_alg[lane]) !=
            gf::Canonical(honest_alg[lane])) {
            alg_equal = false;
            break;
        }
    }
    facts.rec_alg_matches_honest = alg_equal;

    return ClassifyCrossHashChannels(facts);
}

CrossHashBindingReductionStatus
AssessCrossHashBindingReduction()
{
    return CrossHashBindingReductionStatus{};
}

namespace {

bool EvaluateProgramCore(const Program& program,
                         const std::vector<Fp3>& current,
                         const std::vector<Fp3>& next,
                         const std::vector<Fp3>& challenge,
                         Fp3& result,
                         std::string* why)
{
    result = Fp3::Zero();
    // A canonical program owns a declared prefix of a relation trace.  CTL
    // and recursion adapters may append proof-owned auxiliary columns after
    // that prefix; those columns must not change the program's semantics. The
    // verifier-owned challenge vector is likewise supplied post-commitment and
    // must be at least the declared challenge width.
    if (!ValidateProgram(program, why) ||
        current.size() < program.current_width ||
        next.size() < program.next_width ||
        challenge.size() < program.challenge_width) {
        return Fail(why, "evaluation_shape");
    }
    std::vector<Fp3> registers;
    registers.reserve(program.instructions.size());
    for (const Instruction& instruction :
         program.instructions) {
        switch (instruction.opcode) {
        case Opcode::Current:
            registers.push_back(current[instruction.lhs]);
            break;
        case Opcode::Next:
            registers.push_back(next[instruction.lhs]);
            break;
        case Opcode::Challenge:
            registers.push_back(challenge[instruction.lhs]);
            break;
        case Opcode::Constant:
            registers.push_back(instruction.constant);
            break;
        case Opcode::Add:
            registers.push_back(gf::Add(
                registers[instruction.lhs],
                registers[instruction.rhs]));
            break;
        case Opcode::Sub:
            registers.push_back(gf::Sub(
                registers[instruction.lhs],
                registers[instruction.rhs]));
            break;
        case Opcode::Mul:
            registers.push_back(gf::Mul(
                registers[instruction.lhs],
                registers[instruction.rhs]));
            break;
        default:
            return Fail(why, "evaluation_opcode");
        }
    }
    result = registers.back();
    return true;
}

} // namespace

bool EvaluateProgram(const Program& program,
                     const std::vector<Fp3>& current,
                     const std::vector<Fp3>& next,
                     Fp3& result,
                     std::string* why)
{
    // A challenge-free program never reads the post-challenge class; a program
    // that does must use the challenge-carrying overload.
    if (program.challenge_width != 0) {
        result = Fp3::Zero();
        return Fail(why, "evaluation_challenge_required");
    }
    static const std::vector<Fp3> kNoChallenge;
    return EvaluateProgramCore(
        program, current, next, kNoChallenge, result, why);
}

bool EvaluateProgram(const Program& program,
                     const std::vector<Fp3>& current,
                     const std::vector<Fp3>& next,
                     const std::vector<Fp3>& challenge,
                     Fp3& result,
                     std::string* why)
{
    return EvaluateProgramCore(
        program, current, next, challenge, result, why);
}

namespace {

bool BuildAirConstraintSystemFromProgramTableImpl(
    const ProgramTable& table,
    uint32_t n_rows,
    const std::vector<Fp3>& challenge,
    bool challenge_supplied,
    air_quotient::AirConstraintSystem<Fp3>& out,
    std::string* why)
{
    out = {};
    if (!ValidateProgramTable(table, why) || n_rows < 2 ||
        (n_rows & (n_rows - 1U)) != 0) {
        return Fail(why, "air_adapter_shape");
    }
    if (!challenge_supplied && table.challenge_width != 0) {
        // A post-challenge table must be adapted with the challenge overload.
        return Fail(why, "air_adapter_challenge_required");
    }
    if (challenge_supplied &&
        challenge.size() < table.challenge_width) {
        return Fail(why, "air_adapter_challenge_len");
    }
    out.n_rows = n_rows;
    out.n_columns = table.current_width;
    out.constraints.reserve(table.programs.size());
    for (const Program& program : table.programs) {
        air_quotient::AirConstraint<Fp3> constraint;
        // AirConstraint names are diagnostic string literals rather than
        // statement bytes. Role and ordinal are committed by ProgramTable.
        constraint.name = "stage3.constraint_bytecode.v1";
        constraint.kind = program.kind;
        // Real (post-challenge-column) degree drives quotient sizing.
        constraint.alg_degree = program.declared_degree;
        constraint.eval =
            [program, challenge](
                const std::vector<Fp3>& current,
                const std::vector<Fp3>& next) {
                Fp3 result = Fp3::Zero();
                if (!EvaluateProgramCore(
                        program, current, next,
                        challenge, result, nullptr)) {
                    // The quotient evaluator supplies at least the program's
                    // declared prefix. Returning a nonzero value is
                    // fail-closed if that invariant is ever violated.
                    return Fp3::One();
                }
                return result;
            };
        out.constraints.push_back(std::move(constraint));
    }
    return true;
}

} // namespace

bool BuildAirConstraintSystemFromProgramTable(
    const ProgramTable& table,
    uint32_t n_rows,
    air_quotient::AirConstraintSystem<Fp3>& out,
    std::string* why)
{
    static const std::vector<Fp3> kNoChallenge;
    return BuildAirConstraintSystemFromProgramTableImpl(
        table, n_rows, kNoChallenge, false, out, why);
}

bool BuildAirConstraintSystemFromProgramTable(
    const ProgramTable& table,
    uint32_t n_rows,
    const std::vector<Fp3>& challenge,
    air_quotient::AirConstraintSystem<Fp3>& out,
    std::string* why)
{
    return BuildAirConstraintSystemFromProgramTableImpl(
        table, n_rows, challenge, true, out, why);
}

PostChallengeColumnClassAudit AssessPostChallengeColumnClass()
{
    return PostChallengeColumnClassAudit{};
}

bool ProgramTableIsChallengeIndependent(const ProgramTable& table)
{
    // Serialization never encodes a challenge value: `Challenge` loads store
    // only a column index (rhs and constant are canonical zero, enforced by
    // ValidateProgram), and no `Constant` may carry a challenge because the
    // committed bytes are fixed before the challenge is drawn. A valid table is
    // therefore committed identically for every challenge vector.
    std::vector<unsigned char> bytes;
    return SerializeProgramTable(table, bytes);
}

std::vector<RoleMigrationInventory>
CurrentRoleMigrationInventory()
{
    using R = RCStage3RelationRole;
    // Fields: role, state, migrated_constraint_builders,
    //         migrated_transport_ctl_lanes, opaque_callbacks_remain, note.
    return {
        {R::EpisodeDeterministicBuilder,
         MigrationState::Partial, 2, 0, true,
         "endpoint-4 six-column dequant CS 5/5 is canonical "
         "bytecode and semantic-memory CS 3/3 migrated; "
         "seed/XOF/SHA builders remain opaque"},
        {R::EpisodeGemm,
         MigrationState::Partial, 2, 0, true,
         "local GEMM endpoint and semantic-memory CS are canonical "
         "bytecode; full GEMM product builders remain opaque"},
        {R::EpisodeExtract,
         MigrationState::Partial, 3, 1, true,
         "stream-CTL additive gamma-power transport CS 12/12 is canonical "
         "CHALLENGE-INDEPENDENT bytecode over the post-challenge column class "
         "(gamma/alpha/terminal verifier-owned, inverse raw degree 5), "
         "differential-tested vs the native builder; 197-column local mix CS "
         "201/201 and semantic-memory CS 3/3 also bytecode; sampler/hash/"
         "all-tile builders remain opaque"},
        {R::EpisodeWiring,
         MigrationState::Partial, 3, 1, true,
         "transpose dual-LogUp transport CS 6/6 is canonical "
         "CHALLENGE-INDEPENDENT bytecode over the post-challenge column "
         "class (beta/gamma verifier-owned, raw degree 3), differential-"
         "tested vs the native builder; local copy and semantic-memory CS "
         "also bytecode; order/external-producer builders remain opaque"},
        {R::EpisodeTileTree,
         MigrationState::Partial, 2, 1, true,
         "producer-edge additive gamma-power transport CS 134/134 is canonical "
         "CHALLENGE-INDEPENDENT bytecode over the post-challenge column class "
         "(gamma/alpha/terminal verifier-owned, inverse raw degree 5), "
         "differential-tested vs the native builder; semantic-memory CS 3/3 "
         "also bytecode; tile SHA and aggregation builders remain opaque"},
        {R::EpisodeDigest,
         MigrationState::Partial, 4, 0, true,
         "header-target CS 1/1 and typed root-vector CS 4/4 "
         "plus semantic-memory CS 3/3 and PoW borrow-chain CS 14/14 "
         "migrated; SHA builders opaque"},
        {R::CoupledBank,
         MigrationState::Partial, 3, 0, true,
         "dequant CS 5/5, ten-constraint signed-byte bridge and "
         "ten-constraint local bank kernel migrated; other bank/hash "
         "builders opaque"},
        {R::CoupledGemm,
         MigrationState::Partial, 1, 0, true,
         "six-constraint local accumulation kernel is canonical bytecode; "
         "product/opening builders remain opaque"},
        {R::CoupledExchange,
         MigrationState::Partial, 2, 1, true,
         "indexed-permutation grand-product transport CS 6/6 is canonical "
         "CHALLENGE-INDEPENDENT bytecode over the post-challenge column class "
         "(beta-vector/gamma verifier-owned, raw degree 3), differential-"
         "tested vs the native material builder; local fixed-copy kernel also "
         "bytecode; schedule/XOF/mixing builders remain opaque"},
        {R::CoupledPermutation,
         MigrationState::Partial, 2, 1, true,
         "indexed-permutation grand-product transport CS 6/6 is canonical "
         "CHALLENGE-INDEPENDENT bytecode over the post-challenge column class "
         "(beta-vector/gamma verifier-owned, raw degree 3), differential-"
         "tested vs the native builder; local mapped-copy kernel also "
         "bytecode; bit-affine schedule builders remain opaque"},
        {R::CoupledMix,
         MigrationState::Partial, 1, 0, true,
         "288 local limb/range constraints are canonical bytecode; "
         "global mix schedule builders remain opaque"},
        {R::CoupledExtract,
         MigrationState::Partial, 2, 1, true,
         "role-bound 197-column local mix CS 201/201 AND the T_M sampler "
         "transport LogUp CS 6/6 are canonical CHALLENGE-INDEPENDENT bytecode "
         "over the post-challenge column class (gamma/alpha verifier-owned, "
         "logup.phi raw degree 4), differential-tested vs the native builder. "
         "The old obstruction -- kColTfp, a PREPROCESSED column baking gamma/"
         "gamma^2 in the SHARED BuildRcSamplerConstraintSystem (Fp2+Fp3, all "
         "sampler call sites incl. EpisodeExtract's) -- is resolved: the "
         "fingerprint is now the committed column f bound by the in-circuit "
         "identity f = tbl_a + gamma*tbl_b + gamma^2*tbl_c (logup.tfp.bind) to "
         "challenge-INDEPENDENT preprocessed table columns, restoring RAP two-"
         "phase order; sampler/hash/product builders remain opaque"},
        {R::CoupledBarrier,
         MigrationState::Partial, 1, 0, true,
         "typed root-vector CS 4/4 is canonical bytecode; "
         "barrier SHA and link builders remain opaque"},
        {R::CoupledDigest,
         MigrationState::Partial, 1, 0, true,
         "typed root-vector CS 4/4 is canonical bytecode; "
         "digest SHA builders remain opaque"},
    };
}

uint32_t MigratedTransportCtlLaneCount()
{
    uint32_t total = 0;
    for (const auto& role : CurrentRoleMigrationInventory()) {
        total += role.migrated_transport_ctl_lanes;
    }
    return total;
}

TransportCtlMigrationFrontier AssessTransportCtlMigrationFrontier()
{
    TransportCtlMigrationFrontier out;
    out.migrated_lanes = MigratedTransportCtlLaneCount();
    for (const auto& role : CurrentRoleMigrationInventory()) {
        if (role.role == RCStage3RelationRole::CoupledExtract) {
            out.coupled_extract_migrated =
                role.migrated_transport_ctl_lanes >= 1;
        }
    }
    return out;
}

} // namespace matmul::v4::rc::constraint_bytecode
