// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_multirow_v11_unified_verifier_air.h>

#include <matmul/matmul_v4_rc_air_recurse.h>
#include <matmul/matmul_v4_rc_stage3_poseidon_bytecode.h>

#include <algorithm>
#include <chrono>
#include <functional>
#include <iterator>
#include <limits>
#include <utility>

namespace matmul::v4::rc::stage3_multirow_v11_unified_verifier_air {
namespace {

using gf::Fp3;
namespace pa = stage3_poseidon_air;

uint32_t NextPowerOfTwo(uint64_t value)
{
    if (value < 2) return 2;
    if (value > (uint64_t{1} << 31)) return 0;
    uint32_t out = 1;
    while (out < value) out <<= 1;
    return out;
}

uint32_t MaxDegree(
    const aq::AirConstraintSystem<Fp3>& cs)
{
    uint32_t out = 0;
    for (const auto& constraint : cs.constraints) {
        out = std::max(
            out, constraint.alg_degree);
    }
    return out;
}

bool IsParentJoinProofTapeColumn(
    const pj::LayoutV1& layout,
    uint32_t column)
{
    for (uint32_t lane = 0;
         lane < alg_hash::kAlgHashRate; ++lane) {
        if (column == layout.replay.Absorb(lane)) {
            return true;
        }
    }
    for (uint32_t limb = 0;
         limb < alg_hash::kAlgHashDigestLen; ++limb) {
        if (column == layout.replay.DigestClaim(limb)) {
            return true;
        }
    }
    return false;
}

cb::Instruction CurrentInstruction(uint32_t column)
{
    cb::Instruction out;
    out.opcode = cb::Opcode::Current;
    out.lhs = column;
    return out;
}

cb::Instruction ConstantInstruction(const Fp3& value)
{
    cb::Instruction out;
    out.opcode = cb::Opcode::Constant;
    out.constant = value;
    return out;
}

cb::Instruction BinaryInstruction(
    cb::Opcode opcode,
    uint32_t lhs,
    uint32_t rhs)
{
    cb::Instruction out;
    out.opcode = opcode;
    out.lhs = lhs;
    out.rhs = rhs;
    return out;
}

struct AffineFormV1 {
    Fp3 constant{};
    std::vector<std::pair<uint32_t, Fp3>> terms;
};

AffineFormV1 RecoverPermutationOutputAffineV1(
    const pa::Layout& layout,
    uint32_t lane)
{
    std::vector<Fp3> row(
        layout.End(), Fp3::Zero());
    AffineFormV1 out;
    out.constant =
        air_recurse::PermOutputLane(
            layout.perm, row, lane);
    for (uint32_t column = 0;
         column < layout.End();
         ++column) {
        row[column] = Fp3::One();
        const Fp3 coefficient = gf::Sub(
            air_recurse::PermOutputLane(
                layout.perm, row, lane),
            out.constant);
        row[column] = Fp3::Zero();
        if (!gf::IsZero(coefficient)) {
            out.terms.emplace_back(
                column, coefficient);
        }
    }
    return out;
}

uint32_t EmitAffineV1(
    std::vector<cb::Instruction>& instructions,
    const AffineFormV1& affine)
{
    instructions.push_back(
        ConstantInstruction(affine.constant));
    uint32_t accumulator =
        static_cast<uint32_t>(
            instructions.size() - 1);
    for (const auto& [column, coefficient] :
         affine.terms) {
        instructions.push_back(
            ConstantInstruction(coefficient));
        const uint32_t scalar =
            static_cast<uint32_t>(
                instructions.size() - 1);
        instructions.push_back(
            CurrentInstruction(column));
        const uint32_t value =
            static_cast<uint32_t>(
                instructions.size() - 1);
        instructions.push_back(
            BinaryInstruction(
                cb::Opcode::Mul,
                scalar, value));
        const uint32_t term =
            static_cast<uint32_t>(
                instructions.size() - 1);
        instructions.push_back(
            BinaryInstruction(
                cb::Opcode::Add,
                accumulator, term));
        accumulator =
            static_cast<uint32_t>(
                instructions.size() - 1);
    }
    return accumulator;
}

cb::Program NewMerkleHashPinProgramV1(
    uint32_t ordinal,
    uint32_t width)
{
    cb::Program out;
    out.version =
        cb::kConstraintBytecodeVersion;
    out.role =
        RCStage3RelationRole::CompositionLink;
    out.constraint_ordinal = ordinal;
    out.kind = aq::AirKind::kEverywhere;
    out.declared_degree = 1;
    out.current_width = width;
    out.next_width = width;
    out.challenge_width = 0;
    return out;
}

bool BuildParentJoinStatementManifestR0V1(
    const pj::ProductV1& parent_join,
    aq::AirConstraintSystem<Fp3>& cs,
    std::vector<uint32_t>& ordered_columns,
    uint256& root,
    std::string* why)
{
    ordered_columns.clear();
    root.SetNull();
    if (!parent_join.valid ||
        parent_join.columns.size() !=
            parent_join.cs.n_columns ||
        cs.n_rows != parent_join.cs.n_rows ||
        cs.n_columns != parent_join.cs.n_columns) {
        if (why != nullptr) {
            *why =
                "parent_join_statement_manifest_shape";
        }
        return false;
    }
    cs.preprocessed.clear();
    cs.preprocessed_row_group_roots.clear();
    for (uint32_t column :
         parent_join.preprocessed_columns) {
        if (column >= cs.n_columns) {
            if (why != nullptr) {
                *why =
                    "parent_join_statement_manifest_column";
            }
            return false;
        }
        if (IsParentJoinProofTapeColumn(
                parent_join.layout, column)) {
            continue;
        }
        ordered_columns.push_back(column);
        cs.preprocessed.emplace_back(
            column, parent_join.columns[column]);
    }
    if (ordered_columns.empty() ||
        !std::is_sorted(
            ordered_columns.begin(),
            ordered_columns.end()) ||
        std::adjacent_find(
            ordered_columns.begin(),
            ordered_columns.end()) !=
            ordered_columns.end()) {
        if (why != nullptr) {
            *why =
                "parent_join_statement_manifest_order";
        }
        return false;
    }
    cs.preprocessed_pin_ood = true;
    const auto session =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            cs, parent_join.columns,
            ordered_columns);
    if (!session.valid ||
        session.base_row_commitment.IsNull()) {
        if (why != nullptr) {
            *why =
                "parent_join_statement_manifest_root:" +
                session.note;
        }
        return false;
    }
    root = session.base_row_commitment;
    cs.preprocessed_row_group_roots.push_back({
        .version = 1,
        .role =
            aq::AirPreprocessedRowGroupRole::kR0,
        .ordered_columns = ordered_columns,
        .root = root,
    });
    if (why != nullptr) {
        *why =
            "parent_join_statement_manifest_r0";
    }
    return true;
}

struct PhaseViewV1 {
    PhaseV1 phase{PhaseV1::ParentJoin};
    const aq::AirConstraintSystem<Fp3>* cs{nullptr};
    const std::vector<std::vector<Fp3>>* columns{nullptr};
};

bool ShapeExact(const PhaseViewV1& phase)
{
    if (phase.cs == nullptr ||
        phase.columns == nullptr ||
        phase.cs->n_rows < 2 ||
        phase.cs->n_columns == 0 ||
        phase.columns->size() !=
            phase.cs->n_columns) {
        return false;
    }
    for (const auto& column :
         *phase.columns) {
        if (column.size() != phase.cs->n_rows) {
            return false;
        }
    }
    for (const auto& [column, values] :
         phase.cs->preprocessed) {
        if (column >= phase.cs->n_columns ||
            values.size() != phase.cs->n_rows) {
            return false;
        }
    }
    return true;
}

struct BytecodeExprV1 {
    std::vector<cb::Instruction> instructions;
    std::vector<uint32_t> degrees;

    uint32_t Current(uint32_t column)
    {
        cb::Instruction instruction;
        instruction.opcode = cb::Opcode::Current;
        instruction.lhs = column;
        instructions.push_back(instruction);
        degrees.push_back(1);
        return static_cast<uint32_t>(
            instructions.size() - 1);
    }

    uint32_t Next(uint32_t column)
    {
        cb::Instruction instruction;
        instruction.opcode = cb::Opcode::Next;
        instruction.lhs = column;
        instructions.push_back(instruction);
        degrees.push_back(1);
        return static_cast<uint32_t>(
            instructions.size() - 1);
    }

    uint32_t Challenge(uint32_t column)
    {
        cb::Instruction instruction;
        instruction.opcode = cb::Opcode::Challenge;
        instruction.lhs = column;
        instructions.push_back(instruction);
        // Constraint-bytecode intentionally accounts verifier-owned
        // post-commit challenge columns at algebraic degree one.
        degrees.push_back(1);
        return static_cast<uint32_t>(
            instructions.size() - 1);
    }

    uint32_t Constant(const Fp3& value)
    {
        cb::Instruction instruction;
        instruction.opcode = cb::Opcode::Constant;
        instruction.constant = value;
        instructions.push_back(instruction);
        degrees.push_back(0);
        return static_cast<uint32_t>(
            instructions.size() - 1);
    }

    uint32_t Binary(
        cb::Opcode opcode,
        uint32_t left,
        uint32_t right)
    {
        cb::Instruction instruction;
        instruction.opcode = opcode;
        instruction.lhs = left;
        instruction.rhs = right;
        instructions.push_back(instruction);
        degrees.push_back(
            opcode == cb::Opcode::Mul
            ? degrees[left] + degrees[right]
            : std::max(degrees[left], degrees[right]));
        return static_cast<uint32_t>(
            instructions.size() - 1);
    }

    uint32_t Sub(uint32_t left, uint32_t right)
    {
        return Binary(cb::Opcode::Sub, left, right);
    }

    uint32_t Add(uint32_t left, uint32_t right)
    {
        return Binary(cb::Opcode::Add, left, right);
    }

    uint32_t Mul(uint32_t left, uint32_t right)
    {
        return Binary(cb::Opcode::Mul, left, right);
    }
};

template <typename Build>
void AppendBytecodeProgramKindV1(
    cb::ProgramTable& table,
    aq::AirKind kind,
    Build&& build)
{
    BytecodeExprV1 expression;
    build(expression);
    cb::Program program;
    program.version =
        cb::kConstraintBytecodeVersion;
    program.role =
        RCStage3RelationRole::CompositionLink;
    program.constraint_ordinal =
        static_cast<uint32_t>(
            table.programs.size());
    program.kind = kind;
    program.declared_degree =
        expression.degrees.back();
    program.current_width =
        table.current_width;
    program.next_width =
        table.next_width;
    program.challenge_width =
        table.challenge_width;
    program.instructions =
        std::move(expression.instructions);
    table.programs.push_back(
        std::move(program));
}

template <typename Build>
void AppendBytecodeProgramV1(
    cb::ProgramTable& table,
    Build&& build)
{
    AppendBytecodeProgramKindV1(
        table, aq::AirKind::kEverywhere,
        std::forward<Build>(build));
}

bool DigestNonzero(
    const alg_hash::Digest& digest)
{
    for (const auto& limb : digest) {
        if (gf::Canonical(limb) != 0) {
            return true;
        }
    }
    return false;
}

std::vector<uint32_t> PreprocessedColumns(
    const aq::AirConstraintSystem<Fp3>& cs)
{
    std::vector<uint32_t> out;
    out.reserve(cs.preprocessed.size());
    for (const auto& [column, values] :
         cs.preprocessed) {
        (void)values;
        out.push_back(column);
    }
    std::sort(out.begin(), out.end());
    out.erase(
        std::unique(out.begin(), out.end()),
        out.end());
    return out;
}

struct DecoderHornerLayoutV1 {
    // [lane][0 = source, 1 = consumer][stage]:
    // address+gamma*value, occurrence+gamma*h1,
    // kind+gamma*h2, alpha+gamma*h3.
    std::array<
        std::array<
            std::array<
                uint32_t,
                kDecoderHornerStagesV1>,
            2>,
        dj::kDecoderJoinBusLanesV1> column{};
    uint32_t n_columns{0};
};

DecoderHornerLayoutV1 DecoderHornerLayout(
    const dj::LayoutV1& decoder)
{
    DecoderHornerLayoutV1 out;
    uint32_t column = decoder.n_columns;
    for (auto& lane : out.column) {
        for (auto& side : lane) {
            for (auto& stage : side) {
                stage = column++;
            }
        }
    }
    out.n_columns = column;
    return out;
}

std::vector<Fp3> DecoderChallenges(
    const dj::ProductV1& decoder)
{
    return {
        decoder.gamma[0],
        decoder.gamma[1],
        decoder.alpha[0],
        decoder.alpha[1],
    };
}

enum class DeepVmRegisterSideV1 : uint32_t {
    Producer = 0,
    Lhs = 1,
    Rhs = 2,
};

struct DeepVmSsaLayoutV1 {
    uint32_t program_ordinal{0};
    uint32_t instruction_ordinal{0};
    uint32_t lhs_reference{0};
    uint32_t rhs_reference{0};
    uint32_t register_use_multiplicity{0};
    uint32_t constant_value{0};
    std::array<
        std::array<
            std::array<
                uint32_t,
                kDeepVmRegisterHornerStagesV1>,
            kDeepVmRegisterBusSidesV1>,
        kDeepVmRegisterBusLanesV1> horner{};
    std::array<
        std::array<
            uint32_t,
            kDeepVmRegisterBusSidesV1>,
        kDeepVmRegisterBusLanesV1> inverse{};
    std::array<
        uint32_t,
        kDeepVmRegisterBusLanesV1> running{};
    uint32_t n_columns{0};
};

DeepVmSsaLayoutV1 DeepVmSsaLayout(
    const dvm::LayoutV1& deep)
{
    DeepVmSsaLayoutV1 out;
    uint32_t column = deep.n_columns;
    out.program_ordinal = column++;
    out.instruction_ordinal = column++;
    out.lhs_reference = column++;
    out.rhs_reference = column++;
    out.register_use_multiplicity = column++;
    out.constant_value = column++;
    for (auto& lane : out.horner) {
        for (auto& side : lane) {
            for (auto& stage : side) {
                stage = column++;
            }
        }
    }
    for (auto& lane : out.inverse) {
        for (auto& side : lane) {
            side = column++;
        }
    }
    for (auto& running : out.running) {
        running = column++;
    }
    out.n_columns = column;
    return out;
}

bool SameDigest(
    const alg_hash::Digest& left,
    const alg_hash::Digest& right)
{
    for (uint32_t limb = 0;
         limb < left.size(); ++limb) {
        if (gf::Canonical(left[limb]) !=
            gf::Canonical(right[limb])) {
            return false;
        }
    }
    return true;
}

bool CanonicalDigest(
    const alg_hash::Digest& digest)
{
    return std::all_of(
        digest.begin(),
        digest.end(),
        [](gf::Fp limb) {
            return limb < gf::kP;
        });
}

bool DeepVmChallengesValid(
    const std::vector<Fp3>& challenge)
{
    const auto canonical =
        [](const Fp3& value) {
            return value.c0 < gf::kP &&
                value.c1 < gf::kP &&
                value.c2 < gf::kP;
        };
    return
        challenge.size() ==
            kDeepVmChallengeColumnsV1 &&
        std::all_of(
            challenge.begin(),
            challenge.end(),
            canonical) &&
        !gf::IsZero(challenge[0]) &&
        !gf::IsZero(challenge[1]) &&
        !gf::IsZero(challenge[2]) &&
        !gf::IsZero(challenge[3]) &&
        !gf::Eq(challenge[0], challenge[1]) &&
        !gf::Eq(challenge[2], challenge[3]);
}

std::vector<Fp3> DeriveDeepVmRegisterChallengesV1(
    const uint256& operand_precommit_root,
    const alg_hash::Digest& program_root,
    const rv::QueryRangeV1& range)
{
    if (operand_precommit_root.IsNull() ||
        !CanonicalDigest(program_root) ||
        !DigestNonzero(program_root) ||
        range.query_count == 0) {
        return {};
    }
    std::vector<gf::Fp> prefix;
    prefix.reserve(8 + program_root.size() + 7);
    // Arbitrary uint256 words are split into u32 lanes. Absorbing u64
    // directly would admit the Goldilocks x <-> x+p alias.
    for (uint32_t word = 0;
         word < 4; ++word) {
        const uint64_t value =
            operand_precommit_root.GetUint64(
                word);
        prefix.push_back(
            gf::FromU64(
                static_cast<uint32_t>(
                    value)));
        prefix.push_back(
            gf::FromU64(
                static_cast<uint32_t>(
                    value >> 32)));
    }
    prefix.insert(
        prefix.end(),
        program_root.begin(),
        program_root.end());
    prefix.push_back(
        gf::FromU64(0x44565231U)); // 'DVR1'
    prefix.push_back(
        gf::FromU64(range.ordinal));
    prefix.push_back(
        gf::FromU64(range.first_query));
    prefix.push_back(
        gf::FromU64(range.query_count));

    std::vector<Fp3> out;
    out.reserve(kDeepVmChallengeColumnsV1);
    for (uint32_t lane = 0;
         lane < kDeepVmChallengeColumnsV1;
         ++lane) {
        bool selected = false;
        for (uint32_t attempt = 0;
             attempt < 32; ++attempt) {
            auto input = prefix;
            input.push_back(
                gf::FromU64(lane));
            input.push_back(
                gf::FromU64(attempt));
            const auto digest =
                alg_hash::SpongeHashFp(input);
            const Fp3 candidate{
                digest[0],
                digest[1],
                digest[2]};
            const bool pair_collision =
                (lane == 1 &&
                 gf::Eq(candidate, out[0])) ||
                (lane == 3 &&
                 gf::Eq(candidate, out[2]));
            if (!gf::IsZero(candidate) &&
                !pair_collision) {
                out.push_back(candidate);
                selected = true;
                break;
            }
        }
        if (!selected) return {};
    }
    return DeepVmChallengesValid(out)
        ? out
        : std::vector<Fp3>{};
}

bool BuildDecoderStaticPhaseV1(
    const dj::ProductV1& decoder,
    aq::AirConstraintSystem<Fp3>& cs,
    std::vector<std::vector<Fp3>>& columns,
    std::vector<uint32_t>& statement_manifest_columns,
    std::string* why)
{
    cs = {};
    columns.clear();
    statement_manifest_columns.clear();
    if (!decoder.valid ||
        decoder.layout.n_columns == 0 ||
        decoder.columns.size() !=
            decoder.layout.n_columns) {
        if (why != nullptr) {
            *why = "decoder_static_input_shape";
        }
        return false;
    }
    const cb::ProgramTable table =
        BuildDecoderProgramTableV1(
            decoder.layout);
    const auto challenge =
        DecoderChallenges(decoder);
    if (table.programs.size() != 30 ||
        table.current_width !=
            decoder.layout.n_columns +
                kDecoderHornerAuxColumnsV1 ||
        !cb::BuildAirConstraintSystemFromProgramTable(
            table, decoder.cs.n_rows,
            challenge, cs, why)) {
        return false;
    }
    columns.assign(
        cs.n_columns,
        std::vector<Fp3>(
            cs.n_rows, Fp3::Zero()));
    for (uint32_t column = 0;
         column < decoder.layout.n_columns;
         ++column) {
        if (decoder.columns[column].size() !=
            cs.n_rows) {
            if (why != nullptr) {
                *why =
                    "decoder_static_column_rows";
            }
            return false;
        }
        columns[column] =
            decoder.columns[column];
    }
    const auto aux =
        DecoderHornerLayout(decoder.layout);
    for (uint32_t lane = 0;
         lane < dj::kDecoderJoinBusLanesV1;
         ++lane) {
        const Fp3 gamma =
            decoder.gamma[lane];
        const Fp3 alpha =
            decoder.alpha[lane];
        for (uint32_t side = 0;
             side < 2; ++side) {
            const uint32_t kind =
                side == 0
                ? decoder.layout.source_kind
                : decoder.layout.consumer_kind;
            const uint32_t occurrence =
                side == 0
                ? decoder.layout.source_occurrence
                : decoder.layout.consumer_occurrence;
            const uint32_t address =
                side == 0
                ? decoder.layout.source_address
                : decoder.layout.consumer_address;
            const uint32_t value =
                side == 0
                ? decoder.layout.source_value
                : decoder.layout.consumer_claim;
            for (uint32_t row = 0;
                 row < cs.n_rows; ++row) {
                const Fp3 h1 = gf::Add(
                    columns[address][row],
                    gf::Mul(
                        gamma,
                        columns[value][row]));
                const Fp3 h2 = gf::Add(
                    columns[occurrence][row],
                    gf::Mul(gamma, h1));
                const Fp3 h3 = gf::Add(
                    columns[kind][row],
                    gf::Mul(gamma, h2));
                const Fp3 term = gf::Add(
                    alpha,
                    gf::Mul(gamma, h3));
                columns[
                    aux.column[lane][side][0]][row] = h1;
                columns[
                    aux.column[lane][side][1]][row] = h2;
                columns[
                    aux.column[lane][side][2]][row] = h3;
                columns[
                    aux.column[lane][side][3]][row] = term;
            }
        }
    }

    // Independently regenerate the immutable ABI/role/address schedule from
    // typed inventories. Merely copying these cells from decoder.columns and
    // calling them "manifest" would leave a prover-owned R0 surface.
    using ColumnValues =
        std::pair<uint32_t, std::vector<Fp3>>;
    std::vector<ColumnValues> manifest;
    const auto add_manifest =
        [&manifest, &cs](uint32_t column) {
            manifest.emplace_back(
                column,
                std::vector<Fp3>(
                    cs.n_rows,
                    Fp3::Zero()));
            return manifest.size() - 1;
        };
    const size_t active_index =
        add_manifest(decoder.layout.active);
    const size_t source_kind_index =
        add_manifest(decoder.layout.source_kind);
    const size_t source_occurrence_index =
        add_manifest(
            decoder.layout.source_occurrence);
    const size_t source_address_index =
        add_manifest(decoder.layout.source_address);
    const size_t consumer_kind_index =
        add_manifest(decoder.layout.consumer_kind);
    const size_t consumer_occurrence_index =
        add_manifest(
            decoder.layout.consumer_occurrence);
    const size_t consumer_address_index =
        add_manifest(decoder.layout.consumer_address);
    const size_t root_active_index =
        add_manifest(decoder.layout.root_active);
    const size_t root_kind_index =
        add_manifest(decoder.layout.root_kind);
    const size_t root_index_index =
        add_manifest(decoder.layout.root_index);
    const size_t root_word_index =
        add_manifest(decoder.layout.root_word);
    if (decoder.source_occurrences.size() !=
            decoder.consumer_occurrences.size() ||
        decoder.source_occurrences.size() !=
            decoder.real_rows ||
        uint64_t{decoder.child_roots.size()} *
                dj::kDecoderJoinRootWordsV1 >
            cs.n_rows) {
        if (why != nullptr) {
            *why =
                "decoder_static_manifest_inventory";
        }
        return false;
    }
    for (uint32_t row = 0;
         row < decoder.real_rows; ++row) {
        const auto& source =
            decoder.source_occurrences[row];
        const auto& consumer =
            decoder.consumer_occurrences[row];
        manifest[active_index].second[row] =
            Fp3::One();
        manifest[source_kind_index].second[row] =
            gf::FromU64_3(
                static_cast<uint8_t>(
                    source.kind));
        manifest[source_occurrence_index]
            .second[row] =
            gf::FromU64_3(
                source.occurrence_id);
        manifest[source_address_index]
            .second[row] =
            gf::FromU64_3(
                source.source_address);
        manifest[consumer_kind_index].second[row] =
            gf::FromU64_3(
                static_cast<uint8_t>(
                    consumer.kind));
        manifest[consumer_occurrence_index]
            .second[row] =
            gf::FromU64_3(
                consumer.occurrence_id);
        manifest[consumer_address_index]
            .second[row] =
            gf::FromU64_3(
                consumer.source_address);
    }
    uint32_t root_row = 0;
    for (const auto& pin :
         decoder.child_roots) {
        for (uint32_t word = 0;
             word <
                 dj::kDecoderJoinRootWordsV1;
             ++word, ++root_row) {
            manifest[root_active_index]
                .second[root_row] =
                Fp3::One();
            manifest[root_kind_index]
                .second[root_row] =
                gf::FromU64_3(pin.kind);
            manifest[root_index_index]
                .second[root_row] =
                gf::FromU64_3(pin.index);
            manifest[root_word_index]
                .second[root_row] =
                gf::FromU64_3(word);
        }
    }
    for (const auto& [column, canonical] :
         manifest) {
        if (column >= columns.size() ||
            canonical.size() !=
                columns[column].size()) {
            if (why != nullptr) {
                *why =
                    "decoder_static_manifest_shape";
            }
            return false;
        }
        for (uint32_t row = 0;
             row < cs.n_rows; ++row) {
            if (!gf::Eq(
                    canonical[row],
                    columns[column][row])) {
                if (why != nullptr) {
                    *why =
                        "decoder_static_manifest_mismatch";
                }
                return false;
            }
        }
        statement_manifest_columns.push_back(
            column);
    }
    cs.preprocessed.clear();
    cs.preprocessed_row_group_roots.clear();
    for (auto& [column, canonical] :
         manifest) {
        cs.preprocessed.emplace_back(
            column, std::move(canonical));
    }
    cs.preprocessed_pin_ood = true;
    return true;
}

bool BuildDeepVmStaticPhaseV1(
    const dvm::ProductV1& deep,
    const cb::ProgramTable& child_program,
    const alg_hash::Digest& expected_program_root,
    const rv::QueryRangeV1& range,
    const std::vector<Fp3>& challenge,
    aq::AirConstraintSystem<Fp3>& cs,
    std::vector<std::vector<Fp3>>& columns,
    std::vector<uint32_t>& statement_manifest_columns,
    std::string* why)
{
    cs = {};
    columns.clear();
    statement_manifest_columns.clear();
    const cb::ProgramTable table =
        BuildDeepVmProgramTableV1(
            deep.layout);
    const auto computed_child_root =
        cb::CommitProgramTableAlgHash(
            child_program);
    if (!deep.valid ||
        dvm::RecountViolationsV1(
            deep, deep.columns) != 0 ||
        table.programs.size() !=
            kDeepVmCanonicalConstraintsV1 ||
        table.current_width !=
            deep.layout.n_columns +
                kDeepVmExtensionColumnsV1 ||
        deep.columns.size() !=
            deep.layout.n_columns ||
        !cb::ValidateProgramTable(
            child_program, why) ||
        child_program.challenge_width != 0 ||
        !CanonicalDigest(
            expected_program_root) ||
        !CanonicalDigest(deep.program_root) ||
        !CanonicalDigest(computed_child_root) ||
        !DigestNonzero(expected_program_root) ||
        !SameDigest(
            computed_child_root,
            expected_program_root) ||
        !SameDigest(
            deep.program_root,
            expected_program_root) ||
        deep.first_query !=
            range.first_query ||
        deep.query_count !=
            range.query_count ||
        !DeepVmChallengesValid(challenge) ||
        !cb::BuildAirConstraintSystemFromProgramTable(
            table, deep.cs.n_rows,
            challenge, cs, why)) {
        return false;
    }
    columns.assign(
        table.current_width,
        std::vector<Fp3>(
            cs.n_rows, Fp3::Zero()));
    for (uint32_t column = 0;
         column < deep.layout.n_columns;
         ++column) {
        if (deep.columns[column].size() !=
            cs.n_rows) {
            if (why != nullptr) {
                *why =
                    "deep_vm_static_column_rows";
            }
            return false;
        }
        columns[column] = deep.columns[column];
    }
    using ColumnValues =
        std::pair<uint32_t, std::vector<Fp3>>;
    std::vector<ColumnValues> manifest;
    const auto add_manifest =
        [&manifest, &cs](uint32_t column) {
            manifest.emplace_back(
                column,
                std::vector<Fp3>(
                    cs.n_rows,
                    Fp3::Zero()));
            return manifest.size() - 1;
        };
    const auto& l = deep.layout;
    const size_t active =
        add_manifest(l.active);
    const size_t deep_term =
        add_manifest(l.deep_term);
    const size_t deep_finalize =
        add_manifest(l.deep_finalize);
    const size_t vm_instruction =
        add_manifest(l.vm_instruction);
    const size_t quotient_identity =
        add_manifest(l.quotient_identity);
    const size_t query_index =
        add_manifest(l.query);
    const size_t item =
        add_manifest(l.item);
    const size_t deep_start =
        add_manifest(l.deep_start);
    const size_t deep_chain =
        add_manifest(l.deep_chain);
    const std::array<size_t, 6> opcode{{
        add_manifest(l.op_current),
        add_manifest(l.op_next),
        add_manifest(l.op_constant),
        add_manifest(l.op_add),
        add_manifest(l.op_sub),
        add_manifest(l.op_mul),
    }};
    const size_t program_end =
        add_manifest(l.program_end);
    const size_t vm_start =
        add_manifest(l.vm_start);
    const size_t vm_chain =
        add_manifest(l.vm_chain);
    const size_t vm_to_quotient =
        add_manifest(l.vm_to_quotient);
    const size_t quotient_consumer =
        add_manifest(
            l.quotient_tape_deep_consumer);
    const auto ssa = DeepVmSsaLayout(l);
    const size_t program_ordinal =
        add_manifest(ssa.program_ordinal);
    const size_t instruction_ordinal =
        add_manifest(ssa.instruction_ordinal);
    const size_t lhs_reference =
        add_manifest(ssa.lhs_reference);
    const size_t rhs_reference =
        add_manifest(ssa.rhs_reference);
    const size_t register_use_multiplicity =
        add_manifest(
            ssa.register_use_multiplicity);
    const size_t constant_value =
        add_manifest(ssa.constant_value);
    if (manifest.size() !=
            kDeepVmStatementScheduleColumnsV1 ||
        deep.query_count == 0 ||
        child_program.current_width ==
            std::numeric_limits<uint32_t>::max()) {
        if (why != nullptr) {
            *why =
                "deep_vm_static_manifest_shape";
        }
        return false;
    }
    const uint32_t deep_terms_per_query =
        child_program.current_width + 1;
    uint64_t vm_rows64 = 0;
    std::vector<std::vector<uint32_t>>
        register_use;
    register_use.reserve(
        child_program.programs.size());
    for (const auto& program :
         child_program.programs) {
        vm_rows64 +=
            program.instructions.size();
        register_use.emplace_back(
            program.instructions.size(), 0);
        auto& multiplicity =
            register_use.back();
        for (uint32_t pc = 0;
             pc < program.instructions.size();
             ++pc) {
            const auto& instruction =
                program.instructions[pc];
            const bool binary =
                instruction.opcode ==
                    cb::Opcode::Add ||
                instruction.opcode ==
                    cb::Opcode::Sub ||
                instruction.opcode ==
                    cb::Opcode::Mul;
            if (!binary) continue;
            if (instruction.lhs >= pc ||
                instruction.rhs >= pc ||
                multiplicity[
                    instruction.lhs] ==
                    std::numeric_limits<
                        uint32_t>::max() ||
                multiplicity[
                    instruction.rhs] ==
                    std::numeric_limits<
                        uint32_t>::max()) {
                if (why != nullptr) {
                    *why =
                        "deep_vm_static_ssa_inventory";
                }
                return false;
            }
            ++multiplicity[
                instruction.lhs];
            ++multiplicity[
                instruction.rhs];
        }
    }
    const uint64_t rows_per_query =
        uint64_t{deep_terms_per_query} +
        1 + vm_rows64 + 1;
    if (vm_rows64 == 0 ||
        rows_per_query >
            std::numeric_limits<uint32_t>::max() ||
        rows_per_query * deep.query_count !=
            deep.real_rows ||
        deep.real_rows > cs.n_rows) {
        if (why != nullptr) {
            *why =
                "deep_vm_static_manifest_inventory";
        }
        return false;
    }
    uint32_t row = 0;
    for (uint32_t query_offset = 0;
         query_offset < deep.query_count;
         ++query_offset) {
        const uint32_t query =
            deep.first_query + query_offset;
        for (uint32_t column = 0;
             column <
                 deep_terms_per_query;
             ++column, ++row) {
            manifest[active].second[row] =
                Fp3::One();
            manifest[deep_term].second[row] =
                Fp3::One();
            manifest[query_index].second[row] =
                gf::FromU64_3(query);
            manifest[item].second[row] =
                gf::FromU64_3(column);
            manifest[deep_start].second[row] =
                column == 0
                ? Fp3::One()
                : Fp3::Zero();
            manifest[deep_chain].second[row] =
                Fp3::One();
            manifest[quotient_consumer]
                .second[row] =
                column + 1 ==
                    deep_terms_per_query
                ? Fp3::One()
                : Fp3::Zero();
        }
        manifest[active].second[row] =
            Fp3::One();
        manifest[deep_finalize].second[row] =
            Fp3::One();
        manifest[query_index].second[row] =
            gf::FromU64_3(query);
        ++row;

        uint32_t vm_ordinal = 0;
        for (uint32_t program_index = 0;
             program_index <
                 child_program.programs.size();
             ++program_index) {
            const auto& program =
                child_program.programs[
                    program_index];
            for (uint32_t instruction_index = 0;
                 instruction_index <
                     program.instructions.size();
                 ++instruction_index,
                 ++vm_ordinal, ++row) {
                const auto& instruction =
                    program.instructions[
                        instruction_index];
                const auto op =
                    instruction.opcode;
                uint32_t op_index = 0;
                switch (op) {
                case cb::Opcode::Current:
                    op_index = 0;
                    break;
                case cb::Opcode::Next:
                    op_index = 1;
                    break;
                case cb::Opcode::Constant:
                    op_index = 2;
                    break;
                case cb::Opcode::Add:
                    op_index = 3;
                    break;
                case cb::Opcode::Sub:
                    op_index = 4;
                    break;
                case cb::Opcode::Mul:
                    op_index = 5;
                    break;
                case cb::Opcode::Challenge:
                    if (why != nullptr) {
                        *why =
                            "deep_vm_static_challenge_opcode";
                    }
                    return false;
                }
                manifest[active].second[row] =
                    Fp3::One();
                manifest[vm_instruction]
                    .second[row] =
                    Fp3::One();
                manifest[query_index]
                    .second[row] =
                    gf::FromU64_3(query);
                manifest[item].second[row] =
                    gf::FromU64_3(
                        instruction_index);
                manifest[program_ordinal]
                    .second[row] =
                    gf::FromU64_3(
                        program_index);
                manifest[instruction_ordinal]
                    .second[row] =
                    gf::FromU64_3(
                        instruction_index);
                manifest[lhs_reference]
                    .second[row] =
                    gf::FromU64_3(
                        instruction.lhs);
                manifest[rhs_reference]
                    .second[row] =
                    gf::FromU64_3(
                        instruction.rhs);
                manifest[
                    register_use_multiplicity]
                    .second[row] =
                    gf::FromU64_3(
                        register_use[
                            program_index][
                            instruction_index]);
                manifest[constant_value]
                    .second[row] =
                    instruction.constant;
                manifest[opcode[op_index]]
                    .second[row] =
                    Fp3::One();
                const bool last_instruction =
                    instruction_index + 1 ==
                        program.instructions.size();
                manifest[program_end]
                    .second[row] =
                    last_instruction
                    ? Fp3::One()
                    : Fp3::Zero();
                manifest[vm_start].second[row] =
                    vm_ordinal == 0
                    ? Fp3::One()
                    : Fp3::Zero();
                const bool last_vm =
                    uint64_t{vm_ordinal} + 1 ==
                        vm_rows64;
                manifest[vm_chain].second[row] =
                    last_vm
                    ? Fp3::Zero()
                    : Fp3::One();
                manifest[vm_to_quotient]
                    .second[row] =
                    last_vm
                    ? Fp3::One()
                    : Fp3::Zero();
            }
        }
        manifest[active].second[row] =
            Fp3::One();
        manifest[quotient_identity]
            .second[row] =
            Fp3::One();
        manifest[query_index].second[row] =
            gf::FromU64_3(query);
        ++row;
    }
    if (row != deep.real_rows) {
        if (why != nullptr) {
            *why =
                "deep_vm_static_manifest_rows";
        }
        return false;
    }
    for (const auto& [column, canonical] :
         manifest) {
        if (column >= columns.size() ||
            canonical.size() !=
                columns[column].size()) {
            if (why != nullptr) {
                *why =
                    "deep_vm_static_manifest_column";
            }
            return false;
        }
        if (column <
                deep.layout.n_columns) {
            for (uint32_t r = 0;
                 r < cs.n_rows; ++r) {
                if (!gf::Eq(
                        canonical[r],
                        columns[column][r])) {
                    if (why != nullptr) {
                        *why =
                            "deep_vm_static_manifest_mismatch";
                    }
                    return false;
                }
            }
        } else {
            columns[column] = canonical;
        }
        statement_manifest_columns.push_back(
            column);
    }

    // Fill only ordinary post-R0 lookup witness columns. Challenges are the
    // verifier-owned Challenge class supplied to the bytecode adapter.
    std::array<Fp3, kDeepVmRegisterBusLanesV1>
        running_value{
            Fp3::Zero(), Fp3::Zero()};
    const Fp3 register_bus_tag =
        gf::FromU64_3(0x52454731U); // 'REG1'
    for (uint32_t r = 0;
         r < cs.n_rows; ++r) {
        const Fp3 binary_active =
            gf::Add(
                gf::Add(
                    columns[l.op_add][r],
                    columns[l.op_sub][r]),
                columns[l.op_mul][r]);
        const std::array<uint32_t, 3>
            register_column{{
                ssa.instruction_ordinal,
                ssa.lhs_reference,
                ssa.rhs_reference,
            }};
        const std::array<uint32_t, 3>
            value_column{{
                l.instruction_result,
                l.operand_lhs,
                l.operand_rhs,
            }};
        for (uint32_t lane = 0;
             lane <
                 kDeepVmRegisterBusLanesV1;
             ++lane) {
            const Fp3 gamma =
                challenge[lane];
            const Fp3 alpha =
                challenge[2 + lane];
            std::array<Fp3, 3> inverse{
                Fp3::Zero(),
                Fp3::Zero(),
                Fp3::Zero()};
            for (uint32_t side = 0;
                 side <
                     kDeepVmRegisterBusSidesV1;
                 ++side) {
                const Fp3 h0 = gf::Add(
                    columns[
                        register_column[side]][r],
                    gf::Mul(
                        gamma,
                        columns[
                            value_column[side]][r]));
                const Fp3 h1 = gf::Add(
                    columns[
                        ssa.program_ordinal][r],
                    gf::Mul(gamma, h0));
                const Fp3 h2 = gf::Add(
                    columns[l.query][r],
                    gf::Mul(gamma, h1));
                const Fp3 h3 = gf::Add(
                    register_bus_tag,
                    gf::Mul(gamma, h2));
                columns[
                    ssa.horner[lane][side][0]][r] =
                    h0;
                columns[
                    ssa.horner[lane][side][1]][r] =
                    h1;
                columns[
                    ssa.horner[lane][side][2]][r] =
                    h2;
                columns[
                    ssa.horner[lane][side][3]][r] =
                    h3;
                const Fp3 active =
                    side ==
                        static_cast<uint32_t>(
                            DeepVmRegisterSideV1::
                                Producer)
                    ? columns[l.vm_instruction][r]
                    : binary_active;
                const Fp3 denominator =
                    gf::Add(alpha, h3);
                if (!gf::IsZero(active)) {
                    if (gf::IsZero(denominator)) {
                        if (why != nullptr) {
                            *why =
                                "deep_vm_static_register_pole";
                        }
                        return false;
                    }
                    inverse[side] =
                        gf::Inv(denominator);
                }
                columns[
                    ssa.inverse[lane][side]][r] =
                    inverse[side];
            }
            columns[ssa.running[lane]][r] =
                running_value[lane];
            const Fp3 producer =
                gf::Mul(
                    columns[
                        ssa.register_use_multiplicity]
                        [r],
                    inverse[
                        static_cast<uint32_t>(
                            DeepVmRegisterSideV1::
                                Producer)]);
            const Fp3 consumers =
                gf::Mul(
                    binary_active,
                    gf::Add(
                        inverse[
                            static_cast<uint32_t>(
                                DeepVmRegisterSideV1::
                                    Lhs)],
                        inverse[
                            static_cast<uint32_t>(
                                DeepVmRegisterSideV1::
                                    Rhs)]));
            running_value[lane] =
                gf::Add(
                    running_value[lane],
                    gf::Sub(
                        producer,
                        consumers));
        }
    }
    for (const Fp3& terminal :
         running_value) {
        if (!gf::IsZero(terminal)) {
            if (why != nullptr) {
                *why =
                    "deep_vm_static_register_terminal";
            }
            return false;
        }
    }
    cs.preprocessed.clear();
    cs.preprocessed_row_group_roots.clear();
    for (auto& [column, canonical] :
         manifest) {
        cs.preprocessed.emplace_back(
            column, std::move(canonical));
    }
    cs.preprocessed_pin_ood = true;
    return true;
}

void AddConstraint(
    aq::AirConstraintSystem<Fp3>& cs,
    const char* name,
    aq::AirKind kind,
    uint32_t degree,
    std::function<Fp3(
        const std::vector<Fp3>&,
        const std::vector<Fp3>&)> eval)
{
    aq::AirConstraint<Fp3> out;
    out.name = name;
    out.kind = kind;
    out.alg_degree = degree;
    out.eval = std::move(eval);
    cs.constraints.push_back(
        std::move(out));
}

bool AddSchedulerConstraints(
    const LayoutV1& layout,
    aq::AirConstraintSystem<Fp3>& cs,
    alg_hash::Digest& acceptance_program_root,
    alg_hash::Digest& scheduler_program_root,
    std::string* why)
{
    if (!AppendAcceptanceOutputConstraintsV1(
            layout, cs,
            &acceptance_program_root, why)) {
        return false;
    }
    const cb::ProgramTable table =
        BuildSchedulerProgramTableV1(layout);
    aq::AirConstraintSystem<Fp3> adapter;
    if (!cb::BuildAirConstraintSystemFromProgramTable(
            table, cs.n_rows, adapter, why) ||
        adapter.n_columns != cs.n_columns ||
        adapter.constraints.size() !=
            2 + 4 * kPhasesV1) {
        return false;
    }
    scheduler_program_root =
        cb::CommitProgramTableAlgHash(table);
    if (!DigestNonzero(
            scheduler_program_root)) {
        if (why != nullptr) {
            *why =
                "v11_unified_scheduler_program_root";
        }
        return false;
    }
    cs.constraints.insert(
        cs.constraints.end(),
        std::make_move_iterator(
            adapter.constraints.begin()),
        std::make_move_iterator(
            adapter.constraints.end()));
    return true;
}

void AddGatedPhaseConstraint(
    const LayoutV1& layout,
    PhaseV1 phase,
    const aq::AirConstraint<Fp3>& local,
    aq::AirConstraintSystem<Fp3>& out)
{
    uint32_t selector = layout.PhaseTag(phase);
    aq::AirKind global_kind =
        aq::AirKind::kEverywhere;
    switch (local.kind) {
    case aq::AirKind::kEverywhere:
        selector = layout.PhaseTag(phase);
        break;
    case aq::AirKind::kTransition:
        selector =
            layout.PhaseTransition(phase);
        global_kind =
            aq::AirKind::kTransition;
        break;
    case aq::AirKind::kFirstRow:
        selector = layout.PhaseFirst(phase);
        break;
    case aq::AirKind::kLastRow:
        selector = layout.PhaseLast(phase);
        break;
    }
    auto eval = local.eval;
    AddConstraint(
        out,
        local.name == nullptr
        ? "stage3.v11_unified.unnamed_local"
        : local.name,
        global_kind,
        local.alg_degree + 1,
        [selector, eval = std::move(eval)](
            const auto& cur,
            const auto& next) {
            return gf::Mul(
                cur[selector],
                eval(cur, next));
        });
}

} // namespace

uint256 ComputeParentJoinStatementManifestR0RootV1(
    const pj::ProductV1& parent_join,
    uint32_t* ordered_columns,
    std::string* why)
{
    aq::AirConstraintSystem<Fp3> cs =
        parent_join.cs;
    std::vector<uint32_t> columns;
    uint256 root;
    if (!BuildParentJoinStatementManifestR0V1(
            parent_join, cs, columns, root, why)) {
        return {};
    }
    if (ordered_columns != nullptr) {
        *ordered_columns =
            static_cast<uint32_t>(
                columns.size());
    }
    return root;
}

cb::ProgramTable BuildMerkleHashProgramTableV1(
    const mf::HashLayoutV1& layout)
{
    cb::ProgramTable table;
    table.version =
        cb::kConstraintBytecodeVersion;
    table.role =
        RCStage3RelationRole::CompositionLink;
    table.current_width = layout.n_columns;
    table.next_width = layout.n_columns;
    table.challenge_width = 0;
    if (layout.poseidon.perm.base != 0 ||
        layout.poseidon.End() !=
            pa::kFixedColumns ||
        layout.input_pin_base !=
            layout.poseidon.End() ||
        layout.output_pin_base !=
            layout.input_pin_base +
                alg_hash::kAlgHashT ||
        layout.n_columns !=
            layout.output_pin_base +
                alg_hash::kAlgHashDigestLen) {
        return table;
    }

    cb::ProgramTable poseidon;
    std::string why;
    if (!pa::BuildFixedProgramTable(
            poseidon, &why) ||
        poseidon.programs.size() !=
            pa::kFixedConstraints) {
        return {};
    }
    table.programs.reserve(
        pa::kFixedConstraints +
        alg_hash::kAlgHashT +
        alg_hash::kAlgHashDigestLen);
    for (auto program :
         poseidon.programs) {
        program.constraint_ordinal =
            static_cast<uint32_t>(
                table.programs.size());
        program.current_width =
            table.current_width;
        program.next_width =
            table.next_width;
        table.programs.push_back(
            std::move(program));
    }

    for (uint32_t lane = 0;
         lane < alg_hash::kAlgHashT;
         ++lane) {
        cb::Program program =
            NewMerkleHashPinProgramV1(
                static_cast<uint32_t>(
                    table.programs.size()),
                table.current_width);
        program.instructions = {
            CurrentInstruction(
                layout.poseidon.perm
                    .InputCol(lane)),
            CurrentInstruction(
                layout.InputPin(lane)),
            BinaryInstruction(
                cb::Opcode::Sub, 0, 1),
        };
        table.programs.push_back(
            std::move(program));
    }
    for (uint32_t lane = 0;
         lane < alg_hash::kAlgHashDigestLen;
         ++lane) {
        cb::Program program =
            NewMerkleHashPinProgramV1(
                static_cast<uint32_t>(
                    table.programs.size()),
                table.current_width);
        const uint32_t output =
            EmitAffineV1(
                program.instructions,
                RecoverPermutationOutputAffineV1(
                    layout.poseidon, lane));
        program.instructions.push_back(
            CurrentInstruction(
                layout.OutputPin(lane)));
        const uint32_t claim =
            static_cast<uint32_t>(
                program.instructions.size() - 1);
        program.instructions.push_back(
            BinaryInstruction(
                cb::Opcode::Sub,
                output, claim));
        table.programs.push_back(
            std::move(program));
    }
    if (table.programs.size() !=
            pa::kFixedConstraints +
                alg_hash::kAlgHashT +
                alg_hash::kAlgHashDigestLen ||
        !cb::ValidateProgramTable(
            table, &why)) {
        return {};
    }
    return table;
}

cb::ProgramTable BuildMerkleFoldProgramTableV1(
    const mf::FoldLayoutV1& layout)
{
    cb::ProgramTable table;
    table.version =
        cb::kConstraintBytecodeVersion;
    table.role =
        RCStage3RelationRole::CompositionLink;
    table.current_width = layout.n_columns;
    table.next_width = layout.n_columns;
    table.challenge_width = 0;
    if (layout.n_columns != 16 ||
        layout.even != 0 ||
        layout.terminal + 1 !=
            layout.n_columns) {
        return table;
    }
    const Fp3 one = Fp3::One();
    const Fp3 inv2 = Fp3::FromFp(
        gf::Inv(gf::FromU64(2)));

    AppendBytecodeProgramV1(
        table, [=](BytecodeExprV1& e) {
            const uint32_t sum = e.Add(
                e.Current(layout.even),
                e.Current(layout.odd));
            e.Sub(
                e.Current(layout.even_part),
                e.Mul(sum, e.Constant(inv2)));
        });
    AppendBytecodeProgramV1(
        table, [=](BytecodeExprV1& e) {
            const uint32_t left = e.Mul(
                e.Current(layout.odd_part),
                e.Current(layout.x));
            const uint32_t difference = e.Sub(
                e.Current(layout.even),
                e.Current(layout.odd));
            e.Sub(
                left,
                e.Mul(
                    difference,
                    e.Constant(inv2)));
        });
    AppendBytecodeProgramV1(
        table, [=](BytecodeExprV1& e) {
            const uint32_t rhs = e.Add(
                e.Current(layout.even_part),
                e.Mul(
                    e.Current(layout.beta),
                    e.Current(layout.odd_part)));
            e.Sub(
                e.Current(layout.folded),
                rhs);
        });
    for (uint32_t column :
         {layout.side,
          layout.chain_next,
          layout.terminal}) {
        AppendBytecodeProgramV1(
            table, [=](BytecodeExprV1& e) {
                const uint32_t value =
                    e.Current(column);
                e.Mul(
                    value,
                    e.Sub(
                        value,
                        e.Constant(one)));
            });
    }
    AppendBytecodeProgramV1(
        table, [=](BytecodeExprV1& e) {
            e.Sub(
                e.Add(
                    e.Current(layout.chain_next),
                    e.Current(layout.terminal)),
                e.Constant(one));
        });
    AppendBytecodeProgramV1(
        table, [=](BytecodeExprV1& e) {
            const uint32_t selected = e.Add(
                e.Mul(
                    e.Sub(
                        e.Constant(one),
                        e.Current(layout.side)),
                    e.Current(layout.even)),
                e.Mul(
                    e.Current(layout.side),
                    e.Current(layout.odd)));
            e.Sub(
                e.Current(layout.here),
                selected);
        });
    AppendBytecodeProgramV1(
        table, [=](BytecodeExprV1& e) {
            e.Sub(
                e.Current(layout.odd_index),
                e.Add(
                    e.Current(layout.even_index),
                    e.Current(layout.half)));
        });
    AppendBytecodeProgramV1(
        table, [=](BytecodeExprV1& e) {
            e.Sub(
                e.Current(layout.index),
                e.Add(
                    e.Current(layout.even_index),
                    e.Mul(
                        e.Current(layout.side),
                        e.Current(layout.half))));
        });
    AppendBytecodeProgramKindV1(
        table, aq::AirKind::kTransition,
        [=](BytecodeExprV1& e) {
            e.Mul(
                e.Current(layout.chain_next),
                e.Sub(
                    e.Next(layout.here),
                    e.Current(layout.folded)));
        });
    AppendBytecodeProgramKindV1(
        table, aq::AirKind::kTransition,
        [=](BytecodeExprV1& e) {
            e.Mul(
                e.Current(layout.chain_next),
                e.Sub(
                    e.Next(layout.index),
                    e.Current(layout.even_index)));
        });
    AppendBytecodeProgramV1(
        table, [=](BytecodeExprV1& e) {
            e.Mul(
                e.Current(layout.terminal),
                e.Sub(
                    e.Current(layout.folded),
                    e.Current(layout.final_value)));
        });
    std::string why;
    if (table.programs.size() != 13 ||
        !cb::ValidateProgramTable(
            table, &why)) {
        return {};
    }
    return table;
}

cb::ProgramTable BuildDeepVmProgramTableV1(
    const dvm::LayoutV1& l)
{
    const auto ssa = DeepVmSsaLayout(l);
    cb::ProgramTable table;
    table.version =
        cb::kConstraintBytecodeVersion;
    table.role =
        RCStage3RelationRole::CompositionLink;
    table.current_width = ssa.n_columns;
    table.next_width = ssa.n_columns;
    table.challenge_width =
        kDeepVmChallengeColumnsV1;
    if (l.n_columns == 0 ||
        l.quotient_tape_accept + 1 !=
            l.n_columns ||
        ssa.n_columns !=
            l.n_columns +
                kDeepVmExtensionColumnsV1) {
        return table;
    }
    const Fp3 one = Fp3::One();
    const auto append_boolean =
        [&table, one](uint32_t column) {
            AppendBytecodeProgramV1(
                table, [=](
                    BytecodeExprV1& e) {
                    const uint32_t value =
                        e.Current(column);
                    e.Mul(
                        value,
                        e.Sub(
                            value,
                            e.Constant(one)));
                });
        };
    const std::array<uint32_t, 18>
        boolean_columns{{
            l.active,
            l.deep_term,
            l.deep_finalize,
            l.vm_instruction,
            l.quotient_identity,
            l.deep_start,
            l.deep_chain,
            l.op_current,
            l.op_next,
            l.op_constant,
            l.op_add,
            l.op_sub,
            l.op_mul,
            l.program_end,
            l.vm_start,
            l.vm_chain,
            l.vm_to_quotient,
            l.quotient_tape_deep_consumer,
        }};
    for (uint32_t column :
         boolean_columns) {
        append_boolean(column);
    }
    AppendBytecodeProgramV1(
        table, [=](BytecodeExprV1& e) {
            const uint32_t deep = e.Add(
                e.Current(l.deep_term),
                e.Current(l.deep_finalize));
            const uint32_t vm = e.Add(
                e.Current(l.vm_instruction),
                e.Current(l.quotient_identity));
            e.Sub(
                e.Current(l.active),
                e.Add(deep, vm));
        });
    const auto append_product =
        [&table](
            uint32_t output,
            uint32_t left,
            uint32_t right) {
            AppendBytecodeProgramV1(
                table, [=](
                    BytecodeExprV1& e) {
                    e.Sub(
                        e.Current(output),
                        e.Mul(
                            e.Current(left),
                            e.Current(right)));
                });
        };
    const auto append_gated_sum =
        [&table](
            uint32_t gate,
            uint32_t after,
            uint32_t before,
            uint32_t contribution) {
            AppendBytecodeProgramV1(
                table, [=](
                    BytecodeExprV1& e) {
                    e.Mul(
                        e.Current(gate),
                        e.Sub(
                            e.Current(after),
                            e.Add(
                                e.Current(before),
                                e.Current(
                                    contribution))));
                });
        };
    append_product(
        l.u_weight,
        l.coefficient,
        l.x_power);
    append_product(
        l.u_contribution,
        l.u_weight,
        l.current_value);
    append_gated_sum(
        l.deep_term,
        l.u_after,
        l.u_before,
        l.u_contribution);
    append_product(
        l.v1_weight,
        l.coefficient,
        l.z1_power);
    append_product(
        l.v1_contribution,
        l.v1_weight,
        l.eval_z1);
    append_gated_sum(
        l.deep_term,
        l.v1_after,
        l.v1_before,
        l.v1_contribution);
    append_product(
        l.v2_weight,
        l.coefficient,
        l.z2_power);
    append_product(
        l.v2_contribution,
        l.v2_weight,
        l.eval_z2);
    append_gated_sum(
        l.deep_term,
        l.v2_after,
        l.v2_before,
        l.v2_contribution);
    for (uint32_t accumulator :
         {l.u_before,
          l.v1_before,
          l.v2_before}) {
        AppendBytecodeProgramV1(
            table, [=](
                BytecodeExprV1& e) {
                e.Mul(
                    e.Current(l.deep_start),
                    e.Current(accumulator));
            });
    }
    for (const auto [after, before] :
         {std::pair{l.u_after, l.u_before},
          std::pair{l.v1_after, l.v1_before},
          std::pair{l.v2_after, l.v2_before}}) {
        AppendBytecodeProgramKindV1(
            table, aq::AirKind::kTransition,
            [=](BytecodeExprV1& e) {
                e.Mul(
                    e.Current(l.deep_chain),
                    e.Sub(
                        e.Next(before),
                        e.Current(after)));
            });
    }
    const auto append_inverse_product =
        [&table](
            uint32_t output,
            uint32_t x,
            uint32_t z,
            uint32_t inverse) {
            AppendBytecodeProgramV1(
                table, [=](
                    BytecodeExprV1& e) {
                    e.Sub(
                        e.Current(output),
                        e.Mul(
                            e.Sub(
                                e.Current(x),
                                e.Current(z)),
                            e.Current(inverse)));
                });
        };
    append_inverse_product(
        l.inv_product1,
        l.x, l.z1,
        l.inv_x_minus_z1);
    AppendBytecodeProgramV1(
        table, [=](BytecodeExprV1& e) {
            e.Mul(
                e.Current(l.deep_finalize),
                e.Sub(
                    e.Current(l.inv_product1),
                    e.Constant(one)));
        });
    append_inverse_product(
        l.inv_product2,
        l.x, l.z2,
        l.inv_x_minus_z2);
    AppendBytecodeProgramV1(
        table, [=](BytecodeExprV1& e) {
            e.Mul(
                e.Current(l.deep_finalize),
                e.Sub(
                    e.Current(l.inv_product2),
                    e.Constant(one)));
        });
    const auto append_difference_product =
        [&table](
            uint32_t output,
            uint32_t left,
            uint32_t right,
            uint32_t factor) {
            AppendBytecodeProgramV1(
                table, [=](
                    BytecodeExprV1& e) {
                    e.Sub(
                        e.Current(output),
                        e.Mul(
                            e.Sub(
                                e.Current(left),
                                e.Current(right)),
                            e.Current(factor)));
                });
        };
    append_difference_product(
        l.deep_diff_inv1,
        l.u_before,
        l.v1_before,
        l.inv_x_minus_z1);
    append_product(
        l.deep_rhs_term1,
        l.w1,
        l.deep_diff_inv1);
    append_difference_product(
        l.deep_diff_inv2,
        l.u_before,
        l.v2_before,
        l.inv_x_minus_z2);
    append_product(
        l.deep_rhs_term2,
        l.w2,
        l.deep_diff_inv2);
    AppendBytecodeProgramV1(
        table, [=](BytecodeExprV1& e) {
            e.Sub(
                e.Current(l.deep_rhs),
                e.Add(
                    e.Current(l.deep_rhs_term1),
                    e.Current(l.deep_rhs_term2)));
        });
    AppendBytecodeProgramV1(
        table, [=](BytecodeExprV1& e) {
            e.Mul(
                e.Current(l.deep_finalize),
                e.Sub(
                    e.Current(l.expected_deep),
                    e.Current(l.deep_rhs)));
        });
    AppendBytecodeProgramV1(
        table, [=](BytecodeExprV1& e) {
            e.Mul(
                e.Current(l.deep_finalize),
                e.Sub(
                    e.Current(l.first_fold_value),
                    e.Current(l.expected_deep)));
        });
    AppendBytecodeProgramV1(
        table, [=](BytecodeExprV1& e) {
            uint32_t sum =
                e.Constant(Fp3::Zero());
            for (uint32_t column :
                 {l.op_current,
                  l.op_next,
                  l.op_constant,
                  l.op_add,
                  l.op_sub,
                  l.op_mul}) {
                sum = e.Add(
                    sum,
                    e.Current(column));
            }
            e.Sub(
                sum,
                e.Current(l.vm_instruction));
        });
    AppendBytecodeProgramV1(
        table, [=](BytecodeExprV1& e) {
            const uint32_t load = e.Add(
                e.Add(
                    e.Current(l.op_current),
                    e.Current(l.op_next)),
                e.Current(l.op_constant));
            e.Mul(
                load,
                e.Sub(
                    e.Current(
                        l.instruction_result),
                    e.Current(l.operand_lhs)));
        });
    AppendBytecodeProgramV1(
        table, [=](BytecodeExprV1& e) {
            e.Mul(
                e.Current(l.op_add),
                e.Sub(
                    e.Current(
                        l.instruction_result),
                    e.Add(
                        e.Current(l.operand_lhs),
                        e.Current(l.operand_rhs))));
        });
    AppendBytecodeProgramV1(
        table, [=](BytecodeExprV1& e) {
            e.Mul(
                e.Current(l.op_sub),
                e.Sub(
                    e.Current(
                        l.instruction_result),
                    e.Sub(
                        e.Current(l.operand_lhs),
                        e.Current(l.operand_rhs))));
        });
    append_product(
        l.mul_product,
        l.operand_lhs,
        l.operand_rhs);
    AppendBytecodeProgramV1(
        table, [=](BytecodeExprV1& e) {
            e.Mul(
                e.Current(l.op_mul),
                e.Sub(
                    e.Current(
                        l.instruction_result),
                    e.Current(l.mul_product)));
        });
    AppendBytecodeProgramV1(
        table, [=](BytecodeExprV1& e) {
            e.Mul(
                e.Current(l.vm_start),
                e.Current(l.composition_before));
        });
    AppendBytecodeProgramV1(
        table, [=](BytecodeExprV1& e) {
            e.Mul(
                e.Current(l.vm_start),
                e.Sub(
                    e.Current(l.lambda_power),
                    e.Constant(one)));
        });
    append_product(
        l.selected_result,
        l.selector,
        l.instruction_result);
    append_product(
        l.lambda_selected,
        l.lambda_power,
        l.selected_result);
    append_product(
        l.program_contribution,
        l.program_end,
        l.lambda_selected);
    append_gated_sum(
        l.vm_instruction,
        l.composition_after,
        l.composition_before,
        l.program_contribution);
    AppendBytecodeProgramKindV1(
        table, aq::AirKind::kTransition,
        [=](BytecodeExprV1& e) {
            e.Mul(
                e.Current(l.vm_chain),
                e.Sub(
                    e.Next(
                        l.composition_before),
                    e.Current(
                        l.composition_after)));
        });
    AppendBytecodeProgramV1(
        table, [=](BytecodeExprV1& e) {
            e.Sub(
                e.Current(l.lambda_delta),
                e.Mul(
                    e.Current(l.program_end),
                    e.Sub(
                        e.Current(l.air_lambda),
                        e.Constant(one))));
        });
    AppendBytecodeProgramV1(
        table, [=](BytecodeExprV1& e) {
            e.Sub(
                e.Current(l.lambda_after),
                e.Mul(
                    e.Current(l.lambda_power),
                    e.Add(
                        e.Constant(one),
                        e.Current(l.lambda_delta))));
        });
    AppendBytecodeProgramKindV1(
        table, aq::AirKind::kTransition,
        [=](BytecodeExprV1& e) {
            e.Mul(
                e.Current(l.vm_chain),
                e.Sub(
                    e.Next(l.lambda_power),
                    e.Current(l.lambda_after)));
        });
    AppendBytecodeProgramKindV1(
        table, aq::AirKind::kTransition,
        [=](BytecodeExprV1& e) {
            e.Mul(
                e.Current(l.vm_to_quotient),
                e.Sub(
                    e.Next(
                        l.composition_before),
                    e.Current(
                        l.composition_after)));
        });
    append_product(
        l.quotient_product,
        l.zh,
        l.quotient_value);
    AppendBytecodeProgramV1(
        table, [=](BytecodeExprV1& e) {
            e.Mul(
                e.Current(l.quotient_identity),
                e.Sub(
                    e.Current(
                        l.composition_before),
                    e.Current(
                        l.quotient_product)));
        });

    for (uint32_t limb = 0;
         limb < dvm::kFp3TapeLimbsV1;
         ++limb) {
        for (uint32_t bit = 0;
             bit < dvm::kU32TapeBitsV1;
             ++bit) {
            append_boolean(
                l.quotient_tape_bit[
                    limb][bit]);
        }
        AppendBytecodeProgramV1(
            table, [=](
                BytecodeExprV1& e) {
                uint32_t reconstructed =
                    e.Constant(Fp3::Zero());
                for (uint32_t bit = 0;
                     bit <
                         dvm::kU32TapeBitsV1;
                     ++bit) {
                    reconstructed = e.Add(
                        reconstructed,
                        e.Mul(
                            e.Current(
                                l.quotient_tape_bit[
                                    limb][bit]),
                            e.Constant(
                                Fp3::FromFp(
                                    uint64_t{1}
                                    << bit))));
                }
                e.Sub(
                    e.Current(
                        l.quotient_tape_limb[
                            limb]),
                    reconstructed);
            });
        AppendBytecodeProgramKindV1(
            table, aq::AirKind::kTransition,
            [=](BytecodeExprV1& e) {
                e.Mul(
                    e.Sub(
                        e.Constant(one),
                        e.Current(
                            l.quotient_identity)),
                    e.Sub(
                        e.Next(
                            l.quotient_tape_limb[
                                limb]),
                        e.Current(
                            l.quotient_tape_limb[
                                limb])));
            });
    }
    const Fp3 max_u32 =
        Fp3::FromFp(
            std::numeric_limits<
                uint32_t>::max());
    for (uint32_t coordinate = 0;
         coordinate <
             dvm::kFp3CoordinatesV1;
         ++coordinate) {
        const uint32_t high_is_max =
            l.quotient_high_is_max[
                coordinate];
        const uint32_t high_inverse =
            l.quotient_high_delta_inverse[
                coordinate];
        const uint32_t low =
            l.quotient_tape_limb[
                2 * coordinate];
        const uint32_t high =
            l.quotient_tape_limb[
                2 * coordinate + 1];
        append_boolean(high_is_max);
        AppendBytecodeProgramV1(
            table, [=](
                BytecodeExprV1& e) {
                e.Mul(
                    e.Sub(
                        e.Current(high),
                        e.Constant(max_u32)),
                    e.Current(high_is_max));
            });
        AppendBytecodeProgramV1(
            table, [=](
                BytecodeExprV1& e) {
                e.Sub(
                    e.Mul(
                        e.Sub(
                            e.Current(high),
                            e.Constant(max_u32)),
                        e.Current(
                            high_inverse)),
                    e.Sub(
                        e.Constant(one),
                        e.Current(
                            high_is_max)));
            });
        AppendBytecodeProgramV1(
            table, [=](
                BytecodeExprV1& e) {
                e.Mul(
                    e.Current(high_is_max),
                    e.Current(low));
            });
    }
    AppendBytecodeProgramV1(
        table, [=](BytecodeExprV1& e) {
            constexpr uint64_t two32 =
                uint64_t{1} << 32;
            const std::array<Fp3, 3>
                basis{{
                    Fp3{1, 0, 0},
                    Fp3{0, 1, 0},
                    Fp3{0, 0, 1},
                }};
            uint32_t reconstructed =
                e.Constant(Fp3::Zero());
            for (uint32_t coordinate = 0;
                 coordinate <
                     dvm::kFp3CoordinatesV1;
                 ++coordinate) {
                const uint32_t value =
                    e.Add(
                        e.Current(
                            l.quotient_tape_limb[
                                2 * coordinate]),
                        e.Mul(
                            e.Current(
                                l.quotient_tape_limb[
                                    2 * coordinate +
                                    1]),
                            e.Constant(
                                Fp3::FromFp(
                                    two32))));
                reconstructed = e.Add(
                    reconstructed,
                    e.Mul(
                        value,
                        e.Constant(
                            basis[coordinate])));
            }
            e.Sub(
                e.Current(
                    l.quotient_tape_value),
                reconstructed);
        });
    AppendBytecodeProgramV1(
        table, [=](BytecodeExprV1& e) {
            e.Mul(
                e.Current(
                    l.quotient_tape_deep_consumer),
                e.Sub(
                    e.Current(l.current_value),
                    e.Current(
                        l.quotient_tape_value)));
        });
    AppendBytecodeProgramV1(
        table, [=](BytecodeExprV1& e) {
            e.Mul(
                e.Current(l.quotient_identity),
                e.Sub(
                    e.Current(l.quotient_value),
                    e.Current(
                        l.quotient_tape_value)));
        });
    AppendBytecodeProgramV1(
        table, [=](BytecodeExprV1& e) {
            e.Sub(
                e.Current(
                    l.quotient_tape_accept),
                e.Current(
                    l.quotient_identity));
        });

    // Constant operands are selected by verifier-regenerated ProgramTable
    // metadata, never accepted as free witness values.
    AppendBytecodeProgramV1(
        table, [=](BytecodeExprV1& e) {
            e.Mul(
                e.Current(l.op_constant),
                e.Sub(
                    e.Current(l.operand_lhs),
                    e.Current(
                        ssa.constant_value)));
        });

    // Dual-Fp3 indexed register LogUp. Each tuple uses the reverse-Horner
    // denominator
    //
    //   alpha + tag + gamma*(query + gamma*(program +
    //       gamma*(register + gamma*value))).
    //
    // Definitions are weighted by the exact number of references derived
    // from the canonical child ProgramTable; every binary operand consumes
    // one copy. Query/program/register labels prevent cross-instance swaps.
    for (uint32_t lane = 0;
         lane < kDeepVmRegisterBusLanesV1;
         ++lane) {
        const uint32_t gamma_column = lane;
        const uint32_t alpha_column = 2 + lane;
        const Fp3 register_bus_tag =
            gf::FromU64_3(0x52454731U); // 'REG1'
        const auto append_tuple =
            [&](DeepVmRegisterSideV1 side,
                uint32_t register_column,
                uint32_t value_column,
                uint32_t active_column) {
                const uint32_t side_index =
                    static_cast<uint32_t>(side);
                const auto& h =
                    ssa.horner[lane][side_index];
                AppendBytecodeProgramV1(
                    table, [=](
                        BytecodeExprV1& e) {
                        e.Sub(
                            e.Current(h[0]),
                            e.Add(
                                e.Current(
                                    register_column),
                                e.Mul(
                                    e.Challenge(
                                        gamma_column),
                                    e.Current(
                                        value_column))));
                    });
                AppendBytecodeProgramV1(
                    table, [=](
                        BytecodeExprV1& e) {
                        e.Sub(
                            e.Current(h[1]),
                            e.Add(
                                e.Current(
                                    ssa.program_ordinal),
                                e.Mul(
                                    e.Challenge(
                                        gamma_column),
                                    e.Current(h[0]))));
                    });
                AppendBytecodeProgramV1(
                    table, [=](
                        BytecodeExprV1& e) {
                        e.Sub(
                            e.Current(h[2]),
                            e.Add(
                                e.Current(l.query),
                                e.Mul(
                                    e.Challenge(
                                        gamma_column),
                                    e.Current(h[1]))));
                    });
                AppendBytecodeProgramV1(
                    table, [=](
                        BytecodeExprV1& e) {
                        e.Sub(
                            e.Current(h[3]),
                            e.Add(
                                e.Constant(
                                    register_bus_tag),
                                e.Mul(
                                    e.Challenge(
                                        gamma_column),
                                    e.Current(h[2]))));
                    });
                AppendBytecodeProgramV1(
                    table, [=](
                        BytecodeExprV1& e) {
                        e.Sub(
                            e.Mul(
                                e.Current(
                                    ssa.inverse[
                                        lane][side_index]),
                                e.Add(
                                    e.Challenge(
                                        alpha_column),
                                    e.Current(h[3]))),
                            e.Current(active_column));
                    });
            };
        append_tuple(
            DeepVmRegisterSideV1::Producer,
            ssa.instruction_ordinal,
            l.instruction_result,
            l.vm_instruction);
        // The opcode schedule is one-hot and R0-bound, so this sum is exactly
        // the binary-consumer selector for both operands.
        const uint32_t binary_active =
            l.op_add;
        const auto append_consumer_tuple =
            [&](DeepVmRegisterSideV1 side,
                uint32_t register_column,
                uint32_t value_column) {
                const uint32_t side_index =
                    static_cast<uint32_t>(side);
                const auto& h =
                    ssa.horner[lane][side_index];
                AppendBytecodeProgramV1(
                    table, [=](
                        BytecodeExprV1& e) {
                        e.Sub(
                            e.Current(h[0]),
                            e.Add(
                                e.Current(
                                    register_column),
                                e.Mul(
                                    e.Challenge(
                                        gamma_column),
                                    e.Current(
                                        value_column))));
                    });
                AppendBytecodeProgramV1(
                    table, [=](
                        BytecodeExprV1& e) {
                        e.Sub(
                            e.Current(h[1]),
                            e.Add(
                                e.Current(
                                    ssa.program_ordinal),
                                e.Mul(
                                    e.Challenge(
                                        gamma_column),
                                    e.Current(h[0]))));
                    });
                AppendBytecodeProgramV1(
                    table, [=](
                        BytecodeExprV1& e) {
                        e.Sub(
                            e.Current(h[2]),
                            e.Add(
                                e.Current(l.query),
                                e.Mul(
                                    e.Challenge(
                                        gamma_column),
                                    e.Current(h[1]))));
                    });
                AppendBytecodeProgramV1(
                    table, [=](
                        BytecodeExprV1& e) {
                        e.Sub(
                            e.Current(h[3]),
                            e.Add(
                                e.Constant(
                                    register_bus_tag),
                                e.Mul(
                                    e.Challenge(
                                        gamma_column),
                                    e.Current(h[2]))));
                    });
                AppendBytecodeProgramV1(
                    table, [=](
                        BytecodeExprV1& e) {
                        const uint32_t active =
                            e.Add(
                                e.Add(
                                    e.Current(
                                        binary_active),
                                    e.Current(
                                        l.op_sub)),
                                e.Current(
                                    l.op_mul));
                        e.Sub(
                            e.Mul(
                                e.Current(
                                    ssa.inverse[
                                        lane][side_index]),
                                e.Add(
                                    e.Challenge(
                                        alpha_column),
                                    e.Current(h[3]))),
                            active);
                    });
            };
        append_consumer_tuple(
            DeepVmRegisterSideV1::Lhs,
            ssa.lhs_reference,
            l.operand_lhs);
        append_consumer_tuple(
            DeepVmRegisterSideV1::Rhs,
            ssa.rhs_reference,
            l.operand_rhs);

        AppendBytecodeProgramKindV1(
            table, aq::AirKind::kFirstRow,
            [=](BytecodeExprV1& e) {
                e.Current(ssa.running[lane]);
            });
        const auto emit_increment =
            [=](BytecodeExprV1& e) {
                const uint32_t producer =
                    e.Mul(
                        e.Current(
                            ssa.register_use_multiplicity),
                        e.Current(
                            ssa.inverse[lane][
                                static_cast<uint32_t>(
                                    DeepVmRegisterSideV1::
                                        Producer)]));
                const uint32_t binary =
                    e.Add(
                        e.Add(
                            e.Current(l.op_add),
                            e.Current(l.op_sub)),
                        e.Current(l.op_mul));
                const uint32_t consumers =
                    e.Mul(
                        binary,
                        e.Add(
                            e.Current(
                                ssa.inverse[lane][
                                    static_cast<uint32_t>(
                                        DeepVmRegisterSideV1::
                                            Lhs)]),
                            e.Current(
                                ssa.inverse[lane][
                                    static_cast<uint32_t>(
                                        DeepVmRegisterSideV1::
                                            Rhs)])));
                return e.Sub(
                    producer, consumers);
            };
        AppendBytecodeProgramKindV1(
            table, aq::AirKind::kTransition,
            [=](BytecodeExprV1& e) {
                const uint32_t increment =
                    emit_increment(e);
                e.Sub(
                    e.Next(ssa.running[lane]),
                    e.Add(
                        e.Current(
                            ssa.running[lane]),
                        increment));
            });
        AppendBytecodeProgramKindV1(
            table, aq::AirKind::kLastRow,
            [=](BytecodeExprV1& e) {
                e.Add(
                    e.Current(ssa.running[lane]),
                    emit_increment(e));
            });
    }
    std::string why;
    if (table.programs.size() !=
            kDeepVmCanonicalConstraintsV1 ||
        !cb::ValidateProgramTable(
            table, &why) ||
        !cb::ProgramTableIsChallengeIndependent(
            table)) {
        return {};
    }
    return table;
}

DeepVmCanonicalPhaseV1
BuildDeepVmCanonicalPhaseV1(
    const dvm::ProductV1& deep,
    const cb::ProgramTable& child_program,
    const alg_hash::Digest& expected_program_root,
    const rv::QueryRangeV1& range)
{
    DeepVmCanonicalPhaseV1 out;
    out.program =
        BuildDeepVmProgramTableV1(
            deep.layout);
    out.challenge =
        DeriveDeepVmRegisterChallengesV1(
            deep.preprocessed_row_group_root,
            expected_program_root,
            range);
    std::string why;
    if (out.program.programs.size() !=
            kDeepVmCanonicalConstraintsV1 ||
        !BuildDeepVmStaticPhaseV1(
            deep,
            child_program,
            expected_program_root,
            range,
            out.challenge,
            out.cs,
            out.columns,
            out.statement_manifest_columns,
            &why)) {
        out.note =
            "stage3:v11_unified_deep_vm:" +
            why;
        return out;
    }
    const uint64_t violations =
        air_recurse::
            CountWitnessViolationsOnH(
                out.cs, out.columns);
    out.program_and_range_bound =
        SameDigest(
            cb::CommitProgramTableAlgHash(
                child_program),
            expected_program_root) &&
        SameDigest(
            deep.program_root,
            expected_program_root) &&
        deep.first_query ==
            range.first_query &&
        deep.query_count ==
            range.query_count;
    out.constant_schedule_owned =
        out.statement_manifest_columns.size() ==
            kDeepVmStatementScheduleColumnsV1;
    out.register_logup_complete =
        out.program.challenge_width ==
            kDeepVmChallengeColumnsV1 &&
        out.program.current_width ==
            deep.layout.n_columns +
                kDeepVmExtensionColumnsV1 &&
        DeepVmChallengesValid(
            out.challenge);
    out.valid =
        out.program_and_range_bound &&
        out.constant_schedule_owned &&
        out.register_logup_complete &&
        violations == 0;
    out.note = out.valid
        ? "stage3:v11_unified_deep_vm:"
          "constants_and_dual_fp3_register_logup"
        : "stage3:v11_unified_deep_vm:"
          "constraint_failure";
    return out;
}

cb::ProgramTable BuildDecoderProgramTableV1(
    const dj::LayoutV1& layout)
{
    cb::ProgramTable table;
    table.version =
        cb::kConstraintBytecodeVersion;
    table.role =
        RCStage3RelationRole::CompositionLink;
    const auto aux =
        DecoderHornerLayout(layout);
    table.current_width =
        aux.n_columns;
    table.next_width =
        aux.n_columns;
    table.challenge_width =
        kDecoderChallengeColumnsV1;
    if (layout.n_columns == 0 ||
        layout.root_value + 1 !=
            layout.n_columns ||
        aux.n_columns !=
            layout.n_columns +
                kDecoderHornerAuxColumnsV1) {
        return table;
    }
    const Fp3 one = Fp3::One();
    const auto append_boolean =
        [&table, one](uint32_t column) {
            AppendBytecodeProgramV1(
                table,
                [column, one](
                    BytecodeExprV1& e) {
                    const uint32_t value =
                        e.Current(column);
                    e.Mul(
                        value,
                        e.Sub(
                            value,
                            e.Constant(one)));
                });
        };
    append_boolean(layout.active);
    append_boolean(layout.root_active);
    AppendBytecodeProgramV1(
        table, [=](BytecodeExprV1& e) {
            e.Mul(
                e.Current(layout.active),
                e.Sub(
                    e.Current(
                        layout.consumer_claim),
                    e.Current(
                        layout.consumer_pin)));
        });
    AppendBytecodeProgramKindV1(
        table, aq::AirKind::kTransition,
        [=](BytecodeExprV1& e) {
            e.Mul(
                e.Sub(
                    e.Constant(one),
                    e.Current(layout.active)),
                e.Next(layout.active));
        });

    for (uint32_t lane = 0;
         lane < dj::kDecoderJoinBusLanesV1;
         ++lane) {
        const uint32_t gamma_column = lane;
        const uint32_t alpha_column = 2 + lane;
        const auto append_tuple =
            [&](uint32_t side,
                uint32_t kind,
                uint32_t occurrence,
                uint32_t address,
                uint32_t value,
                uint32_t inverse) {
                const auto h =
                    aux.column[lane][side];
                // Reverse Horner:
                // h1 = address + gamma * value
                // h2 = occurrence + gamma * h1
                // h3 = kind + gamma * h2
                // h4 = alpha + gamma * h3.
                // Every relation is degree two under the explicit
                // post-challenge column accounting.
                AppendBytecodeProgramV1(
                    table, [=](
                        BytecodeExprV1& e) {
                        e.Sub(
                            e.Current(h[0]),
                            e.Add(
                                e.Current(address),
                                e.Mul(
                                    e.Challenge(
                                        gamma_column),
                                    e.Current(value))));
                    });
                AppendBytecodeProgramV1(
                    table, [=](
                        BytecodeExprV1& e) {
                        e.Sub(
                            e.Current(h[1]),
                            e.Add(
                                e.Current(occurrence),
                                e.Mul(
                                    e.Challenge(
                                        gamma_column),
                                    e.Current(h[0]))));
                    });
                AppendBytecodeProgramV1(
                    table, [=](
                        BytecodeExprV1& e) {
                        e.Sub(
                            e.Current(h[2]),
                            e.Add(
                                e.Current(kind),
                                e.Mul(
                                    e.Challenge(
                                        gamma_column),
                                    e.Current(h[1]))));
                    });
                AppendBytecodeProgramV1(
                    table, [=](
                        BytecodeExprV1& e) {
                        e.Sub(
                            e.Current(h[3]),
                            e.Add(
                                e.Challenge(
                                    alpha_column),
                                e.Mul(
                                    e.Challenge(
                                        gamma_column),
                                    e.Current(h[2]))));
                    });
                AppendBytecodeProgramV1(
                    table, [=](
                        BytecodeExprV1& e) {
                        e.Sub(
                            e.Mul(
                                e.Current(inverse),
                                e.Current(h[3])),
                            e.Current(layout.active));
                    });
            };
        append_tuple(
            0,
            layout.source_kind,
            layout.source_occurrence,
            layout.source_address,
            layout.source_value,
            layout.source_inverse[lane]);
        append_tuple(
            1,
            layout.consumer_kind,
            layout.consumer_occurrence,
            layout.consumer_address,
            layout.consumer_claim,
            layout.consumer_inverse[lane]);
        AppendBytecodeProgramKindV1(
            table, aq::AirKind::kFirstRow,
            [=](BytecodeExprV1& e) {
                e.Current(
                    layout.running[lane]);
            });
        AppendBytecodeProgramKindV1(
            table, aq::AirKind::kTransition,
            [=](BytecodeExprV1& e) {
                const uint32_t increment =
                    e.Sub(
                        e.Current(
                            layout.source_inverse[
                                lane]),
                        e.Current(
                            layout.consumer_inverse[
                                lane]));
                e.Sub(
                    e.Next(
                        layout.running[lane]),
                    e.Add(
                        e.Current(
                            layout.running[lane]),
                        increment));
            });
        AppendBytecodeProgramKindV1(
            table, aq::AirKind::kLastRow,
            [=](BytecodeExprV1& e) {
                e.Add(
                    e.Current(
                        layout.running[lane]),
                    e.Sub(
                        e.Current(
                            layout.source_inverse[
                                lane]),
                        e.Current(
                            layout.consumer_inverse[
                                lane])));
            });
    }
    std::string why;
    if (table.programs.size() != 30 ||
        !cb::ValidateProgramTable(
            table, &why) ||
        !cb::ProgramTableIsChallengeIndependent(
            table)) {
        return {};
    }
    return table;
}

cb::ProgramTable BuildAcceptanceProgramTableV1(
    const LayoutV1& layout)
{
    cb::ProgramTable table;
    table.version =
        cb::kConstraintBytecodeVersion;
    table.role =
        RCStage3RelationRole::CompositionLink;
    table.current_width = layout.n_columns;
    table.next_width = layout.n_columns;
    table.challenge_width = 0;
    if (layout.n_columns == 0 ||
        layout.acceptance >= layout.n_columns ||
        layout.PhaseFirst(
            PhaseV1::ParentJoin) >=
            layout.n_columns) {
        return table;
    }
    AppendBytecodeProgramV1(
        table,
        [acceptance = layout.acceptance](
            BytecodeExprV1& expression) {
            const uint32_t value =
                expression.Current(acceptance);
            const uint32_t one =
                expression.Constant(Fp3::One());
            const uint32_t value_minus_one =
                expression.Sub(value, one);
            expression.Mul(
                value, value_minus_one);
        });
    AppendBytecodeProgramV1(
        table,
        [acceptance = layout.acceptance,
         parent_first =
             layout.PhaseFirst(
                 PhaseV1::ParentJoin)](
            BytecodeExprV1& expression) {
            expression.Sub(
                expression.Current(acceptance),
                expression.Current(parent_first));
        });
    return table;
}

cb::ProgramTable BuildSchedulerProgramTableV1(
    const LayoutV1& layout)
{
    cb::ProgramTable table;
    table.version =
        cb::kConstraintBytecodeVersion;
    table.role =
        RCStage3RelationRole::CompositionLink;
    table.current_width = layout.n_columns;
    table.next_width = layout.n_columns;
    table.challenge_width = 0;
    bool layout_valid =
        layout.n_columns != 0 &&
        layout.active < layout.n_columns;
    for (uint32_t index = 0;
         index < kPhasesV1;
         ++index) {
        const auto phase =
            static_cast<PhaseV1>(index);
        layout_valid =
            layout_valid &&
            layout.PhaseTag(phase) <
                layout.n_columns &&
            layout.PhaseFirst(phase) <
                layout.n_columns &&
            layout.PhaseLast(phase) <
                layout.n_columns &&
            layout.PhaseTransition(phase) <
                layout.n_columns;
    }
    if (!layout_valid) return table;

    const auto append_boolean =
        [&table](uint32_t column) {
            AppendBytecodeProgramV1(
                table,
                [column](
                    BytecodeExprV1& expression) {
                    const uint32_t value =
                        expression.Current(column);
                    const uint32_t one =
                        expression.Constant(
                            Fp3::One());
                    expression.Mul(
                        value,
                        expression.Sub(
                            value, one));
                });
        };
    append_boolean(layout.active);
    AppendBytecodeProgramV1(
        table,
        [layout](
            BytecodeExprV1& expression) {
            uint32_t sum =
                expression.Current(
                    layout.PhaseTag(
                        PhaseV1::ParentJoin));
            for (uint32_t index = 1;
                 index < kPhasesV1;
                 ++index) {
                sum = expression.Add(
                    sum,
                    expression.Current(
                        layout.PhaseTag(
                            static_cast<PhaseV1>(
                                index))));
            }
            expression.Sub(
                sum,
                expression.Current(
                    layout.active));
        });
    for (uint32_t index = 0;
         index < kPhasesV1;
         ++index) {
        const auto phase =
            static_cast<PhaseV1>(index);
        const uint32_t tag =
            layout.PhaseTag(phase);
        append_boolean(tag);
        for (uint32_t selector : {
                 layout.PhaseFirst(phase),
                 layout.PhaseLast(phase),
                 layout.PhaseTransition(phase)}) {
            AppendBytecodeProgramV1(
                table,
                [tag, selector](
                    BytecodeExprV1& expression) {
                    const uint32_t one =
                        expression.Constant(
                            Fp3::One());
                    const uint32_t tag_value =
                        expression.Current(tag);
                    const uint32_t outside_tag =
                        expression.Sub(
                            one, tag_value);
                    expression.Mul(
                        expression.Current(
                            selector),
                        outside_tag);
                });
        }
    }
    return table;
}

bool AppendAcceptanceOutputConstraintsV1(
    const LayoutV1& layout,
    aq::AirConstraintSystem<Fp3>& cs,
    alg_hash::Digest* program_root,
    std::string* why)
{
    const cb::ProgramTable table =
        BuildAcceptanceProgramTableV1(layout);
    aq::AirConstraintSystem<Fp3> adapter;
    if (cs.n_columns != layout.n_columns ||
        !cb::BuildAirConstraintSystemFromProgramTable(
            table, cs.n_rows, adapter, why) ||
        adapter.n_columns != cs.n_columns ||
        adapter.constraints.size() != 2) {
        return false;
    }
    const auto root =
        cb::CommitProgramTableAlgHash(table);
    if (!DigestNonzero(root)) {
        if (why != nullptr) {
            *why =
                "v11_unified_acceptance_program_root";
        }
        return false;
    }
    if (program_root != nullptr) {
        *program_root = root;
    }
    cs.constraints.insert(
        cs.constraints.end(),
        std::make_move_iterator(
            adapter.constraints.begin()),
        std::make_move_iterator(
            adapter.constraints.end()));
    return true;
}

ProductV1 BuildProductV1(
    const rv::InputV1& input,
    const rv::QueryRangeV1& range)
{
    ProductV1 out;
    out.range = range;
    auto fail = [&out](
                    const std::string& detail) {
        out.valid_foundation = false;
        out.recursive_authority_ready = false;
        out.note =
            "stage3:v11_unified_verifier:" +
            detail;
        return out;
    };
    out.exact_q96_range =
        range.ordinal == 0 &&
        range.first_query == 0 &&
        range.query_count == kQ96QueriesV1;
    if (!out.exact_q96_range ||
        input.expected_child_statement_root.IsNull() ||
        !input.parent_join.valid ||
        input.parent_join
            .preprocessed_row_group_root.IsNull()) {
        return fail("range_statement_or_parent");
    }

    std::vector<uint32_t> words;
    std::string why;
    if (!abi::EncodeCanonicalV1(
            input.proof.envelope,
            words, nullptr, &why)) {
        return fail("encode:" + why);
    }
    const auto decoded =
        abi::DecodeCanonicalV1(words, &why);
    if (!decoded.has_value() ||
        !decoded->canonical ||
        !decoded->complete) {
        return fail("decode:" + why);
    }

    out.parent_join = input.parent_join;
    uint32_t early_parent_r0_columns = 0;
    const uint256 early_parent_r0_root =
        ComputeParentJoinStatementManifestR0RootV1(
            out.parent_join,
            &early_parent_r0_columns, &why);
    if (early_parent_r0_root.IsNull() ||
        early_parent_r0_columns == 0 ||
        early_parent_r0_root !=
            input.expected_child_statement_root) {
        return fail(
            "parent_join_statement_root_mismatch");
    }
    out.merkle_fold =
        mf::BuildShardV1(
            *decoded, input.transcript,
            range.first_query,
            range.query_count);
    if (!out.merkle_fold.valid) {
        return fail(
            "merkle:" +
            out.merkle_fold.note);
    }
    out.deep_vm =
        dvm::BuildProductV1(
            input.proof,
            input.transcript,
            input.child_program,
            input.expected_child_program_root,
            range.first_query,
            range.query_count);
    if (!out.deep_vm.valid) {
        return fail(
            "deep_vm:" +
            out.deep_vm.note);
    }
    out.decoder =
        dj::BuildProductV1(
            *decoded, out.parent_join,
            {out.merkle_fold});
    if (!out.decoder.valid ||
        dj::RecountViolationsV1(
            out.decoder,
            out.decoder.columns) != 0) {
        return fail(
            "decoder:" +
            out.decoder.note);
    }

    cb::ProgramTable parent_join_program;
    np::ManifestV1 parent_join_manifest;
    if (!np::BuildCanonicalProgramTableV1(
            parent_join_program,
            &parent_join_manifest, &why) ||
        !parent_join_manifest
            .canonical_program_table ||
        !parent_join_manifest
            .exact_native_constraint_order ||
        !parent_join_manifest
            .no_opaque_callbacks ||
        parent_join_program.current_width !=
            out.parent_join.cs.n_columns ||
        parent_join_program.next_width !=
            out.parent_join.cs.n_columns ||
        parent_join_program.programs.size() !=
            out.parent_join.cs.constraints.size()) {
        return fail(
            "parent_join_static_program:" +
            why);
    }
    aq::AirConstraintSystem<Fp3>
        parent_join_static_cs;
    if (!cb::BuildAirConstraintSystemFromProgramTable(
            parent_join_program,
            out.parent_join.cs.n_rows,
            parent_join_static_cs,
            &why)) {
        return fail(
            "parent_join_static_adapter:" +
            why);
    }
    std::vector<uint32_t>
        parent_join_statement_manifest_columns;
    if (!BuildParentJoinStatementManifestR0V1(
            out.parent_join,
            parent_join_static_cs,
            parent_join_statement_manifest_columns,
            out.parent_join_statement_manifest_r0_root,
            &why)) {
        return fail(
            "parent_join_statement_manifest_r0:" +
            why);
    }
    out.parent_join_statement_manifest_r0_columns =
        static_cast<uint32_t>(
            parent_join_statement_manifest_columns.size());
    out.parent_join_statement_root_r0_bound =
        out.parent_join_statement_manifest_r0_root ==
            input.expected_child_statement_root;
    if (!out.parent_join_statement_root_r0_bound) {
        return fail(
            "parent_join_statement_root_mismatch");
    }
    if (air_recurse::
            CountWitnessViolationsOnH(
                parent_join_static_cs,
                out.parent_join.columns) != 0) {
        return fail(
            "parent_join_static_witness");
    }
    out.parent_join_program_root =
        cb::CommitProgramTableAlgHash(
            parent_join_program);
    out.parent_join_program_constraints =
        static_cast<uint32_t>(
            parent_join_program.programs.size());
    out.parent_join_constraints_canonical_bytecode =
        out.parent_join_program_constraints ==
            np::kExpectedProgramsV1;
    out.parent_join_program_root_recomputed =
        DigestNonzero(
            out.parent_join_program_root) &&
        out.parent_join_program_root ==
            parent_join_manifest.program_root;
    const auto is_static_r0 =
        [&parent_join_statement_manifest_columns](
            uint32_t column) {
            return std::binary_search(
                parent_join_statement_manifest_columns.begin(),
                parent_join_statement_manifest_columns.end(),
                column);
        };
    out.parent_join_proof_tape_cells_ordinary =
        true;
    for (uint32_t lane = 0;
         lane < alg_hash::kAlgHashRate; ++lane) {
        out.parent_join_proof_tape_cells_ordinary =
            out.parent_join_proof_tape_cells_ordinary &&
            !is_static_r0(
                out.parent_join.layout.replay.Absorb(lane));
    }
    for (uint32_t limb = 0;
         limb < alg_hash::kAlgHashDigestLen; ++limb) {
        out.parent_join_proof_tape_cells_ordinary =
            out.parent_join_proof_tape_cells_ordinary &&
            !is_static_r0(
                out.parent_join.layout.replay.DigestClaim(limb));
    }
    // The canonical layout fixes every proof-tape cell at the physical
    // (row, Absorb(lane)) or (row, DigestClaim(limb)) location.  No
    // prover-selected offset participates in this map.
    out.parent_join_proof_tape_fixed_offsets =
        out.parent_join.layout.replay.n_columns != 0 &&
        out.parent_join.cs.n_rows >= 2;
    // The canonical replay program contains an event-digest capture relation
    // for each of the four Poseidon2 output limbs.
    out.parent_join_digest_claims_poseidon_bound =
        out.parent_join_constraints_canonical_bytecode &&
        out.parent_join_program_root_recomputed;
    out.parent_join_r0_statement_manifest_only =
        out.parent_join_proof_tape_cells_ordinary &&
        out.parent_join_proof_tape_fixed_offsets &&
        out.parent_join_digest_claims_poseidon_bound &&
        out.parent_join_statement_root_r0_bound;
    out.parent_join_cs_independent_of_child_witness =
        out.parent_join_constraints_canonical_bytecode &&
        out.parent_join_program_root_recomputed &&
        out.parent_join_r0_statement_manifest_only;

    const cb::ProgramTable merkle_hash_program =
        BuildMerkleHashProgramTableV1(
            out.merkle_fold.hash_layout);
    aq::AirConstraintSystem<Fp3>
        merkle_hash_static_cs;
    if (merkle_hash_program.programs.size() !=
            pa::kFixedConstraints +
                alg_hash::kAlgHashT +
                alg_hash::kAlgHashDigestLen ||
        merkle_hash_program.current_width !=
            out.merkle_fold.hash_cs.n_columns ||
        merkle_hash_program.next_width !=
            out.merkle_fold.hash_cs.n_columns ||
        merkle_hash_program.programs.size() !=
            out.merkle_fold.hash_cs.constraints.size() ||
        !cb::BuildAirConstraintSystemFromProgramTable(
            merkle_hash_program,
            out.merkle_fold.hash_cs.n_rows,
            merkle_hash_static_cs, &why)) {
        return fail(
            "merkle_hash_static_program:" +
            why);
    }
    if (air_recurse::
            CountWitnessViolationsOnH(
                merkle_hash_static_cs,
                out.merkle_fold.hash_columns) != 0) {
        return fail(
            "merkle_hash_static_witness");
    }
    out.merkle_hash_program_root =
        cb::CommitProgramTableAlgHash(
            merkle_hash_program);
    const cb::ProgramTable
        merkle_hash_program_recomputed =
            BuildMerkleHashProgramTableV1(
                out.merkle_fold.hash_layout);
    out.merkle_hash_program_constraints =
        static_cast<uint32_t>(
            merkle_hash_program.programs.size());
    out.merkle_hash_constraints_canonical_bytecode =
        out.merkle_hash_program_constraints ==
            pa::kFixedConstraints +
                alg_hash::kAlgHashT +
                alg_hash::kAlgHashDigestLen;
    out.merkle_hash_program_root_recomputed =
        DigestNonzero(
            out.merkle_hash_program_root) &&
        merkle_hash_program_recomputed ==
            merkle_hash_program &&
        cb::CommitProgramTableAlgHash(
            merkle_hash_program_recomputed) ==
            out.merkle_hash_program_root;
    // The canonical fixed Merkle chip has no immutable per-row values:
    // all 12 inputs and four digest claims are ordinary committed tape.
    out.merkle_hash_statement_manifest_r0_columns =
        static_cast<uint32_t>(
            merkle_hash_static_cs.preprocessed.size());
    out.merkle_hash_proof_tape_cells =
        alg_hash::kAlgHashT +
        alg_hash::kAlgHashDigestLen;
    out.merkle_hash_proof_tape_cells_ordinary =
        merkle_hash_static_cs.preprocessed.empty();
    out.merkle_hash_proof_tape_fixed_lane_offsets =
        out.merkle_fold.hash_layout.input_pin_base ==
            out.merkle_fold.hash_layout
                .poseidon.End() &&
        out.merkle_fold.hash_layout.output_pin_base ==
            out.merkle_fold.hash_layout
                .input_pin_base +
                alg_hash::kAlgHashT &&
        out.merkle_fold.hash_layout.n_columns ==
            out.merkle_fold.hash_layout
                .output_pin_base +
                alg_hash::kAlgHashDigestLen;
    out.merkle_hash_io_poseidon_bound =
        out.merkle_hash_constraints_canonical_bytecode &&
        out.merkle_hash_program_root_recomputed;
    out.merkle_hash_r0_statement_manifest_only =
        out.merkle_hash_statement_manifest_r0_columns == 0 &&
        out.merkle_hash_proof_tape_cells_ordinary &&
        out.merkle_hash_proof_tape_fixed_lane_offsets &&
        out.merkle_hash_io_poseidon_bound;
    out.merkle_hash_cs_independent_of_child_witness =
        out.merkle_hash_r0_statement_manifest_only;
    // The source-address/path-order bus is owned by a later Decoder static
    // migration. Do not confuse a complete Poseidon row relation with a
    // complete Merkle-path relation.
    out.merkle_hash_row_semantic_carry_complete =
        false;

    const cb::ProgramTable merkle_fold_program =
        BuildMerkleFoldProgramTableV1(
            out.merkle_fold.fold_layout);
    aq::AirConstraintSystem<Fp3>
        merkle_fold_static_cs;
    if (merkle_fold_program.programs.size() != 13 ||
        merkle_fold_program.current_width !=
            out.merkle_fold.fold_cs.n_columns ||
        merkle_fold_program.next_width !=
            out.merkle_fold.fold_cs.n_columns ||
        merkle_fold_program.programs.size() !=
            out.merkle_fold.fold_cs.constraints.size() ||
        !cb::BuildAirConstraintSystemFromProgramTable(
            merkle_fold_program,
            out.merkle_fold.fold_cs.n_rows,
            merkle_fold_static_cs, &why)) {
        return fail(
            "merkle_fold_static_program:" +
            why);
    }
    if (air_recurse::
            CountWitnessViolationsOnH(
                merkle_fold_static_cs,
                out.merkle_fold.fold_columns) != 0) {
        return fail(
            "merkle_fold_static_witness");
    }
    out.merkle_fold_program_root =
        cb::CommitProgramTableAlgHash(
            merkle_fold_program);
    const cb::ProgramTable
        merkle_fold_program_recomputed =
            BuildMerkleFoldProgramTableV1(
                out.merkle_fold.fold_layout);
    out.merkle_fold_program_constraints =
        static_cast<uint32_t>(
            merkle_fold_program.programs.size());
    out.merkle_fold_constraints_canonical_bytecode =
        out.merkle_fold_program_constraints == 13;
    out.merkle_fold_program_root_recomputed =
        DigestNonzero(
            out.merkle_fold_program_root) &&
        merkle_fold_program_recomputed ==
            merkle_fold_program &&
        cb::CommitProgramTableAlgHash(
            merkle_fold_program_recomputed) ==
            out.merkle_fold_program_root;
    out.merkle_fold_statement_manifest_r0_columns =
        static_cast<uint32_t>(
            merkle_fold_static_cs.preprocessed.size());
    out.merkle_fold_proof_tape_cells =
        out.merkle_fold.fold_layout.n_columns;
    out.merkle_fold_proof_tape_cells_ordinary =
        merkle_fold_static_cs.preprocessed.empty() &&
        out.merkle_fold_proof_tape_cells == 16;
    out.merkle_fold_proof_tape_fixed_offsets =
        out.merkle_fold.fold_layout.even == 0 &&
        out.merkle_fold.fold_layout.terminal + 1 ==
            out.merkle_fold.fold_layout.n_columns;
    out.merkle_fold_equations_bound =
        out.merkle_fold_constraints_canonical_bytecode &&
        out.merkle_fold_program_root_recomputed;
    out.merkle_fold_r0_statement_manifest_only =
        out.merkle_fold_statement_manifest_r0_columns == 0 &&
        out.merkle_fold_proof_tape_cells_ordinary &&
        out.merkle_fold_proof_tape_fixed_offsets &&
        out.merkle_fold_equations_bound;
    out.merkle_fold_cs_independent_of_child_witness =
        out.merkle_fold_r0_statement_manifest_only;
    out.merkle_fold_transcript_and_opening_carry_complete =
        false;

    const cb::ProgramTable deep_vm_program =
        BuildDeepVmProgramTableV1(
            out.deep_vm.layout);
    aq::AirConstraintSystem<Fp3>
        deep_vm_static_cs;
    std::vector<std::vector<Fp3>>
        deep_vm_static_columns;
    std::vector<uint32_t>
        deep_vm_statement_manifest_columns;
    const std::vector<Fp3>
        deep_vm_register_challenge =
            DeriveDeepVmRegisterChallengesV1(
                out.deep_vm
                    .preprocessed_row_group_root,
                input.expected_child_program_root,
                range);
    if (deep_vm_program.programs.size() !=
            kDeepVmCanonicalConstraintsV1 ||
        deep_vm_program.current_width !=
            out.deep_vm.layout.n_columns +
                kDeepVmExtensionColumnsV1 ||
        !BuildDeepVmStaticPhaseV1(
            out.deep_vm,
            input.child_program,
            input.expected_child_program_root,
            range,
            deep_vm_register_challenge,
            deep_vm_static_cs,
            deep_vm_static_columns,
            deep_vm_statement_manifest_columns,
            &why)) {
        return fail(
            "deep_vm_static_program:" +
            why);
    }
    if (air_recurse::
            CountWitnessViolationsOnH(
                deep_vm_static_cs,
                deep_vm_static_columns) != 0) {
        return fail(
            "deep_vm_static_witness");
    }
    out.deep_vm_program_root =
        cb::CommitProgramTableAlgHash(
            deep_vm_program);
    const cb::ProgramTable
        deep_vm_program_recomputed =
            BuildDeepVmProgramTableV1(
                out.deep_vm.layout);
    out.deep_vm_program_constraints =
        static_cast<uint32_t>(
            deep_vm_program.programs.size());
    out.deep_vm_constraints_canonical_bytecode =
        out.deep_vm_program_constraints ==
            kDeepVmCanonicalConstraintsV1;
    out.deep_vm_program_root_recomputed =
        DigestNonzero(
            out.deep_vm_program_root) &&
        deep_vm_program_recomputed ==
            deep_vm_program &&
        cb::CommitProgramTableAlgHash(
            deep_vm_program_recomputed) ==
            out.deep_vm_program_root;
    out.deep_vm_statement_manifest_r0_columns =
        static_cast<uint32_t>(
            deep_vm_statement_manifest_columns.size());
    out.deep_vm_proof_tape_cells =
        deep_vm_program.current_width -
            out.deep_vm_statement_manifest_r0_columns;
    out.deep_vm_proof_tape_cells_ordinary =
        out.deep_vm_statement_manifest_r0_columns ==
            kDeepVmStatementScheduleColumnsV1 &&
        out.deep_vm_proof_tape_cells ==
            out.deep_vm.layout.n_columns +
                kDeepVmExtensionColumnsV1 -
                kDeepVmStatementScheduleColumnsV1;
    out.deep_vm_proof_tape_fixed_offsets =
        out.deep_vm.layout.active == 0 &&
        out.deep_vm.layout
                .quotient_tape_accept +
                1 ==
            out.deep_vm.layout.n_columns &&
        DeepVmSsaLayout(
            out.deep_vm.layout).n_columns ==
            deep_vm_program.current_width;
    out.deep_vm_schedule_independently_regenerated =
        out.deep_vm_statement_manifest_r0_columns ==
            kDeepVmStatementScheduleColumnsV1;
    out.deep_vm_program_and_range_bound =
        SameDigest(
            cb::CommitProgramTableAlgHash(
                input.child_program),
            input.expected_child_program_root) &&
        SameDigest(
            out.deep_vm.program_root,
            input.expected_child_program_root) &&
        out.deep_vm.first_query ==
            range.first_query &&
        out.deep_vm.query_count ==
            range.query_count;
    out.deep_vm_program_constants_owned =
        out.deep_vm_schedule_independently_regenerated &&
        out.deep_vm_constraints_canonical_bytecode;
    out.deep_vm_internal_ssa_copy_provenance =
        out.deep_vm_program_constants_owned &&
        deep_vm_program.challenge_width ==
            kDeepVmChallengeColumnsV1 &&
        deep_vm_program.current_width ==
            out.deep_vm.layout.n_columns +
                kDeepVmExtensionColumnsV1;
    out.deep_vm_register_precommit_root =
        out.deep_vm.preprocessed_row_group_root;
    out.deep_vm_register_challenge_carry_complete =
        false;
    out.deep_vm_r0_statement_manifest_only =
        out.deep_vm_proof_tape_cells_ordinary &&
        out.deep_vm_proof_tape_fixed_offsets &&
        out.deep_vm_schedule_independently_regenerated &&
        out.deep_vm_program_root_recomputed &&
        out.deep_vm_program_and_range_bound;
    out.deep_vm_cs_independent_of_child_witness =
        out.deep_vm_constraints_canonical_bytecode &&
        out.deep_vm_r0_statement_manifest_only &&
        out.deep_vm_program_constants_owned &&
        out.deep_vm_internal_ssa_copy_provenance;
    out.deep_vm_value_and_source_carry_complete =
        false;

    const cb::ProgramTable decoder_program =
        BuildDecoderProgramTableV1(
            out.decoder.layout);
    aq::AirConstraintSystem<Fp3>
        decoder_static_cs;
    std::vector<std::vector<Fp3>>
        decoder_static_columns;
    std::vector<uint32_t>
        decoder_statement_manifest_columns;
    if (decoder_program.programs.size() != 30 ||
        decoder_program.current_width !=
            out.decoder.layout.n_columns +
                kDecoderHornerAuxColumnsV1 ||
        !BuildDecoderStaticPhaseV1(
            out.decoder,
            decoder_static_cs,
            decoder_static_columns,
            decoder_statement_manifest_columns,
            &why)) {
        return fail(
            "decoder_static_program:" +
            why);
    }
    if (air_recurse::
            CountWitnessViolationsOnH(
                decoder_static_cs,
                decoder_static_columns) != 0) {
        return fail(
            "decoder_static_witness");
    }
    out.decoder_program_root =
        cb::CommitProgramTableAlgHash(
            decoder_program);
    const cb::ProgramTable
        decoder_program_recomputed =
            BuildDecoderProgramTableV1(
                out.decoder.layout);
    out.decoder_program_constraints =
        static_cast<uint32_t>(
            decoder_program.programs.size());
    out.decoder_constraints_canonical_bytecode =
        out.decoder_program_constraints == 30;
    out.decoder_program_root_recomputed =
        DigestNonzero(
            out.decoder_program_root) &&
        decoder_program_recomputed ==
            decoder_program &&
        cb::CommitProgramTableAlgHash(
            decoder_program_recomputed) ==
            out.decoder_program_root;
    out.decoder_statement_manifest_r0_columns =
        static_cast<uint32_t>(
            decoder_statement_manifest_columns.size());
    out.decoder_proof_tape_cells =
        decoder_program.current_width -
            out.decoder_statement_manifest_r0_columns;
    out.decoder_proof_tape_cells_ordinary =
        out.decoder_statement_manifest_r0_columns == 11 &&
        out.decoder_proof_tape_cells ==
            out.decoder.layout.n_columns +
                kDecoderHornerAuxColumnsV1 -
                11;
    out.decoder_proof_tape_fixed_offsets =
        out.decoder.layout.active == 0 &&
        out.decoder.layout.root_value + 1 ==
            out.decoder.layout.n_columns &&
        decoder_program.current_width ==
            out.decoder.layout.n_columns +
                kDecoderHornerAuxColumnsV1;
    out.decoder_degree_reduced_horner_chain =
        out.decoder_constraints_canonical_bytecode &&
        MaxDegree(decoder_static_cs) <= 2;
    out.decoder_challenge_columns_post_commit =
        decoder_program.challenge_width ==
            kDecoderChallengeColumnsV1;
    out.decoder_program_challenge_independent =
        cb::ProgramTableIsChallengeIndependent(
            decoder_program);
    out.decoder_r0_statement_manifest_only =
        out.decoder_proof_tape_cells_ordinary &&
        out.decoder_proof_tape_fixed_offsets &&
        out.decoder_degree_reduced_horner_chain &&
        out.decoder_program_root_recomputed;
    // The static relation no longer captures proof values or challenges in
    // program/R0 bytes. Ownership still needs two separate same-proof links:
    // transcript -> (gamma,alpha), and child receipts -> root_value.
    out.decoder_challenge_carry_complete =
        false;
    out.decoder_child_root_carry_complete =
        false;
    out.decoder_cs_independent_of_child_witness =
        false;

    const std::array<PhaseViewV1, kPhasesV1>
        views{{
            {PhaseV1::ParentJoin,
             &parent_join_static_cs,
             &out.parent_join.columns},
            {PhaseV1::MerkleHash,
             &merkle_hash_static_cs,
             &out.merkle_fold.hash_columns},
            {PhaseV1::MerkleFold,
             &merkle_fold_static_cs,
             &out.merkle_fold.fold_columns},
            {PhaseV1::DeepVm,
             &deep_vm_static_cs,
             &deep_vm_static_columns},
            {PhaseV1::Decoder,
             &decoder_static_cs,
             &decoder_static_columns},
        }};
    for (const auto& view : views) {
        if (!ShapeExact(view)) {
            return fail("phase_shape");
        }
    }

    uint64_t active_rows = 0;
    uint32_t max_width = 0;
    uint64_t expected_pins = 0;
    for (uint32_t index = 0;
         index < views.size();
         ++index) {
        const auto& view = views[index];
        auto& shape = out.phases[index];
        shape.phase = view.phase;
        shape.first_row =
            static_cast<uint32_t>(
                active_rows);
        shape.rows = view.cs->n_rows;
        shape.columns =
            view.cs->n_columns;
        shape.constraints =
            static_cast<uint32_t>(
                view.cs->constraints.size());
        shape.preprocessed_columns =
            static_cast<uint32_t>(
                view.cs->preprocessed.size());
        shape.max_degree =
            MaxDegree(*view.cs);
        active_rows += view.cs->n_rows;
        max_width =
            std::max(
                max_width,
                view.cs->n_columns);
        expected_pins +=
            view.cs->preprocessed.size();
    }
    if (active_rows >
            std::numeric_limits<uint32_t>::max() ||
        expected_pins >
            std::numeric_limits<uint32_t>::max()) {
        return fail("inventory_overflow");
    }
    out.active_rows =
        static_cast<uint32_t>(
            active_rows);
    out.trace_rows =
        NextPowerOfTwo(active_rows);
    out.trace_cap_fits =
        out.trace_rows != 0 &&
        out.trace_rows <=
            kTraceRowsCapV1;
    out.lde_cap_fits =
        out.trace_rows != 0 &&
        uint64_t{out.trace_rows} *
                kRCFriBlowup <=
            kLdeRowsCapV1;
    if (!out.trace_cap_fits ||
        !out.lde_cap_fits) {
        return fail("row_cap");
    }

    out.expected_preprocessed_columns =
        static_cast<uint32_t>(
            expected_pins);
    out.layout.data_columns = max_width;
    uint32_t cursor = max_width;
    out.layout.phase_tag_base = cursor;
    cursor += kPhasesV1;
    out.layout.phase_first_base = cursor;
    cursor += kPhasesV1;
    out.layout.phase_last_base = cursor;
    cursor += kPhasesV1;
    out.layout.phase_transition_base = cursor;
    cursor += kPhasesV1;
    out.layout.active = cursor++;
    out.layout.acceptance = cursor++;
    out.layout.expected_preprocessed_base =
        cursor;
    cursor +=
        out.expected_preprocessed_columns;
    out.layout.n_columns = cursor;
    out.trace_columns = cursor;
    out.materialized_trace_cells =
        uint64_t{out.trace_rows} *
        out.trace_columns;
    out.columns.assign(
        out.trace_columns,
        std::vector<Fp3>(
            out.trace_rows,
            Fp3::Zero()));
    out.cs.n_rows = out.trace_rows;
    out.cs.n_columns =
        out.trace_columns;
    out.cs.preprocessed_pin_ood = true;

    std::vector<Fp3> active_schedule(
        out.trace_rows, Fp3::Zero());
    for (uint32_t row = 0;
         row < out.active_rows;
         ++row) {
        active_schedule[row] = Fp3::One();
        out.columns[out.layout.active][row] =
            Fp3::One();
    }
    out.columns[out.layout.acceptance][0] =
        Fp3::One();
    out.cs.preprocessed.emplace_back(
        out.layout.active,
        active_schedule);

    uint32_t expected_cursor =
        out.layout.expected_preprocessed_base;
    for (uint32_t index = 0;
         index < views.size();
         ++index) {
        const auto& view = views[index];
        const auto& shape = out.phases[index];
        const uint32_t first = shape.first_row;
        const uint32_t last =
            first + shape.rows - 1;
        for (uint32_t column = 0;
             column < view.cs->n_columns;
             ++column) {
            std::copy(
                (*view.columns)[column].begin(),
                (*view.columns)[column].end(),
                out.columns[column].begin() +
                    first);
        }

        std::vector<Fp3> tag(
            out.trace_rows, Fp3::Zero());
        std::vector<Fp3> first_tag(
            out.trace_rows, Fp3::Zero());
        std::vector<Fp3> last_tag(
            out.trace_rows, Fp3::Zero());
        std::vector<Fp3> transition_tag(
            out.trace_rows, Fp3::Zero());
        for (uint32_t row = first;
             row <= last;
             ++row) {
            tag[row] = Fp3::One();
            if (row < last) {
                transition_tag[row] =
                    Fp3::One();
            }
        }
        first_tag[first] = Fp3::One();
        last_tag[last] = Fp3::One();
        for (const auto& [column, canonical] :
             view.cs->preprocessed) {
            const uint32_t expected =
                expected_cursor++;
            std::copy(
                canonical.begin(),
                canonical.end(),
                out.columns[expected].begin() +
                    first);
            out.cs.preprocessed.emplace_back(
                expected,
                out.columns[expected]);
            AddConstraint(
                out.cs,
                "stage3.v11_unified."
                "phase_preprocessed_equality",
                aq::AirKind::kEverywhere, 2,
                [phase_tag =
                     out.layout.PhaseTag(
                         view.phase),
                 column, expected](
                    const auto& cur,
                    const auto&) {
                    return gf::Mul(
                        cur[phase_tag],
                        gf::Sub(
                            cur[column],
                            cur[expected]));
                });
        }
        for (const auto& constraint :
             view.cs->constraints) {
            AddGatedPhaseConstraint(
                out.layout, view.phase,
                constraint, out.cs);
        }
        const std::array<
            std::pair<uint32_t,
                      std::vector<Fp3>>, 4>
            schedule{{
                {out.layout.PhaseTag(
                     view.phase),
                 std::move(tag)},
                {out.layout.PhaseFirst(
                     view.phase),
                 std::move(first_tag)},
                {out.layout.PhaseLast(
                     view.phase),
                 std::move(last_tag)},
                {out.layout.PhaseTransition(
                     view.phase),
                 std::move(transition_tag)},
            }};
        for (const auto& [column, values] :
             schedule) {
            out.columns[column] = values;
            out.cs.preprocessed.emplace_back(
                column, values);
        }
    }
    if (expected_cursor !=
        out.layout.n_columns) {
        return fail("expected_pin_inventory");
    }
    std::string scheduler_why;
    if (!AddSchedulerConstraints(
            out.layout, out.cs,
            out.acceptance_program_root,
            out.scheduler_program_root,
            &scheduler_why)) {
        return fail(
            "acceptance_bytecode:" +
            scheduler_why);
    }
    out.acceptance_program_constraints = 2;
    out.acceptance_constraints_canonical_bytecode =
        true;
    out.acceptance_program_root_recomputed =
        DigestNonzero(
            out.acceptance_program_root);
    out.scheduler_program_constraints =
        2 + 4 * kPhasesV1;
    out.scheduler_constraints_canonical_bytecode =
        true;
    out.scheduler_program_root_recomputed =
        DigestNonzero(
            out.scheduler_program_root);

    out.preprocessed_columns =
        PreprocessedColumns(out.cs);
    out.constraints =
        static_cast<uint32_t>(
            out.cs.constraints.size());
    out.max_constraint_degree =
        MaxDegree(out.cs);
    out.quotient_len =
        out.cs.QuotientLen();
    const uint32_t commitment_coeffs =
        NextPowerOfTwo(std::max(
            out.trace_rows,
            out.quotient_len));
    out.commitment_coefficients =
        commitment_coeffs;
    out.commitment_lde_rows =
        uint64_t{commitment_coeffs} *
        kRCFriBlowup;
    out.quotient_cap_audit_complete =
        commitment_coeffs != 0;
    out.phase_constraint_systems_canonical_bytecode =
        (out.parent_join_constraints_canonical_bytecode
            ? 1U : 0U) +
        (out.merkle_hash_constraints_canonical_bytecode
            ? 1U : 0U) +
        (out.merkle_fold_constraints_canonical_bytecode
            ? 1U : 0U) +
        (out.deep_vm_constraints_canonical_bytecode
            ? 1U : 0U) +
        (out.decoder_constraints_canonical_bytecode
            ? 1U : 0U);
    out.phase_r0_tables_statement_manifest_only =
        (out.parent_join_r0_statement_manifest_only
            ? 1U : 0U) +
        (out.merkle_hash_r0_statement_manifest_only
            ? 1U : 0U) +
        (out.merkle_fold_r0_statement_manifest_only
            ? 1U : 0U) +
        (out.deep_vm_r0_statement_manifest_only
            ? 1U : 0U) +
        (out.decoder_r0_statement_manifest_only
            ? 1U : 0U);
    out.cs_independent_of_child_witness =
        out.phase_constraint_systems_canonical_bytecode ==
            kPhasesV1 &&
        out.phase_r0_tables_statement_manifest_only ==
            kPhasesV1 &&
        out.parent_join_cs_independent_of_child_witness &&
        out.merkle_hash_cs_independent_of_child_witness &&
        out.merkle_fold_cs_independent_of_child_witness &&
        out.deep_vm_cs_independent_of_child_witness &&
        out.decoder_cs_independent_of_child_witness;
    out.verifier_input_excludes_child_proof =
        false;
    out.lde_cap_fits =
        commitment_coeffs != 0 &&
        out.commitment_lde_rows <=
            kLdeRowsCapV1;
    if (!out.lde_cap_fits) {
        return fail(
            "quotient_lde_cap;rows=" +
            std::to_string(out.trace_rows) +
            ";cols=" +
            std::to_string(out.trace_columns) +
            ";degree=" +
            std::to_string(
                out.max_constraint_degree) +
            ";quotient=" +
            std::to_string(out.quotient_len));
    }
    const auto session =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            out.cs, out.columns,
            out.preprocessed_columns);
    if (!session.valid ||
        session.base_row_commitment.IsNull()) {
        return fail(
            "r0_root:" + session.note);
    }
    out.preprocessed_row_group_root =
        session.base_row_commitment;
    out.cs.preprocessed_row_group_roots.push_back({
        .version = 1,
        .role =
            aq::AirPreprocessedRowGroupRole::kR0,
        .ordered_columns =
            out.preprocessed_columns,
        .root =
            out.preprocessed_row_group_root,
    });
    out.violations =
        air_recurse::
            CountWitnessViolationsOnH(
                out.cs, out.columns);
    out.all_five_phases_executable =
        out.parent_join.valid &&
        out.merkle_fold.valid &&
        out.deep_vm.valid &&
        out.decoder.valid;
    out.vertical_max_width_layout =
        out.layout.data_columns ==
            std::max({
                out.parent_join.cs.n_columns,
                out.merkle_fold.hash_cs.n_columns,
                out.merkle_fold.fold_cs.n_columns,
                deep_vm_static_cs.n_columns,
                decoder_static_cs.n_columns});
    out.one_hot_row_scheduler_constrained =
        true;
    out.local_boundary_kinds_preserved =
        true;
    out.every_phase_preprocessed_pin_r0_bound =
        expected_cursor -
            out.layout
                .expected_preprocessed_base ==
            out.expected_preprocessed_columns &&
        !out.preprocessed_row_group_root.IsNull();
    out.acceptance_ordinary_witness =
        std::find(
            out.preprocessed_columns.begin(),
            out.preprocessed_columns.end(),
            out.layout.acceptance) ==
        out.preprocessed_columns.end();
    out.acceptance_unique =
        std::count_if(
            out.columns[
                out.layout.acceptance].begin(),
            out.columns[
                out.layout.acceptance].end(),
            [](const Fp3& value) {
                return gf::Eq(
                    value, Fp3::One());
            }) == 1 &&
        gf::Eq(
            out.columns[
                out.layout.acceptance][0],
            Fp3::One());
    out.whole_verifier_acceptance_constrained =
        out.acceptance_ordinary_witness &&
        out.acceptance_unique;
    out.direct_cross_phase_cell_carries_complete =
        false;
    out.recursive_authority_ready = false;
    out.valid_foundation =
        out.exact_q96_range &&
        out.all_five_phases_executable &&
        out.vertical_max_width_layout &&
        out.one_hot_row_scheduler_constrained &&
        out.local_boundary_kinds_preserved &&
        out.every_phase_preprocessed_pin_r0_bound &&
        out.acceptance_ordinary_witness &&
        out.acceptance_unique &&
        out.whole_verifier_acceptance_constrained &&
        out.acceptance_constraints_canonical_bytecode &&
        out.acceptance_program_root_recomputed &&
        out.scheduler_constraints_canonical_bytecode &&
        out.scheduler_program_root_recomputed &&
        out.trace_cap_fits &&
        out.lde_cap_fits &&
        out.violations == 0 &&
        out.cs_independent_of_child_witness &&
        out.verifier_input_excludes_child_proof &&
        out.direct_cross_phase_cell_carries_complete &&
        !out.recursive_authority_ready;
    out.note = out.valid_foundation
        ? "stage3:v11_unified_verifier:"
          "five_phase_vertical_split_rap;"
          "acceptance_static_bytecode;"
          "scheduler_static_bytecode;"
          "direct_cross_phase_carries_closed"
        : "stage3:v11_unified_verifier:"
          "constraint_failure";
    return out;
}

uint64_t RecountViolationsV1(
    const ProductV1& product,
    const std::vector<std::vector<Fp3>>& columns)
{
    if (columns.size() !=
        product.cs.n_columns) {
        return
            std::numeric_limits<
                uint64_t>::max();
    }
    for (const auto& column : columns) {
        if (column.size() !=
            product.cs.n_rows) {
            return
                std::numeric_limits<
                    uint64_t>::max();
        }
    }
    return
        air_recurse::
            CountWitnessViolationsOnH(
                product.cs, columns);
}

ProveResultV1 ProveV1(
    const rv::InputV1& input,
    const rv::QueryRangeV1& range,
    const uint256& public_fs_seed)
{
    ProveResultV1 out;
    const auto product =
        BuildProductV1(input, range);
    out.preprocessed_row_group_root =
        product.preprocessed_row_group_root;
    if (!product.valid_foundation ||
        public_fs_seed.IsNull()) {
        out.note =
            "stage3:v11_unified_verifier:"
            "prove:" + product.note;
        return out;
    }
    const auto begin =
        std::chrono::steady_clock::now();
    const auto proved =
        aq::AirQuotientProveRowsSplitRap(
            product.cs, product.columns,
            product.preprocessed_columns,
            public_fs_seed);
    out.prove_micros =
        std::chrono::duration_cast<
            std::chrono::microseconds>(
            std::chrono::steady_clock::now() -
            begin).count();
    if (!proved.ok ||
        !proved.division_exact ||
        proved.proof.batch.groups.empty() ||
        Fri3AlgDigestToUint256(
            proved.proof.batch.groups[0]
                .row_commit.root) !=
            product.preprocessed_row_group_root) {
        out.note =
            "stage3:v11_unified_verifier:"
            "prove:" + proved.note;
        return out;
    }
    std::vector<unsigned char> wire;
    const size_t bytes =
        aq::SerializeAirQuotientSplitRapRowsProof(
            proved.proof, wire);
    if (bytes == 0 || bytes != wire.size()) {
        out.note =
            "stage3:v11_unified_verifier:"
            "prove:serialize";
        return out;
    }
    out.proof = proved.proof;
    out.proof_wire_bytes = bytes;
    out.ok = true;
    out.note =
        "stage3:v11_unified_verifier:"
        "prove:five_phase;"
        "carry_residual_open";
    return out;
}

VerifyResultV1 VerifyV1(
    const rv::InputV1& input,
    const rv::QueryRangeV1& range,
    const aq::AirQuotientSplitRapRowsProof& proof,
    const uint256& public_fs_seed)
{
    VerifyResultV1 out;
    const auto product =
        BuildProductV1(input, range);
    if (!product.valid_foundation ||
        public_fs_seed.IsNull()) {
        out.note =
            "stage3:v11_unified_verifier:"
            "verify:" + product.note;
        return out;
    }
    const auto begin =
        std::chrono::steady_clock::now();
    std::string why;
    out.accepted =
        aq::AirQuotientVerifyRowsSplitRap(
            product.cs, proof,
            product.preprocessed_columns,
            public_fs_seed, &why);
    out.verify_micros =
        std::chrono::duration_cast<
            std::chrono::microseconds>(
            std::chrono::steady_clock::now() -
            begin).count();
    if (proof.batch.groups.empty() ||
        Fri3AlgDigestToUint256(
            proof.batch.groups[0]
                .row_commit.root) !=
            product.preprocessed_row_group_root) {
        out.accepted = false;
        why = "r0_root";
    }
    out.direct_cross_phase_cell_carries_complete =
        product
            .direct_cross_phase_cell_carries_complete;
    out.recursive_authority_ready = false;
    out.note = out.accepted
        ? "stage3:v11_unified_verifier:"
          "verify:five_phase;"
          "carry_residual_open"
        : "stage3:v11_unified_verifier:"
          "verify:" + why;
    return out;
}

} // namespace matmul::v4::rc::stage3_multirow_v11_unified_verifier_air
