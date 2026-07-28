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
             &out.deep_vm.cs,
             &out.deep_vm.columns},
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
        (out.decoder_constraints_canonical_bytecode
            ? 1U : 0U);
    out.phase_r0_tables_statement_manifest_only =
        (out.parent_join_r0_statement_manifest_only
            ? 1U : 0U) +
        (out.merkle_hash_r0_statement_manifest_only
            ? 1U : 0U) +
        (out.merkle_fold_r0_statement_manifest_only
            ? 1U : 0U) +
        (out.decoder_r0_statement_manifest_only
            ? 1U : 0U);
    out.cs_independent_of_child_witness =
        out.phase_constraint_systems_canonical_bytecode ==
            kPhasesV1 &&
        out.phase_r0_tables_statement_manifest_only ==
            kPhasesV1;
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
                out.deep_vm.cs.n_columns,
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
