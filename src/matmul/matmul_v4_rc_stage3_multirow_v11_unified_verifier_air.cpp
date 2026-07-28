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

uint32_t Uint256WordV1(
    const uint256& root, uint32_t word)
{
    const uint64_t limb =
        root.GetUint64(word / 2);
    return word % 2 == 0
        ? static_cast<uint32_t>(limb)
        : static_cast<uint32_t>(limb >> 32);
}

std::array<uint256, kPhasesV1>
PhasePrecommitRootsV1(const ProductV1& product)
{
    std::array<uint256, kPhasesV1> roots{};
    roots[static_cast<uint32_t>(
        PhaseV1::ParentJoin)] =
        product.parent_join_statement_manifest_r0_root;
    roots[static_cast<uint32_t>(
        PhaseV1::DeepVm)] =
        product.deep_vm_register_precommit_root;
    roots[static_cast<uint32_t>(
        PhaseV1::Decoder)] =
        product.decoder.join_tuple_precommit_root;
    for (const auto& pin :
         product.decoder.child_roots) {
        if (pin.index != 0) continue;
        if (pin.kind == 2) {
            roots[static_cast<uint32_t>(
                PhaseV1::MerkleHash)] =
                pin.root;
        } else if (pin.kind == 3) {
            roots[static_cast<uint32_t>(
                PhaseV1::MerkleFold)] =
                pin.root;
        }
    }
    return roots;
}

bool VerifyPhasePrecommitRootOpeningsInternalV1(
    const NormalizedOpeningReceiptV1& receipt,
    std::string* why)
{
    const auto fail = [why](const char* detail) {
        if (why != nullptr) {
            *why =
                std::string{
                    "stage3:v11_unified_opening_receipt:"
                    "phase_root:"} +
                detail;
        }
        return false;
    };
    if (receipt.phase_precommit_root_words !=
            kPhasePrecommitRootWordsV1 ||
        receipt.phase_precommit_root_column_base >
            std::numeric_limits<uint32_t>::max() -
                kPhasePrecommitRootColumnsV1 ||
        receipt.trace_openings.groups[0].role !=
            Fri3AlgMultiRowGroupRole::MainTrace ||
        receipt.trace_openings.groups[0].rows.empty()) {
        return fail("shape");
    }
    const auto& base =
        receipt.trace_openings.base_column_indices;
    const auto& group =
        receipt.trace_openings.groups[0];
    if (base.size() != group.column_count) {
        return fail("base_columns");
    }
    for (uint32_t phase = 0;
         phase < kPhasesV1; ++phase) {
        const auto& root =
            receipt.phase_precommit_root[phase];
        if (root.IsNull()) {
            return fail("null");
        }
        for (uint32_t word = 0;
             word < kPhasePrecommitRootWordsV1;
             ++word) {
            const uint32_t global_column =
                receipt.phase_precommit_root_column_base +
                phase * kPhasePrecommitRootWordsV1 +
                word;
            const auto position =
                std::find(
                    base.begin(), base.end(),
                    global_column);
            if (position == base.end()) {
                return fail("column_omitted");
            }
            const size_t local =
                static_cast<size_t>(
                    position - base.begin());
            const Fp3 expected =
                Fp3::FromFp(
                    Uint256WordV1(root, word));
            for (const auto& row : group.rows) {
                if (local >= row.values.size() ||
                    local >= row.next_values.size() ||
                    !gf::Eq(
                        row.values[local],
                        expected) ||
                    !gf::Eq(
                        row.next_values[local],
                        expected)) {
                    return fail("cell_mismatch");
                }
            }
        }
    }
    return true;
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
    const std::array<
        Fp3,
        kDecoderChallengeColumnsV1>& rooted_challenge,
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
    const std::vector<Fp3> challenge{
        rooted_challenge.begin(),
        rooted_challenge.end()};
    if (std::any_of(
            challenge.begin(),
            challenge.end(),
            [](const Fp3& value) {
                return gf::IsZero(value);
            }) ||
        gf::Eq(challenge[0], challenge[1]) ||
        gf::Eq(challenge[2], challenge[3])) {
        if (why != nullptr) {
            *why =
                "decoder_rooted_challenge";
        }
        return false;
    }
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
            challenge[lane];
        const Fp3 alpha =
            challenge[2 + lane];
        std::fill(
            columns[
                decoder.layout
                    .source_inverse[lane]].begin(),
            columns[
                decoder.layout
                    .source_inverse[lane]].end(),
            Fp3::Zero());
        std::fill(
            columns[
                decoder.layout
                    .consumer_inverse[lane]].begin(),
            columns[
                decoder.layout
                    .consumer_inverse[lane]].end(),
            Fp3::Zero());
        std::fill(
            columns[
                decoder.layout.running[lane]].begin(),
            columns[
                decoder.layout.running[lane]].end(),
            Fp3::Zero());
        Fp3 running = Fp3::Zero();
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
                if (row < decoder.real_rows) {
                    columns[
                        side == 0
                        ? decoder.layout
                            .source_inverse[lane]
                        : decoder.layout
                            .consumer_inverse[lane]][row] =
                        gf::Inv(term);
                }
            }
        }
        for (uint32_t row = 0;
             row < decoder.cs.n_rows;
             ++row) {
            columns[
                decoder.layout.running[lane]][row] =
                running;
            if (row < decoder.real_rows) {
                running = gf::Add(
                    running,
                    gf::Sub(
                        columns[
                            decoder.layout
                                .source_inverse[lane]][row],
                        columns[
                            decoder.layout
                                .consumer_inverse[lane]][row]));
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

struct DeepVmPublicScheduleV1 {
    uint32_t real_rows{0};
    uint32_t trace_rows{0};
    std::vector<uint32_t> ordered_columns;
    std::vector<std::pair<uint32_t, std::vector<Fp3>>>
        columns;
    uint256 root{};
};

bool BuildDeepVmPublicScheduleV1(
    const dvm::LayoutV1& l,
    const cb::ProgramTable& child_program,
    const rv::QueryRangeV1& range,
    uint32_t phase_columns,
    DeepVmPublicScheduleV1& out,
    std::string* why)
{
    out = {};
    if (!cb::ValidateProgramTable(
            child_program, why) ||
        child_program.challenge_width != 0 ||
        range.query_count == 0 ||
        range.first_query >
            abi::kQueryCountV11 ||
        range.query_count >
            abi::kQueryCountV11 -
                range.first_query ||
        child_program.current_width ==
            std::numeric_limits<uint32_t>::max()) {
        if (why != nullptr && why->empty()) {
            *why =
                "deep_vm_public_schedule_input";
        }
        return false;
    }

    uint64_t vm_rows64 = 0;
    std::vector<std::vector<uint32_t>>
        register_use;
    register_use.reserve(
        child_program.programs.size());
    for (const auto& program :
         child_program.programs) {
        if (program.instructions.empty() ||
            vm_rows64 >
                std::numeric_limits<uint32_t>::max() -
                    program.instructions.size()) {
            if (why != nullptr) {
                *why =
                    "deep_vm_public_schedule_vm_rows";
            }
            return false;
        }
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
            if (instruction.opcode ==
                    cb::Opcode::Challenge) {
                if (why != nullptr) {
                    *why =
                        "deep_vm_public_schedule_"
                        "challenge_opcode";
                }
                return false;
            }
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
                        "deep_vm_public_schedule_"
                        "ssa_inventory";
                }
                return false;
            }
            ++multiplicity[
                instruction.lhs];
            ++multiplicity[
                instruction.rhs];
        }
    }
    const uint64_t deep_terms_per_query =
        uint64_t{child_program.current_width} + 1;
    const uint64_t rows_per_query =
        deep_terms_per_query + 1 +
        vm_rows64 + 1;
    const uint64_t real_rows64 =
        rows_per_query * range.query_count;
    if (vm_rows64 == 0 ||
        rows_per_query >
            std::numeric_limits<uint32_t>::max() ||
        real_rows64 >
            std::numeric_limits<uint32_t>::max()) {
        if (why != nullptr) {
            *why =
                "deep_vm_public_schedule_shape";
        }
        return false;
    }
    out.real_rows =
        static_cast<uint32_t>(real_rows64);
    out.trace_rows =
        NextPowerOfTwo(real_rows64);
    if (out.trace_rows == 0 ||
        out.trace_rows >
            kTraceRowsCapV1) {
        if (why != nullptr) {
            *why =
                "deep_vm_public_schedule_trace_rows";
        }
        return false;
    }

    const auto ssa = DeepVmSsaLayout(l);
    const auto add_manifest =
        [&out](uint32_t column) {
            out.columns.emplace_back(
                column,
                std::vector<Fp3>(
                    out.trace_rows,
                    Fp3::Zero()));
            return out.columns.size() - 1;
        };
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
    if (out.columns.size() !=
            kDeepVmStatementScheduleColumnsV1) {
        if (why != nullptr) {
            *why =
                "deep_vm_public_schedule_column_count";
        }
        return false;
    }

    uint32_t row = 0;
    for (uint32_t query_offset = 0;
         query_offset < range.query_count;
         ++query_offset) {
        const uint32_t query =
            range.first_query + query_offset;
        for (uint32_t column = 0;
             column < deep_terms_per_query;
             ++column, ++row) {
            out.columns[active].second[row] =
                Fp3::One();
            out.columns[deep_term].second[row] =
                Fp3::One();
            out.columns[query_index].second[row] =
                gf::FromU64_3(query);
            out.columns[item].second[row] =
                gf::FromU64_3(column);
            out.columns[deep_start].second[row] =
                column == 0
                ? Fp3::One()
                : Fp3::Zero();
            out.columns[deep_chain].second[row] =
                Fp3::One();
            out.columns[quotient_consumer]
                .second[row] =
                column + 1 ==
                    deep_terms_per_query
                ? Fp3::One()
                : Fp3::Zero();
        }
        out.columns[active].second[row] =
            Fp3::One();
        out.columns[deep_finalize].second[row] =
            Fp3::One();
        out.columns[query_index].second[row] =
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
                uint32_t op_index = 0;
                switch (instruction.opcode) {
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
                            "deep_vm_public_schedule_"
                            "challenge_opcode";
                    }
                    return false;
                }
                out.columns[active].second[row] =
                    Fp3::One();
                out.columns[vm_instruction]
                    .second[row] =
                    Fp3::One();
                out.columns[query_index]
                    .second[row] =
                    gf::FromU64_3(query);
                out.columns[item].second[row] =
                    gf::FromU64_3(
                        instruction_index);
                out.columns[program_ordinal]
                    .second[row] =
                    gf::FromU64_3(
                        program_index);
                out.columns[instruction_ordinal]
                    .second[row] =
                    gf::FromU64_3(
                        instruction_index);
                out.columns[lhs_reference]
                    .second[row] =
                    gf::FromU64_3(
                        instruction.lhs);
                out.columns[rhs_reference]
                    .second[row] =
                    gf::FromU64_3(
                        instruction.rhs);
                out.columns[
                    register_use_multiplicity]
                    .second[row] =
                    gf::FromU64_3(
                        register_use[
                            program_index][
                            instruction_index]);
                out.columns[constant_value]
                    .second[row] =
                    instruction.constant;
                out.columns[opcode[op_index]]
                    .second[row] =
                    Fp3::One();
                const bool last_instruction =
                    instruction_index + 1 ==
                        program.instructions.size();
                out.columns[program_end]
                    .second[row] =
                    last_instruction
                    ? Fp3::One()
                    : Fp3::Zero();
                out.columns[vm_start].second[row] =
                    vm_ordinal == 0
                    ? Fp3::One()
                    : Fp3::Zero();
                const bool last_vm =
                    uint64_t{vm_ordinal} + 1 ==
                        vm_rows64;
                out.columns[vm_chain].second[row] =
                    last_vm
                    ? Fp3::Zero()
                    : Fp3::One();
                out.columns[vm_to_quotient]
                    .second[row] =
                    last_vm
                    ? Fp3::One()
                    : Fp3::Zero();
            }
        }
        out.columns[active].second[row] =
            Fp3::One();
        out.columns[quotient_identity]
            .second[row] =
            Fp3::One();
        out.columns[query_index].second[row] =
            gf::FromU64_3(query);
        ++row;
    }
    if (row != out.real_rows) {
        if (why != nullptr) {
            *why =
                "deep_vm_public_schedule_rows";
        }
        return false;
    }

    aq::AirConstraintSystem<Fp3> schedule_cs;
    schedule_cs.n_rows = out.trace_rows;
    schedule_cs.n_columns = phase_columns;
    std::vector<std::vector<Fp3>> schedule_columns(
        phase_columns,
        std::vector<Fp3>(
            out.trace_rows,
            Fp3::Zero()));
    for (const auto& [column, values] :
         out.columns) {
        if (column >= phase_columns ||
            values.size() != out.trace_rows) {
            if (why != nullptr) {
                *why =
                    "deep_vm_public_schedule_column";
            }
            return false;
        }
        out.ordered_columns.push_back(column);
        schedule_columns[column] = values;
        schedule_cs.preprocessed.emplace_back(
            column, values);
    }
    if (!std::is_sorted(
            out.ordered_columns.begin(),
            out.ordered_columns.end()) ||
        std::adjacent_find(
            out.ordered_columns.begin(),
            out.ordered_columns.end()) !=
            out.ordered_columns.end()) {
        if (why != nullptr) {
            *why =
                "deep_vm_public_schedule_order";
        }
        return false;
    }
    schedule_cs.preprocessed_pin_ood = true;
    const auto session =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            schedule_cs,
            schedule_columns,
            out.ordered_columns);
    if (!session.valid ||
        session.base_row_commitment.IsNull()) {
        if (why != nullptr) {
            *why =
                "deep_vm_public_schedule_root:" +
                session.note;
        }
        return false;
    }
    out.root = session.base_row_commitment;
    return true;
}

// Retained only as a differential reference for the former proof-coupled
// construction. Production callers use BuildDeepVmPublicPlanV1 followed by
// MaterializeDeepVmCanonicalPhaseV1.
[[maybe_unused]] bool BuildDeepVmStaticPhaseV1(
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

bool CanonicalFp3V1(const Fp3& value)
{
    return value.c0 < gf::kP &&
        value.c1 < gf::kP &&
        value.c2 < gf::kP;
}

bool FitsU32V1(size_t value)
{
    return value <=
        std::numeric_limits<uint32_t>::max();
}

bool CanonicalFriDigestV1(
    const Fri3AlgDigest& digest)
{
    return std::all_of(
        digest.begin(), digest.end(),
        [](gf::Fp value) {
            return value < gf::kP;
        });
}

bool SameFp3VectorV1(
    const std::vector<Fp3>& left,
    const std::vector<Fp3>& right)
{
    if (left.size() != right.size()) {
        return false;
    }
    for (uint32_t index = 0;
         index < left.size(); ++index) {
        if (!CanonicalFp3V1(left[index]) ||
            !CanonicalFp3V1(right[index]) ||
            !gf::Eq(left[index], right[index])) {
            return false;
        }
    }
    return true;
}

bool SameDigestVectorV1(
    const std::vector<Fri3AlgDigest>& left,
    const std::vector<Fri3AlgDigest>& right)
{
    if (left.size() != right.size()) {
        return false;
    }
    for (uint32_t index = 0;
         index < left.size(); ++index) {
        if (!CanonicalFriDigestV1(left[index]) ||
            !CanonicalFriDigestV1(right[index]) ||
            left[index] != right[index]) {
            return false;
        }
    }
    return true;
}

void AppendU32V1(
    std::vector<gf::Fp>& input,
    uint32_t value)
{
    input.push_back(gf::FromU64(value));
}

void AppendU64SplitV1(
    std::vector<gf::Fp>& input,
    uint64_t value)
{
    AppendU32V1(
        input,
        static_cast<uint32_t>(value));
    AppendU32V1(
        input,
        static_cast<uint32_t>(value >> 32));
}

void AppendUint256U32V1(
    std::vector<gf::Fp>& input,
    const uint256& value)
{
    for (uint32_t word = 0; word < 4;
         ++word) {
        AppendU64SplitV1(
            input, value.GetUint64(word));
    }
}

bool AppendFp3V1(
    std::vector<gf::Fp>& input,
    const Fp3& value)
{
    if (!CanonicalFp3V1(value)) {
        return false;
    }
    input.push_back(value.c0);
    input.push_back(value.c1);
    input.push_back(value.c2);
    return true;
}

bool AppendFriDigestV1(
    std::vector<gf::Fp>& input,
    const Fri3AlgDigest& digest)
{
    if (!CanonicalFriDigestV1(digest)) {
        return false;
    }
    input.insert(
        input.end(),
        digest.begin(), digest.end());
    return true;
}

uint256 CommitTraceOpeningsV1(
    const AuthenticatedTraceOpeningsV1& receipt)
{
    if (!FitsU32V1(
            receipt.base_column_indices.size())) {
        return {};
    }
    std::vector<gf::Fp> input;
    input.reserve(64);
    AppendU32V1(input, 0x55544f31U); // 'UTO1'
    AppendU32V1(input, receipt.version);
    AppendU32V1(input, receipt.trace_rows);
    AppendU32V1(
        input,
        static_cast<uint32_t>(
            receipt.base_column_indices.size()));
    for (uint32_t column :
         receipt.base_column_indices) {
        AppendU32V1(input, column);
    }
    AppendU32V1(
        input,
        static_cast<uint32_t>(
            receipt.groups.size()));
    for (const auto& group : receipt.groups) {
        if (!FitsU32V1(group.rows.size())) {
            return {};
        }
        AppendU32V1(
            input,
            static_cast<uint8_t>(
                group.role));
        AppendU32V1(input, group.first_column);
        AppendU32V1(input, group.column_count);
        AppendU32V1(input, group.n_leaves);
        AppendUint256U32V1(input, group.root);
        AppendU32V1(
            input,
            static_cast<uint32_t>(
                group.rows.size()));
        for (const auto& row : group.rows) {
            if (!FitsU32V1(
                    row.values.size()) ||
                !FitsU32V1(
                    row.siblings.size()) ||
                !FitsU32V1(
                    row.next_values.size()) ||
                !FitsU32V1(
                    row.next_siblings.size())) {
                return {};
            }
            AppendU32V1(
                input, row.query_ordinal);
            AppendU32V1(
                input, row.query_index);
            AppendU32V1(
                input,
                static_cast<uint32_t>(
                    row.values.size()));
            for (const auto& value :
                 row.values) {
                if (!AppendFp3V1(
                        input, value)) {
                    return {};
                }
            }
            AppendU32V1(
                input,
                static_cast<uint32_t>(
                    row.siblings.size()));
            for (const auto& digest :
                 row.siblings) {
                if (!AppendFriDigestV1(
                        input, digest)) {
                    return {};
                }
            }
            AppendU32V1(
                input, row.next_query_index);
            AppendU32V1(
                input,
                static_cast<uint32_t>(
                    row.next_values.size()));
            for (const auto& value :
                 row.next_values) {
                if (!AppendFp3V1(
                        input, value)) {
                    return {};
                }
            }
            AppendU32V1(
                input,
                static_cast<uint32_t>(
                    row.next_siblings.size()));
            for (const auto& digest :
                 row.next_siblings) {
                if (!AppendFriDigestV1(
                        input, digest)) {
                    return {};
                }
            }
        }
    }
    const auto digest =
        alg_hash::SpongeHashFp(input);
    return Fri3AlgDigestToUint256({
        digest[0], digest[1],
        digest[2], digest[3]});
}

std::array<Fp3, kDecoderChallengeColumnsV1>
DeriveDecoderCarryChallengesInternalV1(
    const uint256& tuple_precommit_root)
{
    std::array<
        Fp3,
        kDecoderChallengeColumnsV1> out{};
    if (tuple_precommit_root.IsNull()) {
        return out;
    }
    std::vector<gf::Fp> prefix;
    prefix.reserve(13);
    AppendUint256U32V1(
        prefix, tuple_precommit_root);
    AppendU32V1(prefix, 0x55444a32U); // 'UDJ2'
    for (uint32_t lane = 0;
         lane < out.size(); ++lane) {
        bool selected = false;
        for (uint32_t attempt = 0;
             attempt < 32; ++attempt) {
            auto input = prefix;
            AppendU32V1(input, lane);
            AppendU32V1(input, attempt);
            const auto digest =
                alg_hash::SpongeHashFp(input);
            const Fp3 candidate{
                digest[0], digest[1],
                digest[2]};
            const bool pair_collision =
                (lane == 1 &&
                 gf::Eq(candidate, out[0])) ||
                (lane == 3 &&
                 gf::Eq(candidate, out[2]));
            if (!gf::IsZero(candidate) &&
                !pair_collision) {
                out[lane] = candidate;
                selected = true;
                break;
            }
        }
        if (!selected) return {};
    }
    return out;
}

} // namespace

bool VerifyPhasePrecommitRootOpeningsV1(
    const NormalizedOpeningReceiptV1& receipt,
    std::string* why)
{
    return
        VerifyPhasePrecommitRootOpeningsInternalV1(
            receipt, why);
}

uint256
ComputeAuthenticatedTraceOpeningReceiptRootV1(
    const AuthenticatedTraceOpeningsV1& receipt)
{
    return CommitTraceOpeningsV1(receipt);
}

AuthenticatedTraceOpeningsV1
BuildAuthenticatedTraceOpeningsV1(
    const aq::AirQuotientSplitRapRowsProof& proof)
{
    AuthenticatedTraceOpeningsV1 out;
    out.trace_rows = proof.trace_rows;
    out.base_column_indices =
        proof.base_column_indices;
    if (proof.version != 1 ||
        proof.trace_rows < 2 ||
        proof.batch.groups.size() != 3 ||
        proof.batch.queries.empty() ||
        proof.next_trace_group_rows.size() !=
            proof.batch.queries.size()) {
        out.note =
            "stage3:v11_unified_openings:"
            "proof_shape";
        return out;
    }
    for (uint32_t group_index = 0;
         group_index < out.groups.size();
         ++group_index) {
        const auto& source =
            proof.batch.groups[group_index];
        auto& group =
            out.groups[group_index];
        group.role = source.role;
        group.first_column =
            source.first_column;
        group.column_count =
            source.column_count;
        group.n_leaves =
            source.row_commit.n_leaves;
        group.root =
            Fri3AlgDigestToUint256(
                source.row_commit.root);
        group.rows.reserve(
            proof.batch.queries.size());
        for (uint32_t query_ordinal = 0;
             query_ordinal <
                 proof.batch.queries.size();
             ++query_ordinal) {
            const auto& query =
                proof.batch.queries[
                    query_ordinal];
            if (query.group_rows.size() != 3 ||
                proof.next_trace_group_rows[
                    query_ordinal].size() != 2 ||
                group.n_leaves == 0 ||
                proof.trace_rows == 0 ||
                group.n_leaves %
                    proof.trace_rows != 0) {
                out.note =
                    "stage3:v11_unified_openings:"
                    "query_shape";
                return out;
            }
            const auto& current =
                query.group_rows[group_index];
            const auto& next =
                proof.next_trace_group_rows[
                    query_ordinal][
                        group_index];
            const uint32_t step =
                group.n_leaves /
                proof.trace_rows;
            AuthenticatedTraceRowV1 row;
            row.query_ordinal =
                query_ordinal;
            row.query_index = query.index;
            row.values = current.values;
            row.siblings = current.siblings;
            row.next_query_index =
                (query.index + step) %
                group.n_leaves;
            row.next_values = next.values;
            row.next_siblings =
                next.siblings;
            group.rows.push_back(
                std::move(row));
        }
    }
    out.opening_receipt_root =
        CommitTraceOpeningsV1(out);
    std::string why;
    out.valid =
        !out.opening_receipt_root.IsNull() &&
        VerifyAuthenticatedTraceOpeningsV1(
            out, proof, &why);
    out.every_consumed_cell_merkle_authenticated =
        out.valid;
    out.exact_query_occurrence_order =
        out.valid;
    out.canonical_fp3_and_digest_cells =
        out.valid;
    out.query_schedule_fiat_shamir_verified =
        false;
    out.note = out.valid
        ? "stage3:v11_unified_openings:"
          "r0_rdep_current_next_authenticated"
        : "stage3:v11_unified_openings:" +
          why;
    return out;
}

bool VerifyAuthenticatedTraceOpeningsV1(
    const AuthenticatedTraceOpeningsV1& receipt,
    const aq::AirQuotientSplitRapRowsProof& proof,
    std::string* why)
{
    const auto fail = [why](
                          const std::string& detail) {
        if (why != nullptr) {
            *why =
                "stage3:v11_unified_openings:" +
                detail;
        }
        return false;
    };
    if (receipt.version != kVersionV1 ||
        receipt.trace_rows !=
            proof.trace_rows ||
        receipt.trace_rows < 2 ||
        receipt.base_column_indices !=
            proof.base_column_indices ||
        proof.version != 1 ||
        proof.batch.groups.size() != 3 ||
        proof.batch.queries.empty() ||
        proof.next_trace_group_rows.size() !=
            proof.batch.queries.size() ||
        receipt.opening_receipt_root.IsNull() ||
        CommitTraceOpeningsV1(receipt) !=
            receipt.opening_receipt_root) {
        return fail("receipt_shape_or_root");
    }
    const std::array<
        Fri3AlgMultiRowGroupRole, 2>
        expected_roles{{
            Fri3AlgMultiRowGroupRole::
                MainTrace,
            Fri3AlgMultiRowGroupRole::
                AuxiliaryTrace,
        }};
    for (uint32_t group_index = 0;
         group_index < receipt.groups.size();
         ++group_index) {
        const auto& group =
            receipt.groups[group_index];
        const auto& proof_group =
            proof.batch.groups[group_index];
        const auto root =
            Fri3AlgDigestFromUint256(
                group.root);
        if (group.role !=
                expected_roles[group_index] ||
            group.role != proof_group.role ||
            group.first_column !=
                proof_group.first_column ||
            group.column_count !=
                proof_group.column_count ||
            group.column_count == 0 ||
            group.n_leaves !=
                proof_group.row_commit.n_leaves ||
            group.root !=
                Fri3AlgDigestToUint256(
                    proof_group
                        .row_commit.root) ||
            !root.has_value() ||
            !CanonicalFriDigestV1(*root) ||
            group.rows.size() !=
                proof.batch.queries.size() ||
            group.n_leaves < 2 ||
            (group.n_leaves &
             (group.n_leaves - 1)) != 0 ||
            group.n_leaves %
                receipt.trace_rows != 0) {
            return fail("group_shape_or_root");
        }
        uint32_t path_len = 0;
        for (uint32_t leaves =
                 group.n_leaves;
             leaves > 1; leaves >>= 1) {
            ++path_len;
        }
        const uint32_t step =
            group.n_leaves /
            receipt.trace_rows;
        for (uint32_t query_ordinal = 0;
             query_ordinal <
                 group.rows.size();
             ++query_ordinal) {
            const auto& row =
                group.rows[query_ordinal];
            const auto& query =
                proof.batch.queries[
                    query_ordinal];
            if (query.group_rows.size() != 3 ||
                proof.next_trace_group_rows[
                    query_ordinal].size() != 2) {
                return fail("proof_query_shape");
            }
            const auto& current =
                query.group_rows[
                    group_index];
            const auto& next =
                proof.next_trace_group_rows[
                    query_ordinal][
                        group_index];
            const uint32_t expected_next =
                (query.index + step) %
                group.n_leaves;
            if (row.query_ordinal !=
                    query_ordinal ||
                row.query_index !=
                    query.index ||
                row.query_index >=
                    group.n_leaves ||
                row.next_query_index !=
                    expected_next ||
                row.values.size() !=
                    group.column_count ||
                row.next_values.size() !=
                    group.column_count ||
                row.siblings.size() !=
                    path_len ||
                row.next_siblings.size() !=
                    path_len ||
                !SameFp3VectorV1(
                    row.values,
                    current.values) ||
                !SameFp3VectorV1(
                    row.next_values,
                    next.values) ||
                !SameDigestVectorV1(
                    row.siblings,
                    current.siblings) ||
                !SameDigestVectorV1(
                    row.next_siblings,
                    next.siblings)) {
                return fail(
                    "query_occurrence_or_cells");
            }
            const auto current_leaf =
                alg_hash::LeafHashRow(
                    row.values,
                    row.query_index);
            const auto next_leaf =
                alg_hash::LeafHashRow(
                    row.next_values,
                    row.next_query_index);
            if (!Fri3AlgVerifyPath(
                    current_leaf,
                    row.query_index,
                    row.siblings,
                    *root,
                    group.n_leaves) ||
                !Fri3AlgVerifyPath(
                    next_leaf,
                    row.next_query_index,
                    row.next_siblings,
                    *root,
                    group.n_leaves)) {
                return fail("merkle_path");
            }
        }
    }
    if (why != nullptr) {
        *why =
            "stage3:v11_unified_openings:"
            "authenticated";
    }
    return true;
}

std::array<Fp3, kDecoderChallengeColumnsV1>
DeriveDecoderCarryChallengesV1(
    const uint256& tuple_precommit_root)
{
    return
        DeriveDecoderCarryChallengesInternalV1(
            tuple_precommit_root);
}

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

MerkleFoldPublicShapeV1
BuildMerkleFoldPublicShapeV1(
    const abi::DecodedV1& decoded)
{
    MerkleFoldPublicShapeV1 out;
    const auto fail =
        [&out](const std::string& why) {
            out.valid = false;
            out.note =
                "stage3:v11_unified_merkle_fold_shape:" +
                why;
            return out;
        };
    if (!decoded.canonical ||
        !decoded.complete ||
        !decoded.addresses_unique ||
        !decoded.semantic_keys_unique) {
        return fail("noncanonical_abi");
    }
    const auto& split =
        decoded.envelope.split;
    const auto& batch =
        split.batch;
    if (batch.groups.size() !=
            out.group_columns.size() ||
        batch.queries.size() !=
            abi::kQueryCountV11 ||
        split.next_trace_group_rows.size() !=
            abi::kQueryCountV11 ||
        batch.fold_challenges.empty() ||
        batch.fold_layers.size() !=
            batch.fold_challenges.size() + 1 ||
        batch.n_coeffs < 2 ||
        batch.blowup == 0) {
        return fail("abi_shape");
    }
    const uint64_t n_lde64 =
        uint64_t{batch.n_coeffs} *
        batch.blowup;
    if (n_lde64 >
            std::numeric_limits<uint32_t>::max()) {
        return fail("lde_overflow");
    }
    out.trace_rows = split.trace_rows;
    out.n_coeffs = batch.n_coeffs;
    out.blowup = batch.blowup;
    out.n_lde =
        static_cast<uint32_t>(n_lde64);
    uint32_t cursor = out.n_lde;
    while (cursor > 1 &&
           (cursor & 1U) == 0) {
        ++out.row_depth;
        cursor >>= 1;
    }
    if (cursor != 1 ||
        out.row_depth == 0 ||
        out.trace_rows == 0 ||
        out.n_lde % out.trace_rows != 0) {
        return fail("lde_shape");
    }
    for (uint32_t group = 0;
         group <
             out.group_columns.size();
         ++group) {
        out.group_columns[group] =
            batch.groups[group].column_count;
        if (out.group_columns[group] == 0 ||
            batch.groups[group]
                .row_commit.n_leaves !=
                out.n_lde) {
            return fail("group_shape");
        }
    }
    out.fold_count =
        static_cast<uint32_t>(
            batch.fold_challenges.size());
    out.proof_query_count =
        static_cast<uint32_t>(
            batch.queries.size());
    uint32_t n_coeffs_depth = 0;
    for (cursor = out.n_coeffs;
         cursor > 1 &&
             (cursor & 1U) == 0;
         cursor >>= 1) {
        ++n_coeffs_depth;
    }
    if (cursor != 1 ||
        out.fold_count !=
            n_coeffs_depth) {
        return fail("fold_shape");
    }
    out.canonical_projection = true;
    // This typed projection has no field for a root, opening, query index,
    // challenge, terminal value, public seed or proof source address.
    out.proof_values_excluded = true;
    out.valid = true;
    out.note =
        "stage3:v11_unified_merkle_fold_shape:"
        "canonical_public_projection";
    return out;
}

MerkleFoldPublicPlanV1
BuildMerkleFoldPublicPlanV1(
    const MerkleFoldPublicShapeV1& shape,
    const rv::QueryRangeV1& range)
{
    MerkleFoldPublicPlanV1 out;
    out.shape = shape;
    out.range = range;
    const auto fail =
        [&out](const std::string& why) {
            out.valid = false;
            out.note =
                "stage3:v11_unified_merkle_fold_plan:" +
                why;
            return out;
        };
    if (!shape.valid ||
        !shape.canonical_projection ||
        !shape.proof_values_excluded ||
        range.query_count == 0 ||
        range.first_query >
            shape.proof_query_count ||
        range.query_count >
            shape.proof_query_count -
                range.first_query) {
        return fail("shape_or_range");
    }

    const auto row_leaf_permutations =
        [](uint32_t values) -> uint64_t {
            const uint64_t absorbed =
                uint64_t{3} * values + 2;
            return
                (absorbed +
                 alg_hash::kAlgHashRate - 1) /
                alg_hash::kAlgHashRate;
        };
    uint64_t hash_rows_per_query = 0;
    for (uint32_t group = 0;
         group < 3; ++group) {
        hash_rows_per_query +=
            row_leaf_permutations(
                shape.group_columns[group]) +
            shape.row_depth;
    }
    for (uint32_t group = 0;
         group < 2; ++group) {
        hash_rows_per_query +=
            row_leaf_permutations(
                shape.group_columns[group]) +
            shape.row_depth;
    }
    for (uint32_t fold = 0;
         fold < shape.fold_count;
         ++fold) {
        if (fold >= shape.row_depth) {
            return fail("fold_depth");
        }
        hash_rows_per_query +=
            uint64_t{2} *
            (1 + shape.row_depth - fold);
    }
    const uint64_t hash_real_rows64 =
        hash_rows_per_query *
        range.query_count;
    const uint64_t fold_real_rows64 =
        uint64_t{shape.fold_count} *
        range.query_count;
    if (hash_real_rows64 >
            std::numeric_limits<uint32_t>::max() ||
        fold_real_rows64 >
            std::numeric_limits<uint32_t>::max()) {
        return fail("row_overflow");
    }
    out.hash_real_rows =
        static_cast<uint32_t>(
            hash_real_rows64);
    out.fold_real_rows =
        static_cast<uint32_t>(
            fold_real_rows64);
    out.hash_trace_rows =
        NextPowerOfTwo(
            out.hash_real_rows);
    out.fold_trace_rows =
        NextPowerOfTwo(
            out.fold_real_rows);
    if (out.hash_trace_rows == 0 ||
        out.fold_trace_rows == 0) {
        return fail("trace_rows");
    }

    out.hash_layout =
        mf::CanonicalHashLayoutV1();
    out.fold_layout =
        mf::CanonicalFoldLayoutV1();
    out.hash_program =
        BuildMerkleHashProgramTableV1(
            out.hash_layout);
    out.fold_program =
        BuildMerkleFoldProgramTableV1(
            out.fold_layout);
    std::string why;
    if (out.hash_program.programs.size() !=
            pa::kFixedConstraints +
                alg_hash::kAlgHashT +
                alg_hash::kAlgHashDigestLen ||
        out.fold_program.programs.size() !=
            13 ||
        !cb::ValidateProgramTable(
            out.hash_program, &why) ||
        !cb::ValidateProgramTable(
            out.fold_program, &why) ||
        !cb::BuildAirConstraintSystemFromProgramTable(
            out.hash_program,
            out.hash_trace_rows,
            out.hash_cs, &why) ||
        !cb::BuildAirConstraintSystemFromProgramTable(
            out.fold_program,
            out.fold_trace_rows,
            out.fold_cs, &why)) {
        return fail(
            "canonical_program:" + why);
    }
    out.hash_cs.preprocessed.clear();
    out.hash_cs.preprocessed_row_group_roots.clear();
    out.fold_cs.preprocessed.clear();
    out.fold_cs.preprocessed_row_group_roots.clear();
    out.hash_program_root =
        cb::CommitProgramTableAlgHash(
            out.hash_program);
    out.fold_program_root =
        cb::CommitProgramTableAlgHash(
            out.fold_program);
    out.row_schedule_canonical =
        out.hash_real_rows != 0 &&
        out.fold_real_rows != 0 &&
        out.hash_trace_rows >=
            out.hash_real_rows &&
        out.fold_trace_rows >=
            out.fold_real_rows;
    out.constraint_systems_canonical =
        out.hash_cs.n_rows ==
            out.hash_trace_rows &&
        out.hash_cs.n_columns ==
            out.hash_layout.n_columns &&
        out.hash_cs.constraints.size() ==
            out.hash_program.programs.size() &&
        out.hash_cs.preprocessed.empty() &&
        out.fold_cs.n_rows ==
            out.fold_trace_rows &&
        out.fold_cs.n_columns ==
            out.fold_layout.n_columns &&
        out.fold_cs.constraints.size() ==
            out.fold_program.programs.size() &&
        out.fold_cs.preprocessed.empty();
    out.proof_independent = true;
    out.valid =
        out.row_schedule_canonical &&
        out.constraint_systems_canonical &&
        out.proof_independent &&
        DigestNonzero(
            out.hash_program_root) &&
        DigestNonzero(
            out.fold_program_root);
    out.note = out.valid
        ? "stage3:v11_unified_merkle_fold_plan:"
          "canonical_public_cs"
        : "stage3:v11_unified_merkle_fold_plan:"
          "invalid";
    return out;
}

MerkleFoldCanonicalPhasesV1
MaterializeMerkleFoldCanonicalPhasesV1(
    const MerkleFoldPublicPlanV1& plan,
    const abi::DecodedV1& decoded,
    const mf::ShardProductV1& shard)
{
    MerkleFoldCanonicalPhasesV1 out;
    const auto fail =
        [&out](const std::string& why) {
            out.valid = false;
            out.note =
                "stage3:v11_unified_merkle_fold_witness:" +
                why;
            return out;
        };
    const auto rebuilt =
        BuildMerkleFoldPublicPlanV1(
            plan.shape,
            plan.range);
    const auto decoded_shape =
        BuildMerkleFoldPublicShapeV1(
            decoded);
    const auto same_constraints =
        [](const aq::AirConstraintSystem<Fp3>& left,
           const aq::AirConstraintSystem<Fp3>& right) {
            if (left.n_rows != right.n_rows ||
                left.n_columns !=
                    right.n_columns ||
                left.constraints.size() !=
                    right.constraints.size() ||
                left.preprocessed.size() !=
                    right.preprocessed.size()) {
                return false;
            }
            for (uint32_t ordinal = 0;
                 ordinal <
                     left.constraints.size();
                 ++ordinal) {
                if (left.constraints[ordinal].kind !=
                        right.constraints[ordinal].kind ||
                    left.constraints[ordinal].alg_degree !=
                        right.constraints[ordinal].alg_degree) {
                    return false;
                }
            }
            return true;
        };
    if (!plan.valid ||
        !rebuilt.valid ||
        !decoded_shape.valid ||
        plan.version != kVersionV1 ||
        plan.shape != decoded_shape ||
        plan.shape != rebuilt.shape ||
        plan.range != rebuilt.range ||
        plan.hash_program !=
            rebuilt.hash_program ||
        plan.fold_program !=
            rebuilt.fold_program ||
        !SameDigest(
            plan.hash_program_root,
            rebuilt.hash_program_root) ||
        !SameDigest(
            plan.fold_program_root,
            rebuilt.fold_program_root) ||
        plan.hash_real_rows !=
            rebuilt.hash_real_rows ||
        plan.hash_trace_rows !=
            rebuilt.hash_trace_rows ||
        plan.fold_real_rows !=
            rebuilt.fold_real_rows ||
        plan.fold_trace_rows !=
            rebuilt.fold_trace_rows ||
        !same_constraints(
            plan.hash_cs,
            rebuilt.hash_cs) ||
        !same_constraints(
            plan.fold_cs,
            rebuilt.fold_cs)) {
        return fail("noncanonical_public_plan");
    }
    if (!shard.valid ||
        shard.first_query !=
            plan.range.first_query ||
        shard.query_count !=
            plan.range.query_count ||
        shard.hash_real_rows !=
            plan.hash_real_rows ||
        shard.hash_trace_rows !=
            plan.hash_trace_rows ||
        shard.fold_real_rows !=
            plan.fold_real_rows ||
        shard.fold_trace_rows !=
            plan.fold_trace_rows ||
        shard.hash_layout.n_columns !=
            plan.hash_layout.n_columns ||
        shard.fold_layout.n_columns !=
            plan.fold_layout.n_columns ||
        BuildMerkleHashProgramTableV1(
            shard.hash_layout) !=
            plan.hash_program ||
        BuildMerkleFoldProgramTableV1(
            shard.fold_layout) !=
            plan.fold_program ||
        shard.hash_columns.size() !=
            plan.hash_cs.n_columns ||
        shard.fold_columns.size() !=
            plan.fold_cs.n_columns) {
        return fail("proof_shape");
    }
    for (const auto& column :
         shard.hash_columns) {
        if (column.size() !=
            plan.hash_trace_rows) {
            return fail("hash_column_rows");
        }
    }
    for (const auto& column :
         shard.fold_columns) {
        if (column.size() !=
            plan.fold_trace_rows) {
            return fail("fold_column_rows");
        }
    }
    out.hash_program =
        plan.hash_program;
    out.fold_program =
        plan.fold_program;
    out.hash_cs = plan.hash_cs;
    out.fold_cs = plan.fold_cs;
    out.hash_columns =
        shard.hash_columns;
    out.fold_columns =
        shard.fold_columns;
    if (air_recurse::
            CountWitnessViolationsOnH(
                out.hash_cs,
                out.hash_columns) != 0 ||
        air_recurse::
            CountWitnessViolationsOnH(
                out.fold_cs,
                out.fold_columns) != 0) {
        return fail("constraint_failure");
    }
    out.public_plan_recomputed = true;
    out.proof_tape_ordinary =
        out.hash_cs.preprocessed.empty() &&
        out.fold_cs.preprocessed.empty();
    out.valid =
        out.public_plan_recomputed &&
        out.proof_tape_ordinary;
    out.note = out.valid
        ? "stage3:v11_unified_merkle_fold_witness:"
          "public_plan_materialized"
        : "stage3:v11_unified_merkle_fold_witness:"
          "invalid";
    return out;
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

DeepVmPublicPlanV1
BuildDeepVmPublicPlanV1(
    const cb::ProgramTable& child_program,
    const alg_hash::Digest& expected_program_root,
    const rv::QueryRangeV1& range)
{
    DeepVmPublicPlanV1 out;
    out.range = range;
    out.layout = dvm::CanonicalLayoutV1();
    out.child_program = child_program;
    out.child_program_root =
        expected_program_root;
    out.program =
        BuildDeepVmProgramTableV1(
            out.layout);
    std::string why;
    const auto computed_child_root =
        cb::CommitProgramTableAlgHash(
            child_program);
    DeepVmPublicScheduleV1 schedule;
    if (!cb::ValidateProgramTable(
            child_program, &why) ||
        child_program.challenge_width != 0 ||
        !CanonicalDigest(
            expected_program_root) ||
        !DigestNonzero(
            expected_program_root) ||
        !SameDigest(
            computed_child_root,
            expected_program_root) ||
        out.program.programs.size() !=
            kDeepVmCanonicalConstraintsV1 ||
        out.program.current_width !=
            out.layout.n_columns +
                kDeepVmExtensionColumnsV1 ||
        !cb::ValidateProgramTable(
            out.program, &why) ||
        !cb::ProgramTableIsChallengeIndependent(
            out.program) ||
        !BuildDeepVmPublicScheduleV1(
            out.layout,
            child_program,
            range,
            out.program.current_width,
            schedule,
            &why)) {
        out.note =
            "stage3:v11_unified_deep_vm_plan:" +
            why;
        return out;
    }
    out.real_rows = schedule.real_rows;
    out.trace_rows = schedule.trace_rows;
    out.statement_manifest_columns =
        schedule.ordered_columns;
    out.statement_schedule_root =
        schedule.root;
    out.challenge =
        DeriveDeepVmRegisterChallengesV1(
            out.statement_schedule_root,
            expected_program_root,
            range);
    if (!DeepVmChallengesValid(
            out.challenge) ||
        !cb::BuildAirConstraintSystemFromProgramTable(
            out.program,
            out.trace_rows,
            out.challenge,
            out.cs,
            &why)) {
        out.note =
            "stage3:v11_unified_deep_vm_plan:" +
            why;
        return out;
    }
    out.cs.preprocessed.clear();
    out.cs.preprocessed_row_group_roots.clear();
    for (const auto& entry :
         schedule.columns) {
        out.cs.preprocessed.push_back(entry);
    }
    out.cs.preprocessed_pin_ood = true;
    out.cs.preprocessed_row_group_roots.push_back({
        .version = 1,
        .role =
            aq::AirPreprocessedRowGroupRole::kR0,
        .ordered_columns =
            out.statement_manifest_columns,
        .root =
            out.statement_schedule_root,
    });
    out.child_program_root_recomputed =
        SameDigest(
            computed_child_root,
            expected_program_root) &&
        DigestNonzero(
            out.child_program_root);
    out.statement_schedule_canonical =
        out.statement_manifest_columns.size() ==
            kDeepVmStatementScheduleColumnsV1 &&
        out.cs.preprocessed.size() ==
            kDeepVmStatementScheduleColumnsV1 &&
        out.cs.preprocessed_row_group_roots.size() ==
            1 &&
        out.cs.preprocessed_row_group_roots[0].root ==
            out.statement_schedule_root &&
        !out.statement_schedule_root.IsNull();
    out.constraint_system_canonical =
        out.cs.n_rows == out.trace_rows &&
        out.cs.n_columns ==
            out.program.current_width &&
        out.cs.constraints.size() ==
            out.program.programs.size() &&
        out.program.challenge_width ==
            kDeepVmChallengeColumnsV1 &&
        DeepVmChallengesValid(
            out.challenge);
    out.proof_independent = true;
    out.valid =
        out.child_program_root_recomputed &&
        out.statement_schedule_canonical &&
        out.constraint_system_canonical &&
        out.proof_independent;
    out.note = out.valid
        ? "stage3:v11_unified_deep_vm_plan:"
          "canonical_public_cs"
        : "stage3:v11_unified_deep_vm_plan:"
          "invalid";
    return out;
}

DeepVmCanonicalPhaseV1
MaterializeDeepVmCanonicalPhaseV1(
    const DeepVmPublicPlanV1& plan,
    const dvm::ProductV1& deep)
{
    DeepVmCanonicalPhaseV1 out;
    const auto fail =
        [&out](const std::string& why) {
            out.valid = false;
            out.note =
                "stage3:v11_unified_deep_vm_witness:" +
                why;
            return out;
        };
    const auto rebuilt =
        BuildDeepVmPublicPlanV1(
            plan.child_program,
            plan.child_program_root,
            plan.range);
    const auto same_fp3 =
        [](const std::vector<Fp3>& left,
           const std::vector<Fp3>& right) {
            if (left.size() != right.size()) {
                return false;
            }
            for (uint32_t i = 0;
                 i < left.size(); ++i) {
                if (!gf::Eq(
                        left[i], right[i])) {
                    return false;
                }
            }
            return true;
        };
    const auto same_preprocessed =
        [&same_fp3](
            const aq::AirConstraintSystem<Fp3>& left,
            const aq::AirConstraintSystem<Fp3>& right) {
            if (left.preprocessed.size() !=
                right.preprocessed.size()) {
                return false;
            }
            for (uint32_t i = 0;
                 i < left.preprocessed.size(); ++i) {
                if (left.preprocessed[i].first !=
                        right.preprocessed[i].first ||
                    !same_fp3(
                        left.preprocessed[i].second,
                        right.preprocessed[i].second)) {
                    return false;
                }
            }
            return true;
        };
    const auto same_constraints =
        [](const aq::AirConstraintSystem<Fp3>& left,
           const aq::AirConstraintSystem<Fp3>& right) {
            if (left.n_rows != right.n_rows ||
                left.n_columns != right.n_columns ||
                left.constraints.size() !=
                    right.constraints.size()) {
                return false;
            }
            for (uint32_t i = 0;
                 i < left.constraints.size(); ++i) {
                if (left.constraints[i].kind !=
                        right.constraints[i].kind ||
                    left.constraints[i].alg_degree !=
                        right.constraints[i].alg_degree) {
                    return false;
                }
            }
            return true;
        };
    if (!plan.valid ||
        !rebuilt.valid ||
        plan.version != kVersionV1 ||
        plan.range != rebuilt.range ||
        plan.child_program !=
            rebuilt.child_program ||
        !SameDigest(
            plan.child_program_root,
            rebuilt.child_program_root) ||
        plan.program != rebuilt.program ||
        plan.real_rows != rebuilt.real_rows ||
        plan.trace_rows != rebuilt.trace_rows ||
        plan.statement_manifest_columns !=
            rebuilt.statement_manifest_columns ||
        plan.statement_schedule_root !=
            rebuilt.statement_schedule_root ||
        !same_fp3(
            plan.challenge,
            rebuilt.challenge) ||
        !same_constraints(
            plan.cs, rebuilt.cs) ||
        !same_preprocessed(
            plan.cs, rebuilt.cs)) {
        return fail(
            "noncanonical_public_plan");
    }

    std::string why;
    if (!deep.valid ||
        dvm::RecountViolationsV1(
            deep, deep.columns) != 0 ||
        deep.columns.size() !=
            deep.layout.n_columns ||
        deep.cs.n_rows !=
            plan.trace_rows ||
        deep.real_rows !=
            plan.real_rows ||
        deep.first_query !=
            plan.range.first_query ||
        deep.query_count !=
            plan.range.query_count ||
        !SameDigest(
            deep.program_root,
            plan.child_program_root) ||
        BuildDeepVmProgramTableV1(
            deep.layout) !=
            plan.program) {
        return fail(
            "proof_shape_or_root");
    }

    out.program = plan.program;
    out.cs = plan.cs;
    out.challenge = plan.challenge;
    out.statement_manifest_columns =
        plan.statement_manifest_columns;
    out.columns.assign(
        plan.program.current_width,
        std::vector<Fp3>(
            plan.trace_rows,
            Fp3::Zero()));
    for (uint32_t column = 0;
         column < deep.layout.n_columns;
         ++column) {
        if (deep.columns[column].size() !=
                plan.trace_rows) {
            return fail(
                "proof_column_rows");
        }
        out.columns[column] =
            deep.columns[column];
    }
    for (const auto& [column, canonical] :
         plan.cs.preprocessed) {
        if (column >= out.columns.size() ||
            canonical.size() !=
                plan.trace_rows) {
            return fail(
                "schedule_column_shape");
        }
        if (column <
                deep.layout.n_columns) {
            if (!same_fp3(
                    canonical,
                    out.columns[column])) {
                return fail(
                    "proof_schedule_substitution");
            }
        } else {
            out.columns[column] = canonical;
        }
    }

    const auto& l = plan.layout;
    const auto ssa = DeepVmSsaLayout(l);
    std::array<Fp3, kDeepVmRegisterBusLanesV1>
        running_value{
            Fp3::Zero(), Fp3::Zero()};
    const Fp3 register_bus_tag =
        gf::FromU64_3(0x52454731U);
    for (uint32_t row = 0;
         row < plan.trace_rows; ++row) {
        const Fp3 binary_active =
            gf::Add(
                gf::Add(
                    out.columns[l.op_add][row],
                    out.columns[l.op_sub][row]),
                out.columns[l.op_mul][row]);
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
                plan.challenge[lane];
            const Fp3 alpha =
                plan.challenge[2 + lane];
            std::array<Fp3, 3> inverse{
                Fp3::Zero(),
                Fp3::Zero(),
                Fp3::Zero()};
            for (uint32_t side = 0;
                 side <
                     kDeepVmRegisterBusSidesV1;
                 ++side) {
                const Fp3 h0 = gf::Add(
                    out.columns[
                        register_column[side]][row],
                    gf::Mul(
                        gamma,
                        out.columns[
                            value_column[side]][row]));
                const Fp3 h1 = gf::Add(
                    out.columns[
                        ssa.program_ordinal][row],
                    gf::Mul(gamma, h0));
                const Fp3 h2 = gf::Add(
                    out.columns[l.query][row],
                    gf::Mul(gamma, h1));
                const Fp3 h3 = gf::Add(
                    register_bus_tag,
                    gf::Mul(gamma, h2));
                out.columns[
                    ssa.horner[lane][side][0]][row] =
                    h0;
                out.columns[
                    ssa.horner[lane][side][1]][row] =
                    h1;
                out.columns[
                    ssa.horner[lane][side][2]][row] =
                    h2;
                out.columns[
                    ssa.horner[lane][side][3]][row] =
                    h3;
                const Fp3 active =
                    side ==
                        static_cast<uint32_t>(
                            DeepVmRegisterSideV1::
                                Producer)
                    ? out.columns[
                        l.vm_instruction][row]
                    : binary_active;
                const Fp3 denominator =
                    gf::Add(alpha, h3);
                if (!gf::IsZero(active)) {
                    if (gf::IsZero(denominator)) {
                        return fail(
                            "register_pole");
                    }
                    inverse[side] =
                        gf::Inv(denominator);
                }
                out.columns[
                    ssa.inverse[lane][side]][row] =
                    inverse[side];
            }
            out.columns[ssa.running[lane]][row] =
                running_value[lane];
            const Fp3 producer =
                gf::Mul(
                    out.columns[
                        ssa.register_use_multiplicity]
                        [row],
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
            return fail(
                "register_terminal");
        }
    }

    const uint64_t violations =
        air_recurse::
            CountWitnessViolationsOnH(
                out.cs, out.columns);
    out.program_and_range_bound = true;
    out.constant_schedule_owned = true;
    out.register_logup_complete =
        DeepVmChallengesValid(
            out.challenge);
    out.valid =
        out.program_and_range_bound &&
        out.constant_schedule_owned &&
        out.register_logup_complete &&
        violations == 0;
    out.note = out.valid
        ? "stage3:v11_unified_deep_vm_witness:"
          "public_plan_materialized"
        : "stage3:v11_unified_deep_vm_witness:"
          "constraint_failure";
    return out;
}

DeepVmCanonicalPhaseV1
BuildDeepVmCanonicalPhaseV1(
    const dvm::ProductV1& deep,
    const cb::ProgramTable& child_program,
    const alg_hash::Digest& expected_program_root,
    const rv::QueryRangeV1& range)
{
    const auto plan =
        BuildDeepVmPublicPlanV1(
            child_program,
            expected_program_root,
            range);
    if (!plan.valid) {
        DeepVmCanonicalPhaseV1 out;
        out.note = plan.note;
        return out;
    }
    return MaterializeDeepVmCanonicalPhaseV1(
        plan, deep);
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

cb::ProgramTable
BuildDecoderRootAliasProgramTableV1(
    const LayoutV1& layout,
    const dj::LayoutV1& decoder)
{
    cb::ProgramTable table;
    table.version =
        cb::kConstraintBytecodeVersion;
    table.role =
        RCStage3RelationRole::CompositionLink;
    table.current_width = layout.n_columns;
    table.next_width = layout.n_columns;
    if (layout.n_columns == 0 ||
        layout.n_columns <
            std::max(
                kDecoderRootSelectorColumnsV1,
                kPhasePrecommitRootColumnsV1) ||
        decoder.root_value >=
            layout.data_columns ||
        layout.decoder_root_selector_columns !=
            kDecoderRootSelectorColumnsV1 ||
        layout.decoder_root_selector_base >
            layout.n_columns -
                kDecoderRootSelectorColumnsV1 ||
        layout.phase_precommit_root_base >
            layout.n_columns -
                kPhasePrecommitRootColumnsV1) {
        return table;
    }
    constexpr std::array<PhaseV1, 3>
        owners{{
            PhaseV1::ParentJoin,
            PhaseV1::MerkleHash,
            PhaseV1::MerkleFold,
        }};
    uint32_t selector_ordinal = 0;
    for (const PhaseV1 owner : owners) {
        for (uint32_t word = 0;
             word < kPhasePrecommitRootWordsV1;
             ++word, ++selector_ordinal) {
            const uint32_t selector =
                layout.decoder_root_selector_base +
                selector_ordinal;
            const uint32_t expected =
                layout.PhasePrecommitRoot(
                    owner, word);
            AppendBytecodeProgramV1(
                table,
                [selector,
                 claimed = decoder.root_value,
                 expected](
                    BytecodeExprV1& e) {
                    e.Mul(
                        e.Current(selector),
                        e.Sub(
                            e.Current(claimed),
                            e.Current(expected)));
                });
        }
    }
    std::string why;
    if (table.programs.size() !=
            kDecoderRootSelectorColumnsV1 ||
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

uint256 ComputeNormalizedOpeningReceiptRootV1(
    const NormalizedOpeningReceiptV1& receipt)
{
    std::vector<gf::Fp> input;
    input.reserve(256);
    AppendU32V1(input, 0x554f5231U); // 'UOR1'
    AppendU32V1(input, receipt.version);
    AppendU32V1(input, receipt.range.ordinal);
    AppendU32V1(
        input, receipt.range.first_query);
    AppendU32V1(
        input, receipt.range.query_count);
    AppendUint256U32V1(
        input, receipt.child_statement_root);
    if (!CanonicalDigest(
            receipt.child_program_root)) {
        return {};
    }
    input.insert(
        input.end(),
        receipt.child_program_root.begin(),
        receipt.child_program_root.end());
    for (uint32_t index = 0;
         index < kPhasesV1; ++index) {
        if (!CanonicalDigest(
                receipt.phase_program_root[
                    index])) {
            return {};
        }
        input.insert(
            input.end(),
            receipt.phase_program_root[
                index].begin(),
            receipt.phase_program_root[
                index].end());
        AppendUint256U32V1(
            input,
            receipt.phase_precommit_root[
                index]);
        const auto& shape =
            receipt.phases[index];
        AppendU32V1(
            input,
            static_cast<uint8_t>(
                shape.phase));
        AppendU32V1(input, shape.first_row);
        AppendU32V1(input, shape.rows);
        AppendU32V1(input, shape.columns);
        AppendU32V1(input, shape.constraints);
        AppendU32V1(
            input,
            shape.preprocessed_columns);
        AppendU32V1(
            input, shape.max_degree);
    }
    AppendUint256U32V1(
        input,
        receipt.trace_openings
            .opening_receipt_root);
    AppendU32V1(
        input,
        receipt.phase_precommit_root_column_base);
    AppendU32V1(
        input,
        receipt.phase_precommit_root_words);
    const auto digest =
        alg_hash::SpongeHashFp(input);
    return Fri3AlgDigestToUint256({
        digest[0], digest[1],
        digest[2], digest[3]});
}

NormalizedOpeningReceiptV1
BuildNormalizedOpeningReceiptV1(
    const ProductV1& product,
    const alg_hash::Digest& child_program_root,
    const uint256& child_statement_root,
    const aq::AirQuotientSplitRapRowsProof& proof)
{
    NormalizedOpeningReceiptV1 out;
    out.range = product.range;
    out.child_statement_root =
        child_statement_root;
    out.child_program_root =
        child_program_root;
    out.phase_program_root = {{
        product.parent_join_program_root,
        product.merkle_hash_program_root,
        product.merkle_fold_program_root,
        product.deep_vm_program_root,
        product.decoder_program_root,
    }};
    out.phases = product.phases;
    out.phase_precommit_root_column_base =
        product.layout.phase_precommit_root_base;
    out.trace_openings =
        BuildAuthenticatedTraceOpeningsV1(
            proof);
    out.phase_precommit_root =
        PhasePrecommitRootsV1(product);
    out.receipt_root =
        ComputeNormalizedOpeningReceiptRootV1(
            out);
    out.canonical_programs_bound =
        product
            .phase_constraint_systems_canonical_bytecode ==
                kPhasesV1 &&
        product.parent_join_program_root_recomputed &&
        product.merkle_hash_program_root_recomputed &&
        product.merkle_fold_program_root_recomputed &&
        product.deep_vm_program_root_recomputed &&
        product.decoder_program_root_recomputed;
    std::string phase_root_why;
    out.phase_precommit_roots_opening_authenticated =
        out.trace_openings.valid &&
        VerifyPhasePrecommitRootOpeningsInternalV1(
            out, &phase_root_why);
    out.deep_vm_challenge_replayed =
        out.phase_precommit_roots_opening_authenticated &&
        DeepVmChallengesValid(
            DeriveDeepVmRegisterChallengesV1(
                out.phase_precommit_root[
                    static_cast<uint32_t>(
                        PhaseV1::DeepVm)],
                out.child_program_root,
                out.range));
    const auto decoder_challenge =
        DeriveDecoderCarryChallengesV1(
            out.phase_precommit_root[
                static_cast<uint32_t>(
                    PhaseV1::Decoder)]);
    out.decoder_challenge_replayed =
        out.phase_precommit_roots_opening_authenticated &&
        std::all_of(
            decoder_challenge.begin(),
            decoder_challenge.end(),
            [](const Fp3& value) {
                return !gf::IsZero(value);
            });
    out.verifier_input_excludes_child_proof =
        true;
    out.every_consumed_cell_opening_authenticated =
        out.trace_openings.valid;
    out.complete_phase_verifier_consumption =
        false;
    out.complete_child_receipt_consumption =
        false;
    const bool all_phase_roots =
        std::all_of(
            out.phase_precommit_root.begin(),
            out.phase_precommit_root.end(),
            [](const uint256& root) {
                return !root.IsNull();
            });
    out.valid_foundation =
        !out.receipt_root.IsNull() &&
        !out.child_statement_root.IsNull() &&
        CanonicalDigest(
            out.child_program_root) &&
        DigestNonzero(
            out.child_program_root) &&
        all_phase_roots &&
        out.canonical_programs_bound &&
        out.verifier_input_excludes_child_proof &&
        out.every_consumed_cell_opening_authenticated &&
        out.phase_precommit_roots_opening_authenticated &&
        out.deep_vm_challenge_replayed &&
        out.decoder_challenge_replayed &&
        !out.complete_phase_verifier_consumption &&
        !out.complete_child_receipt_consumption;
    if (out.valid_foundation) {
        const auto verified =
            VerifyNormalizedOpeningReceiptV1(
                out, proof);
        out.valid_foundation =
            verified.accepted_foundation;
    }
    out.note = out.valid_foundation
        ? "stage3:v11_unified_opening_receipt:"
          "raw_child_excluded;current_next_paths_authenticated;"
          "phase_roots_r0_authenticated;challenges_replayed;"
          "phase_verifier_consumption_open"
        : "stage3:v11_unified_opening_receipt:"
          "foundation_failure";
    return out;
}

NormalizedOpeningVerifyResultV1
VerifyNormalizedOpeningReceiptV1(
    const NormalizedOpeningReceiptV1& receipt,
    const aq::AirQuotientSplitRapRowsProof& proof)
{
    NormalizedOpeningVerifyResultV1 out;
    auto fail = [&out](
                    const std::string& detail) {
        out.accepted_foundation = false;
        out.note =
            "stage3:v11_unified_opening_receipt:"
            "verify:" + detail;
        return out;
    };
    if (receipt.version != kVersionV1 ||
        receipt.child_statement_root.IsNull() ||
        !CanonicalDigest(
            receipt.child_program_root) ||
        !DigestNonzero(
            receipt.child_program_root) ||
        receipt.receipt_root.IsNull() ||
        ComputeNormalizedOpeningReceiptRootV1(
            receipt) !=
                receipt.receipt_root) {
        return fail("receipt_root_or_statement");
    }
    std::string opening_why;
    out.opening_paths_verified =
        VerifyAuthenticatedTraceOpeningsV1(
            receipt.trace_openings,
            proof, &opening_why);
    if (!out.opening_paths_verified) {
        return fail(opening_why);
    }

    cb::ProgramTable parent_program;
    np::ManifestV1 parent_manifest;
    std::string program_why;
    if (!np::BuildCanonicalProgramTableV1(
            parent_program,
            &parent_manifest,
            &program_why)) {
        return fail(
            "parent_program:" +
            program_why);
    }
    const std::array<cb::ProgramTable, kPhasesV1>
        programs{{
            parent_program,
            BuildMerkleHashProgramTableV1(),
            BuildMerkleFoldProgramTableV1(),
            BuildDeepVmProgramTableV1(),
            BuildDecoderProgramTableV1(),
        }};
    const std::array<uint32_t, kPhasesV1>
        expected_manifest_columns{{
            kParentJoinStatementScheduleColumnsV1,
            0,
            0,
            kDeepVmStatementScheduleColumnsV1,
            11,
        }};
    uint64_t active_rows = 0;
    uint32_t data_columns = 0;
    uint64_t manifest_columns = 0;
    out.canonical_programs_verified = true;
    for (uint32_t index = 0;
         index < kPhasesV1; ++index) {
        const auto root =
            cb::CommitProgramTableAlgHash(
                programs[index]);
        const auto& shape =
            receipt.phases[index];
        uint32_t program_max_degree = 0;
        for (const auto& program :
             programs[index].programs) {
            program_max_degree =
                std::max(
                    program_max_degree,
                    program.declared_degree);
        }
        const bool power_of_two =
            shape.rows >= 2 &&
            (shape.rows &
             (shape.rows - 1)) == 0;
        out.canonical_programs_verified =
            out.canonical_programs_verified &&
            cb::ValidateProgramTable(
                programs[index],
                &program_why) &&
            cb::ProgramTableIsChallengeIndependent(
                programs[index]) &&
            SameDigest(
                root,
                receipt.phase_program_root[
                    index]) &&
            static_cast<uint32_t>(
                shape.phase) == index &&
            shape.first_row == active_rows &&
            power_of_two &&
            shape.columns ==
                programs[index].current_width &&
            shape.constraints ==
                programs[index].programs.size() &&
            shape.preprocessed_columns ==
                expected_manifest_columns[index] &&
            shape.max_degree ==
                program_max_degree;
        active_rows += shape.rows;
        data_columns =
            std::max(
                data_columns,
                shape.columns);
        manifest_columns +=
            shape.preprocessed_columns;
    }
    const uint64_t expected_trace_columns =
        uint64_t{data_columns} +
        4 * kPhasesV1 + 2 +
        manifest_columns +
        kPhasePrecommitRootColumnsV1 +
        kDecoderRootSelectorColumnsV1;
    const uint64_t expected_phase_root_base =
        uint64_t{data_columns} +
        4 * kPhasesV1 + 2 +
        manifest_columns;
    const uint64_t proof_trace_columns =
        uint64_t{
        proof.batch.groups[0]
                .column_count} +
        proof.batch.groups[1]
            .column_count;
    std::vector<uint32_t>
        expected_base_columns;
    expected_base_columns.reserve(
        4 * kPhasesV1 + 1 +
        manifest_columns);
    const uint32_t active_column =
        data_columns + 4 * kPhasesV1;
    const uint32_t acceptance_column =
        active_column + 1;
    for (uint32_t column = data_columns;
         column <= active_column; ++column) {
        expected_base_columns.push_back(
            column);
    }
    for (uint32_t column =
             acceptance_column + 1;
         column < expected_trace_columns;
         ++column) {
        expected_base_columns.push_back(
            column);
    }
    const bool trace_power_of_two =
        receipt.trace_openings.trace_rows >= 2 &&
        (receipt.trace_openings.trace_rows &
         (receipt.trace_openings.trace_rows - 1)) ==
            0;
    if (!out.canonical_programs_verified ||
        active_rows >
            receipt.trace_openings.trace_rows ||
        !trace_power_of_two ||
        receipt.trace_openings.trace_rows >
            kTraceRowsCapV1 ||
        receipt.range.ordinal != 0 ||
        receipt.range.first_query != 0 ||
        receipt.range.query_count !=
            kQ96QueriesV1 ||
        receipt.phase_precommit_root_words !=
            kPhasePrecommitRootWordsV1 ||
        receipt.phase_precommit_root_column_base !=
            expected_phase_root_base ||
        expected_trace_columns !=
            proof_trace_columns ||
        expected_trace_columns >
            std::numeric_limits<
                uint32_t>::max() ||
        receipt.trace_openings
                .base_column_indices !=
            expected_base_columns ||
        proof.batch.groups[0].column_count !=
            proof.base_column_indices.size() ||
        proof.batch.groups[1].first_column !=
            proof.batch.groups[0].column_count) {
        return fail("canonical_program_or_phase_shape");
    }
    for (const auto& root :
         receipt.phase_precommit_root) {
        if (root.IsNull()) {
            return fail("phase_precommit_root");
        }
    }
    out.phase_precommit_roots_opening_authenticated =
        VerifyPhasePrecommitRootOpeningsInternalV1(
            receipt, &opening_why);
    if (!out.phase_precommit_roots_opening_authenticated) {
        return fail(opening_why);
    }
    const auto deep_challenge =
        DeriveDeepVmRegisterChallengesV1(
            receipt.phase_precommit_root[
                static_cast<uint32_t>(
                    PhaseV1::DeepVm)],
            receipt.child_program_root,
            receipt.range);
    const auto decoder_challenge =
        DeriveDecoderCarryChallengesV1(
            receipt.phase_precommit_root[
                static_cast<uint32_t>(
                    PhaseV1::Decoder)]);
    if (!DeepVmChallengesValid(
            deep_challenge)) {
        return fail("deep_vm_challenge");
    }
    out.deep_vm_challenge = {
        deep_challenge[0],
        deep_challenge[1],
        deep_challenge[2],
        deep_challenge[3],
    };
    out.decoder_challenge =
        decoder_challenge;
    out.challenge_replay_verified =
        std::all_of(
            decoder_challenge.begin(),
            decoder_challenge.end(),
            [](const Fp3& value) {
                return !gf::IsZero(value);
            });
    out.raw_child_proof_excluded = true;
    out.full_split_rap_transcript_verified =
        false;
    out.complete_phase_verifier_consumption =
        false;
    out.complete_child_receipt_consumption =
        false;
    out.accepted_foundation =
        out.opening_paths_verified &&
        out.phase_precommit_roots_opening_authenticated &&
        out.canonical_programs_verified &&
        out.challenge_replay_verified &&
        out.raw_child_proof_excluded &&
        !out.complete_phase_verifier_consumption &&
        !out.complete_child_receipt_consumption;
    out.note =
        "stage3:v11_unified_opening_receipt:"
        "verify:authenticated_foundation;"
        "phase_roots_r0_authenticated;"
        "challenge_replay_closed;"
        "phase_verifier_consumption_open";
    return out;
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

    const MerkleFoldPublicShapeV1
        merkle_fold_public_shape =
            BuildMerkleFoldPublicShapeV1(
                *decoded);
    const MerkleFoldPublicPlanV1
        merkle_fold_public_plan =
            BuildMerkleFoldPublicPlanV1(
                merkle_fold_public_shape,
                range);
    const MerkleFoldCanonicalPhasesV1
        merkle_fold_materialized =
            MaterializeMerkleFoldCanonicalPhasesV1(
                merkle_fold_public_plan,
                *decoded,
                out.merkle_fold);
    if (!merkle_fold_public_shape.valid ||
        !merkle_fold_public_plan.valid ||
        !merkle_fold_materialized.valid) {
        return fail(
            "merkle_fold_public_plan:" +
            (merkle_fold_public_shape.valid
                 ? (merkle_fold_public_plan.valid
                        ? merkle_fold_materialized.note
                        : merkle_fold_public_plan.note)
                 : merkle_fold_public_shape.note));
    }
    const cb::ProgramTable&
        merkle_hash_program =
            merkle_fold_materialized
                .hash_program;
    const auto& merkle_hash_static_cs =
        merkle_fold_materialized.hash_cs;
    const auto& merkle_hash_static_columns =
        merkle_fold_materialized.hash_columns;
    if (merkle_hash_program.programs.size() !=
            pa::kFixedConstraints +
                alg_hash::kAlgHashT +
                alg_hash::kAlgHashDigestLen ||
        merkle_hash_program.current_width !=
            out.merkle_fold.hash_cs.n_columns ||
        merkle_hash_program.next_width !=
            out.merkle_fold.hash_cs.n_columns ||
        merkle_hash_program.programs.size() !=
            out.merkle_fold.hash_cs.constraints.size()) {
        return fail(
            "merkle_hash_static_program");
    }
    if (air_recurse::
            CountWitnessViolationsOnH(
                merkle_hash_static_cs,
                merkle_hash_static_columns) != 0) {
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

    const cb::ProgramTable&
        merkle_fold_program =
            merkle_fold_materialized
                .fold_program;
    const auto& merkle_fold_static_cs =
        merkle_fold_materialized.fold_cs;
    const auto& merkle_fold_static_columns =
        merkle_fold_materialized.fold_columns;
    if (merkle_fold_program.programs.size() != 13 ||
        merkle_fold_program.current_width !=
            out.merkle_fold.fold_cs.n_columns ||
        merkle_fold_program.next_width !=
            out.merkle_fold.fold_cs.n_columns ||
        merkle_fold_program.programs.size() !=
            out.merkle_fold.fold_cs.constraints.size()) {
        return fail(
            "merkle_fold_static_program");
    }
    if (air_recurse::
            CountWitnessViolationsOnH(
                merkle_fold_static_cs,
                merkle_fold_static_columns) != 0) {
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

    const DeepVmPublicPlanV1 deep_vm_plan =
        BuildDeepVmPublicPlanV1(
            input.child_program,
            input.expected_child_program_root,
            range);
    const DeepVmCanonicalPhaseV1
        deep_vm_materialized =
            MaterializeDeepVmCanonicalPhaseV1(
                deep_vm_plan,
                out.deep_vm);
    if (!deep_vm_plan.valid ||
        !deep_vm_materialized.valid) {
        return fail(
            "deep_vm_static_program:" +
            (deep_vm_plan.valid
             ? deep_vm_materialized.note
             : deep_vm_plan.note));
    }
    const cb::ProgramTable& deep_vm_program =
        deep_vm_plan.program;
    const auto& deep_vm_static_cs =
        deep_vm_materialized.cs;
    const auto& deep_vm_static_columns =
        deep_vm_materialized.columns;
    const auto&
        deep_vm_statement_manifest_columns =
            deep_vm_plan
                .statement_manifest_columns;
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
        deep_vm_plan.statement_schedule_root;
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
    const auto decoder_rooted_challenge =
        DeriveDecoderCarryChallengesV1(
            out.decoder
                .join_tuple_precommit_root);
    if (decoder_program.programs.size() != 30 ||
        decoder_program.current_width !=
            out.decoder.layout.n_columns +
                kDecoderHornerAuxColumnsV1 ||
        !BuildDecoderStaticPhaseV1(
            out.decoder,
            decoder_rooted_challenge,
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
             &merkle_hash_static_columns},
            {PhaseV1::MerkleFold,
             &merkle_fold_static_cs,
             &merkle_fold_static_columns},
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
    out.layout.phase_precommit_root_base =
        cursor;
    cursor +=
        kPhasePrecommitRootColumnsV1;
    out.layout.decoder_root_selector_base =
        cursor;
    out.layout.decoder_root_selector_columns =
        kDecoderRootSelectorColumnsV1;
    cursor +=
        out.layout.decoder_root_selector_columns;
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

    const auto phase_precommit_roots =
        PhasePrecommitRootsV1(out);
    if (std::any_of(
            phase_precommit_roots.begin(),
            phase_precommit_roots.end(),
            [](const uint256& root) {
                return root.IsNull();
            })) {
        return fail("phase_precommit_root");
    }
    for (uint32_t phase = 0;
         phase < kPhasesV1; ++phase) {
        for (uint32_t word = 0;
             word < kPhasePrecommitRootWordsV1;
             ++word) {
            const uint32_t column =
                out.layout.PhasePrecommitRoot(
                    static_cast<PhaseV1>(phase),
                    word);
            out.columns[column].assign(
                out.trace_rows,
                Fp3::FromFp(
                    Uint256WordV1(
                        phase_precommit_roots[phase],
                        word)));
            out.cs.preprocessed.emplace_back(
                column, out.columns[column]);
        }
    }

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
        out.layout.phase_precommit_root_base) {
        return fail("expected_pin_inventory");
    }

    const auto& decoder_shape =
        out.phases[static_cast<uint32_t>(
            PhaseV1::Decoder)];
    cb::ProgramTable decoder_root_alias_program;
    decoder_root_alias_program.role =
        RCStage3RelationRole::CompositionLink;
    decoder_root_alias_program.current_width =
        out.layout.n_columns;
    decoder_root_alias_program.next_width =
        out.layout.n_columns;
    uint32_t decoder_root_row = 0;
    uint32_t decoder_selector = 0;
    for (const auto& pin :
         out.decoder.child_roots) {
        PhaseV1 owner;
        if (pin.index != 0) {
            return fail(
                "decoder_root_noncanonical_index");
        }
        if (pin.kind == 1) {
            owner = PhaseV1::ParentJoin;
        } else if (pin.kind == 2) {
            owner = PhaseV1::MerkleHash;
        } else if (pin.kind == 3) {
            owner = PhaseV1::MerkleFold;
        } else {
            return fail(
                "decoder_root_noncanonical_kind");
        }
        for (uint32_t word = 0;
             word < kPhasePrecommitRootWordsV1;
             ++word, ++decoder_root_row,
             ++decoder_selector) {
            if (decoder_selector >=
                    out.layout
                        .decoder_root_selector_columns ||
                decoder_root_row >=
                    decoder_shape.rows) {
                return fail(
                    "decoder_root_selector_overflow");
            }
            const uint32_t selector =
                out.layout.decoder_root_selector_base +
                decoder_selector;
            const uint32_t global_row =
                decoder_shape.first_row +
                decoder_root_row;
            out.columns[selector][global_row] =
                Fp3::One();
            out.cs.preprocessed.emplace_back(
                selector,
                out.columns[selector]);
            AppendBytecodeProgramV1(
                decoder_root_alias_program,
                [selector,
                 claimed =
                     out.decoder.layout.root_value,
                 expected =
                     out.layout.PhasePrecommitRoot(
                         owner, word)](
                    BytecodeExprV1& e) {
                    const uint32_t selector_value =
                        e.Current(selector);
                    const uint32_t claimed_value =
                        e.Current(claimed);
                    const uint32_t expected_value =
                        e.Current(expected);
                    e.Mul(
                        selector_value,
                        e.Sub(
                            claimed_value,
                            expected_value));
                });
        }
    }
    if (decoder_selector !=
            out.layout
                .decoder_root_selector_columns) {
        return fail(
            "decoder_root_selector_inventory");
    }
    aq::AirConstraintSystem<Fp3>
        decoder_root_alias_adapter;
    const cb::ProgramTable
        canonical_decoder_root_alias_program =
            BuildDecoderRootAliasProgramTableV1(
                out.layout,
                out.decoder.layout);
    if (canonical_decoder_root_alias_program !=
            decoder_root_alias_program ||
        !cb::ValidateProgramTable(
            decoder_root_alias_program,
            &why) ||
        !cb::BuildAirConstraintSystemFromProgramTable(
            decoder_root_alias_program,
            out.trace_rows,
            decoder_root_alias_adapter,
            &why) ||
        decoder_root_alias_adapter.constraints.size() !=
            kDecoderRootSelectorColumnsV1) {
        return fail(
            "decoder_root_alias_bytecode:" +
            why);
    }
    out.decoder_root_alias_program_root =
        cb::CommitProgramTableAlgHash(
            decoder_root_alias_program);
    out.decoder_root_alias_constraints_canonical_bytecode =
        DigestNonzero(
            out.decoder_root_alias_program_root);
    out.cs.constraints.insert(
        out.cs.constraints.end(),
        std::make_move_iterator(
            decoder_root_alias_adapter
                .constraints.begin()),
        std::make_move_iterator(
            decoder_root_alias_adapter
                .constraints.end()));
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
    out.phase_precommit_roots_r0_exported =
        std::all_of(
            phase_precommit_roots.begin(),
            phase_precommit_roots.end(),
            [](const uint256& root) {
                return !root.IsNull();
            }) &&
        out.layout.phase_precommit_root_base +
                kPhasePrecommitRootColumnsV1 ==
            out.layout.decoder_root_selector_base;
    out.phase_precommit_roots_canonical_u32 =
        out.phase_precommit_roots_r0_exported;
    out.decoder_root_words_directly_aliased =
        decoder_selector;
    out.decoder_root_rows_directly_aliased =
        decoder_selector ==
            kDecoderRootSelectorColumnsV1;
    out.decoder_child_root_carry_complete =
        out.phase_precommit_roots_r0_exported &&
        out.phase_precommit_roots_canonical_u32 &&
        out.decoder_root_rows_directly_aliased &&
        out.decoder_root_alias_constraints_canonical_bytecode;
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
