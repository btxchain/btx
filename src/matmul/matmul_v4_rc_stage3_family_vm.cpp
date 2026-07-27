// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_family_vm.h>

#include <hash.h>

#include <algorithm>
#include <array>
#include <limits>
#include <memory>

namespace matmul::v4::rc::stage3_family_vm {
namespace {

constexpr char FAMILY_VM_PLAN_DOMAIN[] =
    "BTX_RC_STAGE3_FAMILY_VM_PLAN_V1";

bool IsPowerOfTwo(uint32_t value)
{
    return value >= 2 && (value & (value - 1U)) == 0;
}

uint64_t NextPowerOfTwo(uint64_t value)
{
    if (value < 2) return 2;
    uint64_t result = 1;
    while (result < value) {
        if (result >
            std::numeric_limits<uint64_t>::max() / 2) {
            return 0;
        }
        result <<= 1;
    }
    return result;
}

uint32_t TerminalChecks(
    air_quotient::AirKind kind,
    uint32_t rows)
{
    switch (kind) {
    case air_quotient::AirKind::kEverywhere:
        return rows;
    case air_quotient::AirKind::kTransition:
        return rows - 1U;
    case air_quotient::AirKind::kFirstRow:
    case air_quotient::AirKind::kLastRow:
        return 1;
    }
    return 0;
}

uint256 CommitPlan(const FamilyVmPlanV1& plan)
{
    HashWriter hash;
    hash << FAMILY_VM_PLAN_DOMAIN
         << plan.version
         << static_cast<uint16_t>(plan.role)
         << plan.original_trace_rows
         << plan.original_columns
         << plan.programs
         << plan.instructions_per_original_row
         << plan.source_memory_rows
         << plan.instruction_execution_rows
         << plan.logical_vertical_rows
         << plan.padded_vertical_rows
         << plan.source_read_events
         << plan.source_definition_weight
         << plan.register_read_events
         << plan.register_definition_weight
         << plan.terminal_checks
         << plan.physical_columns
         << plan.direct_query_value_bytes
         << plan.coefficient_cap
         << plan.minimum_vm_segments
         << plan.program_table_commitment;
    for (const auto& limb : plan.program_table_alg_hash) {
        hash << limb;
    }
    hash << plan.source_load_multiplicity;
    hash << static_cast<uint32_t>(
        plan.program_inventory.size());
    for (const auto& program : plan.program_inventory) {
        hash << program.constraint_ordinal
             << static_cast<uint8_t>(program.kind)
             << program.instructions
             << program.current_loads
             << program.next_loads
             << program.register_reads
             << program.terminal_checks
             << program.register_use_multiplicity;
    }
    return hash.GetHash();
}

} // namespace

FamilyVmPlanV1 BuildFamilyVmPlanV1(
    const cb::ProgramTable& table,
    uint32_t original_trace_rows)
{
    FamilyVmPlanV1 out;
    out.role = table.role;
    out.original_trace_rows = original_trace_rows;
    out.original_columns = table.current_width;
    out.programs =
        static_cast<uint32_t>(table.programs.size());
    out.physical_columns =
        kFamilyVmCandidateColumnsV1;

    std::string why;
    if (!IsPowerOfTwo(original_trace_rows) ||
        !cb::ValidateProgramTable(table, &why) ||
        table.current_width != table.next_width ||
        table.programs.size() >
            kFamilyVmRegisterIndexStrideV1) {
        out.note =
            "stage3:family_vm:invalid_statement:" + why;
        return out;
    }

    out.program_table_commitment =
        cb::CommitProgramTable(table);
    out.program_table_alg_hash =
        cb::CommitProgramTableAlgHash(table);
    if (out.program_table_commitment.IsNull() ||
        out.program_table_alg_hash ==
            alg_hash::Digest{}) {
        out.note =
            "stage3:family_vm:null_program_commitment";
        return out;
    }

    out.source_load_multiplicity.assign(
        table.current_width, 0);
    out.program_inventory.reserve(
        table.programs.size());

    uint64_t instruction_count = 0;
    uint64_t source_reads_per_original_row = 0;
    uint64_t register_reads_per_original_row = 0;
    uint64_t terminal_checks = 0;
    for (const auto& program : table.programs) {
        if (program.instructions.size() >
            kFamilyVmRegisterIndexStrideV1) {
            out.note =
                "stage3:family_vm:register_key_pc_range";
            return out;
        }
        FamilyVmProgramInventoryV1 inventory;
        inventory.constraint_ordinal =
            program.constraint_ordinal;
        inventory.kind = program.kind;
        inventory.instructions =
            static_cast<uint32_t>(
                program.instructions.size());
        inventory.terminal_checks =
            TerminalChecks(
                program.kind,
                original_trace_rows);
        inventory.register_use_multiplicity.assign(
            program.instructions.size(), 0);

        for (uint32_t pc = 0;
             pc < program.instructions.size();
             ++pc) {
            const auto& instruction =
                program.instructions[pc];
            switch (instruction.opcode) {
            case cb::Opcode::Current:
                ++inventory.current_loads;
                ++out.source_load_multiplicity[
                    instruction.lhs];
                break;
            case cb::Opcode::Next:
                ++inventory.next_loads;
                ++out.source_load_multiplicity[
                    instruction.lhs];
                break;
            case cb::Opcode::Add:
            case cb::Opcode::Sub:
            case cb::Opcode::Mul:
                inventory.register_reads += 2;
                ++inventory.register_use_multiplicity[
                    instruction.lhs];
                ++inventory.register_use_multiplicity[
                    instruction.rhs];
                break;
            case cb::Opcode::Constant:
                break;
            }
        }
        instruction_count +=
            inventory.instructions;
        source_reads_per_original_row +=
            uint64_t{inventory.current_loads} +
            inventory.next_loads;
        register_reads_per_original_row +=
            inventory.register_reads;
        terminal_checks +=
            inventory.terminal_checks;
        out.program_inventory.push_back(
            std::move(inventory));
    }
    if (instruction_count >
        std::numeric_limits<uint32_t>::max()) {
        out.note =
            "stage3:family_vm:instruction_count";
        return out;
    }

    out.instructions_per_original_row =
        static_cast<uint32_t>(instruction_count);
    out.source_memory_rows =
        uint64_t{original_trace_rows} *
        table.current_width;
    out.instruction_execution_rows =
        uint64_t{original_trace_rows} *
        instruction_count;
    if (out.source_memory_rows >
            std::numeric_limits<uint64_t>::max() -
                out.instruction_execution_rows) {
        out.note =
            "stage3:family_vm:row_overflow";
        return out;
    }
    out.logical_vertical_rows =
        out.source_memory_rows +
        out.instruction_execution_rows;
    out.padded_vertical_rows =
        NextPowerOfTwo(out.logical_vertical_rows);
    if (out.padded_vertical_rows == 0 ||
        out.padded_vertical_rows >
            (uint64_t{1} <<
             kRCFriMaxColumnLog2)) {
        out.note =
            "stage3:family_vm:padded_rows";
        return out;
    }

    out.source_read_events =
        uint64_t{original_trace_rows} *
        source_reads_per_original_row;
    uint64_t source_definition_weight = 0;
    for (uint32_t multiplicity :
         out.source_load_multiplicity) {
        source_definition_weight +=
            uint64_t{original_trace_rows} *
            multiplicity;
    }
    out.source_definition_weight =
        source_definition_weight;

    out.register_read_events =
        uint64_t{original_trace_rows} *
        register_reads_per_original_row;
    uint64_t register_definition_weight = 0;
    for (const auto& program :
         out.program_inventory) {
        for (uint32_t multiplicity :
             program.register_use_multiplicity) {
            register_definition_weight +=
                uint64_t{original_trace_rows} *
                multiplicity;
        }
    }
    out.register_definition_weight =
        register_definition_weight;
    out.terminal_checks = terminal_checks;

    out.direct_query_value_bytes =
        uint64_t{kFamilyVmQueriesV1} *
        out.physical_columns * 24U;
    out.coefficient_cap =
        kFamilyVmCoefficientCapV1;
    out.minimum_vm_segments =
        static_cast<uint32_t>(
            (out.logical_vertical_rows +
             out.coefficient_cap - 1) /
            out.coefficient_cap);

    out.canonical_program_table = true;
    out.exact_row_program_pc_schedule = true;
    out.cyclic_next_row_semantics = true;
    out.source_read_multiset_balanced =
        out.source_read_events ==
        out.source_definition_weight;
    out.register_read_multiset_balanced =
        out.register_read_events ==
        out.register_definition_weight;
    out.register_key_encoding_injective =
        table.programs.size() <=
            kFamilyVmRegisterIndexStrideV1 &&
        std::all_of(
            table.programs.begin(),
            table.programs.end(),
            [](const cb::Program& program) {
                return
                    program.instructions.size() <=
                    kFamilyVmRegisterIndexStrideV1;
            });
    out.selector_terminal_schedule_exact = true;
    out.dual_lanes_after_r0 = true;
    out.original_width_moved_to_trace_length = true;
    out.fixed_width_under_512 =
        out.physical_columns <= 512;
    out.fits_single_split_rap =
        out.padded_vertical_rows <=
        out.coefficient_cap;
    out.split_rap_family_proof_executable = false;
    out.production_authority_ready = false;
    out.schedule_commitment = CommitPlan(out);
    out.valid =
        out.source_read_multiset_balanced &&
        out.register_read_multiset_balanced &&
        out.register_key_encoding_injective &&
        out.fixed_width_under_512 &&
        !out.schedule_commitment.IsNull();
    out.note = out.valid
        ? "stage3:family_vm:canonical_vertical_plan;"
          "split_rap_execution_pending"
        : "stage3:family_vm:accounting_failure";
    return out;
}

bool ValidateFamilyVmPlanV1(
    const cb::ProgramTable& table,
    const FamilyVmPlanV1& plan,
    std::string* why)
{
    const FamilyVmPlanV1 expected =
        BuildFamilyVmPlanV1(
            table, plan.original_trace_rows);
    if (!expected.valid || plan != expected) {
        if (why != nullptr) {
            *why =
                "stage3:family_vm:plan_mismatch";
        }
        return false;
    }
    return true;
}

namespace {

namespace aq = air_quotient;
namespace gf = gkr_field;
using gf::Fp3;

static_assert(
    gf::kP >
    (uint64_t{1} << 2 *
        kFamilyVmRegisterIndexBitsV1));

constexpr char FAMILY_VM_FS_DOMAIN[] =
    "BTX_RC_STAGE3_FAMILY_VM_LOOKUP_FS_V1";

enum VmColumn : uint32_t {
    SOURCE_VALUE = 0,
    RECORD_TYPE,
    VERTICAL_INDEX,
    IS_SOURCE,
    IS_EXEC,
    ORIGINAL_ROW,
    PROGRAM,
    PC,
    INSTRUCTION_ORDINAL,
    AIR_KIND,
    PROGRAM_TERMINAL_INSTRUCTION,
    OPCODE,
    LHS,
    RHS,
    CONSTANT,
    SOURCE_LOOKUP_ROW,
    IS_CURRENT,
    IS_NEXT,
    IS_CONSTANT,
    IS_ADD,
    IS_SUB,
    IS_MUL,
    TERMINAL_ACTIVE,
    SOURCE_DEFINITION_MULTIPLICITY,
    REGISTER_DEFINITION_MULTIPLICITY,
    SOURCE_COLUMN_LAST,
    SOURCE_COLUMN_DELTA_INVERSE,
    ORIGINAL_ROW_LAST,
    ORIGINAL_ROW_DELTA_INVERSE,
    ORIGINAL_ROW_ZERO,
    ORIGINAL_ROW_ZERO_INVERSE,
    INSTRUCTION_LAST,
    INSTRUCTION_DELTA_INVERSE,
    RESULT,
    OPERAND_A,
    OPERAND_B,
    RESIDUAL,
    SOURCE_INVERSE_1,
    SOURCE_INVERSE_2,
    REGISTER_DEFINITION_INVERSE_1,
    REGISTER_DEFINITION_INVERSE_2,
    REGISTER_LHS_INVERSE_1,
    REGISTER_LHS_INVERSE_2,
    REGISTER_RHS_INVERSE_1,
    REGISTER_RHS_INVERSE_2,
    METADATA_INVERSE_1,
    METADATA_INVERSE_2,
    SOURCE_RUNNING_1,
    SOURCE_RUNNING_2,
    REGISTER_RUNNING_1,
    REGISTER_RUNNING_2,
    METADATA_RUNNING_1,
    METADATA_RUNNING_2,
    VM_COLUMNS,
};

static_assert(VM_COLUMNS == kFamilyVmExecutableColumnsV1);

constexpr uint32_t FIRST_LOOKUP_COLUMN = SOURCE_INVERSE_1;

Fp3 U(uint64_t value)
{
    return gf::FromU64_3(value);
}

bool Canonical(const Fp3& value)
{
    return value.c0 < gf::kP &&
        value.c1 < gf::kP &&
        value.c2 < gf::kP;
}

bool Nonzero(const Fp3& value)
{
    return Canonical(value) &&
        !gf::IsZero(value);
}

bool SameDigest(
    const alg_hash::Digest& a,
    const alg_hash::Digest& b)
{
    for (uint32_t i = 0; i < a.size(); ++i) {
        if (gf::Canonical(a[i]) !=
            gf::Canonical(b[i])) {
            return false;
        }
    }
    return true;
}

bool LookupChallengesValid(
    const FamilyVmLookupChallengesV1& challenges)
{
    return
        Nonzero(challenges.gamma1) &&
        Nonzero(challenges.gamma2) &&
        Nonzero(challenges.alpha1) &&
        Nonzero(challenges.alpha2) &&
        !gf::Eq(
            challenges.gamma1,
            challenges.gamma2) &&
        !gf::Eq(
            challenges.alpha1,
            challenges.alpha2);
}

uint256 LookupEpoch(
    const FamilyVmPublicInputsV1& public_inputs,
    const uint256& public_fs_seed)
{
    if (public_fs_seed.IsNull() ||
        public_inputs.public_statement_binding.IsNull() ||
        public_inputs.program_table_commitment.IsNull() ||
        public_inputs.schedule_commitment.IsNull() ||
        public_inputs.phase0_row_group_root.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << FAMILY_VM_FS_DOMAIN
         << public_fs_seed
         << public_inputs.version
         << public_inputs.program_id
         << public_inputs.program_registry_alg_root
         << public_inputs.public_statement_binding
         << public_inputs.program_table_commitment;
    for (const auto& limb :
         public_inputs.program_table_alg_hash) {
        hash << gf::Canonical(limb);
    }
    hash << public_inputs.schedule_commitment
         << public_inputs.phase0_row_group_root
         << public_inputs.original_trace_rows
         << public_inputs.vertical_trace_rows
         << public_inputs.vm_columns;
    return hash.GetHash();
}

bool UniformChallenge(
    const uint256& epoch,
    const char* label,
    uint32_t attempt,
    Fp3& out)
{
    std::array<
        uint64_t,
        kRCFri3AlgDualUniformWords> words{};
    for (uint32_t block = 0;
         block <
             kRCFri3AlgDualUniformHashBlocks;
         ++block) {
        HashWriter hash;
        hash << FAMILY_VM_FS_DOMAIN
             << epoch
             << std::string(label)
             << attempt
             << block;
        const uint256 digest = hash.GetHash();
        for (uint32_t word = 0;
             word < 4;
             ++word) {
            words[4 * block + word] =
                digest.GetUint64(
                    static_cast<int>(word));
        }
    }
    const auto selected =
        Fri3AlgSelectUniformFp3Words(words);
    if (!selected.has_value()) return false;
    out = *selected;
    return true;
}

bool DeriveLookupChallenges(
    const FamilyVmPublicInputsV1& public_inputs,
    const uint256& public_fs_seed,
    FamilyVmLookupChallengesV1& out)
{
    const uint256 epoch =
        LookupEpoch(public_inputs, public_fs_seed);
    if (epoch.IsNull()) return false;
    for (uint32_t attempt = 0;
         attempt < 32;
         ++attempt) {
        FamilyVmLookupChallengesV1 candidate;
        if (UniformChallenge(
                epoch, "gamma1",
                attempt, candidate.gamma1) &&
            UniformChallenge(
                epoch, "gamma2",
                attempt, candidate.gamma2) &&
            UniformChallenge(
                epoch, "alpha1",
                attempt, candidate.alpha1) &&
            UniformChallenge(
                epoch, "alpha2",
                attempt, candidate.alpha2) &&
            LookupChallengesValid(candidate)) {
            out = candidate;
            return true;
        }
    }
    return false;
}

Fp3 Compress4(
    const Fp3& tag,
    const Fp3& a,
    const Fp3& b,
    const Fp3& value,
    const Fp3& gamma)
{
    Fp3 out = tag;
    Fp3 power = gamma;
    out = gf::Add(out, gf::Mul(power, a));
    power = gf::Mul(power, gamma);
    out = gf::Add(out, gf::Mul(power, b));
    power = gf::Mul(power, gamma);
    return gf::Add(
        out, gf::Mul(power, value));
}

Fp3 CompressTuple(
    const Fp3& tag,
    const std::vector<Fp3>& values,
    const Fp3& gamma)
{
    Fp3 out = tag;
    Fp3 power = gamma;
    for (const Fp3& value : values) {
        out = gf::Add(
            out, gf::Mul(power, value));
        power = gf::Mul(power, gamma);
    }
    return out;
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
    cs.constraints.push_back(
        {name, kind, degree,
         std::move(eval)});
}

Fp3 SourceKey(
    const std::vector<Fp3>& row,
    const Fp3& gamma)
{
    const Fp3 value = gf::Add(
        row[SOURCE_VALUE], row[RESULT]);
    return Compress4(
        U(1), row[SOURCE_LOOKUP_ROW],
        row[LHS], value, gamma);
}

Fp3 RegisterDefinitionKey(
    const std::vector<Fp3>& row,
    const Fp3& gamma)
{
    return Compress4(
        U(2), row[ORIGINAL_ROW],
        gf::Add(
            gf::Mul(
                row[PROGRAM],
                U(kFamilyVmRegisterIndexStrideV1)),
            row[PC]),
        row[RESULT], gamma);
}

Fp3 RegisterReadKey(
    const std::vector<Fp3>& row,
    bool rhs,
    const Fp3& gamma)
{
    return Compress4(
        U(2), row[ORIGINAL_ROW],
        gf::Add(
            gf::Mul(
                row[PROGRAM],
                U(kFamilyVmRegisterIndexStrideV1)),
            rhs ? row[RHS] : row[LHS]),
        rhs ? row[OPERAND_B] :
              row[OPERAND_A],
        gamma);
}

Fp3 MetadataKey(
    const std::vector<Fp3>& row,
    const Fp3& gamma)
{
    const Fp3 source = CompressTuple(
        U(4),
        {row[LHS],
         row[
             SOURCE_DEFINITION_MULTIPLICITY]},
        gamma);
    const Fp3 instruction = CompressTuple(
        U(3),
        {row[INSTRUCTION_ORDINAL],
         row[PROGRAM],
         row[PC],
         row[AIR_KIND],
         row[
             PROGRAM_TERMINAL_INSTRUCTION],
         row[OPCODE],
         row[LHS],
         row[RHS],
         row[CONSTANT],
         row[
             REGISTER_DEFINITION_MULTIPLICITY]},
        gamma);
    return gf::Add(
        gf::Mul(row[IS_SOURCE], source),
        gf::Mul(row[IS_EXEC], instruction));
}

Fp3 CanonicalMetadataTerminal(
    const cb::ProgramTable& table,
    const FamilyVmPlanV1& plan,
    const Fp3& gamma,
    const Fp3& alpha,
    bool& pole)
{
    Fp3 sum = Fp3::Zero();
    const Fp3 repetitions =
        U(plan.original_trace_rows);
    for (uint32_t column = 0;
         column < table.current_width;
         ++column) {
        const Fp3 key = CompressTuple(
            U(4),
            {U(column),
             U(plan.source_load_multiplicity[
                 column])},
            gamma);
        const Fp3 denominator =
            gf::Sub(alpha, key);
        if (gf::IsZero(denominator)) {
            pole = true;
            return Fp3::Zero();
        }
        sum = gf::Add(
            sum,
            gf::Mul(
                repetitions,
                gf::Inv(denominator)));
    }
    uint32_t ordinal = 0;
    for (uint32_t program_index = 0;
         program_index < table.programs.size();
         ++program_index) {
        const auto& program =
            table.programs[program_index];
        for (uint32_t pc = 0;
             pc < program.instructions.size();
             ++pc, ++ordinal) {
            const auto& instruction =
                program.instructions[pc];
            const Fp3 key = CompressTuple(
                U(3),
                {U(ordinal),
                 U(program_index),
                 U(pc),
                 U(static_cast<uint8_t>(
                     program.kind)),
                 U(pc + 1 ==
                         program.instructions.size()
                     ? 1
                     : 0),
                 U(static_cast<uint8_t>(
                     instruction.opcode)),
                 U(instruction.lhs),
                 U(instruction.rhs),
                 instruction.constant,
                 U(plan.program_inventory[
                     program_index]
                       .register_use_multiplicity[
                           pc])},
                gamma);
            const Fp3 denominator =
                gf::Sub(alpha, key);
            if (gf::IsZero(denominator)) {
                pole = true;
                return Fp3::Zero();
            }
            sum = gf::Add(
                sum,
                gf::Mul(
                    repetitions,
                    gf::Inv(denominator)));
        }
    }
    return sum;
}

std::vector<uint32_t> Phase0Columns()
{
    std::vector<uint32_t> out;
    out.reserve(FIRST_LOOKUP_COLUMN);
    for (uint32_t column = 0;
         column < FIRST_LOOKUP_COLUMN;
         ++column) {
        out.push_back(column);
    }
    return out;
}

bool TerminalActive(
    aq::AirKind kind,
    uint32_t row,
    uint32_t rows)
{
    switch (kind) {
    case aq::AirKind::kEverywhere:
        return true;
    case aq::AirKind::kTransition:
        return row + 1 < rows;
    case aq::AirKind::kFirstRow:
        return row == 0;
    case aq::AirKind::kLastRow:
        return row + 1 == rows;
    }
    return false;
}

Fp3 KindIndicator(
    const Fp3& value,
    uint32_t selected)
{
    Fp3 numerator = Fp3::One();
    Fp3 denominator = Fp3::One();
    for (uint32_t candidate = 0;
         candidate < 4;
         ++candidate) {
        if (candidate == selected) continue;
        numerator = gf::Mul(
            numerator,
            gf::Sub(value, U(candidate)));
        denominator = gf::Mul(
            denominator,
            gf::Sub(
                U(selected), U(candidate)));
    }
    return gf::Mul(
        numerator, gf::Inv(denominator));
}

aq::AirConstraintSystem<Fp3> BuildVmConstraintSystem(
    const cb::ProgramTable& table,
    const FamilyVmPlanV1& plan,
    const FamilyVmLookupChallengesV1& challenges,
    const uint256& expected_phase0_root)
{
    aq::AirConstraintSystem<Fp3> cs;
    if (!plan.valid ||
        !plan.fits_single_split_rap ||
        (LookupChallengesValid(challenges) ==
         false)) {
        return cs;
    }
    cs.n_rows =
        static_cast<uint32_t>(
            plan.padded_vertical_rows);
    cs.n_columns = VM_COLUMNS;
    if (!expected_phase0_root.IsNull()) {
        cs.preprocessed_row_group_roots.push_back({
            1,
            aq::AirPreprocessedRowGroupRole::kR0,
            Phase0Columns(),
            expected_phase0_root,
        });
    }

    const Fp3 last_vertical =
        U(plan.padded_vertical_rows - 1);
    const Fp3 last_source_column =
        U(table.current_width - 1);
    const Fp3 last_original_row =
        U(plan.original_trace_rows - 1);
    const Fp3 last_instruction =
        U(plan.instructions_per_original_row - 1);
    AddConstraint(
        cs, "family_vm.type_source_boolean",
        aq::AirKind::kEverywhere, 2,
        [](const auto& row, const auto&) {
            return gf::Mul(
                row[IS_SOURCE],
                gf::Sub(
                    row[IS_SOURCE],
                    Fp3::One()));
        });
    AddConstraint(
        cs, "family_vm.type_exec_boolean",
        aq::AirKind::kEverywhere, 2,
        [](const auto& row, const auto&) {
            return gf::Mul(
                row[IS_EXEC],
                gf::Sub(
                    row[IS_EXEC],
                    Fp3::One()));
        });
    AddConstraint(
        cs, "family_vm.type_disjoint",
        aq::AirKind::kEverywhere, 2,
        [](const auto& row, const auto&) {
            return gf::Mul(
                row[IS_SOURCE],
                row[IS_EXEC]);
        });
    AddConstraint(
        cs, "family_vm.record_type",
        aq::AirKind::kEverywhere, 1,
        [](const auto& row, const auto&) {
            return gf::Sub(
                row[RECORD_TYPE],
                gf::Add(
                    row[IS_SOURCE],
                    gf::Mul(
                        U(2), row[IS_EXEC])));
        });
    AddConstraint(
        cs, "family_vm.vertical_first",
        aq::AirKind::kFirstRow, 1,
        [](const auto& row, const auto&) {
            return row[VERTICAL_INDEX];
        });
    AddConstraint(
        cs, "family_vm.vertical_transition",
        aq::AirKind::kTransition, 1,
        [](const auto& row,
           const auto& next) {
            return gf::Sub(
                next[VERTICAL_INDEX],
                gf::Add(
                    row[VERTICAL_INDEX],
                    Fp3::One()));
        });
    AddConstraint(
        cs, "family_vm.vertical_last",
        aq::AirKind::kLastRow, 1,
        [last_vertical](
            const auto& row, const auto&) {
            return gf::Sub(
                row[VERTICAL_INDEX],
                last_vertical);
        });
    AddConstraint(
        cs, "family_vm.schedule_first_source",
        aq::AirKind::kFirstRow, 1,
        [](const auto& row, const auto&) {
            return gf::Sub(
                row[IS_SOURCE],
                Fp3::One());
        });
    AddConstraint(
        cs, "family_vm.schedule_first_row",
        aq::AirKind::kFirstRow, 1,
        [](const auto& row, const auto&) {
            return row[ORIGINAL_ROW];
        });
    AddConstraint(
        cs, "family_vm.schedule_first_column",
        aq::AirKind::kFirstRow, 1,
        [](const auto& row, const auto&) {
            return row[LHS];
        });

    const auto add_zero_test =
        [&](const char* name,
            uint32_t active_column,
            uint32_t value_column,
            Fp3 expected,
            uint32_t flag_column,
            uint32_t inverse_column) {
            AddConstraint(
                cs, name,
                aq::AirKind::kEverywhere, 2,
                [flag_column](
                    const auto& row,
                    const auto&) {
                    return gf::Mul(
                        row[flag_column],
                        gf::Sub(
                            row[flag_column],
                            Fp3::One()));
                });
            AddConstraint(
                cs, "family_vm.zero_test_equal",
                aq::AirKind::kEverywhere, 3,
                [active_column, value_column,
                 expected, flag_column](
                    const auto& row,
                    const auto&) {
                    return gf::Mul(
                        row[active_column],
                        gf::Mul(
                            gf::Sub(
                                row[value_column],
                                expected),
                            row[flag_column]));
                });
            AddConstraint(
                cs, "family_vm.zero_test_inverse",
                aq::AirKind::kEverywhere, 3,
                [active_column, value_column,
                 expected, flag_column,
                 inverse_column](
                    const auto& row,
                    const auto&) {
                    const Fp3 one_minus_flag =
                        gf::Sub(
                            Fp3::One(),
                            row[flag_column]);
                    return gf::Mul(
                        row[active_column],
                        gf::Sub(
                            gf::Mul(
                                gf::Sub(
                                    row[value_column],
                                    expected),
                                row[inverse_column]),
                            one_minus_flag));
                });
            AddConstraint(
                cs, "family_vm.zero_test_flag_inactive",
                aq::AirKind::kEverywhere, 2,
                [active_column, flag_column](
                    const auto& row,
                    const auto&) {
                    return gf::Mul(
                        gf::Sub(
                            Fp3::One(),
                            row[active_column]),
                        row[flag_column]);
                });
            AddConstraint(
                cs, "family_vm.zero_test_inverse_inactive",
                aq::AirKind::kEverywhere, 2,
                [active_column, inverse_column](
                    const auto& row,
                    const auto&) {
                    return gf::Mul(
                        gf::Sub(
                            Fp3::One(),
                            row[active_column]),
                        row[inverse_column]);
                });
        };
    add_zero_test(
        "family_vm.source_column_last_boolean",
        IS_SOURCE, LHS, last_source_column,
        SOURCE_COLUMN_LAST,
        SOURCE_COLUMN_DELTA_INVERSE);
    // Original-row last/zero flags are active for both source and execute
    // rows. A dedicated active column is unnecessary because the two type
    // bits are disjoint, so use a tiny derived-column constraint adapter.
    AddConstraint(
        cs, "family_vm.original_last_boolean",
        aq::AirKind::kEverywhere, 2,
        [](const auto& row, const auto&) {
            return gf::Mul(
                row[ORIGINAL_ROW_LAST],
                gf::Sub(
                    row[ORIGINAL_ROW_LAST],
                    Fp3::One()));
        });
    AddConstraint(
        cs, "family_vm.original_last_equal",
        aq::AirKind::kEverywhere, 3,
        [last_original_row](
            const auto& row,
            const auto&) {
            const Fp3 active = gf::Add(
                row[IS_SOURCE],
                row[IS_EXEC]);
            return gf::Mul(
                active,
                gf::Mul(
                    gf::Sub(
                        row[ORIGINAL_ROW],
                        last_original_row),
                    row[ORIGINAL_ROW_LAST]));
        });
    AddConstraint(
        cs, "family_vm.original_last_inverse",
        aq::AirKind::kEverywhere, 3,
        [last_original_row](
            const auto& row,
            const auto&) {
            const Fp3 active = gf::Add(
                row[IS_SOURCE],
                row[IS_EXEC]);
            return gf::Mul(
                active,
                gf::Sub(
                    gf::Mul(
                        gf::Sub(
                            row[ORIGINAL_ROW],
                            last_original_row),
                        row[
                            ORIGINAL_ROW_DELTA_INVERSE]),
                    gf::Sub(
                        Fp3::One(),
                        row[ORIGINAL_ROW_LAST])));
        });
    AddConstraint(
        cs, "family_vm.original_last_inactive",
        aq::AirKind::kEverywhere, 2,
        [](const auto& row, const auto&) {
            const Fp3 inactive = gf::Sub(
                Fp3::One(),
                gf::Add(
                    row[IS_SOURCE],
                    row[IS_EXEC]));
            return gf::Mul(
                inactive,
                gf::Add(
                    row[ORIGINAL_ROW_LAST],
                    row[
                        ORIGINAL_ROW_DELTA_INVERSE]));
        });
    AddConstraint(
        cs, "family_vm.original_zero_boolean",
        aq::AirKind::kEverywhere, 2,
        [](const auto& row, const auto&) {
            return gf::Mul(
                row[ORIGINAL_ROW_ZERO],
                gf::Sub(
                    row[ORIGINAL_ROW_ZERO],
                    Fp3::One()));
        });
    AddConstraint(
        cs, "family_vm.original_zero_equal",
        aq::AirKind::kEverywhere, 3,
        [](const auto& row, const auto&) {
            const Fp3 active = gf::Add(
                row[IS_SOURCE],
                row[IS_EXEC]);
            return gf::Mul(
                active,
                gf::Mul(
                    row[ORIGINAL_ROW],
                    row[ORIGINAL_ROW_ZERO]));
        });
    AddConstraint(
        cs, "family_vm.original_zero_inverse",
        aq::AirKind::kEverywhere, 3,
        [](const auto& row, const auto&) {
            const Fp3 active = gf::Add(
                row[IS_SOURCE],
                row[IS_EXEC]);
            return gf::Mul(
                active,
                gf::Sub(
                    gf::Mul(
                        row[ORIGINAL_ROW],
                        row[
                            ORIGINAL_ROW_ZERO_INVERSE]),
                    gf::Sub(
                        Fp3::One(),
                        row[ORIGINAL_ROW_ZERO])));
        });
    AddConstraint(
        cs, "family_vm.original_zero_inactive",
        aq::AirKind::kEverywhere, 2,
        [](const auto& row, const auto&) {
            const Fp3 inactive = gf::Sub(
                Fp3::One(),
                gf::Add(
                    row[IS_SOURCE],
                    row[IS_EXEC]));
            return gf::Mul(
                inactive,
                gf::Add(
                    row[ORIGINAL_ROW_ZERO],
                    row[
                        ORIGINAL_ROW_ZERO_INVERSE]));
        });
    add_zero_test(
        "family_vm.instruction_last_boolean",
        IS_EXEC, INSTRUCTION_ORDINAL,
        last_instruction,
        INSTRUCTION_LAST,
        INSTRUCTION_DELTA_INVERSE);

    const auto add_transition =
        [&](const char* name,
            uint32_t degree,
            auto eval) {
            AddConstraint(
                cs, name,
                aq::AirKind::kTransition,
                degree, eval);
        };
    add_transition(
        "family_vm.source_column_step", 3,
        [](const auto& row,
           const auto& next) {
            return gf::Mul(
                gf::Mul(
                    row[IS_SOURCE],
                    gf::Sub(
                        Fp3::One(),
                        row[SOURCE_COLUMN_LAST])),
                gf::Sub(
                    next[LHS],
                    gf::Add(
                        row[LHS],
                        Fp3::One())));
        });
    add_transition(
        "family_vm.source_column_same_row", 3,
        [](const auto& row,
           const auto& next) {
            return gf::Mul(
                gf::Mul(
                    row[IS_SOURCE],
                    gf::Sub(
                        Fp3::One(),
                        row[SOURCE_COLUMN_LAST])),
                gf::Sub(
                    next[ORIGINAL_ROW],
                    row[ORIGINAL_ROW]));
        });
    add_transition(
        "family_vm.source_column_next_type", 3,
        [](const auto& row,
           const auto& next) {
            const Fp3 not_final =
                gf::Sub(
                    Fp3::One(),
                    gf::Mul(
                        row[SOURCE_COLUMN_LAST],
                        row[ORIGINAL_ROW_LAST]));
            return gf::Mul(
                gf::Mul(
                    row[IS_SOURCE],
                    not_final),
                gf::Sub(
                    next[IS_SOURCE],
                    Fp3::One()));
        });
    add_transition(
        "family_vm.source_row_step", 4,
        [](const auto& row,
           const auto& next) {
            const Fp3 advance = gf::Mul(
                row[SOURCE_COLUMN_LAST],
                gf::Sub(
                    Fp3::One(),
                    row[ORIGINAL_ROW_LAST]));
            return gf::Mul(
                row[IS_SOURCE],
                gf::Mul(
                    advance,
                    gf::Sub(
                        next[ORIGINAL_ROW],
                        gf::Add(
                            row[ORIGINAL_ROW],
                            Fp3::One()))));
        });
    add_transition(
        "family_vm.source_row_reset_column", 4,
        [](const auto& row,
           const auto& next) {
            const Fp3 advance = gf::Mul(
                row[SOURCE_COLUMN_LAST],
                gf::Sub(
                    Fp3::One(),
                    row[ORIGINAL_ROW_LAST]));
            return gf::Mul(
                row[IS_SOURCE],
                gf::Mul(
                    advance, next[LHS]));
        });
    add_transition(
        "family_vm.source_to_exec", 4,
        [](const auto& row,
           const auto& next) {
            const Fp3 finish = gf::Mul(
                row[IS_SOURCE],
                gf::Mul(
                    row[SOURCE_COLUMN_LAST],
                    row[ORIGINAL_ROW_LAST]));
            return gf::Mul(
                finish,
                gf::Sub(
                    next[IS_EXEC],
                    Fp3::One()));
        });
    add_transition(
        "family_vm.source_to_exec_row", 4,
        [](const auto& row,
           const auto& next) {
            const Fp3 finish = gf::Mul(
                row[IS_SOURCE],
                gf::Mul(
                    row[SOURCE_COLUMN_LAST],
                    row[ORIGINAL_ROW_LAST]));
            return gf::Mul(
                finish, next[ORIGINAL_ROW]);
        });
    add_transition(
        "family_vm.source_to_exec_instruction", 4,
        [](const auto& row,
           const auto& next) {
            const Fp3 finish = gf::Mul(
                row[IS_SOURCE],
                gf::Mul(
                    row[SOURCE_COLUMN_LAST],
                    row[ORIGINAL_ROW_LAST]));
            return gf::Mul(
                finish,
                next[INSTRUCTION_ORDINAL]);
        });
    add_transition(
        "family_vm.instruction_step", 3,
        [](const auto& row,
           const auto& next) {
            return gf::Mul(
                gf::Mul(
                    row[IS_EXEC],
                    gf::Sub(
                        Fp3::One(),
                        row[INSTRUCTION_LAST])),
                gf::Sub(
                    next[INSTRUCTION_ORDINAL],
                    gf::Add(
                        row[INSTRUCTION_ORDINAL],
                        Fp3::One())));
        });
    add_transition(
        "family_vm.instruction_same_row", 3,
        [](const auto& row,
           const auto& next) {
            return gf::Mul(
                gf::Mul(
                    row[IS_EXEC],
                    gf::Sub(
                        Fp3::One(),
                        row[INSTRUCTION_LAST])),
                gf::Sub(
                    next[ORIGINAL_ROW],
                    row[ORIGINAL_ROW]));
        });
    add_transition(
        "family_vm.instruction_next_type", 3,
        [](const auto& row,
           const auto& next) {
            const Fp3 continues =
                gf::Sub(
                    Fp3::One(),
                    gf::Mul(
                        row[INSTRUCTION_LAST],
                        row[ORIGINAL_ROW_LAST]));
            return gf::Mul(
                gf::Mul(
                    row[IS_EXEC],
                    continues),
                gf::Sub(
                    next[IS_EXEC],
                    Fp3::One()));
        });
    add_transition(
        "family_vm.instruction_row_step", 4,
        [](const auto& row,
           const auto& next) {
            const Fp3 advance = gf::Mul(
                row[INSTRUCTION_LAST],
                gf::Sub(
                    Fp3::One(),
                    row[ORIGINAL_ROW_LAST]));
            return gf::Mul(
                row[IS_EXEC],
                gf::Mul(
                    advance,
                    gf::Sub(
                        next[ORIGINAL_ROW],
                        gf::Add(
                            row[ORIGINAL_ROW],
                            Fp3::One()))));
        });
    add_transition(
        "family_vm.instruction_row_reset", 4,
        [](const auto& row,
           const auto& next) {
            const Fp3 advance = gf::Mul(
                row[INSTRUCTION_LAST],
                gf::Sub(
                    Fp3::One(),
                    row[ORIGINAL_ROW_LAST]));
            return gf::Mul(
                row[IS_EXEC],
                gf::Mul(
                    advance,
                    next[INSTRUCTION_ORDINAL]));
        });
    add_transition(
        "family_vm.exec_to_padding", 4,
        [](const auto& row,
           const auto& next) {
            const Fp3 finish = gf::Mul(
                row[IS_EXEC],
                gf::Mul(
                    row[INSTRUCTION_LAST],
                    row[ORIGINAL_ROW_LAST]));
            return gf::Mul(
                finish,
                gf::Add(
                    next[IS_SOURCE],
                    next[IS_EXEC]));
        });
    add_transition(
        "family_vm.padding_absorbing", 2,
        [](const auto& row,
           const auto& next) {
            const Fp3 padding = gf::Sub(
                Fp3::One(),
                gf::Add(
                    row[IS_SOURCE],
                    row[IS_EXEC]));
            return gf::Mul(
                padding,
                gf::Add(
                    next[IS_SOURCE],
                    next[IS_EXEC]));
        });

    AddConstraint(
        cs, "family_vm.source_value_domain",
        aq::AirKind::kEverywhere, 2,
        [](const auto& row, const auto&) {
            return gf::Mul(
                gf::Sub(
                    Fp3::One(),
                    row[IS_SOURCE]),
                row[SOURCE_VALUE]);
        });
    for (uint32_t column :
         {RESULT, OPERAND_A, OPERAND_B,
          RESIDUAL}) {
        AddConstraint(
            cs, "family_vm.exec_value_domain",
            aq::AirKind::kEverywhere, 2,
            [column](
                const auto& row,
                const auto&) {
                return gf::Mul(
                    gf::Sub(
                        Fp3::One(),
                        row[IS_EXEC]),
                    row[column]);
            });
    }
    AddConstraint(
        cs, "family_vm.opcode_partition",
        aq::AirKind::kEverywhere, 1,
        [](const auto& row, const auto&) {
            Fp3 sum = Fp3::Zero();
            for (uint32_t column =
                     IS_CURRENT;
                 column <= IS_MUL;
                 ++column) {
                sum = gf::Add(
                    sum, row[column]);
            }
            return gf::Sub(
                sum, row[IS_EXEC]);
        });
    for (uint32_t offset = 0;
         offset < 6;
         ++offset) {
        const uint32_t selector =
            IS_CURRENT + offset;
        const Fp3 opcode =
            U(static_cast<uint8_t>(
                cb::Opcode::Current) +
              offset);
        AddConstraint(
            cs, "family_vm.opcode_selector",
            aq::AirKind::kEverywhere, 2,
            [selector, opcode](
                const auto& row,
                const auto&) {
                return gf::Mul(
                    row[selector],
                    gf::Sub(
                        row[OPCODE], opcode));
            });
    }
    AddConstraint(
        cs, "family_vm.program_terminal_boolean",
        aq::AirKind::kEverywhere, 2,
        [](const auto& row, const auto&) {
            return gf::Mul(
                row[
                    PROGRAM_TERMINAL_INSTRUCTION],
                gf::Sub(
                    row[
                        PROGRAM_TERMINAL_INSTRUCTION],
                    Fp3::One()));
        });
    AddConstraint(
        cs, "family_vm.air_kind_range",
        aq::AirKind::kEverywhere, 4,
        [](const auto& row, const auto&) {
            Fp3 product = Fp3::One();
            for (uint32_t kind = 0;
                 kind < 4;
                 ++kind) {
                product = gf::Mul(
                    product,
                    gf::Sub(
                        row[AIR_KIND],
                        U(kind)));
            }
            return gf::Mul(
                row[IS_EXEC], product);
        });
    AddConstraint(
        cs, "family_vm.terminal_schedule",
        aq::AirKind::kEverywhere, 6,
        [](const auto& row, const auto&) {
            const Fp3 everywhere =
                KindIndicator(
                    row[AIR_KIND], 0);
            const Fp3 transition =
                KindIndicator(
                    row[AIR_KIND], 1);
            const Fp3 first =
                KindIndicator(
                    row[AIR_KIND], 2);
            const Fp3 last =
                KindIndicator(
                    row[AIR_KIND], 3);
            Fp3 gate = everywhere;
            gate = gf::Add(
                gate,
                gf::Mul(
                    transition,
                    gf::Sub(
                        Fp3::One(),
                        row[ORIGINAL_ROW_LAST])));
            gate = gf::Add(
                gate,
                gf::Mul(
                    first,
                    row[ORIGINAL_ROW_ZERO]));
            gate = gf::Add(
                gate,
                gf::Mul(
                    last,
                    row[ORIGINAL_ROW_LAST]));
            const Fp3 expected = gf::Mul(
                row[IS_EXEC],
                gf::Mul(
                    row[
                        PROGRAM_TERMINAL_INSTRUCTION],
                    gate));
            return gf::Sub(
                row[TERMINAL_ACTIVE],
                expected);
        });
    AddConstraint(
        cs, "family_vm.nonbinary_operand_a",
        aq::AirKind::kEverywhere, 2,
        [](const auto& row, const auto&) {
            const Fp3 binary = gf::Add(
                row[IS_ADD],
                gf::Add(
                    row[IS_SUB],
                    row[IS_MUL]));
            return gf::Mul(
                gf::Sub(
                    Fp3::One(), binary),
                row[OPERAND_A]);
        });
    AddConstraint(
        cs, "family_vm.nonbinary_operand_b",
        aq::AirKind::kEverywhere, 2,
        [](const auto& row, const auto&) {
            const Fp3 binary = gf::Add(
                row[IS_ADD],
                gf::Add(
                    row[IS_SUB],
                    row[IS_MUL]));
            return gf::Mul(
                gf::Sub(
                    Fp3::One(), binary),
                row[OPERAND_B]);
        });
    AddConstraint(
        cs, "family_vm.constant",
        aq::AirKind::kEverywhere, 2,
        [](const auto& row, const auto&) {
            return gf::Mul(
                row[IS_CONSTANT],
                gf::Sub(
                    row[RESULT],
                    row[CONSTANT]));
        });
    AddConstraint(
        cs, "family_vm.add",
        aq::AirKind::kEverywhere, 2,
        [](const auto& row, const auto&) {
            return gf::Mul(
                row[IS_ADD],
                gf::Sub(
                    row[RESULT],
                    gf::Add(
                        row[OPERAND_A],
                        row[OPERAND_B])));
        });
    AddConstraint(
        cs, "family_vm.sub",
        aq::AirKind::kEverywhere, 2,
        [](const auto& row, const auto&) {
            return gf::Mul(
                row[IS_SUB],
                gf::Sub(
                    row[RESULT],
                    gf::Sub(
                        row[OPERAND_A],
                        row[OPERAND_B])));
        });
    AddConstraint(
        cs, "family_vm.mul",
        aq::AirKind::kEverywhere, 3,
        [](const auto& row, const auto&) {
            return gf::Mul(
                row[IS_MUL],
                gf::Sub(
                    row[RESULT],
                    gf::Mul(
                        row[OPERAND_A],
                        row[OPERAND_B])));
        });
    AddConstraint(
        cs, "family_vm.residual",
        aq::AirKind::kEverywhere, 2,
        [](const auto& row, const auto&) {
            return gf::Sub(
                row[RESIDUAL],
                gf::Mul(
                    row[TERMINAL_ACTIVE],
                    row[RESULT]));
        });
    AddConstraint(
        cs, "family_vm.terminal_zero",
        aq::AirKind::kEverywhere, 2,
        [](const auto& row, const auto&) {
            return gf::Mul(
                row[TERMINAL_ACTIVE],
                row[RESULT]);
        });

    const auto add_inverse =
        [&](const char* name,
            uint32_t inverse_column,
            uint32_t active_column,
            Fp3 alpha,
            Fp3 gamma,
            auto key) {
            AddConstraint(
                cs, name,
                aq::AirKind::kEverywhere, 3,
                [inverse_column,
                 active_column,
                 alpha, gamma, key](
                    const auto& row,
                    const auto&) {
                    const Fp3 active =
                        row[active_column];
                    const Fp3 inverse =
                        row[inverse_column];
                    const Fp3 relation =
                        gf::Sub(
                            gf::Mul(
                                inverse,
                                gf::Sub(
                                    alpha,
                                    key(row, gamma))),
                            Fp3::One());
                    return gf::Add(
                        gf::Mul(
                            active, relation),
                        gf::Mul(
                            gf::Sub(
                                Fp3::One(),
                                active),
                            inverse));
                });
        };
    const auto source_active =
        [](const std::vector<Fp3>& row) {
            return gf::Add(
                row[IS_SOURCE],
                gf::Add(
                    row[IS_CURRENT],
                    row[IS_NEXT]));
        };
    const auto binary_active =
        [](const std::vector<Fp3>& row) {
            return gf::Add(
                row[IS_ADD],
                gf::Add(
                    row[IS_SUB],
                    row[IS_MUL]));
        };
    const auto add_dynamic_inverse =
        [&](const char* name,
            uint32_t inverse_column,
            Fp3 alpha,
            Fp3 gamma,
            uint32_t degree,
            auto active_fn,
            auto key_fn) {
            AddConstraint(
                cs, name,
                aq::AirKind::kEverywhere, degree,
                [inverse_column,
                 alpha, gamma,
                 active_fn, key_fn](
                    const auto& row,
                    const auto&) {
                    const Fp3 active =
                        active_fn(row);
                    const Fp3 inverse =
                        row[inverse_column];
                    const Fp3 relation =
                        gf::Sub(
                            gf::Mul(
                                inverse,
                                gf::Sub(
                                    alpha,
                                    key_fn(
                                        row, gamma))),
                            Fp3::One());
                    return gf::Add(
                        gf::Mul(
                            active, relation),
                        gf::Mul(
                            gf::Sub(
                                Fp3::One(),
                                active),
                            inverse));
                });
        };
    (void)add_inverse;
    const auto source_key =
        [](const auto& row,
           const Fp3& gamma) {
            return SourceKey(row, gamma);
        };
    const auto definition_key =
        [](const auto& row,
           const Fp3& gamma) {
            return RegisterDefinitionKey(
                row, gamma);
        };
    const auto lhs_key =
        [](const auto& row,
           const Fp3& gamma) {
            return RegisterReadKey(
                row, false, gamma);
        };
    const auto rhs_key =
        [](const auto& row,
           const Fp3& gamma) {
            return RegisterReadKey(
                row, true, gamma);
        };
    std::array<Fp3, 2>
        canonical_metadata_terminal{
            Fp3::Zero(), Fp3::Zero()};
    bool metadata_pole = false;
    canonical_metadata_terminal[0] =
        CanonicalMetadataTerminal(
            table, plan,
            challenges.gamma1,
            challenges.alpha1,
            metadata_pole);
    canonical_metadata_terminal[1] =
        CanonicalMetadataTerminal(
            table, plan,
            challenges.gamma2,
            challenges.alpha2,
            metadata_pole);
    if (metadata_pole) return {};
    for (uint32_t lane = 0;
         lane < 2;
         ++lane) {
        const Fp3 gamma = lane == 0
            ? challenges.gamma1
            : challenges.gamma2;
        const Fp3 alpha = lane == 0
            ? challenges.alpha1
            : challenges.alpha2;
        add_dynamic_inverse(
            "family_vm.source_inverse",
            SOURCE_INVERSE_1 + lane,
            alpha, gamma,
            3,
            source_active, source_key);
        add_dynamic_inverse(
            "family_vm.register_definition_inverse",
            REGISTER_DEFINITION_INVERSE_1 +
                lane,
            alpha, gamma,
            3,
            [](const auto& row) {
                return row[IS_EXEC];
            },
            definition_key);
        add_dynamic_inverse(
            "family_vm.register_lhs_inverse",
            REGISTER_LHS_INVERSE_1 + lane,
            alpha, gamma,
            3,
            binary_active, lhs_key);
        add_dynamic_inverse(
            "family_vm.register_rhs_inverse",
            REGISTER_RHS_INVERSE_1 + lane,
            alpha, gamma,
            3,
            binary_active, rhs_key);
        add_dynamic_inverse(
            "family_vm.metadata_inverse",
            METADATA_INVERSE_1 + lane,
            alpha, gamma,
            4,
            [](const auto& row) {
                return gf::Add(
                    row[IS_SOURCE],
                    row[IS_EXEC]);
            },
            [](const auto& row,
               const Fp3& challenge) {
                return MetadataKey(
                    row, challenge);
            });

        const uint32_t source_running =
            SOURCE_RUNNING_1 + lane;
        const uint32_t register_running =
            REGISTER_RUNNING_1 + lane;
        const uint32_t metadata_running =
            METADATA_RUNNING_1 + lane;
        const uint32_t source_inverse =
            SOURCE_INVERSE_1 + lane;
        const uint32_t definition_inverse =
            REGISTER_DEFINITION_INVERSE_1 +
                lane;
        const uint32_t lhs_inverse =
            REGISTER_LHS_INVERSE_1 + lane;
        const uint32_t rhs_inverse =
            REGISTER_RHS_INVERSE_1 + lane;
        const uint32_t metadata_inverse =
            METADATA_INVERSE_1 + lane;
        AddConstraint(
            cs, "family_vm.source_running_first",
            aq::AirKind::kFirstRow, 1,
            [source_running](
                const auto& row,
                const auto&) {
                return row[source_running];
            });
        AddConstraint(
            cs, "family_vm.register_running_first",
            aq::AirKind::kFirstRow, 1,
            [register_running](
                const auto& row,
                const auto&) {
                return row[register_running];
            });
        AddConstraint(
            cs, "family_vm.metadata_running_first",
            aq::AirKind::kFirstRow, 1,
            [metadata_running](
                const auto& row,
                const auto&) {
                return row[metadata_running];
            });
        const auto source_term =
            [source_inverse](
                const std::vector<Fp3>& row) {
                const Fp3 multiplicity =
                    gf::Sub(
                        row[
                            SOURCE_DEFINITION_MULTIPLICITY],
                        gf::Add(
                            row[IS_CURRENT],
                            row[IS_NEXT]));
                return gf::Mul(
                    multiplicity,
                    row[source_inverse]);
            };
        const auto register_term =
            [definition_inverse,
             lhs_inverse,
             rhs_inverse](
                const std::vector<Fp3>& row) {
                Fp3 term = gf::Mul(
                    row[
                        REGISTER_DEFINITION_MULTIPLICITY],
                    row[definition_inverse]);
                const Fp3 read = gf::Add(
                    row[IS_ADD],
                    gf::Add(
                        row[IS_SUB],
                        row[IS_MUL]));
                term = gf::Sub(
                    term,
                    gf::Mul(
                        read,
                        row[lhs_inverse]));
                return gf::Sub(
                    term,
                    gf::Mul(
                        read,
                        row[rhs_inverse]));
            };
        const auto metadata_term =
            [metadata_inverse](
                const std::vector<Fp3>& row) {
                return gf::Mul(
                    gf::Sub(
                        Fp3::Zero(),
                        gf::Add(
                            row[IS_SOURCE],
                            row[IS_EXEC])),
                    row[metadata_inverse]);
            };
        AddConstraint(
            cs, "family_vm.source_running_transition",
            aq::AirKind::kTransition, 2,
            [source_running,
             source_term](
                const auto& row,
                const auto& next) {
                return gf::Sub(
                    next[source_running],
                    gf::Add(
                        row[source_running],
                        source_term(row)));
            });
        AddConstraint(
            cs, "family_vm.register_running_transition",
            aq::AirKind::kTransition, 2,
            [register_running,
             register_term](
                const auto& row,
                const auto& next) {
                return gf::Sub(
                    next[register_running],
                    gf::Add(
                        row[register_running],
                        register_term(row)));
            });
        AddConstraint(
            cs, "family_vm.metadata_running_transition",
            aq::AirKind::kTransition, 2,
            [metadata_running,
             metadata_term](
                const auto& row,
                const auto& next) {
                return gf::Sub(
                    next[metadata_running],
                    gf::Add(
                        row[metadata_running],
                        metadata_term(row)));
            });
        AddConstraint(
            cs, "family_vm.source_running_last",
            aq::AirKind::kLastRow, 2,
            [source_running,
             source_term](
                const auto& row,
                const auto&) {
                return gf::Add(
                    row[source_running],
                    source_term(row));
            });
        AddConstraint(
            cs, "family_vm.register_running_last",
            aq::AirKind::kLastRow, 2,
            [register_running,
             register_term](
                const auto& row,
                const auto&) {
                return gf::Add(
                    row[register_running],
                    register_term(row));
            });
        AddConstraint(
            cs, "family_vm.metadata_running_last",
            aq::AirKind::kLastRow, 2,
            [metadata_running,
             metadata_term,
             expected =
                 canonical_metadata_terminal[
                     lane]](
                const auto& row,
                const auto&) {
                return gf::Add(
                    expected,
                    gf::Add(
                        row[metadata_running],
                        metadata_term(row)));
            });
    }
    return cs;
}

bool FillCanonicalTrace(
    const cb::ProgramTable& table,
    const FamilyVmPlanV1& plan,
    const std::vector<std::vector<Fp3>>& source,
    std::vector<std::vector<Fp3>>& columns,
    std::string& why)
{
    if (!plan.valid ||
        !plan.fits_single_split_rap ||
        plan.padded_vertical_rows >
            std::numeric_limits<uint32_t>::max() ||
        source.size() != table.current_width) {
        why = "trace_shape";
        return false;
    }
    const uint32_t original_rows =
        plan.original_trace_rows;
    for (const auto& column : source) {
        if (column.size() != original_rows) {
            why = "source_column_shape";
            return false;
        }
        for (const Fp3& value : column) {
            if (!Canonical(value)) {
                why = "source_noncanonical";
                return false;
            }
        }
    }
    const uint32_t vertical_rows =
        static_cast<uint32_t>(
            plan.padded_vertical_rows);
    columns.assign(
        VM_COLUMNS,
        std::vector<Fp3>(
            vertical_rows,
            Fp3::Zero()));
    const auto set_zero_test =
        [&](uint32_t trace_row,
            uint32_t value,
            uint32_t expected,
            uint32_t flag_column,
            uint32_t inverse_column) {
            if (value == expected) {
                columns[flag_column][trace_row] =
                    Fp3::One();
            } else {
                columns[inverse_column][trace_row] =
                    gf::Inv(
                        gf::Sub(
                            U(value),
                            U(expected)));
            }
        };
    uint32_t cursor = 0;
    for (uint32_t row = 0;
         row < original_rows;
         ++row) {
        for (uint32_t column = 0;
             column < table.current_width;
             ++column) {
            columns[SOURCE_VALUE][cursor] =
                source[column][row];
            columns[RECORD_TYPE][cursor] =
                U(1);
            columns[VERTICAL_INDEX][cursor] =
                U(cursor);
            columns[IS_SOURCE][cursor] =
                Fp3::One();
            columns[ORIGINAL_ROW][cursor] =
                U(row);
            columns[LHS][cursor] =
                U(column);
            columns[SOURCE_LOOKUP_ROW][cursor] =
                U(row);
            columns[
                SOURCE_DEFINITION_MULTIPLICITY][
                    cursor] =
                U(plan.source_load_multiplicity[
                    column]);
            set_zero_test(
                cursor, column,
                table.current_width - 1,
                SOURCE_COLUMN_LAST,
                SOURCE_COLUMN_DELTA_INVERSE);
            set_zero_test(
                cursor, row,
                original_rows - 1,
                ORIGINAL_ROW_LAST,
                ORIGINAL_ROW_DELTA_INVERSE);
            set_zero_test(
                cursor, row, 0,
                ORIGINAL_ROW_ZERO,
                ORIGINAL_ROW_ZERO_INVERSE);
            ++cursor;
        }
    }
    for (uint32_t row = 0;
         row < original_rows;
         ++row) {
        uint32_t instruction_ordinal = 0;
        for (uint32_t program_index = 0;
             program_index <
                 table.programs.size();
             ++program_index) {
            const auto& program =
                table.programs[program_index];
            std::vector<Fp3> registers;
            registers.reserve(
                program.instructions.size());
            for (uint32_t pc = 0;
                 pc <
                     program.instructions.size();
                 ++pc) {
                const auto& instruction =
                    program.instructions[pc];
                Fp3 result = Fp3::Zero();
                Fp3 operand_a = Fp3::Zero();
                Fp3 operand_b = Fp3::Zero();
                uint32_t selector = 0;
                switch (instruction.opcode) {
                case cb::Opcode::Current:
                    result =
                        source[
                            instruction.lhs][row];
                    selector = IS_CURRENT;
                    break;
                case cb::Opcode::Next:
                    result =
                        source[
                            instruction.lhs][
                            (row + 1) %
                            original_rows];
                    selector = IS_NEXT;
                    break;
                case cb::Opcode::Constant:
                    result =
                        instruction.constant;
                    selector = IS_CONSTANT;
                    break;
                case cb::Opcode::Add:
                    operand_a =
                        registers[
                            instruction.lhs];
                    operand_b =
                        registers[
                            instruction.rhs];
                    result = gf::Add(
                        operand_a, operand_b);
                    selector = IS_ADD;
                    break;
                case cb::Opcode::Sub:
                    operand_a =
                        registers[
                            instruction.lhs];
                    operand_b =
                        registers[
                            instruction.rhs];
                    result = gf::Sub(
                        operand_a, operand_b);
                    selector = IS_SUB;
                    break;
                case cb::Opcode::Mul:
                    operand_a =
                        registers[
                            instruction.lhs];
                    operand_b =
                        registers[
                            instruction.rhs];
                    result = gf::Mul(
                        operand_a, operand_b);
                    selector = IS_MUL;
                    break;
                }
                registers.push_back(result);
                columns[RECORD_TYPE][cursor] =
                    U(2);
                columns[VERTICAL_INDEX][cursor] =
                    U(cursor);
                columns[IS_EXEC][cursor] =
                    Fp3::One();
                columns[ORIGINAL_ROW][cursor] =
                    U(row);
                columns[PROGRAM][cursor] =
                    U(program_index);
                columns[PC][cursor] = U(pc);
                columns[INSTRUCTION_ORDINAL][
                    cursor] =
                    U(instruction_ordinal);
                columns[AIR_KIND][cursor] =
                    U(static_cast<uint8_t>(
                        program.kind));
                columns[
                    PROGRAM_TERMINAL_INSTRUCTION][
                        cursor] =
                    pc + 1 ==
                        program.instructions.size()
                    ? Fp3::One()
                    : Fp3::Zero();
                columns[OPCODE][cursor] =
                    U(static_cast<uint8_t>(
                        instruction.opcode));
                columns[LHS][cursor] =
                    U(instruction.lhs);
                columns[RHS][cursor] =
                    U(instruction.rhs);
                columns[CONSTANT][cursor] =
                    instruction.constant;
                columns[SOURCE_LOOKUP_ROW][cursor] =
                    U(instruction.opcode ==
                            cb::Opcode::Next
                        ? (row + 1) %
                            original_rows
                        : row);
                columns[selector][cursor] =
                    Fp3::One();
                const bool terminal =
                    pc + 1 ==
                        program.instructions.size() &&
                    TerminalActive(
                        program.kind, row,
                        original_rows);
                columns[TERMINAL_ACTIVE][cursor] =
                    terminal
                    ? Fp3::One()
                    : Fp3::Zero();
                columns[
                    REGISTER_DEFINITION_MULTIPLICITY][
                        cursor] =
                    U(plan.program_inventory[
                        program_index]
                          .register_use_multiplicity[
                              pc]);
                set_zero_test(
                    cursor, row,
                    original_rows - 1,
                    ORIGINAL_ROW_LAST,
                    ORIGINAL_ROW_DELTA_INVERSE);
                set_zero_test(
                    cursor, row, 0,
                    ORIGINAL_ROW_ZERO,
                    ORIGINAL_ROW_ZERO_INVERSE);
                set_zero_test(
                    cursor,
                    instruction_ordinal,
                    plan.instructions_per_original_row -
                        1,
                    INSTRUCTION_LAST,
                    INSTRUCTION_DELTA_INVERSE);
                columns[RESULT][cursor] =
                    result;
                columns[OPERAND_A][cursor] =
                    operand_a;
                columns[OPERAND_B][cursor] =
                    operand_b;
                columns[RESIDUAL][cursor] =
                    terminal
                    ? result
                    : Fp3::Zero();
                ++instruction_ordinal;
                ++cursor;
            }
        }
        if (instruction_ordinal !=
            plan.instructions_per_original_row) {
            why =
                "instruction_ordinal_count";
            return false;
        }
    }
    if (cursor !=
        plan.logical_vertical_rows) {
        why = "canonical_schedule_count";
        return false;
    }
    for (; cursor < vertical_rows; ++cursor) {
        columns[VERTICAL_INDEX][cursor] =
            U(cursor);
    }
    return true;
}

bool FillLookupWitness(
    const FamilyVmLookupChallengesV1& challenges,
    std::vector<std::vector<Fp3>>& columns,
    std::string& why)
{
    if (!LookupChallengesValid(challenges) ||
        columns.size() != VM_COLUMNS ||
        columns.front().empty()) {
        why = "lookup_shape";
        return false;
    }
    const uint32_t rows =
        static_cast<uint32_t>(
            columns.front().size());
    std::array<Fp3, 2> source_running{
        Fp3::Zero(), Fp3::Zero()};
    std::array<Fp3, 2> register_running{
        Fp3::Zero(), Fp3::Zero()};
    std::array<Fp3, 2> metadata_running{
        Fp3::Zero(), Fp3::Zero()};
    std::vector<Fp3> current(VM_COLUMNS);
    for (uint32_t row = 0;
         row < rows;
         ++row) {
        for (uint32_t column = 0;
             column < VM_COLUMNS;
             ++column) {
            current[column] =
                columns[column][row];
        }
        const Fp3 source_active = gf::Add(
            current[IS_SOURCE],
            gf::Add(
                current[IS_CURRENT],
                current[IS_NEXT]));
        const Fp3 binary_active = gf::Add(
            current[IS_ADD],
            gf::Add(
                current[IS_SUB],
                current[IS_MUL]));
        for (uint32_t lane = 0;
             lane < 2;
             ++lane) {
            const Fp3 gamma = lane == 0
                ? challenges.gamma1
                : challenges.gamma2;
            const Fp3 alpha = lane == 0
                ? challenges.alpha1
                : challenges.alpha2;
            columns[SOURCE_RUNNING_1 +
                    lane][row] =
                source_running[lane];
            columns[REGISTER_RUNNING_1 +
                    lane][row] =
                register_running[lane];
            columns[METADATA_RUNNING_1 +
                    lane][row] =
                metadata_running[lane];
            auto inverse_for =
                [&](const Fp3& active,
                    const Fp3& key,
                    uint32_t column,
                    Fp3& out) {
                    if (gf::IsZero(active)) {
                        columns[column][row] =
                            Fp3::Zero();
                        return true;
                    }
                    const Fp3 denominator =
                        gf::Sub(alpha, key);
                    if (gf::IsZero(
                            denominator)) {
                        return false;
                    }
                    out = gf::Inv(denominator);
                    columns[column][row] = out;
                    return true;
                };
            Fp3 source_inverse =
                Fp3::Zero();
            Fp3 definition_inverse =
                Fp3::Zero();
            Fp3 lhs_inverse =
                Fp3::Zero();
            Fp3 rhs_inverse =
                Fp3::Zero();
            Fp3 metadata_inverse =
                Fp3::Zero();
            const Fp3 metadata_active =
                gf::Add(
                    current[IS_SOURCE],
                    current[IS_EXEC]);
            if (!inverse_for(
                    source_active,
                    SourceKey(
                        current, gamma),
                    SOURCE_INVERSE_1 + lane,
                    source_inverse) ||
                !inverse_for(
                    current[IS_EXEC],
                    RegisterDefinitionKey(
                        current, gamma),
                    REGISTER_DEFINITION_INVERSE_1 +
                        lane,
                    definition_inverse) ||
                !inverse_for(
                    binary_active,
                    RegisterReadKey(
                        current, false,
                        gamma),
                    REGISTER_LHS_INVERSE_1 +
                        lane,
                    lhs_inverse) ||
                !inverse_for(
                    binary_active,
                    RegisterReadKey(
                        current, true,
                        gamma),
                    REGISTER_RHS_INVERSE_1 +
                        lane,
                    rhs_inverse) ||
                !inverse_for(
                    metadata_active,
                    MetadataKey(
                        current, gamma),
                    METADATA_INVERSE_1 + lane,
                    metadata_inverse)) {
                why = "lookup_pole";
                return false;
            }
            const Fp3 source_multiplicity =
                gf::Sub(
                    current[
                        SOURCE_DEFINITION_MULTIPLICITY],
                    gf::Add(
                        current[IS_CURRENT],
                        current[IS_NEXT]));
            source_running[lane] =
                gf::Add(
                    source_running[lane],
                    gf::Mul(
                        source_multiplicity,
                        source_inverse));
            Fp3 register_term = gf::Mul(
                current[
                    REGISTER_DEFINITION_MULTIPLICITY],
                definition_inverse);
            register_term = gf::Sub(
                register_term,
                gf::Mul(
                    binary_active,
                    lhs_inverse));
            register_term = gf::Sub(
                register_term,
                gf::Mul(
                    binary_active,
                    rhs_inverse));
            register_running[lane] =
                gf::Add(
                    register_running[lane],
                    register_term);
            metadata_running[lane] =
                gf::Sub(
                    metadata_running[lane],
                    gf::Mul(
                        metadata_active,
                        metadata_inverse));
        }
    }
    for (uint32_t lane = 0;
         lane < 2;
         ++lane) {
        if (!gf::IsZero(
                source_running[lane]) ||
            !gf::IsZero(
                register_running[lane])) {
            why = "lookup_terminal_nonzero";
            return false;
        }
    }
    return true;
}

bool PublicInputsMatch(
    const cb::ProgramTable& table,
    const FamilyVmPlanV1& plan,
    const FamilyVmPublicInputsV1& inputs)
{
    return
        inputs.version ==
            kFamilyVmPlanVersionV1 &&
        !inputs.program_registry_alg_root.IsNull() &&
        !inputs.public_statement_binding.IsNull() &&
        inputs.program_table_commitment ==
            plan.program_table_commitment &&
        SameDigest(
            inputs.program_table_alg_hash,
            plan.program_table_alg_hash) &&
        inputs.schedule_commitment ==
            plan.schedule_commitment &&
        !inputs.phase0_row_group_root.IsNull() &&
        inputs.original_trace_rows ==
            plan.original_trace_rows &&
        inputs.vertical_trace_rows ==
            plan.padded_vertical_rows &&
        inputs.vm_columns == VM_COLUMNS &&
        table.role == plan.role;
}

void AppendU16(
    std::vector<unsigned char>& out,
    uint16_t value)
{
    out.push_back(
        static_cast<unsigned char>(value));
    out.push_back(
        static_cast<unsigned char>(
            value >> 8));
}

void AppendU32(
    std::vector<unsigned char>& out,
    uint32_t value)
{
    for (uint32_t byte = 0;
         byte < 4;
         ++byte) {
        out.push_back(
            static_cast<unsigned char>(
                value >> (8 * byte)));
    }
}

void AppendU64(
    std::vector<unsigned char>& out,
    uint64_t value)
{
    for (uint32_t byte = 0;
         byte < 8;
         ++byte) {
        out.push_back(
            static_cast<unsigned char>(
                value >> (8 * byte)));
    }
}

void AppendFp3(
    std::vector<unsigned char>& out,
    const Fp3& value)
{
    AppendU64(out, gf::Canonical(value.c0));
    AppendU64(out, gf::Canonical(value.c1));
    AppendU64(out, gf::Canonical(value.c2));
}

bool ReadU16(
    const std::vector<unsigned char>& bytes,
    size_t& cursor,
    uint16_t& out)
{
    if (cursor > bytes.size() ||
        bytes.size() - cursor < 2) {
        return false;
    }
    out =
        static_cast<uint16_t>(bytes[cursor]) |
        (static_cast<uint16_t>(
             bytes[cursor + 1])
         << 8);
    cursor += 2;
    return true;
}

bool ReadU32(
    const std::vector<unsigned char>& bytes,
    size_t& cursor,
    uint32_t& out)
{
    if (cursor > bytes.size() ||
        bytes.size() - cursor < 4) {
        return false;
    }
    out = 0;
    for (uint32_t byte = 0;
         byte < 4;
         ++byte) {
        out |=
            static_cast<uint32_t>(
                bytes[cursor + byte])
            << (8 * byte);
    }
    cursor += 4;
    return true;
}

bool ReadU64(
    const std::vector<unsigned char>& bytes,
    size_t& cursor,
    uint64_t& out)
{
    if (cursor > bytes.size() ||
        bytes.size() - cursor < 8) {
        return false;
    }
    out = 0;
    for (uint32_t byte = 0;
         byte < 8;
         ++byte) {
        out |=
            static_cast<uint64_t>(
                bytes[cursor + byte])
            << (8 * byte);
    }
    cursor += 8;
    return true;
}

bool ReadFp3(
    const std::vector<unsigned char>& bytes,
    size_t& cursor,
    Fp3& out)
{
    return
        ReadU64(bytes, cursor, out.c0) &&
        ReadU64(bytes, cursor, out.c1) &&
        ReadU64(bytes, cursor, out.c2) &&
        Canonical(out);
}

} // namespace

size_t SerializeFamilyVmProofV1(
    const FamilyVmProofV1& proof,
    std::vector<unsigned char>& out)
{
    out.clear();
    if (proof.version !=
            kFamilyVmPlanVersionV1 ||
        !LookupChallengesValid(
            proof.lookup_challenges)) {
        return 0;
    }
    std::vector<unsigned char> split;
    const size_t split_size =
        aq::SerializeAirQuotientSplitRapRowsProof(
            proof.split_rap, split);
    if (split_size == 0 ||
        split_size != split.size() ||
        split_size >
            aq::
            kAirQuotientSplitRapRowsMaxProofBytesHard ||
        split_size >
            std::numeric_limits<uint32_t>::max()) {
        return 0;
    }
    out.reserve(108 + split.size());
    AppendU32(out, kFamilyVmProofMagicV1);
    AppendU16(out, proof.version);
    AppendU16(out, 0);
    AppendFp3(
        out, proof.lookup_challenges.gamma1);
    AppendFp3(
        out, proof.lookup_challenges.gamma2);
    AppendFp3(
        out, proof.lookup_challenges.alpha1);
    AppendFp3(
        out, proof.lookup_challenges.alpha2);
    AppendU32(
        out,
        static_cast<uint32_t>(
            split.size()));
    out.insert(
        out.end(),
        split.begin(), split.end());
    if (out.size() >
        kFamilyVmMaxProofBytesV1) {
        out.clear();
        return 0;
    }
    return out.size();
}

std::optional<FamilyVmProofV1>
DeserializeFamilyVmProofV1(
    const std::vector<unsigned char>& bytes)
{
    constexpr size_t HEADER_BYTES =
        4 + 2 + 2 + 4 * 24 + 4;
    if (bytes.size() < HEADER_BYTES ||
        bytes.size() >
            kFamilyVmMaxProofBytesV1) {
        return std::nullopt;
    }
    size_t cursor = 0;
    uint32_t magic = 0;
    uint16_t version = 0;
    uint16_t reserved = 0;
    uint32_t split_size = 0;
    FamilyVmProofV1 out;
    if (!ReadU32(bytes, cursor, magic) ||
        magic != kFamilyVmProofMagicV1 ||
        !ReadU16(bytes, cursor, version) ||
        version != kFamilyVmPlanVersionV1 ||
        !ReadU16(bytes, cursor, reserved) ||
        reserved != 0 ||
        !ReadFp3(
            bytes, cursor,
            out.lookup_challenges.gamma1) ||
        !ReadFp3(
            bytes, cursor,
            out.lookup_challenges.gamma2) ||
        !ReadFp3(
            bytes, cursor,
            out.lookup_challenges.alpha1) ||
        !ReadFp3(
            bytes, cursor,
            out.lookup_challenges.alpha2) ||
        !LookupChallengesValid(
            out.lookup_challenges) ||
        !ReadU32(
            bytes, cursor, split_size) ||
        split_size == 0 ||
        split_size >
            aq::
            kAirQuotientSplitRapRowsMaxProofBytesHard ||
        cursor > bytes.size() ||
        bytes.size() - cursor !=
            split_size) {
        return std::nullopt;
    }
    const std::vector<unsigned char> split(
        bytes.begin() + cursor,
        bytes.end());
    auto decoded =
        aq::DeserializeAirQuotientSplitRapRowsProof(
            split);
    if (!decoded.has_value()) {
        return std::nullopt;
    }
    out.version = version;
    out.split_rap = std::move(*decoded);
    std::vector<unsigned char> canonical;
    if (SerializeFamilyVmProofV1(
            out, canonical) != bytes.size() ||
        canonical != bytes) {
        return std::nullopt;
    }
    return out;
}

FamilyVmProveResultV1 ProveFamilyVmV1(
    const cb::ProgramTable& table,
    const std::vector<std::vector<Fp3>>& source_columns,
    uint32_t program_id,
    const uint256& program_registry_alg_root,
    const uint256& public_statement_binding,
    const uint256& public_fs_seed)
{
    FamilyVmProveResultV1 out;
    const auto fail =
        [&](const std::string& detail) {
            out.ok = false;
            out.note =
                "stage3:family_vm:prove:" +
                detail;
            return out;
        };
    if (source_columns.empty() ||
        source_columns.front().size() >
            std::numeric_limits<uint32_t>::max() ||
        program_registry_alg_root.IsNull() ||
        public_statement_binding.IsNull() ||
        public_fs_seed.IsNull()) {
        return fail("statement");
    }
    const uint32_t original_rows =
        static_cast<uint32_t>(
            source_columns.front().size());
    const FamilyVmPlanV1 plan =
        BuildFamilyVmPlanV1(
            table, original_rows);
    if (!plan.valid ||
        !plan.fits_single_split_rap ||
        plan.padded_vertical_rows >
            std::numeric_limits<uint32_t>::max()) {
        return fail(
            "plan_requires_segmentation");
    }
    std::vector<std::vector<Fp3>> columns;
    std::string why;
    if (!FillCanonicalTrace(
            table, plan, source_columns,
            columns, why)) {
        return fail(why);
    }

    // Build the exact challenge-independent row commitment first. The
    // constraint closures do not affect this commitment; nonzero dummy
    // challenges merely provide the canonical CS shape.
    FamilyVmLookupChallengesV1 dummy{
        U(2), U(3), U(5), U(7)};
    const auto provisional_cs =
        BuildVmConstraintSystem(
            table, plan, dummy,
            uint256{});
    if (provisional_cs.n_columns !=
            VM_COLUMNS) {
        return fail("constraint_system");
    }
    const auto phase0_session =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            provisional_cs, columns,
            Phase0Columns());
    if (!phase0_session.valid ||
        phase0_session
            .base_row_commitment.IsNull()) {
        return fail(
            "phase0:" +
            phase0_session.note);
    }

    out.public_inputs.version =
        kFamilyVmPlanVersionV1;
    out.public_inputs.program_id =
        program_id;
    out.public_inputs.program_registry_alg_root =
        program_registry_alg_root;
    out.public_inputs.public_statement_binding =
        public_statement_binding;
    out.public_inputs.program_table_commitment =
        plan.program_table_commitment;
    out.public_inputs.program_table_alg_hash =
        plan.program_table_alg_hash;
    out.public_inputs.schedule_commitment =
        plan.schedule_commitment;
    out.public_inputs.phase0_row_group_root =
        phase0_session.base_row_commitment;
    out.public_inputs.original_trace_rows =
        original_rows;
    out.public_inputs.vertical_trace_rows =
        static_cast<uint32_t>(
            plan.padded_vertical_rows);
    out.public_inputs.vm_columns = VM_COLUMNS;
    if (!DeriveLookupChallenges(
            out.public_inputs, public_fs_seed,
            out.proof.lookup_challenges)) {
        return fail("lookup_challenges");
    }
    if (!FillLookupWitness(
            out.proof.lookup_challenges,
            columns, why)) {
        return fail(why);
    }
    const auto cs =
        BuildVmConstraintSystem(
            table, plan,
            out.proof.lookup_challenges,
            out.public_inputs
                .phase0_row_group_root);
    const auto proved =
        aq::AirQuotientProveRowsSplitRap(
            cs, columns, Phase0Columns(),
            public_fs_seed, {},
            &phase0_session);
    if (!proved.ok ||
        !proved.division_exact) {
        return fail(proved.note);
    }
    if (proved.proof.batch.groups.empty() ||
        Fri3AlgDigestToUint256(
            proved.proof.batch.groups[0]
                .row_commit.root) !=
            out.public_inputs
                .phase0_row_group_root) {
        return fail("phase0_group_equality");
    }
    out.proof.version =
        kFamilyVmPlanVersionV1;
    out.proof.split_rap = proved.proof;
    out.ok = true;
    out.note =
        "stage3:family_vm:prove:"
        "canonical_vertical_split_rap_q192";
    return out;
}

FamilyVmVerifierWorkEstimateV1
EstimateFamilyVmVerifierWorkV1(
    const cb::ProgramTable& table,
    uint32_t original_trace_rows)
{
    FamilyVmVerifierWorkEstimateV1 out;
    const FamilyVmPlanV1 plan =
        BuildFamilyVmPlanV1(
            table, original_trace_rows);
    if (!plan.valid ||
        !plan.fits_single_split_rap) {
        return out;
    }
    out.vertical_trace_rows =
        plan.padded_vertical_rows;
    out.verifier_work_rows =
        uint64_t{table.current_width} +
        plan.instructions_per_original_row +
        kFamilyVmQueriesV1;
    out.verifier_work_cells =
        uint64_t{table.current_width} * 2 +
        uint64_t{
            plan.instructions_per_original_row} *
            10 +
        uint64_t{kFamilyVmQueriesV1} *
            VM_COLUMNS;
    out.materializes_vertical_schedule =
        false;
    out.asymptotically_sublinear = true;
    out.valid = true;
    return out;
}

FamilyVmVerificationAuditV1 VerifyFamilyVmV1(
    const cb::ProgramTable& table,
    const FamilyVmPublicInputsV1& public_inputs,
    const FamilyVmProofV1& proof,
    const uint256& public_fs_seed)
{
    FamilyVmVerificationAuditV1 out;
    out.original_trace_rows =
        public_inputs.original_trace_rows;
    out.vertical_trace_rows =
        public_inputs.vertical_trace_rows;
    out.programs =
        static_cast<uint32_t>(
            table.programs.size());
    const auto fail =
        [&](const std::string& detail) {
            out.valid = false;
            out.production_authority_ready =
                false;
            out.note =
                "stage3:family_vm:verify:" +
                detail;
            return out;
        };
    if (proof.version !=
            kFamilyVmPlanVersionV1 ||
        public_fs_seed.IsNull()) {
        return fail("version_or_seed");
    }
    const FamilyVmPlanV1 plan =
        BuildFamilyVmPlanV1(
            table,
            public_inputs
                .original_trace_rows);
    if (!plan.valid ||
        !plan.fits_single_split_rap ||
        !PublicInputsMatch(
            table, plan, public_inputs)) {
        return fail("public_statement");
    }
    FamilyVmLookupChallengesV1 expected;
    if (!DeriveLookupChallenges(
            public_inputs, public_fs_seed,
            expected) ||
        !(expected ==
          proof.lookup_challenges)) {
        return fail("lookup_transcript");
    }
    const auto cs =
        BuildVmConstraintSystem(
            table, plan,
            proof.lookup_challenges,
            public_inputs
                .phase0_row_group_root);
    if (cs.n_columns != VM_COLUMNS) {
        return fail("constraint_system");
    }
    std::string split_why;
    if (!aq::AirQuotientVerifyRowsSplitRap(
            cs, proof.split_rap,
            Phase0Columns(),
            public_fs_seed,
            &split_why)) {
        return fail(split_why);
    }
    if (proof.split_rap.batch.groups.empty() ||
        Fri3AlgDigestToUint256(
            proof.split_rap.batch.groups[0]
                .row_commit.root) !=
            public_inputs
                .phase0_row_group_root) {
        return fail("phase0_group_root");
    }

    out.instruction_rows =
        plan.instruction_execution_rows;
    out.canonical_program_table_root_pinned =
        true;
    out.program_selection_bound_in_transcript =
        true;
    out.registry_membership_proved = false;
    out.exact_row_program_pc_schedule = true;
    out.program_fetch_metadata_logup_pinned =
        true;
    out.source_multiplicity_consensus_u32 =
        true;
    out.register_multiplicity_consensus_u32 =
        true;
    out.cyclic_current_next_all_rows = true;
    out.dual_lookup_challenges_after_phase0 =
        true;
    out.phase0_group_root_exact = true;
    out.split_rap_quotient_fri_verified =
        true;
    const auto work =
        EstimateFamilyVmVerifierWorkV1(
            table,
            public_inputs.original_trace_rows);
    out.verifier_work_rows =
        work.verifier_work_rows;
    out.verifier_work_cells =
        work.verifier_work_cells;
    out.verifier_rebuilds_full_preprocessed_schedule =
        false;
    out.sublinear_verifier = true;
    out.unsegmented_residual_fold_required =
        false;
    out.segmented_family_fold_executable =
        false;
    // V1 executes a complete unsegmented family VM. It is not promoted to
    // production authority until segmented families have a proof-bound
    // residual fold and the recursive parent consumes this verifier.
    out.production_authority_ready = false;
    out.valid = true;
    out.note =
        "stage3:family_vm:verify:"
        "unsegmented_execution_valid;"
        "algebraic_schedule_and_metadata_logup;"
        "segmented_fold_pending";
    return out;
}

FamilyVmVerificationAuditV1
VerifyFamilyVmResolvedV1(
    const FamilyVmPublicInputsV1& public_inputs,
    const FamilyVmProofV1& proof,
    const uint256& public_fs_seed,
    const FamilyVmProgramResolverV1& resolver)
{
    FamilyVmVerificationAuditV1 out;
    if (!resolver ||
        public_inputs
            .program_registry_alg_root.IsNull()) {
        out.note =
            "stage3:family_vm:resolved:"
            "resolver_or_registry";
        return out;
    }
    cb::ProgramTable selected;
    if (!resolver(
            public_inputs
                .program_registry_alg_root,
            public_inputs.program_id,
            selected)) {
        out.note =
            "stage3:family_vm:resolved:"
            "program_not_selected";
        return out;
    }
    out = VerifyFamilyVmV1(
        selected, public_inputs, proof,
        public_fs_seed);
    if (!out.valid) return out;
    out.registry_membership_proved = true;
    out.note += ";registry_program_resolved";
    return out;
}

} // namespace matmul::v4::rc::stage3_family_vm
