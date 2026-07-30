// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_multirow_v11_acceptance_bytecode.h>

#include <hash.h>

#include <algorithm>
#include <functional>
#include <limits>
#include <utility>

namespace matmul::v4::rc::
stage3_multirow_v11_acceptance_bytecode {
namespace {

using gf::Fp3;

constexpr char kBoundExternalDomainV1[] =
    "BTX_RC_STAGE3_V11_ACCEPTANCE_BOUND_PROGRAM_V1";
constexpr char kBoundRecursiveDomainV1[] =
    "BTX_RC_STAGE3_V11_ACCEPTANCE_BOUND_PROGRAM_ALG_V1";

Fp3 U(uint64_t value)
{
    return gf::FromU64_3(value);
}

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why =
            "stage3:v11_acceptance_bytecode:" +
            detail;
    }
    return false;
}

bool DigestZero(const alg_hash::Digest& digest)
{
    return std::all_of(
        digest.begin(), digest.end(),
        [](gf::Fp value) {
            return gf::Canonical(value) == 0;
        });
}

bool DigestEqual(
    const alg_hash::Digest& lhs,
    const alg_hash::Digest& rhs)
{
    for (uint32_t lane = 0;
         lane < lhs.size(); ++lane) {
        if (gf::Canonical(lhs[lane]) !=
            gf::Canonical(rhs[lane])) {
            return false;
        }
    }
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
    aq::AirConstraint<Fp3> constraint;
    constraint.name = name;
    constraint.kind = kind;
    constraint.alg_degree = degree;
    constraint.eval = std::move(eval);
    cs.constraints.push_back(
        std::move(constraint));
}

bool ConstraintActive(
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

uint64_t CountViolations(
    const aq::AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns)
{
    if (columns.size() != cs.n_columns) {
        return std::numeric_limits<uint64_t>::max();
    }
    for (const auto& column : columns) {
        if (column.size() != cs.n_rows) {
            return std::numeric_limits<uint64_t>::max();
        }
    }
    uint64_t violations = 0;
    std::vector<Fp3> current(cs.n_columns);
    std::vector<Fp3> next(cs.n_columns);
    for (uint32_t row = 0; row < cs.n_rows; ++row) {
        const uint32_t next_row =
            (row + 1) % cs.n_rows;
        for (uint32_t column = 0;
             column < cs.n_columns; ++column) {
            current[column] = columns[column][row];
            next[column] = columns[column][next_row];
        }
        for (const auto& constraint :
             cs.constraints) {
            if (ConstraintActive(
                    constraint.kind,
                    row, cs.n_rows) &&
                !gf::IsZero(
                    constraint.eval(
                        current, next))) {
                ++violations;
            }
        }
    }
    return violations;
}

class Expr {
public:
    uint32_t Current(uint32_t column)
    {
        return Push(
            {cb::Opcode::Current, column, 0, Fp3::Zero()},
            1);
    }

    uint32_t Next(uint32_t column)
    {
        return Push(
            {cb::Opcode::Next, column, 0, Fp3::Zero()},
            1);
    }

    uint32_t Constant(const Fp3& value)
    {
        return Push(
            {cb::Opcode::Constant, 0, 0, value},
            0);
    }

    uint32_t Sub(uint32_t lhs, uint32_t rhs)
    {
        return Binary(cb::Opcode::Sub, lhs, rhs);
    }

    uint32_t Mul(uint32_t lhs, uint32_t rhs)
    {
        return Binary(cb::Opcode::Mul, lhs, rhs);
    }

    [[nodiscard]] uint32_t Degree() const
    {
        return m_degree.empty() ? 0 : m_degree.back();
    }

    std::vector<cb::Instruction> instructions;

private:
    uint32_t Push(
        cb::Instruction instruction,
        uint32_t degree)
    {
        instructions.push_back(std::move(instruction));
        m_degree.push_back(degree);
        return static_cast<uint32_t>(
            instructions.size() - 1);
    }

    uint32_t Binary(
        cb::Opcode opcode,
        uint32_t lhs,
        uint32_t rhs)
    {
        const uint32_t degree =
            opcode == cb::Opcode::Mul
            ? m_degree[lhs] + m_degree[rhs]
            : std::max(
                m_degree[lhs], m_degree[rhs]);
        return Push(
            {opcode, lhs, rhs, Fp3::Zero()},
            degree);
    }

    std::vector<uint32_t> m_degree;
};

template <typename Build>
void Append(
    cb::ProgramTable& table,
    aq::AirKind kind,
    Build&& build)
{
    Expr expression;
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
        expression.Degree();
    program.current_width =
        kAcceptanceProofColumnsV1;
    program.next_width =
        kAcceptanceProofColumnsV1;
    program.challenge_width = 0;
    program.instructions =
        std::move(expression.instructions);
    table.programs.push_back(
        std::move(program));
}

void AppendBoolean(
    cb::ProgramTable& table,
    uint32_t column)
{
    Append(
        table, aq::AirKind::kEverywhere,
        [column](Expr& e) {
            const uint32_t value =
                e.Current(column);
            const uint32_t one =
                e.Constant(Fp3::One());
            const uint32_t minus_one =
                e.Sub(value, one);
            e.Mul(value, minus_one);
        });
}

void BuildReferenceCallbacks(
    AcceptanceInstanceV1& out)
{
    const auto layout = out.layout;
    auto& cs = out.structural_cs;
    cs.n_rows = rp::kRecursiveParentTraceRowsV1;
    cs.n_columns = kAcceptanceProofColumnsV1;
    AddConstraint(
        cs, "stage3.v11_recursive_parent.active_boolean",
        aq::AirKind::kEverywhere, 2,
        [=](const auto& cur, const auto&) {
            return gf::Mul(
                cur[layout.active],
                gf::Sub(
                    cur[layout.active],
                    Fp3::One()));
        });
    AddConstraint(
        cs, "stage3.v11_recursive_parent.ordinal_boolean",
        aq::AirKind::kEverywhere, 2,
        [=](const auto& cur, const auto&) {
            return gf::Mul(
                cur[layout.ordinal],
                gf::Sub(
                    cur[layout.ordinal],
                    Fp3::One()));
        });
    AddConstraint(
        cs, "stage3.v11_recursive_parent.accepted_equals_active",
        aq::AirKind::kEverywhere, 1,
        [=](const auto& cur, const auto&) {
            return gf::Sub(
                cur[layout.accepted],
                cur[layout.active]);
        });
    AddConstraint(
        cs, "stage3.v11_recursive_parent.padding_ordinal_zero",
        aq::AirKind::kEverywhere, 2,
        [=](const auto& cur, const auto&) {
            return gf::Mul(
                gf::Sub(
                    Fp3::One(),
                    cur[layout.active]),
                cur[layout.ordinal]);
        });
    AddConstraint(
        cs, "stage3.v11_recursive_parent.ordinal_first",
        aq::AirKind::kFirstRow, 1,
        [=](const auto& cur, const auto&) {
            return cur[layout.ordinal];
        });
    AddConstraint(
        cs, "stage3.v11_recursive_parent.padding_last",
        aq::AirKind::kLastRow, 1,
        [=](const auto& cur, const auto&) {
            return cur[layout.active];
        });
    AddConstraint(
        cs, "stage3.v11_recursive_parent.first_to_second_active",
        aq::AirKind::kTransition, 3,
        [=](const auto& cur, const auto& next) {
            const Fp3 first =
                gf::Mul(
                    cur[layout.active],
                    gf::Sub(
                        Fp3::One(),
                        cur[layout.ordinal]));
            return gf::Mul(
                first,
                gf::Sub(
                    next[layout.active],
                    Fp3::One()));
        });
    AddConstraint(
        cs, "stage3.v11_recursive_parent.first_to_second_ordinal",
        aq::AirKind::kTransition, 3,
        [=](const auto& cur, const auto& next) {
            const Fp3 first =
                gf::Mul(
                    cur[layout.active],
                    gf::Sub(
                        Fp3::One(),
                        cur[layout.ordinal]));
            return gf::Mul(
                first,
                gf::Sub(
                    next[layout.ordinal],
                    Fp3::One()));
        });
    AddConstraint(
        cs, "stage3.v11_recursive_parent.second_to_padding",
        aq::AirKind::kTransition, 3,
        [=](const auto& cur, const auto& next) {
            const Fp3 second =
                gf::Mul(
                    cur[layout.active],
                    cur[layout.ordinal]);
            return gf::Mul(
                second,
                next[layout.active]);
        });
    AddConstraint(
        cs, "stage3.v11_recursive_parent.padding_stays_padding",
        aq::AirKind::kTransition, 2,
        [=](const auto& cur, const auto& next) {
            return gf::Mul(
                gf::Sub(
                    Fp3::One(),
                    cur[layout.active]),
                next[layout.active]);
        });

    // The static bytecode contains this dependent column equation. The
    // statement-specific callback below retains its historical order (pins
    // first, dependent-zero last) solely for the equivalence audit.
    out.legacy_full_callback_cs = cs;
    AddConstraint(
        cs, "stage3.v11_recursive_parent.v2.dependent_zero",
        aq::AirKind::kEverywhere, 1,
        [](const auto& cur, const auto&) {
            return cur[
                kAcceptanceSemanticColumnsV1];
        });
    auto& full = out.legacy_full_callback_cs;
    for (uint32_t column = 0;
         column < kAcceptanceSemanticColumnsV1;
         ++column) {
        const Fp3 first = out.first_row[column];
        const Fp3 second = out.second_row[column];
        AddConstraint(
            full, "stage3.v11_recursive_parent.pin_first",
            aq::AirKind::kEverywhere, 3,
            [=](const auto& cur, const auto&) {
                const Fp3 selector =
                    gf::Mul(
                        cur[layout.active],
                        gf::Sub(
                            Fp3::One(),
                            cur[layout.ordinal]));
                return gf::Mul(
                    selector,
                    gf::Sub(cur[column], first));
            });
        AddConstraint(
            full, "stage3.v11_recursive_parent.pin_last",
            aq::AirKind::kEverywhere, 3,
            [=](const auto& cur, const auto&) {
                const Fp3 selector =
                    gf::Mul(
                        cur[layout.active],
                        cur[layout.ordinal]);
                return gf::Mul(
                    selector,
                    gf::Sub(cur[column], second));
            });
        AddConstraint(
            full, "stage3.v11_recursive_parent.pin_padding_zero",
            aq::AirKind::kEverywhere, 2,
            [=](const auto& cur, const auto&) {
                return gf::Mul(
                    gf::Sub(
                        Fp3::One(),
                        cur[layout.active]),
                    cur[column]);
            });
    }
    AddConstraint(
        full, "stage3.v11_recursive_parent.v2.dependent_zero",
        aq::AirKind::kEverywhere, 1,
        [](const auto& cur, const auto&) {
            return cur[
                kAcceptanceSemanticColumnsV1];
        });
}

void BuildPrograms(
    const AcceptanceInstanceV1& instance,
    cb::ProgramTable& table)
{
    const auto layout = instance.layout;
    AppendBoolean(table, layout.active);
    AppendBoolean(table, layout.ordinal);
    Append(
        table, aq::AirKind::kEverywhere,
        [=](Expr& e) {
            e.Sub(
                e.Current(layout.accepted),
                e.Current(layout.active));
        });
    Append(
        table, aq::AirKind::kEverywhere,
        [=](Expr& e) {
            const uint32_t one =
                e.Constant(Fp3::One());
            const uint32_t active =
                e.Current(layout.active);
            const uint32_t padding =
                e.Sub(one, active);
            e.Mul(
                padding,
                e.Current(layout.ordinal));
        });
    Append(
        table, aq::AirKind::kFirstRow,
        [=](Expr& e) {
            e.Current(layout.ordinal);
        });
    Append(
        table, aq::AirKind::kLastRow,
        [=](Expr& e) {
            e.Current(layout.active);
        });
    Append(
        table, aq::AirKind::kTransition,
        [=](Expr& e) {
            const uint32_t active =
                e.Current(layout.active);
            const uint32_t one =
                e.Constant(Fp3::One());
            const uint32_t ordinal =
                e.Current(layout.ordinal);
            const uint32_t first =
                e.Mul(
                    active,
                    e.Sub(one, ordinal));
            const uint32_t next_active =
                e.Next(layout.active);
            const uint32_t one_again =
                e.Constant(Fp3::One());
            e.Mul(
                first,
                e.Sub(next_active, one_again));
        });
    Append(
        table, aq::AirKind::kTransition,
        [=](Expr& e) {
            const uint32_t active =
                e.Current(layout.active);
            const uint32_t one =
                e.Constant(Fp3::One());
            const uint32_t ordinal =
                e.Current(layout.ordinal);
            const uint32_t first =
                e.Mul(
                    active,
                    e.Sub(one, ordinal));
            const uint32_t next_ordinal =
                e.Next(layout.ordinal);
            const uint32_t one_again =
                e.Constant(Fp3::One());
            e.Mul(
                first,
                e.Sub(next_ordinal, one_again));
        });
    Append(
        table, aq::AirKind::kTransition,
        [=](Expr& e) {
            const uint32_t second =
                e.Mul(
                    e.Current(layout.active),
                    e.Current(layout.ordinal));
            e.Mul(
                second,
                e.Next(layout.active));
        });
    Append(
        table, aq::AirKind::kTransition,
        [=](Expr& e) {
            const uint32_t one =
                e.Constant(Fp3::One());
            const uint32_t active =
                e.Current(layout.active);
            const uint32_t padding =
                e.Sub(one, active);
            e.Mul(
                padding,
                e.Next(layout.active));
        });
    Append(
        table, aq::AirKind::kEverywhere,
        [](Expr& e) {
            e.Current(
                kAcceptanceSemanticColumnsV1);
        });
}

void AppendUint256U32(
    std::vector<gf::Fp>& out,
    const uint256& value)
{
    for (uint32_t limb = 0; limb < 8; ++limb) {
        const uint32_t offset = 4 * limb;
        const uint32_t word =
            uint32_t{value.data()[offset]} |
            (uint32_t{value.data()[offset + 1]} << 8) |
            (uint32_t{value.data()[offset + 2]} << 16) |
            (uint32_t{value.data()[offset + 3]} << 24);
        out.push_back(gf::FromU64(word));
    }
}

alg_hash::Digest ComputeBoundRecursiveRoot(
    const cb::ProgramTable& table,
    const uint256& manifest_root)
{
    const auto table_root =
        cb::CommitProgramTableAlgHash(table);
    if (DigestZero(table_root) ||
        manifest_root.IsNull()) {
        return {};
    }
    std::vector<gf::Fp> preimage;
    preimage.reserve(64);
    preimage.push_back(
        gf::FromU64(
            sizeof(kBoundRecursiveDomainV1) - 1));
    for (unsigned char byte :
         std::string{kBoundRecursiveDomainV1}) {
        preimage.push_back(gf::FromU64(byte));
    }
    preimage.push_back(
        gf::FromU64(kAcceptanceBytecodeVersionV1));
    preimage.push_back(
        gf::FromU64(rp::kRecursiveParentVersionV2));
    preimage.push_back(
        gf::FromU64(rp::kRecursiveParentTraceRowsV1));
    preimage.push_back(
        gf::FromU64(kAcceptanceSemanticColumnsV1));
    preimage.push_back(
        gf::FromU64(kAcceptanceProofColumnsV1));
    for (gf::Fp lane : table_root) {
        preimage.push_back(gf::Canonical(lane));
    }
    AppendUint256U32(preimage, manifest_root);
    return alg_hash::SpongeHashFp(preimage);
}

uint256 ComputeBoundExternalRoot(
    const cb::ProgramTable& table,
    const uint256& manifest_root)
{
    const uint256 table_root =
        cb::CommitProgramTable(table);
    if (table_root.IsNull() ||
        manifest_root.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << kBoundExternalDomainV1;
    hash << kAcceptanceBytecodeVersionV1;
    hash << rp::kRecursiveParentVersionV2;
    hash << rp::kRecursiveParentTraceRowsV1;
    hash << kAcceptanceSemanticColumnsV1;
    hash << kAcceptanceProofColumnsV1;
    hash << table_root;
    hash << manifest_root;
    return hash.GetHash();
}

bool ExactInstanceShape(
    const AcceptanceInstanceV1& instance)
{
    return
        instance.version ==
            kAcceptanceBytecodeVersionV1 &&
        instance.layout.n_columns ==
            kAcceptanceSemanticColumnsV1 &&
        instance.structural_cs.n_rows ==
            rp::kRecursiveParentTraceRowsV1 &&
        instance.structural_cs.n_columns ==
            kAcceptanceProofColumnsV1 &&
        instance.structural_cs.constraints.size() ==
            kAcceptanceConstraintCountV1 &&
        instance.legacy_full_callback_cs.n_rows ==
            rp::kRecursiveParentTraceRowsV1 &&
        instance.legacy_full_callback_cs.n_columns ==
            kAcceptanceProofColumnsV1 &&
        instance.legacy_full_callback_cs.constraints.size() ==
            kAcceptanceLegacyFullConstraintCountV1 &&
        instance.columns.size() ==
            kAcceptanceProofColumnsV1 &&
        instance.fixed_trace_columns ==
            rp::CanonicalFixedTraceColumnsV2() &&
        instance.fixed_trace_manifest_root ==
            rp::ComputeFixedTraceManifestRootV2(
                instance.fixed_trace_columns) &&
        !instance.fixed_trace_row_root.IsNull() &&
        !instance.parent_statement_root.IsNull();
}

ProgramBindingV1 BindCandidate(
    const AcceptanceInstanceV1& instance,
    const cb::ProgramTable& candidate)
{
    ProgramBindingV1 out;
    out.table = candidate;
    out.table_commitment =
        cb::CommitProgramTableForExternalAndRecursiveUse(
            candidate);
    out.fixed_trace_manifest_root =
        instance.fixed_trace_manifest_root;
    out.parent_statement_root =
        instance.parent_statement_root;
    out.bound_external_root =
        ComputeBoundExternalRoot(
            candidate,
            out.fixed_trace_manifest_root);
    out.bound_recursive_root =
        ComputeBoundRecursiveRoot(
            candidate,
            out.fixed_trace_manifest_root);
    out.fixed_manifest_version_shape_bound =
        !out.bound_external_root.IsNull() &&
        !DigestZero(out.bound_recursive_root);
    out.residual_mask =
        kResidualConsensusRegistryRoot;
    out.statement_independent_program = true;
    out.consensus_registry_bound = false;
    return out;
}

} // namespace

AcceptanceInstanceV1 BuildAcceptanceInstanceV1(
    const std::array<Fp3, kAcceptanceSemanticColumnsV1>& first_row,
    const std::array<Fp3, kAcceptanceSemanticColumnsV1>& second_row,
    const uint256& parent_statement_root)
{
    AcceptanceInstanceV1 out;
    out.layout = rp::CanonicalLayoutV1();
    out.first_row = first_row;
    out.second_row = second_row;
    out.parent_statement_root =
        parent_statement_root;
    BuildReferenceCallbacks(out);
    out.columns.assign(
        kAcceptanceProofColumnsV1,
        std::vector<Fp3>(
            rp::kRecursiveParentTraceRowsV1,
            Fp3::Zero()));
    for (uint32_t column = 0;
         column < kAcceptanceSemanticColumnsV1;
         ++column) {
        out.columns[column][0] =
            out.first_row[column];
        out.columns[column][1] =
            out.second_row[column];
    }
    out.fixed_trace_columns =
        rp::CanonicalFixedTraceColumnsV2();
    out.fixed_trace_manifest_root =
        rp::ComputeFixedTraceManifestRootV2(
            out.fixed_trace_columns);
    const auto fixed_session =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            out.structural_cs,
            out.columns,
            out.fixed_trace_columns);
    if (fixed_session.valid) {
        out.fixed_trace_row_root =
            fixed_session.base_row_commitment;
    }
    out.exact_v2_shape =
        ExactInstanceShape(out);
    out.dependent_zero_column_constrained =
        std::string{
            out.structural_cs.constraints.back().name} ==
        "stage3.v11_recursive_parent.v2.dependent_zero";
    const uint64_t structural_violations =
        CountViolations(
            out.structural_cs, out.columns);
    const uint64_t full_violations =
        CountViolations(
            out.legacy_full_callback_cs,
            out.columns);
    out.valid =
        out.exact_v2_shape &&
        out.dependent_zero_column_constrained &&
        !out.fixed_trace_row_root.IsNull() &&
        structural_violations == 0 &&
        full_violations == 0;
    out.note = out.valid
        ? "stage3:v11_acceptance_bytecode:"
          "callback_instance_exact"
        : "stage3:v11_acceptance_bytecode:"
          "callback_instance_invalid";
    return out;
}

bool BuildCanonicalProgramTableV1(
    const AcceptanceInstanceV1& instance,
    cb::ProgramTable& out,
    std::string* why)
{
    out = {};
    if (!ExactInstanceShape(instance)) {
        return Fail(why, "instance_shape");
    }
    out.version = cb::kConstraintBytecodeVersion;
    out.role =
        RCStage3RelationRole::CompositionLink;
    out.current_width =
        kAcceptanceProofColumnsV1;
    out.next_width =
        kAcceptanceProofColumnsV1;
    out.challenge_width = 0;
    BuildPrograms(instance, out);
    if (out.programs.size() !=
            kAcceptanceConstraintCountV1 ||
        !cb::ValidateProgramTable(out, why)) {
        out = {};
        return Fail(why, "program_table");
    }
    for (uint32_t ordinal = 0;
         ordinal < out.programs.size();
         ++ordinal) {
        if (out.programs[ordinal].kind !=
                instance.structural_cs
                    .constraints[ordinal].kind ||
            out.programs[ordinal].declared_degree !=
                instance.structural_cs
                    .constraints[ordinal].alg_degree) {
            out = {};
            return Fail(why, "callback_metadata");
        }
    }
    return true;
}

DifferentialAuditV1 AuditAgainstCallbacksV1(
    const AcceptanceInstanceV1& instance,
    const cb::ProgramTable& table,
    uint32_t adversarial_probes)
{
    DifferentialAuditV1 out;
    out.callback_constraints =
        static_cast<uint32_t>(
            instance.structural_cs.constraints.size());
    out.bytecode_programs =
        static_cast<uint32_t>(
            table.programs.size());
    out.shape_and_order_exact =
        ExactInstanceShape(instance) &&
        cb::ValidateProgramTable(table, nullptr) &&
        out.callback_constraints ==
            kAcceptanceConstraintCountV1 &&
        out.bytecode_programs ==
            out.callback_constraints;
    if (!out.shape_and_order_exact) {
        out.note =
            "stage3:v11_acceptance_bytecode_audit:shape";
        return out;
    }
    for (uint32_t ordinal = 0;
         ordinal < table.programs.size();
         ++ordinal) {
        if (table.programs[ordinal].kind !=
                instance.structural_cs
                    .constraints[ordinal].kind ||
            table.programs[ordinal].declared_degree !=
                instance.structural_cs
                    .constraints[ordinal].alg_degree) {
            out.note =
                "stage3:v11_acceptance_bytecode_audit:"
                "metadata";
            return out;
        }
    }
    const auto compare =
        [&](const std::vector<Fp3>& current,
            const std::vector<Fp3>& next) {
            for (uint32_t ordinal = 0;
                 ordinal < table.programs.size();
                 ++ordinal) {
                const Fp3 callback =
                    instance.structural_cs
                        .constraints[ordinal]
                        .eval(current, next);
                Fp3 bytecode = Fp3::Zero();
                if (!cb::EvaluateProgram(
                        table.programs[ordinal],
                        current, next,
                        bytecode, nullptr) ||
                    !gf::Eq(callback, bytecode)) {
                    ++out.mismatches;
                }
                ++out.evaluations;
            }
        };
    std::vector<Fp3> current(
        kAcceptanceProofColumnsV1);
    std::vector<Fp3> next(
        kAcceptanceProofColumnsV1);
    for (uint32_t row = 0;
         row < rp::kRecursiveParentTraceRowsV1;
         ++row) {
        const uint32_t next_row =
            (row + 1) %
            rp::kRecursiveParentTraceRowsV1;
        for (uint32_t column = 0;
             column < kAcceptanceProofColumnsV1;
             ++column) {
            current[column] =
                instance.columns[column][row];
            next[column] =
                instance.columns[column][next_row];
        }
        compare(current, next);
    }
    out.honest_rows =
        rp::kRecursiveParentTraceRowsV1;
    const uint64_t honest_evaluations =
        uint64_t{out.honest_rows} *
        out.bytecode_programs;
    out.honest_rows_bit_exact =
        out.mismatches == 0 &&
        out.evaluations ==
            honest_evaluations;
    const uint64_t before_adversarial =
        out.mismatches;
    for (uint32_t probe = 0;
         probe < adversarial_probes; ++probe) {
        for (uint32_t column = 0;
             column < kAcceptanceProofColumnsV1;
             ++column) {
            const uint64_t base =
                1 + uint64_t{probe} * 257 +
                uint64_t{column} * 65537;
            current[column] = Fp3{
                gf::FromU64(base),
                gf::FromU64(base + 17),
                gf::FromU64(base + 31)};
            next[column] = Fp3{
                gf::FromU64(base + 43),
                gf::FromU64(base + 59),
                gf::FromU64(base + 71)};
        }
        compare(current, next);
    }
    out.adversarial_probes =
        adversarial_probes;
    out.adversarial_rows_bit_exact =
        out.mismatches ==
            before_adversarial;
    out.valid =
        out.honest_rows_bit_exact &&
        out.adversarial_rows_bit_exact &&
        out.mismatches == 0;
    out.note = out.valid
        ? "stage3:v11_acceptance_bytecode_audit:"
          "bit_exact"
        : "stage3:v11_acceptance_bytecode_audit:"
          "semantic_drift";
    return out;
}

FixedTraceRedundancyAuditV1
AuditFixedTracePinRedundancyV1(
    const AcceptanceInstanceV1& instance)
{
    FixedTraceRedundancyAuditV1 out;
    out.structural_constraints =
        static_cast<uint32_t>(
            instance.structural_cs.constraints.size());
    out.legacy_full_constraints =
        static_cast<uint32_t>(
            instance.legacy_full_callback_cs
                .constraints.size());
    if (out.legacy_full_constraints >=
            out.structural_constraints) {
        out.legacy_pin_constraints =
            out.legacy_full_constraints -
            out.structural_constraints;
    }
    out.covered_semantic_columns =
        static_cast<uint32_t>(
            instance.fixed_trace_columns.size());
    out.covered_trace_rows =
        instance.structural_cs.n_rows;
    out.exact_ordered_fixed_trace_coverage =
        instance.fixed_trace_columns ==
            rp::CanonicalFixedTraceColumnsV2() &&
        out.covered_semantic_columns ==
            kAcceptanceSemanticColumnsV1 &&
        instance.fixed_trace_manifest_root ==
            rp::ComputeFixedTraceManifestRootV2(
                instance.fixed_trace_columns);
    const auto fixed_session =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            instance.structural_cs,
            instance.columns,
            instance.fixed_trace_columns);
    const auto legacy_fixed_session =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            instance.legacy_full_callback_cs,
            instance.columns,
            instance.fixed_trace_columns);
    out.fixed_trace_root_recomputed =
        fixed_session.valid &&
        legacy_fixed_session.valid &&
        instance.structural_cs.QuotientLen() ==
            instance.legacy_full_callback_cs.QuotientLen() &&
        !fixed_session.base_row_commitment.IsNull() &&
        fixed_session.base_row_commitment ==
            instance.fixed_trace_row_root &&
        legacy_fixed_session.base_row_commitment ==
            instance.fixed_trace_row_root;
    out.statement_owns_fixed_trace_root =
        !instance.parent_statement_root.IsNull() &&
        !instance.fixed_trace_row_root.IsNull();
    out.structural_trace_accepts =
        CountViolations(
            instance.structural_cs,
            instance.columns) == 0;
    out.legacy_full_trace_accepts =
        CountViolations(
            instance.legacy_full_callback_cs,
            instance.columns) == 0;

    // Every historical pin is individually non-vacuous. FixedTrace covers
    // the cell it pins, so changing that cell cannot preserve its public row
    // root without a commitment collision.
    std::vector<Fp3> current(
        kAcceptanceProofColumnsV1);
    std::vector<Fp3> next(
        kAcceptanceProofColumnsV1);
    for (uint32_t column = 0;
         column < kAcceptanceSemanticColumnsV1;
         ++column) {
        for (uint32_t family = 0;
             family < kAcceptancePinConstraintsPerColumnV1;
             ++family) {
            const uint32_t row =
                family == 0 ? 0 :
                family == 1 ? 1 : 2;
            const uint32_t next_row =
                row + 1;
            for (uint32_t lane = 0;
                 lane < kAcceptanceProofColumnsV1;
                 ++lane) {
                current[lane] =
                    instance.columns[lane][row];
                next[lane] =
                    instance.columns[lane][next_row];
            }
            current[column] =
                gf::Add(current[column], U(2));
            const uint32_t ordinal =
                kAcceptanceStructuralConstraintsV1 +
                column *
                    kAcceptancePinConstraintsPerColumnV1 +
                family;
            ++out.pin_family_mutations_tested;
            if (!gf::IsZero(
                    instance.legacy_full_callback_cs
                        .constraints[ordinal]
                        .eval(current, next))) {
                ++out.pin_family_mutations_rejected;
            }
        }
    }

    // Recompute one changed fixed-trace root for each pin family. Exact
    // ordered coverage then extends this preimage-separation witness to every
    // covered cell; preserving the digest would be a commitment collision.
    bool representative_roots_changed = true;
    for (uint32_t family = 0;
         family < kAcceptancePinConstraintsPerColumnV1;
         ++family) {
        auto mutated = instance.columns;
        const uint32_t row =
            family == 0 ? 0 :
            family == 1 ? 1 : 2;
        mutated[instance.layout.accepted][row] =
            gf::Add(
                mutated[instance.layout.accepted][row],
                U(2));
        const auto mutated_session =
            aq::AirQuotientBuildTwoEpochBaseRowSession(
                instance.structural_cs,
                mutated,
                instance.fixed_trace_columns);
        representative_roots_changed &=
            mutated_session.valid &&
            !mutated_session.base_row_commitment.IsNull() &&
            mutated_session.base_row_commitment !=
                instance.fixed_trace_row_root;
    }
    out.every_pin_equation_redundant_under_fixed_trace =
        out.exact_ordered_fixed_trace_coverage &&
        out.fixed_trace_root_recomputed &&
        out.statement_owns_fixed_trace_root &&
        out.pin_family_mutations_tested ==
            kAcceptanceLegacyPinConstraintCountV1 &&
        out.pin_family_mutations_rejected ==
            out.pin_family_mutations_tested &&
        representative_roots_changed;
    out.no_full_callback_equation_nonredundant =
        out.structural_constraints ==
            kAcceptanceConstraintCountV1 &&
        out.legacy_pin_constraints ==
            kAcceptanceLegacyPinConstraintCountV1 &&
        out.legacy_full_constraints ==
            kAcceptanceLegacyFullConstraintCountV1 &&
        out.structural_trace_accepts &&
        out.legacy_full_trace_accepts &&
        out.every_pin_equation_redundant_under_fixed_trace;
    out.valid =
        out.no_full_callback_equation_nonredundant;
    out.note = out.valid
        ? "stage3:v11_acceptance_fixed_trace:"
          "222_legacy_pins_redundant;11_static_required"
        : "stage3:v11_acceptance_fixed_trace:"
          "redundancy_not_established";
    return out;
}

ProgramBindingV1 AssessCanonicalProgramV1(
    const AcceptanceInstanceV1& instance,
    const cb::ProgramTable& candidate,
    uint32_t adversarial_probes)
{
    ProgramBindingV1 out =
        BindCandidate(instance, candidate);
    cb::ProgramTable expected;
    out.exact_program_table =
        BuildCanonicalProgramTableV1(
            instance, expected, nullptr) &&
        candidate == expected;
    const auto audit =
        AuditAgainstCallbacksV1(
            instance, candidate,
            adversarial_probes);
    const auto redundancy =
        AuditFixedTracePinRedundancyV1(
            instance);
    out.exact_callback_order =
        audit.shape_and_order_exact;
    out.fixed_trace_pin_redundancy_proved =
        redundancy.valid;
    AcceptanceInstanceV1 alternate = instance;
    alternate.parent_statement_root.data()[0] ^=
        0x80;
    if (alternate.parent_statement_root.IsNull()) {
        alternate.parent_statement_root.data()[0] = 1;
    }
    cb::ProgramTable alternate_table;
    out.statement_independent_program =
        BuildCanonicalProgramTableV1(
            alternate, alternate_table, nullptr) &&
        alternate_table == candidate;
    out.canonical_bytecode_residual_removable =
        out.exact_program_table &&
        audit.valid &&
        out.fixed_trace_pin_redundancy_proved &&
        out.statement_independent_program;
    out.canonical_bytecode_complete =
        out.canonical_bytecode_residual_removable &&
        out.fixed_manifest_version_shape_bound;
    out.valid =
        out.canonical_bytecode_complete &&
        out.residual_mask != 0 &&
        !out.consensus_registry_bound;
    out.note = out.valid
        ? "stage3:v11_acceptance_bytecode:"
          "canonical_static_relation_complete;"
          "registry_root_open"
        : "stage3:v11_acceptance_bytecode:"
          "candidate_rejected";
    return out;
}

ProgramBindingV1 BuildProgramBindingV1(
    const AcceptanceInstanceV1& instance)
{
    cb::ProgramTable table;
    if (!BuildCanonicalProgramTableV1(
            instance, table, nullptr)) {
        ProgramBindingV1 out;
        out.note =
            "stage3:v11_acceptance_bytecode:"
            "build_failed";
        return out;
    }
    return AssessCanonicalProgramV1(
        instance, table);
}

RegistryMembershipAssessmentV1
AssessRegistryMembershipV1(
    const ProgramBindingV1& binding,
    const ut::ProductionProgramRegistryV1& registry,
    const alg_hash::Digest& expected_consensus_registry_root)
{
    RegistryMembershipAssessmentV1 out;
    out.expected_consensus_registry_root =
        expected_consensus_registry_root;
    out.expected_program_leaf =
        binding.table_commitment;
    out.consensus_root_supplied =
        !DigestZero(expected_consensus_registry_root);
    const auto preimage =
        ut::BuildProductionProgramRegistryAlgHashPreimageV1(
            registry);
    if (!preimage.empty()) {
        out.recomputed_registry_root =
            alg_hash::SpongeHashFp(preimage);
        out.registry_root_recomputed =
            !DigestZero(
                out.recomputed_registry_root) &&
            DigestEqual(
                out.recomputed_registry_root,
                registry.recursive_registry_commitment);
    }
    out.registry_root_matches_consensus =
        out.consensus_root_supplied &&
        out.registry_root_recomputed &&
        DigestEqual(
            out.recomputed_registry_root,
            expected_consensus_registry_root);
    out.exact_program_leaf_matches =
        binding.valid &&
        registry.universal_parent_verifier ==
            binding.table_commitment;
    out.exact_width_matches =
        registry.universal_parent_columns ==
            kAcceptanceProofColumnsV1;
    // The manifest/version/shape pin is carried by the V2 statement. The
    // registry selects only the static verifier program, which is sufficient
    // because the program contains no statement-derived constants.
    out.current_schema_binds_fixed_manifest = false;
    out.static_program_schema_compatible =
        binding.statement_independent_program &&
        binding.fixed_trace_pin_redundancy_proved;
    out.raw_table_membership_proved =
        out.registry_root_matches_consensus &&
        out.exact_program_leaf_matches &&
        out.exact_width_matches;
    out.bound_program_membership_proved =
        out.raw_table_membership_proved &&
        out.static_program_schema_compatible;
    out.production_authority = false;
    out.note =
        out.bound_program_membership_proved
        ? "stage3:v11_acceptance_registry:"
          "static_leaf_authenticated;"
          "global_authority_still_open"
        : "stage3:v11_acceptance_registry:"
          "consensus_root_or_leaf_open";
    return out;
}

} // namespace matmul::v4::rc::
  // stage3_multirow_v11_acceptance_bytecode
