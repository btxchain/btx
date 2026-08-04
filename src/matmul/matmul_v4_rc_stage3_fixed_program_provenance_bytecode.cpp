// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/MIT.

#include <matmul/matmul_v4_rc_stage3_fixed_program_provenance_bytecode.h>

#include <hash.h>
#include <matmul/matmul_v4_rc_stage3_role_bytecode.h>

#include <algorithm>
#include <array>
#include <functional>
#include <utility>

namespace matmul::v4::rc::fixed_program_provenance_bytecode {
namespace {

namespace aq = air_quotient;
namespace gf = gkr_field;
using gf::Fp3;

bool Fail(std::string* why, const char* suffix)
{
    if (why != nullptr) {
        *why =
            std::string{
                "stage3:fixed_program_provenance_bytecode:"} +
            suffix;
    }
    return false;
}

class Builder {
public:
    explicit Builder(cb::Program& program) : m_program(program) {}

    uint32_t Current(uint32_t column)
    {
        return Emit({cb::Opcode::Current, column, 0, Fp3::Zero()});
    }
    uint32_t Next(uint32_t column)
    {
        return Emit({cb::Opcode::Next, column, 0, Fp3::Zero()});
    }
    uint32_t Challenge(uint32_t column)
    {
        return Emit({cb::Opcode::Challenge, column, 0, Fp3::Zero()});
    }
    uint32_t Constant(const Fp3& value)
    {
        return Emit({cb::Opcode::Constant, 0, 0, value});
    }
    uint32_t Add(uint32_t lhs, uint32_t rhs)
    {
        return Emit({cb::Opcode::Add, lhs, rhs, Fp3::Zero()});
    }
    uint32_t Sub(uint32_t lhs, uint32_t rhs)
    {
        return Emit({cb::Opcode::Sub, lhs, rhs, Fp3::Zero()});
    }
    uint32_t Mul(uint32_t lhs, uint32_t rhs)
    {
        return Emit({cb::Opcode::Mul, lhs, rhs, Fp3::Zero()});
    }

private:
    uint32_t Emit(cb::Instruction instruction)
    {
        m_program.instructions.push_back(std::move(instruction));
        return static_cast<uint32_t>(
            m_program.instructions.size() - 1);
    }
    cb::Program& m_program;
};

void Append(
    cb::ProgramTable& table,
    aq::AirKind kind,
    uint32_t degree,
    const std::function<void(Builder&)>& emit)
{
    cb::Program program;
    program.role = table.role;
    program.constraint_ordinal =
        static_cast<uint32_t>(table.programs.size());
    program.kind = kind;
    program.declared_degree = degree;
    program.current_width = table.current_width;
    program.next_width = table.next_width;
    program.challenge_width = table.challenge_width;
    Builder builder(program);
    emit(builder);
    table.programs.push_back(std::move(program));
}

uint32_t OutputValue(Builder& b)
{
    uint32_t word1_selector =
        b.Current(ha::kFixedProgramSelectorBase + 7);
    for (uint32_t selector = 8; selector <= 10; ++selector) {
        word1_selector = b.Add(
            word1_selector,
            b.Current(
                ha::kFixedProgramSelectorBase + selector));
    }
    uint32_t word2_selector =
        b.Current(ha::kFixedProgramSelectorBase);
    for (uint32_t selector = 1; selector <= 4; ++selector) {
        word2_selector = b.Add(
            word2_selector,
            b.Current(
                ha::kFixedProgramSelectorBase + selector));
    }
    const uint32_t word3_selector = b.Add(
        b.Current(ha::kFixedProgramSelectorBase + 5),
        b.Current(ha::kFixedProgramSelectorBase + 6));
    return b.Add(
        b.Mul(
            word1_selector,
            b.Current(ha::ValueColumn(1))),
        b.Add(
            b.Mul(
                word2_selector,
                b.Current(ha::ValueColumn(2))),
            b.Mul(
                word3_selector,
                b.Current(ha::ValueColumn(3)))));
}

uint32_t WeightedInputColumn(uint32_t lane, uint32_t input)
{
    return kWeightedInputBaseV1 + 3 * lane + input;
}

void WidenBase(
    cb::ProgramTable& table,
    RCStage3RelationRole role)
{
    table.role = role;
    table.current_width = kColumnsV1;
    table.next_width = kColumnsV1;
    table.challenge_width = kChallengeWidthV1;
    for (auto& program : table.programs) {
        program.role = role;
        program.current_width = kColumnsV1;
        program.next_width = kColumnsV1;
        program.challenge_width = kChallengeWidthV1;
    }
}

void AppendBoundary(cb::ProgramTable& table)
{
    for (uint32_t word = 0; word < 4; ++word) {
        Append(
            table, aq::AirKind::kEverywhere, 2,
            [word](Builder& b) {
                b.Mul(
                    b.Current(
                        ha::kFixedProgramBoundaryMaskBase + word),
                    b.Sub(
                        b.Current(ha::ValueColumn(word)),
                        b.Current(
                            ha::kFixedProgramBoundaryExpectedBase +
                            word)));
            });
    }
}

void AppendProvenanceLane(
    cb::ProgramTable& table,
    uint32_t lane)
{
    const uint32_t gamma = 2 * lane;
    const uint32_t alpha = gamma + 1;
    const uint32_t producer_inverse =
        lane == 0
        ? ha::kFixedProgramProvenanceProducerInverse1
        : ha::kFixedProgramProvenanceProducerInverse2;
    const uint32_t consumer_base =
        lane == 0
        ? ha::kFixedProgramProvenanceConsumerInverse1Base
        : ha::kFixedProgramProvenanceConsumerInverse2Base;
    const uint32_t running =
        lane == 0
        ? ha::kFixedProgramProvenanceRunning1
        : ha::kFixedProgramProvenanceRunning2;

    Append(
        table, aq::AirKind::kEverywhere, 2,
        [=](Builder& b) {
            const uint32_t tuple = b.Add(
                b.Current(
                    ha::kFixedProgramProvenanceOutputAddress),
                b.Current(kWeightedOutputBaseV1 + lane));
            b.Sub(
                b.Mul(
                    b.Sub(b.Challenge(alpha), tuple),
                    b.Current(producer_inverse)),
                b.Current(
                    ha::kFixedProgramProvenanceOutputHasUse));
        });
    Append(
        table, aq::AirKind::kEverywhere, 2,
        [=](Builder& b) {
            b.Mul(
                b.Sub(
                    b.Constant(Fp3::One()),
                    b.Current(
                        ha::kFixedProgramProvenanceOutputHasUse)),
                b.Current(producer_inverse));
        });
    for (uint32_t input = 0; input < 3; ++input) {
        Append(
            table, aq::AirKind::kEverywhere, 2,
            [=](Builder& b) {
                const uint32_t tuple = b.Add(
                    b.Current(
                        ha::kFixedProgramProvenanceInputAddressBase +
                        input),
                    b.Current(
                        WeightedInputColumn(lane, input)));
                b.Sub(
                    b.Mul(
                        b.Sub(b.Challenge(alpha), tuple),
                        b.Current(consumer_base + input)),
                    b.Current(
                        ha::kFixedProgramProvenanceInputMaskBase +
                        input));
            });
        Append(
            table, aq::AirKind::kEverywhere, 2,
            [=](Builder& b) {
                b.Mul(
                    b.Sub(
                        b.Constant(Fp3::One()),
                        b.Current(
                            ha::kFixedProgramProvenanceInputMaskBase +
                            input)),
                    b.Current(consumer_base + input));
            });
    }
    const auto contribution =
        [=](Builder& b) {
            uint32_t value = b.Mul(
                b.Current(
                    ha::kFixedProgramProvenanceOutputUseCount),
                b.Current(producer_inverse));
            for (uint32_t input = 0; input < 3; ++input) {
                value = b.Sub(
                    value,
                    b.Mul(
                        b.Current(
                            ha::kFixedProgramProvenanceInputMaskBase +
                            input),
                        b.Current(consumer_base + input)));
            }
            return value;
        };
    Append(
        table, aq::AirKind::kFirstRow, 1,
        [=](Builder& b) { b.Current(running); });
    Append(
        table, aq::AirKind::kTransition, 2,
        [=](Builder& b) {
            b.Sub(
                b.Next(running),
                b.Add(b.Current(running), contribution(b)));
        });
    Append(
        table, aq::AirKind::kLastRow, 2,
        [=](Builder& b) {
            b.Add(b.Current(running), contribution(b));
        });
}

void AppendOutput(cb::ProgramTable& table)
{
    Append(
        table, aq::AirKind::kEverywhere, 2,
        [](Builder& b) {
            b.Sub(
                b.Current(kOutputColumnV1),
                OutputValue(b));
        });
}

void AppendChallengeProducts(cb::ProgramTable& table)
{
    for (uint32_t lane = 0; lane < 2; ++lane) {
        const uint32_t gamma = 2 * lane;
        Append(
            table, aq::AirKind::kEverywhere, 2,
            [=](Builder& b) {
                b.Sub(
                    b.Current(kWeightedOutputBaseV1 + lane),
                    b.Mul(
                        b.Challenge(gamma),
                        b.Current(kOutputColumnV1)));
            });
        for (uint32_t input = 0; input < 3; ++input) {
            Append(
                table, aq::AirKind::kEverywhere, 2,
                [=](Builder& b) {
                    b.Sub(
                        b.Current(
                            WeightedInputColumn(lane, input)),
                        b.Mul(
                            b.Challenge(gamma),
                            b.Current(ha::ValueColumn(input))));
                });
        }
    }
}

bool ImmutableColumn(uint32_t column)
{
    return
        (column >= ha::kFixedProgramSelectorBase &&
         column <
             ha::kFixedProgramSelectorBase +
                 ha::kFixedProgramOpcodeCount) ||
        (column >= ha::kFixedProgramBoundaryMaskBase &&
         column <
             ha::kFixedProgramBoundaryMaskBase + 4) ||
        (column >= ha::kFixedProgramProvenanceOutputAddress &&
         column < ha::kFixedProgramProvenanceBaseColumns);
}

bool BuildImmutableSchedule(
    const ha::FixedProgram& program,
    ManifestV1& manifest,
    std::string* why)
{
    std::vector<uint32_t> external(
        program.external_address_count, 0);
    ha::ProgramWitness witness;
    if (!ha::BuildProgramWitness(
            program, external, witness, why)) {
        return false;
    }
    HashWriter seed_hash;
    seed_hash <<
        "BTX/RC/STAGE3/FIXED-PROGRAM/"
        "IMMUTABLE-SCHEDULE-SEED/V1";
    seed_hash << ha::CommitFixedProgram(program);
    const auto instance =
        ha::BuildFixedProgramProvenanceInstance(
            program, witness, external,
            witness.final_words, seed_hash.GetHash());
    if (!instance.valid) {
        if (why != nullptr) *why = instance.note;
        return false;
    }
    const auto& cs = instance.cs;
    HashWriter hash;
    hash <<
        "BTX/RC/STAGE3/FIXED-PROGRAM/"
        "IMMUTABLE-PREPROCESSED/V1";
    hash << kVersionV1;
    hash << static_cast<uint8_t>(program.kind);
    hash << ha::CommitFixedProgram(program);
    hash << cs.n_rows;
    hash << cs.n_columns;
    for (const auto& [column, values] : cs.preprocessed) {
        if (!ImmutableColumn(column)) continue;
        manifest.immutable_schedule_columns.push_back(column);
        hash << column;
        hash << static_cast<uint32_t>(values.size());
        for (const Fp3& value : values) {
            hash << gf::Canonical(value.c0);
            hash << gf::Canonical(value.c1);
            hash << gf::Canonical(value.c2);
        }
    }
    manifest.immutable_schedule_root = hash.GetHash();
    return
        !manifest.immutable_schedule_root.IsNull() &&
        !manifest.immutable_schedule_columns.empty() &&
        std::is_sorted(
            manifest.immutable_schedule_columns.begin(),
            manifest.immutable_schedule_columns.end()) &&
        std::adjacent_find(
            manifest.immutable_schedule_columns.begin(),
            manifest.immutable_schedule_columns.end()) ==
            manifest.immutable_schedule_columns.end();
}

Fp3 NativeOutput(const std::vector<Fp3>& row)
{
    Fp3 word1 = Fp3::Zero();
    for (uint32_t selector = 7; selector <= 10; ++selector) {
        word1 = gf::Add(
            word1,
            gf::Mul(
                row[ha::kFixedProgramSelectorBase + selector],
                row[ha::ValueColumn(1)]));
    }
    Fp3 word2 = Fp3::Zero();
    for (uint32_t selector = 0; selector <= 4; ++selector) {
        word2 = gf::Add(
            word2,
            gf::Mul(
                row[ha::kFixedProgramSelectorBase + selector],
                row[ha::ValueColumn(2)]));
    }
    const Fp3 word3 = gf::Mul(
        gf::Add(
            row[ha::kFixedProgramSelectorBase + 5],
            row[ha::kFixedProgramSelectorBase + 6]),
        row[ha::ValueColumn(3)]);
    return gf::Add(word1, gf::Add(word2, word3));
}

uint64_t SplitMix64(uint64_t& state)
{
    state += UINT64_C(0x9e3779b97f4a7c15);
    uint64_t value = state;
    value =
        (value ^ (value >> 30)) *
        UINT64_C(0xbf58476d1ce4e5b9);
    value =
        (value ^ (value >> 27)) *
        UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31);
}

} // namespace

bool BuildCanonicalProgramTableV1(
    RCStage3RelationRole role,
    ha::ProgramKind program_kind,
    cb::ProgramTable& out,
    ManifestV1* manifest,
    std::string* why)
{
    out = {};
    cb::ProgramTable base;
    if (!BuildRCStage3CoupledHashKernelProgramTable(
            RCStage3RelationRole::EpisodeDigest,
            base, why)) {
        return Fail(why, "base_program");
    }
    WidenBase(base, role);
    out = std::move(base);
    AppendBoundary(out);
    AppendOutput(out);
    AppendChallengeProducts(out);
    AppendProvenanceLane(out, 0);
    AppendProvenanceLane(out, 1);
    if (out.programs.size() != kProgramsV1) {
        out = {};
        return Fail(why, "program_count");
    }
    for (uint32_t ordinal = 0;
         ordinal < out.programs.size();
         ++ordinal) {
        std::string program_why;
        if (!cb::ValidateProgram(
                out.programs[ordinal], &program_why)) {
            if (why != nullptr) {
                *why =
                    "stage3:fixed_program_provenance_bytecode:"
                    "program_" +
                    std::to_string(ordinal) + ":" +
                    program_why;
            }
            out = {};
            return false;
        }
    }
    if (!cb::ValidateProgramTable(out, why)) {
        out = {};
        return false;
    }

    ManifestV1 local;
    local.program_kind = program_kind;
    local.role = role;
    const auto program =
        ha::BuildCanonicalProgram(program_kind);
    local.fixed_program_commitment =
        ha::CommitFixedProgram(program);
    local.rows = 1024;
    local.columns = out.current_width;
    local.programs =
        static_cast<uint32_t>(out.programs.size());
    local.challenge_width = out.challenge_width;
    local.exact_native_constraint_order =
        out.programs.size() == kProgramsV1;
    local.canonical_program_table =
        cb::ValidateProgramTable(out, nullptr);
    local.immutable_schedule_reconstructed =
        BuildImmutableSchedule(program, local, why);
    local.internal_ssa_provenance_complete =
        local.exact_native_constraint_order &&
        local.canonical_program_table &&
        local.immutable_schedule_reconstructed;
    local.residual_mask =
        kResidualPublicBoundarySourceLink |
        kResidualFixedTraceRootConsumption |
        kResidualExactAllInstanceAggregation |
        kResidualRecursiveChildConsumption;
    local.authority_eligible =
        local.internal_ssa_provenance_complete &&
        local.residual_mask == 0;
    local.note =
        "stage3:fixed_program_provenance_bytecode:"
        "exact_local_relation;external_links_open";
    if (manifest != nullptr) *manifest = std::move(local);
    return true;
}

DifferentialAuditV1 AuditAgainstNativeV1(
    RCStage3RelationRole role,
    ha::ProgramKind program_kind,
    uint32_t probes)
{
    DifferentialAuditV1 out;
    cb::ProgramTable table;
    ManifestV1 manifest;
    if (probes == 0 ||
        !BuildCanonicalProgramTableV1(
            role, program_kind, table, &manifest, nullptr)) {
        out.note =
            "stage3:fixed_program_provenance_bytecode:"
            "audit_build";
        return out;
    }
    const auto program =
        ha::BuildCanonicalProgram(program_kind);
    std::vector<uint32_t> external(
        program.external_address_count);
    for (uint32_t i = 0; i < external.size(); ++i) {
        external[i] = 0x9e3779b9U * (i + 1U);
    }
    ha::ProgramWitness witness;
    if (!ha::BuildProgramWitness(
            program, external, witness, nullptr)) {
        out.note =
            "stage3:fixed_program_provenance_bytecode:"
            "audit_witness";
        return out;
    }
    HashWriter seed_hash;
    seed_hash <<
        "BTX/RC/STAGE3/FIXED-PROGRAM/"
        "DIFFERENTIAL-SEED/V1";
    seed_hash << static_cast<uint8_t>(program_kind);
    const auto instance =
        ha::BuildFixedProgramProvenanceInstance(
            program, witness, external,
            witness.final_words, seed_hash.GetHash());
    if (!instance.valid) {
        out.note =
            "stage3:fixed_program_provenance_bytecode:"
            "audit_native";
        return out;
    }
    const auto& native = instance.cs;
    const auto& challenges = instance.challenges;
    out.native_constraints =
        static_cast<uint32_t>(native.constraints.size());
    out.bytecode_programs =
        static_cast<uint32_t>(table.programs.size());
    out.probes = probes;
    out.exact_order =
        out.native_constraints ==
            462 + kBoundaryProgramsV1 +
                kProvenanceProgramsV1 &&
        out.bytecode_programs == kProgramsV1;
    if (!out.exact_order) {
        out.note =
            "stage3:fixed_program_provenance_bytecode:"
            "audit_order";
        return out;
    }
    const std::vector<Fp3> challenge_values{
        challenges.gamma1, challenges.alpha1,
        challenges.gamma2, challenges.alpha2};
    uint64_t state = UINT64_C(0x243f6a8885a308d3);
    for (uint32_t probe = 0; probe < probes; ++probe) {
        std::vector<Fp3> current(kColumnsV1);
        std::vector<Fp3> next(kColumnsV1);
        for (Fp3& value : current) {
            value = gf::FromU64_3(SplitMix64(state));
        }
        for (Fp3& value : next) {
            value = gf::FromU64_3(SplitMix64(state));
        }
        current[kOutputColumnV1] =
            NativeOutput(current);
        for (uint32_t lane = 0; lane < 2; ++lane) {
            const Fp3 gamma_value =
                challenge_values[2 * lane];
            current[kWeightedOutputBaseV1 + lane] =
                gf::Mul(
                    gamma_value,
                    current[kOutputColumnV1]);
            for (uint32_t input = 0; input < 3; ++input) {
                current[
                    WeightedInputColumn(lane, input)] =
                    gf::Mul(
                        gamma_value,
                        current[ha::ValueColumn(input)]);
            }
        }
        for (uint32_t ordinal = 0;
             ordinal < native.constraints.size();
             ++ordinal) {
            const uint32_t bytecode_ordinal =
                ordinal <
                    462 + kBoundaryProgramsV1
                ? ordinal
                : ordinal +
                    kOutputProgramsV1 +
                    kChallengeProductProgramsV1;
            Fp3 interpreted;
            if (!cb::EvaluateProgram(
                    table.programs[bytecode_ordinal],
                    current, next,
                    challenge_values, interpreted) ||
                !gf::Eq(
                    interpreted,
                    native.constraints[ordinal].eval(
                        current, next))) {
                ++out.mismatches;
            }
            ++out.evaluations;
        }

        const uint32_t output_ordinal =
            462 + kBoundaryProgramsV1;
        Fp3 output;
        if (!cb::EvaluateProgram(
                table.programs[output_ordinal],
                current, next,
                challenge_values, output) ||
            !gf::IsZero(output)) {
            ++out.mismatches;
        }
        ++out.evaluations;
        current[kOutputColumnV1] =
            gf::Add(
                current[kOutputColumnV1],
                Fp3::One());
        if (!cb::EvaluateProgram(
                table.programs[output_ordinal],
                current, next,
                challenge_values, output) ||
            gf::IsZero(output)) {
            ++out.mismatches;
        }
        ++out.evaluations;
        current[kOutputColumnV1] =
            NativeOutput(current);

        const uint32_t product_base =
            output_ordinal + kOutputProgramsV1;
        uint32_t product_ordinal = product_base;
        for (uint32_t lane = 0; lane < 2; ++lane) {
            std::array<uint32_t, 4> product_columns{
                kWeightedOutputBaseV1 + lane,
                WeightedInputColumn(lane, 0),
                WeightedInputColumn(lane, 1),
                WeightedInputColumn(lane, 2)};
            for (uint32_t product_column : product_columns) {
                Fp3 product;
                if (!cb::EvaluateProgram(
                        table.programs[product_ordinal],
                        current, next, challenge_values,
                        product) ||
                    !gf::IsZero(product)) {
                    ++out.mismatches;
                }
                ++out.evaluations;
                current[product_column] =
                    gf::Add(
                        current[product_column],
                        Fp3::One());
                if (!cb::EvaluateProgram(
                        table.programs[product_ordinal],
                        current, next, challenge_values,
                        product) ||
                    gf::IsZero(product)) {
                    ++out.mismatches;
                }
                ++out.evaluations;
                current[product_column] =
                    gf::Sub(
                        current[product_column],
                        Fp3::One());
                ++product_ordinal;
            }
        }
    }
    out.challenge_products_checked = true;
    out.output_relation_checked = true;
    out.valid =
        out.exact_order &&
        out.challenge_products_checked &&
        out.output_relation_checked &&
        out.mismatches == 0;
    out.note = out.valid
        ? "stage3:fixed_program_provenance_bytecode:"
          "native_differential_exact"
        : "stage3:fixed_program_provenance_bytecode:"
          "native_differential_mismatch";
    return out;
}

} // namespace matmul::v4::rc::fixed_program_provenance_bytecode
