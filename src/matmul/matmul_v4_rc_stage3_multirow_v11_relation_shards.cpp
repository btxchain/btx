// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_multirow_v11_relation_shards.h>

#include <algorithm>
#include <limits>

namespace matmul::v4::rc::stage3_multirow_v11_relation_shards {
namespace {

using gf::Fp3;

bool DigestEq(
    const alg_hash::Digest& a,
    const alg_hash::Digest& b)
{
    for (uint32_t i = 0; i < alg_hash::kAlgHashDigestLen; ++i) {
        if (gf::Canonical(a[i]) != gf::Canonical(b[i])) return false;
    }
    return true;
}

Fp3 Pow(Fp3 base, uint32_t exponent)
{
    Fp3 out = Fp3::One();
    while (exponent != 0) {
        if ((exponent & 1U) != 0) out = gf::Mul(out, base);
        base = gf::Mul(base, base);
        exponent >>= 1;
    }
    return out;
}

SymbolicCompositionAuditV1 SymbolicAudit(
    const std::array<ShardV1, kRelationShardsV1>& shards,
    uint32_t expected)
{
    SymbolicCompositionAuditV1 out;
    out.expected_terms = expected;
    std::vector<uint32_t> occurrences(expected, 0);
    for (const auto& shard : shards) {
        for (uint32_t local = 0;
             local < shard.program_count; ++local) {
            const uint32_t global = shard.first_program + local;
            if (global >= expected) {
                ++out.wrong_lambda_exponents;
                continue;
            }
            ++occurrences[global];
            ++out.covered_terms;
            if (shard.first_lambda_exponent + local != global) {
                ++out.wrong_lambda_exponents;
            }
        }
    }
    for (uint32_t count : occurrences) {
        if (count == 0) ++out.missing_terms;
        if (count > 1) out.duplicate_terms += count - 1;
    }
    out.exact_disjoint_partition =
        out.covered_terms == expected &&
        out.missing_terms == 0 &&
        out.duplicate_terms == 0;
    out.coefficientwise_lambda_identity =
        out.exact_disjoint_partition &&
        out.wrong_lambda_exponents == 0;
    // Given coefficientwise equality C=sum C_s, multiplication by one shared
    // Z_H distributes exactly: if C_s=Z_H*Q_s for every s, then
    // C=Z_H*sum Q_s. No field sampling is used for this structural fact.
    out.quotient_sum_identity =
        out.coefficientwise_lambda_identity;
    out.valid =
        out.coefficientwise_lambda_identity &&
        out.quotient_sum_identity;
    return out;
}

} // namespace

bool BuildManifestPreimageV1(
    const cb::ProgramTable& full_table,
    const std::array<ShardV1, kRelationShardsV1>& shards,
    std::vector<gf::Fp>& lanes,
    std::string* why)
{
    lanes.clear();
    const auto assessed = np::AssessProgramTableV1(
        full_table, std::numeric_limits<uint32_t>::max());
    if (!assessed.canonical_program_table ||
        !assessed.canonical_field_encodings ||
        !assessed.no_opaque_callbacks) {
        if (why != nullptr) {
            *why = "stage3:v11_relation_shards:manifest_full_table";
        }
        return false;
    }
    lanes.reserve(32 + kRelationShardsV1 * 27);
    lanes.push_back(gf::FromU64(UINT32_C(0x56313152))); // "V11R"
    lanes.push_back(gf::FromU64(UINT32_C(0x53485244))); // "SHRD"
    lanes.push_back(gf::FromU64(kRelationShardVersionV1));
    lanes.push_back(gf::FromU64(kRelationShardsV1));
    lanes.push_back(gf::FromU64(kPreferredQueryShardsV1));
    lanes.push_back(gf::FromU64(kPreferredQueriesPerShardV1));
    lanes.push_back(gf::FromU64(kFallbackQueryShardsV1));
    lanes.push_back(gf::FromU64(kFallbackQueriesPerShardV1));
    for (uint32_t shard = 0;
         shard < kPreferredQueryShardsV1; ++shard) {
        lanes.push_back(gf::FromU64(
            shard * kPreferredQueriesPerShardV1));
        lanes.push_back(gf::FromU64(
            kPreferredQueriesPerShardV1));
    }
    for (uint32_t shard = 0;
         shard < kFallbackQueryShardsV1; ++shard) {
        lanes.push_back(gf::FromU64(
            shard * kFallbackQueriesPerShardV1));
        lanes.push_back(gf::FromU64(
            kFallbackQueriesPerShardV1));
    }
    lanes.push_back(gf::FromU64(full_table.current_width));
    lanes.push_back(gf::FromU64(full_table.next_width));
    lanes.push_back(gf::FromU64(full_table.programs.size()));
    lanes.push_back(gf::FromU64(
        static_cast<uint32_t>(assessed.instruction_count)));
    lanes.insert(
        lanes.end(),
        assessed.program_root.begin(),
        assessed.program_root.end());
    uint32_t expected_first = 0;
    for (uint32_t ordinal = 0; ordinal < shards.size(); ++ordinal) {
        const auto& shard = shards[ordinal];
        const uint64_t actual_instructions =
            [&shard] {
                uint64_t count = 0;
                for (const auto& program :
                     shard.local_table.programs) {
                    count += program.instructions.size();
                }
                return count;
            }();
        std::string local_why;
        const auto actual_root =
            cb::CommitProgramTableAlgHash(shard.local_table);
        const auto actual_q64 = np::AssessExecutionDomainV1(
            shard.local_table, kFallbackQueriesPerShardV1);
        const auto actual_q96 = np::AssessExecutionDomainV1(
            shard.local_table, kPreferredQueriesPerShardV1);
        bool raw_constants_canonical = true;
        for (const auto& program : shard.local_table.programs) {
            for (const auto& instruction : program.instructions) {
                raw_constants_canonical =
                    raw_constants_canonical &&
                    instruction.constant.c0 < gf::kP &&
                    instruction.constant.c1 < gf::kP &&
                    instruction.constant.c2 < gf::kP;
            }
        }
        if (shard.ordinal != ordinal ||
            shard.first_program != expected_first ||
            shard.first_lambda_exponent != shard.first_program ||
            shard.program_count != shard.local_table.programs.size() ||
            shard.instruction_count != actual_instructions ||
            actual_instructions >
                std::numeric_limits<uint32_t>::max() ||
            !cb::ValidateProgramTable(
                shard.local_table, &local_why) ||
            !raw_constants_canonical ||
            !actual_q64.valid ||
            !actual_q96.valid ||
            !DigestEq(actual_root, shard.local_program_root) ||
            shard.max_constraint_degree !=
                actual_q64.max_constraint_degree ||
            actual_q64.max_constraint_degree !=
                actual_q96.max_constraint_degree ||
            shard.q64_real_rows != actual_q64.real_rows ||
            shard.q64_trace_rows != actual_q64.trace_rows ||
            shard.q64_max_composed_degree !=
                actual_q64.max_composed_degree ||
            shard.q64_quotient_len != actual_q64.quotient_len ||
            shard.q64_coefficient_rows !=
                actual_q64.coefficient_rows ||
            shard.q64_lde_rows != actual_q64.lde_rows ||
            shard.q96_real_rows != actual_q96.real_rows ||
            shard.q96_trace_rows != actual_q96.trace_rows ||
            shard.q96_max_composed_degree !=
                actual_q96.max_composed_degree ||
            shard.q96_quotient_len != actual_q96.quotient_len ||
            shard.q96_coefficient_rows !=
                actual_q96.coefficient_rows ||
            shard.q96_lde_rows != actual_q96.lde_rows) {
            lanes.clear();
            if (why != nullptr) {
                *why =
                    "stage3:v11_relation_shards:manifest_shard_" +
                    std::to_string(ordinal);
            }
            return false;
        }
        expected_first += shard.program_count;
        lanes.push_back(gf::FromU64(shard.ordinal));
        lanes.push_back(gf::FromU64(shard.first_program));
        lanes.push_back(gf::FromU64(shard.program_count));
        lanes.push_back(gf::FromU64(shard.first_lambda_exponent));
        lanes.push_back(gf::FromU64(
            static_cast<uint32_t>(shard.instruction_count)));
        lanes.push_back(gf::FromU64(shard.max_constraint_degree));
        lanes.push_back(gf::FromU64(
            static_cast<uint32_t>(shard.q64_real_rows)));
        lanes.push_back(gf::FromU64(shard.q64_trace_rows));
        lanes.push_back(gf::FromU64(
            static_cast<uint32_t>(
                shard.q64_max_composed_degree)));
        lanes.push_back(gf::FromU64(
            static_cast<uint32_t>(shard.q64_quotient_len)));
        lanes.push_back(gf::FromU64(
            shard.q64_coefficient_rows));
        lanes.push_back(gf::FromU64(
            static_cast<uint32_t>(shard.q64_lde_rows)));
        lanes.push_back(gf::FromU64(
            static_cast<uint32_t>(shard.q96_real_rows)));
        lanes.push_back(gf::FromU64(shard.q96_trace_rows));
        lanes.push_back(gf::FromU64(
            static_cast<uint32_t>(
                shard.q96_max_composed_degree)));
        lanes.push_back(gf::FromU64(
            static_cast<uint32_t>(shard.q96_quotient_len)));
        lanes.push_back(gf::FromU64(
            shard.q96_coefficient_rows));
        lanes.push_back(gf::FromU64(
            static_cast<uint32_t>(shard.q96_lde_rows)));
        lanes.insert(
            lanes.end(),
            actual_root.begin(),
            actual_root.end());
    }
    if (expected_first != full_table.programs.size()) {
        lanes.clear();
        if (why != nullptr) {
            *why = "stage3:v11_relation_shards:manifest_coverage";
        }
        return false;
    }
    for (const auto lane : lanes) {
        if (lane >= gf::kP) {
            lanes.clear();
            if (why != nullptr) {
                *why = "stage3:v11_relation_shards:manifest_noncanonical";
            }
            return false;
        }
    }
    if (why != nullptr) {
        *why = "stage3:v11_relation_shards:manifest_preimage";
    }
    return true;
}

alg_hash::Digest ComputeManifestRootV1(
    const cb::ProgramTable& full_table,
    const std::array<ShardV1, kRelationShardsV1>& shards)
{
    std::vector<gf::Fp> lanes;
    if (!BuildManifestPreimageV1(
            full_table, shards, lanes, nullptr)) {
        return {};
    }
    return alg_hash::SpongeHashFp(lanes);
}

bool ReassemblesExactlyV1(
    const cb::ProgramTable& full_table,
    const PlanV1& plan)
{
    cb::ProgramTable rebuilt;
    rebuilt.version = full_table.version;
    rebuilt.role = full_table.role;
    rebuilt.current_width = full_table.current_width;
    rebuilt.next_width = full_table.next_width;
    rebuilt.challenge_width = full_table.challenge_width;
    for (uint32_t shard_ordinal = 0;
         shard_ordinal < plan.shards.size(); ++shard_ordinal) {
        const auto& shard = plan.shards[shard_ordinal];
        if (shard.ordinal != shard_ordinal ||
            shard.first_program != rebuilt.programs.size() ||
            shard.program_count != shard.local_table.programs.size()) {
            return false;
        }
        for (auto program : shard.local_table.programs) {
            program.constraint_ordinal =
                static_cast<uint32_t>(rebuilt.programs.size());
            rebuilt.programs.push_back(std::move(program));
        }
    }
    return rebuilt == full_table;
}

PlanV1 BuildPlanV1(const cb::ProgramTable& full_table)
{
    PlanV1 out;
    const auto full = np::AssessProgramTableV1(
        full_table, std::numeric_limits<uint32_t>::max());
    out.full_programs =
        static_cast<uint32_t>(full_table.programs.size());
    out.full_instructions = full.instruction_count;
    out.full_program_root = full.program_root;
    if (!full.canonical_program_table ||
        !full.canonical_field_encodings ||
        !full.no_opaque_callbacks) {
        out.residual_mask |= kResidualFullProgramInvalid;
        out.note = "stage3:v11_relation_shards:full_program_invalid";
        return out;
    }

    uint32_t cursor = 0;
    for (uint32_t shard_ordinal = 0;
         shard_ordinal < kRelationShardsV1; ++shard_ordinal) {
        auto& shard = out.shards[shard_ordinal];
        shard.ordinal = shard_ordinal;
        shard.first_program = cursor;
        shard.first_lambda_exponent = cursor;
        shard.local_table.version = full_table.version;
        shard.local_table.role = full_table.role;
        shard.local_table.current_width = full_table.current_width;
        shard.local_table.next_width = full_table.next_width;
        shard.local_table.challenge_width =
            full_table.challenge_width;
        while (cursor < full_table.programs.size()) {
            const uint64_t cost =
                full_table.programs[cursor].instructions.size();
            if (!shard.local_table.programs.empty() &&
                shard.instruction_count + cost >
                    np::kFixedPointInstructionCapV1) {
                break;
            }
            if (cost > np::kFixedPointInstructionCapV1) {
                out.residual_mask |= kResidualShardInstructionCap;
                break;
            }
            auto local = full_table.programs[cursor];
            local.constraint_ordinal =
                static_cast<uint32_t>(
                    shard.local_table.programs.size());
            shard.local_table.programs.push_back(std::move(local));
            shard.instruction_count += cost;
            ++cursor;
        }
        shard.program_count =
            static_cast<uint32_t>(
                shard.local_table.programs.size());
        std::string why;
        const bool table_valid =
            !shard.local_table.programs.empty() &&
            cb::ValidateProgramTable(shard.local_table, &why);
        shard.local_program_root =
            table_valid
            ? cb::CommitProgramTableAlgHash(shard.local_table)
            : alg_hash::Digest{};
        shard.program_boundary_exact =
            shard.first_program + shard.program_count == cursor;
        shard.register_dependencies_local = table_valid;
        shard.instruction_cap_fits =
            shard.instruction_count <=
                np::kFixedPointInstructionCapV1;
        const auto q64 = np::AssessExecutionDomainV1(
            shard.local_table, kFallbackQueriesPerShardV1);
        const auto q96 = np::AssessExecutionDomainV1(
            shard.local_table, kPreferredQueriesPerShardV1);
        shard.max_constraint_degree =
            q64.max_constraint_degree;
        shard.q64_real_rows = q64.real_rows;
        shard.q64_trace_rows = q64.trace_rows;
        shard.q64_max_composed_degree =
            q64.max_composed_degree;
        shard.q64_quotient_len = q64.quotient_len;
        shard.q64_coefficient_rows =
            q64.coefficient_rows;
        shard.q64_lde_rows = q64.lde_rows;
        shard.trace_rows_fit = q64.trace_rows_fit;
        shard.lde_rows_fit = q64.lde_rows_fit;
        shard.q96_real_rows = q96.real_rows;
        shard.q96_trace_rows = q96.trace_rows;
        shard.q96_max_composed_degree =
            q96.max_composed_degree;
        shard.q96_quotient_len = q96.quotient_len;
        shard.q96_coefficient_rows =
            q96.coefficient_rows;
        shard.q96_lde_rows = q96.lde_rows;
        shard.q96_trace_rows_fit = q96.trace_rows_fit;
        shard.q96_lde_rows_fit = q96.lde_rows_fit;
        shard.valid =
            table_valid &&
            shard.program_boundary_exact &&
            shard.register_dependencies_local &&
            shard.instruction_cap_fits &&
            shard.trace_rows_fit &&
            shard.lde_rows_fit &&
            shard.q96_trace_rows_fit &&
            shard.q96_lde_rows_fit;
    }
    out.symbolic_composition =
        SymbolicAudit(out.shards, out.full_programs);
    out.exact_program_reassembly =
        cursor == full_table.programs.size() &&
        ReassemblesExactlyV1(full_table, out);
    out.every_relation_shard_executable =
        std::all_of(
            out.shards.begin(), out.shards.end(),
            [](const auto& shard) { return shard.valid; });
    out.shard_manifest_root =
        ComputeManifestRootV1(full_table, out.shards);
    out.manifest_poseidon_bound =
        gf::Canonical(out.shard_manifest_root[0]) != 0 ||
        gf::Canonical(out.shard_manifest_root[1]) != 0 ||
        gf::Canonical(out.shard_manifest_root[2]) != 0 ||
        gf::Canonical(out.shard_manifest_root[3]) != 0;
    out.q96_exact_partition_of_one_q192_transcript =
        kPreferredQueryShardsV1 *
            kPreferredQueriesPerShardV1 == 192;
    out.q96_independent_lanes = false;
    out.q96_soundness_multiplication_claimed = false;
    if (!out.exact_program_reassembly ||
        !out.symbolic_composition.valid) {
        out.residual_mask |= kResidualPartitionIncomplete;
    }
    if (!out.every_relation_shard_executable) {
        for (const auto& shard : out.shards) {
            if (!shard.instruction_cap_fits) {
                out.residual_mask |= kResidualShardInstructionCap;
            }
            if (!shard.trace_rows_fit || !shard.lde_rows_fit ||
                !shard.q96_trace_rows_fit ||
                !shard.q96_lde_rows_fit) {
                out.residual_mask |= kResidualShardLdeCap;
            }
        }
    }
    if (!out.manifest_poseidon_bound) {
        out.residual_mask |= kResidualManifestBinding;
    }
    out.residual_mask |=
        kResidualRecursiveLeafReceipts |
        kResidualRecursiveQuotientJoin;
    out.recursive_leaf_receipts_verified = false;
    out.recursive_quotient_join_executed = false;
    out.recursive_authority_ready = false;
    out.valid_foundation =
        out.every_relation_shard_executable &&
        out.exact_program_reassembly &&
        out.manifest_poseidon_bound &&
        out.q96_exact_partition_of_one_q192_transcript &&
        !out.q96_independent_lanes &&
        !out.q96_soundness_multiplication_claimed &&
        out.symbolic_composition.valid &&
        (out.residual_mask &
            ~(kResidualRecursiveLeafReceipts |
              kResidualRecursiveQuotientJoin)) == 0;
    out.note = out.valid_foundation
        ? "stage3:v11_relation_shards:exact_six_by_two_q96_foundation;"
          "q64_by_three_fallback;"
          "recursive_receipt_and_quotient_join_pending"
        : "stage3:v11_relation_shards:invalid";
    return out;
}

CompositionEvaluationV1 EvaluateCompositionV1(
    const PlanV1& plan,
    const std::vector<Fp3>& residuals,
    const std::vector<Fp3>& selectors,
    const Fp3& lambda,
    const Fp3& zh)
{
    CompositionEvaluationV1 out;
    out.input_shape_exact =
        plan.valid_foundation &&
        residuals.size() == plan.full_programs &&
        selectors.size() == plan.full_programs &&
        !gf::IsZero(zh);
    if (!out.input_shape_exact) return out;
    Fp3 power = Fp3::One();
    for (uint32_t i = 0; i < plan.full_programs; ++i) {
        out.monolithic = gf::Add(
            out.monolithic,
            gf::Mul(power, gf::Mul(selectors[i], residuals[i])));
        power = gf::Mul(power, lambda);
    }
    const Fp3 zh_inverse = gf::Inv(zh);
    for (const auto& shard : plan.shards) {
        Fp3 local_power =
            Pow(lambda, shard.first_lambda_exponent);
        Fp3 partial = Fp3::Zero();
        for (uint32_t local = 0;
             local < shard.program_count; ++local) {
            const uint32_t global = shard.first_program + local;
            partial = gf::Add(
                partial,
                gf::Mul(
                    local_power,
                    gf::Mul(
                        selectors[global],
                        residuals[global])));
            local_power = gf::Mul(local_power, lambda);
        }
        out.partials[shard.ordinal] = partial;
        out.partial_sum = gf::Add(out.partial_sum, partial);
        out.quotient_sum = gf::Add(
            out.quotient_sum,
            gf::Mul(partial, zh_inverse));
    }
    out.zh_times_quotient_sum =
        gf::Mul(zh, out.quotient_sum);
    out.partial_sum_matches =
        gf::Eq(out.monolithic, out.partial_sum);
    out.quotient_sum_matches =
        gf::Eq(out.monolithic, out.zh_times_quotient_sum);
    out.valid =
        out.partial_sum_matches &&
        out.quotient_sum_matches;
    return out;
}

} // namespace matmul::v4::rc::stage3_multirow_v11_relation_shards
