// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_v13_fixedpoint_bytecode_coverage.h>

#include <matmul/matmul_v4_rc_stage3_multirow_v11_normalized_program.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v11_unified_verifier_air.h>

#include <algorithm>
#include <array>
#include <set>
#include <utility>

namespace matmul::v4::rc::stage3_v13_fixedpoint_bytecode_coverage {
namespace {

namespace np = stage3_multirow_v11_normalized_program;
namespace unified =
    stage3_multirow_v11_unified_verifier_air;

enum class FamilyV1 : uint8_t {
    Bytecode,
    Lift,
    Poseidon,
    Tape,
    MerkleFold,
    Deep,
    Alias,
    Acceptance,
    Unknown,
};

bool StartsWith(
    const std::string& value,
    const char* prefix)
{
    return value.rfind(prefix, 0) == 0;
}

FamilyV1 Classify(const std::string& name)
{
    if (name == "stage3.constraint_bytecode.v1") {
        return FamilyV1::Bytecode;
    }
    if (StartsWith(name, "lift.")) {
        return FamilyV1::Lift;
    }
    if (StartsWith(name, "stage3.poseidon.")) {
        return FamilyV1::Poseidon;
    }
    if (StartsWith(name, "stage3.v13_tape.")) {
        return FamilyV1::Tape;
    }
    if (StartsWith(
            name, "stage3.v13_merkle_fold.")) {
        return FamilyV1::MerkleFold;
    }
    if (StartsWith(
            name, "stage3.v13.deep_stream.")) {
        return FamilyV1::Deep;
    }
    if (StartsWith(
            name, "stage3.v13_quotient.") ||
        StartsWith(
            name, "stage3.v13_terminal_parent.") ||
        name == "stage3.v13_complete.shared_tape") {
        return FamilyV1::Alias;
    }
    if (StartsWith(
            name, "stage3.v13_complete.accept_") ||
        StartsWith(
            name, "stage3.v13_two_child.accept_")) {
        return FamilyV1::Acceptance;
    }
    return FamilyV1::Unknown;
}

bool DigestNonzero(const alg_hash::Digest& digest)
{
    return std::any_of(
        digest.begin(), digest.end(),
        [](const auto limb) {
            return limb != 0;
        });
}

bool ValidCanonicalTable(
    const cb::ProgramTable& table,
    alg_hash::Digest& root,
    uint64_t& serialized_bytes)
{
    std::string why;
    std::vector<unsigned char> wire;
    if (!cb::ValidateProgramTable(table, &why) ||
        !cb::ProgramTableIsChallengeIndependent(
            table) ||
        !cb::SerializeProgramTable(
            table, wire, &why) ||
        wire.empty()) {
        return false;
    }
    root = cb::CommitProgramTableAlgHash(table);
    if (!DigestNonzero(root)) {
        return false;
    }
    serialized_bytes += wire.size();
    return true;
}

} // namespace

CallbackCoverageV1 AssessCallbackCoverageV1(
    const aq::AirConstraintSystem<gf::Fp3>& cs)
{
    CallbackCoverageV1 out;
    out.rows = cs.n_rows;
    out.columns = cs.n_columns;
    out.constraints =
        static_cast<uint32_t>(
            cs.constraints.size());
    out.shape_power_of_two =
        cs.n_rows >= 2 &&
        (cs.n_rows & (cs.n_rows - 1)) == 0 &&
        cs.n_columns != 0;
    std::set<std::string> unknown;
    std::set<uint256> canonical_roots;
    for (const auto& constraint : cs.constraints) {
        const bool has_root =
            !constraint
                 .canonical_program_table_root
                 .IsNull();
        const bool has_ordinal =
            constraint
                .canonical_program_ordinal !=
            UINT32_MAX;
        if (has_root && has_ordinal) {
            ++out
                 .canonical_program_provenance_constraints;
            canonical_roots.insert(
                constraint
                    .canonical_program_table_root);
        } else {
            ++out.native_or_unproven_constraints;
            if (has_root != has_ordinal) {
                ++out
                     .invalid_program_provenance_constraints;
            }
        }
        switch (Classify(constraint.name)) {
        case FamilyV1::Bytecode:
            ++out.bytecode_adapter_named_constraints;
            break;
        case FamilyV1::Lift:
            ++out.native_lift_constraints;
            break;
        case FamilyV1::Poseidon:
            ++out.native_poseidon_constraints;
            break;
        case FamilyV1::Tape:
            ++out.native_tape_constraints;
            break;
        case FamilyV1::MerkleFold:
            ++out.native_merkle_fold_constraints;
            break;
        case FamilyV1::Deep:
            ++out.native_deep_constraints;
            break;
        case FamilyV1::Alias:
            ++out.native_alias_constraints;
            break;
        case FamilyV1::Acceptance:
            ++out.native_acceptance_constraints;
            break;
        case FamilyV1::Unknown:
            ++out.unknown_constraints;
            unknown.insert(constraint.name);
            break;
        }
    }
    out.unknown_families.assign(
        unknown.begin(), unknown.end());
    out.canonical_program_roots =
        static_cast<uint32_t>(
            canonical_roots.size());
    const uint32_t named_native_constraints =
        out.native_lift_constraints +
        out.native_poseidon_constraints +
        out.native_tape_constraints +
        out.native_merkle_fold_constraints +
        out.native_deep_constraints +
        out.native_alias_constraints +
        out.native_acceptance_constraints;
    out.classified_constraints =
        out.bytecode_adapter_named_constraints +
        named_native_constraints;
    out.inventory_complete =
        out.shape_power_of_two &&
        out.constraints != 0 &&
        out.unknown_constraints == 0 &&
        out.invalid_program_provenance_constraints ==
            0 &&
        out.classified_constraints ==
            out.constraints &&
        // Reject an acceptance-only or otherwise truncated "parent".
        out.bytecode_adapter_named_constraints != 0 &&
        out.native_tape_constraints != 0 &&
        out.native_merkle_fold_constraints != 0 &&
        out.native_deep_constraints != 0 &&
        out.native_alias_constraints != 0 &&
        out.native_acceptance_constraints != 0;
    out.all_constraints_canonical_bytecode =
        out.inventory_complete &&
        out.native_or_unproven_constraints == 0 &&
        out.canonical_program_roots != 0 &&
        out.canonical_program_provenance_constraints ==
            out.constraints;
    out.whole_parent_program_reentry_ready =
        out.all_constraints_canonical_bytecode;
    out.note = out.whole_parent_program_reentry_ready
        ? "stage3:v13_fixedpoint_coverage:"
          "whole_parent_bytecode_complete"
        : (out.inventory_complete
            ? "stage3:v13_fixedpoint_coverage:"
              "native_callback_residual"
            : "stage3:v13_fixedpoint_coverage:"
              "incomplete_or_unknown_inventory");
    return out;
}

VerticalProgramCoverageV1
AssessCanonicalVerticalProgramsV1()
{
    VerticalProgramCoverageV1 out;
    cb::ProgramTable parent_join;
    np::ManifestV1 parent_manifest;
    std::string why;
    const bool parent_ok =
        np::BuildCanonicalProgramTableV1(
            parent_join, &parent_manifest,
            &why) &&
        parent_manifest.canonical_program_table &&
        parent_manifest.exact_native_constraint_order &&
        parent_manifest.no_opaque_callbacks;
    const std::array<cb::ProgramTable, 5> tables{{
        std::move(parent_join),
        unified::BuildMerkleHashProgramTableV1(),
        unified::BuildMerkleFoldProgramTableV1(),
        unified::BuildDeepVmProgramTableV1(),
        unified::BuildDecoderProgramTableV1(),
    }};
    out.phase_tables =
        static_cast<uint32_t>(tables.size());
    out.phase_roots.resize(tables.size());
    out.every_table_valid = parent_ok;
    out.every_root_nonzero = parent_ok;
    out.every_table_challenge_value_independent =
        parent_ok;
    for (uint32_t index = 0;
         index < tables.size(); ++index) {
        const auto& table = tables[index];
        out.programs +=
            static_cast<uint32_t>(
                table.programs.size());
        out.max_current_width =
            std::max(
                out.max_current_width,
                table.current_width);
        out.max_next_width =
            std::max(
                out.max_next_width,
                table.next_width);
        out.max_challenge_width =
            std::max(
                out.max_challenge_width,
                table.challenge_width);
        alg_hash::Digest root{};
        const bool valid =
            ValidCanonicalTable(
                table, root,
                out.serialized_bytes);
        out.phase_roots[index] = root;
        out.every_table_valid =
            out.every_table_valid && valid;
        out.every_root_nonzero =
            out.every_root_nonzero &&
            DigestNonzero(root);
        out.every_table_challenge_value_independent =
            out.every_table_challenge_value_independent &&
            cb::ProgramTableIsChallengeIndependent(
                table);
    }
    out.canonical_vertical_foundation =
        out.phase_tables == 5 &&
        out.programs != 0 &&
        out.every_table_valid &&
        out.every_root_nonzero &&
        out.every_table_challenge_value_independent;
    out.horizontal_to_vertical_parity_proven =
        false;
    out.recursive_reentry_ready =
        out.canonical_vertical_foundation &&
        out.horizontal_to_vertical_parity_proven;
    out.note = out.recursive_reentry_ready
        ? "stage3:v13_fixedpoint_coverage:"
          "vertical_reentry_complete"
        : (out.canonical_vertical_foundation
            ? "stage3:v13_fixedpoint_coverage:"
              "vertical_tables_complete_parity_open"
            : "stage3:v13_fixedpoint_coverage:"
              "vertical_table_failure");
    return out;
}

ReentryCoverageV1 AssessReentryCoverageV1(
    const aq::AirConstraintSystem<gf::Fp3>& cs)
{
    ReentryCoverageV1 out;
    out.horizontal =
        AssessCallbackCoverageV1(cs);
    out.vertical =
        AssessCanonicalVerticalProgramsV1();

    aq::AirConstraintSystem<gf::Fp3>
        acceptance_only;
    acceptance_only.n_rows = cs.n_rows;
    acceptance_only.n_columns = cs.n_columns;
    for (const auto& constraint : cs.constraints) {
        if (Classify(constraint.name) ==
                FamilyV1::Acceptance) {
            acceptance_only.constraints.push_back(
                constraint);
        }
    }
    out.acceptance_only_attack_rejected =
        !AssessCallbackCoverageV1(
             acceptance_only)
             .inventory_complete;

    auto unknown = cs;
    if (!unknown.constraints.empty()) {
        unknown.constraints.front().name =
            "stage3.attack.unregistered_relation";
    }
    const auto unknown_assessment =
        AssessCallbackCoverageV1(unknown);
    out.unknown_family_attack_rejected =
        cs.constraints.empty() ||
        (!unknown_assessment.inventory_complete &&
         unknown_assessment.unknown_constraints != 0);
    out.exact_callback_to_bytecode_parity =
        out.horizontal
            .whole_parent_program_reentry_ready;
    out.recursive_reentry_ready =
        out.horizontal.inventory_complete &&
        out.vertical.canonical_vertical_foundation &&
        out.acceptance_only_attack_rejected &&
        out.unknown_family_attack_rejected &&
        out.exact_callback_to_bytecode_parity;
    out.note = out.recursive_reentry_ready
        ? "stage3:v13_fixedpoint_coverage:"
          "recursive_reentry_complete"
        : "stage3:v13_fixedpoint_coverage:"
          "recursive_reentry_residual";
    return out;
}

} // namespace matmul::v4::rc::stage3_v13_fixedpoint_bytecode_coverage
