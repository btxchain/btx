// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_v13_fixedpoint_bytecode_coverage.h>

#include <matmul/matmul_v4_rc_stage3_multirow_v11_normalized_program.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v11_unified_verifier_air.h>
#include <matmul/matmul_v4_rc_stage3_v13_proof_tape_bytecode.h>

#include <algorithm>
#include <array>
#include <limits>
#include <map>
#include <set>
#include <utility>

namespace matmul::v4::rc::stage3_v13_fixedpoint_bytecode_coverage {
namespace {

namespace np = stage3_multirow_v11_normalized_program;
namespace unified =
    stage3_multirow_v11_unified_verifier_air;
namespace tape =
    stage3_multirow_v13_proof_tape_air;

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

bool SameInstructionUnderColumnRelocation(
    const cb::Instruction& candidate,
    const cb::Instruction& canonical,
    uint32_t column_base)
{
    if (candidate.opcode != canonical.opcode ||
        candidate.rhs != canonical.rhs ||
        !gf::Eq(
            candidate.constant,
            canonical.constant)) {
        return false;
    }
    if (canonical.opcode == cb::Opcode::Current ||
        canonical.opcode == cb::Opcode::Next) {
        return canonical.lhs <=
                   std::numeric_limits<uint32_t>::max() -
                       column_base &&
            candidate.lhs ==
                canonical.lhs + column_base;
    }
    return candidate.lhs == canonical.lhs;
}

/**
 * Recognize the proof-tape relation by its complete canonical program, not by
 * a diagnostic callback name or one frozen root.  Parent composition must
 * shift Current/Next operands and recommit, so a legitimate child at a
 * nonzero column base necessarily has a different root from the source table.
 */
bool IsCanonicalTapeTableUnderRelocation(
    const cb::ProgramTable& candidate,
    const cb::ProgramTable& canonical)
{
    if (candidate.version != canonical.version ||
        candidate.role != canonical.role ||
        candidate.challenge_width !=
            canonical.challenge_width ||
        candidate.programs.size() !=
            canonical.programs.size() ||
        candidate.current_width <
            canonical.current_width ||
        candidate.next_width <
            canonical.next_width) {
        return false;
    }
    const uint32_t current_base =
        candidate.current_width -
        canonical.current_width;
    const uint32_t next_base =
        candidate.next_width -
        canonical.next_width;
    if (current_base != next_base) {
        return false;
    }
    for (uint32_t ordinal = 0;
         ordinal < canonical.programs.size();
         ++ordinal) {
        const auto& got = candidate.programs[ordinal];
        const auto& expected =
            canonical.programs[ordinal];
        if (got.version != expected.version ||
            got.role != expected.role ||
            got.constraint_ordinal !=
                expected.constraint_ordinal ||
            got.kind != expected.kind ||
            got.declared_degree !=
                expected.declared_degree ||
            got.challenge_width !=
                expected.challenge_width ||
            got.current_width !=
                expected.current_width +
                    current_base ||
            got.next_width !=
                expected.next_width +
                    current_base ||
            got.instructions.size() !=
                expected.instructions.size()) {
            return false;
        }
        for (uint32_t index = 0;
             index < expected.instructions.size();
             ++index) {
            if (!SameInstructionUnderColumnRelocation(
                    got.instructions[index],
                    expected.instructions[index],
                    current_base)) {
                return false;
            }
        }
    }
    return true;
}

struct CanonicalTableAuditV1 {
    bool valid{false};
    bool canonical_tape{false};
    uint32_t programs{0};
    std::vector<aq::AirKind> kinds;
    std::vector<uint32_t> degrees;
    std::vector<uint32_t> ordinal_counts;
};

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
    cb::ProgramTable canonical_tape;
    const bool canonical_tape_built =
        tape::BuildCanonicalProgramTableV1(
            canonical_tape, nullptr);
    std::map<uint256, CanonicalTableAuditV1>
        table_audits;
    for (const auto& constraint : cs.constraints) {
        const bool has_root =
            !constraint
                 .canonical_program_table_root
                 .IsNull();
        const bool has_ordinal =
            constraint
                .canonical_program_ordinal !=
            UINT32_MAX;
        const bool has_wire =
            constraint
                .canonical_program_table_wire !=
                    nullptr &&
            !constraint
                 .canonical_program_table_wire
                 ->empty();
        const bool has_challenges =
            constraint
                .canonical_program_challenges !=
            nullptr;
        if (has_root && has_ordinal &&
            has_wire && has_challenges) {
            auto [entry, inserted] =
                table_audits.emplace(
                    constraint
                        .canonical_program_table_root,
                    CanonicalTableAuditV1{});
            auto& table_audit = entry->second;
            if (inserted) {
                cb::ProgramTable table;
                std::string why;
                table_audit.valid =
                    cb::DeserializeProgramTable(
                        *constraint
                             .canonical_program_table_wire,
                        table, &why) &&
                    cb::ValidateProgramTable(
                        table, &why) &&
                    cb::CommitProgramTable(table) ==
                        constraint
                            .canonical_program_table_root;
                if (table_audit.valid) {
                    table_audit.programs =
                        static_cast<uint32_t>(
                            table.programs.size());
                    table_audit.ordinal_counts.assign(
                        table.programs.size(), 0);
                    table_audit.kinds.reserve(
                        table.programs.size());
                    table_audit.degrees.reserve(
                        table.programs.size());
                    for (const auto& program :
                         table.programs) {
                        table_audit.kinds.push_back(
                            program.kind);
                        table_audit.degrees.push_back(
                            program.declared_degree);
                    }
                    table_audit.canonical_tape =
                        canonical_tape_built &&
                        IsCanonicalTapeTableUnderRelocation(
                            table, canonical_tape);
                }
            }
            const bool ordinal_valid =
                table_audit.valid &&
                has_ordinal &&
                constraint
                    .canonical_program_ordinal <
                    table_audit.programs &&
                constraint.kind ==
                    table_audit.kinds[
                        constraint
                            .canonical_program_ordinal] &&
                constraint.alg_degree ==
                    table_audit.degrees[
                        constraint
                            .canonical_program_ordinal];
            if (ordinal_valid) {
                ++table_audit.ordinal_counts[
                    constraint
                        .canonical_program_ordinal];
                ++out
                     .canonical_program_provenance_constraints;
                canonical_roots.insert(
                    constraint
                        .canonical_program_table_root);
                if (table_audit.canonical_tape) {
                    ++out.canonical_tape_constraints;
                }
            } else {
                ++out.native_or_unproven_constraints;
                ++out
                     .invalid_program_provenance_constraints;
            }
        } else if (!has_root && !has_ordinal &&
                   !has_wire && !has_challenges) {
            ++out.native_or_unproven_constraints;
        } else {
            ++out.native_or_unproven_constraints;
            ++out
                 .invalid_program_provenance_constraints;
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
    for (const auto& [root, table] :
         table_audits) {
        (void)root;
        if (!table.valid ||
            !table.canonical_tape) {
            continue;
        }
        ++out.canonical_tape_program_tables;
        const bool exact_ordinals =
            table.ordinal_counts.size() ==
                table.programs &&
            std::all_of(
                table.ordinal_counts.begin(),
                table.ordinal_counts.end(),
                [](uint32_t count) {
                    return count == 1;
                });
        if (exact_ordinals) {
            ++out
                 .complete_canonical_tape_program_tables;
        }
    }
    out.canonical_tape_inventory_complete =
        out.canonical_tape_program_tables != 0 &&
        out.complete_canonical_tape_program_tables ==
            out.canonical_tape_program_tables;
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
        (out.native_tape_constraints != 0 ||
         out.canonical_tape_inventory_complete) &&
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
