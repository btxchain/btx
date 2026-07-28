// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_safe_v12_recursive_bridge.h>

#include <matmul/matmul_v4_rc_fri_ext3_alg.h>

#include <algorithm>
#include <cstring>
#include <limits>
#include <set>
#include <utility>

namespace matmul::v4::rc::stage3_safe_v12_recursive_bridge {
namespace {

using gf::Fp3;

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:safe_v12_recursive_bridge:" + detail;
    }
    return false;
}

Fp3 U(gf::Fp value)
{
    return Fp3::FromFp(value);
}

Fp3 U32(uint32_t value)
{
    return U(gf::FromU64(value));
}

bool Canonical(gf::Fp value)
{
    return value < gf::kP;
}

bool Canonical(const Fp3& value)
{
    return Canonical(value.c0) &&
        Canonical(value.c1) &&
        Canonical(value.c2);
}

bool Canonical(const alg_hash::Digest& digest)
{
    return std::all_of(
        digest.begin(), digest.end(),
        [](gf::Fp value) { return Canonical(value); });
}

bool SameColumns(
    const std::vector<std::vector<Fp3>>& left,
    const std::vector<std::vector<Fp3>>& right)
{
    if (left.size() != right.size()) return false;
    for (size_t column = 0; column < left.size(); ++column) {
        if (left[column].size() != right[column].size()) return false;
        for (size_t row = 0; row < left[column].size(); ++row) {
            if (!gf::Eq(left[column][row], right[column][row])) {
                return false;
            }
        }
    }
    return true;
}

const fsair::CallTraceV12* FindCall(
    const fsair::ChannelExecutionV12& execution,
    fsair::CallRoleV12 role)
{
    const fsair::CallTraceV12* found = nullptr;
    for (const auto& call : execution.calls) {
        if (call.spec.role != role) continue;
        if (found != nullptr) return nullptr;
        found = &call;
    }
    return found;
}

uint32_t EmitConst(
    std::vector<cb::Instruction>& instructions,
    const Fp3& value)
{
    cb::Instruction instruction;
    instruction.opcode = cb::Opcode::Constant;
    instruction.constant = value;
    instructions.push_back(instruction);
    return static_cast<uint32_t>(instructions.size()) - 1;
}

uint32_t EmitCurrent(
    std::vector<cb::Instruction>& instructions,
    uint32_t column)
{
    cb::Instruction instruction;
    instruction.opcode = cb::Opcode::Current;
    instruction.lhs = column;
    instructions.push_back(instruction);
    return static_cast<uint32_t>(instructions.size()) - 1;
}

uint32_t EmitNext(
    std::vector<cb::Instruction>& instructions,
    uint32_t column)
{
    cb::Instruction instruction;
    instruction.opcode = cb::Opcode::Next;
    instruction.lhs = column;
    instructions.push_back(instruction);
    return static_cast<uint32_t>(instructions.size()) - 1;
}

uint32_t EmitBinary(
    std::vector<cb::Instruction>& instructions,
    cb::Opcode opcode, uint32_t left, uint32_t right)
{
    cb::Instruction instruction;
    instruction.opcode = opcode;
    instruction.lhs = left;
    instruction.rhs = right;
    instructions.push_back(instruction);
    return static_cast<uint32_t>(instructions.size()) - 1;
}

cb::Program NewProgram(
    uint32_t ordinal, aq::AirKind kind,
    uint32_t degree)
{
    cb::Program program;
    program.version = cb::kConstraintBytecodeVersion;
    program.role = RCStage3RelationRole::CompositionLink;
    program.constraint_ordinal = ordinal;
    program.kind = kind;
    program.declared_degree = degree;
    program.current_width = kAirColumnsV12;
    program.next_width = kAirColumnsV12;
    program.challenge_width = 0;
    return program;
}

void AppendEquality(
    cb::ProgramTable& table,
    uint32_t left_column,
    uint32_t right_column,
    aq::AirKind kind = aq::AirKind::kEverywhere)
{
    cb::Program program = NewProgram(
        static_cast<uint32_t>(table.programs.size()),
        kind, 1);
    const uint32_t left =
        EmitCurrent(program.instructions, left_column);
    const uint32_t right =
        EmitCurrent(program.instructions, right_column);
    EmitBinary(
        program.instructions, cb::Opcode::Sub,
        left, right);
    table.programs.push_back(std::move(program));
}

void AppendConstant(
    cb::ProgramTable& table,
    uint32_t column, gf::Fp value)
{
    cb::Program program = NewProgram(
        static_cast<uint32_t>(table.programs.size()),
        aq::AirKind::kEverywhere, 1);
    const uint32_t cell =
        EmitCurrent(program.instructions, column);
    const uint32_t constant =
        EmitConst(program.instructions, U(value));
    EmitBinary(
        program.instructions, cb::Opcode::Sub,
        cell, constant);
    table.programs.push_back(std::move(program));
}

void AppendStable(
    cb::ProgramTable& table, uint32_t column)
{
    cb::Program program = NewProgram(
        static_cast<uint32_t>(table.programs.size()),
        aq::AirKind::kTransition, 1);
    const uint32_t current =
        EmitCurrent(program.instructions, column);
    const uint32_t next =
        EmitNext(program.instructions, column);
    EmitBinary(
        program.instructions, cb::Opcode::Sub,
        next, current);
    table.programs.push_back(std::move(program));
}

void AppendBoolean(
    cb::ProgramTable& table, uint32_t column)
{
    cb::Program program = NewProgram(
        static_cast<uint32_t>(table.programs.size()),
        aq::AirKind::kEverywhere, 2);
    const uint32_t bit =
        EmitCurrent(program.instructions, column);
    const uint32_t one =
        EmitConst(program.instructions, Fp3::One());
    const uint32_t minus_one =
        EmitBinary(
            program.instructions, cb::Opcode::Sub,
            bit, one);
    EmitBinary(
        program.instructions, cb::Opcode::Mul,
        bit, minus_one);
    table.programs.push_back(std::move(program));
}

void AppendMapMarker(
    cb::ProgramTable& table,
    const CellMapEntryV12& entry)
{
    // This zero identity is intentionally part of the canonical ProgramTable:
    // the five immutable map coordinates are therefore committed exactly
    // once, in row order, without turning them into prover-owned selector
    // cells or preprocessed columns.
    cb::Program program = NewProgram(
        static_cast<uint32_t>(table.programs.size()),
        aq::AirKind::kEverywhere, 1);
    const uint32_t counter_a =
        EmitCurrent(
            program.instructions,
            LayoutV12{}.row_counter);
    const uint32_t counter_b =
        EmitCurrent(
            program.instructions,
            LayoutV12{}.row_counter);
    uint32_t acc = EmitBinary(
        program.instructions, cb::Opcode::Sub,
        counter_a, counter_b);
    const uint32_t zero =
        EmitConst(program.instructions, Fp3::Zero());
    for (uint32_t coordinate : {
             entry.row,
             static_cast<uint32_t>(entry.kind),
             entry.lane,
             entry.ordinal,
             entry.source_offset,
             entry.consumer_offset}) {
        const uint32_t encoded =
            EmitConst(program.instructions, U32(coordinate));
        const uint32_t zero_term =
            EmitBinary(
                program.instructions, cb::Opcode::Mul,
                zero, encoded);
        acc = EmitBinary(
            program.instructions, cb::Opcode::Add,
            acc, zero_term);
    }
    table.programs.push_back(std::move(program));
}

std::array<gf::Fp, 6> ShapeFields(
    const fsair::ShapeV12& shape)
{
    return {
        gf::FromU64(shape.child_w),
        gf::FromU64(shape.child_n_rows),
        gf::FromU64(shape.child_quotient_len),
        gf::FromU64(shape.n_coeffs),
        gf::FromU64(shape.n_lde),
        gf::FromU64(shape.n_folds),
    };
}

bool CellMapIsCanonical(
    const std::vector<CellMapEntryV12>& map,
    std::string* why)
{
    const auto expected = CanonicalCellMapV12();
    if (map != expected || map.size() != kTraceRowsV12) {
        return Fail(why, "cell_map_not_canonical");
    }
    std::set<uint32_t> rows;
    std::set<std::array<uint32_t, 6>> identities;
    for (const auto& entry : map) {
        if (!rows.insert(entry.row).second ||
            !identities.insert({
                entry.row,
                static_cast<uint32_t>(entry.kind),
                entry.lane,
                entry.ordinal,
                entry.source_offset,
                entry.consumer_offset}).second) {
            return Fail(why, "cell_map_duplicate");
        }
    }
    return rows.size() == kTraceRowsV12;
}

bool SetRepeated(
    std::vector<std::vector<Fp3>>& columns,
    uint32_t column, gf::Fp value)
{
    if (!Canonical(value) || column >= columns.size()) return false;
    std::fill(columns[column].begin(), columns[column].end(), U(value));
    return true;
}

bool PopulateBits(
    std::vector<std::vector<Fp3>>& columns,
    const LayoutV12& layout, uint32_t row,
    gf::Fp source)
{
    if (!Canonical(source)) return false;
    for (uint32_t bit = 0; bit < kLimbBitsV12; ++bit) {
        columns[layout.Bit(bit)][row] =
            U32(static_cast<uint32_t>((source >> bit) & 1U));
    }
    gf::Fp cumulative = 1;
    for (uint32_t step = 0;
         step < kHighAndStepsV12; ++step) {
        const uint32_t first = 32 + kHighAndChunkV12 * step;
        const uint32_t last =
            std::min<uint32_t>(
                64, first + kHighAndChunkV12);
        for (uint32_t bit = first; bit < last; ++bit) {
            cumulative = gf::Mul(
                cumulative,
                (source >> bit) & 1U);
        }
        columns[layout.HighAnd(step)][row] = U(cumulative);
    }
    return true;
}

bool SameBridge(
    const RecursiveBridgeV12& left,
    const RecursiveBridgeV12& right)
{
    return left.layout.end == right.layout.end &&
        left.shape == right.shape &&
        left.registry == right.registry &&
        left.program_table == right.program_table &&
        left.program_root == right.program_root &&
        left.cell_map == right.cell_map &&
        left.cs.n_rows == right.cs.n_rows &&
        left.cs.n_columns == right.cs.n_columns &&
        left.cs.preprocessed.size() ==
            right.cs.preprocessed.size() &&
        left.cs.preprocessed_pin_ood ==
            right.cs.preprocessed_pin_ood &&
        SameColumns(left.columns, right.columns) &&
        left.verifier_owned_preprocessed_columns ==
            right.verifier_owned_preprocessed_columns &&
        left.proof_owned_preprocessed_columns ==
            right.proof_owned_preprocessed_columns &&
        left.equality_constraints ==
            right.equality_constraints &&
        left.canonical_encoding_constraints ==
            right.canonical_encoding_constraints &&
        left.violations == right.violations &&
        left.exact_cell_map_rebuilt ==
            right.exact_cell_map_rebuilt &&
        left.domain_registry_root_pinned ==
            right.domain_registry_root_pinned &&
        left.typed_terminal_receipts_mapped ==
            right.typed_terminal_receipts_mapped &&
        left.shared_tax_and_nonce_mapped ==
            right.shared_tax_and_nonce_mapped &&
        left.both_query_candidate_vectors_mapped ==
            right.both_query_candidate_vectors_mapped &&
        left.both_q96_outputs_mapped ==
            right.both_q96_outputs_mapped &&
        left.proof_cells_are_ordinary_columns ==
            right.proof_cells_are_ordinary_columns &&
        left.canonical_bytecode_is_relation_source ==
            right.canonical_bytecode_is_relation_source &&
        left.normalized_parent_consumed ==
            right.normalized_parent_consumed &&
        left.recursive_authority_ready ==
            right.recursive_authority_ready &&
        left.valid == right.valid;
}

bool CanonicalDigest(
    const Fri3AlgDigest& digest)
{
    return std::all_of(
        digest.begin(), digest.end(),
        [](gf::Fp value) { return Canonical(value); });
}

bool CanonicalBatchProof(
    const Fri3AlgBatchProof& proof)
{
    if (!CanonicalDigest(proof.row_commit.root) ||
        !Canonical(proof.lambda) ||
        !Canonical(proof.z1) ||
        !Canonical(proof.z2) ||
        !Canonical(proof.w1) ||
        !Canonical(proof.w2) ||
        !Canonical(proof.final_value)) {
        return false;
    }
    const auto canonical_fp3_vector =
        [](const std::vector<Fp3>& values) {
            return std::all_of(
                values.begin(), values.end(),
                [](const Fp3& value) {
                    return Canonical(value);
                });
        };
    if (!canonical_fp3_vector(proof.evals_z1) ||
        !canonical_fp3_vector(proof.evals_z2) ||
        !canonical_fp3_vector(proof.fold_challenges)) {
        return false;
    }
    for (const auto& layer : proof.fold_layers) {
        if (!CanonicalDigest(layer.root)) return false;
    }
    for (const auto& query : proof.queries) {
        if (!canonical_fp3_vector(query.row.values) ||
            !std::all_of(
                query.row.siblings.begin(),
                query.row.siblings.end(),
                [](const Fri3AlgDigest& digest) {
                    return CanonicalDigest(digest);
                })) {
            return false;
        }
        for (const auto& step : query.steps) {
            if (!Canonical(step.even) ||
                !Canonical(step.odd) ||
                !std::all_of(
                    step.even_siblings.begin(),
                    step.even_siblings.end(),
                    [](const Fri3AlgDigest& digest) {
                        return CanonicalDigest(digest);
                    }) ||
                !std::all_of(
                    step.odd_siblings.begin(),
                    step.odd_siblings.end(),
                    [](const Fri3AlgDigest& digest) {
                        return CanonicalDigest(digest);
                    })) {
                return false;
            }
        }
    }
    return true;
}

bool CanonicalRowsProof(
    const aq::AirQuotientRowsProof& proof)
{
    if (!CanonicalBatchProof(proof.batch)) return false;
    for (const auto& per_query : proof.next_openings) {
        for (const auto& opening : per_query) {
            if (!std::all_of(
                    opening.values.begin(),
                    opening.values.end(),
                    [](const Fp3& value) {
                        return Canonical(value);
                    }) ||
                !std::all_of(
                    opening.siblings.begin(),
                    opening.siblings.end(),
                    [](const Fri3AlgDigest& digest) {
                        return CanonicalDigest(digest);
                    })) {
                return false;
            }
        }
    }
    return true;
}

} // namespace

std::vector<CellMapEntryV12> CanonicalCellMapV12()
{
    std::vector<CellMapEntryV12> out;
    out.reserve(kTraceRowsV12);
    uint32_t row = 0;
    for (uint32_t lane = 0; lane < 2; ++lane) {
        for (uint32_t limb = 0; limb < 4; ++limb) {
            out.push_back({
                row++, CellKindV12::FriTerminalReceipt,
                lane, limb,
                4 * lane + limb,
                21 + 4 * lane + limb});
        }
    }
    for (uint32_t lane = 0; lane < 2; ++lane) {
        for (uint32_t limb = 0; limb < 4; ++limb) {
            out.push_back({
                row++, CellKindV12::TaxSigma,
                lane, limb, limb,
                kQueryAbsorbLanesV12 * lane + 5 + limb});
        }
    }
    for (uint32_t lane = 0; lane < 2; ++lane) {
        for (uint32_t word = 0; word < 2; ++word) {
            out.push_back({
                row++, CellKindV12::SharedNonce,
                lane, word, word,
                kQueryAbsorbLanesV12 * lane + 9 + word});
        }
    }
    for (uint32_t lane = 0; lane < 2; ++lane) {
        for (uint32_t offset = 0;
             offset < kQuerySqueezeLanesV12;
             ++offset) {
            out.push_back({
                row++, CellKindV12::QueryCandidate,
                lane, offset,
                lane * kQuerySqueezeLanesV12 + offset,
                lane * kQuerySqueezeLanesV12 + offset});
        }
    }
    for (uint32_t lane = 0; lane < 2; ++lane) {
        for (uint32_t query = 0;
             query < fsair::kQueriesPerLaneV12;
             ++query) {
            out.push_back({
                row++, CellKindV12::QueryOutput,
                lane, query,
                lane * fsair::kQueriesPerLaneV12 + query,
                lane * fsair::kQueriesPerLaneV12 + query});
        }
    }
    while (row < kTraceRowsV12) {
        out.push_back({
            row, CellKindV12::Padding,
            0, row - kActiveMapRowsV12, 0, 0});
        ++row;
    }
    return out;
}

bool BuildRecursiveBridgeProgramTableV12(
    const fsair::ManifestV12& manifest,
    const domains::TranscriptDomainRegistryV12& registry,
    cb::ProgramTable& out,
    std::string* why)
{
    out = {};
    if (!fsair::ValidateManifestV12(manifest, why) ||
        !domains::ValidateTranscriptDomainRegistryV12(
            manifest, registry, why)) {
        return false;
    }
    const LayoutV12 layout;
    out.version = cb::kConstraintBytecodeVersion;
    out.role = RCStage3RelationRole::CompositionLink;
    out.current_width = kAirColumnsV12;
    out.next_width = kAirColumnsV12;
    out.challenge_width = 0;

    // The only public/preprocessed value: expected shape-registry root.
    for (uint32_t limb = 0; limb < 4; ++limb) {
        AppendEquality(
            out,
            layout.ProofRegistryRoot(limb),
            layout.ExpectedRegistryRoot(limb));
    }

    // Exact receipt -> tax-core link.
    for (uint32_t lane = 0; lane < 2; ++lane) {
        for (uint32_t limb = 0; limb < 4; ++limb) {
            AppendEquality(
                out,
                layout.FriTerminal(lane, limb),
                layout.TaxCore(21 + 4 * lane + limb));
        }
    }
    // Shared post-FRI sigma and nonce copied into both typed query requests.
    for (uint32_t lane = 0; lane < 2; ++lane) {
        for (uint32_t limb = 0; limb < 4; ++limb) {
            AppendEquality(
                out, layout.TaxSigma(limb),
                layout.QueryAbsorb(lane, 5 + limb));
        }
        for (uint32_t word = 0; word < 2; ++word) {
            AppendEquality(
                out, layout.Nonce(word),
                layout.QueryAbsorb(lane, 9 + word));
        }
    }

    // The vertical narrow carrier enforces all 980 mapped equalities.
    AppendEquality(out, layout.source, layout.consumer);

    // Stable proof-owned cells prevent row-dependent substitution.
    for (uint32_t column =
             layout.proof_registry_root_base;
         column < layout.source; ++column) {
        AppendStable(out, column);
    }

    // Canonical fixed tax-core framing.
    AppendConstant(
        out, layout.TaxCore(0),
        nirop::kCommonBindingMagicV12);
    AppendConstant(
        out, layout.TaxCore(1),
        gf::FromU64(nirop::kProtocolVersionV12));
    AppendConstant(
        out, layout.TaxCore(2),
        gf::FromU64(nirop::kQueriesPerLaneV12));
    AppendConstant(
        out, layout.TaxCore(3),
        gf::FromU64(fsair::kQueryCandidatesPerLaneV12));
    AppendConstant(
        out, layout.TaxCore(4),
        gf::FromU64(nirop::kTaxedGrindBitsV12));
    uint32_t tag_offset = 29;
    for (const auto& entry : registry.entries) {
        for (gf::Fp tag : entry.tag) {
            AppendConstant(
                out, layout.TaxCore(tag_offset++), tag);
        }
    }
    const auto shape_fields = ShapeFields(manifest.shape);
    for (uint32_t offset = 0;
         offset < shape_fields.size(); ++offset) {
        AppendConstant(
            out, layout.TaxCore(49 + offset),
            shape_fields[offset]);
    }

    // Exact one-call query absorb frame on both independently typed channels.
    for (uint32_t lane = 0; lane < 2; ++lane) {
        const std::array<gf::Fp, 9> fixed = {
            fsair::kEventHeaderMagicV12,
            gf::FromU64(static_cast<uint32_t>(
                fsair::CallRoleV12::AbsorbSharedQueryTax)),
            gf::FromU64(0),
            gf::FromU64(static_cast<uint32_t>(
                alg_hash_typed::RoleV12::TranscriptQuerySeed)),
            gf::FromU64(9),
            gf::FromU64(fsair::kSharedQueryTaxBitsV12),
            gf::FromU64(fsair::kQueryCandidatesPerLaneV12),
            gf::FromU64(kQuerySqueezeLanesV12),
            gf::FromU64(lane),
        };
        // The first eight entries name offsets 0..4 and 11..13. The final
        // lane value is committed by the map markers/registry, not absorbed.
        for (uint32_t offset = 0; offset <= 4; ++offset) {
            AppendConstant(
                out, layout.QueryAbsorb(lane, offset),
                fixed[offset]);
        }
        AppendConstant(
            out, layout.QueryAbsorb(lane, 11), fixed[5]);
        AppendConstant(
            out, layout.QueryAbsorb(lane, 12), fixed[6]);
        AppendConstant(
            out, layout.QueryAbsorb(lane, 13), fixed[7]);
    }

    // Full canonical base-limb decomposition for every mapped source.
    for (uint32_t bit = 0; bit < kLimbBitsV12; ++bit) {
        AppendBoolean(out, layout.Bit(bit));
    }
    {
        cb::Program program = NewProgram(
            static_cast<uint32_t>(out.programs.size()),
            aq::AirKind::kEverywhere, 1);
        uint32_t acc =
            EmitConst(program.instructions, Fp3::Zero());
        for (uint32_t bit = 0; bit < kLimbBitsV12; ++bit) {
            const uint32_t coefficient =
                EmitConst(
                    program.instructions,
                    U(gf::FromU64(
                        uint64_t{1} << bit)));
            const uint32_t value =
                EmitCurrent(
                    program.instructions,
                    layout.Bit(bit));
            const uint32_t term =
                EmitBinary(
                    program.instructions, cb::Opcode::Mul,
                    coefficient, value);
            acc = EmitBinary(
                program.instructions, cb::Opcode::Add,
                acc, term);
        }
        const uint32_t source =
            EmitCurrent(program.instructions, layout.source);
        EmitBinary(
            program.instructions, cb::Opcode::Sub,
            source, acc);
        out.programs.push_back(std::move(program));
    }
    for (uint32_t step = 0;
         step < kHighAndStepsV12; ++step) {
        const uint32_t first =
            32 + kHighAndChunkV12 * step;
        const uint32_t last =
            std::min<uint32_t>(
                64, first + kHighAndChunkV12);
        cb::Program program = NewProgram(
            static_cast<uint32_t>(out.programs.size()),
            aq::AirKind::kEverywhere,
            step == 0 ? last - first
                      : 1 + last - first);
        uint32_t product =
            step == 0
                ? EmitConst(
                      program.instructions, Fp3::One())
                : EmitCurrent(
                      program.instructions,
                      layout.HighAnd(step - 1));
        for (uint32_t bit = first; bit < last; ++bit) {
            const uint32_t value =
                EmitCurrent(
                    program.instructions,
                    layout.Bit(bit));
            product = EmitBinary(
                program.instructions, cb::Opcode::Mul,
                product, value);
        }
        const uint32_t claimed =
            EmitCurrent(
                program.instructions,
                layout.HighAnd(step));
        EmitBinary(
            program.instructions, cb::Opcode::Sub,
            claimed, product);
        out.programs.push_back(std::move(program));
    }
    {
        cb::Program program = NewProgram(
            static_cast<uint32_t>(out.programs.size()),
            aq::AirKind::kEverywhere, 2);
        uint32_t low =
            EmitConst(program.instructions, Fp3::Zero());
        for (uint32_t bit = 0; bit < 32; ++bit) {
            const uint32_t coefficient =
                EmitConst(
                    program.instructions,
                    U(gf::FromU64(
                        uint64_t{1} << bit)));
            const uint32_t value =
                EmitCurrent(
                    program.instructions,
                    layout.Bit(bit));
            const uint32_t term =
                EmitBinary(
                    program.instructions, cb::Opcode::Mul,
                    coefficient, value);
            low = EmitBinary(
                program.instructions, cb::Opcode::Add,
                low, term);
        }
        const uint32_t high_all =
            EmitCurrent(
                program.instructions,
                layout.HighAnd(kHighAndStepsV12 - 1));
        EmitBinary(
            program.instructions, cb::Opcode::Mul,
            high_all, low);
        out.programs.push_back(std::move(program));
    }

    // Deterministic row counter binds the canonical map order.
    {
        cb::Program program = NewProgram(
            static_cast<uint32_t>(out.programs.size()),
            aq::AirKind::kFirstRow, 1);
        const uint32_t counter =
            EmitCurrent(
                program.instructions, layout.row_counter);
        const uint32_t zero =
            EmitConst(program.instructions, Fp3::Zero());
        EmitBinary(
            program.instructions, cb::Opcode::Sub,
            counter, zero);
        out.programs.push_back(std::move(program));
    }
    {
        cb::Program program = NewProgram(
            static_cast<uint32_t>(out.programs.size()),
            aq::AirKind::kTransition, 1);
        const uint32_t current =
            EmitCurrent(
                program.instructions, layout.row_counter);
        const uint32_t one =
            EmitConst(program.instructions, Fp3::One());
        const uint32_t expected =
            EmitBinary(
                program.instructions, cb::Opcode::Add,
                current, one);
        const uint32_t next =
            EmitNext(
                program.instructions, layout.row_counter);
        EmitBinary(
            program.instructions, cb::Opcode::Sub,
            next, expected);
        out.programs.push_back(std::move(program));
    }
    {
        cb::Program program = NewProgram(
            static_cast<uint32_t>(out.programs.size()),
            aq::AirKind::kLastRow, 1);
        const uint32_t counter =
            EmitCurrent(
                program.instructions, layout.row_counter);
        const uint32_t last =
            EmitConst(
                program.instructions,
                U32(kTraceRowsV12 - 1));
        EmitBinary(
            program.instructions, cb::Opcode::Sub,
            counter, last);
        out.programs.push_back(std::move(program));
    }

    // One committed marker for every exact semantic map entry, including
    // padding. Reorder/omission/duplication/offset substitution changes the
    // canonical ProgramTable root even though the coordinates are not witness.
    const auto map = CanonicalCellMapV12();
    for (const auto& entry : map) {
        AppendMapMarker(out, entry);
    }

    if (!cb::ValidateProgramTable(out, why)) {
        out = {};
        return false;
    }
    return true;
}

bool BuildRecursiveBridgeV12(
    const fsair::ManifestV12& manifest,
    const nirop::HybridInputsV12& inputs,
    const nirop::HybridReceiptV12& receipt,
    const alg_hash::Digest& proof_registry_root,
    RecursiveBridgeV12& out,
    std::string* why)
{
    out = {};
    if (!fsair::ValidateManifestV12(manifest, why) ||
        !nirop::ValidateHybridReceiptV12(
            manifest, inputs, receipt, why) ||
        !Canonical(proof_registry_root) ||
        receipt.tax_sigma_core.size() != kTaxCoreLanesV12) {
        return Fail(why, "inputs");
    }
    if (!domains::BuildTranscriptDomainRegistryV12(
            manifest, out.registry, why) ||
        proof_registry_root != out.registry.root ||
        !BuildRecursiveBridgeProgramTableV12(
            manifest, out.registry,
            out.program_table, why) ||
        !cb::BuildAirConstraintSystemFromProgramTable(
            out.program_table, kTraceRowsV12, out.cs, why)) {
        out = {};
        return Fail(why, "verifier_rebuild");
    }
    out.layout = {};
    out.shape = manifest.shape;
    out.program_root =
        cb::CommitProgramTableAlgHash(out.program_table);
    out.cell_map = CanonicalCellMapV12();
    if (!CellMapIsCanonical(out.cell_map, why)) {
        out = {};
        return false;
    }
    out.columns.assign(
        out.cs.n_columns,
        std::vector<Fp3>(out.cs.n_rows, Fp3::Zero()));

    // Registry root: only expected side is verifier-owned preprocessing.
    for (uint32_t limb = 0; limb < 4; ++limb) {
        SetRepeated(
            out.columns,
            out.layout.ExpectedRegistryRoot(limb),
            out.registry.root[limb]);
        SetRepeated(
            out.columns,
            out.layout.ProofRegistryRoot(limb),
            proof_registry_root[limb]);
        out.cs.preprocessed.push_back({
            out.layout.ExpectedRegistryRoot(limb),
            out.columns[
                out.layout.ExpectedRegistryRoot(limb)]});
    }
    out.cs.preprocessed_pin_ood = true;

    for (uint32_t lane = 0; lane < 2; ++lane) {
        for (uint32_t limb = 0; limb < 4; ++limb) {
            if (!SetRepeated(
                    out.columns,
                    out.layout.FriTerminal(lane, limb),
                    receipt.fri_terminal_receipts[lane][limb])) {
                return Fail(why, "terminal_receipt_encoding");
            }
        }
    }
    for (uint32_t offset = 0;
         offset < kTaxCoreLanesV12; ++offset) {
        if (!SetRepeated(
                out.columns, out.layout.TaxCore(offset),
                receipt.tax_sigma_core[offset])) {
            return Fail(why, "tax_core_encoding");
        }
    }
    for (uint32_t limb = 0; limb < 4; ++limb) {
        if (!SetRepeated(
                out.columns, out.layout.TaxSigma(limb),
                receipt.tax_sigma[limb])) {
            return Fail(why, "tax_sigma_encoding");
        }
    }
    const std::array<uint32_t, 2> nonce_words = {
        static_cast<uint32_t>(inputs.shared_grind_nonce),
        static_cast<uint32_t>(
            inputs.shared_grind_nonce >> 32),
    };
    for (uint32_t word = 0; word < 2; ++word) {
        SetRepeated(
            out.columns, out.layout.Nonce(word),
            gf::FromU64(nonce_words[word]));
    }

    std::array<const fsair::CallTraceV12*, 2> absorb{};
    std::array<const fsair::CallTraceV12*, 2> squeeze{};
    for (uint32_t lane = 0; lane < 2; ++lane) {
        const auto& execution =
            receipt.transcript_air.query_lane[lane].
                projected_execution;
        absorb[lane] = FindCall(
            execution,
            fsair::CallRoleV12::AbsorbSharedQueryTax);
        squeeze[lane] = FindCall(
            execution,
            fsair::CallRoleV12::SqueezeQueryVector);
        if (absorb[lane] == nullptr ||
            absorb[lane]->values.size() !=
                kQueryAbsorbLanesV12 ||
            squeeze[lane] == nullptr ||
            squeeze[lane]->values.size() !=
                kQuerySqueezeLanesV12) {
            return Fail(why, "query_call_shape");
        }
        for (uint32_t offset = 0;
             offset < kQueryAbsorbLanesV12; ++offset) {
            if (!SetRepeated(
                    out.columns,
                    out.layout.QueryAbsorb(lane, offset),
                    absorb[lane]->values[offset])) {
                return Fail(why, "query_absorb_encoding");
            }
        }
    }

    for (const auto& entry : out.cell_map) {
        gf::Fp source = 0;
        gf::Fp consumer = 0;
        switch (entry.kind) {
        case CellKindV12::FriTerminalReceipt:
            source = receipt.fri_terminal_receipts
                [entry.lane][entry.ordinal];
            consumer =
                receipt.tax_sigma_core[entry.consumer_offset];
            break;
        case CellKindV12::TaxSigma:
            source = receipt.tax_sigma[entry.ordinal];
            consumer =
                absorb[entry.lane]->
                    values[5 + entry.ordinal];
            break;
        case CellKindV12::SharedNonce:
            source = gf::FromU64(
                nonce_words[entry.ordinal]);
            consumer =
                absorb[entry.lane]->
                    values[9 + entry.ordinal];
            break;
        case CellKindV12::QueryCandidate: {
            source =
                squeeze[entry.lane]->
                    values[entry.ordinal];
            const auto& sampler =
                receipt.transcript_air.query_lane
                    [entry.lane].query_sampler_air;
            const uint32_t candidate =
                entry.ordinal / 3;
            const uint32_t limb =
                entry.ordinal % 3;
            if (candidate >=
                    sampler.source_candidates.size()) {
                return Fail(why, "sampler_source_offset");
            }
            const Fp3 packed =
                sampler.source_candidates[candidate];
            consumer =
                limb == 0 ? packed.c0
                          : (limb == 1 ? packed.c1
                                       : packed.c2);
            break;
        }
        case CellKindV12::QueryOutput: {
            const auto& sampler =
                receipt.transcript_air.query_lane
                    [entry.lane].query_sampler_air;
            if (entry.ordinal >=
                    sampler.selected_indices.size() ||
                entry.ordinal >=
                    receipt.query_indices[entry.lane].size()) {
                return Fail(why, "query_output_offset");
            }
            source = gf::FromU64(
                sampler.selected_indices[entry.ordinal]);
            consumer = gf::FromU64(
                receipt.query_indices
                    [entry.lane][entry.ordinal]);
            break;
        }
        case CellKindV12::Padding:
            source = 0;
            consumer = 0;
            break;
        }
        if (!Canonical(source) || !Canonical(consumer)) {
            return Fail(why, "noncanonical_mapped_cell");
        }
        out.columns[out.layout.source][entry.row] = U(source);
        out.columns[out.layout.consumer][entry.row] = U(consumer);
        if (!PopulateBits(
                out.columns, out.layout,
                entry.row, source)) {
            return Fail(why, "mapped_cell_bits");
        }
        out.columns[out.layout.row_counter][entry.row] =
            U32(entry.row);
    }

    out.verifier_owned_preprocessed_columns = 4;
    out.proof_owned_preprocessed_columns = 0;
    out.equality_constraints =
        4 + 8 + 8 + 4 + 1;
    out.canonical_encoding_constraints =
        64 + kHighAndStepsV12 + 2;
    out.violations =
        CountViolationsV12(out.cs, out.columns);
    out.exact_cell_map_rebuilt = true;
    out.domain_registry_root_pinned = true;
    out.typed_terminal_receipts_mapped = true;
    out.shared_tax_and_nonce_mapped = true;
    out.both_query_candidate_vectors_mapped = true;
    out.both_q96_outputs_mapped = true;
    out.proof_cells_are_ordinary_columns =
        out.cs.preprocessed.size() == 4 &&
        std::all_of(
            out.cs.preprocessed.begin(),
            out.cs.preprocessed.end(),
            [&out](const auto& entry) {
                return entry.first >=
                           out.layout.
                               expected_registry_root_base &&
                    entry.first <
                        out.layout.proof_registry_root_base;
            });
    out.canonical_bytecode_is_relation_source =
        cb::ValidateProgramTable(out.program_table, nullptr) &&
        out.program_root != alg_hash::Digest{};
    out.normalized_parent_consumed = false;
    out.recursive_authority_ready = false;
    out.valid =
        out.violations == 0 &&
        out.proof_owned_preprocessed_columns == 0 &&
        out.proof_cells_are_ordinary_columns &&
        out.canonical_bytecode_is_relation_source;
    out.note = out.valid
        ? "executable V12 bridge; normalized parent copy-in remains open"
        : "invalid V12 recursive bridge";
    if (!out.valid) return Fail(why, "constraints");
    return true;
}

bool ValidateRecursiveBridgeV12(
    const fsair::ManifestV12& manifest,
    const nirop::HybridInputsV12& inputs,
    const nirop::HybridReceiptV12& receipt,
    const alg_hash::Digest& proof_registry_root,
    const RecursiveBridgeV12& bridge,
    std::string* why)
{
    RecursiveBridgeV12 rebuilt;
    if (!BuildRecursiveBridgeV12(
            manifest, inputs, receipt,
            proof_registry_root, rebuilt, why)) {
        return false;
    }
    if (!SameBridge(bridge, rebuilt) ||
        bridge.normalized_parent_consumed ||
        bridge.recursive_authority_ready ||
        CountViolationsV12(
            bridge.cs, bridge.columns) != 0) {
        return Fail(why, "rebuild_mismatch");
    }
    return true;
}

uint32_t CountViolationsV12(
    const aq::AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns)
{
    if (columns.size() != cs.n_columns ||
        cs.n_rows == 0) {
        return std::numeric_limits<uint32_t>::max();
    }
    for (const auto& column : columns) {
        if (column.size() != cs.n_rows) {
            return std::numeric_limits<uint32_t>::max();
        }
    }
    uint32_t violations = 0;
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
        for (const auto& constraint : cs.constraints) {
            bool applies = false;
            switch (constraint.kind) {
            case aq::AirKind::kEverywhere:
                applies = true;
                break;
            case aq::AirKind::kTransition:
                applies = row + 1 < cs.n_rows;
                break;
            case aq::AirKind::kFirstRow:
                applies = row == 0;
                break;
            case aq::AirKind::kLastRow:
                applies = row + 1 == cs.n_rows;
                break;
            }
            if (applies &&
                !gf::IsZero(
                    constraint.eval(current, next))) {
                ++violations;
            }
        }
    }
    return violations;
}

bool ProveRecursiveBridgeV12(
    const RecursiveBridgeV12& bridge,
    const uint256& fs_seed,
    RecursiveBridgeProofV12& out,
    std::string* why)
{
    out = {};
    if (!bridge.valid ||
        bridge.normalized_parent_consumed ||
        bridge.recursive_authority_ready ||
        bridge.violations != 0 ||
        CountViolationsV12(
            bridge.cs, bridge.columns) != 0) {
        return Fail(why, "invalid_bridge_for_prove");
    }
    const auto proved =
        aq::AirQuotientProveRows(
            bridge.cs, bridge.columns, fs_seed);
    if (!proved.ok || !proved.division_exact) {
        return Fail(
            why,
            "air_prove:" + proved.note);
    }
    out.shape = bridge.shape;
    out.registry_root = bridge.registry.root;
    out.program_root = bridge.program_root;
    out.proof = proved.proof;
    out.canonical_proof_encoding =
        CanonicalRowsProof(out.proof);
    out.normalized_parent_consumed = false;
    out.recursive_authority_ready = false;
    out.verified = false;
    out.note =
        "proof built; normalized parent consumption remains false";
    if (!out.canonical_proof_encoding) {
        out = {};
        return Fail(why, "prover_emitted_noncanonical_proof");
    }
    return true;
}

bool VerifyRecursiveBridgeProofV12(
    const fsair::ManifestV12& manifest,
    const RecursiveBridgeProofV12& receipt,
    const uint256& fs_seed,
    std::string* why)
{
    if (receipt.version != kRecursiveBridgeVersionV12 ||
        receipt.shape != manifest.shape ||
        receipt.normalized_parent_consumed ||
        receipt.recursive_authority_ready ||
        !Canonical(receipt.registry_root) ||
        !Canonical(receipt.program_root) ||
        !CanonicalRowsProof(receipt.proof)) {
        return Fail(why, "proof_envelope");
    }
    domains::TranscriptDomainRegistryV12 registry;
    cb::ProgramTable table;
    aq::AirConstraintSystem<Fp3> cs;
    if (!domains::BuildTranscriptDomainRegistryV12(
            manifest, registry, why) ||
        receipt.registry_root != registry.root ||
        !BuildRecursiveBridgeProgramTableV12(
            manifest, registry, table, why) ||
        receipt.program_root !=
            cb::CommitProgramTableAlgHash(table) ||
        !cb::BuildAirConstraintSystemFromProgramTable(
            table, kTraceRowsV12, cs, why)) {
        return Fail(why, "verifier_rebuild");
    }
    const LayoutV12 layout;
    for (uint32_t limb = 0; limb < 4; ++limb) {
        std::vector<Fp3> values(
            kTraceRowsV12,
            U(registry.root[limb]));
        cs.preprocessed.push_back({
            layout.ExpectedRegistryRoot(limb),
            std::move(values)});
    }
    cs.preprocessed_pin_ood = true;
    if (!aq::AirQuotientVerifyRows(
            cs, receipt.proof, fs_seed, why)) {
        return false;
    }
    return true;
}

namespace {

namespace aht = alg_hash_typed;
namespace ar = air_recurse;
namespace p2air = stage3_poseidon_air;
namespace safe = safe_v12;

constexpr gf::Fp kTypedEventProgramMagicV13 =
    UINT64_C(0x4254585346503133); // "BTXSFP13"
constexpr gf::Fp kTypedEventReceiptMagicV13 =
    UINT64_C(0x4254585346523133); // "BTXSFR13"
constexpr char kTypedEventReceiptDomainV13[] =
    "BTX_RC_STAGE3_TYPED_SAFE_EVENT_RECEIPT_V13";

std::vector<uint32_t> TypedEventR0BaseColumnsV13()
{
    const TypedSafeEventParentLayoutV13 layout;
    std::vector<uint32_t> out;
    out.reserve(layout.end - 2 * kTypedSafeEventCtlLanesV13);
    for (uint32_t column = 0;
         column < layout.end; ++column) {
        const bool dependent_acc =
            column >= layout.ctl_acc_base &&
            column <
                layout.ctl_acc_base +
                    kTypedSafeEventCtlLanesV13;
        const bool dependent_inverse =
            column >= layout.ctl_inverse_base &&
            column <
                layout.ctl_inverse_base +
                    kTypedSafeEventCtlLanesV13;
        if (!dependent_acc && !dependent_inverse) {
            out.push_back(column);
        }
    }
    return out;
}

bool CanonicalSplitRapProofV13(
    const aq::AirQuotientSplitRapRowsProof& proof)
{
    std::vector<unsigned char> bytes;
    const size_t encoded =
        aq::SerializeAirQuotientSplitRapRowsProof(
            proof, bytes);
    if (encoded == 0 || encoded != bytes.size()) {
        return false;
    }
    const auto decoded =
        aq::DeserializeAirQuotientSplitRapRowsProof(bytes);
    if (!decoded.has_value()) return false;
    std::vector<unsigned char> roundtrip;
    return aq::SerializeAirQuotientSplitRapRowsProof(
               *decoded, roundtrip) == bytes.size() &&
        roundtrip == bytes;
}

struct TypedEventRowPlanV13 {
    bool active{false};
    bool reset{false};
    bool final{false};
    bool commitment_final{false};
    bool query_seed_final{false};
    uint32_t event{0};
    uint32_t block{0};
    std::array<gf::Fp, safe::kSafeCapacityV12> tag{};
    std::array<bool, kTypedSafeEventRateV13> message_mask{};
    std::array<bool, kTypedSafeEventRateV13> constant_mask{};
    std::array<gf::Fp, kTypedSafeEventRateV13> constant_value{};
    std::array<bool, kTypedSafeEventRateV13> query_seed_mask{};
    std::array<uint32_t, kTypedSafeEventRateV13> query_seed_lane{};
    std::array<bool, kTypedSafeEventSourceSlotsV13> source_mask{};
    std::array<uint32_t, kTypedSafeEventSourceSlotsV13> source_id{};
    std::array<bool, kTypedSafeEventRateV13> consumer_mask{};
    std::array<uint32_t, kTypedSafeEventRateV13> consumer_id{};
};

struct TypedEventPlanV13 {
    std::vector<TypedEventRowPlanV13> rows;
    std::vector<uint32_t> first_row;
    std::vector<uint32_t> final_row;
    std::vector<std::vector<uint32_t>> proof_semantic_id;
    std::vector<std::array<uint32_t, 4>> output_semantic_id;
    uint32_t query_seed_event{std::numeric_limits<uint32_t>::max()};
    uint32_t semantic_count{0};
    uint32_t active_rows{0};
    uint32_t trace_rows{0};
    uint32_t kinds_covered{0};
    bool every_query_uses_seed{false};
};

bool KnownTypedEventKindV13(TypedSafeChallengeKindV13 kind)
{
    return static_cast<uint32_t>(kind) <=
        kTypedSafeEventAuxQuerySeedKindV13;
}

aht::RoleV12 ExpectedTypedEventRoleV13(
    TypedSafeChallengeKindV13 kind)
{
    switch (kind) {
    case TypedSafeChallengeKindV13::AirLambda:
        return aht::RoleV12::TranscriptAirLambda;
    case TypedSafeChallengeKindV13::BatchCoefficient:
        return aht::RoleV12::TranscriptBatchCoefficient;
    case TypedSafeChallengeKindV13::OodZ1:
        return aht::RoleV12::TranscriptOodZ1;
    case TypedSafeChallengeKindV13::OodZ2:
        return aht::RoleV12::TranscriptOodZ2;
    case TypedSafeChallengeKindV13::DeepWeight1:
    case TypedSafeChallengeKindV13::DeepWeight2:
        return aht::RoleV12::TranscriptDeepWeight;
    case TypedSafeChallengeKindV13::FoldBeta:
        return aht::RoleV12::TranscriptFoldBeta;
    case TypedSafeChallengeKindV13::QueryCandidate:
        return aht::RoleV12::TranscriptQueryCandidate;
    case TypedSafeChallengeKindV13::QuerySeed:
        return aht::RoleV12::TranscriptQuerySeed;
    }
    return aht::RoleV12::TranscriptPadding;
}

uint32_t NextPowerOfTwoV13(uint64_t value)
{
    if (value < 2) return 2;
    uint64_t result = 1;
    while (result < value && result <= (UINT64_C(1) << 31)) {
        result <<= 1;
    }
    return result > std::numeric_limits<uint32_t>::max()
        ? 0
        : static_cast<uint32_t>(result);
}

void AppendU32PackedV13(
    std::vector<gf::Fp>& out,
    const std::vector<uint8_t>& bytes)
{
    out.push_back(gf::FromU64(bytes.size()));
    for (size_t offset = 0; offset < bytes.size(); offset += 4) {
        uint32_t word = 0;
        for (uint32_t byte = 0;
             byte < 4 && offset + byte < bytes.size(); ++byte) {
            word |= static_cast<uint32_t>(bytes[offset + byte])
                << (8 * byte);
        }
        out.push_back(gf::FromU64(word));
    }
}

bool TypedEventTagV13(
    aht::RoleV12 role,
    const std::vector<uint8_t>& application_domain,
    uint32_t message_lanes,
    std::array<gf::Fp, safe::kSafeCapacityV12>& tag,
    std::string* why)
{
    std::vector<uint8_t> typed_domain;
    safe::IoPatternBuilderV12 builder;
    safe::IoPatternV12 pattern;
    return safe::TypedDomainV12(
               role, application_domain, typed_domain, why) &&
        builder.Absorb(message_lanes, why) &&
        builder.Squeeze(kTypedSafeEventDigestLanesV13, why) &&
        builder.Build(pattern, why) &&
        safe::DeriveTagV12(pattern, typed_domain, tag, nullptr, why);
}

bool ValidateTypedEventProgramV13(
    const std::vector<TypedSafeEventProgramV13>& program,
    TypedEventPlanV13* audit,
    std::string* why)
{
    if (program.empty() || program.size() > (UINT32_C(1) << 20)) {
        return Fail(why, "v13_event_program_count");
    }
    std::array<bool, kTypedSafeEventRequiredKindsV13> covered{};
    uint32_t query_seed = std::numeric_limits<uint32_t>::max();
    bool every_query_uses_seed = true;
    for (uint32_t event = 0; event < program.size(); ++event) {
        const auto& spec = program[event];
        if (!KnownTypedEventKindV13(spec.kind) ||
            spec.role != ExpectedTypedEventRoleV13(spec.kind) ||
            spec.application_domain.empty() ||
            spec.application_domain.size() > safe::kSafeMaxDomainBytes ||
            spec.message.empty() ||
            spec.message.size() >
                safe::kSafeMaxIoElementsPerPhase) {
            return Fail(why, "v13_event_program_shape");
        }
        const uint32_t kind = static_cast<uint32_t>(spec.kind);
        if (kind < covered.size()) covered[kind] = true;
        if (spec.kind == TypedSafeChallengeKindV13::QuerySeed) {
            if (query_seed != std::numeric_limits<uint32_t>::max()) {
                return Fail(why, "v13_multiple_query_seed_events");
            }
            query_seed = event;
        }
        std::array<uint32_t, 4> query_seed_uses{};
        for (const auto& cell : spec.message) {
            switch (cell.binding) {
            case TypedSafeMessageBindingV13::ProofOwned:
                if (cell.constant != 0 || cell.query_seed_lane != 0) {
                    return Fail(why, "v13_proof_cell_metadata");
                }
                break;
            case TypedSafeMessageBindingV13::Constant:
                if (!Canonical(cell.constant) ||
                    cell.query_seed_lane != 0) {
                    return Fail(why, "v13_constant_cell_metadata");
                }
                break;
            case TypedSafeMessageBindingV13::QuerySeedLane:
                if (cell.constant != 0 ||
                    cell.query_seed_lane >= 4) {
                    return Fail(why, "v13_query_seed_cell_metadata");
                }
                ++query_seed_uses[cell.query_seed_lane];
                break;
            default:
                return Fail(why, "v13_unknown_message_binding");
            }
        }
        if (spec.kind == TypedSafeChallengeKindV13::QueryCandidate) {
            if (query_seed == std::numeric_limits<uint32_t>::max() ||
                query_seed >= event) {
                return Fail(why, "v13_query_precedes_seed");
            }
            every_query_uses_seed &=
                std::all_of(
                    query_seed_uses.begin(), query_seed_uses.end(),
                    [](uint32_t uses) { return uses == 1; });
        } else if (std::any_of(
                       query_seed_uses.begin(), query_seed_uses.end(),
                       [](uint32_t uses) { return uses != 0; })) {
            return Fail(why, "v13_seed_lane_outside_query_event");
        }
    }
    if (query_seed == std::numeric_limits<uint32_t>::max() ||
        !every_query_uses_seed ||
        !std::all_of(
            covered.begin(), covered.end(),
            [](bool value) { return value; })) {
        return Fail(why, "v13_event_coverage");
    }
    if (audit != nullptr) {
        audit->query_seed_event = query_seed;
        audit->every_query_uses_seed = every_query_uses_seed;
        audit->kinds_covered = static_cast<uint32_t>(
            std::count(covered.begin(), covered.end(), true));
    }
    return true;
}

std::array<Fp3, 4> TypedEventCtlChallengesV13(
    const uint256& relation_seed,
    const uint256& r0_row_group_root,
    const alg_hash::Digest& program_root,
    const alg_hash::Digest& transcript_commitment)
{
    std::vector<gf::Fp> base{
        kTypedEventReceiptMagicV13,
        gf::FromU64(kTypedSafeEventParentVersionV13),
    };
    const auto append_uint256 =
        [&base](const uint256& value) {
            for (uint32_t word = 0; word < 8; ++word) {
                uint32_t packed = 0;
                for (uint32_t byte = 0; byte < 4; ++byte) {
                    packed |= static_cast<uint32_t>(
                                  value.data()[4 * word + byte])
                        << (8 * byte);
                }
                base.push_back(gf::FromU64(packed));
            }
        };
    append_uint256(relation_seed);
    append_uint256(r0_row_group_root);
    base.insert(
        base.end(), program_root.begin(), program_root.end());
    base.insert(
        base.end(),
        transcript_commitment.begin(),
        transcript_commitment.end());
    std::array<Fp3, 4> out{};
    for (uint32_t draw = 0; draw < out.size(); ++draw) {
        auto lanes = base;
        lanes.push_back(gf::FromU64(draw));
        alg_hash::Digest digest{};
        if (!aht::SpongeHashFpV12(
                aht::RoleV12::ReceiptCommitment,
                lanes, digest, nullptr)) {
            return {};
        }
        out[draw] = Fp3{
            digest[0], digest[1], digest[2]};
    }
    return out;
}

Fp3 TypedEventFactorV13(
    const Fp3& alpha, const Fp3& gamma,
    const Fp3& id, const Fp3& value)
{
    return gf::Add(
        gamma,
        gf::Add(gf::Mul(alpha, id), value));
}

Fp3 TypedEventSelectedFactorV13(
    const Fp3& alpha, const Fp3& gamma,
    const Fp3& mask, const Fp3& id,
    const Fp3& value)
{
    // mask is a verifier-pinned selector which is Boolean on H.  Writing the
    // selection as a polynomial is load-bearing: branching on IsZero(mask)
    // would not define a polynomial on the quotient coset.
    return gf::Add(
        Fp3::One(),
        gf::Mul(
            mask,
            gf::Sub(
                TypedEventFactorV13(alpha, gamma, id, value),
                Fp3::One())));
}

Fp3 TypedEventQuerySeedLaneV13(
    const Fp3& lane,
    const std::array<Fp3, kTypedSafeEventDigestLanesV13>& seed)
{
    // Lagrange interpolation over the verifier-pinned lane labels 0,1,2,3.
    // This is a degree-three polynomial in `lane` and agrees with seed[lane]
    // on every row of H.  It deliberately avoids inspecting lane.c0, which
    // would be a non-algebraic branch at quotient-domain points.
    Fp3 selected = Fp3::Zero();
    for (uint32_t j = 0; j < seed.size(); ++j) {
        Fp3 basis = Fp3::One();
        Fp3 denominator = Fp3::One();
        for (uint32_t k = 0; k < seed.size(); ++k) {
            if (j == k) continue;
            basis = gf::Mul(
                basis, gf::Sub(lane, U32(k)));
            denominator = gf::Mul(
                denominator,
                gf::Sub(U32(j), U32(k)));
        }
        selected = gf::Add(
            selected,
            gf::Mul(
                seed[j],
                gf::Mul(basis, gf::Inv(denominator))));
    }
    return selected;
}

TypedSafeMessageCellProgramV13 TypedEventConstantCellV13(
    gf::Fp value)
{
    TypedSafeMessageCellProgramV13 out;
    out.binding = TypedSafeMessageBindingV13::Constant;
    out.constant = value;
    return out;
}

TypedSafeMessageCellProgramV13 TypedEventProofCellV13()
{
    TypedSafeMessageCellProgramV13 out;
    out.binding = TypedSafeMessageBindingV13::ProofOwned;
    return out;
}

TypedSafeMessageCellProgramV13 TypedEventSeedCellV13(
    uint32_t lane)
{
    TypedSafeMessageCellProgramV13 out;
    out.binding = TypedSafeMessageBindingV13::QuerySeedLane;
    out.query_seed_lane = lane;
    return out;
}

gf::Fp PackU32ChunkV13(
    const unsigned char* bytes, size_t size, size_t offset)
{
    uint32_t word = 0;
    for (uint32_t byte = 0;
         byte < 4 && offset + byte < size; ++byte) {
        word |= static_cast<uint32_t>(bytes[offset + byte])
            << (8 * byte);
    }
    return gf::FromU64(word);
}

void AppendConstantBytesV13(
    const unsigned char* bytes, size_t size,
    std::vector<TypedSafeMessageCellProgramV13>& program,
    std::vector<gf::Fp>& witness)
{
    for (size_t offset = 0; offset < size; offset += 4) {
        program.push_back(
            TypedEventConstantCellV13(
                PackU32ChunkV13(bytes, size, offset)));
        witness.push_back(0);
    }
}

void AppendProofBytesV13(
    const unsigned char* bytes, size_t size,
    std::vector<TypedSafeMessageCellProgramV13>& program,
    std::vector<gf::Fp>& witness)
{
    for (size_t offset = 0; offset < size; offset += 4) {
        program.push_back(TypedEventProofCellV13());
        witness.push_back(
            PackU32ChunkV13(bytes, size, offset));
    }
}

bool NativeTypedEventKindV13(
    const char* label, uint32_t index,
    TypedSafeChallengeKindV13& kind,
    aht::RoleV12& role,
    std::string* why)
{
    if (label == nullptr) {
        return Fail(why, "v13_native_event_null_label");
    }
    if (std::strcmp(label, "fra3_lambda") == 0) {
        if (index != 0) {
            return Fail(why, "v13_native_lambda_index");
        }
        kind = TypedSafeChallengeKindV13::BatchCoefficient;
        role = aht::RoleV12::TranscriptBatchCoefficient;
        return true;
    }
    if (std::strcmp(label, "fra3_z") == 0) {
        kind = index <
                kRCFri3AlgSafeQ192K2OodCandidatesV13
            ? TypedSafeChallengeKindV13::OodZ1
            : TypedSafeChallengeKindV13::OodZ2;
        role = kind == TypedSafeChallengeKindV13::OodZ1
            ? aht::RoleV12::TranscriptOodZ1
            : aht::RoleV12::TranscriptOodZ2;
        return true;
    }
    if (std::strcmp(label, "fra3_w") == 0) {
        if (index > 1) {
            return Fail(why, "v13_native_deep_index");
        }
        kind = index == 0
            ? TypedSafeChallengeKindV13::DeepWeight1
            : TypedSafeChallengeKindV13::DeepWeight2;
        role = aht::RoleV12::TranscriptDeepWeight;
        return true;
    }
    if (std::strcmp(label, "fra3_fold") == 0) {
        kind = TypedSafeChallengeKindV13::FoldBeta;
        role = aht::RoleV12::TranscriptFoldBeta;
        return true;
    }
    if (std::strcmp(label, "fra3_query") == 0) {
        if (index != 0) {
            return Fail(why, "v13_native_query_seed_index");
        }
        kind = TypedSafeChallengeKindV13::QuerySeed;
        role = aht::RoleV12::TranscriptQuerySeed;
        return true;
    }
    return Fail(why, "v13_native_event_unknown_label");
}

bool NativeTypedEventDigestV13(
    const TypedSafeEventProgramV13& program,
    const TypedSafeEventWitnessV13& witness,
    const alg_hash::Digest* query_seed,
    alg_hash::Digest& digest,
    std::string* why)
{
    if (program.message.size() != witness.message.size()) {
        return Fail(why, "v13_native_event_witness_shape");
    }
    std::vector<gf::Fp> message(program.message.size());
    for (uint32_t ordinal = 0;
         ordinal < program.message.size(); ++ordinal) {
        const auto& cell = program.message[ordinal];
        switch (cell.binding) {
        case TypedSafeMessageBindingV13::ProofOwned:
            message[ordinal] = witness.message[ordinal];
            break;
        case TypedSafeMessageBindingV13::Constant:
            message[ordinal] = cell.constant;
            break;
        case TypedSafeMessageBindingV13::QuerySeedLane:
            if (query_seed == nullptr ||
                cell.query_seed_lane >= query_seed->size()) {
                return Fail(why, "v13_native_event_query_seed");
            }
            message[ordinal] =
                (*query_seed)[cell.query_seed_lane];
            break;
        }
    }
    return safe::SafeCoreDigestV12(
        program.role, program.application_domain,
        message, digest, nullptr, why);
}

bool BuildTypedEventPlanV13(
    const std::vector<TypedSafeEventProgramV13>& program,
    const alg_hash::Digest& program_root,
    const alg_hash::Digest& expected_commitment,
    TypedEventPlanV13& out,
    std::string* why)
{
    out = {};
    if (!Canonical(program_root) ||
        program_root == alg_hash::Digest{} ||
        !Canonical(expected_commitment) ||
        expected_commitment == alg_hash::Digest{} ||
        !ValidateTypedEventProgramV13(program, &out, why)) {
        return false;
    }

    out.proof_semantic_id.resize(program.size());
    out.output_semantic_id.resize(program.size());
    uint32_t semantic_id = 1;
    for (uint32_t event = 0; event < program.size(); ++event) {
        out.proof_semantic_id[event].assign(
            program[event].message.size(), 0);
        for (uint32_t ordinal = 0;
             ordinal < program[event].message.size(); ++ordinal) {
            if (program[event].message[ordinal].binding ==
                TypedSafeMessageBindingV13::ProofOwned) {
                out.proof_semantic_id[event][ordinal] =
                    semantic_id++;
            }
        }
        for (uint32_t lane = 0; lane < 4; ++lane) {
            out.output_semantic_id[event][lane] =
                semantic_id++;
        }
    }
    out.semantic_count = semantic_id - 1;

    uint64_t active_rows = 0;
    for (const auto& spec : program) {
        active_rows +=
            (spec.message.size() + kTypedSafeEventRateV13 - 1) /
            kTypedSafeEventRateV13;
    }
    constexpr uint32_t kCommitHeaderLanes = 7;
    const uint64_t commitment_lanes =
        kCommitHeaderLanes + out.semantic_count;
    const uint64_t commitment_rows =
        (commitment_lanes + kTypedSafeEventRateV13 - 1) /
        kTypedSafeEventRateV13;
    active_rows += commitment_rows;
    out.trace_rows = NextPowerOfTwoV13(active_rows + 1);
    if (out.trace_rows == 0) {
        return Fail(why, "v13_event_trace_rows_overflow");
    }
    out.rows.resize(out.trace_rows);
    out.first_row.resize(program.size());
    out.final_row.resize(program.size());

    uint32_t row = 0;
    for (uint32_t event = 0; event < program.size(); ++event) {
        const auto& spec = program[event];
        std::array<gf::Fp, safe::kSafeCapacityV12> tag{};
        if (!TypedEventTagV13(
                spec.role, spec.application_domain,
                static_cast<uint32_t>(spec.message.size()),
                tag, why)) {
            return false;
        }
        const uint32_t blocks = static_cast<uint32_t>(
            (spec.message.size() + 7) / 8);
        out.first_row[event] = row;
        out.final_row[event] = row + blocks - 1;
        for (uint32_t block = 0; block < blocks; ++block, ++row) {
            auto& r = out.rows[row];
            r.active = true;
            r.reset = block == 0;
            r.final = block + 1 == blocks;
            r.query_seed_final =
                r.final && event == out.query_seed_event;
            r.event = event;
            r.block = block;
            r.tag = tag;
            for (uint32_t lane = 0; lane < 8; ++lane) {
                const uint32_t ordinal = 8 * block + lane;
                if (ordinal >= spec.message.size()) continue;
                r.message_mask[lane] = true;
                const auto& binding = spec.message[ordinal];
                if (binding.binding ==
                    TypedSafeMessageBindingV13::Constant) {
                    r.constant_mask[lane] = true;
                    r.constant_value[lane] = binding.constant;
                } else if (binding.binding ==
                           TypedSafeMessageBindingV13::QuerySeedLane) {
                    r.query_seed_mask[lane] = true;
                    r.query_seed_lane[lane] =
                        binding.query_seed_lane;
                } else {
                    r.source_mask[lane] = true;
                    r.source_id[lane] =
                        out.proof_semantic_id[event][ordinal];
                }
            }
            if (r.final) {
                for (uint32_t lane = 0; lane < 4; ++lane) {
                    r.source_mask[8 + lane] = true;
                    r.source_id[8 + lane] =
                        out.output_semantic_id[event][lane];
                }
            }
        }
    }

    std::vector<gf::Fp> commit_constants{
        kTypedEventReceiptMagicV13,
        gf::FromU64(kTypedSafeEventParentVersionV13),
        program_root[0], program_root[1],
        program_root[2], program_root[3],
        gf::FromU64(out.semantic_count),
    };
    std::array<gf::Fp, safe::kSafeCapacityV12> commit_tag{};
    const std::vector<uint8_t> commit_domain(
        reinterpret_cast<const uint8_t*>(
            kTypedEventReceiptDomainV13),
        reinterpret_cast<const uint8_t*>(
            kTypedEventReceiptDomainV13) +
            sizeof(kTypedEventReceiptDomainV13) - 1);
    const uint32_t commitment_message_lanes =
        static_cast<uint32_t>(
            commit_constants.size() + out.semantic_count);
    if (!TypedEventTagV13(
            aht::RoleV12::ReceiptCommitment,
            commit_domain, commitment_message_lanes,
            commit_tag, why)) {
        return false;
    }
    const uint32_t commitment_first = row;
    uint32_t consumer_id = 1;
    for (uint32_t ordinal = 0;
         ordinal < commitment_message_lanes; ++ordinal) {
        const uint32_t block = ordinal / 8;
        const uint32_t lane = ordinal % 8;
        auto& r = out.rows[commitment_first + block];
        r.active = true;
        r.reset = block == 0;
        r.final =
            ordinal / 8 + 1 ==
            (commitment_message_lanes + 7) / 8;
        r.commitment_final = r.final;
        r.event = static_cast<uint32_t>(program.size());
        r.block = block;
        r.tag = commit_tag;
        r.message_mask[lane] = true;
        if (ordinal < commit_constants.size()) {
            r.constant_mask[lane] = true;
            r.constant_value[lane] =
                commit_constants[ordinal];
        } else {
            r.consumer_mask[lane] = true;
            r.consumer_id[lane] = consumer_id++;
        }
    }
    row = commitment_first +
        (commitment_message_lanes + 7) / 8;
    out.active_rows = row;
    if (row >= out.trace_rows ||
        consumer_id != out.semantic_count + 1) {
        return Fail(why, "v13_event_schedule_terminal");
    }
    return true;
}

void AddTypedEventPreprocessedV13(
    aq::AirConstraintSystem<Fp3>& cs,
    std::vector<std::vector<Fp3>>* columns,
    uint32_t column,
    const std::vector<Fp3>& values)
{
    cs.preprocessed.push_back({column, values});
    if (columns != nullptr) {
        (*columns)[column] = values;
    }
}

bool BuildTypedEventCsV13(
    const std::vector<TypedSafeEventProgramV13>& program,
    const alg_hash::Digest& program_root,
    const alg_hash::Digest& expected_commitment,
    const std::array<Fp3, 4>& challenges,
    TypedEventPlanV13& plan,
    aq::AirConstraintSystem<Fp3>& cs,
    std::vector<std::vector<Fp3>>* columns,
    std::string* why)
{
    if (!BuildTypedEventPlanV13(
            program, program_root, expected_commitment,
            plan, why)) {
        return false;
    }
    const TypedSafeEventParentLayoutV13 layout;
    cs = {};
    cs.n_rows = plan.trace_rows;
    cs.n_columns = layout.end;
    if (columns != nullptr) {
        columns->assign(
            cs.n_columns,
            std::vector<Fp3>(cs.n_rows, Fp3::Zero()));
    }

    std::vector<Fp3> active(cs.n_rows);
    std::vector<Fp3> reset(cs.n_rows);
    std::vector<Fp3> final(cs.n_rows);
    std::vector<Fp3> commitment_final(cs.n_rows);
    std::vector<Fp3> query_seed_final(cs.n_rows);
    std::array<std::vector<Fp3>, 8> message_mask;
    std::array<std::vector<Fp3>, 4> tag;
    std::array<std::vector<Fp3>, 8> constant_mask;
    std::array<std::vector<Fp3>, 8> constant_value;
    std::array<std::vector<Fp3>, 8> query_seed_mask;
    std::array<std::vector<Fp3>, 8> query_seed_lane;
    std::array<std::vector<Fp3>, 12> source_mask;
    std::array<std::vector<Fp3>, 12> source_id;
    std::array<std::vector<Fp3>, 8> consumer_mask;
    std::array<std::vector<Fp3>, 8> consumer_id;
    std::array<std::vector<Fp3>, 4> expected;
    for (auto* array : {
             &message_mask, &constant_mask, &constant_value,
             &query_seed_mask, &query_seed_lane,
             &consumer_mask, &consumer_id}) {
        for (auto& values : *array) values.resize(cs.n_rows);
    }
    for (auto& values : tag) values.resize(cs.n_rows);
    for (auto& values : source_mask) values.resize(cs.n_rows);
    for (auto& values : source_id) values.resize(cs.n_rows);
    for (auto& values : expected) values.resize(cs.n_rows);

    for (uint32_t row = 0; row < cs.n_rows; ++row) {
        const auto& p = plan.rows[row];
        active[row] = U(p.active);
        reset[row] = U(p.reset);
        final[row] = U(p.final);
        commitment_final[row] = U(p.commitment_final);
        query_seed_final[row] = U(p.query_seed_final);
        for (uint32_t lane = 0; lane < 8; ++lane) {
            message_mask[lane][row] = U(p.message_mask[lane]);
            constant_mask[lane][row] = U(p.constant_mask[lane]);
            constant_value[lane][row] = U(p.constant_value[lane]);
            query_seed_mask[lane][row] =
                U(p.query_seed_mask[lane]);
            query_seed_lane[lane][row] =
                U32(p.query_seed_lane[lane]);
            consumer_mask[lane][row] =
                U(p.consumer_mask[lane]);
            consumer_id[lane][row] =
                U32(p.consumer_id[lane]);
        }
        for (uint32_t lane = 0; lane < 4; ++lane) {
            tag[lane][row] = U(p.tag[lane]);
            expected[lane][row] =
                U(expected_commitment[lane]);
        }
        for (uint32_t slot = 0; slot < 12; ++slot) {
            source_mask[slot][row] = U(p.source_mask[slot]);
            source_id[slot][row] = U32(p.source_id[slot]);
        }
    }
    AddTypedEventPreprocessedV13(
        cs, columns, layout.active, active);
    AddTypedEventPreprocessedV13(
        cs, columns, layout.reset, reset);
    AddTypedEventPreprocessedV13(
        cs, columns, layout.final, final);
    AddTypedEventPreprocessedV13(
        cs, columns, layout.commitment_final,
        commitment_final);
    AddTypedEventPreprocessedV13(
        cs, columns, layout.query_seed_final,
        query_seed_final);
    for (uint32_t lane = 0; lane < 8; ++lane) {
        AddTypedEventPreprocessedV13(
            cs, columns, layout.message_mask_base + lane,
            message_mask[lane]);
        AddTypedEventPreprocessedV13(
            cs, columns, layout.constant_mask_base + lane,
            constant_mask[lane]);
        AddTypedEventPreprocessedV13(
            cs, columns, layout.constant_value_base + lane,
            constant_value[lane]);
        AddTypedEventPreprocessedV13(
            cs, columns, layout.query_seed_mask_base + lane,
            query_seed_mask[lane]);
        AddTypedEventPreprocessedV13(
            cs, columns, layout.query_seed_lane_base + lane,
            query_seed_lane[lane]);
        AddTypedEventPreprocessedV13(
            cs, columns, layout.consumer_mask_base + lane,
            consumer_mask[lane]);
        AddTypedEventPreprocessedV13(
            cs, columns, layout.consumer_id_base + lane,
            consumer_id[lane]);
    }
    for (uint32_t lane = 0; lane < 4; ++lane) {
        AddTypedEventPreprocessedV13(
            cs, columns, layout.tag_base + lane, tag[lane]);
        AddTypedEventPreprocessedV13(
            cs, columns,
            layout.expected_commitment_base + lane,
            expected[lane]);
    }
    for (uint32_t slot = 0; slot < 12; ++slot) {
        AddTypedEventPreprocessedV13(
            cs, columns, layout.source_mask_base + slot,
            source_mask[slot]);
        AddTypedEventPreprocessedV13(
            cs, columns, layout.source_id_base + slot,
            source_id[slot]);
    }
    cs.preprocessed_pin_ood = true;

    auto p2 = p2air::BuildSelectorGatedConstraints(
        layout.poseidon, layout.active);
    cs.constraints.insert(
        cs.constraints.end(),
        std::make_move_iterator(p2.begin()),
        std::make_move_iterator(p2.end()));

    for (uint32_t lane = 0; lane < 8; ++lane) {
        {
            aq::AirConstraint<Fp3> c;
            c.name = "stage3.safe_event.message_padding";
            c.kind = aq::AirKind::kEverywhere;
            c.alg_degree = 2;
            c.eval = [layout, lane](
                         const auto& cur, const auto&) {
                return gf::Mul(
                    gf::Sub(
                        Fp3::One(),
                        cur[layout.message_mask_base + lane]),
                    cur[layout.Message(lane)]);
            };
            cs.constraints.push_back(std::move(c));
        }
        for (uint32_t bit = 0; bit < 64; ++bit) {
            aq::AirConstraint<Fp3> c;
            c.name = "stage3.safe_event.message_bit";
            c.kind = aq::AirKind::kEverywhere;
            c.alg_degree = 2;
            const uint32_t col = layout.Bit(lane, bit);
            c.eval = [col](const auto& cur, const auto&) {
                return gf::Mul(
                    cur[col],
                    gf::Sub(cur[col], Fp3::One()));
            };
            cs.constraints.push_back(std::move(c));
        }
        {
            aq::AirConstraint<Fp3> c;
            c.name = "stage3.safe_event.message_recompose";
            c.kind = aq::AirKind::kEverywhere;
            c.alg_degree = 1;
            c.eval = [layout, lane](
                         const auto& cur, const auto&) {
                Fp3 sum = Fp3::Zero();
                for (uint32_t bit = 0; bit < 64; ++bit) {
                    sum = gf::Add(
                        sum,
                        gf::Mul(
                            U(gf::FromU64(uint64_t{1} << bit)),
                            cur[layout.Bit(lane, bit)]));
                }
                return gf::Sub(cur[layout.Message(lane)], sum);
            };
            cs.constraints.push_back(std::move(c));
        }
        for (uint32_t step = 0;
             step < kTypedSafeEventHighAndStepsV13; ++step) {
            aq::AirConstraint<Fp3> c;
            c.name = "stage3.safe_event.message_high_and";
            c.kind = aq::AirKind::kEverywhere;
            c.alg_degree = 7;
            c.eval = [layout, lane, step](
                         const auto& cur, const auto&) {
                Fp3 product = step == 0
                    ? Fp3::One()
                    : cur[layout.HighAnd(lane, step - 1)];
                const uint32_t first = 32 + 6 * step;
                const uint32_t last =
                    std::min<uint32_t>(64, first + 6);
                for (uint32_t bit = first; bit < last; ++bit) {
                    product = gf::Mul(
                        product, cur[layout.Bit(lane, bit)]);
                }
                return gf::Sub(
                    cur[layout.HighAnd(lane, step)], product);
            };
            cs.constraints.push_back(std::move(c));
        }
        {
            aq::AirConstraint<Fp3> c;
            c.name = "stage3.safe_event.message_canonical";
            c.kind = aq::AirKind::kEverywhere;
            c.alg_degree = 2;
            c.eval = [layout, lane](
                         const auto& cur, const auto&) {
                Fp3 low = Fp3::Zero();
                for (uint32_t bit = 0; bit < 32; ++bit) {
                    low = gf::Add(
                        low,
                        gf::Mul(
                            U(gf::FromU64(uint64_t{1} << bit)),
                            cur[layout.Bit(lane, bit)]));
                }
                return gf::Mul(
                    cur[layout.HighAnd(
                        lane,
                        kTypedSafeEventHighAndStepsV13 - 1)],
                    low);
            };
            cs.constraints.push_back(std::move(c));
        }
        {
            aq::AirConstraint<Fp3> c;
            c.name = "stage3.safe_event.constant_binding";
            c.kind = aq::AirKind::kEverywhere;
            c.alg_degree = 2;
            c.eval = [layout, lane](
                         const auto& cur, const auto&) {
                return gf::Mul(
                    cur[layout.constant_mask_base + lane],
                    gf::Sub(
                        cur[layout.Message(lane)],
                        cur[layout.constant_value_base + lane]));
            };
            cs.constraints.push_back(std::move(c));
        }
        {
            aq::AirConstraint<Fp3> c;
            c.name = "stage3.safe_event.query_seed_binding";
            c.kind = aq::AirKind::kEverywhere;
            // query_seed_mask * (message - Lagrange_3(lane, seed)).
            c.alg_degree = 5;
            c.eval = [layout, lane](
                         const auto& cur, const auto&) {
                std::array<
                    Fp3, kTypedSafeEventDigestLanesV13> seed{};
                for (uint32_t seed_lane = 0;
                     seed_lane < seed.size(); ++seed_lane) {
                    seed[seed_lane] =
                        cur[layout.QuerySeed(seed_lane)];
                }
                return gf::Mul(
                    cur[layout.query_seed_mask_base + lane],
                    gf::Sub(
                        cur[layout.Message(lane)],
                        TypedEventQuerySeedLaneV13(
                            cur[layout.query_seed_lane_base + lane],
                            seed)));
            };
            cs.constraints.push_back(std::move(c));
        }
        {
            aq::AirConstraint<Fp3> c;
            c.name = "stage3.safe_event.reset_rate";
            c.kind = aq::AirKind::kEverywhere;
            c.alg_degree = 2;
            c.eval = [layout, lane](
                         const auto& cur, const auto&) {
                return gf::Mul(
                    cur[layout.reset],
                    gf::Sub(
                        cur[layout.poseidon.perm.InputCol(lane)],
                        cur[layout.Message(lane)]));
            };
            cs.constraints.push_back(std::move(c));
        }
        {
            aq::AirConstraint<Fp3> c;
            c.name = "stage3.safe_event.state_rate_transition";
            c.kind = aq::AirKind::kTransition;
            c.alg_degree = 3;
            c.eval = [layout, lane](
                         const auto& cur, const auto& next) {
                const Fp3 gate = gf::Mul(
                    next[layout.active],
                    gf::Sub(Fp3::One(), next[layout.reset]));
                return gf::Mul(
                    gate,
                    gf::Sub(
                        next[layout.poseidon.perm.InputCol(lane)],
                        gf::Add(
                            ar::PermOutputLane(
                                layout.poseidon.perm, cur, lane),
                            next[layout.Message(lane)])));
            };
            cs.constraints.push_back(std::move(c));
        }
    }
    for (uint32_t lane = 0; lane < 4; ++lane) {
        const uint32_t state_lane =
            safe::kSafeRateV12 + lane;
        {
            aq::AirConstraint<Fp3> c;
            c.name = "stage3.safe_event.reset_capacity";
            c.kind = aq::AirKind::kEverywhere;
            c.alg_degree = 2;
            c.eval = [layout, lane, state_lane](
                         const auto& cur, const auto&) {
                return gf::Mul(
                    cur[layout.reset],
                    gf::Sub(
                        cur[layout.poseidon.perm.InputCol(state_lane)],
                        cur[layout.tag_base + lane]));
            };
            cs.constraints.push_back(std::move(c));
        }
        {
            aq::AirConstraint<Fp3> c;
            c.name = "stage3.safe_event.state_capacity_transition";
            c.kind = aq::AirKind::kTransition;
            c.alg_degree = 3;
            c.eval = [layout, state_lane](
                         const auto& cur, const auto& next) {
                const Fp3 gate = gf::Mul(
                    next[layout.active],
                    gf::Sub(Fp3::One(), next[layout.reset]));
                return gf::Mul(
                    gate,
                    gf::Sub(
                        next[layout.poseidon.perm.InputCol(state_lane)],
                        ar::PermOutputLane(
                            layout.poseidon.perm, cur, state_lane)));
            };
            cs.constraints.push_back(std::move(c));
        }
        {
            aq::AirConstraint<Fp3> c;
            c.name = "stage3.safe_event.output";
            c.kind = aq::AirKind::kEverywhere;
            c.alg_degree = 2;
            c.eval = [layout, lane](
                         const auto& cur, const auto&) {
                return gf::Mul(
                    cur[layout.final],
                    gf::Sub(
                        cur[layout.Output(lane)],
                        ar::PermOutputLane(
                            layout.poseidon.perm, cur, lane)));
            };
            cs.constraints.push_back(std::move(c));
        }
        {
            aq::AirConstraint<Fp3> c;
            c.name = "stage3.safe_event.output_zero_elsewhere";
            c.kind = aq::AirKind::kEverywhere;
            c.alg_degree = 2;
            c.eval = [layout, lane](
                         const auto& cur, const auto&) {
                return gf::Mul(
                    gf::Sub(Fp3::One(), cur[layout.final]),
                    cur[layout.Output(lane)]);
            };
            cs.constraints.push_back(std::move(c));
        }
        {
            aq::AirConstraint<Fp3> c;
            c.name = "stage3.safe_event.query_seed_export";
            c.kind = aq::AirKind::kEverywhere;
            c.alg_degree = 2;
            c.eval = [layout, lane](
                         const auto& cur, const auto&) {
                return gf::Mul(
                    cur[layout.query_seed_final],
                    gf::Sub(
                        cur[layout.Output(lane)],
                        cur[layout.QuerySeed(lane)]));
            };
            cs.constraints.push_back(std::move(c));
        }
        {
            aq::AirConstraint<Fp3> c;
            c.name = "stage3.safe_event.query_seed_stable";
            c.kind = aq::AirKind::kTransition;
            c.alg_degree = 1;
            c.eval = [layout, lane](
                         const auto& cur, const auto& next) {
                return gf::Sub(
                    next[layout.QuerySeed(lane)],
                    cur[layout.QuerySeed(lane)]);
            };
            cs.constraints.push_back(std::move(c));
        }
        {
            aq::AirConstraint<Fp3> c;
            c.name = "stage3.safe_event.commitment_boundary";
            c.kind = aq::AirKind::kEverywhere;
            c.alg_degree = 2;
            c.eval = [layout, lane](
                         const auto& cur, const auto&) {
                return gf::Mul(
                    cur[layout.commitment_final],
                    gf::Sub(
                        cur[layout.Output(lane)],
                        cur[layout.expected_commitment_base + lane]));
            };
            cs.constraints.push_back(std::move(c));
        }
    }

    if (std::any_of(
            challenges.begin(), challenges.end(),
            [](const Fp3& value) { return gf::IsZero(value); })) {
        return Fail(why, "v13_ctl_challenge_zero");
    }
    for (uint32_t ctl = 0; ctl < 2; ++ctl) {
        const Fp3 alpha = challenges[2 * ctl];
        const Fp3 gamma = challenges[2 * ctl + 1];
        const uint32_t acc = layout.ctl_acc_base + ctl;
        const uint32_t inverse =
            layout.ctl_inverse_base + ctl;
        auto products =
            [layout, alpha, gamma](const auto& cur) {
                Fp3 numerator = Fp3::One();
                Fp3 denominator = Fp3::One();
                for (uint32_t slot = 0; slot < 12; ++slot) {
                    const Fp3 value = slot < 8
                        ? cur[layout.Message(slot)]
                        : cur[layout.Output(slot - 8)];
                    numerator = gf::Mul(
                        numerator,
                        TypedEventSelectedFactorV13(
                            alpha, gamma,
                            cur[layout.source_mask_base + slot],
                            cur[layout.source_id_base + slot],
                            value));
                }
                for (uint32_t slot = 0; slot < 8; ++slot) {
                    denominator = gf::Mul(
                        denominator,
                        TypedEventSelectedFactorV13(
                            alpha, gamma,
                            cur[layout.consumer_mask_base + slot],
                            cur[layout.consumer_id_base + slot],
                            cur[layout.Message(slot)]));
                }
                return std::pair<Fp3, Fp3>{
                    numerator, denominator};
            };
        {
            aq::AirConstraint<Fp3> c;
            c.name = "stage3.safe_event.ctl_inverse";
            c.kind = aq::AirKind::kEverywhere;
            // Eight selected factors of degree two, times the inverse.
            c.alg_degree = 17;
            c.eval = [products, inverse](
                         const auto& cur, const auto&) {
                return gf::Sub(
                    gf::Mul(products(cur).second, cur[inverse]),
                    Fp3::One());
            };
            cs.constraints.push_back(std::move(c));
        }
        {
            aq::AirConstraint<Fp3> c;
            c.name = "stage3.safe_event.ctl_transition";
            c.kind = aq::AirKind::kTransition;
            // acc * twelve degree-two selected factors * denominator_inverse.
            c.alg_degree = 26;
            c.eval = [products, acc, inverse](
                         const auto& cur, const auto& next) {
                return gf::Sub(
                    next[acc],
                    gf::Mul(
                        cur[acc],
                        gf::Mul(
                            products(cur).first,
                            cur[inverse])));
            };
            cs.constraints.push_back(std::move(c));
        }
        {
            aq::AirConstraint<Fp3> first;
            first.name = "stage3.safe_event.ctl_first";
            first.kind = aq::AirKind::kFirstRow;
            first.alg_degree = 1;
            first.eval = [acc](const auto& cur, const auto&) {
                return gf::Sub(cur[acc], Fp3::One());
            };
            cs.constraints.push_back(std::move(first));
        }
        {
            aq::AirConstraint<Fp3> last;
            last.name = "stage3.safe_event.ctl_last";
            last.kind = aq::AirKind::kLastRow;
            last.alg_degree = 1;
            last.eval = [acc](const auto& cur, const auto&) {
                return gf::Sub(cur[acc], Fp3::One());
            };
            cs.constraints.push_back(std::move(last));
        }
    }
    return true;
}

std::vector<gf::Fp> TypedEventReceiptMessageV13(
    const alg_hash::Digest& program_root,
    const std::vector<gf::Fp>& semantic)
{
    std::vector<gf::Fp> out{
        kTypedEventReceiptMagicV13,
        gf::FromU64(kTypedSafeEventParentVersionV13),
        program_root[0], program_root[1],
        program_root[2], program_root[3],
        gf::FromU64(semantic.size()),
    };
    out.insert(out.end(), semantic.begin(), semantic.end());
    return out;
}

bool PopulateTypedEventBitsV13(
    const TypedSafeEventParentLayoutV13& layout,
    std::vector<std::vector<Fp3>>& columns,
    uint32_t row, uint32_t lane, gf::Fp raw)
{
    if (!Canonical(raw)) return false;
    for (uint32_t bit = 0; bit < 64; ++bit) {
        columns[layout.Bit(lane, bit)][row] =
            U((raw >> bit) & 1U);
    }
    gf::Fp cumulative = 1;
    for (uint32_t step = 0; step < 6; ++step) {
        const uint32_t first = 32 + 6 * step;
        const uint32_t last =
            std::min<uint32_t>(64, first + 6);
        for (uint32_t bit = first; bit < last; ++bit) {
            cumulative = gf::Mul(
                cumulative, (raw >> bit) & 1U);
        }
        columns[layout.HighAnd(lane, step)][row] =
            U(cumulative);
    }
    return true;
}

std::pair<Fp3, Fp3> TypedEventWitnessProductsV13(
    const TypedSafeEventParentLayoutV13& layout,
    const std::vector<std::vector<Fp3>>& columns,
    uint32_t row, const Fp3& alpha, const Fp3& gamma)
{
    Fp3 numerator = Fp3::One();
    Fp3 denominator = Fp3::One();
    for (uint32_t slot = 0; slot < 12; ++slot) {
        if (!gf::IsZero(
                columns[layout.source_mask_base + slot][row])) {
            const Fp3 value = slot < 8
                ? columns[layout.Message(slot)][row]
                : columns[layout.Output(slot - 8)][row];
            numerator = gf::Mul(
                numerator,
                TypedEventFactorV13(
                    alpha, gamma,
                    columns[layout.source_id_base + slot][row],
                    value));
        }
    }
    for (uint32_t slot = 0; slot < 8; ++slot) {
        if (!gf::IsZero(
                columns[layout.consumer_mask_base + slot][row])) {
            denominator = gf::Mul(
                denominator,
                TypedEventFactorV13(
                    alpha, gamma,
                    columns[layout.consumer_id_base + slot][row],
                    columns[layout.Message(slot)][row]));
        }
    }
    return {numerator, denominator};
}

} // namespace

bool BuildNativeFri3AlgSafeEventV13(
    const std::vector<unsigned char>& transcript,
    const char* label,
    uint32_t index,
    NativeTypedSafeEventAuditV13& out,
    std::string* why)
{
    out = {};
    if (transcript.size() >
        std::numeric_limits<uint32_t>::max()) {
        return Fail(why, "v13_native_event_transcript_length");
    }
    if (!NativeTypedEventKindV13(
            label, index, out.program.kind,
            out.program.role, why)) {
        return false;
    }
    const size_t label_size = std::strlen(label);
    if (label_size > std::numeric_limits<uint32_t>::max()) {
        return Fail(why, "v13_native_event_label_length");
    }

    static constexpr char kDomain[] =
        "BTX_RC_FRIB3ALG_Q192_SAFE_K2_V13_CHALLENGE";
    out.program.application_domain.assign(
        reinterpret_cast<const uint8_t*>(kDomain),
        reinterpret_cast<const uint8_t*>(kDomain) +
            sizeof(kDomain) - 1);
    out.program.application_domain.push_back(0);
    out.program.application_domain.insert(
        out.program.application_domain.end(),
        reinterpret_cast<const uint8_t*>(label),
        reinterpret_cast<const uint8_t*>(label) + label_size);

    auto& cells = out.program.message;
    auto& values = out.witness.message;
    const auto append_constant =
        [&](gf::Fp value) {
            cells.push_back(TypedEventConstantCellV13(value));
            values.push_back(0);
        };
    append_constant(gf::FromU64(UINT32_C(0x53414645)));
    append_constant(gf::FromU64(
        kRCFri3AlgSafeQ192K2ProofVersionV13));
    append_constant(gf::FromU64(
        static_cast<uint32_t>(out.program.role)));
    append_constant(gf::FromU64(transcript.size()));
    AppendProofBytesV13(
        transcript.data(), transcript.size(),
        cells, values);
    append_constant(gf::FromU64(label_size));
    AppendConstantBytesV13(
        reinterpret_cast<const unsigned char*>(label),
        label_size, cells, values);
    append_constant(gf::FromU64(index));

    if (!NativeTypedEventDigestV13(
            out.program, out.witness, nullptr,
            out.safe_digest, why)) {
        return false;
    }
    if (out.program.kind ==
        TypedSafeChallengeKindV13::QuerySeed) {
        alg_hash::Digest native_seed{};
        if (!Fri3AlgSafeQ192K2QuerySeedV13(
                transcript, native_seed, why)) {
            return false;
        }
        out.native_output = {
            native_seed[0], native_seed[1], native_seed[2]};
        out.native_air_output_parity =
            native_seed == out.safe_digest;
        out.query_seed_source = true;
    } else {
        if (!Fri3AlgSafeQ192K2ChallengeFp3V13(
                transcript, label, index,
                out.native_output, why)) {
            return false;
        }
        out.native_air_output_parity =
            gf::Eq(
                out.native_output,
                Fp3{
                    out.safe_digest[0],
                    out.safe_digest[1],
                    out.safe_digest[2]});
    }
    out.exact_message_materialized =
        out.program.message.size() ==
            out.witness.message.size() &&
        std::count_if(
            out.program.message.begin(),
            out.program.message.end(),
            [](const auto& cell) {
                return cell.binding ==
                    TypedSafeMessageBindingV13::ProofOwned;
            }) ==
            static_cast<std::ptrdiff_t>(
                (transcript.size() + 3) / 4);
    out.note =
        out.exact_message_materialized &&
                out.native_air_output_parity
        ? "native Fri3Alg SAFE event exactly materialized"
        : "native Fri3Alg SAFE event parity failed";
    if (!out.exact_message_materialized ||
        !out.native_air_output_parity) {
        return Fail(why, "v13_native_event_parity");
    }
    return true;
}

bool BuildNativeFri3AlgSafeQueryCandidateEventV13(
    const alg_hash::Digest& query_seed,
    uint32_t index,
    NativeTypedSafeEventAuditV13& out,
    std::string* why)
{
    out = {};
    if (!Canonical(query_seed)) {
        return Fail(why, "v13_native_query_seed_noncanonical");
    }
    out.program.kind =
        TypedSafeChallengeKindV13::QueryCandidate;
    out.program.role =
        aht::RoleV12::TranscriptQueryCandidate;
    static constexpr char kDomain[] =
        "BTX_RC_FRIB3ALG_Q192_SAFE_K2_V13_QUERY_CANDIDATE";
    out.program.application_domain.assign(
        reinterpret_cast<const uint8_t*>(kDomain),
        reinterpret_cast<const uint8_t*>(kDomain) +
            sizeof(kDomain) - 1);

    auto& cells = out.program.message;
    auto& values = out.witness.message;
    const auto append_constant =
        [&](gf::Fp value) {
            cells.push_back(TypedEventConstantCellV13(value));
            values.push_back(0);
        };
    append_constant(gf::FromU64(UINT32_C(0x53414645)));
    append_constant(gf::FromU64(
        kRCFri3AlgSafeQ192K2ProofVersionV13));
    append_constant(gf::FromU64(
        static_cast<uint32_t>(
            aht::RoleV12::TranscriptQueryCandidate)));
    append_constant(gf::FromU64(query_seed.size()));
    for (uint32_t lane = 0;
         lane < query_seed.size(); ++lane) {
        cells.push_back(TypedEventSeedCellV13(lane));
        values.push_back(0);
    }
    append_constant(gf::FromU64(index));

    if (!NativeTypedEventDigestV13(
            out.program, out.witness, &query_seed,
            out.safe_digest, why) ||
        !Fri3AlgSafeQ192K2QueryCandidateV13(
            query_seed, index, out.native_output, why)) {
        return false;
    }
    out.native_air_output_parity =
        gf::Eq(
            out.native_output,
            Fp3{
                out.safe_digest[0],
                out.safe_digest[1],
                out.safe_digest[2]});
    out.exact_message_materialized =
        out.program.message.size() == 9 &&
        out.witness.message.size() == 9;
    out.query_candidate_consumes_seed =
        std::count_if(
            out.program.message.begin(),
            out.program.message.end(),
            [](const auto& cell) {
                return cell.binding ==
                    TypedSafeMessageBindingV13::QuerySeedLane;
            }) == 4;
    out.note =
        out.exact_message_materialized &&
                out.native_air_output_parity &&
                out.query_candidate_consumes_seed
        ? "native Fri3Alg SAFE query candidate exactly materialized"
        : "native Fri3Alg SAFE query candidate parity failed";
    if (!out.exact_message_materialized ||
        !out.native_air_output_parity ||
        !out.query_candidate_consumes_seed) {
        return Fail(why, "v13_native_query_candidate_parity");
    }
    return true;
}

bool BuildNativeFri3AlgTypedSafeScheduleV13(
    const Fri3AlgBatchProof& proof,
    const uint256& child_fs_seed,
    NativeFri3AlgTypedSafeScheduleV13& out,
    std::string* why)
{
    out = {};
    if (!Fri3AlgSafeQ192K2V13BatchVerifyReplay(
            proof, child_fs_seed, out.replay, why) ||
        !out.replay.native_verified ||
        !out.replay.exact_event_order) {
        out = {};
        return Fail(why, "v13_native_schedule_verifier_replay");
    }
    if (proof.version !=
            kRCFri3AlgSafeQ192K2ProofVersionV13 ||
        proof.n_coeffs == 0 ||
        proof.n_coeffs >
            std::numeric_limits<uint32_t>::max() /
                kRCFriBlowup) {
        out = {};
        return Fail(why, "v13_native_schedule_shape");
    }

    out.program.reserve(out.replay.events.size());
    out.witness.reserve(out.replay.events.size());
    std::array<bool, kTypedSafeEventAuxQuerySeedKindV13 + 1>
        kind_seen{};
    bool query_seed_seen = false;
    bool exact = true;
    bool consumers = true;
    uint32_t query_seed_count = 0;
    std::array<uint32_t, 9> consumer_ordinal{};
    bool z1_selected = false;
    bool z2_selected = false;
    for (uint32_t ordinal = 0;
         ordinal < out.replay.events.size(); ++ordinal) {
        const Fri3AlgSafeV13ReplayEvent& event =
            out.replay.events[ordinal];
        const uint32_t consumer =
            static_cast<uint32_t>(event.consumer);
        if (consumer == 0 ||
            consumer >= consumer_ordinal.size() ||
            event.ordinal != consumer_ordinal[consumer]++) {
            return Fail(
                why,
                "v13_native_schedule_family_ordinal");
        }

        NativeTypedSafeEventAuditV13 audit;
        bool built = false;
        if (event.consumer ==
            Fri3AlgSafeV13Consumer::QueryIndex) {
            if (!query_seed_seen ||
                !event.transcript_before_draw.empty()) {
                return Fail(
                    why,
                    "v13_native_schedule_query_source_order");
            }
            built =
                BuildNativeFri3AlgSafeQueryCandidateEventV13(
                    out.replay.query_seed,
                    event.draw_index, audit, why);
        } else {
            if (event.consumer ==
                Fri3AlgSafeV13Consumer::QuerySeed) {
                if (query_seed_seen) {
                    return Fail(
                        why,
                        "v13_native_schedule_duplicate_query_seed");
                }
                query_seed_seen = true;
                ++query_seed_count;
            } else if (query_seed_seen) {
                // The unique query seed is a phase boundary: after it, only
                // fixed-shape query candidates are legal.
                return Fail(
                    why,
                    "v13_native_schedule_post_query_seed_event");
            }
            built = BuildNativeFri3AlgSafeEventV13(
                event.transcript_before_draw,
                event.label.c_str(), event.draw_index,
                audit, why);
        }
        if (!built) return false;

        exact =
            exact &&
            audit.exact_message_materialized &&
            audit.native_air_output_parity &&
            audit.program.role == event.role &&
            audit.safe_digest == event.safe_digest;
        if (event.consumer ==
            Fri3AlgSafeV13Consumer::QuerySeed) {
            consumers =
                consumers &&
                event.safe_digest == out.replay.query_seed &&
                audit.query_seed_source;
        } else {
            consumers =
                consumers &&
                gf::Eq(
                    audit.native_output,
                    event.consumed_fp3);
        }
        if (event.consumer ==
                Fri3AlgSafeV13Consumer::OodZ1 ||
            event.consumer ==
                Fri3AlgSafeV13Consumer::OodZ2) {
            const bool ext =
                gf::Canonical(
                    event.consumed_fp3.c1) != 0 ||
                gf::Canonical(
                    event.consumed_fp3.c2) != 0;
            const bool is_z2 =
                event.consumer ==
                Fri3AlgSafeV13Consumer::OodZ2;
            const bool acceptable =
                ext &&
                (!is_z2 ||
                 !gf::Eq(
                     event.consumed_fp3,
                     proof.z1));
            bool& already_selected =
                is_z2 ? z2_selected : z1_selected;
            const bool selected =
                acceptable && !already_selected;
            consumers =
                consumers &&
                event.acceptable == acceptable &&
                event.selected == selected;
            if (selected) {
                already_selected = true;
                consumers =
                    consumers &&
                    gf::Eq(
                        event.consumed_fp3,
                        is_z2 ? proof.z2 : proof.z1);
            }
        }
        if (event.consumer ==
            Fri3AlgSafeV13Consumer::QueryIndex) {
            const uint32_t n_lde =
                proof.n_coeffs * kRCFriBlowup;
            if ((n_lde & (n_lde - 1)) != 0 ||
                n_lde == 0) {
                return Fail(
                    why,
                    "v13_native_schedule_query_modulus");
            }
            const unsigned __int128 wide =
                (static_cast<unsigned __int128>(
                     gf::Canonical(
                         event.consumed_fp3.c1))
                 << 64) |
                gf::Canonical(event.consumed_fp3.c0);
            consumers =
                consumers &&
                event.consumed_index ==
                    static_cast<uint32_t>(wide % n_lde) &&
                event.draw_index <
                    kRCFri3AlgNumQueries &&
                event.consumed_index ==
                    proof.queries[event.draw_index].index &&
                audit.query_candidate_consumes_seed;
            ++out.query_candidate_events;
        }

        const uint32_t kind =
            static_cast<uint32_t>(audit.program.kind);
        if (kind >= kind_seen.size()) {
            return Fail(why, "v13_native_schedule_kind");
        }
        kind_seen[kind] = true;
        for (const auto& cell : audit.program.message) {
            if (cell.binding ==
                TypedSafeMessageBindingV13::ProofOwned) {
                ++out.proof_owned_message_cells;
            }
        }
        out.program.push_back(std::move(audit.program));
        out.witness.push_back(std::move(audit.witness));
    }

    const std::array<TypedSafeChallengeKindV13, 8>
        required_fri_kinds{{
            TypedSafeChallengeKindV13::BatchCoefficient,
            TypedSafeChallengeKindV13::OodZ1,
            TypedSafeChallengeKindV13::OodZ2,
            TypedSafeChallengeKindV13::DeepWeight1,
            TypedSafeChallengeKindV13::DeepWeight2,
            TypedSafeChallengeKindV13::FoldBeta,
            TypedSafeChallengeKindV13::QueryCandidate,
            TypedSafeChallengeKindV13::QuerySeed,
        }};
    const bool all_fri_kinds = std::all_of(
        required_fri_kinds.begin(),
        required_fri_kinds.end(),
        [&](TypedSafeChallengeKindV13 kind) {
            return kind_seen[static_cast<uint32_t>(kind)];
        });
    out.events_materialized =
        static_cast<uint32_t>(out.program.size());
    out.native_proof_verified =
        out.replay.native_verified;
    out.exact_event_order =
        out.replay.exact_event_order;
    out.every_snapshot_exactly_materialized = exact;
    out.every_safe_output_matches_native_consumer =
        consumers;
    out.unique_query_seed_then_q192 =
        query_seed_seen &&
        query_seed_count == 1 &&
        out.query_candidate_events ==
            kRCFri3AlgNumQueries &&
        out.replay.query_seed_events == 1 &&
        out.replay.query_candidate_events ==
            kRCFri3AlgNumQueries &&
        z1_selected && z2_selected;
    out.outer_air_lambda_present =
        kind_seen[static_cast<uint32_t>(
            TypedSafeChallengeKindV13::AirLambda)];
    out.normalized_child_cells_bound = false;
    out.valid =
        out.native_proof_verified &&
        out.exact_event_order &&
        out.every_snapshot_exactly_materialized &&
        out.every_safe_output_matches_native_consumer &&
        out.unique_query_seed_then_q192 &&
        all_fri_kinds &&
        !out.outer_air_lambda_present &&
        out.events_materialized ==
            out.replay.events.size() &&
        out.program.size() == out.witness.size() &&
        out.proof_owned_message_cells > 0;
    out.note = out.valid
        ? "native-verified V13 FRI schedule materialized; outer "
          "airq_lambda and normalized same-trace aliases remain"
        : "native V13 FRI schedule materialization failed";
    if (!out.valid) {
        return Fail(why, "v13_native_schedule_incomplete");
    }
    return true;
}

alg_hash::Digest CommitTypedSafeEventProgramV13(
    const std::vector<TypedSafeEventProgramV13>& program)
{
    if (!ValidateTypedEventProgramV13(
            program, nullptr, nullptr)) {
        return {};
    }
    std::vector<gf::Fp> lanes{
        kTypedEventProgramMagicV13,
        gf::FromU64(kTypedSafeEventParentVersionV13),
        gf::FromU64(program.size()),
    };
    for (const auto& event : program) {
        lanes.push_back(gf::FromU64(
            static_cast<uint32_t>(event.kind)));
        lanes.push_back(gf::FromU64(
            static_cast<uint32_t>(event.role)));
        AppendU32PackedV13(lanes, event.application_domain);
        lanes.push_back(gf::FromU64(event.message.size()));
        for (const auto& cell : event.message) {
            lanes.push_back(gf::FromU64(
                static_cast<uint32_t>(cell.binding)));
            lanes.push_back(cell.constant);
            lanes.push_back(gf::FromU64(cell.query_seed_lane));
        }
    }
    alg_hash::Digest root{};
    if (!aht::SpongeHashFpV12(
            aht::RoleV12::ProgramTableCommitment,
            lanes, root, nullptr)) {
        return {};
    }
    return root;
}

bool BuildTypedSafeEventParentV13(
    const std::vector<TypedSafeEventProgramV13>& program,
    const std::vector<TypedSafeEventWitnessV13>& witness,
    const uint256& relation_seed,
    TypedSafeEventParentProductV13& out,
    std::string* why)
{
    out = {};
    if (program.size() != witness.size() ||
        !ValidateTypedEventProgramV13(
            program, nullptr, why)) {
        return Fail(why, "v13_event_witness_count");
    }
    out.program = program;
    out.program_root = CommitTypedSafeEventProgramV13(program);
    if (out.program_root == alg_hash::Digest{}) {
        return Fail(why, "v13_event_program_root");
    }

    std::vector<std::vector<gf::Fp>> resolved(program.size());
    out.event_output.resize(program.size());
    alg_hash::Digest query_seed{};
    std::vector<gf::Fp> semantic;
    std::vector<std::vector<uint32_t>> semantic_id(program.size());
    uint32_t next_id = 1;
    for (uint32_t event = 0; event < program.size(); ++event) {
        if (witness[event].message.size() !=
            program[event].message.size()) {
            return Fail(why, "v13_event_witness_shape");
        }
        resolved[event].resize(program[event].message.size());
        semantic_id[event].resize(program[event].message.size());
        for (uint32_t ordinal = 0;
             ordinal < program[event].message.size(); ++ordinal) {
            const auto& cell = program[event].message[ordinal];
            gf::Fp value = 0;
            if (cell.binding ==
                TypedSafeMessageBindingV13::ProofOwned) {
                value = witness[event].message[ordinal];
                if (!Canonical(value)) {
                    return Fail(why, "v13_noncanonical_proof_cell");
                }
                semantic.push_back(value);
                semantic_id[event][ordinal] = next_id++;
            } else if (cell.binding ==
                       TypedSafeMessageBindingV13::Constant) {
                if (witness[event].message[ordinal] != 0) {
                    return Fail(why, "v13_constant_witness_smuggling");
                }
                value = cell.constant;
            } else {
                if (witness[event].message[ordinal] != 0 ||
                    query_seed == alg_hash::Digest{}) {
                    return Fail(why, "v13_query_seed_witness_smuggling");
                }
                value = query_seed[cell.query_seed_lane];
            }
            resolved[event][ordinal] = value;
        }
        safe::SafeCoreResultV12 audit;
        if (!safe::SafeCoreDigestV12(
                program[event].role,
                program[event].application_domain,
                resolved[event], out.event_output[event],
                &audit, why)) {
            return false;
        }
        if (program[event].kind ==
            TypedSafeChallengeKindV13::QuerySeed) {
            query_seed = out.event_output[event];
        }
        for (gf::Fp value : out.event_output[event]) {
            semantic.push_back(value);
            ++next_id;
        }
    }
    const auto receipt_message =
        TypedEventReceiptMessageV13(
            out.program_root, semantic);
    const std::vector<uint8_t> receipt_domain(
        reinterpret_cast<const uint8_t*>(
            kTypedEventReceiptDomainV13),
        reinterpret_cast<const uint8_t*>(
            kTypedEventReceiptDomainV13) +
            sizeof(kTypedEventReceiptDomainV13) - 1);
    if (!safe::SafeCoreDigestV12(
            aht::RoleV12::ReceiptCommitment,
            receipt_domain, receipt_message,
            out.transcript_commitment, nullptr, why)) {
        return false;
    }

    const std::array<Fp3, 4> placeholder_challenges{
        U32(2), U32(3), U32(5), U32(7)};
    TypedEventPlanV13 plan;
    if (!BuildTypedEventCsV13(
            program, out.program_root,
            out.transcript_commitment,
            placeholder_challenges,
            plan, out.cs, &out.columns, why)) {
        return false;
    }
    const auto& layout = out.layout;
    std::vector<std::vector<gf::Fp>> all_messages = resolved;
    all_messages.push_back(receipt_message);
    std::vector<alg_hash::Digest> all_outputs = out.event_output;
    all_outputs.push_back(out.transcript_commitment);
    std::vector<std::array<gf::Fp, 4>> tags;
    for (uint32_t row = 0; row < plan.trace_rows;) {
        if (!plan.rows[row].active) break;
        const uint32_t event = plan.rows[row].event;
        const auto& message = all_messages[event];
        alg_hash::State state{};
        std::copy(
            plan.rows[row].tag.begin(),
            plan.rows[row].tag.end(),
            state.begin() + safe::kSafeRateV12);
        while (row < plan.trace_rows &&
               plan.rows[row].active &&
               plan.rows[row].event == event) {
            const auto& rp = plan.rows[row];
            for (uint32_t lane = 0; lane < 8; ++lane) {
                const uint32_t ordinal = 8 * rp.block + lane;
                const gf::Fp value =
                    ordinal < message.size() ? message[ordinal] : 0;
                out.columns[layout.Message(lane)][row] = U(value);
                if (!PopulateTypedEventBitsV13(
                        layout, out.columns, row, lane, value)) {
                    return Fail(why, "v13_message_bits");
                }
                state[lane] = gf::Add(state[lane], value);
            }
            const auto p2 =
                p2air::BuildWitness(layout.poseidon, state);
            if (p2.row.size() != layout.poseidon.End()) {
                return Fail(why, "v13_poseidon_witness_width");
            }
            for (uint32_t column = 0;
                 column < p2.row.size(); ++column) {
                out.columns[column][row] = p2.row[column];
            }
            state = p2.output;
            if (rp.final) {
                for (uint32_t lane = 0; lane < 4; ++lane) {
                    out.columns[layout.Output(lane)][row] =
                        U(all_outputs[event][lane]);
                }
            }
            ++row;
        }
    }
    for (uint32_t row = 0; row < plan.trace_rows; ++row) {
        for (uint32_t lane = 0; lane < 4; ++lane) {
            out.columns[layout.QuerySeed(lane)][row] =
                U(query_seed[lane]);
        }
    }

    // Commit every challenge-independent column before sampling LogUp
    // challenges. Accumulators and denominator inverses are the only Rdep
    // columns. This is the two-epoch RAP order required against an adaptive
    // prover; deriving these challenges from relation_seed alone would let
    // the prover choose transcript cells after seeing alpha/gamma.
    out.r0_base_column_indices =
        TypedEventR0BaseColumnsV13();
    out.r0_session =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            out.cs, out.columns,
            out.r0_base_column_indices);
    if (!out.r0_session.valid ||
        out.r0_session.base_row_commitment.IsNull()) {
        return Fail(
            why, "v13_event_r0_commit:" +
                out.r0_session.note);
    }
    out.r0_row_group_root =
        out.r0_session.base_row_commitment;
    out.receipt_ctl_challenges =
        TypedEventCtlChallengesV13(
            relation_seed, out.r0_row_group_root,
            out.program_root,
            out.transcript_commitment);
    if (std::any_of(
            out.receipt_ctl_challenges.begin(),
            out.receipt_ctl_challenges.end(),
            [](const Fp3& value) {
                return gf::IsZero(value);
            })) {
        return Fail(why, "v13_event_r0_challenge_zero");
    }
    TypedEventPlanV13 challenge_plan;
    aq::AirConstraintSystem<Fp3> challenge_cs;
    if (!BuildTypedEventCsV13(
            program, out.program_root,
            out.transcript_commitment,
            out.receipt_ctl_challenges,
            challenge_plan, challenge_cs,
            nullptr, why) ||
        challenge_plan.trace_rows != plan.trace_rows ||
        challenge_plan.semantic_count !=
            plan.semantic_count) {
        return Fail(why, "v13_event_r0_cs_rebuild");
    }
    out.cs = std::move(challenge_cs);
    out.cs.preprocessed_row_group_roots.push_back({
        .version = 1,
        .role =
            aq::AirPreprocessedRowGroupRole::kR0,
        .ordered_columns =
            out.r0_base_column_indices,
        .root = out.r0_row_group_root,
    });

    const auto& challenges =
        out.receipt_ctl_challenges;
    for (uint32_t ctl = 0; ctl < 2; ++ctl) {
        const uint32_t acc = layout.ctl_acc_base + ctl;
        const uint32_t inv = layout.ctl_inverse_base + ctl;
        out.columns[acc][0] = Fp3::One();
        for (uint32_t row = 0;
             row + 1 < plan.trace_rows; ++row) {
            const auto products =
                TypedEventWitnessProductsV13(
                    layout, out.columns, row,
                    challenges[2 * ctl],
                    challenges[2 * ctl + 1]);
            if (gf::IsZero(products.second)) {
                return Fail(why, "v13_ctl_denominator_zero");
            }
            out.columns[inv][row] =
                gf::Inv(products.second);
            out.columns[acc][row + 1] =
                gf::Mul(
                    out.columns[acc][row],
                    gf::Mul(products.first,
                            out.columns[inv][row]));
        }
        out.columns[inv][plan.trace_rows - 1] = Fp3::One();
    }

    for (uint32_t event = 0; event < program.size(); ++event) {
        for (uint32_t ordinal = 0;
             ordinal < program[event].message.size(); ++ordinal) {
            if (program[event].message[ordinal].binding !=
                TypedSafeMessageBindingV13::ProofOwned) {
                continue;
            }
            out.proof_owned_message_locations.push_back({
                event, ordinal,
                plan.first_row[event] + ordinal / 8,
                layout.Message(ordinal % 8)});
        }
        for (uint32_t lane = 0; lane < 4; ++lane) {
            out.output_locations.push_back({
                event, program[event].kind,
                plan.final_row[event],
                layout.Output(lane), lane});
        }
    }
    out.trace_rows = plan.trace_rows;
    out.active_permutation_rows = plan.active_rows;
    out.proof_owned_message_cells =
        static_cast<uint32_t>(
            out.proof_owned_message_locations.size());
    out.semantic_receipt_cells = plan.semantic_count;
    out.challenge_kinds_covered = plan.kinds_covered;
    out.verifier_owned_preprocessed_columns =
        static_cast<uint32_t>(out.cs.preprocessed.size());
    out.proof_owned_preprocessed_columns = 0;
    for (const auto& constraint : out.cs.constraints) {
        out.max_algebraic_degree =
            std::max(
                out.max_algebraic_degree,
                constraint.alg_degree);
    }
    out.violations =
        CountViolationsV12(out.cs, out.columns);
    out.unique_query_seed_event = true;
    out.every_query_uses_seed_output =
        plan.every_query_uses_seed;
    out.complete_challenge_kind_coverage =
        plan.kinds_covered ==
        kTypedSafeEventRequiredKindsV13;
    out.poseidon_relations_executable = true;
    out.dual_fp3_receipt_ctl_terminal =
        out.violations == 0;
    out.receipt_ctl_challenges_after_r0 =
        !out.r0_row_group_root.IsNull() &&
        out.r0_session.valid;
    out.proof_cells_are_ordinary_columns = true;
    out.parent_owns_real_fri_relation = false;
    out.normalized_child_cells_bound = false;
    out.recursive_authority_ready = false;
    out.valid =
        out.violations == 0 &&
        out.receipt_ctl_challenges_after_r0 &&
        out.complete_challenge_kind_coverage &&
        out.unique_query_seed_event &&
        out.every_query_uses_seed_output &&
        out.proof_owned_message_cells > 0 &&
        out.semantic_receipt_cells ==
            out.proof_owned_message_cells +
            4 * program.size() &&
        out.proof_owned_preprocessed_columns == 0;
    out.note = out.valid
        ? "typed SAFE event parent relation valid; normalized child-cell "
          "copy-in remains open"
        : "typed SAFE event parent relation invalid";
    if (!out.valid) return Fail(why, "v13_event_constraints");
    return true;
}

bool ProveTypedSafeEventParentV13(
    const TypedSafeEventParentProductV13& product,
    const uint256& relation_seed,
    TypedSafeEventParentProofV13& out,
    std::string* why)
{
    out = {};
    if (!product.valid ||
        product.normalized_child_cells_bound ||
        product.recursive_authority_ready ||
        !product.receipt_ctl_challenges_after_r0 ||
        !product.r0_session.valid ||
        product.r0_row_group_root.IsNull() ||
        product.violations != 0 ||
        CountViolationsV12(product.cs, product.columns) != 0) {
        return Fail(why, "v13_event_product_for_prove");
    }
    const auto proved =
        aq::AirQuotientProveRowsSplitRap(
            product.cs, product.columns,
            product.r0_base_column_indices,
            relation_seed, {}, &product.r0_session);
    if (!proved.ok || !proved.division_exact ||
        proved.proof.batch.groups.empty() ||
        Fri3AlgDigestToUint256(
            proved.proof.batch.groups[0]
                .row_commit.root) !=
            product.r0_row_group_root) {
        return Fail(why, "v13_event_air_prove:" + proved.note);
    }
    out.program_root = product.program_root;
    out.transcript_commitment =
        product.transcript_commitment;
    out.r0_row_group_root =
        product.r0_row_group_root;
    out.proof = proved.proof;
    out.trace_rows = product.trace_rows;
    out.event_count =
        static_cast<uint32_t>(product.program.size());
    out.canonical_proof_encoding =
        CanonicalSplitRapProofV13(out.proof);
    out.verified = false;
    out.receipt_ctl_challenges_after_r0 = true;
    out.normalized_child_cells_bound = false;
    out.recursive_authority_ready = false;
    out.note =
        "parent-owned FRI built; normalized child copy-in remains open";
    if (!out.canonical_proof_encoding) {
        out = {};
        return Fail(why, "v13_event_noncanonical_proof");
    }
    return true;
}

bool VerifyTypedSafeEventParentProofV13(
    const std::vector<TypedSafeEventProgramV13>& program,
    const TypedSafeEventParentProofV13& proof,
    const uint256& relation_seed,
    std::string* why)
{
    const auto program_root =
        CommitTypedSafeEventProgramV13(program);
    if (proof.version != kTypedSafeEventParentVersionV13 ||
        program_root == alg_hash::Digest{} ||
        proof.program_root != program_root ||
        !Canonical(proof.transcript_commitment) ||
        proof.transcript_commitment == alg_hash::Digest{} ||
        proof.r0_row_group_root.IsNull() ||
        proof.event_count != program.size() ||
        proof.normalized_child_cells_bound ||
        proof.recursive_authority_ready ||
        !proof.receipt_ctl_challenges_after_r0 ||
        !CanonicalSplitRapProofV13(proof.proof) ||
        proof.proof.batch.groups.empty() ||
        Fri3AlgDigestToUint256(
            proof.proof.batch.groups[0]
                .row_commit.root) !=
            proof.r0_row_group_root) {
        return Fail(why, "v13_event_proof_envelope");
    }
    const auto challenges =
        TypedEventCtlChallengesV13(
            relation_seed, proof.r0_row_group_root,
            program_root, proof.transcript_commitment);
    if (std::any_of(
            challenges.begin(), challenges.end(),
            [](const Fp3& value) {
                return gf::IsZero(value);
            })) {
        return Fail(why, "v13_event_verifier_challenge");
    }
    TypedEventPlanV13 plan;
    aq::AirConstraintSystem<Fp3> cs;
    if (!BuildTypedEventCsV13(
            program, program_root,
            proof.transcript_commitment, challenges,
            plan, cs, nullptr, why) ||
        proof.trace_rows != plan.trace_rows) {
        return Fail(why, "v13_event_verifier_rebuild");
    }
    const auto base_indices =
        TypedEventR0BaseColumnsV13();
    cs.preprocessed_row_group_roots.push_back({
        .version = 1,
        .role =
            aq::AirPreprocessedRowGroupRole::kR0,
        .ordered_columns = base_indices,
        .root = proof.r0_row_group_root,
    });
    return aq::AirQuotientVerifyRowsSplitRap(
        cs, proof.proof, base_indices,
        relation_seed, why);
}

} // namespace matmul::v4::rc::stage3_safe_v12_recursive_bridge
