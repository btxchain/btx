// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_safe_v12_recursive_bridge.h>

#include <algorithm>
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

} // namespace matmul::v4::rc::stage3_safe_v12_recursive_bridge
