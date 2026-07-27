// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_multirow_v11_parent_join.h>

#include <algorithm>
#include <functional>
#include <limits>
#include <map>
#include <set>

namespace matmul::v4::rc::stage3_multirow_v11_parent_join {
namespace {

using gf::Fp3;

Fp3 U(uint64_t value)
{
    return gf::FromU64_3(value);
}

bool Applies(aq::AirKind kind, uint32_t row, uint32_t rows)
{
    switch (kind) {
    case aq::AirKind::kEverywhere: return true;
    case aq::AirKind::kTransition: return row + 1 < rows;
    case aq::AirKind::kFirstRow: return row == 0;
    case aq::AirKind::kLastRow: return row + 1 == rows;
    }
    return false;
}

void AddConstraint(
    aq::AirConstraintSystem<Fp3>& cs,
    const char* name, aq::AirKind kind, uint32_t degree,
    std::function<Fp3(const std::vector<Fp3>&,
                      const std::vector<Fp3>&)> eval)
{
    aq::AirConstraint<Fp3> constraint;
    constraint.name = name;
    constraint.kind = kind;
    constraint.alg_degree = degree;
    constraint.eval = std::move(eval);
    cs.constraints.push_back(std::move(constraint));
}

void AddBoolean(aq::AirConstraintSystem<Fp3>& cs,
                const char* name, uint32_t column)
{
    AddConstraint(
        cs, name, aq::AirKind::kEverywhere, 2,
        [column](const auto& cur, const auto&) {
            return gf::Mul(
                cur[column],
                gf::Sub(cur[column], Fp3::One()));
        });
}

uint32_t AppendColumn(LayoutV1& layout)
{
    return layout.n_columns++;
}

CanonicalSplitLayoutV1 AppendCanonicalSplit(LayoutV1& layout)
{
    CanonicalSplitLayoutV1 out;
    out.active = AppendColumn(layout);
    out.address_lo = AppendColumn(layout);
    out.address_hi = AppendColumn(layout);
    out.parent_column_lo = AppendColumn(layout);
    out.parent_column_hi = AppendColumn(layout);
    out.claim_lo = AppendColumn(layout);
    out.claim_hi = AppendColumn(layout);
    out.expected_lo = AppendColumn(layout);
    out.expected_hi = AppendColumn(layout);
    out.bit_base = layout.n_columns;
    layout.n_columns += kRawBitsV1;
    out.high_and_base = layout.n_columns;
    layout.n_columns += kHighAndBitsV1;
    out.low_nonzero = AppendColumn(layout);
    out.low_inverse = AppendColumn(layout);
    return out;
}

Fp3 RecomposeBits(const CanonicalSplitLayoutV1& split,
                  const std::vector<Fp3>& row,
                  uint32_t first, uint32_t count)
{
    Fp3 sum = Fp3::Zero();
    Fp3 power = U(uint64_t{1} << first);
    for (uint32_t bit = first; bit < first + count; ++bit) {
        sum = gf::Add(sum, gf::Mul(power, row[split.Bit(bit)]));
        power = gf::Add(power, power);
    }
    return sum;
}

void AddCanonicalSplitConstraints(
    aq::AirConstraintSystem<Fp3>& cs,
    const CanonicalSplitLayoutV1& split,
    uint32_t replay_column,
    bool expected_is_public)
{
    AddBoolean(
        cs, "stage3.v11_parent_join.split_active",
        split.active);
    for (uint32_t bit = 0; bit < kRawBitsV1; ++bit) {
        AddBoolean(
            cs, "stage3.v11_parent_join.split_bit",
            split.Bit(bit));
    }
    AddConstraint(
        cs, "stage3.v11_parent_join.split_low_bits",
        aq::AirKind::kEverywhere, 2,
        [split](const auto& cur, const auto&) {
            return gf::Sub(
                cur[split.claim_lo],
                RecomposeBits(split, cur, 0, 32));
        });
    AddConstraint(
        cs, "stage3.v11_parent_join.split_high_bits",
        aq::AirKind::kEverywhere, 2,
        [split](const auto& cur, const auto&) {
            Fp3 sum = Fp3::Zero();
            Fp3 power = Fp3::One();
            for (uint32_t bit = 32; bit < 64; ++bit) {
                sum = gf::Add(
                    sum,
                    gf::Mul(power, cur[split.Bit(bit)]));
                power = gf::Add(power, power);
            }
            return gf::Sub(cur[split.claim_hi], sum);
        });
    AddConstraint(
        cs, "stage3.v11_parent_join.split_field_recompose",
        aq::AirKind::kEverywhere, 2,
        [split, replay_column](const auto& cur, const auto&) {
            const Fp3 raw = gf::Add(
                cur[split.claim_lo],
                gf::Mul(U(uint64_t{1} << 32),
                        cur[split.claim_hi]));
            return gf::Mul(
                cur[split.active],
                gf::Sub(raw, cur[replay_column]));
        });
    if (expected_is_public) {
        AddConstraint(
            cs, "stage3.v11_parent_join.split_public_lo",
            aq::AirKind::kEverywhere, 2,
            [split](const auto& cur, const auto&) {
                return gf::Mul(
                    cur[split.active],
                    gf::Sub(
                        cur[split.claim_lo],
                        cur[split.expected_lo]));
            });
        AddConstraint(
            cs, "stage3.v11_parent_join.split_public_hi",
            aq::AirKind::kEverywhere, 2,
            [split](const auto& cur, const auto&) {
                return gf::Mul(
                    cur[split.active],
                    gf::Sub(
                        cur[split.claim_hi],
                        cur[split.expected_hi]));
            });
    }
    AddConstraint(
        cs, "stage3.v11_parent_join.split_low_nonzero_inverse",
        aq::AirKind::kEverywhere, 2,
        [split](const auto& cur, const auto&) {
            return gf::Sub(
                gf::Mul(
                    cur[split.claim_lo],
                    cur[split.low_inverse]),
                cur[split.low_nonzero]);
        });
    AddConstraint(
        cs, "stage3.v11_parent_join.split_low_zero_case",
        aq::AirKind::kEverywhere, 2,
        [split](const auto& cur, const auto&) {
            return gf::Mul(
                cur[split.claim_lo],
                gf::Sub(
                    Fp3::One(),
                    cur[split.low_nonzero]));
        });
    AddBoolean(
        cs, "stage3.v11_parent_join.split_low_nonzero_boolean",
        split.low_nonzero);
    for (uint32_t bit = 0; bit < kHighAndBitsV1; ++bit) {
        AddConstraint(
            cs, "stage3.v11_parent_join.split_high_and",
            aq::AirKind::kEverywhere, 2,
            [split, bit](const auto& cur, const auto&) {
                const Fp3 expected = bit == 0
                    ? cur[split.Bit(32)]
                    : gf::Mul(
                        cur[split.HighAnd(bit - 1)],
                        cur[split.Bit(32 + bit)]);
                return gf::Sub(
                    cur[split.HighAnd(bit)], expected);
            });
    }
    AddConstraint(
        cs, "stage3.v11_parent_join.split_goldilocks_canonical",
        aq::AirKind::kEverywhere, 2,
        [split](const auto& cur, const auto&) {
            return gf::Mul(
                cur[split.HighAnd(kHighAndBitsV1 - 1)],
                cur[split.low_nonzero]);
        });
}

void SetCanonicalSplit(
    const CanonicalSplitLayoutV1& split,
    uint32_t row, uint32_t address_lo, uint32_t address_hi,
    uint32_t lo, uint32_t hi,
    std::vector<std::vector<Fp3>>& columns)
{
    columns[split.active][row] = Fp3::One();
    columns[split.address_lo][row] = U(address_lo);
    columns[split.address_hi][row] = U(address_hi);
    columns[split.claim_lo][row] = U(lo);
    columns[split.claim_hi][row] = U(hi);
    columns[split.expected_lo][row] = U(lo);
    columns[split.expected_hi][row] = U(hi);
    const uint64_t raw =
        uint64_t{lo} | (uint64_t{hi} << 32);
    for (uint32_t bit = 0; bit < 64; ++bit) {
        columns[split.Bit(bit)][row] =
            ((raw >> bit) & 1U) != 0
            ? Fp3::One() : Fp3::Zero();
    }
    bool high_and = true;
    for (uint32_t bit = 0; bit < 32; ++bit) {
        high_and =
            high_and && ((raw >> (32 + bit)) & 1U) != 0;
        columns[split.HighAnd(bit)][row] =
            high_and ? Fp3::One() : Fp3::Zero();
    }
    const bool low_nonzero = lo != 0;
    columns[split.low_nonzero][row] =
        low_nonzero ? Fp3::One() : Fp3::Zero();
    columns[split.low_inverse][row] =
        low_nonzero ? gf::Inv(U(lo)) : Fp3::Zero();
}

std::vector<uint32_t> TerminalRows(const tp::ProductV1& replay)
{
    std::vector<uint32_t> rows;
    for (uint32_t row = 0;
         row < replay.real_sponge_rows; ++row) {
        if (gf::Eq(
                replay.columns[replay.layout.terminal][row],
                Fp3::One())) {
            rows.push_back(row);
        }
    }
    return rows;
}

std::vector<uint32_t> QueryRows(const tp::ProductV1& replay)
{
    std::vector<uint32_t> rows;
    for (uint32_t row = 0; row < replay.trace_rows; ++row) {
        if (gf::Eq(
                replay.columns[
                    replay.layout.query_candidate_active][row],
                Fp3::One())) {
            rows.push_back(row);
        }
    }
    return rows;
}

const abi::SourceCellV1* FindSource(
    const std::vector<abi::SourceCellV1>& sources,
    const abi::SourceKeyV1& key)
{
    const auto it = std::find_if(
        sources.begin(), sources.end(),
        [&key](const auto& source) {
            return source.key == key;
        });
    return it == sources.end() ? nullptr : &*it;
}

const abi::ParentPublicCellV1* FindParent(
    const std::vector<abi::ParentPublicCellV1>& parent,
    const abi::SourceKeyV1& key)
{
    const auto it = std::find_if(
        parent.begin(), parent.end(),
        [&key](const auto& cell) {
            return cell.key == key;
        });
    return it == parent.end() ? nullptr : &*it;
}

abi::SourceKeyV1 Key(
    abi::FieldKindV1 kind, uint32_t a = 0,
    uint32_t d = 0, uint8_t limb = 0)
{
    return {kind, a, 0, 0, d, limb};
}

struct PublicAbsorbBinding {
    abi::SourceKeyV1 key{};
    uint32_t item_offset{0};
};

std::vector<PublicAbsorbBinding> PublicAbsorbBindings(
    const tp::StatementV1& statement)
{
    // Offsets include the two u32 domain lanes prepended to each sponge
    // event.  This binds every non-field public source at its exact AIRL
    // event coordinate.
    std::vector<PublicAbsorbBinding> out;
    for (uint32_t i = 0; i < 8; ++i) {
        out.push_back({
            Key(abi::FieldKindV1::PublicFsSeed, i),
            5 + i});
    }
    out.push_back({
        Key(abi::FieldKindV1::TraceRows), 13});
    out.push_back({
        Key(abi::FieldKindV1::TraceColumns), 14});
    out.push_back({
        Key(abi::FieldKindV1::QuotientLen), 15});
    out.push_back({
        Key(abi::FieldKindV1::BaseColumnCount), 17});
    for (uint32_t i = 0;
         i < statement.base_column_indices.size(); ++i) {
        out.push_back({
            Key(abi::FieldKindV1::BaseColumnIndex, i),
            18 + i});
    }
    return out;
}

bool PreprocessedRootMatches(
    const ProductV1& product,
    const std::vector<std::vector<Fp3>>& columns)
{
    const auto session =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            product.cs, columns,
            product.preprocessed_columns);
    return session.valid &&
        session.base_row_commitment ==
            product.preprocessed_row_group_root;
}

uint32_t Log2Exact(uint32_t value)
{
    if (value < 2 || (value & (value - 1)) != 0) return 0;
    uint32_t out = 0;
    while (value > 1) {
        value >>= 1;
        ++out;
    }
    return out;
}

} // namespace

LayoutV1 CanonicalLayoutV1()
{
    LayoutV1 out;
    out.replay = tp::CanonicalLayoutV1();
    out.n_columns = out.replay.n_columns;
    for (auto& slot : out.public_absorb) {
        slot.active = AppendColumn(out);
        slot.source_address = AppendColumn(out);
        slot.parent_column = AppendColumn(out);
        slot.claim = AppendColumn(out);
        slot.expected = AppendColumn(out);
    }
    for (auto& split : out.public_field) {
        split = AppendCanonicalSplit(out);
    }
    for (auto& split : out.candidate_digest) {
        split = AppendCanonicalSplit(out);
    }
    out.selected_ordinal_address = AppendColumn(out);
    out.selected_ordinal_claim = AppendColumn(out);
    out.query_index_address = AppendColumn(out);
    out.query_index_claim = AppendColumn(out);
    out.coefficient_active = AppendColumn(out);
    out.coefficient_label = AppendColumn(out);
    return out;
}

uint64_t RecountViolationsV1(
    const ProductV1& product,
    const std::vector<std::vector<Fp3>>& columns)
{
    if (columns.size() != product.cs.n_columns) {
        return std::numeric_limits<uint64_t>::max();
    }
    uint64_t violations = 0;
    std::vector<Fp3> cur(product.cs.n_columns);
    std::vector<Fp3> next(product.cs.n_columns);
    for (uint32_t row = 0; row < product.cs.n_rows; ++row) {
        for (uint32_t column = 0;
             column < product.cs.n_columns; ++column) {
            if (columns[column].size() != product.cs.n_rows) {
                return std::numeric_limits<uint64_t>::max();
            }
            cur[column] = columns[column][row];
            next[column] =
                columns[column][(row + 1) % product.cs.n_rows];
        }
        for (const auto& constraint : product.cs.constraints) {
            if (Applies(constraint.kind, row, product.cs.n_rows) &&
                !gf::IsZero(constraint.eval(cur, next))) {
                ++violations;
            }
        }
    }
    if (!PreprocessedRootMatches(product, columns)) ++violations;
    return violations;
}

ProductV1 BuildProductV1(
    const abi::DecodedV1& decoded,
    const std::vector<abi::ParentPublicCellV1>& parent_public,
    const tp::ProductV1& replay,
    const cb::ProductV1& consumer)
{
    ProductV1 out;
    out.layout = CanonicalLayoutV1();
    const auto public_plan =
        abi::BuildPublicStatementJoinV1(decoded, parent_public);
    std::string receipt_why;
    if (!decoded.canonical || !decoded.complete ||
        !public_plan.valid ||
        !replay.valid || !consumer.valid ||
        !tp::VerifyReceiptV1(
            replay.statement, replay.receipt, &receipt_why) ||
        !tp::VerifyReceiptV1(
            replay.statement,
            consumer.transcript_receipt, nullptr) ||
        replay.trace_rows < 2 ||
        replay.layout.n_columns != out.layout.replay.n_columns) {
        out.note =
            "stage3:v11_parent_join:invalid_inputs:" +
            public_plan.note + ":" + receipt_why;
        return out;
    }

    const auto terminals = TerminalRows(replay);
    const auto query_rows = QueryRows(replay);
    const uint32_t columns_count =
        static_cast<uint32_t>(replay.statement.column_len.size());
    const uint32_t coefficient_event_first = 9;
    if (terminals.size() != replay.hash_events ||
        query_rows.size() !=
            tp::kQueriesV1 * tp::kQueryCandidatesV1 ||
        coefficient_event_first + columns_count > terminals.size()) {
        out.note = "stage3:v11_parent_join:event_inventory:"
            "terminals=" + std::to_string(terminals.size()) +
            ":hash_events=" + std::to_string(replay.hash_events) +
            ":query_rows=" + std::to_string(query_rows.size()) +
            ":columns=" + std::to_string(columns_count);
        return out;
    }

    std::array<abi::QueryCandidatesV1, abi::kQueryCountV11>
        candidates{};
    for (uint32_t q = 0; q < tp::kQueriesV1; ++q) {
        for (uint32_t c = 0;
             c < tp::kQueryCandidatesV1; ++c) {
            candidates[q].digest[c] =
                replay.receipt.queries[q].candidate_digest[c];
        }
        candidates[q].selected_ordinal =
            replay.receipt.queries[q].selected_ordinal;
    }
    const auto derived =
        abi::BuildDerivedQueryCandidateExportsV1(
            decoded, candidates);
    if (!derived.valid) {
        out.note =
            "stage3:v11_parent_join:derived:" +
            derived.note;
        return out;
    }

    out.cs = replay.cs;
    out.cs.n_columns = out.layout.n_columns;
    out.columns = replay.columns;
    out.columns.resize(
        out.layout.n_columns,
        std::vector<Fp3>(
            replay.trace_rows, Fp3::Zero()));
    out.cs.preprocessed_row_group_roots.clear();
    out.preprocessed_columns = replay.preprocessed_columns;
    out.replay_hash_events = replay.hash_events;
    out.replay_real_sponge_rows = replay.real_sponge_rows;
    out.replay_terminal_events =
        static_cast<uint32_t>(terminals.size());
    uint32_t all_terminal_rows = 0;
    for (uint32_t row = 0; row < replay.trace_rows; ++row) {
        if (gf::Eq(
                replay.columns[replay.layout.terminal][row],
                Fp3::One())) {
            ++all_terminal_rows;
        }
    }
    out.padding_terminal_rows =
        all_terminal_rows - out.replay_terminal_events;

    auto add_preprocessed = [&out](uint32_t column) {
        out.preprocessed_columns.push_back(column);
    };
    auto set = [&out](uint32_t column, uint32_t row,
                      const Fp3& value) {
        out.columns[column][row] = value;
    };

    for (uint32_t lane = 0;
         lane < kPublicAbsorbSlotsV1; ++lane) {
        const auto slot = out.layout.public_absorb[lane];
        AddBoolean(
            out.cs, "stage3.v11_parent_join.public_absorb_active",
            slot.active);
        AddConstraint(
            out.cs, "stage3.v11_parent_join.public_parent_equality",
            aq::AirKind::kEverywhere, 2,
            [slot](const auto& cur, const auto&) {
                return gf::Mul(
                    cur[slot.active],
                    gf::Sub(cur[slot.claim], cur[slot.expected]));
            });
        AddConstraint(
            out.cs, "stage3.v11_parent_join.public_replay_alias",
            aq::AirKind::kEverywhere, 2,
            [slot, replay_column =
                       out.layout.replay.Absorb(lane)](
                const auto& cur, const auto&) {
                return gf::Mul(
                    cur[slot.active],
                    gf::Sub(
                        cur[slot.claim],
                        cur[replay_column]));
            });
        for (uint32_t column :
             {slot.active, slot.source_address,
              slot.parent_column, slot.expected}) {
            add_preprocessed(column);
        }
    }
    for (uint32_t limb = 0;
         limb < kPublicFieldSlotsV1; ++limb) {
        AddCanonicalSplitConstraints(
            out.cs, out.layout.public_field[limb],
            out.layout.replay.DigestClaim(limb), true);
        for (uint32_t column :
             {out.layout.public_field[limb].active,
              out.layout.public_field[limb].address_lo,
              out.layout.public_field[limb].address_hi,
              out.layout.public_field[limb].parent_column_lo,
              out.layout.public_field[limb].parent_column_hi,
              out.layout.public_field[limb].expected_lo,
              out.layout.public_field[limb].expected_hi}) {
            add_preprocessed(column);
        }
    }

    const uint32_t air_event_start = terminals[0] + 1;
    for (const auto& binding :
         PublicAbsorbBindings(replay.statement)) {
        const auto* source =
            FindSource(decoded.sources, binding.key);
        const auto* parent =
            FindParent(parent_public, binding.key);
        if (source == nullptr || parent == nullptr ||
            source->value != parent->value) {
            out.note =
                "stage3:v11_parent_join:public_absorb_inventory";
            return out;
        }
        const uint32_t row =
            air_event_start + binding.item_offset /
                alg_hash::kAlgHashRate;
        const uint32_t lane =
            binding.item_offset % alg_hash::kAlgHashRate;
        const auto slot = out.layout.public_absorb[lane];
        if (!gf::IsZero(out.columns[slot.active][row])) {
            out.note =
                "stage3:v11_parent_join:public_absorb_collision";
            return out;
        }
        set(slot.active, row, Fp3::One());
        set(slot.source_address, row, U(source->address));
        set(slot.parent_column, row, U(parent->parent_column));
        set(slot.claim, row, U(source->value));
        set(slot.expected, row, U(parent->value));
        ++out.public_source_cells;
        ++out.public_source_records;
    }
    const uint32_t air_terminal = terminals[1];
    for (uint32_t coord = 0;
         coord < kPublicFieldSlotsV1; ++coord) {
        const auto lo_key =
            Key(abi::FieldKindV1::AirConstraintLambda,
                0, coord, 0);
        const auto hi_key =
            Key(abi::FieldKindV1::AirConstraintLambda,
                0, coord, 1);
        const auto* lo = FindSource(decoded.sources, lo_key);
        const auto* hi = FindSource(decoded.sources, hi_key);
        const auto* parent_lo = FindParent(parent_public, lo_key);
        const auto* parent_hi = FindParent(parent_public, hi_key);
        if (lo == nullptr || hi == nullptr ||
            parent_lo == nullptr || parent_hi == nullptr ||
            lo->value != parent_lo->value ||
            hi->value != parent_hi->value) {
            out.note =
                "stage3:v11_parent_join:public_lambda_inventory";
            return out;
        }
        SetCanonicalSplit(
            out.layout.public_field[coord], air_terminal,
            lo->address, hi->address,
            lo->value, hi->value, out.columns);
        set(out.layout.public_field[coord].expected_lo,
            air_terminal, U(parent_lo->value));
        set(out.layout.public_field[coord].expected_hi,
            air_terminal, U(parent_hi->value));
        set(out.layout.public_field[coord].parent_column_lo,
            air_terminal, U(parent_lo->parent_column));
        set(out.layout.public_field[coord].parent_column_hi,
            air_terminal, U(parent_hi->parent_column));
        out.public_source_cells += 2;
        ++out.public_source_records;
    }
    if (out.public_source_cells !=
        decoded.public_statement_cells) {
        out.note =
            "stage3:v11_parent_join:public_inventory_not_exact";
        return out;
    }

    for (uint32_t limb = 0;
         limb < kCandidateDigestLimbsV1; ++limb) {
        AddCanonicalSplitConstraints(
            out.cs, out.layout.candidate_digest[limb],
            out.layout.replay.DigestClaim(limb), false);
        for (uint32_t column :
             {out.layout.candidate_digest[limb].active,
              out.layout.candidate_digest[limb].address_lo,
              out.layout.candidate_digest[limb].address_hi}) {
            add_preprocessed(column);
        }
    }
    AddConstraint(
        out.cs, "stage3.v11_parent_join.selected_ordinal",
        aq::AirKind::kTransition, 2,
        [layout = out.layout](const auto& cur, const auto& next) {
            return gf::Mul(
                cur[layout.replay.query_candidate_first],
                gf::Sub(
                    cur[layout.selected_ordinal_claim],
                    next[layout.replay.candidate_selected]));
        });
    AddConstraint(
        out.cs, "stage3.v11_parent_join.query_index_selected",
        aq::AirKind::kEverywhere, 2,
        [layout = out.layout,
         domain_log = Log2Exact(
             replay.statement.n_coeffs *
             replay.statement.blowup)](
            const auto& cur, const auto&) {
            Fp3 index = Fp3::Zero();
            Fp3 power = Fp3::One();
            for (uint32_t bit = 0; bit < domain_log; ++bit) {
                index = gf::Add(
                    index,
                    gf::Mul(
                        power,
                        cur[layout.candidate_digest[0].Bit(bit)]));
                power = gf::Add(power, power);
            }
            return gf::Mul(
                cur[layout.replay.candidate_selected],
                gf::Sub(
                    index,
                    cur[layout.query_index_claim]));
        });
    AddConstraint(
        out.cs, "stage3.v11_parent_join.query_index_pair",
        aq::AirKind::kTransition, 2,
        [layout = out.layout](const auto& cur, const auto& next) {
            return gf::Mul(
                cur[layout.replay.query_candidate_first],
                gf::Sub(
                    next[layout.query_index_claim],
                    cur[layout.query_index_claim]));
        });
    for (uint32_t column :
         {out.layout.selected_ordinal_address,
          out.layout.query_index_address}) {
        add_preprocessed(column);
    }

    for (uint32_t q = 0; q < tp::kQueriesV1; ++q) {
        const auto query_key =
            Key(abi::FieldKindV1::QueryIndex, q);
        const auto* query_index =
            FindSource(decoded.sources, query_key);
        if (query_index == nullptr ||
            query_index->value !=
                replay.receipt.queries[q].index) {
            out.note =
                "stage3:v11_parent_join:query_index_inventory";
            return out;
        }
        for (uint32_t candidate = 0;
             candidate < tp::kQueryCandidatesV1; ++candidate) {
            const uint32_t row =
                query_rows[2 * q + candidate];
            for (uint32_t limb = 0;
                 limb < kCandidateDigestLimbsV1; ++limb) {
                const auto lo_key = abi::SourceKeyV1{
                    abi::FieldKindV1::QueryCandidateDigest,
                    q, candidate, 0, limb, 0};
                const auto hi_key = abi::SourceKeyV1{
                    abi::FieldKindV1::QueryCandidateDigest,
                    q, candidate, 0, limb, 1};
                const auto* lo =
                    FindSource(derived.sources, lo_key);
                const auto* hi =
                    FindSource(derived.sources, hi_key);
                if (lo == nullptr || hi == nullptr) {
                    out.note =
                        "stage3:v11_parent_join:candidate_inventory";
                    return out;
                }
                SetCanonicalSplit(
                    out.layout.candidate_digest[limb], row,
                    lo->address, hi->address,
                    lo->value, hi->value, out.columns);
                out.derived_candidate_cells += 2;
            }
            set(out.layout.query_index_claim, row,
                U(query_index->value));
            if (candidate == 0) {
                const auto selected_key = abi::SourceKeyV1{
                    abi::FieldKindV1::QuerySelectedCandidate,
                    q, 0, 0, 0, 0};
                const auto* selected =
                    FindSource(derived.sources, selected_key);
                if (selected == nullptr) {
                    out.note =
                        "stage3:v11_parent_join:selected_inventory";
                    return out;
                }
                set(out.layout.selected_ordinal_address, row,
                    U(selected->address));
                set(out.layout.selected_ordinal_claim, row,
                    U(selected->value));
                set(out.layout.query_index_address, row,
                    U(query_index->address));
                ++out.derived_candidate_cells;
                ++out.query_index_cells;
            }
        }
    }

    AddBoolean(
        out.cs, "stage3.v11_parent_join.coefficient_active",
        out.layout.coefficient_active);
    for (uint32_t coefficient = 0;
         coefficient < columns_count; ++coefficient) {
        const uint32_t row =
            terminals[coefficient_event_first + coefficient];
        set(out.layout.coefficient_active, row, Fp3::One());
        set(out.layout.coefficient_label, row, U(coefficient));
        out.coefficient_replay_rows.push_back(row);
    }
    add_preprocessed(out.layout.coefficient_active);
    add_preprocessed(out.layout.coefficient_label);
    out.coefficient_consumer_columns = {
        out.layout.replay.DigestClaim(0),
        out.layout.replay.DigestClaim(1),
        out.layout.replay.DigestClaim(2)};

    std::sort(
        out.preprocessed_columns.begin(),
        out.preprocessed_columns.end());
    out.preprocessed_columns.erase(
        std::unique(
            out.preprocessed_columns.begin(),
            out.preprocessed_columns.end()),
        out.preprocessed_columns.end());
    out.cs.preprocessed.clear();
    for (uint32_t column : out.preprocessed_columns) {
        out.cs.preprocessed.emplace_back(
            column, out.columns[column]);
    }
    out.cs.preprocessed_pin_ood = true;
    const auto session =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            out.cs, out.columns, out.preprocessed_columns);
    if (!session.valid ||
        session.base_row_commitment.IsNull()) {
        out.note =
            "stage3:v11_parent_join:preprocessed_root:" +
            session.note;
        return out;
    }
    out.preprocessed_row_group_root =
        session.base_row_commitment;
    out.cs.preprocessed_row_group_roots.push_back({
        .version = 1,
        .role = aq::AirPreprocessedRowGroupRole::kR0,
        .ordered_columns = out.preprocessed_columns,
        .root = out.preprocessed_row_group_root,
    });
    out.constraints =
        static_cast<uint32_t>(out.cs.constraints.size());
    for (const auto& constraint : out.cs.constraints) {
        out.max_constraint_degree =
            std::max(
                out.max_constraint_degree,
                constraint.alg_degree);
    }
    out.violations =
        RecountViolationsV1(out, out.columns);
    out.public_inventory_exact =
        out.public_source_cells ==
            decoded.public_statement_cells;
    out.public_parent_columns_root_pinned = true;
    out.public_claims_equal_parent_air_constrained = true;
    out.public_claims_equal_replay_air_constrained = true;
    out.derived_candidates_equal_replay_air_constrained = true;
    out.selected_ordinals_equal_replay_air_constrained = true;
    out.selected_query_indices_equal_proof_air_constrained = true;
    out.independent_coefficients_direct_replay_alias = true;
    out.canonical_u64_decomposition_air_constrained = true;
    out.exact_ordered_preprocessed_root =
        PreprocessedRootMatches(out, out.columns);
    out.canonical_abi_claim_cells_air_joined = true;
    out.backend_v11_proof_cells_consumed = false;
    out.recursive_authority_ready = false;
    out.valid =
        out.violations == 0 &&
        out.public_inventory_exact &&
        out.public_parent_columns_root_pinned &&
        out.public_claims_equal_parent_air_constrained &&
        out.public_claims_equal_replay_air_constrained &&
        out.derived_candidates_equal_replay_air_constrained &&
        out.selected_ordinals_equal_replay_air_constrained &&
        out.selected_query_indices_equal_proof_air_constrained &&
        out.independent_coefficients_direct_replay_alias &&
        out.canonical_u64_decomposition_air_constrained &&
        out.exact_ordered_preprocessed_root &&
        out.canonical_abi_claim_cells_air_joined &&
        !out.backend_v11_proof_cells_consumed &&
        !out.recursive_authority_ready;
    out.note = out.valid
        ? "stage3:v11_parent_join:public_and_transcript_cells_air_joined;"
          "backend_child_acceptance_pending"
        : "stage3:v11_parent_join:constraint_failure";
    return out;
}

} // namespace matmul::v4::rc::stage3_multirow_v11_parent_join
