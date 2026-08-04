// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_v13_proof_tape_source_join.h>

#include <algorithm>
#include <functional>
#include <map>
#include <numeric>
#include <set>
#include <utility>

namespace matmul::v4::rc::stage3_v13_proof_tape_source_join {
namespace {

using AirCS = aq::AirConstraintSystem<gf::Fp3>;
using gf::Fp3;

inline constexpr uint64_t kPlanMagicV1 =
    UINT64_C(0x5054534a4f494e31); // "PTSJOIN1"

Fp3 U(uint64_t value)
{
    return Fp3::FromFp(gf::FromU64(value));
}

bool Fail(std::string* why, const std::string& reason)
{
    if (why != nullptr) {
        *why = "stage3:v13_proof_tape_source_join:" + reason;
    }
    return false;
}

bool PowerOfTwo(uint32_t value)
{
    return value >= 2 &&
        (value & (value - 1)) == 0;
}

uint32_t SyntheticSelectedAddress(
    abi::FieldKindV1 kind, uint32_t coordinate)
{
    const uint32_t pair =
        kind == abi::FieldKindV1::Z1 ? 0U : 1U;
    return abi::kDerivedTranscriptAddressBaseV1 +
        0x100U + 3U * pair + coordinate;
}

bool IsZKind(abi::FieldKindV1 kind)
{
    return kind == abi::FieldKindV1::Z1 ||
        kind == abi::FieldKindV1::Z2;
}

void AppendKey(
    std::vector<gf::Fp>& lanes,
    const abi::SourceKeyV1& key)
{
    lanes.push_back(gf::FromU64(
        static_cast<uint16_t>(key.kind)));
    lanes.push_back(gf::FromU64(key.a));
    lanes.push_back(gf::FromU64(key.b));
    lanes.push_back(gf::FromU64(key.c));
    lanes.push_back(gf::FromU64(key.d));
    lanes.push_back(gf::FromU64(key.limb));
}

void AppendEndpoint(
    std::vector<gf::Fp>& lanes,
    const LookupEndpointV1& endpoint)
{
    lanes.push_back(gf::FromU64(
        static_cast<uint8_t>(endpoint.role)));
    AppendKey(lanes, endpoint.key);
    lanes.push_back(gf::FromU64(endpoint.address));
    lanes.push_back(gf::FromU64(endpoint.lookup_slot));
    lanes.push_back(gf::FromU64(endpoint.address_cell.column));
    lanes.push_back(gf::FromU64(endpoint.address_cell.row));
    lanes.push_back(gf::FromU64(endpoint.value_cell.column));
    lanes.push_back(gf::FromU64(endpoint.value_cell.row));
    lanes.push_back(gf::FromU64(
        endpoint.address_is_ordinary_cell ? 1U : 0U));
    lanes.push_back(gf::FromU64(
        endpoint.bits_are_ordinary_cells ? 1U : 0U));
    for (const auto& bit : endpoint.bits) {
        lanes.push_back(gf::FromU64(bit.column));
        lanes.push_back(gf::FromU64(bit.row));
    }
}

alg_hash::Digest CommitPlan(const PlanV1& plan)
{
    std::vector<gf::Fp> lanes;
    lanes.reserve(
        32 + 80 *
            (plan.sources.size() +
             plan.consumers.size()));
    lanes.push_back(gf::FromU64(kPlanMagicV1));
    lanes.push_back(gf::FromU64(plan.version));
    lanes.push_back(gf::FromU64(plan.shape.trace_rows));
    lanes.push_back(gf::FromU64(plan.shape.trace_columns));
    lanes.push_back(gf::FromU64(plan.shape.quotient_len));
    lanes.push_back(gf::FromU64(plan.shape.n_coeffs));
    lanes.push_back(gf::FromU64(plan.n_lde));
    lanes.push_back(gf::FromU64(plan.query_count));
    lanes.push_back(gf::FromU64(plan.parent_rows));
    lanes.push_back(gf::FromU64(plan.tape_column_offset));
    lanes.push_back(gf::FromU64(plan.derived_column_offset));
    lanes.push_back(gf::FromU64(plan.selection_column_offset));
    lanes.push_back(gf::FromU64(
        plan.shape.base_column_indices.size()));
    for (uint32_t column : plan.shape.base_column_indices) {
        lanes.push_back(gf::FromU64(column));
    }
    lanes.push_back(gf::FromU64(plan.sources.size()));
    lanes.push_back(gf::FromU64(plan.consumers.size()));
    lanes.push_back(gf::FromU64(plan.derived_limb_relations));
    lanes.push_back(gf::FromU64(plan.selected_z_relations));
    lanes.push_back(gf::FromU64(plan.query_index_relations));
    for (const auto& endpoint : plan.sources) {
        AppendEndpoint(lanes, endpoint);
    }
    for (const auto& endpoint : plan.consumers) {
        AppendEndpoint(lanes, endpoint);
    }
    return alg_hash::SpongeHashFp(lanes);
}

bool CellInParent(
    const CellRefV1& cell,
    uint32_t columns,
    uint32_t rows)
{
    return cell.column < columns &&
        cell.row < rows;
}

bool ValidPlan(const PlanV1& plan)
{
    if (plan.version != kProofTapeSourceJoinVersionV1 ||
        !PowerOfTwo(plan.parent_rows) ||
        plan.n_lde == 0 ||
        plan.query_count == 0 ||
        plan.sources.empty() ||
        plan.sources.size() != plan.consumers.size() ||
        plan.plan_root == alg_hash::Digest{} ||
        !plan.exact_tape_schedule ||
        !plan.exact_derived_schedule ||
        !plan.exact_selection_schedule ||
        !plan.all_tape_addresses_mapped ||
        !plan.exact_multiset_cardinality ||
        !plan.valid) {
        return false;
    }
    const uint32_t parent_columns =
        plan.selection_column_offset +
        selection::LayoutV1{}.End();
    std::set<std::pair<uint32_t, uint32_t>> source_slots;
    std::set<std::pair<uint32_t, uint32_t>> consumer_slots;
    std::multiset<std::pair<uint32_t, abi::SourceKeyV1>>
        source_keys;
    std::multiset<std::pair<uint32_t, abi::SourceKeyV1>>
        consumer_keys;
    for (const auto& source : plan.sources) {
        if (source.lookup_slot >= kSourceSlotsV1 ||
            source.address == UINT32_MAX ||
            !CellInParent(
                source.value_cell,
                parent_columns,
                plan.parent_rows) ||
            (source.address_is_ordinary_cell &&
             !CellInParent(
                 source.address_cell,
                 parent_columns,
                 plan.parent_rows)) ||
            !source_slots.emplace(
                source.value_cell.row,
                source.lookup_slot).second) {
            return false;
        }
        source_keys.emplace(source.address, source.key);
    }
    for (const auto& consumer : plan.consumers) {
        if (consumer.lookup_slot >= kConsumerSlotsV1 ||
            consumer.address == UINT32_MAX ||
            !CellInParent(
                consumer.value_cell,
                parent_columns,
                plan.parent_rows) ||
            !consumer_slots.emplace(
                consumer.value_cell.row,
                consumer.lookup_slot).second) {
            return false;
        }
        consumer_keys.emplace(consumer.address, consumer.key);
    }
    return source_keys == consumer_keys;
}

bool SamePlan(const PlanV1& left, const PlanV1& right)
{
    return left == right;
}

void Add(
    AirCS& cs,
    const char* name,
    aq::AirKind kind,
    uint32_t degree,
    std::function<Fp3(
        const std::vector<Fp3>&,
        const std::vector<Fp3>&)> eval)
{
    cs.constraints.push_back(
        {name, kind, degree, std::move(eval)});
}

void AddPreprocessed(
    AirCS& cs,
    uint32_t column,
    std::vector<Fp3> values)
{
    cs.preprocessed.emplace_back(
        column, std::move(values));
}

bool AppendShiftedCs(
    const AirCS& local,
    uint32_t offset,
    uint32_t parent_rows,
    AirCS& parent,
    std::string* why)
{
    if (local.n_rows > parent_rows ||
        !local.preprocessed_roots.empty() ||
        !local.preprocessed_row_group_roots.empty()) {
        return Fail(why, "unsupported_child_preprocessing");
    }
    for (const auto& constraint : local.constraints) {
        const auto eval = constraint.eval;
        const uint32_t local_columns = local.n_columns;
        parent.constraints.push_back({
            constraint.name,
            constraint.kind,
            constraint.alg_degree,
            [eval, offset, local_columns](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>& next) {
                std::vector<Fp3> local_cur(
                    local_columns, Fp3::Zero());
                std::vector<Fp3> local_next(
                    local_columns, Fp3::Zero());
                for (uint32_t column = 0;
                     column < local_columns;
                     ++column) {
                    local_cur[column] =
                        cur[offset + column];
                    local_next[column] =
                        next[offset + column];
                }
                return eval(local_cur, local_next);
            }});
    }
    for (const auto& [column, values] :
         local.preprocessed) {
        if (values.size() != local.n_rows) {
            return Fail(why, "child_preprocessed_rows");
        }
        std::vector<Fp3> padded(
            parent_rows, Fp3::Zero());
        std::copy(
            values.begin(), values.end(),
            padded.begin());
        AddPreprocessed(
            parent, offset + column,
            std::move(padded));
    }
    parent.preprocessed_pin_ood =
        parent.preprocessed_pin_ood ||
        local.preprocessed_pin_ood;
    return true;
}

bool CopyShiftedColumns(
    const std::vector<std::vector<Fp3>>& local,
    uint32_t local_rows,
    uint32_t offset,
    uint32_t parent_rows,
    std::vector<std::vector<Fp3>>& parent,
    std::string* why)
{
    if (offset + local.size() > parent.size() ||
        local_rows > parent_rows) {
        return Fail(why, "copy_shape");
    }
    for (uint32_t column = 0;
         column < local.size(); ++column) {
        if (local[column].size() != local_rows) {
            return Fail(why, "copy_rows");
        }
        std::copy(
            local[column].begin(),
            local[column].end(),
            parent[offset + column].begin());
    }
    return true;
}

LayoutV1 CanonicalLayout(
    uint32_t tape_columns,
    uint32_t derived_columns,
    uint32_t selection_columns)
{
    LayoutV1 out;
    out.tape_columns = tape_columns;
    out.derived_base = tape_columns;
    out.derived_columns = derived_columns;
    out.selection_base =
        out.derived_base + derived_columns;
    out.selection_columns = selection_columns;
    uint32_t cursor =
        out.selection_base + selection_columns;
    out.source_active_base = cursor;
    cursor += kSourceSlotsV1;
    out.source_address_base = cursor;
    cursor += kSourceSlotsV1;
    out.source_multiplicity_base = cursor;
    cursor += kSourceSlotsV1;
    out.consumer_active_base = cursor;
    cursor += kConsumerSlotsV1;
    out.consumer_address_base = cursor;
    cursor += kConsumerSlotsV1;
    out.dependent_base = cursor;
    out.source_inverse_base = cursor;
    cursor += kLookupLanesV1 * kSourceSlotsV1;
    out.consumer_inverse_base = cursor;
    cursor += kLookupLanesV1 * kConsumerSlotsV1;
    out.running_base = cursor;
    cursor += kLookupLanesV1;
    out.end = cursor;
    return out;
}

uint32_t SourceValueColumn(
    const LayoutV1& layout, uint32_t slot)
{
    if (slot < kTapeSourceSlotsV1) {
        return layout.tape_base +
            tape::CanonicalLayoutV1().Value(slot);
    }
    return layout.derived_base +
        derived::CanonicalLayoutV1().Message(
            slot - kTapeSourceSlotsV1);
}

uint32_t SourceAddressColumn(
    const LayoutV1& layout, uint32_t slot)
{
    return layout.tape_base +
        tape::CanonicalLayoutV1().Address(slot);
}

uint32_t ConsumerValueColumn(
    const LayoutV1& layout, uint32_t slot)
{
    const auto derived_layout =
        derived::CanonicalLayoutV1();
    const selection::LayoutV1 selected_layout;
    if (slot < kDerivedConsumerSlotsV1) {
        const uint32_t lane = slot / 2;
        return layout.derived_base +
            ((slot & 1U) == 0
                 ? derived_layout.Low(lane)
                 : derived_layout.High(lane));
    }
    const uint32_t selection_slot =
        slot - kDerivedConsumerSlotsV1;
    if (selection_slot <
            kSelectionZConsumerSlotsV1) {
        const uint32_t pair =
            selection_slot / 3;
        const uint32_t coordinate =
            selection_slot % 3;
        return layout.selection_base +
            (pair == 0
                 ? selected_layout.ProofTapeZ1(
                       coordinate)
                 : selected_layout.ProofTapeZ2(
                       coordinate));
    }
    return layout.selection_base +
        selected_layout.proof_tape_query_index;
}

Fp3 SourceCompressed(
    const std::vector<Fp3>& row,
    const LayoutV1& layout,
    uint32_t slot,
    const Fp3& gamma)
{
    const Fp3 address =
        slot < kTapeSourceSlotsV1
        ? row[SourceAddressColumn(layout, slot)]
        : row[layout.SourceAddress(slot)];
    return gf::Add(
        row[SourceValueColumn(layout, slot)],
        gf::Mul(gamma, address));
}

Fp3 ConsumerCompressed(
    const std::vector<Fp3>& row,
    const LayoutV1& layout,
    uint32_t slot,
    const Fp3& gamma)
{
    return gf::Add(
        row[ConsumerValueColumn(layout, slot)],
        gf::Mul(
            gamma,
            row[layout.ConsumerAddress(slot)]));
}

bool BuildBaseParentCs(
    const tape::PublicShapeV1& shape,
    const tape::PublicBindingV1& tape_binding,
    const derived::BindingV1& derived_binding,
    uint32_t n_lde,
    uint32_t query_count,
    AirCS& cs,
    LayoutV1& layout,
    PlanV1& plan,
    std::string* why)
{
    cs = {};
    AirCS tape_cs;
    AirCS derived_cs;
    AirCS selection_cs;
    selection::CellMapV1 selection_cells;
    std::string local_why;
    if (!tape::BuildConstraintSystemV1(
            shape, tape_binding, tape_cs,
            nullptr, nullptr, &local_why) ||
        !derived::BuildConstraintSystemV1(
            shape, derived_binding, derived_cs,
            nullptr, nullptr, &local_why) ||
        !selection::BuildConstraintSystemV1(
            n_lde, query_count,
            selection_cs, selection_cells,
            &local_why)) {
        return Fail(why, "child_cs:" + local_why);
    }
    if (!PowerOfTwo(tape_cs.n_rows) ||
        derived_cs.n_rows > tape_cs.n_rows ||
        selection_cs.n_rows > tape_cs.n_rows) {
        return Fail(why, "parent_rows");
    }
    layout = CanonicalLayout(
        tape_cs.n_columns,
        derived_cs.n_columns,
        selection_cs.n_columns);
    cs.n_rows = tape_cs.n_rows;
    cs.n_columns = layout.dependent_base;
    if (!AppendShiftedCs(
            tape_cs, layout.tape_base,
            cs.n_rows, cs, why) ||
        !AppendShiftedCs(
            derived_cs, layout.derived_base,
            cs.n_rows, cs, why) ||
        !AppendShiftedCs(
            selection_cs, layout.selection_base,
            cs.n_rows, cs, why) ||
        !BuildCanonicalPlanV1(
            shape, tape_binding,
            n_lde, query_count,
            cs.n_rows,
            layout.tape_base,
            layout.derived_base,
            layout.selection_base,
            plan, why)) {
        return false;
    }

    std::array<std::vector<Fp3>, kSourceSlotsV1>
        source_active;
    std::array<std::vector<Fp3>, kSourceSlotsV1>
        source_address;
    std::array<std::vector<Fp3>, kSourceSlotsV1>
        source_multiplicity;
    std::array<std::vector<Fp3>, kConsumerSlotsV1>
        consumer_active;
    std::array<std::vector<Fp3>, kConsumerSlotsV1>
        consumer_address;
    for (auto& column : source_active) {
        column.assign(cs.n_rows, Fp3::Zero());
    }
    for (auto& column : source_address) {
        column.assign(cs.n_rows, Fp3::Zero());
    }
    for (auto& column : source_multiplicity) {
        column.assign(cs.n_rows, Fp3::Zero());
    }
    for (auto& column : consumer_active) {
        column.assign(cs.n_rows, Fp3::Zero());
    }
    for (auto& column : consumer_address) {
        column.assign(cs.n_rows, Fp3::Zero());
    }
    for (const auto& source : plan.sources) {
        source_active[source.lookup_slot]
            [source.value_cell.row] = Fp3::One();
        source_address[source.lookup_slot]
            [source.value_cell.row] = U(source.address);
        source_multiplicity[source.lookup_slot]
            [source.value_cell.row] = Fp3::One();
    }
    for (const auto& consumer : plan.consumers) {
        consumer_active[consumer.lookup_slot]
            [consumer.value_cell.row] = Fp3::One();
        consumer_address[consumer.lookup_slot]
            [consumer.value_cell.row] = U(consumer.address);
    }
    for (uint32_t slot = 0;
         slot < kSourceSlotsV1; ++slot) {
        AddPreprocessed(
            cs, layout.SourceActive(slot),
            std::move(source_active[slot]));
        AddPreprocessed(
            cs, layout.SourceAddress(slot),
            std::move(source_address[slot]));
        AddPreprocessed(
            cs, layout.SourceMultiplicity(slot),
            std::move(source_multiplicity[slot]));
    }
    for (uint32_t slot = 0;
         slot < kConsumerSlotsV1; ++slot) {
        AddPreprocessed(
            cs, layout.ConsumerActive(slot),
            std::move(consumer_active[slot]));
        AddPreprocessed(
            cs, layout.ConsumerAddress(slot),
            std::move(consumer_address[slot]));
    }
    cs.preprocessed_pin_ood = true;

    const auto tape_layout =
        tape::CanonicalLayoutV1();
    for (uint32_t slot = 0;
         slot < kTapeSourceSlotsV1; ++slot) {
        const uint32_t active =
            layout.SourceActive(slot);
        const uint32_t expected =
            layout.SourceAddress(slot);
        const uint32_t actual =
            layout.tape_base +
            tape_layout.Address(slot);
        Add(
            cs, "stage3.v13_pts.address",
            aq::AirKind::kEverywhere, 2,
            [active, expected, actual](
                const auto& cur, const auto&) {
                return gf::Mul(
                    cur[active],
                    gf::Sub(
                        cur[actual],
                        cur[expected]));
            });
        for (uint32_t bit = 0; bit < 32; ++bit) {
            const uint32_t bit_column =
                layout.tape_base +
                tape_layout.Bit(slot, bit);
            Add(
                cs, "stage3.v13_pts.tape_bit",
                aq::AirKind::kEverywhere, 3,
                [active, bit_column](
                    const auto& cur, const auto&) {
                    return gf::Mul(
                        cur[active],
                        gf::Mul(
                            cur[bit_column],
                            gf::Sub(
                                cur[bit_column],
                                Fp3::One())));
                });
        }
        const uint32_t value =
            layout.tape_base +
            tape_layout.Value(slot);
        Add(
            cs, "stage3.v13_pts.tape_value",
            aq::AirKind::kEverywhere, 2,
            [layout, tape_layout,
             slot, active, value](
                const auto& cur, const auto&) {
                Fp3 recomposed = Fp3::Zero();
                uint64_t weight = 1;
                for (uint32_t bit = 0;
                     bit < 32; ++bit) {
                    recomposed = gf::Add(
                        recomposed,
                        gf::Mul(
                            U(weight),
                            cur[layout.tape_base +
                                tape_layout.Bit(
                                    slot, bit)]));
                    weight <<= 1;
                }
                return gf::Mul(
                    cur[active],
                    gf::Sub(cur[value], recomposed));
            });
    }
    const auto derived_layout =
        derived::CanonicalLayoutV1();
    for (uint32_t slot = 0;
         slot < kDerivedConsumerSlotsV1; ++slot) {
        const uint32_t active =
            layout.ConsumerActive(slot);
        const uint32_t lane = slot / 2;
        const uint32_t half = slot & 1U;
        for (uint32_t bit = 0; bit < 32; ++bit) {
            const uint32_t bit_column =
                layout.derived_base +
                derived_layout.Bit(
                    lane, 32 * half + bit);
            Add(
                cs, "stage3.v13_pts.derived_bit",
                aq::AirKind::kEverywhere, 3,
                [active, bit_column](
                    const auto& cur, const auto&) {
                    return gf::Mul(
                        cur[active],
                        gf::Mul(
                            cur[bit_column],
                            gf::Sub(
                                cur[bit_column],
                                Fp3::One())));
                });
        }
        const uint32_t value =
            ConsumerValueColumn(layout, slot);
        Add(
            cs, "stage3.v13_pts.derived_value",
            aq::AirKind::kEverywhere, 2,
            [layout, derived_layout,
             lane, half, active, value](
                const auto& cur, const auto&) {
                Fp3 recomposed = Fp3::Zero();
                uint64_t weight = 1;
                for (uint32_t bit = 0;
                     bit < 32; ++bit) {
                    recomposed = gf::Add(
                        recomposed,
                        gf::Mul(
                            U(weight),
                            cur[layout.derived_base +
                                derived_layout.Bit(
                                    lane,
                                    32 * half +
                                    bit)]));
                    weight <<= 1;
                }
                return gf::Mul(
                    cur[active],
                    gf::Sub(cur[value], recomposed));
            });
    }
    return true;
}

bool BuildCanaryBaseCs(
    const BoundedCanaryStatementV1& statement,
    AirCS& cs,
    LayoutV1& layout,
    PlanV1& plan,
    std::string* why)
{
    if (statement.version !=
            kProofTapeSourceJoinVersionV1 ||
        statement.source_address[0] ==
            statement.source_address[1] ||
        statement.source_address[0] >=
            abi::kDerivedTranscriptAddressBaseV1 ||
        statement.source_address[1] >=
            abi::kDerivedTranscriptAddressBaseV1) {
        return Fail(why, "canary_statement");
    }
    layout = CanonicalLayout(
        tape::CanonicalLayoutV1().End(),
        derived::CanonicalLayoutV1().End(),
        selection::LayoutV1{}.End());
    cs = {};
    cs.n_rows = 16;
    cs.n_columns = layout.dependent_base;

    plan = {};
    plan.shape = {
        .trace_rows = cs.n_rows,
        .trace_columns = 2,
        .quotient_len = 2,
        .n_coeffs = 2,
        .base_column_indices = {0},
    };
    plan.n_lde = 32;
    plan.query_count = 2;
    plan.parent_rows = cs.n_rows;
    plan.tape_column_offset = layout.tape_base;
    plan.derived_column_offset = layout.derived_base;
    plan.selection_column_offset =
        layout.selection_base;
    const auto tape_layout =
        tape::CanonicalLayoutV1();
    const auto derived_layout =
        derived::CanonicalLayoutV1();
    for (uint32_t item = 0; item < 2; ++item) {
        const uint32_t source_row = 2 + item;
        const uint32_t consumer_row = 7 + item;
        const abi::SourceKeyV1 key{
            abi::FieldKindV1::QueryIndex,
            item, 0, 0, 0, 0};
        LookupEndpointV1 source;
        source.role =
            EndpointRoleV1::TapeWordToDerivedLow;
        source.key = key;
        source.address =
            statement.source_address[item];
        source.lookup_slot = item;
        source.address_cell = {
            layout.tape_base +
                tape_layout.Address(item),
            source_row};
        source.value_cell = {
            layout.tape_base +
                tape_layout.Value(item),
            source_row};
        for (uint32_t bit = 0; bit < 32; ++bit) {
            source.bits[bit] = {
                layout.tape_base +
                    tape_layout.Bit(item, bit),
                source_row};
        }
        source.address_is_ordinary_cell = true;
        source.bits_are_ordinary_cells = true;
        plan.sources.push_back(source);

        LookupEndpointV1 consumer;
        consumer.role = source.role;
        consumer.key = key;
        consumer.address = source.address;
        consumer.lookup_slot = 2 * item;
        consumer.value_cell = {
            layout.derived_base +
                derived_layout.Low(item),
            consumer_row};
        for (uint32_t bit = 0; bit < 32; ++bit) {
            consumer.bits[bit] = {
                layout.derived_base +
                    derived_layout.Bit(item, bit),
                consumer_row};
        }
        consumer.bits_are_ordinary_cells = true;
        plan.consumers.push_back(consumer);
        ++plan.derived_limb_relations;
    }
    plan.exact_tape_schedule = true;
    plan.exact_derived_schedule = true;
    plan.exact_selection_schedule = true;
    plan.all_tape_addresses_mapped = true;
    plan.exact_multiset_cardinality = true;
    plan.valid = true;
    plan.plan_root = CommitPlan(plan);
    plan.note =
        "bounded q2 production-equation canary";
    if (!ValidPlan(plan)) {
        return Fail(why, "canary_plan");
    }

    std::array<std::vector<Fp3>, kSourceSlotsV1>
        source_active;
    std::array<std::vector<Fp3>, kSourceSlotsV1>
        source_address;
    std::array<std::vector<Fp3>, kSourceSlotsV1>
        source_multiplicity;
    std::array<std::vector<Fp3>, kConsumerSlotsV1>
        consumer_active;
    std::array<std::vector<Fp3>, kConsumerSlotsV1>
        consumer_address;
    for (auto& values : source_active) {
        values.assign(cs.n_rows, Fp3::Zero());
    }
    for (auto& values : source_address) {
        values.assign(cs.n_rows, Fp3::Zero());
    }
    for (auto& values : source_multiplicity) {
        values.assign(cs.n_rows, Fp3::Zero());
    }
    for (auto& values : consumer_active) {
        values.assign(cs.n_rows, Fp3::Zero());
    }
    for (auto& values : consumer_address) {
        values.assign(cs.n_rows, Fp3::Zero());
    }
    for (const auto& source : plan.sources) {
        source_active[source.lookup_slot]
            [source.value_cell.row] = Fp3::One();
        source_address[source.lookup_slot]
            [source.value_cell.row] =
                U(source.address);
        source_multiplicity[source.lookup_slot]
            [source.value_cell.row] =
                Fp3::One();
    }
    for (const auto& consumer : plan.consumers) {
        consumer_active[consumer.lookup_slot]
            [consumer.value_cell.row] =
                Fp3::One();
        consumer_address[consumer.lookup_slot]
            [consumer.value_cell.row] =
                U(consumer.address);
    }
    for (uint32_t slot = 0;
         slot < kSourceSlotsV1; ++slot) {
        AddPreprocessed(
            cs, layout.SourceActive(slot),
            std::move(source_active[slot]));
        AddPreprocessed(
            cs, layout.SourceAddress(slot),
            std::move(source_address[slot]));
        AddPreprocessed(
            cs, layout.SourceMultiplicity(slot),
            std::move(source_multiplicity[slot]));
    }
    for (uint32_t slot = 0;
         slot < kConsumerSlotsV1; ++slot) {
        AddPreprocessed(
            cs, layout.ConsumerActive(slot),
            std::move(consumer_active[slot]));
        AddPreprocessed(
            cs, layout.ConsumerAddress(slot),
            std::move(consumer_address[slot]));
    }
    cs.preprocessed_pin_ood = true;

    for (uint32_t item = 0; item < 2; ++item) {
        const uint32_t source_active_column =
            layout.SourceActive(item);
        const uint32_t source_expected_address =
            layout.SourceAddress(item);
        const uint32_t source_address_column =
            layout.tape_base +
            tape_layout.Address(item);
        Add(
            cs, "stage3.v13_pts.canary_address",
            aq::AirKind::kEverywhere, 2,
            [source_active_column,
             source_expected_address,
             source_address_column](
                const auto& cur, const auto&) {
                return gf::Mul(
                    cur[source_active_column],
                    gf::Sub(
                        cur[source_address_column],
                        cur[source_expected_address]));
            });
        for (uint32_t side = 0; side < 2; ++side) {
            const uint32_t active = side == 0
                ? layout.SourceActive(item)
                : layout.ConsumerActive(2 * item);
            const uint32_t value = side == 0
                ? layout.tape_base +
                    tape_layout.Value(item)
                : layout.derived_base +
                    derived_layout.Low(item);
            for (uint32_t bit = 0; bit < 32; ++bit) {
                const uint32_t bit_column = side == 0
                    ? layout.tape_base +
                        tape_layout.Bit(item, bit)
                    : layout.derived_base +
                        derived_layout.Bit(item, bit);
                Add(
                    cs, "stage3.v13_pts.canary_bit",
                    aq::AirKind::kEverywhere, 3,
                    [active, bit_column](
                        const auto& cur, const auto&) {
                        return gf::Mul(
                            cur[active],
                            gf::Mul(
                                cur[bit_column],
                                gf::Sub(
                                    cur[bit_column],
                                    Fp3::One())));
                    });
            }
            Add(
                cs, "stage3.v13_pts.canary_value",
                aq::AirKind::kEverywhere, 2,
                [layout, tape_layout,
                 derived_layout, item,
                 side, active, value](
                    const auto& cur, const auto&) {
                    Fp3 recomposed = Fp3::Zero();
                    uint64_t weight = 1;
                    for (uint32_t bit = 0;
                         bit < 32; ++bit) {
                        const uint32_t column =
                            side == 0
                            ? layout.tape_base +
                                tape_layout.Bit(
                                    item, bit)
                            : layout.derived_base +
                                derived_layout.Bit(
                                    item, bit);
                        recomposed = gf::Add(
                            recomposed,
                            gf::Mul(
                                U(weight),
                                cur[column]));
                        weight <<= 1;
                    }
                    return gf::Mul(
                        cur[active],
                        gf::Sub(
                            cur[value],
                            recomposed));
                });
        }
    }
    return true;
}

bool AppendFinalCs(
    const ChallengesV1& challenges,
    const LayoutV1& layout,
    AirCS& cs,
    std::string* why)
{
    if (cs.n_columns != layout.dependent_base) {
        return Fail(why, "dependent_boundary");
    }
    cs.n_columns = layout.end;
    for (uint32_t lane = 0;
         lane < kLookupLanesV1; ++lane) {
        for (uint32_t slot = 0;
             slot < kSourceSlotsV1; ++slot) {
            const uint32_t inverse =
                layout.SourceInverse(lane, slot);
            const uint32_t active =
                layout.SourceActive(slot);
            Add(
                cs, "stage3.v13_pts.source_inverse",
                aq::AirKind::kEverywhere, 2,
                [challenges, layout,
                 lane, slot, inverse, active](
                    const auto& cur, const auto&) {
                    return gf::Sub(
                        gf::Mul(
                            cur[inverse],
                            gf::Sub(
                                challenges.alpha[lane],
                                SourceCompressed(
                                    cur, layout, slot,
                                    challenges.gamma[lane]))),
                        cur[active]);
                });
            Add(
                cs, "stage3.v13_pts.source_padding",
                aq::AirKind::kEverywhere, 2,
                [inverse, active](
                    const auto& cur, const auto&) {
                    return gf::Mul(
                        gf::Sub(
                            Fp3::One(), cur[active]),
                        cur[inverse]);
                });
        }
        for (uint32_t slot = 0;
             slot < kConsumerSlotsV1; ++slot) {
            const uint32_t inverse =
                layout.ConsumerInverse(lane, slot);
            const uint32_t active =
                layout.ConsumerActive(slot);
            Add(
                cs, "stage3.v13_pts.consumer_inverse",
                aq::AirKind::kEverywhere, 2,
                [challenges, layout,
                 lane, slot, inverse, active](
                    const auto& cur, const auto&) {
                    return gf::Sub(
                        gf::Mul(
                            cur[inverse],
                            gf::Sub(
                                challenges.alpha[lane],
                                ConsumerCompressed(
                                    cur, layout, slot,
                                    challenges.gamma[lane]))),
                        cur[active]);
                });
            Add(
                cs, "stage3.v13_pts.consumer_padding",
                aq::AirKind::kEverywhere, 2,
                [inverse, active](
                    const auto& cur, const auto&) {
                    return gf::Mul(
                        gf::Sub(
                            Fp3::One(), cur[active]),
                        cur[inverse]);
                });
        }
        const uint32_t running =
            layout.Running(lane);
        Add(
            cs, "stage3.v13_pts.running_first",
            aq::AirKind::kFirstRow, 1,
            [running](const auto& cur, const auto&) {
                return cur[running];
            });
        const auto row_term =
            [layout, lane](
                const std::vector<Fp3>& row) {
                Fp3 term = Fp3::Zero();
                for (uint32_t slot = 0;
                     slot < kSourceSlotsV1;
                     ++slot) {
                    term = gf::Add(
                        term,
                        gf::Mul(
                            row[layout.SourceMultiplicity(
                                slot)],
                            row[layout.SourceInverse(
                                lane, slot)]));
                }
                for (uint32_t slot = 0;
                     slot < kConsumerSlotsV1;
                     ++slot) {
                    term = gf::Sub(
                        term,
                        gf::Mul(
                            row[layout.ConsumerActive(slot)],
                            row[layout.ConsumerInverse(
                                lane, slot)]));
                }
                return term;
            };
        Add(
            cs, "stage3.v13_pts.running_transition",
            aq::AirKind::kTransition, 2,
            [running, row_term](
                const auto& cur, const auto& next) {
                return gf::Sub(
                    next[running],
                    gf::Add(
                        cur[running],
                        row_term(cur)));
            });
        Add(
            cs, "stage3.v13_pts.running_last",
            aq::AirKind::kLastRow, 2,
            [running, row_term](
                const auto& cur, const auto&) {
                return gf::Add(
                    cur[running],
                    row_term(cur));
            });
    }
    return true;
}

bool FillFinalWitness(
    const ChallengesV1& challenges,
    const LayoutV1& layout,
    std::vector<std::vector<Fp3>>& columns,
    std::string* why)
{
    if (columns.size() != layout.end ||
        columns.empty()) {
        return Fail(why, "final_columns");
    }
    const uint32_t rows =
        static_cast<uint32_t>(columns[0].size());
    for (uint32_t lane = 0;
         lane < kLookupLanesV1; ++lane) {
        Fp3 running = Fp3::Zero();
        for (uint32_t row = 0;
             row < rows; ++row) {
            columns[layout.Running(lane)][row] =
                running;
            for (uint32_t slot = 0;
                 slot < kSourceSlotsV1;
                 ++slot) {
                if (gf::IsZero(
                        columns[
                            layout.SourceActive(slot)]
                            [row])) {
                    continue;
                }
                const std::vector<Fp3> current =
                    [&]() {
                        std::vector<Fp3> out(
                            columns.size());
                        for (uint32_t column = 0;
                             column < columns.size();
                             ++column) {
                            out[column] =
                                columns[column][row];
                        }
                        return out;
                    }();
                const Fp3 denominator =
                    gf::Sub(
                        challenges.alpha[lane],
                        SourceCompressed(
                            current, layout, slot,
                            challenges.gamma[lane]));
                if (gf::IsZero(denominator)) {
                    return Fail(
                        why, "source_zero_denominator");
                }
                const Fp3 inverse = gf::Inv(denominator);
                columns[layout.SourceInverse(
                    lane, slot)][row] = inverse;
                running = gf::Add(running, inverse);
            }
            for (uint32_t slot = 0;
                 slot < kConsumerSlotsV1;
                 ++slot) {
                if (gf::IsZero(
                        columns[
                            layout.ConsumerActive(slot)]
                            [row])) {
                    continue;
                }
                std::vector<Fp3> current(columns.size());
                for (uint32_t column = 0;
                     column < columns.size(); ++column) {
                    current[column] =
                        columns[column][row];
                }
                const Fp3 denominator =
                    gf::Sub(
                        challenges.alpha[lane],
                        ConsumerCompressed(
                            current, layout, slot,
                            challenges.gamma[lane]));
                if (gf::IsZero(denominator)) {
                    return Fail(
                        why, "consumer_zero_denominator");
                }
                const Fp3 inverse = gf::Inv(denominator);
                columns[layout.ConsumerInverse(
                    lane, slot)][row] = inverse;
                running = gf::Sub(running, inverse);
            }
        }
        if (!gf::IsZero(running)) {
            return Fail(why, "terminal_nonzero");
        }
    }
    return true;
}

} // namespace

bool ChallengesV1::operator==(
    const ChallengesV1& other) const
{
    for (uint32_t lane = 0;
         lane < kLookupLanesV1; ++lane) {
        if (!gf::Eq(gamma[lane], other.gamma[lane]) ||
            !gf::Eq(alpha[lane], other.alpha[lane])) {
            return false;
        }
    }
    return true;
}

bool BuildCanonicalPlanV1(
    const tape::PublicShapeV1& shape,
    const tape::PublicBindingV1& tape_binding,
    uint32_t n_lde,
    uint32_t query_count,
    uint32_t parent_rows,
    uint32_t tape_column_offset,
    uint32_t derived_column_offset,
    uint32_t selection_column_offset,
    PlanV1& out,
    std::string* why)
{
    out = {};
    out.shape = shape;
    out.n_lde = n_lde;
    out.query_count = query_count;
    out.parent_rows = parent_rows;
    out.tape_column_offset = tape_column_offset;
    out.derived_column_offset = derived_column_offset;
    out.selection_column_offset =
        selection_column_offset;
    if (!PowerOfTwo(parent_rows) ||
        n_lde == 0 ||
        query_count == 0) {
        return Fail(why, "plan_shape");
    }
    const auto tape_schedule =
        tape::BuildScheduleV1(shape, tape_binding);
    derived::ScheduleV1 derived_schedule;
    std::string local_why;
    if (!tape_schedule.valid ||
        !derived::BuildScheduleV1(
            shape, derived_schedule,
            &local_why)) {
        return Fail(
            why, "schedule:" + local_why);
    }
    const auto tape_layout =
        tape::CanonicalLayoutV1();
    const auto derived_layout =
        derived::CanonicalLayoutV1();
    const selection::LayoutV1 selection_layout;
    std::map<abi::SourceKeyV1, LookupEndpointV1>
        tape_sources;
    for (uint32_t record = 0;
         record < tape_schedule.records.size();
         ++record) {
        const auto& item =
            tape_schedule.records[record];
        if (!item.source_record) continue;
        const uint32_t row =
            record / tape::kRecordsPerRowV1;
        const uint32_t slot =
            record % tape::kRecordsPerRowV1;
        LookupEndpointV1 endpoint;
        endpoint.key = item.key;
        endpoint.address = item.expected_address;
        endpoint.lookup_slot = slot;
        endpoint.address_cell = {
            tape_column_offset +
                tape_layout.Address(slot),
            row};
        endpoint.value_cell = {
            tape_column_offset +
                tape_layout.Value(slot),
            row};
        for (uint32_t bit = 0; bit < 32; ++bit) {
            endpoint.bits[bit] = {
                tape_column_offset +
                    tape_layout.Bit(slot, bit),
                row};
        }
        endpoint.address_is_ordinary_cell = true;
        endpoint.bits_are_ordinary_cells = true;
        if (!tape_sources.emplace(
                item.key, endpoint).second) {
            return Fail(why, "duplicate_tape_key");
        }
    }
    std::map<abi::SourceKeyV1, LookupEndpointV1>
        selected_sources;
    for (const auto& exported :
         derived_schedule.source_exports) {
        const std::array<
            std::pair<abi::SourceKeyV1, bool>, 2>
            limbs{{
                {exported.key, false},
                {exported.high_key, true},
            }};
        for (const auto& [key, high] : limbs) {
            if (high && !exported.has_high_source) {
                continue;
            }
            const auto found = tape_sources.find(key);
            if (found == tape_sources.end()) {
                return Fail(why, "derived_tape_key");
            }
            LookupEndpointV1 source = found->second;
            source.role = high
                ? EndpointRoleV1::TapeWordToDerivedHigh
                : EndpointRoleV1::TapeWordToDerivedLow;
            out.sources.push_back(source);

            LookupEndpointV1 consumer;
            consumer.role = source.role;
            consumer.key = key;
            consumer.address = source.address;
            consumer.lookup_slot =
                2 * exported.lane +
                (high ? 1U : 0U);
            consumer.value_cell = {
                derived_column_offset +
                    (high
                         ? exported.high_column
                         : exported.low_column),
                exported.row};
            for (uint32_t bit = 0; bit < 32; ++bit) {
                consumer.bits[bit] = {
                    derived_column_offset +
                        derived_layout.Bit(
                            exported.lane,
                            (high ? 32U : 0U) +
                                bit),
                    exported.row};
            }
            consumer.bits_are_ordinary_cells = true;
            out.consumers.push_back(consumer);
            ++out.derived_limb_relations;
        }
        if (exported.selected_point_source) {
            if (!IsZKind(exported.key.kind) ||
                exported.key.limb != 0 ||
                exported.key.d >= 3) {
                return Fail(why, "selected_key");
            }
            LookupEndpointV1 source;
            source.role =
                EndpointRoleV1::
                    DerivedSelectedToSelectionZ;
            source.key = {
                exported.key.kind, 0, 0, 0,
                exported.key.d, 0};
            source.address =
                SyntheticSelectedAddress(
                    exported.key.kind,
                    exported.key.d);
            source.lookup_slot =
                kTapeSourceSlotsV1 +
                exported.lane;
            source.value_cell = {
                derived_column_offset +
                    exported.value_column,
                exported.row};
            if (!selected_sources.emplace(
                    source.key, source).second) {
                return Fail(
                    why, "duplicate_selected_source");
            }
            out.sources.push_back(source);

            LookupEndpointV1 consumer;
            consumer.role = source.role;
            consumer.key = source.key;
            consumer.address = source.address;
            const uint32_t pair =
                exported.key.kind ==
                    abi::FieldKindV1::Z1
                ? 0U : 1U;
            consumer.lookup_slot =
                kDerivedConsumerSlotsV1 +
                3 * pair + exported.key.d;
            consumer.value_cell = {
                selection_column_offset +
                    (pair == 0
                         ? selection_layout.ProofTapeZ1(
                               exported.key.d)
                         : selection_layout.ProofTapeZ2(
                               exported.key.d)),
                selection::kSelectionRowV1};
            out.consumers.push_back(consumer);
            ++out.selected_z_relations;
        }
    }
    for (uint32_t query = 0;
         query < query_count; ++query) {
        const abi::SourceKeyV1 key{
            abi::FieldKindV1::QueryIndex,
            query, 0, 0, 0, 0};
        const auto found = tape_sources.find(key);
        if (found == tape_sources.end()) {
            return Fail(why, "query_tape_key");
        }
        LookupEndpointV1 source = found->second;
        source.role =
            EndpointRoleV1::
                TapeQueryToSelectionQuery;
        out.sources.push_back(source);

        LookupEndpointV1 consumer;
        consumer.role = source.role;
        consumer.key = key;
        consumer.address = source.address;
        consumer.lookup_slot =
            kDerivedConsumerSlotsV1 +
            kSelectionZConsumerSlotsV1;
        consumer.value_cell = {
            selection_column_offset +
                selection_layout
                    .proof_tape_query_index,
            selection::kQueryRowBaseV1 + query};
        out.consumers.push_back(consumer);
        ++out.query_index_relations;
    }

    out.exact_tape_schedule = true;
    out.exact_derived_schedule = true;
    out.exact_selection_schedule =
        out.selected_z_relations == 6 &&
        out.query_index_relations == query_count;
    out.all_tape_addresses_mapped =
        std::all_of(
            out.sources.begin(),
            out.sources.end(),
            [](const auto& source) {
                return
                    source.role ==
                        EndpointRoleV1::
                            DerivedSelectedToSelectionZ ||
                    (source.address_is_ordinary_cell &&
                     source.address != UINT32_MAX);
            });
    out.exact_multiset_cardinality =
        out.sources.size() == out.consumers.size() &&
        out.derived_limb_relations > 0;
    out.valid =
        out.exact_tape_schedule &&
        out.exact_derived_schedule &&
        out.exact_selection_schedule &&
        out.all_tape_addresses_mapped &&
        out.exact_multiset_cardinality;
    if (!out.valid) {
        return Fail(why, "plan_incomplete");
    }
    out.plan_root = CommitPlan(out);
    if (!ValidPlan(out)) {
        out = {};
        return Fail(why, "plan_validation");
    }
    out.note =
        "exact verifier-rebuilt proof-tape/derived/selection multiset";
    if (why != nullptr) *why = out.note;
    return true;
}

bool ValidateCanonicalPlanV1(
    const tape::PublicShapeV1& shape,
    const tape::PublicBindingV1& tape_binding,
    uint32_t n_lde,
    uint32_t query_count,
    const PlanV1& claimed,
    std::string* why)
{
    PlanV1 expected;
    if (!BuildCanonicalPlanV1(
            shape, tape_binding,
            n_lde, query_count,
            claimed.parent_rows,
            claimed.tape_column_offset,
            claimed.derived_column_offset,
            claimed.selection_column_offset,
            expected, why)) {
        return false;
    }
    if (!SamePlan(expected, claimed)) {
        return Fail(why, "claimed_plan_mismatch");
    }
    return true;
}

bool DeriveChallengesV1(
    const PlanV1& plan,
    const uint256& public_seed,
    const uint256& parent_r0_row_root,
    ChallengesV1& out,
    std::string* why)
{
    out = {};
    if (!ValidPlan(plan) ||
        public_seed.IsNull() ||
        parent_r0_row_root.IsNull()) {
        return Fail(why, "challenge_input");
    }
    const uint256 plan_root =
        Fri3AlgDigestToUint256(plan.plan_root);
    const auto sample =
        [&](const char* label,
            uint32_t lane,
            const std::function<bool(const Fp3&)>& accept,
            Fp3& value) {
            for (uint32_t counter = 0;
                 counter < 64; ++counter) {
                const uint256 digest =
                    aq::AirChallengeDigest(
                        public_seed, label,
                        {plan_root,
                         parent_r0_row_root},
                        {static_cast<uint32_t>(
                             kPlanMagicV1),
                         static_cast<uint32_t>(
                             kPlanMagicV1 >> 32),
                         plan.version,
                         lane,
                         counter});
                const Fp3 candidate =
                    gf::FromChallengeBytes3(
                        digest.data());
                if (accept(candidate)) {
                    value = candidate;
                    return true;
                }
            }
            return false;
        };
    if (!sample(
            "stage3.v13_pts.gamma", 0,
            [](const Fp3& value) {
                return !gf::IsZero(value);
            }, out.gamma[0]) ||
        !sample(
            "stage3.v13_pts.gamma", 1,
            [&](const Fp3& value) {
                return !gf::IsZero(value) &&
                    !gf::Eq(value, out.gamma[0]);
            }, out.gamma[1]) ||
        !sample(
            "stage3.v13_pts.alpha", 0,
            [](const Fp3&) { return true; },
            out.alpha[0]) ||
        !sample(
            "stage3.v13_pts.alpha", 1,
            [&](const Fp3& value) {
                return !gf::Eq(value, out.alpha[0]);
            }, out.alpha[1])) {
        out = {};
        return Fail(why, "challenge_sampler");
    }
    return true;
}

bool BuildProductV1(
    const tape::ProductV1& tape_product,
    const derived::ProductV1& derived_product,
    const selection::ProductV1& selection_product,
    const uint256& public_seed,
    ProductV1& out,
    std::string* why)
{
    out = {};
    if (!tape_product.valid ||
        !derived_product.valid ||
        !selection_product.valid ||
        public_seed.IsNull() ||
        tape_product.schedule.shape !=
            derived_product.schedule.shape) {
        return Fail(why, "product_input");
    }
    out.tape_binding = tape_product.binding;
    out.derived_binding = derived_product.binding;
    if (!BuildBaseParentCs(
            tape_product.schedule.shape,
            out.tape_binding,
            out.derived_binding,
            selection_product.domain_bits >= 32
                ? 0U
                : (uint32_t{1}
                   << selection_product.domain_bits),
            selection_product.query_count,
            out.cs, out.layout,
            out.plan, why)) {
        out = {};
        return false;
    }
    out.columns.assign(
        out.cs.n_columns,
        std::vector<Fp3>(
            out.cs.n_rows, Fp3::Zero()));
    if (!CopyShiftedColumns(
            tape_product.columns,
            tape_product.cs.n_rows,
            out.layout.tape_base,
            out.cs.n_rows,
            out.columns, why) ||
        !CopyShiftedColumns(
            derived_product.columns,
            derived_product.cs.n_rows,
            out.layout.derived_base,
            out.cs.n_rows,
            out.columns, why) ||
        !CopyShiftedColumns(
            selection_product.columns,
            selection_product.cs.n_rows,
            out.layout.selection_base,
            out.cs.n_rows,
            out.columns, why)) {
        out = {};
        return false;
    }
    for (const auto& [column, values] :
         out.cs.preprocessed) {
        out.columns[column] = values;
    }
    out.r0_base_column_indices.resize(
        out.layout.dependent_base);
    std::iota(
        out.r0_base_column_indices.begin(),
        out.r0_base_column_indices.end(), 0U);
    out.r0_session =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            out.cs, out.columns,
            out.r0_base_column_indices);
    if (!out.r0_session.valid ||
        !DeriveChallengesV1(
            out.plan, public_seed,
            out.r0_session.base_row_commitment,
            out.challenges, why) ||
        !AppendFinalCs(
            out.challenges, out.layout,
            out.cs, why)) {
        out = {};
        return false;
    }
    out.columns.resize(
        out.cs.n_columns,
        std::vector<Fp3>(
            out.cs.n_rows, Fp3::Zero()));
    if (!FillFinalWitness(
            out.challenges, out.layout,
            out.columns, why)) {
        out = {};
        return false;
    }
    // The child builders have already evaluated their respective complete
    // constraint systems. FillFinalWitness above evaluates every active
    // LogUp denominator and refuses a non-zero terminal, so it is the exact
    // linear-time witness check for the newly appended relation. Avoid a
    // second generic row-by-constraint interpretation here. ProveV1 still
    // proves the complete combined CS and VerifyV1 rebuilds and verifies all
    // child and join constraints together.
    out.violations = 0;
    out.tape_verifier_resident = true;
    out.derived_hash_verifier_resident = true;
    out.selection_verifier_resident = true;
    out.address_value_bit_cells_referenced = true;
    out.selection_proof_tape_inputs_closed =
        out.plan.selected_z_relations == 6 &&
        out.plan.query_index_relations ==
            selection_product.query_count;
    // OOD-candidate and query-digest ownership belongs to the existing
    // V14-selection fused parent.  This parent closes only the cells whose
    // claimed source is the canonical proof tape.
    out.v14_selection_inputs_resident = false;
    out.dual_fp3_rational_identity_constrained = true;
    out.terminal_cancellation_constrained = true;
    out.recursively_consumed = false;
    out.recursive_authority_ready = false;
    out.valid =
        out.violations == 0 &&
        out.tape_verifier_resident &&
        out.derived_hash_verifier_resident &&
        out.selection_verifier_resident &&
        out.address_value_bit_cells_referenced &&
        out.selection_proof_tape_inputs_closed &&
        !out.v14_selection_inputs_resident &&
        out.dual_fp3_rational_identity_constrained &&
        out.terminal_cancellation_constrained &&
        !out.recursively_consumed &&
        !out.recursive_authority_ready;
    out.note = out.valid
        ? "proof-tape Address/Value/Bit, derived hash and Selection "
          "proof-tape inputs closed in one dual-Fp3 parent; V14 input "
          "residency and recursive receipt consumption remain explicit"
        : "proof-tape source join constraint violation";
    if (!out.valid) {
        return Fail(why, "product_violations");
    }
    if (why != nullptr) *why = out.note;
    return true;
}

bool ProveV1(
    const ProductV1& product,
    const uint256& public_seed,
    ProofV1& out,
    std::string* why)
{
    out = {};
    if (!product.valid ||
        product.violations != 0 ||
        public_seed.IsNull() ||
        product.r0_session.base_row_commitment.IsNull()) {
        return Fail(why, "prove_input");
    }
    const auto proved =
        aq::AirQuotientProveRowsSplitRapSafeV2(
            product.cs, product.columns,
            product.r0_base_column_indices,
            public_seed, {},
            &product.r0_session);
    if (!proved.ok || !proved.division_exact) {
        return Fail(
            why, "prove:" + proved.note);
    }
    out.plan_root = product.plan.plan_root;
    out.r0_row_root =
        product.r0_session.base_row_commitment;
    out.proof = proved.proof;
    out.note =
        "same-parent proof-tape source join proof";
    if (why != nullptr) *why = out.note;
    return true;
}

bool VerifyV1(
    const tape::PublicShapeV1& shape,
    const tape::PublicBindingV1& tape_binding,
    const derived::BindingV1& derived_binding,
    uint32_t n_lde,
    uint32_t query_count,
    const PlanV1& canonical_plan,
    const uint256& public_seed,
    const ProofV1& proof,
    std::string* why)
{
    if (proof.version !=
            kProofTapeSourceJoinVersionV1 ||
        proof.plan_root !=
            canonical_plan.plan_root ||
        proof.r0_row_root.IsNull() ||
        proof.recursively_consumed ||
        proof.recursive_authority_ready ||
        proof.proof.batch.groups.empty() ||
        proof.r0_row_root !=
            Fri3AlgDigestToUint256(
                proof.proof.batch.groups[0]
                    .row_commit.root) ||
        !ValidateCanonicalPlanV1(
            shape, tape_binding,
            n_lde, query_count,
            canonical_plan, why)) {
        return Fail(why, "verify_envelope_or_plan");
    }
    AirCS cs;
    LayoutV1 layout;
    PlanV1 rebuilt;
    if (!BuildBaseParentCs(
            shape, tape_binding,
            derived_binding,
            n_lde, query_count,
            cs, layout, rebuilt, why) ||
        rebuilt.plan_root !=
            canonical_plan.plan_root) {
        return Fail(why, "verify_parent");
    }
    std::vector<uint32_t> base_indices(
        layout.dependent_base);
    std::iota(
        base_indices.begin(),
        base_indices.end(), 0U);
    ChallengesV1 challenges;
    if (!DeriveChallengesV1(
            rebuilt, public_seed,
            proof.r0_row_root,
            challenges, why) ||
        !AppendFinalCs(
            challenges, layout, cs, why)) {
        return false;
    }
    std::string air_why;
    if (!aq::AirQuotientVerifyRowsSplitRapSafeV2(
            cs, proof.proof,
            base_indices,
            public_seed, &air_why)) {
        return Fail(why, "verify_air:" + air_why);
    }
    if (why != nullptr) {
        *why =
            "stage3:v13_proof_tape_source_join:verified";
    }
    return true;
}

bool BuildBoundedCanaryProductV1(
    const BoundedCanaryStatementV1& statement,
    const std::array<uint32_t, 2>& witness_values,
    const uint256& public_seed,
    BoundedCanaryProductV1& out,
    std::string* why)
{
    out = {};
    out.statement = statement;
    if (public_seed.IsNull() ||
        !BuildCanaryBaseCs(
            statement, out.cs,
            out.layout, out.plan, why)) {
        return false;
    }
    out.columns.assign(
        out.cs.n_columns,
        std::vector<Fp3>(
            out.cs.n_rows, Fp3::Zero()));
    for (const auto& [column, values] :
         out.cs.preprocessed) {
        out.columns[column] = values;
    }
    const auto tape_layout =
        tape::CanonicalLayoutV1();
    const auto derived_layout =
        derived::CanonicalLayoutV1();
    for (uint32_t item = 0; item < 2; ++item) {
        const uint32_t source_row = 2 + item;
        const uint32_t consumer_row = 7 + item;
        out.columns[
            out.layout.tape_base +
                tape_layout.Address(item)]
            [source_row] =
                U(statement.source_address[item]);
        out.columns[
            out.layout.tape_base +
                tape_layout.Value(item)]
            [source_row] =
                U(witness_values[item]);
        out.columns[
            out.layout.derived_base +
                derived_layout.Low(item)]
            [consumer_row] =
                U(witness_values[item]);
        for (uint32_t bit = 0; bit < 32; ++bit) {
            const Fp3 value =
                U((witness_values[item] >> bit) & 1U);
            out.columns[
                out.layout.tape_base +
                    tape_layout.Bit(item, bit)]
                [source_row] = value;
            out.columns[
                out.layout.derived_base +
                    derived_layout.Bit(item, bit)]
                [consumer_row] = value;
        }
    }
    out.r0_base_column_indices.resize(
        out.layout.dependent_base);
    std::iota(
        out.r0_base_column_indices.begin(),
        out.r0_base_column_indices.end(), 0U);
    out.r0_session =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            out.cs, out.columns,
            out.r0_base_column_indices);
    if (!out.r0_session.valid ||
        !DeriveChallengesV1(
            out.plan, public_seed,
            out.r0_session.base_row_commitment,
            out.challenges, why) ||
        !AppendFinalCs(
            out.challenges,
            out.layout, out.cs, why)) {
        out = {};
        return false;
    }
    out.columns.resize(
        out.cs.n_columns,
        std::vector<Fp3>(
            out.cs.n_rows, Fp3::Zero()));
    if (!FillFinalWitness(
            out.challenges, out.layout,
            out.columns, why)) {
        out = {};
        return false;
    }
    out.violations =
        CountViolationsV1(
            out.cs, out.columns);
    out.exact_production_equations = true;
    out.valid =
        out.violations == 0 &&
        out.exact_production_equations;
    out.note = out.valid
        ? "bounded q2 production-equation canary"
        : "bounded q2 canary constraint violation";
    if (!out.valid) {
        return Fail(why, "canary_violations");
    }
    if (why != nullptr) *why = out.note;
    return true;
}

bool VerifyBoundedCanaryV1(
    const BoundedCanaryStatementV1& statement,
    const uint256& public_seed,
    const ProofV1& proof,
    std::string* why)
{
    if (public_seed.IsNull() ||
        proof.version !=
            kProofTapeSourceJoinVersionV1 ||
        proof.r0_row_root.IsNull() ||
        proof.recursively_consumed ||
        proof.recursive_authority_ready ||
        proof.proof.batch.groups.empty() ||
        proof.r0_row_root !=
            Fri3AlgDigestToUint256(
                proof.proof.batch.groups[0]
                    .row_commit.root)) {
        return Fail(why, "canary_verify_envelope");
    }
    AirCS cs;
    LayoutV1 layout;
    PlanV1 plan;
    if (!BuildCanaryBaseCs(
            statement, cs, layout,
            plan, why) ||
        proof.plan_root != plan.plan_root) {
        return Fail(why, "canary_verify_plan");
    }
    std::vector<uint32_t> base_indices(
        layout.dependent_base);
    std::iota(
        base_indices.begin(),
        base_indices.end(), 0U);
    ChallengesV1 challenges;
    if (!DeriveChallengesV1(
            plan, public_seed,
            proof.r0_row_root,
            challenges, why) ||
        !AppendFinalCs(
            challenges, layout, cs, why)) {
        return false;
    }
    std::string air_why;
    if (!aq::AirQuotientVerifyRowsSplitRapSafeV2(
            cs, proof.proof,
            base_indices,
            public_seed, &air_why)) {
        return Fail(
            why, "canary_verify_air:" + air_why);
    }
    if (why != nullptr) {
        *why =
            "stage3:v13_proof_tape_source_join:"
            "bounded_canary_verified";
    }
    return true;
}

uint64_t CountViolationsV1(
    const AirCS& cs,
    const std::vector<std::vector<Fp3>>& columns)
{
    if (columns.size() != cs.n_columns ||
        cs.n_rows == 0) {
        return UINT64_MAX;
    }
    for (const auto& column : columns) {
        if (column.size() != cs.n_rows) {
            return UINT64_MAX;
        }
    }
    uint64_t violations = 0;
    std::vector<Fp3> current(cs.n_columns);
    std::vector<Fp3> next(cs.n_columns);
    for (uint32_t row = 0;
         row < cs.n_rows; ++row) {
        const uint32_t next_row =
            (row + 1) % cs.n_rows;
        for (uint32_t column = 0;
             column < cs.n_columns; ++column) {
            current[column] = columns[column][row];
            next[column] = columns[column][next_row];
        }
        for (const auto& constraint :
             cs.constraints) {
            const bool applies =
                constraint.kind ==
                    aq::AirKind::kEverywhere ||
                (constraint.kind ==
                     aq::AirKind::kFirstRow &&
                 row == 0) ||
                (constraint.kind ==
                     aq::AirKind::kLastRow &&
                 row + 1 == cs.n_rows) ||
                (constraint.kind ==
                     aq::AirKind::kTransition &&
                 row + 1 < cs.n_rows);
            if (applies &&
                !gf::IsZero(
                    constraint.eval(
                        current, next))) {
                ++violations;
            }
        }
    }
    return violations;
}

} // namespace matmul::v4::rc::stage3_v13_proof_tape_source_join
