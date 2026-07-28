// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_v13_deep_source_logup_parent.h>

#include <algorithm>
#include <functional>
#include <limits>
#include <map>
#include <numeric>
#include <set>
#include <utility>

namespace matmul::v4::rc::stage3_v13_deep_source_logup_parent {
namespace {

namespace dvm = stage3_multirow_v11_deep_vm;
using AirCS = aq::AirConstraintSystem<gf::Fp3>;
using gf::Fp3;

inline constexpr uint64_t kPlanMagicV1 =
    UINT64_C(0x4431334c4f475550); // "D13LOGUP"

struct RecordRef {
    uint32_t row{UINT32_MAX};
    uint32_t slot{UINT32_MAX};
};

Fp3 U(uint64_t value)
{
    return Fp3::FromFp(gf::FromU64(value));
}

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why =
            "stage3:v13_deep_source_logup_parent:" +
            detail;
    }
    return false;
}

bool PowerOfTwo(uint32_t value)
{
    return value >= 2 &&
        (value & (value - 1)) == 0;
}

bool IsPreprocessed(const AirCS& cs, uint32_t column)
{
    return std::any_of(
        cs.preprocessed.begin(),
        cs.preprocessed.end(),
        [column](const auto& item) {
            return item.first == column;
        });
}

bool CanonicalU32(const Fp3& value, uint32_t& out)
{
    if (value.c1 != 0 ||
        value.c2 != 0 ||
        value.c0 >
            std::numeric_limits<uint32_t>::max()) {
        return false;
    }
    out = static_cast<uint32_t>(value.c0);
    return true;
}

abi::SourceKeyV1 Key(
    abi::FieldKindV1 kind,
    uint32_t a = 0,
    uint32_t b = 0,
    uint32_t c = 0,
    uint32_t d = 0,
    uint8_t limb = 0)
{
    abi::SourceKeyV1 out;
    out.kind = kind;
    out.a = a;
    out.b = b;
    out.c = c;
    out.d = d;
    out.limb = limb;
    return out;
}

const tape::SourceAddressCellV1* FindTapeSource(
    const tape::ProductV1& product,
    uint32_t address)
{
    const auto found = std::find_if(
        product.source_cells.begin(),
        product.source_cells.end(),
        [address](const auto& source) {
            return source.address == address;
        });
    return found == product.source_cells.end()
        ? nullptr
        : &*found;
}

const tape::SourceAddressCellV1* FindTapeSource(
    const tape::ProductV1& product,
    const abi::SourceKeyV1& key)
{
    const auto found = std::find_if(
        product.source_cells.begin(),
        product.source_cells.end(),
        [&key](const auto& source) {
            return source.key == key;
        });
    return found == product.source_cells.end()
        ? nullptr
        : &*found;
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

alg_hash::Digest CommitPlan(const PlanV1& plan)
{
    std::vector<gf::Fp> lanes;
    lanes.reserve(
        32 + 14 * plan.occurrences.size() +
        4 * plan.sources.size());
    lanes.push_back(gf::FromU64(kPlanMagicV1));
    lanes.push_back(gf::FromU64(plan.version));
    lanes.push_back(gf::FromU64(plan.shape.trace_rows));
    lanes.push_back(gf::FromU64(plan.shape.trace_columns));
    lanes.push_back(gf::FromU64(plan.shape.quotient_len));
    lanes.push_back(gf::FromU64(plan.shape.n_coeffs));
    lanes.push_back(gf::FromU64(plan.range.first_query));
    lanes.push_back(gf::FromU64(plan.range.query_count));
    lanes.push_back(gf::FromU64(plan.parent_rows));
    lanes.push_back(gf::FromU64(plan.tape_column_base));
    lanes.push_back(gf::FromU64(plan.deep_column_base));
    lanes.push_back(gf::FromU64(
        plan.shape.base_column_indices.size()));
    for (uint32_t column :
         plan.shape.base_column_indices) {
        lanes.push_back(gf::FromU64(column));
    }
    lanes.push_back(gf::FromU64(plan.occurrences.size()));
    lanes.push_back(gf::FromU64(plan.sources.size()));
    lanes.push_back(gf::FromU64(plan.limb_occurrences));
    lanes.push_back(gf::FromU64(
        plan.source_multiplicity_sum));
    for (const auto& occurrence :
         plan.occurrences) {
        lanes.push_back(gf::FromU64(
            static_cast<uint8_t>(
                occurrence.kind)));
        lanes.push_back(gf::FromU64(occurrence.query));
        lanes.push_back(gf::FromU64(occurrence.item));
        lanes.push_back(gf::FromU64(occurrence.row));
        lanes.push_back(gf::FromU64(occurrence.slot));
        lanes.push_back(gf::FromU64(
            occurrence.consumer_column));
        AppendKey(lanes, occurrence.key);
        lanes.push_back(gf::FromU64(
            occurrence.source_address));
    }
    for (const auto& source : plan.sources) {
        lanes.push_back(gf::FromU64(source.address));
        lanes.push_back(gf::FromU64(source.multiplicity));
        lanes.push_back(gf::FromU64(source.row));
        lanes.push_back(gf::FromU64(source.slot));
    }
    return alg_hash::SpongeHashFp(lanes);
}

LayoutV1 CanonicalLayout(uint32_t original_columns)
{
    LayoutV1 out;
    out.original_columns = original_columns;
    uint32_t cursor = original_columns;
    out.source_carry = cursor++;
    out.source_emit_value = cursor++;
    out.source_emit_active = cursor++;
    out.source_emit_address = cursor++;
    out.source_emit_multiplicity = cursor++;
    out.source_carry_weight_base = cursor;
    cursor += kTapeSlotsV1;
    out.source_emit_weight_base = cursor;
    cursor += kTapeSlotsV1;
    out.consumer_active_base = cursor;
    cursor += kConsumerSlotsV1;
    out.consumer_address_base = cursor;
    cursor += kConsumerSlotsV1;
    out.dependent_base = cursor;
    out.source_inverse_base = cursor;
    cursor += kLookupLanesV1;
    out.consumer_inverse_base = cursor;
    cursor +=
        kLookupLanesV1 *
        kConsumerSlotsV1;
    out.running_base = cursor;
    cursor += kLookupLanesV1;
    out.end = cursor;
    return out;
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
    const std::vector<Fp3>& values)
{
    cs.preprocessed.emplace_back(column, values);
}

uint32_t KindNumber(ConsumerKindV1 kind)
{
    return static_cast<uint32_t>(kind);
}

uint32_t KindSlot(ConsumerKindV1 kind)
{
    return KindNumber(kind) - 1;
}

uint32_t DeepColumnForKind(
    const dvm::LayoutV1& layout,
    ConsumerKindV1 kind)
{
    switch (kind) {
    case ConsumerKindV1::DeepCurrent:
        return layout.current_value;
    case ConsumerKindV1::EvalZ1:
        return layout.eval_z1;
    case ConsumerKindV1::EvalZ2:
        return layout.eval_z2;
    case ConsumerKindV1::Z1:
        return layout.z1;
    case ConsumerKindV1::Z2:
        return layout.z2;
    case ConsumerKindV1::DeepWeight1:
        return layout.w1;
    case ConsumerKindV1::DeepWeight2:
        return layout.w2;
    case ConsumerKindV1::VmCurrent:
    case ConsumerKindV1::VmNext:
        return layout.operand_lhs;
    case ConsumerKindV1::AirLambda:
        return layout.air_lambda;
    }
    return UINT32_MAX;
}

Fp3 LimbWeight(uint32_t limb)
{
    const gf::Fp two32 =
        gf::FromU64(UINT64_C(1) << 32);
    switch (limb) {
    case 0: return Fp3{1, 0, 0};
    case 1: return Fp3{two32, 0, 0};
    case 2: return Fp3{0, 1, 0};
    case 3: return Fp3{0, two32, 0};
    case 4: return Fp3{0, 0, 1};
    case 5: return Fp3{0, 0, two32};
    }
    return Fp3::Zero();
}

bool AddOccurrence(
    const tape::ProductV1& tape_product,
    uint32_t row,
    uint32_t query,
    uint32_t item,
    ConsumerKindV1 kind,
    const abi::SourceKeyV1& base_key,
    std::map<uint32_t, uint32_t>& multiplicity,
    PlanV1& plan,
    std::string* why)
{
    OccurrenceV1 occurrence;
    occurrence.kind = kind;
    occurrence.query = query;
    occurrence.item = item;
    occurrence.row = row;
    occurrence.slot = KindSlot(kind);
    occurrence.consumer_column =
        DeepColumnForKind(
            dvm::CanonicalLayoutV1(), kind);
    occurrence.key = base_key;
    for (uint32_t limb = 0;
         limb < kFieldLimbsV1; ++limb) {
        auto key = base_key;
        key.d = limb / 2;
        key.limb =
            static_cast<uint8_t>(limb % 2);
        const auto* source =
            FindTapeSource(tape_product, key);
        if (source == nullptr) {
            return Fail(why, "missing_fp3_source");
        }
        if (limb == 0) {
            occurrence.source_address =
                source->address;
        } else if (
            source->address !=
                occurrence.source_address + limb) {
            return Fail(
                why, "nonconsecutive_fp3_source");
        }
    }
    ++multiplicity[occurrence.source_address];
    plan.occurrences.push_back(
        std::move(occurrence));
    return true;
}

bool BuildPlan(
    const tape::ProductV1& tape_product,
    const qp::ProductV1& physical,
    const rv::QueryRangeV1& range,
    PlanV1& out,
    std::string* why)
{
    out = {};
    out.shape = tape_product.schedule.shape;
    out.range = range;
    out.parent_rows = physical.cs.n_rows;
    out.tape_column_base =
        physical.tape_attachment.column_base;
    out.deep_column_base =
        physical.deep_attachment.column_base;
    const auto& phase = physical.deep_phase;
    const auto& layout = physical.deep_plan.layout;
    if (!tape_product.valid ||
        !physical.valid ||
        !phase.valid ||
        !PowerOfTwo(out.parent_rows) ||
        phase.cs.n_rows > out.parent_rows) {
        return Fail(why, "plan_input");
    }

    std::map<uint32_t, uint32_t> multiplicity;
    std::set<std::pair<uint32_t, uint32_t>>
        occupied;
    for (uint32_t row = 0;
         row < physical.deep_plan.real_rows;
         ++row) {
        uint32_t query = 0;
        uint32_t item = 0;
        if (!CanonicalU32(
                phase.columns[layout.query][row],
                query) ||
            !CanonicalU32(
                phase.columns[layout.item][row],
                item)) {
            return Fail(why, "row_coordinate");
        }
        const auto add =
            [&](ConsumerKindV1 kind,
                const abi::SourceKeyV1& key) {
                const uint32_t slot =
                    KindSlot(kind);
                if (!occupied.emplace(
                        row, slot).second) {
                    return Fail(
                        why, "consumer_collision");
                }
                return AddOccurrence(
                    tape_product, row, query,
                    item, kind, key,
                    multiplicity, out, why);
            };
        if (gf::Eq(
                phase.columns[
                    layout.deep_term][row],
                Fp3::One())) {
            uint32_t address = 0;
            if (!CanonicalU32(
                    phase.columns[
                        layout.source_address][row],
                    address)) {
                return Fail(
                    why, "deep_source_address");
            }
            const auto* current =
                FindTapeSource(
                    tape_product, address);
            if (current == nullptr ||
                current->key.kind !=
                    abi::FieldKindV1::
                        QueryRowValue ||
                current->key.a != query) {
                return Fail(
                    why, "deep_current_key");
            }
            // Query quotient ownership is already closed by the physical
            // quotient parent consumed below.
            if (current->key.b != 2 &&
                !add(
                    ConsumerKindV1::DeepCurrent,
                    current->key)) {
                return false;
            }
            if (!add(
                    ConsumerKindV1::EvalZ1,
                    Key(
                        abi::FieldKindV1::EvalZ1,
                        item)) ||
                !add(
                    ConsumerKindV1::EvalZ2,
                    Key(
                        abi::FieldKindV1::EvalZ2,
                        item))) {
                return false;
            }
        } else if (gf::Eq(
                       phase.columns[
                           layout.deep_finalize][row],
                       Fp3::One())) {
            if (!add(
                    ConsumerKindV1::Z1,
                    Key(abi::FieldKindV1::Z1)) ||
                !add(
                    ConsumerKindV1::Z2,
                    Key(abi::FieldKindV1::Z2)) ||
                !add(
                    ConsumerKindV1::DeepWeight1,
                    Key(
                        abi::FieldKindV1::
                            DeepWeight1)) ||
                !add(
                    ConsumerKindV1::DeepWeight2,
                    Key(
                        abi::FieldKindV1::
                            DeepWeight2))) {
                return false;
            }
        } else if (gf::Eq(
                       phase.columns[
                           layout.vm_instruction][row],
                       Fp3::One())) {
            if (gf::Eq(
                    phase.columns[
                        layout.op_current][row],
                    Fp3::One()) ||
                gf::Eq(
                    phase.columns[
                        layout.op_next][row],
                    Fp3::One())) {
                uint32_t address = 0;
                if (!CanonicalU32(
                        phase.columns[
                            layout.source_address][row],
                        address)) {
                    return Fail(
                        why, "vm_source_address");
                }
                const auto* source =
                    FindTapeSource(
                        tape_product, address);
                const bool current =
                    gf::Eq(
                        phase.columns[
                            layout.op_current][row],
                        Fp3::One());
                if (source == nullptr ||
                    source->key.kind !=
                        (current
                            ? abi::FieldKindV1::
                                QueryRowValue
                            : abi::FieldKindV1::
                                NextRowValue) ||
                    source->key.a != query ||
                    !add(
                        current
                            ? ConsumerKindV1::
                                VmCurrent
                            : ConsumerKindV1::
                                VmNext,
                        source->key)) {
                    return Fail(
                        why, "vm_source_key");
                }
            }
            if (!add(
                    ConsumerKindV1::AirLambda,
                    Key(
                        abi::FieldKindV1::
                            AirConstraintLambda))) {
                return false;
            }
        }
    }
    if (out.occurrences.empty()) {
        return Fail(why, "empty_occurrences");
    }

    uint64_t sum = 0;
    for (const auto& [address, count] :
         multiplicity) {
        const auto* end =
            FindTapeSource(
                tape_product,
                address +
                    kFieldLimbsV1 - 1);
        if (end == nullptr ||
            end->row >= out.parent_rows ||
            end->slot >= kTapeSlotsV1 ||
            count == 0) {
            return Fail(
                why, "source_group_end");
        }
        out.sources.push_back({
            .address = address,
            .multiplicity = count,
            .row = end->row,
            .slot = end->slot,
        });
        sum += count;
    }
    out.limb_occurrences =
        uint64_t{out.occurrences.size()} *
        kFieldLimbsV1;
    out.source_multiplicity_sum = sum;
    out.exact_structural_rows = true;
    out.exact_v13_addresses = true;
    out.exact_multiplicities =
        sum == out.occurrences.size();
    out.proof_values_excluded = true;
    out.plan_root = CommitPlan(out);
    out.valid =
        out.exact_structural_rows &&
        out.exact_v13_addresses &&
        out.exact_multiplicities &&
        out.proof_values_excluded &&
        out.plan_root != alg_hash::Digest{};
    out.note = out.valid
        ? "stage3:v13_deep_source_logup_parent:"
          "exact_stream_plan"
        : "stage3:v13_deep_source_logup_parent:"
          "invalid_stream_plan";
    return out.valid ||
        Fail(why, "plan_invariant");
}

bool DeriveChallenges(
    const PlanV1& plan,
    const uint256& public_seed,
    const uint256& r0_root,
    ChallengesV1& out,
    std::string* why)
{
    out = {};
    if (!plan.valid ||
        public_seed.IsNull() ||
        r0_root.IsNull()) {
        return Fail(why, "challenge_input");
    }
    const uint256 plan_root =
        Fri3AlgDigestToUint256(plan.plan_root);
    const auto sample =
        [&](const char* label,
            uint32_t lane,
            const std::function<bool(const Fp3&)>&
                accept,
            Fp3& value) {
            for (uint32_t counter = 0;
                 counter < 64; ++counter) {
                const uint256 digest =
                    aq::AirChallengeDigest(
                        public_seed, label,
                        {plan_root, r0_root},
                        {
                            static_cast<uint32_t>(
                                kPlanMagicV1),
                            static_cast<uint32_t>(
                                kPlanMagicV1 >> 32),
                            plan.version,
                            lane,
                            counter,
                        });
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
            "stage3.v13.deep_stream.gamma", 0,
            [](const Fp3& value) {
                return !gf::IsZero(value);
            }, out.gamma[0]) ||
        !sample(
            "stage3.v13.deep_stream.gamma", 1,
            [&](const Fp3& value) {
                return !gf::IsZero(value) &&
                    !gf::Eq(
                        value, out.gamma[0]);
            }, out.gamma[1]) ||
        !sample(
            "stage3.v13.deep_stream.alpha", 0,
            [](const Fp3&) { return true; },
            out.alpha[0]) ||
        !sample(
            "stage3.v13.deep_stream.alpha", 1,
            [&](const Fp3& value) {
                return !gf::Eq(
                    value, out.alpha[0]);
            }, out.alpha[1])) {
        return Fail(why, "challenge_sampler");
    }
    return true;
}

std::map<uint32_t, RecordRef> TapeRefs(
    const tape::ProductV1& product)
{
    std::map<uint32_t, RecordRef> out;
    for (const auto& source :
         product.source_cells) {
        out.emplace(
            source.address,
            RecordRef{
                source.row, source.slot});
    }
    return out;
}

bool MaterializeBase(
    const qp::ProductV1& physical,
    const PlanV1& plan,
    const std::map<uint32_t, RecordRef>& refs,
    const LayoutV1& layout,
    std::vector<std::vector<Fp3>>& columns,
    std::string* why)
{
    const auto tape_layout =
        tape::CanonicalLayoutV1();
    std::map<std::pair<uint32_t, uint32_t>,
             std::pair<uint32_t, uint32_t>>
        selected;
    std::map<uint32_t, TapeSourceV1> ending;
    for (const auto& group : plan.sources) {
        if (!ending.emplace(
                group.row, group).second) {
            return Fail(
                why, "multiple_group_ends_per_row");
        }
        for (uint32_t limb = 0;
             limb < kFieldLimbsV1; ++limb) {
            const auto found =
                refs.find(group.address + limb);
            if (found == refs.end() ||
                found->second.row >= plan.parent_rows ||
                found->second.slot >=
                    kTapeSlotsV1 ||
                !selected.emplace(
                    std::make_pair(
                        found->second.row,
                        found->second.slot),
                    std::make_pair(
                        group.address,
                        limb)).second) {
                return Fail(
                    why, "record_ref_inventory");
            }
        }
    }
    for (const auto& [cell, group_limb] :
         selected) {
        const uint32_t row = cell.first;
        const uint32_t slot = cell.second;
        const uint32_t group_address =
            group_limb.first;
        const uint32_t limb =
            group_limb.second;
        const auto end = ending.find(row);
        const bool emit =
            end != ending.end() &&
            end->second.address ==
                group_address;
        columns[
            emit
                ? layout.SourceEmitWeight(slot)
                : layout.SourceCarryWeight(slot)]
            [row] = LimbWeight(limb);
    }
    for (const auto& [row, group] : ending) {
        columns[layout.source_emit_active][row] =
            Fp3::One();
        columns[layout.source_emit_address][row] =
            U(group.address);
        columns[
            layout.source_emit_multiplicity][row] =
            U(group.multiplicity);
    }
    for (const auto& occurrence :
         plan.occurrences) {
        if (occurrence.slot >=
                kConsumerSlotsV1 ||
            occurrence.row >= plan.parent_rows) {
            return Fail(
                why, "consumer_ref");
        }
        columns[layout.ConsumerActive(
            occurrence.slot)]
            [occurrence.row] = Fp3::One();
        columns[layout.ConsumerAddress(
            occurrence.slot)]
            [occurrence.row] =
            U(occurrence.source_address);
    }

    Fp3 carry = Fp3::Zero();
    for (uint32_t row = 0;
         row < plan.parent_rows; ++row) {
        columns[layout.source_carry][row] =
            carry;
        Fp3 carry_contribution = Fp3::Zero();
        Fp3 emit_contribution = Fp3::Zero();
        for (uint32_t slot = 0;
             slot < kTapeSlotsV1; ++slot) {
            const Fp3 value =
                columns[
                    physical.tape_attachment
                        .ParentColumn(
                            tape_layout.Value(
                                slot))][row];
            carry_contribution = gf::Add(
                carry_contribution,
                gf::Mul(
                    columns[
                        layout.SourceCarryWeight(
                            slot)][row],
                    value));
            emit_contribution = gf::Add(
                emit_contribution,
                gf::Mul(
                    columns[
                        layout.SourceEmitWeight(
                            slot)][row],
                    value));
        }
        const bool emits = !gf::IsZero(
            columns[layout.source_emit_active][row]);
        if (emits) {
            columns[
                layout.source_emit_value][row] =
                gf::Add(
                    carry, emit_contribution);
            carry = carry_contribution;
        } else {
            carry = gf::Add(
                carry, carry_contribution);
        }
    }
    if (!gf::IsZero(carry)) {
        return Fail(why, "unterminated_source_stream");
    }
    return true;
}

uint64_t PhysicalMultisetMismatches(
    const qp::ProductV1& physical,
    const PlanV1& plan,
    const LayoutV1& layout,
    const std::vector<std::vector<Fp3>>& columns)
{
    std::map<uint32_t, Fp3> source_values;
    for (const auto& source : plan.sources) {
        source_values.emplace(
            source.address,
            columns[layout.source_emit_value]
                [source.row]);
    }
    uint64_t mismatches = 0;
    for (const auto& occurrence :
         plan.occurrences) {
        const auto found =
            source_values.find(
                occurrence.source_address);
        const uint32_t physical_column =
            physical.deep_attachment.ParentColumn(
                DeepColumnForKind(
                    physical.deep_plan.layout,
                    occurrence.kind));
        if (found == source_values.end() ||
            physical_column >= columns.size() ||
            !gf::Eq(
                found->second,
                columns[physical_column]
                    [occurrence.row])) {
            ++mismatches;
        }
    }
    return mismatches;
}

Fp3 SourceRowContribution(
    const std::vector<Fp3>& row,
    uint32_t tape_base,
    const LayoutV1& layout,
    bool emit)
{
    const auto tape_layout =
        tape::CanonicalLayoutV1();
    Fp3 out = Fp3::Zero();
    for (uint32_t slot = 0;
         slot < kTapeSlotsV1; ++slot) {
        out = gf::Add(
            out,
            gf::Mul(
                row[
                    emit
                        ? layout.SourceEmitWeight(
                            slot)
                        : layout.SourceCarryWeight(
                            slot)],
                row[tape_base +
                    tape_layout.Value(slot)]));
    }
    return out;
}

bool AppendBaseConstraints(
    const qp::ProductV1& physical,
    const LayoutV1& layout,
    AirCS& cs,
    std::string* why)
{
    if (cs.n_columns !=
            layout.original_columns) {
        return Fail(why, "base_boundary");
    }
    cs.n_columns = layout.dependent_base;
    const uint32_t tape_base =
        physical.tape_attachment.column_base;
    Add(
        cs, "stage3.v13.deep_stream.emit_boolean",
        aq::AirKind::kEverywhere, 2,
        [layout](const auto& cur, const auto&) {
            return gf::Mul(
                cur[layout.source_emit_active],
                gf::Sub(
                    cur[layout.source_emit_active],
                    Fp3::One()));
        });
    Add(
        cs, "stage3.v13.deep_stream.carry_first",
        aq::AirKind::kFirstRow, 1,
        [layout](const auto& cur, const auto&) {
            return cur[layout.source_carry];
        });
    const auto after =
        [tape_base, layout](
            const std::vector<Fp3>& row) {
            return gf::Add(
                gf::Mul(
                    gf::Sub(
                        Fp3::One(),
                        row[
                            layout
                                .source_emit_active]),
                    row[layout.source_carry]),
                SourceRowContribution(
                    row, tape_base,
                    layout, false));
        };
    Add(
        cs, "stage3.v13.deep_stream.carry_transition",
        aq::AirKind::kTransition, 2,
        [layout, after](
            const auto& cur, const auto& next) {
            return gf::Sub(
                next[layout.source_carry],
                after(cur));
        });
    Add(
        cs, "stage3.v13.deep_stream.carry_last",
        aq::AirKind::kLastRow, 2,
        [after](const auto& cur, const auto&) {
            return after(cur);
        });
    Add(
        cs, "stage3.v13.deep_stream.emit_value",
        aq::AirKind::kEverywhere, 2,
        [tape_base, layout](
            const auto& cur, const auto&) {
            return gf::Mul(
                cur[layout.source_emit_active],
                gf::Sub(
                    cur[layout.source_emit_value],
                    gf::Add(
                        cur[layout.source_carry],
                        SourceRowContribution(
                            cur, tape_base,
                            layout, true))));
        });
    Add(
        cs, "stage3.v13.deep_stream.emit_padding",
        aq::AirKind::kEverywhere, 2,
        [layout](const auto& cur, const auto&) {
            return gf::Mul(
                gf::Sub(
                    Fp3::One(),
                    cur[layout.source_emit_active]),
                cur[layout.source_emit_value]);
        });
    for (uint32_t slot = 0;
         slot < kConsumerSlotsV1; ++slot) {
        const uint32_t active =
            layout.ConsumerActive(slot);
        Add(
            cs,
            "stage3.v13.deep_stream.consumer_boolean",
            aq::AirKind::kEverywhere, 2,
            [active](const auto& cur, const auto&) {
                return gf::Mul(
                    cur[active],
                    gf::Sub(
                        cur[active],
                        Fp3::One()));
            });
        const auto kind =
            static_cast<ConsumerKindV1>(
                slot + 1);
        const uint32_t local_column =
            DeepColumnForKind(
                physical.deep_plan.layout, kind);
        const uint32_t physical_column =
            physical.deep_attachment.ParentColumn(
                local_column);
        if (local_column == UINT32_MAX ||
            physical_column >=
                layout.original_columns ||
            IsPreprocessed(cs, physical_column)) {
            return Fail(
                why, "ordinary_deep_consumer");
        }
    }
    return true;
}

Fp3 SourceCompressed(
    const std::vector<Fp3>& row,
    const LayoutV1& layout,
    const Fp3& gamma)
{
    return gf::Add(
        row[layout.source_emit_address],
        gf::Mul(
            gamma,
            row[layout.source_emit_value]));
}

Fp3 ConsumerCompressed(
    const std::vector<Fp3>& row,
    uint32_t deep_base,
    const dvm::LayoutV1& deep,
    const LayoutV1& layout,
    uint32_t slot,
    const Fp3& gamma)
{
    const auto kind =
        static_cast<ConsumerKindV1>(
            slot + 1);
    return gf::Add(
        row[layout.ConsumerAddress(slot)],
        gf::Mul(
            gamma,
            row[deep_base +
                DeepColumnForKind(deep, kind)]));
}

bool AppendFinalConstraints(
    const qp::ProductV1& physical,
    const ChallengesV1& challenges,
    const LayoutV1& layout,
    AirCS& cs,
    std::string* why)
{
    if (cs.n_columns != layout.dependent_base) {
        return Fail(why, "dependent_boundary");
    }
    cs.n_columns = layout.end;
    const uint32_t deep_base =
        physical.deep_attachment.column_base;
    const auto deep = physical.deep_plan.layout;
    for (uint32_t lane = 0;
         lane < kLookupLanesV1; ++lane) {
        const uint32_t source_inverse =
            layout.SourceInverse(lane);
        Add(
            cs, "stage3.v13.deep_stream.source_inverse",
            aq::AirKind::kEverywhere, 2,
            [challenges, layout, lane,
             source_inverse](
                const auto& cur, const auto&) {
                return gf::Sub(
                    gf::Mul(
                        cur[source_inverse],
                        gf::Sub(
                            challenges.alpha[lane],
                            SourceCompressed(
                                cur, layout,
                                challenges.gamma[
                                    lane]))),
                    cur[
                        layout.source_emit_active]);
            });
        Add(
            cs, "stage3.v13.deep_stream.source_padding",
            aq::AirKind::kEverywhere, 2,
            [layout, source_inverse](
                const auto& cur, const auto&) {
                return gf::Mul(
                    gf::Sub(
                        Fp3::One(),
                        cur[
                            layout
                                .source_emit_active]),
                    cur[source_inverse]);
            });
        for (uint32_t slot = 0;
             slot < kConsumerSlotsV1; ++slot) {
            const uint32_t inverse =
                layout.ConsumerInverse(
                    lane, slot);
            const uint32_t active =
                layout.ConsumerActive(slot);
            Add(
                cs,
                "stage3.v13.deep_stream."
                "consumer_inverse",
                aq::AirKind::kEverywhere, 2,
                [challenges, deep_base, deep,
                 layout, lane, slot,
                 inverse, active](
                    const auto& cur,
                    const auto&) {
                    return gf::Sub(
                        gf::Mul(
                            cur[inverse],
                            gf::Sub(
                                challenges.alpha[lane],
                                ConsumerCompressed(
                                    cur, deep_base,
                                    deep, layout,
                                    slot,
                                    challenges
                                        .gamma[lane]))),
                        cur[active]);
                });
            Add(
                cs,
                "stage3.v13.deep_stream."
                "consumer_padding",
                aq::AirKind::kEverywhere, 2,
                [inverse, active](
                    const auto& cur,
                    const auto&) {
                    return gf::Mul(
                        gf::Sub(
                            Fp3::One(),
                            cur[active]),
                        cur[inverse]);
                });
        }
        const uint32_t running =
            layout.Running(lane);
        const auto row_term =
            [layout, lane](
                const std::vector<Fp3>& row) {
                Fp3 term = gf::Mul(
                    row[
                        layout
                            .source_emit_multiplicity],
                    row[layout.SourceInverse(lane)]);
                for (uint32_t slot = 0;
                     slot < kConsumerSlotsV1;
                     ++slot) {
                    term = gf::Sub(
                        term,
                        gf::Mul(
                            row[
                                layout
                                    .ConsumerActive(
                                        slot)],
                            row[
                                layout
                                    .ConsumerInverse(
                                        lane,
                                        slot)]));
                }
                return term;
            };
        Add(
            cs, "stage3.v13.deep_stream.running_first",
            aq::AirKind::kFirstRow, 1,
            [running](const auto& cur, const auto&) {
                return cur[running];
            });
        Add(
            cs,
            "stage3.v13.deep_stream.running_transition",
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
            cs, "stage3.v13.deep_stream.running_last",
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
    const qp::ProductV1& physical,
    const ChallengesV1& challenges,
    const LayoutV1& layout,
    std::vector<std::vector<Fp3>>& columns,
    std::string* why)
{
    const uint32_t deep_base =
        physical.deep_attachment.column_base;
    const auto deep = physical.deep_plan.layout;
    const uint32_t rows =
        static_cast<uint32_t>(
            columns.front().size());
    for (uint32_t lane = 0;
         lane < kLookupLanesV1; ++lane) {
        Fp3 running = Fp3::Zero();
        for (uint32_t row = 0;
             row < rows; ++row) {
            columns[layout.Running(lane)][row] =
                running;
            std::vector<Fp3> current(columns.size());
            for (uint32_t column = 0;
                 column < columns.size(); ++column) {
                current[column] =
                    columns[column][row];
            }
            if (!gf::IsZero(
                    current[
                        layout
                            .source_emit_active])) {
                const Fp3 denominator =
                    gf::Sub(
                        challenges.alpha[lane],
                        SourceCompressed(
                            current, layout,
                            challenges.gamma[lane]));
                if (gf::IsZero(denominator)) {
                    return Fail(
                        why, "source_zero_denominator");
                }
                const Fp3 inverse =
                    gf::Inv(denominator);
                columns[
                    layout.SourceInverse(lane)]
                    [row] = inverse;
                running = gf::Add(
                    running,
                    gf::Mul(
                        current[
                            layout
                                .source_emit_multiplicity],
                        inverse));
            }
            for (uint32_t slot = 0;
                 slot < kConsumerSlotsV1; ++slot) {
                if (gf::IsZero(
                        current[
                            layout.ConsumerActive(
                                slot)])) {
                    continue;
                }
                const Fp3 denominator =
                    gf::Sub(
                        challenges.alpha[lane],
                        ConsumerCompressed(
                            current, deep_base,
                            deep, layout, slot,
                            challenges.gamma[lane]));
                if (gf::IsZero(denominator)) {
                    return Fail(
                        why,
                        "consumer_zero_denominator");
                }
                const Fp3 inverse =
                    gf::Inv(denominator);
                columns[
                    layout.ConsumerInverse(
                        lane, slot)][row] =
                    inverse;
                running = gf::Sub(
                    running, inverse);
            }
        }
        if (!gf::IsZero(running)) {
            return Fail(why, "terminal_nonzero");
        }
    }
    return true;
}

void AddRelationPreprocessed(
    const LayoutV1& layout,
    AirCS& cs,
    const std::vector<std::vector<Fp3>>& columns)
{
    AddPreprocessed(
        cs, layout.source_emit_active,
        columns[layout.source_emit_active]);
    AddPreprocessed(
        cs, layout.source_emit_address,
        columns[layout.source_emit_address]);
    AddPreprocessed(
        cs, layout.source_emit_multiplicity,
        columns[layout.source_emit_multiplicity]);
    for (uint32_t slot = 0;
         slot < kTapeSlotsV1; ++slot) {
        AddPreprocessed(
            cs, layout.SourceCarryWeight(slot),
            columns[
                layout.SourceCarryWeight(slot)]);
        AddPreprocessed(
            cs, layout.SourceEmitWeight(slot),
            columns[
                layout.SourceEmitWeight(slot)]);
    }
    for (uint32_t slot = 0;
         slot < kConsumerSlotsV1; ++slot) {
        AddPreprocessed(
            cs, layout.ConsumerActive(slot),
            columns[layout.ConsumerActive(slot)]);
        AddPreprocessed(
            cs, layout.ConsumerAddress(slot),
            columns[layout.ConsumerAddress(slot)]);
    }
    cs.preprocessed_pin_ood = true;
}

bool FinalizeParent(
    const qp::ProductV1& physical,
    const uint256& public_seed,
    ProductV1& out,
    std::string* why)
{
    if (!AppendBaseConstraints(
            physical, out.layout,
            out.cs, why)) {
        return false;
    }
    AddRelationPreprocessed(
        out.layout, out.cs, out.columns);
    out.r0_base_column_indices.resize(
        out.layout.dependent_base);
    std::iota(
        out.r0_base_column_indices.begin(),
        out.r0_base_column_indices.end(),
        0U);
    out.r0_session =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            out.cs, out.columns,
            out.r0_base_column_indices);
    if (!out.r0_session.valid ||
        out.r0_session.base_row_commitment.IsNull()) {
        return Fail(why, "parent_r0");
    }
    out.cs.preprocessed_row_group_roots.clear();
    out.cs.preprocessed_row_group_roots.push_back({
        .version = 1,
        .role =
            aq::AirPreprocessedRowGroupRole::kR0,
        .ordered_columns =
            out.r0_base_column_indices,
        .root =
            out.r0_session.base_row_commitment,
    });
    if (!DeriveChallenges(
            out.plan, public_seed,
            out.r0_session.base_row_commitment,
            out.challenges, why) ||
        !AppendFinalConstraints(
            physical, out.challenges,
            out.layout, out.cs, why)) {
        return false;
    }
    out.columns.resize(
        out.layout.end,
        std::vector<Fp3>(
            out.cs.n_rows, Fp3::Zero()));
    return true;
}

bool Applies(
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

} // namespace

bool BuildProductV1(
    const tape::ProductV1& tape_product,
    const dvm::ProductV1& deep_product,
    const cb::ProgramTable& child_program,
    const alg_hash::Digest& expected_program_root,
    const rv::QueryRangeV1& range,
    const uint256& public_seed,
    ProductV1& out,
    std::string* why)
{
    out = {};
    qp::ProductV1 physical;
    if (!qp::BuildProductV1(
            tape_product, deep_product,
            child_program,
            expected_program_root,
            range, physical, why) ||
        !BuildPlan(
            tape_product, physical,
            range, out.plan, why)) {
        out = {};
        return false;
    }
    out.layout =
        CanonicalLayout(physical.cs.n_columns);
    out.cs = physical.cs;
    out.columns = std::move(physical.columns);
    out.columns.resize(
        out.layout.dependent_base,
        std::vector<Fp3>(
            out.cs.n_rows, Fp3::Zero()));
    if (!MaterializeBase(
            physical, out.plan,
            TapeRefs(tape_product),
            out.layout, out.columns, why)) {
        out = {};
        return false;
    }
    out.violations =
        physical.violations +
        PhysicalMultisetMismatches(
            physical, out.plan,
            out.layout, out.columns);
    // This deterministic precheck is only an early reject. Consensus
    // soundness remains the proof-owned dual-Fp3 LogUp below.
    if (out.violations != 0) {
        out.note =
            "stage3:v13_deep_source_logup_parent:"
            "physical_multiset_precheck_reject";
        return Fail(
            why, "physical_multiset_precheck");
    }
    if (!FinalizeParent(
            physical, public_seed,
            out, why)) {
        out = {};
        return false;
    }
    if (!FillFinalWitness(
            physical, out.challenges,
            out.layout, out.columns, why)) {
        out = {};
        return false;
    }

    out.violations = physical.violations;
    // MaterializeBase directly evaluates the source stream from physical
    // tape cells. FillFinalWitness refuses either non-invertible lookup or a
    // non-zero terminal. Child products were independently exact before
    // attachment, so no second full-domain callback scan is needed here.
    out.every_occurrence_materialized =
        out.plan.exact_multiplicities &&
        out.plan.source_multiplicity_sum ==
            out.plan.occurrences.size();
    out.fp3_limb_reconstruction_constrained = true;
    out.canonical_u32_and_goldilocks_constrained =
        tape_product.canonical_u32_decomposition_air &&
        tape_product.canonical_fp_pairs_air;
    out.exact_source_multiplicity_constrained =
        out.plan.exact_multiplicities;
    out.physical_tape_stream_consumed =
        out.layout.end -
            out.layout.original_columns ==
        kAdditionalColumnsV1;
    out.challenges_after_complete_r0 =
        out.r0_session.valid;
    out.dual_fp3_terminal_cancelled = true;
    out.first_fold_owned_by_merkle_parent = true;
    out.recursively_consumed = false;
    out.recursive_authority_ready = false;
    out.valid =
        out.violations == 0 &&
        out.every_occurrence_materialized &&
        out.fp3_limb_reconstruction_constrained &&
        out.canonical_u32_and_goldilocks_constrained &&
        out.exact_source_multiplicity_constrained &&
        out.physical_tape_stream_consumed &&
        out.challenges_after_complete_r0 &&
        out.dual_fp3_terminal_cancelled &&
        out.first_fold_owned_by_merkle_parent &&
        !out.recursively_consumed &&
        !out.recursive_authority_ready;
    out.note = out.valid
        ? "stage3:v13_deep_source_logup_parent:"
          "physical_tape_stream_consumed;"
          "57_column_delta;"
          "recursive_consumption_pending"
        : "stage3:v13_deep_source_logup_parent:"
          "stream_relation_invalid";
    if (!out.valid) {
        return Fail(why, "invariant");
    }
    if (why != nullptr) *why = out.note;
    return true;
}

uint64_t CountViolationsV1(
    const AirCS& cs,
    const std::vector<std::vector<Fp3>>& columns)
{
    if (cs.n_rows < 2 ||
        columns.size() != cs.n_columns) {
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
            current[column] =
                columns[column][row];
            next[column] =
                columns[column][next_row];
        }
        for (const auto& constraint :
             cs.constraints) {
            if (Applies(
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

ProductV1 BuildBoundedCanaryV1(
    CanaryMutationV1 mutation,
    const uint256& public_seed,
    std::string* why)
{
    ProductV1 out;
    qp::ProductV1 physical;
    const auto tape_layout =
        tape::CanonicalLayoutV1();
    const auto deep_layout =
        dvm::CanonicalLayoutV1();
    physical.deep_plan.layout = deep_layout;
    physical.tape_attachment.column_base = 0;
    physical.tape_attachment.semantic_child_columns =
        tape_layout.End();
    physical.tape_attachment.valid = true;
    physical.deep_attachment.column_base =
        tape_layout.End();
    physical.deep_attachment.semantic_child_columns =
        deep_layout.n_columns;
    physical.deep_attachment.valid = true;
    physical.cs.n_rows = 8;

    // A bounded copy of the tape AIR's load-bearing canonical pair check.
    // The production parent consumes the complete tape AIR instead.
    const uint32_t pair_base =
        physical.deep_attachment.column_base +
        deep_layout.n_columns;
    const uint32_t low_bits = pair_base;
    const uint32_t high_bits = low_bits + 32;
    const uint32_t high_is_max = high_bits + 32;
    const uint32_t high_inverse = high_is_max + 1;
    const uint32_t pair_active = high_inverse + 1;
    physical.cs.n_columns = pair_active + 1;
    physical.columns.assign(
        physical.cs.n_columns,
        std::vector<Fp3>(
            physical.cs.n_rows,
            Fp3::Zero()));
    const uint32_t source_row = 3;
    const uint32_t low_column =
        tape_layout.Value(0);
    const uint32_t high_column =
        tape_layout.Value(1);
    for (uint32_t half = 0; half < 2; ++half) {
        const uint32_t value_column =
            half == 0 ? low_column : high_column;
        const uint32_t bits =
            half == 0 ? low_bits : high_bits;
        for (uint32_t bit = 0; bit < 32; ++bit) {
            Add(
                physical.cs,
                "test.v13.deep_stream.tape_bit",
                aq::AirKind::kEverywhere, 3,
                [bits, bit, pair_active](
                    const auto& cur,
                    const auto&) {
                    return gf::Mul(
                        cur[pair_active],
                        gf::Mul(
                            cur[bits + bit],
                            gf::Sub(
                                cur[bits + bit],
                                Fp3::One())));
                });
        }
        Add(
            physical.cs,
            "test.v13.deep_stream.tape_u32",
            aq::AirKind::kEverywhere, 2,
            [value_column, bits, pair_active](
                const auto& cur,
                const auto&) {
                Fp3 sum = Fp3::Zero();
                uint64_t weight = 1;
                for (uint32_t bit = 0;
                     bit < 32; ++bit) {
                    sum = gf::Add(
                        sum,
                        gf::Mul(
                            U(weight),
                            cur[bits + bit]));
                    weight <<= 1;
                }
                return gf::Mul(
                    cur[pair_active],
                    gf::Sub(
                        cur[value_column], sum));
            });
    }
    Add(
        physical.cs,
        "test.v13.deep_stream.high_zero_test",
        aq::AirKind::kEverywhere, 3,
        [high_column, high_is_max,
         high_inverse, pair_active](
            const auto& cur, const auto&) {
            return gf::Mul(
                cur[pair_active],
                gf::Sub(
                    gf::Mul(
                        gf::Sub(
                            U(UINT32_MAX),
                            cur[high_column]),
                        cur[high_inverse]),
                    gf::Sub(
                        Fp3::One(),
                        cur[high_is_max])));
        });
    Add(
        physical.cs,
        "test.v13.deep_stream.high_forward",
        aq::AirKind::kEverywhere, 3,
        [high_column, high_is_max,
         pair_active](
            const auto& cur, const auto&) {
            return gf::Mul(
                cur[pair_active],
                gf::Mul(
                    gf::Sub(
                        U(UINT32_MAX),
                        cur[high_column]),
                    cur[high_is_max]));
        });
    Add(
        physical.cs,
        "test.v13.deep_stream.pair_canonical",
        aq::AirKind::kEverywhere, 3,
        [low_column, high_is_max,
         pair_active](
            const auto& cur, const auto&) {
            return gf::Mul(
                cur[pair_active],
                gf::Mul(
                    cur[low_column],
                    cur[high_is_max]));
        });

    out.layout =
        CanonicalLayout(physical.cs.n_columns);
    out.cs = physical.cs;
    out.columns = physical.columns;
    out.columns.resize(
        out.layout.dependent_base,
        std::vector<Fp3>(
            out.cs.n_rows, Fp3::Zero()));

    const uint32_t first_address = 17;
    const uint32_t consumer_row = 1;
    const uint32_t duplicate_row = 6;
    Fp3 consumer_value{17, 19, 23};
    std::array<uint32_t, 6> limbs{
        17, 0, 19, 0, 23, 0};
    if (mutation ==
            CanaryMutationV1::GoldilocksAliasXp) {
        consumer_value = Fp3{7, 19, 23};
        limbs[0] = 8;
        limbs[1] = UINT32_MAX;
    }
    out.columns[
        physical.deep_attachment.ParentColumn(
            deep_layout.current_value)]
        [consumer_row] = consumer_value;

    std::map<uint32_t, RecordRef> refs;
    for (uint32_t limb = 0;
         limb < kFieldLimbsV1; ++limb) {
        const uint32_t row =
            source_row + limb / kTapeSlotsV1;
        const uint32_t slot =
            limb % kTapeSlotsV1;
        const uint32_t address =
            first_address + limb;
        refs.emplace(address, RecordRef{row, slot});
        out.columns[
            tape_layout.Address(slot)][row] =
            U(address);
        uint32_t value = limbs[limb];
        if (mutation ==
                CanaryMutationV1::
                    Fp3LimbSubstitution &&
            limb == 0) {
            ++value;
        }
        out.columns[
            tape_layout.Value(slot)][row] =
            U(value);
    }
    const uint32_t low =
        static_cast<uint32_t>(
            out.columns[low_column][source_row].c0);
    const uint32_t high =
        static_cast<uint32_t>(
            out.columns[high_column][source_row].c0);
    out.columns[pair_active][source_row] =
        Fp3::One();
    for (uint32_t bit = 0; bit < 32; ++bit) {
        out.columns[low_bits + bit][source_row] =
            U((low >> bit) & 1U);
        out.columns[high_bits + bit][source_row] =
            U((high >> bit) & 1U);
    }
    const uint32_t delta = UINT32_MAX - high;
    const bool is_max = delta == 0;
    out.columns[high_is_max][source_row] =
        U(is_max ? 1 : 0);
    out.columns[high_inverse][source_row] =
        is_max
        ? Fp3::Zero()
        : gf::Inv(U(delta));

    out.plan.version = kVersionV1;
    out.plan.shape = {
        .trace_rows = 8,
        .trace_columns = 1,
        .quotient_len = 8,
        .n_coeffs = 8,
        .base_column_indices = {0},
    };
    out.plan.range = {
        .ordinal = 0,
        .first_query = 0,
        .query_count = 1,
    };
    out.plan.parent_rows = 8;
    out.plan.tape_column_base = 0;
    out.plan.deep_column_base =
        physical.deep_attachment.column_base;
    out.plan.occurrences.push_back({
        .kind = ConsumerKindV1::DeepCurrent,
        .query = 0,
        .item = 0,
        .row = consumer_row,
        .slot = KindSlot(
            ConsumerKindV1::DeepCurrent),
        .consumer_column =
            deep_layout.current_value,
        .key =
            Key(
                abi::FieldKindV1::QueryRowValue,
                0, 0, 0),
        .source_address = first_address,
    });
    out.plan.sources.push_back({
        .address = first_address,
        .multiplicity = 1,
        .row =
            refs[first_address + 5].row,
        .slot =
            refs[first_address + 5].slot,
    });
    out.plan.limb_occurrences = 6;
    out.plan.source_multiplicity_sum = 1;
    out.plan.exact_structural_rows = true;
    out.plan.exact_v13_addresses = true;
    out.plan.exact_multiplicities = true;
    out.plan.proof_values_excluded = true;
    out.plan.plan_root = CommitPlan(out.plan);
    out.plan.valid = true;

    if (!MaterializeBase(
            physical, out.plan, refs,
            out.layout, out.columns, why)) {
        out.note = "bounded_materialize_failed";
        return out;
    }
    const uint32_t consumer_slot =
        KindSlot(ConsumerKindV1::DeepCurrent);
    if (mutation ==
            CanaryMutationV1::OmitOccurrence) {
        out.columns[
            out.layout.ConsumerActive(
                consumer_slot)][consumer_row] =
            Fp3::Zero();
    } else if (
        mutation ==
            CanaryMutationV1::ReaddressOccurrence) {
        out.columns[
            out.layout.ConsumerAddress(
                consumer_slot)][consumer_row] =
            U(first_address + 1);
    } else if (
        mutation ==
            CanaryMutationV1::DuplicateOccurrence) {
        out.columns[
            physical.deep_attachment.ParentColumn(
                deep_layout.current_value)]
            [duplicate_row] = consumer_value;
        out.columns[
            out.layout.ConsumerActive(
                consumer_slot)][duplicate_row] =
            Fp3::One();
        out.columns[
            out.layout.ConsumerAddress(
                consumer_slot)][duplicate_row] =
            U(first_address);
    }

    if (!FinalizeParent(
            physical, public_seed, out, why)) {
        out.note = "bounded_finalize_failed";
        return out;
    }
    std::string terminal_why;
    const bool terminal_ok =
        FillFinalWitness(
            physical, out.challenges,
            out.layout, out.columns,
            &terminal_why);
    out.violations =
        CountViolationsV1(
            out.cs, out.columns);
    out.every_occurrence_materialized =
        mutation == CanaryMutationV1::Honest;
    out.fp3_limb_reconstruction_constrained = true;
    out.canonical_u32_and_goldilocks_constrained =
        true;
    out.exact_source_multiplicity_constrained =
        true;
    out.physical_tape_stream_consumed =
        out.layout.end -
            out.layout.original_columns ==
        kAdditionalColumnsV1;
    out.challenges_after_complete_r0 = true;
    out.dual_fp3_terminal_cancelled =
        terminal_ok && out.violations == 0;
    out.recursively_consumed = false;
    out.recursive_authority_ready = false;
    out.valid =
        mutation == CanaryMutationV1::Honest &&
        out.violations == 0 &&
        out.dual_fp3_terminal_cancelled;
    out.note = out.valid
        ? "stage3:v13_deep_source_logup_parent:"
          "bounded_stream_exact"
        : "stage3:v13_deep_source_logup_parent:"
          "bounded_stream_rejected:" +
              terminal_why;
    if (why != nullptr) *why = out.note;
    return out;
}

} // namespace matmul::v4::rc::stage3_v13_deep_source_logup_parent
