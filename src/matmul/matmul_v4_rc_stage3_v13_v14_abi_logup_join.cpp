// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_v13_v14_abi_logup_join.h>

#include <matmul/matmul_v4_rc_stage3_safe_v12.h>

#include <algorithm>
#include <array>
#include <functional>
#include <limits>
#include <map>
#include <set>
#include <tuple>
#include <utility>

namespace matmul::v4::rc::stage3_v13_v14_abi_logup_join {
namespace {

namespace aht = alg_hash_typed;
namespace safe = safe_v12;
using gf::Fp3;
using AirCS = aq::AirConstraintSystem<Fp3>;

constexpr uint32_t kPlanMagicV1 = UINT32_C(0x314a4241); // "ABJ1"
constexpr uint32_t kChallengeCandidatesV1 = 8;
constexpr uint64_t kU32Bound = uint64_t{1} << 32;

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:v13_v14_abi_logup_join:" + detail;
    }
    return false;
}

Fp3 U(uint64_t value)
{
    return gf::FromU64_3(value);
}

bool Canonical(const Fp3& value)
{
    return value.c0 < gf::kP &&
        value.c1 < gf::kP &&
        value.c2 < gf::kP;
}

bool PowerOfTwo(uint32_t value)
{
    return value >= 2 &&
        (value & (value - 1)) == 0;
}

bool ValidCell(const CellRefV1& cell, const AirCS& cs)
{
    return cell.row < cs.n_rows &&
        cell.column < cs.n_columns;
}

bool Contains(
    const std::vector<uint32_t>& ordered,
    uint32_t value)
{
    return std::binary_search(
        ordered.begin(), ordered.end(), value);
}

bool StrictlyIncreasing(
    const std::vector<uint32_t>& values,
    uint32_t upper_bound)
{
    if (values.empty()) return false;
    uint32_t previous = 0;
    for (uint32_t index = 0;
         index < values.size(); ++index) {
        if (values[index] >= upper_bound ||
            (index != 0 &&
             values[index] <= previous)) {
            return false;
        }
        previous = values[index];
    }
    return true;
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
    cs.constraints.push_back({
        name, kind, degree, std::move(eval)});
}

void AddPreprocessed(
    AirCS& cs,
    std::vector<std::vector<Fp3>>* columns,
    uint32_t column,
    std::vector<Fp3> values)
{
    if (columns != nullptr) {
        (*columns)[column] = values;
    }
    cs.preprocessed.push_back({
        column, std::move(values)});
}

bool SamePlan(const PlanV1& left, const PlanV1& right)
{
    return left.version == right.version &&
        left.shape == right.shape &&
        left.v14_program_root ==
            right.v14_program_root &&
        left.parent_rows == right.parent_rows &&
        left.tape_column_offset ==
            right.tape_column_offset &&
        left.v14_column_offset ==
            right.v14_column_offset &&
        left.sources == right.sources &&
        left.consumers == right.consumers &&
        left.unique_source_bytes ==
            right.unique_source_bytes &&
        left.consumer_occurrences ==
            right.consumer_occurrences &&
        left.source_multiplicity_sum ==
            right.source_multiplicity_sum &&
        left.plan_root == right.plan_root &&
        left.exact_manifest_rebuild ==
            right.exact_manifest_rebuild &&
        left.exact_physical_cell_map ==
            right.exact_physical_cell_map &&
        left.exact_multiplicity_accounting ==
            right.exact_multiplicity_accounting &&
        left.valid == right.valid;
}

void AppendDigest(
    std::vector<gf::Fp>& lanes,
    const alg_hash::Digest& digest)
{
    lanes.insert(
        lanes.end(), digest.begin(), digest.end());
}

void AppendUint256U32(
    std::vector<gf::Fp>& lanes,
    const uint256& value)
{
    for (uint32_t word = 0; word < 8; ++word) {
        uint32_t limb = 0;
        for (uint32_t byte = 0; byte < 4; ++byte) {
            limb |=
                static_cast<uint32_t>(
                    value.data()[4 * word + byte])
                << (8 * byte);
        }
        lanes.push_back(gf::FromU64(limb));
    }
}

alg_hash::Digest CommitPlan(const PlanV1& plan)
{
    std::vector<gf::Fp> lanes;
    lanes.reserve(
        16 + 9 * plan.sources.size() +
        7 * plan.consumers.size());
    lanes.push_back(gf::FromU64(kPlanMagicV1));
    lanes.push_back(gf::FromU64(plan.version));
    lanes.push_back(gf::FromU64(plan.shape.trace_rows));
    lanes.push_back(
        gf::FromU64(plan.shape.trace_columns));
    lanes.push_back(
        gf::FromU64(plan.shape.quotient_len));
    lanes.push_back(gf::FromU64(plan.shape.n_coeffs));
    lanes.push_back(
        gf::FromU64(plan.parent_rows));
    lanes.push_back(
        gf::FromU64(plan.tape_column_offset));
    lanes.push_back(
        gf::FromU64(plan.v14_column_offset));
    lanes.push_back(
        gf::FromU64(plan.shape.base_column_indices.size()));
    for (uint32_t column :
         plan.shape.base_column_indices) {
        lanes.push_back(gf::FromU64(column));
    }
    AppendDigest(lanes, plan.v14_program_root);
    lanes.push_back(
        gf::FromU64(plan.sources.size()));
    lanes.push_back(
        gf::FromU64(plan.consumers.size()));
    for (const auto& source : plan.sources) {
        lanes.push_back(
            gf::FromU64(source.abi_address));
        lanes.push_back(
            gf::FromU64(source.byte_in_word));
        lanes.push_back(
            gf::FromU64(source.multiplicity));
        lanes.push_back(
            gf::FromU64(source.lookup_slot));
        lanes.push_back(
            gf::FromU64(source.address.column));
        lanes.push_back(
            gf::FromU64(source.address.row));
        lanes.push_back(
            gf::FromU64(source.value.column));
        lanes.push_back(
            gf::FromU64(source.value.row));
        for (const auto& bit : source.byte_bits) {
            lanes.push_back(gf::FromU64(bit.column));
            lanes.push_back(gf::FromU64(bit.row));
        }
    }
    for (const auto& consumer : plan.consumers) {
        lanes.push_back(
            gf::FromU64(consumer.abi_address));
        lanes.push_back(
            gf::FromU64(consumer.byte_in_abi_word));
        lanes.push_back(
            gf::FromU64(consumer.byte_in_message_word));
        lanes.push_back(
            gf::FromU64(consumer.lookup_slot));
        lanes.push_back(
            gf::FromU64(consumer.message.column));
        lanes.push_back(
            gf::FromU64(consumer.message.row));
    }
    alg_hash::Digest out{};
    if (!aht::SpongeHashFpV12(
            aht::RoleV12::ProgramTableCommitment,
            lanes, out)) {
        return {};
    }
    return out;
}

bool ValidPlan(const PlanV1& plan)
{
    if (plan.version !=
            kAbiLogUpJoinVersionV1 ||
        !PowerOfTwo(plan.parent_rows) ||
        plan.v14_program_root ==
            alg_hash::Digest{} ||
        plan.plan_root ==
            alg_hash::Digest{} ||
        plan.sources.empty() ||
        plan.consumers.empty() ||
        plan.unique_source_bytes !=
            plan.sources.size() ||
        plan.consumer_occurrences !=
            plan.consumers.size() ||
        plan.source_multiplicity_sum !=
            plan.consumers.size() ||
        !plan.exact_manifest_rebuild ||
        !plan.exact_physical_cell_map ||
        !plan.exact_multiplicity_accounting ||
        !plan.valid) {
        return false;
    }
    uint64_t multiplicity_sum = 0;
    std::set<
        std::pair<uint32_t, uint32_t>>
        source_positions;
    std::set<
        std::pair<uint32_t, uint32_t>>
        consumer_positions;
    const auto tape_layout =
        tape::CanonicalLayoutV1();
    const bridge::TypedSafeDirectParentLayoutV14
        v14_layout;
    for (const auto& source : plan.sources) {
        const uint32_t record =
            tape::kPublicPrefixRecordsV1 +
            tape::kHeaderRecordsV1 +
            source.abi_address;
        const uint32_t expected_row =
            record / tape::kRecordsPerRowV1;
        const uint32_t record_slot =
            record % tape::kRecordsPerRowV1;
        const uint32_t expected_lookup_slot =
            4 * record_slot +
            source.byte_in_word;
        if (source.abi_address == UINT32_MAX ||
            source.byte_in_word >= 4 ||
            source.multiplicity == 0 ||
            expected_row >= plan.parent_rows ||
            source.lookup_slot !=
                expected_lookup_slot ||
            source.address != CellRefV1{
                plan.tape_column_offset +
                    tape_layout.Address(
                        record_slot),
                expected_row} ||
            source.value != CellRefV1{
                plan.tape_column_offset +
                    tape_layout.Value(
                        record_slot),
                expected_row} ||
            !source_positions.insert({
                source.address.row,
                source.lookup_slot}).second) {
            return false;
        }
        for (uint32_t bit = 0;
             bit < source.byte_bits.size(); ++bit) {
            if (source.byte_bits[bit] != CellRefV1{
                    plan.tape_column_offset +
                        tape_layout.Bit(
                            record_slot,
                            8 * source.byte_in_word +
                                bit),
                    expected_row}) {
                return false;
            }
        }
        multiplicity_sum += source.multiplicity;
    }
    for (const auto& consumer : plan.consumers) {
        const uint32_t lane =
            consumer.lookup_slot / 4;
        if (consumer.abi_address == UINT32_MAX ||
            consumer.byte_in_abi_word >= 4 ||
            consumer.byte_in_message_word >= 4 ||
            consumer.lookup_slot >=
                kConsumerByteSlotsPerRowV1 ||
            consumer.lookup_slot % 4 !=
                consumer.byte_in_message_word ||
            consumer.message.row >=
                plan.parent_rows ||
            consumer.message != CellRefV1{
                plan.v14_column_offset +
                    v14_layout.Message(lane),
                consumer.message.row} ||
            !consumer_positions.insert({
                consumer.message.row,
                consumer.lookup_slot}).second) {
            return false;
        }
    }
    return multiplicity_sum ==
            plan.source_multiplicity_sum &&
        CommitPlan(plan) == plan.plan_root;
}

bool PlanRefsValid(
    const PlanV1& plan,
    const AirCS& cs,
    const std::vector<uint32_t>& base_indices)
{
    if (cs.n_rows != plan.parent_rows ||
        !StrictlyIncreasing(
            base_indices, cs.n_columns)) {
        return false;
    }
    for (const auto& source : plan.sources) {
        if (!ValidCell(source.address, cs) ||
            !ValidCell(source.value, cs) ||
            !Contains(
                base_indices,
                source.address.column) ||
            !Contains(
                base_indices,
                source.value.column)) {
            return false;
        }
        for (const auto& bit : source.byte_bits) {
            if (!ValidCell(bit, cs) ||
                !Contains(base_indices, bit.column)) {
                return false;
            }
        }
    }
    for (const auto& consumer : plan.consumers) {
        if (!ValidCell(consumer.message, cs) ||
            !Contains(
                base_indices,
                consumer.message.column)) {
            return false;
        }
    }
    return true;
}

LayoutV1 CanonicalLayout(
    uint32_t original_columns)
{
    LayoutV1 out;
    out.original_columns = original_columns;
    out.consumer_bit_base = original_columns;
    out.consumer_decompose_mask_base =
        out.consumer_bit_base +
        safe_v12::kSafeRateV12 * 32;
    out.source_active_base =
        out.consumer_decompose_mask_base +
        safe_v12::kSafeRateV12;
    out.source_multiplicity_base =
        out.source_active_base +
        kSourceByteSlotsPerRowV1;
    out.consumer_active_base =
        out.source_multiplicity_base +
        kSourceByteSlotsPerRowV1;
    out.consumer_key_base =
        out.consumer_active_base +
        kConsumerByteSlotsPerRowV1;
    out.dependent_base =
        out.consumer_key_base +
        kConsumerByteSlotsPerRowV1;
    out.source_inverse_base =
        out.dependent_base;
    out.consumer_inverse_base =
        out.source_inverse_base +
        kLookupLanesV1 *
            kSourceByteSlotsPerRowV1;
    out.running_base =
        out.consumer_inverse_base +
        kLookupLanesV1 *
            kConsumerByteSlotsPerRowV1;
    out.end =
        out.running_base + kLookupLanesV1;
    return out;
}

LayoutV1 RelocateDependentLayout(
    const LayoutV1& base,
    uint32_t dependent_column_base)
{
    LayoutV1 out = base;
    out.dependent_base =
        dependent_column_base;
    out.source_inverse_base =
        out.dependent_base;
    out.consumer_inverse_base =
        out.source_inverse_base +
        kLookupLanesV1 *
            kSourceByteSlotsPerRowV1;
    out.running_base =
        out.consumer_inverse_base +
        kLookupLanesV1 *
            kConsumerByteSlotsPerRowV1;
    out.end =
        out.running_base + kLookupLanesV1;
    return out;
}

Fp3 SourceByte(
    const std::vector<Fp3>& row,
    const PlanV1& plan,
    uint32_t slot)
{
    const auto tape_layout =
        tape::CanonicalLayoutV1();
    const uint32_t record_slot = slot / 4;
    const uint32_t byte = slot % 4;
    Fp3 out = Fp3::Zero();
    uint64_t weight = 1;
    for (uint32_t bit = 0; bit < 8; ++bit) {
        out = gf::Add(
            out,
            gf::Mul(
                U(weight),
                row[
                    plan.tape_column_offset +
                    tape_layout.Bit(
                        record_slot,
                        8 * byte + bit)]));
        weight <<= 1;
    }
    return out;
}

Fp3 SourceAddress(
    const std::vector<Fp3>& row,
    const PlanV1& plan,
    uint32_t slot)
{
    const auto tape_layout =
        tape::CanonicalLayoutV1();
    return row[
        plan.tape_column_offset +
        tape_layout.Address(slot / 4)];
}

Fp3 ConsumerByte(
    const std::vector<Fp3>& row,
    const LayoutV1& layout,
    uint32_t slot)
{
    const uint32_t lane = slot / 4;
    const uint32_t byte = slot % 4;
    Fp3 out = Fp3::Zero();
    uint64_t weight = 1;
    for (uint32_t bit = 0; bit < 8; ++bit) {
        out = gf::Add(
            out,
            gf::Mul(
                U(weight),
                row[layout.ConsumerBit(
                    lane, 8 * byte + bit)]));
        weight <<= 1;
    }
    return out;
}

Fp3 SourceCompressed(
    const std::vector<Fp3>& row,
    const PlanV1& plan,
    uint32_t slot,
    const Fp3& gamma)
{
    const Fp3 key = gf::Add(
        gf::Mul(U(4), SourceAddress(
            row, plan, slot)),
        U(slot % 4));
    return gf::Add(
        key,
        gf::Mul(
            gamma,
            SourceByte(row, plan, slot)));
}

Fp3 ConsumerCompressed(
    const std::vector<Fp3>& row,
    const LayoutV1& layout,
    uint32_t slot,
    const Fp3& gamma)
{
    return gf::Add(
        row[layout.ConsumerKey(slot)],
        gf::Mul(
            gamma,
            ConsumerByte(row, layout, slot)));
}

bool AppendBaseCs(
    const PlanV1& plan,
    AirCS& cs,
    std::vector<std::vector<Fp3>>* columns,
    LayoutV1& layout,
    std::string* why)
{
    if (!ValidPlan(plan) ||
        cs.n_rows != plan.parent_rows ||
        cs.n_columns == 0 ||
        (columns != nullptr &&
         columns->size() != cs.n_columns)) {
        return Fail(why, "base_shape");
    }
    if (columns != nullptr) {
        for (const auto& column : *columns) {
            if (column.size() != cs.n_rows) {
                return Fail(why, "base_column_rows");
            }
        }
    }
    layout = CanonicalLayout(cs.n_columns);
    cs.n_columns = layout.dependent_base;
    if (columns != nullptr) {
        columns->resize(
            cs.n_columns,
            std::vector<Fp3>(
                cs.n_rows, Fp3::Zero()));
    }
    // Every schedule column below is verifier-owned.  The generic row-wise
    // verifier therefore requires their z1/z2 evaluations to be checked
    // against the exact regenerated fixed polynomials.
    cs.preprocessed_pin_ood = true;

    std::array<std::vector<Fp3>,
               safe_v12::kSafeRateV12>
        decompose_mask;
    std::array<std::vector<Fp3>,
               kSourceByteSlotsPerRowV1>
        source_active;
    std::array<std::vector<Fp3>,
               kSourceByteSlotsPerRowV1>
        source_multiplicity;
    std::array<std::vector<Fp3>,
               kConsumerByteSlotsPerRowV1>
        consumer_active;
    std::array<std::vector<Fp3>,
               kConsumerByteSlotsPerRowV1>
        consumer_key;
    for (auto& values : decompose_mask) {
        values.assign(
            cs.n_rows, Fp3::Zero());
    }
    for (auto& values : source_active) {
        values.assign(cs.n_rows, Fp3::Zero());
    }
    for (auto& values : source_multiplicity) {
        values.assign(cs.n_rows, Fp3::Zero());
    }
    for (auto& values : consumer_active) {
        values.assign(cs.n_rows, Fp3::Zero());
    }
    for (auto& values : consumer_key) {
        values.assign(cs.n_rows, Fp3::Zero());
    }

    for (const auto& source : plan.sources) {
        source_active[source.lookup_slot]
            [source.address.row] = Fp3::One();
        source_multiplicity[source.lookup_slot]
            [source.address.row] =
                U(source.multiplicity);
    }
    for (const auto& consumer : plan.consumers) {
        const uint32_t lane =
            consumer.lookup_slot / 4;
        decompose_mask[lane]
            [consumer.message.row] = Fp3::One();
        consumer_active[consumer.lookup_slot]
            [consumer.message.row] = Fp3::One();
        const uint64_t key =
            4 * uint64_t{consumer.abi_address} +
            consumer.byte_in_abi_word;
        if (key >= gf::kP) {
            return Fail(why, "consumer_key_range");
        }
        consumer_key[consumer.lookup_slot]
            [consumer.message.row] = U(key);
    }
    for (uint32_t lane = 0;
         lane < safe_v12::kSafeRateV12;
         ++lane) {
        AddPreprocessed(
            cs, columns,
            layout.ConsumerDecomposeMask(lane),
            std::move(decompose_mask[lane]));
    }
    for (uint32_t slot = 0;
         slot < kSourceByteSlotsPerRowV1;
         ++slot) {
        AddPreprocessed(
            cs, columns,
            layout.SourceActive(slot),
            std::move(source_active[slot]));
        AddPreprocessed(
            cs, columns,
            layout.SourceMultiplicity(slot),
            std::move(source_multiplicity[slot]));
    }
    for (uint32_t slot = 0;
         slot < kConsumerByteSlotsPerRowV1;
         ++slot) {
        AddPreprocessed(
            cs, columns,
            layout.ConsumerActive(slot),
            std::move(consumer_active[slot]));
        AddPreprocessed(
            cs, columns,
            layout.ConsumerKey(slot),
            std::move(consumer_key[slot]));
    }

    const auto tape_layout =
        tape::CanonicalLayoutV1();
    for (uint32_t record_slot = 0;
         record_slot < tape::kRecordsPerRowV1;
         ++record_slot) {
        for (uint32_t bit = 0;
             bit < 32; ++bit) {
            const uint32_t byte = bit / 8;
            const uint32_t active =
                layout.SourceActive(
                    4 * record_slot + byte);
            const uint32_t bit_column =
                plan.tape_column_offset +
                tape_layout.Bit(
                    record_slot, bit);
            Add(
                cs,
                "stage3.abi_logup.source_bit",
                aq::AirKind::kEverywhere, 3,
                [active, bit_column](
                    const auto& cur,
                    const auto&) {
                    return gf::Mul(
                        cur[active],
                        gf::Mul(
                            cur[bit_column],
                            gf::Sub(
                                cur[bit_column],
                                Fp3::One())));
                });
        }
        const uint32_t value_column =
            plan.tape_column_offset +
            tape_layout.Value(record_slot);
        Add(
            cs,
            "stage3.abi_logup.source_value",
            aq::AirKind::kEverywhere, 2,
            [layout, tape_layout, plan,
             record_slot, value_column](
                const auto& cur,
                const auto&) {
                Fp3 active = Fp3::Zero();
                for (uint32_t byte = 0;
                     byte < 4; ++byte) {
                    active = gf::Add(
                        active,
                        cur[layout.SourceActive(
                            4 * record_slot + byte)]);
                }
                Fp3 recomposed = Fp3::Zero();
                uint64_t weight = 1;
                for (uint32_t bit = 0;
                     bit < 32; ++bit) {
                    recomposed = gf::Add(
                        recomposed,
                        gf::Mul(
                            U(weight),
                            cur[
                                plan.tape_column_offset +
                                tape_layout.Bit(
                                    record_slot,
                                    bit)]));
                    weight <<= 1;
                }
                return gf::Mul(
                    active,
                    gf::Sub(
                        cur[value_column],
                        recomposed));
            });
    }

    const bridge::TypedSafeDirectParentLayoutV14
        v14_layout;
    for (uint32_t lane = 0;
         lane < safe_v12::kSafeRateV12;
         ++lane) {
        const uint32_t mask =
            layout.ConsumerDecomposeMask(lane);
        for (uint32_t bit = 0;
             bit < 32; ++bit) {
            const uint32_t bit_column =
                layout.ConsumerBit(lane, bit);
            // mask=1 -> b is boolean; mask=0 -> b is exactly zero.
            Add(
                cs,
                "stage3.abi_logup.consumer_bit",
                aq::AirKind::kEverywhere, 2,
                [mask, bit_column](
                    const auto& cur,
                    const auto&) {
                    return gf::Mul(
                        cur[bit_column],
                        gf::Sub(
                            cur[bit_column],
                            cur[mask]));
                });
        }
        const uint32_t message_column =
            plan.v14_column_offset +
            v14_layout.Message(lane);
        Add(
            cs,
            "stage3.abi_logup.consumer_u32",
            aq::AirKind::kEverywhere, 2,
            [layout, mask, lane,
             message_column](
                const auto& cur,
                const auto&) {
                Fp3 recomposed = Fp3::Zero();
                uint64_t weight = 1;
                for (uint32_t bit = 0;
                     bit < 32; ++bit) {
                    recomposed = gf::Add(
                        recomposed,
                        gf::Mul(
                            U(weight),
                            cur[layout.ConsumerBit(
                                lane, bit)]));
                    weight <<= 1;
                }
                return gf::Mul(
                    cur[mask],
                    gf::Sub(
                        cur[message_column],
                        recomposed));
            });
    }
    return true;
}

bool FillBaseWitness(
    const PlanV1& plan,
    const LayoutV1& layout,
    std::vector<std::vector<Fp3>>& columns,
    std::string* why)
{
    const bridge::TypedSafeDirectParentLayoutV14
        v14_layout;
    std::set<std::pair<uint32_t, uint32_t>>
        decomposed;
    for (const auto& consumer : plan.consumers) {
        const uint32_t lane =
            consumer.lookup_slot / 4;
        if (!decomposed.insert({
                consumer.message.row, lane}).second) {
            continue;
        }
        const Fp3 value =
            columns[
                plan.v14_column_offset +
                v14_layout.Message(lane)]
                [consumer.message.row];
        if (!Canonical(value) ||
            value.c1 != 0 ||
            value.c2 != 0 ||
            value.c0 >= kU32Bound) {
            return Fail(
                why,
                "consumer_message_not_u32");
        }
        for (uint32_t bit = 0;
             bit < 32; ++bit) {
            columns[layout.ConsumerBit(
                lane, bit)]
                [consumer.message.row] =
                    U((value.c0 >> bit) & 1U);
        }
    }
    return true;
}

bool AppendFinalCs(
    const PlanV1& plan,
    const ChallengesV1& challenges,
    const LayoutV1& layout,
    AirCS& cs,
    std::vector<std::vector<Fp3>>* columns,
    std::string* why)
{
    if (cs.n_columns !=
            layout.dependent_base ||
        layout.end <=
            layout.dependent_base) {
        return Fail(why, "final_layout");
    }
    cs.n_columns = layout.end;
    if (columns != nullptr) {
        columns->resize(
            cs.n_columns,
            std::vector<Fp3>(
                cs.n_rows, Fp3::Zero()));
    }

    for (uint32_t lane = 0;
         lane < kLookupLanesV1;
         ++lane) {
        for (uint32_t slot = 0;
             slot < kSourceByteSlotsPerRowV1;
             ++slot) {
            const uint32_t inverse =
                layout.SourceInverse(lane, slot);
            const uint32_t active =
                layout.SourceActive(slot);
            Add(
                cs,
                "stage3.abi_logup.source_inverse",
                aq::AirKind::kEverywhere, 2,
                [plan, challenges,
                 lane, slot, inverse, active](
                    const auto& cur,
                    const auto&) {
                    return gf::Sub(
                        gf::Mul(
                            cur[inverse],
                            gf::Sub(
                                challenges.alpha[lane],
                                SourceCompressed(
                                    cur, plan, slot,
                                    challenges.gamma[lane]))),
                        cur[active]);
                });
            Add(
                cs,
                "stage3.abi_logup.source_inverse_padding",
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
        for (uint32_t slot = 0;
             slot < kConsumerByteSlotsPerRowV1;
             ++slot) {
            const uint32_t inverse =
                layout.ConsumerInverse(
                    lane, slot);
            const uint32_t active =
                layout.ConsumerActive(slot);
            Add(
                cs,
                "stage3.abi_logup.consumer_inverse",
                aq::AirKind::kEverywhere, 2,
                [layout, challenges,
                 lane, slot, inverse, active](
                    const auto& cur,
                    const auto&) {
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
                cs,
                "stage3.abi_logup.consumer_inverse_padding",
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
        Add(
            cs,
            "stage3.abi_logup.running_first",
            aq::AirKind::kFirstRow, 1,
            [running](
                const auto& cur,
                const auto&) {
                return cur[running];
            });
        const auto row_term =
            [layout, lane](
                const std::vector<Fp3>& row) {
                Fp3 out = Fp3::Zero();
                for (uint32_t slot = 0;
                     slot <
                         kSourceByteSlotsPerRowV1;
                     ++slot) {
                    out = gf::Add(
                        out,
                        gf::Mul(
                            row[layout.SourceMultiplicity(
                                slot)],
                            row[layout.SourceInverse(
                                lane, slot)]));
                }
                for (uint32_t slot = 0;
                     slot <
                         kConsumerByteSlotsPerRowV1;
                     ++slot) {
                    out = gf::Sub(
                        out,
                        gf::Mul(
                            row[layout.ConsumerActive(
                                slot)],
                            row[layout.ConsumerInverse(
                                lane, slot)]));
                }
                return out;
            };
        Add(
            cs,
            "stage3.abi_logup.running_transition",
            aq::AirKind::kTransition, 2,
            [running, row_term](
                const auto& cur,
                const auto& next) {
                return gf::Sub(
                    next[running],
                    gf::Add(
                        cur[running],
                        row_term(cur)));
            });
        Add(
            cs,
            "stage3.abi_logup.running_last",
            aq::AirKind::kLastRow, 2,
            [running, row_term](
                const auto& cur,
                const auto&) {
                return gf::Add(
                    cur[running],
                    row_term(cur));
            });
    }
    return true;
}

bool FillFinalWitness(
    const PlanV1& plan,
    const ChallengesV1& challenges,
    const LayoutV1& layout,
    std::vector<std::vector<Fp3>>& columns,
    std::string* why)
{
    std::array<Fp3, kLookupLanesV1>
        running{};
    for (uint32_t row = 0;
         row < plan.parent_rows; ++row) {
        std::vector<Fp3> current(
            columns.size());
        for (uint32_t column = 0;
             column < columns.size(); ++column) {
            current[column] =
                columns[column][row];
        }
        for (uint32_t lane = 0;
             lane < kLookupLanesV1; ++lane) {
            columns[layout.Running(lane)][row] =
                running[lane];
            for (uint32_t slot = 0;
                 slot <
                     kSourceByteSlotsPerRowV1;
                 ++slot) {
                const bool active = !gf::IsZero(
                    columns[layout.SourceActive(
                        slot)][row]);
                if (!active) continue;
                const Fp3 denominator =
                    gf::Sub(
                        challenges.alpha[lane],
                        SourceCompressed(
                            current, plan, slot,
                            challenges.gamma[lane]));
                if (gf::IsZero(denominator)) {
                    return Fail(
                        why,
                        "source_denominator_pole");
                }
                const Fp3 inverse =
                    gf::Inv(denominator);
                columns[layout.SourceInverse(
                    lane, slot)][row] = inverse;
                running[lane] = gf::Add(
                    running[lane],
                    gf::Mul(
                        columns[
                            layout.SourceMultiplicity(
                                slot)][row],
                        inverse));
            }
            for (uint32_t slot = 0;
                 slot <
                     kConsumerByteSlotsPerRowV1;
                 ++slot) {
                const bool active = !gf::IsZero(
                    columns[layout.ConsumerActive(
                        slot)][row]);
                if (!active) continue;
                const Fp3 denominator =
                    gf::Sub(
                        challenges.alpha[lane],
                        ConsumerCompressed(
                            current, layout, slot,
                            challenges.gamma[lane]));
                if (gf::IsZero(denominator)) {
                    return Fail(
                        why,
                        "consumer_denominator_pole");
                }
                const Fp3 inverse =
                    gf::Inv(denominator);
                columns[layout.ConsumerInverse(
                    lane, slot)][row] = inverse;
                running[lane] = gf::Sub(
                    running[lane], inverse);
            }
        }
    }
    return true;
}

bool BuildVerifierCs(
    const PlanV1& plan,
    const ChallengesV1& challenges,
    const AirCS& resident,
    const std::vector<uint32_t>& parent_base,
    AirCS& out,
    LayoutV1& layout,
    std::vector<uint32_t>& base_indices,
    std::string* why)
{
    if (!PlanRefsValid(
            plan, resident, parent_base)) {
        return Fail(why, "verifier_parent_refs");
    }
    out = resident;
    if (!AppendBaseCs(
            plan, out, nullptr, layout, why)) {
        return false;
    }
    base_indices = parent_base;
    for (uint32_t column =
             layout.original_columns;
         column < layout.dependent_base;
         ++column) {
        base_indices.push_back(column);
    }
    return AppendFinalCs(
        plan, challenges, layout,
        out, nullptr, why);
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

bool BuildCanonicalPlanV1(
    const tape::PublicShapeV1& shape,
    const tape::PublicBindingV1& tape_binding,
    const std::vector<
        bridge::TypedSafeEventProgramV13>&
        v14_program,
    const manifest::ManifestV1&
        occurrence_manifest,
    uint32_t parent_rows,
    uint32_t tape_column_offset,
    uint32_t v14_column_offset,
    PlanV1& out,
    std::string* why)
{
    out = {};
    out.shape = shape;
    out.parent_rows = parent_rows;
    out.tape_column_offset =
        tape_column_offset;
    out.v14_column_offset =
        v14_column_offset;
    if (!PowerOfTwo(parent_rows)) {
        return Fail(why, "parent_rows");
    }
    std::string local_why;
    if (!manifest::
            ValidateCanonicalOccurrenceManifestV1(
                shape, v14_program,
                occurrence_manifest,
                &local_why)) {
        return Fail(
            why, "manifest:" + local_why);
    }
    out.exact_manifest_rebuild = true;
    out.v14_program_root =
        bridge::CommitTypedSafeEventProgramV13(
            v14_program);
    if (out.v14_program_root !=
            occurrence_manifest.program_root) {
        return Fail(why, "program_root");
    }
    const tape::ScheduleV1 tape_schedule =
        tape::BuildScheduleV1(
            shape, tape_binding);
    if (!tape_schedule.valid ||
        tape_schedule.trace_rows >
            parent_rows) {
        return Fail(why, "tape_schedule");
    }

    std::map<std::pair<uint32_t, uint8_t>,
             uint32_t> multiplicities;
    for (const auto& occurrence :
         occurrence_manifest.byte_occurrences) {
        if (!occurrence.canonical_abi_source) {
            continue;
        }
        if (occurrence.abi_source_address ==
                UINT32_MAX ||
            occurrence.byte_in_abi_word >= 4 ||
            occurrence.byte_in_message_word >= 4 ||
            occurrence.consumer_event >=
                v14_program.size() ||
            occurrence.consumer_row >=
                parent_rows ||
            occurrence.consumer_message_ordinal >=
                v14_program[
                    occurrence.consumer_event]
                    .message.size()) {
            return Fail(why, "occurrence_shape");
        }
        const uint32_t lane =
            occurrence
                .consumer_message_ordinal % 8;
        const uint32_t lookup_slot =
            4 * lane +
            occurrence.byte_in_message_word;
        ConsumerByteV1 consumer;
        consumer.abi_address =
            occurrence.abi_source_address;
        consumer.byte_in_abi_word =
            occurrence.byte_in_abi_word;
        consumer.byte_in_message_word =
            occurrence.byte_in_message_word;
        consumer.lookup_slot = lookup_slot;
        consumer.message = {
            v14_column_offset +
                bridge::
                    TypedSafeDirectParentLayoutV14{}
                        .Message(lane),
            occurrence.consumer_row,
        };
        out.consumers.push_back(consumer);
        ++multiplicities[{
            occurrence.abi_source_address,
            occurrence.byte_in_abi_word}];
    }
    if (out.consumers.empty()) {
        return Fail(why, "no_consumers");
    }

    const auto tape_layout =
        tape::CanonicalLayoutV1();
    for (const auto& [key, multiplicity] :
         multiplicities) {
        const uint32_t address = key.first;
        const uint32_t byte = key.second;
        if (address >=
            tape_schedule.semantic_sources.size() ||
            tape_schedule.semantic_sources[address]
                .address != address ||
            multiplicity == 0) {
            return Fail(why, "source_address");
        }
        const uint32_t record =
            tape::kPublicPrefixRecordsV1 +
            tape::kHeaderRecordsV1 +
            address;
        const uint32_t row =
            record /
            tape::kRecordsPerRowV1;
        const uint32_t record_slot =
            record %
            tape::kRecordsPerRowV1;
        if (row >= parent_rows) {
            return Fail(why, "source_row");
        }
        SourceByteV1 source;
        source.abi_address = address;
        source.byte_in_word =
            static_cast<uint8_t>(byte);
        source.multiplicity = multiplicity;
        source.lookup_slot =
            4 * record_slot + byte;
        source.address = {
            tape_column_offset +
                tape_layout.Address(
                    record_slot),
            row,
        };
        source.value = {
            tape_column_offset +
                tape_layout.Value(record_slot),
            row,
        };
        for (uint32_t bit = 0;
             bit < 8; ++bit) {
            source.byte_bits[bit] = {
                tape_column_offset +
                    tape_layout.Bit(
                        record_slot,
                        8 * byte + bit),
                row,
            };
        }
        out.source_multiplicity_sum +=
            multiplicity;
        out.sources.push_back(source);
    }
    out.unique_source_bytes =
        static_cast<uint32_t>(
            out.sources.size());
    out.consumer_occurrences =
        static_cast<uint32_t>(
            out.consumers.size());
    out.exact_physical_cell_map = true;
    out.exact_multiplicity_accounting =
        out.source_multiplicity_sum ==
            out.consumer_occurrences;
    out.valid =
        out.exact_manifest_rebuild &&
        out.exact_physical_cell_map &&
        out.exact_multiplicity_accounting;
    out.plan_root = CommitPlan(out);
    out.valid &=
        out.plan_root != alg_hash::Digest{};
    out.note = out.valid
        ? "exact canonical ABI multiplicity schedule; "
          "same-parent values remain physical cell references"
        : "canonical ABI schedule incomplete";
    if (!ValidPlan(out)) {
        out.valid = false;
        return Fail(why, "plan_invariant");
    }
    if (why != nullptr) *why = out.note;
    return true;
}

bool ValidateCanonicalPlanV1(
    const tape::PublicShapeV1& shape,
    const tape::PublicBindingV1& tape_binding,
    const std::vector<
        bridge::TypedSafeEventProgramV13>&
        v14_program,
    const manifest::ManifestV1&
        occurrence_manifest,
    const PlanV1& claimed,
    std::string* why)
{
    PlanV1 rebuilt;
    std::string local_why;
    if (!BuildCanonicalPlanV1(
            shape, tape_binding, v14_program,
            occurrence_manifest,
            claimed.parent_rows,
            claimed.tape_column_offset,
            claimed.v14_column_offset,
            rebuilt, &local_why)) {
        return Fail(
            why, "rebuild:" + local_why);
    }
    if (!SamePlan(rebuilt, claimed)) {
        return Fail(
            why, "claimed_plan_mismatch");
    }
    if (why != nullptr) {
        *why =
            "stage3:v13_v14_abi_logup_join:"
            "plan_validated";
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
    const auto r0 =
        Fri3AlgDigestFromUint256(
            parent_r0_row_root);
    if (!r0.has_value()) {
        return Fail(
            why, "challenge_noncanonical_r0");
    }
    const auto sample =
        [&](const char* label,
            const std::function<bool(
                const Fp3&)>& accept,
            Fp3& value) {
            std::vector<uint8_t> domain;
            static constexpr char kBase[] =
                "BTX_RC_STAGE3_V13_V14_ABI_LOGUP_CHALLENGE_V1";
            domain.insert(
                domain.end(),
                reinterpret_cast<const uint8_t*>(
                    kBase),
                reinterpret_cast<const uint8_t*>(
                    kBase) +
                    sizeof(kBase) - 1);
            domain.push_back(0);
            for (const char* p = label;
                 *p != 0; ++p) {
                domain.push_back(
                    static_cast<uint8_t>(*p));
            }
            for (uint32_t counter = 0;
                 counter <
                     kChallengeCandidatesV1;
                 ++counter) {
                std::vector<gf::Fp> message;
                message.reserve(24);
                message.push_back(
                    gf::FromU64(kPlanMagicV1));
                message.push_back(
                    gf::FromU64(plan.version));
                message.push_back(
                    gf::FromU64(counter));
                AppendUint256U32(
                    message, public_seed);
                AppendDigest(
                    message, plan.plan_root);
                AppendDigest(message, *r0);
                alg_hash::Digest digest{};
                if (!safe::SafeCoreDigestV12(
                        aht::RoleV12::
                            ReceiptCommitment,
                        domain, message,
                        digest)) {
                    return false;
                }
                const Fp3 candidate{
                    gf::Canonical(digest[0]),
                    gf::Canonical(digest[1]),
                    gf::Canonical(digest[2]),
                };
                if (accept(candidate)) {
                    value = candidate;
                    return true;
                }
            }
            return false;
        };
    if (!sample(
            "gamma1",
            [](const Fp3& value) {
                return !gf::IsZero(value);
            },
            out.gamma[0]) ||
        !sample(
            "gamma2",
            [&](const Fp3& value) {
                return !gf::IsZero(value) &&
                    !gf::Eq(
                        value, out.gamma[0]);
            },
            out.gamma[1]) ||
        !sample(
            "alpha1",
            [](const Fp3&) { return true; },
            out.alpha[0]) ||
        !sample(
            "alpha2",
            [&](const Fp3& value) {
                return !gf::Eq(
                    value, out.alpha[0]);
            },
            out.alpha[1])) {
        out = {};
        return Fail(
            why, "challenge_sampler_exhausted");
    }
    if (why != nullptr) {
        *why =
            "stage3:v13_v14_abi_logup_join:"
            "post_r0_challenges";
    }
    return true;
}

bool AppendEmbeddedBaseConstraintSystemV1(
    const PlanV1& plan,
    const std::vector<uint32_t>&
        parent_r0_base_column_indices,
    AirCS& parent_cs,
    EmbeddedBaseV1& out,
    std::string* why)
{
    out = {};
    if (!ValidPlan(plan) ||
        !PlanRefsValid(
            plan, parent_cs,
            parent_r0_base_column_indices)) {
        return Fail(why, "embedded_base_parent");
    }
    out.plan = plan;
    out.original_columns = parent_cs.n_columns;
    if (!AppendBaseCs(
            plan, parent_cs, nullptr,
            out.layout, why)) {
        out = {};
        return false;
    }
    out.complete_r0_base_column_indices =
        parent_r0_base_column_indices;
    for (uint32_t column =
             out.layout.original_columns;
         column < out.layout.dependent_base;
         ++column) {
        out.complete_r0_base_column_indices
            .push_back(column);
    }
    out.appended_r0_columns =
        out.layout.dependent_base -
        out.layout.original_columns;
    out.physical_parent_cells_in_r0 = true;
    out.verifier_schedule_preprocessed =
        parent_cs.preprocessed_pin_ood;
    out.challenge_columns_absent =
        parent_cs.n_columns ==
            out.layout.dependent_base &&
        out.layout.dependent_base <
            out.layout.end;
    out.valid =
        out.physical_parent_cells_in_r0 &&
        out.verifier_schedule_preprocessed &&
        out.challenge_columns_absent &&
        StrictlyIncreasing(
            out.complete_r0_base_column_indices,
            parent_cs.n_columns) &&
        out.complete_r0_base_column_indices.size() ==
            parent_r0_base_column_indices.size() +
                out.appended_r0_columns;
    out.note = out.valid
        ? "canonical ABI base embedded before global R0"
        : "embedded ABI base incomplete";
    if (!out.valid) {
        return Fail(why, "embedded_base_invariant");
    }
    if (why != nullptr) *why = out.note;
    return true;
}

bool AppendEmbeddedBaseProductV1(
    const PlanV1& plan,
    const std::vector<uint32_t>&
        parent_r0_base_column_indices,
    AirCS& parent_cs,
    std::vector<std::vector<Fp3>>&
        parent_columns,
    EmbeddedBaseV1& out,
    std::string* why)
{
    out = {};
    if (!ValidPlan(plan) ||
        !PlanRefsValid(
            plan, parent_cs,
            parent_r0_base_column_indices) ||
        parent_columns.size() !=
            parent_cs.n_columns) {
        return Fail(why, "embedded_base_product_parent");
    }
    for (const auto& column : parent_columns) {
        if (column.size() != parent_cs.n_rows) {
            return Fail(
                why,
                "embedded_base_product_rows");
        }
    }
    out.plan = plan;
    out.original_columns = parent_cs.n_columns;
    if (!AppendBaseCs(
            plan, parent_cs, &parent_columns,
            out.layout, why) ||
        !FillBaseWitness(
            plan, out.layout,
            parent_columns, why)) {
        out = {};
        return false;
    }
    out.complete_r0_base_column_indices =
        parent_r0_base_column_indices;
    for (uint32_t column =
             out.layout.original_columns;
         column < out.layout.dependent_base;
         ++column) {
        out.complete_r0_base_column_indices
            .push_back(column);
    }
    out.appended_r0_columns =
        out.layout.dependent_base -
        out.layout.original_columns;
    out.physical_parent_cells_in_r0 = true;
    out.verifier_schedule_preprocessed =
        parent_cs.preprocessed_pin_ood;
    out.challenge_columns_absent =
        parent_cs.n_columns ==
            out.layout.dependent_base &&
        parent_columns.size() ==
            out.layout.dependent_base &&
        out.layout.dependent_base <
            out.layout.end;
    out.valid =
        out.physical_parent_cells_in_r0 &&
        out.verifier_schedule_preprocessed &&
        out.challenge_columns_absent &&
        StrictlyIncreasing(
            out.complete_r0_base_column_indices,
            parent_cs.n_columns) &&
        out.complete_r0_base_column_indices.size() ==
            parent_r0_base_column_indices.size() +
                out.appended_r0_columns;
    out.note = out.valid
        ? "canonical ABI base witness embedded before global R0"
        : "embedded ABI base witness incomplete";
    if (!out.valid) {
        return Fail(
            why, "embedded_base_product_invariant");
    }
    if (why != nullptr) *why = out.note;
    return true;
}

bool AppendEmbeddedFinalConstraintSystemV1(
    const PlanV1& plan,
    const EmbeddedBaseV1& base,
    const uint256& domain_separated_public_seed,
    const uint256& global_r0_row_root,
    const std::vector<uint32_t>&
        global_r0_base_column_indices,
    AirCS& parent_cs,
    EmbeddedFinalizationV1& out,
    std::string* why)
{
    out = {};
    const bool required_columns_present =
        std::all_of(
            base.complete_r0_base_column_indices.begin(),
            base.complete_r0_base_column_indices.end(),
            [&global_r0_base_column_indices](
                uint32_t column) {
                return Contains(
                    global_r0_base_column_indices,
                    column);
            });
    if (!base.valid ||
        !SamePlan(plan, base.plan) ||
        domain_separated_public_seed.IsNull() ||
        global_r0_row_root.IsNull() ||
        !required_columns_present ||
        parent_cs.n_rows != plan.parent_rows ||
        parent_cs.n_columns <
            base.layout.dependent_base ||
        !StrictlyIncreasing(
            global_r0_base_column_indices,
            parent_cs.n_columns)) {
        return Fail(
            why, "embedded_final_verifier_parent");
    }
    out.global_r0_row_root =
        global_r0_row_root;
    out.dependent_column_base =
        parent_cs.n_columns;
    out.relocated_layout =
        RelocateDependentLayout(
            base.layout,
            out.dependent_column_base);
    if (!DeriveChallengesV1(
            plan,
            domain_separated_public_seed,
            global_r0_row_root,
            out.challenges, why) ||
        !AppendFinalCs(
            plan, out.challenges,
            out.relocated_layout, parent_cs,
            nullptr, why)) {
        out = {};
        return false;
    }
    out.dependent_columns =
        parent_cs.n_columns -
        out.dependent_column_base;
    out.exact_global_r0_indices = true;
    out.challenges_derived_after_global_r0 =
        true;
    out.dual_fp3_rational_identity_constrained =
        out.dependent_columns ==
            out.relocated_layout.end -
                out.relocated_layout.dependent_base &&
        parent_cs.n_columns ==
            out.relocated_layout.end;
    out.valid =
        out.exact_global_r0_indices &&
        out.challenges_derived_after_global_r0 &&
        out.dual_fp3_rational_identity_constrained;
    out.note = out.valid
        ? "ABI dependent constraints derived from global parent R0"
        : "embedded ABI verifier finalization incomplete";
    if (!out.valid) {
        return Fail(
            why, "embedded_final_verifier_invariant");
    }
    if (why != nullptr) *why = out.note;
    return true;
}

bool AppendEmbeddedFinalProductV1(
    const PlanV1& plan,
    const EmbeddedBaseV1& base,
    const uint256& domain_separated_public_seed,
    const aq::AirQuotientTwoEpochBaseRowSession&
        global_r0_session,
    AirCS& parent_cs,
    std::vector<std::vector<Fp3>>&
        parent_columns,
    EmbeddedFinalizationV1& out,
    std::string* why)
{
    out = {};
    const bool required_columns_present =
        std::all_of(
            base.complete_r0_base_column_indices.begin(),
            base.complete_r0_base_column_indices.end(),
            [&global_r0_session](
                uint32_t column) {
                return Contains(
                    global_r0_session
                        .base_column_indices,
                    column);
            });
    if (!base.valid ||
        !SamePlan(plan, base.plan) ||
        domain_separated_public_seed.IsNull() ||
        !global_r0_session.valid ||
        global_r0_session.trace_rows !=
            parent_cs.n_rows ||
        global_r0_session.base_row_commitment.IsNull() ||
        !required_columns_present ||
        parent_cs.n_rows != plan.parent_rows ||
        parent_cs.n_columns <
            base.layout.dependent_base ||
        parent_columns.size() !=
            parent_cs.n_columns ||
        !StrictlyIncreasing(
            global_r0_session.base_column_indices,
            parent_cs.n_columns)) {
        return Fail(
            why, "embedded_final_product_parent");
    }
    for (const auto& column : parent_columns) {
        if (column.size() != parent_cs.n_rows) {
            return Fail(
                why, "embedded_final_product_rows");
        }
    }
    out.global_r0_row_root =
        global_r0_session.base_row_commitment;
    out.dependent_column_base =
        parent_cs.n_columns;
    out.relocated_layout =
        RelocateDependentLayout(
            base.layout,
            out.dependent_column_base);
    if (!DeriveChallengesV1(
            plan,
            domain_separated_public_seed,
            global_r0_session.base_row_commitment,
            out.challenges, why) ||
        !AppendFinalCs(
            plan, out.challenges,
            out.relocated_layout, parent_cs,
            &parent_columns, why) ||
        !FillFinalWitness(
            plan, out.challenges,
            out.relocated_layout,
            parent_columns,
            why)) {
        out = {};
        return false;
    }
    out.dependent_columns =
        parent_cs.n_columns -
        out.dependent_column_base;
    out.exact_global_r0_indices = true;
    out.challenges_derived_after_global_r0 =
        true;
    out.dual_fp3_rational_identity_constrained =
        out.dependent_columns ==
            out.relocated_layout.end -
                out.relocated_layout.dependent_base &&
        parent_cs.n_columns ==
            out.relocated_layout.end &&
        parent_columns.size() ==
            out.relocated_layout.end;
    out.valid =
        out.exact_global_r0_indices &&
        out.challenges_derived_after_global_r0 &&
        out.dual_fp3_rational_identity_constrained;
    out.note = out.valid
        ? "ABI dependent witness derived from retained global parent R0"
        : "embedded ABI product finalization incomplete";
    if (!out.valid) {
        return Fail(
            why, "embedded_final_product_invariant");
    }
    if (why != nullptr) *why = out.note;
    return true;
}

bool BuildProductV1(
    const PlanV1& plan,
    const uint256& public_seed,
    const AirCS& resident_parent_cs,
    const std::vector<std::vector<Fp3>>&
        resident_parent_columns,
    const std::vector<uint32_t>&
        parent_r0_base_column_indices,
    ProductV1& out,
    std::string* why)
{
    out = {};
    out.plan = plan;
    if (!ValidPlan(plan) ||
        public_seed.IsNull() ||
        !PlanRefsValid(
            plan, resident_parent_cs,
            parent_r0_base_column_indices) ||
        resident_parent_columns.size() !=
            resident_parent_cs.n_columns) {
        return Fail(why, "product_parent");
    }
    out.cs = resident_parent_cs;
    out.columns = resident_parent_columns;
    if (!AppendBaseCs(
            plan, out.cs, &out.columns,
            out.layout, why) ||
        !FillBaseWitness(
            plan, out.layout,
            out.columns, why)) {
        out = {};
        return false;
    }
    out.r0_base_column_indices =
        parent_r0_base_column_indices;
    for (uint32_t column =
             out.layout.original_columns;
         column <
             out.layout.dependent_base;
         ++column) {
        out.r0_base_column_indices.push_back(
            column);
    }
    out.r0_session =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            out.cs, out.columns,
            out.r0_base_column_indices);
    if (!out.r0_session.valid ||
        !DeriveChallengesV1(
            plan, public_seed,
            out.r0_session.base_row_commitment,
            out.challenges, why) ||
        !AppendFinalCs(
            plan, out.challenges,
            out.layout, out.cs,
            &out.columns, why) ||
        !FillFinalWitness(
            plan, out.challenges,
            out.layout, out.columns,
            why)) {
        out = {};
        return false;
    }
    out.violations =
        CountViolationsV1(
            out.cs, out.columns);
    out.actual_tape_cells_referenced = true;
    out.actual_v14_message_cells_referenced =
        true;
    out.consumer_u32_decomposition_constrained =
        true;
    out.exact_schedule_multiplicities_preprocessed =
        true;
    out.challenges_after_complete_r0 = true;
    out.dual_fp3_rational_identity_constrained =
        true;
    out.terminal_cancellation_constrained =
        true;
    out.source_and_consumer_verifiers_resident =
        false;
    out.recursively_consumed = false;
    out.recursive_authority_ready = false;
    out.valid =
        out.violations == 0 &&
        out.actual_tape_cells_referenced &&
        out.actual_v14_message_cells_referenced &&
        out.consumer_u32_decomposition_constrained &&
        out.exact_schedule_multiplicities_preprocessed &&
        out.challenges_after_complete_r0 &&
        out.dual_fp3_rational_identity_constrained &&
        out.terminal_cancellation_constrained &&
        !out.source_and_consumer_verifiers_resident &&
        !out.recursively_consumed &&
        !out.recursive_authority_ready;
    out.note = out.valid
        ? "dual-Fp3 same-parent ABI LogUp closes exact "
          "Address/Value-to-Message equality; full verifier-family "
          "residency and recursive consumption remain explicit"
        : "ABI LogUp witness violates the canonical relation";
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
        public_seed.IsNull() ||
        product.r0_session.base_row_commitment
            .IsNull()) {
        return Fail(why, "prove_product");
    }
    const auto proved =
        aq::AirQuotientProveRowsSplitRapSafeV2(
            product.cs,
            product.columns,
            product.r0_base_column_indices,
            public_seed, {},
            &product.r0_session);
    if (!proved.ok ||
        !proved.division_exact) {
        return Fail(
            why, "prove:" + proved.note);
    }
    out.plan_root =
        product.plan.plan_root;
    out.r0_row_root =
        product.r0_session
            .base_row_commitment;
    out.proof = proved.proof;
    out.recursively_consumed = false;
    out.recursive_authority_ready = false;
    out.note =
        "canonical ABI LogUp proof; recursive "
        "same-parent consumption pending";
    if (why != nullptr) *why = out.note;
    return true;
}

bool VerifyV1(
    const tape::PublicShapeV1& shape,
    const tape::PublicBindingV1& tape_binding,
    const std::vector<
        bridge::TypedSafeEventProgramV13>&
        v14_program,
    const manifest::ManifestV1&
        occurrence_manifest,
    const PlanV1& canonical_plan,
    const uint256& public_seed,
    const AirCS& resident_parent_cs,
    const std::vector<uint32_t>&
        parent_r0_base_column_indices,
    const ProofV1& proof,
    std::string* why)
{
    std::string canonical_why;
    if (!ValidateCanonicalPlanV1(
            shape, tape_binding, v14_program,
            occurrence_manifest,
            canonical_plan, &canonical_why)) {
        return Fail(
            why,
            "verify_plan:" + canonical_why);
    }
    if (proof.version !=
            kAbiLogUpJoinVersionV1 ||
        proof.plan_root !=
            canonical_plan.plan_root ||
        proof.r0_row_root.IsNull() ||
        proof.recursively_consumed ||
        proof.recursive_authority_ready ||
        proof.proof.batch.groups.empty() ||
        proof.r0_row_root !=
            Fri3AlgDigestToUint256(
                proof.proof.batch.groups[0]
                    .row_commit.root)) {
        return Fail(why, "verify_envelope");
    }
    ChallengesV1 challenges;
    if (!DeriveChallengesV1(
            canonical_plan, public_seed,
            proof.r0_row_root,
            challenges, why)) {
        return false;
    }
    AirCS cs;
    LayoutV1 layout;
    std::vector<uint32_t> base_indices;
    if (!BuildVerifierCs(
            canonical_plan, challenges,
            resident_parent_cs,
            parent_r0_base_column_indices,
            cs, layout, base_indices, why)) {
        return false;
    }
    std::string air_why;
    if (!aq::AirQuotientVerifyRowsSplitRapSafeV2(
            cs, proof.proof,
            base_indices,
            public_seed, &air_why)) {
        return Fail(
            why, "verify_air:" + air_why);
    }
    if (why != nullptr) {
        *why =
            "stage3:v13_v14_abi_logup_join:"
            "verified";
    }
    return true;
}

uint64_t CountViolationsV1(
    const AirCS& cs,
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

bool BuildBoundedPhysicalCanaryPlanV1(
    const BoundedPhysicalCanaryStatementV1& statement,
    uint32_t parent_rows,
    uint32_t tape_column_offset,
    uint32_t v14_column_offset,
    PlanV1& out,
    std::string* why)
{
    out = {};
    if (statement.version != kAbiLogUpJoinVersionV1 ||
        !PowerOfTwo(parent_rows) ||
        statement.byte_in_word >= 4 ||
        statement.byte_in_message_word >= 4 ||
        statement.consumer_row >= parent_rows) {
        return Fail(why, "bounded_canary_statement");
    }

    const uint64_t record64 =
        uint64_t{tape::kPublicPrefixRecordsV1} +
        uint64_t{tape::kHeaderRecordsV1} +
        statement.abi_address;
    if (record64 > UINT32_MAX) {
        return Fail(why, "bounded_canary_record");
    }
    const uint32_t record =
        static_cast<uint32_t>(record64);
    const uint32_t source_row =
        record / tape::kRecordsPerRowV1;
    const uint32_t record_slot =
        record % tape::kRecordsPerRowV1;
    if (source_row >= parent_rows) {
        return Fail(why, "bounded_canary_source_row");
    }

    out.version = kAbiLogUpJoinVersionV1;
    out.shape.trace_rows = 2;
    out.shape.trace_columns = 2;
    out.shape.quotient_len = 2;
    out.shape.n_coeffs = 2;
    out.shape.base_column_indices = {0};
    out.v14_program_root = {
        gf::FromU64(1),
        gf::FromU64(2),
        gf::FromU64(3),
        gf::FromU64(4),
    };
    out.parent_rows = parent_rows;
    out.tape_column_offset = tape_column_offset;
    out.v14_column_offset = v14_column_offset;

    const tape::LayoutV1 tape_layout =
        tape::CanonicalLayoutV1();
    SourceByteV1 source;
    source.abi_address = statement.abi_address;
    source.byte_in_word = statement.byte_in_word;
    source.multiplicity = 1;
    source.lookup_slot =
        4 * record_slot + statement.byte_in_word;
    source.address = {
        tape_column_offset +
            tape_layout.Address(record_slot),
        source_row,
    };
    source.value = {
        tape_column_offset +
            tape_layout.Value(record_slot),
        source_row,
    };
    for (uint32_t bit = 0; bit < 8; ++bit) {
        source.byte_bits[bit] = {
            tape_column_offset +
                tape_layout.Bit(
                    record_slot,
                    8 * statement.byte_in_word + bit),
            source_row,
        };
    }
    out.sources.push_back(source);

    ConsumerByteV1 consumer;
    consumer.abi_address = statement.abi_address;
    consumer.byte_in_abi_word =
        statement.byte_in_word;
    consumer.byte_in_message_word =
        statement.byte_in_message_word;
    consumer.lookup_slot =
        statement.byte_in_message_word;
    consumer.message = {
        v14_column_offset +
            bridge::TypedSafeDirectParentLayoutV14{}
                .Message(0),
        statement.consumer_row,
    };
    out.consumers.push_back(consumer);

    out.unique_source_bytes = 1;
    out.consumer_occurrences = 1;
    out.source_multiplicity_sum = 1;
    out.exact_manifest_rebuild = true;
    out.exact_physical_cell_map = true;
    out.exact_multiplicity_accounting = true;
    out.valid = true;
    out.plan_root = CommitPlan(out);
    out.note =
        "bounded proof-level canary using production physical "
        "tape/V14 cells and dual-Fp3 LogUp; not a production "
        "statement or recursive-consumption claim";
    if (!ValidPlan(out)) {
        out.valid = false;
        return Fail(why, "bounded_canary_plan");
    }
    if (why != nullptr) *why = out.note;
    return true;
}

} // namespace matmul::v4::rc::stage3_v13_v14_abi_logup_join
