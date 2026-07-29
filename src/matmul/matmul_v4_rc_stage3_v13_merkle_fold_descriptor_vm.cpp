// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/MIT.

#include <matmul/matmul_v4_rc_stage3_v13_merkle_fold_descriptor_vm.h>

#include <matmul/matmul_v4_rc_stage3_constraint_bytecode.h>

#include <hash.h>

#include <algorithm>
#include <bit>
#include <limits>
#include <map>
#include <numeric>
#include <set>

namespace matmul::v4::rc::stage3_v13_merkle_fold_descriptor_vm {
namespace {

namespace cb = constraint_bytecode;
using AirCS = aq::AirConstraintSystem<gf::Fp3>;
using Fp3 = gf::Fp3;

inline constexpr uint64_t kPlanMagicV1 =
    UINT64_C(0x4d4644564d563031); // "MFDVMV01"
inline constexpr uint64_t kHashFamilyDomainV1 =
    UINT64_C(0x48415348564d3031); // "HASHVM01"
inline constexpr uint64_t kFoldFamilyDomainV1 =
    UINT64_C(0x464f4c44564d3031); // "FOLDVM01"
inline constexpr std::array<uint64_t, 6> kTerminalTagV1{{
    0,
    UINT64_C(0x544150455f535243), // TAPE_SRC
    UINT64_C(0x484153485f494e50), // HASH_INP
    UINT64_C(0x5052494f525f4f55), // PRIOR_OU
    UINT64_C(0x484153485f4f5554), // HASH_OUT
    UINT64_C(0x464f4c445f494e50), // FOLD_INP
}};

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:v13_merkle_fold_descriptor_vm:" +
            detail;
    }
    return false;
}

bool PowerOfTwo(uint32_t value)
{
    return value >= 2 && (value & (value - 1)) == 0;
}

bool Nonzero(const alg_hash::Digest& digest)
{
    return std::any_of(
        digest.begin(), digest.end(),
        [](gf::Fp value) {
            return gf::Canonical(value) != 0;
        });
}

bool ZeroState(const alg_hash::State& state)
{
    return std::all_of(
        state.begin(), state.end(),
        [](gf::Fp value) {
            return gf::Canonical(value) == 0;
        });
}

bool EqualState(
    const alg_hash::State& left,
    const alg_hash::State& right)
{
    for (uint32_t lane = 0;
         lane < alg_hash::kAlgHashT; ++lane) {
        if (gf::Canonical(left[lane]) !=
            gf::Canonical(right[lane])) {
            return false;
        }
    }
    return true;
}

Fp3 U(uint64_t value)
{
    return gf::FromU64_3(value);
}

void AppendU64(std::vector<gf::Fp>& lanes, uint64_t value)
{
    // Never absorb a u64 in one Goldilocks lane: x and x+p alias.
    lanes.push_back(gf::FromU64(
        static_cast<uint32_t>(value)));
    lanes.push_back(gf::FromU64(
        static_cast<uint32_t>(value >> 32)));
}

void AppendKey(
    std::vector<gf::Fp>& lanes,
    const abi::SourceKeyV1& key)
{
    AppendU64(lanes, static_cast<uint16_t>(key.kind));
    AppendU64(lanes, key.a);
    AppendU64(lanes, key.b);
    AppendU64(lanes, key.c);
    AppendU64(lanes, key.d);
    AppendU64(lanes, key.limb);
}

void AppendFp3(std::vector<gf::Fp>& lanes, const Fp3& value)
{
    lanes.push_back(value.c0);
    lanes.push_back(value.c1);
    lanes.push_back(value.c2);
}

void AppendDigest(
    std::vector<gf::Fp>& lanes,
    const alg_hash::Digest& digest)
{
    lanes.insert(lanes.end(), digest.begin(), digest.end());
}

void AppendState(
    std::vector<gf::Fp>& lanes,
    const alg_hash::State& state)
{
    lanes.insert(lanes.end(), state.begin(), state.end());
}

void AppendUint256(
    std::vector<gf::Fp>& lanes,
    const uint256& value)
{
    for (uint32_t word = 0; word < 8; ++word) {
        uint32_t limb = 0;
        for (uint32_t byte = 0; byte < 4; ++byte) {
            limb |=
                uint32_t{value.begin()[
                    4 * word + byte]}
                << (8 * byte);
        }
        lanes.push_back(gf::FromU64(limb));
    }
}

bool ValidSourceShards(
    const std::array<SourceShardV1, kTapeShardsV1>& shards)
{
    std::set<uint32_t> address;
    uint64_t expected_begin = 0;
    for (uint32_t shard_ordinal = 0;
         shard_ordinal < kTapeShardsV1;
         ++shard_ordinal) {
        const auto& shard = shards[shard_ordinal];
        const bool first = shard_ordinal == 0;
        if (shard.version != kVersionV1 ||
            shard.shard_ordinal != shard_ordinal ||
            !PowerOfTwo(shard.trace_rows) ||
            shard.global_ordinal_begin != expected_begin ||
            shard.global_ordinal_begin >=
                shard.global_ordinal_end ||
            shard.global_ordinal_end > UINT32_MAX ||
            shard.global_ordinal_end -
                    shard.global_ordinal_begin !=
                uint64_t{shard.trace_rows} *
                    kShardSourceSlotsV1 ||
            !Nonzero(shard.source_domain_root) ||
            (first
                 ? !ZeroState(shard.state_in)
                 : ZeroState(shard.state_in)) ||
            ZeroState(shard.state_out) ||
            shard.last_shard !=
                (shard_ordinal + 1 == kTapeShardsV1) ||
            !shard.exact_contiguous_interval ||
            !shard.state_boundary_bound ||
            !shard.valid) {
            return false;
        }
        if (!first &&
            !EqualState(
                shards[shard_ordinal - 1].state_out,
                shard.state_in)) {
            return false;
        }
        std::set<std::pair<uint32_t, uint32_t>> physical;
        std::set<uint64_t> ordinal;
        for (const auto& cell : shard.cells) {
            if (cell.global_ordinal <
                    shard.global_ordinal_begin ||
                cell.global_ordinal >=
                    shard.global_ordinal_end ||
                cell.global_ordinal > UINT32_MAX ||
                cell.row >= shard.trace_rows ||
                cell.slot >= kShardSourceSlotsV1 ||
                !physical.emplace(
                    cell.row, cell.slot).second ||
                !ordinal.emplace(
                    cell.global_ordinal).second ||
                !address.emplace(cell.address).second) {
                return false;
            }
            const uint64_t expected =
                shard.global_ordinal_begin +
                uint64_t{cell.row} *
                    kShardSourceSlotsV1 +
                cell.slot;
            if (cell.global_ordinal != expected) {
                return false;
            }
        }
        expected_begin = shard.global_ordinal_end;
    }
    return true;
}

alg_hash::Digest ProofTapeRoot(
    const std::array<SourceShardV1, kTapeShardsV1>& shards)
{
    alg_hash::Digest out{};
    const auto& final_state =
        shards.back().state_out;
    std::copy_n(
        final_state.begin(),
        alg_hash::kAlgHashDigestLen,
        out.begin());
    return out;
}

const SourceCellV1* FindSource(
    const std::array<SourceShardV1, kTapeShardsV1>& shards,
    uint32_t address,
    uint32_t* shard_ordinal = nullptr)
{
    const SourceCellV1* found = nullptr;
    for (uint32_t shard = 0;
         shard < kTapeShardsV1; ++shard) {
        const auto it = std::find_if(
            shards[shard].cells.begin(),
            shards[shard].cells.end(),
            [address](const SourceCellV1& cell) {
                return cell.address == address;
            });
        if (it == shards[shard].cells.end()) continue;
        if (found != nullptr) return nullptr;
        found = &*it;
        if (shard_ordinal != nullptr) {
            *shard_ordinal = shard;
        }
    }
    return found;
}

bool AssignSource(
    const std::array<SourceShardV1, kTapeShardsV1>& shards,
    uint32_t address,
    SourceSlotV1& destination)
{
    if (address == UINT32_MAX) return true;
    uint32_t shard_ordinal = UINT32_MAX;
    const SourceCellV1* cell =
        FindSource(shards, address, &shard_ordinal);
    if (cell == nullptr) return false;
    const SourceSlotV1 expected{
        true,
        shard_ordinal,
        cell->global_ordinal,
        cell->address,
        cell->key,
    };
    if (destination.active && !(destination == expected)) {
        return false;
    }
    destination = expected;
    return true;
}

HashLaneDescriptorV1 DescribeHashLane(
    const merkle::HashLaneExpressionV1& expression,
    bool& ok)
{
    using Kind = merkle::HashLaneExpressionKindV1;
    HashLaneDescriptorV1 out;
    const Fp3 one = Fp3::One();
    const Fp3 two32 = U(uint64_t{1} << 32);
    out.constant = expression.constant;
    out.prior_active =
        expression.prior_task_row != UINT32_MAX;
    out.prior_task_row = expression.prior_task_row;
    out.prior_output_lane = expression.prior_output_lane;
    switch (expression.kind) {
    case Kind::Constant:
        break;
    case Kind::AbiU32:
        out.w0 = one;
        break;
    case Kind::AbiFpCoordinate:
        out.w0 = one;
        out.w1 = two32;
        break;
    case Kind::PriorOutput:
    case Kind::PriorOutputPlusConstant:
        out.w_prior = one;
        break;
    case Kind::PriorOutputPlusAbiU32:
        out.w_prior = one;
        out.w0 = one;
        break;
    case Kind::PriorOutputPlusAbiFpCoordinate:
        out.w_prior = one;
        out.w0 = one;
        out.w1 = two32;
        break;
    case Kind::DerivedNextIndex:
        out.w_effective_index = one;
        break;
    case Kind::PriorOutputPlusDerivedNextIndex:
        out.w_prior = one;
        out.w_effective_index = one;
        break;
    case Kind::SelectPriorOrSiblingLeft:
        out.w_prior = one;
        out.select_left = true;
        break;
    case Kind::SelectPriorOrSiblingRight:
        out.w0 = one;
        out.w1 = two32;
        out.select_right = true;
        break;
    default:
        ok = false;
        break;
    }
    if (out.select_left && out.select_right) ok = false;
    return out;
}

alg_hash::Digest CommitPlan(const PlanV1& plan)
{
    std::vector<gf::Fp> lanes;
    lanes.reserve(
        256 + plan.rows.size() *
            (32 + 12 * kHashLanesV1 +
             14 * kSourceSlotsV1));
    AppendU64(lanes, kPlanMagicV1);
    AppendU64(lanes, plan.version);
    AppendU64(lanes, static_cast<uint8_t>(plan.family));
    AppendU64(lanes, plan.family_tag);
    AppendU64(lanes, plan.parent_rows);
    AppendU64(lanes, plan.relation_rows);
    AppendU64(lanes, plan.selector_n_lde);
    AppendU64(lanes, plan.selector_stride);
    AppendU64(lanes, plan.manifest_reads);
    AppendDigest(lanes, plan.proof_tape_root);
    AppendUint256(lanes, plan.source_inventory_root);
    for (const auto& shard : plan.source_shards) {
        AppendU64(lanes, shard.version);
        AppendU64(lanes, shard.shard_ordinal);
        AppendU64(lanes, shard.global_ordinal_begin);
        AppendU64(lanes, shard.global_ordinal_end);
        AppendU64(lanes, shard.trace_rows);
        AppendU64(lanes, shard.last_shard ? 1U : 0U);
        AppendDigest(lanes, shard.source_domain_root);
        AppendState(lanes, shard.state_in);
        AppendState(lanes, shard.state_out);
    }
    AppendU64(lanes, plan.rows.size());
    for (const auto& row : plan.rows) {
        AppendU64(lanes, row.active ? 1U : 0U);
        AppendU64(lanes, row.task_ordinal);
        AppendU64(lanes, row.selector_active ? 1U : 0U);
        AppendU64(
            lanes,
            row.selector_is_derived_next ? 1U : 0U);
        AppendU64(lanes, row.selector_bit);
        for (const auto& source : row.source) {
            AppendU64(lanes, source.active ? 1U : 0U);
            AppendU64(lanes, source.source_shard_ordinal);
            AppendU64(lanes, source.global_ordinal);
            AppendU64(lanes, source.address);
            AppendKey(lanes, source.key);
        }
        for (const auto& lane : row.hash_lane) {
            AppendFp3(lanes, lane.w0);
            AppendFp3(lanes, lane.w1);
            AppendFp3(lanes, lane.w_prior);
            AppendFp3(lanes, lane.w_effective_index);
            AppendFp3(lanes, lane.constant);
            AppendU64(lanes, lane.select_left ? 1U : 0U);
            AppendU64(lanes, lane.select_right ? 1U : 0U);
            AppendU64(lanes, lane.prior_active ? 1U : 0U);
            AppendU64(lanes, lane.prior_task_row);
            AppendU64(lanes, lane.prior_output_lane);
        }
        for (bool active : row.hash_output_active) {
            AppendU64(lanes, active ? 1U : 0U);
        }
    }
    for (const auto& multiplicities :
         plan.source_multiplicity) {
        AppendU64(lanes, multiplicities.size());
        for (uint32_t multiplicity : multiplicities) {
            AppendU64(lanes, multiplicity);
        }
    }
    return alg_hash::SpongeHashFp(lanes);
}

bool ValidPlan(const PlanV1& plan)
{
    if (plan.version != kVersionV1 ||
        plan.family_tag == 0 ||
        !ValidSourceShards(plan.source_shards) ||
        !Nonzero(plan.proof_tape_root) ||
        plan.proof_tape_root !=
            ProofTapeRoot(plan.source_shards) ||
        plan.source_inventory_root.IsNull() ||
        !PowerOfTwo(plan.parent_rows) ||
        plan.relation_rows == 0 ||
        plan.relation_rows > plan.parent_rows ||
        (plan.family == FamilyV1::Hash &&
         (plan.selector_n_lde == 0 ||
          !PowerOfTwo(plan.selector_n_lde) ||
          plan.selector_stride == 0 ||
          plan.selector_stride >= plan.selector_n_lde)) ||
        plan.rows.size() != plan.parent_rows ||
        plan.manifest_reads == 0 ||
        plan.manifest_reads > kMaxManifestReadsV1 ||
        !Nonzero(plan.schedule_root) ||
        !plan.exact_relation_schedule ||
        !plan.exact_source_multiplicity ||
        !plan.exact_prior_memory_schedule ||
        !plan.exact_manifest_count ||
        !plan.zero_padding_canonical ||
        !plan.valid) {
        return false;
    }
    uint64_t reads = 0;
    uint64_t multiplicity = 0;
    for (uint32_t shard = 0;
         shard < kTapeShardsV1; ++shard) {
        if (plan.source_multiplicity[shard].size() !=
            plan.source_shards[shard].cells.size()) {
            return false;
        }
        for (uint32_t count :
             plan.source_multiplicity[shard]) {
            multiplicity += count;
        }
    }
    for (uint32_t row = 0;
         row < plan.rows.size(); ++row) {
        const auto& descriptor = plan.rows[row];
        if (descriptor.active !=
                (row < plan.relation_rows) ||
            descriptor.task_ordinal !=
                (descriptor.active ? row : UINT32_MAX)) {
            return false;
        }
        if (!descriptor.active &&
            descriptor != RowDescriptorV1{}) {
            return false;
        }
        for (const auto& source : descriptor.source) {
            if (!source.active) {
                if (source != SourceSlotV1{}) return false;
                continue;
            }
            ++reads;
            if (source.source_shard_ordinal >=
                    kTapeShardsV1 ||
                source.global_ordinal > UINT32_MAX) {
                return false;
            }
            const auto& shard =
                plan.source_shards[
                    source.source_shard_ordinal];
            if (source.global_ordinal <
                    shard.global_ordinal_begin ||
                source.global_ordinal >=
                    shard.global_ordinal_end) {
                return false;
            }
            uint32_t actual_shard = UINT32_MAX;
            const SourceCellV1* cell =
                FindSource(
                    plan.source_shards,
                    source.address,
                    &actual_shard);
            if (cell == nullptr ||
                actual_shard !=
                    source.source_shard_ordinal ||
                cell->global_ordinal !=
                    source.global_ordinal ||
                !(cell->key == source.key)) {
                return false;
            }
        }
        if (plan.family == FamilyV1::Hash &&
            descriptor.active) {
            for (const auto& lane :
                 descriptor.hash_lane) {
                if (lane.prior_active &&
                    (lane.prior_task_row >= row ||
                     lane.prior_output_lane >=
                         kHashLanesV1)) {
                    return false;
                }
            }
            if (descriptor.selector_active &&
                (!descriptor.source[
                    kHashSelectorSlotV1].active ||
                 descriptor.selector_bit >= 32)) {
                return false;
            }
        }
    }
    return reads == plan.manifest_reads &&
        multiplicity == reads &&
        CommitPlan(plan) == plan.schedule_root;
}

void PopulateMultiplicity(PlanV1& plan)
{
    plan.manifest_reads = 0;
    for (uint32_t shard = 0;
         shard < kTapeShardsV1; ++shard) {
        plan.source_multiplicity[shard].assign(
            plan.source_shards[shard].cells.size(), 0);
    }
    for (const auto& row : plan.rows) {
        for (const auto& source : row.source) {
            if (!source.active) continue;
            ++plan.manifest_reads;
            const uint32_t shard =
                source.source_shard_ordinal;
            const auto& cells =
                plan.source_shards[shard].cells;
            const auto it = std::find_if(
                cells.begin(), cells.end(),
                [&](const SourceCellV1& cell) {
                    return cell.global_ordinal ==
                        source.global_ordinal;
                });
            if (it == cells.end()) continue;
            const size_t index =
                static_cast<size_t>(
                    std::distance(cells.begin(), it));
            ++plan.source_multiplicity[shard][index];
        }
    }
}

} // namespace

bool HashLaneDescriptorV1::operator==(
    const HashLaneDescriptorV1& other) const
{
    return gf::Eq(w0, other.w0) &&
        gf::Eq(w1, other.w1) &&
        gf::Eq(w_prior, other.w_prior) &&
        gf::Eq(
            w_effective_index,
            other.w_effective_index) &&
        gf::Eq(constant, other.constant) &&
        select_left == other.select_left &&
        select_right == other.select_right &&
        prior_active == other.prior_active &&
        prior_task_row == other.prior_task_row &&
        prior_output_lane == other.prior_output_lane;
}

bool BuildHashPlanV1(
    const std::array<SourceShardV1, kTapeShardsV1>& shards,
    const uint256& source_inventory_root,
    uint64_t family_tag,
    uint32_t parent_rows,
    uint32_t selector_n_lde,
    uint32_t selector_stride,
    const merkle::TypedHashPlanV1& hash_plan,
    PlanV1& out,
    std::string* why)
{
    out = {};
    if (!ValidSourceShards(shards) ||
        family_tag == 0 ||
        source_inventory_root.IsNull() ||
        !PowerOfTwo(parent_rows) ||
        !PowerOfTwo(selector_n_lde) ||
        selector_stride == 0 ||
        selector_stride >= selector_n_lde ||
        !hash_plan.valid ||
        !hash_plan.every_input_lane_resolved ||
        !hash_plan.every_prior_precedes_consumer ||
        !hash_plan.every_source_address_canonical ||
        !hash_plan.lane_ownership_unique ||
        !hash_plan.output_inventory_complete ||
        hash_plan.task_rows == 0 ||
        hash_plan.task_rows > parent_rows ||
        hash_plan.resolved_input_lanes !=
            hash_plan.expected_input_lanes ||
        hash_plan.expected_input_lanes !=
            uint64_t{hash_plan.task_rows} *
                kHashLanesV1 ||
        hash_plan.output_aliases !=
            hash_plan.expected_output_aliases) {
        return Fail(why, "hash_plan_input");
    }
    out.family = FamilyV1::Hash;
    out.family_tag = family_tag ^ kHashFamilyDomainV1;
    out.source_shards = shards;
    out.proof_tape_root = ProofTapeRoot(shards);
    out.source_inventory_root = source_inventory_root;
    out.parent_rows = parent_rows;
    out.relation_rows = hash_plan.task_rows;
    out.selector_n_lde = selector_n_lde;
    out.selector_stride = selector_stride;
    out.rows.resize(parent_rows);
    for (uint32_t row = 0;
         row < out.relation_rows; ++row) {
        out.rows[row].active = true;
        out.rows[row].task_ordinal = row;
    }
    bool ok = true;
    for (const auto& expression : hash_plan.inputs) {
        if (!expression.resolved ||
            expression.task_row >=
                out.relation_rows ||
            expression.lane >= kHashLanesV1) {
            return Fail(why, "hash_expression_shape");
        }
        auto& row = out.rows[expression.task_row];
        row.hash_lane[expression.lane] =
            DescribeHashLane(expression, ok);
        if (!ok ||
            !AssignSource(
                shards,
                expression.source_addresses[0],
                row.source[2 * expression.lane]) ||
            !AssignSource(
                shards,
                expression.source_addresses[1],
                row.source[
                    2 * expression.lane + 1])) {
            return Fail(why, "hash_expression_source");
        }
        if (expression.selector_address != UINT32_MAX) {
            if (!AssignSource(
                    shards,
                    expression.selector_address,
                    row.source[
                        kHashSelectorSlotV1])) {
                return Fail(why, "hash_selector_source");
            }
            if (row.selector_active &&
                (row.selector_bit !=
                     expression.selector_bit ||
                 row.selector_is_derived_next !=
                     expression
                         .selector_is_derived_next)) {
                return Fail(why, "hash_selector_conflict");
            }
            row.selector_active = true;
            row.selector_bit = expression.selector_bit;
            row.selector_is_derived_next =
                expression.selector_is_derived_next;
        }
    }
    for (const auto& output : hash_plan.outputs) {
        if (output.task_row >= out.relation_rows ||
            output.lane >= kHashOutputLanesV1) {
            return Fail(why, "hash_output_shape");
        }
        auto& row = out.rows[output.task_row];
        const uint32_t base =
            kHashOutputSlotBaseV1 + 2 * output.lane;
        if (!AssignSource(
                shards,
                output.source_addresses[0],
                row.source[base]) ||
            !AssignSource(
                shards,
                output.source_addresses[1],
                row.source[base + 1])) {
            return Fail(why, "hash_output_source");
        }
        row.hash_output_active[output.lane] = true;
    }
    PopulateMultiplicity(out);
    out.exact_relation_schedule = true;
    out.exact_source_multiplicity = true;
    out.exact_prior_memory_schedule = true;
    out.exact_manifest_count =
        out.manifest_reads <= kMaxManifestReadsV1;
    out.zero_padding_canonical = true;
    out.valid = true;
    out.schedule_root = CommitPlan(out);
    if (!ValidPlan(out)) {
        out = {};
        return Fail(why, "hash_plan_invariant");
    }
    out.note =
        "cross-shard exact hash descriptor manifest";
    if (why != nullptr) *why = out.note;
    return true;
}

bool BuildFoldPlanV1(
    const std::array<SourceShardV1, kTapeShardsV1>& shards,
    const uint256& source_inventory_root,
    uint64_t family_tag,
    uint32_t parent_rows,
    const merkle::TypedFoldPlanV1& fold_plan,
    PlanV1& out,
    std::string* why)
{
    out = {};
    if (!ValidSourceShards(shards) ||
        family_tag == 0 ||
        source_inventory_root.IsNull() ||
        !PowerOfTwo(parent_rows) ||
        !fold_plan.valid ||
        !fold_plan.every_source_address_canonical ||
        !fold_plan.exact_query_fold_schedule ||
        fold_plan.real_rows == 0 ||
        fold_plan.real_rows !=
            fold_plan.expected_real_rows ||
        fold_plan.real_rows > parent_rows) {
        return Fail(why, "fold_plan_input");
    }
    out.family = FamilyV1::Fold;
    out.family_tag = family_tag ^ kFoldFamilyDomainV1;
    out.source_shards = shards;
    out.proof_tape_root = ProofTapeRoot(shards);
    out.source_inventory_root = source_inventory_root;
    out.parent_rows = parent_rows;
    out.relation_rows = fold_plan.real_rows;
    out.rows.resize(parent_rows);
    for (const auto& fold : fold_plan.rows) {
        if (!fold.valid ||
            fold.row >= out.relation_rows) {
            return Fail(why, "fold_row_shape");
        }
        auto& row = out.rows[fold.row];
        row.active = true;
        row.task_ordinal = fold.row;
        uint32_t slot = 0;
        const auto assign_array =
            [&](const std::array<uint32_t, 6>& addresses) {
                for (uint32_t address : addresses) {
                    if (slot >= kSourceSlotsV1 ||
                        !AssignSource(
                            shards, address,
                            row.source[slot++])) {
                        return false;
                    }
                }
                return true;
            };
        if (!assign_array(fold.even) ||
            !assign_array(fold.odd) ||
            !assign_array(fold.beta) ||
            !assign_array(fold.final_value) ||
            !AssignSource(
                shards, fold.index,
                row.source[slot++]) ||
            !AssignSource(
                shards, fold.even_index,
                row.source[slot++]) ||
            !AssignSource(
                shards, fold.odd_index,
                row.source[slot++]) ||
            slot != 27) {
            return Fail(why, "fold_source_inventory");
        }
    }
    for (uint32_t row = 0;
         row < out.relation_rows; ++row) {
        if (!out.rows[row].active) {
            return Fail(why, "fold_schedule_gap");
        }
    }
    PopulateMultiplicity(out);
    out.exact_relation_schedule = true;
    out.exact_source_multiplicity = true;
    out.exact_prior_memory_schedule = true;
    out.exact_manifest_count =
        out.manifest_reads <= kMaxManifestReadsV1;
    out.zero_padding_canonical = true;
    out.valid = true;
    out.schedule_root = CommitPlan(out);
    if (!ValidPlan(out)) {
        out = {};
        return Fail(why, "fold_plan_invariant");
    }
    out.note =
        "cross-shard exact fold descriptor manifest";
    if (why != nullptr) *why = out.note;
    return true;
}

uint32_t LayoutV1::SourceValue(uint32_t slot) const
{
    return source_value_base + slot;
}
uint32_t LayoutV1::SourceActive(uint32_t slot) const
{
    return source_active_base + slot;
}
uint32_t LayoutV1::SourceGlobalOrdinal(uint32_t slot) const
{
    return source_global_ordinal_base + slot;
}
uint32_t LayoutV1::SourceAddressTag(uint32_t slot) const
{
    return source_address_tag_base + slot;
}
uint32_t LayoutV1::CoverageRoot(uint32_t limb) const
{
    return coverage_root_base + limb;
}
uint32_t LayoutV1::HashCoefficient(
    uint32_t lane, uint32_t coefficient) const
{
    return hash_coefficient_base +
        lane * 7 + coefficient;
}
uint32_t LayoutV1::HashPriorActive(uint32_t lane) const
{
    return hash_prior_active_base + lane;
}
uint32_t LayoutV1::HashPriorTask(uint32_t lane) const
{
    return hash_prior_task_base + lane;
}
uint32_t LayoutV1::HashPriorLane(uint32_t lane) const
{
    return hash_prior_lane_base + lane;
}
uint32_t LayoutV1::HashSelectorChoice(uint32_t bit) const
{
    return hash_selector_choice_base + bit;
}
uint32_t LayoutV1::HashOutputActive(uint32_t lane) const
{
    return hash_output_active_base + lane;
}
uint32_t LayoutV1::HashSourceSelectorBit(uint32_t bit) const
{
    return hash_source_selector_bit_base + bit;
}
uint32_t LayoutV1::HashEffectiveSelectorBit(uint32_t bit) const
{
    return hash_effective_selector_bit_base + bit;
}
uint32_t LayoutV1::HashPriorValue(uint32_t lane) const
{
    return hash_prior_value_base + lane;
}
uint32_t LayoutV1::HashExpectedInput(uint32_t lane) const
{
    return hash_expected_input_base + lane;
}
uint32_t LayoutV1::TapeConsumerInverse(
    uint32_t lane, uint32_t slot) const
{
    return tape_consumer_inverse_base +
        lane * kSourceSlotsV1 + slot;
}
uint32_t LayoutV1::HashInputInverse(
    uint32_t lane, uint32_t input_lane) const
{
    return hash_input_inverse_base +
        lane * kHashLanesV1 + input_lane;
}
uint32_t LayoutV1::PriorConsumerInverse(
    uint32_t lane, uint32_t output_lane) const
{
    return prior_consumer_inverse_base +
        lane * kHashLanesV1 + output_lane;
}
uint32_t LayoutV1::HashOutputInverse(
    uint32_t lane, uint32_t output_lane) const
{
    return hash_output_inverse_base +
        lane * kHashOutputLanesV1 + output_lane;
}
uint32_t LayoutV1::FoldInputInverse(
    uint32_t lane, uint32_t input_lane) const
{
    return fold_input_inverse_base +
        lane * kFoldInputLanesV1 + input_lane;
}

namespace {

inline constexpr uint32_t kTerminalGroupsV1 =
    5;

uint32_t TerminalGroup(
    TerminalFamilyV1 family, uint32_t /*shard*/)
{
    switch (family) {
    case TerminalFamilyV1::Tape:
        return 0;
    case TerminalFamilyV1::HashInput:
        return 1;
    case TerminalFamilyV1::PriorOutput:
        return 2;
    case TerminalFamilyV1::HashOutputAlias:
        return 3;
    case TerminalFamilyV1::FoldInput:
        return 4;
    }
    return UINT32_MAX;
}

LayoutV1 DeterministicLayout(
    uint32_t base, FamilyV1 family)
{
    LayoutV1 out;
    uint32_t cursor = base;
    out.source_value_base = cursor;
    cursor += kSourceSlotsV1;
    out.source_active_base = cursor;
    cursor += kSourceSlotsV1;
    out.source_global_ordinal_base = cursor;
    cursor += kSourceSlotsV1;
    out.source_address_tag_base = cursor;
    cursor += kSourceSlotsV1;
    out.coverage_root_base = cursor;
    cursor += alg_hash::kAlgHashDigestLen;
    out.row_active = cursor++;
    out.task_ordinal = cursor++;
    if (family == FamilyV1::Hash) {
        out.hash_coefficient_base = cursor;
        cursor += 7 * kHashLanesV1;
        out.hash_prior_active_base = cursor;
        cursor += kHashLanesV1;
        out.hash_prior_task_base = cursor;
        cursor += kHashLanesV1;
        out.hash_prior_lane_base = cursor;
        cursor += kHashLanesV1;
        out.hash_selector_active = cursor++;
        out.hash_selector_derived = cursor++;
        out.hash_selector_choice_base = cursor;
        cursor += 32;
        out.hash_output_active_base = cursor;
        cursor += kHashOutputLanesV1;
        out.hash_source_selector_bit_base = cursor;
        cursor += 32;
        out.hash_effective_selector = cursor++;
        out.hash_effective_selector_bit_base = cursor;
        cursor += 32;
        out.hash_selector_wrap = cursor++;
        out.hash_selected_bit = cursor++;
        out.hash_prior_value_base = cursor;
        cursor += kHashLanesV1;
        out.hash_expected_input_base = cursor;
        cursor += kHashLanesV1;
    }
    out.deterministic_end = cursor;
    return out;
}

void CompleteDependentLayout(LayoutV1& layout)
{
    uint32_t cursor = layout.deterministic_end;
    layout.tape_consumer_inverse_base = cursor;
    cursor += kLookupLanesV1 * kSourceSlotsV1;
    layout.hash_input_inverse_base = cursor;
    cursor += kLookupLanesV1 * kHashLanesV1;
    layout.prior_consumer_inverse_base = cursor;
    cursor += kLookupLanesV1 * kHashLanesV1;
    layout.hash_output_inverse_base = cursor;
    cursor += kLookupLanesV1 * kHashOutputLanesV1;
    layout.fold_input_inverse_base = cursor;
    cursor += kLookupLanesV1 * kFoldInputLanesV1;
    layout.running_base = cursor;
    cursor += kTerminalGroupsV1 * kLookupLanesV1;
    layout.terminal_base = cursor;
    cursor += kTerminalGroupsV1 * kLookupLanesV1;
    layout.acceptance = cursor++;
    layout.end = cursor;
}

class ExprV1 {
public:
    std::vector<cb::Instruction> instruction;
    std::vector<uint32_t> degree;

    uint32_t Current(uint32_t column)
    {
        cb::Instruction out;
        out.opcode = cb::Opcode::Current;
        out.lhs = column;
        instruction.push_back(out);
        degree.push_back(1);
        return static_cast<uint32_t>(
            instruction.size() - 1);
    }
    uint32_t Next(uint32_t column)
    {
        cb::Instruction out;
        out.opcode = cb::Opcode::Next;
        out.lhs = column;
        instruction.push_back(out);
        degree.push_back(1);
        return static_cast<uint32_t>(
            instruction.size() - 1);
    }
    uint32_t Challenge(uint32_t index)
    {
        cb::Instruction out;
        out.opcode = cb::Opcode::Challenge;
        out.lhs = index;
        instruction.push_back(out);
        // V3 challenges are verifier scalars, never trace polynomials.
        degree.push_back(0);
        return static_cast<uint32_t>(
            instruction.size() - 1);
    }
    uint32_t Constant(const Fp3& value)
    {
        cb::Instruction out;
        out.opcode = cb::Opcode::Constant;
        out.constant = value;
        instruction.push_back(out);
        degree.push_back(0);
        return static_cast<uint32_t>(
            instruction.size() - 1);
    }
    uint32_t Binary(
        cb::Opcode opcode,
        uint32_t left,
        uint32_t right)
    {
        cb::Instruction out;
        out.opcode = opcode;
        out.lhs = left;
        out.rhs = right;
        instruction.push_back(out);
        degree.push_back(
            opcode == cb::Opcode::Mul
                ? degree[left] + degree[right]
                : std::max(
                    degree[left], degree[right]));
        return static_cast<uint32_t>(
            instruction.size() - 1);
    }
    uint32_t Add(uint32_t left, uint32_t right)
    {
        return Binary(cb::Opcode::Add, left, right);
    }
    uint32_t Sub(uint32_t left, uint32_t right)
    {
        return Binary(cb::Opcode::Sub, left, right);
    }
    uint32_t Mul(uint32_t left, uint32_t right)
    {
        return Binary(cb::Opcode::Mul, left, right);
    }
};

template <typename Build>
void AppendProgram(
    cb::ProgramTable& table,
    aq::AirKind kind,
    Build&& build)
{
    ExprV1 expression;
    build(expression);
    cb::Program program;
    program.version =
        cb::kConstraintBytecodeScalarChallengeVersion;
    program.role = RCStage3RelationRole::CompositionLink;
    program.constraint_ordinal =
        static_cast<uint32_t>(table.programs.size());
    program.kind = kind;
    program.declared_degree =
        expression.degree.back();
    program.current_width = table.current_width;
    program.next_width = table.next_width;
    program.challenge_width = table.challenge_width;
    program.instructions =
        std::move(expression.instruction);
    table.programs.push_back(std::move(program));
}

bool DegreeCapsHold(const AirCS& cs)
{
    for (const auto& constraint : cs.constraints) {
        const bool boundary =
            constraint.kind == aq::AirKind::kFirstRow ||
            constraint.kind == aq::AirKind::kLastRow;
        if ((boundary && constraint.alg_degree > 2) ||
            (!boundary && constraint.alg_degree > 3)) {
            return false;
        }
    }
    return true;
}

bool AppendTable(
    const cb::ProgramTable& table,
    uint32_t rows,
    const std::vector<Fp3>& challenges,
    AirCS& parent,
    alg_hash::Digest* root,
    uint32_t* appended,
    std::string* why)
{
    std::string local;
    if (!cb::ValidateProgramTable(table, &local) ||
        !cb::ProgramTableIsChallengeIndependent(table)) {
        for (uint32_t ordinal = 0;
             ordinal < table.programs.size();
             ++ordinal) {
            std::string program_why;
            if (!cb::ValidateProgram(
                    table.programs[ordinal],
                    &program_why)) {
                return Fail(
                    why,
                    "program[" +
                        std::to_string(ordinal) +
                        "]:" + program_why);
            }
        }
        return Fail(why, "program:" + local);
    }
    AirCS adapter;
    if (!cb::BuildAirConstraintSystemFromProgramTable(
            table, rows, challenges, adapter, &local)) {
        return Fail(
            why, "program_adapter:" + local);
    }
    if (!DegreeCapsHold(adapter)) {
        return Fail(why, "program_degree_cap");
    }
    if (appended != nullptr) {
        *appended =
            static_cast<uint32_t>(
                adapter.constraints.size());
    }
    for (auto& constraint : adapter.constraints) {
        parent.constraints.push_back(
            std::move(constraint));
    }
    if (root != nullptr) {
        *root = cb::CommitProgramTableAlgHash(table);
    }
    return true;
}

uint32_t ComposeWord(
    ExprV1& e,
    const LayoutV1& layout,
    uint32_t slot)
{
    return e.Add(
        e.Current(layout.SourceValue(slot)),
        e.Mul(
            e.Constant(U(uint64_t{1} << 32)),
            e.Current(
                layout.SourceValue(slot + 1))));
}

uint32_t HashExpected(
    ExprV1& e,
    const LayoutV1& layout,
    uint32_t lane)
{
    const uint32_t s0 =
        e.Current(layout.SourceValue(2 * lane));
    const uint32_t s1 =
        e.Current(layout.SourceValue(2 * lane + 1));
    const uint32_t prior =
        e.Current(layout.HashPriorValue(lane));
    const uint32_t effective =
        e.Current(layout.hash_effective_selector);
    uint32_t expected =
        e.Current(layout.HashCoefficient(lane, 4));
    const std::array<uint32_t, 4> value{{
        s0, s1, prior, effective}};
    for (uint32_t coefficient = 0;
         coefficient < value.size();
         ++coefficient) {
        expected = e.Add(
            expected,
            e.Mul(
                e.Current(
                    layout.HashCoefficient(
                        lane, coefficient)),
                value[coefficient]));
    }
    const uint32_t sibling =
        e.Add(
            s0,
            e.Mul(
                e.Constant(U(uint64_t{1} << 32)),
                s1));
    const uint32_t selected =
        e.Current(layout.hash_selected_bit);
    expected = e.Add(
        expected,
        e.Mul(
            e.Current(
                layout.HashCoefficient(lane, 5)),
            e.Mul(
                selected,
                e.Sub(sibling, prior))));
    return e.Add(
        expected,
        e.Mul(
            e.Current(
                layout.HashCoefficient(lane, 6)),
            e.Mul(
                selected,
                e.Sub(prior, sibling))));
}

uint32_t FoldInput(
    ExprV1& e,
    const LayoutV1& layout,
    uint32_t input_lane)
{
    if (input_lane >= 4) {
        return e.Current(
            layout.SourceValue(24 + input_lane - 4));
    }
    uint32_t value = e.Constant(Fp3::Zero());
    for (uint32_t coordinate = 0;
         coordinate < 3; ++coordinate) {
        const uint32_t word = ComposeWord(
            e, layout,
            input_lane * 6 + 2 * coordinate);
        Fp3 basis = Fp3::Zero();
        if (coordinate == 0) {
            basis.c0 = gf::FromU64(1);
        } else if (coordinate == 1) {
            basis.c1 = gf::FromU64(1);
        } else {
            basis.c2 = gf::FromU64(1);
        }
        value = e.Add(
            value,
            e.Mul(e.Constant(basis), word));
    }
    return value;
}

cb::ProgramTable BuildDeterministicPrograms(
    const PlanV1& plan,
    const LayoutV1& layout)
{
    cb::ProgramTable table;
    table.version =
        cb::kConstraintBytecodeScalarChallengeVersion;
    table.role = RCStage3RelationRole::CompositionLink;
    table.current_width = layout.deterministic_end;
    table.next_width = layout.deterministic_end;
    table.challenge_width = 0;
    const Fp3 one = Fp3::One();
    for (uint32_t slot = 0;
         slot < kSourceSlotsV1; ++slot) {
        AppendProgram(
            table, aq::AirKind::kEverywhere,
            [=](ExprV1& e) {
                e.Mul(
                    e.Sub(
                        e.Constant(one),
                        e.Current(
                            layout.SourceActive(slot))),
                    e.Current(
                        layout.SourceValue(slot)));
            });
    }
    if (plan.family == FamilyV1::Hash) {
        for (uint32_t lane = 0;
             lane < kHashLanesV1; ++lane) {
            AppendProgram(
                table, aq::AirKind::kEverywhere,
                [=](ExprV1& e) {
                    e.Mul(
                        e.Sub(
                            e.Constant(one),
                            e.Current(
                                layout.HashPriorActive(
                                    lane))),
                        e.Current(
                            layout.HashPriorValue(lane)));
                });
            AppendProgram(
                table, aq::AirKind::kEverywhere,
                [=](ExprV1& e) {
                    e.Sub(
                        e.Current(
                            layout.HashExpectedInput(
                                lane)),
                        HashExpected(e, layout, lane));
                });
        }
        for (uint32_t bit = 0; bit < 32; ++bit) {
            AppendProgram(
                table, aq::AirKind::kEverywhere,
                [=](ExprV1& e) {
                    const uint32_t value =
                        e.Current(
                            layout.HashSourceSelectorBit(
                                bit));
                    e.Mul(
                        value,
                        e.Sub(value, e.Constant(one)));
                });
            AppendProgram(
                table, aq::AirKind::kEverywhere,
                [=](ExprV1& e) {
                    const uint32_t value =
                        e.Current(
                            layout
                                .HashEffectiveSelectorBit(
                                    bit));
                    e.Mul(
                        value,
                        e.Sub(value, e.Constant(one)));
                });
        }
        AppendProgram(
            table, aq::AirKind::kEverywhere,
            [=](ExprV1& e) {
                uint32_t value =
                    e.Constant(Fp3::Zero());
                uint64_t weight = 1;
                for (uint32_t bit = 0;
                     bit < 32; ++bit) {
                    value = e.Add(
                        value,
                        e.Mul(
                            e.Constant(U(weight)),
                            e.Current(
                                layout
                                    .HashSourceSelectorBit(
                                        bit))));
                    weight <<= 1;
                }
                e.Sub(
                    e.Current(
                        layout.SourceValue(
                            kHashSelectorSlotV1)),
                    value);
            });
        AppendProgram(
            table, aq::AirKind::kEverywhere,
            [=](ExprV1& e) {
                uint32_t value =
                    e.Constant(Fp3::Zero());
                uint64_t weight = 1;
                for (uint32_t bit = 0;
                     bit < 32; ++bit) {
                    value = e.Add(
                        value,
                        e.Mul(
                            e.Constant(U(weight)),
                            e.Current(
                                layout
                                    .HashEffectiveSelectorBit(
                                        bit))));
                    weight <<= 1;
                }
                e.Sub(
                    e.Current(
                        layout.hash_effective_selector),
                    value);
            });
        const uint32_t selector_bits =
            std::countr_zero(plan.selector_n_lde);
        for (uint32_t bit = selector_bits;
             bit < 32; ++bit) {
            AppendProgram(
                table, aq::AirKind::kEverywhere,
                [=](ExprV1& e) {
                    e.Current(
                        layout.HashSourceSelectorBit(bit));
                });
            AppendProgram(
                table, aq::AirKind::kEverywhere,
                [=](ExprV1& e) {
                    e.Current(
                        layout
                            .HashEffectiveSelectorBit(bit));
                });
        }
        AppendProgram(
            table, aq::AirKind::kEverywhere,
            [=](ExprV1& e) {
                const uint32_t wrap =
                    e.Current(layout.hash_selector_wrap);
                e.Mul(
                    wrap,
                    e.Sub(wrap, e.Constant(one)));
            });
        AppendProgram(
            table, aq::AirKind::kEverywhere,
            [=](ExprV1& e) {
                e.Mul(
                    e.Sub(
                        e.Constant(one),
                        e.Current(
                            layout.hash_selector_derived)),
                    e.Current(
                        layout.hash_selector_wrap));
            });
        AppendProgram(
            table, aq::AirKind::kEverywhere,
            [=](ExprV1& e) {
                const uint32_t source =
                    e.Current(
                        layout.SourceValue(
                            kHashSelectorSlotV1));
                const uint32_t derived =
                    e.Current(
                        layout.hash_selector_derived);
                const uint32_t wrap =
                    e.Current(layout.hash_selector_wrap);
                e.Sub(
                    e.Current(
                        layout.hash_effective_selector),
                    e.Sub(
                        e.Add(
                            source,
                            e.Mul(
                                derived,
                                e.Constant(U(
                                    plan
                                        .selector_stride)))),
                        e.Mul(
                            e.Mul(derived, wrap),
                            e.Constant(U(
                                plan
                                    .selector_n_lde)))));
            });
        AppendProgram(
            table, aq::AirKind::kEverywhere,
            [=](ExprV1& e) {
                uint32_t selected =
                    e.Constant(Fp3::Zero());
                for (uint32_t bit = 0;
                     bit < 32; ++bit) {
                    selected = e.Add(
                        selected,
                        e.Mul(
                            e.Current(
                                layout.HashSelectorChoice(
                                    bit)),
                            e.Current(
                                layout
                                    .HashEffectiveSelectorBit(
                                        bit))));
                }
                e.Sub(
                    e.Current(layout.hash_selected_bit),
                    selected);
            });
        AppendProgram(
            table, aq::AirKind::kEverywhere,
            [=](ExprV1& e) {
                const uint32_t selected =
                    e.Current(layout.hash_selected_bit);
                e.Mul(
                    selected,
                    e.Sub(selected, e.Constant(one)));
            });
    }
    return table;
}

} // namespace

uint32_t LayoutV1::Running(
    TerminalFamilyV1 family,
    uint32_t shard,
    uint32_t lane) const
{
    return running_base +
        TerminalGroup(family, shard) *
            kLookupLanesV1 +
        lane;
}

uint32_t LayoutV1::Terminal(
    TerminalFamilyV1 family,
    uint32_t shard,
    uint32_t lane) const
{
    return terminal_base +
        TerminalGroup(family, shard) *
            kLookupLanesV1 +
        lane;
}

bool AppendDeterministicConstraintSystemV1(
    const PlanV1& plan,
    AirCS& cs,
    DeterministicAttachmentV1& out,
    std::string* why)
{
    out = {};
    if (!ValidPlan(plan) ||
        cs.n_rows != plan.parent_rows) {
        return Fail(why, "deterministic_input");
    }
    out.plan = plan;
    out.layout =
        DeterministicLayout(cs.n_columns, plan.family);
    const uint32_t old_columns = cs.n_columns;
    cs.n_columns = out.layout.deterministic_end;
    const uint32_t rows = cs.n_rows;
    uint32_t preprocessed_columns = 0;
    const auto add_preprocessed =
        [&](uint32_t column,
            std::vector<Fp3> values) {
            cs.preprocessed.emplace_back(
                column, std::move(values));
            ++preprocessed_columns;
        };
    for (uint32_t slot = 0;
         slot < kSourceSlotsV1; ++slot) {
        std::vector<Fp3> active(rows, Fp3::Zero());
        std::vector<Fp3> ordinal(rows, Fp3::Zero());
        std::vector<Fp3> address_tag(rows, Fp3::Zero());
        for (uint32_t row = 0; row < rows; ++row) {
            const auto& source =
                plan.rows[row].source[slot];
            if (!source.active) continue;
            active[row] = Fp3::One();
            ordinal[row] = U(source.global_ordinal);
            address_tag[row] = U(
                uint64_t{source.address} +
                (uint64_t{source.source_shard_ordinal}
                 << 32));
        }
        add_preprocessed(
            out.layout.SourceActive(slot),
            std::move(active));
        add_preprocessed(
            out.layout.SourceGlobalOrdinal(slot),
            std::move(ordinal));
        add_preprocessed(
            out.layout.SourceAddressTag(slot),
            std::move(address_tag));
    }
    for (uint32_t limb = 0;
         limb < alg_hash::kAlgHashDigestLen; ++limb) {
        std::vector<Fp3> values(rows, Fp3::Zero());
        values[0] =
            Fp3::FromFp(plan.schedule_root[limb]);
        add_preprocessed(
            out.layout.CoverageRoot(limb),
            std::move(values));
    }
    std::vector<Fp3> row_active(rows, Fp3::Zero());
    std::vector<Fp3> task_ordinal(rows, Fp3::Zero());
    for (uint32_t row = 0; row < rows; ++row) {
        if (!plan.rows[row].active) continue;
        row_active[row] = Fp3::One();
        task_ordinal[row] =
            U(plan.rows[row].task_ordinal);
    }
    add_preprocessed(
        out.layout.row_active,
        std::move(row_active));
    add_preprocessed(
        out.layout.task_ordinal,
        std::move(task_ordinal));

    if (plan.family == FamilyV1::Hash) {
        for (uint32_t lane = 0;
             lane < kHashLanesV1; ++lane) {
            std::array<std::vector<Fp3>, 7> coefficient;
            for (auto& values : coefficient) {
                values.assign(rows, Fp3::Zero());
            }
            std::vector<Fp3> prior_active(
                rows, Fp3::Zero());
            std::vector<Fp3> prior_task(
                rows, Fp3::Zero());
            std::vector<Fp3> prior_lane(
                rows, Fp3::Zero());
            for (uint32_t row = 0;
                 row < plan.relation_rows; ++row) {
                const auto& descriptor =
                    plan.rows[row].hash_lane[lane];
                coefficient[0][row] = descriptor.w0;
                coefficient[1][row] = descriptor.w1;
                coefficient[2][row] =
                    descriptor.w_prior;
                coefficient[3][row] =
                    descriptor.w_effective_index;
                coefficient[4][row] =
                    descriptor.constant;
                coefficient[5][row] =
                    descriptor.select_left
                        ? Fp3::One()
                        : Fp3::Zero();
                coefficient[6][row] =
                    descriptor.select_right
                        ? Fp3::One()
                        : Fp3::Zero();
                if (descriptor.prior_active) {
                    prior_active[row] = Fp3::One();
                    prior_task[row] =
                        U(descriptor.prior_task_row);
                    prior_lane[row] =
                        U(descriptor.prior_output_lane);
                }
            }
            for (uint32_t index = 0;
                 index < coefficient.size(); ++index) {
                add_preprocessed(
                    out.layout.HashCoefficient(
                        lane, index),
                    std::move(coefficient[index]));
            }
            add_preprocessed(
                out.layout.HashPriorActive(lane),
                std::move(prior_active));
            add_preprocessed(
                out.layout.HashPriorTask(lane),
                std::move(prior_task));
            add_preprocessed(
                out.layout.HashPriorLane(lane),
                std::move(prior_lane));
        }
        std::vector<Fp3> selector_active(
            rows, Fp3::Zero());
        std::vector<Fp3> selector_derived(
            rows, Fp3::Zero());
        std::array<std::vector<Fp3>, 32>
            selector_choice;
        for (auto& values : selector_choice) {
            values.assign(rows, Fp3::Zero());
        }
        std::array<std::vector<Fp3>,
                   kHashOutputLanesV1>
            output_active;
        for (auto& values : output_active) {
            values.assign(rows, Fp3::Zero());
        }
        for (uint32_t row = 0;
             row < plan.relation_rows; ++row) {
            const auto& descriptor = plan.rows[row];
            if (descriptor.selector_active) {
                selector_active[row] = Fp3::One();
                selector_derived[row] =
                    descriptor.selector_is_derived_next
                        ? Fp3::One()
                        : Fp3::Zero();
                selector_choice[
                    descriptor.selector_bit][row] =
                    Fp3::One();
            }
            for (uint32_t lane = 0;
                 lane < kHashOutputLanesV1; ++lane) {
                output_active[lane][row] =
                    descriptor
                            .hash_output_active[lane]
                        ? Fp3::One()
                        : Fp3::Zero();
            }
        }
        add_preprocessed(
            out.layout.hash_selector_active,
            std::move(selector_active));
        add_preprocessed(
            out.layout.hash_selector_derived,
            std::move(selector_derived));
        for (uint32_t bit = 0; bit < 32; ++bit) {
            add_preprocessed(
                out.layout.HashSelectorChoice(bit),
                std::move(selector_choice[bit]));
        }
        for (uint32_t lane = 0;
             lane < kHashOutputLanesV1; ++lane) {
            add_preprocessed(
                out.layout.HashOutputActive(lane),
                std::move(output_active[lane]));
        }
    }
    cs.preprocessed_pin_ood = true;
    const cb::ProgramTable table =
        BuildDeterministicPrograms(plan, out.layout);
    if (!AppendTable(
            table, rows, {}, cs,
            &out.deterministic_program_root,
            &out.constraints_appended, why)) {
        return false;
    }
    out.columns_appended =
        cs.n_columns - old_columns;
    out.preprocessed_columns = preprocessed_columns;
    out.source_values_ordinary = true;
    out.fixed_schedule_preprocessed = true;
    out.prior_memory_values_ordinary =
        plan.family == FamilyV1::Hash;
    out.unused_slots_zero_constrained = true;
    out.v3_scalar_challenges = true;
    out.degree_caps_closed = DegreeCapsHold(cs);
    out.valid =
        out.columns_appended != 0 &&
        out.preprocessed_columns != 0 &&
        Nonzero(out.deterministic_program_root) &&
        out.source_values_ordinary &&
        out.fixed_schedule_preprocessed &&
        out.unused_slots_zero_constrained &&
        out.v3_scalar_challenges &&
        out.degree_caps_closed;
    out.note = out.valid
        ? "V3 exact descriptor schedule committed; post-all-R0 terminals pending"
        : "deterministic descriptor invariant";
    if (!out.valid) {
        return Fail(why, "deterministic_invariant");
    }
    if (why != nullptr) *why = out.note;
    return true;
}

namespace {

bool BaseField(const Fp3& value)
{
    return gf::Canonical(value.c1) == 0 &&
        gf::Canonical(value.c2) == 0;
}

Fp3 EvaluateHashLaneWitness(
    const RowDescriptorV1& row,
    uint32_t lane,
    const std::array<Fp3, kSourceSlotsV1>& source,
    const Fp3& prior,
    uint32_t effective,
    uint32_t selected)
{
    const auto& descriptor = row.hash_lane[lane];
    Fp3 expected = descriptor.constant;
    expected = gf::Add(
        expected,
        gf::Mul(
            descriptor.w0, source[2 * lane]));
    expected = gf::Add(
        expected,
        gf::Mul(
            descriptor.w1,
            source[2 * lane + 1]));
    expected = gf::Add(
        expected,
        gf::Mul(descriptor.w_prior, prior));
    expected = gf::Add(
        expected,
        gf::Mul(
            descriptor.w_effective_index,
            U(effective)));
    const Fp3 sibling = gf::Add(
        source[2 * lane],
        gf::Mul(
            U(uint64_t{1} << 32),
            source[2 * lane + 1]));
    if (descriptor.select_left) {
        expected = gf::Add(
            expected,
            gf::Mul(
                U(selected),
                gf::Sub(sibling, prior)));
    }
    if (descriptor.select_right) {
        expected = gf::Add(
            expected,
            gf::Mul(
                U(selected),
                gf::Sub(prior, sibling)));
    }
    return expected;
}

} // namespace

bool AppendDeterministicWitnessV1(
    const PlanV1& plan,
    const abi::DecodedV1& decoded,
    AirCS& cs,
    std::vector<std::vector<Fp3>>& columns,
    DeterministicAttachmentV1& out,
    std::string* why)
{
    const uint32_t old_columns = cs.n_columns;
    if (!decoded.canonical ||
        !decoded.complete ||
        !decoded.addresses_unique ||
        !decoded.semantic_keys_unique ||
        columns.size() != old_columns) {
        return Fail(why, "witness_input");
    }
    if (!AppendDeterministicConstraintSystemV1(
            plan, cs, out, why)) {
        return false;
    }
    for (const auto& column : columns) {
        if (column.size() != cs.n_rows) {
            return Fail(why, "witness_parent_rows");
        }
    }
    columns.resize(
        cs.n_columns,
        std::vector<Fp3>(
            cs.n_rows, Fp3::Zero()));
    std::vector<
        std::array<Fp3, kHashLanesV1>>
        hash_output(
            plan.relation_rows,
            std::array<Fp3, kHashLanesV1>{});
    for (uint32_t row = 0;
         row < plan.relation_rows; ++row) {
        std::array<Fp3, kSourceSlotsV1>
            source_value{};
        for (uint32_t slot = 0;
             slot < kSourceSlotsV1; ++slot) {
            const auto& source =
                plan.rows[row].source[slot];
            if (!source.active) continue;
            if (source.address >=
                    decoded.sources.size() ||
                decoded.sources[source.address].address !=
                    source.address ||
                !(decoded.sources[source.address].key ==
                  source.key)) {
                return Fail(
                    why, "witness_source_manifest");
            }
            source_value[slot] =
                U(decoded.sources[source.address].value);
            columns[
                out.layout.SourceValue(slot)][row] =
                source_value[slot];
        }
        if (plan.family != FamilyV1::Hash) continue;
        uint32_t source_selector = 0;
        uint32_t effective = 0;
        uint32_t wrap = 0;
        uint32_t selected = 0;
        if (plan.rows[row].selector_active) {
            source_selector = static_cast<uint32_t>(
                gf::Canonical(
                    source_value[
                        kHashSelectorSlotV1].c0));
            const uint64_t candidate =
                uint64_t{source_selector} +
                (plan.rows[row]
                         .selector_is_derived_next
                     ? plan.selector_stride
                     : 0U);
            wrap =
                candidate >= plan.selector_n_lde ? 1U : 0U;
            effective = static_cast<uint32_t>(
                candidate -
                uint64_t{wrap} * plan.selector_n_lde);
            selected =
                (effective >>
                 plan.rows[row].selector_bit) &
                1U;
        }
        if (source_selector >= plan.selector_n_lde ||
            effective >= plan.selector_n_lde) {
            return Fail(why, "witness_selector_range");
        }
        for (uint32_t bit = 0; bit < 32; ++bit) {
            columns[
                out.layout.HashSourceSelectorBit(bit)]
                [row] =
                U((source_selector >> bit) & 1U);
            columns[
                out.layout
                    .HashEffectiveSelectorBit(bit)]
                [row] =
                U((effective >> bit) & 1U);
        }
        columns[
            out.layout.hash_effective_selector][row] =
            U(effective);
        columns[out.layout.hash_selector_wrap][row] =
            U(wrap);
        columns[out.layout.hash_selected_bit][row] =
            U(selected);
        alg_hash::State permutation{};
        for (uint32_t lane = 0;
             lane < kHashLanesV1; ++lane) {
            const auto& descriptor =
                plan.rows[row].hash_lane[lane];
            Fp3 prior = Fp3::Zero();
            if (descriptor.prior_active) {
                if (descriptor.prior_task_row >= row ||
                    descriptor.prior_output_lane >=
                        kHashLanesV1) {
                    return Fail(
                        why, "witness_prior_order");
                }
                prior =
                    hash_output[
                        descriptor.prior_task_row]
                               [descriptor
                                    .prior_output_lane];
                columns[
                    out.layout.HashPriorValue(lane)]
                       [row] = prior;
            }
            const Fp3 expected =
                EvaluateHashLaneWitness(
                    plan.rows[row], lane,
                    source_value, prior,
                    effective, selected);
            columns[
                out.layout.HashExpectedInput(lane)]
                   [row] = expected;
            if (!BaseField(expected)) {
                return Fail(
                    why, "witness_nonbase_hash_input");
            }
            permutation[lane] = expected.c0;
        }
        alg_hash::Permute(permutation);
        for (uint32_t lane = 0;
             lane < kHashLanesV1; ++lane) {
            hash_output[row][lane] =
                Fp3::FromFp(permutation[lane]);
        }
    }
    for (const auto& [column, values] :
         cs.preprocessed) {
        if (column >= old_columns) {
            columns[column] = values;
        }
    }
    return true;
}

uint256 ComputePublicTapeChallengeSeedV1(
    const alg_hash::Digest& proof_tape_root,
    const uint256& source_inventory_root)
{
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_V14_TAPE_ROOT_SOURCE_CHALLENGE_V1";
    hash << kVersionV1;
    for (gf::Fp lane : proof_tape_root) {
        hash << static_cast<uint64_t>(
            gf::Canonical(lane));
    }
    hash << source_inventory_root;
    return hash.GetHash();
}

bool DeriveChallengesV1(
    const PlanV1& plan,
    ChallengesV1& out,
    std::string* why)
{
    out = {};
    const uint256 seed =
        ComputePublicTapeChallengeSeedV1(
            plan.proof_tape_root,
            plan.source_inventory_root);
    if (!ValidPlan(plan) || seed.IsNull()) {
        return Fail(why, "challenge_input");
    }
    for (uint32_t lane = 0;
         lane < kLookupLanesV1; ++lane) {
        const uint256 gamma_digest =
            aq::AirChallengeDigest(
                seed,
                "stage3.v14_tape_root.source_gamma",
                {plan.source_inventory_root},
                {lane});
        const uint256 alpha_digest =
            aq::AirChallengeDigest(
                seed,
                "stage3.v14_tape_root.source_alpha",
                {plan.source_inventory_root},
                {lane});
        out.gamma[lane] =
            gf::FromChallengeBytes3(
                gamma_digest.data());
        out.alpha[lane] =
            gf::FromChallengeBytes3(
                alpha_digest.data());
    }
    if (gf::IsZero(out.gamma[0]) ||
        gf::IsZero(out.gamma[1]) ||
        gf::Eq(out.gamma[0], out.gamma[1]) ||
        gf::Eq(out.alpha[0], out.alpha[1])) {
        out = {};
        return Fail(why, "challenge_sampling");
    }
    return true;
}

namespace {

uint32_t TupleDenominator(
    ExprV1& e,
    uint32_t lane,
    uint64_t family_tag,
    TerminalFamilyV1 terminal_family,
    const std::vector<uint32_t>& fields)
{
    const uint32_t gamma = e.Challenge(lane);
    uint32_t power = gamma;
    uint32_t tuple = e.Constant(U(family_tag));
    tuple = e.Add(
        tuple,
        e.Mul(
            power,
            e.Constant(U(
                kTerminalTagV1[
                    static_cast<uint8_t>(
                        terminal_family)]))));
    for (uint32_t field : fields) {
        power = e.Mul(power, gamma);
        tuple = e.Add(
            tuple, e.Mul(power, field));
    }
    return e.Sub(e.Challenge(2 + lane), tuple);
}

template <typename Active, typename Denominator>
void AppendInversePair(
    cb::ProgramTable& table,
    uint32_t inverse,
    Active&& active,
    Denominator&& denominator)
{
    const Fp3 one = Fp3::One();
    AppendProgram(
        table, aq::AirKind::kEverywhere,
        [=](ExprV1& e) {
            e.Sub(
                e.Mul(
                    e.Current(inverse),
                    denominator(e)),
                active(e));
        });
    AppendProgram(
        table, aq::AirKind::kEverywhere,
        [=](ExprV1& e) {
            e.Mul(
                e.Sub(e.Constant(one), active(e)),
                e.Current(inverse));
        });
}

cb::ProgramTable BuildFinalPrograms(
    const PlanV1& plan,
    const LayoutV1& layout)
{
    cb::ProgramTable table;
    table.version =
        cb::kConstraintBytecodeScalarChallengeVersion;
    table.role = RCStage3RelationRole::CompositionLink;
    table.current_width = layout.end;
    table.next_width = layout.end;
    table.challenge_width =
        2 * kLookupLanesV1;
    const Fp3 one = Fp3::One();
    for (uint32_t lane = 0;
         lane < kLookupLanesV1; ++lane) {
        for (uint32_t slot = 0;
             slot < kSourceSlotsV1; ++slot) {
            const uint32_t inverse =
                layout.TapeConsumerInverse(
                    lane, slot);
            AppendInversePair(
                table, inverse,
                [=](ExprV1& e) {
                    return e.Current(
                        layout.SourceActive(slot));
                },
                [=](ExprV1& e) {
                    return TupleDenominator(
                        e, lane, plan.family_tag,
                        TerminalFamilyV1::Tape,
                        {
                            e.Current(
                                layout
                                    .SourceAddressTag(
                                        slot)),
                            e.Current(
                                layout
                                    .SourceGlobalOrdinal(
                                        slot)),
                            e.Current(
                                layout.SourceValue(
                                    slot)),
                        });
                });
        }
        if (plan.family == FamilyV1::Hash) {
            for (uint32_t input_lane = 0;
                 input_lane < kHashLanesV1;
                 ++input_lane) {
                AppendInversePair(
                    table,
                    layout.HashInputInverse(
                        lane, input_lane),
                    [=](ExprV1& e) {
                        return e.Current(
                            layout.row_active);
                    },
                    [=](ExprV1& e) {
                        return TupleDenominator(
                            e, lane, plan.family_tag,
                            TerminalFamilyV1::HashInput,
                            {
                                e.Current(
                                    layout.task_ordinal),
                                e.Constant(U(input_lane)),
                                e.Current(
                                    layout.HashExpectedInput(
                                        input_lane)),
                            });
                    });
                AppendInversePair(
                    table,
                    layout.PriorConsumerInverse(
                        lane, input_lane),
                    [=](ExprV1& e) {
                        return e.Current(
                            layout.HashPriorActive(
                                input_lane));
                    },
                    [=](ExprV1& e) {
                        return TupleDenominator(
                            e, lane, plan.family_tag,
                            TerminalFamilyV1::PriorOutput,
                            {
                                e.Current(
                                    layout.HashPriorTask(
                                        input_lane)),
                                e.Current(
                                    layout.HashPriorLane(
                                        input_lane)),
                                e.Current(
                                    layout.HashPriorValue(
                                        input_lane)),
                            });
                    });
            }
            for (uint32_t output_lane = 0;
                 output_lane < kHashOutputLanesV1;
                 ++output_lane) {
                const uint32_t source_slot =
                    kHashOutputSlotBaseV1 +
                    2 * output_lane;
                AppendInversePair(
                    table,
                    layout.HashOutputInverse(
                        lane, output_lane),
                    [=](ExprV1& e) {
                        return e.Current(
                            layout.HashOutputActive(
                                output_lane));
                    },
                    [=](ExprV1& e) {
                        return TupleDenominator(
                            e, lane, plan.family_tag,
                            TerminalFamilyV1::
                                HashOutputAlias,
                            {
                                e.Current(
                                    layout.task_ordinal),
                                e.Constant(U(output_lane)),
                                ComposeWord(
                                    e, layout,
                                    source_slot),
                            });
                    });
            }
        } else {
            for (uint32_t input_lane = 0;
                 input_lane < kFoldInputLanesV1;
                 ++input_lane) {
                AppendInversePair(
                    table,
                    layout.FoldInputInverse(
                        lane, input_lane),
                    [=](ExprV1& e) {
                        return e.Current(
                            layout.row_active);
                    },
                    [=](ExprV1& e) {
                        return TupleDenominator(
                            e, lane, plan.family_tag,
                            TerminalFamilyV1::FoldInput,
                            {
                                e.Current(
                                    layout.task_ordinal),
                                e.Constant(U(input_lane)),
                                FoldInput(
                                    e, layout,
                                    input_lane),
                            });
                    });
            }
        }

        const auto append_running =
            [&](TerminalFamilyV1 family,
                uint32_t shard,
                const auto& row_term) {
                const uint32_t running =
                    layout.Running(
                        family, shard, lane);
                const uint32_t terminal =
                    layout.Terminal(
                        family, shard, lane);
                AppendProgram(
                    table, aq::AirKind::kFirstRow,
                    [=](ExprV1& e) {
                        e.Current(running);
                    });
                AppendProgram(
                    table, aq::AirKind::kTransition,
                    [=](ExprV1& e) {
                        e.Sub(
                            e.Next(running),
                            e.Add(
                                e.Current(running),
                                row_term(e)));
                    });
                AppendProgram(
                    table, aq::AirKind::kLastRow,
                    [=](ExprV1& e) {
                        e.Sub(
                            e.Current(terminal),
                            e.Add(
                                e.Current(running),
                                row_term(e)));
                    });
            };
        append_running(
            TerminalFamilyV1::Tape, 0,
            [=](ExprV1& e) {
                uint32_t term =
                    e.Constant(Fp3::Zero());
                for (uint32_t slot = 0;
                     slot < kSourceSlotsV1; ++slot) {
                    term = e.Add(
                        term,
                        e.Mul(
                            e.Current(
                                layout.SourceActive(
                                    slot)),
                            e.Current(
                                layout
                                    .TapeConsumerInverse(
                                        lane, slot))));
                }
                return term;
            });
        append_running(
            TerminalFamilyV1::HashInput, 0,
            [=](ExprV1& e) {
                uint32_t term =
                    e.Constant(Fp3::Zero());
                for (uint32_t input_lane = 0;
                     input_lane < kHashLanesV1;
                     ++input_lane) {
                    term = e.Add(
                        term,
                        e.Mul(
                            e.Current(layout.row_active),
                            e.Current(
                                layout.HashInputInverse(
                                    lane,
                                    input_lane))));
                }
                return term;
            });
        append_running(
            TerminalFamilyV1::PriorOutput, 0,
            [=](ExprV1& e) {
                uint32_t term =
                    e.Constant(Fp3::Zero());
                for (uint32_t output_lane = 0;
                     output_lane < kHashLanesV1;
                     ++output_lane) {
                    term = e.Add(
                        term,
                        e.Mul(
                            e.Current(
                                layout.HashPriorActive(
                                    output_lane)),
                            e.Current(
                                layout
                                    .PriorConsumerInverse(
                                        lane,
                                        output_lane))));
                }
                return term;
            });
        append_running(
            TerminalFamilyV1::HashOutputAlias, 0,
            [=](ExprV1& e) {
                uint32_t term =
                    e.Constant(Fp3::Zero());
                for (uint32_t output_lane = 0;
                     output_lane <
                         kHashOutputLanesV1;
                     ++output_lane) {
                    term = e.Add(
                        term,
                        e.Mul(
                            e.Current(
                                layout.HashOutputActive(
                                    output_lane)),
                            e.Current(
                                layout.HashOutputInverse(
                                    lane,
                                    output_lane))));
                }
                return term;
            });
        append_running(
            TerminalFamilyV1::FoldInput, 0,
            [=](ExprV1& e) {
                uint32_t term =
                    e.Constant(Fp3::Zero());
                for (uint32_t input_lane = 0;
                     input_lane <
                         kFoldInputLanesV1;
                     ++input_lane) {
                    term = e.Add(
                        term,
                        e.Mul(
                            e.Current(layout.row_active),
                            e.Current(
                                layout.FoldInputInverse(
                                    lane,
                                    input_lane))));
                }
                return term;
            });
    }
    AppendProgram(
        table, aq::AirKind::kFirstRow,
        [=](ExprV1& e) {
            e.Sub(
                e.Current(layout.acceptance),
                e.Constant(one));
        });
    return table;
}

Fp3 TupleDenominatorWitness(
    const ChallengesV1& challenge,
    uint32_t lane,
    uint64_t family_tag,
    TerminalFamilyV1 terminal_family,
    const std::vector<Fp3>& fields)
{
    const Fp3 gamma = challenge.gamma[lane];
    Fp3 power = gamma;
    Fp3 tuple = U(family_tag);
    auto append =
        [&](const Fp3& field) {
            tuple = gf::Add(
                tuple, gf::Mul(power, field));
            power = gf::Mul(power, gamma);
        };
    append(U(
        kTerminalTagV1[
            static_cast<uint8_t>(
                terminal_family)]));
    for (const Fp3& field : fields) {
        append(field);
    }
    return gf::Sub(
        challenge.alpha[lane], tuple);
}

Fp3 FoldInputWitness(
    const LayoutV1& layout,
    const std::vector<std::vector<Fp3>>& columns,
    uint32_t row,
    uint32_t input_lane)
{
    if (input_lane >= 4) {
        return columns[
            layout.SourceValue(
                24 + input_lane - 4)][row];
    }
    Fp3 value = Fp3::Zero();
    for (uint32_t coordinate = 0;
         coordinate < 3; ++coordinate) {
        const uint32_t slot =
            input_lane * 6 + 2 * coordinate;
        const Fp3 word = gf::Add(
            columns[layout.SourceValue(slot)][row],
            gf::Mul(
                U(uint64_t{1} << 32),
                columns[
                    layout.SourceValue(slot + 1)][row]));
        Fp3 basis = Fp3::Zero();
        if (coordinate == 0) {
            basis.c0 = gf::FromU64(1);
        } else if (coordinate == 1) {
            basis.c1 = gf::FromU64(1);
        } else {
            basis.c2 = gf::FromU64(1);
        }
        value = gf::Add(
            value, gf::Mul(basis, word));
    }
    return value;
}

} // namespace

bool AppendFinalConstraintSystemV1(
    const DeterministicAttachmentV1& deterministic,
    AirCS& cs,
    FinalizationV1& out,
    std::string* why)
{
    out = {};
    if (!deterministic.valid ||
        deterministic.layout.deterministic_end >
            cs.n_columns ||
        !DeriveChallengesV1(
            deterministic.plan, out.challenges,
            why)) {
        return Fail(why, "final_input");
    }
    LayoutV1 layout = deterministic.layout;
    CompleteDependentLayout(layout);
    out.dependent_column_base = cs.n_columns;
    cs.n_columns = layout.end;
    const cb::ProgramTable table =
        BuildFinalPrograms(
            deterministic.plan, layout);
    const std::vector<Fp3> challenges{
        out.challenges.gamma[0],
        out.challenges.gamma[1],
        out.challenges.alpha[0],
        out.challenges.alpha[1],
    };
    if (!AppendTable(
            table, cs.n_rows, challenges, cs,
            &out.final_program_root,
            &out.constraints_appended, why)) {
        return false;
    }
    out.dependent_columns =
        cs.n_columns - out.dependent_column_base;
    for (uint32_t lane = 0;
         lane < kLookupLanesV1; ++lane) {
        out.tape_terminal_column[lane] =
            layout.Terminal(
                TerminalFamilyV1::Tape, 0, lane);
        out.hash_input_terminal_column[lane] =
            layout.Terminal(
                TerminalFamilyV1::HashInput, 0, lane);
        out.prior_output_terminal_column[lane] =
            layout.Terminal(
                TerminalFamilyV1::PriorOutput, 0, lane);
        out.hash_output_terminal_column[lane] =
            layout.Terminal(
                TerminalFamilyV1::HashOutputAlias, 0, lane);
        out.fold_input_terminal_column[lane] =
            layout.Terminal(
                TerminalFamilyV1::FoldInput, 0, lane);
    }
    out.public_tape_root_challenges = true;
    out.dual_fp3_terminals = true;
    out.terminal_cells_constrained = true;
    out.v3_scalar_challenges = true;
    out.degree_caps_closed = DegreeCapsHold(cs);
    out.valid =
        out.dependent_columns != 0 &&
        Nonzero(out.final_program_root) &&
        out.public_tape_root_challenges &&
        out.dual_fp3_terminals &&
        out.terminal_cells_constrained &&
        out.v3_scalar_challenges &&
        out.degree_caps_closed;
    out.note = out.valid
        ? "V3 descriptor terminal receipt uses public tape-root challenges"
        : "final descriptor invariant";
    if (!out.valid) {
        return Fail(why, "final_invariant");
    }
    if (why != nullptr) *why = out.note;
    return true;
}

bool AppendFinalWitnessV1(
    const DeterministicAttachmentV1& deterministic,
    AirCS& cs,
    std::vector<std::vector<Fp3>>& columns,
    FinalizationV1& out,
    std::string* why)
{
    if (!deterministic.valid ||
        columns.size() != cs.n_columns) {
        return Fail(why, "final_witness_input");
    }
    if (!AppendFinalConstraintSystemV1(
            deterministic, cs, out, why)) {
        return false;
    }
    columns.resize(
        cs.n_columns,
        std::vector<Fp3>(
            cs.n_rows, Fp3::Zero()));
    LayoutV1 layout = deterministic.layout;
    CompleteDependentLayout(layout);
    std::array<
        std::array<Fp3, kLookupLanesV1>,
        kTerminalGroupsV1>
        running{};
    const auto add_inverse =
        [&](uint32_t inverse_column,
            uint32_t row,
            uint32_t lane,
            uint32_t group,
            const Fp3& denominator) {
            if (gf::IsZero(denominator)) return false;
            const Fp3 inverse = gf::Inv(denominator);
            columns[inverse_column][row] = inverse;
            running[group][lane] =
                gf::Add(
                    running[group][lane], inverse);
            return true;
        };
    for (uint32_t row = 0;
         row < cs.n_rows; ++row) {
        for (uint32_t lane = 0;
             lane < kLookupLanesV1; ++lane) {
            for (uint32_t group = 0;
                 group < kTerminalGroupsV1;
                 ++group) {
                columns[
                    layout.running_base +
                        group * kLookupLanesV1 +
                        lane][row] =
                    running[group][lane];
            }
            for (uint32_t slot = 0;
                 slot < kSourceSlotsV1; ++slot) {
                if (gf::IsZero(
                        columns[
                            layout.SourceActive(slot)]
                               [row])) {
                    continue;
                }
                const Fp3 denominator =
                    TupleDenominatorWitness(
                        out.challenges, lane,
                        deterministic.plan.family_tag,
                        TerminalFamilyV1::Tape,
                        {
                            columns[
                                layout.SourceAddressTag(
                                    slot)][row],
                            columns[
                                layout
                                    .SourceGlobalOrdinal(
                                        slot)][row],
                            columns[
                                layout.SourceValue(slot)]
                                   [row],
                        });
                if (!add_inverse(
                        layout.TapeConsumerInverse(
                            lane, slot),
                        row, lane, 0, denominator)) {
                    return Fail(
                        why,
                        "tape_zero_denominator");
                }
            }
            if (deterministic.plan.family ==
                FamilyV1::Hash) {
                for (uint32_t input_lane = 0;
                     input_lane < kHashLanesV1;
                     ++input_lane) {
                    if (!gf::IsZero(
                            columns[layout.row_active]
                                   [row])) {
                        ExprV1 unused;
                        (void)unused;
                        const Fp3 expected =
                            columns[
                                layout.HashExpectedInput(
                                    input_lane)][row];
                        const Fp3 denominator =
                            TupleDenominatorWitness(
                                out.challenges, lane,
                                deterministic.plan
                                    .family_tag,
                                TerminalFamilyV1::
                                    HashInput,
                                {
                                    columns[
                                        layout.task_ordinal]
                                        [row],
                                    U(input_lane),
                                    expected,
                                });
                        if (!add_inverse(
                                layout.HashInputInverse(
                                    lane, input_lane),
                                row, lane, 1,
                                denominator)) {
                            return Fail(
                                why,
                                "hash_input_zero_denominator");
                        }
                    }
                    if (!gf::IsZero(
                            columns[
                                layout.HashPriorActive(
                                    input_lane)][row])) {
                        const Fp3 denominator =
                            TupleDenominatorWitness(
                                out.challenges, lane,
                                deterministic.plan
                                    .family_tag,
                                TerminalFamilyV1::
                                    PriorOutput,
                                {
                                    columns[
                                        layout.HashPriorTask(
                                            input_lane)]
                                        [row],
                                    columns[
                                        layout.HashPriorLane(
                                            input_lane)]
                                        [row],
                                    columns[
                                        layout.HashPriorValue(
                                            input_lane)]
                                        [row],
                                });
                        if (!add_inverse(
                                layout
                                    .PriorConsumerInverse(
                                        lane,
                                        input_lane),
                                row, lane, 2,
                                denominator)) {
                            return Fail(
                                why,
                                "prior_zero_denominator");
                        }
                    }
                }
                for (uint32_t output_lane = 0;
                     output_lane <
                         kHashOutputLanesV1;
                     ++output_lane) {
                    if (gf::IsZero(
                            columns[
                                layout.HashOutputActive(
                                    output_lane)][row])) {
                        continue;
                    }
                    const uint32_t slot =
                        kHashOutputSlotBaseV1 +
                        2 * output_lane;
                    const Fp3 value = gf::Add(
                        columns[
                            layout.SourceValue(slot)][row],
                        gf::Mul(
                            U(uint64_t{1} << 32),
                            columns[
                                layout.SourceValue(
                                    slot + 1)][row]));
                    const Fp3 denominator =
                        TupleDenominatorWitness(
                            out.challenges, lane,
                            deterministic.plan.family_tag,
                            TerminalFamilyV1::
                                HashOutputAlias,
                            {
                                columns[
                                    layout.task_ordinal][row],
                                U(output_lane),
                                value,
                            });
                    if (!add_inverse(
                            layout.HashOutputInverse(
                                lane, output_lane),
                            row, lane, 3,
                            denominator)) {
                        return Fail(
                            why,
                            "hash_output_zero_denominator");
                    }
                }
            } else if (!gf::IsZero(
                           columns[layout.row_active]
                                  [row])) {
                for (uint32_t input_lane = 0;
                     input_lane <
                         kFoldInputLanesV1;
                     ++input_lane) {
                    const Fp3 value =
                        FoldInputWitness(
                            layout, columns,
                            row, input_lane);
                    const Fp3 denominator =
                        TupleDenominatorWitness(
                            out.challenges, lane,
                            deterministic.plan.family_tag,
                            TerminalFamilyV1::FoldInput,
                            {
                                columns[
                                    layout.task_ordinal][row],
                                U(input_lane),
                                value,
                            });
                    if (!add_inverse(
                            layout.FoldInputInverse(
                                lane, input_lane),
                            row, lane, 4,
                            denominator)) {
                        return Fail(
                            why,
                            "fold_input_zero_denominator");
                    }
                }
            }
        }
    }
    const uint32_t last = cs.n_rows - 1;
    for (uint32_t group = 0;
         group < kTerminalGroupsV1; ++group) {
        for (uint32_t lane = 0;
             lane < kLookupLanesV1; ++lane) {
            columns[
                layout.terminal_base +
                    group * kLookupLanesV1 +
                    lane][last] =
                running[group][lane];
        }
    }
    columns[layout.acceptance][0] = Fp3::One();
    auto& receipt = out.receipt;
    receipt.schedule_root =
        deterministic.plan.schedule_root;
    for (uint32_t shard = 0;
         shard < kTapeShardsV1; ++shard) {
        receipt.tape_domain_root[shard] =
            deterministic.plan
                .source_shards[shard]
                .source_domain_root;
        receipt.state_in[shard] =
            deterministic.plan
                .source_shards[shard].state_in;
        receipt.state_out[shard] =
            deterministic.plan
                .source_shards[shard].state_out;
    }
    for (uint32_t lane = 0;
         lane < kLookupLanesV1; ++lane) {
        receipt.tape_consumer[lane] =
            running[0][lane];
        receipt.hash_input[lane] =
            running[1][lane];
        receipt.prior_output[lane] =
            running[2][lane];
        receipt.hash_output[lane] =
            running[3][lane];
        receipt.fold_input[lane] =
            running[4][lane];
    }
    receipt.manifest_reads =
        deterministic.plan.manifest_reads;
    receipt.exact_four_shards = true;
    receipt.full_state_bound = true;
    receipt.exact_manifest_count =
        deterministic.plan.exact_manifest_count;
    receipt.valid =
        Nonzero(receipt.schedule_root) &&
        receipt.exact_four_shards &&
        receipt.full_state_bound &&
        receipt.exact_manifest_count;
    receipt.note = receipt.valid
        ? "descriptor consumer terminals bind four tape shards and full state boundaries"
        : "descriptor terminal receipt invariant";
    if (!receipt.valid) {
        return Fail(why, "receipt_invariant");
    }
    return true;
}

uint64_t CountViolationsV1(
    const AirCS& cs,
    const std::vector<std::vector<Fp3>>& columns)
{
    return merkle::CountViolationsV1(cs, columns);
}

} // namespace matmul::v4::rc::stage3_v13_merkle_fold_descriptor_vm
