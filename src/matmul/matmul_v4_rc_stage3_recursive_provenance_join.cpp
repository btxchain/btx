// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_recursive_provenance_join.h>

#include <matmul/matmul_v4_rc_stage3_air_quotient_codec.h>

#include <hash.h>

#include <algorithm>
#include <chrono>
#include <limits>
#include <map>
#include <tuple>
#include <utility>

namespace matmul::v4::rc::recursive_provenance_join {
namespace {

using E = RCStage3RelationEndpoint;
using K = RecursiveProvenanceEventKindV1;
using Fp3 = gf::Fp3;

constexpr char kScheduleDomain[] =
    "BTX_RC_STAGE3_RECURSIVE_PROVENANCE_SCHEDULE_V1";
constexpr char kProofSeedDomain[] =
    "BTX_RC_STAGE3_RECURSIVE_PROVENANCE_PROOF_FS_V1";
constexpr char kParentAliasScheduleDomain[] =
    "BTX_RC_STAGE3_RECURSIVE_PROVENANCE_PARENT_ALIAS_SCHEDULE_V1";
constexpr char kParentAliasProofSeedDomain[] =
    "BTX_RC_STAGE3_RECURSIVE_PROVENANCE_PARENT_ALIAS_PROOF_FS_V1";

constexpr std::array<RCStage3RelationRole,
                     kRecursiveProvenanceRoleCountV1>
    kRoleOrder{
        RCStage3RelationRole::EpisodeDeterministicBuilder,
        RCStage3RelationRole::EpisodeGemm,
        RCStage3RelationRole::EpisodeExtract,
        RCStage3RelationRole::EpisodeWiring,
        RCStage3RelationRole::EpisodeTileTree,
        RCStage3RelationRole::EpisodeDigest,
        RCStage3RelationRole::CoupledBank,
        RCStage3RelationRole::CoupledGemm,
        RCStage3RelationRole::CoupledExchange,
        RCStage3RelationRole::CoupledPermutation,
        RCStage3RelationRole::CoupledMix,
        RCStage3RelationRole::CoupledExtract,
        RCStage3RelationRole::CoupledBarrier,
        RCStage3RelationRole::CoupledDigest,
    };

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:recursive_provenance_join:" + detail;
    }
    return false;
}

uint32_t NextPowerOfTwo(uint32_t value)
{
    uint32_t out = 2;
    while (out < value) {
        if (out > std::numeric_limits<uint32_t>::max() / 2U) {
            return 0;
        }
        out *= 2U;
    }
    return out;
}

std::array<uint32_t, kRecursiveProvenanceRootLimbsV1>
RootLimbs(const uint256& root)
{
    std::array<uint32_t, kRecursiveProvenanceRootLimbsV1> out{};
    for (uint32_t limb = 0; limb < out.size(); ++limb) {
        const uint32_t offset = 4U * limb;
        out[limb] =
            static_cast<uint32_t>(root.begin()[offset]) |
            (static_cast<uint32_t>(root.begin()[offset + 1]) << 8) |
            (static_cast<uint32_t>(root.begin()[offset + 2]) << 16) |
            (static_cast<uint32_t>(root.begin()[offset + 3]) << 24);
    }
    return out;
}

Fp3 U32(uint32_t value)
{
    return Fp3::FromFp(gf::FromU64(value));
}

bool IsCanonicalU32(const Fp3& value)
{
    return gf::Canonical(value.c1) == 0 &&
           gf::Canonical(value.c2) == 0 &&
           gf::Canonical(value.c0) <=
               std::numeric_limits<uint32_t>::max();
}

bool IsPowerOfTwo(uint32_t value)
{
    return value >= 2 && (value & (value - 1U)) == 0;
}

bool ShapeValid(const RecursiveProvenanceShapeV1& shape,
                std::string* why)
{
    if (shape.version != kRecursiveProvenanceJoinVersionV1) {
        return Fail(why, "shape_version");
    }
    if (shape.episode_round_roots == 0 ||
        shape.coupled_barriers == 0 ||
        shape.coupled_lobes == 0) {
        return Fail(why, "zero_shape");
    }
    if (shape.episode_builder_params_root.IsNull() ||
        shape.episode_header_target_root.IsNull()) {
        return Fail(why, "null_public_anchor");
    }
    const uint64_t gemms =
        static_cast<uint64_t>(shape.coupled_barriers) *
        shape.coupled_lobes;
    const uint64_t material =
        static_cast<uint64_t>(shape.coupled_barriers) *
        shape.coupled_exchange_rounds;
    if (gemms > std::numeric_limits<uint32_t>::max() ||
        material > std::numeric_limits<uint32_t>::max()) {
        return Fail(why, "shape_overflow");
    }
    return true;
}

RCStage3RelationRole ExpectedRole(E endpoint)
{
    for (const auto role : kRoleOrder) {
        const auto& endpoints =
            RequiredRCStage3RelationEndpoints(role);
        if (std::find(endpoints.begin(), endpoints.end(), endpoint) !=
            endpoints.end()) {
            return role;
        }
    }
    return {};
}

void Add(std::vector<RecursiveProvenanceEventKeyV1>& out,
         E producer,
         E consumer,
         K kind,
         uint32_t producer_position,
         uint32_t consumer_position,
         const char* construction)
{
    out.push_back({
        producer,
        consumer,
        kind,
        producer_position,
        consumer_position,
        construction});
}

bool EventLess(const RecursiveProvenanceEventKeyV1& lhs,
               const RecursiveProvenanceEventKeyV1& rhs)
{
    return std::tie(
               lhs.producer, lhs.consumer, lhs.kind,
               lhs.producer_position, lhs.consumer_position,
               lhs.construction) <
           std::tie(
               rhs.producer, rhs.consumer, rhs.kind,
               rhs.producer_position, rhs.consumer_position,
               rhs.construction);
}

RecursiveProvenanceJoinLayoutV1 MakeLayout()
{
    RecursiveProvenanceJoinLayoutV1 out;
    uint32_t column = 0;
    out.claimed_row_kind = column++;
    out.claimed_role = column++;
    out.claimed_endpoint = column++;
    out.claimed_producer = column++;
    out.claimed_consumer = column++;
    out.claimed_event_kind = column++;
    out.claimed_producer_position = column++;
    out.claimed_consumer_position = column++;
    for (auto& value : out.left_root) value = column++;
    for (auto& value : out.right_root) value = column++;
    out.pp_active = column++;
    out.pp_row_kind = column++;
    out.pp_role = column++;
    out.pp_endpoint = column++;
    out.pp_producer = column++;
    out.pp_consumer = column++;
    out.pp_event_kind = column++;
    out.pp_producer_position = column++;
    out.pp_consumer_position = column++;
    out.pp_anchor_selector = column++;
    for (auto& value : out.pp_anchor_root) value = column++;
    out.total_columns = column;
    return out;
}

void AddGatedEquality(
    aq::AirConstraintSystem<Fp3>& cs,
    const char* name,
    uint32_t left,
    uint32_t right,
    uint32_t selector)
{
    aq::AirConstraint<Fp3> constraint;
    constraint.name = name;
    constraint.kind = aq::AirKind::kEverywhere;
    constraint.alg_degree = 2;
    constraint.eval =
        [left, right, selector](
            const std::vector<Fp3>& cur,
            const std::vector<Fp3>&) {
            return gf::Mul(
                cur[selector],
                gf::Sub(cur[left], cur[right]));
        };
    cs.constraints.push_back(std::move(constraint));
}

struct CanonicalRow {
    RecursiveProvenanceRowKindV1 kind{
        RecursiveProvenanceRowKindV1::Padding};
    RCStage3RelationRole role{};
    E endpoint{};
    E producer{};
    E consumer{};
    K event_kind{K::GraphNamedRoot};
    uint32_t producer_position{0};
    uint32_t consumer_position{0};
    uint256 left_root{};
    uint256 right_root{};
    bool anchor{false};
    uint256 anchor_root{};
};

bool ExactWitnessSchedule(
    const RecursiveProvenanceShapeV1& shape,
    const RecursiveProvenanceWitnessV1& witness,
    const std::vector<RecursiveProvenanceEventKeyV1>& expected_events,
    std::vector<CanonicalRow>& rows,
    bool& every_verified,
    std::string* why)
{
    rows.clear();
    every_verified = true;
    if (witness.version != kRecursiveProvenanceJoinVersionV1) {
        return Fail(why, "witness_version");
    }
    if (witness.roles.size() != kRoleOrder.size()) {
        return Fail(why, "role_omission_or_duplicate");
    }
    for (uint32_t i = 0; i < kRoleOrder.size(); ++i) {
        const auto& cell = witness.roles[i];
        if (cell.role != kRoleOrder[i]) {
            return Fail(why, "role_relabel_or_reorder");
        }
        if (cell.locally_verified_child_root.IsNull() ||
            cell.named_role_root.IsNull()) {
            return Fail(why, "role_null_root");
        }
        every_verified =
            every_verified && cell.child_locally_verified;
        CanonicalRow row;
        row.kind = RecursiveProvenanceRowKindV1::Role;
        row.role = cell.role;
        row.left_root = cell.locally_verified_child_root;
        row.right_root = cell.named_role_root;
        rows.push_back(std::move(row));
    }

    const auto cells = CurrentRCStage3RelationEndpointCellAudit();
    if (cells.size() != kRecursiveProvenanceEndpointCountV1 ||
        witness.endpoints.size() != cells.size()) {
        return Fail(why, "endpoint_omission_or_duplicate");
    }
    for (uint32_t i = 0; i < cells.size(); ++i) {
        const auto& expected = cells[i];
        const auto& cell = witness.endpoints[i];
        if (cell.endpoint != expected.endpoint ||
            cell.role != expected.role ||
            cell.role != ExpectedRole(cell.endpoint)) {
            return Fail(why, "endpoint_relabel_or_reorder");
        }
        if (cell.locally_verified_child_output_root.IsNull() ||
            cell.named_endpoint_root.IsNull()) {
            return Fail(why, "endpoint_null_root");
        }
        every_verified =
            every_verified && cell.child_locally_verified;
        CanonicalRow row;
        row.kind = RecursiveProvenanceRowKindV1::Endpoint;
        row.role = cell.role;
        row.endpoint = cell.endpoint;
        row.left_root =
            cell.locally_verified_child_output_root;
        row.right_root = cell.named_endpoint_root;
        if (cell.endpoint == E::EpisodeBuilderParams) {
            row.anchor = true;
            row.anchor_root =
                shape.episode_builder_params_root;
        } else if (
            cell.endpoint == E::EpisodeDigestHeaderTarget) {
            row.anchor = true;
            row.anchor_root =
                shape.episode_header_target_root;
        }
        rows.push_back(std::move(row));
    }

    if (witness.events.size() != expected_events.size()) {
        return Fail(why, "event_omission_or_duplicate");
    }
    for (uint32_t i = 0; i < expected_events.size(); ++i) {
        const auto& cell = witness.events[i];
        if (cell.key != expected_events[i]) {
            return Fail(why, "event_relabel_reorder_or_round_shift");
        }
        if (cell.producer_child_output_root.IsNull() ||
            cell.consumer_named_input_root.IsNull()) {
            return Fail(why, "event_null_root");
        }
        every_verified =
            every_verified &&
            cell.producer_child_locally_verified &&
            cell.consumer_child_locally_verified;
        CanonicalRow row;
        row.kind = RecursiveProvenanceRowKindV1::Event;
        row.producer = cell.key.producer;
        row.consumer = cell.key.consumer;
        row.event_kind = cell.key.kind;
        row.producer_position = cell.key.producer_position;
        row.consumer_position = cell.key.consumer_position;
        row.left_root = cell.producer_child_output_root;
        row.right_root = cell.consumer_named_input_root;
        rows.push_back(std::move(row));
    }
    return true;
}

RecursiveProvenanceWitnessV1 VerifierShapeWitness(
    const RecursiveProvenanceShapeV1& shape)
{
    RecursiveProvenanceWitnessV1 out;
    // Root values are ordinary trace cells and do not affect construction of
    // the verifier's constraint system.  This non-null canonical filler only
    // lets us reuse the single schedule builder.  Endpoints 1 and 25 are
    // replaced by their actual public anchors below.
    const uint256 filler = shape.episode_builder_params_root;
    for (const auto role : kRoleOrder) {
        out.roles.push_back({role, filler, filler, true});
    }
    for (const auto& endpoint :
         CurrentRCStage3RelationEndpointCellAudit()) {
        uint256 root = filler;
        if (endpoint.endpoint == E::EpisodeBuilderParams) {
            root = shape.episode_builder_params_root;
        } else if (
            endpoint.endpoint == E::EpisodeDigestHeaderTarget) {
            root = shape.episode_header_target_root;
        }
        out.endpoints.push_back({
            endpoint.endpoint, endpoint.role,
            root, root, true});
    }
    std::vector<RecursiveProvenanceEventKeyV1> events;
    if (!BuildCanonicalRecursiveProvenanceEventScheduleV1(
            shape, events, nullptr)) {
        return {};
    }
    for (const auto& event : events) {
        out.events.push_back({
            event, filler, filler, true, true});
    }
    return out;
}

AirQuotientProofAlg CanonicalAlgProof(
    const aq::AirQuotientRowsProof& proof)
{
    AirQuotientProofAlg out;
    out.batch = proof.batch;
    out.next_openings = proof.next_openings;
    out.trace_commit = proof.trace_commit;
    return out;
}

bool ParentColumnsValid(
    const aq::AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns)
{
    if (!IsPowerOfTwo(cs.n_rows) ||
        columns.size() != cs.n_columns) {
        return false;
    }
    return std::all_of(
        columns.begin(), columns.end(),
        [&cs](const auto& column) {
            return column.size() == cs.n_rows;
        });
}

bool IsPreprocessedColumn(
    const aq::AirConstraintSystem<Fp3>& cs,
    uint32_t column)
{
    return std::any_of(
        cs.preprocessed.begin(),
        cs.preprocessed.end(),
        [column](const auto& item) {
            return item.first == column;
        });
}

bool ValidOrdinaryRootRef(
    const aq::AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns,
    const RecursiveProvenanceParentRootRefV1& root)
{
    for (const auto& limb : root.limb) {
        if (limb.column >= cs.n_columns ||
            limb.row >= cs.n_rows ||
            IsPreprocessedColumn(cs, limb.column) ||
            !IsCanonicalU32(
                columns[limb.column][limb.row])) {
            return false;
        }
    }
    return true;
}

uint64_t CellKey(
    const RecursiveProvenanceParentCellRefV1& cell)
{
    return (uint64_t{cell.column} << 32) | cell.row;
}

struct AliasSelectorCache {
    struct Interval {
        uint32_t source{UINT32_MAX};
        uint32_t sink{UINT32_MAX};
        uint32_t carry{UINT32_MAX};
    };
    std::map<uint32_t, uint32_t> point;
    std::map<std::pair<uint32_t, uint32_t>, Interval>
        interval;
};

uint32_t PointSelector(
    aq::AirConstraintSystem<Fp3>& cs,
    std::vector<std::vector<Fp3>>& columns,
    uint32_t row,
    AliasSelectorCache& cache,
    RecursiveProvenanceParentAliasAttachmentV1& out)
{
    const auto found = cache.point.find(row);
    if (found != cache.point.end()) return found->second;
    const uint32_t selector = cs.n_columns++;
    columns.push_back(
        std::vector<Fp3>(cs.n_rows, Fp3::Zero()));
    columns[selector][row] = Fp3::One();
    cs.preprocessed.emplace_back(
        selector, columns[selector]);
    cache.point.emplace(row, selector);
    ++out.selector_columns;
    return selector;
}

AliasSelectorCache::Interval IntervalSelectors(
    aq::AirConstraintSystem<Fp3>& cs,
    std::vector<std::vector<Fp3>>& columns,
    uint32_t low_row,
    uint32_t high_row,
    AliasSelectorCache& cache,
    RecursiveProvenanceParentAliasAttachmentV1& out)
{
    const auto key = std::make_pair(low_row, high_row);
    const auto found = cache.interval.find(key);
    if (found != cache.interval.end()) {
        return found->second;
    }
    AliasSelectorCache::Interval selectors;
    selectors.source = cs.n_columns++;
    selectors.sink = cs.n_columns++;
    selectors.carry = cs.n_columns++;
    columns.resize(
        cs.n_columns,
        std::vector<Fp3>(cs.n_rows, Fp3::Zero()));
    columns[selectors.source][low_row] = Fp3::One();
    columns[selectors.sink][high_row] = Fp3::One();
    for (uint32_t row = low_row; row < high_row; ++row) {
        columns[selectors.carry][row] = Fp3::One();
    }
    cs.preprocessed.emplace_back(
        selectors.source, columns[selectors.source]);
    cs.preprocessed.emplace_back(
        selectors.sink, columns[selectors.sink]);
    cs.preprocessed.emplace_back(
        selectors.carry, columns[selectors.carry]);
    cache.interval.emplace(key, selectors);
    out.selector_columns += 3;
    return selectors;
}

void AddParentAlias(
    aq::AirConstraintSystem<Fp3>& cs,
    std::vector<std::vector<Fp3>>& columns,
    const RecursiveProvenanceParentCellRefV1& source,
    const RecursiveProvenanceParentCellRefV1& sink,
    AliasSelectorCache& selector_cache,
    RecursiveProvenanceParentAliasAttachmentV1& out)
{
    RecursiveProvenanceParentCellRefV1 low = source;
    RecursiveProvenanceParentCellRefV1 high = sink;
    if (low.row > high.row) std::swap(low, high);

    if (low.row == high.row) {
        const uint32_t selector = PointSelector(
            cs, columns, low.row,
            selector_cache, out);
        cs.constraints.push_back({
            "stage3.recursive_provenance.parent_alias.same_row",
            aq::AirKind::kEverywhere,
            2,
            [selector, low, high](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    cur[selector],
                    gf::Sub(
                        cur[low.column],
                        cur[high.column]));
            }});
        ++out.same_row_equalities;
        ++out.limb_equalities;
        return;
    }

    const uint32_t carrier = cs.n_columns++;
    columns.push_back(
        std::vector<Fp3>(cs.n_rows, Fp3::Zero()));
    ++out.carrier_columns;
    const auto selectors = IntervalSelectors(
        cs, columns, low.row, high.row,
        selector_cache, out);
    const Fp3 value = columns[low.column][low.row];
    for (uint32_t row = low.row; row <= high.row; ++row) {
        columns[carrier][row] = value;
    }
    cs.constraints.push_back({
        "stage3.recursive_provenance.parent_alias.source",
        aq::AirKind::kEverywhere,
        2,
        [carrier, source_selector = selectors.source, low](
            const std::vector<Fp3>& cur,
            const std::vector<Fp3>&) {
            return gf::Mul(
                cur[source_selector],
                gf::Sub(
                    cur[carrier],
                    cur[low.column]));
        }});
    cs.constraints.push_back({
        "stage3.recursive_provenance.parent_alias.sink",
        aq::AirKind::kEverywhere,
        2,
        [carrier, sink_selector = selectors.sink, high](
            const std::vector<Fp3>& cur,
            const std::vector<Fp3>&) {
            return gf::Mul(
                cur[sink_selector],
                gf::Sub(
                    cur[carrier],
                    cur[high.column]));
        }});
    cs.constraints.push_back({
        "stage3.recursive_provenance.parent_alias.carry",
        aq::AirKind::kTransition,
        2,
        [carrier, carry_selector = selectors.carry](
            const std::vector<Fp3>& cur,
            const std::vector<Fp3>& next) {
            return gf::Mul(
                cur[carry_selector],
                gf::Sub(
                    next[carrier],
                    cur[carrier]));
        }});
    ++out.cross_row_equalities;
    ++out.limb_equalities;
}

void AddPublicAnchor(
    aq::AirConstraintSystem<Fp3>& cs,
    std::vector<std::vector<Fp3>>& columns,
    const RecursiveProvenanceParentRootRefV1& sink,
    const uint256& public_root,
    AliasSelectorCache& selector_cache,
    RecursiveProvenanceParentAliasAttachmentV1& out)
{
    const auto limbs = RootLimbs(public_root);
    for (uint32_t limb = 0; limb < limbs.size(); ++limb) {
        const auto ref = sink.limb[limb];
        const uint32_t selector = PointSelector(
            cs, columns, ref.row,
            selector_cache, out);
        const Fp3 expected = U32(limbs[limb]);
        cs.constraints.push_back({
            "stage3.recursive_provenance.parent_alias.public_anchor",
            aq::AirKind::kEverywhere,
            2,
            [selector, ref, expected](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    cur[selector],
                    gf::Sub(
                        cur[ref.column],
                        expected));
            }});
        ++out.public_anchor_equalities;
    }
}

} // namespace

const std::array<RCStage3RelationRole,
                 kRecursiveProvenanceRoleCountV1>&
CanonicalRecursiveProvenanceRoleOrderV1()
{
    return kRoleOrder;
}

uint256
ComputeRecursiveProvenanceParentAliasScheduleCommitmentV1(
    const RecursiveProvenanceShapeV1& shape,
    const RecursiveProvenanceParentAliasRefsV1& refs)
{
    if (!ShapeValid(shape, nullptr) ||
        refs.version != kRecursiveProvenanceJoinVersionV1 ||
        refs.parent_rows < 2 ||
        refs.parent_original_columns == 0) {
        return {};
    }
    std::vector<RecursiveProvenanceEventKeyV1>
        canonical_events;
    if (!BuildCanonicalRecursiveProvenanceEventScheduleV1(
            shape, canonical_events, nullptr) ||
        refs.events.size() != canonical_events.size()) {
        return {};
    }
    const auto endpoints =
        CurrentRCStage3RelationEndpointCellAudit();
    if (endpoints.size() !=
        kRecursiveProvenanceEndpointCountV1) {
        return {};
    }
    for (uint32_t role = 0;
         role < refs.roles.size(); ++role) {
        if (refs.roles[role].role != kRoleOrder[role]) {
            return {};
        }
    }
    for (uint32_t endpoint = 0;
         endpoint < refs.endpoints.size(); ++endpoint) {
        if (refs.endpoints[endpoint].endpoint !=
                endpoints[endpoint].endpoint ||
            refs.endpoints[endpoint].role !=
                endpoints[endpoint].role ||
            refs.endpoints[endpoint].role !=
                ExpectedRole(
                    refs.endpoints[endpoint].endpoint)) {
            return {};
        }
    }
    for (uint32_t event = 0;
         event < refs.events.size(); ++event) {
        if (refs.events[event].key !=
            canonical_events[event]) {
            return {};
        }
    }

    const uint256 semantic_schedule =
        ComputeRecursiveProvenanceScheduleCommitmentV1(
            shape, canonical_events);
    if (semantic_schedule.IsNull()) return {};
    HashWriter hash;
    hash << kParentAliasScheduleDomain
         << kRecursiveProvenanceJoinVersionV1
         << semantic_schedule
         << refs.parent_rows
         << refs.parent_original_columns;
    const auto append_root_ref =
        [&hash](
            const RecursiveProvenanceParentRootRefV1&
                root) {
            for (const auto& cell : root.limb) {
                hash << cell.column << cell.row;
            }
        };
    const auto append_alias =
        [&append_root_ref](
            const RecursiveProvenanceParentRootAliasV1&
                alias) {
            append_root_ref(alias.verifier_output);
            append_root_ref(alias.named_consumer);
        };
    hash << static_cast<uint32_t>(refs.roles.size());
    for (const auto& role : refs.roles) {
        hash << static_cast<uint16_t>(role.role);
        append_alias(role.root);
    }
    hash << static_cast<uint32_t>(refs.endpoints.size());
    for (const auto& endpoint : refs.endpoints) {
        hash << static_cast<uint16_t>(endpoint.endpoint)
             << static_cast<uint16_t>(endpoint.role);
        append_alias(endpoint.root);
    }
    hash << static_cast<uint32_t>(refs.events.size());
    for (uint32_t event = 0;
         event < refs.events.size(); ++event) {
        hash << event;
        append_alias(refs.events[event].root);
    }
    return hash.GetHash();
}

uint256 ComputeRecursiveProvenanceParentAliasFsSeedV1(
    const RecursiveProvenanceShapeV1& shape,
    const uint256& fixed_offset_schedule_commitment)
{
    if (!ShapeValid(shape, nullptr) ||
        fixed_offset_schedule_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << kParentAliasProofSeedDomain
         << kRecursiveProvenanceJoinVersionV1
         << shape.episode_builder_params_root
         << shape.episode_header_target_root
         << fixed_offset_schedule_commitment;
    return hash.GetHash();
}

bool AppendRecursiveProvenanceParentAliasesV1(
    aq::AirConstraintSystem<Fp3>& parent_cs,
    std::vector<std::vector<Fp3>>& parent_columns,
    const RecursiveProvenanceShapeV1& shape,
    const RecursiveProvenanceParentAliasRefsV1& refs,
    const uint256& expected_fixed_offset_schedule_commitment,
    RecursiveProvenanceParentAliasAttachmentV1& out,
    std::string* why)
{
    out = {};
    if (!ShapeValid(shape, why) ||
        refs.version != kRecursiveProvenanceJoinVersionV1 ||
        !ParentColumnsValid(parent_cs, parent_columns)) {
        return Fail(why, "parent_alias_shape");
    }
    out.parent_witness_shape_exact =
        refs.parent_rows == parent_cs.n_rows &&
        refs.parent_original_columns == parent_cs.n_columns;
    out.fixed_offset_schedule_commitment =
        ComputeRecursiveProvenanceParentAliasScheduleCommitmentV1(
            shape, refs);
    out.fixed_offset_schedule_bound =
        out.parent_witness_shape_exact &&
        !expected_fixed_offset_schedule_commitment.IsNull() &&
        out.fixed_offset_schedule_commitment ==
            expected_fixed_offset_schedule_commitment;
    if (!out.parent_witness_shape_exact ||
        !out.fixed_offset_schedule_bound) {
        return Fail(
            why,
            "parent_alias_fixed_offset_schedule");
    }
    std::vector<RecursiveProvenanceEventKeyV1>
        canonical_events;
    if (!BuildCanonicalRecursiveProvenanceEventScheduleV1(
            shape, canonical_events, why) ||
        refs.events.size() != canonical_events.size()) {
        return Fail(why, "parent_alias_event_count");
    }
    const auto endpoints =
        CurrentRCStage3RelationEndpointCellAudit();
    if (endpoints.size() !=
            kRecursiveProvenanceEndpointCountV1) {
        return Fail(why, "parent_alias_endpoint_audit");
    }
    for (uint32_t role = 0;
         role < refs.roles.size(); ++role) {
        if (refs.roles[role].role != kRoleOrder[role]) {
            return Fail(why, "parent_alias_role_order");
        }
    }
    for (uint32_t endpoint = 0;
         endpoint < refs.endpoints.size(); ++endpoint) {
        if (refs.endpoints[endpoint].endpoint !=
                endpoints[endpoint].endpoint ||
            refs.endpoints[endpoint].role !=
                endpoints[endpoint].role) {
            return Fail(why, "parent_alias_endpoint_order");
        }
    }
    for (uint32_t event = 0;
         event < refs.events.size(); ++event) {
        if (refs.events[event].key !=
            canonical_events[event]) {
            return Fail(why, "parent_alias_event_order");
        }
    }

    const auto validate_alias =
        [&](const RecursiveProvenanceParentRootAliasV1&
                alias) {
            return ValidOrdinaryRootRef(
                       parent_cs, parent_columns,
                       alias.verifier_output) &&
                   ValidOrdinaryRootRef(
                       parent_cs, parent_columns,
                       alias.named_consumer);
        };
    std::vector<uint64_t> source_cells;
    std::vector<uint64_t> sink_cells;
    source_cells.reserve(
        (kRecursiveProvenanceRoleCountV1 +
         kRecursiveProvenanceEndpointCountV1 +
         refs.events.size()) *
        kRecursiveProvenanceRootLimbsV1);
    sink_cells.reserve(source_cells.capacity());
    const auto collect_alias =
        [&](const RecursiveProvenanceParentRootAliasV1&
                alias) {
            for (uint32_t limb = 0;
                 limb <
                    kRecursiveProvenanceRootLimbsV1;
                 ++limb) {
                source_cells.push_back(
                    CellKey(
                        alias.verifier_output.limb[limb]));
                sink_cells.push_back(
                    CellKey(
                        alias.named_consumer.limb[limb]));
            }
        };
    for (const auto& alias : refs.roles) {
        if (!validate_alias(alias.root)) {
            return Fail(
                why,
                "parent_alias_role_ref_or_preprocessed");
        }
        collect_alias(alias.root);
    }
    for (const auto& alias : refs.endpoints) {
        if (!validate_alias(alias.root)) {
            return Fail(
                why,
                "parent_alias_endpoint_ref_or_preprocessed");
        }
        collect_alias(alias.root);
    }
    for (const auto& event : refs.events) {
        if (!validate_alias(event.root)) {
            return Fail(
                why,
                "parent_alias_event_ref_or_preprocessed");
        }
        collect_alias(event.root);
    }
    const auto all_distinct =
        [](std::vector<uint64_t> cells) {
            std::sort(cells.begin(), cells.end());
            return std::adjacent_find(
                       cells.begin(), cells.end()) ==
                   cells.end();
        };
    std::vector<uint64_t> all_cells = source_cells;
    all_cells.insert(
        all_cells.end(),
        sink_cells.begin(), sink_cells.end());
    if (!all_distinct(source_cells) ||
        !all_distinct(sink_cells) ||
        !all_distinct(all_cells)) {
        return Fail(
            why,
            "parent_alias_collapsed_or_tautological_cell_refs");
    }

    out.original_columns = parent_cs.n_columns;
    AliasSelectorCache selector_cache;
    const auto append_root =
        [&](const RecursiveProvenanceParentRootAliasV1&
                alias) {
            for (uint32_t limb = 0;
                 limb <
                    kRecursiveProvenanceRootLimbsV1;
                 ++limb) {
                AddParentAlias(
                    parent_cs, parent_columns,
                    alias.verifier_output.limb[limb],
                    alias.named_consumer.limb[limb],
                    selector_cache,
                    out);
            }
        };
    for (const auto& alias : refs.roles) {
        append_root(alias.root);
        ++out.role_root_aliases;
    }
    for (const auto& alias : refs.endpoints) {
        append_root(alias.root);
        ++out.endpoint_root_aliases;
    }
    for (const auto& event : refs.events) {
        append_root(event.root);
        ++out.temporal_root_aliases;
    }

    // Public endpoint 1 and 25 consumers are additionally bound to the
    // verifier-reconstructed public statement.  The constants are public CS
    // parameters; only their row selectors enter preprocessing.
    AddPublicAnchor(
        parent_cs, parent_columns,
        refs.endpoints[0].root.named_consumer,
        shape.episode_builder_params_root,
        selector_cache, out);
    AddPublicAnchor(
        parent_cs, parent_columns,
        refs.endpoints[24].root.named_consumer,
        shape.episode_header_target_root,
        selector_cache, out);
    parent_cs.preprocessed_pin_ood = true;

    out.appended_columns =
        parent_cs.n_columns - out.original_columns;
    out.exact_role_order = true;
    out.exact_endpoint_order = true;
    out.exact_event_order = true;
    out.all_66_root_aliases_literal =
        out.role_root_aliases ==
            kRecursiveProvenanceRoleCountV1 &&
        out.endpoint_root_aliases ==
            kRecursiveProvenanceEndpointCountV1;
    out.every_temporal_alias_literal =
        out.temporal_root_aliases ==
            canonical_events.size();
    out.aliased_values_are_ordinary_columns = true;
    out.source_and_sink_cells_disjoint = true;
    out.semantic_export_cells_distinct = true;
    out.selectors_only_new_preprocessing = true;
    out.cross_row_transport_constrained =
        out.limb_equalities ==
            (out.role_root_aliases +
             out.endpoint_root_aliases +
             out.temporal_root_aliases) *
                kRecursiveProvenanceRootLimbsV1;
    out.no_child_tape_hash_required = true;
    out.parent_trace_commitment_binding_model = true;
    out.violations =
        CountRecursiveProvenanceJoinViolationsV1(
            parent_cs, parent_columns);

    // The outer proof commits these ordinary parent-witness cells directly;
    // hashing the full child tape again would add no binding.  This bounded
    // slice proves only the fixed-offset equality bus.  Do not accept a host
    // bool/certificate for the still-missing semantic ownership of either
    // side.
    out.verifier_output_semantics_constrained = false;
    out.named_consumer_semantics_constrained = false;
    out.complete_child_acceptance_in_same_parent = false;
    out.same_parent_child_verifier_owned = false;
    out.recursive_authority = false;
    out.residuals = {
        "complete_child_proof_decoder_not_in_parent_air",
        "complete_child_fiat_shamir_replay_not_in_parent_air",
        "child_acceptance_not_constrained_in_same_parent",
        "verifier_output_semantics_not_constrained_in_same_parent",
        "named_consumer_semantics_not_constrained_in_same_parent"};
    out.valid =
        out.exact_role_order &&
        out.exact_endpoint_order &&
        out.exact_event_order &&
        out.parent_witness_shape_exact &&
        out.fixed_offset_schedule_bound &&
        !out.fixed_offset_schedule_commitment.IsNull() &&
        out.all_66_root_aliases_literal &&
        out.every_temporal_alias_literal &&
        out.aliased_values_are_ordinary_columns &&
        out.source_and_sink_cells_disjoint &&
        out.semantic_export_cells_distinct &&
        out.selectors_only_new_preprocessing &&
        out.cross_row_transport_constrained &&
        out.no_child_tape_hash_required &&
        out.parent_trace_commitment_binding_model &&
        out.public_anchor_equalities ==
            2 * kRecursiveProvenanceRootLimbsV1 &&
        out.violations == 0 &&
        !out.verifier_output_semantics_constrained &&
        !out.named_consumer_semantics_constrained &&
        !out.complete_child_acceptance_in_same_parent &&
        !out.same_parent_child_verifier_owned &&
        !out.recursive_authority;
    out.note = out.valid
        ? "stage3:recursive_provenance_join:"
          "14_role_52_endpoint_and_all_temporal_fixed_offset_aliases;"
          "parent_witness_committed_without_child_tape_hash;"
          "source_sink_semantics_and_child_acceptance_open"
        : "stage3:recursive_provenance_join:"
          "parent_alias_constraint_violation";
    if (why != nullptr) *why = out.note;
    return out.valid;
}

bool BuildCanonicalRecursiveProvenanceEventScheduleV1(
    const RecursiveProvenanceShapeV1& shape,
    std::vector<RecursiveProvenanceEventKeyV1>& out,
    std::string* why)
{
    out.clear();
    if (!ShapeValid(shape, why)) return false;

    const auto graph = CurrentRCStage3ProvenanceGraphAudit();
    if (!graph.exact_52_order ||
        !graph.exact_public_roots_1_and_25 ||
        !graph.every_non_public_node_has_a_producer ||
        !graph.no_missing_out_of_range_self_or_duplicate_producer ||
        !graph.capability_flags_fail_closed ||
        graph.nodes.size() != kRecursiveProvenanceEndpointCountV1) {
        return Fail(why, "source_graph_audit");
    }

    // Preserve every graph-declared named aggregate-root edge.
    for (const auto& node : graph.nodes) {
        for (const auto& edge : node.producers) {
            Add(
                out, edge.producer, node.endpoint,
                K::GraphNamedRoot, UINT32_MAX, UINT32_MAX,
                edge.construction.c_str());
        }
    }

    // Episode round-root cells.  These are deliberately not replaced by the
    // endpoint-23 vector root.
    for (uint32_t round = 0;
         round < shape.episode_round_roots; ++round) {
        Add(
            out, E::EpisodeTileTreeRoot,
            E::EpisodeDigestRoundRoots,
            K::EpisodeTileRootAtRound, round, round,
            "episode_tile_root_vector_ctl_v1:"
            "typed_byte_same_trace_dual_logup:round");
        Add(
            out, E::EpisodeDigestRoundRoots,
            E::EpisodeBuilderSeedChain,
            K::EpisodeRoundRootFeedback, round, round,
            "episode_builder_seed_chain_v1:"
            "round_roots:round");
    }

    // The following exact instance counts/positions mirror the eight
    // equality families executed by ValidateRCStage3CoupledChainProduct.
    const uint32_t barriers = shape.coupled_barriers;
    const uint32_t lobes = shape.coupled_lobes;
    const uint32_t exchange_rounds =
        shape.coupled_exchange_rounds;
    for (uint32_t barrier = 0; barrier < barriers; ++barrier) {
        for (uint32_t lobe = 0; lobe < lobes; ++lobe) {
            const uint32_t gemm_position =
                barrier * lobes + lobe;
            Add(
                out, E::CoupledBankPages,
                E::CoupledGemmOperandB,
                K::CoupledBankPageToGemmB,
                gemm_position, gemm_position,
                "coupled_chain_product_v1:"
                "bank_pages_to_gemm_b:instance");
            Add(
                out, E::CoupledGemmOutputY,
                E::CoupledExchangeInput,
                K::CoupledGemmYToFixedExchange,
                gemm_position, gemm_position,
                "coupled_chain_product_v1:"
                "gemm_y_to_exchange_input:instance");
            if (barrier > 0) {
                Add(
                    out, E::CoupledExtractOutput,
                    E::CoupledGemmOperandA,
                    K::CoupledPriorExtractToGemmA,
                    (barrier - 1U) * lobes + lobe,
                    gemm_position,
                    "coupled_chain_product_v1:"
                    "prior_extract_to_gemm_a:instance");
            }
        }

        Add(
            out, E::CoupledPermutationOutput,
            E::CoupledMixInput,
            K::CoupledPermutationToMix,
            barrier, barrier,
            "coupled_chain_product_v1:"
            "permutation_output_to_mix_input:barrier");

        if (exchange_rounds == 0) {
            Add(
                out, E::CoupledMixOutput,
                E::CoupledExtractInput,
                K::CoupledZeroRoundMixToExtract,
                barrier, barrier,
                "coupled_chain_product_v1:"
                "zero_round_mix_to_extract:barrier");
        } else {
            const uint32_t base = barrier * exchange_rounds;
            Add(
                out, E::CoupledMixOutput,
                E::CoupledExchangeInput,
                K::CoupledMixToMaterialRound0,
                barrier, base,
                "coupled_chain_product_v1:"
                "mix_to_material_round0:barrier");
            for (uint32_t round = 1;
                 round < exchange_rounds; ++round) {
                Add(
                    out, E::CoupledExchangeOutput,
                    E::CoupledExchangeInput,
                    K::CoupledMaterialRoundChain,
                    base + round - 1U, base + round,
                    "coupled_chain_product_v1:"
                    "material_round_chain:round");
            }
            Add(
                out, E::CoupledExchangeOutput,
                E::CoupledExtractInput,
                K::CoupledFinalMaterialToExtract,
                base + exchange_rounds - 1U, barrier,
                "coupled_chain_product_v1:"
                "material_final_to_extract:barrier");
        }

        Add(
            out, E::CoupledBarrierOutput,
            E::CoupledDigestBankAndBarriers,
            K::CoupledBarrierOutputToDigest,
            barrier, barrier,
            "global_root_chain_v1:"
            "barrier_outputs_to_digest:barrier");
    }

    std::sort(out.begin(), out.end(), EventLess);
    if (std::adjacent_find(out.begin(), out.end()) != out.end()) {
        out.clear();
        return Fail(why, "duplicate_canonical_event");
    }
    return true;
}

uint256 ComputeRecursiveProvenanceScheduleCommitmentV1(
    const RecursiveProvenanceShapeV1& shape,
    const std::vector<RecursiveProvenanceEventKeyV1>& events)
{
    if (!ShapeValid(shape, nullptr)) return {};
    std::vector<RecursiveProvenanceEventKeyV1> canonical;
    if (!BuildCanonicalRecursiveProvenanceEventScheduleV1(
            shape, canonical, nullptr) ||
        canonical != events) {
        return {};
    }
    HashWriter hash;
    hash << kScheduleDomain
         << kRecursiveProvenanceJoinVersionV1
         << shape.episode_round_roots
         << shape.coupled_barriers
         << shape.coupled_lobes
         << shape.coupled_exchange_rounds
         << shape.episode_builder_params_root
         << shape.episode_header_target_root
         << static_cast<uint32_t>(kRoleOrder.size());
    for (const auto role : kRoleOrder) {
        hash << static_cast<uint16_t>(role);
    }
    const auto endpoints =
        CurrentRCStage3RelationEndpointCellAudit();
    hash << static_cast<uint32_t>(endpoints.size());
    for (const auto& endpoint : endpoints) {
        hash << static_cast<uint16_t>(endpoint.endpoint)
             << static_cast<uint16_t>(endpoint.role);
    }
    hash << static_cast<uint32_t>(events.size());
    for (const auto& event : events) {
        hash << static_cast<uint16_t>(event.producer)
             << static_cast<uint16_t>(event.consumer)
             << static_cast<uint16_t>(event.kind)
             << event.producer_position
             << event.consumer_position
             << event.construction;
    }
    return hash.GetHash();
}

RecursiveProvenanceJoinProductV1
BuildRecursiveProvenanceJoinV1(
    const RecursiveProvenanceShapeV1& shape,
    const RecursiveProvenanceWitnessV1& witness)
{
    RecursiveProvenanceJoinProductV1 out;
    out.shape = shape;
    std::string why;
    std::vector<RecursiveProvenanceEventKeyV1> expected_events;
    if (!BuildCanonicalRecursiveProvenanceEventScheduleV1(
            shape, expected_events, &why)) {
        out.note = why;
        return out;
    }
    out.schedule_commitment =
        ComputeRecursiveProvenanceScheduleCommitmentV1(
            shape, expected_events);
    if (out.schedule_commitment.IsNull()) {
        out.note =
            "stage3:recursive_provenance_join:"
            "schedule_commitment";
        return out;
    }

    std::vector<CanonicalRow> rows;
    bool every_verified = false;
    if (!ExactWitnessSchedule(
            shape, witness, expected_events, rows,
            every_verified, &why)) {
        out.note = why;
        return out;
    }

    out.layout = MakeLayout();
    out.active_rows = static_cast<uint32_t>(rows.size());
    out.cs.n_rows = NextPowerOfTwo(out.active_rows);
    out.cs.n_columns = out.layout.total_columns;
    if (out.cs.n_rows == 0) {
        out.note =
            "stage3:recursive_provenance_join:row_overflow";
        return out;
    }
    out.columns.assign(
        out.cs.n_columns,
        std::vector<Fp3>(out.cs.n_rows, Fp3::Zero()));

    const auto fill_pp = [&](uint32_t column,
                             uint32_t row,
                             uint32_t value) {
        out.columns[column][row] = U32(value);
    };
    const auto fill_root = [&](const auto& columns,
                               uint32_t row,
                               const uint256& root) {
        const auto limbs = RootLimbs(root);
        for (uint32_t limb = 0; limb < limbs.size(); ++limb) {
            out.columns[columns[limb]][row] = U32(limbs[limb]);
        }
    };

    for (uint32_t row = 0; row < rows.size(); ++row) {
        const auto& spec = rows[row];
        const uint32_t kind =
            static_cast<uint32_t>(spec.kind);
        const uint32_t role =
            static_cast<uint32_t>(spec.role);
        const uint32_t endpoint =
            static_cast<uint32_t>(spec.endpoint);
        const uint32_t producer =
            static_cast<uint32_t>(spec.producer);
        const uint32_t consumer =
            static_cast<uint32_t>(spec.consumer);
        const uint32_t event_kind =
            static_cast<uint32_t>(spec.event_kind);

        fill_pp(out.layout.claimed_row_kind, row, kind);
        fill_pp(out.layout.claimed_role, row, role);
        fill_pp(out.layout.claimed_endpoint, row, endpoint);
        fill_pp(out.layout.claimed_producer, row, producer);
        fill_pp(out.layout.claimed_consumer, row, consumer);
        fill_pp(
            out.layout.claimed_event_kind, row, event_kind);
        fill_pp(
            out.layout.claimed_producer_position,
            row, spec.producer_position);
        fill_pp(
            out.layout.claimed_consumer_position,
            row, spec.consumer_position);
        fill_root(out.layout.left_root, row, spec.left_root);
        fill_root(out.layout.right_root, row, spec.right_root);

        fill_pp(out.layout.pp_active, row, 1);
        fill_pp(out.layout.pp_row_kind, row, kind);
        fill_pp(out.layout.pp_role, row, role);
        fill_pp(out.layout.pp_endpoint, row, endpoint);
        fill_pp(out.layout.pp_producer, row, producer);
        fill_pp(out.layout.pp_consumer, row, consumer);
        fill_pp(out.layout.pp_event_kind, row, event_kind);
        fill_pp(
            out.layout.pp_producer_position,
            row, spec.producer_position);
        fill_pp(
            out.layout.pp_consumer_position,
            row, spec.consumer_position);
        if (spec.anchor) {
            fill_pp(out.layout.pp_anchor_selector, row, 1);
            fill_root(
                out.layout.pp_anchor_root, row,
                spec.anchor_root);
        }
    }

    const std::array<std::pair<uint32_t, uint32_t>, 8>
        metadata{{
            {out.layout.claimed_row_kind,
             out.layout.pp_row_kind},
            {out.layout.claimed_role,
             out.layout.pp_role},
            {out.layout.claimed_endpoint,
             out.layout.pp_endpoint},
            {out.layout.claimed_producer,
             out.layout.pp_producer},
            {out.layout.claimed_consumer,
             out.layout.pp_consumer},
            {out.layout.claimed_event_kind,
             out.layout.pp_event_kind},
            {out.layout.claimed_producer_position,
             out.layout.pp_producer_position},
            {out.layout.claimed_consumer_position,
             out.layout.pp_consumer_position},
        }};
    for (const auto [claimed, expected] : metadata) {
        AddGatedEquality(
            out.cs,
            "stage3.recursive_provenance.canonical_position",
            claimed, expected, out.layout.pp_active);
    }
    for (uint32_t limb = 0;
         limb < kRecursiveProvenanceRootLimbsV1; ++limb) {
        AddGatedEquality(
            out.cs,
            "stage3.recursive_provenance.named_root_equality",
            out.layout.left_root[limb],
            out.layout.right_root[limb],
            out.layout.pp_active);
        AddGatedEquality(
            out.cs,
            "stage3.recursive_provenance.public_anchor",
            out.layout.right_root[limb],
            out.layout.pp_anchor_root[limb],
            out.layout.pp_anchor_selector);
    }

    const std::array<uint32_t, 18> pp_columns{{
        out.layout.pp_active,
        out.layout.pp_row_kind,
        out.layout.pp_role,
        out.layout.pp_endpoint,
        out.layout.pp_producer,
        out.layout.pp_consumer,
        out.layout.pp_event_kind,
        out.layout.pp_producer_position,
        out.layout.pp_consumer_position,
        out.layout.pp_anchor_selector,
        out.layout.pp_anchor_root[0],
        out.layout.pp_anchor_root[1],
        out.layout.pp_anchor_root[2],
        out.layout.pp_anchor_root[3],
        out.layout.pp_anchor_root[4],
        out.layout.pp_anchor_root[5],
        out.layout.pp_anchor_root[6],
        out.layout.pp_anchor_root[7],
    }};
    for (const uint32_t column : pp_columns) {
        out.cs.preprocessed.emplace_back(
            column, out.columns[column]);
    }
    out.cs.preprocessed_pin_ood = true;

    out.graph_named_root_events =
        static_cast<uint32_t>(std::count_if(
            expected_events.begin(), expected_events.end(),
            [](const auto& event) {
                return event.kind == K::GraphNamedRoot;
            }));
    out.temporal_events =
        static_cast<uint32_t>(expected_events.size()) -
        out.graph_named_root_events;
    out.violations =
        CountRecursiveProvenanceJoinViolationsV1(
            out.cs, out.columns);
    out.exact_role_order = true;
    out.exact_endpoint_order = true;
    out.exact_event_order = true;
    out.public_anchors_1_and_25_pinned = true;
    out.every_supplied_cell_host_reported_locally_verified =
        every_verified;
    out.values_are_ordinary_witness_columns = true;
    out.selectors_and_positions_preprocessed = true;
    out.temporal_edges_explicit = out.temporal_events != 0;
    out.same_parent_child_verifier_owned = false;
    out.recursive_authority = false;
    out.production_complete = false;
    out.valid =
        out.violations == 0 &&
        out.every_supplied_cell_host_reported_locally_verified &&
        out.exact_role_order &&
        out.exact_endpoint_order &&
        out.exact_event_order &&
        out.public_anchors_1_and_25_pinned &&
        out.values_are_ordinary_witness_columns &&
        out.selectors_and_positions_preprocessed &&
        out.temporal_edges_explicit;
    out.note = out.valid
        ? "stage3:recursive_provenance_join:"
          "52_endpoints_14_roles_and_temporal_cells_equal;"
          "same_parent_child_verifier_ownership_open"
        : "stage3:recursive_provenance_join:"
          "equality_or_host_reported_local_verification";
    return out;
}

uint32_t CountRecursiveProvenanceJoinViolationsV1(
    const aq::AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns)
{
    if (cs.n_rows < 2 ||
        columns.size() != cs.n_columns) {
        return std::numeric_limits<uint32_t>::max();
    }
    for (const auto& column : columns) {
        if (column.size() != cs.n_rows) {
            return std::numeric_limits<uint32_t>::max();
        }
    }
    uint32_t violations = 0;
    for (uint32_t row = 0; row < cs.n_rows; ++row) {
        std::vector<Fp3> cur(cs.n_columns);
        std::vector<Fp3> next(cs.n_columns);
        const uint32_t next_row =
            row + 1U < cs.n_rows ? row + 1U : row;
        for (uint32_t column = 0;
             column < cs.n_columns; ++column) {
            cur[column] = columns[column][row];
            next[column] = columns[column][next_row];
        }
        for (const auto& constraint : cs.constraints) {
            bool active = false;
            switch (constraint.kind) {
            case aq::AirKind::kEverywhere:
                active = true;
                break;
            case aq::AirKind::kTransition:
                active = row + 1U < cs.n_rows;
                break;
            case aq::AirKind::kFirstRow:
                active = row == 0;
                break;
            case aq::AirKind::kLastRow:
                active = row + 1U == cs.n_rows;
                break;
            }
            if (active &&
                !gf::IsZero(constraint.eval(cur, next))) {
                if (violations !=
                    std::numeric_limits<uint32_t>::max()) {
                    ++violations;
                }
            }
        }
    }
    return violations;
}

uint256 ComputeRecursiveProvenanceJoinFsSeedV1(
    const RecursiveProvenanceShapeV1& shape,
    const uint256& schedule_commitment)
{
    if (!ShapeValid(shape, nullptr) ||
        schedule_commitment.IsNull()) {
        return {};
    }
    std::vector<RecursiveProvenanceEventKeyV1> events;
    if (!BuildCanonicalRecursiveProvenanceEventScheduleV1(
            shape, events, nullptr) ||
        ComputeRecursiveProvenanceScheduleCommitmentV1(
            shape, events) != schedule_commitment) {
        return {};
    }
    HashWriter hash;
    hash << kProofSeedDomain
         << kRecursiveProvenanceJoinVersionV1
         << schedule_commitment;
    return hash.GetHash();
}

RecursiveProvenanceJoinProofV1
ProveRecursiveProvenanceJoinV1(
    const RecursiveProvenanceJoinProductV1& product,
    const aq::AirProveOptions& options)
{
    RecursiveProvenanceJoinProofV1 out;
    out.shape = product.shape;
    out.schedule_commitment = product.schedule_commitment;
    if (!product.valid ||
        product.violations != 0 ||
        product.schedule_commitment.IsNull()) {
        out.note =
            "stage3:recursive_provenance_join:prove:product";
        return out;
    }
    out.fs_seed = ComputeRecursiveProvenanceJoinFsSeedV1(
        product.shape, product.schedule_commitment);
    if (out.fs_seed.IsNull()) {
        out.note =
            "stage3:recursive_provenance_join:prove:seed";
        return out;
    }

    const auto prove_begin = std::chrono::steady_clock::now();
    const auto proved = aq::AirQuotientProveRows(
        product.cs, product.columns, out.fs_seed, options);
    const auto prove_end = std::chrono::steady_clock::now();
    out.prove_micros = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            prove_end - prove_begin).count());
    out.quotient_division_exact =
        proved.ok && proved.division_exact;
    if (!out.quotient_division_exact) {
        out.note =
            "stage3:recursive_provenance_join:prove:" +
            proved.note;
        return out;
    }
    out.proof = proved.proof;

    std::string why;
    const auto verify_begin = std::chrono::steady_clock::now();
    out.locally_verified =
        aq::AirQuotientVerifyRows(
            product.cs, out.proof, out.fs_seed, &why);
    const auto verify_end = std::chrono::steady_clock::now();
    out.verify_micros = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            verify_end - verify_begin).count());
    if (!out.locally_verified) {
        out.note =
            "stage3:recursive_provenance_join:"
            "prove_verify:" + why;
        return out;
    }

    const AirQuotientProofAlg canonical =
        CanonicalAlgProof(out.proof);
    if (SerializeAirQuotientProofAlg(
            canonical, out.canonical_proof_bytes, &why) &&
        !out.canonical_proof_bytes.empty()) {
        const auto decoded =
            DeserializeAirQuotientProofAlg(
                out.canonical_proof_bytes, &why);
        std::vector<unsigned char> reencoded;
        out.canonical_codec =
            decoded.has_value() &&
            SerializeAirQuotientProofAlg(
                *decoded, reencoded, &why) &&
            reencoded == out.canonical_proof_bytes &&
            aq::AirQuotientVerify<
                Fp3, aq::AirFriBackendAlg<Fp3>>(
                product.cs, *decoded, out.fs_seed, &why);
    }
    out.same_parent_child_verifier_owned = false;
    out.recursive_authority = false;
    out.production_complete = false;
    out.valid =
        out.quotient_division_exact &&
        out.locally_verified &&
        out.canonical_codec;
    out.note = out.valid
        ? "stage3:recursive_provenance_join:"
          "air_quotient_fri_verified;"
          "same_parent_child_verifier_ownership_open"
        : "stage3:recursive_provenance_join:"
          "canonical_codec:" + why;
    return out;
}

bool VerifyRecursiveProvenanceJoinProofV1(
    const RecursiveProvenanceShapeV1& expected_shape,
    const RecursiveProvenanceJoinProofV1& proof,
    std::string* why)
{
    if (proof.version != kRecursiveProvenanceJoinVersionV1 ||
        proof.shape != expected_shape) {
        return Fail(why, "verify_shape");
    }
    std::vector<RecursiveProvenanceEventKeyV1> events;
    if (!BuildCanonicalRecursiveProvenanceEventScheduleV1(
            expected_shape, events, why)) {
        return false;
    }
    const uint256 schedule_commitment =
        ComputeRecursiveProvenanceScheduleCommitmentV1(
            expected_shape, events);
    const uint256 fs_seed =
        ComputeRecursiveProvenanceJoinFsSeedV1(
            expected_shape, schedule_commitment);
    if (schedule_commitment.IsNull() ||
        fs_seed.IsNull() ||
        proof.schedule_commitment != schedule_commitment ||
        proof.fs_seed != fs_seed) {
        return Fail(why, "verify_public_transcript");
    }

    const RecursiveProvenanceJoinProductV1 verifier_product =
        BuildRecursiveProvenanceJoinV1(
            expected_shape,
            VerifierShapeWitness(expected_shape));
    if (!verifier_product.valid) {
        return Fail(why, "verify_constraint_system");
    }
    std::string air_why;
    if (!aq::AirQuotientVerifyRows(
            verifier_product.cs, proof.proof,
            fs_seed, &air_why)) {
        return Fail(why, "verify_air:" + air_why);
    }
    if (why != nullptr) {
        *why =
            "stage3:recursive_provenance_join:"
            "air_quotient_fri_ok;"
            "same_parent_child_verifier_ownership_open";
    }
    return true;
}

} // namespace matmul::v4::rc::recursive_provenance_join
