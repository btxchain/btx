// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_unified_root.h>

#include <hash.h>
#include <matmul/matmul_v4_rc_stage3_aggregation_schedule.h>
#include <matmul/matmul_v4_rc_stage3_composition.h>
#include <matmul/matmul_v4_rc_stage3_narrow_recurse.h>
#include <matmul/matmul_v4_rc_stage3_soundness_scenarios.h>

#include <algorithm>
#include <array>
#include <limits>
#include <utility>

namespace matmul::v4::rc {
namespace {

constexpr char STATEMENT_DOMAIN[] =
    "BTX_RC_STAGE3_UNIFIED_STATEMENT_V2";
constexpr char ROOT_SEED_DOMAIN[] =
    "BTX_RC_STAGE3_UNIFIED_ROOT_SEED_V3";
constexpr char SOUNDNESS_MANIFEST_DOMAIN[] =
    "BTX_RC_STAGE3_UNIFIED_SOUNDNESS_MANIFEST_V1";
constexpr char ROLE_LEAF_DOMAIN[] =
    "BTX_RC_STAGE3_UNIFIED_ROLE_LEAF_V1";
constexpr char PADDING_LEAF_DOMAIN[] =
    "BTX_RC_STAGE3_UNIFIED_PADDING_LEAF_V1";
constexpr char TREE_NODE_DOMAIN[] =
    "BTX_RC_STAGE3_UNIFIED_TREE_NODE_V1";
constexpr char NODE_SEED_DOMAIN[] =
    "BTX_RC_STAGE3_UNIFIED_NODE_SEED_V1";
constexpr char RECURSIVE_PROOF_DOMAIN[] =
    "BTX_RC_STAGE3_UNIFIED_RECURSIVE_PROOF_V1";
constexpr char CTL_PROOF_BUNDLE_DOMAIN[] =
    "BTX_RC_STAGE3_UNIFIED_CTL_PROOF_BUNDLE_V1";
constexpr uint64_t LOG2_32_17_Q32 = 3919317253ULL;
constexpr uint16_t UNIFIED_FRI_QUERIES =
    static_cast<uint16_t>(kRCFri3AlgNumQueries);

constexpr std::array<RCStage3RelationRole, kRCStage3UnifiedRoleCount>
    UNIFIED_ROLE_ORDER{
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

constexpr std::array<RCStage3UnifiedSoundnessSite,
                     kRCStage3UnifiedSoundnessSiteCount>
    SOUNDNESS_SITE_MANIFEST{{
        {RCStage3UnifiedSoundnessSiteKind::RelationLeaf, 0, 0,
         RCStage3RelationRole::EpisodeDeterministicBuilder, UNIFIED_FRI_QUERIES},
        {RCStage3UnifiedSoundnessSiteKind::RelationLeaf, 0, 1,
         RCStage3RelationRole::EpisodeGemm, UNIFIED_FRI_QUERIES},
        {RCStage3UnifiedSoundnessSiteKind::RelationLeaf, 0, 2,
         RCStage3RelationRole::EpisodeExtract, UNIFIED_FRI_QUERIES},
        {RCStage3UnifiedSoundnessSiteKind::RelationLeaf, 0, 3,
         RCStage3RelationRole::EpisodeWiring, UNIFIED_FRI_QUERIES},
        {RCStage3UnifiedSoundnessSiteKind::RelationLeaf, 0, 4,
         RCStage3RelationRole::EpisodeTileTree, UNIFIED_FRI_QUERIES},
        {RCStage3UnifiedSoundnessSiteKind::RelationLeaf, 0, 5,
         RCStage3RelationRole::EpisodeDigest, UNIFIED_FRI_QUERIES},
        {RCStage3UnifiedSoundnessSiteKind::RelationLeaf, 0, 6,
         RCStage3RelationRole::CoupledBank, UNIFIED_FRI_QUERIES},
        {RCStage3UnifiedSoundnessSiteKind::RelationLeaf, 0, 7,
         RCStage3RelationRole::CoupledGemm, UNIFIED_FRI_QUERIES},
        {RCStage3UnifiedSoundnessSiteKind::RelationLeaf, 0, 8,
         RCStage3RelationRole::CoupledExchange, UNIFIED_FRI_QUERIES},
        {RCStage3UnifiedSoundnessSiteKind::RelationLeaf, 0, 9,
         RCStage3RelationRole::CoupledPermutation, UNIFIED_FRI_QUERIES},
        {RCStage3UnifiedSoundnessSiteKind::RelationLeaf, 0, 10,
         RCStage3RelationRole::CoupledMix, UNIFIED_FRI_QUERIES},
        {RCStage3UnifiedSoundnessSiteKind::RelationLeaf, 0, 11,
         RCStage3RelationRole::CoupledExtract, UNIFIED_FRI_QUERIES},
        {RCStage3UnifiedSoundnessSiteKind::RelationLeaf, 0, 12,
         RCStage3RelationRole::CoupledBarrier, UNIFIED_FRI_QUERIES},
        {RCStage3UnifiedSoundnessSiteKind::RelationLeaf, 0, 13,
         RCStage3RelationRole::CoupledDigest, UNIFIED_FRI_QUERIES},
        {RCStage3UnifiedSoundnessSiteKind::AggregationNode, 1, 0, {}, UNIFIED_FRI_QUERIES},
        {RCStage3UnifiedSoundnessSiteKind::AggregationNode, 1, 1, {}, UNIFIED_FRI_QUERIES},
        {RCStage3UnifiedSoundnessSiteKind::AggregationNode, 1, 2, {}, UNIFIED_FRI_QUERIES},
        {RCStage3UnifiedSoundnessSiteKind::AggregationNode, 1, 3, {}, UNIFIED_FRI_QUERIES},
        {RCStage3UnifiedSoundnessSiteKind::AggregationNode, 1, 4, {}, UNIFIED_FRI_QUERIES},
        {RCStage3UnifiedSoundnessSiteKind::AggregationNode, 1, 5, {}, UNIFIED_FRI_QUERIES},
        {RCStage3UnifiedSoundnessSiteKind::AggregationNode, 1, 6, {}, UNIFIED_FRI_QUERIES},
        {RCStage3UnifiedSoundnessSiteKind::AggregationNode, 1, 7, {}, UNIFIED_FRI_QUERIES},
        {RCStage3UnifiedSoundnessSiteKind::AggregationNode, 2, 0, {}, UNIFIED_FRI_QUERIES},
        {RCStage3UnifiedSoundnessSiteKind::AggregationNode, 2, 1, {}, UNIFIED_FRI_QUERIES},
        {RCStage3UnifiedSoundnessSiteKind::AggregationNode, 2, 2, {}, UNIFIED_FRI_QUERIES},
        {RCStage3UnifiedSoundnessSiteKind::AggregationNode, 2, 3, {}, UNIFIED_FRI_QUERIES},
        {RCStage3UnifiedSoundnessSiteKind::AggregationNode, 3, 0, {}, UNIFIED_FRI_QUERIES},
        {RCStage3UnifiedSoundnessSiteKind::AggregationNode, 3, 1, {}, UNIFIED_FRI_QUERIES},
        {RCStage3UnifiedSoundnessSiteKind::AggregationNode, 4, 0, {}, UNIFIED_FRI_QUERIES},
    }};

bool Fail(std::string* why, const std::string& message)
{
    if (why != nullptr) *why = "stage3:unified_root:" + message;
    return false;
}

uint32_t CeilLog2(uint32_t value)
{
    if (value <= 1) return 0;
    uint32_t bits = 0;
    --value;
    while (value != 0) {
        value >>= 1;
        ++bits;
    }
    return bits;
}

uint32_t CeilLog2U64(uint64_t value)
{
    if (value <= 1) return 0;
    uint32_t bits = 0;
    --value;
    while (value != 0) {
        value >>= 1;
        ++bits;
    }
    return bits;
}

uint32_t Fp3UnionBits(uint64_t numerator)
{
    // Goldilocks p > 2^63, hence |Fp3| = p^3 > 2^189.
    constexpr uint32_t FP3_CONSERVATIVE_BITS = 189;
    const uint32_t loss = CeilLog2U64(std::max<uint64_t>(1, numerator));
    return loss >= FP3_CONSERVATIVE_BITS
               ? 0
               : FP3_CONSERVATIVE_BITS - loss;
}

void WritePublicStatementContext(HashWriter& hash,
                                 const RCStage3SuccinctProof& statement)
{
    const auto& p = statement.public_inputs;
    hash << statement.magic;
    hash << statement.version;
    hash << static_cast<uint8_t>(statement.authority);
    hash << static_cast<uint8_t>(statement.statement);
    hash << p.height;
    hash << p.n_bits;
    hash << p.episode_profile;
    hash << p.coupled_profile;
    hash << p.transcript_version;
    hash << p.header_commitment;
    hash << p.params_commitment;
    hash << p.target;
    hash << p.sigma;
    hash << p.episode_digest;
    hash << p.coupled_digest;
    hash << p.final_digest;
}

void WriteParameters(HashWriter& hash,
                     const RCStage3UnifiedRootParameters& parameters)
{
    hash << static_cast<uint8_t>(parameters.topology);
    hash << parameters.aggregation_arity;
    hash << parameters.aggregation_depth;
    hash << parameters.role_leaf_count;
    hash << parameters.normalized_leaf_count;
    hash << parameters.fri_queries;
    hash << parameters.fri_repetition_lanes;
    hash << static_cast<uint8_t>(parameters.fri_batching_mode);
    hash << static_cast<uint8_t>(parameters.fri_commitment_scenario);
    hash << parameters.fri_queries_per_lane;
    hash << parameters.grinding_bits;
    hash << parameters.target_soundness_bits;
    hash << parameters.soundness_union_bound_instances;
    hash << parameters.max_recursive_air_columns;
}

class Writer {
public:
    void U8(uint8_t value) { m_out.push_back(value); }

    void U16(uint16_t value)
    {
        U8(static_cast<uint8_t>(value));
        U8(static_cast<uint8_t>(value >> 8));
    }

    void U32(uint32_t value)
    {
        for (unsigned i = 0; i < 4; ++i) {
            U8(static_cast<uint8_t>(value >> (8 * i)));
        }
    }

    void U64(uint64_t value)
    {
        for (unsigned i = 0; i < 8; ++i) {
            U8(static_cast<uint8_t>(value >> (8 * i)));
        }
    }

    void Uint256(const uint256& value)
    {
        m_out.insert(m_out.end(), value.data(), value.data() + value.size());
    }

    void Fp3(const gkr_field::Fp3& value)
    {
        U64(gkr_field::Canonical(value.c0));
        U64(gkr_field::Canonical(value.c1));
        U64(gkr_field::Canonical(value.c2));
    }

    void Bytes(const std::vector<unsigned char>& bytes)
    {
        m_out.insert(m_out.end(), bytes.begin(), bytes.end());
    }

    [[nodiscard]] size_t Size() const { return m_out.size(); }

    std::vector<unsigned char> Take() { return std::move(m_out); }

private:
    std::vector<unsigned char> m_out;
};

class Reader {
public:
    explicit Reader(const std::vector<unsigned char>& bytes)
        : m_pos(bytes.data()), m_end(bytes.data() + bytes.size())
    {
    }

    bool U8(uint8_t& value)
    {
        if (Remaining() < 1) return false;
        value = *m_pos++;
        return true;
    }

    bool U16(uint16_t& value)
    {
        if (Remaining() < 2) return false;
        value = static_cast<uint16_t>(m_pos[0]) |
                (static_cast<uint16_t>(m_pos[1]) << 8);
        m_pos += 2;
        return true;
    }

    bool U32(uint32_t& value)
    {
        if (Remaining() < 4) return false;
        value = 0;
        for (unsigned i = 0; i < 4; ++i) {
            value |= static_cast<uint32_t>(m_pos[i]) << (8 * i);
        }
        m_pos += 4;
        return true;
    }

    bool U64(uint64_t& value)
    {
        if (Remaining() < 8) return false;
        value = 0;
        for (unsigned i = 0; i < 8; ++i) {
            value |= static_cast<uint64_t>(m_pos[i]) << (8 * i);
        }
        m_pos += 8;
        return true;
    }

    bool Uint256(uint256& value)
    {
        if (Remaining() < value.size()) return false;
        std::copy_n(m_pos, value.size(), value.data());
        m_pos += value.size();
        return true;
    }

    bool Fp3(gkr_field::Fp3& value)
    {
        if (!U64(value.c0) || !U64(value.c1) || !U64(value.c2)) {
            return false;
        }
        return value.c0 < gkr_field::kP &&
               value.c1 < gkr_field::kP &&
               value.c2 < gkr_field::kP;
    }

    bool Bytes(size_t count, std::vector<unsigned char>& bytes)
    {
        if (count > Remaining()) return false;
        bytes.assign(m_pos, m_pos + count);
        m_pos += count;
        return true;
    }

    [[nodiscard]] size_t Remaining() const
    {
        return static_cast<size_t>(m_end - m_pos);
    }

private:
    const unsigned char* m_pos;
    const unsigned char* m_end;
};

void WriteParameters(Writer& writer,
                     const RCStage3UnifiedRootParameters& parameters)
{
    writer.U8(static_cast<uint8_t>(parameters.topology));
    writer.U8(parameters.aggregation_arity);
    writer.U8(parameters.aggregation_depth);
    writer.U8(
        static_cast<uint8_t>(
            (static_cast<uint8_t>(parameters.fri_batching_mode) << 7) |
            ((parameters.fri_commitment_scenario ==
                      Fri3AlgDualCommitmentScenario::
                          SharedMasterDerivedChildren
                  ? 1U
                  : 0U)
             << 6) |
            parameters.fri_repetition_lanes));
    writer.U16(parameters.role_leaf_count);
    writer.U16(parameters.normalized_leaf_count);
    writer.U16(parameters.fri_queries);
    writer.U16(parameters.grinding_bits);
    writer.U16(parameters.target_soundness_bits);
    writer.U16(parameters.fri_queries_per_lane);
    writer.U32(parameters.soundness_union_bound_instances);
    writer.U32(parameters.max_recursive_air_columns);
}

bool ReadParameters(Reader& reader,
                    RCStage3UnifiedRootParameters& parameters)
{
    uint8_t topology{0};
    uint8_t fri_repetition_descriptor{0};
    if (!reader.U8(topology) || !reader.U8(parameters.aggregation_arity) ||
        !reader.U8(parameters.aggregation_depth) ||
        !reader.U8(fri_repetition_descriptor) ||
        !reader.U16(parameters.role_leaf_count) ||
        !reader.U16(parameters.normalized_leaf_count) ||
        !reader.U16(parameters.fri_queries) ||
        !reader.U16(parameters.grinding_bits) ||
        !reader.U16(parameters.target_soundness_bits) ||
        !reader.U16(parameters.fri_queries_per_lane) ||
        !reader.U32(parameters.soundness_union_bound_instances) ||
        !reader.U32(parameters.max_recursive_air_columns)) {
        return false;
    }
    parameters.fri_repetition_lanes =
        fri_repetition_descriptor & 0x3fU;
    parameters.fri_batching_mode =
        static_cast<RCStage3UnifiedFriBatchingMode>(
            fri_repetition_descriptor >> 7);
    parameters.fri_commitment_scenario =
        (fri_repetition_descriptor & 0x40U) != 0
        ? Fri3AlgDualCommitmentScenario::SharedMasterDerivedChildren
        : Fri3AlgDualCommitmentScenario::
              FullyDuplicatedLaneCommitments;
    parameters.topology = static_cast<RCStage3UnifiedTopology>(topology);
    return true;
}

void WriteCtlManifest(Writer& writer, const RCStage3CtlManifest& manifest)
{
    writer.U32(manifest.bus_id);
    writer.Uint256(manifest.transcript_seed);
    writer.U16(static_cast<uint16_t>(manifest.participants.size()));
    for (const auto& participant : manifest.participants) {
        writer.U16(static_cast<uint16_t>(participant.role));
        writer.U64(participant.event_count);
        writer.U64(participant.send_count);
        writer.U64(participant.receive_count);
        writer.Uint256(participant.schedule_commitment);
    }
}

bool ReadCtlManifest(Reader& reader, RCStage3CtlManifest& manifest)
{
    uint16_t participant_count{0};
    if (!reader.U32(manifest.bus_id) ||
        !reader.Uint256(manifest.transcript_seed) ||
        !reader.U16(participant_count) ||
        participant_count != kRCStage3UnifiedRoleCount) {
        return false;
    }
    manifest.participants.resize(participant_count);
    for (auto& participant : manifest.participants) {
        uint16_t role{0};
        if (!reader.U16(role) ||
            !reader.U64(participant.event_count) ||
            !reader.U64(participant.send_count) ||
            !reader.U64(participant.receive_count) ||
            !reader.Uint256(participant.schedule_commitment)) {
            return false;
        }
        participant.role = static_cast<RCStage3RelationRole>(role);
    }
    return true;
}

bool ValidateUnifiedCtlBundleShape(
    const RCStage3UnifiedCtlProofBundle& bundle,
    std::string* why)
{
    using namespace stage3_ctl_col;
    if (bundle.magic != kRCStage3UnifiedCtlBundleMagic) {
        return Fail(why, "ctl_bundle:bad_magic");
    }
    if (bundle.version != kRCStage3UnifiedCtlBundleVersion) {
        return Fail(why, "ctl_bundle:bad_version");
    }
    if (bundle.registry_version != kRCStage3UnifiedRootRegistryVersion) {
        return Fail(why, "ctl_bundle:bad_registry_version");
    }
    if (bundle.root_seed.IsNull() ||
        bundle.ctl_composition_commitment.IsNull()) {
        return Fail(why, "ctl_bundle:null_binding");
    }
    if (bundle.children.size() != kRCStage3UnifiedRoleCount) {
        return Fail(why, "ctl_bundle:child_count");
    }
    const auto& order = RCStage3UnifiedRoleOrder();
    for (size_t i = 0; i < bundle.children.size(); ++i) {
        const auto& child = bundle.children[i];
        const auto& proof = child.proof;
        if (child.role != order[i] ||
            child.relation_export.role != child.role) {
            return Fail(why, "ctl_bundle:role_order");
        }
        std::vector<unsigned char> relation_export;
        if (!SerializeRCStage3CtlRelationExportPin(
                child.relation_export, relation_export)) {
            return Fail(why, "ctl_bundle:relation_export");
        }
        std::string schedule_why;
        if (!ValidateRCStage3CtlSchedule(
                child.schedule, &schedule_why)) {
            return Fail(why, "ctl_bundle:schedule:" + schedule_why);
        }
        if (proof.batch.columns.size() != NUM_COLUMNS + 1 ||
            proof.batch.column_len.size() != NUM_COLUMNS + 1 ||
            proof.batch.queries.size() != kRCFriBatchNumQueries ||
            proof.next_openings.size() != proof.batch.queries.size() ||
            !proof.trace_commit.IsNull()) {
            return Fail(why, "ctl_bundle:air_shape");
        }
        for (const auto& row : proof.next_openings) {
            if (row.size() != NUM_COLUMNS) {
                return Fail(why, "ctl_bundle:opening_width");
            }
            for (const auto& path : row) {
                if (path.leaf.c0 >= gkr_field::kP ||
                    path.leaf.c1 >= gkr_field::kP ||
                    path.leaf.c2 >= gkr_field::kP ||
                    path.siblings.size() > 64) {
                    return Fail(why, "ctl_bundle:opening_encoding");
                }
            }
        }
    }
    return true;
}

void WriteCtlSchedule(Writer& writer, const RCStage3CtlSchedule& schedule)
{
    writer.U32(static_cast<uint32_t>(schedule.events.size()));
    for (const auto& event : schedule.events) {
        writer.U32(event.namespace_id);
        writer.U32(event.stage);
        writer.U32(event.address);
        writer.U8(static_cast<uint8_t>(event.multiplicity));
    }
}

bool ReadCtlSchedule(Reader& reader, RCStage3CtlSchedule& schedule)
{
    static constexpr size_t EVENT_BYTES = 3 * sizeof(uint32_t) + sizeof(uint8_t);
    uint32_t event_count{0};
    if (!reader.U32(event_count) || event_count == 0 ||
        event_count > kRCStage3CtlMaxEvents ||
        event_count > reader.Remaining() / EVENT_BYTES) {
        return false;
    }
    schedule.events.resize(event_count);
    for (auto& event : schedule.events) {
        uint8_t multiplicity{0};
        if (!reader.U32(event.namespace_id) ||
            !reader.U32(event.stage) ||
            !reader.U32(event.address) ||
            !reader.U8(multiplicity) ||
            (multiplicity != 1 && multiplicity != UINT8_MAX)) {
            return false;
        }
        event.multiplicity = static_cast<int8_t>(multiplicity);
    }
    return true;
}

bool WriteCtlAirProof(Writer& writer,
                      const RCStage3CtlAirProof& proof)
{
    std::vector<unsigned char> batch;
    if (SerializeFri3BatchProof(proof.batch, batch) == 0 ||
        batch.size() > kRCFriMaxProofBytesHard ||
        proof.next_openings.size() > UINT32_MAX) {
        return false;
    }
    writer.U32(static_cast<uint32_t>(batch.size()));
    writer.Bytes(batch);
    writer.Uint256(proof.trace_commit);
    writer.U32(static_cast<uint32_t>(proof.next_openings.size()));
    for (const auto& row : proof.next_openings) {
        if (row.size() > UINT32_MAX) return false;
        writer.U32(static_cast<uint32_t>(row.size()));
        for (const auto& path : row) {
            if (path.siblings.size() > UINT32_MAX) return false;
            writer.U32(path.index);
            writer.Fp3(path.leaf);
            writer.U32(static_cast<uint32_t>(path.siblings.size()));
            for (const auto& sibling : path.siblings) {
                writer.Uint256(sibling);
            }
        }
    }
    return true;
}

bool ReadCtlAirProof(Reader& reader,
                     RCStage3CtlAirProof& proof)
{
    uint32_t batch_size{0};
    if (!reader.U32(batch_size) || batch_size == 0 ||
        batch_size > kRCFriMaxProofBytesHard ||
        batch_size > reader.Remaining()) {
        return false;
    }
    std::vector<unsigned char> batch_bytes;
    if (!reader.Bytes(batch_size, batch_bytes)) return false;
    const auto batch = DeserializeFri3BatchProof(batch_bytes);
    if (!batch) return false;
    std::vector<unsigned char> canonical_batch;
    if (SerializeFri3BatchProof(*batch, canonical_batch) !=
            batch_bytes.size() ||
        canonical_batch != batch_bytes) {
        return false;
    }
    proof.batch = *batch;
    uint32_t row_count{0};
    if (!reader.Uint256(proof.trace_commit) ||
        !reader.U32(row_count) ||
        row_count != proof.batch.queries.size() ||
        row_count > kRCFriBatchNumQueries) {
        return false;
    }
    proof.next_openings.resize(row_count);
    for (auto& row : proof.next_openings) {
        uint32_t path_count{0};
        if (!reader.U32(path_count) ||
            path_count != stage3_ctl_col::NUM_COLUMNS) {
            return false;
        }
        row.resize(path_count);
        for (auto& path : row) {
            uint32_t sibling_count{0};
            if (!reader.U32(path.index) ||
                !reader.Fp3(path.leaf) ||
                !reader.U32(sibling_count) ||
                sibling_count > 64) {
                return false;
            }
            path.siblings.resize(sibling_count);
            for (auto& sibling : path.siblings) {
                if (!reader.Uint256(sibling)) return false;
            }
        }
    }
    return true;
}

uint256 TreeNodeCommitment(uint8_t level, uint16_t index,
                           const uint256& left, const uint256& right)
{
    HashWriter hash;
    hash << TREE_NODE_DOMAIN;
    hash << level;
    hash << index;
    hash << left;
    hash << right;
    return hash.GetHash();
}

bool ValidateStatementCommitmentRegistry(
    const RCStage3SuccinctProof& statement,
    const RCStage3UnifiedRootPublicPin& pin,
    std::string* why)
{
    const auto required =
        RequiredRCStage3RelationRoles(RCStage3StatementKind::Composed);
    if (required.size() != kRCStage3UnifiedRoleCount + 1 ||
        statement.commitments.size() != required.size()) {
        return Fail(why, "statement_commitment_count");
    }
    for (size_t i = 0; i < UNIFIED_ROLE_ORDER.size(); ++i) {
        if (required[i] != UNIFIED_ROLE_ORDER[i] ||
            statement.commitments[i].role != UNIFIED_ROLE_ORDER[i] ||
            pin.roles[i].relation_commitment !=
                statement.commitments[i].root) {
            return Fail(why, "relation_commitment_mismatch");
        }
    }
    const auto& link = statement.commitments.back();
    if (required.back() != RCStage3RelationRole::CompositionLink ||
        link.role != RCStage3RelationRole::CompositionLink ||
        pin.composition_link_commitment != link.root) {
        return Fail(why, "composition_link_commitment_mismatch");
    }
    return true;
}

} // namespace

const std::array<RCStage3RelationRole, kRCStage3UnifiedRoleCount>&
RCStage3UnifiedRoleOrder()
{
    return UNIFIED_ROLE_ORDER;
}

const std::array<RCStage3UnifiedSoundnessSite,
                 kRCStage3UnifiedSoundnessSiteCount>&
RCStage3UnifiedSoundnessSiteManifest()
{
    return SOUNDNESS_SITE_MANIFEST;
}

uint256 ComputeRCStage3UnifiedSoundnessManifestCommitment()
{
    HashWriter hash;
    hash << SOUNDNESS_MANIFEST_DOMAIN;
    hash << static_cast<uint16_t>(SOUNDNESS_SITE_MANIFEST.size());
    for (const auto& site : SOUNDNESS_SITE_MANIFEST) {
        hash << static_cast<uint8_t>(site.kind);
        hash << site.tree_level;
        hash << site.tree_index;
        hash << static_cast<uint16_t>(site.role);
        hash << site.fri_queries;
    }
    return hash.GetHash();
}

uint256 ComputeRCStage3UnifiedProductionSiteManifestCommitment()
{
    using namespace soundness_scenarios;
    const ProductionProofSiteManifest manifest =
        BuildProductionProofSiteManifest(
            SelectedProductionProofSitePolicy());
    std::string why;
    if (!ValidateProductionProofSiteManifest(manifest, &why) ||
        !manifest.complete_global_upper_bound_manifest_derived ||
        !manifest.executable_rejection_paths_enforce_policy) {
        return {};
    }
    return manifest.commitment;
}

uint256
ComputeRCStage3UnifiedProductionAggregationScheduleCommitment()
{
    using namespace soundness_scenarios;
    const ProductionProofSiteManifest manifest =
        BuildProductionProofSiteManifest(
            SelectedProductionProofSitePolicy());
    std::string why;
    if (!ValidateProductionProofSiteManifest(manifest, &why)) {
        return {};
    }
    const auto schedule =
        aggregation_scheduler::BuildProductionAggregationSchedule(
            manifest);
    if (!aggregation_scheduler::
            ValidateProductionAggregationSchedule(
                manifest, schedule, &why)) {
        return {};
    }
    return schedule.commitment;
}

RCStage3UnifiedSoundnessLedger
AssessRCStage3UnifiedGlobalSoundness(
    const RCStage3UnifiedRootPublicPin& pin)
{
    RCStage3UnifiedSoundnessLedger out;
    const auto& parameters = pin.parameters;
    const uint64_t proof_sites =
        parameters.soundness_union_bound_instances;
    const uint32_t fri_bits =
        RCStage3UnifiedRootSoundnessBits(parameters);
    const uint32_t site_log2 = CeilLog2(proof_sites);
    const auto fri_bcs =
        narrow_recurse::AssessFriBcsRepetition(
            parameters.fri_repetition_lanes,
            parameters.fri_queries_per_lane,
            192,
            24,
            4,
            3,
            parameters.grinding_bits,
            site_log2,
            256,
            kRCFri3AlgBatchMaxColumns,
            parameters.fri_batching_mode ==
                    RCStage3UnifiedFriBatchingMode::
                        IndependentCoefficients
                ? narrow_recurse::FriBatchingChallengeMode::
                      IndependentCoefficients
                : narrow_recurse::FriBatchingChallengeMode::
                      SinglePowerChallenge,
            kRCFri3AlgDualUniformWords,
            3,
            kRCFri3AlgBatchMaxColumns + 26);
    const bool dual_q128_shape_matches =
        parameters.fri_repetition_lanes ==
            kRCFri3AlgDualNumLanes &&
        parameters.fri_queries_per_lane ==
            kRCFri3AlgDualQueriesPerLane &&
        parameters.fri_batching_mode ==
            RCStage3UnifiedFriBatchingMode::
                IndependentCoefficients &&
        proof_sites != 0;
    const auto oracle_hybrid =
        AssessFri3AlgDualOracleHybrid(
            parameters.fri_commitment_scenario,
            kRCFri3AlgBatchMaxColumns, 24, site_log2);
    out.terms.push_back({
        RCStage3UnifiedSoundnessTermKind::FriProximityAndGrinding,
        proof_sites,
        fri_bits,
        parameters.fri_queries == kRCFri3AlgNumQueries &&
            parameters.grinding_bits == kRCFriGrindingBits &&
            proof_sites != 0,
        true,
        "unique-decoding proximity term after g-bit grinding and the "
        "declared candidate proof-site budget"});
    out.terms.push_back({
        RCStage3UnifiedSoundnessTermKind::FriFieldDomain,
        proof_sites,
        fri_bcs.all_query_conservative_floor_bits,
        dual_q128_shape_matches &&
            fri_bcs.bcs_bound_numerically_accounted &&
            fri_bcs.published_batching_constant_exact,
        false,
        "the provable FRI RBR term, BCS random-oracle term, NIROP "
        "repetition and declared site union are numerically instantiated. "
        "The deliberately conservative all-query screen is 101 bits for "
        "dual Q128 with independent batching at LDE 2^24, so its parameter "
        "screen passes before "
        "the open full-oracle domain-separation, common-commitment hybrid, "
        "batch-manifest, global-site and recursive-verifier reductions. "
        "No numeric screen is a Definition-2 certificate until those "
        "reductions close"});

    uint64_t trace_numerator{0};
    const uint64_t width_factor =
        static_cast<uint64_t>(parameters.max_recursive_air_columns) + 2;
    if (proof_sites != 0 &&
        width_factor <=
            std::numeric_limits<uint64_t>::max() / proof_sites) {
        trace_numerator = width_factor * proof_sites;
    }
    out.terms.push_back({
        RCStage3UnifiedSoundnessTermKind::Fp3TraceBatching,
        proof_sites,
        trace_numerator == 0 ? 0 : Fp3UnionBits(trace_numerator),
        trace_numerator != 0,
        false,
        "Fp3 row/column RLC bound is quantitative, but the complete "
        "all-shard batching reduction and exact challenge count are absent"});

    out.terms.push_back({
        RCStage3UnifiedSoundnessTermKind::Fp3ConstraintBatching,
        0,
        0,
        false,
        false,
        "exact global constraint, degree and independent batching-challenge "
        "counts are not yet available"});

    const RCStage3CtlSoundnessLedger ctl_ledger =
        AssessRCStage3CtlSoundness(
            {pin.ctl_manifest}, parameters.grinding_bits, 1);
    out.terms.push_back({
        RCStage3UnifiedSoundnessTermKind::CtlTupleCompression,
        ctl_ledger.bus_count,
        ctl_ledger.false_accept_bits_after_losses,
        ctl_ledger.manifests_exact &&
            ctl_ledger.commit_then_challenge &&
            ctl_ledger.independent_domain_separated_lanes &&
            ctl_ledger.uniform_challenge_sampling &&
            ctl_ledger.bounded_challenge_sampling,
        false,
        "exact represented-bus LogUp bound is "
        "sum_b[4(E_b-1)]^2/|Fp3|^2: each lane charges "
        "3(E_b-1) tuple-compression roots plus the explicit E_b-1 "
        "nonzero rational-numerator roots required by LogUp soundness. "
        "Both complete (gamma,alpha) pairs are transcript-domain-separated "
        "and v3 uses bounded unbiased Fp3 sampling. The recursive reduction "
        "remains incomplete until every all-tile bus and its executed child "
        "AIR proof are consumed by the unified root"});

    out.terms.push_back({
        RCStage3UnifiedSoundnessTermKind::CtlDenominatorPoles,
        ctl_ledger.total_events,
        std::min(
            ctl_ledger.pole_completeness_bits_after_losses,
            ctl_ledger.sampler_exhaustion_bits_after_losses),
        ctl_ledger.manifests_exact &&
            ctl_ledger.pole_completeness_bits_after_losses != 0 &&
            ctl_ledger.sampler_exhaustion_bits_after_losses != 0,
        false,
        "denominator poles make the inverse AIR unsatisfiable and the "
        "bounded unbiased sampler can exhaust; both are honest-completeness "
        "losses, not false-accept soundness. They are recorded diagnostically "
        "while the exact global multi-bus manifest remains unclosed"});

    out.terms.push_back({
        RCStage3UnifiedSoundnessTermKind::HashCollision,
        proof_sites,
        oracle_hybrid.common_commitment_union_floor_bits,
        false,
        false,
        parameters.fri_commitment_scenario ==
                Fri3AlgDualCommitmentScenario::
                    SharedMasterDerivedChildren
            ? "selected shared-master V5 conditionally leaves a 102-bit "
              "AlgHash binding floor after the exact selected-manifest "
              "site union; "
              "the binding/ROM reduction and complete hash invocation "
              "manifest are absent"
            : "duplicated lane-prefixed V5 conditionally leaves a 101-bit "
              "two-lane collision-union floor after the exact "
              "selected-manifest site union; the NIROP/hash reduction and "
              "complete invocation "
              "manifest are absent"});
    out.terms.push_back({
        RCStage3UnifiedSoundnessTermKind::FiatShamirModel,
        0,
        0,
        false,
        false,
        "the complete recursive transcript replay and random-oracle "
        "reduction are absent"});
    out.terms.push_back({
        RCStage3UnifiedSoundnessTermKind::PowGrindingComposition,
        1,
        fri_bits,
        parameters.grinding_bits == kRCFriGrindingBits,
        false,
        "the configured grinding loss is charged in the FRI term, but the "
        "global PoW/Fiat-Shamir composition theorem is absent"});
    out.terms.push_back({
        RCStage3UnifiedSoundnessTermKind::GlobalFalseAcceptUnion,
        0,
        0,
        false,
        false,
        "the smallest individual exponent is not a global theorem. Distinct "
        "FRI, batching, CTL, hash and Fiat-Shamir failure probabilities must "
        "be composed with an explicit additive union, without double-counting "
        "correlated diagnostics. The exact Q128/hash two-event calculator "
        "does this for that pair only; the complete ledger composition is "
        "not implemented"});

    bool complete = true;
    uint32_t provisional = std::numeric_limits<uint32_t>::max();
    for (const auto& term : out.terms) {
        complete &= term.quantitatively_accounted &&
                    term.reduction_complete;
        if (term.quantitatively_accounted &&
            term.conservative_bits != 0) {
            provisional =
                std::min(provisional, term.conservative_bits);
        }
    }
    out.provisional_known_term_bits =
        provisional == std::numeric_limits<uint32_t>::max()
            ? 0
            : provisional;
    out.theorem_complete = complete;
    out.certified_bits =
        complete ? out.provisional_known_term_bits : 0;
    out.authority_eligible =
        out.theorem_complete &&
        out.certified_bits >= parameters.target_soundness_bits &&
        kRCFri3AlgFormalSoundnessReady &&
        kRCStage3UnifiedRootExecutable &&
        kRCStage3UnifiedRootAuthorityReady;
    return out;
}

uint32_t RCStage3UnifiedRootSoundnessBits(
    const RCStage3UnifiedRootParameters& parameters)
{
    if (parameters.fri_queries == 0 ||
        parameters.soundness_union_bound_instances == 0) {
        return 0;
    }
    const uint64_t product =
        static_cast<uint64_t>(parameters.fri_queries) * LOG2_32_17_Q32;
    const uint32_t proximity_bits = static_cast<uint32_t>(product >> 32);
    const uint64_t losses =
        static_cast<uint64_t>(parameters.grinding_bits) +
        CeilLog2(parameters.soundness_union_bound_instances);
    if (losses >= proximity_bits) return 0;
    return proximity_bits - static_cast<uint32_t>(losses);
}

uint256 ComputeRCStage3UnifiedStatementCommitment(
    const RCStage3SuccinctProof& statement)
{
    HashWriter hash;
    hash << STATEMENT_DOMAIN;
    WritePublicStatementContext(hash, statement);
    hash << static_cast<uint32_t>(statement.commitments.size());
    for (const auto& commitment : statement.commitments) {
        hash << static_cast<uint16_t>(commitment.role);
        hash << commitment.root;
    }
    return hash.GetHash();
}

uint256 ComputeRCStage3UnifiedRootSeed(
    const RCStage3UnifiedRootPublicPin& pin)
{
    HashWriter hash;
    hash << ROOT_SEED_DOMAIN;
    hash << pin.magic;
    hash << pin.version;
    hash << pin.registry_version;
    WriteParameters(hash, pin.parameters);
    hash << pin.statement_commitment;
    hash << pin.final_digest;
    hash << static_cast<uint16_t>(pin.roles.size());
    for (const auto& role : pin.roles) {
        hash << static_cast<uint16_t>(role.role);
        hash << role.relation_commitment;
        hash << role.ctl_child_commitment;
    }
    hash << pin.composition_link_commitment;
    hash << pin.ctl_composition_commitment;
    hash << pin.soundness_manifest_commitment;
    hash << pin.production_site_manifest_commitment;
    hash << pin.production_aggregation_schedule_commitment;
    hash << pin.normalized_leaf_tree_commitment;
    return hash.GetHash();
}

uint256 ComputeRCStage3UnifiedRoleLeafCommitment(
    const RCStage3UnifiedRolePin& role)
{
    if (role.relation_commitment.IsNull() ||
        role.ctl_child_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << ROLE_LEAF_DOMAIN;
    hash << static_cast<uint16_t>(role.role);
    hash << role.relation_commitment;
    hash << role.ctl_child_commitment;
    return hash.GetHash();
}

uint256 ComputeRCStage3UnifiedNormalizedLeafTreeCommitment(
    const RCStage3UnifiedRootPublicPin& pin)
{
    if (pin.roles.size() != kRCStage3UnifiedRoleCount ||
        pin.statement_commitment.IsNull() || pin.final_digest.IsNull() ||
        pin.composition_link_commitment.IsNull() ||
        pin.ctl_composition_commitment.IsNull()) {
        return {};
    }

    std::array<uint256, kRCStage3UnifiedNormalizedLeafCount> level{};
    for (size_t i = 0; i < pin.roles.size(); ++i) {
        level[i] = ComputeRCStage3UnifiedRoleLeafCommitment(pin.roles[i]);
        if (level[i].IsNull()) return {};
    }
    {
        HashWriter hash;
        hash << PADDING_LEAF_DOMAIN;
        hash << static_cast<uint16_t>(14);
        hash << pin.composition_link_commitment;
        level[14] = hash.GetHash();
    }
    {
        HashWriter hash;
        hash << PADDING_LEAF_DOMAIN;
        hash << static_cast<uint16_t>(15);
        hash << pin.statement_commitment;
        hash << pin.final_digest;
        hash << pin.ctl_composition_commitment;
        level[15] = hash.GetHash();
    }

    size_t width = level.size();
    uint8_t tree_level = 1;
    while (width > 1) {
        for (size_t i = 0; i < width / 2; ++i) {
            level[i] = TreeNodeCommitment(
                tree_level, static_cast<uint16_t>(i),
                level[2 * i], level[2 * i + 1]);
        }
        width /= 2;
        ++tree_level;
    }
    return level[0];
}

uint256 ComputeRCStage3UnifiedAggregationNodeSeed(
    const uint256& root_seed,
    uint8_t tree_level,
    uint16_t tree_index,
    const uint256& left_child_commitment,
    const uint256& right_child_commitment)
{
    if (root_seed.IsNull() || tree_level == 0 || tree_level > 4 ||
        tree_index >= (uint16_t{1} << (4 - tree_level)) ||
        left_child_commitment.IsNull() ||
        right_child_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << NODE_SEED_DOMAIN;
    hash << root_seed;
    hash << tree_level;
    hash << tree_index;
    hash << left_child_commitment;
    hash << right_child_commitment;
    return hash.GetHash();
}

uint256 CommitRCStage3UnifiedRecursiveProof(
    const std::vector<unsigned char>& recursive_proof)
{
    if (recursive_proof.empty() ||
        recursive_proof.size() > kRCStage3UnifiedRootMaxProofBytes) {
        return {};
    }
    HashWriter hash;
    hash << RECURSIVE_PROOF_DOMAIN;
    hash << static_cast<uint32_t>(recursive_proof.size());
    for (const unsigned char byte : recursive_proof) hash << byte;
    return hash.GetHash();
}

bool ValidateRCStage3UnifiedRootStructure(
    const RCStage3UnifiedRootPublicPin& pin,
    std::string* why)
{
    if (pin.magic != kRCStage3UnifiedRootMagic) {
        return Fail(why, "bad_magic");
    }
    if (pin.version != kRCStage3UnifiedRootVersion) {
        return Fail(why, "bad_version");
    }
    if (pin.registry_version != kRCStage3UnifiedRootRegistryVersion) {
        return Fail(why, "bad_registry_version");
    }
    if (pin.parameters != CanonicalRCStage3UnifiedRootParameters()) {
        return Fail(why, "noncanonical_parameters");
    }
    if (RCStage3UnifiedRootSoundnessBits(pin.parameters) <
        pin.parameters.target_soundness_bits) {
        return Fail(why, "soundness_target_not_met");
    }
    if (pin.statement_commitment.IsNull()) {
        return Fail(why, "null_statement_commitment");
    }
    if (pin.final_digest.IsNull()) return Fail(why, "null_final_digest");
    if (pin.roles.size() != UNIFIED_ROLE_ORDER.size()) {
        return Fail(why, "role_count");
    }
    if (pin.ctl_manifest.transcript_seed != pin.statement_commitment) {
        return Fail(why, "ctl_manifest_statement_binding");
    }
    if (pin.ctl_manifest.participants.size() != UNIFIED_ROLE_ORDER.size() ||
        pin.ctl_children.size() != UNIFIED_ROLE_ORDER.size()) {
        return Fail(why, "ctl_participant_count");
    }
    for (size_t i = 0; i < pin.roles.size(); ++i) {
        const auto& role = pin.roles[i];
        if (role.role != UNIFIED_ROLE_ORDER[i]) {
            return Fail(why, "role_order");
        }
        if (role.relation_commitment.IsNull()) {
            return Fail(why, "null_relation_commitment");
        }
        if (role.ctl_child_commitment.IsNull()) {
            return Fail(why, "null_ctl_child_commitment");
        }
        if (pin.ctl_manifest.participants[i].role != role.role ||
            pin.ctl_children[i].role != role.role) {
            return Fail(why, "ctl_role_order");
        }
        if (role.ctl_child_commitment !=
            CommitRCStage3CtlChildPin(pin.ctl_children[i])) {
            return Fail(why, "ctl_child_commitment_mismatch");
        }
    }
    if (pin.composition_link_commitment.IsNull()) {
        return Fail(why, "null_composition_link_commitment");
    }
    std::string ctl_why;
    if (!VerifyRCStage3CtlPublicPinComposition(
            pin.ctl_manifest, pin.ctl_children, &ctl_why)) {
        return Fail(why, "ctl_composition:" + ctl_why);
    }
    if (pin.ctl_composition_commitment.IsNull() ||
        pin.ctl_composition_commitment !=
            CommitRCStage3CtlComposition(
                pin.ctl_manifest, pin.ctl_children)) {
        return Fail(why, "ctl_composition_commitment_mismatch");
    }
    if (pin.soundness_manifest_commitment !=
        ComputeRCStage3UnifiedSoundnessManifestCommitment() ||
        pin.parameters.soundness_union_bound_instances <
            SOUNDNESS_SITE_MANIFEST.size()) {
        return Fail(why, "soundness_manifest_mismatch");
    }
    const uint256 production_site_manifest =
        ComputeRCStage3UnifiedProductionSiteManifestCommitment();
    if (production_site_manifest.IsNull() ||
        pin.production_site_manifest_commitment !=
            production_site_manifest) {
        return Fail(why, "production_site_manifest_mismatch");
    }
    const auto selected_production_manifest =
        soundness_scenarios::BuildProductionProofSiteManifest(
            soundness_scenarios::
                SelectedProductionProofSitePolicy());
    if (selected_production_manifest.commitment.IsNull() ||
        selected_production_manifest.union_bound_cap >
            std::numeric_limits<uint32_t>::max() ||
        pin.parameters.soundness_union_bound_instances !=
            selected_production_manifest.union_bound_cap) {
        return Fail(why, "production_site_union_cap_mismatch");
    }
    const uint256 production_aggregation_schedule =
        ComputeRCStage3UnifiedProductionAggregationScheduleCommitment();
    if (production_aggregation_schedule.IsNull() ||
        pin.production_aggregation_schedule_commitment !=
            production_aggregation_schedule) {
        return Fail(
            why, "production_aggregation_schedule_mismatch");
    }
    for (const auto& site : SOUNDNESS_SITE_MANIFEST) {
        if (site.fri_queries != pin.parameters.fri_queries) {
            return Fail(why, "soundness_query_mismatch");
        }
    }
    if (pin.normalized_leaf_tree_commitment.IsNull() ||
        pin.normalized_leaf_tree_commitment !=
            ComputeRCStage3UnifiedNormalizedLeafTreeCommitment(pin)) {
        return Fail(why, "normalized_leaf_tree_mismatch");
    }
    if (pin.normalized_recursive_root_commitment.IsNull()) {
        return Fail(why, "null_recursive_root_commitment");
    }
    if (pin.recursive_proof.empty()) return Fail(why, "empty_recursive_proof");
    if (pin.recursive_proof.size() > kRCStage3UnifiedRootMaxProofBytes) {
        return Fail(why, "recursive_proof_oversize");
    }
    if (pin.normalized_recursive_root_commitment !=
        CommitRCStage3UnifiedRecursiveProof(pin.recursive_proof)) {
        return Fail(why, "recursive_proof_commitment_mismatch");
    }
    return true;
}

bool ValidateRCStage3UnifiedRootPublicBinding(
    const RCStage3SuccinctProof& statement,
    const RCStage3UnifiedRootPublicPin& pin,
    std::string* why)
{
    if (!ValidateRCStage3UnifiedRootStructure(pin, why)) return false;
    if (statement.statement != RCStage3StatementKind::Composed) {
        return Fail(why, "statement_not_composed");
    }
    std::string statement_why;
    if (!ValidateRCStage3ProofStructure(statement, &statement_why)) {
        return Fail(why, "invalid_statement:" + statement_why);
    }
    if (!VerifyRCStage3CompositionLink(statement, &statement_why)) {
        return Fail(why, "invalid_composition:" + statement_why);
    }
    const uint256 expected_final = ComputeRCStage3FinalDigest(statement);
    if (expected_final.IsNull() ||
        statement.public_inputs.final_digest != expected_final) {
        return Fail(why, "invalid_statement_final_digest");
    }
    if (pin.final_digest != expected_final) {
        return Fail(why, "final_digest_mismatch");
    }
    if (pin.statement_commitment !=
        ComputeRCStage3UnifiedStatementCommitment(statement)) {
        return Fail(why, "statement_commitment_mismatch");
    }
    return ValidateStatementCommitmentRegistry(statement, pin, why);
}

bool SerializeRCStage3UnifiedRootPublicPin(
    const RCStage3UnifiedRootPublicPin& pin,
    std::vector<unsigned char>& out,
    std::string* why)
{
    out.clear();
    if (!ValidateRCStage3UnifiedRootStructure(pin, why)) return false;
    if (pin.recursive_proof.size() >
        std::numeric_limits<uint32_t>::max()) {
        return Fail(why, "recursive_proof_length_overflow");
    }

    Writer writer;
    writer.U32(pin.magic);
    writer.U16(pin.version);
    writer.U16(pin.registry_version);
    WriteParameters(writer, pin.parameters);
    writer.Uint256(pin.statement_commitment);
    writer.Uint256(pin.final_digest);
    writer.U16(static_cast<uint16_t>(pin.roles.size()));
    for (const auto& role : pin.roles) {
        writer.U16(static_cast<uint16_t>(role.role));
        writer.Uint256(role.relation_commitment);
        writer.Uint256(role.ctl_child_commitment);
    }
    writer.Uint256(pin.composition_link_commitment);
    WriteCtlManifest(writer, pin.ctl_manifest);
    writer.U16(static_cast<uint16_t>(pin.ctl_children.size()));
    for (const auto& child : pin.ctl_children) {
        std::vector<unsigned char> encoded_child;
        if (!SerializeRCStage3CtlChildPin(child, encoded_child, why) ||
            encoded_child.size() > std::numeric_limits<uint16_t>::max()) {
            out.clear();
            return Fail(why, "ctl_child_serialize");
        }
        writer.U16(static_cast<uint16_t>(encoded_child.size()));
        writer.Bytes(encoded_child);
    }
    writer.Uint256(pin.ctl_composition_commitment);
    writer.Uint256(pin.soundness_manifest_commitment);
    writer.Uint256(pin.production_site_manifest_commitment);
    writer.Uint256(
        pin.production_aggregation_schedule_commitment);
    writer.Uint256(pin.normalized_leaf_tree_commitment);
    writer.Uint256(pin.normalized_recursive_root_commitment);
    writer.U32(static_cast<uint32_t>(pin.recursive_proof.size()));
    writer.Bytes(pin.recursive_proof);
    out = writer.Take();
    if (out.size() > kRCStage3UnifiedRootMaxProofBytes) {
        out.clear();
        return Fail(why, "serialized_oversize");
    }
    return true;
}

std::optional<RCStage3UnifiedRootPublicPin>
DeserializeRCStage3UnifiedRootPublicPin(
    const std::vector<unsigned char>& bytes,
    std::string* why)
{
    if (bytes.empty()) {
        Fail(why, "empty");
        return std::nullopt;
    }
    if (bytes.size() > kRCStage3UnifiedRootMaxProofBytes) {
        Fail(why, "serialized_oversize");
        return std::nullopt;
    }

    Reader reader(bytes);
    RCStage3UnifiedRootPublicPin pin;
    uint16_t role_count{0};
    if (!reader.U32(pin.magic) || !reader.U16(pin.version) ||
        !reader.U16(pin.registry_version) ||
        !ReadParameters(reader, pin.parameters) ||
        !reader.Uint256(pin.statement_commitment) ||
        !reader.Uint256(pin.final_digest) ||
        !reader.U16(role_count)) {
        Fail(why, "truncated_header");
        return std::nullopt;
    }
    if (role_count != kRCStage3UnifiedRoleCount ||
        role_count > reader.Remaining() / 66) {
        Fail(why, "bad_role_count");
        return std::nullopt;
    }
    pin.roles.resize(role_count);
    for (auto& role : pin.roles) {
        uint16_t raw_role{0};
        if (!reader.U16(raw_role) ||
            !reader.Uint256(role.relation_commitment) ||
            !reader.Uint256(role.ctl_child_commitment)) {
            Fail(why, "truncated_role");
            return std::nullopt;
        }
        role.role = static_cast<RCStage3RelationRole>(raw_role);
    }
    uint32_t proof_size{0};
    uint16_t ctl_child_count{0};
    if (!reader.Uint256(pin.composition_link_commitment) ||
        !ReadCtlManifest(reader, pin.ctl_manifest) ||
        !reader.U16(ctl_child_count) ||
        ctl_child_count != kRCStage3UnifiedRoleCount) {
        Fail(why, "truncated_ctl_header");
        return std::nullopt;
    }
    pin.ctl_children.resize(ctl_child_count);
    for (auto& child : pin.ctl_children) {
        uint16_t child_size{0};
        std::vector<unsigned char> encoded_child;
        if (!reader.U16(child_size) || child_size == 0 ||
            !reader.Bytes(child_size, encoded_child)) {
            Fail(why, "truncated_ctl_child");
            return std::nullopt;
        }
        const auto decoded_child =
            DeserializeRCStage3CtlChildPin(encoded_child, why);
        if (!decoded_child.has_value()) {
            Fail(why, "bad_ctl_child");
            return std::nullopt;
        }
        child = *decoded_child;
    }
    if (!reader.Uint256(pin.ctl_composition_commitment) ||
        !reader.Uint256(pin.soundness_manifest_commitment) ||
        !reader.Uint256(pin.production_site_manifest_commitment) ||
        !reader.Uint256(
            pin.production_aggregation_schedule_commitment) ||
        !reader.Uint256(pin.normalized_leaf_tree_commitment) ||
        !reader.Uint256(pin.normalized_recursive_root_commitment) ||
        !reader.U32(proof_size)) {
        Fail(why, "truncated_footer");
        return std::nullopt;
    }
    if (proof_size == 0 ||
        proof_size > kRCStage3UnifiedRootMaxProofBytes ||
        proof_size != reader.Remaining() ||
        !reader.Bytes(proof_size, pin.recursive_proof)) {
        Fail(why, "bad_recursive_proof_size");
        return std::nullopt;
    }
    if (reader.Remaining() != 0) {
        Fail(why, "trailing_bytes");
        return std::nullopt;
    }
    if (!ValidateRCStage3UnifiedRootStructure(pin, why)) {
        return std::nullopt;
    }
    return pin;
}

bool VerifyRCStage3UnifiedCtlProofBundle(
    const RCStage3UnifiedRootPublicPin& pin,
    const RCStage3UnifiedCtlProofBundle& bundle,
    std::string* why)
{
    if (!ValidateRCStage3UnifiedRootStructure(pin, why)) {
        return false;
    }
    if (!ValidateUnifiedCtlBundleShape(bundle, why)) {
        return false;
    }
    if (bundle.root_seed != ComputeRCStage3UnifiedRootSeed(pin)) {
        return Fail(why, "ctl_bundle:root_seed_binding");
    }
    if (bundle.ctl_composition_commitment !=
            pin.ctl_composition_commitment ||
        bundle.ctl_composition_commitment !=
            CommitRCStage3CtlComposition(
                pin.ctl_manifest, pin.ctl_children)) {
        return Fail(why, "ctl_bundle:composition_binding");
    }

    std::vector<RCStage3CtlSchedule> schedules;
    std::vector<RCStage3CtlAirProof> proofs;
    schedules.reserve(bundle.children.size());
    proofs.reserve(bundle.children.size());
    for (size_t i = 0; i < bundle.children.size(); ++i) {
        const auto& child = bundle.children[i];
        if (child.role != pin.ctl_manifest.participants[i].role ||
            child.role != pin.ctl_children[i].role ||
            CommitRCStage3CtlSchedule(child.schedule) !=
                pin.ctl_children[i].schedule_commitment) {
            return Fail(why, "ctl_bundle:manifest_pin_proof_binding");
        }
        std::string export_why;
        if (!VerifyRCStage3CtlRelationExportBinding(
                child.relation_export, pin.ctl_children[i],
                child.schedule, child.proof,
                pin.roles[i].relation_commitment, &export_why)) {
            return Fail(
                why, "ctl_bundle:relation_export:" + export_why);
        }
        schedules.push_back(child.schedule);
        proofs.push_back(child.proof);
    }

    // VerifyRCStage3CtlBusAirProofs performs the per-role native
    // VerifyRCStage3CtlChildAirProof calls in manifest order, then verifies
    // the signed terminal composition exactly once.
    std::string ctl_why;
    if (!VerifyRCStage3CtlBusAirProofs(
            pin.ctl_manifest, pin.ctl_children,
            schedules, proofs, &ctl_why)) {
        return Fail(why, "ctl_bundle:proof:" + ctl_why);
    }
    if (why != nullptr) {
        *why =
            "stage3:unified_root:ctl_bundle_ok_native_recursive_consumption_pending";
    }
    return true;
}

bool SerializeRCStage3UnifiedCtlProofBundle(
    const RCStage3UnifiedCtlProofBundle& bundle,
    std::vector<unsigned char>& out,
    std::string* why)
{
    out.clear();
    if (!ValidateUnifiedCtlBundleShape(bundle, why)) return false;
    // Preflight the schedule-only lower bound before the writer can reserve or
    // append attacker-sized in-memory schedules. Each event has exactly three
    // u32 coordinates plus one multiplicity byte on wire. Proof bytes are
    // charged incrementally below.
    static constexpr size_t HEADER_BYTES =
        sizeof(uint32_t) + 2 * sizeof(uint16_t) + 2 * 32 +
        sizeof(uint16_t);
    static constexpr size_t CHILD_SCHEDULE_HEADER_BYTES =
        sizeof(uint16_t) + kRCStage3CtlRelationExportBytes +
        sizeof(uint32_t);
    static constexpr size_t EVENT_BYTES =
        3 * sizeof(uint32_t) + sizeof(uint8_t);
    size_t minimum_bytes = HEADER_BYTES;
    for (const auto& child : bundle.children) {
        if (minimum_bytes >
            kRCStage3UnifiedCtlBundleMaxBytes -
                CHILD_SCHEDULE_HEADER_BYTES) {
            return Fail(why, "ctl_bundle:encoded_size");
        }
        minimum_bytes += CHILD_SCHEDULE_HEADER_BYTES;
        if (child.schedule.events.size() >
            (kRCStage3UnifiedCtlBundleMaxBytes - minimum_bytes) /
                EVENT_BYTES) {
            return Fail(why, "ctl_bundle:encoded_size");
        }
        minimum_bytes += child.schedule.events.size() * EVENT_BYTES;
    }

    Writer writer;
    writer.U32(bundle.magic);
    writer.U16(bundle.version);
    writer.U16(bundle.registry_version);
    writer.Uint256(bundle.root_seed);
    writer.Uint256(bundle.ctl_composition_commitment);
    writer.U16(static_cast<uint16_t>(bundle.children.size()));
    for (const auto& child : bundle.children) {
        writer.U16(static_cast<uint16_t>(child.role));
        std::vector<unsigned char> relation_export;
        if (!SerializeRCStage3CtlRelationExportPin(
                child.relation_export, relation_export) ||
            relation_export.size() !=
                kRCStage3CtlRelationExportBytes) {
            return Fail(why, "ctl_bundle:relation_export_encode");
        }
        writer.Bytes(relation_export);
        WriteCtlSchedule(writer, child.schedule);
        if (writer.Size() > kRCStage3UnifiedCtlBundleMaxBytes) {
            return Fail(why, "ctl_bundle:encoded_size");
        }
        if (!WriteCtlAirProof(writer, child.proof)) {
            return Fail(why, "ctl_bundle:proof_encode");
        }
        if (writer.Size() > kRCStage3UnifiedCtlBundleMaxBytes) {
            return Fail(why, "ctl_bundle:encoded_size");
        }
    }
    out = writer.Take();
    if (out.size() > kRCStage3UnifiedCtlBundleMaxBytes) {
        out.clear();
        return Fail(why, "ctl_bundle:encoded_size");
    }
    if (why != nullptr) *why = "stage3:unified_root:ctl_bundle_codec_ok";
    return true;
}

std::optional<RCStage3UnifiedCtlProofBundle>
DeserializeRCStage3UnifiedCtlProofBundle(
    const std::vector<unsigned char>& bytes,
    std::string* why)
{
    if (bytes.empty() ||
        bytes.size() > kRCStage3UnifiedCtlBundleMaxBytes) {
        if (why != nullptr) {
            *why = "stage3:unified_root:ctl_bundle:encoded_size";
        }
        return std::nullopt;
    }
    Reader reader(bytes);
    RCStage3UnifiedCtlProofBundle bundle;
    uint16_t child_count{0};
    if (!reader.U32(bundle.magic) ||
        !reader.U16(bundle.version) ||
        !reader.U16(bundle.registry_version) ||
        !reader.Uint256(bundle.root_seed) ||
        !reader.Uint256(bundle.ctl_composition_commitment) ||
        !reader.U16(child_count) ||
        child_count != kRCStage3UnifiedRoleCount) {
        if (why != nullptr) {
            *why = "stage3:unified_root:ctl_bundle:header";
        }
        return std::nullopt;
    }
    bundle.children.resize(child_count);
    for (auto& child : bundle.children) {
        uint16_t role{0};
        std::vector<unsigned char> relation_export_bytes;
        if (!reader.U16(role) ||
            !reader.Bytes(
                kRCStage3CtlRelationExportBytes,
                relation_export_bytes) ||
            !ReadCtlSchedule(reader, child.schedule) ||
            !ReadCtlAirProof(reader, child.proof)) {
            if (why != nullptr) {
                *why = "stage3:unified_root:ctl_bundle:child";
            }
            return std::nullopt;
        }
        child.role = static_cast<RCStage3RelationRole>(role);
        const auto relation_export =
            DeserializeRCStage3CtlRelationExportPin(
                relation_export_bytes);
        if (!relation_export.has_value()) {
            if (why != nullptr) {
                *why =
                    "stage3:unified_root:ctl_bundle:relation_export";
            }
            return std::nullopt;
        }
        child.relation_export = *relation_export;
    }
    if (reader.Remaining() != 0 ||
        !ValidateUnifiedCtlBundleShape(bundle, why)) {
        return std::nullopt;
    }
    std::vector<unsigned char> canonical;
    if (!SerializeRCStage3UnifiedCtlProofBundle(
            bundle, canonical, why) ||
        canonical != bytes) {
        if (why != nullptr) {
            *why = "stage3:unified_root:ctl_bundle:noncanonical";
        }
        return std::nullopt;
    }
    if (why != nullptr) *why = "stage3:unified_root:ctl_bundle_codec_ok";
    return bundle;
}

uint256 CommitRCStage3UnifiedCtlProofBundle(
    const RCStage3UnifiedCtlProofBundle& bundle)
{
    std::vector<unsigned char> encoded;
    if (!SerializeRCStage3UnifiedCtlProofBundle(bundle, encoded)) {
        return {};
    }
    HashWriter hash;
    hash << CTL_PROOF_BUNDLE_DOMAIN;
    hash << encoded;
    return hash.GetHash();
}

bool VerifyRCStage3UnifiedRootProof(
    const RCStage3SuccinctProof& statement,
    const RCStage3UnifiedRootPublicPin& pin,
    std::string* why)
{
    if (!ValidateRCStage3UnifiedRootPublicBinding(statement, pin, why)) {
        return false;
    }
    const RCStage3UnifiedSoundnessLedger ledger =
        AssessRCStage3UnifiedGlobalSoundness(pin);
    if (!ledger.theorem_complete ||
        ledger.certified_bits <
            pin.parameters.target_soundness_bits) {
        return Fail(why, "soundness_theorem_incomplete");
    }
    static_assert(!kRCStage3UnifiedRootExecutable);
    return Fail(why, "recursive_engine_unavailable");
}

} // namespace matmul::v4::rc
