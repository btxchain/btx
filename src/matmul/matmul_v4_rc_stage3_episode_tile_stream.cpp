// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_episode_tile_stream.h>
#include <matmul/matmul_v4_rc_stage3_role_bytecode.h>

#include <hash.h>

#include <algorithm>
#include <limits>

namespace matmul::v4::rc {
namespace {

namespace aq = air_quotient;
namespace gf = gkr_field;
using gf::Fp3;

constexpr char LAYER_ROOT_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_STREAMED_LAYER_OUTPUT_V1";
constexpr char COLLECTION_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_TILE_STREAM_PRODUCT_V1";
constexpr char LEAF_CTL_PIN_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_TILE_STREAM_LEAF_CTL_PIN_V1";
constexpr char LEAF_CTL_TRANSCRIPT_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_TILE_STREAM_LEAF_CTL_TRANSCRIPT_V1";
constexpr char LEAF_CTL_BRIDGE_SEED_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_TILE_STREAM_LEAF_BRIDGE_AIR_V1";
constexpr char LEAF_CTL_PRODUCT_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_TILE_STREAM_LEAF_CTL_PRODUCT_V1";
constexpr char LEAF_CTL_PROOF_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_TILE_STREAM_LEAF_CTL_PROOF_V1";
constexpr char LEAF_CTL_COLLECTION_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_TILE_STREAM_LEAF_CTL_COLLECTION_V1";
constexpr uint32_t LEAF_CTL_NAMESPACE = 0x4553544cU; // "ESTL"
constexpr uint32_t LEAF_CTL_STAGE = 19;
constexpr uint64_t STREAM_ADDRESS_DOMAIN =
    UINT64_C(0x4553000000000000);
constexpr uint64_t STREAM_ADDRESS_ROUND_STRIDE =
    UINT64_C(1) << 40;

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:episode_tile_stream:" + detail;
    }
    return false;
}

bool CheckedAdd(uint64_t a, uint64_t b, uint64_t& out)
{
    if (b > std::numeric_limits<uint64_t>::max() - a) {
        return false;
    }
    out = a + b;
    return true;
}

bool IsEpisodeStatement(const RCStage3SuccinctProof& statement)
{
    return statement.statement == RCStage3StatementKind::Episode ||
           statement.statement == RCStage3StatementKind::Composed;
}

uint64_t StreamAddressBegin(uint32_t round_index)
{
    if (round_index >= (UINT64_C(1) << 12)) return 0;
    return STREAM_ADDRESS_DOMAIN +
           static_cast<uint64_t>(round_index) *
               STREAM_ADDRESS_ROUND_STRIDE;
}

bool ExpectedTileOutputRoot(
    const std::vector<uint8_t>& stream,
    uint64_t byte_begin,
    const RCStage3EpisodeAirPublicPin& pin,
    uint256& out,
    std::string* why)
{
    if (byte_begin > stream.size() ||
        stream.size() - byte_begin < kRCMxBlockLen ||
        pin.n_rows < kRCMxBlockLen ||
        pin.n_coeffs < pin.n_rows) {
        return Fail(why, "tile_output_shape");
    }
    std::vector<Fp3> values(pin.n_rows, Fp3::Zero());
    for (uint32_t i = 0; i < kRCMxBlockLen; ++i) {
        const uint8_t byte = stream[byte_begin + i];
        const int64_t signed_value =
            byte < 128 ? static_cast<int64_t>(byte)
                       : static_cast<int64_t>(byte) - 256;
        values[i] = Fp3::FromFp(gf::FromSigned(signed_value));
    }
    out = aq::AirCommittedValuesRoot<Fp3>(
        values, pin.n_coeffs);
    return !out.IsNull() ||
           Fail(why, "null_tile_output_root");
}

bool BuildExpectedStreamMemoryRoots(
    const std::vector<uint8_t>& stream,
    std::vector<uint256>& roots,
    std::string* why)
{
    roots.clear();
    if (stream.empty()) {
        return Fail(why, "empty_round_stream");
    }
    uint64_t begin = 0;
    while (begin < stream.size()) {
        const uint32_t logical_rows =
            static_cast<uint32_t>(std::min<uint64_t>(
                kRCStage3EpisodeSemanticMaxRows,
                stream.size() - begin));
        std::vector<Fp3> values(logical_rows, Fp3::Zero());
        for (uint32_t i = 0; i < logical_rows; ++i) {
            const uint8_t byte = stream[begin + i];
            const int64_t signed_value =
                byte < 128 ? static_cast<int64_t>(byte)
                           : static_cast<int64_t>(byte) - 256;
            values[i] =
                Fp3::FromFp(gf::FromSigned(signed_value));
        }
        const auto root =
            ComputeRCStage3EpisodeSemanticValueRoot(
                values, logical_rows,
                FriNextPow2(logical_rows), why);
        if (!root.has_value()) return false;
        roots.push_back(*root);
        begin += logical_rows;
    }
    return true;
}

bool TilePinIdentityIsExact(
    const RCStage3EpisodeAirPublicPin& pin,
    const uint256& statement_commitment,
    const uint256& expected_output_root,
    std::string* why)
{
    if (pin.role != RCStage3RelationRole::EpisodeExtract ||
        pin.family !=
            RCStage3EpisodeAirFamily::ExtractSamplerCoreFp3V1 ||
        pin.statement_commitment != statement_commitment ||
        // The outer product supplies the all-tile schedule. Each sampler is
        // an independently seeded singleton, avoiding the registry's 2^20
        // flat-shard cap at production dimensions.
        pin.shard_index != 0 || pin.shard_count != 1 ||
        pin.logical_rows < kRCMxBlockLen ||
        pin.n_rows < kRCMxBlockLen ||
        pin.column_roots.size() != aq::kRcSamplerNumCols ||
        pin.column_roots[aq::kColOut].column != aq::kColOut ||
        pin.column_roots[aq::kColOut].root !=
            expected_output_root ||
        ComputeRCStage3EpisodeAirPinCommitment(pin).IsNull()) {
        return Fail(why, "tile_pin_identity");
    }
    return true;
}

Fp3 U64(uint64_t value)
{
    return Fp3::FromFp(gf::FromU64(value));
}

Fp3 SignedByte(uint8_t byte)
{
    return Fp3::FromFp(gf::FromSigned(
        byte < 128
            ? static_cast<int64_t>(byte)
            : static_cast<int64_t>(byte) - 256));
}

uint256 LeafCtlPinCommitment(
    const RCStage3EpisodeTileStreamLeafCtlPin& pin)
{
    if (pin.version != kRCStage3EpisodeTileStreamLeafCtlVersion ||
        pin.statement_commitment.IsNull() ||
        pin.tile_stream_collection_commitment.IsNull() ||
        pin.tile_tree_manifest_commitment.IsNull() ||
        pin.source_memory_manifest_commitment.IsNull() ||
        pin.logical_rows == 0 ||
        pin.n_rows < pin.logical_rows ||
        (pin.n_rows & (pin.n_rows - 1)) != 0 ||
        pin.value_root.IsNull() ||
        pin.program_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << LEAF_CTL_PIN_DOMAIN;
    hash << pin.version;
    hash << pin.statement_commitment;
    hash << pin.tile_stream_collection_commitment;
    hash << pin.tile_tree_manifest_commitment;
    hash << pin.source_memory_manifest_commitment;
    hash << pin.round_index;
    hash << pin.shard_index;
    hash << pin.value_begin;
    hash << pin.logical_rows;
    hash << pin.n_rows;
    hash << pin.value_root;
    hash << pin.program_commitment;
    return hash.GetHash();
}

bool BuildLeafCtlPin(
    const RCStage3SuccinctProof& statement,
    const RCStage3EpisodeTileStreamProduct& tile_stream,
    uint32_t round_index,
    const RCStage3EpisodeSemanticMemoryShard& source,
    RCStage3EpisodeTileStreamLeafCtlPin& out,
    std::string* why)
{
    out = {};
    if (round_index >= tile_stream.rounds.size()) {
        return Fail(why, "leaf_ctl_pin_round");
    }
    const auto& round = tile_stream.rounds[round_index];
    constraint_bytecode::ProgramTable table;
    if (source.manifest.endpoint !=
            RCStage3RelationEndpoint::EpisodeTileTreeStream ||
        source.manifest.role !=
            RCStage3RelationRole::EpisodeTileTree ||
        source.manifest.logical_rows == 0 ||
        source.manifest.n_rows <
            source.manifest.logical_rows ||
        source.value_begin >
            round.tree.tree_manifest.stream.size() ||
        round.tree.tree_manifest.stream.size() -
                source.value_begin <
            source.manifest.logical_rows ||
        !BuildRCStage3EpisodeTileTreeByteBridgeProgramTable(
            table, why)) {
        return Fail(why, "leaf_ctl_pin_shape");
    }
    out.statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    out.tile_stream_collection_commitment =
        tile_stream.collection_commitment;
    out.tile_tree_manifest_commitment =
        round.tree.tree_manifest.commitment;
    out.source_memory_manifest_commitment =
        source.manifest.manifest_commitment;
    out.round_index = round_index;
    out.shard_index = source.shard_index;
    out.value_begin = source.value_begin;
    out.logical_rows = source.manifest.logical_rows;
    out.n_rows = source.manifest.n_rows;
    out.value_root =
        source.manifest.canonical_value_root;
    out.program_commitment =
        constraint_bytecode::CommitProgramTable(table);
    out.pin_commitment = LeafCtlPinCommitment(out);
    return !out.pin_commitment.IsNull() ||
        Fail(why, "leaf_ctl_pin_commitment");
}

std::vector<uint8_t> LeafCtlBytes(
    const RCStage3EpisodeTileStreamRound& round,
    const RCStage3EpisodeSemanticMemoryShard& source)
{
    const auto begin = static_cast<size_t>(source.value_begin);
    const auto end =
        begin + source.manifest.logical_rows;
    if (begin > round.tree.tree_manifest.stream.size() ||
        end > round.tree.tree_manifest.stream.size()) {
        return {};
    }
    return std::vector<uint8_t>(
        round.tree.tree_manifest.stream.begin() + begin,
        round.tree.tree_manifest.stream.begin() + end);
}

std::vector<Fp3> SignedByteValues(
    const std::vector<uint8_t>& bytes,
    uint32_t n_rows)
{
    std::vector<Fp3> out(n_rows, Fp3::Zero());
    for (size_t i = 0; i < bytes.size(); ++i) {
        out[i] = SignedByte(bytes[i]);
    }
    return out;
}

bool BuildLeafBridgeColumns(
    const RCStage3EpisodeTileStreamLeafCtlPin& pin,
    const std::vector<uint8_t>& bytes,
    const aq::AirConstraintSystem<Fp3>& cs,
    std::vector<std::vector<Fp3>>& out)
{
    if (bytes.size() != pin.logical_rows ||
        cs.n_rows != pin.n_rows ||
        cs.n_columns != kRCStage3EpisodeTileBridgeColumns) {
        return false;
    }
    out.assign(
        cs.n_columns,
        std::vector<Fp3>(cs.n_rows, Fp3::Zero()));
    for (const auto& [column, values] : cs.preprocessed) {
        out[column] = values;
    }
    for (uint32_t row = 0; row < pin.logical_rows; ++row) {
        const uint8_t byte = bytes[row];
        const Fp3 value = SignedByte(byte);
        out[kRCStage3EpisodeTileBridgeValue][row] = value;
        out[kRCStage3EpisodeTileBridgeExport][row] = value;
        out[kRCStage3EpisodeTileBridgeByte][row] = U64(byte);
        out[kRCStage3EpisodeTileBridgeSign][row] =
            U64(byte >> 7);
        for (uint32_t bit = 0; bit < 8; ++bit) {
            out[kRCStage3EpisodeTileBridgeBitBase + bit][row] =
                U64((byte >> bit) & 1U);
        }
    }
    return true;
}

RCStage3CtlSchedule LeafCtlSchedule(
    uint32_t n_rows,
    int8_t multiplicity)
{
    RCStage3CtlSchedule out;
    out.events.reserve(n_rows);
    for (uint32_t row = 0; row < n_rows; ++row) {
        out.events.push_back({
            LEAF_CTL_NAMESPACE,
            LEAF_CTL_STAGE,
            row,
            multiplicity,
        });
    }
    return out;
}

RCStage3CtlParticipantSpec LeafCtlParticipant(
    RCStage3RelationRole role,
    const RCStage3CtlSchedule& schedule,
    bool sends)
{
    RCStage3CtlParticipantSpec out;
    out.role = role;
    out.event_count = schedule.events.size();
    out.send_count = sends ? out.event_count : 0;
    out.receive_count = sends ? 0 : out.event_count;
    out.schedule_commitment =
        CommitRCStage3CtlSchedule(schedule);
    return out;
}

uint256 LeafCtlTranscriptSeed(
    const RCStage3EpisodeTileStreamLeafCtlPin& pin)
{
    if (pin.pin_commitment != LeafCtlPinCommitment(pin)) {
        return {};
    }
    HashWriter hash;
    hash << LEAF_CTL_TRANSCRIPT_DOMAIN;
    hash << pin.pin_commitment;
    return hash.GetHash();
}

uint256 LeafBridgeSeed(
    const RCStage3EpisodeTileStreamLeafCtlPin& pin)
{
    if (pin.pin_commitment != LeafCtlPinCommitment(pin)) {
        return {};
    }
    HashWriter hash;
    hash << LEAF_CTL_BRIDGE_SEED_DOMAIN;
    hash << pin.pin_commitment;
    return hash.GetHash();
}

void HashLeafCtlPath(
    HashWriter& hash,
    const Fri3MerklePath& path)
{
    hash << path.index;
    hash << gf::Canonical(path.leaf.c0);
    hash << gf::Canonical(path.leaf.c1);
    hash << gf::Canonical(path.leaf.c2);
    hash << static_cast<uint32_t>(path.siblings.size());
    for (const auto& sibling : path.siblings) hash << sibling;
}

uint256 CommitLeafCtlProduct(
    const aq::AirQuotientProof<Fp3>& proof)
{
    std::vector<unsigned char> batch;
    if (SerializeFri3BatchProof(proof.batch, batch) == 0) {
        return {};
    }
    HashWriter hash;
    hash << LEAF_CTL_PRODUCT_DOMAIN;
    hash << batch;
    hash << proof.trace_commit;
    hash << static_cast<uint32_t>(
        proof.next_openings.size());
    for (const auto& query : proof.next_openings) {
        hash << static_cast<uint32_t>(query.size());
        for (const auto& path : query) {
            HashLeafCtlPath(hash, path);
        }
    }
    return hash.GetHash();
}

uint256 CommitLeafCtlShardProof(
    const RCStage3EpisodeTileStreamLeafCtlShardProof& proof)
{
    const uint256 composition =
        CommitRCStage3CtlComposition(
            proof.manifest, proof.pins);
    if (proof.bridge_pin.pin_commitment.IsNull() ||
        proof.producer_product_commitment.IsNull() ||
        proof.consumer_product_commitment.IsNull() ||
        composition.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << LEAF_CTL_PROOF_DOMAIN;
    hash << proof.bridge_pin.pin_commitment;
    hash << composition;
    hash << proof.producer_product_commitment;
    hash << proof.consumer_product_commitment;
    return hash.GetHash();
}

uint256 CommitLeafCtlCollection(
    const RCStage3EpisodeTileStreamLeafCtlProof& proof)
{
    if (proof.version !=
            kRCStage3EpisodeTileStreamLeafCtlVersion ||
        proof.statement_commitment.IsNull() ||
        proof.tile_stream_collection_commitment.IsNull() ||
        proof.shards.empty()) {
        return {};
    }
    HashWriter hash;
    hash << LEAF_CTL_COLLECTION_DOMAIN;
    hash << proof.version;
    hash << proof.statement_commitment;
    hash << proof.tile_stream_collection_commitment;
    hash << static_cast<uint32_t>(proof.shards.size());
    for (const auto& shard : proof.shards) {
        if (shard.proof_commitment.IsNull()) return {};
        hash << shard.proof_commitment;
    }
    return hash.GetHash();
}

} // namespace

bool RCStage3EpisodeLayerIsStreamed(RCGkrLayerKind kind)
{
    return kind == RCGkrLayerKind::GemmPhase1SV ||
           kind == RCGkrLayerKind::GemmPhase2Fwd;
}

bool BuildRCStage3EpisodeTileTreeByteBridgeConstraintSystem(
    const RCStage3EpisodeTileStreamLeafCtlPin& pin,
    const std::vector<uint8_t>& bytes,
    aq::AirConstraintSystem<Fp3>& out,
    std::string* why)
{
    out = {};
    constraint_bytecode::ProgramTable table;
    if (pin.pin_commitment != LeafCtlPinCommitment(pin) ||
        bytes.size() != pin.logical_rows ||
        !BuildRCStage3EpisodeTileTreeByteBridgeProgramTable(
            table, why) ||
        constraint_bytecode::CommitProgramTable(table) !=
            pin.program_commitment ||
        !constraint_bytecode::
            BuildAirConstraintSystemFromProgramTable(
                table, pin.n_rows, out, why)) {
        return Fail(why, "leaf_bridge_constraint_shape");
    }
    const std::vector<Fp3> values =
        SignedByteValues(bytes, pin.n_rows);
    if (aq::AirCommittedValuesRoot<Fp3>(
            values, pin.n_rows) != pin.value_root) {
        out = {};
        return Fail(why, "leaf_bridge_value_root");
    }
    std::vector<Fp3> active(
        pin.n_rows, Fp3::Zero());
    std::vector<Fp3> address(
        pin.n_rows, Fp3::Zero());
    std::vector<Fp3> expected(
        pin.n_rows, Fp3::Zero());
    for (uint32_t row = 0; row < pin.logical_rows; ++row) {
        active[row] = Fp3::One();
        address[row] = U64(pin.value_begin + row);
        expected[row] = SignedByte(bytes[row]);
    }
    out.preprocessed.emplace_back(
        kRCStage3EpisodeTileBridgeActive,
        std::move(active));
    out.preprocessed.emplace_back(
        kRCStage3EpisodeTileBridgeAddress,
        std::move(address));
    out.preprocessed.emplace_back(
        kRCStage3EpisodeTileBridgeExpected,
        std::move(expected));
    return true;
}

bool ProveRCStage3EpisodeTileStreamLeafCtl(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeTileStreamProduct& tile_stream,
    RCStage3EpisodeTileStreamLeafCtlProof& out,
    std::string* why)
{
    out = {};
    if (!VerifyRCStage3EpisodeTileStreamProduct(
            statement, manifest, tile_stream, why)) {
        return Fail(why, "leaf_ctl_prove_source_product");
    }
    out.statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    out.tile_stream_collection_commitment =
        tile_stream.collection_commitment;
    size_t shard_count = 0;
    for (const auto& round : tile_stream.rounds) {
        shard_count += round.stream_memory.shards.size();
    }
    if (shard_count == 0 ||
        shard_count > kRCStage3CtlMaxEvents) {
        return Fail(why, "leaf_ctl_prove_shard_count");
    }
    out.shards.reserve(shard_count);
    for (uint32_t round_index = 0;
         round_index < tile_stream.rounds.size();
         ++round_index) {
        const auto& round = tile_stream.rounds[round_index];
        for (const auto& source :
             round.stream_memory.shards) {
            RCStage3EpisodeTileStreamLeafCtlShardProof proof;
            if (!BuildLeafCtlPin(
                    statement, tile_stream,
                    round_index, source,
                    proof.bridge_pin, why)) {
                return Fail(why, "leaf_ctl_prove_pin");
            }
            const std::vector<uint8_t> bytes =
                LeafCtlBytes(round, source);
            const std::vector<Fp3> bus_values =
                SignedByteValues(
                    bytes, proof.bridge_pin.n_rows);
            aq::AirConstraintSystem<Fp3> producer_cs;
            aq::AirConstraintSystem<Fp3> consumer_cs;
            std::vector<std::vector<Fp3>> producer_columns;
            std::vector<std::vector<Fp3>> consumer_columns;
            if (bytes.size() !=
                    proof.bridge_pin.logical_rows ||
                !BuildRCStage3EpisodeSemanticMemoryConstraintSystem(
                    source.manifest, producer_cs, why) ||
                !BuildRCStage3EpisodeSemanticMemoryWitness(
                    source.manifest,
                    std::vector<Fp3>(
                        bus_values.begin(),
                        bus_values.begin() +
                            proof.bridge_pin.logical_rows),
                    producer_columns, why) ||
                !BuildRCStage3EpisodeTileTreeByteBridgeConstraintSystem(
                    proof.bridge_pin, bytes,
                    consumer_cs, why) ||
                !BuildLeafBridgeColumns(
                    proof.bridge_pin, bytes,
                    consumer_cs, consumer_columns)) {
                return Fail(
                    why, "leaf_ctl_prove_relation_columns");
            }

            proof.producer_schedule =
                LeafCtlSchedule(
                    proof.bridge_pin.n_rows, 1);
            proof.consumer_schedule =
                LeafCtlSchedule(
                    proof.bridge_pin.n_rows, -1);
            proof.manifest.bus_id =
                kRCStage3EpisodeTileStreamLeafCtlBusId;
            proof.manifest.transcript_seed =
                LeafCtlTranscriptSeed(
                    proof.bridge_pin);
            proof.manifest.participants = {
                LeafCtlParticipant(
                    RCStage3RelationRole::EpisodeTileTree,
                    proof.producer_schedule, true),
                LeafCtlParticipant(
                    RCStage3RelationRole::CompositionLink,
                    proof.consumer_schedule, false),
            };
            proof.pins.resize(2);
            for (size_t index = 0;
                 index < proof.pins.size(); ++index) {
                const auto& participant =
                    proof.manifest.participants[index];
                auto& pin = proof.pins[index];
                pin.role = participant.role;
                pin.bus_id = proof.manifest.bus_id;
                pin.event_count =
                    participant.event_count;
                pin.send_count =
                    participant.send_count;
                pin.receive_count =
                    participant.receive_count;
                pin.schedule_commitment =
                    participant.schedule_commitment;
            }
            proof.pins[0].trace_commitment =
                ComputeRCStage3CtlDegree2PrechallengeTraceCommitment(
                    proof.producer_schedule, bus_values);
            proof.pins[1].trace_commitment =
                ComputeRCStage3CtlDegree2PrechallengeTraceCommitment(
                    proof.consumer_schedule, bus_values);
            RCStage3CtlChallenges challenges;
            if (proof.pins[0].trace_commitment.IsNull() ||
                proof.pins[1].trace_commitment.IsNull() ||
                !DeriveRCStage3CtlChallenges(
                    proof.manifest, proof.pins,
                    challenges, why)) {
                return Fail(
                    why, "leaf_ctl_prove_challenges");
            }
            const auto producer_ctl =
                BuildRCStage3CtlDegree2Witness(
                    proof.producer_schedule,
                    bus_values, challenges);
            const auto consumer_ctl =
                BuildRCStage3CtlDegree2Witness(
                    proof.consumer_schedule,
                    bus_values, challenges);
            if (!producer_ctl.ok || !consumer_ctl.ok) {
                return Fail(
                    why, "leaf_ctl_prove_ctl_witness");
            }
            const uint256 challenge_commitment =
                CommitRCStage3CtlChallenges(challenges);
            for (auto& pin : proof.pins) {
                pin.challenge_commitment =
                    challenge_commitment;
            }
            proof.pins[0].terminal =
                producer_ctl.terminal;
            proof.pins[1].terminal =
                consumer_ctl.terminal;

            aq::AirConstraintSystem<Fp3>
                producer_product_cs;
            aq::AirConstraintSystem<Fp3>
                consumer_product_cs;
            RCStage3RelationCtlDegree2DirectAliasLayout
                producer_layout;
            RCStage3RelationCtlDegree2DirectAliasLayout
                consumer_layout;
            if (!BuildRCStage3RelationCtlDegree2DirectAliasConstraintSystem(
                    producer_cs,
                    {kRCStage3CtlDegree2Version,
                     proof.producer_schedule,
                     challenges,
                     producer_ctl.terminal},
                    kRCStage3EpisodeMemoryExport,
                    producer_product_cs,
                    &producer_layout, why) ||
                !BuildRCStage3RelationCtlDegree2DirectAliasConstraintSystem(
                    consumer_cs,
                    {kRCStage3CtlDegree2Version,
                     proof.consumer_schedule,
                     challenges,
                     consumer_ctl.terminal},
                    kRCStage3EpisodeTileBridgeExport,
                    consumer_product_cs,
                    &consumer_layout, why)) {
                return false;
            }
            std::vector<std::vector<Fp3>>
                producer_product_columns;
            std::vector<std::vector<Fp3>>
                consumer_product_columns;
            if (!BuildRCStage3RelationCtlDegree2DirectAliasWitness(
                    producer_layout,
                    producer_columns, producer_ctl,
                    producer_product_columns, why) ||
                !BuildRCStage3RelationCtlDegree2DirectAliasWitness(
                    consumer_layout,
                    consumer_columns, consumer_ctl,
                    consumer_product_columns, why)) {
                return false;
            }
            const uint256 producer_seed =
                ComputeRCStage3RelationCtlDirectAliasSeed(
                    RCStage3RelationEndpoint::
                        EpisodeTileTreeStream,
                    ComputeRCStage3EpisodeSemanticMemorySeed(
                        source.manifest),
                    proof.producer_schedule,
                    challenges,
                    producer_ctl.terminal,
                    kRCStage3EpisodeMemoryExport);
            const uint256 consumer_seed =
                ComputeRCStage3RelationCtlDirectAliasSeed(
                    RCStage3RelationEndpoint::
                        EpisodeTileTreeLeafHash,
                    LeafBridgeSeed(
                        proof.bridge_pin),
                    proof.consumer_schedule,
                    challenges,
                    consumer_ctl.terminal,
                    kRCStage3EpisodeTileBridgeExport);
            const auto producer_proved =
                aq::AirQuotientProve<Fp3>(
                    producer_product_cs,
                    producer_product_columns,
                    producer_seed);
            const auto consumer_proved =
                aq::AirQuotientProve<Fp3>(
                    consumer_product_cs,
                    consumer_product_columns,
                    consumer_seed);
            if (!producer_proved.ok ||
                !producer_proved.division_exact ||
                !consumer_proved.ok ||
                !consumer_proved.division_exact) {
                return Fail(
                    why, "leaf_ctl_prove_products");
            }
            proof.producer_product =
                producer_proved.proof;
            proof.consumer_product =
                consumer_proved.proof;
            proof.producer_product_commitment =
                CommitLeafCtlProduct(
                    proof.producer_product);
            proof.consumer_product_commitment =
                CommitLeafCtlProduct(
                    proof.consumer_product);
            proof.pins[0].auxiliary_commitment =
                proof.producer_product_commitment;
            proof.pins[1].auxiliary_commitment =
                proof.consumer_product_commitment;
            proof.proof_commitment =
                CommitLeafCtlShardProof(proof);
            if (proof.proof_commitment.IsNull() ||
                !VerifyRCStage3CtlPublicPinComposition(
                    proof.manifest, proof.pins, why)) {
                return Fail(
                    why, "leaf_ctl_prove_commitment_or_terminal");
            }
            out.shards.push_back(std::move(proof));
        }
    }
    out.collection_commitment =
        CommitLeafCtlCollection(out);
    if (out.collection_commitment.IsNull()) {
        out = {};
        return Fail(why, "leaf_ctl_prove_collection");
    }
    if (why != nullptr) {
        *why =
            "stage3:episode_tile_stream:endpoint19_memory_export_"
            "equals_endpoint20_leaf_preimage_signed_bytes_via_"
            "same_trace_ctl";
    }
    return true;
}

bool VerifyRCStage3EpisodeTileStreamLeafCtl(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeTileStreamProduct& tile_stream,
    const RCStage3EpisodeTileStreamLeafCtlProof& proof,
    std::string* why)
{
    const uint256 statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    if (proof.version !=
            kRCStage3EpisodeTileStreamLeafCtlVersion ||
        proof.statement_commitment !=
            statement_commitment ||
        proof.tile_stream_collection_commitment !=
            tile_stream.collection_commitment ||
        !VerifyRCStage3EpisodeTileStreamProduct(
            statement, manifest, tile_stream, why)) {
        return Fail(why, "leaf_ctl_verify_source_product");
    }
    size_t proof_index = 0;
    for (uint32_t round_index = 0;
         round_index < tile_stream.rounds.size();
         ++round_index) {
        const auto& round = tile_stream.rounds[round_index];
        for (const auto& source :
             round.stream_memory.shards) {
            if (proof_index >= proof.shards.size()) {
                return Fail(
                    why, "leaf_ctl_verify_shard_omission");
            }
            const auto& actual =
                proof.shards[proof_index++];
            RCStage3EpisodeTileStreamLeafCtlPin expected_pin;
            if (!BuildLeafCtlPin(
                    statement, tile_stream,
                    round_index, source,
                    expected_pin, why) ||
                actual.bridge_pin != expected_pin) {
                return Fail(
                    why, "leaf_ctl_verify_pin");
            }
            const std::vector<uint8_t> bytes =
                LeafCtlBytes(round, source);
            const std::vector<Fp3> bus_values =
                SignedByteValues(
                    bytes, expected_pin.n_rows);
            const RCStage3CtlSchedule producer_schedule =
                LeafCtlSchedule(expected_pin.n_rows, 1);
            const RCStage3CtlSchedule consumer_schedule =
                LeafCtlSchedule(expected_pin.n_rows, -1);
            RCStage3CtlManifest expected_manifest;
            expected_manifest.bus_id =
                kRCStage3EpisodeTileStreamLeafCtlBusId;
            expected_manifest.transcript_seed =
                LeafCtlTranscriptSeed(expected_pin);
            expected_manifest.participants = {
                LeafCtlParticipant(
                    RCStage3RelationRole::EpisodeTileTree,
                    producer_schedule, true),
                LeafCtlParticipant(
                    RCStage3RelationRole::CompositionLink,
                    consumer_schedule, false),
            };
            if (actual.manifest != expected_manifest ||
                actual.producer_schedule !=
                    producer_schedule ||
                actual.consumer_schedule !=
                    consumer_schedule ||
                actual.pins.size() != 2 ||
                actual.pins[0].trace_commitment !=
                    ComputeRCStage3CtlDegree2PrechallengeTraceCommitment(
                        producer_schedule, bus_values) ||
                actual.pins[1].trace_commitment !=
                    ComputeRCStage3CtlDegree2PrechallengeTraceCommitment(
                        consumer_schedule, bus_values)) {
                return Fail(
                    why, "leaf_ctl_verify_manifest_or_r0");
            }
            for (size_t participant_index = 0;
                 participant_index < 2;
                 ++participant_index) {
                const auto& participant =
                    expected_manifest.participants[
                        participant_index];
                const auto& pin =
                    actual.pins[participant_index];
                if (pin.role != participant.role ||
                    pin.bus_id !=
                        expected_manifest.bus_id ||
                    pin.event_count !=
                        participant.event_count ||
                    pin.send_count !=
                        participant.send_count ||
                    pin.receive_count !=
                        participant.receive_count ||
                    pin.schedule_commitment !=
                        participant.schedule_commitment) {
                    return Fail(
                        why, "leaf_ctl_verify_participant");
                }
            }
            RCStage3CtlChallenges challenges;
            if (!DeriveRCStage3CtlChallenges(
                    actual.manifest, actual.pins,
                    challenges, why)) {
                return false;
            }
            const uint256 challenge_commitment =
                CommitRCStage3CtlChallenges(challenges);
            if (actual.pins[0].challenge_commitment !=
                    challenge_commitment ||
                actual.pins[1].challenge_commitment !=
                    challenge_commitment) {
                return Fail(
                    why, "leaf_ctl_verify_challenges");
            }

            aq::AirConstraintSystem<Fp3> producer_cs;
            aq::AirConstraintSystem<Fp3> consumer_cs;
            aq::AirConstraintSystem<Fp3>
                producer_product_cs;
            aq::AirConstraintSystem<Fp3>
                consumer_product_cs;
            RCStage3RelationCtlDegree2DirectAliasLayout
                producer_layout;
            RCStage3RelationCtlDegree2DirectAliasLayout
                consumer_layout;
            if (!BuildRCStage3EpisodeSemanticMemoryConstraintSystem(
                    source.manifest, producer_cs, why) ||
                !BuildRCStage3EpisodeTileTreeByteBridgeConstraintSystem(
                    expected_pin, bytes,
                    consumer_cs, why) ||
                !BuildRCStage3RelationCtlDegree2DirectAliasConstraintSystem(
                    producer_cs,
                    {kRCStage3CtlDegree2Version,
                     producer_schedule,
                     challenges,
                     actual.pins[0].terminal},
                    kRCStage3EpisodeMemoryExport,
                    producer_product_cs,
                    &producer_layout, why) ||
                !BuildRCStage3RelationCtlDegree2DirectAliasConstraintSystem(
                    consumer_cs,
                    {kRCStage3CtlDegree2Version,
                     consumer_schedule,
                     challenges,
                     actual.pins[1].terminal},
                    kRCStage3EpisodeTileBridgeExport,
                    consumer_product_cs,
                    &consumer_layout, why)) {
                return false;
            }
            const auto shape_ok =
                [](const aq::AirQuotientProof<Fp3>& quotient,
                   const aq::AirConstraintSystem<Fp3>& cs) {
                    return quotient.batch.n_coeffs ==
                               cs.n_rows &&
                        quotient.batch.columns.size() ==
                            static_cast<size_t>(
                                cs.n_columns) + 1 &&
                        quotient.batch.column_len.size() ==
                            quotient.batch.columns.size();
                };
            if (!shape_ok(
                    actual.producer_product,
                    producer_product_cs) ||
                !shape_ok(
                    actual.consumer_product,
                    consumer_product_cs) ||
                actual.producer_product.batch.columns[
                    producer_layout.source_column].root !=
                    expected_pin.value_root ||
                actual.producer_product.batch.columns[
                    producer_layout.ctl_value_column].root !=
                    expected_pin.value_root ||
                actual.consumer_product.batch.columns[
                    consumer_layout.source_column].root !=
                    expected_pin.value_root ||
                actual.consumer_product.batch.columns[
                    consumer_layout.ctl_value_column].root !=
                    expected_pin.value_root) {
                return Fail(
                    why, "leaf_ctl_verify_value_roots");
            }
            const auto trace_matches =
                [](const RCStage3CtlSchedule& schedule,
                   const RCStage3CtlChildPin& pin,
                   const aq::AirQuotientProof<Fp3>& product,
                   const RCStage3RelationCtlDegree2DirectAliasLayout&
                       layout) {
                    std::array<uint256, 5> roots{};
                    for (uint32_t column =
                             stage3_ctl_degree2_col::NAMESPACE;
                         column <=
                             stage3_ctl_degree2_col::MULTIPLICITY;
                         ++column) {
                        roots[column] =
                            product.batch.columns[
                                layout.ctl_column_base +
                                column].root;
                    }
                    return pin.trace_commitment ==
                        ComputeRCStage3CtlDegree2PrechallengeTraceCommitmentFromRoots(
                            schedule,
                            product.batch.column_len[
                                layout.ctl_column_base],
                            product.batch.n_coeffs,
                            roots);
                };
            if (!trace_matches(
                    producer_schedule, actual.pins[0],
                    actual.producer_product,
                    producer_layout) ||
                !trace_matches(
                    consumer_schedule, actual.pins[1],
                    actual.consumer_product,
                    consumer_layout)) {
                return Fail(
                    why, "leaf_ctl_verify_trace_roots");
            }
            const uint256 producer_seed =
                ComputeRCStage3RelationCtlDirectAliasSeed(
                    RCStage3RelationEndpoint::
                        EpisodeTileTreeStream,
                    ComputeRCStage3EpisodeSemanticMemorySeed(
                        source.manifest),
                    producer_schedule,
                    challenges,
                    actual.pins[0].terminal,
                    kRCStage3EpisodeMemoryExport);
            const uint256 consumer_seed =
                ComputeRCStage3RelationCtlDirectAliasSeed(
                    RCStage3RelationEndpoint::
                        EpisodeTileTreeLeafHash,
                    LeafBridgeSeed(expected_pin),
                    consumer_schedule,
                    challenges,
                    actual.pins[1].terminal,
                    kRCStage3EpisodeTileBridgeExport);
            std::string air_why;
            if (!aq::AirQuotientVerify<Fp3>(
                    producer_product_cs,
                    actual.producer_product,
                    producer_seed, &air_why)) {
                return Fail(
                    why, "leaf_ctl_verify_producer:" +
                        air_why);
            }
            if (!aq::AirQuotientVerify<Fp3>(
                    consumer_product_cs,
                    actual.consumer_product,
                    consumer_seed, &air_why)) {
                return Fail(
                    why, "leaf_ctl_verify_consumer:" +
                        air_why);
            }
            const uint256 producer_commitment =
                CommitLeafCtlProduct(
                    actual.producer_product);
            const uint256 consumer_commitment =
                CommitLeafCtlProduct(
                    actual.consumer_product);
            if (producer_commitment.IsNull() ||
                consumer_commitment.IsNull() ||
                actual.producer_product_commitment !=
                    producer_commitment ||
                actual.consumer_product_commitment !=
                    consumer_commitment ||
                actual.pins[0].auxiliary_commitment !=
                    producer_commitment ||
                actual.pins[1].auxiliary_commitment !=
                    consumer_commitment ||
                actual.proof_commitment !=
                    CommitLeafCtlShardProof(actual) ||
                !VerifyRCStage3CtlPublicPinComposition(
                    actual.manifest, actual.pins,
                    why)) {
                return Fail(
                    why, "leaf_ctl_verify_commitment_or_terminal");
            }
        }
    }
    if (proof_index != proof.shards.size() ||
        proof.collection_commitment !=
            CommitLeafCtlCollection(proof)) {
        return Fail(
            why, "leaf_ctl_verify_collection");
    }
    if (why != nullptr) {
        *why =
            "stage3:episode_tile_stream:endpoint19_proof_owned_"
            "stream_cells_equal_endpoint20_leaf_preimage_bytes";
    }
    return true;
}

uint256 ComputeRCStage3EpisodeStreamedLayerOutputRoot(
    const RCStage3GemmExtractManifest& manifest,
    uint32_t layer_ordinal,
    const std::vector<uint256>& ordered_tile_output_roots)
{
    if (layer_ordinal >= manifest.layers.size()) return {};
    const auto& layer = manifest.layers[layer_ordinal];
    if (layer.ordinal != layer_ordinal ||
        layer.extract_tile_count == 0 ||
        ordered_tile_output_roots.size() !=
            layer.extract_tile_count) {
        return {};
    }
    HashWriter hash;
    hash << LAYER_ROOT_DOMAIN;
    hash << manifest.statement_commitment;
    hash << layer.ordinal;
    hash << static_cast<uint32_t>(layer.kind);
    hash << layer.round;
    hash << layer.layer;
    hash << layer.m;
    hash << layer.n;
    hash << layer.out_first_column;
    hash << layer.out_chunks;
    hash << layer.extract_tile_begin;
    hash << layer.extract_tile_count;
    for (const auto& root : ordered_tile_output_roots) {
        if (root.IsNull()) return {};
        hash << root;
    }
    return hash.GetHash();
}

uint256 ComputeRCStage3EpisodeTileStreamCollectionCommitment(
    const RCStage3EpisodeTileStreamProduct& product)
{
    if (product.version !=
            kRCStage3EpisodeTileStreamProductVersion ||
        product.statement_commitment.IsNull() ||
        product.gemm_extract_manifest_commitment.IsNull() ||
        product.expected_rounds == 0 ||
        product.expected_stream_tiles == 0 ||
        product.tiles.size() != product.expected_stream_tiles ||
        product.rounds.size() != product.expected_rounds) {
        return {};
    }
    HashWriter hash;
    hash << COLLECTION_DOMAIN;
    hash << product.version;
    hash << product.statement_commitment;
    hash << product.gemm_extract_manifest_commitment;
    hash << product.expected_rounds;
    hash << product.expected_stream_tiles;
    hash << static_cast<uint32_t>(product.tiles.size());
    for (uint32_t i = 0; i < product.tiles.size(); ++i) {
        const auto& tile = product.tiles[i];
        const uint256 pin_commitment =
            ComputeRCStage3EpisodeAirPinCommitment(tile.pin);
        if (tile.global_stream_tile != i ||
            pin_commitment.IsNull()) {
            return {};
        }
        hash << tile.global_stream_tile;
        hash << tile.layer_ordinal;
        hash << tile.layer_tile_index;
        hash << tile.stream_byte_begin;
        hash << pin_commitment;
    }
    hash << static_cast<uint32_t>(product.rounds.size());
    for (uint32_t i = 0; i < product.rounds.size(); ++i) {
        const auto& round = product.rounds[i];
        if (round.round_index != i ||
            round.tree.round_index != i ||
            round.tree.tree_manifest.commitment.IsNull() ||
            round.stream_memory.bundle_commitment.IsNull()) {
            return {};
        }
        hash << round.round_index;
        hash << round.tree.tree_manifest.commitment;
        hash << round.tree.tree_manifest.root;
        hash << round.stream_memory.bundle_commitment;
    }
    return hash.GetHash();
}

bool ValidateRCStage3EpisodeTileStreamSchedule(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeTileStreamProduct& product,
    std::string* why)
{
    const uint256 statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    const uint256 manifest_commitment =
        ComputeRCStage3GemmExtractManifestCommitment(manifest);
    if (!IsEpisodeStatement(statement) ||
        statement_commitment.IsNull() ||
        !ValidateRCStage3GemmExtractManifestBinding(
            statement, manifest, why) ||
        manifest_commitment.IsNull()) {
        return Fail(why, "public_statement_or_manifest");
    }

    uint64_t expected_tiles64 = 0;
    for (const auto& layer : manifest.layers) {
        if (RCStage3EpisodeLayerIsStreamed(layer.kind) &&
            !CheckedAdd(
                expected_tiles64, layer.extract_tile_count,
                expected_tiles64)) {
            return Fail(why, "stream_tile_overflow");
        }
    }
    if (expected_tiles64 == 0 ||
        expected_tiles64 >
            std::numeric_limits<uint32_t>::max() ||
        product.version !=
            kRCStage3EpisodeTileStreamProductVersion ||
        product.statement_commitment != statement_commitment ||
        product.gemm_extract_manifest_commitment !=
            manifest_commitment ||
        product.expected_rounds != manifest.params.rounds ||
        product.expected_stream_tiles != expected_tiles64 ||
        product.tiles.size() != expected_tiles64 ||
        product.rounds.size() != manifest.params.rounds) {
        return Fail(why, "product_shape");
    }

    uint32_t global_tile = 0;
    for (uint32_t round_index = 0;
         round_index < manifest.params.rounds; ++round_index) {
        const auto& round = product.rounds[round_index];
        const auto& tree = round.tree;
        const auto& tree_manifest = tree.tree_manifest;
        if (round.round_index != round_index ||
            tree.round_index != round_index ||
            tree_manifest.t_leaf != manifest.params.T_leaf ||
            tree_manifest.commitment.IsNull() ||
            tree_manifest.root.IsNull() ||
            tree_manifest.hash_nodes.empty() ||
            tree_manifest.hash_nodes.back().digest !=
                tree_manifest.root ||
            tree_manifest.commitment !=
                stage3_hash_air::CommitTileTreeManifest(
                    tree_manifest) ||
            tree.hash_bundle.endpoint !=
                RCStage3RelationEndpoint::EpisodeTileTreeRoot ||
            tree.hash_bundle.statement_commitment !=
                statement_commitment ||
            tree.hash_bundle.manifest_commitment !=
                tree_manifest.commitment ||
            round.stream_memory.endpoint !=
                RCStage3RelationEndpoint::EpisodeTileTreeStream ||
            round.stream_memory.statement_commitment !=
                statement_commitment ||
            round.stream_memory.total_instance_count !=
                tree_manifest.stream.size() ||
            round.stream_memory.address_begin !=
                StreamAddressBegin(round_index) ||
            round.stream_memory.address_stride != 1) {
            return Fail(
                why, "round_" + std::to_string(round_index) +
                         "_identity");
        }

        uint64_t stream_byte = 0;
        bool saw_streamed_layer = false;
        for (uint32_t layer_ordinal = 0;
             layer_ordinal < manifest.layers.size();
             ++layer_ordinal) {
            const auto& layer = manifest.layers[layer_ordinal];
            if (layer.round != round_index ||
                !RCStage3EpisodeLayerIsStreamed(layer.kind)) {
                continue;
            }
            saw_streamed_layer = true;
            std::vector<uint256> layer_output_roots;
            layer_output_roots.reserve(
                static_cast<size_t>(layer.extract_tile_count));
            for (uint64_t layer_tile = 0;
                 layer_tile < layer.extract_tile_count;
                 ++layer_tile) {
                if (global_tile >= product.tiles.size()) {
                    return Fail(why, "tile_omission");
                }
                const auto& tile = product.tiles[global_tile];
                uint256 expected_output_root;
                if (tile.global_stream_tile != global_tile ||
                    tile.layer_ordinal != layer_ordinal ||
                    tile.layer_tile_index != layer_tile ||
                    tile.stream_byte_begin != stream_byte ||
                    !ExpectedTileOutputRoot(
                        tree_manifest.stream, stream_byte,
                        tile.pin, expected_output_root, why) ||
                    !TilePinIdentityIsExact(
                        tile.pin, statement_commitment,
                        expected_output_root, why)) {
                    return Fail(
                        why, "tile_" +
                                 std::to_string(global_tile) +
                                 "_identity_or_output");
                }
                layer_output_roots.push_back(
                    tile.pin.column_roots[aq::kColOut].root);
                stream_byte += kRCMxBlockLen;
                ++global_tile;
            }
            const uint256 layer_root =
                ComputeRCStage3EpisodeStreamedLayerOutputRoot(
                    manifest, layer_ordinal, layer_output_roots);
            if (layer_root.IsNull() ||
                layer.bindings.extract_output_root != layer_root) {
                return Fail(
                    why, "layer_" +
                             std::to_string(layer_ordinal) +
                             "_output_root");
            }
        }
        if (!saw_streamed_layer ||
            stream_byte != tree_manifest.stream.size()) {
            return Fail(
                why, "round_" + std::to_string(round_index) +
                         "_stream_coverage");
        }
    }
    if (global_tile != product.tiles.size()) {
        return Fail(why, "trailing_tiles");
    }
    const uint256 collection =
        ComputeRCStage3EpisodeTileStreamCollectionCommitment(
            product);
    if (collection.IsNull() ||
        product.collection_commitment != collection) {
        return Fail(why, "collection_commitment");
    }
    return true;
}

bool VerifyRCStage3EpisodeTileStreamProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeTileStreamProduct& product,
    std::string* why)
{
    if (!ValidateRCStage3EpisodeTileStreamSchedule(
            statement, manifest, product, why)) {
        return false;
    }

    for (uint32_t i = 0; i < product.tiles.size(); ++i) {
        if (!VerifyRCStage3EpisodeAirShard(
                statement, product.tiles[i].pin,
                product.tiles[i].proof, why)) {
            return Fail(
                why, "tile_" + std::to_string(i) +
                         "_sampler_proof");
        }
    }

    const uint256 statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    for (uint32_t round_index = 0;
         round_index < product.rounds.size(); ++round_index) {
        const auto& round = product.rounds[round_index];
        std::vector<uint256> stream_roots;
        if (!BuildExpectedStreamMemoryRoots(
                round.tree.tree_manifest.stream,
                stream_roots, why) ||
            !VerifyRCStage3EpisodeSemanticMemoryBundle(
                RCStage3RelationEndpoint::EpisodeTileTreeStream,
                statement_commitment,
                round.tree.tree_manifest.stream.size(),
                StreamAddressBegin(round_index), 1,
                stream_roots, round.stream_memory, why)) {
            return Fail(
                why, "round_" + std::to_string(round_index) +
                         "_stream_memory");
        }
        if (!VerifyRCStage3EpisodeTileTreeSemantic(
                statement,
                RCStage3RelationEndpoint::EpisodeTileTreeRoot,
                round.tree.tree_manifest,
                round.tree.hash_bundle,
                round.tree.hash_binding, why)) {
            return Fail(
                why, "round_" + std::to_string(round_index) +
                         "_tile_tree_hash_product");
        }
    }
    if (why != nullptr) {
        *why =
            "stage3:episode_tile_stream:endpoints_19_22_exact_flat_"
            "product_ok;upstream_gemm_inputs_and_recursion_pending";
    }
    return true;
}

RCStage3EpisodeTileStreamAudit
CurrentRCStage3EpisodeTileStreamAudit()
{
    RCStage3EpisodeTileStreamAudit out;
    out.verifier_derived_emission_schedule = true;
    out.every_streamed_extract_shard_executed = true;
    out.extract_out_to_stream_byte_equality = true;
    out.proof_owned_stream_memory_executed = true;
    out.stream_to_leaf_same_trace_ctl_executable = true;
    out.every_leaf_hash_executed = true;
    out.leaf_to_internal_same_trace_ctl_executable = true;
    out.every_internal_hash_executed = true;
    out.internal_to_typed_root_same_trace_ctl_executable = true;
    out.canonical_round_root_derived = true;
    out.endpoints_19_through_22_locally_complete = true;
    out.all_extract_inputs_and_gemm_provenance_complete = false;
    out.recursively_consumed = false;
    out.transitively_complete = false;
    out.remaining =
        "the flat reference product is not recursively consumed, and the "
        "endpoint-14 through endpoint-22 proof-owned dual-lane CTL chain "
        "executes; sampler children still lack complete GEMM-input, ChaCha, scale, "
        "non-streamed Extract provenance, and normalized recursion";
    return out;
}

static_assert(
    kRCStage3EpisodeTileStreamLocalRelationExecutable);
static_assert(
    !kRCStage3EpisodeTileStreamTransitivelyComplete);

} // namespace matmul::v4::rc
