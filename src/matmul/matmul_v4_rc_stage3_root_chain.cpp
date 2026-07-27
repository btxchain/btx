// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_root_chain.h>

#include <hash.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_stage3_role_bytecode.h>

#include <algorithm>
#include <cstring>
#include <limits>
#include <optional>

namespace matmul::v4::rc {
namespace {

namespace aq = air_quotient;
namespace gf = gkr_field;
namespace ha = stage3_hash_air;
namespace hs = stage3_hash_semantic;
using Fp3 = gf::Fp3;
using AirCS = aq::AirConstraintSystem<Fp3>;

constexpr char PIN_DOMAIN[] = "BTX_RC_STAGE3_ROOT_CHAIN_VECTOR_PIN_V1";
constexpr char SEED_DOMAIN[] = "BTX_RC_STAGE3_ROOT_CHAIN_VECTOR_AIR_V1";
constexpr char BARRIER_COLLECTION_DOMAIN[] =
    "BTX_RC_STAGE3_ROOT_CHAIN_BARRIERS_V1";
constexpr char DIGEST_POW_CTL_TRANSCRIPT_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_DIGEST_POW_CTL_TRANSCRIPT_V1";
constexpr char DIGEST_POW_CTL_PRODUCT_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_DIGEST_POW_CTL_PRODUCT_V1";
constexpr char DIGEST_POW_CTL_LANE_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_DIGEST_POW_CTL_LANE_V1";
constexpr char DIGEST_POW_CTL_PROOF_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_DIGEST_POW_CTL_PROOF_V1";
constexpr uint32_t DIGEST_POW_CTL_NAMESPACE = 0x45504447U; // "EPDG"
constexpr uint32_t DIGEST_POW_CTL_DIGEST_STAGE = 24;
constexpr uint32_t DIGEST_POW_CTL_TARGET_STAGE = 25;

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) *why = "stage3:root_chain:" + detail;
    return false;
}

bool IsRootChainEndpoint(RCStage3RelationEndpoint endpoint)
{
    using E = RCStage3RelationEndpoint;
    switch (endpoint) {
    case E::EpisodeDigestRoundRoots:
    case E::EpisodeDigestValue:
    case E::CoupledBarrierInput:
    case E::CoupledBarrierHash:
    case E::CoupledBarrierOutput:
    case E::CoupledDigestBankAndBarriers:
    case E::CoupledDigestHash:
    case E::CoupledDigestValue:
        return true;
    default:
        return false;
    }
}

uint32_t NextPowerOfTwo(uint32_t value)
{
    uint32_t out = 2;
    while (out < value) out <<= 1;
    return out;
}

Fp3 U64(uint64_t value)
{
    return Fp3::FromFp(gf::FromU64(value));
}

uint64_t AddressBegin(RCStage3RelationEndpoint endpoint)
{
    return UINT64_C(0x5243000000000000) |
           (static_cast<uint64_t>(
                static_cast<uint16_t>(endpoint)) << 32);
}

uint256 ValueRoot(const std::vector<uint8_t>& bytes, uint32_t n_rows)
{
    std::vector<Fp3> values(n_rows, Fp3::Zero());
    for (uint32_t i = 0; i < bytes.size(); ++i) {
        values[i] = U64(bytes[i]);
    }
    return aq::AirCommittedValuesRoot<Fp3>(values, n_rows);
}

uint256 PinCommitment(const RCStage3RootChainVectorPin& pin)
{
    HashWriter hash;
    hash << PIN_DOMAIN;
    hash << pin.version;
    hash << static_cast<uint16_t>(pin.endpoint);
    hash << pin.statement_commitment;
    hash << pin.collection_commitment;
    hash << pin.logical_rows;
    hash << pin.n_rows;
    hash << pin.address_begin;
    hash << pin.value_root;
    return hash.GetHash();
}

bool ValidatePin(const RCStage3RootChainVectorPin& pin, std::string* why)
{
    if (pin.version != kRCStage3RootChainVersion ||
        !IsRootChainEndpoint(pin.endpoint) ||
        pin.statement_commitment.IsNull() ||
        pin.collection_commitment.IsNull() ||
        pin.logical_rows == 0 ||
        pin.logical_rows > kRCStage3RootChainMaxVectorBytes ||
        pin.n_rows != NextPowerOfTwo(pin.logical_rows) ||
        pin.n_rows > kRCStage3RootChainMaxVectorBytes ||
        pin.address_begin != AddressBegin(pin.endpoint) ||
        pin.value_root.IsNull() ||
        pin.pin_commitment != PinCommitment(pin)) {
        return Fail(why, "vector_pin");
    }
    return true;
}

uint256 VectorSeed(const RCStage3RootChainVectorPin& pin)
{
    if (!ValidatePin(pin, nullptr)) return {};
    HashWriter hash;
    hash << SEED_DOMAIN;
    hash << pin.pin_commitment;
    return hash.GetHash();
}

std::optional<RCStage3RelationRole> RootChainRole(
    RCStage3RelationEndpoint endpoint)
{
    using E = RCStage3RelationEndpoint;
    switch (endpoint) {
    case E::EpisodeDigestRoundRoots:
    case E::EpisodeDigestValue:
        return RCStage3RelationRole::EpisodeDigest;
    case E::CoupledBarrierInput:
    case E::CoupledBarrierHash:
    case E::CoupledBarrierOutput:
        return RCStage3RelationRole::CoupledBarrier;
    case E::CoupledDigestBankAndBarriers:
    case E::CoupledDigestHash:
    case E::CoupledDigestValue:
        return RCStage3RelationRole::CoupledDigest;
    default:
        return std::nullopt;
    }
}

std::vector<uint8_t> HashBytes(const uint256& value)
{
    return std::vector<uint8_t>(value.begin(), value.end());
}

void AppendHash(std::vector<uint8_t>& out, const uint256& value)
{
    out.insert(out.end(), value.begin(), value.end());
}

std::vector<uint8_t> EpisodeRoundRootBytes(
    const ha::EpisodeDigestManifest& manifest)
{
    std::vector<uint8_t> out;
    out.reserve(manifest.round_roots.size() * 32);
    for (const auto& root : manifest.round_roots) AppendHash(out, root);
    return out;
}

std::vector<uint8_t> BarrierInputBytes(
    const std::vector<RCStage3CoupledBarrierRootChainEntry>& barriers)
{
    size_t count = 0;
    for (const auto& entry : barriers) {
        count += entry.manifest.state_bytes.size();
    }
    std::vector<uint8_t> out;
    out.reserve(count);
    for (const auto& entry : barriers) {
        out.insert(
            out.end(), entry.manifest.state_bytes.begin(),
            entry.manifest.state_bytes.end());
    }
    return out;
}

std::vector<uint8_t> BarrierOutputBytes(
    const std::vector<RCStage3CoupledBarrierRootChainEntry>& barriers)
{
    std::vector<uint8_t> out;
    out.reserve(barriers.size() * 32);
    for (const auto& entry : barriers) {
        AppendHash(out, entry.manifest.direct.digest);
    }
    return out;
}

std::vector<uint8_t> CoupledDigestInputBytes(
    const ha::CoupledDigestManifest& manifest)
{
    std::vector<uint8_t> out;
    out.reserve(32 + manifest.barrier_roots.size() * 32);
    AppendHash(out, manifest.bank_root);
    for (const auto& root : manifest.barrier_roots) AppendHash(out, root);
    return out;
}

uint256 BarrierCollectionCommitmentImpl(
    const std::vector<RCStage3CoupledBarrierRootChainEntry>& barriers)
{
    HashWriter hash;
    hash << BARRIER_COLLECTION_DOMAIN;
    hash << kRCStage3RootChainVersion;
    hash << static_cast<uint32_t>(barriers.size());
    for (uint32_t i = 0; i < barriers.size(); ++i) {
        hash << i;
        hash << barriers[i].manifest.commitment;
    }
    return hash.GetHash();
}

bool IsEpisodeStatement(const RCStage3SuccinctProof& statement)
{
    return statement.statement == RCStage3StatementKind::Episode ||
           statement.statement == RCStage3StatementKind::Composed;
}

bool IsCoupledStatement(const RCStage3SuccinctProof& statement)
{
    return statement.statement == RCStage3StatementKind::Coupled ||
           statement.statement == RCStage3StatementKind::Composed;
}

bool DirectBoundaryStructural(
    const ha::DirectSha256dManifest& direct,
    ha::DirectHashRelation expected_relation,
    std::string* why)
{
    if (direct.relation != expected_relation ||
        direct.preimage.empty() ||
        direct.sha256d.mode != ha::ShaMode::Double ||
        direct.sha256d.preimage != direct.preimage ||
        direct.sha256d.commitment !=
            ha::CommitShaManifest(direct.sha256d) ||
        direct.commitment !=
            ha::CommitDirectSha256dManifest(direct)) {
        return Fail(why, "direct_manifest");
    }
    const uint256 digest{
        Span<const unsigned char>{
            direct.sha256d.digest.data(),
            direct.sha256d.digest.size()}};
    if (direct.digest != digest) {
        return Fail(why, "direct_digest_projection");
    }
    // This adapter checks padding, the two-pass boundary layout, chaining
    // equality and terminal-word projection. It does not execute SHA
    // compression; that is exclusively the provenance AIR's job.
    std::vector<ha::FixedProgramBoundaryInstance> boundaries;
    if (!ha::BuildDirectSha256dManifestBoundaryInstances(
            direct, boundaries, why) ||
        boundaries.empty()) {
        return Fail(why, "direct_boundaries");
    }
    return true;
}

std::vector<Fp3> ByteValues(const uint256& value)
{
    std::vector<Fp3> out(kRCStage3EpisodePowRows);
    for (uint32_t row = 0;
         row < kRCStage3EpisodePowRows; ++row) {
        out[row] = U64(value.data()[row]);
    }
    return out;
}

bool BuildRootChainVectorWitness(
    const RCStage3RootChainVectorPin& pin,
    const std::vector<uint8_t>& values,
    std::vector<std::vector<Fp3>>& out,
    std::string* why)
{
    AirCS cs;
    if (!BuildRCStage3RootChainVectorConstraintSystem(
            pin, values, cs, why)) {
        return false;
    }
    out.assign(
        kRCStage3RootChainColumns,
        std::vector<Fp3>(pin.n_rows, Fp3::Zero()));
    for (const auto& [column, canonical] : cs.preprocessed) {
        out[column] = canonical;
    }
    for (uint32_t row = 0; row < pin.logical_rows; ++row) {
        out[kRCStage3RootChainValue][row] =
            U64(values[row]);
        out[kRCStage3RootChainExport][row] =
            U64(values[row]);
    }
    return true;
}

bool BuildHeaderTargetWitness(
    const RCStage3EpisodeHeaderTargetPin& pin,
    std::vector<std::vector<Fp3>>& out,
    std::string* why)
{
    AirCS cs;
    if (!BuildRCStage3EpisodeHeaderTargetConstraintSystem(
            pin, cs, why)) {
        return false;
    }
    out.assign(
        cs.n_columns,
        std::vector<Fp3>(cs.n_rows, Fp3::Zero()));
    for (const auto& [column, canonical] : cs.preprocessed) {
        out[column] = canonical;
    }
    for (uint32_t row = 0; row < cs.n_rows; ++row) {
        out[kRCStage3EpisodeHeaderTargetByte][row] =
            U64(pin.target.data()[row]);
    }
    return true;
}

RCStage3CtlSchedule DigestPowCtlSchedule(
    uint32_t stage,
    int8_t multiplicity)
{
    RCStage3CtlSchedule out;
    out.events.reserve(kRCStage3EpisodePowRows);
    for (uint32_t row = 0;
         row < kRCStage3EpisodePowRows; ++row) {
        out.events.push_back({
            DIGEST_POW_CTL_NAMESPACE,
            stage,
            row,
            multiplicity,
        });
    }
    return out;
}

RCStage3CtlParticipantSpec DigestPowCtlParticipant(
    RCStage3RelationRole role,
    const RCStage3CtlSchedule& schedule)
{
    RCStage3CtlParticipantSpec out;
    out.role = role;
    out.event_count = schedule.events.size();
    for (const auto& event : schedule.events) {
        if (event.multiplicity == 1) {
            ++out.send_count;
        } else if (event.multiplicity == -1) {
            ++out.receive_count;
        }
    }
    out.schedule_commitment =
        CommitRCStage3CtlSchedule(schedule);
    return out;
}

uint256 DigestPowCtlTranscriptSeed(
    const RCStage3SuccinctProof& statement,
    const RCStage3RootChainVectorPin& digest_pin,
    const RCStage3EpisodeHeaderTargetPin& target_pin,
    const RCStage3EpisodePowPin& pow_pin,
    uint32_t bus_id)
{
    HashWriter hash;
    hash << DIGEST_POW_CTL_TRANSCRIPT_DOMAIN;
    hash << kRCStage3EpisodeDigestPowCtlVersion;
    hash << RCStage3EpisodeStatementCommitment(statement);
    hash << digest_pin.pin_commitment;
    hash << target_pin.pin_commitment;
    hash << pow_pin.pin_commitment;
    hash << bus_id;
    return hash.GetHash();
}

void HashProofPath(
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

uint256 CommitDigestPowCtlProduct(
    const aq::AirQuotientProof<Fp3>& proof)
{
    std::vector<unsigned char> batch;
    if (SerializeFri3BatchProof(proof.batch, batch) == 0) {
        return {};
    }
    HashWriter hash;
    hash << DIGEST_POW_CTL_PRODUCT_DOMAIN;
    hash << batch;
    hash << proof.trace_commit;
    hash << static_cast<uint32_t>(
        proof.next_openings.size());
    for (const auto& query : proof.next_openings) {
        hash << static_cast<uint32_t>(query.size());
        for (const auto& path : query) {
            HashProofPath(hash, path);
        }
    }
    return hash.GetHash();
}

uint256 CommitDigestPowCtlLane(
    const RCStage3EpisodeDigestPowCtlLaneProof& lane)
{
    const uint256 composition =
        CommitRCStage3CtlComposition(
            lane.manifest, lane.pins);
    if (composition.IsNull() ||
        lane.producer_product_commitment.IsNull() ||
        lane.consumer_product_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << DIGEST_POW_CTL_LANE_DOMAIN;
    hash << lane.manifest.bus_id;
    hash << composition;
    hash << lane.producer_product_commitment;
    hash << lane.consumer_product_commitment;
    return hash.GetHash();
}

uint256 CommitDigestPowCtlProof(
    const RCStage3EpisodeDigestPowCtlProof& proof)
{
    if (proof.version !=
            kRCStage3EpisodeDigestPowCtlVersion ||
        proof.pow_pin.pin_commitment.IsNull() ||
        proof.digest_lane.lane_commitment.IsNull() ||
        proof.target_lane.lane_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << DIGEST_POW_CTL_PROOF_DOMAIN;
    hash << proof.version;
    hash << proof.pow_pin.pin_commitment;
    hash << proof.digest_lane.lane_commitment;
    hash << proof.target_lane.lane_commitment;
    return hash.GetHash();
}

bool BuildDigestPowCtlLane(
    const RCStage3SuccinctProof& statement,
    const RCStage3RootChainVectorPin& digest_pin,
    const RCStage3EpisodeHeaderTargetPin& target_pin,
    const RCStage3EpisodePowPin& pow_pin,
    RCStage3RelationEndpoint producer_endpoint,
    uint32_t bus_id,
    uint32_t stage,
    const AirCS& producer_cs,
    const std::vector<std::vector<Fp3>>& producer_columns,
    uint32_t producer_source_column,
    const uint256& producer_seed,
    const std::vector<Fp3>& values,
    const AirCS& consumer_cs,
    const std::vector<std::vector<Fp3>>& consumer_columns,
    uint32_t consumer_source_column,
    RCStage3EpisodeDigestPowCtlLaneProof& out,
    std::string* why)
{
    out = {};
    if (producer_cs.n_rows != kRCStage3EpisodePowRows ||
        consumer_cs.n_rows != kRCStage3EpisodePowRows ||
        producer_source_column >= producer_cs.n_columns ||
        consumer_source_column >= consumer_cs.n_columns ||
        producer_columns.size() != producer_cs.n_columns ||
        consumer_columns.size() != consumer_cs.n_columns ||
        values.size() != kRCStage3EpisodePowRows ||
        producer_seed.IsNull()) {
        return Fail(why, "digest_pow_ctl:lane_shape");
    }
    out.producer_schedule =
        DigestPowCtlSchedule(stage, 1);
    out.consumer_schedule =
        DigestPowCtlSchedule(stage, -1);
    out.manifest.bus_id = bus_id;
    out.manifest.transcript_seed =
        DigestPowCtlTranscriptSeed(
            statement, digest_pin, target_pin,
            pow_pin, bus_id);
    out.manifest.participants = {
        DigestPowCtlParticipant(
            RCStage3RelationRole::EpisodeDigest,
            out.producer_schedule),
        DigestPowCtlParticipant(
            RCStage3RelationRole::CompositionLink,
            out.consumer_schedule),
    };

    out.pins.resize(2);
    for (size_t index = 0; index < out.pins.size(); ++index) {
        const auto& participant =
            out.manifest.participants[index];
        auto& pin = out.pins[index];
        pin.role = participant.role;
        pin.bus_id = out.manifest.bus_id;
        pin.event_count = participant.event_count;
        pin.send_count = participant.send_count;
        pin.receive_count = participant.receive_count;
        pin.schedule_commitment =
            participant.schedule_commitment;
    }
    out.pins[0].trace_commitment =
        ComputeRCStage3CtlDegree2PrechallengeTraceCommitment(
            out.producer_schedule, values);
    out.pins[1].trace_commitment =
        ComputeRCStage3CtlDegree2PrechallengeTraceCommitment(
            out.consumer_schedule, values);
    RCStage3CtlChallenges challenges;
    if (out.pins[0].trace_commitment.IsNull() ||
        out.pins[1].trace_commitment.IsNull() ||
        !DeriveRCStage3CtlChallenges(
            out.manifest, out.pins, challenges, why)) {
        return Fail(why, "digest_pow_ctl:lane_challenges");
    }
    const auto producer_ctl =
        BuildRCStage3CtlDegree2Witness(
            out.producer_schedule, values, challenges);
    const auto consumer_ctl =
        BuildRCStage3CtlDegree2Witness(
            out.consumer_schedule, values, challenges);
    if (!producer_ctl.ok || !consumer_ctl.ok) {
        return Fail(why, "digest_pow_ctl:lane_ctl_witness");
    }
    const uint256 challenge_commitment =
        CommitRCStage3CtlChallenges(challenges);
    out.pins[0].challenge_commitment =
        challenge_commitment;
    out.pins[1].challenge_commitment =
        challenge_commitment;
    out.pins[0].terminal = producer_ctl.terminal;
    out.pins[1].terminal = consumer_ctl.terminal;

    AirCS producer_product_cs;
    AirCS consumer_product_cs;
    RCStage3RelationCtlDegree2DirectAliasLayout producer_layout;
    RCStage3RelationCtlDegree2DirectAliasLayout consumer_layout;
    if (!BuildRCStage3RelationCtlDegree2DirectAliasConstraintSystem(
            producer_cs,
            {kRCStage3CtlDegree2Version,
             out.producer_schedule,
             challenges,
             producer_ctl.terminal},
            producer_source_column,
            producer_product_cs,
            &producer_layout, why) ||
        !BuildRCStage3RelationCtlDegree2DirectAliasConstraintSystem(
            consumer_cs,
            {kRCStage3CtlDegree2Version,
             out.consumer_schedule,
             challenges,
             consumer_ctl.terminal},
            consumer_source_column,
            consumer_product_cs,
            &consumer_layout, why)) {
        return false;
    }
    std::vector<std::vector<Fp3>> producer_product_columns;
    std::vector<std::vector<Fp3>> consumer_product_columns;
    if (!BuildRCStage3RelationCtlDegree2DirectAliasWitness(
            producer_layout, producer_columns, producer_ctl,
            producer_product_columns, why) ||
        !BuildRCStage3RelationCtlDegree2DirectAliasWitness(
            consumer_layout, consumer_columns, consumer_ctl,
            consumer_product_columns, why)) {
        return false;
    }
    const uint256 producer_product_seed =
        ComputeRCStage3RelationCtlDirectAliasSeed(
            producer_endpoint, producer_seed,
            out.producer_schedule, challenges,
            producer_ctl.terminal,
            producer_source_column);
    const uint256 consumer_product_seed =
        ComputeRCStage3RelationCtlDirectAliasSeed(
            RCStage3RelationEndpoint::EpisodeDigestPow,
            ComputeRCStage3EpisodePowSeed(pow_pin),
            out.consumer_schedule, challenges,
            consumer_ctl.terminal,
            consumer_source_column);
    const auto producer_proved =
        aq::AirQuotientProve<Fp3>(
            producer_product_cs,
            producer_product_columns,
            producer_product_seed);
    const auto consumer_proved =
        aq::AirQuotientProve<Fp3>(
            consumer_product_cs,
            consumer_product_columns,
            consumer_product_seed);
    if (!producer_proved.ok ||
        !producer_proved.division_exact ||
        !consumer_proved.ok ||
        !consumer_proved.division_exact) {
        return Fail(
            why, "digest_pow_ctl:lane_product_prove");
    }
    out.producer_product = producer_proved.proof;
    out.consumer_product = consumer_proved.proof;
    out.producer_product_commitment =
        CommitDigestPowCtlProduct(out.producer_product);
    out.consumer_product_commitment =
        CommitDigestPowCtlProduct(out.consumer_product);
    out.pins[0].auxiliary_commitment =
        out.producer_product_commitment;
    out.pins[1].auxiliary_commitment =
        out.consumer_product_commitment;
    out.lane_commitment =
        CommitDigestPowCtlLane(out);
    if (out.lane_commitment.IsNull() ||
        !VerifyRCStage3CtlPublicPinComposition(
            out.manifest, out.pins, why)) {
        return Fail(why, "digest_pow_ctl:lane_composition");
    }
    return true;
}

} // namespace

uint256 ComputeRCStage3RootChainBarrierCollectionCommitment(
    const std::vector<RCStage3CoupledBarrierRootChainEntry>& barriers)
{
    if (barriers.empty()) return {};
    return BarrierCollectionCommitmentImpl(barriers);
}

bool BuildRCStage3RootChainVectorPin(
    RCStage3RelationEndpoint endpoint,
    const uint256& statement_commitment,
    const uint256& collection_commitment,
    const std::vector<uint8_t>& values,
    RCStage3RootChainVectorPin& out,
    std::string* why)
{
    out = {};
    if (!IsRootChainEndpoint(endpoint) ||
        statement_commitment.IsNull() ||
        collection_commitment.IsNull() ||
        values.empty() ||
        values.size() > kRCStage3RootChainMaxVectorBytes) {
        return Fail(why, "vector_builder_shape");
    }
    out.endpoint = endpoint;
    out.statement_commitment = statement_commitment;
    out.collection_commitment = collection_commitment;
    out.logical_rows = static_cast<uint32_t>(values.size());
    out.n_rows = NextPowerOfTwo(out.logical_rows);
    out.address_begin = AddressBegin(endpoint);
    out.value_root = ValueRoot(values, out.n_rows);
    out.pin_commitment = PinCommitment(out);
    return ValidatePin(out, why);
}

bool BuildRCStage3RootChainVectorConstraintSystem(
    const RCStage3RootChainVectorPin& pin,
    const std::vector<uint8_t>& expected_values,
    AirCS& out,
    std::string* why)
{
    if (!ValidatePin(pin, why) ||
        expected_values.size() != pin.logical_rows ||
        ValueRoot(expected_values, pin.n_rows) != pin.value_root) {
        return Fail(why, "vector_constraint_public_values");
    }
    out = {};
    const auto role = RootChainRole(pin.endpoint);
    constraint_bytecode::ProgramTable table;
    if (!role.has_value() ||
        !BuildRCStage3RootChainVectorProgramTable(
            *role, table, why) ||
        table.current_width !=
            kRCStage3RootChainColumns ||
        !constraint_bytecode::
            BuildAirConstraintSystemFromProgramTable(
                table, pin.n_rows, out, why)) {
        return Fail(why, "vector_constraint_bytecode");
    }
    std::vector<Fp3> active(pin.n_rows, Fp3::Zero());
    std::vector<Fp3> address(pin.n_rows, Fp3::Zero());
    std::vector<Fp3> expected(pin.n_rows, Fp3::Zero());
    for (uint32_t row = 0; row < pin.logical_rows; ++row) {
        active[row] = Fp3::One();
        address[row] = U64(pin.address_begin + row);
        expected[row] = U64(expected_values[row]);
    }
    out.preprocessed.emplace_back(
        kRCStage3RootChainActive, std::move(active));
    out.preprocessed.emplace_back(
        kRCStage3RootChainAddress, std::move(address));
    out.preprocessed.emplace_back(
        kRCStage3RootChainExpected, std::move(expected));

    return true;
}

uint256 ComputeRCStage3RootChainVectorSeed(
    const RCStage3RootChainVectorPin& pin)
{
    return VectorSeed(pin);
}

bool ProveRCStage3RootChainVector(
    const RCStage3RootChainVectorPin& pin,
    const std::vector<uint8_t>& values,
    RCStage3RootChainVectorProof& out,
    std::string* why)
{
    out = {};
    AirCS cs;
    if (!BuildRCStage3RootChainVectorConstraintSystem(
            pin, values, cs, why)) {
        return false;
    }
    std::vector<std::vector<Fp3>> columns(
        kRCStage3RootChainColumns,
        std::vector<Fp3>(pin.n_rows, Fp3::Zero()));
    for (const auto& [column, canonical] : cs.preprocessed) {
        columns[column] = canonical;
    }
    for (uint32_t row = 0; row < pin.logical_rows; ++row) {
        const Fp3 value = U64(values[row]);
        columns[kRCStage3RootChainValue][row] = value;
        columns[kRCStage3RootChainExport][row] = value;
    }
    const auto proved = aq::AirQuotientProve<Fp3>(
        cs, columns, VectorSeed(pin));
    if (!proved.ok || !proved.division_exact) {
        return Fail(why, "vector_prove:" + proved.note);
    }
    out.version = kRCStage3RootChainVersion;
    out.pin_commitment = pin.pin_commitment;
    out.quotient = proved.proof;
    return true;
}

bool VerifyRCStage3RootChainVector(
    RCStage3RelationEndpoint endpoint,
    const uint256& statement_commitment,
    const uint256& collection_commitment,
    const std::vector<uint8_t>& expected_values,
    const RCStage3RootChainVectorPin& pin,
    const RCStage3RootChainVectorProof& proof,
    std::string* why)
{
    RCStage3RootChainVectorPin expected;
    if (!BuildRCStage3RootChainVectorPin(
            endpoint, statement_commitment, collection_commitment,
            expected_values, expected, why) ||
        pin != expected ||
        proof.version != kRCStage3RootChainVersion ||
        proof.pin_commitment != pin.pin_commitment) {
        return Fail(why, "vector_public_binding");
    }
    AirCS cs;
    if (!BuildRCStage3RootChainVectorConstraintSystem(
            pin, expected_values, cs, why)) {
        return false;
    }
    std::string air_why;
    if (!aq::AirQuotientVerify<Fp3>(
            cs, proof.quotient, VectorSeed(pin), &air_why)) {
        return Fail(why, "vector_verify:" + air_why);
    }
    return true;
}

bool ValidateRCStage3EpisodeDigestManifestStructural(
    const ha::EpisodeDigestManifest& manifest,
    uint32_t expected_rounds,
    std::string* why)
{
    if (expected_rounds == 0 ||
        manifest.expected_rounds != expected_rounds ||
        manifest.round_roots.size() != expected_rounds ||
        manifest.commitment !=
            ha::CommitEpisodeDigestManifest(manifest) ||
        manifest.direct.relation !=
            ha::DirectHashRelation::EpisodeDigest) {
        return Fail(why, "episode_manifest_shape");
    }
    std::vector<uint8_t> preimage;
    preimage.insert(
        preimage.end(),
        reinterpret_cast<const uint8_t*>(kRCEpisodeTag),
        reinterpret_cast<const uint8_t*>(kRCEpisodeTag) +
            sizeof(kRCEpisodeTag) - 1);
    for (const auto& root : manifest.round_roots) {
        if (root.IsNull()) return Fail(why, "episode_null_round_root");
        AppendHash(preimage, root);
    }
    if (manifest.direct.preimage != preimage ||
        !DirectBoundaryStructural(
            manifest.direct,
            ha::DirectHashRelation::EpisodeDigest, why)) {
        return Fail(why, "episode_typed_preimage");
    }
    return true;
}

bool ValidateRCStage3CoupledBarrierManifestStructural(
    const RCStage3CoupledShape& shape,
    uint32_t expected_barrier,
    const ha::CoupledBarrierManifest& manifest,
    std::string* why)
{
    if (shape.barriers == 0 ||
        expected_barrier >= shape.barriers ||
        manifest.transcript_version != shape.transcript_version ||
        manifest.expected_barriers != shape.barriers ||
        manifest.barrier_index != expected_barrier ||
        manifest.state_bytes.empty() ||
        manifest.commitment !=
            ha::CommitCoupledBarrierManifest(manifest)) {
        return Fail(why, "barrier_manifest_shape");
    }
    const auto& tags =
        RCCoupDomainTagsForVersion(manifest.transcript_version);
    std::vector<uint8_t> preimage;
    const size_t tag_size = std::strlen(tags.barrier);
    preimage.insert(
        preimage.end(),
        reinterpret_cast<const uint8_t*>(tags.barrier),
        reinterpret_cast<const uint8_t*>(tags.barrier) + tag_size);
    for (uint32_t shift = 0; shift < 32; shift += 8) {
        preimage.push_back(
            static_cast<uint8_t>(manifest.barrier_index >> shift));
    }
    preimage.insert(
        preimage.end(), manifest.state_bytes.begin(),
        manifest.state_bytes.end());
    if (manifest.direct.preimage != preimage ||
        !DirectBoundaryStructural(
            manifest.direct,
            ha::DirectHashRelation::CoupledBarrier, why)) {
        return Fail(why, "barrier_typed_preimage");
    }
    return true;
}

bool ValidateRCStage3CoupledDigestManifestStructural(
    const RCStage3CoupledShape& shape,
    const ha::CoupledDigestManifest& manifest,
    std::string* why)
{
    if (shape.barriers == 0 ||
        manifest.transcript_version != shape.transcript_version ||
        manifest.expected_barriers != shape.barriers ||
        manifest.barrier_roots.size() != shape.barriers ||
        manifest.bank_root.IsNull() ||
        manifest.commitment !=
            ha::CommitCoupledDigestManifest(manifest)) {
        return Fail(why, "coupled_digest_manifest_shape");
    }
    const auto& tags =
        RCCoupDomainTagsForVersion(manifest.transcript_version);
    std::vector<uint8_t> preimage;
    const size_t tag_size = std::strlen(tags.episode);
    preimage.insert(
        preimage.end(),
        reinterpret_cast<const uint8_t*>(tags.episode),
        reinterpret_cast<const uint8_t*>(tags.episode) + tag_size);
    AppendHash(preimage, manifest.bank_root);
    for (const auto& root : manifest.barrier_roots) {
        if (root.IsNull()) {
            return Fail(why, "coupled_digest_null_barrier");
        }
        AppendHash(preimage, root);
    }
    if (manifest.direct.preimage != preimage ||
        !DirectBoundaryStructural(
            manifest.direct,
            ha::DirectHashRelation::CoupledDigest, why)) {
        return Fail(why, "coupled_digest_typed_preimage");
    }
    return true;
}

bool VerifyRCStage3EpisodeDigestRootChain(
    const RCStage3SuccinctProof& statement,
    uint32_t expected_rounds,
    const RCStage3EpisodeDigestRootChainProof& proof,
    std::string* why)
{
    if (!IsEpisodeStatement(statement) ||
        !ValidateRCStage3EpisodeDigestManifestStructural(
            proof.manifest, expected_rounds, why) ||
        proof.manifest.direct.digest !=
            statement.public_inputs.episode_digest) {
        return Fail(why, "episode_outer_statement");
    }
    const uint256 statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    const std::vector<uint8_t> roots =
        EpisodeRoundRootBytes(proof.manifest);
    if (!VerifyRCStage3RootChainVector(
            RCStage3RelationEndpoint::EpisodeDigestRoundRoots,
            statement_commitment, proof.manifest.commitment, roots,
            proof.round_roots_pin, proof.round_roots_proof, why)) {
        return false;
    }
    if (!VerifyRCStage3EpisodeDirectSha256dSemantic(
            statement,
            RCStage3RelationEndpoint::EpisodeDigestValue,
            proof.manifest.direct, proof.hash_bundle,
            proof.hash_binding, why)) {
        return Fail(why, "episode_hash_provenance");
    }
    const std::vector<uint8_t> digest =
        HashBytes(proof.manifest.direct.digest);
    if (!VerifyRCStage3RootChainVector(
            RCStage3RelationEndpoint::EpisodeDigestValue,
            statement_commitment, proof.manifest.commitment, digest,
            proof.digest_pin, proof.digest_proof, why)) {
        return false;
    }
    if (why != nullptr) {
        *why =
            "stage3:root_chain:episode_digest_local_chain_ok_"
            "round_root_producer_link_pending";
    }
    return true;
}

bool ProveRCStage3EpisodeDigestRootChain(
    const RCStage3SuccinctProof& statement,
    uint32_t expected_rounds,
    const std::vector<uint256>& round_roots,
    RCStage3EpisodeDigestRootChainProof& out,
    std::string* why)
{
    out = {};
    if (!IsEpisodeStatement(statement) ||
        !ha::BuildEpisodeDigestManifest(
            expected_rounds, round_roots, out.manifest, why) ||
        out.manifest.direct.digest !=
            statement.public_inputs.episode_digest) {
        out = {};
        return Fail(why, "episode_prove_manifest_or_outer_digest");
    }
    const uint256 statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    const std::vector<uint8_t> roots =
        EpisodeRoundRootBytes(out.manifest);
    if (!BuildRCStage3RootChainVectorPin(
            RCStage3RelationEndpoint::EpisodeDigestRoundRoots,
            statement_commitment, out.manifest.commitment, roots,
            out.round_roots_pin, why) ||
        !ProveRCStage3RootChainVector(
            out.round_roots_pin, roots,
            out.round_roots_proof, why)) {
        out = {};
        return Fail(why, "episode_prove_round_roots");
    }
    std::vector<ha::FixedProgramBoundaryInstance> boundaries;
    if (!ha::BuildDirectSha256dManifestBoundaryInstances(
            out.manifest.direct, boundaries, why)) {
        out = {};
        return Fail(why, "episode_prove_hash_boundaries");
    }
    const auto sha_program =
        ha::BuildCanonicalProgram(ha::ProgramKind::Sha256Compression);
    if (!hs::ProveFlatBoundaryProofBundle(
            RCStage3RelationEndpoint::EpisodeDigestValue,
            statement_commitment, out.manifest.direct.commitment,
            sha_program, boundaries, out.hash_bundle, why) ||
        !ProveRCStage3EpisodeHashSemanticBinding(
            statement, RCStage3RelationEndpoint::EpisodeDigestValue,
            boundaries, hs::BoundaryPort::ExternalThenFinal,
            out.hash_binding, why)) {
        out = {};
        return Fail(why, "episode_prove_hash");
    }
    const std::vector<uint8_t> digest =
        HashBytes(out.manifest.direct.digest);
    if (!BuildRCStage3RootChainVectorPin(
            RCStage3RelationEndpoint::EpisodeDigestValue,
            statement_commitment, out.manifest.commitment, digest,
            out.digest_pin, why) ||
        !ProveRCStage3RootChainVector(
            out.digest_pin, digest, out.digest_proof, why) ||
        !VerifyRCStage3EpisodeDigestRootChain(
            statement, expected_rounds, out, why)) {
        out = {};
        return Fail(why, "episode_prove_digest");
    }
    return true;
}

namespace {

bool VerifyDigestPowCtlLane(
    const RCStage3SuccinctProof& statement,
    const RCStage3RootChainVectorPin& digest_pin,
    const RCStage3EpisodeHeaderTargetPin& target_pin,
    const RCStage3EpisodePowPin& pow_pin,
    RCStage3RelationEndpoint producer_endpoint,
    uint32_t bus_id,
    uint32_t stage,
    const AirCS& producer_cs,
    uint32_t producer_source_column,
    const uint256& producer_seed,
    const AirCS& consumer_cs,
    uint32_t consumer_source_column,
    const std::vector<Fp3>& values,
    const uint256& expected_value_root,
    const RCStage3EpisodeDigestPowCtlLaneProof& lane,
    std::string* why)
{
    const RCStage3CtlSchedule producer_schedule =
        DigestPowCtlSchedule(stage, 1);
    const RCStage3CtlSchedule consumer_schedule =
        DigestPowCtlSchedule(stage, -1);
    RCStage3CtlManifest manifest;
    manifest.bus_id = bus_id;
    manifest.transcript_seed =
        DigestPowCtlTranscriptSeed(
            statement, digest_pin, target_pin,
            pow_pin, bus_id);
    manifest.participants = {
        DigestPowCtlParticipant(
            RCStage3RelationRole::EpisodeDigest,
            producer_schedule),
        DigestPowCtlParticipant(
            RCStage3RelationRole::CompositionLink,
            consumer_schedule),
    };
    if (lane.manifest != manifest ||
        lane.producer_schedule != producer_schedule ||
        lane.consumer_schedule != consumer_schedule ||
        lane.pins.size() != 2 ||
        expected_value_root.IsNull() ||
        producer_seed.IsNull()) {
        return Fail(why, "digest_pow_ctl:verify_lane_manifest");
    }
    for (size_t index = 0; index < lane.pins.size(); ++index) {
        const auto& pin = lane.pins[index];
        const auto& participant =
            lane.manifest.participants[index];
        if (pin.role != participant.role ||
            pin.bus_id != lane.manifest.bus_id ||
            pin.event_count != participant.event_count ||
            pin.send_count != participant.send_count ||
            pin.receive_count != participant.receive_count ||
            pin.schedule_commitment !=
                participant.schedule_commitment) {
            return Fail(
                why, "digest_pow_ctl:verify_lane_participant");
        }
    }
    if (lane.pins[0].trace_commitment !=
            ComputeRCStage3CtlDegree2PrechallengeTraceCommitment(
                producer_schedule, values) ||
        lane.pins[1].trace_commitment !=
            ComputeRCStage3CtlDegree2PrechallengeTraceCommitment(
                consumer_schedule, values)) {
        return Fail(
            why, "digest_pow_ctl:verify_lane_prechallenge");
    }
    RCStage3CtlChallenges challenges;
    if (!DeriveRCStage3CtlChallenges(
            lane.manifest, lane.pins,
            challenges, why)) {
        return false;
    }
    const uint256 challenge_commitment =
        CommitRCStage3CtlChallenges(challenges);
    if (lane.pins[0].challenge_commitment !=
            challenge_commitment ||
        lane.pins[1].challenge_commitment !=
            challenge_commitment) {
        return Fail(
            why, "digest_pow_ctl:verify_lane_challenge");
    }

    AirCS producer_product_cs;
    AirCS consumer_product_cs;
    RCStage3RelationCtlDegree2DirectAliasLayout producer_layout;
    RCStage3RelationCtlDegree2DirectAliasLayout consumer_layout;
    if (!BuildRCStage3RelationCtlDegree2DirectAliasConstraintSystem(
            producer_cs,
            {kRCStage3CtlDegree2Version,
             producer_schedule,
             challenges,
             lane.pins[0].terminal},
            producer_source_column,
            producer_product_cs,
            &producer_layout, why) ||
        !BuildRCStage3RelationCtlDegree2DirectAliasConstraintSystem(
            consumer_cs,
            {kRCStage3CtlDegree2Version,
             consumer_schedule,
             challenges,
             lane.pins[1].terminal},
            consumer_source_column,
            consumer_product_cs,
            &consumer_layout, why)) {
        return false;
    }
    const auto proof_shape_ok =
        [](const aq::AirQuotientProof<Fp3>& proof,
           const AirCS& cs) {
            if (proof.batch.n_coeffs != cs.n_rows ||
                proof.batch.columns.size() !=
                    static_cast<size_t>(cs.n_columns) + 1 ||
                proof.batch.column_len.size() !=
                    proof.batch.columns.size()) {
                return false;
            }
            return std::all_of(
                proof.batch.column_len.begin(),
                proof.batch.column_len.end(),
                [&](uint32_t length) {
                    return length <= cs.n_rows;
                });
        };
    if (!proof_shape_ok(
            lane.producer_product,
            producer_product_cs) ||
        !proof_shape_ok(
            lane.consumer_product,
            consumer_product_cs) ||
        lane.producer_product.batch.columns[
            producer_layout.source_column].root !=
            expected_value_root ||
        lane.consumer_product.batch.columns[
            consumer_layout.source_column].root !=
            expected_value_root ||
        lane.producer_product.batch.columns[
            producer_layout.ctl_value_column].root !=
            expected_value_root ||
        lane.consumer_product.batch.columns[
            consumer_layout.ctl_value_column].root !=
            expected_value_root) {
        return Fail(
            why, "digest_pow_ctl:verify_lane_value_root");
    }

    const auto trace_matches =
        [](const RCStage3CtlSchedule& schedule,
           const RCStage3CtlChildPin& pin,
           const aq::AirQuotientProof<Fp3>& proof,
           const RCStage3RelationCtlDegree2DirectAliasLayout& layout) {
            std::array<uint256, 5> roots{};
            for (uint32_t column =
                     stage3_ctl_degree2_col::NAMESPACE;
                 column <=
                     stage3_ctl_degree2_col::MULTIPLICITY;
                 ++column) {
                roots[column] =
                    proof.batch.columns[
                        layout.ctl_column_base + column].root;
            }
            return pin.trace_commitment ==
                ComputeRCStage3CtlDegree2PrechallengeTraceCommitmentFromRoots(
                    schedule,
                    proof.batch.column_len[
                        layout.ctl_column_base],
                    proof.batch.n_coeffs,
                    roots);
        };
    if (!trace_matches(
            producer_schedule, lane.pins[0],
            lane.producer_product, producer_layout) ||
        !trace_matches(
            consumer_schedule, lane.pins[1],
            lane.consumer_product, consumer_layout)) {
        return Fail(
            why, "digest_pow_ctl:verify_lane_trace_roots");
    }
    const uint256 producer_product_seed =
        ComputeRCStage3RelationCtlDirectAliasSeed(
            producer_endpoint, producer_seed,
            producer_schedule, challenges,
            lane.pins[0].terminal,
            producer_source_column);
    const uint256 consumer_product_seed =
        ComputeRCStage3RelationCtlDirectAliasSeed(
            RCStage3RelationEndpoint::EpisodeDigestPow,
            ComputeRCStage3EpisodePowSeed(pow_pin),
            consumer_schedule, challenges,
            lane.pins[1].terminal,
            consumer_source_column);
    std::string air_why;
    if (!aq::AirQuotientVerify<Fp3>(
            producer_product_cs,
            lane.producer_product,
            producer_product_seed, &air_why)) {
        return Fail(
            why, "digest_pow_ctl:verify_lane_producer:" +
                air_why);
    }
    if (!aq::AirQuotientVerify<Fp3>(
            consumer_product_cs,
            lane.consumer_product,
            consumer_product_seed, &air_why)) {
        return Fail(
            why, "digest_pow_ctl:verify_lane_consumer:" +
                air_why);
    }
    const uint256 producer_commitment =
        CommitDigestPowCtlProduct(
            lane.producer_product);
    const uint256 consumer_commitment =
        CommitDigestPowCtlProduct(
            lane.consumer_product);
    if (producer_commitment.IsNull() ||
        consumer_commitment.IsNull() ||
        lane.producer_product_commitment !=
            producer_commitment ||
        lane.consumer_product_commitment !=
            consumer_commitment ||
        lane.pins[0].auxiliary_commitment !=
            producer_commitment ||
        lane.pins[1].auxiliary_commitment !=
            consumer_commitment ||
        lane.lane_commitment !=
            CommitDigestPowCtlLane(lane) ||
        !VerifyRCStage3CtlPublicPinComposition(
            lane.manifest, lane.pins, why)) {
        return Fail(
            why, "digest_pow_ctl:verify_lane_commitment_or_terminal");
    }
    return true;
}

} // namespace

bool ProveRCStage3EpisodeDigestPowCtl(
    const RCStage3SuccinctProof& statement,
    uint32_t expected_rounds,
    const RCStage3EpisodeDigestRootChainProof& digest_chain,
    const RCStage3EpisodeHeaderTargetProduct& header_target,
    RCStage3EpisodeDigestPowCtlProof& out,
    std::string* why)
{
    out = {};
    if (!VerifyRCStage3EpisodeDigestRootChain(
            statement, expected_rounds,
            digest_chain, why) ||
        !VerifyRCStage3EpisodeHeaderTargetProduct(
            statement,
            statement.public_inputs.header_commitment,
            statement.public_inputs.n_bits,
            statement.public_inputs.target,
            header_target, why)) {
        return Fail(
            why, "digest_pow_ctl:source_relations");
    }
    const auto pow_pin =
        BuildRCStage3EpisodePowPin(statement, why);
    if (!pow_pin.has_value() ||
        digest_chain.digest_pin.logical_rows !=
            kRCStage3EpisodePowRows ||
        digest_chain.digest_pin.n_rows !=
            kRCStage3EpisodePowRows) {
        return Fail(why, "digest_pow_ctl:public_pins");
    }
    out.pow_pin = *pow_pin;

    const std::vector<uint8_t> digest_bytes =
        HashBytes(statement.public_inputs.episode_digest);
    const std::vector<Fp3> digest_values =
        ByteValues(statement.public_inputs.episode_digest);
    const std::vector<Fp3> target_values =
        ByteValues(statement.public_inputs.target);

    AirCS digest_cs;
    AirCS target_cs;
    AirCS pow_cs;
    std::vector<std::vector<Fp3>> digest_columns;
    std::vector<std::vector<Fp3>> target_columns;
    std::vector<std::vector<Fp3>> pow_columns;
    if (!BuildRCStage3RootChainVectorConstraintSystem(
            digest_chain.digest_pin,
            digest_bytes, digest_cs, why) ||
        !BuildRootChainVectorWitness(
            digest_chain.digest_pin,
            digest_bytes, digest_columns, why) ||
        !BuildRCStage3EpisodeHeaderTargetConstraintSystem(
            header_target.pin, target_cs, why) ||
        !BuildHeaderTargetWitness(
            header_target.pin, target_columns, why) ||
        !BuildRCStage3EpisodePowConstraintSystem(
            out.pow_pin, pow_cs, why) ||
        !BuildRCStage3EpisodePowWitness(
            out.pow_pin, pow_columns, why)) {
        return Fail(
            why, "digest_pow_ctl:relation_witnesses");
    }

    if (!BuildDigestPowCtlLane(
            statement,
            digest_chain.digest_pin,
            header_target.pin,
            out.pow_pin,
            RCStage3RelationEndpoint::EpisodeDigestValue,
            kRCStage3EpisodeDigestPowCtlBusId,
            DIGEST_POW_CTL_DIGEST_STAGE,
            digest_cs, digest_columns,
            kRCStage3RootChainValue,
            VectorSeed(digest_chain.digest_pin),
            digest_values,
            pow_cs, pow_columns,
            kRCStage3EpisodePowDigestByte,
            out.digest_lane, why) ||
        !BuildDigestPowCtlLane(
            statement,
            digest_chain.digest_pin,
            header_target.pin,
            out.pow_pin,
            RCStage3RelationEndpoint::
                EpisodeDigestHeaderTarget,
            kRCStage3EpisodeDigestPowCtlBusId + 1,
            DIGEST_POW_CTL_TARGET_STAGE,
            target_cs, target_columns,
            kRCStage3EpisodeHeaderTargetByte,
            ComputeRCStage3EpisodeHeaderTargetSeed(
                header_target.pin),
            target_values,
            pow_cs, pow_columns,
            kRCStage3EpisodePowTargetByte,
            out.target_lane, why)) {
        out = {};
        return Fail(
            why, "digest_pow_ctl:lane_prove");
    }
    out.version =
        kRCStage3EpisodeDigestPowCtlVersion;
    out.proof_commitment =
        CommitDigestPowCtlProof(out);
    if (out.proof_commitment.IsNull()) {
        out = {};
        return Fail(
            why, "digest_pow_ctl:proof_commitment");
    }
    if (why != nullptr) {
        *why =
            "stage3:root_chain:"
            "endpoint24_digest_and_endpoint25_target_"
            "equal_endpoint26_pow_columns_via_dual_lane_ctl";
    }
    return true;
}

bool VerifyRCStage3EpisodeDigestPowCtl(
    const RCStage3SuccinctProof& statement,
    uint32_t expected_rounds,
    const RCStage3EpisodeDigestRootChainProof& digest_chain,
    const RCStage3EpisodeHeaderTargetProduct& header_target,
    const RCStage3EpisodeDigestPowCtlProof& proof,
    std::string* why)
{
    if (proof.version !=
            kRCStage3EpisodeDigestPowCtlVersion ||
        !VerifyRCStage3EpisodeDigestRootChain(
            statement, expected_rounds,
            digest_chain, why) ||
        !VerifyRCStage3EpisodeHeaderTargetProduct(
            statement,
            statement.public_inputs.header_commitment,
            statement.public_inputs.n_bits,
            statement.public_inputs.target,
            header_target, why)) {
        return Fail(
            why, "digest_pow_ctl:verify_source_relations");
    }
    const auto expected_pow =
        BuildRCStage3EpisodePowPin(statement, why);
    if (!expected_pow.has_value() ||
        proof.pow_pin != *expected_pow) {
        return Fail(
            why, "digest_pow_ctl:verify_pow_pin");
    }
    const std::vector<uint8_t> digest_bytes =
        HashBytes(statement.public_inputs.episode_digest);
    const std::vector<Fp3> digest_values =
        ByteValues(statement.public_inputs.episode_digest);
    const std::vector<Fp3> target_values =
        ByteValues(statement.public_inputs.target);
    AirCS digest_cs;
    AirCS target_cs;
    AirCS pow_cs;
    if (!BuildRCStage3RootChainVectorConstraintSystem(
            digest_chain.digest_pin,
            digest_bytes, digest_cs, why) ||
        !BuildRCStage3EpisodeHeaderTargetConstraintSystem(
            header_target.pin, target_cs, why) ||
        !BuildRCStage3EpisodePowConstraintSystem(
            proof.pow_pin, pow_cs, why)) {
        return Fail(
            why, "digest_pow_ctl:verify_relation_systems");
    }
    const uint256 digest_root =
        aq::AirCommittedValuesRoot<Fp3>(
            digest_values,
            kRCStage3EpisodePowRows);
    const uint256 target_root =
        aq::AirCommittedValuesRoot<Fp3>(
            target_values,
            kRCStage3EpisodePowRows);
    if (digest_root !=
            digest_chain.digest_pin.value_root ||
        !VerifyDigestPowCtlLane(
            statement,
            digest_chain.digest_pin,
            header_target.pin,
            proof.pow_pin,
            RCStage3RelationEndpoint::EpisodeDigestValue,
            kRCStage3EpisodeDigestPowCtlBusId,
            DIGEST_POW_CTL_DIGEST_STAGE,
            digest_cs,
            kRCStage3RootChainValue,
            VectorSeed(digest_chain.digest_pin),
            pow_cs,
            kRCStage3EpisodePowDigestByte,
            digest_values,
            digest_root,
            proof.digest_lane, why) ||
        !VerifyDigestPowCtlLane(
            statement,
            digest_chain.digest_pin,
            header_target.pin,
            proof.pow_pin,
            RCStage3RelationEndpoint::
                EpisodeDigestHeaderTarget,
            kRCStage3EpisodeDigestPowCtlBusId + 1,
            DIGEST_POW_CTL_TARGET_STAGE,
            target_cs,
            kRCStage3EpisodeHeaderTargetByte,
            ComputeRCStage3EpisodeHeaderTargetSeed(
                header_target.pin),
            pow_cs,
            kRCStage3EpisodePowTargetByte,
            target_values,
            target_root,
            proof.target_lane, why)) {
        return false;
    }
    if (proof.proof_commitment !=
            CommitDigestPowCtlProof(proof)) {
        return Fail(
            why, "digest_pow_ctl:verify_proof_commitment");
    }
    if (why != nullptr) {
        *why =
            "stage3:root_chain:"
            "endpoint24_and_25_proof_owned_bytes_equal_"
            "endpoint26_digest_and_target_columns";
    }
    return true;
}

bool ProveRCStage3CoupledRootChain(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const uint256& bank_root,
    const std::vector<std::vector<uint8_t>>& barrier_state_bytes,
    RCStage3CoupledRootChainProof& out,
    std::string* why)
{
    out = {};
    if (!IsCoupledStatement(statement) ||
        bank_root.IsNull() ||
        barrier_state_bytes.size() != shape.barriers) {
        return Fail(why, "coupled_prove_shape");
    }
    const uint256 statement_commitment =
        CommitRCStage3CoupledStatement(statement.public_inputs);
    const auto sha_program =
        ha::BuildCanonicalProgram(ha::ProgramKind::Sha256Compression);
    out.barriers.resize(shape.barriers);
    std::vector<uint256> barrier_roots;
    barrier_roots.reserve(shape.barriers);
    for (uint32_t i = 0; i < shape.barriers; ++i) {
        auto& entry = out.barriers[i];
        if (!ha::BuildCoupledBarrierManifest(
                shape.transcript_version, shape.barriers, i,
                barrier_state_bytes[i], entry.manifest, why)) {
            out = {};
            return Fail(
                why, "coupled_prove_barrier_manifest_" +
                    std::to_string(i));
        }
        std::vector<ha::FixedProgramBoundaryInstance> boundaries;
        if (!ha::BuildDirectSha256dManifestBoundaryInstances(
                entry.manifest.direct, boundaries, why) ||
            !hs::ProveFlatBoundaryProofBundle(
                RCStage3RelationEndpoint::CoupledBarrierHash,
                statement_commitment,
                entry.manifest.direct.commitment,
                sha_program, boundaries, entry.hash_bundle, why) ||
            !BuildRCStage3CoupledHashSemanticPin(
                RCStage3RelationEndpoint::CoupledBarrierHash,
                shape, statement_commitment,
                entry.manifest.direct.commitment, boundaries,
                hs::BoundaryPort::ExternalThenFinal,
                entry.hash_pin, why)) {
            out = {};
            return Fail(
                why, "coupled_prove_barrier_hash_" +
                    std::to_string(i));
        }
        barrier_roots.emplace_back(
            entry.manifest.direct.digest);
    }
    if (!ha::BuildCoupledDigestManifest(
            shape.transcript_version, shape.barriers,
            bank_root, barrier_roots, out.digest_manifest, why) ||
        out.digest_manifest.direct.digest !=
            statement.public_inputs.coupled_digest) {
        out = {};
        return Fail(why, "coupled_prove_digest_manifest_or_outer");
    }
    const uint256 collection =
        ComputeRCStage3RootChainBarrierCollectionCommitment(
            out.barriers);
    const std::vector<uint8_t> inputs =
        BarrierInputBytes(out.barriers);
    const std::vector<uint8_t> outputs =
        BarrierOutputBytes(out.barriers);
    if (!BuildRCStage3RootChainVectorPin(
            RCStage3RelationEndpoint::CoupledBarrierInput,
            statement_commitment, collection, inputs,
            out.barrier_inputs_pin, why) ||
        !ProveRCStage3RootChainVector(
            out.barrier_inputs_pin, inputs,
            out.barrier_inputs_proof, why) ||
        !BuildRCStage3RootChainVectorPin(
            RCStage3RelationEndpoint::CoupledBarrierOutput,
            statement_commitment, collection, outputs,
            out.barrier_outputs_pin, why) ||
        !ProveRCStage3RootChainVector(
            out.barrier_outputs_pin, outputs,
            out.barrier_outputs_proof, why)) {
        out = {};
        return Fail(why, "coupled_prove_barrier_vectors");
    }
    const std::vector<uint8_t> digest_inputs =
        CoupledDigestInputBytes(out.digest_manifest);
    if (!BuildRCStage3RootChainVectorPin(
            RCStage3RelationEndpoint::CoupledDigestBankAndBarriers,
            statement_commitment, out.digest_manifest.commitment,
            digest_inputs, out.digest_inputs_pin, why) ||
        !ProveRCStage3RootChainVector(
            out.digest_inputs_pin, digest_inputs,
            out.digest_inputs_proof, why)) {
        out = {};
        return Fail(why, "coupled_prove_digest_inputs");
    }
    std::vector<ha::FixedProgramBoundaryInstance> digest_boundaries;
    if (!ha::BuildDirectSha256dManifestBoundaryInstances(
            out.digest_manifest.direct,
            digest_boundaries, why) ||
        !hs::ProveFlatBoundaryProofBundle(
            RCStage3RelationEndpoint::CoupledDigestHash,
            statement_commitment,
            out.digest_manifest.direct.commitment,
            sha_program, digest_boundaries,
            out.digest_hash_bundle, why) ||
        !BuildRCStage3CoupledHashSemanticPin(
            RCStage3RelationEndpoint::CoupledDigestHash,
            shape, statement_commitment,
            out.digest_manifest.direct.commitment,
            digest_boundaries,
            hs::BoundaryPort::ExternalThenFinal,
            out.digest_hash_pin, why)) {
        out = {};
        return Fail(why, "coupled_prove_digest_hash");
    }
    const std::vector<uint8_t> digest =
        HashBytes(out.digest_manifest.direct.digest);
    if (!BuildRCStage3RootChainVectorPin(
            RCStage3RelationEndpoint::CoupledDigestValue,
            statement_commitment, out.digest_manifest.commitment,
            digest, out.digest_value_pin, why) ||
        !ProveRCStage3RootChainVector(
            out.digest_value_pin, digest,
            out.digest_value_proof, why) ||
        !VerifyRCStage3CoupledRootChain(
            statement, shape, out, why)) {
        out = {};
        return Fail(why, "coupled_prove_digest_value");
    }
    return true;
}

bool VerifyRCStage3CoupledBarrierRootChain(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledRootChainProof& proof,
    std::string* why)
{
    if (!IsCoupledStatement(statement) ||
        proof.barriers.size() != shape.barriers) {
        return Fail(why, "coupled_barrier_outer_shape");
    }
    const uint256 statement_commitment =
        CommitRCStage3CoupledStatement(statement.public_inputs);
    for (uint32_t i = 0; i < proof.barriers.size(); ++i) {
        const auto& entry = proof.barriers[i];
        if (!ValidateRCStage3CoupledBarrierManifestStructural(
                shape, i, entry.manifest, why) ||
            !VerifyRCStage3CoupledBarrierHashSemantic(
                statement, shape, entry.manifest,
                entry.hash_bundle, entry.hash_pin, why)) {
            return Fail(why, "barrier_" + std::to_string(i));
        }
    }
    const uint256 barrier_collection =
        ComputeRCStage3RootChainBarrierCollectionCommitment(
            proof.barriers);
    const std::vector<uint8_t> barrier_inputs =
        BarrierInputBytes(proof.barriers);
    const std::vector<uint8_t> barrier_outputs =
        BarrierOutputBytes(proof.barriers);
    if (!VerifyRCStage3RootChainVector(
            RCStage3RelationEndpoint::CoupledBarrierInput,
            statement_commitment, barrier_collection, barrier_inputs,
            proof.barrier_inputs_pin,
            proof.barrier_inputs_proof, why) ||
        !VerifyRCStage3RootChainVector(
            RCStage3RelationEndpoint::CoupledBarrierOutput,
            statement_commitment, barrier_collection,
            barrier_outputs, proof.barrier_outputs_pin,
            proof.barrier_outputs_proof, why)) {
        return false;
    }
    if (why != nullptr) {
        *why = "stage3:root_chain:coupled_barrier_local_ok";
    }
    return true;
}

bool VerifyRCStage3CoupledDigestRootChain(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledRootChainProof& proof,
    std::string* why)
{
    if (!IsCoupledStatement(statement) ||
        proof.barriers.size() != shape.barriers ||
        !ValidateRCStage3CoupledDigestManifestStructural(
            shape, proof.digest_manifest, why) ||
        proof.digest_manifest.direct.digest !=
            statement.public_inputs.coupled_digest) {
        return Fail(why, "coupled_digest_outer_shape");
    }
    const uint256 statement_commitment =
        CommitRCStage3CoupledStatement(statement.public_inputs);
    for (uint32_t i = 0; i < proof.barriers.size(); ++i) {
        const auto& entry = proof.barriers[i];
        if (!ValidateRCStage3CoupledBarrierManifestStructural(
                shape, i, entry.manifest, why) ||
            entry.manifest.direct.digest !=
                proof.digest_manifest.barrier_roots[i]) {
            return Fail(why, "digest_barrier_struct_" + std::to_string(i));
        }
    }
    const std::vector<uint8_t> digest_inputs =
        CoupledDigestInputBytes(proof.digest_manifest);
    if (!VerifyRCStage3RootChainVector(
            RCStage3RelationEndpoint::CoupledDigestBankAndBarriers,
            statement_commitment, proof.digest_manifest.commitment,
            digest_inputs, proof.digest_inputs_pin,
            proof.digest_inputs_proof, why) ||
        !VerifyRCStage3CoupledDigestHashSemantic(
            statement, shape, proof.digest_manifest,
            proof.digest_hash_bundle, proof.digest_hash_pin, why)) {
        return Fail(why, "coupled_digest_hash");
    }
    const std::vector<uint8_t> digest =
        HashBytes(proof.digest_manifest.direct.digest);
    if (!VerifyRCStage3RootChainVector(
            RCStage3RelationEndpoint::CoupledDigestValue,
            statement_commitment, proof.digest_manifest.commitment,
            digest, proof.digest_value_pin,
            proof.digest_value_proof, why)) {
        return false;
    }
    if (why != nullptr) {
        *why = "stage3:root_chain:coupled_digest_local_ok";
    }
    return true;
}

bool VerifyRCStage3CoupledRootChain(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledRootChainProof& proof,
    std::string* why)
{
    if (!VerifyRCStage3CoupledBarrierRootChain(
            statement, shape, proof, why) ||
        !VerifyRCStage3CoupledDigestRootChain(
            statement, shape, proof, why)) {
        return false;
    }
    if (why != nullptr) {
        *why =
            "stage3:root_chain:coupled_barriers_and_digest_local_chain_ok_"
            "extract_and_bank_producer_links_pending";
    }
    return true;
}

bool VerifyRCStage3CoupledRootChainWithFlatBankProducer(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledBankRootExecution& bank,
    const RCStage3CoupledRootChainProof& proof,
    std::string* why)
{
    if (!VerifyRCStage3CoupledBankRootExecution(
            statement, shape, bank, why)) {
        return Fail(why, "coupled_bank_producer");
    }
    if (!VerifyRCStage3CoupledRootChain(
            statement, shape, proof, why)) {
        return false;
    }
    if (bank.manifest.bank_root !=
        proof.digest_manifest.bank_root) {
        return Fail(why, "coupled_bank_digest_root_equality");
    }
    if (why != nullptr) {
        *why =
            "stage3:root_chain:coupled_bank_and_barrier_immediate_"
            "producer_roots_equal_endpoint28_and47_ancestry_pending";
    }
    return true;
}

bool VerifyRCStage3CoupledRootChainWithBoundedBankProductProducer(
    const RCStage3SuccinctProof& statement,
    const CBlockHeader& header,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledBankProduct& bank_product,
    const RCStage3CoupledBankRootExecution& flat_bank,
    const RCStage3CoupledRootChainProof& proof,
    std::string* why)
{
    if (!VerifyRCStage3CoupledBankFlatSourceLink(
            statement, header, shape, bank_product,
            flat_bank, why)) {
        return Fail(why, "coupled_bounded_bank_product");
    }
    if (!VerifyRCStage3CoupledRootChain(
            statement, shape, proof, why)) {
        return false;
    }
    if (flat_bank.manifest.bank_root !=
        proof.digest_manifest.bank_root) {
        return Fail(
            why, "coupled_bounded_bank_digest_root_equality");
    }
    if (why != nullptr) {
        *why =
            "stage3:root_chain:endpoints27_28_29_to_50_bank_branch_"
            "complete_endpoint47_barrier_ancestry_and_recursion_pending";
    }
    return true;
}

bool VerifyRCStage3CoupledRootChainWithStreamingBankProducer(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const uint256& expected_bank_page_byte_root,
    const RCStage3CoupledBankStreamManifest& bank_manifest,
    const RCStage3CoupledBankStreamRecursiveProof& bank_root,
    const RCStage3CoupledBankStreamSecondPassProof& bank_second_pass,
    const RCStage3CoupledRootChainProof& proof,
    std::string* why)
{
    if (!ValidateRCStage3CoupledBankStreamManifest(
            statement, shape, expected_bank_page_byte_root,
            bank_manifest, why) ||
        !VerifyRCStage3CoupledBankStreamRecursiveRootAndSecondPass(
            bank_manifest, bank_root, bank_second_pass, why)) {
        return Fail(why, "coupled_streaming_bank_producer");
    }
    if (!VerifyRCStage3CoupledRootChain(
            statement, shape, proof, why)) {
        return false;
    }
    if (bank_second_pass.bank_root !=
        proof.digest_manifest.bank_root) {
        return Fail(
            why, "coupled_streaming_bank_digest_root_equality");
    }
    if (why != nullptr) {
        *why =
            "stage3:root_chain:coupled_streaming_bank_and_barrier_"
            "immediate_producer_roots_equal_endpoint28_and47_ancestry_"
            "and_succinct_fixed_point_pending";
    }
    return true;
}

std::vector<RCStage3RootChainEndpointAudit>
CurrentRCStage3RootChainEndpointAudit()
{
    using E = RCStage3RelationEndpoint;
    std::vector<RCStage3RootChainEndpointAudit> out;
    const auto append =
        [&](E endpoint, bool hash, bool downstream, bool outer,
            bool upstream, bool local, bool producer,
            const char* remaining) {
            RCStage3RootChainEndpointAudit audit;
            audit.endpoint = endpoint;
            audit.typed_manifest_executable = true;
            audit.proof_owned_vector_executable = !hash;
            audit.hash_provenance_executable = hash;
            audit.downstream_equality_executable = downstream;
            audit.outer_statement_equality_executable = outer;
            audit.upstream_relation_equality_executable = upstream;
            audit.local_relation_complete = local;
            audit.producer_graph_complete = producer;
            audit.strict_semantic_complete = local && producer;
            audit.remaining = remaining;
            out.push_back(std::move(audit));
        };
    append(
        E::EpisodeDigestRoundRoots, false, true, false, true,
        true, false,
        "both endpoint-22 typed root BYTE -> endpoint-23 VALUE and "
        "endpoint-23 VALUE -> endpoint-24 typed preimage bytes execute as "
        "exact-row same-trace CTL products; endpoint-20 -> 21 -> 22 also "
        "executes through proof-owned SHA cells, while transitive closure "
        "still waits on endpoint-19 Extract ancestry and recursion");
    append(
        E::EpisodeDigestValue, true, true, true, true,
        true, false,
        "both endpoint-23 VALUE -> endpoint-24 typed preimage bytes and "
        "endpoint-24 VALUE -> endpoint-26 DIGEST_BYTE execute as exact-row "
        "same-trace CTL products; transitive completeness still waits on "
        "endpoint-23 round-root ancestry");
    append(
        E::CoupledBarrierInput, false, true, false, false,
        false, false,
        "the all-instance Extract-output proof must export the identical "
        "ordered state-byte vector");
    append(E::CoupledBarrierHash, true, true, false, true,
           true, false, "");
    append(E::CoupledBarrierOutput, false, true, false, true,
           true, false, "");
    append(
        E::CoupledDigestBankAndBarriers, false, true, false, true,
        true, false,
        "the exact ordered bank+barrier vector, all barrier-output root "
        "equalities, and both bank-root proof seams execute; transitive "
        "closure still waits on endpoint 28 bank-page provenance and "
        "endpoint 47 barrier-input provenance");
    append(
        E::CoupledDigestHash, true, true, false, false,
        true, false,
        "hash provenance executes; transitive completeness waits on "
        "CoupledBankRoot");
    append(
        E::CoupledDigestValue, false, true, true, false,
        true, false,
        "outer equality executes; transitive completeness waits on "
        "CoupledBankRoot");
    return out;
}

} // namespace matmul::v4::rc
