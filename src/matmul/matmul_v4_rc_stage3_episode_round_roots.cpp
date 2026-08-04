// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_episode_round_roots.h>
#include <matmul/matmul_v4_rc_stage3_role_bytecode.h>

#include <hash.h>

#include <algorithm>

namespace matmul::v4::rc {
namespace {

namespace aq = air_quotient;
namespace cb = constraint_bytecode;
namespace gf = gkr_field;
using Fp3 = gf::Fp3;
using AirCS = aq::AirConstraintSystem<Fp3>;

constexpr char COLLECTION_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_ROUND_ROOT_PRODUCERS_V1";
constexpr char DIGEST_CTL_PIN_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_ROUND_ROOT_DIGEST_CTL_PIN_V1";
constexpr char DIGEST_CTL_TRANSCRIPT_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_ROUND_ROOT_DIGEST_CTL_TRANSCRIPT_V1";
constexpr char DIGEST_CTL_BRIDGE_SEED_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_ROUND_ROOT_DIGEST_BRIDGE_AIR_V1";
constexpr char DIGEST_CTL_PRODUCT_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_ROUND_ROOT_DIGEST_CTL_PRODUCT_V1";
constexpr char DIGEST_CTL_PROOF_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_ROUND_ROOT_DIGEST_CTL_PROOF_V1";
constexpr char TILE_ROOT_CTL_PIN_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_TILE_ROOT_VECTOR_CTL_PIN_V1";
constexpr char TILE_ROOT_CTL_TRANSCRIPT_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_TILE_ROOT_VECTOR_CTL_TRANSCRIPT_V1";
constexpr char TILE_ROOT_CTL_BRIDGE_SEED_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_TILE_ROOT_BYTE_BRIDGE_AIR_V1";
constexpr char TILE_ROOT_CTL_PROOF_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_TILE_ROOT_VECTOR_CTL_PROOF_V1";
constexpr uint32_t DIGEST_CTL_NAMESPACE = 0x45523234U; // "ER24"
constexpr uint32_t DIGEST_CTL_STAGE = 23;
constexpr uint32_t TILE_ROOT_CTL_NAMESPACE = 0x45523233U; // "ER23"
constexpr uint32_t TILE_ROOT_CTL_STAGE = 22;
constexpr uint32_t TILE_BRIDGE_ACTIVE = 0;
constexpr uint32_t TILE_BRIDGE_ADDRESS = 1;
constexpr uint32_t TILE_BRIDGE_EXPECTED = 2;
constexpr uint32_t TILE_BRIDGE_VALUE = 3;
constexpr uint32_t TILE_BRIDGE_EXPORT = 4;
constexpr uint32_t TILE_BRIDGE_BYTE = 5;
constexpr uint32_t TILE_BRIDGE_SIGN = 6;
constexpr uint32_t TILE_BRIDGE_BIT_BASE = 7;
constexpr uint32_t TILE_BRIDGE_COLUMNS = 15;

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:episode_round_roots:" + detail;
    }
    return false;
}

bool IsEpisodeStatement(const RCStage3SuccinctProof& statement)
{
    return statement.statement == RCStage3StatementKind::Episode ||
           statement.statement == RCStage3StatementKind::Composed;
}

void AppendRootBytes(std::vector<uint8_t>& out, const uint256& root)
{
    out.insert(out.end(), root.begin(), root.end());
}

Fp3 U64(uint64_t value)
{
    return Fp3::FromFp(gf::FromU64(value));
}

std::vector<uint8_t> RoundRootBytes(
    const stage3_hash_air::EpisodeDigestManifest& manifest)
{
    std::vector<uint8_t> out;
    out.reserve(manifest.round_roots.size() * 32);
    for (const auto& root : manifest.round_roots) {
        AppendRootBytes(out, root);
    }
    return out;
}

uint256 DigestCtlPinCommitment(
    const RCStage3EpisodeRoundRootDigestCtlPin& pin)
{
    if (pin.version !=
            kRCStage3EpisodeRoundRootDigestCtlVersion ||
        pin.statement_commitment.IsNull() ||
        pin.digest_manifest_commitment.IsNull() ||
        pin.producer_collection_commitment.IsNull() ||
        pin.logical_rows == 0 ||
        pin.n_rows < pin.logical_rows ||
        (pin.n_rows & (pin.n_rows - 1)) != 0 ||
        pin.value_root.IsNull() ||
        pin.program_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << DIGEST_CTL_PIN_DOMAIN;
    hash << pin.version;
    hash << pin.statement_commitment;
    hash << pin.digest_manifest_commitment;
    hash << pin.producer_collection_commitment;
    hash << pin.logical_rows;
    hash << pin.n_rows;
    hash << pin.address_begin;
    hash << pin.value_root;
    hash << pin.program_commitment;
    return hash.GetHash();
}

bool BuildDigestCtlPin(
    const RCStage3SuccinctProof& statement,
    const RCStage3EpisodeDigestRootChainProof& root_chain,
    const RCStage3EpisodeRoundRootProducerProduct& producers,
    RCStage3EpisodeRoundRootDigestCtlPin& out,
    std::string* why)
{
    out = {};
    cb::ProgramTable table;
    const auto root_bytes =
        RoundRootBytes(root_chain.manifest);
    if (root_bytes.empty() ||
        root_chain.round_roots_pin.logical_rows !=
            root_bytes.size() ||
        !BuildRCStage3EpisodeDigestPreimageByteBridgeProgramTable(
            table, why)) {
        return Fail(why, "digest_ctl_pin_shape");
    }
    out.statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    out.digest_manifest_commitment =
        root_chain.manifest.commitment;
    out.producer_collection_commitment =
        producers.collection_commitment;
    out.logical_rows =
        static_cast<uint32_t>(root_bytes.size());
    out.n_rows = root_chain.round_roots_pin.n_rows;
    out.address_begin =
        root_chain.round_roots_pin.address_begin;
    out.value_root =
        root_chain.round_roots_pin.value_root;
    out.program_commitment = cb::CommitProgramTable(table);
    out.pin_commitment = DigestCtlPinCommitment(out);
    return !out.pin_commitment.IsNull() ||
        Fail(why, "digest_ctl_pin_commitment");
}

uint256 DigestCtlBridgeSeed(
    const RCStage3EpisodeRoundRootDigestCtlPin& pin)
{
    if (pin.pin_commitment !=
            DigestCtlPinCommitment(pin)) {
        return {};
    }
    HashWriter hash;
    hash << DIGEST_CTL_BRIDGE_SEED_DOMAIN;
    hash << pin.pin_commitment;
    return hash.GetHash();
}

RCStage3CtlSchedule DigestCtlSchedule(
    uint32_t n_rows,
    int8_t multiplicity)
{
    RCStage3CtlSchedule out;
    out.events.reserve(n_rows);
    for (uint32_t row = 0; row < n_rows; ++row) {
        out.events.push_back({
            DIGEST_CTL_NAMESPACE,
            DIGEST_CTL_STAGE,
            row,
            multiplicity,
        });
    }
    return out;
}

RCStage3CtlParticipantSpec DigestCtlParticipant(
    RCStage3RelationRole role,
    const RCStage3CtlSchedule& schedule)
{
    RCStage3CtlParticipantSpec out;
    out.role = role;
    out.event_count = schedule.events.size();
    out.send_count =
        role == RCStage3RelationRole::EpisodeDigest
        ? out.event_count : 0;
    out.receive_count =
        role == RCStage3RelationRole::CompositionLink
        ? out.event_count : 0;
    out.schedule_commitment =
        CommitRCStage3CtlSchedule(schedule);
    return out;
}

uint256 DigestCtlTranscriptSeed(
    const RCStage3EpisodeRoundRootDigestCtlPin& pin)
{
    HashWriter hash;
    hash << DIGEST_CTL_TRANSCRIPT_DOMAIN;
    hash << pin.pin_commitment;
    return hash.GetHash();
}

void HashPath(
    HashWriter& hash,
    const Fri3MerklePath& path)
{
    hash << path.index;
    hash << gf::Canonical(path.leaf.c0);
    hash << gf::Canonical(path.leaf.c1);
    hash << gf::Canonical(path.leaf.c2);
    hash << static_cast<uint32_t>(
        path.siblings.size());
    for (const auto& sibling : path.siblings) {
        hash << sibling;
    }
}

uint256 CommitDigestCtlProduct(
    const aq::AirQuotientProof<Fp3>& proof)
{
    std::vector<unsigned char> batch;
    if (SerializeFri3BatchProof(
            proof.batch, batch) == 0) {
        return {};
    }
    HashWriter hash;
    hash << DIGEST_CTL_PRODUCT_DOMAIN;
    hash << batch;
    hash << proof.trace_commit;
    hash << static_cast<uint32_t>(
        proof.next_openings.size());
    for (const auto& query : proof.next_openings) {
        hash << static_cast<uint32_t>(query.size());
        for (const auto& path : query) HashPath(hash, path);
    }
    return hash.GetHash();
}

uint256 CommitDigestCtlProof(
    const RCStage3EpisodeRoundRootDigestCtlProof& proof)
{
    const uint256 composition =
        CommitRCStage3CtlComposition(
            proof.manifest, proof.pins);
    if (proof.version !=
            kRCStage3EpisodeRoundRootDigestCtlVersion ||
        proof.bridge_pin.pin_commitment.IsNull() ||
        proof.producer_product_commitment.IsNull() ||
        proof.consumer_product_commitment.IsNull() ||
        composition.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << DIGEST_CTL_PROOF_DOMAIN;
    hash << proof.version;
    hash << proof.bridge_pin.pin_commitment;
    hash << composition;
    hash << proof.producer_product_commitment;
    hash << proof.consumer_product_commitment;
    return hash.GetHash();
}

uint256 TileRootCtlPinCommitment(
    const RCStage3EpisodeRoundRootDigestCtlPin& pin)
{
    if (pin.version !=
            kRCStage3EpisodeRoundRootDigestCtlVersion ||
        pin.statement_commitment.IsNull() ||
        pin.digest_manifest_commitment.IsNull() ||
        pin.producer_collection_commitment.IsNull() ||
        pin.logical_rows == 0 ||
        pin.n_rows < pin.logical_rows ||
        (pin.n_rows & (pin.n_rows - 1)) != 0 ||
        pin.value_root.IsNull() ||
        pin.program_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << TILE_ROOT_CTL_PIN_DOMAIN;
    hash << pin.version;
    hash << pin.statement_commitment;
    hash << pin.digest_manifest_commitment;
    hash << pin.producer_collection_commitment;
    hash << pin.logical_rows;
    hash << pin.n_rows;
    hash << pin.address_begin;
    hash << pin.value_root;
    hash << pin.program_commitment;
    return hash.GetHash();
}

bool BuildTileRootCtlPin(
    const RCStage3SuccinctProof& statement,
    const RCStage3EpisodeDigestRootChainProof& root_chain,
    const RCStage3EpisodeRoundRootProducerProduct& producers,
    RCStage3EpisodeRoundRootDigestCtlPin& out,
    std::string* why)
{
    out = {};
    cb::ProgramTable table;
    const auto root_bytes =
        RoundRootBytes(root_chain.manifest);
    if (root_bytes.empty() ||
        root_chain.round_roots_pin.logical_rows !=
            root_bytes.size() ||
        !BuildRCStage3EpisodeTileTreeByteBridgeProgramTable(
            table, why)) {
        return Fail(why, "tile_root_ctl_pin_shape");
    }
    out.statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    out.digest_manifest_commitment =
        root_chain.manifest.commitment;
    out.producer_collection_commitment =
        producers.collection_commitment;
    out.logical_rows =
        static_cast<uint32_t>(root_bytes.size());
    out.n_rows = root_chain.round_roots_pin.n_rows;
    out.address_begin =
        root_chain.round_roots_pin.address_begin;
    out.value_root =
        root_chain.round_roots_pin.value_root;
    out.program_commitment = cb::CommitProgramTable(table);
    out.pin_commitment =
        TileRootCtlPinCommitment(out);
    return !out.pin_commitment.IsNull() ||
        Fail(why, "tile_root_ctl_pin_commitment");
}

uint256 TileRootCtlTranscriptSeed(
    const RCStage3EpisodeRoundRootDigestCtlPin& pin)
{
    if (pin.pin_commitment !=
            TileRootCtlPinCommitment(pin)) {
        return {};
    }
    HashWriter hash;
    hash << TILE_ROOT_CTL_TRANSCRIPT_DOMAIN;
    hash << pin.pin_commitment;
    return hash.GetHash();
}

uint256 TileRootBridgeSeed(
    const RCStage3EpisodeRoundRootDigestCtlPin& pin)
{
    if (pin.pin_commitment !=
            TileRootCtlPinCommitment(pin)) {
        return {};
    }
    HashWriter hash;
    hash << TILE_ROOT_CTL_BRIDGE_SEED_DOMAIN;
    hash << pin.pin_commitment;
    return hash.GetHash();
}

RCStage3CtlSchedule TileRootCtlSchedule(
    uint32_t n_rows,
    int8_t multiplicity)
{
    RCStage3CtlSchedule out;
    out.events.reserve(n_rows);
    for (uint32_t row = 0; row < n_rows; ++row) {
        out.events.push_back({
            TILE_ROOT_CTL_NAMESPACE,
            TILE_ROOT_CTL_STAGE,
            row,
            multiplicity,
        });
    }
    return out;
}

RCStage3CtlParticipantSpec TileRootCtlParticipant(
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

bool BuildTileRootBridgeConstraintSystem(
    const RCStage3EpisodeRoundRootDigestCtlPin& pin,
    const std::vector<uint8_t>& bytes,
    AirCS& out,
    std::string* why)
{
    out = {};
    cb::ProgramTable table;
    if (pin.pin_commitment !=
            TileRootCtlPinCommitment(pin) ||
        bytes.size() != pin.logical_rows ||
        !BuildRCStage3EpisodeTileTreeByteBridgeProgramTable(
            table, why) ||
        cb::CommitProgramTable(table) !=
            pin.program_commitment ||
        !cb::BuildAirConstraintSystemFromProgramTable(
            table, pin.n_rows, out, why)) {
        return Fail(why, "tile_root_bridge_constraint_shape");
    }
    std::vector<Fp3> unsigned_values(
        pin.n_rows, Fp3::Zero());
    std::vector<Fp3> active(
        pin.n_rows, Fp3::Zero());
    std::vector<Fp3> address(
        pin.n_rows, Fp3::Zero());
    std::vector<Fp3> expected(
        pin.n_rows, Fp3::Zero());
    for (uint32_t row = 0; row < pin.logical_rows; ++row) {
        unsigned_values[row] = U64(bytes[row]);
        active[row] = Fp3::One();
        address[row] = U64(pin.address_begin + row);
        expected[row] = Fp3::FromFp(gf::FromSigned(
            bytes[row] < 128
                ? static_cast<int64_t>(bytes[row])
                : static_cast<int64_t>(bytes[row]) - 256));
    }
    if (aq::AirCommittedValuesRoot<Fp3>(
            unsigned_values, pin.n_rows) !=
        pin.value_root) {
        out = {};
        return Fail(why, "tile_root_bridge_value_root");
    }
    out.preprocessed.emplace_back(
        TILE_BRIDGE_ACTIVE, std::move(active));
    out.preprocessed.emplace_back(
        TILE_BRIDGE_ADDRESS, std::move(address));
    out.preprocessed.emplace_back(
        TILE_BRIDGE_EXPECTED, std::move(expected));
    return true;
}

bool BuildTileRootBridgeColumns(
    const RCStage3EpisodeRoundRootDigestCtlPin& pin,
    const std::vector<uint8_t>& bytes,
    const AirCS& cs,
    std::vector<std::vector<Fp3>>& out)
{
    if (bytes.size() != pin.logical_rows ||
        cs.n_columns != TILE_BRIDGE_COLUMNS ||
        cs.n_rows != pin.n_rows) {
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
        const Fp3 signed_value =
            Fp3::FromFp(gf::FromSigned(
                byte < 128
                    ? static_cast<int64_t>(byte)
                    : static_cast<int64_t>(byte) - 256));
        out[TILE_BRIDGE_VALUE][row] = signed_value;
        out[TILE_BRIDGE_EXPORT][row] = signed_value;
        out[TILE_BRIDGE_BYTE][row] = U64(byte);
        out[TILE_BRIDGE_SIGN][row] = U64(byte >> 7);
        for (uint32_t bit = 0; bit < 8; ++bit) {
            out[TILE_BRIDGE_BIT_BASE + bit][row] =
                U64((byte >> bit) & 1U);
        }
    }
    return true;
}

uint256 CommitTileRootCtlProof(
    const RCStage3EpisodeTileTreeRootVectorCtlProof& proof)
{
    const uint256 composition =
        CommitRCStage3CtlComposition(
            proof.manifest, proof.pins);
    if (proof.version !=
            kRCStage3EpisodeRoundRootDigestCtlVersion ||
        proof.bridge_pin.pin_commitment.IsNull() ||
        proof.producer_product_commitment.IsNull() ||
        proof.consumer_product_commitment.IsNull() ||
        composition.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << TILE_ROOT_CTL_PROOF_DOMAIN;
    hash << proof.version;
    hash << proof.bridge_pin.pin_commitment;
    hash << composition;
    hash << proof.producer_product_commitment;
    hash << proof.consumer_product_commitment;
    return hash.GetHash();
}

bool BuildRootVectorColumns(
    const RCStage3RootChainVectorPin& pin,
    const std::vector<uint8_t>& values,
    const AirCS& cs,
    std::vector<std::vector<Fp3>>& out)
{
    if (values.size() != pin.logical_rows ||
        cs.n_columns != kRCStage3RootChainColumns ||
        cs.n_rows != pin.n_rows) {
        return false;
    }
    out.assign(
        cs.n_columns,
        std::vector<Fp3>(cs.n_rows, Fp3::Zero()));
    for (const auto& [column, canonical] :
         cs.preprocessed) {
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

bool BuildDigestBridgeColumns(
    const RCStage3EpisodeRoundRootDigestCtlPin& pin,
    const std::vector<uint8_t>& values,
    const AirCS& cs,
    std::vector<std::vector<Fp3>>& out)
{
    if (values.size() != pin.logical_rows ||
        cs.n_columns !=
            kRCStage3EpisodeDigestBridgeColumns ||
        cs.n_rows != pin.n_rows) {
        return false;
    }
    out.assign(
        cs.n_columns,
        std::vector<Fp3>(cs.n_rows, Fp3::Zero()));
    for (const auto& [column, canonical] :
         cs.preprocessed) {
        out[column] = canonical;
    }
    for (uint32_t row = 0; row < pin.logical_rows; ++row) {
        const uint8_t value = values[row];
        out[kRCStage3EpisodeDigestBridgeValue][row] =
            U64(value);
        out[kRCStage3EpisodeDigestBridgeExport][row] =
            U64(value);
        for (uint32_t bit = 0; bit < 8; ++bit) {
            out[kRCStage3EpisodeDigestBridgeBitBase + bit][row] =
                U64((value >> bit) & 1U);
        }
    }
    return true;
}

} // namespace

uint256 ComputeRCStage3EpisodeRoundRootProducerCollectionCommitment(
    const RCStage3EpisodeRoundRootProducerProduct& product)
{
    if (product.version !=
            kRCStage3EpisodeRoundRootProductVersion ||
        product.statement_commitment.IsNull() ||
        product.expected_rounds == 0 ||
        product.digest_manifest_commitment.IsNull() ||
        product.rounds.size() != product.expected_rounds) {
        return {};
    }
    HashWriter hash;
    hash << COLLECTION_DOMAIN;
    hash << product.version;
    hash << product.statement_commitment;
    hash << product.expected_rounds;
    hash << product.digest_manifest_commitment;
    hash << static_cast<uint32_t>(product.rounds.size());
    for (uint32_t i = 0; i < product.rounds.size(); ++i) {
        const auto& round = product.rounds[i];
        if (round.round_index != i ||
            round.tree_manifest.commitment.IsNull() ||
            round.tree_manifest.root.IsNull()) {
            return {};
        }
        hash << round.round_index;
        hash << round.tree_manifest.commitment;
        hash << round.tree_manifest.root;
    }
    return hash.GetHash();
}

bool BuildRCStage3EpisodeDigestPreimageByteBridgeConstraintSystem(
    const RCStage3EpisodeRoundRootDigestCtlPin& pin,
    const std::vector<uint8_t>& root_bytes,
    AirCS& out,
    std::string* why)
{
    out = {};
    cb::ProgramTable table;
    if (pin.pin_commitment !=
            DigestCtlPinCommitment(pin) ||
        root_bytes.size() != pin.logical_rows ||
        !BuildRCStage3EpisodeDigestPreimageByteBridgeProgramTable(
            table, why) ||
        cb::CommitProgramTable(table) !=
            pin.program_commitment ||
        !cb::BuildAirConstraintSystemFromProgramTable(
            table, pin.n_rows, out, why)) {
        return Fail(
            why, "digest_bridge_constraint_shape");
    }
    std::vector<Fp3> values(
        pin.n_rows, Fp3::Zero());
    std::vector<Fp3> active(
        pin.n_rows, Fp3::Zero());
    std::vector<Fp3> address(
        pin.n_rows, Fp3::Zero());
    std::vector<Fp3> expected(
        pin.n_rows, Fp3::Zero());
    for (uint32_t row = 0;
         row < pin.logical_rows; ++row) {
        active[row] = Fp3::One();
        address[row] = U64(
            pin.address_begin + row);
        expected[row] = U64(root_bytes[row]);
        values[row] = U64(root_bytes[row]);
    }
    if (aq::AirCommittedValuesRoot<Fp3>(
            values, pin.n_rows) !=
            pin.value_root) {
        out = {};
        return Fail(
            why, "digest_bridge_value_root");
    }
    out.preprocessed.emplace_back(
        kRCStage3EpisodeDigestBridgeActive,
        std::move(active));
    out.preprocessed.emplace_back(
        kRCStage3EpisodeDigestBridgeAddress,
        std::move(address));
    out.preprocessed.emplace_back(
        kRCStage3EpisodeDigestBridgeExpected,
        std::move(expected));
    return true;
}

bool ProveRCStage3EpisodeRoundRootDigestCtl(
    const RCStage3SuccinctProof& statement,
    uint32_t expected_rounds,
    const RCStage3EpisodeDigestRootChainProof& root_chain,
    const RCStage3EpisodeRoundRootProducerProduct& producers,
    RCStage3EpisodeRoundRootDigestCtlProof& out,
    std::string* why)
{
    out = {};
    if (!VerifyRCStage3EpisodeDigestRootChainWithRoundRootProducers(
            statement, expected_rounds,
            root_chain, producers, why) ||
        !BuildDigestCtlPin(
            statement, root_chain,
            producers, out.bridge_pin, why)) {
        return Fail(
            why, "digest_ctl_prove_sources");
    }
    const std::vector<uint8_t> root_bytes =
        RoundRootBytes(root_chain.manifest);
    AirCS producer_cs;
    AirCS consumer_cs;
    std::vector<std::vector<Fp3>> producer_columns;
    std::vector<std::vector<Fp3>> consumer_columns;
    if (!BuildRCStage3RootChainVectorConstraintSystem(
            root_chain.round_roots_pin,
            root_bytes, producer_cs, why) ||
        !BuildRootVectorColumns(
            root_chain.round_roots_pin,
            root_bytes, producer_cs,
            producer_columns) ||
        !BuildRCStage3EpisodeDigestPreimageByteBridgeConstraintSystem(
            out.bridge_pin, root_bytes,
            consumer_cs, why) ||
        !BuildDigestBridgeColumns(
            out.bridge_pin, root_bytes,
            consumer_cs, consumer_columns)) {
        return Fail(
            why, "digest_ctl_prove_relation_columns");
    }

    std::vector<Fp3> bus_values(
        out.bridge_pin.n_rows, Fp3::Zero());
    for (uint32_t row = 0;
         row < out.bridge_pin.logical_rows; ++row) {
        bus_values[row] = U64(root_bytes[row]);
    }
    out.producer_schedule =
        DigestCtlSchedule(
            out.bridge_pin.n_rows, 1);
    out.consumer_schedule =
        DigestCtlSchedule(
            out.bridge_pin.n_rows, -1);
    out.manifest.bus_id =
        kRCStage3EpisodeRoundRootDigestCtlBusId;
    out.manifest.transcript_seed =
        DigestCtlTranscriptSeed(out.bridge_pin);
    out.manifest.participants = {
        DigestCtlParticipant(
            RCStage3RelationRole::EpisodeDigest,
            out.producer_schedule),
        DigestCtlParticipant(
            RCStage3RelationRole::CompositionLink,
            out.consumer_schedule),
    };
    out.pins.resize(2);
    for (size_t index = 0;
         index < out.pins.size(); ++index) {
        const auto& participant =
            out.manifest.participants[index];
        auto& pin = out.pins[index];
        pin.role = participant.role;
        pin.bus_id = out.manifest.bus_id;
        pin.event_count =
            participant.event_count;
        pin.send_count =
            participant.send_count;
        pin.receive_count =
            participant.receive_count;
        pin.schedule_commitment =
            participant.schedule_commitment;
    }
    out.pins[0].trace_commitment =
        ComputeRCStage3CtlDegree2PrechallengeTraceCommitment(
            out.producer_schedule,
            bus_values);
    out.pins[1].trace_commitment =
        ComputeRCStage3CtlDegree2PrechallengeTraceCommitment(
            out.consumer_schedule,
            bus_values);
    RCStage3CtlChallenges challenges;
    if (out.pins[0].trace_commitment.IsNull() ||
        out.pins[1].trace_commitment.IsNull() ||
        !DeriveRCStage3CtlChallenges(
            out.manifest, out.pins,
            challenges, why)) {
        return Fail(
            why, "digest_ctl_prove_challenges");
    }
    const auto producer_ctl =
        BuildRCStage3CtlDegree2Witness(
            out.producer_schedule,
            bus_values, challenges);
    const auto consumer_ctl =
        BuildRCStage3CtlDegree2Witness(
            out.consumer_schedule,
            bus_values, challenges);
    if (!producer_ctl.ok || !consumer_ctl.ok) {
        return Fail(
            why, "digest_ctl_prove_ctl_witness");
    }
    const uint256 challenge_commitment =
        CommitRCStage3CtlChallenges(challenges);
    for (auto& pin : out.pins) {
        pin.challenge_commitment =
            challenge_commitment;
    }
    out.pins[0].terminal =
        producer_ctl.terminal;
    out.pins[1].terminal =
        consumer_ctl.terminal;

    AirCS producer_product_cs;
    AirCS consumer_product_cs;
    RCStage3RelationCtlDegree2DirectAliasLayout
        producer_layout;
    RCStage3RelationCtlDegree2DirectAliasLayout
        consumer_layout;
    if (!BuildRCStage3RelationCtlDegree2DirectAliasConstraintSystem(
            producer_cs,
            {kRCStage3CtlDegree2Version,
             out.producer_schedule,
             challenges,
             producer_ctl.terminal},
            kRCStage3RootChainValue,
            producer_product_cs,
            &producer_layout, why) ||
        !BuildRCStage3RelationCtlDegree2DirectAliasConstraintSystem(
            consumer_cs,
            {kRCStage3CtlDegree2Version,
             out.consumer_schedule,
             challenges,
             consumer_ctl.terminal},
            kRCStage3EpisodeDigestBridgeExport,
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
                EpisodeDigestRoundRoots,
            ComputeRCStage3RootChainVectorSeed(
                root_chain.round_roots_pin),
            out.producer_schedule,
            challenges,
            producer_ctl.terminal,
            kRCStage3RootChainValue);
    const uint256 consumer_seed =
        ComputeRCStage3RelationCtlDirectAliasSeed(
            RCStage3RelationEndpoint::
                EpisodeDigestValue,
            DigestCtlBridgeSeed(out.bridge_pin),
            out.consumer_schedule,
            challenges,
            consumer_ctl.terminal,
            kRCStage3EpisodeDigestBridgeExport);
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
            why, "digest_ctl_prove_products");
    }
    out.producer_product =
        producer_proved.proof;
    out.consumer_product =
        consumer_proved.proof;
    out.producer_product_commitment =
        CommitDigestCtlProduct(
            out.producer_product);
    out.consumer_product_commitment =
        CommitDigestCtlProduct(
            out.consumer_product);
    out.pins[0].auxiliary_commitment =
        out.producer_product_commitment;
    out.pins[1].auxiliary_commitment =
        out.consumer_product_commitment;
    out.proof_commitment =
        CommitDigestCtlProof(out);
    if (out.proof_commitment.IsNull() ||
        !VerifyRCStage3CtlPublicPinComposition(
            out.manifest, out.pins, why)) {
        out = {};
        return Fail(
            why, "digest_ctl_prove_commitment_or_terminal");
    }
    if (why != nullptr) {
        *why =
            "stage3:episode_round_roots:"
            "endpoint23_value_equals_endpoint24_"
            "typed_preimage_bytes_via_same_trace_ctl";
    }
    return true;
}

bool VerifyRCStage3EpisodeRoundRootDigestCtl(
    const RCStage3SuccinctProof& statement,
    uint32_t expected_rounds,
    const RCStage3EpisodeDigestRootChainProof& root_chain,
    const RCStage3EpisodeRoundRootProducerProduct& producers,
    const RCStage3EpisodeRoundRootDigestCtlProof& proof,
    std::string* why)
{
    RCStage3EpisodeRoundRootDigestCtlPin expected_pin;
    if (proof.version !=
            kRCStage3EpisodeRoundRootDigestCtlVersion ||
        !VerifyRCStage3EpisodeDigestRootChainWithRoundRootProducers(
            statement, expected_rounds,
            root_chain, producers, why) ||
        !BuildDigestCtlPin(
            statement, root_chain,
            producers, expected_pin, why) ||
        proof.bridge_pin != expected_pin) {
        return Fail(
            why, "digest_ctl_verify_sources_or_pin");
    }
    const std::vector<uint8_t> root_bytes =
        RoundRootBytes(root_chain.manifest);
    std::vector<Fp3> bus_values(
        expected_pin.n_rows, Fp3::Zero());
    for (uint32_t row = 0;
         row < expected_pin.logical_rows; ++row) {
        bus_values[row] = U64(root_bytes[row]);
    }
    const RCStage3CtlSchedule producer_schedule =
        DigestCtlSchedule(expected_pin.n_rows, 1);
    const RCStage3CtlSchedule consumer_schedule =
        DigestCtlSchedule(expected_pin.n_rows, -1);
    RCStage3CtlManifest manifest;
    manifest.bus_id =
        kRCStage3EpisodeRoundRootDigestCtlBusId;
    manifest.transcript_seed =
        DigestCtlTranscriptSeed(expected_pin);
    manifest.participants = {
        DigestCtlParticipant(
            RCStage3RelationRole::EpisodeDigest,
            producer_schedule),
        DigestCtlParticipant(
            RCStage3RelationRole::CompositionLink,
            consumer_schedule),
    };
    if (proof.manifest != manifest ||
        proof.producer_schedule !=
            producer_schedule ||
        proof.consumer_schedule !=
            consumer_schedule ||
        proof.pins.size() != 2 ||
        proof.pins[0].trace_commitment !=
            ComputeRCStage3CtlDegree2PrechallengeTraceCommitment(
                producer_schedule, bus_values) ||
        proof.pins[1].trace_commitment !=
            ComputeRCStage3CtlDegree2PrechallengeTraceCommitment(
                consumer_schedule, bus_values)) {
        return Fail(
            why, "digest_ctl_verify_manifest_or_r0");
    }
    for (size_t index = 0;
         index < proof.pins.size(); ++index) {
        const auto& pin = proof.pins[index];
        const auto& participant =
            manifest.participants[index];
        if (pin.role != participant.role ||
            pin.bus_id != manifest.bus_id ||
            pin.event_count !=
                participant.event_count ||
            pin.send_count !=
                participant.send_count ||
            pin.receive_count !=
                participant.receive_count ||
            pin.schedule_commitment !=
                participant.schedule_commitment) {
            return Fail(
                why, "digest_ctl_verify_participant");
        }
    }
    RCStage3CtlChallenges challenges;
    if (!DeriveRCStage3CtlChallenges(
            proof.manifest, proof.pins,
            challenges, why)) {
        return false;
    }
    const uint256 challenge_commitment =
        CommitRCStage3CtlChallenges(challenges);
    if (proof.pins[0].challenge_commitment !=
            challenge_commitment ||
        proof.pins[1].challenge_commitment !=
            challenge_commitment) {
        return Fail(
            why, "digest_ctl_verify_challenges");
    }

    AirCS producer_cs;
    AirCS consumer_cs;
    AirCS producer_product_cs;
    AirCS consumer_product_cs;
    RCStage3RelationCtlDegree2DirectAliasLayout
        producer_layout;
    RCStage3RelationCtlDegree2DirectAliasLayout
        consumer_layout;
    if (!BuildRCStage3RootChainVectorConstraintSystem(
            root_chain.round_roots_pin,
            root_bytes, producer_cs, why) ||
        !BuildRCStage3EpisodeDigestPreimageByteBridgeConstraintSystem(
            expected_pin, root_bytes,
            consumer_cs, why) ||
        !BuildRCStage3RelationCtlDegree2DirectAliasConstraintSystem(
            producer_cs,
            {kRCStage3CtlDegree2Version,
             producer_schedule,
             challenges,
             proof.pins[0].terminal},
            kRCStage3RootChainValue,
            producer_product_cs,
            &producer_layout, why) ||
        !BuildRCStage3RelationCtlDegree2DirectAliasConstraintSystem(
            consumer_cs,
            {kRCStage3CtlDegree2Version,
             consumer_schedule,
             challenges,
             proof.pins[1].terminal},
            kRCStage3EpisodeDigestBridgeExport,
            consumer_product_cs,
            &consumer_layout, why)) {
        return false;
    }
    const auto shape_ok =
        [](const aq::AirQuotientProof<Fp3>& actual,
           const AirCS& cs) {
            return actual.batch.n_coeffs ==
                    cs.n_rows &&
                actual.batch.columns.size() ==
                    static_cast<size_t>(
                        cs.n_columns) + 1 &&
                actual.batch.column_len.size() ==
                    actual.batch.columns.size();
        };
    if (!shape_ok(
            proof.producer_product,
            producer_product_cs) ||
        !shape_ok(
            proof.consumer_product,
            consumer_product_cs) ||
        proof.producer_product.batch.columns[
            producer_layout.source_column].root !=
            expected_pin.value_root ||
        proof.producer_product.batch.columns[
            producer_layout.ctl_value_column].root !=
            expected_pin.value_root ||
        proof.consumer_product.batch.columns[
            consumer_layout.source_column].root !=
            expected_pin.value_root ||
        proof.consumer_product.batch.columns[
            consumer_layout.ctl_value_column].root !=
            expected_pin.value_root) {
        return Fail(
            why, "digest_ctl_verify_value_roots");
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
            producer_schedule, proof.pins[0],
            proof.producer_product,
            producer_layout) ||
        !trace_matches(
            consumer_schedule, proof.pins[1],
            proof.consumer_product,
            consumer_layout)) {
        return Fail(
            why, "digest_ctl_verify_trace_roots");
    }
    const uint256 producer_seed =
        ComputeRCStage3RelationCtlDirectAliasSeed(
            RCStage3RelationEndpoint::
                EpisodeDigestRoundRoots,
            ComputeRCStage3RootChainVectorSeed(
                root_chain.round_roots_pin),
            producer_schedule,
            challenges,
            proof.pins[0].terminal,
            kRCStage3RootChainValue);
    const uint256 consumer_seed =
        ComputeRCStage3RelationCtlDirectAliasSeed(
            RCStage3RelationEndpoint::
                EpisodeDigestValue,
            DigestCtlBridgeSeed(expected_pin),
            consumer_schedule,
            challenges,
            proof.pins[1].terminal,
            kRCStage3EpisodeDigestBridgeExport);
    std::string air_why;
    if (!aq::AirQuotientVerify<Fp3>(
            producer_product_cs,
            proof.producer_product,
            producer_seed, &air_why)) {
        return Fail(
            why, "digest_ctl_verify_producer:" +
                air_why);
    }
    if (!aq::AirQuotientVerify<Fp3>(
            consumer_product_cs,
            proof.consumer_product,
            consumer_seed, &air_why)) {
        return Fail(
            why, "digest_ctl_verify_consumer:" +
                air_why);
    }
    const uint256 producer_commitment =
        CommitDigestCtlProduct(
            proof.producer_product);
    const uint256 consumer_commitment =
        CommitDigestCtlProduct(
            proof.consumer_product);
    if (producer_commitment.IsNull() ||
        consumer_commitment.IsNull() ||
        proof.producer_product_commitment !=
            producer_commitment ||
        proof.consumer_product_commitment !=
            consumer_commitment ||
        proof.pins[0].auxiliary_commitment !=
            producer_commitment ||
        proof.pins[1].auxiliary_commitment !=
            consumer_commitment ||
        proof.proof_commitment !=
            CommitDigestCtlProof(proof) ||
        !VerifyRCStage3CtlPublicPinComposition(
            proof.manifest, proof.pins, why)) {
        return Fail(
            why, "digest_ctl_verify_commitment_or_terminal");
    }
    if (why != nullptr) {
        *why =
            "stage3:episode_round_roots:"
            "endpoint23_proof_owned_root_bytes_equal_"
            "endpoint24_typed_sha_preimage_bytes";
    }
    return true;
}

bool ProveRCStage3EpisodeTileTreeRootVectorCtl(
    const RCStage3SuccinctProof& statement,
    uint32_t expected_rounds,
    const RCStage3EpisodeDigestRootChainProof& root_chain,
    const RCStage3EpisodeRoundRootProducerProduct& producers,
    RCStage3EpisodeTileTreeRootVectorCtlProof& out,
    std::string* why)
{
    out = {};
    if (!VerifyRCStage3EpisodeDigestRootChainWithRoundRootProducers(
            statement, expected_rounds,
            root_chain, producers, why) ||
        !BuildTileRootCtlPin(
            statement, root_chain, producers,
            out.bridge_pin, why)) {
        return Fail(why, "tile_root_ctl_prove_sources");
    }
    const auto bytes = RoundRootBytes(root_chain.manifest);
    AirCS producer_cs;
    AirCS consumer_cs;
    std::vector<std::vector<Fp3>> producer_columns;
    std::vector<std::vector<Fp3>> consumer_columns;
    if (!BuildTileRootBridgeConstraintSystem(
            out.bridge_pin, bytes, producer_cs, why) ||
        !BuildTileRootBridgeColumns(
            out.bridge_pin, bytes, producer_cs,
            producer_columns) ||
        !BuildRCStage3RootChainVectorConstraintSystem(
            root_chain.round_roots_pin, bytes,
            consumer_cs, why) ||
        !BuildRootVectorColumns(
            root_chain.round_roots_pin, bytes,
            consumer_cs, consumer_columns)) {
        return Fail(why, "tile_root_ctl_prove_columns");
    }
    std::vector<Fp3> values(
        out.bridge_pin.n_rows, Fp3::Zero());
    for (uint32_t row = 0;
         row < out.bridge_pin.logical_rows; ++row) {
        values[row] = U64(bytes[row]);
    }
    out.producer_schedule =
        TileRootCtlSchedule(out.bridge_pin.n_rows, 1);
    out.consumer_schedule =
        TileRootCtlSchedule(out.bridge_pin.n_rows, -1);
    out.manifest.bus_id =
        kRCStage3EpisodeTileTreeRootVectorCtlBusId;
    out.manifest.transcript_seed =
        TileRootCtlTranscriptSeed(out.bridge_pin);
    out.manifest.participants = {
        TileRootCtlParticipant(
            RCStage3RelationRole::EpisodeTileTree,
            out.producer_schedule, true),
        TileRootCtlParticipant(
            RCStage3RelationRole::EpisodeDigest,
            out.consumer_schedule, false),
    };
    out.pins.resize(2);
    for (size_t i = 0; i < 2; ++i) {
        const auto& participant =
            out.manifest.participants[i];
        auto& pin = out.pins[i];
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
    if (!DeriveRCStage3CtlChallenges(
            out.manifest, out.pins, challenges, why)) {
        return Fail(why, "tile_root_ctl_prove_challenges");
    }
    const auto producer_ctl =
        BuildRCStage3CtlDegree2Witness(
            out.producer_schedule, values, challenges);
    const auto consumer_ctl =
        BuildRCStage3CtlDegree2Witness(
            out.consumer_schedule, values, challenges);
    if (!producer_ctl.ok || !consumer_ctl.ok) {
        return Fail(why, "tile_root_ctl_prove_witness");
    }
    const uint256 challenge_commitment =
        CommitRCStage3CtlChallenges(challenges);
    for (auto& pin : out.pins) {
        pin.challenge_commitment = challenge_commitment;
    }
    out.pins[0].terminal = producer_ctl.terminal;
    out.pins[1].terminal = consumer_ctl.terminal;

    AirCS producer_product_cs;
    AirCS consumer_product_cs;
    RCStage3RelationCtlDegree2DirectAliasLayout producer_layout;
    RCStage3RelationCtlDegree2DirectAliasLayout consumer_layout;
    if (!BuildRCStage3RelationCtlDegree2DirectAliasConstraintSystem(
            producer_cs,
            {kRCStage3CtlDegree2Version,
             out.producer_schedule, challenges,
             producer_ctl.terminal},
            TILE_BRIDGE_BYTE, producer_product_cs,
            &producer_layout, why) ||
        !BuildRCStage3RelationCtlDegree2DirectAliasConstraintSystem(
            consumer_cs,
            {kRCStage3CtlDegree2Version,
             out.consumer_schedule, challenges,
             consumer_ctl.terminal},
            kRCStage3RootChainValue, consumer_product_cs,
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
    const uint256 producer_seed =
        ComputeRCStage3RelationCtlDirectAliasSeed(
            RCStage3RelationEndpoint::EpisodeTileTreeRoot,
            TileRootBridgeSeed(out.bridge_pin),
            out.producer_schedule, challenges,
            producer_ctl.terminal, TILE_BRIDGE_BYTE);
    const uint256 consumer_seed =
        ComputeRCStage3RelationCtlDirectAliasSeed(
            RCStage3RelationEndpoint::EpisodeDigestRoundRoots,
            ComputeRCStage3RootChainVectorSeed(
                root_chain.round_roots_pin),
            out.consumer_schedule, challenges,
            consumer_ctl.terminal,
            kRCStage3RootChainValue);
    const auto producer_proved =
        aq::AirQuotientProve<Fp3>(
            producer_product_cs,
            producer_product_columns, producer_seed);
    const auto consumer_proved =
        aq::AirQuotientProve<Fp3>(
            consumer_product_cs,
            consumer_product_columns, consumer_seed);
    if (!producer_proved.ok ||
        !producer_proved.division_exact ||
        !consumer_proved.ok ||
        !consumer_proved.division_exact) {
        return Fail(why, "tile_root_ctl_prove_products");
    }
    out.producer_product = producer_proved.proof;
    out.consumer_product = consumer_proved.proof;
    out.producer_product_commitment =
        CommitDigestCtlProduct(out.producer_product);
    out.consumer_product_commitment =
        CommitDigestCtlProduct(out.consumer_product);
    out.pins[0].auxiliary_commitment =
        out.producer_product_commitment;
    out.pins[1].auxiliary_commitment =
        out.consumer_product_commitment;
    out.proof_commitment = CommitTileRootCtlProof(out);
    if (out.proof_commitment.IsNull() ||
        !VerifyRCStage3CtlPublicPinComposition(
            out.manifest, out.pins, why)) {
        out = {};
        return Fail(why, "tile_root_ctl_prove_commitment");
    }
    return true;
}

bool VerifyRCStage3EpisodeTileTreeRootVectorCtl(
    const RCStage3SuccinctProof& statement,
    uint32_t expected_rounds,
    const RCStage3EpisodeDigestRootChainProof& root_chain,
    const RCStage3EpisodeRoundRootProducerProduct& producers,
    const RCStage3EpisodeTileTreeRootVectorCtlProof& proof,
    std::string* why)
{
    RCStage3EpisodeRoundRootDigestCtlPin expected_pin;
    if (proof.version !=
            kRCStage3EpisodeRoundRootDigestCtlVersion ||
        !VerifyRCStage3EpisodeDigestRootChainWithRoundRootProducers(
            statement, expected_rounds,
            root_chain, producers, why) ||
        !BuildTileRootCtlPin(
            statement, root_chain, producers,
            expected_pin, why) ||
        proof.bridge_pin != expected_pin) {
        return Fail(why, "tile_root_ctl_verify_sources");
    }
    const auto bytes = RoundRootBytes(root_chain.manifest);
    std::vector<Fp3> values(
        expected_pin.n_rows, Fp3::Zero());
    for (uint32_t row = 0;
         row < expected_pin.logical_rows; ++row) {
        values[row] = U64(bytes[row]);
    }
    const auto producer_schedule =
        TileRootCtlSchedule(expected_pin.n_rows, 1);
    const auto consumer_schedule =
        TileRootCtlSchedule(expected_pin.n_rows, -1);
    RCStage3CtlManifest manifest;
    manifest.bus_id =
        kRCStage3EpisodeTileTreeRootVectorCtlBusId;
    manifest.transcript_seed =
        TileRootCtlTranscriptSeed(expected_pin);
    manifest.participants = {
        TileRootCtlParticipant(
            RCStage3RelationRole::EpisodeTileTree,
            producer_schedule, true),
        TileRootCtlParticipant(
            RCStage3RelationRole::EpisodeDigest,
            consumer_schedule, false),
    };
    if (proof.manifest != manifest ||
        proof.producer_schedule != producer_schedule ||
        proof.consumer_schedule != consumer_schedule ||
        proof.pins.size() != 2 ||
        proof.pins[0].trace_commitment !=
            ComputeRCStage3CtlDegree2PrechallengeTraceCommitment(
                producer_schedule, values) ||
        proof.pins[1].trace_commitment !=
            ComputeRCStage3CtlDegree2PrechallengeTraceCommitment(
                consumer_schedule, values)) {
        return Fail(why, "tile_root_ctl_verify_manifest");
    }
    for (size_t i = 0; i < 2; ++i) {
        const auto& participant = manifest.participants[i];
        const auto& pin = proof.pins[i];
        if (pin.role != participant.role ||
            pin.bus_id != manifest.bus_id ||
            pin.event_count != participant.event_count ||
            pin.send_count != participant.send_count ||
            pin.receive_count != participant.receive_count ||
            pin.schedule_commitment !=
                participant.schedule_commitment) {
            return Fail(why, "tile_root_ctl_verify_participant");
        }
    }
    RCStage3CtlChallenges challenges;
    if (!DeriveRCStage3CtlChallenges(
            proof.manifest, proof.pins,
            challenges, why)) {
        return false;
    }
    const uint256 challenge_commitment =
        CommitRCStage3CtlChallenges(challenges);
    if (proof.pins[0].challenge_commitment !=
            challenge_commitment ||
        proof.pins[1].challenge_commitment !=
            challenge_commitment) {
        return Fail(why, "tile_root_ctl_verify_challenges");
    }
    AirCS producer_cs;
    AirCS consumer_cs;
    AirCS producer_product_cs;
    AirCS consumer_product_cs;
    RCStage3RelationCtlDegree2DirectAliasLayout producer_layout;
    RCStage3RelationCtlDegree2DirectAliasLayout consumer_layout;
    if (!BuildTileRootBridgeConstraintSystem(
            expected_pin, bytes, producer_cs, why) ||
        !BuildRCStage3RootChainVectorConstraintSystem(
            root_chain.round_roots_pin, bytes,
            consumer_cs, why) ||
        !BuildRCStage3RelationCtlDegree2DirectAliasConstraintSystem(
            producer_cs,
            {kRCStage3CtlDegree2Version,
             producer_schedule, challenges,
             proof.pins[0].terminal},
            TILE_BRIDGE_BYTE, producer_product_cs,
            &producer_layout, why) ||
        !BuildRCStage3RelationCtlDegree2DirectAliasConstraintSystem(
            consumer_cs,
            {kRCStage3CtlDegree2Version,
             consumer_schedule, challenges,
             proof.pins[1].terminal},
            kRCStage3RootChainValue, consumer_product_cs,
            &consumer_layout, why)) {
        return false;
    }
    const auto shape_ok = [](
        const aq::AirQuotientProof<Fp3>& q,
        const AirCS& cs) {
        return q.batch.n_coeffs == cs.n_rows &&
            q.batch.columns.size() ==
                static_cast<size_t>(cs.n_columns) + 1 &&
            q.batch.column_len.size() ==
                q.batch.columns.size();
    };
    if (!shape_ok(proof.producer_product, producer_product_cs) ||
        !shape_ok(proof.consumer_product, consumer_product_cs) ||
        proof.producer_product.batch.columns[
            producer_layout.source_column].root !=
            expected_pin.value_root ||
        proof.producer_product.batch.columns[
            producer_layout.ctl_value_column].root !=
            expected_pin.value_root ||
        proof.consumer_product.batch.columns[
            consumer_layout.source_column].root !=
            expected_pin.value_root ||
        proof.consumer_product.batch.columns[
            consumer_layout.ctl_value_column].root !=
            expected_pin.value_root) {
        return Fail(why, "tile_root_ctl_verify_roots");
    }
    const auto trace_matches = [](
        const RCStage3CtlSchedule& schedule,
        const RCStage3CtlChildPin& pin,
        const aq::AirQuotientProof<Fp3>& product,
        const RCStage3RelationCtlDegree2DirectAliasLayout& layout) {
        std::array<uint256, 5> roots{};
        for (uint32_t column =
                 stage3_ctl_degree2_col::NAMESPACE;
             column <=
                 stage3_ctl_degree2_col::MULTIPLICITY;
             ++column) {
            roots[column] = product.batch.columns[
                layout.ctl_column_base + column].root;
        }
        return pin.trace_commitment ==
            ComputeRCStage3CtlDegree2PrechallengeTraceCommitmentFromRoots(
                schedule,
                product.batch.column_len[
                    layout.ctl_column_base],
                product.batch.n_coeffs, roots);
    };
    if (!trace_matches(
            producer_schedule, proof.pins[0],
            proof.producer_product, producer_layout) ||
        !trace_matches(
            consumer_schedule, proof.pins[1],
            proof.consumer_product, consumer_layout)) {
        return Fail(why, "tile_root_ctl_verify_trace");
    }
    const uint256 producer_seed =
        ComputeRCStage3RelationCtlDirectAliasSeed(
            RCStage3RelationEndpoint::EpisodeTileTreeRoot,
            TileRootBridgeSeed(expected_pin),
            producer_schedule, challenges,
            proof.pins[0].terminal, TILE_BRIDGE_BYTE);
    const uint256 consumer_seed =
        ComputeRCStage3RelationCtlDirectAliasSeed(
            RCStage3RelationEndpoint::EpisodeDigestRoundRoots,
            ComputeRCStage3RootChainVectorSeed(
                root_chain.round_roots_pin),
            consumer_schedule, challenges,
            proof.pins[1].terminal,
            kRCStage3RootChainValue);
    std::string air_why;
    if (!aq::AirQuotientVerify<Fp3>(
            producer_product_cs, proof.producer_product,
            producer_seed, &air_why) ||
        !aq::AirQuotientVerify<Fp3>(
            consumer_product_cs, proof.consumer_product,
            consumer_seed, &air_why)) {
        return Fail(why, "tile_root_ctl_verify_air:" + air_why);
    }
    const uint256 producer_commitment =
        CommitDigestCtlProduct(proof.producer_product);
    const uint256 consumer_commitment =
        CommitDigestCtlProduct(proof.consumer_product);
    if (producer_commitment.IsNull() ||
        consumer_commitment.IsNull() ||
        proof.producer_product_commitment !=
            producer_commitment ||
        proof.consumer_product_commitment !=
            consumer_commitment ||
        proof.pins[0].auxiliary_commitment !=
            producer_commitment ||
        proof.pins[1].auxiliary_commitment !=
            consumer_commitment ||
        proof.proof_commitment !=
            CommitTileRootCtlProof(proof) ||
        !VerifyRCStage3CtlPublicPinComposition(
            proof.manifest, proof.pins, why)) {
        return Fail(why, "tile_root_ctl_verify_commitment");
    }
    return true;
}

bool ProveRCStage3EpisodeRoundRootProducerProduct(
    const RCStage3SuccinctProof& statement,
    uint32_t expected_rounds,
    const RCStage3EpisodeDigestRootChainProof& root_chain,
    const std::vector<stage3_hash_air::TileTreeManifest>& trees,
    RCStage3EpisodeRoundRootProducerProduct& out,
    std::string* why)
{
    out = {};
    if (!IsEpisodeStatement(statement) ||
        expected_rounds == 0 ||
        trees.size() != expected_rounds ||
        root_chain.manifest.round_roots.size() != expected_rounds) {
        return Fail(why, "prove_shape");
    }
    out.statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    out.expected_rounds = expected_rounds;
    out.digest_manifest_commitment =
        root_chain.manifest.commitment;
    out.rounds.resize(expected_rounds);
    const auto program = stage3_hash_air::BuildCanonicalProgram(
        stage3_hash_air::ProgramKind::Sha256Compression);
    for (uint32_t i = 0; i < expected_rounds; ++i) {
        auto& round = out.rounds[i];
        round.round_index = i;
        round.tree_manifest = trees[i];
        if (round.tree_manifest.root !=
                root_chain.manifest.round_roots[i]) {
            out = {};
            return Fail(
                why, "prove_root_alias_" + std::to_string(i));
        }
        std::vector<
            stage3_hash_air::FixedProgramBoundaryInstance> boundaries;
        if (!stage3_hash_air::BuildTileTreeManifestBoundaryInstances(
                round.tree_manifest, boundaries, why) ||
            !stage3_hash_semantic::ProveFlatBoundaryProofBundle(
                RCStage3RelationEndpoint::EpisodeTileTreeRoot,
                out.statement_commitment,
                round.tree_manifest.commitment, program,
                boundaries, round.hash_bundle, why) ||
            !ProveRCStage3EpisodeHashSemanticBinding(
                statement,
                RCStage3RelationEndpoint::EpisodeTileTreeRoot,
                boundaries,
                stage3_hash_semantic::BoundaryPort::
                    ExternalThenFinal,
                round.hash_binding, why)) {
            out = {};
            return Fail(
                why, "prove_round_" + std::to_string(i));
        }
    }
    out.collection_commitment =
        ComputeRCStage3EpisodeRoundRootProducerCollectionCommitment(
            out);
    if (out.collection_commitment.IsNull() ||
        !VerifyRCStage3EpisodeDigestRootChainWithRoundRootProducers(
            statement, expected_rounds, root_chain, out, why)) {
        out = {};
        return Fail(why, "prove_self_verify");
    }
    return true;
}

bool ValidateRCStage3EpisodeRoundRootProducerSchedule(
    const RCStage3SuccinctProof& statement,
    uint32_t expected_rounds,
    const stage3_hash_air::EpisodeDigestManifest& digest_manifest,
    const RCStage3EpisodeRoundRootProducerProduct& product,
    std::string* why)
{
    const uint256 statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    if (!IsEpisodeStatement(statement) ||
        statement_commitment.IsNull() ||
        !ValidateRCStage3EpisodeDigestManifestStructural(
            digest_manifest, expected_rounds, why)) {
        return Fail(why, "public_statement_or_digest_manifest");
    }
    if (product.version !=
            kRCStage3EpisodeRoundRootProductVersion ||
        product.statement_commitment != statement_commitment ||
        product.expected_rounds != expected_rounds ||
        product.digest_manifest_commitment !=
            digest_manifest.commitment ||
        product.rounds.size() != expected_rounds) {
        return Fail(why, "product_shape");
    }
    for (uint32_t round_index = 0;
         round_index < expected_rounds; ++round_index) {
        const auto& round = product.rounds[round_index];
        if (round.round_index != round_index ||
            round.tree_manifest.commitment !=
                stage3_hash_air::CommitTileTreeManifest(
                    round.tree_manifest) ||
            round.tree_manifest.root.IsNull() ||
            round.tree_manifest.root !=
                digest_manifest.round_roots[round_index] ||
            round.hash_bundle.endpoint !=
                RCStage3RelationEndpoint::EpisodeTileTreeRoot ||
            round.hash_bundle.statement_commitment !=
                statement_commitment ||
            round.hash_bundle.manifest_commitment !=
                round.tree_manifest.commitment) {
            return Fail(
                why, "round_" + std::to_string(round_index) +
                         "_identity_or_root");
        }
    }
    const uint256 collection =
        ComputeRCStage3EpisodeRoundRootProducerCollectionCommitment(
            product);
    if (collection.IsNull() ||
        product.collection_commitment != collection) {
        return Fail(why, "collection_commitment");
    }
    return true;
}

bool VerifyRCStage3EpisodeRoundRootProducerProduct(
    const RCStage3SuccinctProof& statement,
    uint32_t expected_rounds,
    const stage3_hash_air::EpisodeDigestManifest& digest_manifest,
    const RCStage3RootChainVectorPin& round_roots_pin,
    const RCStage3RootChainVectorProof& round_roots_proof,
    const RCStage3EpisodeRoundRootProducerProduct& product,
    std::string* why)
{
    if (!ValidateRCStage3EpisodeRoundRootProducerSchedule(
            statement, expected_rounds, digest_manifest,
            product, why)) {
        return false;
    }

    std::vector<uint8_t> produced_root_bytes;
    produced_root_bytes.reserve(
        static_cast<size_t>(expected_rounds) * 32);
    for (uint32_t round_index = 0;
         round_index < expected_rounds; ++round_index) {
        const auto& round = product.rounds[round_index];
        if (!VerifyRCStage3EpisodeTileTreeSemantic(
                statement,
                RCStage3RelationEndpoint::EpisodeTileTreeRoot,
                round.tree_manifest, round.hash_bundle,
                round.hash_binding, why)) {
            return Fail(
                why, "round_" + std::to_string(round_index) +
                         "_tile_tree_proof");
        }
        AppendRootBytes(
            produced_root_bytes, round.tree_manifest.root);
    }

    const uint256 statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    if (!VerifyRCStage3RootChainVector(
            RCStage3RelationEndpoint::EpisodeDigestRoundRoots,
            statement_commitment, digest_manifest.commitment,
            produced_root_bytes, round_roots_pin,
            round_roots_proof, why)) {
        return Fail(why, "round_root_vector_proof");
    }
    if (why != nullptr) {
        *why =
            "stage3:episode_round_roots:all_round_tile_tree_roots_"
            "executed_and_equal_to_digest_vector;"
            "tile_stream_producer_and_recursion_pending";
    }
    return true;
}

bool VerifyRCStage3EpisodeDigestRootChainWithRoundRootProducers(
    const RCStage3SuccinctProof& statement,
    uint32_t expected_rounds,
    const RCStage3EpisodeDigestRootChainProof& root_chain,
    const RCStage3EpisodeRoundRootProducerProduct& producers,
    std::string* why)
{
    if (!VerifyRCStage3EpisodeRoundRootProducerProduct(
            statement, expected_rounds, root_chain.manifest,
            root_chain.round_roots_pin,
            root_chain.round_roots_proof, producers, why)) {
        return false;
    }
    if (!VerifyRCStage3EpisodeDigestRootChain(
            statement, expected_rounds, root_chain, why)) {
        return Fail(why, "downstream_digest_root_chain");
    }
    if (why != nullptr) {
        *why =
            "stage3:episode_round_roots:producer_and_digest_chain_ok;"
            "tile_stream_producer_and_recursion_pending";
    }
    return true;
}

RCStage3EpisodeRoundRootProducerAudit
CurrentRCStage3EpisodeRoundRootProducerAudit()
{
    RCStage3EpisodeRoundRootProducerAudit out;
    out.verifier_ordered_round_schedule = true;
    out.all_tile_tree_hash_children_executed = true;
    out.tile_root_to_digest_vector_equality = true;
    out.immediate_producer_link_executable = true;
    out.proof_owned_digest_vector_executed = true;
    out.tile_root_to_round_vector_ctl_executable = true;
    out.round_root_to_digest_preimage_ctl_executable = true;
    out.downstream_digest_chain_composable = true;
    out.local_relation_complete = true;
    out.upstream_tile_stream_equality = false;
    out.recursively_consumed = false;
    out.transitively_complete = false;
    out.remaining =
        "tile-tree stream bytes are not yet equality-bound to every "
        "executed Extract output; endpoint-22 to 23 and 23 to 24 CTLs "
        "execute but are not yet recursively consumed";
    return out;
}

static_assert(
    kRCStage3EpisodeRoundRootProducerLocalRelationExecutable);
static_assert(
    !kRCStage3EpisodeRoundRootProducerTransitivelyComplete);

} // namespace matmul::v4::rc
