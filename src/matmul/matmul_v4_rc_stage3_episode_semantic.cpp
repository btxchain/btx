// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_episode_semantic.h>

#include <hash.h>
#include <matmul/matmul_v4_rc_stage3_role_bytecode.h>

#include <algorithm>
#include <array>
#include <limits>

namespace matmul::v4::rc {
namespace {

using Fp3 = gkr_field::Fp3;
using T = air_quotient::AirField<Fp3>;
using AirCS = air_quotient::AirConstraintSystem<Fp3>;

constexpr char SCHEDULE_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_SEMANTIC_MEMORY_SCHEDULE_V1";
constexpr char MANIFEST_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_SEMANTIC_MEMORY_MANIFEST_V1";
constexpr char SEED_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_SEMANTIC_MEMORY_AIR_V1";
constexpr char POW_PIN_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_POW_PIN_V1";
constexpr char POW_SEED_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_POW_AIR_V1";
constexpr char MEMORY_BUNDLE_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_SEMANTIC_MEMORY_BUNDLE_V1";

bool Fail(std::string* why, const std::string& message)
{
    if (why != nullptr) *why = "stage3:episode_semantic:" + message;
    return false;
}

uint32_t NextPowerOfTwo(uint32_t value)
{
    uint32_t out = 2;
    while (out < value) out <<= 1;
    return out;
}

bool IsPowerOfTwo(uint32_t value)
{
    return value >= 2 && (value & (value - 1)) == 0;
}

Fp3 U64(uint64_t value)
{
    return T::FromU64(value);
}

uint256 ScheduleCommitment(
    RCStage3RelationEndpoint endpoint,
    RCStage3RelationRole role,
    uint64_t instance_count,
    uint32_t logical_rows,
    uint32_t n_rows,
    uint64_t address_begin,
    uint64_t address_stride)
{
    HashWriter hash;
    hash << SCHEDULE_DOMAIN;
    hash << kRCStage3EpisodeSemanticMemoryVersion;
    hash << static_cast<uint16_t>(endpoint);
    hash << static_cast<uint16_t>(role);
    hash << instance_count;
    hash << logical_rows;
    hash << n_rows;
    hash << address_begin;
    hash << address_stride;
    return hash.GetHash();
}

uint256 ManifestCommitment(
    const RCStage3EpisodeSemanticMemoryManifest& manifest)
{
    HashWriter hash;
    hash << MANIFEST_DOMAIN;
    hash << manifest.magic;
    hash << manifest.version;
    hash << static_cast<uint16_t>(manifest.endpoint);
    hash << static_cast<uint16_t>(manifest.role);
    hash << manifest.statement_commitment;
    hash << manifest.instance_count;
    hash << manifest.logical_rows;
    hash << manifest.n_rows;
    hash << manifest.address_begin;
    hash << manifest.address_stride;
    hash << manifest.canonical_value_root;
    hash << manifest.schedule_commitment;
    return hash.GetHash();
}

uint256 PowPinCommitment(const RCStage3EpisodePowPin& pin)
{
    HashWriter hash;
    hash << POW_PIN_DOMAIN;
    hash << pin.version;
    hash << pin.statement_commitment;
    hash << pin.episode_digest;
    hash << pin.target;
    return hash.GetHash();
}

bool ValidatePowPin(const RCStage3EpisodePowPin& pin, std::string* why)
{
    if (pin.version != kRCStage3EpisodeSemanticMemoryVersion ||
        pin.statement_commitment.IsNull() ||
        pin.pin_commitment != PowPinCommitment(pin)) {
        return Fail(why, "pow:pin");
    }
    return true;
}

uint64_t HashSemanticAddressBegin(
    RCStage3RelationEndpoint endpoint,
    stage3_hash_semantic::BoundaryPort port)
{
    return UINT64_C(0x4550000000000000) |
           (static_cast<uint64_t>(
                static_cast<uint16_t>(endpoint)) << 32) |
           (static_cast<uint64_t>(
                static_cast<uint8_t>(port)) << 24);
}

bool IsEpisodeStatement(const RCStage3SuccinctProof& statement)
{
    return statement.statement == RCStage3StatementKind::Episode ||
           statement.statement == RCStage3StatementKind::Composed;
}

bool VerifyHashSemanticMemoryBinding(
    const RCStage3SuccinctProof& statement,
    RCStage3RelationEndpoint endpoint,
    const std::vector<
        stage3_hash_air::FixedProgramBoundaryInstance>& boundaries,
    const RCStage3EpisodeHashSemanticBinding& binding,
    std::string* why)
{
    if (binding.port !=
        stage3_hash_semantic::BoundaryPort::ExternalThenFinal) {
        return Fail(why, "hash_binding:port");
    }
    const uint256 statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    if (statement_commitment.IsNull()) {
        return Fail(why, "hash_binding:statement");
    }
    const auto expected =
        BuildRCStage3EpisodeHashSemanticMemoryManifest(
            statement, endpoint, boundaries, binding.port, why);
    if (!expected.has_value() ||
        binding.memory_manifest != *expected) {
        return Fail(why, "hash_binding:memory_manifest");
    }
    if (!VerifyRCStage3EpisodeSemanticMemory(
            statement_commitment, binding.memory_manifest,
            binding.memory_proof, why)) {
        return false;
    }
    return true;
}

std::vector<Fp3> PaddedValues(
    const std::vector<Fp3>& values,
    uint32_t logical_rows,
    uint32_t n_rows)
{
    std::vector<Fp3> out(n_rows, Fp3::Zero());
    std::copy_n(values.begin(), logical_rows, out.begin());
    return out;
}

std::string EndpointGap(RCStage3RelationEndpoint endpoint)
{
    using E = RCStage3RelationEndpoint;
    switch (endpoint) {
    case E::EpisodeBuilderParams:
        return "consensus-regenerated endpoint-1 product executes; normalized recursive consumption remains";
    case E::EpisodeBuilderSeedChain:
        return "all ordered single-SHA seed steps execute; later-round root ancestry and normalized recursion remain";
    case E::EpisodeBuilderOperandXof:
        return "bounded counter-XOF product executes; production counter-range streaming and normalized recursion remain";
    case E::EpisodeBuilderTrace:
        return "builder subproofs are not yet recursively joined into the canonical trace root";
    case E::EpisodeGemmOperandA:
    case E::EpisodeGemmOperandB:
        return "the local GEMM cell AIR exists, but its root-authenticated memory proof is not yet composed with every manifest layer";
    case E::EpisodeGemmOutputY:
        return "the local product cell and memory opening exist, but complete sumcheck aggregation is absent";
    case E::EpisodeGemmSumcheck:
        return "the full manifest-derived batched sumcheck verifier is not executable end-to-end";
    case E::EpisodeGemmSignedRange:
        return "native relation-to-two-CTL VALUE-root equality executes; normalized recursive consumption remains";
    case E::EpisodeExtractInput:
        return "all bounded input openings execute; GEMM producer equality and production recursive streaming remain";
    case E::EpisodeExtractSampler:
        return "all bounded sampler walks and input/output aliases execute; producer ancestry and recursion remain";
    case E::EpisodeExtractChaCha:
        return "every bounded ChaCha consumption child executes; normalized recursive aggregation remains";
    case E::EpisodeExtractScale:
        return "every bounded scale SHA child executes; normalized recursive aggregation remains";
    case E::EpisodeExtractOutput:
        return "bounded dequant outputs equal endpoint-19 inputs; GEMM ancestry and production recursion remain";
    case E::EpisodeWiringCopy:
        return "row equality exists, but the complete immutable copy-edge product is not executed";
    case E::EpisodeWiringTranspose:
        return "the complete transpose permutation product is not executed";
    case E::EpisodeWiringResidual:
        return "the signed residual-add relation is not executed for every manifest edge";
    case E::EpisodeWiringRoundOrder:
        return "the full round/layer state-machine transition relation is not executed";
    case E::EpisodeTileTreeStream:
        return "complete bounded emission schedule is proof-owned and same-trace CTL joined to all canonical leaf-preimage bytes; upstream Extract ancestry and normalized recursion remain";
    case E::EpisodeTileTreeLeafHash:
        return "every bounded canonical leaf child executes and its preimage bytes are same-trace CTL joined to endpoint 19; leaf-output to internal-input CTL and normalized recursion remain";
    case E::EpisodeTileTreeInternalHash:
        return "every bounded canonical internal child executes; normalized recursive aggregation remains";
    case E::EpisodeTileTreeRoot:
        return "leaf/internal children reduce to the canonical root; upstream Extract ancestry and recursion remain";
    case E::EpisodeDigestRoundRoots:
        return "the exact endpoint-22 root-byte stream is same-trace CTL joined through endpoint 23 to the typed episode-digest preimage; leaf/internal tile-tree ancestry and normalized recursion remain";
    case E::EpisodeDigestValue:
        return "endpoint-23 bytes are same-trace CTL joined to the typed SHA256d preimage and endpoint-24 output is same-trace CTL joined to endpoint 26; tile-tree ancestry and normalized recursion remain";
    case E::EpisodeDigestHeaderTarget:
        return "consensus-bound header/nBits/target product executes; normalized recursive consumption remains";
    case E::EpisodeDigestPow:
        return "the statement-pinned 256-bit comparison AIR executes and its DIGEST_BYTE/TARGET_BYTE columns are same-trace dual-LogUp aliases of endpoints 24/25; endpoint-24 ancestry and normalized recursive consumption remain";
    default:
        return "not an episode endpoint";
    }
}

} // namespace

std::optional<RCStage3RelationRole>
RCStage3EpisodeEndpointRole(RCStage3RelationEndpoint endpoint)
{
    const uint16_t id = static_cast<uint16_t>(endpoint);
    if (id >= 1 && id <= 4) {
        return RCStage3RelationRole::EpisodeDeterministicBuilder;
    }
    if (id >= 5 && id <= 9) {
        return RCStage3RelationRole::EpisodeGemm;
    }
    if (id >= 10 && id <= 14) {
        return RCStage3RelationRole::EpisodeExtract;
    }
    if (id >= 15 && id <= 18) {
        return RCStage3RelationRole::EpisodeWiring;
    }
    if (id >= 19 && id <= 22) {
        return RCStage3RelationRole::EpisodeTileTree;
    }
    if (id >= 23 && id <= 26) {
        return RCStage3RelationRole::EpisodeDigest;
    }
    return std::nullopt;
}

std::optional<uint256> ComputeRCStage3EpisodeSemanticValueRoot(
    const std::vector<Fp3>& values,
    uint32_t logical_rows,
    uint32_t n_rows,
    std::string* why)
{
    if (logical_rows == 0 ||
        logical_rows > kRCStage3EpisodeSemanticMaxRows ||
        values.size() != logical_rows) {
        Fail(why, "value_root:logical_rows");
        return std::nullopt;
    }
    if (!IsPowerOfTwo(n_rows) ||
        n_rows != NextPowerOfTwo(logical_rows) ||
        n_rows > kRCStage3EpisodeSemanticMaxRows) {
        Fail(why, "value_root:n_rows");
        return std::nullopt;
    }
    const auto padded = PaddedValues(values, logical_rows, n_rows);
    return air_quotient::AirCommittedValuesRoot<Fp3>(padded, n_rows);
}

std::optional<RCStage3EpisodeSemanticMemoryManifest>
BuildRCStage3EpisodeSemanticMemoryManifest(
    RCStage3RelationEndpoint endpoint,
    const uint256& statement_commitment,
    uint64_t instance_count,
    uint32_t logical_rows,
    uint64_t address_begin,
    uint64_t address_stride,
    const uint256& canonical_value_root,
    std::string* why)
{
    const auto role = RCStage3EpisodeEndpointRole(endpoint);
    if (!role.has_value()) {
        Fail(why, "manifest:endpoint");
        return std::nullopt;
    }
    if (statement_commitment.IsNull() || canonical_value_root.IsNull()) {
        Fail(why, "manifest:null_root");
        return std::nullopt;
    }
    if (logical_rows == 0 ||
        logical_rows > kRCStage3EpisodeSemanticMaxRows ||
        instance_count != logical_rows ||
        address_stride == 0) {
        Fail(why, "manifest:shape");
        return std::nullopt;
    }
    const uint32_t n_rows = NextPowerOfTwo(logical_rows);
    const uint64_t last_index = logical_rows - 1;
    if (last_index >
            (std::numeric_limits<uint64_t>::max() - address_begin) /
                address_stride) {
        Fail(why, "manifest:address_overflow");
        return std::nullopt;
    }

    RCStage3EpisodeSemanticMemoryManifest out;
    out.endpoint = endpoint;
    out.role = *role;
    out.statement_commitment = statement_commitment;
    out.instance_count = instance_count;
    out.logical_rows = logical_rows;
    out.n_rows = n_rows;
    out.address_begin = address_begin;
    out.address_stride = address_stride;
    out.canonical_value_root = canonical_value_root;
    out.schedule_commitment = ScheduleCommitment(
        out.endpoint, out.role, out.instance_count, out.logical_rows,
        out.n_rows, out.address_begin, out.address_stride);
    out.manifest_commitment = ManifestCommitment(out);
    if (!ValidateRCStage3EpisodeSemanticMemoryManifest(out, why)) {
        return std::nullopt;
    }
    return out;
}

bool ValidateRCStage3EpisodeSemanticMemoryManifest(
    const RCStage3EpisodeSemanticMemoryManifest& manifest,
    std::string* why)
{
    if (manifest.magic != kRCStage3EpisodeSemanticMemoryMagic ||
        manifest.version != kRCStage3EpisodeSemanticMemoryVersion) {
        return Fail(why, "manifest:format");
    }
    const auto role = RCStage3EpisodeEndpointRole(manifest.endpoint);
    if (!role.has_value() || manifest.role != *role) {
        return Fail(why, "manifest:role");
    }
    if (manifest.statement_commitment.IsNull() ||
        manifest.canonical_value_root.IsNull() ||
        manifest.logical_rows == 0 ||
        manifest.logical_rows > kRCStage3EpisodeSemanticMaxRows ||
        manifest.instance_count != manifest.logical_rows ||
        !IsPowerOfTwo(manifest.n_rows) ||
        manifest.n_rows != NextPowerOfTwo(manifest.logical_rows) ||
        manifest.n_rows > kRCStage3EpisodeSemanticMaxRows ||
        manifest.address_stride == 0) {
        return Fail(why, "manifest:shape");
    }
    const uint64_t last_index = manifest.logical_rows - 1;
    if (last_index >
            (std::numeric_limits<uint64_t>::max() -
             manifest.address_begin) /
                manifest.address_stride) {
        return Fail(why, "manifest:address_overflow");
    }
    if (manifest.schedule_commitment != ScheduleCommitment(
            manifest.endpoint, manifest.role, manifest.instance_count,
            manifest.logical_rows, manifest.n_rows,
            manifest.address_begin, manifest.address_stride)) {
        return Fail(why, "manifest:schedule_commitment");
    }
    if (manifest.manifest_commitment != ManifestCommitment(manifest)) {
        return Fail(why, "manifest:commitment");
    }
    return true;
}

bool BuildRCStage3EpisodeSemanticMemoryConstraintSystem(
    const RCStage3EpisodeSemanticMemoryManifest& manifest,
    AirCS& out,
    std::string* why)
{
    if (!ValidateRCStage3EpisodeSemanticMemoryManifest(manifest, why)) {
        return false;
    }
    out = {};
    constraint_bytecode::ProgramTable table;
    if (!BuildRCStage3EpisodeSemanticMemoryProgramTable(
            manifest.role, table, why) ||
        table.current_width !=
            kRCStage3EpisodeMemoryColumns ||
        !constraint_bytecode::
            BuildAirConstraintSystemFromProgramTable(
                table, manifest.n_rows, out, why)) {
        return Fail(why, "memory:bytecode");
    }

    std::vector<Fp3> active(out.n_rows, Fp3::Zero());
    std::vector<Fp3> address(out.n_rows, Fp3::Zero());
    std::vector<Fp3> remaining(out.n_rows, Fp3::Zero());
    std::vector<Fp3> endpoint(
        out.n_rows, U64(static_cast<uint16_t>(manifest.endpoint)));
    std::vector<Fp3> role(
        out.n_rows, U64(static_cast<uint16_t>(manifest.role)));
    for (uint32_t row = 0; row < manifest.logical_rows; ++row) {
        active[row] = Fp3::One();
        address[row] =
            U64(manifest.address_begin + row * manifest.address_stride);
        remaining[row] = U64(manifest.logical_rows - row);
    }
    out.preprocessed.emplace_back(
        kRCStage3EpisodeMemoryActive, std::move(active));
    out.preprocessed.emplace_back(
        kRCStage3EpisodeMemoryAddress, std::move(address));
    out.preprocessed.emplace_back(
        kRCStage3EpisodeMemoryRemaining, std::move(remaining));
    out.preprocessed.emplace_back(
        kRCStage3EpisodeMemoryEndpoint, std::move(endpoint));
    out.preprocessed.emplace_back(
        kRCStage3EpisodeMemoryRole, std::move(role));
    out.preprocessed_roots.emplace_back(
        kRCStage3EpisodeMemoryValue, manifest.canonical_value_root);

    return true;
}

bool BuildRCStage3EpisodeSemanticMemoryWitness(
    const RCStage3EpisodeSemanticMemoryManifest& manifest,
    const std::vector<Fp3>& values,
    std::vector<std::vector<Fp3>>& out,
    std::string* why)
{
    AirCS cs;
    if (!BuildRCStage3EpisodeSemanticMemoryConstraintSystem(
            manifest, cs, why)) {
        return false;
    }
    const auto root = ComputeRCStage3EpisodeSemanticValueRoot(
        values, manifest.logical_rows, manifest.n_rows, why);
    if (!root.has_value() || *root != manifest.canonical_value_root) {
        return Fail(why, "witness:canonical_value_root");
    }
    out.assign(
        kRCStage3EpisodeMemoryColumns,
        std::vector<Fp3>(manifest.n_rows, Fp3::Zero()));
    for (const auto& [column, canonical] : cs.preprocessed) {
        out[column] = canonical;
    }
    out[kRCStage3EpisodeMemoryValue] =
        PaddedValues(values, manifest.logical_rows, manifest.n_rows);
    out[kRCStage3EpisodeMemoryExport] =
        out[kRCStage3EpisodeMemoryValue];
    return true;
}

uint256 ComputeRCStage3EpisodeSemanticMemorySeed(
    const RCStage3EpisodeSemanticMemoryManifest& manifest)
{
    if (!ValidateRCStage3EpisodeSemanticMemoryManifest(manifest, nullptr)) {
        return {};
    }
    HashWriter hash;
    hash << SEED_DOMAIN;
    hash << kRCStage3EpisodeSemanticMemoryVersion;
    hash << manifest.manifest_commitment;
    hash << manifest.statement_commitment;
    hash << manifest.schedule_commitment;
    hash << manifest.canonical_value_root;
    return hash.GetHash();
}

bool ProveRCStage3EpisodeSemanticMemory(
    const RCStage3EpisodeSemanticMemoryManifest& manifest,
    const std::vector<Fp3>& values,
    RCStage3EpisodeSemanticMemoryProof& out,
    std::string* why)
{
    out = {};
    AirCS cs;
    std::vector<std::vector<Fp3>> columns;
    if (!BuildRCStage3EpisodeSemanticMemoryConstraintSystem(
            manifest, cs, why) ||
        !BuildRCStage3EpisodeSemanticMemoryWitness(
            manifest, values, columns, why)) {
        return false;
    }
    const uint256 seed =
        ComputeRCStage3EpisodeSemanticMemorySeed(manifest);
    const auto proved =
        air_quotient::AirQuotientProve<Fp3>(cs, columns, seed);
    if (!proved.ok || !proved.division_exact) {
        return Fail(why, "prove:" + proved.note);
    }
    out.version = kRCStage3EpisodeSemanticMemoryVersion;
    out.manifest_commitment = manifest.manifest_commitment;
    out.quotient = proved.proof;
    return true;
}

bool VerifyRCStage3EpisodeSemanticMemory(
    const uint256& expected_statement_commitment,
    const RCStage3EpisodeSemanticMemoryManifest& manifest,
    const RCStage3EpisodeSemanticMemoryProof& proof,
    std::string* why)
{
    if (!ValidateRCStage3EpisodeSemanticMemoryManifest(manifest, why)) {
        return false;
    }
    if (expected_statement_commitment.IsNull() ||
        manifest.statement_commitment != expected_statement_commitment) {
        return Fail(why, "verify:statement_commitment");
    }
    if (proof.version != kRCStage3EpisodeSemanticMemoryVersion ||
        proof.manifest_commitment != manifest.manifest_commitment) {
        return Fail(why, "verify:proof_manifest");
    }
    if (proof.quotient.batch.n_coeffs != manifest.n_rows ||
        proof.quotient.batch.columns.size() !=
            kRCStage3EpisodeMemoryColumns + 1) {
        return Fail(why, "verify:proof_shape");
    }
    if (proof.quotient.batch
            .columns[kRCStage3EpisodeMemoryValue].root !=
        manifest.canonical_value_root) {
        return Fail(why, "verify:value_root");
    }
    if (proof.quotient.batch
            .columns[kRCStage3EpisodeMemoryExport].root !=
        manifest.canonical_value_root) {
        return Fail(why, "verify:export_root");
    }
    AirCS cs;
    if (!BuildRCStage3EpisodeSemanticMemoryConstraintSystem(
            manifest, cs, why)) {
        return false;
    }
    std::string air_why;
    if (!air_quotient::AirQuotientVerify<Fp3>(
            cs, proof.quotient,
            ComputeRCStage3EpisodeSemanticMemorySeed(manifest),
            &air_why)) {
        return Fail(why, "verify:air:" + air_why);
    }
    return true;
}

bool BuildRCStage3EpisodeSemanticMemoryShardManifests(
    RCStage3RelationEndpoint endpoint,
    const uint256& statement_commitment,
    uint64_t total_instance_count,
    uint64_t address_begin,
    uint64_t address_stride,
    const std::vector<uint256>& canonical_value_roots,
    std::vector<RCStage3EpisodeSemanticMemoryShard>& out,
    std::string* why)
{
    out.clear();
    if (!RCStage3EpisodeEndpointRole(endpoint).has_value() ||
        statement_commitment.IsNull() ||
        total_instance_count == 0 ||
        address_stride == 0) {
        return Fail(why, "shards:shape");
    }
    const uint64_t max_total =
        uint64_t{kRCStage3EpisodeSemanticMaxRows} *
        kRCStage3EpisodeSemanticMaxRows;
    if (total_instance_count > max_total) {
        return Fail(why, "shards:total_limit");
    }
    const uint64_t shard_count64 =
        (total_instance_count +
         kRCStage3EpisodeSemanticMaxRows - 1) /
        kRCStage3EpisodeSemanticMaxRows;
    if (shard_count64 == 0 ||
        shard_count64 > kRCStage3EpisodeSemanticMaxRows ||
        canonical_value_roots.size() != shard_count64) {
        return Fail(why, "shards:root_count");
    }
    if ((total_instance_count - 1) >
            (std::numeric_limits<uint64_t>::max() -
             address_begin) /
                address_stride) {
        return Fail(why, "shards:address_overflow");
    }
    out.reserve(static_cast<size_t>(shard_count64));
    uint64_t value_begin = 0;
    for (uint32_t shard_index = 0;
         shard_index < shard_count64; ++shard_index) {
        const uint32_t logical_rows = static_cast<uint32_t>(
            std::min<uint64_t>(
                kRCStage3EpisodeSemanticMaxRows,
                total_instance_count - value_begin));
        const uint64_t shard_address =
            address_begin + value_begin * address_stride;
        const auto manifest =
            BuildRCStage3EpisodeSemanticMemoryManifest(
                endpoint, statement_commitment,
                logical_rows, logical_rows,
                shard_address, address_stride,
                canonical_value_roots[shard_index], why);
        if (!manifest.has_value()) return false;
        RCStage3EpisodeSemanticMemoryShard shard;
        shard.shard_index = shard_index;
        shard.value_begin = value_begin;
        shard.manifest = *manifest;
        out.push_back(std::move(shard));
        value_begin += logical_rows;
    }
    if (value_begin != total_instance_count) {
        return Fail(why, "shards:coverage");
    }
    return true;
}

uint256 ComputeRCStage3EpisodeSemanticMemoryBundleCommitment(
    const RCStage3EpisodeSemanticMemoryBundle& bundle)
{
    HashWriter hash;
    hash << MEMORY_BUNDLE_DOMAIN;
    hash << bundle.version;
    hash << static_cast<uint16_t>(bundle.endpoint);
    hash << bundle.statement_commitment;
    hash << bundle.total_instance_count;
    hash << bundle.address_begin;
    hash << bundle.address_stride;
    hash << static_cast<uint32_t>(bundle.shards.size());
    for (const auto& shard : bundle.shards) {
        hash << shard.shard_index;
        hash << shard.value_begin;
        hash << shard.manifest.manifest_commitment;
        hash << shard.manifest.canonical_value_root;
        hash << shard.proof.version;
        hash << shard.proof.manifest_commitment;
        hash << shard.proof.quotient.trace_commit;
        hash << shard.proof.quotient.batch.version;
        hash << shard.proof.quotient.batch.blowup;
        hash << shard.proof.quotient.batch.n_coeffs;
        hash << static_cast<uint32_t>(
            shard.proof.quotient.batch.columns.size());
        for (const auto& column :
             shard.proof.quotient.batch.columns) {
            hash << column.root;
        }
        hash << static_cast<uint32_t>(
            shard.proof.quotient.batch.column_len.size());
        for (uint32_t length :
             shard.proof.quotient.batch.column_len) {
            hash << length;
        }
    }
    return hash.GetHash();
}

bool ProveRCStage3EpisodeSemanticMemoryBundle(
    RCStage3RelationEndpoint endpoint,
    const uint256& statement_commitment,
    uint64_t address_begin,
    uint64_t address_stride,
    const std::vector<Fp3>& values,
    RCStage3EpisodeSemanticMemoryBundle& out,
    std::string* why)
{
    out = {};
    if (values.empty() ||
        values.size() >
            uint64_t{kRCStage3EpisodeSemanticMaxRows} *
                kRCStage3EpisodeSemanticMaxRows) {
        return Fail(why, "bundle_prove:value_count");
    }
    const uint64_t total = values.size();
    const uint64_t shard_count =
        (total + kRCStage3EpisodeSemanticMaxRows - 1) /
        kRCStage3EpisodeSemanticMaxRows;
    std::vector<uint256> roots;
    roots.reserve(static_cast<size_t>(shard_count));
    uint64_t value_begin = 0;
    while (value_begin < total) {
        const uint32_t logical_rows = static_cast<uint32_t>(
            std::min<uint64_t>(
                kRCStage3EpisodeSemanticMaxRows,
                total - value_begin));
        std::vector<Fp3> shard_values(
            values.begin() + value_begin,
            values.begin() + value_begin + logical_rows);
        const auto root =
            ComputeRCStage3EpisodeSemanticValueRoot(
                shard_values, logical_rows,
                NextPowerOfTwo(logical_rows), why);
        if (!root.has_value()) return false;
        roots.push_back(*root);
        value_begin += logical_rows;
    }

    out.version = kRCStage3EpisodeSemanticMemoryVersion;
    out.endpoint = endpoint;
    out.statement_commitment = statement_commitment;
    out.total_instance_count = total;
    out.address_begin = address_begin;
    out.address_stride = address_stride;
    if (!BuildRCStage3EpisodeSemanticMemoryShardManifests(
            endpoint, statement_commitment, total,
            address_begin, address_stride, roots,
            out.shards, why)) {
        out = {};
        return false;
    }
    for (auto& shard : out.shards) {
        std::vector<Fp3> shard_values(
            values.begin() + shard.value_begin,
            values.begin() + shard.value_begin +
                shard.manifest.logical_rows);
        if (!ProveRCStage3EpisodeSemanticMemory(
                shard.manifest, shard_values,
                shard.proof, why)) {
            out = {};
            return false;
        }
    }
    out.bundle_commitment =
        ComputeRCStage3EpisodeSemanticMemoryBundleCommitment(out);
    return !out.bundle_commitment.IsNull() ||
           Fail(why, "bundle_prove:null_commitment");
}

bool VerifyRCStage3EpisodeSemanticMemoryBundle(
    RCStage3RelationEndpoint expected_endpoint,
    const uint256& expected_statement_commitment,
    uint64_t expected_total_instance_count,
    uint64_t expected_address_begin,
    uint64_t expected_address_stride,
    const std::vector<uint256>& expected_canonical_value_roots,
    const RCStage3EpisodeSemanticMemoryBundle& bundle,
    std::string* why)
{
    if (bundle.version !=
            kRCStage3EpisodeSemanticMemoryVersion ||
        bundle.endpoint != expected_endpoint ||
        bundle.statement_commitment !=
            expected_statement_commitment ||
        bundle.total_instance_count !=
            expected_total_instance_count ||
        bundle.address_begin != expected_address_begin ||
        bundle.address_stride != expected_address_stride ||
        expected_total_instance_count == 0 ||
        expected_address_stride == 0) {
        return Fail(why, "bundle_verify:public_shape");
    }
    const uint64_t shard_count =
        (expected_total_instance_count +
         kRCStage3EpisodeSemanticMaxRows - 1) /
        kRCStage3EpisodeSemanticMaxRows;
    if (bundle.shards.size() != shard_count) {
        return Fail(why, "bundle_verify:shard_count");
    }
    if (expected_canonical_value_roots.size() != shard_count) {
        return Fail(why, "bundle_verify:root_count");
    }
    std::vector<RCStage3EpisodeSemanticMemoryShard> expected;
    if (!BuildRCStage3EpisodeSemanticMemoryShardManifests(
            expected_endpoint, expected_statement_commitment,
            expected_total_instance_count,
            expected_address_begin, expected_address_stride,
            expected_canonical_value_roots, expected, why)) {
        return false;
    }
    for (uint32_t i = 0; i < bundle.shards.size(); ++i) {
        const auto& actual = bundle.shards[i];
        if (actual.shard_index != expected[i].shard_index ||
            actual.value_begin != expected[i].value_begin ||
            actual.manifest != expected[i].manifest) {
            return Fail(why, "bundle_verify:partition");
        }
        if (!VerifyRCStage3EpisodeSemanticMemory(
                expected_statement_commitment,
                actual.manifest, actual.proof, why)) {
            return false;
        }
    }
    if (bundle.bundle_commitment !=
        ComputeRCStage3EpisodeSemanticMemoryBundleCommitment(
            bundle)) {
        return Fail(why, "bundle_verify:commitment");
    }
    return true;
}

std::optional<RCStage3EpisodePowPin>
BuildRCStage3EpisodePowPin(
    const RCStage3SuccinctProof& statement,
    std::string* why)
{
    if (statement.statement != RCStage3StatementKind::Episode &&
        statement.statement != RCStage3StatementKind::Composed) {
        Fail(why, "pow:statement_kind");
        return std::nullopt;
    }
    RCStage3EpisodePowPin out;
    out.statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    if (out.statement_commitment.IsNull()) {
        Fail(why, "pow:statement_commitment");
        return std::nullopt;
    }
    out.episode_digest = statement.public_inputs.episode_digest;
    out.target = statement.public_inputs.target;
    out.pin_commitment = PowPinCommitment(out);
    return out;
}

bool BuildRCStage3EpisodePowConstraintSystem(
    const RCStage3EpisodePowPin& pin,
    AirCS& out,
    std::string* why)
{
    if (!ValidatePowPin(pin, why)) return false;
    constraint_bytecode::ProgramTable table;
    if (!BuildRCStage3EpisodePowProgramTable(
            table, why) ||
        table.current_width !=
            kRCStage3EpisodePowColumns ||
        !constraint_bytecode::
            BuildAirConstraintSystemFromProgramTable(
                table, kRCStage3EpisodePowRows,
                out, why)) {
        return Fail(why, "pow:bytecode");
    }

    std::vector<Fp3> digest(kRCStage3EpisodePowRows);
    std::vector<Fp3> target(kRCStage3EpisodePowRows);
    for (uint32_t row = 0; row < kRCStage3EpisodePowRows; ++row) {
        // uint256 stores its arithmetic representation least-significant
        // byte first.  The borrow chain therefore advances in row order.
        digest[row] = U64(pin.episode_digest.data()[row]);
        target[row] = U64(pin.target.data()[row]);
    }
    out.preprocessed.emplace_back(
        kRCStage3EpisodePowDigestByte, std::move(digest));
    out.preprocessed.emplace_back(
        kRCStage3EpisodePowTargetByte, std::move(target));
    return true;
}

bool BuildRCStage3EpisodePowWitness(
    const RCStage3EpisodePowPin& pin,
    std::vector<std::vector<Fp3>>& out,
    std::string* why)
{
    AirCS cs;
    if (!BuildRCStage3EpisodePowConstraintSystem(pin, cs, why)) {
        return false;
    }
    out.assign(
        kRCStage3EpisodePowColumns,
        std::vector<Fp3>(kRCStage3EpisodePowRows, Fp3::Zero()));
    for (const auto& [column, canonical] : cs.preprocessed) {
        out[column] = canonical;
    }
    uint32_t borrow = 0;
    for (uint32_t row = 0; row < kRCStage3EpisodePowRows; ++row) {
        const int32_t raw =
            static_cast<int32_t>(pin.target.data()[row]) -
            static_cast<int32_t>(pin.episode_digest.data()[row]) -
            static_cast<int32_t>(borrow);
        const uint32_t borrow_out = raw < 0 ? 1U : 0U;
        const uint32_t difference =
            static_cast<uint32_t>(raw + 256 * borrow_out);
        out[kRCStage3EpisodePowBorrow][row] = U64(borrow);
        out[kRCStage3EpisodePowBorrowOut][row] = U64(borrow_out);
        for (uint32_t bit = 0; bit < 8; ++bit) {
            out[kRCStage3EpisodePowDiffBitBase + bit][row] =
                U64((difference >> bit) & 1U);
        }
        borrow = borrow_out;
    }
    return true;
}

uint256 ComputeRCStage3EpisodePowSeed(
    const RCStage3EpisodePowPin& pin)
{
    if (!ValidatePowPin(pin, nullptr)) return {};
    HashWriter hash;
    hash << POW_SEED_DOMAIN;
    hash << kRCStage3EpisodeSemanticMemoryVersion;
    hash << pin.pin_commitment;
    return hash.GetHash();
}

bool ProveRCStage3EpisodePow(
    const RCStage3SuccinctProof& statement,
    RCStage3EpisodePowProof& out,
    std::string* why)
{
    out = {};
    const auto pin = BuildRCStage3EpisodePowPin(statement, why);
    if (!pin.has_value()) return false;
    AirCS cs;
    std::vector<std::vector<Fp3>> columns;
    if (!BuildRCStage3EpisodePowConstraintSystem(*pin, cs, why) ||
        !BuildRCStage3EpisodePowWitness(*pin, columns, why)) {
        return false;
    }
    const auto proved = air_quotient::AirQuotientProve<Fp3>(
        cs, columns, ComputeRCStage3EpisodePowSeed(*pin));
    if (!proved.ok || !proved.division_exact) {
        return Fail(why, "pow:prove:" + proved.note);
    }
    out.version = kRCStage3EpisodeSemanticMemoryVersion;
    out.pin_commitment = pin->pin_commitment;
    out.quotient = proved.proof;
    return true;
}

bool VerifyRCStage3EpisodePow(
    const RCStage3SuccinctProof& statement,
    const RCStage3EpisodePowPin& pin,
    const RCStage3EpisodePowProof& proof,
    std::string* why)
{
    const auto expected = BuildRCStage3EpisodePowPin(statement, why);
    if (!expected.has_value() || pin != *expected) {
        return Fail(why, "pow:public_pin");
    }
    if (proof.version != kRCStage3EpisodeSemanticMemoryVersion ||
        proof.pin_commitment != pin.pin_commitment) {
        return Fail(why, "pow:proof_pin");
    }
    AirCS cs;
    if (!BuildRCStage3EpisodePowConstraintSystem(pin, cs, why)) {
        return false;
    }
    std::string air_why;
    if (!air_quotient::AirQuotientVerify<Fp3>(
            cs, proof.quotient,
            ComputeRCStage3EpisodePowSeed(pin), &air_why)) {
        return Fail(why, "pow:verify:" + air_why);
    }
    return true;
}

std::optional<RCStage3EpisodeSemanticMemoryManifest>
BuildRCStage3EpisodeHashSemanticMemoryManifest(
    const RCStage3SuccinctProof& statement,
    RCStage3RelationEndpoint endpoint,
    const std::vector<
        stage3_hash_air::FixedProgramBoundaryInstance>& boundaries,
    stage3_hash_semantic::BoundaryPort port,
    std::string* why)
{
    if (!IsEpisodeStatement(statement) ||
        !RCStage3EpisodeEndpointRole(endpoint).has_value() ||
        (port != stage3_hash_semantic::BoundaryPort::External &&
         port != stage3_hash_semantic::BoundaryPort::Final &&
         port !=
             stage3_hash_semantic::BoundaryPort::ExternalThenFinal)) {
        Fail(why, "hash_manifest:shape");
        return std::nullopt;
    }
    uint256 root;
    uint32_t logical_rows{0};
    uint32_t n_rows{0};
    if (!stage3_hash_semantic::ComputeCanonicalBoundaryValueRoot(
            boundaries, port, root, logical_rows, n_rows, why)) {
        return std::nullopt;
    }
    const auto manifest =
        BuildRCStage3EpisodeSemanticMemoryManifest(
            endpoint, RCStage3EpisodeStatementCommitment(statement),
            logical_rows, logical_rows,
            HashSemanticAddressBegin(endpoint, port), 1, root, why);
    if (!manifest.has_value() || manifest->n_rows != n_rows) {
        Fail(why, "hash_manifest:n_rows");
        return std::nullopt;
    }
    return manifest;
}

bool ProveRCStage3EpisodeHashSemanticBinding(
    const RCStage3SuccinctProof& statement,
    RCStage3RelationEndpoint endpoint,
    const std::vector<
        stage3_hash_air::FixedProgramBoundaryInstance>& boundaries,
    stage3_hash_semantic::BoundaryPort port,
    RCStage3EpisodeHashSemanticBinding& out,
    std::string* why)
{
    out = {};
    const auto manifest =
        BuildRCStage3EpisodeHashSemanticMemoryManifest(
            statement, endpoint, boundaries, port, why);
    std::vector<Fp3> values;
    if (!manifest.has_value() ||
        !stage3_hash_semantic::BuildCanonicalBoundaryValues(
            boundaries, port, values, why)) {
        return Fail(why, "hash_binding_prove:manifest");
    }
    out.port = port;
    out.memory_manifest = *manifest;
    if (!ProveRCStage3EpisodeSemanticMemory(
            out.memory_manifest, values, out.memory_proof, why)) {
        out = {};
        return Fail(why, "hash_binding_prove:memory");
    }
    return true;
}

bool VerifyRCStage3EpisodeHashSemanticBinding(
    const RCStage3SuccinctProof& statement,
    RCStage3RelationEndpoint endpoint,
    const std::vector<
        stage3_hash_air::FixedProgramBoundaryInstance>& boundaries,
    const RCStage3EpisodeHashSemanticBinding& binding,
    std::string* why)
{
    return VerifyHashSemanticMemoryBinding(
        statement, endpoint, boundaries, binding, why);
}

bool VerifyRCStage3EpisodeShaSemantic(
    const RCStage3SuccinctProof& statement,
    RCStage3RelationEndpoint endpoint,
    const stage3_hash_air::ShaManifest& manifest,
    const stage3_hash_semantic::FlatBoundaryProofBundle& hash_bundle,
    const RCStage3EpisodeHashSemanticBinding& binding,
    std::string* why)
{
    if (endpoint !=
            RCStage3RelationEndpoint::EpisodeBuilderSeedChain &&
        endpoint !=
            RCStage3RelationEndpoint::EpisodeExtractScale) {
        return Fail(why, "sha:endpoint");
    }
    std::vector<stage3_hash_air::FixedProgramBoundaryInstance>
        boundaries;
    if (!stage3_hash_air::BuildShaManifestBoundaryInstances(
            manifest, boundaries, why) ||
        !stage3_hash_semantic::VerifyShaManifestBundle(
            endpoint, manifest, hash_bundle, why)) {
        return false;
    }
    return VerifyHashSemanticMemoryBinding(
        statement, endpoint, boundaries, binding, why);
}

bool VerifyRCStage3EpisodeCounterXofSemantic(
    const RCStage3SuccinctProof& statement,
    RCStage3RelationEndpoint endpoint,
    const stage3_hash_air::CounterXofManifest& manifest,
    const stage3_hash_semantic::FlatBoundaryProofBundle& hash_bundle,
    const RCStage3EpisodeHashSemanticBinding& binding,
    std::string* why)
{
    if (endpoint !=
            RCStage3RelationEndpoint::EpisodeBuilderSeedChain &&
        endpoint !=
            RCStage3RelationEndpoint::EpisodeBuilderOperandXof) {
        return Fail(why, "counter_xof:endpoint");
    }
    std::vector<stage3_hash_air::FixedProgramBoundaryInstance>
        boundaries;
    if (!stage3_hash_air::BuildCounterXofManifestBoundaryInstances(
            manifest, boundaries, why) ||
        !stage3_hash_semantic::VerifyCounterXofManifestBundle(
            endpoint, manifest, hash_bundle, why)) {
        return false;
    }
    return VerifyHashSemanticMemoryBinding(
        statement, endpoint, boundaries, binding, why);
}

bool VerifyRCStage3EpisodeChaChaSemantic(
    const RCStage3SuccinctProof& statement,
    RCStage3RelationEndpoint endpoint,
    const stage3_hash_air::ChaChaConsumptionManifest& manifest,
    const stage3_hash_semantic::FlatBoundaryProofBundle& hash_bundle,
    const RCStage3EpisodeHashSemanticBinding& binding,
    std::string* why)
{
    if (endpoint !=
            RCStage3RelationEndpoint::EpisodeBuilderOperandXof &&
        endpoint !=
            RCStage3RelationEndpoint::EpisodeExtractChaCha) {
        return Fail(why, "chacha:endpoint");
    }
    std::vector<stage3_hash_air::FixedProgramBoundaryInstance>
        boundaries;
    if (!stage3_hash_air::BuildChaChaManifestBoundaryInstances(
            manifest, boundaries, why) ||
        !stage3_hash_semantic::VerifyChaChaManifestBundle(
            endpoint, manifest, hash_bundle, why)) {
        return false;
    }
    return VerifyHashSemanticMemoryBinding(
        statement, endpoint, boundaries, binding, why);
}

bool VerifyRCStage3EpisodeTileTreeSemantic(
    const RCStage3SuccinctProof& statement,
    RCStage3RelationEndpoint endpoint,
    const stage3_hash_air::TileTreeManifest& manifest,
    const stage3_hash_semantic::FlatBoundaryProofBundle& hash_bundle,
    const RCStage3EpisodeHashSemanticBinding& binding,
    std::string* why)
{
    const uint16_t id = static_cast<uint16_t>(endpoint);
    if (id <
            static_cast<uint16_t>(
                RCStage3RelationEndpoint::EpisodeTileTreeStream) ||
        id >
            static_cast<uint16_t>(
                RCStage3RelationEndpoint::EpisodeTileTreeRoot)) {
        return Fail(why, "tile_tree:endpoint");
    }
    std::vector<stage3_hash_air::FixedProgramBoundaryInstance>
        boundaries;
    if (!stage3_hash_air::BuildTileTreeManifestBoundaryInstances(
            manifest, boundaries, why) ||
        !stage3_hash_semantic::VerifyTileTreeManifestBundle(
            endpoint, manifest, hash_bundle, why)) {
        return false;
    }
    return VerifyHashSemanticMemoryBinding(
        statement, endpoint, boundaries, binding, why);
}

bool VerifyRCStage3EpisodeDirectSha256dSemantic(
    const RCStage3SuccinctProof& statement,
    RCStage3RelationEndpoint endpoint,
    const stage3_hash_air::DirectSha256dManifest& manifest,
    const stage3_hash_semantic::FlatBoundaryProofBundle& hash_bundle,
    const RCStage3EpisodeHashSemanticBinding& binding,
    std::string* why)
{
    if (endpoint != RCStage3RelationEndpoint::EpisodeDigestValue) {
        return Fail(why, "direct_sha256d:endpoint");
    }
    std::vector<stage3_hash_air::FixedProgramBoundaryInstance>
        boundaries;
    if (!stage3_hash_air::BuildDirectSha256dManifestBoundaryInstances(
            manifest, boundaries, why) ||
        !stage3_hash_semantic::VerifyDirectSha256dManifestBundle(
            endpoint, manifest, hash_bundle, why)) {
        return false;
    }
    return VerifyHashSemanticMemoryBinding(
        statement, endpoint, boundaries, binding, why);
}

std::vector<RCStage3EpisodeSemanticEndpointAudit>
CurrentRCStage3EpisodeSemanticEndpointAudit()
{
    std::vector<RCStage3EpisodeSemanticEndpointAudit> out;
    out.reserve(kRCStage3EpisodeSemanticEndpointCount);
    for (uint16_t id = 1;
         id <= kRCStage3EpisodeSemanticEndpointCount; ++id) {
        const auto endpoint =
            static_cast<RCStage3RelationEndpoint>(id);
        const auto role = RCStage3EpisodeEndpointRole(endpoint);
        RCStage3EpisodeSemanticEndpointAudit audit;
        audit.endpoint = endpoint;
        audit.role = *role;
        audit.canonical_schedule_executable = true;
        audit.proof_owned_memory_executable = true;
        audit.canonical_root_authenticated = true;
        audit.same_trace_export_constrained = true;
        audit.recursively_consumed = false;

        switch (endpoint) {
        case RCStage3RelationEndpoint::EpisodeGemmOperandA:
        case RCStage3RelationEndpoint::EpisodeGemmOperandB:
        case RCStage3RelationEndpoint::EpisodeGemmOutputY:
            audit.local_semantic_air_available = true;
            audit.source = "episode_air:gemm_endpoint_fp3 + semantic_memory_v1";
            break;
        case RCStage3RelationEndpoint::EpisodeGemmSignedRange:
            audit.local_semantic_air_available = true;
            audit.semantic_relation_complete = true;
            audit.source =
                "gemm_extract:signed_range + executed_dual_ctl + semantic_memory_v1";
            break;
        case RCStage3RelationEndpoint::EpisodeExtractSampler:
        case RCStage3RelationEndpoint::EpisodeExtractOutput:
            audit.local_semantic_air_available = true;
            audit.source =
                "episode_air:extract_sampler_core_fp3 + semantic_memory_v1";
            break;
        case RCStage3RelationEndpoint::EpisodeWiringCopy:
            audit.local_semantic_air_available = true;
            audit.source =
                "episode_air:wiring_equality_fp3 + semantic_memory_v1";
            break;
        case RCStage3RelationEndpoint::EpisodeDigestPow:
            audit.local_semantic_air_available = true;
            audit.semantic_relation_complete = true;
            audit.source =
                "episode_semantic:256_bit_borrow_comparison_air + "
                "root_chain:endpoint24_25_to_26_degree2_direct_alias_ctl";
            break;
        case RCStage3RelationEndpoint::EpisodeBuilderSeedChain:
        case RCStage3RelationEndpoint::EpisodeBuilderOperandXof:
        case RCStage3RelationEndpoint::EpisodeExtractChaCha:
        case RCStage3RelationEndpoint::EpisodeTileTreeLeafHash:
        case RCStage3RelationEndpoint::EpisodeTileTreeInternalHash:
        case RCStage3RelationEndpoint::EpisodeDigestValue:
            audit.local_semantic_air_available = true;
            audit.source =
                "hash_air:fixed_program_provenance + semantic_memory_v1";
            break;
        default:
            audit.source = "semantic_memory_v1";
            break;
        }
        audit.remaining = EndpointGap(endpoint);
        out.push_back(std::move(audit));
    }
    return out;
}

} // namespace matmul::v4::rc
