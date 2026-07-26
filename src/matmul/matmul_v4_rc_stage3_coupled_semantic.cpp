// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_coupled_semantic.h>

#include <hash.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>

namespace matmul::v4::rc {
namespace {

namespace aq = air_quotient;
namespace gf = gkr_field;
namespace ha = stage3_hash_air;
namespace hs = stage3_hash_semantic;
using gf::Fp3;
using CS = aq::AirConstraintSystem<Fp3>;
using Constraint = aq::AirConstraint<Fp3>;

constexpr char SCHEDULE_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_SEMANTIC_SCHEDULE_V1";
constexpr char MEMORY_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_SEMANTIC_MEMORY_V1";
constexpr char PROOF_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_SEMANTIC_PROOF_V1";
constexpr char HASH_SCHEDULE_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_HASH_SEMANTIC_SCHEDULE_V1";
constexpr char SHARD_SCHEDULE_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_SEMANTIC_SHARD_SCHEDULE_V1";
constexpr char FLAT_BUNDLE_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_SEMANTIC_FLAT_BUNDLE_V1";

bool Fail(std::string* why, const std::string& message)
{
    if (why != nullptr) *why = "stage3:coupled_semantic:" + message;
    return false;
}

bool IsCoupledEndpoint(RCStage3RelationEndpoint endpoint)
{
    const auto id = static_cast<uint16_t>(endpoint);
    return id >= 27 && id <= 52;
}

bool IsCanonical(const Fp3& value)
{
    return value.c0 < gf::kP && value.c1 < gf::kP && value.c2 < gf::kP;
}

void HashFp3(HashWriter& hash, const Fp3& value)
{
    hash << gf::Canonical(value.c0);
    hash << gf::Canonical(value.c1);
    hash << gf::Canonical(value.c2);
}

std::vector<Fp3> Slice(const std::vector<Fp3>& row,
                       uint32_t offset,
                       uint32_t count)
{
    if (offset > row.size() || count > row.size() - offset) return {};
    return {row.begin() + offset, row.begin() + offset + count};
}

void CopyConstraints(const CS& source, CS& destination)
{
    for (const auto& constraint : source.constraints) {
        Constraint copy;
        copy.name = constraint.name;
        copy.kind = constraint.kind;
        copy.alg_degree = constraint.alg_degree;
        copy.eval =
            [eval = constraint.eval, columns = source.n_columns](
                const std::vector<Fp3>& current,
                const std::vector<Fp3>& next) {
                return eval(Slice(current, 0, columns),
                            Slice(next, 0, columns));
            };
        destination.constraints.push_back(std::move(copy));
    }
    destination.preprocessed = source.preprocessed;
    destination.preprocessed_roots = source.preprocessed_roots;
}

RCStage3RelationRole EndpointRole(RCStage3RelationEndpoint endpoint)
{
    using E = RCStage3RelationEndpoint;
    switch (endpoint) {
    case E::CoupledBankSeedXof:
    case E::CoupledBankPages:
    case E::CoupledBankRoot:
        return RCStage3RelationRole::CoupledBank;
    case E::CoupledGemmOperandA:
    case E::CoupledGemmOperandB:
    case E::CoupledGemmOutputY:
    case E::CoupledGemmSignedRange:
        return RCStage3RelationRole::CoupledGemm;
    case E::CoupledExchangeInput:
    case E::CoupledExchangeHashXof:
    case E::CoupledExchangeOutput:
        return RCStage3RelationRole::CoupledExchange;
    case E::CoupledPermutationInput:
    case E::CoupledPermutationOutput:
        return RCStage3RelationRole::CoupledPermutation;
    case E::CoupledMixInput:
    case E::CoupledMixArithmetic:
    case E::CoupledMixOutput:
        return RCStage3RelationRole::CoupledMix;
    case E::CoupledExtractInput:
    case E::CoupledExtractSampler:
    case E::CoupledExtractChaCha:
    case E::CoupledExtractScale:
    case E::CoupledExtractOutput:
        return RCStage3RelationRole::CoupledExtract;
    case E::CoupledBarrierInput:
    case E::CoupledBarrierHash:
    case E::CoupledBarrierOutput:
        return RCStage3RelationRole::CoupledBarrier;
    case E::CoupledDigestBankAndBarriers:
    case E::CoupledDigestHash:
    case E::CoupledDigestValue:
        return RCStage3RelationRole::CoupledDigest;
    default:
        return RCStage3RelationRole::EpisodeDeterministicBuilder;
    }
}

std::vector<uint32_t> Inclusive(uint32_t begin, uint32_t end)
{
    std::vector<uint32_t> out;
    for (uint32_t i = begin; i <= end; ++i) out.push_back(i);
    return out;
}

std::vector<uint32_t> EndpointSources(RCStage3RelationEndpoint endpoint)
{
    using E = RCStage3RelationEndpoint;
    using namespace coupled_air_col;
    switch (endpoint) {
    case E::CoupledBankPages:
        // Entire nibble, table result, scale and dequant tuple.
        return Inclusive(BANK_NIB, BANK_OUT);
    case E::CoupledGemmOperandA: return {GEMM_A};
    case E::CoupledGemmOperandB: return {GEMM_B};
    case E::CoupledGemmOutputY: return {GEMM_ACC, GEMM_OUT};
    case E::CoupledExchangeInput:
    case E::CoupledPermutationInput:
        return {COPY_INPUT};
    case E::CoupledExchangeOutput:
    case E::CoupledPermutationOutput:
        return {COPY_OUTPUT};
    case E::CoupledMixInput:
        return Inclusive(MIX_A_LIMB, MIX_B_LIMB + 3U);
    case E::CoupledMixArithmetic:
        return Inclusive(MIX_SUM_LIMB, MIX_BORROW + 3U);
    case E::CoupledMixOutput:
        return Inclusive(MIX_SUM_LIMB, MIX_DIFF_LIMB + 3U);
    case E::CoupledExtractInput:
        return {aq::kColUMix, aq::kColGoldQ, aq::kColGoldV,
                aq::kColVLow28, aq::kColVb0, aq::kColVb1,
                aq::kColVb2, aq::kColVb3};
    case E::CoupledExtractSampler:
        return Inclusive(aq::kColAct, aq::kColVb3);
    case E::CoupledExtractScale:
        return {aq::kColE0, aq::kColE1};
    case E::CoupledExtractOutput:
        return {aq::kColMuOut, aq::kColOut};
    default:
        return {};
    }
}

uint256 ScheduleCommitment(
    RCStage3RelationEndpoint endpoint,
    RCStage3RelationRole role,
    const RCStage3CoupledAirRequest& request,
    uint64_t instances,
    uint32_t relation_rows,
    const std::vector<uint32_t>& sources)
{
    if (!IsCoupledEndpoint(endpoint) || sources.empty() ||
        request.role != role || instances == 0 || relation_rows < 2) {
        return {};
    }
    HashWriter hash;
    hash << SCHEDULE_DOMAIN;
    hash << kRCStage3CoupledSemanticVersion;
    hash << static_cast<uint16_t>(endpoint);
    hash << static_cast<uint16_t>(role);
    hash << CommitRCStage3CoupledShape(request.shape);
    hash << instances;
    hash << relation_rows;
    hash << static_cast<uint32_t>(sources.size());
    for (uint32_t source : sources) hash << source;
    hash << request.extract_scale_e;
    HashFp3(hash, request.gamma);
    HashFp3(hash, request.alpha);
    return hash.GetHash();
}

bool FullVector(RCStage3RelationEndpoint endpoint)
{
    using E = RCStage3RelationEndpoint;
    switch (endpoint) {
    case E::CoupledBankPages:
    case E::CoupledGemmOperandA:
    case E::CoupledGemmOperandB:
    case E::CoupledGemmOutputY:
    case E::CoupledExchangeInput:
    case E::CoupledExchangeOutput:
    case E::CoupledPermutationInput:
    case E::CoupledPermutationOutput:
    case E::CoupledMixInput:
    case E::CoupledMixArithmetic:
    case E::CoupledMixOutput:
    case E::CoupledExtractInput:
    case E::CoupledExtractSampler:
    case E::CoupledExtractScale:
    case E::CoupledExtractOutput:
        return true;
    default:
        return false;
    }
}

bool HashChildAvailable(RCStage3RelationEndpoint endpoint)
{
    using E = RCStage3RelationEndpoint;
    switch (endpoint) {
    case E::CoupledBankSeedXof:
    case E::CoupledExchangeHashXof:
    case E::CoupledExtractChaCha:
    case E::CoupledBarrierHash:
    case E::CoupledDigestHash:
        return true;
    default:
        return false;
    }
}

std::string MissingRelation(RCStage3RelationEndpoint endpoint)
{
    using E = RCStage3RelationEndpoint;
    switch (endpoint) {
    case E::CoupledBankSeedXof:
        return "all SHA-XOF boundary proofs and memory root execute; bank-page consumer root-chain equality remains";
    case E::CoupledBankRoot:
        return "complete page-to-bank AlgHash/SHA commitment tree child is absent";
    case E::CoupledGemmSignedRange:
        return "coupled GEMM A/B/Y columns lack complete signed-bit/range lookup children";
    case E::CoupledExchangeHashXof:
        return "all SHA-XOF boundary proofs and memory root execute; exchange input/output root-chain equality remains";
    case E::CoupledExtractChaCha:
        return "all ChaCha boundary proofs and memory root execute; KAPPA-to-sampler cross-trace equality remains";
    case E::CoupledBarrierInput:
        return "Extract output vector is not yet consumed by a complete barrier-hash child";
    case E::CoupledBarrierHash:
        return "all SHA256d boundary proofs and memory root execute; barrier input/output root-chain equality remains";
    case E::CoupledBarrierOutput:
        return "barrier digest words are not yet equality-linked into the next barrier and digest roles";
    case E::CoupledDigestBankAndBarriers:
        return "bank/barrier roots are not all recursively consumed by the digest child";
    case E::CoupledDigestHash:
        return "all SHA256d boundary proofs and memory root execute; bank/barrier/digest root-chain equality remains";
    case E::CoupledDigestValue:
        return "digest output is not yet equality-linked to the public coupled digest";
    default:
        return "all scheduled instances still require recursive child aggregation";
    }
}

bool IsHashSemanticEndpoint(RCStage3RelationEndpoint endpoint)
{
    using E = RCStage3RelationEndpoint;
    return endpoint == E::CoupledBankSeedXof ||
           endpoint == E::CoupledExchangeHashXof ||
           endpoint == E::CoupledExtractChaCha ||
           endpoint == E::CoupledBarrierHash ||
           endpoint == E::CoupledDigestHash;
}

uint256 HashScheduleCommitment(
    RCStage3RelationEndpoint endpoint,
    const RCStage3CoupledShape& shape,
    const uint256& manifest_commitment,
    hs::BoundaryPort port,
    uint64_t instances,
    uint32_t logical_rows,
    uint32_t n_rows)
{
    if (!IsHashSemanticEndpoint(endpoint) ||
        manifest_commitment.IsNull() || instances == 0 ||
        logical_rows == 0 || n_rows < logical_rows ||
        (n_rows & (n_rows - 1U)) != 0) {
        return {};
    }
    HashWriter hash;
    hash << HASH_SCHEDULE_DOMAIN;
    hash << kRCStage3CoupledSemanticVersion;
    hash << static_cast<uint16_t>(endpoint);
    hash << static_cast<uint16_t>(EndpointRole(endpoint));
    hash << CommitRCStage3CoupledShape(shape);
    hash << manifest_commitment;
    hash << static_cast<uint8_t>(port);
    hash << instances;
    hash << logical_rows;
    hash << n_rows;
    return hash.GetHash();
}

bool VerifyHashPinCommon(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const std::vector<ha::FixedProgramBoundaryInstance>& boundaries,
    const uint256& manifest_commitment,
    const hs::FlatBoundaryProofBundle& bundle,
    const RCStage3CoupledHashSemanticPin& pin,
    std::string* why)
{
    if (!IsHashSemanticEndpoint(pin.endpoint) ||
        pin.version != kRCStage3CoupledSemanticVersion ||
        pin.statement_commitment !=
            CommitRCStage3CoupledStatement(statement.public_inputs) ||
        bundle.statement_commitment != pin.statement_commitment ||
        bundle.endpoint != pin.endpoint ||
        bundle.manifest_commitment != manifest_commitment ||
        pin.manifest_commitment != manifest_commitment ||
        pin.shape_commitment != CommitRCStage3CoupledShape(shape)) {
        return Fail(why, "hash:public_pin");
    }
    RCStage3CoupledHashSemanticPin expected;
    if (!BuildRCStage3CoupledHashSemanticPin(
            pin.endpoint, shape, pin.statement_commitment,
            manifest_commitment, boundaries, pin.port,
            expected, why)) {
        return false;
    }
    if (pin.version != expected.version ||
        pin.endpoint != expected.endpoint ||
        pin.port != expected.port ||
        pin.statement_commitment != expected.statement_commitment ||
        pin.shape_commitment != expected.shape_commitment ||
        pin.manifest_commitment != expected.manifest_commitment ||
        pin.schedule_commitment != expected.schedule_commitment ||
        pin.instance_count != expected.instance_count ||
        pin.logical_rows != expected.logical_rows ||
        pin.n_rows != expected.n_rows ||
        pin.boundary_value_root != expected.boundary_value_root ||
        pin.semantic_memory_root != expected.semantic_memory_root) {
        return Fail(why, "hash:memory_binding");
    }
    if (why != nullptr) {
        *why =
            "stage3:coupled_semantic:all_hash_instances_and_"
            "canonical_boundary_memory_ok_root_chain_pending";
    }
    return true;
}

void AppendLe32(std::vector<uint8_t>& out, uint32_t value)
{
    for (uint32_t i = 0; i < 4; ++i) {
        out.push_back(static_cast<uint8_t>(value >> (8 * i)));
    }
}

bool StructuralBarrierManifest(
    const RCStage3CoupledShape& shape,
    const ha::CoupledBarrierManifest& manifest,
    std::string* why)
{
    if (manifest.transcript_version != shape.transcript_version ||
        manifest.expected_barriers != shape.barriers ||
        manifest.barrier_index >= shape.barriers ||
        manifest.state_bytes.empty() ||
        manifest.direct.relation !=
            ha::DirectHashRelation::CoupledBarrier ||
        manifest.commitment !=
            ha::CommitCoupledBarrierManifest(manifest)) {
        return Fail(why, "barrier:structural_shape");
    }
    const auto& tags =
        RCCoupDomainTagsForVersion(manifest.transcript_version);
    std::vector<uint8_t> preimage;
    const size_t tag_len = std::strlen(tags.barrier);
    preimage.insert(
        preimage.end(),
        reinterpret_cast<const uint8_t*>(tags.barrier),
        reinterpret_cast<const uint8_t*>(tags.barrier) + tag_len);
    AppendLe32(preimage, manifest.barrier_index);
    preimage.insert(
        preimage.end(), manifest.state_bytes.begin(),
        manifest.state_bytes.end());
    if (manifest.direct.preimage != preimage) {
        return Fail(why, "barrier:preimage");
    }
    return true;
}

bool StructuralDigestManifest(
    const RCStage3CoupledShape& shape,
    const ha::CoupledDigestManifest& manifest,
    std::string* why)
{
    if (manifest.transcript_version != shape.transcript_version ||
        manifest.expected_barriers != shape.barriers ||
        manifest.barrier_roots.size() != shape.barriers ||
        manifest.bank_root.IsNull() ||
        manifest.direct.relation !=
            ha::DirectHashRelation::CoupledDigest ||
        manifest.commitment !=
            ha::CommitCoupledDigestManifest(manifest)) {
        return Fail(why, "digest:structural_shape");
    }
    const auto& tags =
        RCCoupDomainTagsForVersion(manifest.transcript_version);
    std::vector<uint8_t> preimage;
    const size_t tag_len = std::strlen(tags.episode);
    preimage.insert(
        preimage.end(),
        reinterpret_cast<const uint8_t*>(tags.episode),
        reinterpret_cast<const uint8_t*>(tags.episode) + tag_len);
    preimage.insert(
        preimage.end(), manifest.bank_root.begin(),
        manifest.bank_root.end());
    for (const auto& root : manifest.barrier_roots) {
        if (root.IsNull()) return Fail(why, "digest:null_barrier_root");
        preimage.insert(preimage.end(), root.begin(), root.end());
    }
    if (manifest.direct.preimage != preimage) {
        return Fail(why, "digest:preimage");
    }
    return true;
}

} // namespace

bool ResolveRCStage3CoupledSemanticEndpointSpec(
    RCStage3RelationEndpoint endpoint,
    const RCStage3CoupledAirRequest& request,
    RCStage3CoupledSemanticEndpointSpec& out,
    std::string* why)
{
    out = {};
    if (!IsCoupledEndpoint(endpoint) ||
        EndpointRole(endpoint) != request.role ||
        !IsCanonical(request.gamma) ||
        !IsCanonical(request.alpha)) {
        return Fail(why, "spec:identity");
    }
    RCStage3CoupledAirEntry entry;
    if (!ResolveRCStage3CoupledAir(request, entry, why)) {
        return Fail(why, "spec:role");
    }
    const auto counts =
        ExpectedRCStage3CoupledRelationCounts(request.role, request.shape, why);
    if (!counts.has_value()) return false;

    out.endpoint = endpoint;
    out.role = request.role;
    out.source_columns = EndpointSources(endpoint);
    out.relation_rows = entry.constraints.n_rows;
    out.required_instances = counts->primary;
    out.shape_commitment = CommitRCStage3CoupledShape(request.shape);
    out.relation_air_available =
        entry.constraint_system_available && !out.source_columns.empty();
    out.full_vector_export = FullVector(endpoint);
    out.canonical_schedule = out.relation_air_available;
    out.complete_instance_aggregation = false;
    out.relation_family =
        out.relation_air_available ? "coupled_role_air+canonical_memory_v1"
                                   : "unresolved";
    if (out.relation_air_available) {
        for (uint32_t source : out.source_columns) {
            if (source >= entry.constraints.n_columns) {
                return Fail(why, "spec:source_column");
            }
        }
        out.schedule_commitment = ScheduleCommitment(
            endpoint, request.role, request, out.required_instances,
            out.relation_rows, out.source_columns);
        if (out.schedule_commitment.IsNull()) {
            return Fail(why, "spec:schedule");
        }
    }
    out.remaining = MissingRelation(endpoint);
    if (why != nullptr) {
        *why = out.relation_air_available
            ? "stage3:coupled_semantic:spec_ok"
            : "stage3:coupled_semantic:relation_child_missing";
    }
    return true;
}

bool BuildRCStage3CoupledSemanticConstraintSystem(
    const RCStage3CoupledSemanticEndpointSpec& spec,
    const CS& relation_cs,
    CS& out,
    RCStage3CoupledSemanticLayout* layout,
    std::string* why)
{
    out = {};
    if (!spec.relation_air_available || !spec.full_vector_export ||
        !spec.canonical_schedule || spec.source_columns.empty() ||
        spec.relation_rows != relation_cs.n_rows ||
        relation_cs.n_rows < 2 || relation_cs.n_columns == 0 ||
        relation_cs.constraints.empty() ||
        spec.schedule_commitment.IsNull() ||
        spec.source_columns.size() >
            (std::numeric_limits<uint32_t>::max() -
             relation_cs.n_columns) / 3U) {
        return Fail(why, "cs:spec");
    }
    for (uint32_t source : spec.source_columns) {
        if (source >= relation_cs.n_columns) {
            return Fail(why, "cs:source");
        }
    }

    RCStage3CoupledSemanticLayout local;
    local.endpoint = spec.endpoint;
    local.role = spec.role;
    local.relation_columns = relation_cs.n_columns;
    local.memory_column_base = relation_cs.n_columns;
    local.total_columns = relation_cs.n_columns +
                          3U * spec.source_columns.size();
    local.source_columns = spec.source_columns;
    local.schedule_commitment = spec.schedule_commitment;

    out.n_rows = relation_cs.n_rows;
    out.n_columns = local.total_columns;
    out.preprocessed_pin_ood = true;
    CopyConstraints(relation_cs, out);

    for (uint32_t port = 0; port < spec.source_columns.size(); ++port) {
        std::vector<Fp3> roles(out.n_rows, gf::FromU64_3(
            static_cast<uint16_t>(spec.role)));
        std::vector<Fp3> addresses(out.n_rows);
        for (uint32_t row = 0; row < out.n_rows; ++row) {
            const uint64_t address =
                (static_cast<uint64_t>(
                     static_cast<uint16_t>(spec.endpoint)) << 40) |
                (static_cast<uint64_t>(port) << 32) |
                row;
            addresses[row] = gf::FromU64_3(address);
        }
        out.preprocessed.emplace_back(
            local.RoleColumn(port), std::move(roles));
        out.preprocessed.emplace_back(
            local.AddressColumn(port), std::move(addresses));

        Constraint alias;
        alias.name = "stage3.coupled_semantic.proof_owned_value";
        alias.kind = aq::AirKind::kEverywhere;
        alias.alg_degree = 1;
        const uint32_t source = spec.source_columns[port];
        const uint32_t value = local.ValueColumn(port);
        alias.eval =
            [source, value](const std::vector<Fp3>& current,
                            const std::vector<Fp3>&) {
                return gf::Sub(current[value], current[source]);
            };
        out.constraints.push_back(std::move(alias));
    }

    if (layout != nullptr) *layout = local;
    if (why != nullptr) *why = "stage3:coupled_semantic:cs_ok";
    return true;
}

bool BuildRCStage3CoupledSemanticWitness(
    const RCStage3CoupledSemanticLayout& layout,
    const std::vector<std::vector<Fp3>>& relation_columns,
    std::vector<std::vector<Fp3>>& out,
    std::string* why)
{
    out.clear();
    if (layout.relation_columns == 0 ||
        layout.memory_column_base != layout.relation_columns ||
        layout.source_columns.empty() ||
        layout.total_columns !=
            layout.relation_columns + 3U * layout.source_columns.size() ||
        layout.schedule_commitment.IsNull() ||
        relation_columns.size() != layout.relation_columns ||
        relation_columns.empty()) {
        return Fail(why, "witness:layout");
    }
    const size_t rows = relation_columns.front().size();
    if (rows < 2) return Fail(why, "witness:rows");
    for (const auto& column : relation_columns) {
        if (column.size() != rows) {
            return Fail(why, "witness:column_rows");
        }
    }
    out = relation_columns;
    for (uint32_t port = 0; port < layout.source_columns.size(); ++port) {
        if (layout.source_columns[port] >= relation_columns.size()) {
            return Fail(why, "witness:source");
        }
        // Preprocessed ROLE and ADDRESS are included as trace columns by the
        // prover. The verifier regenerates their roots from the CS.
        out.emplace_back(
            rows, gf::FromU64_3(static_cast<uint16_t>(layout.role)));
        std::vector<Fp3> addresses(rows);
        for (uint32_t row = 0; row < rows; ++row) {
            const uint64_t address =
                (static_cast<uint64_t>(
                     static_cast<uint16_t>(layout.endpoint)) << 40) |
                (static_cast<uint64_t>(port) << 32) |
                row;
            addresses[row] = gf::FromU64_3(address);
        }
        out.push_back(std::move(addresses));
        out.push_back(relation_columns[layout.source_columns[port]]);
    }
    if (why != nullptr) *why = "stage3:coupled_semantic:witness_ok";
    return true;
}

uint256 ComputeRCStage3CoupledSemanticMemoryRoot(
    RCStage3RelationEndpoint endpoint,
    RCStage3RelationRole role,
    uint64_t instance_count,
    const uint256& shape_commitment,
    const uint256& schedule_commitment,
    const std::vector<uint256>& value_column_roots)
{
    if (!IsCoupledEndpoint(endpoint) || EndpointRole(endpoint) != role ||
        instance_count == 0 || shape_commitment.IsNull() ||
        schedule_commitment.IsNull() || value_column_roots.empty()) {
        return {};
    }
    HashWriter hash;
    hash << MEMORY_DOMAIN;
    hash << kRCStage3CoupledSemanticVersion;
    hash << static_cast<uint16_t>(endpoint);
    hash << static_cast<uint16_t>(role);
    hash << instance_count;
    hash << shape_commitment;
    hash << schedule_commitment;
    hash << static_cast<uint32_t>(value_column_roots.size());
    for (const auto& root : value_column_roots) {
        if (root.IsNull()) return {};
        hash << root;
    }
    return hash.GetHash();
}

uint256 ComputeRCStage3CoupledSemanticProofSeed(
    const RCStage3CoupledSemanticPublicPin& pin)
{
    if (pin.version != kRCStage3CoupledSemanticVersion ||
        !IsCoupledEndpoint(pin.endpoint) ||
        EndpointRole(pin.endpoint) != pin.request.role ||
        pin.statement_commitment.IsNull() ||
        pin.shape_commitment.IsNull() ||
        pin.schedule_commitment.IsNull() ||
        pin.semantic_memory_root.IsNull() ||
        pin.instance_count == 0 ||
        pin.relation_column_roots.empty() ||
        pin.value_column_roots.empty()) {
        return {};
    }
    HashWriter hash;
    hash << PROOF_DOMAIN;
    hash << pin.version;
    hash << static_cast<uint16_t>(pin.endpoint);
    hash << static_cast<uint16_t>(pin.request.role);
    hash << pin.statement_commitment;
    hash << pin.shape_commitment;
    hash << pin.schedule_commitment;
    hash << pin.instance_begin;
    hash << pin.instance_span;
    hash << pin.semantic_memory_root;
    hash << pin.instance_count;
    hash << static_cast<uint32_t>(pin.relation_column_roots.size());
    for (const auto& root : pin.relation_column_roots) hash << root;
    hash << static_cast<uint32_t>(pin.value_column_roots.size());
    for (const auto& root : pin.value_column_roots) hash << root;
    return hash.GetHash();
}

uint256 ComputeRCStage3CoupledSemanticShardSchedule(
    const uint256& base_schedule_commitment,
    uint64_t instance_begin,
    uint64_t instance_span,
    uint64_t total_instances)
{
    if (base_schedule_commitment.IsNull() ||
        instance_span == 0 || total_instances == 0 ||
        instance_begin >= total_instances ||
        instance_span > total_instances - instance_begin) {
        return {};
    }
    HashWriter hash;
    hash << SHARD_SCHEDULE_DOMAIN;
    hash << kRCStage3CoupledSemanticVersion;
    hash << base_schedule_commitment;
    hash << instance_begin;
    hash << instance_span;
    hash << total_instances;
    return hash.GetHash();
}

bool VerifyRCStage3CoupledSemanticProof(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledSemanticPublicPin& pin,
    const aq::AirQuotientProof<Fp3>& proof,
    std::string* why)
{
    const uint256 statement_commitment =
        CommitRCStage3CoupledStatement(statement.public_inputs);
    RCStage3CoupledSemanticEndpointSpec spec;
    if (pin.statement_commitment != statement_commitment ||
        !ResolveRCStage3CoupledSemanticEndpointSpec(
            pin.endpoint, pin.request, spec, why) ||
        !spec.relation_air_available ||
        !spec.full_vector_export ||
        pin.shape_commitment != spec.shape_commitment ||
        pin.instance_count != spec.required_instances ||
        pin.value_column_roots.size() != spec.source_columns.size()) {
        return Fail(why, "verify:pin");
    }
    uint256 expected_schedule = spec.schedule_commitment;
    if (pin.instance_span != 0) {
        if (pin.instance_span != 1 ||
            pin.instance_begin >= spec.required_instances) {
            return Fail(why, "verify:shard_range");
        }
        expected_schedule =
            ComputeRCStage3CoupledSemanticShardSchedule(
                spec.schedule_commitment, pin.instance_begin,
                pin.instance_span, spec.required_instances);
    } else if (pin.instance_begin != 0) {
        return Fail(why, "verify:standalone_begin");
    }
    if (expected_schedule.IsNull() ||
        pin.schedule_commitment != expected_schedule) {
        return Fail(why, "verify:schedule");
    }
    const uint256 memory = ComputeRCStage3CoupledSemanticMemoryRoot(
        pin.endpoint, pin.request.role, pin.instance_count,
        pin.shape_commitment, pin.schedule_commitment,
        pin.value_column_roots);
    if (memory.IsNull() || memory != pin.semantic_memory_root) {
        return Fail(why, "verify:memory_root");
    }

    RCStage3CoupledAirEntry entry;
    if (!ResolveRCStage3CoupledAir(pin.request, entry, why) ||
        !entry.constraint_system_available ||
        pin.relation_column_roots.size() != entry.constraints.n_columns) {
        return Fail(why, "verify:relation");
    }
    for (uint32_t column = 0;
         column < pin.relation_column_roots.size(); ++column) {
        if (pin.relation_column_roots[column].IsNull()) {
            return Fail(why, "verify:null_relation_root");
        }
        entry.constraints.preprocessed_roots.emplace_back(
            column, pin.relation_column_roots[column]);
    }

    CS combined;
    RCStage3CoupledSemanticLayout layout;
    if (!BuildRCStage3CoupledSemanticConstraintSystem(
            spec, entry.constraints, combined, &layout, why)) {
        return false;
    }
    if (proof.batch.columns.size() !=
            static_cast<size_t>(combined.n_columns) + 1U ||
        proof.batch.column_len.size() != proof.batch.columns.size()) {
        return Fail(why, "verify:proof_shape");
    }
    for (uint32_t column = 0;
         column < pin.relation_column_roots.size(); ++column) {
        if (proof.batch.columns[column].root !=
            pin.relation_column_roots[column]) {
            return Fail(why, "verify:relation_root");
        }
    }
    for (uint32_t port = 0; port < pin.value_column_roots.size(); ++port) {
        if (proof.batch.columns[layout.ValueColumn(port)].root !=
                pin.value_column_roots[port] ||
            proof.batch.columns[layout.source_columns[port]].root !=
                pin.value_column_roots[port]) {
            return Fail(why, "verify:value_alias_root");
        }
    }

    const uint256 seed = ComputeRCStage3CoupledSemanticProofSeed(pin);
    std::string air_why;
    if (seed.IsNull() ||
        !aq::AirQuotientVerify<Fp3>(
            combined, proof, seed, &air_why)) {
        return Fail(why, "verify:air:" + air_why);
    }
    if (why != nullptr) {
        *why =
            "stage3:coupled_semantic:local_vector_and_memory_proof_ok_"
            "recursive_instance_aggregation_pending";
    }
    return true;
}

uint256 ComputeRCStage3CoupledSemanticFlatBundleCommitment(
    const RCStage3CoupledSemanticFlatBundle& bundle)
{
    if (bundle.version != kRCStage3CoupledSemanticVersion ||
        !IsCoupledEndpoint(bundle.endpoint) ||
        bundle.statement_commitment.IsNull() ||
        bundle.total_instances == 0 ||
        bundle.shards.size() != bundle.total_instances) {
        return {};
    }
    HashWriter hash;
    hash << FLAT_BUNDLE_DOMAIN;
    hash << bundle.version;
    hash << static_cast<uint16_t>(bundle.endpoint);
    hash << bundle.statement_commitment;
    hash << bundle.total_instances;
    hash << static_cast<uint64_t>(bundle.shards.size());
    for (const auto& shard : bundle.shards) {
        const auto& pin = shard.pin;
        hash << shard.instance_begin;
        hash << pin.instance_begin;
        hash << pin.instance_span;
        hash << pin.instance_count;
        hash << pin.schedule_commitment;
        hash << pin.semantic_memory_root;
        hash << static_cast<uint32_t>(pin.relation_column_roots.size());
        for (const auto& root : pin.relation_column_roots) hash << root;
        hash << static_cast<uint32_t>(pin.value_column_roots.size());
        for (const auto& root : pin.value_column_roots) hash << root;
        hash << static_cast<uint32_t>(
            shard.proof.batch.columns.size());
        for (const auto& column : shard.proof.batch.columns) {
            hash << column.root;
        }
        hash << shard.proof.trace_commit;
    }
    return hash.GetHash();
}

bool VerifyRCStage3CoupledSemanticFlatBundle(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledSemanticFlatBundle& bundle,
    std::string* why)
{
    if (bundle.version != kRCStage3CoupledSemanticVersion ||
        !IsCoupledEndpoint(bundle.endpoint) ||
        bundle.statement_commitment !=
            CommitRCStage3CoupledStatement(statement.public_inputs) ||
        bundle.total_instances == 0 ||
        bundle.total_instances >
            kRCStage3CoupledSemanticMaxFlatShards ||
        bundle.shards.size() != bundle.total_instances) {
        return Fail(why, "flat:shape");
    }
    for (uint64_t i = 0; i < bundle.total_instances; ++i) {
        const auto& shard = bundle.shards[i];
        if (shard.instance_begin != i ||
            shard.pin.endpoint != bundle.endpoint ||
            shard.pin.statement_commitment !=
                bundle.statement_commitment ||
            shard.pin.instance_begin != i ||
            shard.pin.instance_span != 1 ||
            shard.pin.instance_count != bundle.total_instances) {
            return Fail(why, "flat:order_or_range");
        }
        if (!VerifyRCStage3CoupledSemanticProof(
                statement, shard.pin, shard.proof, why)) {
            return Fail(
                why, "flat:shard_" + std::to_string(i));
        }
    }
    const uint256 commitment =
        ComputeRCStage3CoupledSemanticFlatBundleCommitment(bundle);
    if (commitment.IsNull() ||
        bundle.bundle_commitment != commitment) {
        return Fail(why, "flat:commitment");
    }
    if (why != nullptr) {
        *why =
            "stage3:coupled_semantic:exact_flat_all_instances_ok";
    }
    return true;
}

bool BuildRCStage3CoupledHashSemanticPin(
    RCStage3RelationEndpoint endpoint,
    const RCStage3CoupledShape& shape,
    const uint256& statement_commitment,
    const uint256& manifest_commitment,
    const std::vector<ha::FixedProgramBoundaryInstance>& boundaries,
    hs::BoundaryPort port,
    RCStage3CoupledHashSemanticPin& out,
    std::string* why)
{
    out = {};
    if (!IsHashSemanticEndpoint(endpoint) ||
        statement_commitment.IsNull() ||
        manifest_commitment.IsNull() ||
        boundaries.empty()) {
        return Fail(why, "hash:builder_shape");
    }
    uint256 boundary_root;
    uint32_t logical_rows{0};
    uint32_t n_rows{0};
    if (!hs::ComputeCanonicalBoundaryValueRoot(
            boundaries, port, boundary_root,
            logical_rows, n_rows, why)) {
        return Fail(why, "hash:boundary_root");
    }
    const uint256 shape_commitment =
        CommitRCStage3CoupledShape(shape);
    const uint256 schedule = HashScheduleCommitment(
        endpoint, shape, manifest_commitment, port,
        boundaries.size(), logical_rows, n_rows);
    const uint256 memory =
        ComputeRCStage3CoupledSemanticMemoryRoot(
            endpoint, EndpointRole(endpoint), boundaries.size(),
            shape_commitment, schedule, {boundary_root});
    if (shape_commitment.IsNull() || schedule.IsNull() ||
        boundary_root.IsNull() || memory.IsNull()) {
        return Fail(why, "hash:builder_commitment");
    }
    out.endpoint = endpoint;
    out.port = port;
    out.statement_commitment = statement_commitment;
    out.shape_commitment = shape_commitment;
    out.manifest_commitment = manifest_commitment;
    out.schedule_commitment = schedule;
    out.instance_count = boundaries.size();
    out.logical_rows = logical_rows;
    out.n_rows = n_rows;
    out.boundary_value_root = boundary_root;
    out.semantic_memory_root = memory;
    if (why != nullptr) *why = "stage3:coupled_semantic:hash_pin_ok";
    return true;
}

bool VerifyRCStage3CoupledCounterXofSemantic(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const ha::CounterXofManifest& manifest,
    const hs::FlatBoundaryProofBundle& bundle,
    const RCStage3CoupledHashSemanticPin& pin,
    std::string* why)
{
    using E = RCStage3RelationEndpoint;
    if (pin.endpoint != E::CoupledBankSeedXof &&
        pin.endpoint != E::CoupledExchangeHashXof) {
        return Fail(why, "counter_xof:endpoint");
    }
    std::vector<ha::FixedProgramBoundaryInstance> boundaries;
    if (!ha::BuildCounterXofManifestBoundaryInstances(
            manifest, boundaries, why) ||
        !hs::VerifyCounterXofManifestBundle(
            pin.endpoint, manifest, bundle, why)) {
        return Fail(why, "counter_xof:proof");
    }
    return VerifyHashPinCommon(
        statement, shape, boundaries, manifest.commitment,
        bundle, pin, why);
}

bool VerifyRCStage3CoupledChaChaSemantic(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const ha::ChaChaConsumptionManifest& manifest,
    const hs::FlatBoundaryProofBundle& bundle,
    const RCStage3CoupledHashSemanticPin& pin,
    std::string* why)
{
    if (pin.endpoint !=
        RCStage3RelationEndpoint::CoupledExtractChaCha) {
        return Fail(why, "chacha:endpoint");
    }
    std::vector<ha::FixedProgramBoundaryInstance> boundaries;
    if (!ha::BuildChaChaManifestBoundaryInstances(
            manifest, boundaries, why) ||
        !hs::VerifyChaChaManifestBundle(
            pin.endpoint, manifest, bundle, why)) {
        return Fail(why, "chacha:proof");
    }
    return VerifyHashPinCommon(
        statement, shape, boundaries, manifest.commitment,
        bundle, pin, why);
}

bool VerifyRCStage3CoupledBarrierHashSemantic(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const ha::CoupledBarrierManifest& manifest,
    const hs::FlatBoundaryProofBundle& bundle,
    const RCStage3CoupledHashSemanticPin& pin,
    std::string* why)
{
    if (pin.endpoint !=
            RCStage3RelationEndpoint::CoupledBarrierHash ||
        !StructuralBarrierManifest(shape, manifest, why)) {
        return Fail(why, "barrier:endpoint_or_manifest");
    }
    std::vector<ha::FixedProgramBoundaryInstance> boundaries;
    if (!ha::BuildDirectSha256dManifestBoundaryInstances(
            manifest.direct, boundaries, why) ||
        !hs::VerifyDirectSha256dManifestBundle(
            pin.endpoint, manifest.direct, bundle, why)) {
        return Fail(why, "barrier:proof");
    }
    return VerifyHashPinCommon(
        statement, shape, boundaries, manifest.direct.commitment,
        bundle, pin, why);
}

bool VerifyRCStage3CoupledDigestHashSemantic(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const ha::CoupledDigestManifest& manifest,
    const hs::FlatBoundaryProofBundle& bundle,
    const RCStage3CoupledHashSemanticPin& pin,
    std::string* why)
{
    if (pin.endpoint !=
            RCStage3RelationEndpoint::CoupledDigestHash ||
        !StructuralDigestManifest(shape, manifest, why)) {
        return Fail(why, "digest:endpoint_or_manifest");
    }
    std::vector<ha::FixedProgramBoundaryInstance> boundaries;
    if (!ha::BuildDirectSha256dManifestBoundaryInstances(
            manifest.direct, boundaries, why) ||
        !hs::VerifyDirectSha256dManifestBundle(
            pin.endpoint, manifest.direct, bundle, why)) {
        return Fail(why, "digest:proof");
    }
    return VerifyHashPinCommon(
        statement, shape, boundaries, manifest.direct.commitment,
        bundle, pin, why);
}

std::vector<RCStage3CoupledSemanticAudit>
CurrentRCStage3CoupledSemanticAudit(
    const RCStage3CoupledShape& shape,
    const Fp3& gamma,
    const Fp3& alpha,
    uint8_t extract_scale_e)
{
    std::vector<RCStage3CoupledSemanticAudit> out;
    out.reserve(26);
    for (uint16_t id = 27; id <= 52; ++id) {
        const auto endpoint =
            static_cast<RCStage3RelationEndpoint>(id);
        const RCStage3RelationRole role = EndpointRole(endpoint);
        RCStage3CoupledSemanticEndpointSpec spec;
        std::string ignored;
        const bool resolved =
            ResolveRCStage3CoupledSemanticEndpointSpec(
                endpoint,
                {role, shape, gamma, alpha, extract_scale_e},
                spec, &ignored);

        RCStage3CoupledSemanticAudit audit;
        audit.endpoint = endpoint;
        audit.role = role;
        audit.hash_or_xof_child_executable =
            HashChildAvailable(endpoint);
        audit.relation_air_cell =
            (resolved && spec.relation_air_available) ||
            audit.hash_or_xof_child_executable;
        audit.full_vector_export =
            (resolved && spec.full_vector_export) ||
            audit.hash_or_xof_child_executable;
        audit.canonical_memory_schedule =
            (resolved && spec.canonical_schedule) ||
            audit.hash_or_xof_child_executable;
        audit.proof_owned_memory_root =
            audit.relation_air_cell &&
            audit.full_vector_export &&
            audit.canonical_memory_schedule;
        audit.complete_instance_aggregation =
            audit.proof_owned_memory_root;
        audit.canonical_root_chain_link = false;
        audit.semantic_relation_complete =
            audit.proof_owned_memory_root &&
            audit.complete_instance_aggregation &&
            audit.canonical_root_chain_link;
        audit.construction = audit.hash_or_xof_child_executable
            ? "exact flat all-instance fixed-program provenance proofs + "
              "canonical external/final boundary VALUE root"
            : (audit.proof_owned_memory_root
                ? "same-quotient full-vector alias + verifier-derived "
                  "(role,address,value) AlgHash commitments"
                : "no complete executable relation child");
        audit.remaining = MissingRelation(endpoint);
        out.push_back(std::move(audit));
    }
    return out;
}

} // namespace matmul::v4::rc
