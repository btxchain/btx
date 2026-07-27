// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_coupled_missing_relations.h>

#include <hash.h>
#include <span.h>

#include <algorithm>
#include <cstring>
#include <limits>

namespace matmul::v4::rc {
namespace {

namespace aq = air_quotient;
namespace gf = gkr_field;
namespace ha = stage3_hash_air;
namespace hs = stage3_hash_semantic;
using gf::Fp3;

constexpr char BANK_MANIFEST_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_BANK_ROOT_MANIFEST_V1";
constexpr char PORT_SCHEDULE_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_BOUNDARY_PORT_SCHEDULE_V1";
constexpr char RANGE_SCHEDULE_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_SIGNED_RANGE_SCHEDULE_V1";
constexpr char RANGE_MANIFEST_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_SIGNED_RANGE_MANIFEST_V1";
constexpr char RANGE_VALUE_ROOTS_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_SIGNED_RANGE_VALUE_ROOTS_V1";

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:coupled_missing_relations:" + detail;
    }
    return false;
}

bool CheckedMul(uint64_t a, uint64_t b, uint64_t& out)
{
    if (a != 0 && b > std::numeric_limits<uint64_t>::max() / a) {
        return false;
    }
    out = a * b;
    return true;
}

bool IsCoupledStatement(const RCStage3SuccinctProof& statement)
{
    return statement.statement == RCStage3StatementKind::Coupled ||
           statement.statement == RCStage3StatementKind::Composed;
}

uint32_t NextPowerOfTwo(uint32_t value)
{
    if (value <= 2) return 2;
    --value;
    value |= value >> 1;
    value |= value >> 2;
    value |= value >> 4;
    value |= value >> 8;
    value |= value >> 16;
    return value + 1;
}

uint256 DigestUint(const std::array<uint8_t, 32>& digest)
{
    return uint256{Span<const unsigned char>{
        digest.data(), digest.size()}};
}

RCStage3RelationRole EndpointRole(RCStage3RelationEndpoint endpoint)
{
    using E = RCStage3RelationEndpoint;
    switch (endpoint) {
    case E::CoupledBankRoot:
        return RCStage3RelationRole::CoupledBank;
    case E::CoupledGemmSignedRange:
        return RCStage3RelationRole::CoupledGemm;
    case E::CoupledBarrierInput:
    case E::CoupledBarrierOutput:
        return RCStage3RelationRole::CoupledBarrier;
    case E::CoupledDigestBankAndBarriers:
    case E::CoupledDigestValue:
        return RCStage3RelationRole::CoupledDigest;
    default:
        return RCStage3RelationRole::EpisodeDeterministicBuilder;
    }
}

bool IsAllowedPort(RCStage3RelationEndpoint endpoint,
                   hs::BoundaryPort port)
{
    using E = RCStage3RelationEndpoint;
    if (endpoint == E::CoupledBankRoot) {
        return port == hs::BoundaryPort::External ||
               port == hs::BoundaryPort::Final;
    }
    if (endpoint == E::CoupledBarrierInput) {
        return port == hs::BoundaryPort::External;
    }
    if (endpoint == E::CoupledBarrierOutput) {
        return port == hs::BoundaryPort::Final;
    }
    if (endpoint == E::CoupledDigestBankAndBarriers) {
        return port == hs::BoundaryPort::External;
    }
    if (endpoint == E::CoupledDigestValue) {
        return port == hs::BoundaryPort::Final;
    }
    return false;
}

uint256 BoundarySchedule(
    RCStage3RelationEndpoint endpoint,
    hs::BoundaryPort port,
    const RCStage3CoupledShape& shape,
    const uint256& manifest_commitment,
    uint64_t instance_count,
    uint32_t logical_rows,
    uint32_t n_rows)
{
    if (!IsAllowedPort(endpoint, port) ||
        manifest_commitment.IsNull() || instance_count == 0 ||
        logical_rows == 0 || n_rows < logical_rows ||
        (n_rows & (n_rows - 1U)) != 0) {
        return {};
    }
    HashWriter hash;
    hash << PORT_SCHEDULE_DOMAIN;
    hash << kRCStage3CoupledMissingRelationsVersion;
    hash << static_cast<uint16_t>(endpoint);
    hash << static_cast<uint16_t>(EndpointRole(endpoint));
    hash << static_cast<uint8_t>(port);
    hash << CommitRCStage3CoupledShape(shape);
    hash << manifest_commitment;
    hash << instance_count;
    hash << logical_rows;
    hash << n_rows;
    return hash.GetHash();
}

bool ExpectedBankBytes(const RCStage3CoupledShape& shape,
                       uint64_t& page_bytes,
                       std::string* why)
{
    const auto counts = ExpectedRCStage3CoupledRelationCounts(
        RCStage3RelationRole::CoupledBank, shape, why);
    uint64_t one_page{0};
    if (!counts.has_value() ||
        counts->primary != shape.bank_pages ||
        !CheckedMul(shape.lobe_width, shape.lobe_width, one_page) ||
        !CheckedMul(one_page, shape.bank_pages, page_bytes) ||
        page_bytes == 0) {
        return Fail(why, "bank:shape");
    }
    return true;
}

bool StructuralBankManifest(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledBankRootManifest& manifest,
    std::string* why)
{
    uint64_t page_bytes{0};
    const uint256 statement_commitment =
        CommitRCStage3CoupledStatement(statement.public_inputs);
    if (manifest.version !=
            kRCStage3CoupledMissingRelationsVersion ||
        manifest.statement_commitment != statement_commitment ||
        !ExpectedBankBytes(manifest.shape, page_bytes, why) ||
        manifest.sha256d.mode != ha::ShaMode::Double ||
        manifest.sha256d.commitment.IsNull() ||
        manifest.bank_root.IsNull() ||
        manifest.bank_root != DigestUint(manifest.sha256d.digest) ||
        manifest.commitment !=
            CommitRCStage3CoupledBankRootManifest(manifest)) {
        return Fail(why, "bank:manifest");
    }
    const auto& tags =
        RCCoupDomainTagsForVersion(manifest.shape.transcript_version);
    const size_t tag_len = std::strlen(tags.bank);
    if (page_bytes >
            std::numeric_limits<size_t>::max() - tag_len ||
        manifest.sha256d.preimage.size() !=
            tag_len + static_cast<size_t>(page_bytes) ||
        !std::equal(
            reinterpret_cast<const uint8_t*>(tags.bank),
            reinterpret_cast<const uint8_t*>(tags.bank) + tag_len,
            manifest.sha256d.preimage.begin())) {
        return Fail(why, "bank:preimage_schedule");
    }
    return true;
}

bool PinEqualsExpected(
    RCStage3RelationEndpoint endpoint,
    hs::BoundaryPort port,
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const uint256& manifest_commitment,
    const std::vector<ha::FixedProgramBoundaryInstance>& boundaries,
    const RCStage3CoupledBoundaryPortPin& supplied,
    std::string* why)
{
    RCStage3CoupledBoundaryPortPin expected;
    if (!BuildRCStage3CoupledBoundaryPortPin(
            endpoint, port, statement, shape, manifest_commitment,
            boundaries, expected, why)) {
        return false;
    }
    if (!(supplied == expected)) {
        return Fail(why, "boundary_pin");
    }
    return true;
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
        return Fail(why, "barrier:manifest");
    }
    uint64_t state_bytes{0};
    if (!CheckedMul(shape.lobes, shape.rows_per_lobe, state_bytes) ||
        !CheckedMul(state_bytes, shape.lobe_width, state_bytes) ||
        manifest.state_bytes.size() != state_bytes) {
        return Fail(why, "barrier:state_size");
    }
    const auto& tags =
        RCCoupDomainTagsForVersion(manifest.transcript_version);
    std::vector<uint8_t> preimage;
    const size_t tag_len = std::strlen(tags.barrier);
    preimage.insert(
        preimage.end(),
        reinterpret_cast<const uint8_t*>(tags.barrier),
        reinterpret_cast<const uint8_t*>(tags.barrier) + tag_len);
    for (uint32_t i = 0; i < 4; ++i) {
        preimage.push_back(
            static_cast<uint8_t>(manifest.barrier_index >> (8 * i)));
    }
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
        return Fail(why, "digest:manifest");
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
        if (root.IsNull()) return Fail(why, "digest:null_barrier");
        preimage.insert(preimage.end(), root.begin(), root.end());
    }
    if (manifest.direct.preimage != preimage) {
        return Fail(why, "digest:preimage");
    }
    return true;
}

bool ExpectedSignedRange(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    RCStage3CoupledSignedRangeManifest& out,
    std::string* why)
{
    out = {};
    const auto counts = ExpectedRCStage3CoupledRelationCounts(
        RCStage3RelationRole::CoupledGemm, shape, why);
    uint64_t cells_per_gemm{0};
    uint64_t cells{0};
    uint64_t bound{0};
    if (!counts.has_value() ||
        !CheckedMul(shape.rows_per_lobe, shape.lobe_width,
                    cells_per_gemm) ||
        !CheckedMul(counts->primary, cells_per_gemm, cells) ||
        !CheckedMul(shape.lobe_width, uint64_t{48} * 48, bound) ||
        cells == 0 || bound == 0 ||
        bound >= (uint64_t{1} << kRCStage3SignedRangeBits)) {
        return Fail(why, "range:shape");
    }
    const uint64_t shard_count =
        (cells + kRCStage3SignedRangeMaxShardRows - 1) /
        kRCStage3SignedRangeMaxShardRows;
    if (shard_count == 0 ||
        shard_count > std::numeric_limits<uint32_t>::max()) {
        return Fail(why, "range:shard_count");
    }
    out.statement_commitment =
        CommitRCStage3CoupledStatement(statement.public_inputs);
    out.shape = shape;
    out.scheduled_gemms = counts->primary;
    out.total_output_cells = cells;
    out.max_abs = bound;
    out.shard_count = static_cast<uint32_t>(shard_count);
    HashWriter schedule;
    schedule << RANGE_SCHEDULE_DOMAIN;
    schedule << kRCStage3CoupledMissingRelationsVersion;
    schedule << out.statement_commitment;
    schedule << CommitRCStage3CoupledShape(shape);
    schedule << out.scheduled_gemms;
    schedule << out.total_output_cells;
    schedule << out.max_abs;
    schedule << out.shard_count;
    schedule << kRCStage3SignedRangeMaxShardRows;
    out.schedule_commitment = schedule.GetHash();
    out.commitment =
        CommitRCStage3CoupledSignedRangeManifest(out);
    if (out.statement_commitment.IsNull() ||
        out.schedule_commitment.IsNull() ||
        out.commitment.IsNull()) {
        return Fail(why, "range:commitment");
    }
    return true;
}

} // namespace

uint256 CommitRCStage3CoupledBankRootManifest(
    const RCStage3CoupledBankRootManifest& manifest)
{
    if (manifest.version !=
            kRCStage3CoupledMissingRelationsVersion ||
        manifest.statement_commitment.IsNull() ||
        manifest.sha256d.commitment.IsNull() ||
        manifest.bank_root.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << BANK_MANIFEST_DOMAIN;
    hash << manifest.version;
    hash << manifest.statement_commitment;
    hash << CommitRCStage3CoupledShape(manifest.shape);
    hash << manifest.sha256d.commitment;
    hash << manifest.bank_root;
    return hash.GetHash();
}

bool BuildRCStage3CoupledBankRootManifest(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const std::vector<uint8_t>& page_bytes,
    RCStage3CoupledBankRootManifest& out,
    std::string* why)
{
    out = {};
    uint64_t expected_bytes{0};
    if (!ExpectedBankBytes(shape, expected_bytes, why) ||
        expected_bytes != page_bytes.size()) {
        return Fail(why, "bank:page_bytes");
    }
    const auto& tags =
        RCCoupDomainTagsForVersion(shape.transcript_version);
    const size_t tag_len = std::strlen(tags.bank);
    std::vector<uint8_t> preimage;
    if (page_bytes.size() >
        std::numeric_limits<size_t>::max() - tag_len) {
        return Fail(why, "bank:preimage_overflow");
    }
    preimage.reserve(tag_len + page_bytes.size());
    preimage.insert(
        preimage.end(),
        reinterpret_cast<const uint8_t*>(tags.bank),
        reinterpret_cast<const uint8_t*>(tags.bank) + tag_len);
    preimage.insert(preimage.end(), page_bytes.begin(), page_bytes.end());
    if (!ha::BuildShaManifest(
            preimage, ha::ShaMode::Double, out.sha256d, why)) {
        return Fail(why, "bank:sha_builder");
    }
    out.statement_commitment =
        CommitRCStage3CoupledStatement(statement.public_inputs);
    out.shape = shape;
    out.bank_root = DigestUint(out.sha256d.digest);
    out.commitment =
        CommitRCStage3CoupledBankRootManifest(out);
    return !out.commitment.IsNull() ||
           Fail(why, "bank:commitment");
}

bool BuildRCStage3CoupledBoundaryPortPin(
    RCStage3RelationEndpoint endpoint,
    hs::BoundaryPort port,
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const uint256& manifest_commitment,
    const std::vector<ha::FixedProgramBoundaryInstance>& boundaries,
    RCStage3CoupledBoundaryPortPin& out,
    std::string* why)
{
    out = {};
    if (!IsAllowedPort(endpoint, port) ||
        boundaries.empty() || manifest_commitment.IsNull()) {
        return Fail(why, "boundary:identity");
    }
    uint256 value_root;
    uint32_t logical_rows{0};
    uint32_t n_rows{0};
    if (!hs::ComputeCanonicalBoundaryValueRoot(
            boundaries, port, value_root,
            logical_rows, n_rows, why)) {
        return Fail(why, "boundary:value_root");
    }
    out.endpoint = endpoint;
    out.port = port;
    out.statement_commitment =
        CommitRCStage3CoupledStatement(statement.public_inputs);
    out.shape_commitment = CommitRCStage3CoupledShape(shape);
    out.manifest_commitment = manifest_commitment;
    out.instance_count = boundaries.size();
    out.logical_rows = logical_rows;
    out.n_rows = n_rows;
    out.value_root = value_root;
    out.schedule_commitment = BoundarySchedule(
        endpoint, port, shape, manifest_commitment,
        out.instance_count, logical_rows, n_rows);
    out.semantic_memory_root =
        ComputeRCStage3CoupledSemanticMemoryRoot(
            endpoint, EndpointRole(endpoint), out.instance_count,
            out.shape_commitment, out.schedule_commitment,
            {out.value_root});
    if (out.statement_commitment.IsNull() ||
        out.shape_commitment.IsNull() ||
        out.schedule_commitment.IsNull() ||
        out.value_root.IsNull() ||
        out.semantic_memory_root.IsNull()) {
        out = {};
        return Fail(why, "boundary:commitment");
    }
    return true;
}

bool ProveRCStage3CoupledBankRootExecution(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const std::vector<uint8_t>& page_bytes,
    RCStage3CoupledBankRootExecution& out,
    std::string* why)
{
    out = {};
    if (!BuildRCStage3CoupledBankRootManifest(
            statement, shape, page_bytes, out.manifest, why)) {
        return Fail(why, "bank:prove_manifest");
    }
    std::vector<ha::FixedProgramBoundaryInstance> boundaries;
    if (!ha::BuildShaManifestBoundaryInstances(
            out.manifest.sha256d, boundaries, why)) {
        out = {};
        return Fail(why, "bank:prove_boundaries");
    }
    const auto program =
        ha::BuildCanonicalProgram(ha::ProgramKind::Sha256Compression);
    if (!hs::ProveFlatBoundaryProofBundle(
            RCStage3RelationEndpoint::CoupledBankRoot,
            out.manifest.statement_commitment,
            out.manifest.sha256d.commitment,
            program, boundaries, out.hash_proofs, why) ||
        !BuildRCStage3CoupledBoundaryPortPin(
            RCStage3RelationEndpoint::CoupledBankRoot,
            hs::BoundaryPort::External, statement, shape,
            out.manifest.sha256d.commitment, boundaries,
            out.bank_bytes, why) ||
        !BuildRCStage3CoupledBoundaryPortPin(
            RCStage3RelationEndpoint::CoupledBankRoot,
            hs::BoundaryPort::Final, statement, shape,
            out.manifest.sha256d.commitment, boundaries,
            out.bank_digest, why)) {
        out = {};
        return Fail(why, "bank:prove_children");
    }
    if (!VerifyRCStage3CoupledBankRootExecution(
            statement, shape, out, why)) {
        out = {};
        return Fail(why, "bank:prove_self_verify");
    }
    return true;
}

bool VerifyRCStage3CoupledBankRootExecution(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& expected_shape,
    const RCStage3CoupledBankRootExecution& execution,
    std::string* why)
{
    if (!IsCoupledStatement(statement) ||
        execution.manifest.shape != expected_shape ||
        !StructuralBankManifest(statement, execution.manifest, why) ||
        execution.hash_proofs.endpoint !=
            RCStage3RelationEndpoint::CoupledBankRoot ||
        execution.hash_proofs.statement_commitment !=
            execution.manifest.statement_commitment ||
        !hs::VerifyShaManifestBundle(
            RCStage3RelationEndpoint::CoupledBankRoot,
            execution.manifest.sha256d,
            execution.hash_proofs, why)) {
        return Fail(why, "bank:proof");
    }
    std::vector<ha::FixedProgramBoundaryInstance> boundaries;
    if (!ha::BuildShaManifestBoundaryInstances(
            execution.manifest.sha256d, boundaries, why) ||
        !PinEqualsExpected(
            RCStage3RelationEndpoint::CoupledBankRoot,
            hs::BoundaryPort::External, statement,
            execution.manifest.shape,
            execution.manifest.sha256d.commitment,
            boundaries, execution.bank_bytes, why) ||
        !PinEqualsExpected(
            RCStage3RelationEndpoint::CoupledBankRoot,
            hs::BoundaryPort::Final, statement,
            execution.manifest.shape,
            execution.manifest.sha256d.commitment,
            boundaries, execution.bank_digest, why)) {
        return Fail(why, "bank:ports");
    }
    if (why != nullptr) {
        *why = "stage3:coupled_missing_relations:bank_root_all_sha_"
               "instances_ok_bank_page_root_link_pending";
    }
    return true;
}

uint256 CommitRCStage3CoupledSignedRangeManifest(
    const RCStage3CoupledSignedRangeManifest& manifest)
{
    if (manifest.version !=
            kRCStage3CoupledMissingRelationsVersion ||
        manifest.statement_commitment.IsNull() ||
        manifest.scheduled_gemms == 0 ||
        manifest.total_output_cells == 0 ||
        manifest.max_abs == 0 ||
        manifest.max_abs >=
            (uint64_t{1} << kRCStage3SignedRangeBits) ||
        manifest.shard_count == 0 ||
        manifest.schedule_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << RANGE_MANIFEST_DOMAIN;
    hash << manifest.version;
    hash << manifest.statement_commitment;
    hash << CommitRCStage3CoupledShape(manifest.shape);
    hash << manifest.scheduled_gemms;
    hash << manifest.total_output_cells;
    hash << manifest.max_abs;
    hash << manifest.shard_count;
    hash << manifest.schedule_commitment;
    return hash.GetHash();
}

bool BuildRCStage3CoupledSignedRangeManifest(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    RCStage3CoupledSignedRangeManifest& out,
    std::string* why)
{
    return ExpectedSignedRange(statement, shape, out, why);
}

bool MakeRCStage3CoupledSignedRangePin(
    const RCStage3CoupledSignedRangeManifest& manifest,
    uint32_t shard_index,
    RCStage3SignedRangePin& out,
    std::string* why)
{
    out = {};
    if (manifest.commitment.IsNull() ||
        manifest.commitment !=
            CommitRCStage3CoupledSignedRangeManifest(manifest) ||
        shard_index >= manifest.shard_count) {
        return Fail(why, "range:pin_manifest");
    }
    const uint64_t offset =
        static_cast<uint64_t>(shard_index) *
        kRCStage3SignedRangeMaxShardRows;
    if (offset >= manifest.total_output_cells) {
        return Fail(why, "range:pin_offset");
    }
    const uint32_t logical_rows = static_cast<uint32_t>(
        std::min<uint64_t>(
            kRCStage3SignedRangeMaxShardRows,
            manifest.total_output_cells - offset));
    out.statement_commitment = manifest.statement_commitment;
    out.manifest_commitment = manifest.commitment;
    out.layer_ordinal = 0;
    out.shard_index = shard_index;
    out.shard_count = manifest.shard_count;
    out.cell_begin = offset;
    out.logical_rows = logical_rows;
    out.n_rows = NextPowerOfTwo(logical_rows);
    out.max_abs = manifest.max_abs;
    out.column_roots.resize(kRCStage3SignedRangeColumns);
    for (uint32_t i = 0; i < out.column_roots.size(); ++i) {
        out.column_roots[i].column = i;
    }
    return true;
}

uint256 CommitRCStage3CoupledSignedRangeValueRoots(
    const RCStage3CoupledSignedRangeManifest& manifest,
    const std::vector<RCStage3CoupledSignedRangeShardProof>& shards)
{
    if (manifest.commitment.IsNull() ||
        shards.size() != manifest.shard_count) {
        return {};
    }
    HashWriter hash;
    hash << RANGE_VALUE_ROOTS_DOMAIN;
    hash << kRCStage3CoupledMissingRelationsVersion;
    hash << manifest.commitment;
    hash << manifest.total_output_cells;
    hash << static_cast<uint32_t>(shards.size());
    for (uint32_t i = 0; i < shards.size(); ++i) {
        const auto& pin = shards[i].pin;
        if (pin.shard_index != i ||
            pin.column_roots.size() !=
                kRCStage3SignedRangeColumns ||
            pin.column_roots[kRCStage3RangeValue].root.IsNull()) {
            return {};
        }
        hash << pin.cell_begin;
        hash << pin.logical_rows;
        hash << pin.column_roots[kRCStage3RangeValue].root;
    }
    return hash.GetHash();
}

bool VerifyRCStage3CoupledSignedRangeExecution(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& expected_shape,
    const RCStage3CoupledSignedRangeExecution& execution,
    std::string* why)
{
    RCStage3CoupledSignedRangeManifest expected_manifest;
    if (!IsCoupledStatement(statement) ||
        execution.manifest.shape != expected_shape ||
        !ExpectedSignedRange(
            statement, expected_shape,
            expected_manifest, why) ||
        !(execution.manifest == expected_manifest) ||
        execution.shards.size() !=
            execution.manifest.shard_count) {
        return Fail(why, "range:manifest");
    }
    for (uint32_t i = 0; i < execution.shards.size(); ++i) {
        RCStage3SignedRangePin expected_pin;
        if (!MakeRCStage3CoupledSignedRangePin(
                execution.manifest, i, expected_pin, why)) {
            return false;
        }
        const auto& shard = execution.shards[i];
        if (shard.pin.statement_commitment !=
                expected_pin.statement_commitment ||
            shard.pin.manifest_commitment !=
                expected_pin.manifest_commitment ||
            shard.pin.layer_ordinal != expected_pin.layer_ordinal ||
            shard.pin.shard_index != expected_pin.shard_index ||
            shard.pin.shard_count != expected_pin.shard_count ||
            shard.pin.cell_begin != expected_pin.cell_begin ||
            shard.pin.logical_rows != expected_pin.logical_rows ||
            shard.pin.n_rows != expected_pin.n_rows ||
            shard.pin.max_abs != expected_pin.max_abs ||
            shard.pin.column_roots.size() !=
                kRCStage3SignedRangeColumns) {
            return Fail(why, "range:pin");
        }
        for (uint32_t column = 0;
             column < shard.pin.column_roots.size(); ++column) {
            if (shard.pin.column_roots[column].column != column ||
                shard.pin.column_roots[column].root.IsNull()) {
                return Fail(why, "range:column_pin");
            }
        }
        aq::AirConstraintSystem<Fp3> cs;
        if (!ResolveRCStage3SignedRangeKernelConstraintSystem(
                shard.pin, cs, why) ||
            shard.proof.batch.columns.size() !=
                kRCStage3SignedRangeColumns + 1U ||
            shard.proof.batch.column_len.size() !=
                kRCStage3SignedRangeColumns + 1U ||
            shard.proof.batch.n_coeffs != shard.pin.n_rows) {
            return Fail(why, "range:proof_shape");
        }
        for (uint32_t column = 0;
             column < shard.pin.column_roots.size(); ++column) {
            if (shard.proof.batch.columns[column].root !=
                    shard.pin.column_roots[column].root) {
                return Fail(why, "range:proof_root");
            }
        }
        const uint256 seed =
            ComputeRCStage3SignedRangeSeed(shard.pin);
        std::string air_why;
        if (seed.IsNull() ||
            !aq::AirQuotientVerify<Fp3>(
                cs, shard.proof, seed, &air_why)) {
            return Fail(why, "range:air:" + air_why);
        }
    }
    const uint256 value_roots =
        CommitRCStage3CoupledSignedRangeValueRoots(
            execution.manifest, execution.shards);
    if (value_roots.IsNull() ||
        value_roots != execution.value_roots_commitment) {
        return Fail(why, "range:value_roots");
    }
    if (why != nullptr) {
        *why = "stage3:coupled_missing_relations:all_coupled_gemm_"
               "outputs_range_proved_gemm_output_root_link_pending";
    }
    return true;
}

bool VerifyRCStage3CoupledBarrierEndpointExecution(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledBarrierEndpointExecution& execution,
    std::string* why)
{
    if (!IsCoupledStatement(statement) ||
        !StructuralBarrierManifest(shape, execution.manifest, why) ||
        execution.hash_proofs.endpoint !=
            RCStage3RelationEndpoint::CoupledBarrierHash ||
        execution.hash_proofs.statement_commitment !=
            CommitRCStage3CoupledStatement(statement.public_inputs) ||
        !hs::VerifyDirectSha256dManifestBundle(
            RCStage3RelationEndpoint::CoupledBarrierHash,
            execution.manifest.direct,
            execution.hash_proofs, why)) {
        return Fail(why, "barrier:proof");
    }
    std::vector<ha::FixedProgramBoundaryInstance> boundaries;
    if (!ha::BuildDirectSha256dManifestBoundaryInstances(
            execution.manifest.direct, boundaries, why) ||
        !PinEqualsExpected(
            RCStage3RelationEndpoint::CoupledBarrierInput,
            hs::BoundaryPort::External, statement, shape,
            execution.manifest.direct.commitment, boundaries,
            execution.input, why) ||
        !PinEqualsExpected(
            RCStage3RelationEndpoint::CoupledBarrierOutput,
            hs::BoundaryPort::Final, statement, shape,
            execution.manifest.direct.commitment, boundaries,
            execution.output, why)) {
        return Fail(why, "barrier:ports");
    }
    if (why != nullptr) {
        *why = "stage3:coupled_missing_relations:barrier_input_output_"
               "proof_owned_extract_and_digest_root_links_pending";
    }
    return true;
}

bool VerifyRCStage3CoupledDigestEndpointExecution(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledDigestEndpointExecution& execution,
    bool require_public_digest,
    std::string* why)
{
    if (!IsCoupledStatement(statement) ||
        !StructuralDigestManifest(shape, execution.manifest, why) ||
        execution.hash_proofs.endpoint !=
            RCStage3RelationEndpoint::CoupledDigestHash ||
        execution.hash_proofs.statement_commitment !=
            CommitRCStage3CoupledStatement(statement.public_inputs) ||
        !hs::VerifyDirectSha256dManifestBundle(
            RCStage3RelationEndpoint::CoupledDigestHash,
            execution.manifest.direct,
            execution.hash_proofs, why)) {
        return Fail(why, "digest:proof");
    }
    std::vector<ha::FixedProgramBoundaryInstance> boundaries;
    if (!ha::BuildDirectSha256dManifestBoundaryInstances(
            execution.manifest.direct, boundaries, why) ||
        !PinEqualsExpected(
            RCStage3RelationEndpoint::CoupledDigestBankAndBarriers,
            hs::BoundaryPort::External, statement, shape,
            execution.manifest.direct.commitment, boundaries,
            execution.bank_and_barriers, why) ||
        !PinEqualsExpected(
            RCStage3RelationEndpoint::CoupledDigestValue,
            hs::BoundaryPort::Final, statement, shape,
            execution.manifest.direct.commitment, boundaries,
            execution.digest_value, why)) {
        return Fail(why, "digest:ports");
    }
    if (require_public_digest &&
        execution.manifest.direct.digest !=
            statement.public_inputs.coupled_digest) {
        return Fail(why, "digest:outer_statement");
    }
    if (why != nullptr) {
        *why = require_public_digest
            ? "stage3:coupled_missing_relations:digest_output_equals_"
              "outer_statement_inputs_root_links_pending"
            : "stage3:coupled_missing_relations:digest_ports_proof_owned_"
              "outer_statement_and_inputs_root_links_pending";
    }
    return true;
}

std::vector<RCStage3CoupledMissingEndpointAudit>
CurrentRCStage3CoupledMissingEndpointAudit(
    const RCStage3CoupledShape& shape)
{
    using E = RCStage3RelationEndpoint;
    uint64_t bank_bytes{0};
    const bool bank_shape =
        ExpectedBankBytes(shape, bank_bytes, nullptr);
    const auto& tags =
        RCCoupDomainTagsForVersion(shape.transcript_version);
    const size_t bank_tag_len = std::strlen(tags.bank);
    const bool bank_flat_exact =
        bank_shape &&
        bank_bytes <=
            ha::kMaxHashManifestPreimage - std::min(
                bank_tag_len, ha::kMaxHashManifestPreimage);
    std::vector<RCStage3CoupledMissingEndpointAudit> out{
        {E::CoupledBankRoot, true, true, bank_flat_exact,
         bank_flat_exact, false, bank_flat_exact, false, false,
         bank_flat_exact
             ? "executed equality from bank-page values to SHA external words"
             : "flat V1 bank SHA manifest exceeds the 16 MiB preimage cap; "
               "streaming recursive SHA aggregation is required"},
        {E::CoupledGemmSignedRange, true, true, true, true, false,
         true, false, false,
         "executed equality from GEMM output cells to ordered range VALUE roots"},
        {E::CoupledBarrierInput, true, true, true, true, false,
         false, false, false,
         "executed Extract-output to barrier-input projection link"},
        {E::CoupledBarrierOutput, true, true, true, true, false,
         true, false, false,
         "executed barrier-output to digest/next-barrier link"},
        {E::CoupledDigestBankAndBarriers, true, true, true, true, false,
         true, false, false,
         "the exact ordered bank+barrier hash-input vector executes; "
         "transitive producer closure still waits on endpoint 28 bank-page "
         "provenance and endpoint 47 barrier-input provenance"},
        {E::CoupledDigestValue, true, true, true, true, true,
         true, false, false,
         "digest output equals the outer statement, but the bank and "
         "barrier input producer graph remains incomplete"},
    };
    return out;
}

static_assert(kRCStage3CoupledBankRootLocalEngineExecutable);
static_assert(kRCStage3CoupledSignedRangeLocalEngineExecutable);
static_assert(kRCStage3CoupledBarrierPortsLocalEngineExecutable);
static_assert(kRCStage3CoupledDigestPortsLocalEngineExecutable);
static_assert(!kRCStage3CoupledMissingRelationsAuthorityReady);

} // namespace matmul::v4::rc
