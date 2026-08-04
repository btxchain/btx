// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_episode_semantic_alg.h>

#include <hash.h>
#include <matmul/matmul_v4_rc_stage3_constraint_bytecode.h>
#include <matmul/matmul_v4_rc_stage3_role_bytecode.h>

#include <algorithm>
#include <array>
#include <limits>

namespace matmul::v4::rc::episode_semantic_alg {
namespace {

using Fp3 = gf::Fp3;

constexpr char SCHEDULE_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_SEMANTIC_ALG_SCHEDULE_V2";
constexpr char MANIFEST_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_SEMANTIC_ALG_MANIFEST_V2";
constexpr char CS_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_SEMANTIC_ALG_EXPECTED_CS_V2";
constexpr char SEED_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_SEMANTIC_ALG_SAFE_SPLIT_RAP_V2";
constexpr char PROOF_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_SEMANTIC_ALG_PROOF_V2";
constexpr char ALL_INSTANCE_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_SEMANTIC_ALG_ALL_INSTANCES_V2";
constexpr char BUNDLE_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_SEMANTIC_ALG_BUNDLE_V2";

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:episode_semantic_alg:" + detail;
    }
    return false;
}

uint32_t NextPowerOfTwo(uint32_t value)
{
    uint32_t out = 2;
    while (out < value) out <<= 1;
    return out;
}

bool PowerOfTwo(uint32_t value)
{
    return value >= 2 && (value & (value - 1U)) == 0;
}

Fp3 U64(uint64_t value)
{
    return gf::FromU64_3(value);
}

uint256 PackDigest(const alg_hash::Digest& digest)
{
    return Fri3AlgDigestToUint256(digest);
}

uint256 ScheduleCommitment(const LeafManifestV2& manifest)
{
    HashWriter hash;
    hash << SCHEDULE_DOMAIN << manifest.version;
    hash << static_cast<uint16_t>(manifest.endpoint);
    hash << static_cast<uint16_t>(manifest.role);
    hash << manifest.layer_ordinal;
    hash << manifest.shard_ordinal;
    hash << manifest.shard_count;
    hash << manifest.total_instance_count;
    hash << manifest.value_begin;
    hash << manifest.logical_rows;
    hash << manifest.n_rows;
    hash << manifest.address_begin;
    hash << manifest.address_stride;
    return hash.GetHash();
}

uint256 ExpectedCsCommitment(const LeafManifestV2& manifest)
{
    HashWriter hash;
    hash << CS_DOMAIN << manifest.version;
    hash << manifest.program_table_sha256d;
    hash << manifest.program_table_alg;
    hash << manifest.schedule_commitment;
    hash << manifest.authority_r0_root;
    const auto base = CanonicalBaseColumnsV2();
    hash << static_cast<uint32_t>(base.size());
    for (uint32_t column : base) hash << column;
    hash << kRCStage3EpisodeMemoryColumns;
    hash << manifest.n_rows;
    return hash.GetHash();
}

uint256 ManifestCommitment(const LeafManifestV2& manifest)
{
    HashWriter hash;
    hash << MANIFEST_DOMAIN << manifest.magic << manifest.version;
    hash << static_cast<uint16_t>(manifest.endpoint);
    hash << static_cast<uint16_t>(manifest.role);
    hash << manifest.layer_ordinal;
    hash << manifest.shard_ordinal;
    hash << manifest.shard_count;
    hash << manifest.total_instance_count;
    hash << manifest.value_begin;
    hash << manifest.logical_rows;
    hash << manifest.n_rows;
    hash << manifest.address_begin;
    hash << manifest.address_stride;
    hash << manifest.statement_commitment;
    hash << manifest.producer_vector_root_alg;
    hash << manifest.program_table_sha256d;
    hash << manifest.program_table_alg;
    hash << manifest.schedule_commitment;
    hash << manifest.authority_r0_root;
    hash << manifest.expected_cs_commitment;
    return hash.GetHash();
}

uint256 Seed(const LeafManifestV2& manifest)
{
    HashWriter hash;
    hash << SEED_DOMAIN << manifest.version;
    hash << manifest.statement_commitment;
    hash << manifest.manifest_commitment;
    hash << manifest.expected_cs_commitment;
    hash << manifest.authority_r0_root;
    return hash.GetHash();
}

uint256 ProofCommitment(
    const LeafManifestV2& manifest,
    const aq::AirQuotientSplitRapRowsProof& proof,
    uint64_t* bytes_out)
{
    std::vector<unsigned char> bytes;
    const size_t written =
        aq::SerializeAirQuotientSplitRapRowsProof(proof, bytes);
    if (bytes_out != nullptr) *bytes_out = written;
    if (written == 0 || written != bytes.size()) return {};
    HashWriter hash;
    hash << PROOF_DOMAIN << kVersionV2;
    hash << manifest.manifest_commitment;
    hash << bytes;
    return hash.GetHash();
}

bool FillSchedule(
    const LeafManifestV2& manifest,
    std::vector<std::vector<Fp3>>& columns,
    std::string* why)
{
    if (!PowerOfTwo(manifest.n_rows) ||
        manifest.n_rows > kMaxRowsV2 ||
        manifest.logical_rows == 0 ||
        manifest.logical_rows > manifest.n_rows) {
        return Fail(why, "schedule_shape");
    }
    columns.assign(
        kRCStage3EpisodeMemoryColumns,
        std::vector<Fp3>(manifest.n_rows, Fp3::Zero()));
    for (uint32_t row = 0; row < manifest.n_rows; ++row) {
        columns[kRCStage3EpisodeMemoryEndpoint][row] =
            U64(static_cast<uint16_t>(manifest.endpoint));
        columns[kRCStage3EpisodeMemoryRole][row] =
            U64(static_cast<uint16_t>(manifest.role));
    }
    for (uint32_t row = 0; row < manifest.logical_rows; ++row) {
        columns[kRCStage3EpisodeMemoryActive][row] = Fp3::One();
        columns[kRCStage3EpisodeMemoryAddress][row] =
            U64(manifest.address_begin + row);
        columns[kRCStage3EpisodeMemoryRemaining][row] =
            U64(manifest.logical_rows - row);
    }
    return true;
}

bool BuildUnpinnedSystem(
    const LeafManifestV2& manifest,
    aq::AirConstraintSystem<Fp3>& out,
    std::string* why)
{
    cb::ProgramTable table;
    if (!BuildCanonicalProgramTableV2(
            manifest.endpoint, table, why) ||
        cb::CommitProgramTable(table) !=
            manifest.program_table_sha256d ||
        PackDigest(cb::CommitProgramTableAlgHash(table)) !=
            manifest.program_table_alg ||
        !cb::BuildAirConstraintSystemFromProgramTable(
            table, manifest.n_rows, out, why)) {
        return Fail(why, "canonical_program");
    }
    std::vector<std::vector<Fp3>> schedule;
    if (!FillSchedule(manifest, schedule, why)) return false;
    for (uint32_t column = kRCStage3EpisodeMemoryActive;
         column <= kRCStage3EpisodeMemoryRole; ++column) {
        out.preprocessed.emplace_back(
            column, std::move(schedule[column]));
    }
    out.preprocessed_pin_ood = true;
    return true;
}

bool BuildPrototype(
    RCStage3RelationEndpoint endpoint,
    uint32_t layer_ordinal,
    uint32_t shard_ordinal,
    uint32_t shard_count,
    uint64_t total,
    uint64_t value_begin,
    uint32_t logical_rows,
    const uint256& statement_commitment,
    const uint256& producer_vector_root_alg,
    LeafManifestV2& out,
    std::string* why)
{
    const auto role = RCStage3EpisodeEndpointRole(endpoint);
    if (!IsSupportedEndpointV2(endpoint) ||
        !role.has_value() ||
        statement_commitment.IsNull() ||
        producer_vector_root_alg.IsNull() ||
        total == 0 || logical_rows == 0 ||
        logical_rows > kMaxRowsV2 ||
        shard_count == 0 ||
        shard_ordinal >= shard_count ||
        value_begin >= total ||
        logical_rows > total - value_begin) {
        return Fail(why, "prototype_shape");
    }
    cb::ProgramTable table;
    if (!BuildCanonicalProgramTableV2(endpoint, table, why)) {
        return false;
    }
    out = {};
    out.endpoint = endpoint;
    out.role = *role;
    out.layer_ordinal = layer_ordinal;
    out.shard_ordinal = shard_ordinal;
    out.shard_count = shard_count;
    out.total_instance_count = total;
    out.value_begin = value_begin;
    out.logical_rows = logical_rows;
    out.n_rows = NextPowerOfTwo(logical_rows);
    out.address_begin =
        CanonicalAddressV2(endpoint, layer_ordinal, value_begin);
    out.address_stride = 1;
    out.statement_commitment = statement_commitment;
    out.producer_vector_root_alg = producer_vector_root_alg;
    out.program_table_sha256d =
        cb::CommitProgramTable(table);
    out.program_table_alg =
        PackDigest(cb::CommitProgramTableAlgHash(table));
    out.schedule_commitment = ScheduleCommitment(out);
    if (out.address_begin == 0 ||
        out.program_table_sha256d.IsNull() ||
        out.program_table_alg.IsNull() ||
        out.schedule_commitment.IsNull()) {
        return Fail(why, "prototype_commitment");
    }
    return true;
}

uint256 AllInstanceCommitment(const BundleV2& bundle)
{
    HashWriter hash;
    hash << ALL_INSTANCE_DOMAIN << bundle.version;
    hash << static_cast<uint16_t>(bundle.endpoint);
    hash << bundle.layer_ordinal;
    hash << bundle.total_instance_count;
    hash << bundle.statement_commitment;
    hash << bundle.producer_vector_root_alg;
    hash << static_cast<uint32_t>(bundle.leaves.size());
    for (const auto& leaf : bundle.leaves) {
        hash << leaf.manifest.shard_ordinal;
        hash << leaf.manifest.shard_count;
        hash << leaf.manifest.value_begin;
        hash << leaf.manifest.logical_rows;
        hash << leaf.manifest.address_begin;
        hash << leaf.manifest.authority_r0_root;
        hash << leaf.manifest.manifest_commitment;
    }
    return hash.GetHash();
}

} // namespace

bool IsSupportedEndpointV2(RCStage3RelationEndpoint endpoint)
{
    return endpoint ==
               RCStage3RelationEndpoint::EpisodeGemmOperandA ||
           endpoint ==
               RCStage3RelationEndpoint::EpisodeGemmOperandB ||
           endpoint ==
               RCStage3RelationEndpoint::EpisodeGemmOutputY;
}

std::vector<uint32_t> CanonicalBaseColumnsV2()
{
    return {
        kRCStage3EpisodeMemoryActive,
        kRCStage3EpisodeMemoryAddress,
        kRCStage3EpisodeMemoryRemaining,
        kRCStage3EpisodeMemoryEndpoint,
        kRCStage3EpisodeMemoryRole,
        kRCStage3EpisodeMemoryValue,
    };
}

uint64_t CanonicalAddressV2(
    RCStage3RelationEndpoint endpoint,
    uint32_t layer_ordinal,
    uint64_t value_ordinal)
{
    if (!IsSupportedEndpointV2(endpoint) ||
        layer_ordinal > 0xffffU ||
        value_ordinal > 0xffffffffULL) {
        return 0;
    }
    return UINT64_C(0x5300000000000000) |
        (static_cast<uint64_t>(
             static_cast<uint16_t>(endpoint)) << 48) |
        (static_cast<uint64_t>(layer_ordinal) << 32) |
        value_ordinal;
}

bool BuildCanonicalProgramTableV2(
    RCStage3RelationEndpoint endpoint,
    cb::ProgramTable& out,
    std::string* why)
{
    const auto role = RCStage3EpisodeEndpointRole(endpoint);
    if (!IsSupportedEndpointV2(endpoint) || !role.has_value() ||
        !BuildRCStage3EpisodeSemanticMemoryProgramTable(
            *role, out, why) ||
        out.current_width !=
            kRCStage3EpisodeMemoryColumns ||
        out.challenge_width != 0 ||
        !cb::ProgramTableIsChallengeIndependent(out)) {
        out = {};
        return Fail(why, "program_table");
    }
    return true;
}

bool ValidateLeafManifestV2(
    const LeafManifestV2& manifest,
    std::string* why)
{
    if (manifest.magic != kMagicV2 ||
        manifest.version != kVersionV2 ||
        !IsSupportedEndpointV2(manifest.endpoint)) {
        return Fail(why, "manifest_format");
    }
    const auto role =
        RCStage3EpisodeEndpointRole(manifest.endpoint);
    if (!role.has_value() || manifest.role != *role ||
        manifest.statement_commitment.IsNull() ||
        manifest.producer_vector_root_alg.IsNull() ||
        manifest.authority_r0_root.IsNull() ||
        !Fri3AlgDigestFromUint256(
             manifest.authority_r0_root).has_value() ||
        manifest.shard_count == 0 ||
        manifest.shard_ordinal >= manifest.shard_count ||
        manifest.total_instance_count == 0 ||
        manifest.value_begin >=
            manifest.total_instance_count ||
        manifest.logical_rows == 0 ||
        manifest.logical_rows > kMaxRowsV2 ||
        manifest.logical_rows >
            manifest.total_instance_count -
                manifest.value_begin ||
        !PowerOfTwo(manifest.n_rows) ||
        manifest.n_rows !=
            NextPowerOfTwo(manifest.logical_rows) ||
        manifest.address_stride != 1 ||
        manifest.address_begin != CanonicalAddressV2(
            manifest.endpoint, manifest.layer_ordinal,
            manifest.value_begin)) {
        return Fail(why, "manifest_shape");
    }
    cb::ProgramTable table;
    if (!BuildCanonicalProgramTableV2(
            manifest.endpoint, table, why) ||
        manifest.program_table_sha256d !=
            cb::CommitProgramTable(table) ||
        manifest.program_table_alg != PackDigest(
            cb::CommitProgramTableAlgHash(table))) {
        return Fail(why, "manifest_program");
    }
    if (manifest.schedule_commitment !=
            ScheduleCommitment(manifest) ||
        manifest.expected_cs_commitment !=
            ExpectedCsCommitment(manifest) ||
        manifest.manifest_commitment !=
            ManifestCommitment(manifest)) {
        return Fail(why, "manifest_commitment");
    }
    return true;
}

bool BuildExpectedConstraintSystemV2(
    const LeafManifestV2& manifest,
    aq::AirConstraintSystem<Fp3>& out,
    std::string* why)
{
    if (!ValidateLeafManifestV2(manifest, why) ||
        !BuildUnpinnedSystem(manifest, out, why)) {
        return false;
    }
    out.preprocessed_row_group_roots.push_back({
        .version = 1,
        .role = aq::AirPreprocessedRowGroupRole::kR0,
        .ordered_columns = CanonicalBaseColumnsV2(),
        .root = manifest.authority_r0_root,
    });
    return true;
}

bool BuildWitnessV2(
    const LeafManifestV2& manifest,
    const std::vector<Fp3>& values,
    std::vector<std::vector<Fp3>>& out,
    std::string* why)
{
    if (!ValidateLeafManifestV2(manifest, why) ||
        values.size() != manifest.logical_rows ||
        !FillSchedule(manifest, out, why)) {
        return Fail(why, "witness_shape");
    }
    std::copy(
        values.begin(), values.end(),
        out[kRCStage3EpisodeMemoryValue].begin());
    out[kRCStage3EpisodeMemoryExport] =
        out[kRCStage3EpisodeMemoryValue];

    aq::AirConstraintSystem<Fp3> unpinned;
    if (!BuildUnpinnedSystem(manifest, unpinned, why)) {
        return false;
    }
    const auto r0 =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            unpinned, out, CanonicalBaseColumnsV2());
    if (!r0.valid ||
        r0.base_row_commitment !=
            manifest.authority_r0_root) {
        return Fail(why, "witness_r0_root");
    }
    return true;
}

VerificationInputV2 BuildVerificationInputV2(
    const LeafReceiptV2& receipt)
{
    VerificationInputV2 out;
    std::string why;
    if (receipt.version != kVersionV2 ||
        receipt.normalized_recursive_source ||
        receipt.recursively_consumed ||
        receipt.base_column_indices !=
            CanonicalBaseColumnsV2() ||
        receipt.public_fs_seed !=
            Seed(receipt.manifest) ||
        receipt.manifest.expected_cs_commitment.IsNull() ||
        !BuildExpectedConstraintSystemV2(
            receipt.manifest, out.expected_cs, &why)) {
        out.note = why.empty()
            ? "stage3:episode_semantic_alg:verification_input"
            : why;
        return out;
    }
    out.expected_base_column_indices =
        receipt.base_column_indices;
    out.proof = &receipt.proof;
    out.public_fs_seed = receipt.public_fs_seed;
    out.expected_cs_commitment =
        receipt.manifest.expected_cs_commitment;
    out.valid = true;
    out.note =
        "stage3:episode_semantic_alg:expected_cs_proof_seed";
    return out;
}

bool ProveBundleWithOwningValuesV2(
    RCStage3RelationEndpoint endpoint,
    uint32_t layer_ordinal,
    const uint256& statement_commitment,
    const uint256& expected_producer_vector_root_alg,
    const std::vector<Fp3>& values,
    BundleV2& out,
    std::string* why)
{
    out = {};
    if (!IsSupportedEndpointV2(endpoint) ||
        statement_commitment.IsNull() ||
        values.empty() ||
        values.size() > std::numeric_limits<uint32_t>::max() ||
        RCStage3VectorRootAlgCommitment(values) !=
            expected_producer_vector_root_alg) {
        return Fail(why, "prove_source_root");
    }
    const uint64_t total = values.size();
    const uint32_t shard_count =
        static_cast<uint32_t>(
            (total + kMaxRowsV2 - 1) / kMaxRowsV2);
    out.version = kVersionV2;
    out.endpoint = endpoint;
    out.layer_ordinal = layer_ordinal;
    out.total_instance_count = total;
    out.statement_commitment = statement_commitment;
    out.producer_vector_root_alg =
        expected_producer_vector_root_alg;
    out.leaves.reserve(shard_count);

    uint64_t value_begin = 0;
    for (uint32_t shard = 0; shard < shard_count; ++shard) {
        const uint32_t logical_rows =
            static_cast<uint32_t>(
                std::min<uint64_t>(
                    kMaxRowsV2, total - value_begin));
        std::vector<Fp3> shard_values(
            values.begin() + value_begin,
            values.begin() + value_begin + logical_rows);
        LeafReceiptV2 receipt;
        auto& manifest = receipt.manifest;
        if (!BuildPrototype(
                endpoint, layer_ordinal, shard,
                shard_count, total, value_begin,
                logical_rows, statement_commitment,
                expected_producer_vector_root_alg,
                manifest, why)) {
            out = {};
            return false;
        }
        std::vector<std::vector<Fp3>> columns;
        if (!FillSchedule(manifest, columns, why)) {
            out = {};
            return false;
        }
        std::copy(
            shard_values.begin(), shard_values.end(),
            columns[kRCStage3EpisodeMemoryValue].begin());
        columns[kRCStage3EpisodeMemoryExport] =
            columns[kRCStage3EpisodeMemoryValue];
        aq::AirConstraintSystem<Fp3> unpinned;
        if (!BuildUnpinnedSystem(
                manifest, unpinned, why)) {
            out = {};
            return false;
        }
        const auto r0 =
            aq::AirQuotientBuildTwoEpochBaseRowSession(
                unpinned, columns,
                CanonicalBaseColumnsV2());
        if (!r0.valid ||
            r0.base_row_commitment.IsNull()) {
            out = {};
            return Fail(
                why, "prove_r0:" + r0.note);
        }
        manifest.authority_r0_root =
            r0.base_row_commitment;
        manifest.expected_cs_commitment =
            ExpectedCsCommitment(manifest);
        manifest.manifest_commitment =
            ManifestCommitment(manifest);
        aq::AirConstraintSystem<Fp3> cs;
        if (!ValidateLeafManifestV2(manifest, why) ||
            !BuildExpectedConstraintSystemV2(
                manifest, cs, why) ||
            !BuildWitnessV2(
                manifest, shard_values, columns, why)) {
            out = {};
            return false;
        }
        const auto retained =
            aq::AirQuotientBuildTwoEpochBaseRowSession(
                cs, columns, CanonicalBaseColumnsV2());
        if (!retained.valid ||
            retained.base_row_commitment !=
                manifest.authority_r0_root) {
            out = {};
            return Fail(why, "prove_retained_r0");
        }
        receipt.base_column_indices =
            CanonicalBaseColumnsV2();
        receipt.public_fs_seed = Seed(manifest);
        const auto proved =
            aq::AirQuotientProveRowsSplitRapSafeV2(
                cs, columns,
                receipt.base_column_indices,
                receipt.public_fs_seed, {}, &retained);
        if (!proved.ok || !proved.division_exact) {
            out = {};
            return Fail(
                why, "prove_split_rap:" + proved.note);
        }
        receipt.proof = proved.proof;
        receipt.proof_commitment = ProofCommitment(
            manifest, receipt.proof,
            &receipt.proof_bytes);
        receipt.normalized_recursive_source = false;
        receipt.recursively_consumed = false;
        if (receipt.proof_commitment.IsNull() ||
            receipt.proof_bytes == 0) {
            out = {};
            return Fail(why, "prove_codec");
        }
        out.leaves.push_back(std::move(receipt));
        value_begin += logical_rows;
    }
    if (value_begin != total) {
        out = {};
        return Fail(why, "prove_coverage");
    }
    out.exact_all_instance_commitment =
        AllInstanceCommitment(out);
    out.host_owning_values_bound = true;
    out.normalized_recursive_source = false;
    out.recursively_consumed = false;
    out.bundle_commitment = ComputeBundleCommitmentV2(out);
    const auto audit = VerifyBundleWithOwningValuesV2(
        endpoint, layer_ordinal, statement_commitment,
        expected_producer_vector_root_alg, values, out);
    if (!audit.accepted ||
        !audit.host_owning_values_bound) {
        out = {};
        return Fail(
            why, "prove_self_verify:" + audit.note);
    }
    return true;
}

VerificationAuditV2 VerifyBundleV2(
    RCStage3RelationEndpoint expected_endpoint,
    uint32_t expected_layer_ordinal,
    const uint256& expected_statement_commitment,
    uint64_t expected_total_instance_count,
    const uint256& expected_producer_vector_root_alg,
    const BundleV2& bundle)
{
    VerificationAuditV2 out;
    auto fail = [&](const std::string& detail) {
        out.note =
            "stage3:episode_semantic_alg:verify:" + detail;
        return out;
    };
    if (bundle.version != kVersionV2 ||
        !IsSupportedEndpointV2(expected_endpoint) ||
        bundle.endpoint != expected_endpoint ||
        bundle.layer_ordinal !=
            expected_layer_ordinal ||
        bundle.total_instance_count !=
            expected_total_instance_count ||
        bundle.statement_commitment !=
            expected_statement_commitment ||
        bundle.producer_vector_root_alg !=
            expected_producer_vector_root_alg ||
        expected_statement_commitment.IsNull() ||
        expected_producer_vector_root_alg.IsNull() ||
        expected_total_instance_count == 0 ||
        bundle.normalized_recursive_source ||
        bundle.recursively_consumed) {
        return fail("public_shape");
    }
    const uint32_t expected_shards =
        static_cast<uint32_t>(
            (expected_total_instance_count +
             kMaxRowsV2 - 1) / kMaxRowsV2);
    if (bundle.leaves.size() != expected_shards) {
        return fail("leaf_count");
    }
    uint64_t covered = 0;
    for (uint32_t i = 0; i < expected_shards; ++i) {
        const auto& receipt = bundle.leaves[i];
        const auto& manifest = receipt.manifest;
        const uint32_t expected_rows =
            static_cast<uint32_t>(
                std::min<uint64_t>(
                    kMaxRowsV2,
                    expected_total_instance_count -
                        covered));
        if (manifest.endpoint != expected_endpoint ||
            manifest.layer_ordinal !=
                expected_layer_ordinal ||
            manifest.shard_ordinal != i ||
            manifest.shard_count != expected_shards ||
            manifest.total_instance_count !=
                expected_total_instance_count ||
            manifest.value_begin != covered ||
            manifest.logical_rows != expected_rows ||
            manifest.address_begin != CanonicalAddressV2(
                expected_endpoint,
                expected_layer_ordinal, covered) ||
            manifest.statement_commitment !=
                expected_statement_commitment ||
            manifest.producer_vector_root_alg !=
                expected_producer_vector_root_alg ||
            !ValidateLeafManifestV2(
                manifest, &out.note)) {
            return fail("partition");
        }
        const auto input =
            BuildVerificationInputV2(receipt);
        if (!input.valid || input.proof == nullptr ||
            input.expected_cs_commitment !=
                manifest.expected_cs_commitment) {
            return fail("verification_input:" + input.note);
        }
        if (receipt.proof.version !=
                aq::kAirQuotientSplitRapRowsSafeProofVersionV2 ||
            receipt.proof.batch.groups.size() != 3 ||
            Fri3AlgDigestToUint256(
                receipt.proof.batch.groups[0]
                    .row_commit.root) !=
                manifest.authority_r0_root) {
            return fail("proof_shape");
        }
        uint64_t proof_bytes = 0;
        if (ProofCommitment(
                manifest, receipt.proof,
                &proof_bytes) !=
                receipt.proof_commitment ||
            proof_bytes != receipt.proof_bytes) {
            return fail("proof_commitment");
        }
        std::string air_why;
        if (!aq::AirQuotientVerifyRowsSplitRapSafeV2(
                input.expected_cs, *input.proof,
                input.expected_base_column_indices,
                input.public_fs_seed, &air_why)) {
            return fail("split_rap:" + air_why);
        }
        covered += manifest.logical_rows;
        ++out.verified_leaves;
    }
    if (covered != expected_total_instance_count) {
        return fail("coverage");
    }
    if (bundle.exact_all_instance_commitment !=
            AllInstanceCommitment(bundle) ||
        bundle.bundle_commitment !=
            ComputeBundleCommitmentV2(bundle)) {
        return fail("bundle_commitment");
    }
    out.covered_instances = covered;
    out.canonical_program_table = true;
    out.exact_partition = true;
    out.exact_addresses = true;
    out.all_safe_split_rap_proofs_verified = true;
    out.host_owning_values_bound = false;
    out.normalized_recursive_source = false;
    out.recursively_consumed = false;
    out.accepted = true;
    out.note =
        "stage3:episode_semantic_alg:native_safe_receipts_verified;"
        "producer_value_equality_requires_owning_adapter_or_parent";
    return out;
}

VerificationAuditV2 VerifyBundleWithOwningValuesV2(
    RCStage3RelationEndpoint expected_endpoint,
    uint32_t expected_layer_ordinal,
    const uint256& expected_statement_commitment,
    const uint256& expected_producer_vector_root_alg,
    const std::vector<Fp3>& values,
    const BundleV2& bundle)
{
    auto out = VerifyBundleV2(
        expected_endpoint, expected_layer_ordinal,
        expected_statement_commitment, values.size(),
        expected_producer_vector_root_alg, bundle);
    if (!out.accepted) return out;
    if (values.empty() ||
        RCStage3VectorRootAlgCommitment(values) !=
            expected_producer_vector_root_alg) {
        out.accepted = false;
        out.note =
            "stage3:episode_semantic_alg:owning_vector_root";
        return out;
    }
    uint64_t begin = 0;
    for (const auto& receipt : bundle.leaves) {
        const uint32_t count =
            receipt.manifest.logical_rows;
        if (begin + count > values.size()) {
            out.accepted = false;
            out.note =
                "stage3:episode_semantic_alg:owning_partition";
            return out;
        }
        std::vector<Fp3> shard_values(
            values.begin() + begin,
            values.begin() + begin + count);
        std::vector<std::vector<Fp3>> columns;
        if (!BuildWitnessV2(
                receipt.manifest, shard_values,
                columns, &out.note)) {
            out.accepted = false;
            return out;
        }
        begin += count;
    }
    if (begin != values.size()) {
        out.accepted = false;
        out.note =
            "stage3:episode_semantic_alg:owning_coverage";
        return out;
    }
    out.host_owning_values_bound = true;
    out.normalized_recursive_source = false;
    out.recursively_consumed = false;
    out.note =
        "stage3:episode_semantic_alg:host_owning_values_exact;"
        "normalized_recursive_source_open";
    return out;
}

uint256 ComputeBundleCommitmentV2(
    const BundleV2& bundle)
{
    HashWriter hash;
    hash << BUNDLE_DOMAIN << bundle.version;
    hash << static_cast<uint16_t>(bundle.endpoint);
    hash << bundle.layer_ordinal;
    hash << bundle.total_instance_count;
    hash << bundle.statement_commitment;
    hash << bundle.producer_vector_root_alg;
    hash << bundle.exact_all_instance_commitment;
    hash << static_cast<uint32_t>(bundle.leaves.size());
    for (const auto& leaf : bundle.leaves) {
        hash << leaf.manifest.manifest_commitment;
        hash << leaf.public_fs_seed;
        hash << leaf.proof_commitment;
        hash << leaf.proof_bytes;
    }
    hash << bundle.host_owning_values_bound;
    hash << bundle.normalized_recursive_source;
    hash << bundle.recursively_consumed;
    return hash.GetHash();
}

} // namespace matmul::v4::rc::episode_semantic_alg
