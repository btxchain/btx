// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_episode_relation_product.h>

#include <hash.h>

#include <algorithm>
#include <limits>

namespace matmul::v4::rc {
namespace {

using Fp3 = gkr_field::Fp3;

constexpr char VECTOR_ROOT_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_WIRING_VECTOR_ROOT_V1";
constexpr char EDGE_PRODUCT_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_WIRING_EDGE_PRODUCT_V1";
constexpr char CLOSURE_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_WIRING_CLOSURE_V1";

bool Fail(std::string* why, const std::string& message)
{
    if (why != nullptr) {
        *why = "stage3:episode_relation_product:" + message;
    }
    return false;
}

uint32_t NextPowerOfTwo(uint32_t value)
{
    uint32_t out = 2;
    while (out < value) out <<= 1;
    return out;
}

bool CheckedMul(uint64_t a, uint64_t b, uint64_t& out)
{
    if (a != 0 && b > std::numeric_limits<uint64_t>::max() / a) {
        return false;
    }
    out = a * b;
    return true;
}

uint64_t EdgeAddressBegin(uint32_t first_column)
{
    // Λ currently uses far fewer than 2^24 committed columns.  Reserving
    // 32 address bits for the row keeps every <=2^28 tensor vector disjoint.
    return kRCStage3EpisodeRelationProductAddressBase |
           (static_cast<uint64_t>(first_column) << 32);
}

uint256 RegisteredRoot(
    const RCStage3GemmExtractLayerManifest& layer,
    RCStage3EpisodeWiringOperandSlot slot)
{
    return slot == RCStage3EpisodeWiringOperandSlot::A
        ? layer.bindings.operand_a_root
        : layer.bindings.operand_b_root;
}

bool SameScheduleIdentity(
    const RCStage3EpisodeWiringCopyScheduleEntry& a,
    const RCStage3EpisodeWiringCopyScheduleEntry& b)
{
    return a == b;
}

uint256 LocalProofCommitment(
    const RCStage3EpisodeWiringCopyAirShard& shard)
{
    if (shard.proof.batch.columns.size() != 3) return {};
    HashWriter hash;
    hash << "BTX_RC_STAGE3_EPISODE_WIRING_LOCAL_PROOF_V1";
    hash << shard.shard_index;
    hash << shard.value_begin;
    hash << ComputeRCStage3EpisodeAirPinCommitment(shard.pin);
    hash << shard.proof.batch.n_coeffs;
    hash << shard.proof.batch.pow_grind_nonce;
    for (const auto& column : shard.proof.batch.columns) {
        hash << column.root;
    }
    hash << shard.proof.trace_commit;
    return hash.GetHash();
}

bool ValidateStatementAndManifest(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    std::string* why)
{
    if (!ValidateRCStage3GemmExtractManifestBinding(
            statement, manifest, why)) {
        return false;
    }
    if (manifest.statement_commitment !=
        RCStage3EpisodeStatementCommitment(statement)) {
        return Fail(why, "statement_commitment");
    }
    return true;
}

} // namespace

std::optional<std::vector<RCStage3EpisodeWiringCopyScheduleEntry>>
BuildRCStage3EpisodeWiringCopySchedule(
    const RCStage3GemmExtractManifest& manifest,
    std::string* why)
{
    if (!ValidateRCStage3GemmExtractManifest(manifest, why)) {
        return std::nullopt;
    }
    const RCGkrLayout layout = RCGkrTraceLayout(manifest.params);
    if (layout.layers.size() != manifest.layers.size()) {
        Fail(why, "schedule:layout_size");
        return std::nullopt;
    }

    std::vector<RCStage3EpisodeWiringCopyScheduleEntry> out;
    out.reserve(layout.layers.size() * 2);
    for (uint32_t layer_ordinal = 0;
         layer_ordinal < layout.layers.size(); ++layer_ordinal) {
        const auto& layer = layout.layers[layer_ordinal];
        const auto& registered = manifest.layers[layer_ordinal];
        const auto append =
            [&](RCStage3EpisodeWiringOperandSlot slot,
                const RCGkrOperandRef& ref,
                uint64_t rows,
                uint64_t cols) -> bool {
            if (ref.transpose) return true;
            uint64_t count{0};
            if (!CheckedMul(rows, cols, count) || count == 0 ||
                ref.n_chunks == 0 || ref.first_column >= (1U << 24) ||
                count > (uint64_t{1} << 32)) {
                return false;
            }
            RCStage3EpisodeWiringCopyScheduleEntry entry;
            entry.schedule_index = out.size();
            entry.layer_ordinal = layer_ordinal;
            entry.slot = slot;
            entry.first_column = ref.first_column;
            entry.n_chunks = ref.n_chunks;
            entry.value_count = count;
            entry.address_begin = EdgeAddressBegin(ref.first_column);
            entry.registered_vector_root =
                RegisteredRoot(registered, slot);
            if (entry.registered_vector_root.IsNull()) return false;
            out.push_back(std::move(entry));
            return true;
        };
        if (!append(
                RCStage3EpisodeWiringOperandSlot::A,
                layer.a, layer.m, layer.k) ||
            !append(
                RCStage3EpisodeWiringOperandSlot::B,
                layer.b, layer.k, layer.n)) {
            Fail(why, "schedule:edge_shape");
            return std::nullopt;
        }
    }
    if (out.empty()) {
        Fail(why, "schedule:empty");
        return std::nullopt;
    }
    return out;
}

uint256 ComputeRCStage3EpisodeWiringVectorRoot(
    const uint256& statement_commitment,
    uint32_t first_column,
    uint32_t n_chunks,
    uint64_t value_count,
    const std::vector<uint256>& ordered_shard_roots)
{
    if (statement_commitment.IsNull() || n_chunks == 0 ||
        value_count == 0 || first_column >= (1U << 24)) {
        return {};
    }
    const uint64_t expected_shards =
        (value_count + kRCStage3EpisodeSemanticMaxRows - 1) /
        kRCStage3EpisodeSemanticMaxRows;
    if (ordered_shard_roots.size() != expected_shards ||
        std::any_of(
            ordered_shard_roots.begin(), ordered_shard_roots.end(),
            [](const uint256& root) { return root.IsNull(); })) {
        return {};
    }
    HashWriter hash;
    hash << VECTOR_ROOT_DOMAIN;
    hash << kRCStage3EpisodeRelationProductVersion;
    hash << statement_commitment;
    hash << first_column;
    hash << n_chunks;
    hash << value_count;
    hash << static_cast<uint32_t>(ordered_shard_roots.size());
    for (const auto& root : ordered_shard_roots) hash << root;
    return hash.GetHash();
}

std::optional<uint256>
ComputeRCStage3EpisodeWiringVectorRootFromValues(
    const uint256& statement_commitment,
    uint32_t first_column,
    uint32_t n_chunks,
    const std::vector<Fp3>& values,
    std::string* why)
{
    if (values.empty()) {
        Fail(why, "vector_root:empty");
        return std::nullopt;
    }
    std::vector<uint256> roots;
    for (uint64_t begin = 0; begin < values.size();
         begin += kRCStage3EpisodeSemanticMaxRows) {
        const uint32_t rows = static_cast<uint32_t>(
            std::min<uint64_t>(
                kRCStage3EpisodeSemanticMaxRows,
                values.size() - begin));
        std::vector<Fp3> shard(
            values.begin() + begin, values.begin() + begin + rows);
        const auto root = ComputeRCStage3EpisodeSemanticValueRoot(
            shard, rows, NextPowerOfTwo(rows), why);
        if (!root.has_value()) return std::nullopt;
        roots.push_back(*root);
    }
    const uint256 root = ComputeRCStage3EpisodeWiringVectorRoot(
        statement_commitment, first_column, n_chunks,
        values.size(), roots);
    if (root.IsNull()) {
        Fail(why, "vector_root:commitment");
        return std::nullopt;
    }
    return root;
}

uint256 ComputeRCStage3EpisodeWiringCopyEdgeProductCommitment(
    const RCStage3EpisodeWiringCopyEdgeProduct& product)
{
    if (product.magic != kRCStage3EpisodeRelationProductMagic ||
        product.version != kRCStage3EpisodeRelationProductVersion ||
        product.relation_shards.empty() ||
        product.source_memory.bundle_commitment.IsNull() ||
        product.destination_memory.bundle_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << EDGE_PRODUCT_DOMAIN;
    hash << product.magic;
    hash << product.version;
    hash << product.schedule.schedule_index;
    hash << product.schedule.layer_ordinal;
    hash << static_cast<uint8_t>(product.schedule.slot);
    hash << product.schedule.first_column;
    hash << product.schedule.n_chunks;
    hash << product.schedule.value_count;
    hash << product.schedule.address_begin;
    hash << product.schedule.registered_vector_root;
    hash << static_cast<uint32_t>(product.relation_shards.size());
    for (const auto& shard : product.relation_shards) {
        const uint256 local = LocalProofCommitment(shard);
        if (local.IsNull()) return {};
        hash << local;
    }
    hash << product.source_memory.bundle_commitment;
    hash << product.destination_memory.bundle_commitment;
    return hash.GetHash();
}

uint256 ComputeRCStage3EpisodeWiringCopyClosureCommitment(
    const RCStage3EpisodeWiringCopyClosure& closure)
{
    if (closure.magic != kRCStage3EpisodeRelationProductMagic ||
        closure.version != kRCStage3EpisodeRelationProductVersion ||
        closure.statement_commitment.IsNull() ||
        closure.manifest_commitment.IsNull() ||
        closure.edges.empty()) {
        return {};
    }
    HashWriter hash;
    hash << CLOSURE_DOMAIN;
    hash << closure.magic;
    hash << closure.version;
    hash << closure.statement_commitment;
    hash << closure.manifest_commitment;
    hash << static_cast<uint32_t>(closure.edges.size());
    for (const auto& edge : closure.edges) {
        if (edge.product_commitment.IsNull()) return {};
        hash << edge.product_commitment;
    }
    return hash.GetHash();
}

bool ProveRCStage3EpisodeWiringCopyEdgeProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeWiringCopyScheduleEntry& expected,
    const std::vector<Fp3>& source,
    const std::vector<Fp3>& destination,
    RCStage3EpisodeWiringCopyEdgeProduct& out,
    std::string* why)
{
    out = {};
    if (!ValidateStatementAndManifest(statement, manifest, why)) {
        return false;
    }
    const auto schedule =
        BuildRCStage3EpisodeWiringCopySchedule(manifest, why);
    if (!schedule.has_value() ||
        expected.schedule_index >= schedule->size() ||
        !SameScheduleIdentity(
            expected, (*schedule)[expected.schedule_index])) {
        return Fail(why, "prove:schedule");
    }
    if (source.size() != expected.value_count ||
        destination.size() != expected.value_count) {
        return Fail(why, "prove:value_count");
    }

    const auto source_root =
        ComputeRCStage3EpisodeWiringVectorRootFromValues(
            manifest.statement_commitment, expected.first_column,
            expected.n_chunks, source, why);
    const auto destination_root =
        ComputeRCStage3EpisodeWiringVectorRootFromValues(
            manifest.statement_commitment, expected.first_column,
            expected.n_chunks, destination, why);
    if (!source_root.has_value() || !destination_root.has_value() ||
        *source_root != expected.registered_vector_root ||
        *destination_root != expected.registered_vector_root) {
        return Fail(why, "prove:registered_root");
    }

    out.magic = kRCStage3EpisodeRelationProductMagic;
    out.version = kRCStage3EpisodeRelationProductVersion;
    out.schedule = expected;
    const uint32_t shard_count = static_cast<uint32_t>(
        (expected.value_count +
         kRCStage3EpisodeSemanticMaxRows - 1) /
        kRCStage3EpisodeSemanticMaxRows);
    out.relation_shards.reserve(shard_count);
    for (uint32_t shard_index = 0;
         shard_index < shard_count; ++shard_index) {
        const uint64_t begin =
            static_cast<uint64_t>(shard_index) *
            kRCStage3EpisodeSemanticMaxRows;
        const uint32_t logical_rows = static_cast<uint32_t>(
            std::min<uint64_t>(
                kRCStage3EpisodeSemanticMaxRows,
                expected.value_count - begin));
        const uint32_t n_rows = NextPowerOfTwo(logical_rows);
        std::vector<std::vector<Fp3>> columns(
            2, std::vector<Fp3>(n_rows, Fp3::Zero()));
        std::copy_n(
            source.begin() + begin, logical_rows, columns[0].begin());
        std::copy_n(
            destination.begin() + begin, logical_rows,
            columns[1].begin());

        RCStage3EpisodeWiringCopyAirShard shard;
        shard.shard_index = shard_index;
        shard.value_begin = begin;
        auto& pin = shard.pin;
        pin.role = RCStage3RelationRole::EpisodeWiring;
        pin.family =
            RCStage3EpisodeAirFamily::WiringEqualityFp3V1;
        pin.statement_commitment = manifest.statement_commitment;
        pin.shard_index = shard_index;
        pin.shard_count = shard_count;
        pin.logical_rows = logical_rows;
        pin.n_rows = n_rows;
        pin.n_coeffs = n_rows;
        for (uint32_t column = 0; column < 2; ++column) {
            pin.column_roots.push_back(
                {column,
                 air_quotient::AirCommittedValuesRoot<Fp3>(
                     columns[column], n_rows)});
        }

        air_quotient::AirConstraintSystem<Fp3> cs;
        if (!ResolveRCStage3EpisodeAirConstraintSystem(
                statement, pin, cs, why)) {
            return false;
        }
        const auto proved =
            air_quotient::AirQuotientProve<Fp3>(
                cs, columns,
                ComputeRCStage3EpisodeAirSeed(statement, pin));
        if (!proved.ok || !proved.division_exact) {
            return Fail(why, "prove:local_air:" + proved.note);
        }
        shard.proof = proved.proof;
        out.relation_shards.push_back(std::move(shard));
    }

    if (!ProveRCStage3EpisodeSemanticMemoryBundle(
            RCStage3RelationEndpoint::EpisodeWiringCopy,
            manifest.statement_commitment, expected.address_begin, 1,
            source, out.source_memory, why) ||
        !ProveRCStage3EpisodeSemanticMemoryBundle(
            RCStage3RelationEndpoint::EpisodeWiringCopy,
            manifest.statement_commitment, expected.address_begin, 1,
            destination, out.destination_memory, why)) {
        out = {};
        return false;
    }
    out.product_commitment =
        ComputeRCStage3EpisodeWiringCopyEdgeProductCommitment(out);
    if (out.product_commitment.IsNull()) {
        out = {};
        return Fail(why, "prove:product_commitment");
    }
    return true;
}

bool VerifyRCStage3EpisodeWiringCopyEdgeProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeWiringCopyScheduleEntry& expected,
    const RCStage3EpisodeWiringCopyEdgeProduct& product,
    std::string* why)
{
    if (!ValidateStatementAndManifest(statement, manifest, why)) {
        return false;
    }
    if (product.magic != kRCStage3EpisodeRelationProductMagic ||
        product.version != kRCStage3EpisodeRelationProductVersion ||
        !SameScheduleIdentity(product.schedule, expected)) {
        return Fail(why, "verify:public_shape");
    }
    const uint32_t shard_count = static_cast<uint32_t>(
        (expected.value_count +
         kRCStage3EpisodeSemanticMaxRows - 1) /
        kRCStage3EpisodeSemanticMaxRows);
    if (product.relation_shards.size() != shard_count) {
        return Fail(why, "verify:shard_count");
    }

    std::vector<uint256> source_roots;
    std::vector<uint256> destination_roots;
    source_roots.reserve(shard_count);
    destination_roots.reserve(shard_count);
    for (uint32_t shard_index = 0;
         shard_index < shard_count; ++shard_index) {
        const auto& shard = product.relation_shards[shard_index];
        const uint64_t begin =
            static_cast<uint64_t>(shard_index) *
            kRCStage3EpisodeSemanticMaxRows;
        const uint32_t logical_rows = static_cast<uint32_t>(
            std::min<uint64_t>(
                kRCStage3EpisodeSemanticMaxRows,
                expected.value_count - begin));
        const uint32_t n_rows = NextPowerOfTwo(logical_rows);
        const auto& pin = shard.pin;
        if (shard.shard_index != shard_index ||
            shard.value_begin != begin ||
            pin.role != RCStage3RelationRole::EpisodeWiring ||
            pin.family !=
                RCStage3EpisodeAirFamily::WiringEqualityFp3V1 ||
            pin.statement_commitment != manifest.statement_commitment ||
            pin.shard_index != shard_index ||
            pin.shard_count != shard_count ||
            pin.logical_rows != logical_rows ||
            pin.n_rows != n_rows || pin.n_coeffs != n_rows ||
            pin.extract_scale_e != 0 ||
            pin.column_roots.size() != 2 ||
            pin.column_roots[0].column != 0 ||
            pin.column_roots[1].column != 1) {
            return Fail(why, "verify:canonical_shard");
        }
        if (!VerifyRCStage3EpisodeAirShard(
                statement, pin, shard.proof, why)) {
            return false;
        }
        source_roots.push_back(pin.column_roots[0].root);
        destination_roots.push_back(pin.column_roots[1].root);
    }

    if (!VerifyRCStage3EpisodeSemanticMemoryBundle(
            RCStage3RelationEndpoint::EpisodeWiringCopy,
            manifest.statement_commitment, expected.value_count,
            expected.address_begin, 1, source_roots,
            product.source_memory, why) ||
        !VerifyRCStage3EpisodeSemanticMemoryBundle(
            RCStage3RelationEndpoint::EpisodeWiringCopy,
            manifest.statement_commitment, expected.value_count,
            expected.address_begin, 1, destination_roots,
            product.destination_memory, why)) {
        return false;
    }

    const uint256 source_root =
        ComputeRCStage3EpisodeWiringVectorRoot(
            manifest.statement_commitment, expected.first_column,
            expected.n_chunks, expected.value_count, source_roots);
    const uint256 destination_root =
        ComputeRCStage3EpisodeWiringVectorRoot(
            manifest.statement_commitment, expected.first_column,
            expected.n_chunks, expected.value_count,
            destination_roots);
    if (source_root != expected.registered_vector_root ||
        destination_root != expected.registered_vector_root) {
        return Fail(why, "verify:registered_root");
    }
    if (product.product_commitment !=
        ComputeRCStage3EpisodeWiringCopyEdgeProductCommitment(
            product)) {
        return Fail(why, "verify:product_commitment");
    }
    return true;
}

bool VerifyRCStage3EpisodeWiringCopyClosure(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeWiringCopyClosure& closure,
    std::string* why)
{
    if (!ValidateStatementAndManifest(statement, manifest, why)) {
        return false;
    }
    const uint256 manifest_commitment =
        ComputeRCStage3GemmExtractManifestCommitment(manifest);
    if (closure.magic != kRCStage3EpisodeRelationProductMagic ||
        closure.version != kRCStage3EpisodeRelationProductVersion ||
        closure.statement_commitment != manifest.statement_commitment ||
        closure.manifest_commitment != manifest_commitment) {
        return Fail(why, "closure:public_shape");
    }
    const auto schedule =
        BuildRCStage3EpisodeWiringCopySchedule(manifest, why);
    if (!schedule.has_value() ||
        closure.edges.size() != schedule->size()) {
        return Fail(why, "closure:edge_count");
    }
    for (uint32_t index = 0; index < schedule->size(); ++index) {
        if (!VerifyRCStage3EpisodeWiringCopyEdgeProduct(
                statement, manifest, (*schedule)[index],
                closure.edges[index], why)) {
            return false;
        }
    }
    if (closure.closure_commitment !=
        ComputeRCStage3EpisodeWiringCopyClosureCommitment(closure)) {
        return Fail(why, "closure:commitment");
    }
    return true;
}

std::vector<RCStage3EpisodeRelationProductEndpointStatus>
CurrentRCStage3EpisodeRelationProductEndpointStatus()
{
    using E = RCStage3RelationEndpoint;
    return {
        {E::EpisodeGemmOperandA, true, true, false, false, false, false,
         "the local A column is only the sumcheck chain-end opening; "
         "full matrix A openings and the executed sumcheck are not joined"},
        {E::EpisodeGemmOperandB, true, true, false, false, false, false,
         "the local B column is only the sumcheck chain-end opening; "
         "full matrix B openings and the executed sumcheck are not joined"},
        {E::EpisodeGemmOutputY, true, true, false, false, false, false,
         "gf=a*b does not prove Y=A*B; the manifest-wide sumcheck and "
         "claim-to-Y opening remain"},
        {E::EpisodeExtractSampler, true, true, false, false, false, false,
         "RcSampler proves one fixed-program tile; segmented all-tile "
         "boundaries and degree-aligned flat-memory aliases remain"},
        {E::EpisodeExtractOutput, true, true, false, false, false, false,
         "the sampler output column is local; every tile output is not yet "
         "aggregated into each manifest extract-output root"},
        {E::EpisodeWiringCopy, true, true, true, true, false, false,
         "the complete local equality product executes, but the manifest "
         "operand root still needs equality to the executed producer/root "
         "graph before strict semantic closure"},
    };
}

} // namespace matmul::v4::rc
