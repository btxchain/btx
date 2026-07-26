// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_episode_builder_operand_xof.h>

#include <hash.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <limits>

namespace matmul::v4::rc {
namespace {

namespace gf = gkr_field;
namespace ha = stage3_hash_air;
namespace hs = stage3_hash_semantic;
using gf::Fp3;

constexpr char PRODUCT_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_BUILDER_OPERAND_XOF_V1";
constexpr uint8_t MANTISSA_DOMAIN = 0x6d;
constexpr uint8_t SCALE_DOMAIN = 0x65;
constexpr uint32_t UNUSED_INDEX = std::numeric_limits<uint32_t>::max();
constexpr uint64_t MEMORY_ADDRESS_BEGIN =
    UINT64_C(0x4550000300000000);

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:episode_builder_operand_xof:" + detail;
    }
    return false;
}

uint256 DigestUint(const std::array<uint8_t, 32>& digest)
{
    return uint256{Span<const unsigned char>{
        digest.data(), digest.size()}};
}

void AppendLe32(std::vector<uint8_t>& out, uint32_t value)
{
    for (uint32_t shift = 0; shift < 32; shift += 8) {
        out.push_back(static_cast<uint8_t>(value >> shift));
    }
}

std::vector<uint8_t> TaggedSeedPreimage(
    const std::string& tag,
    const uint256& source)
{
    std::vector<uint8_t> out(tag.begin(), tag.end());
    out.insert(out.end(), source.begin(), source.end());
    return out;
}

std::vector<uint8_t> RowBlockPreimage(
    const uint256& source,
    uint32_t block)
{
    std::vector<uint8_t> out(
        reinterpret_cast<const uint8_t*>(kRCX0RowBlockTag),
        reinterpret_cast<const uint8_t*>(kRCX0RowBlockTag) +
            sizeof(kRCX0RowBlockTag) - 1);
    out.insert(out.end(), source.begin(), source.end());
    AppendLe32(out, block);
    return out;
}

std::vector<uint256> RoundSeeds(
    const RCStage3EpisodeBuilderSeedChainProduct& parent)
{
    std::vector<uint256> out;
    out.reserve(parent.steps.size());
    for (const auto& step : parent.steps) {
        out.push_back(DigestUint(step.sha.digest));
    }
    return out;
}

struct InstanceSpec {
    RCStage3EpisodeOperandKind kind{};
    uint32_t round{UNUSED_INDEX};
    uint32_t layer{UNUSED_INDEX};
    uint32_t row_block{UNUSED_INDEX};
    bool shared{false};
    uint32_t rows{0};
    uint32_t cols{0};
    uint256 source{};
    std::vector<std::vector<uint8_t>> derivation_preimages;
};

bool AddSpec(
    std::vector<InstanceSpec>& out,
    RCStage3EpisodeOperandKind kind,
    uint32_t round, uint32_t layer, uint32_t row_block,
    bool shared, uint32_t rows, uint32_t cols,
    const uint256& source, const std::string& tag,
    bool x0_row_block, std::string* why)
{
    if (rows == 0 || cols == 0 ||
        (rows % kRCMxBlockLen) != 0 ||
        (cols % kRCMxBlockLen) != 0 ||
        source.IsNull()) {
        return Fail(why, "spec_geometry");
    }
    InstanceSpec spec;
    spec.kind = kind;
    spec.round = round;
    spec.layer = layer;
    spec.row_block = row_block;
    spec.shared = shared;
    spec.rows = rows;
    spec.cols = cols;
    spec.source = source;
    spec.derivation_preimages.push_back(
        TaggedSeedPreimage(tag, source));
    if (x0_row_block) {
        // Empty is a verifier instruction, not a witness value: the second
        // preimage is reconstructed from the first proof's claimed digest.
        // The fixed-program proof then establishes that digest without a
        // verifier-native SHA replay.
        spec.derivation_preimages.emplace_back();
    }
    out.push_back(std::move(spec));
    return true;
}

bool CanonicalSpecs(
    const RCEpisodeParams& params,
    const RCStage3EpisodeBuilderSeedChainProduct& seed_chain,
    std::vector<InstanceSpec>& out,
    std::string* why)
{
    out.clear();
    if (!ValidateRCEpisodeParams(params) ||
        seed_chain.steps.size() != params.rounds) {
        return Fail(why, "spec_public_shape");
    }
    const auto seeds = RoundSeeds(seed_chain);
    const bool shared = UseDatacenterSharedFfnWeights(params);
    if (shared) {
        if (!AddSpec(
                out, RCStage3EpisodeOperandKind::K,
                UNUSED_INDEX, UNUSED_INDEX, UNUSED_INDEX, true,
                params.n_ctx, params.d_head,
                seed_chain.sigma, "BTX_RC_KV_K_V1", false, why) ||
            !AddSpec(
                out, RCStage3EpisodeOperandKind::V,
                UNUSED_INDEX, UNUSED_INDEX, UNUSED_INDEX, true,
                params.n_ctx, params.d_head,
                seed_chain.sigma, "BTX_RC_KV_V_V1", false, why) ||
            !AddSpec(
                out, RCStage3EpisodeOperandKind::WUp,
                UNUSED_INDEX, UNUSED_INDEX, UNUSED_INDEX, true,
                params.d_model, params.d_ff,
                seed_chain.sigma, "BTX_RC_WUP_V1", false, why) ||
            !AddSpec(
                out, RCStage3EpisodeOperandKind::WDown,
                UNUSED_INDEX, UNUSED_INDEX, UNUSED_INDEX, true,
                params.d_ff, params.d_model,
                seed_chain.sigma, "BTX_RC_WDN_V1", false, why)) {
            return false;
        }
    }
    for (uint32_t round = 0; round < params.rounds; ++round) {
        if (!AddSpec(
                out, RCStage3EpisodeOperandKind::Q,
                round, UNUSED_INDEX, UNUSED_INDEX, false,
                params.n_q, params.d_head, seeds[round],
                "BTX_RC_Q_V1", false, why)) {
            return false;
        }
        if (!shared &&
            (!AddSpec(
                out, RCStage3EpisodeOperandKind::K,
                round, UNUSED_INDEX, UNUSED_INDEX, false,
                params.n_ctx, params.d_head, seeds[round],
                "BTX_RC_KV_K_V1", false, why) ||
             !AddSpec(
                out, RCStage3EpisodeOperandKind::V,
                round, UNUSED_INDEX, UNUSED_INDEX, false,
                params.n_ctx, params.d_head, seeds[round],
                "BTX_RC_KV_V_V1", false, why))) {
            return false;
        }
        if (UseDatacenterRowBlockX0(params)) {
            const uint32_t blocks =
                params.b_seq / kRCX0RowBlockRows;
            for (uint32_t block = 0; block < blocks; ++block) {
                if (!AddSpec(
                        out, RCStage3EpisodeOperandKind::X0,
                        round, UNUSED_INDEX, block, false,
                        kRCX0RowBlockRows, params.d_model,
                        seeds[round], "BTX_RC_X0_V1", true, why)) {
                    return false;
                }
            }
        } else if (!AddSpec(
                out, RCStage3EpisodeOperandKind::X0,
                round, UNUSED_INDEX, UNUSED_INDEX, false,
                params.b_seq, params.d_model, seeds[round],
                "BTX_RC_X0_V1", false, why)) {
            return false;
        }
        if (!shared) {
            for (uint32_t layer = 0; layer < params.L_lyr; ++layer) {
                char tag[40];
                std::snprintf(
                    tag, sizeof(tag), "BTX_RC_WUP_%u_V1", layer);
                if (!AddSpec(
                        out, RCStage3EpisodeOperandKind::WUp,
                        round, layer, UNUSED_INDEX, false,
                        params.d_model, params.d_ff, seeds[round],
                        tag, false, why)) {
                    return false;
                }
                std::snprintf(
                    tag, sizeof(tag), "BTX_RC_WDN_%u_V1", layer);
                if (!AddSpec(
                        out, RCStage3EpisodeOperandKind::WDown,
                        round, layer, UNUSED_INDEX, false,
                        params.d_ff, params.d_model, seeds[round],
                        tag, false, why)) {
                    return false;
                }
            }
        }
    }
    return !out.empty() || Fail(why, "empty_schedule");
}

bool CounterShape(
    const ha::CounterXofManifest& manifest,
    const uint256& seed, uint8_t domain,
    ha::CounterXofMode mode, uint64_t count,
    std::string* why)
{
    std::vector<ha::FixedProgramBoundaryInstance> boundaries;
    if (manifest.seed != seed || manifest.domain != domain ||
        manifest.mode != mode ||
        manifest.output_count != count ||
        manifest.output.size() != count ||
        manifest.commitment !=
            ha::CommitCounterXofManifest(manifest) ||
        !ha::BuildCounterXofManifestBoundaryInstances(
            manifest, boundaries, why) ||
        (count != 0 && boundaries.empty())) {
        return Fail(why, "counter_shape");
    }
    return true;
}

bool OutputValues(
    const std::vector<RCStage3EpisodeOperandXofInstance>& instances,
    std::vector<Fp3>& values,
    std::string* why)
{
    values.clear();
    for (const auto& instance : instances) {
        if (instance.mantissa.output.size() >
                std::numeric_limits<size_t>::max() - values.size() ||
            instance.scale.output.size() >
                std::numeric_limits<size_t>::max() - values.size() -
                    instance.mantissa.output.size()) {
            return Fail(why, "output_overflow");
        }
        for (uint8_t byte : instance.mantissa.output) {
            const int64_t signed_value = byte < 128
                ? byte : static_cast<int64_t>(byte) - 256;
            values.push_back(
                Fp3::FromFp(gf::FromSigned(signed_value)));
        }
        for (uint8_t scale : instance.scale.output) {
            values.push_back(Fp3::FromFp(gf::FromU64(scale)));
        }
    }
    return !values.empty() || Fail(why, "empty_outputs");
}

bool ExpectedMemoryRoots(
    const std::vector<Fp3>& values,
    std::vector<uint256>& roots,
    std::string* why)
{
    roots.clear();
    uint64_t begin = 0;
    while (begin < values.size()) {
        const uint32_t count = static_cast<uint32_t>(
            std::min<uint64_t>(
                kRCStage3EpisodeSemanticMaxRows,
                values.size() - begin));
        const uint32_t n_rows = FriNextPow2(count);
        std::vector<Fp3> shard(
            values.begin() + begin,
            values.begin() + begin + count);
        const auto root = ComputeRCStage3EpisodeSemanticValueRoot(
            shard, count, n_rows, why);
        if (!root.has_value()) return false;
        roots.push_back(*root);
        begin += count;
    }
    return true;
}

bool BuildStructuralMemory(
    const uint256& statement_commitment,
    const std::vector<Fp3>& values,
    RCStage3EpisodeSemanticMemoryBundle& out,
    std::string* why)
{
    out = {};
    std::vector<uint256> roots;
    if (!ExpectedMemoryRoots(values, roots, why)) return false;
    out.version = kRCStage3EpisodeSemanticMemoryVersion;
    out.endpoint =
        RCStage3RelationEndpoint::EpisodeBuilderOperandXof;
    out.statement_commitment = statement_commitment;
    out.total_instance_count = values.size();
    out.address_begin = MEMORY_ADDRESS_BEGIN;
    out.address_stride = 1;
    if (!BuildRCStage3EpisodeSemanticMemoryShardManifests(
            out.endpoint, statement_commitment, values.size(),
            out.address_begin, out.address_stride, roots,
            out.shards, why)) {
        return false;
    }
    out.bundle_commitment =
        ComputeRCStage3EpisodeSemanticMemoryBundleCommitment(out);
    return !out.bundle_commitment.IsNull() ||
           Fail(why, "memory_commitment");
}

bool ProveBundle(
    RCStage3RelationEndpoint endpoint,
    const uint256& statement_commitment,
    const uint256& manifest_commitment,
    const std::vector<ha::FixedProgramBoundaryInstance>& boundaries,
    ha::ProgramKind kind,
    hs::FlatBoundaryProofBundle& out,
    std::string* why)
{
    out = {};
    out.endpoint = endpoint;
    out.statement_commitment = statement_commitment;
    out.manifest_commitment = manifest_commitment;
    out.proofs.resize(boundaries.size());
    const auto program = ha::BuildCanonicalProgram(kind);
    for (uint32_t i = 0; i < boundaries.size(); ++i) {
        ha::ProgramWitness witness;
        if (!ha::BuildProgramWitness(
                program, boundaries[i].external_values,
                witness, why) ||
            !ha::ProveFixedProgramProvenanceAir(
                program, witness, boundaries[i].external_values,
                boundaries[i].final_words,
                hs::ComputeBoundaryProofSeed(
                    endpoint, statement_commitment,
                    manifest_commitment, i, boundaries.size()),
                out.proofs[i], why)) {
            return false;
        }
    }
    return true;
}

} // namespace

uint256 ComputeRCStage3EpisodeBuilderOperandXofProductCommitment(
    const RCStage3EpisodeBuilderOperandXofProduct& product)
{
    if (product.version !=
            kRCStage3EpisodeBuilderOperandXofVersion ||
        product.statement_commitment.IsNull() ||
        product.params_commitment.IsNull() ||
        product.seed_chain_product_commitment.IsNull() ||
        product.output_cells == 0 || product.instances.empty() ||
        product.output_memory.bundle_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << PRODUCT_DOMAIN << product.version;
    hash << product.statement_commitment;
    hash << product.params_commitment;
    hash << product.seed_chain_product_commitment;
    hash << product.output_cells;
    hash << static_cast<uint64_t>(product.instances.size());
    for (uint64_t i = 0; i < product.instances.size(); ++i) {
        const auto& x = product.instances[i];
        if (x.schedule_index != i ||
            x.seed_derivations.empty() ||
            x.mantissa.commitment.IsNull() ||
            x.scale.commitment.IsNull()) {
            return {};
        }
        hash << x.schedule_index;
        hash << static_cast<uint8_t>(x.kind);
        hash << x.round_index << x.layer_index << x.row_block;
        hash << x.episode_shared << x.rows << x.cols << x.source;
        hash << static_cast<uint32_t>(x.seed_derivations.size());
        for (const auto& derivation : x.seed_derivations) {
            hash << derivation.sha.commitment;
        }
        hash << x.mantissa.commitment << x.scale.commitment;
    }
    hash << product.output_memory.bundle_commitment;
    return hash.GetHash();
}

bool BuildRCStage3EpisodeBuilderOperandXofProduct(
    const RCStage3SuccinctProof& statement,
    const RCEpisodeParams& params,
    const RCStage3EpisodeBuilderSeedChainProduct& seed_chain,
    RCStage3EpisodeBuilderOperandXofProduct& out,
    std::string* why)
{
    out = {};
    const uint256 statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    std::vector<InstanceSpec> specs;
    if (statement_commitment.IsNull() ||
        seed_chain.product_commitment.IsNull() ||
        !CanonicalSpecs(params, seed_chain, specs, why)) {
        return Fail(why, "build_shape");
    }
    out.version = kRCStage3EpisodeBuilderOperandXofVersion;
    out.statement_commitment = statement_commitment;
    out.params_commitment = statement.public_inputs.params_commitment;
    out.seed_chain_product_commitment =
        seed_chain.product_commitment;
    out.instances.reserve(specs.size());
    for (uint64_t i = 0; i < specs.size(); ++i) {
        const auto& spec = specs[i];
        RCStage3EpisodeOperandXofInstance x;
        x.schedule_index = i;
        x.kind = spec.kind;
        x.round_index = spec.round;
        x.layer_index = spec.layer;
        x.row_block = spec.row_block;
        x.episode_shared = spec.shared;
        x.rows = spec.rows;
        x.cols = spec.cols;
        x.source = spec.source;
        uint256 derived;
        for (const auto& preimage : spec.derivation_preimages) {
            RCStage3EpisodeOperandSeedDerivation derivation;
            const std::vector<uint8_t> exact_preimage =
                preimage.empty()
                    ? RowBlockPreimage(derived, spec.row_block)
                    : preimage;
            if (!ha::BuildShaManifest(
                    exact_preimage, ha::ShaMode::Single,
                    derivation.sha, why)) {
                return Fail(why, "build_derivation");
            }
            derived = DigestUint(derivation.sha.digest);
            derivation.proof.endpoint =
                RCStage3RelationEndpoint::EpisodeBuilderOperandXof;
            derivation.proof.statement_commitment =
                statement_commitment;
            derivation.proof.manifest_commitment =
                derivation.sha.commitment;
            x.seed_derivations.push_back(std::move(derivation));
        }
        uint64_t mantissa_count =
            uint64_t{x.rows} * x.cols;
        const uint64_t scale_count =
            uint64_t{x.rows} * (x.cols / kRCMxBlockLen);
        if (!ha::BuildCounterXofManifest(
                derived, MANTISSA_DOMAIN,
                ha::CounterXofMode::MantissaE2M1,
                mantissa_count, x.mantissa, why) ||
            !ha::BuildCounterXofManifest(
                derived, SCALE_DOMAIN,
                ha::CounterXofMode::Scale2Bit,
                scale_count, x.scale, why)) {
            return Fail(
                why, "build_counter_" + std::to_string(i));
        }
        x.mantissa_proof.endpoint =
            RCStage3RelationEndpoint::EpisodeBuilderOperandXof;
        x.mantissa_proof.statement_commitment =
            statement_commitment;
        x.mantissa_proof.manifest_commitment =
            x.mantissa.commitment;
        x.scale_proof.endpoint = x.mantissa_proof.endpoint;
        x.scale_proof.statement_commitment =
            statement_commitment;
        x.scale_proof.manifest_commitment =
            x.scale.commitment;
        out.output_cells += mantissa_count + scale_count;
        out.instances.push_back(std::move(x));
    }
    std::vector<Fp3> values;
    if (!OutputValues(out.instances, values, why) ||
        values.size() != out.output_cells ||
        !BuildStructuralMemory(
            statement_commitment, values,
            out.output_memory, why)) {
        return Fail(why, "build_memory");
    }
    out.product_commitment =
        ComputeRCStage3EpisodeBuilderOperandXofProductCommitment(out);
    return !out.product_commitment.IsNull() ||
           Fail(why, "build_commitment");
}

bool ProveRCStage3EpisodeBuilderOperandXofProduct(
    const RCStage3SuccinctProof& statement,
    const RCEpisodeParams& params,
    const RCStage3EpisodeBuilderSeedChainProduct& seed_chain,
    RCStage3EpisodeBuilderOperandXofProduct& out,
    std::string* why)
{
    if (!VerifyRCStage3EpisodeBuilderSeedChainProduct(
            statement, params, seed_chain, why) ||
        !BuildRCStage3EpisodeBuilderOperandXofProduct(
            statement, params, seed_chain, out, why)) {
        return Fail(why, "prove_parent_or_build");
    }
    for (auto& x : out.instances) {
        for (auto& derivation : x.seed_derivations) {
            std::vector<ha::FixedProgramBoundaryInstance> boundaries;
            if (!ha::BuildShaManifestBoundaryInstances(
                    derivation.sha, boundaries, why) ||
                !ProveBundle(
                    RCStage3RelationEndpoint::EpisodeBuilderOperandXof,
                    out.statement_commitment,
                    derivation.sha.commitment, boundaries,
                    ha::ProgramKind::Sha256Compression,
                    derivation.proof, why)) {
                return Fail(why, "prove_derivation");
            }
        }
        std::vector<ha::FixedProgramBoundaryInstance> boundaries;
        if (!ha::BuildCounterXofManifestBoundaryInstances(
                x.mantissa, boundaries, why) ||
            !ProveBundle(
                RCStage3RelationEndpoint::EpisodeBuilderOperandXof,
                out.statement_commitment, x.mantissa.commitment,
                boundaries, ha::ProgramKind::Sha256Compression,
                x.mantissa_proof, why) ||
            !ha::BuildCounterXofManifestBoundaryInstances(
                x.scale, boundaries, why) ||
            !ProveBundle(
                RCStage3RelationEndpoint::EpisodeBuilderOperandXof,
                out.statement_commitment, x.scale.commitment,
                boundaries, ha::ProgramKind::Sha256Compression,
                x.scale_proof, why)) {
            return Fail(why, "prove_counter");
        }
    }
    std::vector<Fp3> values;
    if (!OutputValues(out.instances, values, why) ||
        !ProveRCStage3EpisodeSemanticMemoryBundle(
            RCStage3RelationEndpoint::EpisodeBuilderOperandXof,
            out.statement_commitment, MEMORY_ADDRESS_BEGIN, 1,
            values, out.output_memory, why)) {
        return Fail(why, "prove_memory");
    }
    out.product_commitment =
        ComputeRCStage3EpisodeBuilderOperandXofProductCommitment(out);
    return !out.product_commitment.IsNull();
}

bool ValidateRCStage3EpisodeBuilderOperandXofSchedule(
    const RCStage3SuccinctProof& statement,
    const RCEpisodeParams& params,
    const RCStage3EpisodeBuilderSeedChainProduct& seed_chain,
    const RCStage3EpisodeBuilderOperandXofProduct& product,
    std::string* why)
{
    std::vector<InstanceSpec> specs;
    const uint256 statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    if (product.version !=
            kRCStage3EpisodeBuilderOperandXofVersion ||
        product.statement_commitment != statement_commitment ||
        product.params_commitment !=
            statement.public_inputs.params_commitment ||
        product.seed_chain_product_commitment !=
            seed_chain.product_commitment ||
        !CanonicalSpecs(params, seed_chain, specs, why) ||
        product.instances.size() != specs.size()) {
        return Fail(why, "schedule_shape");
    }
    uint64_t output_cells{0};
    for (uint64_t i = 0; i < specs.size(); ++i) {
        const auto& spec = specs[i];
        const auto& x = product.instances[i];
        if (x.schedule_index != i || x.kind != spec.kind ||
            x.round_index != spec.round ||
            x.layer_index != spec.layer ||
            x.row_block != spec.row_block ||
            x.episode_shared != spec.shared ||
            x.rows != spec.rows || x.cols != spec.cols ||
            x.source != spec.source ||
            x.seed_derivations.size() !=
                spec.derivation_preimages.size()) {
            return Fail(why, "schedule_order_" + std::to_string(i));
        }
        uint256 derived;
        for (uint32_t d = 0;
             d < x.seed_derivations.size(); ++d) {
            const auto& derivation = x.seed_derivations[d];
            const std::vector<uint8_t> expected_preimage =
                spec.derivation_preimages[d].empty()
                    ? RowBlockPreimage(derived, spec.row_block)
                    : spec.derivation_preimages[d];
            std::vector<ha::FixedProgramBoundaryInstance> boundaries;
            if (derivation.sha.mode != ha::ShaMode::Single ||
                derivation.sha.preimage !=
                    expected_preimage ||
                derivation.sha.commitment !=
                    ha::CommitShaManifest(derivation.sha) ||
                !ha::BuildShaManifestBoundaryInstances(
                    derivation.sha, boundaries, why) ||
                boundaries.size() != 1 ||
                derivation.proof.endpoint !=
                    RCStage3RelationEndpoint::EpisodeBuilderOperandXof ||
                derivation.proof.statement_commitment !=
                    statement_commitment ||
                derivation.proof.manifest_commitment !=
                    derivation.sha.commitment) {
                return Fail(why, "derivation_" + std::to_string(i));
            }
            derived = DigestUint(derivation.sha.digest);
        }
        const uint64_t mantissa_count =
            uint64_t{x.rows} * x.cols;
        const uint64_t scale_count =
            uint64_t{x.rows} * (x.cols / kRCMxBlockLen);
        if (!CounterShape(
                x.mantissa, derived, MANTISSA_DOMAIN,
                ha::CounterXofMode::MantissaE2M1,
                mantissa_count, why) ||
            !CounterShape(
                x.scale, derived, SCALE_DOMAIN,
                ha::CounterXofMode::Scale2Bit,
                scale_count, why) ||
            x.mantissa_proof.endpoint !=
                RCStage3RelationEndpoint::EpisodeBuilderOperandXof ||
            x.mantissa_proof.statement_commitment !=
                statement_commitment ||
            x.mantissa_proof.manifest_commitment !=
                x.mantissa.commitment ||
            x.scale_proof.endpoint !=
                RCStage3RelationEndpoint::EpisodeBuilderOperandXof ||
            x.scale_proof.statement_commitment !=
                statement_commitment ||
            x.scale_proof.manifest_commitment !=
                x.scale.commitment) {
            return Fail(why, "counter_" + std::to_string(i));
        }
        output_cells += mantissa_count + scale_count;
    }
    std::vector<Fp3> values;
    std::vector<uint256> roots;
    if (product.output_cells != output_cells ||
        !OutputValues(product.instances, values, why) ||
        values.size() != output_cells ||
        !ExpectedMemoryRoots(values, roots, why) ||
        product.output_memory.endpoint !=
            RCStage3RelationEndpoint::EpisodeBuilderOperandXof ||
        product.output_memory.statement_commitment !=
            statement_commitment ||
        product.output_memory.total_instance_count != output_cells ||
        product.output_memory.address_begin != MEMORY_ADDRESS_BEGIN ||
        product.output_memory.address_stride != 1 ||
        product.output_memory.shards.size() != roots.size()) {
        return Fail(why, "memory_shape");
    }
    for (uint32_t i = 0; i < roots.size(); ++i) {
        if (product.output_memory.shards[i]
                .manifest.canonical_value_root != roots[i]) {
            return Fail(why, "memory_root_" + std::to_string(i));
        }
    }
    if (product.product_commitment !=
            ComputeRCStage3EpisodeBuilderOperandXofProductCommitment(
                product)) {
        return Fail(why, "product_commitment");
    }
    return true;
}

bool VerifyRCStage3EpisodeBuilderOperandXofProduct(
    const RCStage3SuccinctProof& statement,
    const RCEpisodeParams& params,
    const RCStage3EpisodeBuilderSeedChainProduct& seed_chain,
    const RCStage3EpisodeBuilderOperandXofProduct& product,
    std::string* why)
{
    if (!VerifyRCStage3EpisodeBuilderSeedChainProduct(
            statement, params, seed_chain, why) ||
        !ValidateRCStage3EpisodeBuilderOperandXofSchedule(
            statement, params, seed_chain, product, why)) {
        return Fail(why, "parent_or_schedule");
    }
    for (const auto& x : product.instances) {
        for (const auto& derivation : x.seed_derivations) {
            if (!hs::VerifyShaManifestBundle(
                    RCStage3RelationEndpoint::EpisodeBuilderOperandXof,
                    derivation.sha, derivation.proof, why)) {
                return Fail(why, "derivation_proof");
            }
        }
        if (!hs::VerifyCounterXofManifestBundle(
                RCStage3RelationEndpoint::EpisodeBuilderOperandXof,
                x.mantissa, x.mantissa_proof, why) ||
            !hs::VerifyCounterXofManifestBundle(
                RCStage3RelationEndpoint::EpisodeBuilderOperandXof,
                x.scale, x.scale_proof, why)) {
            return Fail(why, "counter_proof");
        }
    }
    std::vector<Fp3> values;
    std::vector<uint256> roots;
    if (!OutputValues(product.instances, values, why) ||
        !ExpectedMemoryRoots(values, roots, why) ||
        !VerifyRCStage3EpisodeSemanticMemoryBundle(
            RCStage3RelationEndpoint::EpisodeBuilderOperandXof,
            product.statement_commitment, values.size(),
            MEMORY_ADDRESS_BEGIN, 1, roots,
            product.output_memory, why)) {
        return Fail(why, "memory_proof");
    }
    return true;
}

RCStage3EpisodeBuilderOperandXofAudit
CurrentRCStage3EpisodeBuilderOperandXofAudit(
    bool endpoint1_ancestor_complete,
    bool endpoint2_ancestor_complete)
{
    RCStage3EpisodeBuilderOperandXofAudit out;
    out.exact_unique_operand_schedule = true;
    out.seed_derivation_sha_executable = true;
    out.all_counter_xof_children_executable = true;
    // Consensus operand expansion is SHA-256 counter-XOF. ChaCha belongs to
    // Extract and is deliberately not invented here.
    out.chacha_required_by_consensus = false;
    out.output_memory_equality_executable = true;
    out.local_relation_complete =
        kRCStage3EpisodeBuilderOperandXofLocalProductExecutable;
    out.endpoint1_ancestor_complete =
        endpoint1_ancestor_complete;
    out.endpoint2_ancestor_complete =
        endpoint2_ancestor_complete;
    out.producer_provenance_complete =
        endpoint1_ancestor_complete &&
        endpoint2_ancestor_complete;
    out.semantic_complete =
        out.local_relation_complete &&
        out.producer_provenance_complete;
    out.production_streaming_manifest_complete =
        kRCStage3EpisodeBuilderOperandXofProductionStreamingComplete;
    out.recursively_consumed = false;
    out.remaining =
        "CounterXofManifest retains a 16 MiB flat-output cap; production "
        "W_up/W_down require a counter-range streaming manifest and "
        "normalized recursive consumption";
    return out;
}

} // namespace matmul::v4::rc
