// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_episode_builder_seed_chain.h>

#include <hash.h>

#include <algorithm>
#include <cstring>
#include <limits>

namespace matmul::v4::rc {
namespace {

namespace gf = gkr_field;
namespace ha = stage3_hash_air;
namespace hs = stage3_hash_semantic;
using gf::Fp3;

constexpr char PRODUCT_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_BUILDER_SEED_CHAIN_V1";
constexpr uint64_t SEED_MEMORY_ADDRESS_BEGIN =
    UINT64_C(0x4550000200000000);

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:episode_builder_seed_chain:" + detail;
    }
    return false;
}

bool IsEpisodeStatement(const RCStage3SuccinctProof& statement)
{
    return statement.statement == RCStage3StatementKind::Episode ||
           statement.statement == RCStage3StatementKind::Composed;
}

void AppendLe32(std::vector<uint8_t>& out, uint32_t value)
{
    for (uint32_t shift = 0; shift < 32; shift += 8) {
        out.push_back(static_cast<uint8_t>(value >> shift));
    }
}

void AppendHash(std::vector<uint8_t>& out, const uint256& value)
{
    out.insert(out.end(), value.begin(), value.end());
}

uint256 DigestUint(const std::array<uint8_t, 32>& digest)
{
    return uint256{Span<const unsigned char>{
        digest.data(), digest.size()}};
}

std::vector<uint8_t> RoundRootBytes(
    const ha::EpisodeDigestManifest& manifest)
{
    std::vector<uint8_t> out;
    out.reserve(manifest.round_roots.size() * 32);
    for (const auto& root : manifest.round_roots) {
        AppendHash(out, root);
    }
    return out;
}

std::vector<uint8_t> SeedPreimage(
    const uint256& source,
    uint32_t round_index)
{
    std::vector<uint8_t> out;
    out.insert(
        out.end(),
        reinterpret_cast<const uint8_t*>(kRCRoundTag),
        reinterpret_cast<const uint8_t*>(kRCRoundTag) +
            sizeof(kRCRoundTag) - 1);
    AppendHash(out, source);
    AppendLe32(out, round_index);
    return out;
}

bool SeedBoundaryValues(
    const std::vector<RCStage3EpisodeBuilderSeedStep>& steps,
    std::vector<Fp3>& values,
    std::string* why)
{
    values.clear();
    if (steps.empty() ||
        steps.size() >
            kRCStage3EpisodeSemanticMaxRows / 8U) {
        return Fail(why, "seed_value_count");
    }
    values.reserve(steps.size() * 8);
    for (uint32_t round_index = 0;
         round_index < steps.size(); ++round_index) {
        const auto& step = steps[round_index];
        std::vector<ha::FixedProgramBoundaryInstance> boundaries;
        if (step.round_index != round_index ||
            step.sha.mode != ha::ShaMode::Single ||
            step.sha.preimage !=
                SeedPreimage(step.source, round_index) ||
            step.sha.commitment != ha::CommitShaManifest(step.sha) ||
            !ha::BuildShaManifestBoundaryInstances(
                step.sha, boundaries, why) ||
            boundaries.size() != 1 ||
            boundaries[0].final_words.size() != 8) {
            return Fail(
                why, "seed_boundary_" +
                    std::to_string(round_index));
        }
        for (uint32_t word : boundaries[0].final_words) {
            values.push_back(Fp3::FromFp(gf::FromU64(word)));
        }
    }
    return true;
}

bool ExpectedSeedMemoryManifest(
    const uint256& statement_commitment,
    const std::vector<RCStage3EpisodeBuilderSeedStep>& steps,
    RCStage3EpisodeSemanticMemoryManifest& out,
    std::vector<Fp3>& values,
    std::string* why)
{
    if (!SeedBoundaryValues(steps, values, why)) return false;
    const uint32_t logical_rows =
        static_cast<uint32_t>(values.size());
    const uint32_t n_rows = FriNextPow2(logical_rows);
    const auto root = ComputeRCStage3EpisodeSemanticValueRoot(
        values, logical_rows, n_rows, why);
    if (!root.has_value()) return false;
    const auto manifest =
        BuildRCStage3EpisodeSemanticMemoryManifest(
            RCStage3RelationEndpoint::EpisodeBuilderSeedChain,
            statement_commitment, logical_rows, logical_rows,
            SEED_MEMORY_ADDRESS_BEGIN, 1, *root, why);
    if (!manifest.has_value()) return false;
    out = *manifest;
    return true;
}

bool ProveShaStep(
    const uint256& statement_commitment,
    RCStage3EpisodeBuilderSeedStep& step,
    std::string* why)
{
    std::vector<ha::FixedProgramBoundaryInstance> boundaries;
    if (!ha::BuildShaManifestBoundaryInstances(
            step.sha, boundaries, why) ||
        boundaries.size() != 1) {
        return Fail(why, "prove_boundary");
    }
    step.hash_proof = {};
    step.hash_proof.endpoint =
        RCStage3RelationEndpoint::EpisodeBuilderSeedChain;
    step.hash_proof.statement_commitment =
        statement_commitment;
    step.hash_proof.manifest_commitment =
        step.sha.commitment;
    step.hash_proof.proofs.resize(boundaries.size());
    const auto program = ha::BuildCanonicalProgram(
        ha::ProgramKind::Sha256Compression);
    for (uint32_t i = 0; i < boundaries.size(); ++i) {
        ha::ProgramWitness witness;
        if (!ha::BuildProgramWitness(
                program, boundaries[i].external_values,
                witness, why) ||
            witness.final_words != boundaries[i].final_words) {
            return Fail(why, "prove_witness");
        }
        const uint256 seed = hs::ComputeBoundaryProofSeed(
            step.hash_proof.endpoint, statement_commitment,
            step.sha.commitment, i, boundaries.size());
        if (!ha::ProveFixedProgramProvenanceAir(
                program, witness, boundaries[i].external_values,
                boundaries[i].final_words, seed,
                step.hash_proof.proofs[i], why)) {
            return Fail(why, "prove_air");
        }
    }
    return true;
}

bool StructuralProduct(
    const RCStage3SuccinctProof& statement,
    const RCEpisodeParams& expected_params,
    const RCStage3EpisodeBuilderSeedChainProduct& product,
    RCStage3EpisodeSemanticMemoryManifest& expected_memory,
    std::vector<Fp3>& seed_values,
    std::string* why)
{
    const uint256 statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    if (!IsEpisodeStatement(statement) ||
        statement_commitment.IsNull() ||
        statement.public_inputs.header_commitment.IsNull() ||
        statement.public_inputs.params_commitment.IsNull() ||
        statement.public_inputs.sigma.IsNull() ||
        !ValidateRCEpisodeParams(expected_params) ||
        expected_params.rounds >
            kRCStage3EpisodeSemanticMaxRows / 8U ||
        product.version !=
            kRCStage3EpisodeBuilderSeedChainVersion ||
        product.statement_commitment != statement_commitment ||
        product.header_commitment !=
            statement.public_inputs.header_commitment ||
        product.params_commitment !=
            statement.public_inputs.params_commitment ||
        product.sigma != statement.public_inputs.sigma ||
        product.expected_rounds != expected_params.rounds ||
        product.steps.size() != expected_params.rounds ||
        !ValidateRCStage3EpisodeDigestManifestStructural(
            product.round_root_manifest,
            expected_params.rounds, why) ||
        product.round_root_manifest.direct.digest !=
            statement.public_inputs.episode_digest) {
        return Fail(why, "public_shape");
    }
    for (uint32_t round_index = 0;
         round_index < product.expected_rounds; ++round_index) {
        const auto& step = product.steps[round_index];
        const uint256 expected_source = round_index == 0
            ? statement.public_inputs.sigma
            : product.round_root_manifest
                  .round_roots[round_index - 1];
        if (step.round_index != round_index ||
            step.source != expected_source ||
            step.hash_proof.endpoint !=
                RCStage3RelationEndpoint::EpisodeBuilderSeedChain ||
            step.hash_proof.statement_commitment !=
                statement_commitment ||
            step.hash_proof.manifest_commitment !=
                step.sha.commitment) {
            return Fail(
                why, "step_identity_" +
                    std::to_string(round_index));
        }
    }
    if (!ExpectedSeedMemoryManifest(
            statement_commitment, product.steps,
            expected_memory, seed_values, why) ||
        product.seed_memory_manifest != expected_memory) {
        return Fail(why, "seed_memory");
    }
    const uint256 commitment =
        ComputeRCStage3EpisodeBuilderSeedChainProductCommitment(
            product);
    if (commitment.IsNull() ||
        product.product_commitment != commitment) {
        return Fail(why, "product_commitment");
    }
    return true;
}

} // namespace

uint256 ComputeRCStage3EpisodeBuilderSeedChainProductCommitment(
    const RCStage3EpisodeBuilderSeedChainProduct& product)
{
    if (product.version !=
            kRCStage3EpisodeBuilderSeedChainVersion ||
        product.statement_commitment.IsNull() ||
        product.header_commitment.IsNull() ||
        product.params_commitment.IsNull() ||
        product.sigma.IsNull() ||
        product.expected_rounds == 0 ||
        product.steps.size() != product.expected_rounds ||
        product.round_root_manifest.commitment.IsNull() ||
        product.params_product.memory_manifest
            .manifest_commitment.IsNull() ||
        product.round_roots_pin.pin_commitment.IsNull() ||
        product.seed_memory_manifest.manifest_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << PRODUCT_DOMAIN;
    hash << product.version;
    hash << product.statement_commitment;
    hash << product.header_commitment;
    hash << product.params_commitment;
    hash << product.sigma;
    hash << product.expected_rounds;
    hash << product.round_root_manifest.commitment;
    hash << product.params_product.memory_manifest
                .manifest_commitment;
    hash << product.round_roots_pin.pin_commitment;
    hash << static_cast<uint32_t>(product.steps.size());
    for (uint32_t i = 0; i < product.steps.size(); ++i) {
        const auto& step = product.steps[i];
        if (step.round_index != i || step.source.IsNull() ||
            step.sha.commitment.IsNull()) {
            return {};
        }
        hash << step.round_index;
        hash << step.source;
        hash << step.sha.commitment;
        hash << DigestUint(step.sha.digest);
    }
    hash << product.seed_memory_manifest.manifest_commitment;
    return hash.GetHash();
}

bool ProveRCStage3EpisodeBuilderSeedChainProduct(
    const RCStage3SuccinctProof& statement,
    const RCEpisodeParams& expected_params,
    const ha::EpisodeDigestManifest& round_root_manifest,
    RCStage3EpisodeBuilderSeedChainProduct& out,
    std::string* why)
{
    out = {};
    const uint256 statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    if (!IsEpisodeStatement(statement) ||
        statement_commitment.IsNull() ||
        !ValidateRCEpisodeParams(expected_params) ||
        expected_params.rounds >
            kRCStage3EpisodeSemanticMaxRows / 8U ||
        !ValidateRCStage3EpisodeDigestManifestStructural(
            round_root_manifest, expected_params.rounds, why) ||
        round_root_manifest.direct.digest !=
            statement.public_inputs.episode_digest) {
        return Fail(why, "prove_public_shape");
    }
    out.version = kRCStage3EpisodeBuilderSeedChainVersion;
    out.statement_commitment = statement_commitment;
    out.header_commitment =
        statement.public_inputs.header_commitment;
    out.params_commitment =
        statement.public_inputs.params_commitment;
    out.sigma = statement.public_inputs.sigma;
    out.expected_rounds = expected_params.rounds;
    out.round_root_manifest = round_root_manifest;

    if (!ProveRCStage3EpisodeBuilderParamsProduct(
            statement_commitment, expected_params,
            out.params_product, why)) {
        return Fail(why, "prove_params_parent");
    }
    const std::vector<uint8_t> round_roots =
        RoundRootBytes(round_root_manifest);
    if (!BuildRCStage3RootChainVectorPin(
            RCStage3RelationEndpoint::EpisodeDigestRoundRoots,
            statement_commitment, round_root_manifest.commitment,
            round_roots, out.round_roots_pin, why) ||
        !ProveRCStage3RootChainVector(
            out.round_roots_pin, round_roots,
            out.round_roots_proof, why)) {
        return Fail(why, "prove_round_roots");
    }

    out.steps.resize(expected_params.rounds);
    for (uint32_t round_index = 0;
         round_index < expected_params.rounds; ++round_index) {
        auto& step = out.steps[round_index];
        step.round_index = round_index;
        step.source = round_index == 0
            ? statement.public_inputs.sigma
            : round_root_manifest.round_roots[
                  round_index - 1];
        if (!ha::BuildShaManifest(
                SeedPreimage(step.source, round_index),
                ha::ShaMode::Single, step.sha, why) ||
            !ProveShaStep(
                statement_commitment, step, why)) {
            return Fail(
                why, "prove_seed_" +
                    std::to_string(round_index));
        }
    }

    std::vector<Fp3> seed_values;
    if (!ExpectedSeedMemoryManifest(
            statement_commitment, out.steps,
            out.seed_memory_manifest, seed_values, why) ||
        !ProveRCStage3EpisodeSemanticMemory(
            out.seed_memory_manifest, seed_values,
            out.seed_memory_proof, why)) {
        return Fail(why, "prove_seed_memory");
    }
    out.product_commitment =
        ComputeRCStage3EpisodeBuilderSeedChainProductCommitment(
            out);
    if (out.product_commitment.IsNull()) {
        return Fail(why, "prove_product_commitment");
    }
    if (why != nullptr) {
        *why =
            "stage3:episode_builder_seed_chain:all_seed_"
            "sha_and_memory_proofs_built";
    }
    return true;
}

bool VerifyRCStage3EpisodeBuilderSeedChainProduct(
    const RCStage3SuccinctProof& statement,
    const RCEpisodeParams& expected_params,
    const RCStage3EpisodeBuilderSeedChainProduct& product,
    std::string* why)
{
    RCStage3EpisodeSemanticMemoryManifest expected_memory;
    std::vector<Fp3> seed_values;
    if (!StructuralProduct(
            statement, expected_params, product,
            expected_memory, seed_values, why)) {
        return false;
    }
    if (!VerifyRCStage3EpisodeBuilderParamsProduct(
            product.statement_commitment, expected_params,
            product.params_product, why)) {
        return Fail(why, "params_parent");
    }
    const std::vector<uint8_t> round_roots =
        RoundRootBytes(product.round_root_manifest);
    if (!VerifyRCStage3RootChainVector(
            RCStage3RelationEndpoint::EpisodeDigestRoundRoots,
            product.statement_commitment,
            product.round_root_manifest.commitment,
            round_roots, product.round_roots_pin,
            product.round_roots_proof, why)) {
        return Fail(why, "round_root_vector");
    }
    for (uint32_t round_index = 0;
         round_index < product.expected_rounds; ++round_index) {
        const auto& step = product.steps[round_index];
        if (!hs::VerifyShaManifestBundle(
                RCStage3RelationEndpoint::EpisodeBuilderSeedChain,
                step.sha, step.hash_proof, why)) {
            return Fail(
                why, "seed_sha_" +
                    std::to_string(round_index));
        }
    }
    if (!VerifyRCStage3EpisodeSemanticMemory(
            product.statement_commitment,
            expected_memory, product.seed_memory_proof, why)) {
        return Fail(why, "seed_memory_proof");
    }
    if (why != nullptr) {
        *why =
            "stage3:episode_builder_seed_chain:exact_all_round_"
            "sha_provenance_and_seed_memory_product_ok";
    }
    return true;
}

RCStage3EpisodeBuilderSeedChainAudit
CurrentRCStage3EpisodeBuilderSeedChainAudit(
    bool public_consensus_ancestor_complete,
    bool endpoint1_ancestor_complete,
    bool round_root_ancestor_complete)
{
    RCStage3EpisodeBuilderSeedChainAudit out;
    out.verifier_ordered_schedule = true;
    out.exact_all_instance_sha_execution = true;
    out.final_seed_words_memory_link = true;
    out.endpoint1_params_product_executed = true;
    out.round_root_vector_executed = true;
    out.local_relation_complete =
        kRCStage3EpisodeBuilderSeedChainLocalProductExecutable;
    out.public_consensus_ancestor_complete =
        public_consensus_ancestor_complete;
    out.endpoint1_ancestor_complete =
        endpoint1_ancestor_complete;
    out.round_root_ancestor_complete =
        round_root_ancestor_complete;
    out.producer_provenance_complete =
        public_consensus_ancestor_complete &&
        endpoint1_ancestor_complete &&
        round_root_ancestor_complete;
    out.semantic_complete =
        out.local_relation_complete &&
        out.producer_provenance_complete;
    out.recursively_consumed =
        kRCStage3EpisodeBuilderSeedChainRecursivelyConsumed;
    if (out.semantic_complete && !out.recursively_consumed) {
        out.remaining =
            "normalized recursive child consumption remains";
    } else if (!out.semantic_complete) {
        out.remaining =
            "unified graph must close public consensus, endpoint-1 params, "
            "and endpoint-23 round-root producer ancestry";
    }
    return out;
}

static_assert(
    kRCStage3EpisodeBuilderSeedChainLocalProductExecutable);
static_assert(
    !kRCStage3EpisodeBuilderSeedChainRecursivelyConsumed);

} // namespace matmul::v4::rc
