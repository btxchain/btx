// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_fixed_program_semantic_product.h>

#include <hash.h>
#include <matmul/matmul_v4_rc_stage3_hash_semantic.h>

#include <algorithm>
#include <limits>
#include <type_traits>

namespace matmul::v4::rc::fixed_program_semantic_product {
namespace {

namespace gf = gkr_field;
namespace hs = stage3_hash_semantic;

struct Recipe {
    sites::ProductionProofSiteKind kind;
    RCStage3RelationRole role;
    RCStage3RelationEndpoint endpoint;
    ha::ProgramKind program_kind;
    uint8_t payload_index;
    const char* domain;
};

constexpr uint8_t SHA = 0;
constexpr uint8_t XOF = 1;
constexpr uint8_t CHACHA = 2;

constexpr std::array<Recipe, kFamilyCountV1> RECIPES{{
    {sites::ProductionProofSiteKind::EpisodeScaleSha,
     RCStage3RelationRole::EpisodeExtract,
     RCStage3RelationEndpoint::EpisodeExtractScale,
     ha::ProgramKind::Sha256Compression, SHA,
     "BTX_RC_STAGE3_FIXED_PRODUCT_EPISODE_SCALE_SHA_V1"},
    {sites::ProductionProofSiteKind::EpisodeExtractChaCha,
     RCStage3RelationRole::EpisodeExtract,
     RCStage3RelationEndpoint::EpisodeExtractChaCha,
     ha::ProgramKind::ChaCha20Block, CHACHA,
     "BTX_RC_STAGE3_FIXED_PRODUCT_EPISODE_EXTRACT_CHACHA_V1"},
    {sites::ProductionProofSiteKind::CoupledBankCounterXof,
     RCStage3RelationRole::CoupledBank,
     RCStage3RelationEndpoint::CoupledBankSeedXof,
     ha::ProgramKind::Sha256Compression, XOF,
     "BTX_RC_STAGE3_FIXED_PRODUCT_COUPLED_BANK_XOF_V1"},
    {sites::ProductionProofSiteKind::CoupledBankCommitmentSha256d,
     RCStage3RelationRole::CoupledBank,
     RCStage3RelationEndpoint::CoupledBankRoot,
     ha::ProgramKind::Sha256Compression, SHA,
     "BTX_RC_STAGE3_FIXED_PRODUCT_COUPLED_BANK_SHA_V1"},
    {sites::ProductionProofSiteKind::CoupledLobeInitCounterXof,
     RCStage3RelationRole::CoupledGemm,
     RCStage3RelationEndpoint::CoupledGemmOperandA,
     ha::ProgramKind::Sha256Compression, XOF,
     "BTX_RC_STAGE3_FIXED_PRODUCT_COUPLED_LOBE_XOF_V1"},
    {sites::ProductionProofSiteKind::CoupledPageScheduleXof,
     RCStage3RelationRole::CoupledGemm,
     RCStage3RelationEndpoint::CoupledGemmOperandB,
     ha::ProgramKind::Sha256Compression, XOF,
     "BTX_RC_STAGE3_FIXED_PRODUCT_COUPLED_PAGE_XOF_V1"},
    {sites::ProductionProofSiteKind::CoupledExchangeXof,
     RCStage3RelationRole::CoupledExchange,
     RCStage3RelationEndpoint::CoupledExchangeHashXof,
     ha::ProgramKind::Sha256Compression, XOF,
     "BTX_RC_STAGE3_FIXED_PRODUCT_COUPLED_EXCHANGE_XOF_V1"},
    {sites::ProductionProofSiteKind::CoupledPermutationXof,
     RCStage3RelationRole::CoupledPermutation,
     RCStage3RelationEndpoint::CoupledPermutationInput,
     ha::ProgramKind::Sha256Compression, XOF,
     "BTX_RC_STAGE3_FIXED_PRODUCT_COUPLED_PERMUTATION_XOF_V1"},
    {sites::ProductionProofSiteKind::CoupledMixXof,
     RCStage3RelationRole::CoupledMix,
     RCStage3RelationEndpoint::CoupledMixInput,
     ha::ProgramKind::Sha256Compression, XOF,
     "BTX_RC_STAGE3_FIXED_PRODUCT_COUPLED_MIX_XOF_V1"},
    {sites::ProductionProofSiteKind::CoupledExtractScaleSha,
     RCStage3RelationRole::CoupledExtract,
     RCStage3RelationEndpoint::CoupledExtractScale,
     ha::ProgramKind::Sha256Compression, SHA,
     "BTX_RC_STAGE3_FIXED_PRODUCT_COUPLED_EXTRACT_SCALE_SHA_V1"},
    {sites::ProductionProofSiteKind::CoupledExtractChaCha,
     RCStage3RelationRole::CoupledExtract,
     RCStage3RelationEndpoint::CoupledExtractChaCha,
     ha::ProgramKind::ChaCha20Block, CHACHA,
     "BTX_RC_STAGE3_FIXED_PRODUCT_COUPLED_EXTRACT_CHACHA_V1"},
}};

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:fixed_program_semantic_product:" + detail;
    }
    return false;
}

uint256 TypedDomain(const Recipe& recipe)
{
    HashWriter hash;
    hash << std::string{recipe.domain};
    hash << static_cast<uint8_t>(recipe.kind);
    hash << static_cast<uint8_t>(recipe.role);
    hash << static_cast<uint16_t>(recipe.endpoint);
    hash << static_cast<uint8_t>(recipe.program_kind);
    return hash.GetHash();
}

uint256 CommitSchedule(
    const Recipe& recipe,
    const std::vector<ha::FixedProgramBoundaryInstance>& boundaries)
{
    HashWriter hash;
    hash << std::string{"BTX_RC_STAGE3_FIXED_PRODUCT_SCHEDULE_V1"};
    hash << TypedDomain(recipe);
    hash << static_cast<uint32_t>(boundaries.size());
    for (uint32_t i = 0; i < boundaries.size(); ++i) {
        hash << i;
        hash << static_cast<uint32_t>(
            boundaries[i].external_values.size());
        for (uint32_t word : boundaries[i].external_values) hash << word;
        hash << static_cast<uint32_t>(
            boundaries[i].final_words.size());
        for (uint32_t word : boundaries[i].final_words) hash << word;
    }
    return hash.GetHash();
}

bool DecodePayload(
    const Recipe& recipe,
    const FamilyPayloadV1& payload,
    uint256& manifest_commitment,
    std::vector<ha::FixedProgramBoundaryInstance>& boundaries,
    std::string* why)
{
    manifest_commitment.SetNull();
    boundaries.clear();
    std::string local;
    if (recipe.payload_index == SHA) {
        const auto* manifest = std::get_if<ha::ShaManifest>(&payload);
        if (manifest == nullptr ||
            manifest->commitment !=
                ha::CommitShaManifest(*manifest) ||
            !ha::BuildShaManifestBoundaryInstances(
                *manifest, boundaries, &local)) {
            return Fail(why, "sha_payload:" + local);
        }
        manifest_commitment = ha::CommitShaManifest(*manifest);
    } else if (recipe.payload_index == XOF) {
        const auto* manifest =
            std::get_if<ha::CounterXofManifest>(&payload);
        if (manifest == nullptr ||
            manifest->commitment !=
                ha::CommitCounterXofManifest(*manifest) ||
            !ha::BuildCounterXofManifestBoundaryInstances(
                *manifest, boundaries, &local)) {
            return Fail(why, "xof_payload:" + local);
        }
        manifest_commitment =
            ha::CommitCounterXofManifest(*manifest);
    } else {
        const auto* manifest =
            std::get_if<ha::ChaChaConsumptionManifest>(&payload);
        if (manifest == nullptr ||
            manifest->commitment !=
                ha::CommitChaChaConsumptionManifest(*manifest) ||
            !ha::BuildChaChaManifestBoundaryInstances(
                *manifest, boundaries, &local)) {
            return Fail(why, "chacha_payload:" + local);
        }
        manifest_commitment =
            ha::CommitChaChaConsumptionManifest(*manifest);
    }
    if (manifest_commitment.IsNull() || boundaries.empty() ||
        boundaries.size() > std::numeric_limits<uint32_t>::max()) {
        return Fail(why, "payload_shape");
    }
    return true;
}

uint256 CommitAllInstances(
    const std::array<FamilyStatementV1, kFamilyCountV1>& families)
{
    HashWriter hash;
    hash << std::string{
        "BTX_RC_STAGE3_FIXED_PRODUCT_ALL_INSTANCES_V1"};
    hash << kFamilyCountV1;
    for (const auto& family : families) {
        hash << family.family_ordinal;
        hash << static_cast<uint8_t>(family.kind);
        hash << static_cast<uint8_t>(family.role);
        hash << static_cast<uint16_t>(family.endpoint);
        hash << static_cast<uint8_t>(family.program_kind);
        hash << family.program_boundary_begin;
        hash << family.boundary_count;
        hash << family.output_logical_rows;
        hash << family.output_padded_rows;
        hash << family.typed_domain;
        hash << family.manifest_commitment;
        hash << family.immutable_schedule_commitment;
        hash << family.boundary_pinned_output_root;
    }
    return hash.GetHash();
}

uint256 CommitStatement(const ProductManifestV1& manifest)
{
    HashWriter hash;
    hash << std::string{"BTX_RC_STAGE3_FIXED_PRODUCT_STATEMENT_V1"};
    hash << manifest.version;
    hash << manifest.production_site_manifest_commitment;
    hash << manifest.sha_boundary_count;
    hash << manifest.chacha_boundary_count;
    hash << manifest.exact_all_instance_root;
    for (const auto& family : manifest.families) {
        hash << family.typed_domain;
        hash << family.manifest_commitment;
        hash << family.immutable_schedule_commitment;
        hash << family.boundary_pinned_output_root;
        hash << family.program_boundary_begin;
        hash << family.boundary_count;
    }
    return hash.GetHash();
}

uint256 ChildSeed(
    const uint256& fs_seed,
    const uint256& statement,
    ha::ProgramKind kind,
    uint32_t total,
    uint32_t child,
    uint32_t begin,
    uint32_t count)
{
    HashWriter hash;
    hash << std::string{"BTX_RC_STAGE3_FIXED_PRODUCT_CHILD_V1"};
    hash << fs_seed;
    hash << statement;
    hash << static_cast<uint8_t>(kind);
    hash << total;
    hash << child;
    hash << begin;
    hash << count;
    return hash.GetHash();
}

bool Derive(
    const FamilyInputsV1& inputs,
    ProductManifestV1& manifest,
    std::vector<ha::FixedProgramBoundaryInstance>& sha,
    std::vector<ha::FixedProgramBoundaryInstance>& chacha,
    std::string* why)
{
    manifest = {};
    sha.clear();
    chacha.clear();
    const auto production =
        sites::BuildProductionProofSiteManifest(
            sites::SelectedProductionProofSitePolicy());
    std::string production_why;
    if (!sites::ValidateProductionProofSiteManifest(
            production, &production_why) ||
        production.commitment.IsNull()) {
        return Fail(why, "production_manifest:" + production_why);
    }
    manifest.production_site_manifest_commitment =
        production.commitment;

    for (uint32_t i = 0; i < kFamilyCountV1; ++i) {
        const Recipe& recipe = RECIPES[i];
        if (inputs[i].kind != recipe.kind) {
            return Fail(why, "family_order:" + std::to_string(i));
        }
        uint256 manifest_root;
        std::vector<ha::FixedProgramBoundaryInstance> boundaries;
        if (!DecodePayload(
                recipe, inputs[i].payload, manifest_root,
                boundaries, why)) {
            return false;
        }
        FamilyStatementV1 family;
        family.kind = recipe.kind;
        family.role = recipe.role;
        family.endpoint = recipe.endpoint;
        family.program_kind = recipe.program_kind;
        family.family_ordinal = i;
        auto& batch =
            recipe.program_kind ==
                    ha::ProgramKind::Sha256Compression
                ? sha
                : chacha;
        family.program_boundary_begin =
            static_cast<uint32_t>(batch.size());
        family.boundary_count =
            static_cast<uint32_t>(boundaries.size());
        family.typed_domain = TypedDomain(recipe);
        family.manifest_commitment = manifest_root;
        family.immutable_schedule_commitment =
            CommitSchedule(recipe, boundaries);
        if (family.typed_domain.IsNull() ||
            family.immutable_schedule_commitment.IsNull() ||
            !hs::ComputeCanonicalBoundaryValueRoot(
                boundaries, hs::BoundaryPort::Final,
                family.boundary_pinned_output_root,
                family.output_logical_rows,
                family.output_padded_rows, why)) {
            return Fail(why, "family_roots:" + std::to_string(i));
        }
        batch.insert(
            batch.end(), boundaries.begin(), boundaries.end());
        manifest.families[i] = family;
    }
    if (sha.empty() || chacha.empty() ||
        sha.size() > std::numeric_limits<uint32_t>::max() ||
        chacha.size() > std::numeric_limits<uint32_t>::max()) {
        return Fail(why, "batch_shape");
    }
    manifest.sha_boundary_count =
        static_cast<uint32_t>(sha.size());
    manifest.chacha_boundary_count =
        static_cast<uint32_t>(chacha.size());
    manifest.exact_all_instance_root =
        CommitAllInstances(manifest.families);
    manifest.canonical_family_order = true;
    manifest.immutable_schedule_derived = true;
    manifest.opcode_selector_children_required = true;
    manifest.internal_ssa_copy_children_required = true;
    manifest.boundary_public_pins_required = true;
    manifest.exact_input_manifest_aggregation = true;
    manifest.production_manifest_derived = false;
    manifest.production_all_instance_aggregation = false;
    manifest.public_boundary_values = true;
    manifest.proof_owned_output_exports = false;
    manifest.caller_manifests_bound_to_role_proofs = false;
    manifest.recursive_child_consumed = false;
    manifest.semantic_closure = false;
    manifest.production_authority = false;
    manifest.statement_commitment = CommitStatement(manifest);
    if (manifest.exact_all_instance_root.IsNull() ||
        manifest.statement_commitment.IsNull()) {
        return Fail(why, "statement_root");
    }
    return true;
}

bool ProveBatch(
    const std::vector<ha::FixedProgramBoundaryInstance>& boundaries,
    ha::ProgramKind kind,
    const uint256& fs_seed,
    const ProductManifestV1& manifest,
    ProgramBatchProofV1& out,
    std::string* why)
{
    out = {};
    out.program_kind = kind;
    out.boundary_count = static_cast<uint32_t>(boundaries.size());
    const auto program = ha::BuildCanonicalProgram(kind);
    const uint32_t chunks =
        (out.boundary_count + kMaxBoundariesPerChildV1 - 1U) /
        kMaxBoundariesPerChildV1;
    out.children.resize(chunks);
    for (uint32_t child = 0; child < chunks; ++child) {
        const uint32_t begin =
            child * kMaxBoundariesPerChildV1;
        const uint32_t count = std::min(
            kMaxBoundariesPerChildV1,
            out.boundary_count - begin);
        std::vector<ha::FixedProgramBoundaryInstance> slice(
            boundaries.begin() + begin,
            boundaries.begin() + begin + count);
        const uint256 seed = ChildSeed(
            fs_seed, manifest.statement_commitment, kind,
            out.boundary_count, child, begin, count);
        if (!ha::ProveFixedProgramVerticalProvenanceAir(
                program, slice, seed, out.children[child], why)) {
            out = {};
            return Fail(
                why, "prove_child:" + std::to_string(child));
        }
    }
    return true;
}

bool VerifyBatch(
    const std::vector<ha::FixedProgramBoundaryInstance>& boundaries,
    ha::ProgramKind kind,
    const uint256& fs_seed,
    const ProductManifestV1& manifest,
    const ProgramBatchProofV1& proof,
    std::string* why)
{
    const uint32_t count =
        static_cast<uint32_t>(boundaries.size());
    const uint32_t chunks =
        (count + kMaxBoundariesPerChildV1 - 1U) /
        kMaxBoundariesPerChildV1;
    if (proof.program_kind != kind ||
        proof.boundary_count != count ||
        proof.children.size() != chunks) {
        return Fail(why, "verify_batch_shape");
    }
    const auto program = ha::BuildCanonicalProgram(kind);
    for (uint32_t child = 0; child < chunks; ++child) {
        const uint32_t begin =
            child * kMaxBoundariesPerChildV1;
        const uint32_t child_count = std::min(
            kMaxBoundariesPerChildV1, count - begin);
        std::vector<ha::FixedProgramBoundaryInstance> slice(
            boundaries.begin() + begin,
            boundaries.begin() + begin + child_count);
        const uint256 seed = ChildSeed(
            fs_seed, manifest.statement_commitment, kind,
            count, child, begin, child_count);
        std::string child_why;
        if (!ha::VerifyFixedProgramVerticalProvenanceAir(
                program, slice, seed, proof.children[child],
                &child_why)) {
            return Fail(
                why, "verify_child:" + std::to_string(child) +
                    ":" + child_why);
        }
    }
    return true;
}

} // namespace

bool BuildProductManifestV1(
    const FamilyInputsV1& inputs,
    ProductManifestV1& out,
    std::string* why)
{
    std::vector<ha::FixedProgramBoundaryInstance> sha;
    std::vector<ha::FixedProgramBoundaryInstance> chacha;
    return Derive(inputs, out, sha, chacha, why);
}

bool ProveProductV1(
    const FamilyInputsV1& inputs,
    const uint256& fs_seed,
    ProductProofV1& out,
    std::string* why)
{
    out = {};
    if (fs_seed.IsNull()) return Fail(why, "null_fs_seed");
    std::vector<ha::FixedProgramBoundaryInstance> sha;
    std::vector<ha::FixedProgramBoundaryInstance> chacha;
    if (!Derive(inputs, out.manifest, sha, chacha, why) ||
        !ProveBatch(
            sha, ha::ProgramKind::Sha256Compression,
            fs_seed, out.manifest, out.sha, why) ||
        !ProveBatch(
            chacha, ha::ProgramKind::ChaCha20Block,
            fs_seed, out.manifest, out.chacha, why)) {
        out = {};
        return false;
    }
    out.valid = true;
    out.note =
        "stage3:fixed_program_semantic_product:"
        "eleven_typed_input_families_proved;"
        "role_source_and_recursion_open";
    return true;
}

bool VerifyProductV1(
    const FamilyInputsV1& inputs,
    const uint256& fs_seed,
    const ProductProofV1& proof,
    std::string* why)
{
    if (fs_seed.IsNull() || proof.version != kVersionV1 ||
        !proof.valid) {
        return Fail(why, "proof_shape");
    }
    ProductManifestV1 expected;
    std::vector<ha::FixedProgramBoundaryInstance> sha;
    std::vector<ha::FixedProgramBoundaryInstance> chacha;
    if (!Derive(inputs, expected, sha, chacha, why) ||
        proof.manifest != expected ||
        proof.manifest.recursive_child_consumed ||
        proof.manifest.semantic_closure ||
        proof.manifest.production_authority) {
        return Fail(why, "canonical_manifest");
    }
    if (!VerifyBatch(
            sha, ha::ProgramKind::Sha256Compression,
            fs_seed, expected, proof.sha, why) ||
        !VerifyBatch(
            chacha, ha::ProgramKind::ChaCha20Block,
            fs_seed, expected, proof.chacha, why)) {
        return false;
    }
    if (why != nullptr) {
        *why =
            "stage3:fixed_program_semantic_product:"
            "eleven_typed_input_families_verified;"
            "role_source_and_recursion_open";
    }
    return true;
}

bool DecodeCanonicalU32V1(
    const Fp3& cell,
    uint32_t& out,
    std::string* why)
{
    out = 0;
    if (cell.c0 != gf::Canonical(cell.c0) ||
        cell.c1 != 0 || cell.c2 != 0 ||
        cell.c0 > std::numeric_limits<uint32_t>::max()) {
        return Fail(why, "noncanonical_u32");
    }
    out = static_cast<uint32_t>(cell.c0);
    return true;
}

} // namespace matmul::v4::rc::fixed_program_semantic_product
