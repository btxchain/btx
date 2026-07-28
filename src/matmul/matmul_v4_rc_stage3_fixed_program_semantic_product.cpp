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

Fp3 U64(uint64_t value)
{
    return Fp3::FromFp(gf::FromU64(value));
}

uint32_t OutputSlot(const ha::ProgramRow& row)
{
    switch (row.opcode) {
    case ha::ProgramOpcode::ShaChoice32:
    case ha::ProgramOpcode::ShaMajority32:
        return 3;
    case ha::ProgramOpcode::ShaSmallSigma0:
    case ha::ProgramOpcode::ShaSmallSigma1:
    case ha::ProgramOpcode::ShaBigSigma0:
    case ha::ProgramOpcode::ShaBigSigma1:
        return 1;
    default:
        return 2;
    }
}

void HashFp3(HashWriter& hash, const Fp3& value)
{
    hash << value.c0;
    hash << value.c1;
    hash << value.c2;
}

struct BatchMapV2 {
    std::vector<uint32_t> family;
    std::vector<uint32_t> family_boundary;
};

bool BuildBatchMapV2(
    const ProductManifestV1& manifest,
    ha::ProgramKind kind,
    uint32_t boundary_count,
    BatchMapV2& out,
    std::string* why)
{
    out.family.assign(
        boundary_count, std::numeric_limits<uint32_t>::max());
    out.family_boundary.assign(boundary_count, 0);
    for (const auto& family : manifest.families) {
        if (family.program_kind != kind) continue;
        if (family.program_boundary_begin > boundary_count ||
            family.boundary_count >
                boundary_count - family.program_boundary_begin) {
            return Fail(why, "witness_batch_map_range");
        }
        for (uint32_t local = 0;
             local < family.boundary_count; ++local) {
            const uint32_t index =
                family.program_boundary_begin + local;
            if (out.family[index] !=
                std::numeric_limits<uint32_t>::max()) {
                return Fail(why, "witness_batch_map_overlap");
            }
            out.family[index] = family.family_ordinal;
            out.family_boundary[index] = local;
        }
    }
    if (std::find(
            out.family.begin(), out.family.end(),
            std::numeric_limits<uint32_t>::max()) !=
        out.family.end()) {
        return Fail(why, "witness_batch_map_hole");
    }
    return true;
}

struct WitnessChunkShapeV2 {
    uint32_t child_ordinal{0};
    uint32_t global_source_begin{0};
    std::vector<ha::FixedProgramBoundaryInstance>
        honest_boundaries;
    std::vector<ha::FixedProgramBoundaryInstance>
        public_templates;
    std::vector<std::vector<uint8_t>> public_masks;
    std::vector<ha::FixedProgramWitnessBoundaryLink> links;
    std::vector<uint32_t> family;
    std::vector<uint32_t> family_boundary;
    uint32_t source_count{0};
    uint32_t sink_count{0};
};

bool BuildWitnessChunkShapeV2(
    const std::vector<ha::FixedProgramBoundaryInstance>& batch,
    const BatchMapV2& map,
    ha::ProgramKind kind,
    uint32_t child_ordinal,
    uint32_t begin,
    uint32_t count,
    bool build_honest_witness,
    WitnessChunkShapeV2& out,
    std::string* why)
{
    out = {};
    if (count == 0 ||
        count > kMaxWitnessSourcesPerChildV2 ||
        begin > batch.size() || count > batch.size() - begin ||
        map.family.size() != batch.size() ||
        map.family_boundary.size() != batch.size()) {
        return Fail(why, "witness_chunk_shape");
    }
    const auto program = ha::BuildCanonicalProgram(kind);
    const uint32_t final_count =
        static_cast<uint32_t>(program.final_addresses.size());
    if (final_count == 0 ||
        program.external_address_count < final_count) {
        return Fail(why, "witness_sink_capacity");
    }
    const uint32_t sources_per_sink =
        program.external_address_count / final_count;
    const uint32_t linked_sinks =
        (count + sources_per_sink - 1U) / sources_per_sink;
    uint32_t scheduled_instances = 1;
    while (scheduled_instances < count + linked_sinks) {
        scheduled_instances <<= 1;
    }
    if (scheduled_instances < 2) {
        scheduled_instances = 2;
    }
    // The witness-boundary builder repeats its final semantic instance when
    // filling power-of-two padding rows.  That is unsuitable here: the final
    // linked sink contains private values, so a verifier constructing only
    // the public statement would derive different preprocessed padding.
    // Materialize every padding lane as a canonical all-zero auxiliary sink
    // instead.  Its public inputs are fixed and its execution is proved, so
    // no extra proof-owned source or unconstrained value is introduced.
    const uint32_t sinks = scheduled_instances - count;
    if (scheduled_instances > 64 ||
        linked_sinks > sinks) {
        return Fail(why, "witness_chunk_instances");
    }
    out.child_ordinal = child_ordinal;
    out.global_source_begin = begin;
    out.source_count = count;
    out.sink_count = sinks;
    out.family.assign(
        map.family.begin() + begin,
        map.family.begin() + begin + count);
    out.family_boundary.assign(
        map.family_boundary.begin() + begin,
        map.family_boundary.begin() + begin + count);
    if (build_honest_witness) {
        out.honest_boundaries.assign(
            batch.begin() + begin, batch.begin() + begin + count);
    } else {
        out.honest_boundaries.resize(count);
        for (auto& boundary : out.honest_boundaries) {
            boundary.external_values.assign(
                program.external_address_count, 0);
            boundary.final_words.assign(final_count, 0);
        }
    }
    out.public_templates.resize(count + sinks);
    out.public_masks.resize(count + sinks);
    for (uint32_t source = 0; source < count; ++source) {
        auto& public_boundary = out.public_templates[source];
        public_boundary.external_values.assign(
            program.external_address_count, 0);
        public_boundary.final_words.assign(final_count, 0);
        out.public_masks[source].assign(
            program.external_address_count, 0);
    }
    for (uint32_t sink = 0; sink < sinks; ++sink) {
        ha::FixedProgramBoundaryInstance honest_sink;
        honest_sink.external_values.assign(
            program.external_address_count, 0);
        auto& public_sink = out.public_templates[count + sink];
        public_sink.external_values.assign(
            program.external_address_count, 0);
        public_sink.final_words.assign(final_count, 0);
        out.public_masks[count + sink].assign(
            program.external_address_count, 1);
        out.honest_boundaries.push_back(std::move(honest_sink));
    }
    for (uint32_t source = 0; source < count; ++source) {
        const uint32_t sink = source / sources_per_sink;
        const uint32_t sink_slot = source % sources_per_sink;
        for (uint32_t word = 0; word < final_count; ++word) {
            const uint32_t target_address =
                sink_slot * final_count + word + 1U;
            if (build_honest_witness) {
                out.honest_boundaries[count + sink]
                    .external_values[target_address - 1U] =
                    out.honest_boundaries[source].final_words[word];
            }
            out.public_masks[count + sink]
                [target_address - 1U] = 0;
            ha::FixedProgramWitnessBoundaryLink link;
            link.source_instance = source;
            link.source_final_word = word;
            link.target_instance = count + sink;
            link.target_external_address = target_address;
            link.link_id =
                UINT64_C(0x4658500000000000) +
                static_cast<uint64_t>(child_ordinal) *
                    UINT64_C(0x100000) +
                static_cast<uint64_t>(source) *
                    UINT64_C(0x100) +
                word + 1U;
            if (link.link_id >= gf::kP) {
                return Fail(why, "witness_link_namespace");
            }
            out.links.push_back(link);
        }
    }
    for (uint32_t sink = 0;
         build_honest_witness && sink < sinks; ++sink) {
        ha::ProgramWitness witness;
        std::string local;
        auto& boundary = out.honest_boundaries[count + sink];
        if (!ha::BuildProgramWitness(
                program, boundary.external_values,
                witness, &local)) {
            return Fail(why, "witness_sink_execute:" + local);
        }
        boundary.final_words = std::move(witness.final_words);
    }
    return true;
}

uint64_t OutputEventIdV2(
    uint32_t family,
    uint32_t family_boundary,
    uint32_t word)
{
    return UINT64_C(0x4658501000000000) +
        static_cast<uint64_t>(family) * UINT64_C(0x100000000) +
        static_cast<uint64_t>(family_boundary) *
            UINT64_C(0x10000) +
        word + 1U;
}

uint64_t ExternalInputEventIdV2(
    const WitnessChunkShapeV2& shape,
    uint32_t source,
    uint32_t address)
{
    return UINT64_C(0x4558430000000000) +
        static_cast<uint64_t>(shape.child_ordinal) *
            UINT64_C(0x100000000) +
        static_cast<uint64_t>(
            shape.global_source_begin + source) *
            UINT64_C(0x100000) +
        address;
}

bool AppendExternalInputCopyCtlV2(
    const ha::FixedProgram& program,
    const WitnessChunkShapeV2& shape,
    const RCStage3CtlChallenges& challenges,
    air_quotient::AirConstraintSystem<Fp3>& cs,
    std::vector<std::vector<Fp3>>* columns,
    std::string* why)
{
    constexpr uint32_t SLOT_COUNT = 3;
    if (shape.source_count == 0 ||
        shape.honest_boundaries.size() < shape.source_count ||
        (columns != nullptr &&
         (columns->size() != cs.n_columns ||
          (!columns->empty() &&
           columns->front().size() != cs.n_rows)))) {
        return Fail(why, "witness_external_copy_shape");
    }
    std::vector<uint32_t> use_count(
        program.external_address_count + 1U, 0);
    for (const auto& row : program.rows) {
        for (uint32_t slot = 0;
             slot < row.input_count; ++slot) {
            const uint32_t address =
                row.input_address[slot];
            if (address >= 1 &&
                address <=
                    program.external_address_count) {
                ++use_count[address];
            }
        }
    }
    for (uint32_t address = 1;
         address <= program.external_address_count;
         ++address) {
        if (use_count[address] == 0) {
            return Fail(
                why, "witness_external_copy_unused_address");
        }
    }

    const uint32_t producer_mult_base = cs.n_columns;
    cs.n_columns += SLOT_COUNT;
    const uint32_t consumer_id_base = cs.n_columns;
    cs.n_columns += SLOT_COUNT;
    const uint32_t consumer_inv1_base = cs.n_columns;
    cs.n_columns += SLOT_COUNT;
    const uint32_t consumer_inv2_base = cs.n_columns;
    cs.n_columns += SLOT_COUNT;
    const uint32_t running1 = cs.n_columns++;
    const uint32_t running2 = cs.n_columns++;

    std::array<std::vector<Fp3>, SLOT_COUNT> p_mult;
    std::array<std::vector<Fp3>, SLOT_COUNT> c_id;
    for (uint32_t slot = 0; slot < SLOT_COUNT; ++slot) {
        p_mult[slot].assign(cs.n_rows, Fp3::Zero());
        c_id[slot].assign(cs.n_rows, Fp3::Zero());
    }
    uint64_t event_count = 0;
    for (uint32_t source = 0;
         source < shape.source_count; ++source) {
        std::vector<uint8_t> seen(
            program.external_address_count + 1U, 0);
        for (uint32_t phase = 0;
             phase < program.rows.size(); ++phase) {
            const auto& row = program.rows[phase];
            const uint32_t trace_row =
                source * 1024U + phase;
            if (trace_row >= cs.n_rows ||
                row.input_count > SLOT_COUNT) {
                return Fail(
                    why, "witness_external_copy_row");
            }
            for (uint32_t slot = 0;
                 slot < row.input_count; ++slot) {
                const uint32_t address =
                    row.input_address[slot];
                if (address == 0 ||
                    address >
                        program.external_address_count) {
                    continue;
                }
                const uint64_t id =
                    ExternalInputEventIdV2(
                        shape, source, address);
                if (id >= gf::kP ||
                    use_count[address] == 0) {
                    return Fail(
                        why, "witness_external_copy_id");
                }
                c_id[slot][trace_row] = U64(id);
                ++event_count;
                if (!seen[address]) {
                    p_mult[slot][trace_row] =
                        U64(use_count[address]);
                    seen[address] = 1;
                }
            }
        }
    }
    if (event_count == 0) {
        return Fail(why, "witness_external_copy_empty");
    }
    for (uint32_t slot = 0; slot < SLOT_COUNT; ++slot) {
        cs.preprocessed.emplace_back(
            producer_mult_base + slot, p_mult[slot]);
        cs.preprocessed.emplace_back(
            consumer_id_base + slot, c_id[slot]);
    }
    cs.preprocessed_pin_ood = true;
    const std::array<Fp3, 2> alpha{
        challenges.alpha1, challenges.alpha2};
    const std::array<Fp3, 2> gamma{
        challenges.gamma1, challenges.gamma2};
    const std::array<uint32_t, 2> c_inv_base{
        consumer_inv1_base, consumer_inv2_base};
    const std::array<uint32_t, 2> running{
        running1, running2};
    // Weight every rational term by its nonzero, preprocessed event id.
    // Besides preserving multiset equality (the same id weights both sides),
    // this makes id=0 the padding selector.  The first occurrence is both a
    // producer and consumer, so its consumer id and inverse also serve the
    // producer; fifteen redundant mask/producer-id/inverse columns stay off
    // the wire.
    if (columns != nullptr) {
        columns->resize(
            cs.n_columns,
            std::vector<Fp3>(cs.n_rows, Fp3::Zero()));
        for (uint32_t slot = 0;
             slot < SLOT_COUNT; ++slot) {
            (*columns)[producer_mult_base + slot] =
                p_mult[slot];
            (*columns)[consumer_id_base + slot] =
                c_id[slot];
        }
        std::array<Fp3, 2> sums{
            Fp3::Zero(), Fp3::Zero()};
        for (uint32_t row = 0; row < cs.n_rows; ++row) {
            for (uint32_t lane = 0; lane < 2; ++lane) {
                (*columns)[running[lane]][row] =
                    sums[lane];
                for (uint32_t slot = 0;
                     slot < SLOT_COUNT; ++slot) {
                    if (!gf::IsZero(c_id[slot][row])) {
                        const Fp3 denominator = gf::Sub(
                            alpha[lane],
                            gf::Add(
                                c_id[slot][row],
                                gf::Mul(
                                    gamma[lane],
                                    (*columns)[
                                        ha::ValueColumn(slot)]
                                                  [row])));
                        if (gf::IsZero(denominator)) {
                            return Fail(
                                why,
                                "witness_external_copy_pole");
                        }
                        const uint32_t inverse =
                            c_inv_base[lane] + slot;
                        (*columns)[inverse][row] =
                            gf::Inv(denominator);
                        const Fp3 weighted_inverse =
                            gf::Mul(
                                c_id[slot][row],
                                (*columns)[inverse][row]);
                        sums[lane] = gf::Add(
                            sums[lane],
                            gf::Mul(
                                p_mult[slot][row],
                                weighted_inverse));
                        sums[lane] = gf::Sub(
                            sums[lane], weighted_inverse);
                    } else if (!gf::IsZero(
                                   p_mult[slot][row])) {
                        return Fail(
                            why,
                            "witness_external_copy_producer");
                    }
                }
            }
        }
        if (!gf::IsZero(sums[0]) ||
            !gf::IsZero(sums[1])) {
            return Fail(
                why, "witness_external_copy_terminal");
        }
    }
    for (uint32_t lane = 0; lane < 2; ++lane) {
        const uint32_t cinv = c_inv_base[lane];
        const uint32_t run = running[lane];
        for (uint32_t slot = 0;
             slot < SLOT_COUNT; ++slot) {
            cs.constraints.push_back({
                "stage3.fixed_product_v2.external_consumer_inverse",
                air_quotient::AirKind::kEverywhere, 3,
                [consumer_id_base,
                 cinv, slot, lane, alpha, gamma](
                    const auto& cur, const auto&) {
                    const Fp3 denominator = gf::Sub(
                        alpha[lane],
                        gf::Add(
                            cur[consumer_id_base + slot],
                            gf::Mul(
                                gamma[lane],
                                cur[ha::ValueColumn(slot)])));
                    return gf::Mul(
                        cur[consumer_id_base + slot],
                        gf::Sub(
                            gf::Mul(
                                denominator,
                                cur[cinv + slot]),
                            Fp3::One()));
                }});
        }
        cs.constraints.push_back({
            "stage3.fixed_product_v2.external_running_first",
            air_quotient::AirKind::kFirstRow, 1,
            [run](const auto& cur, const auto&) {
                return cur[run];
            }});
        auto contribution =
            [producer_mult_base, consumer_id_base,
             cinv](
                const auto& cur) {
                Fp3 value = Fp3::Zero();
                for (uint32_t slot = 0;
                     slot < SLOT_COUNT; ++slot) {
                    const Fp3 weighted_inverse =
                        gf::Mul(
                            cur[consumer_id_base + slot],
                            cur[cinv + slot]);
                    value = gf::Add(
                        value,
                        gf::Mul(
                            cur[producer_mult_base + slot],
                            weighted_inverse));
                    value = gf::Sub(
                        value, weighted_inverse);
                }
                return value;
            };
        cs.constraints.push_back({
            "stage3.fixed_product_v2.external_running_transition",
            air_quotient::AirKind::kTransition, 3,
            [run, contribution](
                const auto& cur, const auto& next) {
                return gf::Sub(
                    next[run],
                    gf::Add(cur[run], contribution(cur)));
            }});
        cs.constraints.push_back({
            "stage3.fixed_product_v2.external_running_last",
            air_quotient::AirKind::kLastRow, 3,
            [run, contribution](
                const auto& cur, const auto&) {
                return gf::Add(
                    cur[run], contribution(cur));
            }});
    }
    return true;
}

bool AppendOutputProducerCtlV2(
    const ha::FixedProgram& program,
    const WitnessChunkShapeV2& shape,
    const RCStage3CtlChallenges& challenges,
    air_quotient::AirConstraintSystem<Fp3>& cs,
    const std::vector<uint32_t>& final_output_rows,
    std::vector<std::vector<Fp3>>* columns,
    const DualFp3ProducerTerminalV2* claimed_terminal,
    DualFp3ProducerTerminalV2& terminal,
    std::string* why)
{
    if (shape.source_count == 0 ||
        shape.family.size() != shape.source_count ||
        shape.family_boundary.size() != shape.source_count ||
        final_output_rows.size() !=
            shape.honest_boundaries.size() *
                program.final_addresses.size() ||
        (columns != nullptr &&
         (columns->size() != cs.n_columns ||
          (!columns->empty() &&
           columns->front().size() != cs.n_rows)))) {
        return Fail(why, "witness_output_ctl_shape");
    }
    constexpr uint32_t SLOT_COUNT = 4;
    const uint32_t selector_column = cs.n_columns++;
    const uint32_t id_column = cs.n_columns++;
    const uint32_t slot_mask_base = cs.n_columns;
    cs.n_columns += SLOT_COUNT;
    const uint32_t inverse1 = cs.n_columns++;
    const uint32_t inverse2 = cs.n_columns++;
    const uint32_t running1 = cs.n_columns++;
    const uint32_t running2 = cs.n_columns++;
    std::vector<Fp3> selector(cs.n_rows, Fp3::Zero());
    std::vector<Fp3> ids(cs.n_rows, Fp3::Zero());
    std::array<std::vector<Fp3>, SLOT_COUNT> masks;
    for (auto& mask : masks) {
        mask.assign(cs.n_rows, Fp3::Zero());
    }
    const uint32_t final_count =
        static_cast<uint32_t>(program.final_addresses.size());
    for (uint32_t source = 0;
         source < shape.source_count; ++source) {
        for (uint32_t word = 0; word < final_count; ++word) {
            const uint32_t row =
                final_output_rows[source * final_count + word];
            if (row >= cs.n_rows || !gf::IsZero(selector[row])) {
                return Fail(why, "witness_output_ctl_row");
            }
            const uint32_t phase = row % 1024U;
            if (phase >= program.rows.size()) {
                return Fail(why, "witness_output_ctl_phase");
            }
            const uint32_t slot = OutputSlot(program.rows[phase]);
            const uint64_t id = OutputEventIdV2(
                shape.family[source],
                shape.family_boundary[source], word);
            if (slot >= SLOT_COUNT || id >= gf::kP) {
                return Fail(why, "witness_output_ctl_event");
            }
            selector[row] = Fp3::One();
            ids[row] = U64(id);
            masks[slot][row] = Fp3::One();
        }
    }
    cs.preprocessed.emplace_back(
        selector_column, selector);
    cs.preprocessed.emplace_back(id_column, ids);
    for (uint32_t slot = 0; slot < SLOT_COUNT; ++slot) {
        cs.preprocessed.emplace_back(
            slot_mask_base + slot, masks[slot]);
    }
    cs.preprocessed_pin_ood = true;
    auto value_at =
        [slot_mask_base](const std::vector<Fp3>& row) {
            Fp3 value = Fp3::Zero();
            for (uint32_t slot = 0; slot < SLOT_COUNT; ++slot) {
                value = gf::Add(
                    value,
                    gf::Mul(
                        row[slot_mask_base + slot],
                        row[ha::ValueColumn(slot)]));
            }
            return value;
        };
    const std::array<Fp3, 2> alpha{
        challenges.alpha1, challenges.alpha2};
    const std::array<Fp3, 2> gamma{
        challenges.gamma1, challenges.gamma2};
    const std::array<uint32_t, 2> inverse{
        inverse1, inverse2};
    const std::array<uint32_t, 2> running{
        running1, running2};
    if (columns != nullptr) {
        columns->resize(
            cs.n_columns,
            std::vector<Fp3>(cs.n_rows, Fp3::Zero()));
        (*columns)[selector_column] = selector;
        (*columns)[id_column] = ids;
        for (uint32_t slot = 0;
             slot < SLOT_COUNT; ++slot) {
            (*columns)[slot_mask_base + slot] = masks[slot];
        }
        std::array<Fp3, 2> sums{
            Fp3::Zero(), Fp3::Zero()};
        for (uint32_t row = 0; row < cs.n_rows; ++row) {
            for (uint32_t lane = 0; lane < 2; ++lane) {
                (*columns)[running[lane]][row] = sums[lane];
                if (gf::IsZero(selector[row])) continue;
                Fp3 direct = Fp3::Zero();
                for (uint32_t slot = 0;
                     slot < SLOT_COUNT; ++slot) {
                    if (!gf::IsZero(masks[slot][row])) {
                        direct = gf::Add(
                            direct,
                            (*columns)[ha::ValueColumn(slot)][row]);
                    }
                }
                const Fp3 tuple = gf::Add(
                    ids[row], gf::Mul(gamma[lane], direct));
                const Fp3 denominator =
                    gf::Sub(alpha[lane], tuple);
                if (gf::IsZero(denominator)) {
                    return Fail(why, "witness_output_ctl_pole");
                }
                const Fp3 contribution = gf::Inv(denominator);
                (*columns)[inverse[lane]][row] = contribution;
                sums[lane] = gf::Add(sums[lane], contribution);
            }
        }
        terminal.lane1 = sums[0];
        terminal.lane2 = sums[1];
    } else {
        if (claimed_terminal == nullptr) {
            return Fail(why, "witness_output_ctl_terminal");
        }
        terminal = *claimed_terminal;
    }
    const std::array<Fp3, 2> terminal_values{
        terminal.lane1, terminal.lane2};
    for (uint32_t lane = 0; lane < 2; ++lane) {
        const uint32_t inv = inverse[lane];
        const uint32_t run = running[lane];
        cs.constraints.push_back({
            "stage3.fixed_product_v2.output_producer_inverse",
            air_quotient::AirKind::kEverywhere, 3,
            [selector_column, id_column, inv,
             lane, alpha, gamma, value_at](
                const auto& cur, const auto&) {
                const Fp3 tuple = gf::Add(
                    cur[id_column],
                    gf::Mul(gamma[lane], value_at(cur)));
                return gf::Sub(
                    gf::Mul(
                        gf::Sub(alpha[lane], tuple),
                        cur[inv]),
                    cur[selector_column]);
            }});
        cs.constraints.push_back({
            "stage3.fixed_product_v2.output_producer_padding",
            air_quotient::AirKind::kEverywhere, 2,
            [selector_column, inv](
                const auto& cur, const auto&) {
                return gf::Mul(
                    gf::Sub(
                        Fp3::One(), cur[selector_column]),
                    cur[inv]);
            }});
        cs.constraints.push_back({
            "stage3.fixed_product_v2.output_producer_first",
            air_quotient::AirKind::kFirstRow, 1,
            [run](const auto& cur, const auto&) {
                return cur[run];
            }});
        cs.constraints.push_back({
            "stage3.fixed_product_v2.output_producer_transition",
            air_quotient::AirKind::kTransition, 1,
            [run, inv](const auto& cur, const auto& next) {
                return gf::Sub(
                    next[run], gf::Add(cur[run], cur[inv]));
            }});
        cs.constraints.push_back({
            "stage3.fixed_product_v2.output_producer_last",
            air_quotient::AirKind::kLastRow, 1,
            [run, inv, lane, terminal_values](
                const auto& cur, const auto&) {
                return gf::Sub(
                    gf::Add(cur[run], cur[inv]),
                    terminal_values[lane]);
            }});
    }
    return true;
}

bool CheckPreprocessedWitnessV2(
    const air_quotient::AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns,
    std::string* why)
{
    for (const auto& [column, expected] : cs.preprocessed) {
        if (column >= columns.size() ||
            expected.size() != cs.n_rows ||
            columns[column].size() != cs.n_rows) {
            return Fail(
                why, "witness_preprocessed_shape:" +
                    std::to_string(column));
        }
        for (uint32_t row = 0; row < cs.n_rows; ++row) {
            if (!gf::Eq(expected[row], columns[column][row])) {
                return Fail(
                    why, "witness_preprocessed_value:" +
                        std::to_string(column) + ":" +
                        std::to_string(row));
            }
        }
    }
    return true;
}

bool CheckPreprocessedSystemsV2(
    const air_quotient::AirConstraintSystem<Fp3>& prover,
    const air_quotient::AirConstraintSystem<Fp3>& verifier,
    std::string* why)
{
    if (prover.n_rows != verifier.n_rows ||
        prover.n_columns != verifier.n_columns ||
        prover.preprocessed.size() !=
            verifier.preprocessed.size()) {
        return Fail(why, "witness_preprocessed_system_shape");
    }
    for (uint32_t i = 0;
         i < prover.preprocessed.size(); ++i) {
        const auto& left = prover.preprocessed[i];
        const auto& right = verifier.preprocessed[i];
        if (left.first != right.first ||
            left.second.size() != right.second.size()) {
            return Fail(
                why, "witness_preprocessed_system_column:" +
                    std::to_string(i));
        }
        for (uint32_t row = 0;
             row < left.second.size(); ++row) {
            if (!gf::Eq(
                    left.second[row],
                    right.second[row])) {
                return Fail(
                    why,
                    "witness_preprocessed_system_value:" +
                        std::to_string(left.first) + ":" +
                        std::to_string(row));
            }
        }
    }
    return true;
}

uint256 BoundarySeedV2(
    const uint256& fs_seed,
    const uint256& caller_statement,
    ha::ProgramKind kind,
    uint32_t child,
    uint32_t begin,
    uint32_t count)
{
    HashWriter hash;
    hash << std::string{
        "BTX_RC_STAGE3_FIXED_PRODUCT_WITNESS_BOUNDARY_V2"};
    hash << fs_seed;
    hash << caller_statement;
    hash << static_cast<uint8_t>(kind);
    hash << child;
    hash << begin;
    hash << count;
    return hash.GetHash();
}

uint256 CommitFragmentV2(const FamilyExportFragmentV2& fragment)
{
    HashWriter hash;
    hash << std::string{
        "BTX_RC_STAGE3_FIXED_PRODUCT_EXPORT_FRAGMENT_V2"};
    hash << fragment.child_ordinal;
    hash << fragment.family_ordinal;
    hash << fragment.family_boundary_begin;
    hash << fragment.source_instance_begin;
    hash << fragment.source_instance_count;
    hash << fragment.input_cell_count;
    hash << fragment.output_cell_count;
    hash << fragment.typed_input_cell_handle_root;
    hash << fragment.typed_output_producer_root;
    return hash.GetHash();
}

uint256 CommitChildStatementV2(
    const WitnessChildStatementV2& child)
{
    HashWriter hash;
    hash << std::string{
        "BTX_RC_STAGE3_FIXED_PRODUCT_WITNESS_CHILD_V2"};
    hash << static_cast<uint8_t>(child.program_kind);
    hash << child.child_ordinal;
    hash << child.global_source_begin;
    hash << child.source_instance_count;
    hash << child.sink_instance_count;
    hash << child.scheduled_instances;
    hash << child.output_event_count;
    hash << child.public_boundary_statement;
    hash << child.base_row_commitment;
    HashFp3(hash, child.output_producer_terminal.lane1);
    HashFp3(hash, child.output_producer_terminal.lane2);
    hash << child.typed_fragment_root;
    hash << static_cast<uint32_t>(child.fragments.size());
    for (const auto& fragment : child.fragments) {
        hash << CommitFragmentV2(fragment);
    }
    return hash.GetHash();
}

bool BuildFragmentsV2(
    const ProductManifestV1& caller_manifest,
    const ha::FixedProgram& program,
    const WitnessChunkShapeV2& shape,
    const std::vector<uint32_t>& final_output_rows,
    const uint256& public_statement,
    const uint256& r0_root,
    std::vector<FamilyExportFragmentV2>& out,
    std::string* why)
{
    out.clear();
    const uint32_t final_count =
        static_cast<uint32_t>(program.final_addresses.size());
    if (shape.source_count == 0 ||
        final_output_rows.size() !=
            shape.honest_boundaries.size() * final_count ||
        r0_root.IsNull() || public_statement.IsNull()) {
        return Fail(why, "witness_fragment_shape");
    }
    uint32_t source = 0;
    while (source < shape.source_count) {
        const uint32_t family = shape.family[source];
        if (family >= kFamilyCountV1) {
            return Fail(why, "witness_fragment_family");
        }
        uint32_t end = source + 1;
        while (end < shape.source_count &&
               shape.family[end] == family &&
               shape.family_boundary[end] ==
                   shape.family_boundary[end - 1] + 1U) {
            ++end;
        }
        FamilyExportFragmentV2 fragment;
        fragment.child_ordinal = shape.child_ordinal;
        fragment.family_ordinal = family;
        fragment.family_boundary_begin =
            shape.family_boundary[source];
        fragment.source_instance_begin = source;
        fragment.source_instance_count = end - source;
        HashWriter input_hash;
        input_hash << std::string{
            "BTX_RC_STAGE3_FIXED_PRODUCT_PRIVATE_INPUT_CELLS_V2"};
        input_hash << caller_manifest.families[family].typed_domain;
        input_hash << public_statement;
        input_hash << r0_root;
        input_hash << ha::CommitFixedProgram(program);
        input_hash << shape.child_ordinal;
        input_hash << family;
        input_hash << fragment.family_boundary_begin;
        input_hash << fragment.source_instance_count;
        HashWriter output_hash;
        output_hash << std::string{
            "BTX_RC_STAGE3_FIXED_PRODUCT_PRIVATE_OUTPUT_CELLS_V2"};
        output_hash << caller_manifest.families[family].typed_domain;
        output_hash << public_statement;
        output_hash << r0_root;
        output_hash << ha::CommitFixedProgram(program);
        output_hash << shape.child_ordinal;
        output_hash << family;
        output_hash << fragment.family_boundary_begin;
        output_hash << fragment.source_instance_count;
        for (uint32_t instance = source;
             instance < end; ++instance) {
            for (uint32_t phase = 0;
                 phase < program.rows.size(); ++phase) {
                const auto& row = program.rows[phase];
                for (uint32_t slot = 0;
                     slot < row.input_count; ++slot) {
                    const uint32_t address =
                        row.input_address[slot];
                    if (address == 0 ||
                        address >
                            program.external_address_count) {
                        continue;
                    }
                    const uint32_t trace_row =
                        instance * 1024U + phase;
                    input_hash << trace_row;
                    input_hash << ha::ValueColumn(slot);
                    input_hash << address;
                    ++fragment.input_cell_count;
                }
            }
            for (uint32_t word = 0;
                 word < final_count; ++word) {
                const uint32_t trace_row =
                    final_output_rows[
                        instance * final_count + word];
                const uint32_t phase = trace_row % 1024U;
                if (phase >= program.rows.size()) {
                    return Fail(why, "witness_fragment_output_row");
                }
                output_hash << trace_row;
                output_hash <<
                    ha::ValueColumn(
                        OutputSlot(program.rows[phase]));
                output_hash << OutputEventIdV2(
                    family, shape.family_boundary[instance], word);
                ++fragment.output_cell_count;
            }
        }
        fragment.typed_input_cell_handle_root =
            input_hash.GetHash();
        fragment.typed_output_producer_root =
            output_hash.GetHash();
        if (fragment.input_cell_count == 0 ||
            fragment.output_cell_count == 0 ||
            fragment.typed_input_cell_handle_root.IsNull() ||
            fragment.typed_output_producer_root.IsNull()) {
            return Fail(why, "witness_fragment_empty");
        }
        out.push_back(fragment);
        source = end;
    }
    return true;
}

uint256 CommitFragmentListV2(
    const std::vector<FamilyExportFragmentV2>& fragments)
{
    HashWriter hash;
    hash << std::string{
        "BTX_RC_STAGE3_FIXED_PRODUCT_FRAGMENT_LIST_V2"};
    hash << static_cast<uint32_t>(fragments.size());
    for (const auto& fragment : fragments) {
        hash << CommitFragmentV2(fragment);
    }
    return hash.GetHash();
}

uint256 AggregateFamilyFragmentsV2(
    uint32_t family,
    bool output,
    const std::vector<WitnessChildStatementV2>& children,
    uint32_t& count)
{
    HashWriter hash;
    hash << std::string{
        output
            ? "BTX_RC_STAGE3_FIXED_PRODUCT_FAMILY_OUTPUTS_V2"
            : "BTX_RC_STAGE3_FIXED_PRODUCT_FAMILY_INPUTS_V2"};
    hash << family;
    count = 0;
    for (const auto& child : children) {
        for (const auto& fragment : child.fragments) {
            if (fragment.family_ordinal != family) continue;
            hash << fragment.child_ordinal;
            hash << fragment.family_boundary_begin;
            hash << fragment.source_instance_count;
            hash << (output
                ? fragment.typed_output_producer_root
                : fragment.typed_input_cell_handle_root);
            ++count;
        }
    }
    return count == 0 ? uint256{} : hash.GetHash();
}

uint256 CommitWitnessManifestV2(
    const WitnessProductManifestV2& manifest)
{
    HashWriter hash;
    hash << std::string{
        "BTX_RC_STAGE3_FIXED_PRODUCT_WITNESS_MANIFEST_V2"};
    hash << manifest.version;
    hash << manifest.caller_input_statement_commitment;
    for (const auto& family : manifest.families) {
        hash << static_cast<uint8_t>(family.kind);
        hash << static_cast<uint8_t>(family.role);
        hash << static_cast<uint16_t>(family.endpoint);
        hash << static_cast<uint8_t>(family.program_kind);
        hash << family.family_ordinal;
        hash << family.boundary_count;
        hash << family.fragment_count;
        hash << family.caller_manifest_commitment;
        hash << family.typed_domain;
        hash << family.proof_owned_input_root;
        hash << family.proof_owned_output_producer_root;
    }
    hash << static_cast<uint32_t>(manifest.children.size());
    for (const auto& child : manifest.children) {
        hash << CommitChildStatementV2(child);
    }
    hash << manifest.exact_instance_schedule_root;
    hash << manifest.canonical_family_order;
    hash << manifest.private_boundary_inputs;
    hash << manifest.private_boundary_outputs;
    hash << manifest.proof_owned_input_exports;
    hash << manifest.proof_owned_output_exports;
    hash << manifest.dual_fp3_external_input_copy_ctl;
    hash << manifest.dual_fp3_output_producer_ctl;
    hash << manifest.auxiliary_sinks_equality_constrained;
    hash << manifest.private_chacha_internal_ssa_ctl;
    hash << manifest.caller_manifests_bound_to_role_proofs;
    hash << manifest.consumer_ctl_linked;
    hash << manifest.recursive_child_consumed;
    hash << manifest.semantic_closure;
    hash << manifest.production_authority;
    return hash.GetHash();
}

bool BuildWitnessManifestV2(
    const ProductManifestV1& caller_manifest,
    const std::vector<WitnessChildStatementV2>& children,
    WitnessProductManifestV2& out,
    std::string* why)
{
    out = {};
    out.caller_input_statement_commitment =
        caller_manifest.statement_commitment;
    out.children = children;
    uint32_t observed_boundaries = 0;
    for (uint32_t family_index = 0;
         family_index < kFamilyCountV1; ++family_index) {
        const auto& source =
            caller_manifest.families[family_index];
        auto& family = out.families[family_index];
        family.kind = source.kind;
        family.role = source.role;
        family.endpoint = source.endpoint;
        family.program_kind = source.program_kind;
        family.family_ordinal = family_index;
        family.boundary_count = source.boundary_count;
        family.caller_manifest_commitment =
            source.manifest_commitment;
        family.typed_domain = source.typed_domain;
        uint32_t input_fragments = 0;
        uint32_t output_fragments = 0;
        family.proof_owned_input_root =
            AggregateFamilyFragmentsV2(
                family_index, false, children,
                input_fragments);
        family.proof_owned_output_producer_root =
            AggregateFamilyFragmentsV2(
                family_index, true, children,
                output_fragments);
        family.fragment_count = input_fragments;
        if (input_fragments == 0 ||
            input_fragments != output_fragments ||
            family.proof_owned_input_root.IsNull() ||
            family.proof_owned_output_producer_root.IsNull()) {
            return Fail(why, "witness_family_fragments");
        }
        observed_boundaries += family.boundary_count;
    }
    HashWriter schedule;
    schedule << std::string{
        "BTX_RC_STAGE3_FIXED_PRODUCT_INSTANCE_SCHEDULE_V2"};
    schedule << observed_boundaries;
    schedule << static_cast<uint32_t>(children.size());
    for (const auto& child : children) {
        schedule << CommitChildStatementV2(child);
    }
    out.exact_instance_schedule_root = schedule.GetHash();
    out.canonical_family_order = true;
    out.private_boundary_inputs = true;
    out.private_boundary_outputs = true;
    out.proof_owned_input_exports = true;
    out.proof_owned_output_exports = true;
    out.dual_fp3_external_input_copy_ctl = true;
    out.dual_fp3_output_producer_ctl = true;
    out.auxiliary_sinks_equality_constrained = true;
    out.private_chacha_internal_ssa_ctl = true;
    out.caller_manifests_bound_to_role_proofs = false;
    out.consumer_ctl_linked = false;
    out.recursive_child_consumed = false;
    out.semantic_closure = false;
    out.production_authority = false;
    out.statement_commitment =
        CommitWitnessManifestV2(out);
    if (out.caller_input_statement_commitment.IsNull() ||
        out.exact_instance_schedule_root.IsNull() ||
        out.statement_commitment.IsNull()) {
        return Fail(why, "witness_manifest_root");
    }
    return true;
}

uint256 WitnessProofSeedV2(
    const uint256& fs_seed,
    const uint256& manifest_statement,
    const WitnessChildStatementV2& child)
{
    HashWriter hash;
    hash << std::string{
        "BTX_RC_STAGE3_FIXED_PRODUCT_SPLIT_RAP_V2"};
    hash << fs_seed;
    hash << manifest_statement;
    hash << CommitChildStatementV2(child);
    return hash.GetHash();
}

uint256 PrivateChaChaStatementV2(
    const ProductManifestV1& caller_manifest,
    const WitnessChunkShapeV2& shape)
{
    HashWriter hash;
    hash << std::string{
        "BTX_RC_STAGE3_FIXED_PRODUCT_PRIVATE_CHACHA_V2"};
    hash << caller_manifest.statement_commitment;
    hash << ha::CommitFixedProgram(
        ha::BuildCanonicalProgram(
            ha::ProgramKind::ChaCha20Block));
    hash << shape.child_ordinal;
    hash << shape.global_source_begin;
    hash << shape.source_count;
    for (uint32_t source = 0;
         source < shape.source_count; ++source) {
        hash << shape.family[source];
        hash << shape.family_boundary[source];
    }
    return hash.GetHash();
}

bool DerivePrivateChaChaChallengesV2(
    const uint256& fs_seed,
    const uint256& public_statement,
    const uint256& r0_root,
    RCStage3CtlChallenges& out,
    std::string* why)
{
    RCStage3CtlSchedule send;
    send.events.push_back({
        .namespace_id = 0x46584332U,
        .stage = 2,
        .address = 1,
        .multiplicity = 1,
    });
    RCStage3CtlSchedule receive = send;
    receive.events[0].multiplicity = -1;
    RCStage3CtlManifest manifest;
    manifest.bus_id = 0x46584332U;
    HashWriter transcript;
    transcript << std::string{
        "BTX_RC_STAGE3_FIXED_PRODUCT_PRIVATE_CHACHA_CTL_V2"};
    transcript << fs_seed;
    transcript << public_statement;
    transcript << r0_root;
    manifest.transcript_seed = transcript.GetHash();
    manifest.participants = {
        {
            .role = RCStage3RelationRole::CoupledExtract,
            .event_count = 1,
            .send_count = 1,
            .receive_count = 0,
            .schedule_commitment =
                CommitRCStage3CtlSchedule(send),
        },
        {
            .role = RCStage3RelationRole::CompositionLink,
            .event_count = 1,
            .send_count = 0,
            .receive_count = 1,
            .schedule_commitment =
                CommitRCStage3CtlSchedule(receive),
        },
    };
    std::vector<RCStage3CtlChildPin> pins(2);
    for (uint32_t i = 0; i < 2; ++i) {
        pins[i].role = manifest.participants[i].role;
        pins[i].bus_id = manifest.bus_id;
        pins[i].event_count =
            manifest.participants[i].event_count;
        pins[i].send_count =
            manifest.participants[i].send_count;
        pins[i].receive_count =
            manifest.participants[i].receive_count;
        pins[i].schedule_commitment =
            manifest.participants[i].schedule_commitment;
        pins[i].trace_commitment = r0_root;
    }
    return DeriveRCStage3CtlChallenges(
        manifest, pins, out, why);
}

bool BuildPrivateChaChaBaseV2(
    const ha::FixedProgram& program,
    const ha::FixedProgramBoundaryInstance* honest,
    air_quotient::AirConstraintSystem<Fp3>& cs,
    std::vector<std::vector<Fp3>>* columns,
    std::vector<uint32_t>& base_columns,
    std::vector<uint32_t>& final_output_rows,
    std::string* why)
{
    if (program.kind != ha::ProgramKind::ChaCha20Block ||
        !ha::BuildFixedProgramConstraintSystem(
            program, cs, why) ||
        cs.n_rows != 1024) {
        return Fail(why, "private_chacha_base_cs");
    }
    if (honest != nullptr) {
        ha::ProgramWitness witness;
        if (honest->external_values.size() !=
                program.external_address_count ||
            honest->final_words.size() !=
                program.final_addresses.size() ||
            !ha::BuildProgramWitness(
                program, honest->external_values,
                witness, why) ||
            witness.final_words != honest->final_words ||
            columns == nullptr ||
            !ha::BuildFixedProgramAirWitness(
                program, witness, *columns, why)) {
            return Fail(why, "private_chacha_base_witness");
        }
    }
    base_columns.resize(cs.n_columns);
    for (uint32_t column = 0;
         column < cs.n_columns; ++column) {
        base_columns[column] = column;
    }
    final_output_rows.assign(
        program.final_addresses.size(), 0);
    for (uint32_t phase = 0;
         phase < program.rows.size(); ++phase) {
        const auto found = std::find(
            program.final_addresses.begin(),
            program.final_addresses.end(),
            program.rows[phase].output_address);
        if (found != program.final_addresses.end()) {
            final_output_rows[
                static_cast<size_t>(
                    found -
                    program.final_addresses.begin())] =
                phase;
        }
    }
    cs.preprocessed_pin_ood = true;
    return true;
}

bool AppendPrivateChaChaInternalSsaCtlV2(
    const ha::FixedProgram& program,
    const RCStage3CtlChallenges& challenges,
    air_quotient::AirConstraintSystem<Fp3>& cs,
    std::vector<std::vector<Fp3>>* columns,
    std::string* why)
{
    constexpr uint32_t SLOT_COUNT = 4;
    constexpr uint64_t ID_BASE =
        UINT64_C(0x4353534100000000);
    const uint32_t max_address =
        program.rows.empty()
        ? program.external_address_count
        : program.rows.back().output_address;
    std::vector<uint32_t> use_count(max_address + 1, 0);
    for (const auto& row : program.rows) {
        for (uint32_t slot = 0;
             slot < row.input_count; ++slot) {
            const uint32_t address =
                row.input_address[slot];
            if (address >
                    program.external_address_count &&
                address < use_count.size()) {
                ++use_count[address];
            }
        }
    }
    const uint32_t producer_mask = cs.n_columns++;
    const uint32_t producer_id = cs.n_columns++;
    const uint32_t producer_mult = cs.n_columns++;
    const uint32_t producer_slot_base = cs.n_columns;
    cs.n_columns += SLOT_COUNT;
    const uint32_t consumer_mask_base = cs.n_columns;
    cs.n_columns += 3;
    const uint32_t consumer_id_base = cs.n_columns;
    cs.n_columns += 3;
    const uint32_t producer_inv1 = cs.n_columns++;
    const uint32_t producer_inv2 = cs.n_columns++;
    const uint32_t consumer_inv1_base = cs.n_columns;
    cs.n_columns += 3;
    const uint32_t consumer_inv2_base = cs.n_columns;
    cs.n_columns += 3;
    const uint32_t running1 = cs.n_columns++;
    const uint32_t running2 = cs.n_columns++;
    std::vector<Fp3> p_mask(cs.n_rows, Fp3::Zero());
    std::vector<Fp3> p_id(cs.n_rows, Fp3::Zero());
    std::vector<Fp3> p_mult(cs.n_rows, Fp3::Zero());
    std::array<std::vector<Fp3>, SLOT_COUNT> p_slots;
    std::array<std::vector<Fp3>, 3> c_masks;
    std::array<std::vector<Fp3>, 3> c_ids;
    for (auto& values : p_slots) {
        values.assign(cs.n_rows, Fp3::Zero());
    }
    for (auto& values : c_masks) {
        values.assign(cs.n_rows, Fp3::Zero());
    }
    for (auto& values : c_ids) {
        values.assign(cs.n_rows, Fp3::Zero());
    }
    for (uint32_t phase = 0;
         phase < program.rows.size(); ++phase) {
        const auto& row = program.rows[phase];
        if (row.output_address >
                program.external_address_count &&
            row.output_address < use_count.size() &&
            use_count[row.output_address] != 0) {
            const uint64_t id =
                ID_BASE + row.output_address;
            if (id >= gf::kP) {
                return Fail(why, "private_chacha_ssa_id");
            }
            p_mask[phase] = Fp3::One();
            p_id[phase] = U64(id);
            p_mult[phase] =
                U64(use_count[row.output_address]);
            p_slots[OutputSlot(row)][phase] =
                Fp3::One();
        }
        for (uint32_t slot = 0;
             slot < row.input_count; ++slot) {
            const uint32_t address =
                row.input_address[slot];
            if (address <=
                    program.external_address_count) {
                continue;
            }
            const uint64_t id = ID_BASE + address;
            if (slot >= c_masks.size() ||
                id >= gf::kP) {
                return Fail(
                    why, "private_chacha_ssa_consumer");
            }
            c_masks[slot][phase] = Fp3::One();
            c_ids[slot][phase] = U64(id);
        }
    }
    cs.preprocessed.emplace_back(producer_mask, p_mask);
    cs.preprocessed.emplace_back(producer_id, p_id);
    cs.preprocessed.emplace_back(producer_mult, p_mult);
    for (uint32_t slot = 0;
         slot < SLOT_COUNT; ++slot) {
        cs.preprocessed.emplace_back(
            producer_slot_base + slot, p_slots[slot]);
    }
    for (uint32_t slot = 0; slot < 3; ++slot) {
        cs.preprocessed.emplace_back(
            consumer_mask_base + slot, c_masks[slot]);
        cs.preprocessed.emplace_back(
            consumer_id_base + slot, c_ids[slot]);
    }
    const std::array<Fp3, 2> alpha{
        challenges.alpha1, challenges.alpha2};
    const std::array<Fp3, 2> gamma{
        challenges.gamma1, challenges.gamma2};
    const std::array<uint32_t, 2> p_inv{
        producer_inv1, producer_inv2};
    const std::array<uint32_t, 2> c_inv_base{
        consumer_inv1_base, consumer_inv2_base};
    const std::array<uint32_t, 2> running{
        running1, running2};
    auto producer_value =
        [producer_slot_base](const std::vector<Fp3>& row) {
            Fp3 value = Fp3::Zero();
            for (uint32_t slot = 0;
                 slot < SLOT_COUNT; ++slot) {
                value = gf::Add(
                    value,
                    gf::Mul(
                        row[producer_slot_base + slot],
                        row[ha::ValueColumn(slot)]));
            }
            return value;
        };
    if (columns != nullptr) {
        columns->resize(
            cs.n_columns,
            std::vector<Fp3>(cs.n_rows, Fp3::Zero()));
        (*columns)[producer_mask] = p_mask;
        (*columns)[producer_id] = p_id;
        (*columns)[producer_mult] = p_mult;
        for (uint32_t slot = 0;
             slot < SLOT_COUNT; ++slot) {
            (*columns)[producer_slot_base + slot] =
                p_slots[slot];
        }
        for (uint32_t slot = 0; slot < 3; ++slot) {
            (*columns)[consumer_mask_base + slot] =
                c_masks[slot];
            (*columns)[consumer_id_base + slot] =
                c_ids[slot];
        }
        std::array<Fp3, 2> sums{
            Fp3::Zero(), Fp3::Zero()};
        for (uint32_t row = 0; row < cs.n_rows; ++row) {
            for (uint32_t lane = 0; lane < 2; ++lane) {
                (*columns)[running[lane]][row] = sums[lane];
                if (!gf::IsZero(p_mask[row])) {
                    Fp3 value = Fp3::Zero();
                    for (uint32_t slot = 0;
                         slot < SLOT_COUNT; ++slot) {
                        if (!gf::IsZero(p_slots[slot][row])) {
                            value = gf::Add(
                                value,
                                (*columns)[
                                    ha::ValueColumn(slot)][row]);
                        }
                    }
                    const Fp3 denominator = gf::Sub(
                        alpha[lane],
                        gf::Add(
                            p_id[row],
                            gf::Mul(gamma[lane], value)));
                    if (gf::IsZero(denominator)) {
                        return Fail(
                            why, "private_chacha_ssa_pole");
                    }
                    (*columns)[p_inv[lane]][row] =
                        gf::Inv(denominator);
                    sums[lane] = gf::Add(
                        sums[lane],
                        gf::Mul(
                            p_mult[row],
                            (*columns)[p_inv[lane]][row]));
                }
                for (uint32_t slot = 0;
                     slot < 3; ++slot) {
                    if (gf::IsZero(c_masks[slot][row])) {
                        continue;
                    }
                    const Fp3 denominator = gf::Sub(
                        alpha[lane],
                        gf::Add(
                            c_ids[slot][row],
                            gf::Mul(
                                gamma[lane],
                                (*columns)[
                                    ha::ValueColumn(slot)][row])));
                    if (gf::IsZero(denominator)) {
                        return Fail(
                            why, "private_chacha_ssa_pole");
                    }
                    const uint32_t inverse =
                        c_inv_base[lane] + slot;
                    (*columns)[inverse][row] =
                        gf::Inv(denominator);
                    sums[lane] = gf::Sub(
                        sums[lane],
                        (*columns)[inverse][row]);
                }
            }
        }
        if (!gf::IsZero(sums[0]) ||
            !gf::IsZero(sums[1])) {
            return Fail(why, "private_chacha_ssa_terminal");
        }
    }
    for (uint32_t lane = 0; lane < 2; ++lane) {
        const uint32_t pinv = p_inv[lane];
        const uint32_t cinv = c_inv_base[lane];
        const uint32_t run = running[lane];
        cs.constraints.push_back({
            "stage3.fixed_product_v2.chacha_ssa_producer_inverse",
            air_quotient::AirKind::kEverywhere, 3,
            [producer_mask, producer_id, pinv, lane,
             alpha, gamma, producer_value](
                const auto& cur, const auto&) {
                const Fp3 denominator = gf::Sub(
                    alpha[lane],
                    gf::Add(
                        cur[producer_id],
                        gf::Mul(
                            gamma[lane],
                            producer_value(cur))));
                return gf::Sub(
                    gf::Mul(denominator, cur[pinv]),
                    cur[producer_mask]);
            }});
        cs.constraints.push_back({
            "stage3.fixed_product_v2.chacha_ssa_producer_padding",
            air_quotient::AirKind::kEverywhere, 2,
            [producer_mask, pinv](
                const auto& cur, const auto&) {
                return gf::Mul(
                    gf::Sub(
                        Fp3::One(), cur[producer_mask]),
                    cur[pinv]);
            }});
        for (uint32_t slot = 0; slot < 3; ++slot) {
            cs.constraints.push_back({
                "stage3.fixed_product_v2.chacha_ssa_consumer_inverse",
                air_quotient::AirKind::kEverywhere, 2,
                [consumer_mask_base, consumer_id_base,
                 cinv, slot, lane, alpha, gamma](
                    const auto& cur, const auto&) {
                    const Fp3 denominator = gf::Sub(
                        alpha[lane],
                        gf::Add(
                            cur[consumer_id_base + slot],
                            gf::Mul(
                                gamma[lane],
                                cur[ha::ValueColumn(slot)])));
                    return gf::Sub(
                        gf::Mul(
                            denominator,
                            cur[cinv + slot]),
                        cur[consumer_mask_base + slot]);
                }});
            cs.constraints.push_back({
                "stage3.fixed_product_v2.chacha_ssa_consumer_padding",
                air_quotient::AirKind::kEverywhere, 2,
                [consumer_mask_base, cinv, slot](
                    const auto& cur, const auto&) {
                    return gf::Mul(
                        gf::Sub(
                            Fp3::One(),
                            cur[consumer_mask_base + slot]),
                        cur[cinv + slot]);
                }});
        }
        cs.constraints.push_back({
            "stage3.fixed_product_v2.chacha_ssa_first",
            air_quotient::AirKind::kFirstRow, 1,
            [run](const auto& cur, const auto&) {
                return cur[run];
            }});
        cs.constraints.push_back({
            "stage3.fixed_product_v2.chacha_ssa_transition",
            air_quotient::AirKind::kTransition, 2,
            [run, pinv, cinv, producer_mult](
                const auto& cur, const auto& next) {
                Fp3 contribution = gf::Mul(
                    cur[producer_mult], cur[pinv]);
                for (uint32_t slot = 0;
                     slot < 3; ++slot) {
                    contribution = gf::Sub(
                        contribution, cur[cinv + slot]);
                }
                return gf::Sub(
                    next[run],
                    gf::Add(cur[run], contribution));
            }});
        cs.constraints.push_back({
            "stage3.fixed_product_v2.chacha_ssa_last",
            air_quotient::AirKind::kLastRow, 2,
            [run, pinv, cinv, producer_mult](
                const auto& cur, const auto&) {
                Fp3 contribution = gf::Mul(
                    cur[producer_mult], cur[pinv]);
                for (uint32_t slot = 0;
                     slot < 3; ++slot) {
                    contribution = gf::Sub(
                        contribution, cur[cinv + slot]);
                }
                return gf::Add(cur[run], contribution);
            }});
    }
    return true;
}

struct PreparedWitnessChildV2 {
    WitnessChunkShapeV2 shape;
    air_quotient::AirConstraintSystem<Fp3> cs;
    std::vector<std::vector<Fp3>> columns;
    std::vector<uint32_t> base_columns;
    air_quotient::AirQuotientTwoEpochBaseRowSession r0;
    WitnessChildStatementV2 statement;
};

bool PrepareWitnessBatchV2(
    const std::vector<ha::FixedProgramBoundaryInstance>& batch,
    const BatchMapV2& map,
    const ProductManifestV1& caller_manifest,
    ha::ProgramKind kind,
    const uint256& fs_seed,
    uint32_t& child_ordinal,
    std::vector<PreparedWitnessChildV2>& out,
    std::string* why)
{
    const auto program = ha::BuildCanonicalProgram(kind);
    if (kind != ha::ProgramKind::Sha256Compression) {
        return Fail(why, "witness_batch_requires_sha");
    }
    for (uint32_t begin = 0; begin < batch.size();
         begin += kMaxWitnessSourcesPerChildV2) {
        const uint32_t count = std::min<uint32_t>(
            kMaxWitnessSourcesPerChildV2,
            static_cast<uint32_t>(batch.size()) - begin);
        PreparedWitnessChildV2 prepared;
        if (!BuildWitnessChunkShapeV2(
                batch, map, kind, child_ordinal,
                begin, count, true, prepared.shape, why)) {
            return false;
        }
        const uint256 boundary_seed = BoundarySeedV2(
            fs_seed, caller_manifest.statement_commitment,
            kind, child_ordinal, begin, count);
        auto instance =
            ha::BuildFixedProgramVerticalWitnessBoundaryInstance(
                program, prepared.shape.honest_boundaries,
                prepared.shape.public_masks,
                prepared.shape.links, boundary_seed);
        if (!instance.valid ||
            instance.base_row_commitment.IsNull() ||
            !instance.base_row_tree_cache) {
            return Fail(
                why, "witness_instance:" +
                    instance.note);
        }
        DualFp3ProducerTerminalV2 terminal;
        if (!AppendExternalInputCopyCtlV2(
                program, prepared.shape,
                instance.challenges,
                instance.cs, &instance.columns, why) ||
            !AppendOutputProducerCtlV2(
                program, prepared.shape,
                instance.challenges,
                instance.cs,
                instance.final_output_rows,
                &instance.columns, nullptr,
                terminal, why)) {
            return false;
        }
        if (!CheckPreprocessedWitnessV2(
                instance.cs, instance.columns, why)) {
            return false;
        }
        auto verifier_audit =
            ha::BuildFixedProgramVerticalWitnessBoundaryVerifierInstance(
                program, prepared.shape.public_templates,
                prepared.shape.public_masks,
                prepared.shape.links, boundary_seed,
                instance.base_row_commitment);
        DualFp3ProducerTerminalV2 audit_terminal;
        if (!verifier_audit.valid) {
            return Fail(
                why, "witness_verifier_audit:" +
                    verifier_audit.note);
        }
        if (!AppendExternalInputCopyCtlV2(
                program, prepared.shape,
                verifier_audit.challenges,
                verifier_audit.cs, nullptr, why) ||
            !AppendOutputProducerCtlV2(
                program, prepared.shape,
                verifier_audit.challenges,
                verifier_audit.cs,
                verifier_audit.final_output_rows,
                nullptr, &terminal, audit_terminal, why) ||
            !(audit_terminal == terminal)) {
            return Fail(why, "witness_verifier_audit_terminal");
        }
        if (!CheckPreprocessedSystemsV2(
                instance.cs, verifier_audit.cs, why)) {
            return false;
        }
        prepared.r0 =
            air_quotient::AirQuotientBuildTwoEpochBaseRowSession(
                instance.cs,
                instance.columns,
                instance.base_column_indices);
        if (!prepared.r0.valid ||
            prepared.r0.base_row_commitment !=
                instance.base_row_commitment) {
            return Fail(
                why, "witness_r0_reuse:" +
                    prepared.r0.note);
        }
        auto& statement = prepared.statement;
        statement.program_kind = kind;
        statement.child_ordinal = child_ordinal;
        statement.global_source_begin = begin;
        statement.source_instance_count = count;
        statement.sink_instance_count =
            prepared.shape.sink_count;
        statement.scheduled_instances =
            instance.scheduled_instances;
        statement.output_event_count =
            count * program.final_addresses.size();
        statement.public_boundary_statement =
            instance.public_statement;
        statement.base_row_commitment =
            instance.base_row_commitment;
        statement.output_producer_terminal = terminal;
        if (!BuildFragmentsV2(
                caller_manifest, program, prepared.shape,
                instance.final_output_rows,
                statement.public_boundary_statement,
                statement.base_row_commitment,
                statement.fragments, why)) {
            return false;
        }
        statement.typed_fragment_root =
            CommitFragmentListV2(statement.fragments);
        if (statement.typed_fragment_root.IsNull()) {
            return Fail(why, "witness_fragment_root");
        }
        prepared.cs = std::move(instance.cs);
        prepared.columns = std::move(instance.columns);
        prepared.base_columns =
            std::move(instance.base_column_indices);
        out.push_back(std::move(prepared));
        ++child_ordinal;
    }
    return true;
}

bool PreparePrivateChaChaBatchV2(
    const std::vector<ha::FixedProgramBoundaryInstance>& batch,
    const BatchMapV2& map,
    const ProductManifestV1& caller_manifest,
    const uint256& fs_seed,
    uint32_t& child_ordinal,
    std::vector<PreparedWitnessChildV2>& out,
    std::string* why)
{
    const auto program = ha::BuildCanonicalProgram(
        ha::ProgramKind::ChaCha20Block);
    for (uint32_t begin = 0; begin < batch.size(); ++begin) {
        PreparedWitnessChildV2 prepared;
        auto& shape = prepared.shape;
        shape.child_ordinal = child_ordinal;
        shape.global_source_begin = begin;
        shape.source_count = 1;
        shape.sink_count = 0;
        shape.honest_boundaries = {batch[begin]};
        shape.public_templates.resize(1);
        shape.public_templates[0].external_values.assign(
            program.external_address_count, 0);
        shape.public_templates[0].final_words.assign(
            program.final_addresses.size(), 0);
        shape.public_masks.assign(
            1, std::vector<uint8_t>(
                   program.external_address_count, 0));
        shape.family = {map.family[begin]};
        shape.family_boundary = {
            map.family_boundary[begin]};
        std::vector<uint32_t> final_rows;
        if (!BuildPrivateChaChaBaseV2(
                program, &batch[begin], prepared.cs,
                &prepared.columns, prepared.base_columns,
                final_rows, why)) {
            return false;
        }
        const uint256 public_statement =
            PrivateChaChaStatementV2(
                caller_manifest, shape);
        auto initial_r0 =
            air_quotient::AirQuotientBuildTwoEpochBaseRowSession(
                prepared.cs, prepared.columns,
                prepared.base_columns);
        if (!initial_r0.valid ||
            initial_r0.base_row_commitment.IsNull() ||
            public_statement.IsNull()) {
            return Fail(
                why, "private_chacha_initial_r0:" +
                    initial_r0.note);
        }
        prepared.cs.preprocessed_row_group_roots.push_back({
            .version = 1,
            .role =
                air_quotient::
                    AirPreprocessedRowGroupRole::kR0,
            .ordered_columns = prepared.base_columns,
            .root = initial_r0.base_row_commitment,
        });
        RCStage3CtlChallenges challenges;
        if (!DerivePrivateChaChaChallengesV2(
                fs_seed, public_statement,
                initial_r0.base_row_commitment,
                challenges, why) ||
            !AppendExternalInputCopyCtlV2(
                program, shape, challenges, prepared.cs,
                &prepared.columns, why) ||
            !AppendPrivateChaChaInternalSsaCtlV2(
                program, challenges, prepared.cs,
                &prepared.columns, why)) {
            return false;
        }
        DualFp3ProducerTerminalV2 terminal;
        if (!AppendOutputProducerCtlV2(
                program, shape, challenges, prepared.cs,
                final_rows, &prepared.columns, nullptr,
                terminal, why)) {
            return false;
        }
        if (!CheckPreprocessedWitnessV2(
                prepared.cs, prepared.columns, why)) {
            return false;
        }
        prepared.r0 =
            air_quotient::AirQuotientBuildTwoEpochBaseRowSession(
                prepared.cs, prepared.columns,
                prepared.base_columns);
        if (!prepared.r0.valid ||
            prepared.r0.base_row_commitment !=
                initial_r0.base_row_commitment) {
            return Fail(
                why, "private_chacha_r0_reuse:" +
                    prepared.r0.note);
        }
        auto& statement = prepared.statement;
        statement.program_kind =
            ha::ProgramKind::ChaCha20Block;
        statement.child_ordinal = child_ordinal;
        statement.global_source_begin = begin;
        statement.source_instance_count = 1;
        statement.sink_instance_count = 0;
        statement.scheduled_instances = 1;
        statement.output_event_count =
            program.final_addresses.size();
        statement.public_boundary_statement =
            public_statement;
        statement.base_row_commitment =
            prepared.r0.base_row_commitment;
        statement.output_producer_terminal = terminal;
        if (!BuildFragmentsV2(
                caller_manifest, program, shape,
                final_rows,
                statement.public_boundary_statement,
                statement.base_row_commitment,
                statement.fragments, why)) {
            return false;
        }
        statement.typed_fragment_root =
            CommitFragmentListV2(statement.fragments);
        if (statement.typed_fragment_root.IsNull()) {
            return Fail(
                why, "private_chacha_fragment_root");
        }
        out.push_back(std::move(prepared));
        ++child_ordinal;
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

bool ProveWitnessProductV2(
    const FamilyInputsV1& inputs,
    const uint256& fs_seed,
    WitnessProductProofV2& out,
    std::string* why)
{
    out = {};
    if (fs_seed.IsNull()) {
        return Fail(why, "witness_null_fs_seed");
    }
    ProductManifestV1 caller_manifest;
    std::vector<ha::FixedProgramBoundaryInstance> sha;
    std::vector<ha::FixedProgramBoundaryInstance> chacha;
    if (!Derive(
            inputs, caller_manifest, sha, chacha, why)) {
        return false;
    }
    BatchMapV2 sha_map;
    BatchMapV2 chacha_map;
    if (!BuildBatchMapV2(
            caller_manifest,
            ha::ProgramKind::Sha256Compression,
            static_cast<uint32_t>(sha.size()),
            sha_map, why) ||
        !BuildBatchMapV2(
            caller_manifest,
            ha::ProgramKind::ChaCha20Block,
            static_cast<uint32_t>(chacha.size()),
            chacha_map, why)) {
        return false;
    }
    std::vector<PreparedWitnessChildV2> prepared;
    uint32_t child_ordinal = 0;
    if (!PrepareWitnessBatchV2(
            sha, sha_map, caller_manifest,
            ha::ProgramKind::Sha256Compression,
            fs_seed, child_ordinal, prepared, why) ||
        !PreparePrivateChaChaBatchV2(
            chacha, chacha_map, caller_manifest,
            fs_seed, child_ordinal, prepared, why)) {
        return false;
    }
    std::vector<WitnessChildStatementV2> statements;
    statements.reserve(prepared.size());
    for (const auto& child : prepared) {
        statements.push_back(child.statement);
    }
    if (!BuildWitnessManifestV2(
            caller_manifest, statements,
            out.manifest, why)) {
        return false;
    }
    out.children.resize(prepared.size());
    for (uint32_t child = 0;
         child < prepared.size(); ++child) {
        const uint256 seed = WitnessProofSeedV2(
            fs_seed, out.manifest.statement_commitment,
            prepared[child].statement);
        const auto proved =
            air_quotient::AirQuotientProveRowsSplitRap(
                prepared[child].cs,
                prepared[child].columns,
                prepared[child].base_columns,
                seed, {}, &prepared[child].r0);
        if (!proved.ok || !proved.division_exact ||
            proved.proof.batch.groups.size() != 3 ||
            Fri3AlgDigestToUint256(
                proved.proof.batch.groups[0]
                    .row_commit.root) !=
                prepared[child].statement
                    .base_row_commitment) {
            return Fail(
                why, "witness_prove_child:" +
                    std::to_string(child) + ":" +
                    proved.note);
        }
        out.children[child].statement =
            prepared[child].statement;
        out.children[child].quotient = proved.proof;
    }
    out.valid = true;
    out.note =
        "stage3:fixed_program_semantic_product:"
        "private_boundary_copy_and_output_producer_ctl_proved;"
        "role_consumers_and_recursion_open";
    return true;
}

bool VerifyWitnessProductV2(
    const FamilyInputsV1& inputs,
    const uint256& fs_seed,
    const WitnessProductProofV2& proof,
    std::string* why)
{
    if (fs_seed.IsNull() ||
        proof.version != kWitnessVersionV2 ||
        !proof.valid || proof.children.empty()) {
        return Fail(why, "witness_proof_shape");
    }
    ProductManifestV1 caller_manifest;
    std::vector<ha::FixedProgramBoundaryInstance> sha;
    std::vector<ha::FixedProgramBoundaryInstance> chacha;
    if (!Derive(
            inputs, caller_manifest, sha, chacha, why)) {
        return false;
    }
    BatchMapV2 sha_map;
    BatchMapV2 chacha_map;
    if (!BuildBatchMapV2(
            caller_manifest,
            ha::ProgramKind::Sha256Compression,
            static_cast<uint32_t>(sha.size()),
            sha_map, why) ||
        !BuildBatchMapV2(
            caller_manifest,
            ha::ProgramKind::ChaCha20Block,
            static_cast<uint32_t>(chacha.size()),
            chacha_map, why)) {
        return false;
    }
    struct VerifierChild {
        air_quotient::AirConstraintSystem<Fp3> cs;
        std::vector<uint32_t> base_columns;
        WitnessChildStatementV2 statement;
    };
    std::vector<VerifierChild> verified_shapes;
    std::vector<WitnessChildStatementV2> statements;
    uint32_t child_ordinal = 0;
    auto prepare_batch =
        [&](const std::vector<
                ha::FixedProgramBoundaryInstance>& batch,
            const BatchMapV2& map,
            ha::ProgramKind kind) {
            if (kind !=
                ha::ProgramKind::Sha256Compression) {
                return Fail(
                    why, "witness_verifier_batch_requires_sha");
            }
            const auto program = ha::BuildCanonicalProgram(kind);
            for (uint32_t begin = 0; begin < batch.size();
                 begin += kMaxWitnessSourcesPerChildV2) {
                if (child_ordinal >= proof.children.size()) {
                    return Fail(why, "witness_child_omitted");
                }
                const uint32_t count = std::min<uint32_t>(
                    kMaxWitnessSourcesPerChildV2,
                    static_cast<uint32_t>(batch.size()) - begin);
                WitnessChunkShapeV2 shape;
                if (!BuildWitnessChunkShapeV2(
                        batch, map, kind, child_ordinal,
                        begin, count, false, shape, why)) {
                    return false;
                }
                const auto& supplied =
                    proof.children[child_ordinal];
                if (supplied.statement.program_kind != kind ||
                    supplied.statement.child_ordinal !=
                        child_ordinal ||
                    supplied.statement.global_source_begin !=
                        begin ||
                    supplied.statement.source_instance_count !=
                        count ||
                    supplied.statement.base_row_commitment
                        .IsNull()) {
                    return Fail(
                        why, "witness_child_static_shape");
                }
                const uint256 boundary_seed = BoundarySeedV2(
                    fs_seed,
                    caller_manifest.statement_commitment,
                    kind, child_ordinal, begin, count);
                auto instance =
                    ha::BuildFixedProgramVerticalWitnessBoundaryVerifierInstance(
                        program, shape.public_templates,
                        shape.public_masks, shape.links,
                        boundary_seed,
                        supplied.statement
                            .base_row_commitment);
                if (!instance.valid ||
                    instance.base_row_commitment !=
                        supplied.statement
                            .base_row_commitment) {
                    return Fail(
                        why, "witness_verifier_instance:" +
                            instance.note);
                }
                DualFp3ProducerTerminalV2 terminal;
                if (!AppendExternalInputCopyCtlV2(
                        program, shape, instance.challenges,
                        instance.cs, nullptr, why) ||
                    !AppendOutputProducerCtlV2(
                        program, shape, instance.challenges,
                        instance.cs,
                        instance.final_output_rows, nullptr,
                        &supplied.statement
                             .output_producer_terminal,
                        terminal, why)) {
                    return false;
                }
                WitnessChildStatementV2 expected;
                expected.program_kind = kind;
                expected.child_ordinal = child_ordinal;
                expected.global_source_begin = begin;
                expected.source_instance_count = count;
                expected.sink_instance_count =
                    shape.sink_count;
                expected.scheduled_instances =
                    instance.scheduled_instances;
                expected.output_event_count =
                    count *
                    static_cast<uint32_t>(
                        program.final_addresses.size());
                expected.public_boundary_statement =
                    instance.public_statement;
                expected.base_row_commitment =
                    instance.base_row_commitment;
                expected.output_producer_terminal = terminal;
                if (!BuildFragmentsV2(
                        caller_manifest, program, shape,
                        instance.final_output_rows,
                        expected.public_boundary_statement,
                        expected.base_row_commitment,
                        expected.fragments, why)) {
                    return false;
                }
                expected.typed_fragment_root =
                    CommitFragmentListV2(
                        expected.fragments);
                if (!(supplied.statement == expected)) {
                    return Fail(
                        why, "witness_child_statement");
                }
                VerifierChild verified;
                verified.cs = std::move(instance.cs);
                verified.base_columns =
                    std::move(instance.base_column_indices);
                verified.statement = expected;
                verified_shapes.push_back(
                    std::move(verified));
                statements.push_back(std::move(expected));
                ++child_ordinal;
            }
            return true;
        };
    auto prepare_chacha = [&]() {
        const auto program = ha::BuildCanonicalProgram(
            ha::ProgramKind::ChaCha20Block);
        for (uint32_t begin = 0;
             begin < chacha.size(); ++begin) {
            if (child_ordinal >= proof.children.size()) {
                return Fail(
                    why, "private_chacha_child_omitted");
            }
            WitnessChunkShapeV2 shape;
            shape.child_ordinal = child_ordinal;
            shape.global_source_begin = begin;
            shape.source_count = 1;
            shape.sink_count = 0;
            shape.honest_boundaries.resize(1);
            shape.honest_boundaries[0]
                .external_values.assign(
                    program.external_address_count, 0);
            shape.honest_boundaries[0]
                .final_words.assign(
                    program.final_addresses.size(), 0);
            shape.family = {chacha_map.family[begin]};
            shape.family_boundary = {
                chacha_map.family_boundary[begin]};
            const auto& supplied =
                proof.children[child_ordinal];
            if (supplied.statement.program_kind !=
                    ha::ProgramKind::ChaCha20Block ||
                supplied.statement.child_ordinal !=
                    child_ordinal ||
                supplied.statement.global_source_begin !=
                    begin ||
                supplied.statement.source_instance_count != 1 ||
                supplied.statement.sink_instance_count != 0 ||
                supplied.statement.scheduled_instances != 1 ||
                supplied.statement.base_row_commitment.IsNull()) {
                return Fail(
                    why, "private_chacha_child_static_shape");
            }
            air_quotient::AirConstraintSystem<Fp3> cs;
            std::vector<uint32_t> base_columns;
            std::vector<uint32_t> final_rows;
            if (!BuildPrivateChaChaBaseV2(
                    program, nullptr, cs, nullptr,
                    base_columns, final_rows, why)) {
                return false;
            }
            const uint256 public_statement =
                PrivateChaChaStatementV2(
                    caller_manifest, shape);
            cs.preprocessed_row_group_roots.push_back({
                .version = 1,
                .role =
                    air_quotient::
                        AirPreprocessedRowGroupRole::kR0,
                .ordered_columns = base_columns,
                .root = supplied.statement
                    .base_row_commitment,
            });
            RCStage3CtlChallenges challenges;
            if (!DerivePrivateChaChaChallengesV2(
                    fs_seed, public_statement,
                    supplied.statement
                        .base_row_commitment,
                    challenges, why) ||
                !AppendExternalInputCopyCtlV2(
                    program, shape, challenges, cs,
                    nullptr, why) ||
                !AppendPrivateChaChaInternalSsaCtlV2(
                    program, challenges, cs, nullptr,
                    why)) {
                return false;
            }
            DualFp3ProducerTerminalV2 terminal;
            if (!AppendOutputProducerCtlV2(
                    program, shape, challenges, cs,
                    final_rows, nullptr,
                    &supplied.statement
                         .output_producer_terminal,
                    terminal, why)) {
                return false;
            }
            WitnessChildStatementV2 expected;
            expected.program_kind =
                ha::ProgramKind::ChaCha20Block;
            expected.child_ordinal = child_ordinal;
            expected.global_source_begin = begin;
            expected.source_instance_count = 1;
            expected.sink_instance_count = 0;
            expected.scheduled_instances = 1;
            expected.output_event_count =
                program.final_addresses.size();
            expected.public_boundary_statement =
                public_statement;
            expected.base_row_commitment =
                supplied.statement.base_row_commitment;
            expected.output_producer_terminal = terminal;
            if (!BuildFragmentsV2(
                    caller_manifest, program, shape,
                    final_rows,
                    expected.public_boundary_statement,
                    expected.base_row_commitment,
                    expected.fragments, why)) {
                return false;
            }
            expected.typed_fragment_root =
                CommitFragmentListV2(
                    expected.fragments);
            if (!(supplied.statement == expected)) {
                return Fail(
                    why, "private_chacha_child_statement");
            }
            VerifierChild verified;
            verified.cs = std::move(cs);
            verified.base_columns =
                std::move(base_columns);
            verified.statement = expected;
            verified_shapes.push_back(
                std::move(verified));
            statements.push_back(std::move(expected));
            ++child_ordinal;
        }
        return true;
    };
    if (!prepare_batch(
            sha, sha_map,
            ha::ProgramKind::Sha256Compression) ||
        !prepare_chacha() ||
        child_ordinal != proof.children.size()) {
        return Fail(why, "witness_child_count");
    }
    WitnessProductManifestV2 expected_manifest;
    if (!BuildWitnessManifestV2(
            caller_manifest, statements,
            expected_manifest, why) ||
        !(proof.manifest == expected_manifest) ||
        proof.manifest.caller_manifests_bound_to_role_proofs ||
        proof.manifest.consumer_ctl_linked ||
        proof.manifest.recursive_child_consumed ||
        proof.manifest.semantic_closure ||
        proof.manifest.production_authority) {
        return Fail(why, "witness_canonical_manifest");
    }
    for (uint32_t child = 0;
         child < proof.children.size(); ++child) {
        const auto& supplied = proof.children[child];
        if (!(supplied.statement ==
              expected_manifest.children[child]) ||
            supplied.quotient.base_column_indices !=
                verified_shapes[child].base_columns ||
            supplied.quotient.batch.groups.size() != 3 ||
            Fri3AlgDigestToUint256(
                supplied.quotient.batch.groups[0]
                    .row_commit.root) !=
                supplied.statement.base_row_commitment) {
            return Fail(why, "witness_quotient_shape");
        }
        const uint256 seed = WitnessProofSeedV2(
            fs_seed,
            expected_manifest.statement_commitment,
            verified_shapes[child].statement);
        std::string child_why;
        if (!air_quotient::AirQuotientVerifyRowsSplitRap(
                verified_shapes[child].cs,
                supplied.quotient,
                verified_shapes[child].base_columns,
                seed, &child_why)) {
            return Fail(
                why, "witness_verify_child:" +
                    std::to_string(child) + ":" +
                    child_why);
        }
    }
    if (why != nullptr) {
        *why =
            "stage3:fixed_program_semantic_product:"
            "private_boundaries_and_output_producer_ctl_verified;"
            "role_consumers_and_recursion_open";
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
