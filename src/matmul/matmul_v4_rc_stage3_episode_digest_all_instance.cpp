// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_episode_digest_all_instance.h>

#include <hash.h>
#include <matmul/matmul_v4_rc_stage3_coupled_signed_range_stream.h>
#include <matmul/matmul_v4_rc_stage3_air_quotient_codec.h>
#include <matmul/matmul_v4_rc_stage3_hash_semantic.h>

#include <algorithm>
#include <limits>
#include <utility>

namespace matmul::v4::rc::episode_digest_all_instance {
namespace {

namespace hs = stage3_hash_semantic;

constexpr char kBoundaryScheduleDomain[] =
    "BTX_RC_STAGE3_EPISODE_DIGEST_BOUNDARY_SCHEDULE_V1";
constexpr char kSiteStatementDomain[] =
    "BTX_RC_STAGE3_EPISODE_DIGEST_SITE_STATEMENT_V1";
constexpr char kSiteFsDomain[] =
    "BTX_RC_STAGE3_EPISODE_DIGEST_SITE_FS_V1";
constexpr char kSiteSetDomain[] =
    "BTX_RC_STAGE3_EPISODE_DIGEST_EXACT_SITE_SET_V1";
constexpr char kTerminalDomain[] =
    "BTX_RC_STAGE3_EPISODE_DIGEST_TERMINAL_WORDS_V1";
constexpr char kEndpointBindingDomain[] =
    "BTX_RC_STAGE3_EPISODE_DIGEST_ENDPOINT_BINDING_V1";
constexpr char kProofWireDomain[] =
    "BTX_RC_STAGE3_EPISODE_DIGEST_PROOF_WIRE_V1";
constexpr char kProductDomain[] =
    "BTX_RC_STAGE3_EPISODE_DIGEST_ALL_INSTANCE_PRODUCT_V1";

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why =
            "stage3:episode_digest_all_instance:" +
            detail;
    }
    return false;
}

bool IsEpisodeStatement(const RCStage3SuccinctProof& statement)
{
    return statement.statement ==
               RCStage3StatementKind::Episode ||
        statement.statement ==
               RCStage3StatementKind::Composed;
}

void HashFp3(HashWriter& hash, const gf::Fp3& value)
{
    hash << gf::Canonical(value.c0);
    hash << gf::Canonical(value.c1);
    hash << gf::Canonical(value.c2);
}

uint256 ProofWireRoot(const std::vector<unsigned char>& bytes)
{
    if (bytes.empty()) return {};
    HashWriter hash;
    hash << kProofWireDomain;
    hash << static_cast<uint64_t>(bytes.size());
    hash << bytes;
    return hash.GetHash();
}

fp::AlgAirProof ToCanonicalAlgProof(
    aq::AirQuotientRowsProof proof)
{
    fp::AlgAirProof out;
    out.batch = std::move(proof.batch);
    out.next_openings =
        std::move(proof.next_openings);
    out.trace_commit = proof.trace_commit;
    return out;
}

struct CanonicalFamilyV1 {
    sites::ProductionProofSiteManifest site_manifest;
    scheduler::ProductionAggregationSchedule schedule;
    sites::ProductionProofSiteEntry site_entry;
    scheduler::FamilyLeafRange family_range;
    ha::FixedProgram program;
    std::vector<ha::FixedProgramBoundaryInstance>
        boundaries;
    tape::ShardSourceChallengesV2 shared_challenges;
    uint256 statement_commitment{};
    uint256 program_root{};
    uint256 boundary_schedule_root{};
    uint256 output_root{};
    uint256 terminal_digest{};
    uint256 terminal_word_root{};
    uint256 exact_site_root{};
};

uint256 TerminalWordRoot(
    const ha::EpisodeDigestManifest& manifest,
    const std::vector<ha::FixedProgramBoundaryInstance>&
        boundaries)
{
    if (boundaries.empty() ||
        boundaries.back().final_words.empty()) {
        return {};
    }
    HashWriter hash;
    hash << kTerminalDomain;
    hash << manifest.commitment;
    hash << manifest.direct.digest;
    hash << static_cast<uint32_t>(
        boundaries.size() - 1);
    hash << boundaries.back().final_words;
    return hash.GetHash();
}

uint256 EndpointBindingRoot(
    const RCStage3EpisodeDigestRootChainProof& root_chain)
{
    namespace signed_range =
        coupled_signed_range_stream;
    if (root_chain.manifest.commitment.IsNull() ||
        root_chain.round_roots_pin.pin_commitment.IsNull() ||
        root_chain.digest_pin.pin_commitment.IsNull() ||
        root_chain.hash_binding.memory_manifest.
            manifest_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << kEndpointBindingDomain;
    hash << kVersionV1;
    hash << root_chain.manifest.commitment;
    hash << root_chain.round_roots_pin.pin_commitment;
    hash << root_chain.round_roots_proof.pin_commitment;
    hash << signed_range::CommitAirQuotientProofV1(
        root_chain.round_roots_proof.quotient);
    hash << root_chain.hash_bundle.version;
    hash << static_cast<uint16_t>(
        root_chain.hash_bundle.endpoint);
    hash << root_chain.hash_bundle.statement_commitment;
    hash << root_chain.hash_bundle.manifest_commitment;
    hash << static_cast<uint32_t>(
        root_chain.hash_bundle.proofs.size());
    for (const auto& proof :
         root_chain.hash_bundle.proofs) {
        hash << proof.version;
        hash << proof.boundary_statement;
        hash << proof.challenge_commitment;
        hash << signed_range::CommitAirQuotientProofV1(
            proof.quotient);
    }
    hash << static_cast<uint8_t>(
        root_chain.hash_binding.port);
    hash << root_chain.hash_binding.memory_manifest.
        manifest_commitment;
    hash << root_chain.hash_binding.memory_proof.
        manifest_commitment;
    hash << signed_range::CommitAirQuotientProofV1(
        root_chain.hash_binding.memory_proof.quotient);
    hash << root_chain.digest_pin.pin_commitment;
    hash << root_chain.digest_proof.pin_commitment;
    hash << signed_range::CommitAirQuotientProofV1(
        root_chain.digest_proof.quotient);
    return hash.GetHash();
}

uint256 BoundaryScheduleRoot(
    const ha::FixedProgram& program,
    const ha::EpisodeDigestManifest& manifest,
    const std::vector<ha::FixedProgramBoundaryInstance>&
        boundaries)
{
    if (boundaries.empty()) return {};
    HashWriter hash;
    hash << kBoundaryScheduleDomain;
    hash << manifest.commitment;
    hash << ha::CommitFixedProgram(program);
    hash << static_cast<uint32_t>(
        boundaries.size());
    for (uint32_t boundary = 0;
         boundary < boundaries.size(); ++boundary) {
        const auto& row = boundaries[boundary];
        if (row.external_values.empty() ||
            row.final_words.empty()) {
            return {};
        }
        hash << boundary;
        hash << static_cast<uint32_t>(
            row.external_values.size());
        for (uint32_t value : row.external_values) {
            hash << value;
        }
        hash << static_cast<uint32_t>(
            row.final_words.size());
        for (uint32_t value : row.final_words) {
            hash << value;
        }
    }
    return hash.GetHash();
}

uint256 SiteStatementRoot(
    const CanonicalFamilyV1& family,
    uint32_t site_ordinal,
    uint32_t boundary_begin,
    uint32_t boundary_count)
{
    if (boundary_count == 0 ||
        boundary_begin > family.boundaries.size() ||
        boundary_count >
            family.boundaries.size() -
                boundary_begin) {
        return {};
    }
    HashWriter hash;
    hash << kSiteStatementDomain;
    hash << kVersionV1;
    hash << family.statement_commitment;
    hash << family.site_manifest.commitment;
    hash << family.schedule.commitment;
    hash << family.site_entry.proof_sites;
    hash << family.family_range.family_index;
    hash << family.family_range.first_leaf_site;
    hash << family.family_range.leaf_count;
    hash << site_ordinal;
    hash << family.family_range.first_leaf_site +
            site_ordinal;
    hash << boundary_begin;
    hash << boundary_count;
    hash << static_cast<uint32_t>(
        family.boundaries.size());
    hash << family.program_root;
    hash << family.boundary_schedule_root;
    hash << family.output_root;
    hash << family.terminal_digest;
    hash << family.terminal_word_root;
    for (uint32_t boundary = boundary_begin;
         boundary < boundary_begin + boundary_count;
         ++boundary) {
        const auto& row = family.boundaries[boundary];
        hash << boundary;
        hash << row.external_values;
        hash << row.final_words;
    }
    return hash.GetHash();
}

uint256 SiteFsSeed(
    const TapeChallengeContextV1& context,
    const CanonicalFamilyV1& family,
    uint32_t site_ordinal,
    uint32_t boundary_begin,
    uint32_t boundary_count,
    const uint256& site_statement_root)
{
    if (site_statement_root.IsNull()) return {};
    HashWriter hash;
    hash << kSiteFsDomain;
    hash << kVersionV1;
    for (gf::Fp lane : context.binding.tape_root) {
        hash << static_cast<uint64_t>(lane);
    }
    hash << context.binding.program_root;
    hash << context.binding.statement_root;
    hash << context.binding.public_fs_seed;
    hash << context.binding.proof_wire_root;
    hash << context.source_inventory_root;
    hash << context.shard_count;
    for (uint32_t lane = 0; lane < 2; ++lane) {
        HashFp3(
            hash,
            family.shared_challenges.gamma[lane]);
        HashFp3(
            hash,
            family.shared_challenges.alpha[lane]);
    }
    hash << family.statement_commitment;
    hash << family.site_manifest.commitment;
    hash << family.schedule.commitment;
    hash << family.program_root;
    hash << family.boundary_schedule_root;
    hash << family.output_root;
    hash << family.terminal_digest;
    hash << family.terminal_word_root;
    hash << site_ordinal;
    hash << boundary_begin;
    hash << boundary_count;
    hash << site_statement_root;
    return hash.GetHash();
}

uint256 ExactSiteRoot(const CanonicalFamilyV1& family)
{
    if (family.family_range.leaf_count == 0 ||
        family.boundaries.empty()) {
        return {};
    }
    HashWriter hash;
    hash << kSiteSetDomain;
    hash << kVersionV1;
    hash << static_cast<uint8_t>(
        sites::ProductionProofSiteKind::
            EpisodeDigestSha256d);
    hash << static_cast<uint16_t>(
        RCStage3RelationRole::EpisodeDigest);
    hash << family.family_range.family_index;
    hash << family.family_range.first_leaf_site;
    hash << family.family_range.leaf_count;
    hash << family.site_entry.logical_units;
    hash << family.site_entry.units_per_site;
    hash << family.site_entry.proof_sites;
    hash << family.boundary_schedule_root;
    hash << family.output_root;
    hash << family.terminal_digest;
    hash << family.terminal_word_root;
    for (uint32_t site = 0;
         site < family.family_range.leaf_count;
         ++site) {
        const uint32_t begin =
            site * kBoundariesPerProofSiteV1;
        const uint32_t count =
            std::min<uint32_t>(
                kBoundariesPerProofSiteV1,
                static_cast<uint32_t>(
                    family.boundaries.size()) -
                    begin);
        hash << site;
        hash << family.family_range.first_leaf_site +
                site;
        hash << begin;
        hash << count;
    }
    return hash.GetHash();
}

bool BuildCanonicalFamily(
    const RCStage3SuccinctProof& statement,
    const ha::EpisodeDigestManifest& manifest,
    const TapeChallengeContextV1& tape_context,
    CanonicalFamilyV1& out,
    std::string* why)
{
    out = {};
    const RCEpisodeParams params =
        MakeDatacenterRCEpisodeParams();
    out.statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    if (!IsEpisodeStatement(statement) ||
        out.statement_commitment.IsNull() ||
        !ValidateRCStage3EpisodeDigestManifestStructural(
            manifest, params.rounds, why) ||
        manifest.direct.digest !=
            statement.public_inputs.episode_digest) {
        return Fail(why, "statement_or_manifest");
    }

    out.site_manifest =
        sites::BuildProductionProofSiteManifest(
            sites::SelectedProductionProofSitePolicy());
    out.schedule =
        scheduler::BuildProductionAggregationSchedule(
            out.site_manifest);
    if (!sites::ValidateProductionProofSiteManifest(
            out.site_manifest, why) ||
        !scheduler::ValidateProductionAggregationSchedule(
            out.site_manifest, out.schedule, why)) {
        return Fail(why, "production_schedule");
    }
    const auto site_found = std::find_if(
        out.site_manifest.entries.begin(),
        out.site_manifest.entries.end(),
        [](const auto& entry) {
            return entry.kind ==
                sites::ProductionProofSiteKind::
                    EpisodeDigestSha256d;
        });
    const auto range_found = std::find_if(
        out.schedule.families.begin(),
        out.schedule.families.end(),
        [](const auto& range) {
            return range.kind ==
                sites::ProductionProofSiteKind::
                    EpisodeDigestSha256d;
        });
    if (site_found ==
            out.site_manifest.entries.end() ||
        range_found == out.schedule.families.end()) {
        return Fail(why, "family_absent");
    }
    out.site_entry = *site_found;
    out.family_range = *range_found;
    if (out.site_entry.role !=
            RCStage3RelationRole::EpisodeDigest ||
        out.site_entry.units_per_site !=
            kBoundariesPerProofSiteV1 ||
        out.site_entry.proof_sites !=
            out.family_range.leaf_count ||
        out.family_range.family_index !=
            static_cast<uint32_t>(
                site_found -
                out.site_manifest.entries.begin())) {
        return Fail(why, "family_range");
    }

    if (!ha::BuildDirectSha256dManifestBoundaryInstances(
            manifest.direct, out.boundaries, why) ||
        out.boundaries.empty() ||
        out.boundaries.size() >
            std::numeric_limits<uint32_t>::max() ||
        out.site_entry.logical_units !=
            out.boundaries.size() ||
        out.site_entry.proof_sites !=
            (out.boundaries.size() +
                 kBoundariesPerProofSiteV1 - 1U) /
                kBoundariesPerProofSiteV1) {
        return Fail(why, "boundary_inventory");
    }

    out.program = ha::BuildCanonicalProgram(
        ha::ProgramKind::Sha256Compression);
    std::string program_why;
    if (!ha::ValidateCanonicalProgram(
            out.program, &program_why)) {
        return Fail(
            why, "program:" + program_why);
    }
    out.program_root =
        ha::CommitFixedProgram(out.program);
    out.boundary_schedule_root =
        BoundaryScheduleRoot(
            out.program, manifest, out.boundaries);
    uint32_t output_rows = 0;
    uint32_t output_n_rows = 0;
    if (!hs::ComputeCanonicalBoundaryValueRoot(
            out.boundaries, hs::BoundaryPort::Final,
            out.output_root, output_rows,
            output_n_rows, why) ||
        output_rows != out.boundaries.size() *
            out.program.final_addresses.size() ||
        output_n_rows < output_rows) {
        return Fail(why, "output_root");
    }
    out.terminal_digest = manifest.direct.digest;
    out.terminal_word_root =
        TerminalWordRoot(manifest, out.boundaries);
    if (!tape::DeriveShardPublicSourceChallengesV3(
            tape_context.shape,
            tape_context.binding,
            tape_context.source_inventory_root,
            tape_context.shard_count,
            out.shared_challenges)) {
        return Fail(why, "tape_v3_challenges");
    }
    out.exact_site_root = ExactSiteRoot(out);
    if (out.program_root.IsNull() ||
        out.boundary_schedule_root.IsNull() ||
        out.output_root.IsNull() ||
        out.terminal_word_root.IsNull() ||
        out.exact_site_root.IsNull()) {
        return Fail(why, "canonical_roots");
    }
    return true;
}

bool BuildSiteInstance(
    const TapeChallengeContextV1& tape_context,
    const CanonicalFamilyV1& family,
    uint32_t site_ordinal,
    ha::FixedProgramVerticalProvenanceInstance& instance,
    SiteReceiptV1& statement,
    std::string* why)
{
    if (site_ordinal >=
        family.family_range.leaf_count) {
        return Fail(why, "site_ordinal");
    }
    const uint32_t begin =
        site_ordinal *
        kBoundariesPerProofSiteV1;
    if (begin >= family.boundaries.size()) {
        return Fail(why, "site_begin");
    }
    const uint32_t count =
        std::min<uint32_t>(
            kBoundariesPerProofSiteV1,
            static_cast<uint32_t>(
                family.boundaries.size()) - begin);
    std::vector<ha::FixedProgramBoundaryInstance>
        chunk(
            family.boundaries.begin() + begin,
            family.boundaries.begin() + begin + count);

    statement = {};
    statement.site_ordinal = site_ordinal;
    statement.global_leaf_site =
        family.family_range.first_leaf_site +
        site_ordinal;
    statement.boundary_begin = begin;
    statement.boundary_count = count;
    statement.site_statement_root =
        SiteStatementRoot(
            family, site_ordinal, begin, count);
    statement.public_fs_seed =
        SiteFsSeed(
            tape_context, family, site_ordinal,
            begin, count,
            statement.site_statement_root);
    if (statement.site_statement_root.IsNull() ||
        statement.public_fs_seed.IsNull()) {
        return Fail(why, "site_roots");
    }
    instance =
        ha::BuildFixedProgramVerticalProvenanceInstance(
            family.program, chunk,
            statement.public_fs_seed);
    if (!instance.valid ||
        instance.semantic_instances != count ||
        instance.boundary_statement.IsNull() ||
        instance.columns.size() !=
            instance.cs.n_columns) {
        return Fail(
            why, "site_instance:" +
                instance.note);
    }
    statement.boundary_statement =
        instance.boundary_statement;
    return true;
}

bool SameSiteStatement(
    const SiteReceiptV1& supplied,
    const SiteReceiptV1& expected)
{
    return supplied.site_ordinal ==
            expected.site_ordinal &&
        supplied.global_leaf_site ==
            expected.global_leaf_site &&
        supplied.boundary_begin ==
            expected.boundary_begin &&
        supplied.boundary_count ==
            expected.boundary_count &&
        supplied.boundary_statement ==
            expected.boundary_statement &&
        supplied.site_statement_root ==
            expected.site_statement_root &&
        supplied.public_fs_seed ==
            expected.public_fs_seed;
}

} // namespace

uint256 CommitProofWireV1(
    const std::vector<unsigned char>& proof_bytes)
{
    return ProofWireRoot(proof_bytes);
}

uint256 CommitProductV1(const ProductV1& product)
{
    if (product.version != kVersionV1 ||
        product.manifest.commitment.IsNull() ||
        product.statement_commitment.IsNull() ||
        product.production_site_manifest_commitment.IsNull() ||
        product.aggregation_schedule_commitment.IsNull() ||
        product.leaf_site_count == 0 ||
        product.sites.size() !=
            product.leaf_site_count ||
        product.boundary_count == 0 ||
        product.program_root.IsNull() ||
        product.exact_boundary_schedule_root.IsNull() ||
        product.proof_owned_output_root.IsNull() ||
        product.terminal_word_root.IsNull() ||
        product.endpoint_binding_root.IsNull() ||
        product.exact_site_root.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << kProductDomain;
    hash << product.version;
    hash << product.manifest.commitment;
    hash << product.statement_commitment;
    hash << product.production_site_manifest_commitment;
    hash << product.aggregation_schedule_commitment;
    hash << product.family_index;
    hash << product.first_leaf_site;
    hash << product.leaf_site_count;
    hash << product.boundary_count;
    hash << product.program_root;
    hash << product.exact_boundary_schedule_root;
    hash << product.proof_owned_output_root;
    hash << product.terminal_digest;
    hash << product.terminal_word_root;
    hash << product.endpoint_binding_root;
    hash << product.exact_site_root;
    hash << static_cast<uint32_t>(
        product.sites.size());
    for (const auto& site : product.sites) {
        if (site.site_statement_root.IsNull() ||
            site.public_fs_seed.IsNull() ||
            site.proof_commitment.IsNull() ||
            site.proof_wire_root.IsNull() ||
            site.proof_bytes.empty()) {
            return {};
        }
        hash << site.site_ordinal;
        hash << site.global_leaf_site;
        hash << site.boundary_begin;
        hash << site.boundary_count;
        hash << site.boundary_statement;
        hash << site.site_statement_root;
        hash << site.public_fs_seed;
        hash << site.proof_commitment;
        hash << site.proof_wire_root;
    }
    hash << product.exact_production_family_coverage;
    hash << product.every_site_proof_verified;
    hash << product.endpoint_root_chain_verified;
    hash << product.ordinary_recursive_leaf_compatible;
    hash << product.normalized_recursive_consumed;
    hash << product.production_authority;
    return hash.GetHash();
}

bool ProveProductV1(
    const RCStage3SuccinctProof& statement,
    const ha::EpisodeDigestManifest& manifest,
    const TapeChallengeContextV1& tape_context,
    ProductV1& out,
    std::string* why)
{
    out = {};
    CanonicalFamilyV1 family;
    if (!BuildCanonicalFamily(
            statement, manifest, tape_context,
            family, why)) {
        return false;
    }
    out.manifest = manifest;
    out.statement_commitment =
        family.statement_commitment;
    out.production_site_manifest_commitment =
        family.site_manifest.commitment;
    out.aggregation_schedule_commitment =
        family.schedule.commitment;
    out.family_index =
        family.family_range.family_index;
    out.first_leaf_site =
        family.family_range.first_leaf_site;
    out.leaf_site_count =
        family.family_range.leaf_count;
    out.boundary_count =
        static_cast<uint32_t>(
            family.boundaries.size());
    out.program_root = family.program_root;
    out.exact_boundary_schedule_root =
        family.boundary_schedule_root;
    out.proof_owned_output_root =
        family.output_root;
    out.terminal_digest =
        family.terminal_digest;
    out.terminal_word_root =
        family.terminal_word_root;
    if (!ProveRCStage3EpisodeDigestRootChain(
            statement,
            static_cast<uint32_t>(
                manifest.round_roots.size()),
            manifest.round_roots,
            out.endpoint_root_chain, why) ||
        out.endpoint_root_chain.manifest != manifest) {
        out = {};
        return Fail(why, "endpoint_root_chain_prove");
    }
    out.endpoint_binding_root =
        EndpointBindingRoot(
            out.endpoint_root_chain);
    if (out.endpoint_binding_root.IsNull()) {
        out = {};
        return Fail(why, "endpoint_binding_root");
    }
    out.exact_site_root =
        family.exact_site_root;
    out.sites.resize(out.leaf_site_count);

    for (uint32_t site = 0;
         site < out.sites.size(); ++site) {
        ha::FixedProgramVerticalProvenanceInstance
            instance;
        SiteReceiptV1 receipt;
        if (!BuildSiteInstance(
                tape_context, family, site,
                instance, receipt, why)) {
            out = {};
            return false;
        }
        auto proved =
            aq::AirQuotientProveRows(
                instance.cs, instance.columns,
                receipt.public_fs_seed, {});
        if (!proved.ok ||
            !proved.division_exact) {
            out = {};
            return Fail(
                why, "prove_site_" +
                    std::to_string(site) + ":" +
                    proved.note);
        }
        fp::AlgAirProof proof =
            ToCanonicalAlgProof(
                std::move(proved.proof));
        std::string verify_why;
        if (!aq::AirQuotientVerify<
                gf::Fp3,
                aq::AirFriBackendAlg<gf::Fp3>>(
                instance.cs, proof,
                receipt.public_fs_seed,
                &verify_why)) {
            out = {};
            return Fail(
                why, "self_verify_site_" +
                    std::to_string(site) + ":" +
                    verify_why);
        }
        if (!SerializeAirQuotientProofAlg(
                proof, receipt.proof_bytes,
                &verify_why) ||
            receipt.proof_bytes.empty()) {
            out = {};
            return Fail(
                why, "serialize_site_" +
                    std::to_string(site) + ":" +
                    verify_why);
        }
        receipt.proof_commitment =
            fp::ComputeNormalizedAlgAirProofCommitment(
                proof);
        receipt.proof_wire_root =
            ProofWireRoot(receipt.proof_bytes);
        if (receipt.proof_commitment.IsNull() ||
            receipt.proof_wire_root.IsNull()) {
            out = {};
            return Fail(why, "site_commitment");
        }
        out.sites[site] =
            std::move(receipt);
    }
    out.exact_production_family_coverage = true;
    out.every_site_proof_verified = true;
    out.endpoint_root_chain_verified = true;
    out.ordinary_recursive_leaf_compatible = true;
    out.normalized_recursive_consumed = false;
    out.production_authority = false;
    out.note =
        "stage3:episode_digest_all_instance:"
        "exact_production_digest_family_proved;"
        "ordinary_narrow_child_ready;"
        "upstream_tile_stream_and_parent_consumption_open";
    out.product_commitment =
        CommitProductV1(out);
    if (out.product_commitment.IsNull() ||
        !VerifyProductV1(
            statement, tape_context, out, why)) {
        out = {};
        return Fail(why, "prove_self_verify");
    }
    return true;
}

bool VerifyProductV1(
    const RCStage3SuccinctProof& statement,
    const TapeChallengeContextV1& tape_context,
    const ProductV1& product,
    std::string* why)
{
    if (product.version != kVersionV1 ||
        !product.exact_production_family_coverage ||
        !product.every_site_proof_verified ||
        !product.endpoint_root_chain_verified ||
        !product.ordinary_recursive_leaf_compatible ||
        product.normalized_recursive_consumed ||
        product.production_authority) {
        return Fail(why, "product_flags");
    }
    CanonicalFamilyV1 family;
    if (!BuildCanonicalFamily(
            statement, product.manifest,
            tape_context, family, why)) {
        return false;
    }
    std::string endpoint_why;
    if (product.endpoint_root_chain.manifest !=
            product.manifest ||
        !VerifyRCStage3EpisodeDigestRootChain(
            statement,
            static_cast<uint32_t>(
                product.manifest.round_roots.size()),
            product.endpoint_root_chain,
            &endpoint_why) ||
        product.endpoint_binding_root !=
            EndpointBindingRoot(
                product.endpoint_root_chain)) {
        return Fail(
            why, "endpoint_root_chain:" +
                endpoint_why);
    }
    if (product.statement_commitment !=
            family.statement_commitment ||
        product.production_site_manifest_commitment !=
            family.site_manifest.commitment ||
        product.aggregation_schedule_commitment !=
            family.schedule.commitment ||
        product.family_index !=
            family.family_range.family_index ||
        product.first_leaf_site !=
            family.family_range.first_leaf_site ||
        product.leaf_site_count !=
            family.family_range.leaf_count ||
        product.boundary_count !=
            family.boundaries.size() ||
        product.program_root !=
            family.program_root ||
        product.exact_boundary_schedule_root !=
            family.boundary_schedule_root ||
        product.proof_owned_output_root !=
            family.output_root ||
        product.terminal_digest !=
            family.terminal_digest ||
        product.terminal_word_root !=
            family.terminal_word_root ||
        product.exact_site_root !=
            family.exact_site_root ||
        product.sites.size() !=
            family.family_range.leaf_count) {
        return Fail(why, "canonical_metadata");
    }

    for (uint32_t site = 0;
         site < product.sites.size(); ++site) {
        ha::FixedProgramVerticalProvenanceInstance
            instance;
        SiteReceiptV1 expected;
        if (!BuildSiteInstance(
                tape_context, family, site,
                instance, expected, why)) {
            return false;
        }
        const auto& supplied =
            product.sites[site];
        if (!SameSiteStatement(
                supplied, expected) ||
            supplied.proof_bytes.empty() ||
            supplied.proof_wire_root !=
                ProofWireRoot(
                    supplied.proof_bytes)) {
            return Fail(
                why, "site_statement_" +
                    std::to_string(site));
        }
        std::string codec_why;
        const auto decoded =
            DeserializeAirQuotientProofAlg(
                supplied.proof_bytes,
                &codec_why);
        std::vector<unsigned char> canonical;
        if (!decoded.has_value() ||
            !SerializeAirQuotientProofAlg(
                *decoded, canonical,
                &codec_why) ||
            canonical !=
                supplied.proof_bytes ||
            supplied.proof_commitment !=
                fp::ComputeNormalizedAlgAirProofCommitment(
                    *decoded)) {
            return Fail(
                why, "site_codec_" +
                    std::to_string(site) + ":" +
                    codec_why);
        }
        std::string proof_why;
        if (!aq::AirQuotientVerify<
                gf::Fp3,
                aq::AirFriBackendAlg<gf::Fp3>>(
                instance.cs, *decoded,
                supplied.public_fs_seed,
                &proof_why)) {
            return Fail(
                why, "site_proof_" +
                    std::to_string(site) + ":" +
                    proof_why);
        }
    }
    if (product.product_commitment.IsNull() ||
        product.product_commitment !=
            CommitProductV1(product)) {
        return Fail(why, "product_commitment");
    }
    if (why != nullptr) {
        *why =
            "stage3:episode_digest_all_instance:"
            "exact_manifest_sites_and_alg_proofs_verified;"
            "normalized_parent_consumption_open";
    }
    return true;
}

bool BuildRecursiveChildInputsV1(
    const RCStage3SuccinctProof& statement,
    const TapeChallengeContextV1& tape_context,
    const ProductV1& product,
    std::vector<RecursiveChildInputV1>& out,
    std::string* why)
{
    out.clear();
    if (!VerifyProductV1(
            statement, tape_context,
            product, why)) {
        return false;
    }
    CanonicalFamilyV1 family;
    if (!BuildCanonicalFamily(
            statement, product.manifest,
            tape_context, family, why)) {
        return false;
    }
    out.reserve(product.sites.size());
    for (uint32_t site = 0;
         site < product.sites.size(); ++site) {
        ha::FixedProgramVerticalProvenanceInstance
            instance;
        SiteReceiptV1 expected;
        if (!BuildSiteInstance(
                tape_context, family, site,
                instance, expected, why)) {
            out.clear();
            return false;
        }
        const auto decoded =
            DeserializeAirQuotientProofAlg(
                product.sites[site].proof_bytes,
                why);
        if (!decoded.has_value()) {
            out.clear();
            return Fail(
                why, "recursive_child_decode");
        }
        RecursiveChildInputV1 input;
        input.cs = std::move(instance.cs);
        input.proof = *decoded;
        input.public_fs_seed =
            expected.public_fs_seed;
        input.site_statement_root =
            expected.site_statement_root;
        input.global_leaf_site =
            expected.global_leaf_site;
        out.push_back(std::move(input));
    }
    if (why != nullptr) {
        *why =
            "stage3:episode_digest_all_instance:"
            "ordinary_recursive_children_rebuilt";
    }
    return true;
}

} // namespace matmul::v4::rc::episode_digest_all_instance
