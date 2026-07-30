// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_universal_topology.h>

#include <hash.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>

#include <algorithm>
#include <cstring>
#include <limits>
#include <set>

namespace matmul::v4::rc::universal_topology {
namespace {

using gkr_field::Fp;

constexpr char REGISTRY_BYTES_DOMAIN[] =
    "BTX_RC_STAGE3_PRODUCTION_PROGRAM_REGISTRY_V1";
constexpr char LEAF_STATEMENT_DOMAIN[] =
    "BTX_RC_STAGE3_UNIVERSAL_LEAF_STATEMENT_V1";
constexpr char PARENT_STATEMENT_DOMAIN[] =
    "BTX_RC_STAGE3_UNIVERSAL_PARENT_STATEMENT_V1";
constexpr char SCHEMA_DOMAIN[] =
    "BTX_RC_STAGE3_PUBLIC_INPUT_SCHEMA_V1";
constexpr char REGISTRY_PUBLIC_PIN_DOMAIN[] =
    "BTX_RC_STAGE3_PRODUCTION_PROGRAM_REGISTRY_PUBLIC_PIN_V1";

bool Fail(std::string* why, const char* detail)
{
    if (why != nullptr) {
        *why = std::string{"stage3:universal_topology:"} + detail;
    }
    return false;
}

bool AlgDigestZero(const ah::Digest& digest)
{
    return std::all_of(
        digest.begin(), digest.end(),
        [](Fp value) {
            return gkr_field::Canonical(value) == 0;
        });
}

void PutU16(std::vector<unsigned char>& out, uint16_t value)
{
    out.push_back(static_cast<unsigned char>(value));
    out.push_back(static_cast<unsigned char>(value >> 8));
}

void PutU32(std::vector<unsigned char>& out, uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i) {
        out.push_back(
            static_cast<unsigned char>(value >> (8 * i)));
    }
}

void PutU64(std::vector<unsigned char>& out, uint64_t value)
{
    for (unsigned i = 0; i < 8; ++i) {
        out.push_back(
            static_cast<unsigned char>(value >> (8 * i)));
    }
}

void PutUint256(
    std::vector<unsigned char>& out,
    const uint256& value)
{
    out.insert(out.end(), value.begin(), value.end());
}

void PutAlgDigest(
    std::vector<unsigned char>& out,
    const ah::Digest& digest)
{
    for (Fp value : digest) {
        PutU64(out, gkr_field::Canonical(value));
    }
}

void PutBool(std::vector<unsigned char>& out, bool value)
{
    out.push_back(value ? 1 : 0);
}

std::vector<Fp> BytesToAlgPreimage(
    const char* domain,
    const std::vector<unsigned char>& bytes)
{
    std::vector<Fp> out;
    const size_t domain_size = std::strlen(domain);
    out.reserve(
        4 + (domain_size + 3) / 4 +
        (bytes.size() + 3) / 4);
    auto append = [&](const unsigned char* data, size_t size) {
        out.push_back(gkr_field::FromU64(size));
        for (size_t offset = 0; offset < size; offset += 4) {
            uint64_t word = 0;
            for (size_t i = 0;
                 i < 4 && offset + i < size; ++i) {
                word |=
                    uint64_t{data[offset + i]} << (8 * i);
            }
            out.push_back(gkr_field::FromU64(word));
        }
    };
    append(
        reinterpret_cast<const unsigned char*>(domain),
        domain_size);
    append(bytes.data(), bytes.size());
    return out;
}

uint32_t MaxDegree(const cb::ProgramTable& table)
{
    uint32_t result = 0;
    for (const auto& program : table.programs) {
        result = std::max(result, program.declared_degree);
    }
    return result;
}

std::vector<unsigned char> RegistryBytes(
    const ProductionProgramRegistryV1& registry)
{
    std::vector<unsigned char> out;
    PutU16(out, registry.version);
    PutUint256(out, registry.site_manifest_commitment);
    PutUint256(out, registry.aggregation_schedule_commitment);
    PutU32(out, registry.families.size());
    for (const auto& family : registry.families) {
        PutU32(out, family.family_index);
        PutU16(out, static_cast<uint16_t>(family.kind));
        PutU16(out, static_cast<uint16_t>(family.role));
        PutU32(out, family.maximum_columns);
        PutU32(out, family.constraint_count);
        PutU32(out, family.maximum_constraint_degree);
        PutUint256(out, family.program.external_sha256d);
        PutAlgDigest(out, family.program.recursive_alg_hash);
        PutBool(out, family.program.same_canonical_serialization);
        PutUint256(
            out, family.public_input_schema.external_sha256d);
        PutAlgDigest(
            out, family.public_input_schema.recursive_alg_hash);
        PutU64(out, family.public_input_schema.byte_length);
        PutBool(
            out, family.public_input_schema.same_canonical_bytes);
        PutU32(out, family.semantic_endpoints.size());
        for (uint16_t endpoint : family.semantic_endpoints) {
            PutU16(out, endpoint);
        }
        PutBool(out, family.semantic_relation_complete);
    }
    PutUint256(
        out,
        registry.universal_parent_verifier.external_sha256d);
    PutAlgDigest(
        out,
        registry.universal_parent_verifier.recursive_alg_hash);
    PutBool(
        out,
        registry.universal_parent_verifier
            .same_canonical_serialization);
    PutUint256(
        out,
        registry.normalized_root_verifier.external_sha256d);
    PutAlgDigest(
        out,
        registry.normalized_root_verifier.recursive_alg_hash);
    PutBool(
        out,
        registry.normalized_root_verifier
            .same_canonical_serialization);
    PutU32(out, registry.universal_parent_columns);
    PutU32(out, registry.normalized_root_columns);
    return out;
}

void SetRegistryCommitments(
    ProductionProgramRegistryV1& registry)
{
    const std::vector<unsigned char> bytes =
        RegistryBytes(registry);
    HashWriter hash;
    hash << REGISTRY_BYTES_DOMAIN;
    hash << bytes;
    registry.external_registry_commitment =
        hash.GetHash();
    registry.recursive_registry_commitment =
        ah::SpongeHashFp(
            BytesToAlgPreimage(
                REGISTRY_BYTES_DOMAIN, bytes));
}

bool RegistryStructurallyValid(
    const sites::ProductionProofSiteManifest& manifest,
    const sched::ProductionAggregationSchedule& schedule,
    const ProductionProgramRegistryV1& registry)
{
    if (registry.version !=
            kProductionProgramRegistryVersionV1 ||
        registry.site_manifest_commitment !=
            manifest.commitment ||
        registry.aggregation_schedule_commitment !=
            schedule.commitment ||
        registry.families.size() !=
            manifest.entries.size() ||
        registry.families.size() !=
            kProductionProgramFamilyCountV1 ||
        registry.external_registry_commitment.IsNull() ||
        AlgDigestZero(registry.recursive_registry_commitment) ||
        registry.universal_parent_columns == 0 ||
        registry.normalized_root_columns == 0 ||
        !registry.exact_family_order ||
        !registry.every_program_canonical ||
        !registry.every_public_input_schema_bound ||
        !registry.every_program_within_column_cap) {
        return false;
    }
    for (size_t i = 0; i < registry.families.size(); ++i) {
        const auto& entry = registry.families[i];
        const auto& expected = manifest.entries[i];
        if (entry.family_index != i ||
            entry.kind != expected.kind ||
            entry.role != expected.role ||
            entry.maximum_columns == 0 ||
            entry.maximum_columns >
                kUniversalVerifierColumnCapV1 ||
            entry.constraint_count == 0 ||
            entry.maximum_constraint_degree == 0 ||
            entry.program.external_sha256d.IsNull() ||
            AlgDigestZero(entry.program.recursive_alg_hash) ||
            !entry.program.same_canonical_serialization ||
            entry.public_input_schema.external_sha256d.IsNull() ||
            AlgDigestZero(
                entry.public_input_schema.recursive_alg_hash) ||
            !entry.public_input_schema.same_canonical_bytes) {
            return false;
        }
    }
    ProductionProgramRegistryV1 copy = registry;
    copy.external_registry_commitment.SetNull();
    copy.recursive_registry_commitment = {};
    SetRegistryCommitments(copy);
    return
        copy.external_registry_commitment ==
            registry.external_registry_commitment &&
        copy.recursive_registry_commitment ==
            registry.recursive_registry_commitment;
}

const ProductionFamilyProgramEntryV1* FamilyEntry(
    const ProductionProgramRegistryV1& registry,
    uint32_t family_index)
{
    if (family_index >= registry.families.size()) {
        return nullptr;
    }
    const auto& entry = registry.families[family_index];
    return entry.family_index == family_index
        ? &entry
        : nullptr;
}

const sched::FamilyLeafRange* FamilyRange(
    const sched::ProductionAggregationSchedule& schedule,
    uint32_t family_index)
{
    if (family_index >= schedule.families.size()) {
        return nullptr;
    }
    const auto& family = schedule.families[family_index];
    return family.family_index == family_index
        ? &family
        : nullptr;
}

UniversalStatementBindingV1 CommitStatement(
    const char* domain,
    const std::vector<unsigned char>& bytes)
{
    UniversalStatementBindingV1 out;
    HashWriter hash;
    hash << domain;
    hash << bytes;
    out.external_sha256d = hash.GetHash();
    out.recursive_alg_hash =
        ah::SpongeHashFp(
            BytesToAlgPreimage(domain, bytes));
    return out;
}

} // namespace

ByteCommitmentPairV1 CommitCanonicalBytesV1(
    const char* domain,
    const std::vector<unsigned char>& bytes)
{
    ByteCommitmentPairV1 out;
    if (domain == nullptr || domain[0] == '\0') {
        return out;
    }
    out.byte_length = bytes.size();
    HashWriter hash;
    hash << domain;
    hash << bytes;
    out.external_sha256d = hash.GetHash();
    out.recursive_alg_hash =
        ah::SpongeHashFp(
            BytesToAlgPreimage(domain, bytes));
    out.same_canonical_bytes =
        !out.external_sha256d.IsNull() &&
        !AlgDigestZero(out.recursive_alg_hash);
    return out;
}

bool ValidateProductionFamilyPhaseDescriptorV1(
    const cb::ProgramTable& program,
    const ProductionFamilyPhaseDescriptorV1& phase,
    bool require_producer_export,
    std::string* why)
{
    const uint256 program_root =
        cb::CommitProgramTable(program);
    if (!cb::ValidateProgramTable(program, why) ||
        phase.version != 1 ||
        phase.program_root.IsNull() ||
        phase.program_root != program_root ||
        phase.role != program.role ||
        phase.current_width != program.current_width ||
        phase.challenge_width != program.challenge_width ||
        program.current_width == 0) {
        return Fail(why, "family_phase_identity");
    }
    if (program.challenge_width == 0) {
        if (!phase.producer_manifest_exported ||
            phase.challenge_epoch !=
                ProductionChallengeEpochV1::None ||
            phase.r0_base_columns.size() !=
                program.current_width) {
            return Fail(
                why, "family_phase_challenge_free");
        }
        for (uint32_t column = 0;
             column < program.current_width; ++column) {
            if (phase.r0_base_columns[column] != column) {
                return Fail(
                    why,
                    "family_phase_challenge_free_order");
            }
        }
        return true;
    }
    if (phase.challenge_epoch !=
            ProductionChallengeEpochV1::
                BytecodeP2AfterSafeR0) {
        return Fail(why, "family_phase_epoch");
    }
    if (!phase.producer_manifest_exported) {
        if (require_producer_export ||
            !phase.r0_base_columns.empty()) {
            return Fail(why, "family_phase_not_exported");
        }
        // Canonical fail-closed inventory record: the family exists and its
        // exact missing phase declaration is registry-bound, but it cannot be
        // used to construct a child Split-RAP statement.
        return true;
    }
    if (phase.r0_base_columns.empty() ||
        phase.r0_base_columns.size() >=
            program.current_width) {
        return Fail(why, "family_phase_split_shape");
    }
    uint32_t previous = 0;
    for (size_t i = 0;
         i < phase.r0_base_columns.size(); ++i) {
        const uint32_t column =
            phase.r0_base_columns[i];
        if (column >= program.current_width ||
            (i != 0 && column <= previous)) {
            return Fail(why, "family_phase_split_order");
        }
        previous = column;
    }
    return true;
}

bool SerializeProductionFamilyPhaseDescriptorV1(
    const ProductionFamilyPhaseDescriptorV1& phase,
    std::vector<unsigned char>& out,
    std::string* why)
{
    out.clear();
    if (phase.version != 1 ||
        phase.program_root.IsNull() ||
        phase.current_width == 0 ||
        phase.r0_base_columns.size() >
            phase.current_width ||
        (phase.challenge_width == 0 &&
         phase.challenge_epoch !=
             ProductionChallengeEpochV1::None) ||
        (phase.challenge_width != 0 &&
         phase.challenge_epoch !=
             ProductionChallengeEpochV1::
                 BytecodeP2AfterSafeR0)) {
        return Fail(why, "family_phase_serialize");
    }
    static constexpr char domain[] =
        "BTX_RC_STAGE3_FAMILY_PHASE_DESCRIPTOR_V1";
    out.insert(
        out.end(), domain, domain + sizeof(domain) - 1);
    PutU16(out, phase.version);
    PutU32(out, phase.family_index);
    PutU16(out, static_cast<uint16_t>(phase.kind));
    PutU16(out, static_cast<uint16_t>(phase.role));
    PutUint256(out, phase.program_root);
    PutU32(out, phase.current_width);
    PutU32(out, phase.challenge_width);
    out.push_back(
        static_cast<unsigned char>(
            phase.challenge_epoch));
    PutBool(out, phase.producer_manifest_exported);
    PutU32(
        out,
        static_cast<uint32_t>(
            phase.r0_base_columns.size()));
    for (const uint32_t column :
         phase.r0_base_columns) {
        PutU32(out, column);
    }
    return true;
}

std::vector<alg_hash::Fp>
BuildProductionProgramRegistryAlgHashPreimageV1(
    const ProductionProgramRegistryV1& registry)
{
    return BytesToAlgPreimage(
        REGISTRY_BYTES_DOMAIN,
        RegistryBytes(registry));
}

ProductionProgramRegistryV1 BuildProductionProgramRegistryV1(
    const sites::ProductionProofSiteManifest& manifest,
    const sched::ProductionAggregationSchedule& schedule,
    const std::vector<ProductionFamilyProgramSourceV1>& families,
    const cb::ProgramTable& universal_parent_verifier,
    const cb::ProgramTable& normalized_root_verifier)
{
    ProductionProgramRegistryV1 out;
    std::string why;
    if (!sites::ValidateProductionProofSiteManifest(
            manifest, &why) ||
        !sched::ValidateProductionAggregationSchedule(
            manifest, schedule, &why) ||
        families.size() != manifest.entries.size() ||
        families.size() !=
            kProductionProgramFamilyCountV1 ||
        !cb::ValidateProgramTable(
            universal_parent_verifier, &why) ||
        !cb::ValidateProgramTable(
            normalized_root_verifier, &why) ||
        universal_parent_verifier.role !=
            RCStage3RelationRole::CompositionLink ||
        normalized_root_verifier.role !=
            RCStage3RelationRole::CompositionLink) {
        return out;
    }
    out.site_manifest_commitment = manifest.commitment;
    out.aggregation_schedule_commitment =
        schedule.commitment;
    out.universal_parent_verifier =
        cb::CommitProgramTableForExternalAndRecursiveUse(
            universal_parent_verifier);
    out.normalized_root_verifier =
        cb::CommitProgramTableForExternalAndRecursiveUse(
            normalized_root_verifier);
    out.universal_parent_columns =
        universal_parent_verifier.current_width;
    out.normalized_root_columns =
        normalized_root_verifier.current_width;
    out.exact_family_order = true;
    out.every_program_canonical = true;
    out.every_public_input_schema_bound = true;
    out.every_program_within_column_cap =
        out.universal_parent_columns <=
            kUniversalVerifierColumnCapV1 &&
        out.normalized_root_columns <=
            kUniversalVerifierColumnCapV1;
    out.every_semantic_relation_complete = true;

    std::set<uint16_t> endpoint_union;
    out.families.reserve(families.size());
    for (size_t i = 0; i < families.size(); ++i) {
        const auto& source = families[i];
        const auto& site = manifest.entries[i];
        if (source.family_index != i ||
            source.kind != site.kind ||
            source.role != site.role ||
            source.program.role != site.role ||
            !cb::ValidateProgramTable(source.program, &why) ||
            !ValidateProductionFamilyPhaseDescriptorV1(
                source.program, source.phase,
                /*require_producer_export=*/false, &why) ||
            !std::is_sorted(
                source.semantic_endpoints.begin(),
                source.semantic_endpoints.end()) ||
            std::adjacent_find(
                source.semantic_endpoints.begin(),
                source.semantic_endpoints.end()) !=
                source.semantic_endpoints.end()) {
            return {};
        }
        const auto& role_endpoints =
            RequiredRCStage3RelationEndpoints(source.role);
        for (const uint16_t endpoint :
             source.semantic_endpoints) {
            if (endpoint == 0 || endpoint > 52 ||
                std::find_if(
                    role_endpoints.begin(),
                    role_endpoints.end(),
                    [endpoint](RCStage3RelationEndpoint value) {
                        return static_cast<uint16_t>(value) ==
                            endpoint;
                    }) == role_endpoints.end()) {
                return {};
            }
        }
        ProductionFamilyProgramEntryV1 entry;
        entry.family_index = source.family_index;
        entry.kind = source.kind;
        entry.role = source.role;
        entry.maximum_columns =
            source.program.current_width;
        entry.constraint_count =
            source.program.programs.size();
        entry.maximum_constraint_degree =
            MaxDegree(source.program);
        entry.program =
            cb::CommitProgramTableForExternalAndRecursiveUse(
                source.program);
        entry.public_input_schema =
            CommitCanonicalBytesV1(
                SCHEMA_DOMAIN,
                source.public_input_schema);
        entry.semantic_endpoints =
            source.semantic_endpoints;
        entry.semantic_relation_complete =
            source.semantic_relation_complete;
        out.every_program_canonical =
            out.every_program_canonical &&
            entry.program.same_canonical_serialization &&
            !entry.program.external_sha256d.IsNull() &&
            !AlgDigestZero(
                entry.program.recursive_alg_hash);
        out.every_public_input_schema_bound =
            out.every_public_input_schema_bound &&
            entry.public_input_schema.same_canonical_bytes;
        out.every_program_within_column_cap =
            out.every_program_within_column_cap &&
            entry.maximum_columns <=
                kUniversalVerifierColumnCapV1;
        out.every_semantic_relation_complete =
            out.every_semantic_relation_complete &&
            entry.semantic_relation_complete;
        endpoint_union.insert(
            entry.semantic_endpoints.begin(),
            entry.semantic_endpoints.end());
        out.families.push_back(std::move(entry));
    }
    // Empty endpoint subsets are permitted for helper families, but a
    // production-complete registry must collectively name the exact ABI.
    if (out.every_semantic_relation_complete &&
        (endpoint_union.size() != 52 ||
         *endpoint_union.begin() != 1 ||
         *endpoint_union.rbegin() != 52)) {
        return {};
    }
    SetRegistryCommitments(out);
    if (!RegistryStructurallyValid(
            manifest, schedule, out)) {
        return {};
    }
    return out;
}

ProductionProgramRegistryPublicPinV1
BuildProductionProgramRegistryPublicPinV1(
    const ProductionProgramRegistryV1& registry)
{
    ProductionProgramRegistryPublicPinV1 out;
    if (registry.site_manifest_commitment.IsNull() ||
        registry.aggregation_schedule_commitment.IsNull() ||
        registry.external_registry_commitment.IsNull() ||
        AlgDigestZero(
            registry.recursive_registry_commitment)) {
        return out;
    }
    out.site_manifest_commitment =
        registry.site_manifest_commitment;
    out.aggregation_schedule_commitment =
        registry.aggregation_schedule_commitment;
    out.external_registry_commitment =
        registry.external_registry_commitment;
    out.recursive_registry_commitment =
        registry.recursive_registry_commitment;
    HashWriter hash;
    hash << REGISTRY_PUBLIC_PIN_DOMAIN;
    hash << out.version;
    hash << out.site_manifest_commitment;
    hash << out.aggregation_schedule_commitment;
    hash << out.external_registry_commitment;
    for (Fp value : out.recursive_registry_commitment) {
        hash << gkr_field::Canonical(value);
    }
    hash << out.recursive_alg_hash_is_program_authority;
    hash << out.external_sha256d_is_audit_only;
    out.binding = hash.GetHash();
    return out;
}

ProductionProgramConsensusPinV1
BuildProductionProgramConsensusPinV1(
    const ProductionProgramRegistryV1& registry)
{
    ProductionProgramConsensusPinV1 out;
    const ProductionProgramRegistryPublicPinV1 public_pin =
        BuildProductionProgramRegistryPublicPinV1(registry);
    if (public_pin.binding.IsNull()) return {};

    for (size_t limb_index = 0;
         limb_index < public_pin.recursive_registry_commitment.size();
         ++limb_index) {
        const uint64_t limb = gkr_field::Canonical(
            public_pin.recursive_registry_commitment[limb_index]);
        for (size_t byte_index = 0; byte_index < 8; ++byte_index) {
            out.recursive_alg_hash_root.data()[
                8 * limb_index + byte_index] =
                static_cast<unsigned char>(
                    limb >> (8 * byte_index));
        }
    }
    out.external_sha256d_audit_root =
        public_pin.external_registry_commitment;
    out.registry_binding = public_pin.binding;

    if (!ValidateProductionProgramConsensusPinV1(out)) return {};
    return out;
}

bool ValidateProductionProgramRegistryPublicPinV1(
    const ProductionProgramRegistryV1& registry,
    const ProductionProgramRegistryPublicPinV1& pin,
    const uint256& audit_expected_external_commitment,
    const ah::Digest& consensus_expected_recursive_commitment,
    std::string* why)
{
    if (AlgDigestZero(
            consensus_expected_recursive_commitment) ||
        registry.recursive_registry_commitment !=
            consensus_expected_recursive_commitment ||
        !pin.recursive_alg_hash_is_program_authority ||
        !pin.external_sha256d_is_audit_only) {
        return Fail(why, "public_pin_recursive_authority");
    }
    if (!audit_expected_external_commitment.IsNull() &&
        registry.external_registry_commitment !=
            audit_expected_external_commitment) {
        return Fail(why, "public_pin_external_audit");
    }
    const auto expected =
        BuildProductionProgramRegistryPublicPinV1(
            registry);
    if (expected.binding.IsNull() ||
        pin != expected) {
        return Fail(why, "public_pin_substitution");
    }
    return true;
}

bool ValidateProductionProgramRegistryV1(
    const sites::ProductionProofSiteManifest& manifest,
    const sched::ProductionAggregationSchedule& schedule,
    const ProductionProgramRegistryV1& registry,
    const uint256& expected_external_commitment,
    const ah::Digest& expected_recursive_commitment,
    std::string* why)
{
    if (!RegistryStructurallyValid(
            manifest, schedule, registry)) {
        return Fail(why, "registry_structure");
    }
    if (expected_external_commitment.IsNull() ||
        AlgDigestZero(expected_recursive_commitment) ||
        registry.external_registry_commitment !=
            expected_external_commitment ||
        registry.recursive_registry_commitment !=
            expected_recursive_commitment) {
        return Fail(why, "registry_not_root_pinned");
    }
    return true;
}

UniversalTopologyAssessmentV1
AssessUniversalProductionTopologyV1(
    const sites::ProductionProofSiteManifest& manifest,
    const sched::ProductionAggregationSchedule& schedule,
    const ProductionProgramRegistryV1& registry)
{
    UniversalTopologyAssessmentV1 out;
    std::string why;
    out.exact_schedule_manifest_derived =
        sites::ValidateProductionProofSiteManifest(
            manifest, &why) &&
        sched::ValidateProductionAggregationSchedule(
            manifest, schedule, &why) &&
        manifest.relation_leaf_sites ==
            schedule.relation_leaf_sites &&
        manifest.below_root_aggregation_sites ==
            schedule.below_root_parent_sites &&
        manifest.final_tree_aggregation_sites ==
            schedule.final_tree_parent_sites &&
        manifest.total_proof_sites ==
            schedule.total_proof_sites;
    out.relation_leaf_sites =
        manifest.relation_leaf_sites;
    out.arity_four_parent_sites =
        manifest.below_root_aggregation_sites;
    out.final_tree_parent_sites =
        manifest.final_tree_aggregation_sites;
    out.exact_total_sites =
        manifest.total_proof_sites;
    out.shard_proof_instances =
        manifest.total_proof_sites;
    out.shard_coverage_and_recursion_events =
        manifest.total_proof_sites;
    out.family_batched_leaf_proof_instances =
        manifest.entries.size();
    uint64_t family_parent_instances{0};
    for (const auto& role_plan : schedule.roles) {
        uint64_t width = static_cast<uint64_t>(
            std::count_if(
                manifest.entries.begin(), manifest.entries.end(),
                [&](const sites::ProductionProofSiteEntry& entry) {
                    return entry.role == role_plan.role;
                }));
        while (width > 1) {
            width = width / schedule.arity +
                    static_cast<uint64_t>(
                        width % schedule.arity != 0);
            family_parent_instances += width;
        }
    }
    out.family_batched_parent_proof_instances =
        family_parent_instances +
        manifest.final_tree_aggregation_sites;
    out.family_batched_total_proof_instances =
        out.family_batched_leaf_proof_instances +
        out.family_batched_parent_proof_instances;
    if (out.exact_total_sites <=
        std::numeric_limits<uint64_t>::max() /
            (kDeprecatedWidthLeafShardsV1 +
             kDeprecatedWidthParentsV1)) {
        out.rejected_product_site_diagnostic =
            out.exact_total_sites *
            (kDeprecatedWidthLeafShardsV1 +
             kDeprecatedWidthParentsV1);
    }
    out.one_program_selector_per_family =
        RegistryStructurallyValid(
            manifest, schedule, registry);
    out.parent_is_constant_width_universal_program =
        out.one_program_selector_per_family &&
        registry.universal_parent_columns <=
            kUniversalVerifierColumnCapV1;
    out.normalized_root_is_constant_width_program =
        out.one_program_selector_per_family &&
        registry.normalized_root_columns <=
            kUniversalVerifierColumnCapV1;
    out.width_shards_are_not_site_multiplicity =
        out.exact_schedule_manifest_derived &&
        out.parent_is_constant_width_universal_program &&
        out.normalized_root_is_constant_width_program;
    out.registry_is_root_pinnable =
        out.one_program_selector_per_family;
    out.semantic_programs_complete =
        registry.every_semantic_relation_complete;
    // The registry and selectors execute natively, but the recursive AIR
    // does not yet replay the universal interpreter/child verifier.
    out.recursive_program_selection_executable = false;
    // Family batching would retain every row/constraint event in the global
    // soundness ledger while amortizing commitments, quotient construction,
    // and FRI over each family. No current primitive proves a shard-indexed
    // disjoint union with one quotient/FRI proof, so this remains an explicit
    // economic alternative rather than silently replacing the exact topology.
    out.family_batched_single_quotient_fri_executable = false;
    out.family_batched_candidate_selectable = false;
    out.shard_tree_economically_production_candidate = false;
    out.production_topology_enforced = false;
    out.note =
        out.width_shards_are_not_site_multiplicity
            ? "stage3:universal_topology:exact_heterogeneous_site_count;"
              "program_selection_recursive_execution_pending;"
              "family_batching_requires_single_quotient_fri_backend"
            : "stage3:universal_topology:incomplete_registry_or_schedule";
    return out;
}

UniversalStatementBindingV1 BindUniversalLeafStatementV1(
    const sites::ProductionProofSiteManifest& manifest,
    const sched::ProductionAggregationSchedule& schedule,
    const ProductionProgramRegistryV1& registry,
    const UniversalLeafSelectorV1& selector,
    std::string* why)
{
    UniversalStatementBindingV1 out;
    if (!RegistryStructurallyValid(
            manifest, schedule, registry) ||
        selector.version != kUniversalStatementVersionV1 ||
        selector.unified_root_seed.IsNull() ||
        selector.registry_external_commitment !=
            registry.external_registry_commitment ||
        selector.registry_recursive_commitment !=
            registry.recursive_registry_commitment ||
        selector.public_input_commitment.IsNull() ||
        AlgDigestZero(selector.trace_commitment)) {
        Fail(why, "leaf_header");
        return out;
    }
    const auto* entry =
        FamilyEntry(registry, selector.family_index);
    const auto* range =
        FamilyRange(schedule, selector.family_index);
    if (entry == nullptr || range == nullptr ||
        selector.family_local_site >= range->leaf_count ||
        selector.global_leaf_site !=
            range->first_leaf_site +
                selector.family_local_site ||
        selector.global_leaf_site >=
            schedule.relation_leaf_sites ||
        entry->kind != range->kind ||
        entry->role != range->role) {
        Fail(why, "leaf_selector");
        return out;
    }
    std::vector<unsigned char> bytes;
    PutU16(bytes, selector.version);
    PutUint256(bytes, selector.unified_root_seed);
    PutUint256(bytes, manifest.commitment);
    PutUint256(bytes, schedule.commitment);
    PutUint256(
        bytes, registry.external_registry_commitment);
    PutAlgDigest(
        bytes, registry.recursive_registry_commitment);
    PutU32(bytes, selector.family_index);
    PutU16(bytes, static_cast<uint16_t>(entry->kind));
    PutU16(bytes, static_cast<uint16_t>(entry->role));
    PutU64(bytes, selector.global_leaf_site);
    PutU64(bytes, selector.family_local_site);
    PutUint256(bytes, entry->program.external_sha256d);
    PutAlgDigest(bytes, entry->program.recursive_alg_hash);
    PutUint256(
        bytes,
        entry->public_input_schema.external_sha256d);
    PutAlgDigest(
        bytes,
        entry->public_input_schema.recursive_alg_hash);
    PutUint256(bytes, selector.public_input_commitment);
    PutAlgDigest(bytes, selector.trace_commitment);
    out = CommitStatement(LEAF_STATEMENT_DOMAIN, bytes);
    out.program_and_schema_resolved_from_registry = true;
    out.manifest_schedule_and_site_bound = true;
    out.public_inputs_bound = true;
    return out;
}

UniversalStatementBindingV1 BindUniversalParentStatementV1(
    const sites::ProductionProofSiteManifest& manifest,
    const sched::ProductionAggregationSchedule& schedule,
    const ProductionProgramRegistryV1& registry,
    const UniversalParentSelectorV1& selector,
    std::string* why)
{
    UniversalStatementBindingV1 out;
    if (!RegistryStructurallyValid(
            manifest, schedule, registry) ||
        selector.version != kUniversalStatementVersionV1 ||
        selector.unified_root_seed.IsNull() ||
        selector.registry_external_commitment !=
            registry.external_registry_commitment ||
        selector.registry_recursive_commitment !=
            registry.recursive_registry_commitment ||
        selector.public_input_commitment.IsNull()) {
        Fail(why, "parent_header");
        return out;
    }
    const auto work =
        sched::ProductionAggregationParentWorkItem(
            schedule,
            selector.unified_root_seed,
            selector.parent_ordinal,
            why);
    if (!work.has_value() ||
        selector.child_receipt_roots.size() !=
            work->child_count ||
        std::any_of(
            selector.child_receipt_roots.begin(),
            selector.child_receipt_roots.end(),
            AlgDigestZero)) {
        Fail(why, "parent_selector");
        return out;
    }
    std::vector<unsigned char> bytes;
    PutU16(bytes, selector.version);
    PutUint256(bytes, selector.unified_root_seed);
    PutUint256(bytes, manifest.commitment);
    PutUint256(bytes, schedule.commitment);
    PutUint256(
        bytes, registry.external_registry_commitment);
    PutAlgDigest(
        bytes, registry.recursive_registry_commitment);
    PutU64(bytes, selector.parent_ordinal);
    PutU16(bytes, static_cast<uint16_t>(work->role));
    PutU32(bytes, work->level);
    PutU64(bytes, work->parent_site);
    PutU64(bytes, work->first_child_site);
    PutU32(bytes, work->child_count);
    PutUint256(bytes, work->seed);
    PutUint256(
        bytes,
        registry.universal_parent_verifier
            .external_sha256d);
    PutAlgDigest(
        bytes,
        registry.universal_parent_verifier
            .recursive_alg_hash);
    PutUint256(bytes, selector.public_input_commitment);
    PutU32(bytes, selector.child_receipt_roots.size());
    for (const auto& root : selector.child_receipt_roots) {
        PutAlgDigest(bytes, root);
    }
    out = CommitStatement(PARENT_STATEMENT_DOMAIN, bytes);
    out.program_and_schema_resolved_from_registry = true;
    out.manifest_schedule_and_site_bound = true;
    out.public_inputs_bound = true;
    return out;
}

} // namespace matmul::v4::rc::universal_topology
