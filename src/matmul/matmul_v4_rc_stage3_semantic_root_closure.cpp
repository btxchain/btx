// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_semantic_root_closure.h>

#include <matmul/matmul_v4_rc_stage3_ctl.h>
#include <matmul/matmul_v4_rc_stage3_provenance_graph.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>

#include <hash.h>

#include <algorithm>
#include <limits>
#include <set>
#include <utility>

namespace matmul::v4::rc::semantic_root_closure {
namespace {

using gf::Fp3;

constexpr char kManifestDomain[] =
    "BTX_RC_STAGE3_SEMANTIC_ROOT_CLOSURE_MANIFEST_V1";
constexpr char kReceiptDomain[] =
    "BTX_RC_STAGE3_SEMANTIC_ROOT_RECEIPT_STATEMENT_V1";

bool Fail(std::string* why, const std::string& reason)
{
    if (why != nullptr) {
        *why = "stage3:semantic_root_closure:" + reason;
    }
    return false;
}

std::array<uint32_t, kSemanticRootU32WordsV1>
Uint256Words(const uint256& value)
{
    std::array<uint32_t, kSemanticRootU32WordsV1> out{};
    for (uint32_t word = 0; word < out.size(); ++word) {
        const uint32_t offset = 4U * word;
        out[word] =
            static_cast<uint32_t>(value.begin()[offset]) |
            (static_cast<uint32_t>(value.begin()[offset + 1]) << 8) |
            (static_cast<uint32_t>(value.begin()[offset + 2]) << 16) |
            (static_cast<uint32_t>(value.begin()[offset + 3]) << 24);
    }
    return out;
}

std::array<uint32_t, kSemanticRootU32WordsV1>
AlgDigestWords(const ah::Digest& value)
{
    std::array<uint32_t, kSemanticRootU32WordsV1> out{};
    for (uint32_t lane = 0; lane < value.size(); ++lane) {
        const uint64_t canonical =
            static_cast<uint64_t>(gf::Canonical(value[lane]));
        out[2U * lane] = static_cast<uint32_t>(canonical);
        out[2U * lane + 1U] =
            static_cast<uint32_t>(canonical >> 32);
    }
    return out;
}

template <size_t N>
void HashWords(HashWriter& hash, const std::array<uint32_t, N>& words)
{
    for (const uint32_t word : words) hash << word;
}

bool AllZero(const std::array<uint32_t, kSemanticRootU32WordsV1>& words)
{
    return std::all_of(
        words.begin(), words.end(),
        [](uint32_t word) { return word == 0; });
}

uint32_t NextPowerOfTwo(uint32_t value)
{
    uint32_t out = 2;
    while (out < value) {
        if (out >
            std::numeric_limits<uint32_t>::max() / 2U) {
            return 0;
        }
        out *= 2U;
    }
    return out;
}

bool IsStructuralStub(
    const topo::ProductionFamilyProgramSourceV1& source)
{
    namespace cb = constraint_bytecode;
    return
        !source.semantic_relation_complete &&
        source.semantic_endpoints.empty() &&
        source.program.current_width == 1 &&
        source.program.next_width == 1 &&
        source.program.programs.size() == 1 &&
        source.program.programs[0].instructions.size() == 1 &&
        source.program.programs[0].instructions[0].opcode ==
            cb::Opcode::Current;
}

const RCStage3SemanticEndpointStatus* FindSemantic(
    const RCStage3SemanticStatus& status,
    RCStage3RelationEndpoint endpoint)
{
    const auto found = std::find_if(
        status.endpoints.begin(), status.endpoints.end(),
        [endpoint](const RCStage3SemanticEndpointStatus& value) {
            return value.endpoint == endpoint;
        });
    return found == status.endpoints.end() ? nullptr : &*found;
}

const RCStage3RelationEndpointCellAudit* FindCell(
    const std::vector<RCStage3RelationEndpointCellAudit>& cells,
    RCStage3RelationEndpoint endpoint)
{
    const auto found = std::find_if(
        cells.begin(), cells.end(),
        [endpoint](const RCStage3RelationEndpointCellAudit& value) {
            return value.endpoint == endpoint;
        });
    return found == cells.end() ? nullptr : &*found;
}

const RCStage3ProvenanceNode* FindProvenance(
    const RCStage3ProvenanceGraphAudit& graph,
    RCStage3RelationEndpoint endpoint)
{
    const auto found = std::find_if(
        graph.nodes.begin(), graph.nodes.end(),
        [endpoint](const RCStage3ProvenanceNode& value) {
            return value.endpoint == endpoint;
        });
    return found == graph.nodes.end() ? nullptr : &*found;
}

const topo::ProductionFamilyProgramSourceV1* FindExactFamily(
    const std::vector<topo::ProductionFamilyProgramSourceV1>& sources,
    RCStage3RelationEndpoint endpoint,
    RCStage3RelationRole role,
    bool& duplicate)
{
    duplicate = false;
    const topo::ProductionFamilyProgramSourceV1* out = nullptr;
    const uint16_t id = static_cast<uint16_t>(endpoint);
    for (const auto& source : sources) {
        if (!source.semantic_relation_complete ||
            source.role != role ||
            std::find(
                source.semantic_endpoints.begin(),
                source.semantic_endpoints.end(),
                id) == source.semantic_endpoints.end()) {
            continue;
        }
        if (out != nullptr) {
            duplicate = true;
            return nullptr;
        }
        out = &source;
    }
    return out;
}

std::string MissingDescription(
    const SemanticRootEndpointManifestV1& endpoint)
{
    std::string out;
    const auto add = [&out](const char* value) {
        if (!out.empty()) out += ",";
        out += value;
    };
    if (endpoint.missing_sources &
        MissingExactProgramTableV1) {
        add("canonical ProgramTable semantic_endpoints has no exact key");
    }
    if (endpoint.missing_sources &
        MissingRelationProofCellV1) {
        add("relation proof exports no immutable endpoint cell");
    }
    if (endpoint.missing_sources &
        MissingSameTraceCtlValueAliasV1) {
        add("no same-trace relation-cell to CTL::VALUE equality");
    }
    if (endpoint.missing_sources &
        MissingRecursiveProvenanceEqualityV1) {
        add("provenance edge has no normalized recursive equality cell");
    }
    if (endpoint.missing_sources &
        MissingChildReceiptAcceptanceCellV1) {
        add("normalized parent exports no endpoint child-acceptance cell");
    }
    if (endpoint.missing_sources &
        MissingTransitiveSemanticClosureV1) {
        add("strict local+producer semantic closure is incomplete");
    }
    if (endpoint.missing_sources &
        MissingRecursiveCtlRationalIdentityV1) {
        add("recursive receipt does not own the ordered CTL tuple, "
            "multiplicity/domain, post-commit denominators, and global "
            "zero terminal identity");
    }
    return out;
}

bool ManifestShapeValid(
    const SemanticRootClosureManifestV1& manifest,
    std::string* why)
{
    if (manifest.version != kSemanticRootClosureVersionV1 ||
        manifest.roles.size() !=
            kRCStage3RelationClosureRoleCount ||
        manifest.endpoints.size() !=
            kRCStage3RelationClosureEndpointCount ||
        manifest.production_site_manifest_commitment.IsNull() ||
        manifest.closure_commitment.IsNull()) {
        return Fail(why, "manifest_shape");
    }
    const auto& roles = RCStage3UnifiedRoleOrder();
    std::set<uint16_t> seen_endpoints;
    std::set<uint32_t> seen_exact_families;
    uint32_t endpoint_cursor = 0;
    for (uint32_t role_index = 0;
         role_index < roles.size(); ++role_index) {
        const auto& role = manifest.roles[role_index];
        const auto& required =
            RequiredRCStage3RelationEndpoints(roles[role_index]);
        if (role.role != roles[role_index] ||
            role.first_endpoint_index != endpoint_cursor ||
            role.endpoint_count != required.size()) {
            return Fail(why, "role_order");
        }
        for (uint32_t local = 0;
             local < required.size(); ++local, ++endpoint_cursor) {
            const auto& endpoint =
                manifest.endpoints[endpoint_cursor];
            const uint16_t id =
                static_cast<uint16_t>(endpoint.endpoint);
            if (endpoint.endpoint != required[local] ||
                endpoint.role != role.role ||
                endpoint.role_ordinal != role_index ||
                endpoint.endpoint_ordinal != local ||
                !seen_endpoints.insert(id).second) {
                return Fail(why, "endpoint_order");
            }
            if (endpoint.exact_program_table) {
                if (endpoint.family_index ==
                        kSemanticRootNoFamilyV1 ||
                    AllZero(
                        endpoint
                            .program_external_sha256d_words) ||
                    AllZero(
                        endpoint
                            .program_recursive_alg_hash_words) ||
                    !seen_exact_families.insert(
                        endpoint.family_index).second) {
                    return Fail(why, "exact_program_key");
                }
            } else if (
                endpoint.family_index !=
                    kSemanticRootNoFamilyV1 ||
                !AllZero(
                    endpoint
                        .program_external_sha256d_words) ||
                !AllZero(
                    endpoint
                        .program_recursive_alg_hash_words)) {
                return Fail(why, "unclaimed_program_key");
            }
            if (endpoint.ctl.relation_value_same_trace &&
                (!endpoint.relation_proof_cell ||
                 endpoint.ctl.namespace_column !=
                     stage3_ctl_degree2_col::NAMESPACE ||
                 endpoint.ctl.stage_column !=
                     stage3_ctl_degree2_col::STAGE ||
                 endpoint.ctl.address_column !=
                     stage3_ctl_degree2_col::ADDRESS ||
                 endpoint.ctl.value_column !=
                     stage3_ctl_degree2_col::VALUE ||
                 endpoint.ctl.multiplicity_column !=
                     stage3_ctl_degree2_col::MULTIPLICITY ||
                 endpoint.ctl.inverse_alpha1_column !=
                     stage3_ctl_degree2_col::INVERSE1 ||
                 endpoint.ctl.inverse_alpha2_column !=
                     stage3_ctl_degree2_col::INVERSE2 ||
                 endpoint.ctl.running_alpha1_column !=
                     stage3_ctl_degree2_col::RUNNING1 ||
                 endpoint.ctl.running_alpha2_column !=
                     stage3_ctl_degree2_col::RUNNING2 ||
                 !endpoint.ctl.last_row ||
                 !endpoint.ctl.tuple_columns_owned ||
                 !endpoint.ctl
                      .ordered_schedule_and_multiplicity_pinned ||
                 !endpoint.ctl.post_commit_challenges_bound ||
                 !endpoint.ctl
                      .denominators_nonzero_constrained)) {
                return Fail(why, "ctl_descriptor");
            }
            if (endpoint.ctl.recursive_rational_identity_consumed &&
                (!endpoint.ctl.relation_value_same_trace ||
                 !endpoint.ctl.global_terminal_zero_consumed)) {
                return Fail(why, "ctl_recursive_overclaim");
            }
        }
    }
    if (endpoint_cursor != manifest.endpoints.size()) {
        return Fail(why, "endpoint_count");
    }
    return true;
}

SemanticRootClosureAirLayoutV1 MakeAirLayout()
{
    SemanticRootClosureAirLayoutV1 out;
    uint32_t column = 0;
    out.claimed_endpoint = column++;
    out.claimed_role = column++;
    out.claimed_role_ordinal = column++;
    out.claimed_endpoint_ordinal = column++;
    out.claimed_family_index = column++;
    out.claimed_proof_site_kind = column++;
    out.claimed_relation_column = column++;
    out.claimed_missing_sources = column++;
    out.claimed_program_external_base = column;
    column += kSemanticRootU32WordsV1;
    out.claimed_program_recursive_base = column;
    column += kSemanticRootU32WordsV1;
    out.expected_active = column++;
    out.expected_endpoint = column++;
    out.expected_role = column++;
    out.expected_role_ordinal = column++;
    out.expected_endpoint_ordinal = column++;
    out.expected_family_index = column++;
    out.expected_proof_site_kind = column++;
    out.expected_relation_column = column++;
    out.expected_missing_sources = column++;
    out.expected_program_external_base = column;
    column += kSemanticRootU32WordsV1;
    out.expected_program_recursive_base = column;
    column += kSemanticRootU32WordsV1;
    out.total_columns = column;
    return out;
}

void AddExactColumnConstraint(
    aq::AirConstraintSystem<Fp3>& cs,
    uint32_t claimed,
    uint32_t expected,
    const char* name)
{
    cs.constraints.push_back({
        name,
        aq::AirKind::kEverywhere,
        1,
        [claimed, expected](
            const std::vector<Fp3>& current,
            const std::vector<Fp3>&) {
            return gf::Sub(
                current[claimed],
                current[expected]);
        }});
}

} // namespace

SemanticRootClosureManifestV1
BuildSemanticRootClosureManifestV1(
    const RCStage3CoupledShape& shape,
    const gf::Fp3& gamma,
    const gf::Fp3& alpha,
    uint8_t extract_scale_e,
    bool production_mode)
{
    SemanticRootClosureManifestV1 out;
    const sites::ProductionProofSiteManifest site_manifest =
        sites::BuildProductionProofSiteManifest(
            sites::SelectedProductionProofSitePolicy());
    const auto sources =
        topo::BuildProductionFamilyProgramSourcesV1(
            site_manifest);
    const auto migration =
        topo::AssessProductionFamilyProgramMigrationV1(
            sources);
    const auto semantic = CurrentRCStage3SemanticStatus(
        shape, gamma, alpha, extract_scale_e,
        production_mode);
    const auto cells =
        CurrentRCStage3RelationEndpointCellAudit();
    const auto provenance =
        CurrentRCStage3ProvenanceGraphAudit();
    std::string why;
    out.production_registry_canonical =
        sites::ValidateProductionProofSiteManifest(
            site_manifest, &why) &&
        topo::ValidateProductionFamilyProgramSourcesV1(
            site_manifest, sources, &why);
    out.no_structural_stub_claims =
        migration.families_structural_stubs == 0;
    out.production_site_manifest_commitment =
        site_manifest.commitment;

    const auto& role_order = RCStage3UnifiedRoleOrder();
    out.roles.reserve(role_order.size());
    out.endpoints.reserve(
        kRCStage3RelationClosureEndpointCount);
    uint32_t endpoint_index = 0;
    for (uint32_t role_index = 0;
         role_index < role_order.size(); ++role_index) {
        SemanticRootRoleManifestV1 role;
        role.role = role_order[role_index];
        role.first_endpoint_index = endpoint_index;
        const auto& required =
            RequiredRCStage3RelationEndpoints(role.role);
        role.endpoint_count =
            static_cast<uint32_t>(required.size());
        for (uint32_t local = 0;
             local < required.size(); ++local, ++endpoint_index) {
            SemanticRootEndpointManifestV1 endpoint;
            endpoint.endpoint = required[local];
            endpoint.role = role.role;
            endpoint.role_ordinal = role_index;
            endpoint.endpoint_ordinal = local;
            endpoint.provenance_node_index =
                static_cast<uint32_t>(
                    static_cast<uint16_t>(
                        endpoint.endpoint) - 1U);

            bool duplicate_family{false};
            const auto* family = FindExactFamily(
                sources, endpoint.endpoint,
                endpoint.role, duplicate_family);
            if (family != nullptr && !duplicate_family &&
                !IsStructuralStub(*family)) {
                const auto keys =
                    constraint_bytecode::
                        CommitProgramTableForExternalAndRecursiveUse(
                            family->program);
                endpoint.family_index =
                    family->family_index;
                endpoint.proof_site_kind =
                    family->kind;
                endpoint.program_external_sha256d_words =
                    Uint256Words(keys.external_sha256d);
                endpoint.program_recursive_alg_hash_words =
                    AlgDigestWords(keys.recursive_alg_hash);
                endpoint.exact_program_table =
                    keys.same_canonical_serialization;
            }

            const auto* cell = FindCell(
                cells, endpoint.endpoint);
            if (cell != nullptr) {
                endpoint.relation_proof_cell =
                    cell->relation_air_cell;
                endpoint.relation_column =
                    cell->relation_air_cell
                    ? cell->relation_column
                    : kSemanticRootNoColumnV1;
                endpoint.relation_source = cell->source;
                if (cell->same_trace_ctl_alias) {
                    endpoint.ctl.ctl_layout_version =
                        kRCStage3CtlDegree2Version;
                    endpoint.ctl.namespace_column =
                        stage3_ctl_degree2_col::NAMESPACE;
                    endpoint.ctl.stage_column =
                        stage3_ctl_degree2_col::STAGE;
                    endpoint.ctl.address_column =
                        stage3_ctl_degree2_col::ADDRESS;
                    endpoint.ctl.value_column =
                        stage3_ctl_degree2_col::VALUE;
                    endpoint.ctl.multiplicity_column =
                        stage3_ctl_degree2_col::MULTIPLICITY;
                    endpoint.ctl.inverse_alpha1_column =
                        stage3_ctl_degree2_col::INVERSE1;
                    endpoint.ctl.inverse_alpha2_column =
                        stage3_ctl_degree2_col::INVERSE2;
                    endpoint.ctl.running_alpha1_column =
                        stage3_ctl_degree2_col::RUNNING1;
                    endpoint.ctl.running_alpha2_column =
                        stage3_ctl_degree2_col::RUNNING2;
                    endpoint.ctl.last_row = true;
                    endpoint.ctl.relation_value_same_trace =
                        true;
                    // These properties are constraints of the complete local
                    // degree-two direct product. They do not imply the
                    // normalized parent consumed its result.
                    endpoint.ctl.tuple_columns_owned = true;
                    endpoint.ctl
                        .ordered_schedule_and_multiplicity_pinned =
                        true;
                    endpoint.ctl.post_commit_challenges_bound =
                        true;
                    endpoint.ctl
                        .denominators_nonzero_constrained =
                        true;
                }
            }

            const auto* node = FindProvenance(
                provenance, endpoint.endpoint);
            if (node != nullptr) {
                endpoint.provenance_producer_count =
                    static_cast<uint32_t>(
                        node->producers.size());
                endpoint.recursive_provenance_equality =
                    !node->public_root &&
                    !node->producers.empty() &&
                     std::all_of(
                         node->producers.begin(),
                         node->producers.end(),
                         [](const RCStage3ProvenanceEdge& edge) {
                             return edge
                                 .normalized_recursive_executable;
                         });
            }

            const auto* status = FindSemantic(
                semantic, endpoint.endpoint);
            if (status != nullptr) {
                endpoint.local_relation_complete =
                    status->local_relation_complete;
                endpoint.producer_provenance_complete =
                    status->producer_provenance_complete;
                endpoint.semantic_complete =
                    status->semantic_complete;
                endpoint.recursively_consumed =
                    status->recursively_consumed;
                // Recursive consumption is the only current evidence of an
                // endpoint-specific child acceptance cell. A local verifier
                // bool or a receipt hash is not a parent AIR cell.
                endpoint.child_receipt_acceptance_cell =
                    status->recursively_consumed;
                // No current status record can certify the stronger LogUp
                // rational identity by a terminal digest alone. Recursive
                // consumption is necessary, but the explicit global-zero
                // terminal cell is still absent, so this remains false.
                endpoint.ctl
                    .recursive_rational_identity_consumed =
                    false;
            }

            if (!endpoint.exact_program_table) {
                endpoint.missing_sources |=
                    MissingExactProgramTableV1;
            }
            if (!endpoint.relation_proof_cell) {
                endpoint.missing_sources |=
                    MissingRelationProofCellV1;
            }
            if (!endpoint.ctl.relation_value_same_trace) {
                endpoint.missing_sources |=
                    MissingSameTraceCtlValueAliasV1;
            }
            if (!endpoint.recursive_provenance_equality) {
                endpoint.missing_sources |=
                    MissingRecursiveProvenanceEqualityV1;
            }
            if (!endpoint.child_receipt_acceptance_cell) {
                endpoint.missing_sources |=
                    MissingChildReceiptAcceptanceCellV1;
            }
            if (!endpoint.semantic_complete) {
                endpoint.missing_sources |=
                    MissingTransitiveSemanticClosureV1;
            }
            if (!endpoint.ctl
                     .recursive_rational_identity_consumed) {
                endpoint.missing_sources |=
                    MissingRecursiveCtlRationalIdentityV1;
            }
            endpoint.exact_missing_source =
                MissingDescription(endpoint);

            role.exact_program_endpoints +=
                endpoint.exact_program_table;
            role.ctl_value_alias_endpoints +=
                endpoint.ctl.relation_value_same_trace;
            role.semantic_complete_endpoints +=
                endpoint.semantic_complete;
            role.recursively_consumed_endpoints +=
                endpoint.recursively_consumed;
            out.exact_program_endpoints +=
                endpoint.exact_program_table;
            out.relation_proof_cell_endpoints +=
                endpoint.relation_proof_cell;
            out.same_trace_ctl_value_endpoints +=
                endpoint.ctl.relation_value_same_trace;
            out.recursive_provenance_endpoints +=
                endpoint.recursive_provenance_equality;
            out.child_receipt_acceptance_endpoints +=
                endpoint.child_receipt_acceptance_cell;
            out.semantic_complete_endpoints +=
                endpoint.semantic_complete;
            out.recursively_consumed_endpoints +=
                endpoint.recursively_consumed;
            out.endpoints.push_back(std::move(endpoint));
        }
        role.complete =
            role.endpoint_count != 0 &&
            role.exact_program_endpoints ==
                role.endpoint_count &&
            role.ctl_value_alias_endpoints ==
                role.endpoint_count &&
            role.semantic_complete_endpoints ==
                role.endpoint_count &&
            role.recursively_consumed_endpoints ==
                role.endpoint_count;
        out.complete_roles += role.complete;
        out.roles.push_back(role);
    }

    out.exact_role_order =
        out.roles.size() ==
            kRCStage3RelationClosureRoleCount;
    out.exact_endpoint_order =
        out.endpoints.size() ==
            kRCStage3RelationClosureEndpointCount;
    for (uint32_t index = 0;
         index < out.endpoints.size(); ++index) {
        out.exact_endpoint_order =
            out.exact_endpoint_order &&
            static_cast<uint16_t>(
                out.endpoints[index].endpoint) ==
                index + 1U;
    }
    out.canonical_u32_commitment = true;
    out.local_inventory_complete =
        out.exact_role_order &&
        out.exact_endpoint_order &&
        out.production_registry_canonical &&
        out.no_structural_stub_claims;
    out.recursive_semantic_closure_complete =
        out.local_inventory_complete &&
        out.complete_roles == out.roles.size() &&
        out.semantic_complete_endpoints ==
            out.endpoints.size() &&
        out.recursively_consumed_endpoints ==
            out.endpoints.size();
    out.production_authority =
        out.recursive_semantic_closure_complete;
    for (const auto& endpoint : out.endpoints) {
        if (endpoint.missing_sources != 0) {
            out.residuals.push_back(
                std::to_string(
                    static_cast<uint16_t>(
                        endpoint.endpoint)) +
                ":" + endpoint.exact_missing_source);
        }
    }
    out.closure_commitment =
        ComputeSemanticRootClosureCommitmentV1(out);
    return out;
}

uint256 ComputeSemanticRootClosureCommitmentV1(
    const SemanticRootClosureManifestV1& manifest)
{
    HashWriter hash;
    hash << kManifestDomain;
    hash << manifest.version;
    hash << manifest.production_site_manifest_commitment;
    hash << static_cast<uint32_t>(manifest.roles.size());
    for (const auto& role : manifest.roles) {
        hash << static_cast<uint16_t>(role.role);
        hash << role.first_endpoint_index;
        hash << role.endpoint_count;
        hash << role.exact_program_endpoints;
        hash << role.ctl_value_alias_endpoints;
        hash << role.semantic_complete_endpoints;
        hash << role.recursively_consumed_endpoints;
        hash << static_cast<uint8_t>(role.complete);
    }
    hash << static_cast<uint32_t>(
        manifest.endpoints.size());
    for (const auto& endpoint : manifest.endpoints) {
        hash << static_cast<uint16_t>(endpoint.endpoint);
        hash << static_cast<uint16_t>(endpoint.role);
        hash << endpoint.role_ordinal;
        hash << endpoint.endpoint_ordinal;
        hash << endpoint.family_index;
        hash << static_cast<uint8_t>(
            endpoint.proof_site_kind);
        HashWords(
            hash,
            endpoint.program_external_sha256d_words);
        HashWords(
            hash,
            endpoint.program_recursive_alg_hash_words);
        hash << static_cast<uint8_t>(
            endpoint.exact_program_table);
        hash << endpoint.relation_column;
        hash << static_cast<uint8_t>(
            endpoint.relation_proof_cell);
        hash << endpoint.ctl.ctl_layout_version;
        hash << endpoint.ctl.namespace_column;
        hash << endpoint.ctl.stage_column;
        hash << endpoint.ctl.address_column;
        hash << endpoint.ctl.value_column;
        hash << endpoint.ctl.multiplicity_column;
        hash << endpoint.ctl.inverse_alpha1_column;
        hash << endpoint.ctl.inverse_alpha2_column;
        hash << endpoint.ctl.running_alpha1_column;
        hash << endpoint.ctl.running_alpha2_column;
        hash << static_cast<uint8_t>(
            endpoint.ctl.last_row);
        hash << static_cast<uint8_t>(
            endpoint.ctl.relation_value_same_trace);
        hash << static_cast<uint8_t>(
            endpoint.ctl.tuple_columns_owned);
        hash << static_cast<uint8_t>(
            endpoint.ctl
                .ordered_schedule_and_multiplicity_pinned);
        hash << static_cast<uint8_t>(
            endpoint.ctl.post_commit_challenges_bound);
        hash << static_cast<uint8_t>(
            endpoint.ctl.denominators_nonzero_constrained);
        hash << static_cast<uint8_t>(
            endpoint.ctl.global_terminal_zero_consumed);
        hash << static_cast<uint8_t>(
            endpoint.ctl
                .recursive_rational_identity_consumed);
        hash << endpoint.provenance_node_index;
        hash << endpoint.provenance_producer_count;
        hash << static_cast<uint8_t>(
            endpoint.recursive_provenance_equality);
        hash << static_cast<uint8_t>(
            endpoint.child_receipt_acceptance_cell);
        hash << static_cast<uint8_t>(
            endpoint.local_relation_complete);
        hash << static_cast<uint8_t>(
            endpoint.producer_provenance_complete);
        hash << static_cast<uint8_t>(
            endpoint.semantic_complete);
        hash << static_cast<uint8_t>(
            endpoint.recursively_consumed);
        hash << endpoint.missing_sources;
    }
    hash << manifest.exact_program_endpoints;
    hash << manifest.relation_proof_cell_endpoints;
    hash << manifest.same_trace_ctl_value_endpoints;
    hash << manifest.recursive_provenance_endpoints;
    hash << manifest.child_receipt_acceptance_endpoints;
    hash << manifest.semantic_complete_endpoints;
    hash << manifest.recursively_consumed_endpoints;
    hash << manifest.complete_roles;
    hash << static_cast<uint8_t>(
        manifest.exact_role_order);
    hash << static_cast<uint8_t>(
        manifest.exact_endpoint_order);
    hash << static_cast<uint8_t>(
        manifest.production_registry_canonical);
    hash << static_cast<uint8_t>(
        manifest.no_structural_stub_claims);
    hash << static_cast<uint8_t>(
        manifest.canonical_u32_commitment);
    hash << static_cast<uint8_t>(
        manifest.local_inventory_complete);
    hash << static_cast<uint8_t>(
        manifest.recursive_semantic_closure_complete);
    hash << static_cast<uint8_t>(
        manifest.production_authority);
    return hash.GetHash();
}

bool ValidateSemanticRootClosureManifestV1(
    const SemanticRootClosureManifestV1& manifest,
    const RCStage3CoupledShape& shape,
    const gf::Fp3& gamma,
    const gf::Fp3& alpha,
    uint8_t extract_scale_e,
    bool production_mode,
    std::string* why)
{
    if (!ManifestShapeValid(manifest, why) ||
        manifest.closure_commitment !=
            ComputeSemanticRootClosureCommitmentV1(
                manifest)) {
        return Fail(why, "commitment");
    }
    const auto expected =
        BuildSemanticRootClosureManifestV1(
            shape, gamma, alpha, extract_scale_e,
            production_mode);
    if (!(manifest == expected)) {
        return Fail(why, "canonical_substitution");
    }
    if (why != nullptr) {
        *why =
            "stage3:semantic_root_closure:"
            "canonical_manifest";
    }
    return true;
}

uint256 ComputeSemanticRootReceiptStatementCommitmentV1(
    const SemanticRootReceiptStatementV1& statement)
{
    HashWriter hash;
    hash << kReceiptDomain;
    hash << statement.version;
    hash << statement.closure_manifest_commitment;
    hash << static_cast<uint32_t>(
        statement.endpoints.size());
    for (const auto& endpoint : statement.endpoints) {
        hash << static_cast<uint16_t>(endpoint.endpoint);
        hash << static_cast<uint16_t>(endpoint.role);
        hash << endpoint.family_index;
        HashWords(
            hash,
            endpoint.program_recursive_alg_hash_words);
        HashWords(
            hash,
            endpoint.relation_semantic_root_words);
        HashWords(
            hash,
            endpoint.provenance_root_words);
        HashWords(
            hash,
            endpoint.receipt_semantic_root_words);
        HashWords(
            hash,
            endpoint.ctl_schedule_commitment_words);
        HashWords(
            hash,
            endpoint.ctl_challenge_commitment_words);
        HashWords(hash, endpoint.ctl_terminal_words);
        hash << endpoint.ctl_rational_identity_acceptance;
        hash << endpoint.child_acceptance;
    }
    return hash.GetHash();
}

bool ValidateSemanticRootReceiptStatementV1(
    const SemanticRootClosureManifestV1& manifest,
    const SemanticRootReceiptStatementV1& statement,
    std::string* why)
{
    if (!ManifestShapeValid(manifest, why) ||
        statement.version !=
            kSemanticRootClosureVersionV1 ||
        statement.closure_manifest_commitment !=
            manifest.closure_commitment ||
        statement.endpoints.size() !=
            manifest.endpoints.size() ||
        statement.statement_commitment.IsNull() ||
        statement.statement_commitment !=
            ComputeSemanticRootReceiptStatementCommitmentV1(
                statement) ||
        statement.all_sources_available !=
            manifest.recursive_semantic_closure_complete ||
        statement.recursively_consumable !=
            manifest.recursive_semantic_closure_complete ||
        statement.production_authority !=
            manifest.production_authority) {
        return Fail(why, "receipt_shape_or_status");
    }
    for (uint32_t index = 0;
         index < statement.endpoints.size(); ++index) {
        const auto& expected = manifest.endpoints[index];
        const auto& endpoint = statement.endpoints[index];
        if (endpoint.endpoint != expected.endpoint ||
            endpoint.role != expected.role ||
            endpoint.family_index !=
                expected.family_index ||
            endpoint.program_recursive_alg_hash_words !=
                expected
                    .program_recursive_alg_hash_words ||
            endpoint.relation_semantic_root_words !=
                endpoint.provenance_root_words ||
            endpoint.relation_semantic_root_words !=
                endpoint.receipt_semantic_root_words ||
            endpoint.ctl_rational_identity_acceptance !=
                static_cast<uint32_t>(
                    expected.ctl
                        .recursive_rational_identity_consumed) ||
            endpoint.child_acceptance !=
                static_cast<uint32_t>(
                    expected
                        .child_receipt_acceptance_cell)) {
            return Fail(
                why,
                "receipt_endpoint:" +
                    std::to_string(index + 1U));
        }
        const bool unowned_ctl_data =
            std::any_of(
                endpoint.ctl_schedule_commitment_words.begin(),
                endpoint.ctl_schedule_commitment_words.end(),
                [](uint32_t word) { return word != 0; }) ||
            std::any_of(
                endpoint.ctl_challenge_commitment_words.begin(),
                endpoint.ctl_challenge_commitment_words.end(),
                [](uint32_t word) { return word != 0; }) ||
            std::any_of(
                endpoint.ctl_terminal_words.begin(),
                endpoint.ctl_terminal_words.end(),
                [](uint32_t word) { return word != 0; });
        if (!expected.ctl.relation_value_same_trace &&
            unowned_ctl_data) {
            return Fail(
                why,
                "receipt_unowned_ctl_terminal:" +
                    std::to_string(index + 1U));
        }
    }
    if (why != nullptr) {
        *why =
            "stage3:semantic_root_closure:"
            "receipt_binding_valid_not_authority";
    }
    return true;
}

SemanticRootClosureAirV1
BuildSemanticRootClosureAirV1(
    const SemanticRootClosureManifestV1& manifest)
{
    SemanticRootClosureAirV1 out;
    std::string why;
    if (!ManifestShapeValid(manifest, &why) ||
        manifest.closure_commitment !=
            ComputeSemanticRootClosureCommitmentV1(
                manifest)) {
        out.note = why;
        return out;
    }
    out.closure_manifest_commitment =
        manifest.closure_commitment;
    out.layout = MakeAirLayout();
    out.active_rows =
        static_cast<uint32_t>(
            manifest.endpoints.size());
    out.cs.n_rows = NextPowerOfTwo(out.active_rows);
    out.cs.n_columns = out.layout.total_columns;
    // The Alg/row-wise FRI backend does not carry dense per-column roots.
    // Bind every immutable schedule column at the common OOD point instead
    // of silently treating host-side preprocessed vectors as public.
    out.cs.preprocessed_pin_ood = true;
    if (out.cs.n_rows == 0) {
        out.note = "stage3:semantic_root_closure:air_rows";
        return out;
    }
    out.columns.assign(
        out.cs.n_columns,
        std::vector<Fp3>(
            out.cs.n_rows, Fp3::Zero()));
    const auto put =
        [&out](uint32_t column, uint32_t row,
               uint32_t value) {
            out.columns[column][row] =
                Fp3::FromFp(gf::FromU64(value));
        };
    for (uint32_t row = 0;
         row < manifest.endpoints.size(); ++row) {
        const auto& endpoint =
            manifest.endpoints[row];
        put(
            out.layout.claimed_endpoint, row,
            static_cast<uint16_t>(
                endpoint.endpoint));
        put(
            out.layout.claimed_role, row,
            static_cast<uint16_t>(endpoint.role));
        put(
            out.layout.claimed_role_ordinal, row,
            endpoint.role_ordinal);
        put(
            out.layout.claimed_endpoint_ordinal, row,
            endpoint.endpoint_ordinal);
        put(
            out.layout.claimed_family_index, row,
            endpoint.family_index);
        put(
            out.layout.claimed_proof_site_kind, row,
            static_cast<uint8_t>(
                endpoint.proof_site_kind));
        put(
            out.layout.claimed_relation_column, row,
            endpoint.relation_column);
        put(
            out.layout.claimed_missing_sources, row,
            endpoint.missing_sources);
        put(out.layout.expected_active, row, 1);
        put(
            out.layout.expected_endpoint, row,
            static_cast<uint16_t>(
                endpoint.endpoint));
        put(
            out.layout.expected_role, row,
            static_cast<uint16_t>(endpoint.role));
        put(
            out.layout.expected_role_ordinal, row,
            endpoint.role_ordinal);
        put(
            out.layout.expected_endpoint_ordinal, row,
            endpoint.endpoint_ordinal);
        put(
            out.layout.expected_family_index, row,
            endpoint.family_index);
        put(
            out.layout.expected_proof_site_kind, row,
            static_cast<uint8_t>(
                endpoint.proof_site_kind));
        put(
            out.layout.expected_relation_column, row,
            endpoint.relation_column);
        put(
            out.layout.expected_missing_sources, row,
            endpoint.missing_sources);
        for (uint32_t word = 0;
             word < kSemanticRootU32WordsV1;
             ++word) {
            put(
                out.layout
                        .claimed_program_external_base +
                    word,
                row,
                endpoint
                    .program_external_sha256d_words[word]);
            put(
                out.layout
                        .claimed_program_recursive_base +
                    word,
                row,
                endpoint
                    .program_recursive_alg_hash_words[word]);
            put(
                out.layout
                        .expected_program_external_base +
                    word,
                row,
                endpoint
                    .program_external_sha256d_words[word]);
            put(
                out.layout
                        .expected_program_recursive_base +
                    word,
                row,
                endpoint
                    .program_recursive_alg_hash_words[word]);
        }
    }

    for (uint32_t column =
             out.layout.expected_active;
         column < out.layout.total_columns;
         ++column) {
        out.cs.preprocessed.push_back(
            {column, out.columns[column]});
    }
    AddExactColumnConstraint(
        out.cs,
        out.layout.claimed_endpoint,
        out.layout.expected_endpoint,
        "stage3.semantic_root.endpoint");
    AddExactColumnConstraint(
        out.cs,
        out.layout.claimed_role,
        out.layout.expected_role,
        "stage3.semantic_root.role");
    AddExactColumnConstraint(
        out.cs,
        out.layout.claimed_role_ordinal,
        out.layout.expected_role_ordinal,
        "stage3.semantic_root.role_ordinal");
    AddExactColumnConstraint(
        out.cs,
        out.layout.claimed_endpoint_ordinal,
        out.layout.expected_endpoint_ordinal,
        "stage3.semantic_root.endpoint_ordinal");
    AddExactColumnConstraint(
        out.cs,
        out.layout.claimed_family_index,
        out.layout.expected_family_index,
        "stage3.semantic_root.family");
    AddExactColumnConstraint(
        out.cs,
        out.layout.claimed_proof_site_kind,
        out.layout.expected_proof_site_kind,
        "stage3.semantic_root.site_kind");
    AddExactColumnConstraint(
        out.cs,
        out.layout.claimed_relation_column,
        out.layout.expected_relation_column,
        "stage3.semantic_root.relation_column");
    AddExactColumnConstraint(
        out.cs,
        out.layout.claimed_missing_sources,
        out.layout.expected_missing_sources,
        "stage3.semantic_root.missing_sources");
    for (uint32_t word = 0;
         word < kSemanticRootU32WordsV1;
         ++word) {
        AddExactColumnConstraint(
            out.cs,
            out.layout.claimed_program_external_base +
                word,
            out.layout.expected_program_external_base +
                word,
            "stage3.semantic_root.program_external");
        AddExactColumnConstraint(
            out.cs,
            out.layout.claimed_program_recursive_base +
                word,
            out.layout.expected_program_recursive_base +
                word,
            "stage3.semantic_root.program_recursive");
    }
    out.violations =
        CountSemanticRootClosureAirViolationsV1(
            out.cs, out.columns);
    out.exact_manifest_pinned =
        out.violations == 0;
    out.values_are_ordinary_witness = true;
    out.only_expected_schedule_preprocessed = true;
    out.recursive_semantic_closure_complete =
        manifest.recursive_semantic_closure_complete;
    out.production_authority =
        manifest.production_authority;
    out.valid =
        out.exact_manifest_pinned &&
        out.values_are_ordinary_witness &&
        out.only_expected_schedule_preprocessed;
    out.note =
        out.valid
        ? "stage3:semantic_root_closure:"
          "exact_inventory_air_valid_not_recursive_authority"
        : "stage3:semantic_root_closure:"
          "inventory_air_invalid";
    return out;
}

uint32_t CountSemanticRootClosureAirViolationsV1(
    const aq::AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns)
{
    if (cs.n_rows < 2 ||
        columns.size() != cs.n_columns) {
        return UINT32_MAX;
    }
    for (const auto& column : columns) {
        if (column.size() != cs.n_rows) {
            return UINT32_MAX;
        }
    }
    uint64_t violations = 0;
    for (uint32_t row = 0; row < cs.n_rows; ++row) {
        std::vector<Fp3> current(cs.n_columns);
        std::vector<Fp3> next(cs.n_columns);
        const uint32_t next_row =
            (row + 1U) % cs.n_rows;
        for (uint32_t column = 0;
             column < cs.n_columns; ++column) {
            current[column] = columns[column][row];
            next[column] =
                columns[column][next_row];
        }
        for (const auto& constraint :
             cs.constraints) {
            bool active = false;
            switch (constraint.kind) {
            case aq::AirKind::kEverywhere:
                active = true;
                break;
            case aq::AirKind::kTransition:
                active = row + 1U < cs.n_rows;
                break;
            case aq::AirKind::kFirstRow:
                active = row == 0;
                break;
            case aq::AirKind::kLastRow:
                active = row + 1U == cs.n_rows;
                break;
            }
            if (active &&
                !gf::IsZero(
                    constraint.eval(current, next))) {
                ++violations;
            }
        }
    }
    return violations >
               std::numeric_limits<uint32_t>::max()
        ? UINT32_MAX
        : static_cast<uint32_t>(violations);
}

bool DecodeCanonicalSemanticU32CellV1(
    const gf::Fp3& cell,
    uint32_t& out)
{
    if (cell.c0 >= gf::kP ||
        cell.c1 >= gf::kP ||
        cell.c2 >= gf::kP ||
        cell.c1 != 0 ||
        cell.c2 != 0 ||
        cell.c0 >
            std::numeric_limits<uint32_t>::max()) {
        return false;
    }
    out = static_cast<uint32_t>(cell.c0);
    return true;
}

} // namespace matmul::v4::rc::semantic_root_closure
