// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_multirow_v11_semantic_ctl.h>

#include <matmul/matmul_v4_rc_stage3_production_family_programs.h>
#include <matmul/matmul_v4_rc_stage3_ali_manifest.h>
#include <matmul/matmul_v4_rc_stage3_semantic_endpoint_program_bridge.h>
#include <matmul/matmul_v4_rc_stage3_universal_topology.h>

#include <hash.h>

#include <algorithm>
#include <limits>
#include <set>
#include <utility>

namespace matmul::v4::rc::multirow_v11_semantic_ctl {
namespace {

namespace bridge = semantic_endpoint_program_bridge;
namespace sites = soundness_scenarios;
namespace topo = universal_topology;
namespace ali = stage3_ali_manifest;

constexpr char kSourceCommitDomain[] =
    "BTX_RC_STAGE3_MULTIROW_V11_SEMANTIC_CTL_SOURCE_V1";
constexpr char kConsumerCommitDomain[] =
    "BTX_RC_STAGE3_MULTIROW_V11_SEMANTIC_CTL_CONSUMER_V1";
constexpr char kChallengeDomain[] =
    "BTX_RC_STAGE3_MULTIROW_V11_SEMANTIC_CTL_CHALLENGE_V1";
constexpr uint32_t kLogicalDirectionExportToConsumer = 1;

void HashWords(
    HashWriter& hash,
    const std::array<uint32_t, kDigestWordsV1>& words);

bool Fail(std::string* why, const std::string& reason)
{
    if (why != nullptr) {
        *why =
            "stage3:multirow_v11_semantic_ctl:" + reason;
    }
    return false;
}

gf::Fp3 U32(uint32_t value)
{
    return gf::Fp3::FromFp(gf::FromU64(value));
}

std::array<uint32_t, kDigestWordsV1> Uint256Words(
    const uint256& value)
{
    std::array<uint32_t, kDigestWordsV1> out{};
    for (uint32_t word = 0; word < out.size(); ++word) {
        const uint32_t offset = 4U * word;
        out[word] =
            static_cast<uint32_t>(value.begin()[offset]) |
            (static_cast<uint32_t>(
                 value.begin()[offset + 1]) << 8) |
            (static_cast<uint32_t>(
                 value.begin()[offset + 2]) << 16) |
            (static_cast<uint32_t>(
                 value.begin()[offset + 3]) << 24);
    }
    return out;
}

uint64_t ReadU64(const uint256& value, uint32_t word)
{
    uint64_t out = 0;
    const uint32_t offset = 8U * word;
    for (uint32_t byte = 0; byte < 8; ++byte) {
        out |=
            static_cast<uint64_t>(
                value.begin()[offset + byte])
            << (8U * byte);
    }
    return out;
}

bool DeriveFp3(
    const uint256& source_commitment,
    const uint256& consumer_commitment,
    const uint256& bridge_commitment,
    const uint256& ali_binding,
    const uint256& statement_root,
    uint32_t lane,
    uint32_t purpose,
    gf::Fp3& out)
{
    std::array<uint64_t, 3> coordinates{};
    uint32_t accepted = 0;
    for (uint32_t counter = 0;
         counter < 16 && accepted < coordinates.size();
         ++counter) {
        HashWriter hash;
        hash << std::string(kChallengeDomain);
        hash << source_commitment;
        hash << consumer_commitment;
        hash << bridge_commitment;
        hash << ali_binding;
        hash << statement_root;
        hash << lane;
        hash << purpose;
        hash << counter;
        const uint256 digest = hash.GetHash();
        for (uint32_t word = 0;
             word < 4 && accepted < coordinates.size();
             ++word) {
            const uint64_t candidate =
                ReadU64(digest, word);
            if (candidate < gf::kP) {
                coordinates[accepted++] = candidate;
            }
        }
    }
    if (accepted != coordinates.size()) return false;
    out = gf::Fp3{
        coordinates[0],
        coordinates[1],
        coordinates[2]};
    return !gf::IsZero(out);
}

uint256 CommitChallenges(const RCStage3CtlChallenges& challenges)
{
    HashWriter hash;
    hash << std::string(kChallengeDomain);
    for (const gf::Fp3& challenge :
         {challenges.gamma1, challenges.alpha1,
          challenges.gamma2, challenges.alpha2}) {
        hash << gf::Canonical(challenge.c0);
        hash << gf::Canonical(challenge.c1);
        hash << gf::Canonical(challenge.c2);
    }
    return hash.GetHash();
}

LayoutV1 MakeLayout()
{
    LayoutV1 out;
    uint32_t column = 0;
    out.active = column++;
    out.polarity = column++;
    out.role = column++;
    out.endpoint = column++;
    out.direction = column++;
    out.occurrence = column++;
    out.temporal_order = column++;
    out.family_index = column++;
    out.site_kind = column++;
    out.ownership_bits = column++;
    out.program_external_base = column;
    column += kDigestWordsV1;
    out.program_recursive_base = column;
    column += kDigestWordsV1;
    out.ali_compiled_program_base = column;
    column += kDigestWordsV1;
    out.statement_root_base = column;
    column += kDigestWordsV1;
    out.value_base = column;
    column += kValueWordsV1;
    out.value_bits_base = column;
    column += kValueWordsV1 * kBitsPerValueWordV1;
    out.inverse1 = column++;
    out.inverse2 = column++;
    out.term1 = column++;
    out.term2 = column++;
    out.running1 = column++;
    out.running2 = column++;
    out.total_columns = column;
    return out;
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

uint32_t OwnershipBits(
    const bridge::SemanticEndpointProgramBindingV1& endpoint)
{
    return
        (static_cast<uint32_t>(
             endpoint.selected_program_key) << 0) |
        (static_cast<uint32_t>(
             endpoint.canonical_output_metadata) << 1) |
        (static_cast<uint32_t>(
             endpoint.executed_relation_cell) << 2) |
        (static_cast<uint32_t>(
             endpoint.relation_column_exact) << 3) |
        (static_cast<uint32_t>(
             endpoint.same_trace_ctl_alias) << 4) |
        (static_cast<uint32_t>(
             endpoint.direct_alias_ready) << 5) |
        (static_cast<uint32_t>(
             endpoint.recursive_child_accepted) << 6);
}

std::array<uint32_t, kDigestWordsV1> AlgDigestWords(
    const alg_hash::Digest& value)
{
    std::array<uint32_t, kDigestWordsV1> out{};
    for (uint32_t lane = 0; lane < value.size(); ++lane) {
        const uint64_t canonical =
            gf::Canonical(value[lane]);
        out[2U * lane] =
            static_cast<uint32_t>(canonical);
        out[2U * lane + 1U] =
            static_cast<uint32_t>(canonical >> 32);
    }
    return out;
}

uint256 BindAlgDigest(
    const alg_hash::Digest& value)
{
    HashWriter hash;
    hash << std::string(
        "BTX_RC_STAGE3_MULTIROW_V11_SEMANTIC_CTL_ALI_BINDING_V1");
    const auto words = AlgDigestWords(value);
    HashWords(hash, words);
    return hash.GetHash();
}

uint32_t ResidualMask(
    const bridge::SemanticEndpointProgramBindingV1& endpoint)
{
    uint32_t out = ResidualNoRecursiveCtlConsumptionV1;
    if (!endpoint.selected_program_key) {
        out |= ResidualNoSelectedProgramV1;
    }
    if (!endpoint.canonical_output_metadata) {
        out |= ResidualNoCanonicalOutputV1;
    }
    if (!endpoint.executed_relation_cell) {
        out |= ResidualNoRelationAirCellV1;
    }
    if (!endpoint.same_trace_ctl_alias) {
        out |= ResidualNoSameTraceCtlAliasV1;
    }
    if (!endpoint.recursive_child_accepted) {
        out |= ResidualNoRecursiveChildAcceptanceV1;
    }
    return out;
}

std::string ResidualText(
    const bridge::SemanticEndpointProgramBindingV1& endpoint)
{
    if (!endpoint.direct_alias_ready) {
        return endpoint.residual;
    }
    return
        "literal ProgramTable relation cell is same-trace aliased to "
        "CTL::VALUE; normalized recursive child consumption is absent";
}

bool CanonicalCells(
    const std::vector<EndpointCellsV1>& cells,
    const bridge::SemanticEndpointProgramBridgeManifestV1& manifest,
    std::string* why)
{
    if (cells.size() != kEndpointFamiliesV1 ||
        manifest.endpoints.size() != kEndpointFamiliesV1) {
        return Fail(why, "endpoint_count");
    }
    std::set<uint16_t> seen;
    for (uint32_t row = 0; row < cells.size(); ++row) {
        const auto& cell = cells[row];
        const auto& expected = manifest.endpoints[row];
        if (cell.endpoint != expected.endpoint ||
            cell.role != expected.role ||
            cell.occurrence != expected.endpoint_ordinal) {
            return Fail(why, "endpoint_role_or_order");
        }
        if (!seen.insert(
                static_cast<uint16_t>(cell.endpoint)).second) {
            return Fail(why, "duplicate_endpoint");
        }
        for (uint64_t word : cell.source_words) {
            if (word > UINT32_MAX) {
                return Fail(why, "source_noncanonical_u32");
            }
        }
        for (uint64_t word : cell.consumer_words) {
            if (word > UINT32_MAX) {
                return Fail(why, "consumer_noncanonical_u32");
            }
        }
    }
    return true;
}

void HashWords(
    HashWriter& hash,
    const std::array<uint32_t, kDigestWordsV1>& words)
{
    for (uint32_t word : words) hash << word;
}

uint256 CommitTupleSide(
    const char* domain,
    const uint256& statement_root,
    const bridge::SemanticEndpointProgramBridgeManifestV1& manifest,
    const ali::ProductionAliManifestV1& ali_manifest,
    const std::vector<EndpointCellsV1>& cells,
    bool source)
{
    HashWriter hash;
    hash << std::string(domain);
    hash << manifest.production_site_manifest_commitment;
    hash << manifest.bridge_commitment;
    hash << BindAlgDigest(ali_manifest.commitment);
    hash << statement_root;
    hash << static_cast<uint32_t>(cells.size());
    for (uint32_t row = 0; row < cells.size(); ++row) {
        const auto& binding = manifest.endpoints[row];
        const auto& cell = cells[row];
        hash << static_cast<uint16_t>(cell.role);
        hash << static_cast<uint16_t>(cell.endpoint);
        hash << kLogicalDirectionExportToConsumer;
        hash << cell.occurrence;
        hash << row;
        hash << binding.family_index;
        hash << static_cast<uint8_t>(
            binding.proof_site_kind);
        hash << OwnershipBits(binding);
        HashWords(
            hash,
            binding.program_external_sha256d_words);
        HashWords(
            hash,
            binding.program_recursive_alg_hash_words);
        if (binding.family_index <
            ali_manifest.families.size()) {
            HashWords(
                hash,
                AlgDigestWords(
                    ali_manifest
                        .families[binding.family_index]
                        .compiled_program_key));
        } else {
            HashWords(
                hash,
                std::array<uint32_t, kDigestWordsV1>{});
        }
        for (uint64_t word :
             source ? cell.source_words :
                      cell.consumer_words) {
            hash << static_cast<uint32_t>(word);
        }
    }
    return hash.GetHash();
}

gf::Fp3 CompressRow(
    const std::vector<gf::Fp3>& row,
    const LayoutV1& layout,
    const gf::Fp3& gamma)
{
    gf::Fp3 out = gf::Fp3::Zero();
    const auto absorb =
        [&out, &gamma](const gf::Fp3& value) {
            out = gf::Add(gf::Mul(out, gamma), value);
        };
    absorb(row[layout.role]);
    absorb(row[layout.endpoint]);
    absorb(row[layout.direction]);
    absorb(row[layout.occurrence]);
    absorb(row[layout.temporal_order]);
    absorb(row[layout.family_index]);
    absorb(row[layout.site_kind]);
    absorb(row[layout.ownership_bits]);
    for (uint32_t word = 0; word < kDigestWordsV1; ++word) {
        absorb(row[layout.program_external_base + word]);
    }
    for (uint32_t word = 0; word < kDigestWordsV1; ++word) {
        absorb(row[layout.program_recursive_base + word]);
    }
    for (uint32_t word = 0; word < kDigestWordsV1; ++word) {
        absorb(
            row[layout.ali_compiled_program_base + word]);
    }
    for (uint32_t word = 0; word < kDigestWordsV1; ++word) {
        absorb(row[layout.statement_root_base + word]);
    }
    for (uint32_t word = 0; word < kValueWordsV1; ++word) {
        absorb(row[layout.value_base + word]);
    }
    return out;
}

void AddConstraint(
    aq::AirConstraintSystem<gf::Fp3>& cs,
    const char* name,
    aq::AirKind kind,
    uint32_t degree,
    std::function<gf::Fp3(
        const std::vector<gf::Fp3>&,
        const std::vector<gf::Fp3>&)> eval)
{
    cs.constraints.push_back(
        {name, kind, degree, std::move(eval)});
}

bool Active(
    aq::AirKind kind,
    uint32_t row,
    uint32_t rows)
{
    switch (kind) {
    case aq::AirKind::kEverywhere:
        return true;
    case aq::AirKind::kTransition:
        return row + 1U < rows;
    case aq::AirKind::kFirstRow:
        return row == 0;
    case aq::AirKind::kLastRow:
        return row + 1U == rows;
    }
    return false;
}

bool SameChallenges(
    const RCStage3CtlChallenges& a,
    const RCStage3CtlChallenges& b)
{
    return a == b;
}

bool SamePreprocessed(
    const std::vector<
        std::pair<uint32_t, std::vector<gf::Fp3>>>& a,
    const std::vector<
        std::pair<uint32_t, std::vector<gf::Fp3>>>& b)
{
    if (a.size() != b.size()) return false;
    for (uint32_t entry = 0; entry < a.size(); ++entry) {
        if (a[entry].first != b[entry].first ||
            a[entry].second.size() !=
                b[entry].second.size()) {
            return false;
        }
        for (uint32_t row = 0;
             row < a[entry].second.size(); ++row) {
            if (!gf::Eq(
                    a[entry].second[row],
                    b[entry].second[row])) {
                return false;
            }
        }
    }
    return true;
}

bool SameColumns(
    const std::vector<std::vector<gf::Fp3>>& a,
    const std::vector<std::vector<gf::Fp3>>& b)
{
    if (a.size() != b.size()) return false;
    for (uint32_t column = 0;
         column < a.size(); ++column) {
        if (a[column].size() != b[column].size()) {
            return false;
        }
        for (uint32_t row = 0;
             row < a[column].size(); ++row) {
            if (!gf::Eq(a[column][row], b[column][row])) {
                return false;
            }
        }
    }
    return true;
}

} // namespace

std::vector<EndpointCellsV1>
BuildDeterministicEndpointCellsV1(uint32_t salt)
{
    std::vector<EndpointCellsV1> out;
    const auto manifest =
        bridge::BuildSemanticEndpointProgramBridgeManifestV1();
    out.reserve(manifest.endpoints.size());
    for (const auto& binding : manifest.endpoints) {
        EndpointCellsV1 cells;
        cells.endpoint = binding.endpoint;
        cells.role = binding.role;
        cells.occurrence = binding.endpoint_ordinal;
        for (uint32_t word = 0; word < kValueWordsV1; ++word) {
            const uint32_t value =
                salt * 0x101U +
                (binding.endpoint_ordinal + 1U) *
                    0x10001U +
                word * 0x1000003U;
            cells.source_words[word] = value;
            cells.consumer_words[word] = value;
        }
        out.push_back(cells);
    }
    return out;
}

ProductV1 BuildProductV1(
    const uint256& expected_statement_root,
    const std::vector<EndpointCellsV1>& endpoint_cells)
{
    ProductV1 out;
    out.expected_statement_root = expected_statement_root;
    out.endpoint_cells = endpoint_cells;

    const sites::ProductionProofSiteManifest site_manifest =
        sites::BuildProductionProofSiteManifest(
            sites::SelectedProductionProofSitePolicy());
    const auto sources =
        topo::BuildProductionFamilyProgramSourcesV1(
            site_manifest);
    const auto migration =
        topo::AssessProductionFamilyProgramMigrationV1(
            sources);
    const auto semantic_manifest =
        bridge::BuildSemanticEndpointProgramBridgeManifestV1();
    const auto ali_manifest =
        ali::BuildProductionAliManifestV1();
    std::string why;
    out.canonical_program_inventory =
        sites::ValidateProductionProofSiteManifest(
            site_manifest, &why) &&
        topo::ValidateProductionFamilyProgramSourcesV1(
            site_manifest, sources, &why) &&
        bridge::ValidateSemanticEndpointProgramBridgeManifestV1(
            semantic_manifest, &why) &&
        sources.size() == kProgramFamiliesV1 &&
        migration.families_total == kProgramFamiliesV1 &&
        migration.families_non_stub == kProgramFamiliesV1 &&
        migration.families_structural_stubs == 0;
    out.canonical_program_families =
        out.canonical_program_inventory
        ? static_cast<uint32_t>(sources.size()) : 0;
    out.production_site_manifest_commitment =
        site_manifest.commitment;
    out.semantic_program_bridge_commitment =
        semantic_manifest.bridge_commitment;
    out.canonical_ali_inventory =
        ali::ValidateProductionAliManifestV1(
            ali_manifest, &why) &&
        ali_manifest.local_manifest_complete &&
        ali_manifest.families.size() ==
            kProgramFamiliesV1 &&
        !ali_manifest.recursive_root_consumed &&
        !ali_manifest.production_authority;
    out.production_ali_manifest_binding =
        BindAlgDigest(ali_manifest.commitment);

    if (expected_statement_root.IsNull() ||
        !out.canonical_program_inventory ||
        !out.canonical_ali_inventory ||
        !CanonicalCells(
            endpoint_cells, semantic_manifest, &why)) {
        out.note =
            why.empty()
            ? "stage3:multirow_v11_semantic_ctl:inputs"
            : why;
        return out;
    }

    out.source_tuple_commitment = CommitTupleSide(
        kSourceCommitDomain, expected_statement_root,
        semantic_manifest, ali_manifest,
        endpoint_cells, true);
    out.consumer_tuple_commitment = CommitTupleSide(
        kConsumerCommitDomain, expected_statement_root,
        semantic_manifest, ali_manifest,
        endpoint_cells, false);
    if (out.source_tuple_commitment.IsNull() ||
        out.consumer_tuple_commitment.IsNull() ||
        !DeriveFp3(
            out.source_tuple_commitment,
            out.consumer_tuple_commitment,
            out.semantic_program_bridge_commitment,
            out.production_ali_manifest_binding,
            expected_statement_root, 1, 1,
            out.challenges.gamma1) ||
        !DeriveFp3(
            out.source_tuple_commitment,
            out.consumer_tuple_commitment,
            out.semantic_program_bridge_commitment,
            out.production_ali_manifest_binding,
            expected_statement_root, 1, 2,
            out.challenges.alpha1) ||
        !DeriveFp3(
            out.source_tuple_commitment,
            out.consumer_tuple_commitment,
            out.semantic_program_bridge_commitment,
            out.production_ali_manifest_binding,
            expected_statement_root, 2, 1,
            out.challenges.gamma2) ||
        !DeriveFp3(
            out.source_tuple_commitment,
            out.consumer_tuple_commitment,
            out.semantic_program_bridge_commitment,
            out.production_ali_manifest_binding,
            expected_statement_root, 2, 2,
            out.challenges.alpha2)) {
        out.note =
            "stage3:multirow_v11_semantic_ctl:"
            "challenge_sampling";
        return out;
    }
    out.challenge_commitment =
        CommitChallenges(out.challenges);
    out.commitments_before_challenges = true;
    out.independent_domain_separated_lanes =
        !gf::Eq(
            out.challenges.gamma1,
            out.challenges.gamma2) &&
        !gf::Eq(
            out.challenges.alpha1,
            out.challenges.alpha2);
    if (!out.independent_domain_separated_lanes) {
        out.note =
            "stage3:multirow_v11_semantic_ctl:"
            "challenge_lane_collision";
        return out;
    }

    out.layout = MakeLayout();
    out.cs.n_rows =
        NextPowerOfTwo(2U * kEndpointFamiliesV1);
    out.cs.n_columns = out.layout.total_columns;
    out.cs.preprocessed_pin_ood = true;
    out.columns.assign(
        out.cs.n_columns,
        std::vector<gf::Fp3>(
            out.cs.n_rows, gf::Fp3::Zero()));
    const auto statement_words =
        Uint256Words(expected_statement_root);
    const auto put =
        [&out](uint32_t column,
               uint32_t row,
               const gf::Fp3& value) {
            out.columns[column][row] = value;
        };
    const auto put_u32 =
        [&put](uint32_t column,
               uint32_t row,
               uint32_t value) {
            put(column, row, U32(value));
        };

    out.endpoints.reserve(kEndpointFamiliesV1);
    for (uint32_t endpoint_row = 0;
         endpoint_row < kEndpointFamiliesV1;
         ++endpoint_row) {
        const auto& binding =
            semantic_manifest.endpoints[endpoint_row];
        const auto& cells = endpoint_cells[endpoint_row];
        EndpointCoverageV1 coverage;
        coverage.endpoint = binding.endpoint;
        coverage.role = binding.role;
        coverage.occurrence = binding.endpoint_ordinal;
        coverage.family_index = binding.family_index;
        coverage.relation_column = binding.relation_column;
        coverage.represented = true;
        coverage.exact_consumer = true;
        coverage.selected_program =
            binding.selected_program_key;
        coverage.literal_proof_owned_export =
            binding.direct_alias_ready;
        coverage.dual_logup_constrained = true;
        coverage.recursively_consumed = false;
        coverage.residual_mask = ResidualMask(binding);
        coverage.residual = ResidualText(binding);
        out.endpoints.push_back(coverage);

        out.represented_endpoints += coverage.represented;
        out.exact_consumer_endpoints +=
            coverage.exact_consumer;
        out.selected_program_endpoints +=
            coverage.selected_program;
        out.proof_owned_export_endpoints +=
            coverage.literal_proof_owned_export;
        out.dual_logup_endpoint_pairs +=
            coverage.dual_logup_constrained;

        for (uint32_t side = 0; side < 2; ++side) {
            const uint32_t row =
                2U * endpoint_row + side;
            put_u32(out.layout.active, row, 1);
            put(
                out.layout.polarity, row,
                side == 0
                ? gf::Fp3::One()
                : gf::Neg(gf::Fp3::One()));
            put_u32(
                out.layout.role, row,
                static_cast<uint16_t>(binding.role));
            put_u32(
                out.layout.endpoint, row,
                static_cast<uint16_t>(binding.endpoint));
            put_u32(
                out.layout.direction, row,
                kLogicalDirectionExportToConsumer);
            put_u32(
                out.layout.occurrence, row,
                binding.endpoint_ordinal);
            put_u32(
                out.layout.temporal_order, row,
                endpoint_row);
            put_u32(
                out.layout.family_index, row,
                binding.family_index);
            put_u32(
                out.layout.site_kind, row,
                static_cast<uint8_t>(
                    binding.proof_site_kind));
            put_u32(
                out.layout.ownership_bits, row,
                OwnershipBits(binding));
            for (uint32_t word = 0;
                 word < kDigestWordsV1; ++word) {
                put_u32(
                    out.layout.program_external_base +
                        word,
                    row,
                    binding
                        .program_external_sha256d_words[
                            word]);
                put_u32(
                    out.layout.program_recursive_base +
                        word,
                    row,
                    binding
                        .program_recursive_alg_hash_words[
                            word]);
                const auto compiled_words =
                    binding.family_index <
                            ali_manifest.families.size()
                    ? AlgDigestWords(
                          ali_manifest
                              .families[
                                  binding.family_index]
                              .compiled_program_key)
                    : std::array<
                          uint32_t,
                          kDigestWordsV1>{};
                put_u32(
                    out.layout.ali_compiled_program_base +
                        word,
                    row, compiled_words[word]);
                put_u32(
                    out.layout.statement_root_base +
                        word,
                    row, statement_words[word]);
            }
            const auto& words =
                side == 0 ? cells.source_words :
                            cells.consumer_words;
            for (uint32_t word = 0;
                 word < kValueWordsV1; ++word) {
                const uint32_t value =
                    static_cast<uint32_t>(words[word]);
                put_u32(
                    out.layout.value_base + word,
                    row, value);
                for (uint32_t bit = 0;
                     bit < kBitsPerValueWordV1;
                     ++bit) {
                    put_u32(
                        out.layout.value_bits_base +
                            word *
                                kBitsPerValueWordV1 +
                            bit,
                        row, (value >> bit) & 1U);
                }
            }
        }
    }

    out.roles.reserve(kRolesV1);
    for (const RCStage3RelationRole role :
         RCStage3UnifiedRoleOrder()) {
        RoleCoverageV1 coverage;
        coverage.role = role;
        const auto& required =
            RequiredRCStage3RelationEndpoints(role);
        coverage.required_endpoints =
            static_cast<uint32_t>(required.size());
        for (const auto& endpoint : out.endpoints) {
            if (endpoint.role != role) continue;
            ++coverage.represented_endpoints;
            coverage.proof_owned_exports +=
                endpoint.literal_proof_owned_export;
            coverage.recursively_consumed_endpoints +=
                endpoint.recursively_consumed;
            const uint32_t id =
                static_cast<uint16_t>(endpoint.endpoint);
            coverage.endpoint_mask |=
                uint64_t{1} << (id - 1U);
            if (endpoint.literal_proof_owned_export) {
                coverage.proof_owned_mask |=
                    uint64_t{1} << (id - 1U);
            }
        }
        coverage.complete =
            coverage.required_endpoints != 0 &&
            coverage.represented_endpoints ==
                coverage.required_endpoints &&
            coverage.proof_owned_exports ==
                coverage.required_endpoints &&
            coverage.recursively_consumed_endpoints ==
                coverage.required_endpoints;
        out.represented_roles +=
            coverage.represented_endpoints ==
            coverage.required_endpoints;
        out.complete_roles += coverage.complete;
        out.roles.push_back(coverage);
    }

    const std::array<uint32_t, 42> preprocessed_columns = {
        out.layout.active,
        out.layout.polarity,
        out.layout.role,
        out.layout.endpoint,
        out.layout.direction,
        out.layout.occurrence,
        out.layout.temporal_order,
        out.layout.family_index,
        out.layout.site_kind,
        out.layout.ownership_bits,
        out.layout.program_external_base + 0,
        out.layout.program_external_base + 1,
        out.layout.program_external_base + 2,
        out.layout.program_external_base + 3,
        out.layout.program_external_base + 4,
        out.layout.program_external_base + 5,
        out.layout.program_external_base + 6,
        out.layout.program_external_base + 7,
        out.layout.program_recursive_base + 0,
        out.layout.program_recursive_base + 1,
        out.layout.program_recursive_base + 2,
        out.layout.program_recursive_base + 3,
        out.layout.program_recursive_base + 4,
        out.layout.program_recursive_base + 5,
        out.layout.program_recursive_base + 6,
        out.layout.program_recursive_base + 7,
        out.layout.ali_compiled_program_base + 0,
        out.layout.ali_compiled_program_base + 1,
        out.layout.ali_compiled_program_base + 2,
        out.layout.ali_compiled_program_base + 3,
        out.layout.ali_compiled_program_base + 4,
        out.layout.ali_compiled_program_base + 5,
        out.layout.ali_compiled_program_base + 6,
        out.layout.ali_compiled_program_base + 7,
        out.layout.statement_root_base + 0,
        out.layout.statement_root_base + 1,
        out.layout.statement_root_base + 2,
        out.layout.statement_root_base + 3,
        out.layout.statement_root_base + 4,
        out.layout.statement_root_base + 5,
        out.layout.statement_root_base + 6,
        out.layout.statement_root_base + 7,
    };
    for (uint32_t column : preprocessed_columns) {
        out.cs.preprocessed.push_back(
            {column, out.columns[column]});
    }

    for (uint32_t word = 0;
         word < kValueWordsV1; ++word) {
        for (uint32_t bit = 0;
             bit < kBitsPerValueWordV1; ++bit) {
            const uint32_t bit_column =
                out.layout.value_bits_base +
                word * kBitsPerValueWordV1 + bit;
            AddConstraint(
                out.cs, "semantic_ctl.value_bit_boolean",
                aq::AirKind::kEverywhere, 2,
                [bit_column](
                    const std::vector<gf::Fp3>& row,
                    const std::vector<gf::Fp3>&) {
                    return gf::Mul(
                        row[bit_column],
                        gf::Sub(
                            row[bit_column],
                            gf::Fp3::One()));
                });
        }
        const uint32_t value_column =
            out.layout.value_base + word;
        const uint32_t bits_base =
            out.layout.value_bits_base +
            word * kBitsPerValueWordV1;
        AddConstraint(
            out.cs, "semantic_ctl.value_u32_recompose",
            aq::AirKind::kEverywhere, 1,
            [value_column, bits_base](
                const std::vector<gf::Fp3>& row,
                const std::vector<gf::Fp3>&) {
                gf::Fp3 reconstructed =
                    gf::Fp3::Zero();
                gf::Fp coefficient = 1;
                for (uint32_t bit = 0;
                     bit < kBitsPerValueWordV1;
                     ++bit) {
                    reconstructed = gf::Add(
                        reconstructed,
                        gf::MulBase(
                            row[bits_base + bit],
                            coefficient));
                    coefficient = gf::Add(
                        coefficient, coefficient);
                }
                return gf::Sub(
                    row[value_column],
                    reconstructed);
            });
    }

    AddConstraint(
        out.cs, "semantic_ctl.inverse1",
        aq::AirKind::kEverywhere, 2,
        [layout = out.layout,
         challenges = out.challenges](
            const std::vector<gf::Fp3>& row,
            const std::vector<gf::Fp3>&) {
            return gf::Sub(
                gf::Mul(
                    row[layout.inverse1],
                    gf::Sub(
                        challenges.alpha1,
                        CompressRow(
                            row, layout,
                            challenges.gamma1))),
                row[layout.active]);
        });
    AddConstraint(
        out.cs, "semantic_ctl.inverse2",
        aq::AirKind::kEverywhere, 2,
        [layout = out.layout,
         challenges = out.challenges](
            const std::vector<gf::Fp3>& row,
            const std::vector<gf::Fp3>&) {
            return gf::Sub(
                gf::Mul(
                    row[layout.inverse2],
                    gf::Sub(
                        challenges.alpha2,
                        CompressRow(
                            row, layout,
                            challenges.gamma2))),
                row[layout.active]);
        });
    AddConstraint(
        out.cs, "semantic_ctl.term1",
        aq::AirKind::kEverywhere, 2,
        [layout = out.layout](
            const std::vector<gf::Fp3>& row,
            const std::vector<gf::Fp3>&) {
            return gf::Sub(
                row[layout.term1],
                gf::Mul(
                    row[layout.polarity],
                    row[layout.inverse1]));
        });
    AddConstraint(
        out.cs, "semantic_ctl.term2",
        aq::AirKind::kEverywhere, 2,
        [layout = out.layout](
            const std::vector<gf::Fp3>& row,
            const std::vector<gf::Fp3>&) {
            return gf::Sub(
                row[layout.term2],
                gf::Mul(
                    row[layout.polarity],
                    row[layout.inverse2]));
        });
    AddConstraint(
        out.cs, "semantic_ctl.running1_first",
        aq::AirKind::kFirstRow, 1,
        [layout = out.layout](
            const std::vector<gf::Fp3>& row,
            const std::vector<gf::Fp3>&) {
            return row[layout.running1];
        });
    AddConstraint(
        out.cs, "semantic_ctl.running2_first",
        aq::AirKind::kFirstRow, 1,
        [layout = out.layout](
            const std::vector<gf::Fp3>& row,
            const std::vector<gf::Fp3>&) {
            return row[layout.running2];
        });
    AddConstraint(
        out.cs, "semantic_ctl.running1_transition",
        aq::AirKind::kTransition, 1,
        [layout = out.layout](
            const std::vector<gf::Fp3>& row,
            const std::vector<gf::Fp3>& next) {
            return gf::Sub(
                next[layout.running1],
                gf::Add(
                    row[layout.running1],
                    row[layout.term1]));
        });
    AddConstraint(
        out.cs, "semantic_ctl.running2_transition",
        aq::AirKind::kTransition, 1,
        [layout = out.layout](
            const std::vector<gf::Fp3>& row,
            const std::vector<gf::Fp3>& next) {
            return gf::Sub(
                next[layout.running2],
                gf::Add(
                    row[layout.running2],
                    row[layout.term2]));
        });
    AddConstraint(
        out.cs, "semantic_ctl.running1_last",
        aq::AirKind::kLastRow, 1,
        [layout = out.layout](
            const std::vector<gf::Fp3>& row,
            const std::vector<gf::Fp3>&) {
            return gf::Add(
                row[layout.running1],
                row[layout.term1]);
        });
    AddConstraint(
        out.cs, "semantic_ctl.running2_last",
        aq::AirKind::kLastRow, 1,
        [layout = out.layout](
            const std::vector<gf::Fp3>& row,
            const std::vector<gf::Fp3>&) {
            return gf::Add(
                row[layout.running2],
                row[layout.term2]);
        });

    gf::Fp3 running1 = gf::Fp3::Zero();
    gf::Fp3 running2 = gf::Fp3::Zero();
    for (uint32_t row = 0; row < out.cs.n_rows; ++row) {
        out.columns[out.layout.running1][row] =
            running1;
        out.columns[out.layout.running2][row] =
            running2;
        if (gf::Eq(
                out.columns[out.layout.active][row],
                gf::Fp3::One())) {
            const gf::Fp3 compressed1 =
                CompressRow(
                    [&out, row]() {
                        std::vector<gf::Fp3> values(
                            out.cs.n_columns);
                        for (uint32_t column = 0;
                             column < out.cs.n_columns;
                             ++column) {
                            values[column] =
                                out.columns[column][row];
                        }
                        return values;
                    }(),
                    out.layout,
                    out.challenges.gamma1);
            const gf::Fp3 compressed2 =
                CompressRow(
                    [&out, row]() {
                        std::vector<gf::Fp3> values(
                            out.cs.n_columns);
                        for (uint32_t column = 0;
                             column < out.cs.n_columns;
                             ++column) {
                            values[column] =
                                out.columns[column][row];
                        }
                        return values;
                    }(),
                    out.layout,
                    out.challenges.gamma2);
            const gf::Fp3 denominator1 =
                gf::Sub(
                    out.challenges.alpha1,
                    compressed1);
            const gf::Fp3 denominator2 =
                gf::Sub(
                    out.challenges.alpha2,
                    compressed2);
            if (gf::IsZero(denominator1) ||
                gf::IsZero(denominator2)) {
                out.note =
                    "stage3:multirow_v11_semantic_ctl:"
                    "logup_denominator_pole";
                return out;
            }
            out.columns[out.layout.inverse1][row] =
                gf::Inv(denominator1);
            out.columns[out.layout.inverse2][row] =
                gf::Inv(denominator2);
        }
        out.columns[out.layout.term1][row] =
            gf::Mul(
                out.columns[out.layout.polarity][row],
                out.columns[out.layout.inverse1][row]);
        out.columns[out.layout.term2][row] =
            gf::Mul(
                out.columns[out.layout.polarity][row],
                out.columns[out.layout.inverse2][row]);
        running1 = gf::Add(
            running1,
            out.columns[out.layout.term1][row]);
        running2 = gf::Add(
            running2,
            out.columns[out.layout.term2][row]);
    }

    out.violations =
        CountAirViolationsV1(out.cs, out.columns);
    out.canonical_u32_values = true;
    out.exact_endpoint_order =
        out.endpoints.size() == kEndpointFamiliesV1;
    out.exact_role_order =
        out.roles.size() == kRolesV1;
    out.all_endpoint_pairs_algebraically_constrained =
        out.dual_logup_endpoint_pairs ==
            kEndpointFamiliesV1 &&
        out.violations == 0;
    out.tuple_commitments_recursively_bound = false;
    out.all_sources_proof_owned =
        out.proof_owned_export_endpoints ==
        kEndpointFamiliesV1;
    out.recursive_consumption_complete =
        out.recursively_consumed_endpoints ==
            kEndpointFamiliesV1 &&
        out.complete_roles == kRolesV1;
    out.production_authority =
        out.recursive_consumption_complete &&
        out.all_sources_proof_owned &&
        kProductionAuthorityV1;
    out.valid_foundation =
        out.canonical_program_inventory &&
        out.canonical_ali_inventory &&
        out.canonical_program_families ==
            kProgramFamiliesV1 &&
        out.represented_endpoints ==
            kEndpointFamiliesV1 &&
        out.exact_consumer_endpoints ==
            kEndpointFamiliesV1 &&
        out.represented_roles == kRolesV1 &&
        out.canonical_u32_values &&
        out.commitments_before_challenges &&
        out.independent_domain_separated_lanes &&
        out.all_endpoint_pairs_algebraically_constrained &&
        !out.tuple_commitments_recursively_bound &&
        !out.all_sources_proof_owned &&
        !out.recursive_consumption_complete &&
        !out.production_authority;
    out.note =
        out.valid_foundation
        ? "stage3:multirow_v11_semantic_ctl:"
          "52_pairs_dual_logup_21_proof_owned_31_residual"
        : "stage3:multirow_v11_semantic_ctl:"
          "foundation_invalid";
    return out;
}

bool ValidateProductV1(
    const ProductV1& product,
    const uint256& expected_statement_root,
    std::string* why)
{
    if (expected_statement_root.IsNull() ||
        product.expected_statement_root !=
            expected_statement_root) {
        return Fail(why, "statement_root");
    }
    const ProductV1 expected = BuildProductV1(
        expected_statement_root, product.endpoint_cells);
    if (!expected.valid_foundation) {
        return Fail(why, "canonical_regeneration");
    }
    if (product.version != expected.version ||
        product.production_site_manifest_commitment !=
            expected.production_site_manifest_commitment ||
        product.semantic_program_bridge_commitment !=
            expected.semantic_program_bridge_commitment ||
        product.production_ali_manifest_binding !=
            expected.production_ali_manifest_binding ||
        product.source_tuple_commitment !=
            expected.source_tuple_commitment ||
        product.consumer_tuple_commitment !=
            expected.consumer_tuple_commitment ||
        product.challenge_commitment !=
            expected.challenge_commitment ||
        !SameChallenges(
            product.challenges, expected.challenges) ||
        product.endpoints != expected.endpoints ||
        product.roles != expected.roles) {
        return Fail(why, "commitment_or_inventory");
    }
    if (product.cs.n_rows != expected.cs.n_rows ||
        product.cs.n_columns != expected.cs.n_columns ||
        product.cs.constraints.size() !=
            expected.cs.constraints.size() ||
        !SamePreprocessed(
            product.cs.preprocessed,
            expected.cs.preprocessed) ||
        !SameColumns(
            product.columns, expected.columns) ||
        CountAirViolationsV1(
            expected.cs, product.columns) != 0) {
        return Fail(why, "air_constraints");
    }
    if (!product.valid_foundation ||
        product.all_sources_proof_owned ||
        product.tuple_commitments_recursively_bound ||
        product.recursive_consumption_complete ||
        product.production_authority) {
        return Fail(why, "fail_closed_status");
    }
    if (why != nullptr) {
        *why =
            "stage3:multirow_v11_semantic_ctl:"
            "valid_foundation_not_recursive_authority";
    }
    return true;
}

uint32_t CountAirViolationsV1(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    const std::vector<std::vector<gf::Fp3>>& columns)
{
    if (cs.n_rows < 2 || columns.size() != cs.n_columns) {
        return UINT32_MAX;
    }
    for (const auto& column : columns) {
        if (column.size() != cs.n_rows) return UINT32_MAX;
    }
    uint64_t violations = 0;
    for (const auto& [column, expected] :
         cs.preprocessed) {
        if (column >= columns.size() ||
            expected.size() != cs.n_rows) {
            return UINT32_MAX;
        }
        for (uint32_t row = 0; row < cs.n_rows; ++row) {
            violations +=
                !gf::Eq(columns[column][row],
                        expected[row]);
        }
    }
    std::vector<gf::Fp3> current(cs.n_columns);
    std::vector<gf::Fp3> next(cs.n_columns);
    for (uint32_t row = 0; row < cs.n_rows; ++row) {
        const uint32_t next_row =
            (row + 1U) % cs.n_rows;
        for (uint32_t column = 0;
             column < cs.n_columns; ++column) {
            current[column] = columns[column][row];
            next[column] = columns[column][next_row];
        }
        for (const auto& constraint : cs.constraints) {
            if (Active(
                    constraint.kind, row, cs.n_rows) &&
                !gf::IsZero(
                    constraint.eval(current, next))) {
                ++violations;
            }
        }
    }
    return
        violations > UINT32_MAX
        ? UINT32_MAX
        : static_cast<uint32_t>(violations);
}

} // namespace matmul::v4::rc::multirow_v11_semantic_ctl
