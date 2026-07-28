// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_normalized_production_parent_builder.h>

#include <arith_uint256.h>
#include <consensus/params.h>
#include <matmul/matmul_v4_rc_air_recurse.h>
#include <matmul/matmul_v4_rc_air_quotient_alg.h>
#include <matmul/matmul_v4_rc_coupled.h>
#include <matmul/matmul_v4_rc_stage3_consensus.h>
#include <matmul/matmul_v4_rc_stage3_hash_air.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>
#include <primitives/block.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <utility>
#include <vector>

namespace matmul::v4::rc::normalized_production_parent_builder {
namespace {

namespace composer = stage3_air_parent_composer;
namespace gf = gkr_field;
namespace hash_air = stage3_hash_air;

using AirCS = air_quotient::AirConstraintSystem<gf::Fp3>;
using AirConstraint = air_quotient::AirConstraint<gf::Fp3>;
using Role = RCStage3RelationRole;

void Note(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why =
            "stage3:normalized_production_parent_builder:" +
            detail;
    }
}

bool PowerOfTwo(uint32_t value)
{
    return value >= 2 && (value & (value - 1U)) == 0;
}

std::array<uint32_t, 8> Root8(const uint256& root)
{
    std::array<uint32_t, 8> out{};
    for (uint32_t word = 0; word < out.size(); ++word) {
        const uint32_t offset = 4U * word;
        out[word] =
            static_cast<uint32_t>(root.begin()[offset]) |
            (static_cast<uint32_t>(root.begin()[offset + 1]) << 8) |
            (static_cast<uint32_t>(root.begin()[offset + 2]) << 16) |
            (static_cast<uint32_t>(root.begin()[offset + 3]) << 24);
    }
    return out;
}

std::array<uint32_t, 8> Root8(const alg_hash::Digest& root)
{
    std::array<uint32_t, 8> out{};
    for (uint32_t limb = 0; limb < root.size(); ++limb) {
        const uint64_t canonical = gf::Canonical(root[limb]);
        out[2U * limb] = static_cast<uint32_t>(canonical);
        out[2U * limb + 1U] =
            static_cast<uint32_t>(canonical >> 32);
    }
    return out;
}

std::array<uint32_t, 4> Limbs4(uint64_t value)
{
    return {
        static_cast<uint32_t>(value & 0xffffU),
        static_cast<uint32_t>((value >> 16) & 0xffffU),
        static_cast<uint32_t>((value >> 32) & 0xffffU),
        static_cast<uint32_t>((value >> 48) & 0xffffU),
    };
}

bool ValidProduct(
    const RCStage3RoleAirProduct& product,
    std::string& reason)
{
    reason.clear();
    if (!product.ok) {
        reason = "builder:" + product.note;
        return false;
    }
    if (!PowerOfTwo(product.cs.n_rows)) {
        reason = "rows";
        return false;
    }
    if (product.cs.n_columns != product.witness.size()) {
        reason = "witness_width";
        return false;
    }
    if (product.endpoints !=
        RequiredRCStage3RelationEndpoints(product.role)) {
        reason = "endpoint_order";
        return false;
    }
    if (product.endpoint_value_columns.size() !=
        product.endpoints.size()) {
        reason = "endpoint_value_columns";
        return false;
    }
    if (product.endpoint_committed_roots.size() !=
        product.endpoints.size()) {
        reason = "endpoint_roots";
        return false;
    }
    for (const auto& column : product.witness) {
        if (column.size() != product.cs.n_rows) {
            reason = "witness_rows";
            return false;
        }
    }
    for (uint32_t column : product.endpoint_value_columns) {
        if (column >= product.cs.n_columns) {
            reason = "endpoint_column_range";
            return false;
        }
    }
    uint32_t first_row = 0;
    std::string family;
    const uint32_t violations =
        air_recurse::CountWitnessViolationsOnH(
            product.cs, product.witness,
            &first_row, &family);
    if (violations != 0) {
        reason =
            "witness_violation:" + family +
            ":row=" + std::to_string(first_row);
        return false;
    }
    return true;
}

bool BuildBlockRoleProducts(
    const ProductionParentBuildInputV1& input,
    std::vector<RCStage3RoleAirProduct>& products,
    std::array<RCStage3StreamEndpointManifest, 2>&
        builder_stream_manifests,
    uint256& episode_digest,
    uint256& coupled_digest,
    uint256& composed_digest,
    std::string* why)
{
    products.clear();
    episode_digest.SetNull();
    coupled_digest.SetNull();
    composed_digest.SetNull();

    const CBlock& block = *input.solved_block;
    const Consensus::Params& params = *input.params;
    const RCEpisodeParams episode =
        ResolveRCEpisodeParams(params, input.height);
    if (!ValidateRCEpisodeParams(episode)) {
        Note(why, "episode_params");
        return false;
    }

    // Recompute from the finalized header even when the solver supplied a
    // transcript hint.  A future optimization may consume the hint after
    // independently checking every round root; the production construction
    // must not make a pointer supplied by the miner an authority input.
    std::vector<RCRoundTranscript> rounds;
    episode_digest =
        RecomputeResidentCurriculumReference(
            block, episode, input.height, {}, &rounds);
    if (episode_digest.IsNull() ||
        rounds.size() != episode.rounds ||
        rounds.empty() ||
        rounds.front().stream.empty()) {
        Note(why, "episode_recompute");
        return false;
    }
    (void)input.episode_rounds;
    std::vector<uint256> round_roots;
    round_roots.reserve(rounds.size());
    for (const auto& round : rounds) {
        if (round.round_root.IsNull()) {
            Note(why, "episode_round_root");
            return false;
        }
        round_roots.push_back(round.round_root);
    }

    const RCCoupParams coupled_params =
        ResolveRCCoupParams(params);
    const RCCoupOptions coupled_options =
        ResolveRCCoupOptions(params);
    if (!ValidateRCCoupParams(coupled_params)) {
        Note(why, "coupled_params");
        return false;
    }
    RCCoupEpisodeTranscript coupled;
    coupled_digest =
        RecomputeCoupledPuzzleReference(
            block, input.height, coupled_params,
            coupled_options, {}, nullptr, &coupled);
    const uint256 assembled_coupled =
        AssembleCoupledEpisodeDigest(
            coupled.bank_root, coupled.barrier_roots,
            coupled_options.transcript_version);
    if (coupled_digest.IsNull() ||
        coupled_digest != assembled_coupled ||
        coupled.bank_root.IsNull() ||
        coupled.barrier_roots.empty() ||
        coupled.gemms.empty() ||
        coupled.gemms.front().A.empty() ||
        coupled.gemms.front().B.empty() ||
        coupled.extracts.empty()) {
        Note(why, "coupled_recompute");
        return false;
    }

    composed_digest =
        ComputeRCStage3ComposedWorkDigest(
            block, params, input.height,
            episode_digest, coupled_digest);
    if (composed_digest.IsNull() ||
        composed_digest != block.matmul_digest ||
        UintToArith256(composed_digest) >
            UintToArith256(input.target)) {
        Note(why, "composed_digest");
        return false;
    }

    std::vector<uint8_t> round0(
        rounds.front().stream.begin(),
        rounds.front().stream.end());
    hash_air::TileTreeManifest tile_tree;
    std::string tile_why;
    if (!hash_air::BuildTileTreeManifest(
            round0, episode.T_leaf, tile_tree,
            &tile_why) ||
        tile_tree.root != round_roots.front()) {
        Note(why, "tile_tree:" + tile_why);
        return false;
    }

    const auto bank_pages =
        DeriveCoupledBankPages(
            block, input.height, coupled_params,
            coupled_options.transcript_version);
    if (bank_pages.empty() ||
        bank_pages.front().empty()) {
        Note(why, "coupled_bank_pages");
        return false;
    }

    const int64_t episode_a =
        static_cast<int64_t>(rounds.front().stream[0]);
    const int64_t episode_b =
        static_cast<int64_t>(
            rounds.front().stream.size() > 1
                ? rounds.front().stream[1]
                : rounds.front().stream[0]);
    const gf::Fp3 episode_cell =
        gf::FromSigned3(episode_a);
    const int64_t coupled_a =
        static_cast<int64_t>(
            coupled.gemms.front().A[0]);
    const int64_t coupled_b =
        static_cast<int64_t>(
            coupled.gemms.front().B[0]);
    const gf::Fp3 coupled_cell =
        gf::FromSigned3(coupled_a);
    const auto& extract = coupled.extracts.front();
    const uint64_t mix_a_value =
        extract.extract_in.empty()
            ? uint64_t{0}
            : static_cast<uint64_t>(
                  extract.extract_in[0]);
    const uint64_t mix_b_value =
        extract.extract_in.size() > 1
            ? static_cast<uint64_t>(
                  extract.extract_in[1])
            : uint64_t{0};
    const auto mix_a = Limbs4(mix_a_value);
    const auto mix_b = Limbs4(mix_b_value);
    const uint8_t bank_nibble =
        static_cast<uint8_t>(
            bank_pages.front().front()) &
        0x0fU;

    products.reserve(kRCStage3RelationClosureRoleCount);

    {
        const std::vector<gf::Fp3> openings = {
            gf::Fp3::FromFp(
                gf::FromU64(episode.rounds))};
        // seed_a/seed_b are stream VALUES, not SHA commitment roots.  The
        // canonical heavy children authenticate these exact words under their
        // endpoint-specific domains; derive the light role's root and CTL
        // value from the same manifests so the parent and child state the
        // same proposition.
        builder_stream_manifests = {
                BuildRCStage3StreamEndpointCanonicalManifest(
                    RCStage3StreamFamilyForEndpoint(
                        RCStage3RelationEndpoint::
                            EpisodeBuilderSeedChain),
                    Root8(block.seed_a), 0, 3),
                BuildRCStage3StreamEndpointCanonicalManifest(
                    RCStage3StreamFamilyForEndpoint(
                        RCStage3RelationEndpoint::
                            EpisodeBuilderOperandXof),
                    Root8(block.seed_b), 0, 3),
            };
        const std::vector<
            RCStage3StreamEndpointManifest>
            stream_manifests{
                builder_stream_manifests.begin(),
                builder_stream_manifests.end()};
        products.push_back(
            BuildRCStage3NoKernelRoleAir(
                Role::EpisodeDeterministicBuilder,
                nullptr, &openings, nullptr,
                &stream_manifests));
    }
    products.push_back(
        BuildRCStage3EpisodeGemmRoleAir(
            nullptr, &episode_a, &episode_b,
            &round_roots.front()));
    {
        const auto stream_cell =
            [&rounds](size_t index) {
                const auto& stream =
                    rounds.front().stream;
                return gf::FromSigned3(
                    static_cast<int64_t>(
                        stream[index % stream.size()]));
            };
        const std::vector<gf::Fp3> openings = {
            stream_cell(0), stream_cell(2),
            stream_cell(4), stream_cell(6),
        };
        const std::vector<std::array<uint32_t, 8>>
            stream_roots = {
                Root8(round_roots.front()),
            };
        products.push_back(
            BuildRCStage3NoKernelRoleAir(
                Role::EpisodeExtract, nullptr,
                &openings, &stream_roots));
    }
    products.push_back(
        BuildRCStage3EpisodeWiringRoleAir(
            nullptr, &episode_cell));
    {
        const uint256 leaf =
            tile_tree.leaf_hashes.empty()
                ? tile_tree.root
                : tile_tree.leaf_hashes.front();
        const uint256 internal =
            tile_tree.hash_nodes.empty()
                ? tile_tree.root
                : tile_tree.hash_nodes.back().digest;
        const std::vector<std::array<uint32_t, 8>>
            roots = {
                Root8(tile_tree.commitment),
                Root8(leaf),
                Root8(internal),
                Root8(tile_tree.root),
            };
        products.push_back(
            BuildRCStage3PureStreamRoleAirFromRoots(
                Role::EpisodeTileTree, roots,
                nullptr));
    }
    {
        const std::vector<std::array<uint32_t, 8>>
            roots = {
                Root8(round_roots.front()),
                Root8(episode_digest),
                Root8(RCStage3HeaderCommitment(block)),
                Root8(input.target),
            };
        products.push_back(
            BuildRCStage3PureStreamRoleAirFromRoots(
                Role::EpisodeDigest, roots,
                nullptr));
    }

    {
        const std::vector<std::array<uint32_t, 8>>
            roots = {
                Root8(coupled_digest),
                Root8(coupled.bank_root),
            };
        products.push_back(
            BuildRCStage3CoupledMixedRoleAir(
                Role::CoupledBank, nullptr,
                nullptr, &bank_nibble, &roots));
    }
    products.push_back(
        BuildRCStage3CoupledGemmRoleAir(
            nullptr, &coupled_a, &coupled_b,
            &coupled.barrier_roots.front()));
    {
        const std::vector<std::array<uint32_t, 8>>
            roots = {
                Root8(coupled.barrier_roots.front()),
            };
        products.push_back(
            BuildRCStage3CoupledMixedRoleAir(
                Role::CoupledExchange, nullptr,
                &coupled_cell, nullptr, &roots));
    }
    products.push_back(
        BuildRCStage3CoupledPermutationRoleAir(
            coupled_cell, 0, 3, nullptr));
    products.push_back(
        BuildRCStage3CoupledScalarRoleAir(
            Role::CoupledMix, 0, 3, nullptr,
            &mix_a, &mix_b));
    {
        const auto extract_input =
            [&extract](size_t index) {
                return gf::FromSigned3(
                    index < extract.extract_in.size()
                        ? extract.extract_in[index]
                        : int64_t{0});
            };
        const gf::Fp3 extract_output =
            gf::FromSigned3(
                extract.extract_out.empty()
                    ? int64_t{0}
                    : static_cast<int64_t>(
                          extract.extract_out.front()));
        const std::vector<gf::Fp3> openings = {
            extract_input(0),
            extract_input(1),
            gf::FromU64_3(0),
            extract_output,
        };
        const std::vector<std::array<uint32_t, 8>>
            roots = {
                Root8(extract.extract_prf),
            };
        products.push_back(
            BuildRCStage3NoKernelRoleAir(
                Role::CoupledExtract, nullptr,
                &openings, &roots));
    }
    {
        const std::vector<std::array<uint32_t, 8>>
            roots = {
                Root8(coupled.barrier_roots.front()),
                Root8(coupled.bank_root),
                Root8(coupled.barrier_roots.back()),
            };
        products.push_back(
            BuildRCStage3PureStreamRoleAirFromRoots(
                Role::CoupledBarrier, roots,
                nullptr));
    }
    {
        const std::vector<std::array<uint32_t, 8>>
            roots = {
                Root8(coupled.bank_root),
                Root8(coupled_digest),
                Root8(coupled_digest),
            };
        products.push_back(
            BuildRCStage3PureStreamRoleAirFromRoots(
                Role::CoupledDigest, roots,
                nullptr));
    }

    const auto& order = RCStage3UnifiedRoleOrder();
    if (products.size() != order.size()) {
        Note(why, "role_count");
        return false;
    }
    for (uint32_t role = 0;
         role < products.size(); ++role) {
        std::string product_why;
        if (products[role].role != order[role]) {
            product_why = "role_order";
        } else {
            (void)ValidProduct(
                products[role], product_why);
        }
        if (!product_why.empty()) {
            Note(
                why,
                "role_product:" +
                    std::string(
                        RCStage3RelationRoleName(
                            order[role])) +
                    ":" + product_why);
            return false;
        }
    }
    return true;
}

void AddRootBankPin(
    AirCS& cs,
    uint32_t column,
    uint32_t expected)
{
    cs.constraints.push_back(
        {
            "stage3.production_endpoint_bank.root_word",
            air_quotient::AirKind::kEverywhere,
            1,
            [column, expected](
                const std::vector<gf::Fp3>& current,
                const std::vector<gf::Fp3>&) {
                return gf::Sub(
                    current[column],
                    gf::Fp3::FromFp(
                        gf::FromU64(expected)));
            },
        });
}

void AddEndpointValueAlias(
    AirCS& cs,
    uint32_t bank_column,
    uint32_t role_column)
{
    cs.constraints.push_back(
        {
            "stage3.production_endpoint_bank.value_alias",
            air_quotient::AirKind::kFirstRow,
            1,
            [bank_column, role_column](
                const std::vector<gf::Fp3>& current,
                const std::vector<gf::Fp3>&) {
                return gf::Sub(
                    current[bank_column],
                    current[role_column]);
            },
        });
    cs.constraints.push_back(
        {
            "stage3.production_endpoint_bank.value_constant",
            air_quotient::AirKind::kTransition,
            1,
            [bank_column](
                const std::vector<gf::Fp3>& current,
                const std::vector<gf::Fp3>& next) {
                return gf::Sub(
                    next[bank_column],
                    current[bank_column]);
            },
        });
}

void AddSameParentFirstRowAlias(
    AirCS& cs,
    uint32_t left,
    uint32_t right,
    const char* name)
{
    cs.constraints.push_back(
        {
            name,
            air_quotient::AirKind::kFirstRow,
            1,
            [left, right](
                const std::vector<gf::Fp3>& current,
                const std::vector<gf::Fp3>&) {
                return gf::Sub(
                    current[left],
                    current[right]);
            },
        });
}

bool AppendCanonicalEndpointBank(
    const std::vector<RCStage3RoleAirProduct>& products,
    AirCS& parent_cs,
    std::vector<std::vector<gf::Fp3>>& parent_columns,
    std::vector<ProductionRolePlacementV1>& placements,
    uint32_t expected_endpoint_count,
    std::string* why)
{
    if (placements.size() != products.size() ||
        parent_cs.n_rows < 2 ||
        parent_columns.size() != parent_cs.n_columns) {
        Note(why, "endpoint_bank_parent_shape");
        return false;
    }
    uint32_t endpoint_count = 0;
    for (uint32_t role = 0;
         role < products.size(); ++role) {
        const auto& product = products[role];
        auto& placement = placements[role];
        placement.endpoints.reserve(
            product.endpoints.size());
        for (uint32_t endpoint = 0;
             endpoint < product.endpoints.size();
             ++endpoint) {
            ProductionEndpointPlacementV1 pin;
            pin.role = product.role;
            pin.endpoint = product.endpoints[endpoint];
            pin.role_ordinal = role;
            pin.endpoint_ordinal = endpoint_count;
            pin.parent_value_column =
                placement.attachment.ParentColumn(
                    product.endpoint_value_columns[
                        endpoint]);
            if (pin.parent_value_column >=
                parent_cs.n_columns) {
                Note(why, "endpoint_parent_column");
                return false;
            }

            pin.bank_value_column =
                parent_cs.n_columns++;
            const gf::Fp3 value =
                parent_columns[
                    pin.parent_value_column][0];
            parent_columns.push_back(
                std::vector<gf::Fp3>(
                    parent_cs.n_rows, value));
            AddEndpointValueAlias(
                parent_cs, pin.bank_value_column,
                pin.parent_value_column);

            pin.committed_root =
                product.endpoint_committed_roots[
                    endpoint];
            const auto root_words =
                Root8(pin.committed_root);
            for (uint32_t word = 0;
                 word < root_words.size(); ++word) {
                pin.root_word_columns[word] =
                    parent_cs.n_columns++;
                parent_columns.push_back(
                    std::vector<gf::Fp3>(
                        parent_cs.n_rows,
                        gf::Fp3::FromFp(
                            gf::FromU64(
                                root_words[word]))));
                AddRootBankPin(
                    parent_cs,
                    pin.root_word_columns[word],
                    root_words[word]);
            }
            pin.literal_value_alias = true;
            placement.endpoints.push_back(pin);
            ++endpoint_count;
        }
    }
    if (endpoint_count !=
        expected_endpoint_count) {
        Note(why, "endpoint_bank_count");
        return false;
    }
    return true;
}

bool AppendDirectBuilderStreamChildren(
    const std::array<
        RCStage3StreamEndpointManifest, 2>&
        manifests,
    const std::array<
        RCStage3StreamEndpointClosure, 2>&
        closures,
    uint32_t parent_rows,
    AirCS& parent_cs,
    std::vector<std::vector<gf::Fp3>>&
        parent_columns,
    std::vector<ProductionRolePlacementV1>&
        placements,
    std::vector<
        ProductionDirectStreamChildPlacementV1>&
        out,
    std::string* why)
{
    if (placements.empty() ||
        placements.front().role !=
            Role::EpisodeDeterministicBuilder ||
        placements.front().endpoints.size() != 4 ||
        parent_rows < 2) {
        Note(why, "builder_direct_parent_shape");
        return false;
    }
    constexpr std::array<
        RCStage3RelationEndpoint, 2>
        endpoints{
            RCStage3RelationEndpoint::
                EpisodeBuilderSeedChain,
            RCStage3RelationEndpoint::
                EpisodeBuilderOperandXof,
        };
    out.clear();
    out.reserve(endpoints.size());
    for (uint32_t child = 0;
         child < endpoints.size(); ++child) {
        const auto& closure = closures[child];
        const auto& role_pin =
            placements.front().endpoints[
                child + 1U];
        if (!closure.ok ||
            role_pin.endpoint != endpoints[child] ||
            closure.family !=
                RCStage3StreamFamilyForEndpoint(
                    endpoints[child]) ||
            closure.child_value_export_column >=
                closure.child_cs.n_columns ||
            closure.child_output_export_base + 8U >
                closure.child_cs.n_columns) {
            Note(why, "builder_direct_child_shape");
            return false;
        }

        // The standalone child pins its own R0 commitment so a Split-RAP
        // receipt can be verified.  Horizontal composition commits one
        // different global row, so those commitment pins are intentionally
        // removed; every preprocessed value and every semantic constraint is
        // still appended and the final parent proof rebuilds one global root.
        AirCS child_cs = closure.child_cs;
        child_cs.preprocessed_roots.clear();
        child_cs.preprocessed_row_group_roots.clear();

        ProductionDirectStreamChildPlacementV1
            placed;
        placed.endpoint = endpoints[child];
        placed.manifest = manifests[child];
        placed.child_rows =
            closure.child_cs.n_rows;
        std::string compose_why;
        if (!composer::AppendChildLiftedV1(
                parent_cs, parent_columns,
                child_cs, closure.child_witness,
                parent_rows,
                static_cast<uint32_t>(
                    placements.size()) +
                    child,
                placed.attachment,
                &compose_why)) {
            Note(
                why,
                "builder_direct_child_append:" +
                    compose_why);
            return false;
        }

        placed.child_value_parent_column =
            placed.attachment.ParentColumn(
                closure
                    .child_value_export_column);
        placed.role_bank_value_column =
            role_pin.bank_value_column;
        AddSameParentFirstRowAlias(
            parent_cs,
            placed.child_value_parent_column,
            placed.role_bank_value_column,
            "stage3.production_builder_child."
            "value_same_parent_alias");
        placed.value_same_parent_aliased = true;
        for (uint32_t word = 0; word < 8;
             ++word) {
            placed.child_root_parent_columns[word] =
                placed.attachment.ParentColumn(
                    closure
                        .child_output_export_base +
                    word);
            placed.role_root_word_columns[word] =
                role_pin.root_word_columns[word];
            AddSameParentFirstRowAlias(
                parent_cs,
                placed
                    .child_root_parent_columns[
                        word],
                placed.role_root_word_columns[word],
                "stage3.production_builder_child."
                "root_same_parent_alias");
        }
        placed.root_same_parent_aliased = true;
        placed.complete_relation_same_parent =
            placed.attachment.valid &&
            placed.value_same_parent_aliased &&
            placed.root_same_parent_aliased;
        out.push_back(std::move(placed));
    }
    return out.size() == endpoints.size() &&
        std::all_of(
            out.begin(), out.end(),
            [](const auto& child) {
                return child
                    .complete_relation_same_parent;
            });
}

bool AssembleDirectBuilderParent(
    const std::vector<RCStage3RoleAirProduct>&
        products,
    const std::array<
        RCStage3StreamEndpointManifest, 2>&
        manifests,
    const std::array<
        RCStage3StreamEndpointClosure, 2>&
        closures,
    uint32_t common_rows,
    uint32_t expected_endpoint_count,
    ProductionRelationParentCandidateV1& out,
    std::string* why)
{
    out.cs = {};
    out.columns.clear();
    out.roles.clear();
    out.direct_builder_stream_children.clear();

    out.roles.reserve(products.size());
    for (uint32_t ordinal = 0;
         ordinal < products.size(); ++ordinal) {
        std::string compose_why;
        ProductionRolePlacementV1 placement;
        placement.role = products[ordinal].role;
        if (!composer::AppendChildLiftedV1(
                out.cs, out.columns,
                products[ordinal].cs,
                products[ordinal].witness,
                common_rows, ordinal,
                placement.attachment,
                &compose_why)) {
            Note(
                why,
                "role_append:" + compose_why);
            return false;
        }
        out.roles.push_back(std::move(placement));
    }
    if (!AppendCanonicalEndpointBank(
            products, out.cs, out.columns,
            out.roles, expected_endpoint_count,
            why) ||
        !AppendDirectBuilderStreamChildren(
            manifests, closures, common_rows,
            out.cs, out.columns, out.roles,
            out.direct_builder_stream_children,
            why)) {
        return false;
    }
    return true;
}

std::vector<uint32_t>
DirectParentBaseColumns(
    const ProductionRelationParentCandidateV1& parent,
    const std::array<
        RCStage3StreamEndpointClosure, 2>&
        closures)
{
    std::vector<uint32_t> out;
    if (parent.direct_builder_stream_children.size() !=
        closures.size()) {
        return out;
    }
    const uint32_t ordinary_parent_columns =
        parent.direct_builder_stream_children.front()
            .attachment.column_base;
    out.reserve(
        ordinary_parent_columns + 4096U);
    for (uint32_t column = 0;
         column < ordinary_parent_columns;
         ++column) {
        out.push_back(column);
    }
    for (uint32_t child = 0;
         child < closures.size(); ++child) {
        const auto& attachment =
            parent.direct_builder_stream_children[
                child].attachment;
        const auto& closure = closures[child];
        const uint32_t semantic_columns =
            closure.child_cs.n_columns;
        std::vector<uint32_t> local_base;
        for (const auto& pin :
             closure.child_cs
                 .preprocessed_row_group_roots) {
            if (pin.version == 1 &&
                pin.role ==
                    air_quotient::
                        AirPreprocessedRowGroupRole::
                            kR0) {
                local_base = pin.ordered_columns;
                break;
            }
        }
        // The three stream-word address selectors are appended after the
        // standalone R0 was committed.  They are fixed schedule columns and
        // belong to the global parent's pre-challenge group.
        if (semantic_columns < 7U) {
            return {};
        }
        const uint32_t value_selector_base =
            semantic_columns - 3U;
        for (uint32_t selector = 0;
             selector < 3; ++selector) {
            local_base.push_back(
                value_selector_base + selector);
        }
        std::sort(
            local_base.begin(), local_base.end());
        local_base.erase(
            std::unique(
                local_base.begin(),
                local_base.end()),
            local_base.end());
        for (uint32_t local : local_base) {
            if (local >= semantic_columns) {
                return {};
            }
            out.push_back(
                attachment.ParentColumn(local));
            out.push_back(
                attachment.ParentColumn(
                    semantic_columns + local));
        }
        // AppendChildLiftedV1 owns five fixed selectors after ordinary and
        // wrap columns.
        for (uint32_t selector = 0;
             selector < 5; ++selector) {
            out.push_back(
                attachment.ParentColumn(
                    2U * semantic_columns +
                    selector));
        }
    }
    std::sort(out.begin(), out.end());
    out.erase(
        std::unique(out.begin(), out.end()),
        out.end());
    return out;
}

} // namespace

const char* ProductionParentBuildStatusNameV1(
    ProductionParentBuildStatusV1 status)
{
    switch (status) {
    case ProductionParentBuildStatusV1::NotRequired:
        return "not_required";
    case ProductionParentBuildStatusV1::InvalidRequest:
        return "invalid_request";
    case ProductionParentBuildStatusV1::UnsupportedStatement:
        return "unsupported_statement";
    case ProductionParentBuildStatusV1::ProgramRegistryUnavailable:
        return "program_registry_unavailable";
    case ProductionParentBuildStatusV1::CompleteRelationParentUnavailable:
        return "complete_relation_parent_unavailable";
    case ProductionParentBuildStatusV1::Built:
        return "built";
    }
    return "unknown";
}

bool BuildDirectBuilderStreamParentCanaryV1(
    const std::array<
        RCStage3StreamEndpointManifest, 2>&
        manifests,
    const uint256& public_fs_seed,
    ProductionRelationParentCandidateV1& out,
    std::string* why)
{
    out = {};
    if (public_fs_seed.IsNull()) {
        Note(why, "builder_canary_seed");
        return false;
    }
    const std::vector<gf::Fp3> openings{
        gf::Fp3::FromFp(gf::FromU64(1))};
    const std::vector<
        RCStage3StreamEndpointManifest>
        stream_manifests{
            manifests.begin(), manifests.end()};
    std::vector<RCStage3RoleAirProduct>
        products;
    products.push_back(
        BuildRCStage3NoKernelRoleAir(
            Role::EpisodeDeterministicBuilder,
            why, &openings, nullptr,
            &stream_manifests));
    if (!products.front().ok) {
        Note(why, "builder_canary_role");
        return false;
    }

    constexpr std::array<
        RCStage3RelationEndpoint, 2>
        endpoints{
            RCStage3RelationEndpoint::
                EpisodeBuilderSeedChain,
            RCStage3RelationEndpoint::
                EpisodeBuilderOperandXof,
        };
    std::array<
        RCStage3StreamEndpointClosure, 2>
        closures;
    uint32_t common_rows =
        products.front().cs.n_rows;
    for (uint32_t child = 0;
         child < closures.size(); ++child) {
        closures[child] =
            RCStage3StreamEndpointClose(
                RCStage3StreamFamilyForEndpoint(
                    endpoints[child]),
                manifests[child], public_fs_seed,
                nullptr, false);
        if (!closures[child].ok) {
            Note(
                why,
                "builder_canary_child:" +
                    closures[child].note);
            return false;
        }
        common_rows =
            std::max(
                common_rows,
                closures[child].child_cs.n_rows);
    }
    if (!PowerOfTwo(common_rows) ||
        !AssembleDirectBuilderParent(
            products, manifests, closures,
            common_rows, 4U, out, why)) {
        return false;
    }
    const std::vector<uint32_t> base_columns =
        DirectParentBaseColumns(out, closures);
    std::string base_why;
    const uint256 base_root =
        air_quotient::
            AirQuotientTwoEpochBaseRowCommitment(
                out.cs, out.columns,
                base_columns, &base_why);
    if (base_columns.empty() ||
        base_root.IsNull()) {
        Note(
            why,
            "builder_canary_base:" + base_why);
        return false;
    }
    for (uint32_t child = 0;
         child < closures.size(); ++child) {
        closures[child] =
            RCStage3StreamEndpointClose(
                RCStage3StreamFamilyForEndpoint(
                    endpoints[child]),
                manifests[child], public_fs_seed,
                nullptr, false, base_root);
        if (!closures[child].ok) {
            Note(
                why,
                "builder_canary_child_rebuild:" +
                    closures[child].note);
            return false;
        }
    }
    if (!AssembleDirectBuilderParent(
            products, manifests, closures,
            common_rows, 4U, out, why)) {
        return false;
    }
    out.direct_parent_base_column_indices =
        DirectParentBaseColumns(out, closures);
    if (out.direct_parent_base_column_indices !=
        base_columns) {
        Note(why, "builder_canary_base_columns_drift");
        return false;
    }
    out.direct_parent_base_row_root = base_root;
    out.direct_builder_public_fs_seed =
        public_fs_seed;
    out.cs.preprocessed_row_group_roots.push_back(
        {
            .version = 1,
            .role =
                air_quotient::
                    AirPreprocessedRowGroupRole::kR0,
            .ordered_columns =
                out.direct_parent_base_column_indices,
            .root =
                out.direct_parent_base_row_root,
        });
    out.endpoint_count = 4;
    out.all_endpoint_cells_literal = true;
    out.builder_stream_relations_same_parent =
        out.direct_builder_stream_children.size() ==
            2U &&
        std::all_of(
            out.direct_builder_stream_children.begin(),
            out.direct_builder_stream_children.end(),
            [](const auto& child) {
                return child
                    .complete_relation_same_parent;
            });
    out.witness_violations =
        air_recurse::CountWitnessViolationsOnH(
            out.cs, out.columns);
    out.local_parent_valid =
        out.builder_stream_relations_same_parent &&
        out.witness_violations == 0;
    out.recursive_semantic_closure_complete =
        false;
    out.production_authority = false;
    out.note =
        out.local_parent_valid
        ? "stage3:normalized_production_parent_builder:"
          "bounded_direct_builder_parent_valid"
        : "stage3:normalized_production_parent_builder:"
          "bounded_direct_builder_parent_invalid";
    if (!out.local_parent_valid) {
        Note(why, "builder_canary_invalid");
        return false;
    }
    if (why != nullptr) *why = out.note;
    return true;
}

bool BuildRelationParentCandidateForSolvedBlockV1(
    const ProductionParentBuildInputV1& input,
    ProductionRelationParentCandidateV1& out,
    std::string* why)
{
    out = {};
    if (input.version !=
            kProductionParentBuildInputVersionV1 ||
        input.solved_block == nullptr ||
        input.params == nullptr ||
        input.height < 0 ||
        input.target.IsNull()) {
        Note(why, "request");
        return false;
    }
    const auto statement =
        RequiredRCStage3Statement(
            *input.params, input.height);
    if (!statement.has_value() ||
        *statement != RCStage3StatementKind::Composed) {
        Note(why, "composed_statement_required");
        return false;
    }

    std::vector<RCStage3RoleAirProduct> products;
    std::array<
        RCStage3StreamEndpointManifest, 2>
        builder_stream_manifests;
    if (!BuildBlockRoleProducts(
            input, products,
            builder_stream_manifests,
            out.episode_digest,
            out.coupled_digest, out.composed_digest,
            why)) {
        return false;
    }

    out.direct_builder_public_fs_seed =
        input.solved_block->GetHash();
    if (out.direct_builder_public_fs_seed.IsNull()) {
        Note(why, "builder_direct_public_seed");
        return false;
    }
    std::array<
        RCStage3StreamEndpointClosure, 2>
        builder_stream_closures;
    constexpr std::array<
        RCStage3RelationEndpoint, 2>
        builder_stream_endpoints{
            RCStage3RelationEndpoint::
                EpisodeBuilderSeedChain,
            RCStage3RelationEndpoint::
                EpisodeBuilderOperandXof,
        };
    for (uint32_t child = 0;
         child < builder_stream_closures.size();
         ++child) {
        builder_stream_closures[child] =
            RCStage3StreamEndpointClose(
                RCStage3StreamFamilyForEndpoint(
                    builder_stream_endpoints[child]),
                builder_stream_manifests[child],
                out.direct_builder_public_fs_seed,
                nullptr,
                /*run_cs_checks=*/false);
        if (!builder_stream_closures[child].ok) {
            Note(
                why,
                "builder_direct_child:" +
                    builder_stream_closures[child]
                        .note);
            return false;
        }
    }

    uint32_t common_rows = 0;
    for (const auto& product : products) {
        common_rows =
            std::max(common_rows, product.cs.n_rows);
    }
    for (const auto& closure :
         builder_stream_closures) {
        common_rows =
            std::max(
                common_rows,
                closure.child_cs.n_rows);
    }
    if (!PowerOfTwo(common_rows)) {
        Note(why, "common_rows");
        return false;
    }

    // Assemble once to retain the exact global pre-challenge group. Rebuild
    // both SHA children from that parent-owned R0 root, then assemble the
    // final parent with those derived CTL challenges. This prevents a prover
    // from choosing the heavy-child witness after seeing its LogUp challenge.
    if (!AssembleDirectBuilderParent(
            products,
            builder_stream_manifests,
            builder_stream_closures,
            common_rows,
            kRCStage3RelationClosureEndpointCount,
            out,
            why)) {
        return false;
    }
    const std::vector<uint32_t>
        parent_base_columns =
            DirectParentBaseColumns(
                out, builder_stream_closures);
    if (parent_base_columns.empty()) {
        Note(why, "builder_direct_parent_base_columns");
        return false;
    }
    std::string base_why;
    const uint256 parent_base_root =
        air_quotient::
            AirQuotientTwoEpochBaseRowCommitment(
                out.cs, out.columns,
                parent_base_columns, &base_why);
    if (parent_base_root.IsNull()) {
        Note(
            why,
            "builder_direct_parent_base_root:" +
                base_why);
        return false;
    }
    for (uint32_t child = 0;
         child < builder_stream_closures.size();
         ++child) {
        builder_stream_closures[child] =
            RCStage3StreamEndpointClose(
                RCStage3StreamFamilyForEndpoint(
                    builder_stream_endpoints[child]),
                builder_stream_manifests[child],
                out.direct_builder_public_fs_seed,
                nullptr,
                /*run_cs_checks=*/false,
                parent_base_root);
        if (!builder_stream_closures[child].ok) {
            Note(
                why,
                "builder_direct_child_rebuild:" +
                    builder_stream_closures[child]
                        .note);
            return false;
        }
    }
    if (!AssembleDirectBuilderParent(
            products, builder_stream_manifests,
            builder_stream_closures,
            common_rows,
            kRCStage3RelationClosureEndpointCount,
            out, why)) {
        return false;
    }
    out.direct_parent_base_column_indices =
        DirectParentBaseColumns(
            out, builder_stream_closures);
    if (out.direct_parent_base_column_indices !=
            parent_base_columns ||
        air_quotient::
            AirQuotientTwoEpochBaseRowCommitment(
                out.cs, out.columns,
                out.direct_parent_base_column_indices,
                &base_why) != parent_base_root) {
        Note(why, "builder_direct_parent_base_drift");
        return false;
    }
    out.direct_parent_base_row_root =
        parent_base_root;
    out.cs.preprocessed_row_group_roots.push_back(
        {
            .version = 1,
            .role =
                air_quotient::
                    AirPreprocessedRowGroupRole::kR0,
            .ordered_columns =
                out.direct_parent_base_column_indices,
            .root =
                out.direct_parent_base_row_root,
        });
    out.builder_stream_relations_same_parent =
        out.direct_builder_stream_children.size() ==
            2U &&
        std::all_of(
            out.direct_builder_stream_children.begin(),
            out.direct_builder_stream_children.end(),
            [](const auto& child) {
                return child
                    .complete_relation_same_parent;
            });

    out.endpoint_count = 0;
    out.exact_role_order =
        out.roles.size() ==
        RCStage3UnifiedRoleOrder().size();
    out.exact_endpoint_order =
        out.exact_role_order;
    out.all_endpoint_cells_literal =
        out.exact_role_order;
    for (uint32_t role = 0;
         role < out.roles.size(); ++role) {
        const auto& placement = out.roles[role];
        if (placement.role !=
            RCStage3UnifiedRoleOrder()[role] ||
            placement.endpoints.size() !=
                RequiredRCStage3RelationEndpoints(
                    placement.role).size()) {
            out.exact_role_order = false;
            out.exact_endpoint_order = false;
        }
        for (uint32_t endpoint = 0;
             endpoint <
                 placement.endpoints.size();
             ++endpoint) {
            const auto& pin =
                placement.endpoints[endpoint];
            if (pin.endpoint !=
                    RequiredRCStage3RelationEndpoints(
                        placement.role)[endpoint] ||
                pin.endpoint_ordinal !=
                    out.endpoint_count) {
                out.exact_endpoint_order = false;
            }
            out.all_endpoint_cells_literal =
                out.all_endpoint_cells_literal &&
                pin.literal_value_alias;
            ++out.endpoint_count;
        }
    }

    out.witness_violations =
        air_recurse::CountWitnessViolationsOnH(
            out.cs, out.columns);
    out.local_parent_valid =
        out.exact_role_order &&
        out.exact_endpoint_order &&
        out.endpoint_count ==
            kRCStage3RelationClosureEndpointCount &&
        out.all_endpoint_cells_literal &&
        out.builder_stream_relations_same_parent &&
        out.witness_violations == 0;

    out.recursive_semantic_closure_complete = true;
    for (const auto& audit :
         CurrentRCStage3RelationClosureRoleAudit()) {
        if (!audit.role_complete ||
            !audit.recursive_ctl_consumption ||
            audit.proof_derived_ctl_endpoints !=
                audit.required_endpoints) {
            out.recursive_semantic_closure_complete =
                false;
            out.residuals.push_back(
                std::string{
                    RCStage3RelationRoleName(
                        audit.role)} +
                ":" + audit.remaining);
        }
    }
    out.production_authority =
        out.local_parent_valid &&
        out.recursive_semantic_closure_complete;
    out.note =
        out.production_authority
            ? "stage3:normalized_production_parent_builder:"
              "complete_relation_parent_candidate"
            : "stage3:normalized_production_parent_builder:"
              "local_14_role_52_endpoint_parent_valid;"
              "recursive_semantic_child_consumption_open";
    if (!out.local_parent_valid) {
        Note(why, "local_parent_invalid");
        return false;
    }
    if (why != nullptr) *why = out.note;
    return true;
}

ProductionParentBuildStatusV1 BuildForSolvedBlockV1(
    const ProductionParentBuildInputV1& input,
    consumer::CanonicalRelationParentProductV1& out,
    std::string* why)
{
    out = {};
    if (input.version !=
            kProductionParentBuildInputVersionV1 ||
        input.solved_block == nullptr ||
        input.params == nullptr ||
        input.height < 0 ||
        input.target.IsNull()) {
        Note(why, "request");
        return ProductionParentBuildStatusV1::
            InvalidRequest;
    }
    const auto statement =
        RequiredRCStage3Statement(
            *input.params, input.height);
    if (!statement.has_value()) {
        Note(why, "not_required");
        return ProductionParentBuildStatusV1::
            NotRequired;
    }
    if (*statement !=
        RCStage3StatementKind::Composed) {
        Note(
            why,
            "complete_normalized_parent_requires_"
            "composed_episode_and_coupled_statement");
        return ProductionParentBuildStatusV1::
            UnsupportedStatement;
    }
    ProductionProgramConsensusPinV1 registry_pin;
    registry_pin.recursive_alg_hash_root =
        input.params
            ->hashMatMulRCStage3ProgramRegistryAlgRoot;
    registry_pin.external_sha256d_audit_root =
        input.params
            ->hashMatMulRCStage3ProgramRegistryShaAuditRoot;
    registry_pin.registry_binding =
        input.params
            ->hashMatMulRCStage3ProgramRegistryBinding;
    std::string pin_why;
    if (!ValidateProductionProgramConsensusPinV1(
            registry_pin, &pin_why)) {
        Note(why, "program_registry:" + pin_why);
        return ProductionParentBuildStatusV1::
            ProgramRegistryUnavailable;
    }

    // Avoid recomputing a datacenter-scale winner only to discover a static
    // semantic child is still absent.  This is not a readiness shortcut: the
    // same audit is recomputed again inside the candidate, and the candidate
    // remains directly executable in the gated real-data harness.
    for (const auto& audit :
         CurrentRCStage3RelationClosureRoleAudit()) {
        if (!audit.role_complete ||
            !audit.recursive_ctl_consumption ||
            audit.proof_derived_ctl_endpoints !=
                audit.required_endpoints) {
            Note(
                why,
                "complete_relation_parent:"
                "block_to_14_role_52_endpoint_assembler_available;"
                "recursive_semantic_child_consumption_open");
            return ProductionParentBuildStatusV1::
                CompleteRelationParentUnavailable;
        }
    }

    ProductionRelationParentCandidateV1 candidate;
    std::string candidate_why;
    if (!BuildRelationParentCandidateForSolvedBlockV1(
            input, candidate, &candidate_why)) {
        Note(why, "relation_parent:" + candidate_why);
        return ProductionParentBuildStatusV1::
            CompleteRelationParentUnavailable;
    }
    if (!candidate.production_authority) {
        Note(
            why,
            "complete_relation_parent:"
            "local_14_role_52_endpoint_parent_built;"
            "recursive_semantic_child_consumption_open");
        return ProductionParentBuildStatusV1::
            CompleteRelationParentUnavailable;
    }

    // This is intentionally unreachable while the live semantic audit reports
    // any incomplete role.  Once those child proofs are actually consumed,
    // this is the single remaining conversion: retain one global R0, build the
    // independently reconstructible NAV3 inventory, and move the exact parent
    // CS/columns into the executable receipt consumer.
    Note(
        why,
        "complete_relation_parent:"
        "nav3_public_inventory_conversion_open");
    return ProductionParentBuildStatusV1::
        CompleteRelationParentUnavailable;
}

} // namespace matmul::v4::rc::normalized_production_parent_builder
