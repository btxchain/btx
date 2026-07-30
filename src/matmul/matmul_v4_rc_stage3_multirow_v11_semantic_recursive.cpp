// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_multirow_v11_semantic_recursive.h>

#include <matmul/matmul_v4_rc_air_recurse.h>

#include <algorithm>
#include <functional>
#include <limits>
#include <set>

namespace matmul::v4::rc::multirow_v11_semantic_recursive {
namespace {

namespace ar = air_recurse;
namespace exports = multirow_v11_semantic_exports;
namespace pa = stage3_poseidon_air;

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why =
            "stage3:multirow_v11_semantic_recursive:" +
            detail;
    }
    return false;
}

gf::Fp3 U32(uint32_t value)
{
    return gf::Fp3::FromFp(gf::FromU64(value));
}

void PushU32(std::vector<gf::Fp>& lanes, uint32_t value)
{
    lanes.push_back(gf::FromU64(value));
}

void PushU64(std::vector<gf::Fp>& lanes, uint64_t value)
{
    PushU32(lanes, static_cast<uint32_t>(value));
    PushU32(lanes, static_cast<uint32_t>(value >> 32));
}

void PushBytes(
    std::vector<gf::Fp>& lanes,
    const unsigned char* bytes,
    size_t length)
{
    PushU64(lanes, length);
    for (size_t offset = 0; offset < length; offset += 4) {
        uint32_t word = 0;
        for (size_t byte = 0;
             byte < 4 && offset + byte < length;
             ++byte) {
            word |=
                static_cast<uint32_t>(
                    bytes[offset + byte])
                << (8U * byte);
        }
        PushU32(lanes, word);
    }
}

void PushString(
    std::vector<gf::Fp>& lanes,
    const char* text)
{
    const size_t length = std::char_traits<char>::length(text);
    PushBytes(
        lanes,
        reinterpret_cast<const unsigned char*>(text),
        length);
}

std::array<uint32_t, kWordsV1> U256Words(
    const uint256& value)
{
    std::array<uint32_t, kWordsV1> out{};
    for (uint32_t word = 0; word < out.size(); ++word) {
        for (uint32_t byte = 0; byte < 4; ++byte) {
            out[word] |=
                static_cast<uint32_t>(
                    value.data()[4U * word + byte])
                << (8U * byte);
        }
    }
    return out;
}

void PushU256(
    std::vector<gf::Fp>& lanes,
    const uint256& value)
{
    for (uint32_t word : U256Words(value)) {
        PushU32(lanes, word);
    }
}

uint256 PackDigest(const alg_hash::Digest& digest)
{
    return Fri3AlgDigestToUint256(digest);
}

uint256 P2Commit(const std::vector<gf::Fp>& lanes)
{
    return PackDigest(alg_hash::SpongeHashFp(lanes));
}

bool CanonicalDigest(const uint256& value)
{
    return !value.IsNull() &&
        Fri3AlgDigestFromUint256(value).has_value();
}

std::array<uint32_t, kWordsV1> RootWords(
    const alg_hash::Digest& root,
    bool* canonical = nullptr)
{
    std::array<uint32_t, kWordsV1> out{};
    bool ok = true;
    for (uint32_t lane = 0; lane < root.size(); ++lane) {
        ok &= root[lane] < gf::kP;
        const uint64_t value = gf::Canonical(root[lane]);
        out[2U * lane] =
            static_cast<uint32_t>(value);
        out[2U * lane + 1U] =
            static_cast<uint32_t>(value >> 32);
    }
    if (canonical != nullptr) *canonical = ok;
    return out;
}

uint256 SideAuthenticationRoot(
    const char* domain,
    RCStage3RelationEndpoint endpoint,
    RCStage3RelationRole role,
    uint32_t ordinal,
    OutputOriginV1 origin,
    const uint256& statement_root,
    const uint256& program_root,
    const uint256& transcript_root,
    const std::array<uint64_t, kWordsV1>& words)
{
    std::vector<gf::Fp> lanes;
    PushString(lanes, domain);
    PushU32(lanes, kVersionV1);
    PushU32(lanes, static_cast<uint16_t>(endpoint));
    PushU32(lanes, static_cast<uint8_t>(role));
    PushU32(lanes, ordinal);
    PushU32(lanes, static_cast<uint32_t>(origin));
    PushU256(lanes, statement_root);
    PushU256(lanes, program_root);
    PushU256(lanes, transcript_root);
    PushU32(lanes, words.size());
    for (uint64_t word : words) {
        PushU32(lanes, static_cast<uint32_t>(word));
    }
    return P2Commit(lanes);
}

bool CanonicalRoles(
    const std::vector<RCStage3RoleAirProduct>& roles,
    std::string* why)
{
    const auto order = RCStage3UnifiedRoleOrder();
    if (roles.size() != order.size()) {
        return Fail(why, "role_count");
    }
    std::set<uint16_t> seen;
    for (uint32_t i = 0; i < roles.size(); ++i) {
        const auto& role = roles[i];
        if (role.role != order[i] ||
            !seen.insert(
                static_cast<uint16_t>(
                    role.role)).second) {
            return Fail(why, "role_order_or_duplicate");
        }
        const auto local =
            exports::BuildProductV1({role}, {});
        if (!local.all_supplied_artifacts_valid ||
            local.role_proofs.size() != 1 ||
            !exports::ValidateRoleExportProofV1(
                local.role_proofs.front(), why)) {
            return Fail(why, "role_air");
        }
    }
    return true;
}

const RCStage3RoleAirProduct* FindRole(
    const std::vector<RCStage3RoleAirProduct>& roles,
    RCStage3RelationRole role)
{
    const auto found = std::find_if(
        roles.begin(), roles.end(),
        [role](const RCStage3RoleAirProduct& item) {
            return item.role == role;
        });
    return found == roles.end() ? nullptr : &*found;
}

bool IsHeavy(RCStage3RelationEndpoint endpoint)
{
    const auto routes = heavy::CanonicalHeavyRoutesV1();
    return std::any_of(
        routes.begin(), routes.end(),
        [endpoint](const heavy::HeavyRouteV1& route) {
            return route.endpoint == endpoint;
        });
}

const alg_hash::Digest* EndpointRoot(
    const RCStage3RoleAirProduct& role,
    RCStage3RelationEndpoint endpoint)
{
    const auto found = std::find(
        role.endpoints.begin(),
        role.endpoints.end(), endpoint);
    if (found == role.endpoints.end()) return nullptr;
    const size_t index =
        static_cast<size_t>(
            found - role.endpoints.begin());
    if (index >=
        role.endpoint_committed_roots.size()) {
        return nullptr;
    }
    return &role.endpoint_committed_roots[index];
}

bool CanonicalBlock(
    const ReceiptOutputBlockV1& block,
    const exports::CanonicalExportRouteV1& route,
    const uint256& statement_root,
    const uint256& program_root,
    const uint256& transcript_root,
    std::string* why)
{
    const OutputOriginV1 expected_origin =
        IsHeavy(route.endpoint)
        ? OutputOriginV1::HeavyVerifierReceiptR0
        : OutputOriginV1::ExistingRoleDirectAlias;
    if (block.endpoint != route.endpoint ||
        block.role != route.role ||
        block.ordinal != route.ordinal ||
        block.origin != expected_origin ||
        block.statement_root != statement_root ||
        block.program_root != program_root ||
        block.transcript_root != transcript_root) {
        return Fail(why, "block_route_or_common_root");
    }
    for (uint64_t word : block.producer_words) {
        if (word > UINT32_MAX) {
            return Fail(why, "producer_noncanonical_u32");
        }
    }
    for (uint64_t word : block.consumer_words) {
        if (word > UINT32_MAX) {
            return Fail(why, "consumer_noncanonical_u32");
        }
    }
    if (block.producer_words !=
        block.consumer_words) {
        return Fail(why, "producer_consumer");
    }
    const uint256 producer =
        SideAuthenticationRoot(
            "BTX_RC_STAGE3_MULTIROW_V11_SEMANTIC_RECURSIVE_PRODUCER_V1",
            block.endpoint, block.role,
            block.ordinal, block.origin,
            statement_root, program_root,
            transcript_root, block.producer_words);
    const uint256 consumer =
        SideAuthenticationRoot(
            "BTX_RC_STAGE3_MULTIROW_V11_SEMANTIC_RECURSIVE_CONSUMER_V1",
            block.endpoint, block.role,
            block.ordinal, block.origin,
            statement_root, program_root,
            transcript_root, block.consumer_words);
    if (!CanonicalDigest(
            block.producer_authentication_root) ||
        !CanonicalDigest(
            block.consumer_authentication_root) ||
        block.producer_authentication_root != producer ||
        block.consumer_authentication_root != consumer) {
        return Fail(why, "block_authentication_root");
    }
    return true;
}

std::vector<gf::Fp> DomainHeaderLanes()
{
    std::vector<gf::Fp> domain;
    PushString(
        domain,
        "BTX_RC_STAGE3_MULTIROW_V11_SEMANTIC_RECURSIVE_ORDERED_SET_V1");
    const auto digest = alg_hash::SpongeHashFp(domain);
    const auto words =
        U256Words(PackDigest(digest));
    std::vector<gf::Fp> out;
    out.reserve(kHeaderLanesV1);
    for (uint32_t word : words) PushU32(out, word);
    PushU32(out, kVersionV1);
    PushU32(out, kEndpointCountV1);
    PushU32(out, kBlockLanesV1);
    PushU32(
        out,
        kHeaderLanesV1 +
            kEndpointCountV1 * kBlockLanesV1);
    PushU32(out, kHeaderLanesV1);
    while (out.size() < kHeaderLanesV1) {
        PushU32(out, 0);
    }
    return out;
}

std::vector<gf::Fp> OrderedPayload(
    const std::vector<ReceiptOutputBlockV1>& blocks)
{
    std::vector<gf::Fp> out = DomainHeaderLanes();
    out.reserve(
        kHeaderLanesV1 +
        blocks.size() * kBlockLanesV1);
    for (uint32_t i = 0; i < blocks.size(); ++i) {
        const auto& block = blocks[i];
        std::vector<gf::Fp> lanes;
        lanes.reserve(kBlockLanesV1);
        PushU32(lanes, kBlockLanesV1);
        PushU32(lanes, i);
        PushU32(
            lanes,
            static_cast<uint32_t>(block.origin));
        PushU32(lanes, 0);
        PushU32(
            lanes,
            static_cast<uint16_t>(block.endpoint));
        PushU32(
            lanes,
            static_cast<uint8_t>(block.role));
        PushU32(lanes, block.ordinal);
        PushU32(
            lanes,
            static_cast<uint32_t>(block.origin));
        PushU256(lanes, block.statement_root);
        PushU256(lanes, block.program_root);
        PushU256(lanes, block.transcript_root);
        PushU256(
            lanes,
            block.producer_authentication_root);
        PushU256(
            lanes,
            block.consumer_authentication_root);
        for (uint64_t word : block.producer_words) {
            PushU32(lanes, static_cast<uint32_t>(word));
        }
        for (uint64_t word : block.consumer_words) {
            PushU32(lanes, static_cast<uint32_t>(word));
        }
        if (lanes.size() != kBlockLanesV1) {
            return {};
        }
        out.insert(out.end(), lanes.begin(), lanes.end());
    }
    return out;
}

uint32_t NextPow2(uint32_t value)
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

void Add(
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

void AddBoolean(
    aq::AirConstraintSystem<gf::Fp3>& cs,
    const char* name,
    uint32_t column)
{
    Add(
        cs, name, aq::AirKind::kEverywhere, 2,
        [column](const auto& current, const auto&) {
            return gf::Mul(
                current[column],
                gf::Sub(
                    current[column],
                    gf::Fp3::One()));
        });
}

gf::Fp3 PermOutput(
    const pa::Layout& layout,
    const std::vector<gf::Fp3>& row,
    uint32_t lane)
{
    return ar::PermOutputLane(
        layout.perm, row, lane);
}

bool Applies(
    aq::AirKind kind,
    uint32_t row,
    uint32_t rows)
{
    switch (kind) {
    case aq::AirKind::kEverywhere: return true;
    case aq::AirKind::kTransition:
        return row + 1 < rows;
    case aq::AirKind::kFirstRow: return row == 0;
    case aq::AirKind::kLastRow:
        return row + 1 == rows;
    }
    return false;
}

bool SameFp3Vector(
    const std::vector<gf::Fp3>& a,
    const std::vector<gf::Fp3>& b)
{
    if (a.size() != b.size()) return false;
    for (uint32_t i = 0; i < a.size(); ++i) {
        if (!gf::Eq(a[i], b[i])) return false;
    }
    return true;
}

uint256 ParentSeed(
    const uint256& statement,
    const uint256& program,
    const uint256& transcript,
    const uint256& ordered)
{
    std::vector<gf::Fp> lanes;
    PushString(
        lanes,
        "BTX_RC_STAGE3_MULTIROW_V11_SEMANTIC_RECURSIVE_PARENT_SEED_V1");
    PushU32(lanes, kVersionV1);
    PushU256(lanes, statement);
    PushU256(lanes, program);
    PushU256(lanes, transcript);
    PushU256(lanes, ordered);
    return P2Commit(lanes);
}

bool SameProductShape(
    const ProductV1& a,
    const ProductV1& b)
{
    const auto same_layout =
        [](const LayoutV1& x, const LayoutV1& y) {
            return
                x.poseidon.perm.base ==
                    y.poseidon.perm.base &&
                x.poseidon.x2_base ==
                    y.poseidon.x2_base &&
                x.poseidon.x4_base ==
                    y.poseidon.x4_base &&
                x.poseidon.x6_base ==
                    y.poseidon.x6_base &&
                x.hash_active == y.hash_active &&
                x.endpoint_first == y.endpoint_first &&
                x.terminal == y.terminal &&
                x.endpoint == y.endpoint &&
                x.role == y.role &&
                x.ordinal == y.ordinal &&
                x.origin == y.origin &&
                x.statement_base == y.statement_base &&
                x.program_base == y.program_base &&
                x.transcript_base == y.transcript_base &&
                x.producer_auth_base ==
                    y.producer_auth_base &&
                x.consumer_auth_base ==
                    y.consumer_auth_base &&
                x.producer_base == y.producer_base &&
                x.consumer_base == y.consumer_base &&
                x.producer_bits_base ==
                    y.producer_bits_base &&
                x.consumer_bits_base ==
                    y.consumer_bits_base &&
                x.message_base == y.message_base &&
                x.expected_statement_base ==
                    y.expected_statement_base &&
                x.expected_program_base ==
                    y.expected_program_base &&
                x.expected_transcript_base ==
                    y.expected_transcript_base &&
                x.expected_endpoint ==
                    y.expected_endpoint &&
                x.expected_role == y.expected_role &&
                x.expected_ordinal ==
                    y.expected_ordinal &&
                x.expected_origin ==
                    y.expected_origin &&
                x.ordered_root_base ==
                    y.ordered_root_base &&
                x.total_columns == y.total_columns;
        };
    const auto same_columns =
        [](const auto& x, const auto& y) {
            if (x.size() != y.size()) return false;
            for (uint32_t col = 0; col < x.size(); ++col) {
                if (x[col].size() != y[col].size()) {
                    return false;
                }
                for (uint32_t row = 0;
                     row < x[col].size(); ++row) {
                    if (x[col][row].c0 != y[col][row].c0 ||
                        x[col][row].c1 != y[col][row].c1 ||
                        x[col][row].c2 != y[col][row].c2) {
                        return false;
                    }
                }
            }
            return true;
        };
    const auto same_preprocessed =
        [](const auto& x, const auto& y) {
            if (x.size() != y.size()) return false;
            for (uint32_t i = 0; i < x.size(); ++i) {
                if (x[i].first != y[i].first ||
                    !SameFp3Vector(
                        x[i].second,
                        y[i].second)) {
                    return false;
                }
            }
            return true;
        };
    const auto same_constraints =
        [](const auto& x, const auto& y) {
            if (x.size() != y.size()) return false;
            for (uint32_t i = 0; i < x.size(); ++i) {
                const std::string xn =
                    x[i].name == nullptr ? "" : x[i].name;
                const std::string yn =
                    y[i].name == nullptr ? "" : y[i].name;
                if (xn != yn ||
                    x[i].kind != y[i].kind ||
                    x[i].alg_degree !=
                        y[i].alg_degree) {
                    return false;
                }
            }
            return true;
        };
    return
        a.version == b.version &&
        a.expected_statement_root ==
            b.expected_statement_root &&
        a.expected_program_root ==
            b.expected_program_root &&
        a.expected_transcript_root ==
            b.expected_transcript_root &&
        a.ordered_set_root == b.ordered_set_root &&
        a.parent_fs_seed == b.parent_fs_seed &&
        a.preprocessed_row_group_root ==
            b.preprocessed_row_group_root &&
        a.preprocessed_columns ==
            b.preprocessed_columns &&
        a.blocks == b.blocks &&
        a.literal_pairs == b.literal_pairs &&
        same_layout(a.layout, b.layout) &&
        a.cs.n_rows == b.cs.n_rows &&
        a.cs.n_columns == b.cs.n_columns &&
        same_preprocessed(
            a.cs.preprocessed,
            b.cs.preprocessed) &&
        a.cs.preprocessed_pin_ood ==
            b.cs.preprocessed_pin_ood &&
        a.cs.preprocessed_row_group_roots ==
            b.cs.preprocessed_row_group_roots &&
        same_constraints(
            a.cs.constraints, b.cs.constraints) &&
        same_columns(a.columns, b.columns) &&
        a.hash_rows == b.hash_rows &&
        a.trace_rows == b.trace_rows &&
        a.trace_columns == b.trace_columns &&
        a.constraints == b.constraints &&
        a.max_degree == b.max_degree &&
        a.existing_outputs == b.existing_outputs &&
        a.heavy_outputs == b.heavy_outputs &&
        a.violations == b.violations &&
        a.role_products_canonical ==
            b.role_products_canonical &&
        a.exact_endpoint_order ==
            b.exact_endpoint_order &&
        a.exact_origin_partition ==
            b.exact_origin_partition &&
        a.common_roots_constrained ==
            b.common_roots_constrained &&
        a.producer_consumer_equality_constrained ==
            b.producer_consumer_equality_constrained &&
        a.canonical_u32_constrained ==
            b.canonical_u32_constrained &&
        a.ordered_poseidon_root_constrained ==
            b.ordered_poseidon_root_constrained &&
        a.exact_r0_root_pinned ==
            b.exact_r0_root_pinned &&
        a.child_verifier_cells_connected ==
            b.child_verifier_cells_connected &&
        a.recursive_authority ==
            b.recursive_authority &&
        a.valid_foundation == b.valid_foundation;
}

} // namespace

std::vector<ReceiptOutputBlockV1>
BuildReceiptOutputBlocksV1(
    const std::vector<RCStage3RoleAirProduct>& roles,
    const uint256& statement_root,
    const uint256& program_root,
    const uint256& transcript_root,
    std::string* why)
{
    std::vector<ReceiptOutputBlockV1> out;
    if (!CanonicalDigest(statement_root) ||
        !CanonicalDigest(program_root) ||
        !CanonicalDigest(transcript_root) ||
        !CanonicalRoles(roles, why)) {
        Fail(why, "public_root_or_roles");
        return out;
    }
    const auto routes =
        exports::CanonicalExportRoutesV1();
    out.reserve(routes.size());
    for (const auto& route : routes) {
        const auto* role =
            FindRole(roles, route.role);
        const auto* root = role == nullptr
            ? nullptr
            : EndpointRoot(*role, route.endpoint);
        bool root_canonical = false;
        if (root == nullptr) {
            Fail(why, "endpoint_root_absent");
            return {};
        }
        const auto words =
            RootWords(*root, &root_canonical);
        if (!root_canonical) {
            Fail(why, "endpoint_root_noncanonical");
            return {};
        }
        ReceiptOutputBlockV1 block;
        block.endpoint = route.endpoint;
        block.role = route.role;
        block.ordinal = route.ordinal;
        block.origin = IsHeavy(route.endpoint)
            ? OutputOriginV1::HeavyVerifierReceiptR0
            : OutputOriginV1::ExistingRoleDirectAlias;
        block.statement_root = statement_root;
        block.program_root = program_root;
        block.transcript_root = transcript_root;
        for (uint32_t word = 0; word < words.size(); ++word) {
            block.producer_words[word] = words[word];
            block.consumer_words[word] = words[word];
        }
        block.producer_authentication_root =
            SideAuthenticationRoot(
                "BTX_RC_STAGE3_MULTIROW_V11_SEMANTIC_RECURSIVE_PRODUCER_V1",
                block.endpoint, block.role,
                block.ordinal, block.origin,
                statement_root, program_root,
                transcript_root, block.producer_words);
        block.consumer_authentication_root =
            SideAuthenticationRoot(
                "BTX_RC_STAGE3_MULTIROW_V11_SEMANTIC_RECURSIVE_CONSUMER_V1",
                block.endpoint, block.role,
                block.ordinal, block.origin,
                statement_root, program_root,
                transcript_root, block.consumer_words);
        if (!CanonicalBlock(
                block, route, statement_root,
                program_root, transcript_root, why)) {
            return {};
        }
        out.push_back(std::move(block));
    }
    return out;
}

ProductV1 BuildProductV1(
    const std::vector<RCStage3RoleAirProduct>& roles,
    const uint256& statement_root,
    const uint256& program_root,
    const uint256& transcript_root)
{
    ProductV1 out;
    out.expected_statement_root = statement_root;
    out.expected_program_root = program_root;
    out.expected_transcript_root = transcript_root;
    std::string why;
    out.blocks = BuildReceiptOutputBlocksV1(
        roles, statement_root, program_root,
        transcript_root, &why);
    if (out.blocks.size() != kEndpointCountV1) {
        out.note = why;
        return out;
    }
    out.role_products_canonical = true;

    const auto routes =
        exports::CanonicalExportRoutesV1();
    out.exact_endpoint_order = true;
    out.exact_origin_partition = true;
    for (uint32_t i = 0; i < out.blocks.size(); ++i) {
        out.exact_endpoint_order &=
            out.blocks[i].endpoint == routes[i].endpoint &&
            out.blocks[i].role == routes[i].role &&
            out.blocks[i].ordinal == routes[i].ordinal;
        const bool is_heavy = IsHeavy(out.blocks[i].endpoint);
        out.exact_origin_partition &=
            out.blocks[i].origin ==
                (is_heavy
                 ? OutputOriginV1::HeavyVerifierReceiptR0
                 : OutputOriginV1::ExistingRoleDirectAlias);
        out.heavy_outputs += is_heavy;
        out.existing_outputs += !is_heavy;
        ctl::EndpointCellsV1 cells;
        cells.endpoint = out.blocks[i].endpoint;
        cells.role = out.blocks[i].role;
        cells.occurrence = out.blocks[i].ordinal;
        cells.source_words =
            out.blocks[i].producer_words;
        cells.consumer_words =
            out.blocks[i].consumer_words;
        out.literal_pairs.push_back(std::move(cells));
    }

    std::vector<gf::Fp> payload =
        OrderedPayload(out.blocks);
    if (payload.empty()) {
        out.note =
            "stage3:multirow_v11_semantic_recursive:payload";
        return out;
    }
    out.ordered_set_root =
        P2Commit(payload);
    out.parent_fs_seed =
        ParentSeed(
            statement_root, program_root,
            transcript_root, out.ordered_set_root);
    if (!CanonicalDigest(out.ordered_set_root) ||
        !CanonicalDigest(out.parent_fs_seed)) {
        out.note =
            "stage3:multirow_v11_semantic_recursive:root";
        return out;
    }

    // Exact SpongeHashFp 10* padding.
    payload.push_back(gf::FromU64(1));
    while (payload.size() % alg_hash::kAlgHashRate != 0) {
        payload.push_back(gf::FromU64(0));
    }
    out.hash_rows =
        static_cast<uint32_t>(
            payload.size() / alg_hash::kAlgHashRate);
    out.trace_rows = NextPow2(out.hash_rows);
    if (out.trace_rows == 0) {
        out.note =
            "stage3:multirow_v11_semantic_recursive:rows";
        return out;
    }

    out.layout.poseidon = pa::CanonicalLayout(0);
    uint32_t column = out.layout.poseidon.End();
    out.layout.hash_active = column++;
    out.layout.endpoint_first = column++;
    out.layout.terminal = column++;
    out.layout.endpoint = column++;
    out.layout.role = column++;
    out.layout.ordinal = column++;
    out.layout.origin = column++;
    out.layout.statement_base = column;
    column += kWordsV1;
    out.layout.program_base = column;
    column += kWordsV1;
    out.layout.transcript_base = column;
    column += kWordsV1;
    out.layout.producer_auth_base = column;
    column += kWordsV1;
    out.layout.consumer_auth_base = column;
    column += kWordsV1;
    out.layout.producer_base = column;
    column += kWordsV1;
    out.layout.consumer_base = column;
    column += kWordsV1;
    out.layout.producer_bits_base = column;
    column += kWordsV1 * kWordBitsV1;
    out.layout.consumer_bits_base = column;
    column += kWordsV1 * kWordBitsV1;
    out.layout.message_base = column;
    column += alg_hash::kAlgHashRate;
    out.layout.expected_statement_base = column;
    column += kWordsV1;
    out.layout.expected_program_base = column;
    column += kWordsV1;
    out.layout.expected_transcript_base = column;
    column += kWordsV1;
    out.layout.expected_endpoint = column++;
    out.layout.expected_role = column++;
    out.layout.expected_ordinal = column++;
    out.layout.expected_origin = column++;
    out.layout.ordered_root_base = column;
    column += alg_hash::kAlgHashDigestLen;
    out.layout.total_columns = column;

    if (!pa::BuildFixedSystem(
            out.trace_rows, out.cs, &why)) {
        out.note = why;
        return out;
    }
    out.cs.n_columns = out.layout.total_columns;
    out.columns.assign(
        out.layout.total_columns,
        std::vector<gf::Fp3>(
            out.trace_rows, gf::Fp3::Zero()));

    const auto set =
        [&out](uint32_t col, uint32_t row,
               const gf::Fp3& value) {
            out.columns[col][row] = value;
        };

    alg_hash::State sponge{};
    for (uint32_t row = 0; row < out.trace_rows; ++row) {
        alg_hash::State input{};
        if (row < out.hash_rows) {
            set(
                out.layout.hash_active, row,
                gf::Fp3::One());
            input = sponge;
            for (uint32_t lane = 0;
                 lane < alg_hash::kAlgHashRate;
                 ++lane) {
                const gf::Fp message =
                    payload[row * alg_hash::kAlgHashRate + lane];
                input[lane] =
                    gf::Add(input[lane], message);
                set(
                    out.layout.message_base + lane,
                    row,
                    gf::Fp3::FromFp(message));
            }
        }
        const pa::Witness witness =
            pa::BuildWitness(
                out.layout.poseidon, input);
        for (uint32_t col = 0;
             col < out.layout.poseidon.End();
             ++col) {
            set(col, row, witness.row[col]);
        }
        if (row < out.hash_rows) {
            sponge = witness.output;
        }
    }
    const uint32_t terminal_row = out.hash_rows - 1U;
    set(
        out.layout.terminal, terminal_row,
        gf::Fp3::One());

    const auto statement_words =
        U256Words(statement_root);
    const auto program_words =
        U256Words(program_root);
    const auto transcript_words =
        U256Words(transcript_root);
    for (uint32_t row = 0; row < out.trace_rows; ++row) {
        for (uint32_t word = 0; word < kWordsV1; ++word) {
            set(
                out.layout.expected_statement_base + word,
                row, U32(statement_words[word]));
            set(
                out.layout.expected_program_base + word,
                row, U32(program_words[word]));
            set(
                out.layout.expected_transcript_base + word,
                row, U32(transcript_words[word]));
        }
        for (uint32_t lane = 0;
             lane < alg_hash::kAlgHashDigestLen;
             ++lane) {
            set(
                out.layout.ordered_root_base + lane,
                row,
                gf::Fp3::FromFp(
                    sponge[lane]));
        }
    }

    for (uint32_t i = 0; i < out.blocks.size(); ++i) {
        const uint32_t row =
            kHeaderLanesV1 /
                alg_hash::kAlgHashRate +
            i * (kBlockLanesV1 /
                 alg_hash::kAlgHashRate);
        const auto& block = out.blocks[i];
        set(
            out.layout.endpoint_first, row,
            gf::Fp3::One());
        set(
            out.layout.endpoint, row,
            U32(static_cast<uint16_t>(
                block.endpoint)));
        set(
            out.layout.role, row,
            U32(static_cast<uint8_t>(
                block.role)));
        set(
            out.layout.ordinal, row,
            U32(block.ordinal));
        set(
            out.layout.origin, row,
            U32(static_cast<uint32_t>(
                block.origin)));
        set(
            out.layout.expected_endpoint, row,
            out.columns[out.layout.endpoint][row]);
        set(
            out.layout.expected_role, row,
            out.columns[out.layout.role][row]);
        set(
            out.layout.expected_ordinal, row,
            out.columns[out.layout.ordinal][row]);
        set(
            out.layout.expected_origin, row,
            out.columns[out.layout.origin][row]);
        const auto producer_auth =
            U256Words(
                block.producer_authentication_root);
        const auto consumer_auth =
            U256Words(
                block.consumer_authentication_root);
        for (uint32_t word = 0; word < kWordsV1; ++word) {
            set(
                out.layout.statement_base + word,
                row, U32(statement_words[word]));
            set(
                out.layout.program_base + word,
                row, U32(program_words[word]));
            set(
                out.layout.transcript_base + word,
                row, U32(transcript_words[word]));
            set(
                out.layout.producer_auth_base + word,
                row, U32(producer_auth[word]));
            set(
                out.layout.consumer_auth_base + word,
                row, U32(consumer_auth[word]));
            const uint32_t producer =
                static_cast<uint32_t>(
                    block.producer_words[word]);
            const uint32_t consumer =
                static_cast<uint32_t>(
                    block.consumer_words[word]);
            set(
                out.layout.producer_base + word,
                row, U32(producer));
            set(
                out.layout.consumer_base + word,
                row, U32(consumer));
            for (uint32_t bit = 0;
                 bit < kWordBitsV1; ++bit) {
                set(
                    out.layout.ProducerBit(word, bit),
                    row,
                    U32((producer >> bit) & 1U));
                set(
                    out.layout.ConsumerBit(word, bit),
                    row,
                    U32((consumer >> bit) & 1U));
            }
        }
    }

    AddBoolean(
        out.cs,
        "semantic_recursive:hash_active",
        out.layout.hash_active);
    AddBoolean(
        out.cs,
        "semantic_recursive:endpoint_first",
        out.layout.endpoint_first);
    AddBoolean(
        out.cs,
        "semantic_recursive:terminal",
        out.layout.terminal);
    for (uint32_t word = 0; word < kWordsV1; ++word) {
        for (uint32_t bit = 0;
             bit < kWordBitsV1; ++bit) {
            AddBoolean(
                out.cs,
                "semantic_recursive:producer_bit",
                out.layout.ProducerBit(word, bit));
            AddBoolean(
                out.cs,
                "semantic_recursive:consumer_bit",
                out.layout.ConsumerBit(word, bit));
        }
        Add(
            out.cs,
            "semantic_recursive:producer_recompose",
            aq::AirKind::kEverywhere, 2,
            [layout = out.layout, word](
                const auto& current, const auto&) {
                gf::Fp3 sum = gf::Fp3::Zero();
                uint64_t weight = 1;
                for (uint32_t bit = 0;
                     bit < kWordBitsV1; ++bit) {
                    sum = gf::Add(
                        sum,
                        gf::Mul(
                            current[
                                layout.ProducerBit(
                                    word, bit)],
                            gf::Fp3::FromFp(
                                gf::FromU64(weight))));
                    weight <<= 1;
                }
                return gf::Mul(
                    current[layout.endpoint_first],
                    gf::Sub(
                        current[
                            layout.producer_base + word],
                        sum));
            });
        Add(
            out.cs,
            "semantic_recursive:consumer_recompose",
            aq::AirKind::kEverywhere, 2,
            [layout = out.layout, word](
                const auto& current, const auto&) {
                gf::Fp3 sum = gf::Fp3::Zero();
                uint64_t weight = 1;
                for (uint32_t bit = 0;
                     bit < kWordBitsV1; ++bit) {
                    sum = gf::Add(
                        sum,
                        gf::Mul(
                            current[
                                layout.ConsumerBit(
                                    word, bit)],
                            gf::Fp3::FromFp(
                                gf::FromU64(weight))));
                    weight <<= 1;
                }
                return gf::Mul(
                    current[layout.endpoint_first],
                    gf::Sub(
                        current[
                            layout.consumer_base + word],
                        sum));
            });
        Add(
            out.cs,
            "semantic_recursive:producer_consumer",
            aq::AirKind::kEverywhere, 2,
            [layout = out.layout, word](
                const auto& current, const auto&) {
                return gf::Mul(
                    current[layout.endpoint_first],
                    gf::Sub(
                        current[
                            layout.producer_base + word],
                        current[
                            layout.consumer_base + word]));
            });
    }

    const std::array<
        std::pair<uint32_t, uint32_t>, 4>
        route_pairs{{
            {out.layout.endpoint,
             out.layout.expected_endpoint},
            {out.layout.role,
             out.layout.expected_role},
            {out.layout.ordinal,
             out.layout.expected_ordinal},
            {out.layout.origin,
             out.layout.expected_origin},
        }};
    for (const auto& [value, expected] :
         route_pairs) {
        Add(
            out.cs,
            "semantic_recursive:route_pin",
            aq::AirKind::kEverywhere, 2,
            [layout = out.layout,
             value, expected](
                const auto& current, const auto&) {
                return gf::Mul(
                    current[layout.endpoint_first],
                    gf::Sub(
                        current[value],
                        current[expected]));
            });
    }
    const std::array<
        std::pair<uint32_t, uint32_t>, 3>
        common_pairs{{
            {out.layout.statement_base,
             out.layout.expected_statement_base},
            {out.layout.program_base,
             out.layout.expected_program_base},
            {out.layout.transcript_base,
             out.layout.expected_transcript_base},
        }};
    for (const auto& [value, expected] :
         common_pairs) {
        for (uint32_t word = 0;
             word < kWordsV1; ++word) {
            Add(
                out.cs,
                "semantic_recursive:common_root",
                aq::AirKind::kEverywhere, 2,
                [layout = out.layout,
                 value, expected, word](
                    const auto& current,
                    const auto&) {
                    return gf::Mul(
                        current[
                            layout.endpoint_first],
                        gf::Sub(
                            current[value + word],
                            current[
                                expected + word]));
                });
        }
    }

    for (uint32_t lane = 0;
         lane < alg_hash::kAlgHashT; ++lane) {
        Add(
            out.cs,
            "semantic_recursive:first_sponge_input",
            aq::AirKind::kFirstRow, 1,
            [layout = out.layout, lane](
                const auto& current, const auto&) {
                const gf::Fp3 message =
                    lane < alg_hash::kAlgHashRate
                    ? current[
                          layout.message_base + lane]
                    : gf::Fp3::Zero();
                return gf::Sub(
                    current[
                        layout.poseidon.perm.InputCol(
                            lane)],
                    message);
            });
        Add(
            out.cs,
            "semantic_recursive:sponge_chain",
            aq::AirKind::kTransition, 2,
            [layout = out.layout, lane](
                const auto& current,
                const auto& next) {
                const gf::Fp3 message =
                    lane < alg_hash::kAlgHashRate
                    ? next[
                          layout.message_base + lane]
                    : gf::Fp3::Zero();
                return gf::Mul(
                    next[layout.hash_active],
                    gf::Sub(
                        next[
                            layout.poseidon.perm
                                .InputCol(lane)],
                        gf::Add(
                            PermOutput(
                                layout.poseidon,
                                current, lane),
                            message)));
            });
    }
    for (uint32_t lane = 0;
         lane < alg_hash::kAlgHashDigestLen;
         ++lane) {
        Add(
            out.cs,
            "semantic_recursive:ordered_root",
            aq::AirKind::kEverywhere, 2,
            [layout = out.layout, lane](
                const auto& current, const auto&) {
                return gf::Mul(
                    current[layout.terminal],
                    gf::Sub(
                        PermOutput(
                            layout.poseidon,
                            current, lane),
                        current[
                            layout.ordered_root_base +
                            lane]));
            });
    }

    out.preprocessed_columns = {
        out.layout.hash_active,
        out.layout.endpoint_first,
        out.layout.terminal,
        out.layout.endpoint,
        out.layout.role,
        out.layout.ordinal,
        out.layout.origin,
        out.layout.expected_endpoint,
        out.layout.expected_role,
        out.layout.expected_ordinal,
        out.layout.expected_origin,
    };
    const auto add_range =
        [&out](uint32_t base, uint32_t count) {
            for (uint32_t i = 0; i < count; ++i) {
                out.preprocessed_columns.push_back(
                    base + i);
            }
        };
    add_range(out.layout.statement_base, 7U * kWordsV1);
    add_range(
        out.layout.message_base,
        alg_hash::kAlgHashRate);
    add_range(
        out.layout.expected_statement_base,
        3U * kWordsV1);
    add_range(
        out.layout.ordered_root_base,
        alg_hash::kAlgHashDigestLen);
    std::sort(
        out.preprocessed_columns.begin(),
        out.preprocessed_columns.end());
    out.preprocessed_columns.erase(
        std::unique(
            out.preprocessed_columns.begin(),
            out.preprocessed_columns.end()),
        out.preprocessed_columns.end());
    for (uint32_t col :
         out.preprocessed_columns) {
        out.cs.preprocessed.emplace_back(
            col, out.columns[col]);
    }
    out.cs.preprocessed_pin_ood = true;
    const auto session =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            out.cs, out.columns,
            out.preprocessed_columns);
    if (!session.valid ||
        session.base_row_commitment.IsNull()) {
        out.note =
            "stage3:multirow_v11_semantic_recursive:r0:" +
            session.note;
        return out;
    }
    out.preprocessed_row_group_root =
        session.base_row_commitment;
    out.cs.preprocessed_row_group_roots.push_back({
        .version = 1,
        .role =
            aq::AirPreprocessedRowGroupRole::kR0,
        .ordered_columns =
            out.preprocessed_columns,
        .root =
            out.preprocessed_row_group_root,
    });

    out.trace_columns = out.cs.n_columns;
    out.constraints =
        static_cast<uint32_t>(
            out.cs.constraints.size());
    for (const auto& constraint :
         out.cs.constraints) {
        out.max_degree = std::max(
            out.max_degree,
            constraint.alg_degree);
    }
    out.violations =
        RecountViolationsV1(out, out.columns);
    out.common_roots_constrained = true;
    out.producer_consumer_equality_constrained = true;
    out.canonical_u32_constrained = true;
    out.ordered_poseidon_root_constrained = true;
    out.exact_r0_root_pinned = true;
    out.child_verifier_cells_connected = false;
    out.recursive_authority = false;
    out.valid_foundation =
        out.role_products_canonical &&
        out.exact_endpoint_order &&
        out.exact_origin_partition &&
        out.existing_outputs ==
            kExistingEndpointCountV1 &&
        out.heavy_outputs ==
            kHeavyEndpointCountV1 &&
        out.literal_pairs.size() ==
            kEndpointCountV1 &&
        out.violations == 0;
    out.note = out.valid_foundation
        ? "bounded 52-pair R0/Poseidon parent executes; "
          "child verifier cells are not yet in-parent"
        : "foundation invalid";
    return out;
}

uint64_t RecountViolationsV1(
    const ProductV1& product,
    const std::vector<std::vector<gf::Fp3>>& columns)
{
    if (columns.size() != product.cs.n_columns) {
        return UINT64_MAX;
    }
    for (const auto& column : columns) {
        if (column.size() != product.cs.n_rows) {
            return UINT64_MAX;
        }
    }
    uint64_t out = 0;
    std::vector<gf::Fp3> current(
        product.cs.n_columns);
    std::vector<gf::Fp3> next(
        product.cs.n_columns);
    for (uint32_t row = 0;
         row < product.cs.n_rows; ++row) {
        const uint32_t next_row =
            (row + 1U) % product.cs.n_rows;
        for (uint32_t col = 0;
             col < product.cs.n_columns; ++col) {
            current[col] = columns[col][row];
            next[col] = columns[col][next_row];
        }
        for (const auto& constraint :
             product.cs.constraints) {
            if (Applies(
                    constraint.kind, row,
                    product.cs.n_rows) &&
                !gf::IsZero(
                    constraint.eval(
                        current, next))) {
                ++out;
            }
        }
    }
    for (uint32_t col :
         product.preprocessed_columns) {
        const auto found = std::find_if(
            product.cs.preprocessed.begin(),
            product.cs.preprocessed.end(),
            [col](const auto& item) {
                return item.first == col;
            });
        if (found ==
                product.cs.preprocessed.end() ||
            !SameFp3Vector(
                found->second, columns[col])) {
            ++out;
        }
    }
    return out;
}

bool ValidateProductV1(
    const ProductV1& product,
    const std::vector<RCStage3RoleAirProduct>& roles,
    const uint256& statement_root,
    const uint256& program_root,
    const uint256& transcript_root,
    std::string* why)
{
    const ProductV1 rebuilt =
        BuildProductV1(
            roles, statement_root,
            program_root, transcript_root);
    if (!SameProductShape(product, rebuilt) ||
        product.version != kVersionV1 ||
        !product.valid_foundation ||
        product.child_verifier_cells_connected ||
        product.recursive_authority ||
        RecountViolationsV1(
            product, product.columns) != 0) {
        return Fail(why, "product");
    }
    return true;
}

} // namespace matmul::v4::rc::multirow_v11_semantic_recursive
