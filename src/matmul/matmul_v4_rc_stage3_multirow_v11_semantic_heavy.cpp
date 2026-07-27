// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_multirow_v11_semantic_heavy.h>

#include <algorithm>
#include <set>

namespace matmul::v4::rc::multirow_v11_semantic_heavy {
namespace {

namespace gf = gkr_field;

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:multirow_v11_semantic_heavy:" + detail;
    }
    return false;
}

std::array<uint32_t, kRootWordsV1> RootWords(
    const alg_hash::Digest& root)
{
    std::array<uint32_t, kRootWordsV1> out{};
    for (uint32_t lane = 0; lane < root.size(); ++lane) {
        const uint64_t value = gf::Canonical(root[lane]);
        out[2U * lane] = static_cast<uint32_t>(value);
        out[2U * lane + 1U] =
            static_cast<uint32_t>(value >> 32);
    }
    return out;
}

bool RawCanonicalRoot(const alg_hash::Digest& root)
{
    return std::all_of(
        root.begin(), root.end(),
        [](gf::Fp lane) { return lane < gf::kP; });
}

void P2PushU32(std::vector<gf::Fp>& lanes, uint32_t value)
{
    lanes.push_back(gf::FromU64(value));
}

void P2PushU64(std::vector<gf::Fp>& lanes, uint64_t value)
{
    P2PushU32(lanes, static_cast<uint32_t>(value));
    P2PushU32(
        lanes, static_cast<uint32_t>(value >> 32));
}

void P2PushBytes(
    std::vector<gf::Fp>& lanes,
    const unsigned char* bytes,
    size_t length)
{
    /*
     * The length prefix plus little-endian four-byte packing is injective.
     * Every emitted lane is a u32, hence strictly below Goldilocks p; there is
     * no x -> x+p field alias at this serialization boundary.
     */
    P2PushU64(lanes, length);
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
        P2PushU32(lanes, word);
    }
}

void P2PushString(
    std::vector<gf::Fp>& lanes,
    const char* text)
{
    const size_t length = std::char_traits<char>::length(text);
    P2PushBytes(
        lanes,
        reinterpret_cast<const unsigned char*>(text),
        length);
}

void P2PushU256(
    std::vector<gf::Fp>& lanes,
    const uint256& value)
{
    /*
     * A uint256 is eight u32 lanes, never four u64 lanes.  The latter would
     * identify x and x+p.  This map is byte-injective for arbitrary external
     * seeds, even when they are not encodings of field digests.
     */
    for (uint32_t limb = 0; limb < 8; ++limb) {
        uint32_t word = 0;
        for (uint32_t byte = 0; byte < 4; ++byte) {
            word |=
                static_cast<uint32_t>(
                    value.data()[4U * limb + byte])
                << (8U * byte);
        }
        P2PushU32(lanes, word);
    }
}

uint256 P2Commit(const std::vector<gf::Fp>& lanes)
{
    return Fri3AlgDigestToUint256(
        alg_hash::SpongeHashFp(lanes));
}

bool CanonicalPackedDigest(const uint256& value)
{
    return Fri3AlgDigestFromUint256(value).has_value();
}

const HeavyRouteV1* FindRoute(
    RCStage3RelationEndpoint endpoint)
{
    static const auto routes = CanonicalHeavyRoutesV1();
    const auto found = std::find_if(
        routes.begin(), routes.end(),
        [endpoint](const HeavyRouteV1& route) {
            return route.endpoint == endpoint;
        });
    return found == routes.end() ? nullptr : &*found;
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

const HeavyChildProofV1* FindChild(
    const std::vector<HeavyChildProofV1>& children,
    RCStage3RelationEndpoint endpoint)
{
    const auto found = std::find_if(
        children.begin(), children.end(),
        [endpoint](const HeavyChildProofV1& item) {
            return item.route.endpoint == endpoint;
        });
    return found == children.end() ? nullptr : &*found;
}

bool CanonicalRole(
    const RCStage3RoleAirProduct& role,
    std::string* why)
{
    const auto expected =
        RequiredRCStage3RelationEndpoints(role.role);
    if (!role.ok ||
        role.endpoints != expected ||
        role.endpoint_committed_roots.size() !=
            expected.size()) {
        return Fail(why, "role_shape");
    }
    for (const auto& root : role.endpoint_committed_roots) {
        if (!RawCanonicalRoot(root)) {
            return Fail(why, "role_root_noncanonical");
        }
    }
    const auto local = exports::BuildProductV1({role}, {});
    if (!local.no_duplicate_roles ||
        !local.all_supplied_artifacts_valid ||
        local.role_proofs.size() != 1 ||
        !exports::ValidateRoleExportProofV1(
            local.role_proofs.front(), why)) {
        return Fail(why, "role_air");
    }
    return true;
}

bool RoleRoot(
    const RCStage3RoleAirProduct& role,
    const HeavyRouteV1& route,
    std::array<uint32_t, kRootWordsV1>& words,
    std::string* why)
{
    if (role.role != route.role ||
        !CanonicalRole(role, why)) {
        return false;
    }
    const auto found = std::find(
        role.endpoints.begin(), role.endpoints.end(),
        route.endpoint);
    if (found == role.endpoints.end()) {
        return Fail(why, "role_endpoint_absent");
    }
    const size_t index =
        static_cast<size_t>(found - role.endpoints.begin());
    words = RootWords(role.endpoint_committed_roots[index]);
    return true;
}

void P2PushManifest(
    std::vector<gf::Fp>& lanes,
    const RCStage3StreamEndpointManifest& manifest)
{
    P2PushU32(lanes, manifest.leaf_index);
    P2PushU32(
        lanes,
        static_cast<uint32_t>(
            manifest.stream_value.size()));
    for (uint32_t word : manifest.stream_value) {
        P2PushU32(lanes, word);
    }
    P2PushU64(lanes, manifest.siblings.size());
    for (const auto& sibling : manifest.siblings) {
        P2PushU32(
            lanes,
            static_cast<uint32_t>(sibling.size()));
        for (uint32_t word : sibling) {
            P2PushU32(lanes, word);
        }
    }
    P2PushU64(lanes, manifest.directions.size());
    for (bool direction : manifest.directions) {
        P2PushU32(
            lanes, static_cast<uint32_t>(direction));
    }
}

uint256 ChildSeed(
    const char* domain,
    const uint256& public_fs_seed,
    const HeavyRouteV1& route,
    const RCStage3StreamEndpointManifest& manifest,
    const std::array<uint32_t, kRootWordsV1>& root)
{
    std::vector<gf::Fp> lanes;
    lanes.reserve(
        64 + manifest.siblings.size() * 9U);
    P2PushString(lanes, domain);
    P2PushU32(lanes, kVersionV1);
    P2PushU256(lanes, public_fs_seed);
    P2PushU32(
        lanes, static_cast<uint16_t>(route.endpoint));
    P2PushU32(
        lanes, static_cast<uint8_t>(route.role));
    P2PushU32(lanes, route.ordinal);
    P2PushU32(
        lanes, static_cast<uint8_t>(route.family));
    P2PushU32(lanes, root.size());
    for (uint32_t word : root) {
        P2PushU32(lanes, word);
    }
    P2PushManifest(lanes, manifest);
    return P2Commit(lanes);
}

std::vector<uint32_t> ChildR0Columns(
    const RCStage3StreamEndpointClosure& closure)
{
    for (const auto& pin :
         closure.child_cs.preprocessed_row_group_roots) {
        if (pin.version == 1 &&
            pin.role ==
                aq::AirPreprocessedRowGroupRole::kR0) {
            return pin.ordered_columns;
        }
    }
    return {};
}

uint256 PinnedChildR0Root(
    const RCStage3StreamEndpointClosure& closure)
{
    for (const auto& pin :
         closure.child_cs.preprocessed_row_group_roots) {
        if (pin.version == 1 &&
            pin.role ==
                aq::AirPreprocessedRowGroupRole::kR0) {
            return pin.root;
        }
    }
    return {};
}

uint256 CodecCommitment(
    const HeavyRouteV1& route,
    const std::array<uint32_t, kRootWordsV1>& root,
    const aq::AirQuotientSplitRapRowsProof& proof,
    size_t* proof_bytes)
{
    std::vector<unsigned char> bytes;
    const size_t written =
        aq::SerializeAirQuotientSplitRapRowsProof(
            proof, bytes);
    if (proof_bytes != nullptr) {
        *proof_bytes = written;
    }
    if (written == 0 || written != bytes.size()) {
        return {};
    }
    std::vector<gf::Fp> lanes;
    lanes.reserve(32 + (bytes.size() + 3U) / 4U);
    P2PushString(
        lanes,
        "BTX_RC_STAGE3_MULTIROW_V11_SEMANTIC_HEAVY_CODEC_V1");
    P2PushU32(lanes, kVersionV1);
    P2PushU32(
        lanes, static_cast<uint16_t>(route.endpoint));
    P2PushU32(
        lanes, static_cast<uint8_t>(route.role));
    P2PushU32(lanes, route.ordinal);
    P2PushU32(lanes, root.size());
    for (uint32_t word : root) {
        P2PushU32(lanes, word);
    }
    P2PushBytes(lanes, bytes.data(), bytes.size());
    return P2Commit(lanes);
}

bool RebuildClosure(
    const HeavyRouteV1& route,
    const RCStage3StreamEndpointManifest& manifest,
    const std::array<uint32_t, kRootWordsV1>& root,
    const uint256& public_fs_seed,
    RCStage3StreamEndpointClosure& closure,
    std::string* why)
{
    if (manifest.siblings.size() !=
            manifest.directions.size() ||
        manifest.siblings.size() > 31) {
        return Fail(why, "manifest_shape");
    }
    const uint256 closure_seed = ChildSeed(
        "BTX_RC_STAGE3_MULTIROW_V11_SEMANTIC_HEAVY_CLOSURE_V1",
        public_fs_seed, route, manifest, root);
    if (closure_seed.IsNull()) {
        return Fail(why, "closure_seed");
    }
    std::string close_why;
    closure = RCStage3StreamEndpointClose(
        route.family, manifest, closure_seed,
        &close_why, true);
    if (!closure.ok ||
        closure.family != route.family ||
        closure.committed_root != root ||
        closure.child_violations != 0 ||
        closure.bind_violations != 0 ||
        closure.child_output_export_base +
                kRootWordsV1 >
            closure.child_cs.n_columns ||
        ChildR0Columns(closure).empty() ||
        PinnedChildR0Root(closure).IsNull() ||
        !CanonicalPackedDigest(
            PinnedChildR0Root(closure))) {
        return Fail(
            why, "closure:" + close_why);
    }
    return true;
}

bool SameInventory(
    const ProductV1& a,
    const ProductV1& b)
{
    if (a.version != b.version ||
        a.endpoints.size() != b.endpoints.size() ||
        a.residual_endpoint_ids !=
            b.residual_endpoint_ids ||
        a.supplied_roles != b.supplied_roles ||
        a.required_roles != b.required_roles ||
        a.verified_children != b.verified_children ||
        a.semantic_literal_endpoints !=
            b.semantic_literal_endpoints ||
        a.total_proof_bytes != b.total_proof_bytes ||
        a.exact_inventory != b.exact_inventory ||
        a.no_duplicate_roles != b.no_duplicate_roles ||
        a.no_duplicate_children !=
            b.no_duplicate_children ||
        a.all_required_roles_supplied !=
            b.all_required_roles_supplied ||
        a.all_children_verified !=
            b.all_children_verified ||
        a.semantic_exports_complete !=
            b.semantic_exports_complete ||
        a.recursively_consumed != b.recursively_consumed ||
        a.complete != b.complete ||
        a.valid != b.valid ||
        a.production_authority !=
            b.production_authority) {
        return false;
    }
    for (size_t i = 0; i < a.endpoints.size(); ++i) {
        const auto& x = a.endpoints[i];
        const auto& y = b.endpoints[i];
        if (x.route != y.route ||
            x.role_supplied != y.role_supplied ||
            x.child_supplied != y.child_supplied ||
            x.role_root_canonical !=
                y.role_root_canonical ||
            x.root_matches_role !=
                y.root_matches_role ||
            x.split_rap_verified !=
                y.split_rap_verified ||
            x.r0_root != y.r0_root ||
            x.proof_bytes != y.proof_bytes) {
            return false;
        }
    }
    return true;
}

} // namespace

std::array<HeavyRouteV1, kHeavyEndpointCountV1>
CanonicalHeavyRoutesV1()
{
    std::array<HeavyRouteV1, kHeavyEndpointCountV1> out{};
    const auto all = exports::CanonicalExportRoutesV1();
    uint32_t count = 0;
    for (const auto& route : all) {
        if (route.kind !=
            exports::ProducerKindV1::StreamChild) {
            continue;
        }
        if (count >= out.size()) {
            return {};
        }
        out[count++] = {
            route.endpoint,
            route.role,
            route.ordinal,
            RCStage3StreamFamilyForEndpoint(
                route.endpoint)};
    }
    return count == out.size() ? out
                               : std::array<
                                     HeavyRouteV1,
                                     kHeavyEndpointCountV1>{};
}

HeavyChildProofV1 ProveHeavyChildV1(
    const RCStage3RoleAirProduct& role,
    RCStage3RelationEndpoint endpoint,
    const RCStage3StreamEndpointManifest& manifest,
    const uint256& public_fs_seed,
    std::string* why)
{
    HeavyChildProofV1 out;
    const auto* route = FindRoute(endpoint);
    if (route == nullptr || public_fs_seed.IsNull()) {
        out.residual = "route_or_seed";
        Fail(why, out.residual);
        return out;
    }
    out.route = *route;
    out.manifest = manifest;
    if (!RoleRoot(
            role, out.route, out.committed_root, why)) {
        out.residual = "role_root";
        return out;
    }
    RCStage3StreamEndpointClosure closure;
    if (!RebuildClosure(
            out.route, out.manifest,
            out.committed_root, public_fs_seed,
            closure, why)) {
        out.residual = "closure_root";
        return out;
    }
    out.r0_columns = ChildR0Columns(closure);
    const uint256 proof_seed = ChildSeed(
        "BTX_RC_STAGE3_MULTIROW_V11_SEMANTIC_HEAVY_PROOF_V1",
        public_fs_seed, out.route, out.manifest,
        out.committed_root);
    const auto proved =
        aq::AirQuotientProveRowsSplitRap(
            closure.child_cs, closure.child_witness,
            out.r0_columns, proof_seed);
    out.quotient_division_exact =
        proved.division_exact;
    if (!proved.ok || !proved.division_exact) {
        out.residual =
            "split_rap_prove:" + proved.note;
        Fail(why, out.residual);
        return out;
    }
    out.split_rap = proved.proof;
    out.child_rows = closure.child_cs.n_rows;
    out.child_columns = closure.child_cs.n_columns;
    out.semantic_compressions =
        closure.child_semantic_compressions;
    if (out.split_rap.batch.groups.size() != 3) {
        out.residual = "split_rap_groups";
        Fail(why, out.residual);
        return out;
    }
    out.r0_root = Fri3AlgDigestToUint256(
        out.split_rap.batch.groups[0].row_commit.root);
    out.proof_commitment = CodecCommitment(
        out.route, out.committed_root,
        out.split_rap, &out.proof_bytes);
    if (out.r0_root.IsNull() ||
        out.proof_commitment.IsNull()) {
        out.residual = "proof_commitment";
        Fail(why, out.residual);
        return out;
    }
    out.native_verifier_accepted =
        VerifyHeavyChildV1(
            role, out, public_fs_seed, why);
    out.recursively_consumed = false;
    out.residual = out.native_verifier_accepted
        ? "native Q192 child verifies; normalized parent "
          "consumption remains absent"
        : "native_verify";
    return out;
}

bool VerifyHeavyChildV1(
    const RCStage3RoleAirProduct& role,
    const HeavyChildProofV1& proof,
    const uint256& public_fs_seed,
    std::string* why)
{
    const auto* route = FindRoute(proof.route.endpoint);
    if (proof.version != kVersionV1 ||
        route == nullptr ||
        proof.route != *route ||
        public_fs_seed.IsNull() ||
        !CanonicalPackedDigest(proof.r0_root) ||
        !CanonicalPackedDigest(
            proof.proof_commitment) ||
        proof.recursively_consumed ||
        !proof.quotient_division_exact) {
        return Fail(why, "proof_shape");
    }
    std::array<uint32_t, kRootWordsV1> role_root{};
    if (!RoleRoot(role, *route, role_root, why) ||
        role_root != proof.committed_root) {
        return Fail(why, "role_root");
    }
    RCStage3StreamEndpointClosure closure;
    if (!RebuildClosure(
            *route, proof.manifest, role_root,
            public_fs_seed, closure, why)) {
        return false;
    }
    const auto r0_columns = ChildR0Columns(closure);
    if (proof.r0_columns != r0_columns ||
        proof.child_rows != closure.child_cs.n_rows ||
        proof.child_columns != closure.child_cs.n_columns ||
        proof.semantic_compressions !=
            closure.child_semantic_compressions ||
        proof.split_rap.trace_rows !=
            closure.child_cs.n_rows ||
        proof.split_rap.base_column_indices !=
            r0_columns ||
        proof.split_rap.batch.groups.size() != 3) {
        return Fail(why, "child_shape");
    }
    const uint256 r0_root = Fri3AlgDigestToUint256(
        proof.split_rap.batch.groups[0].row_commit.root);
    if (r0_root.IsNull() ||
        r0_root != proof.r0_root ||
        r0_root != PinnedChildR0Root(closure)) {
        return Fail(why, "r0_root");
    }
    const uint256 proof_seed = ChildSeed(
        "BTX_RC_STAGE3_MULTIROW_V11_SEMANTIC_HEAVY_PROOF_V1",
        public_fs_seed, *route, proof.manifest,
        role_root);
    std::string verify_why;
    if (!aq::AirQuotientVerifyRowsSplitRap(
            closure.child_cs, proof.split_rap,
            r0_columns, proof_seed, &verify_why)) {
        return Fail(
            why, "split_rap_verify:" + verify_why);
    }
    size_t proof_bytes = 0;
    const uint256 commitment = CodecCommitment(
        *route, role_root, proof.split_rap,
        &proof_bytes);
    if (commitment.IsNull() ||
        commitment != proof.proof_commitment ||
        proof_bytes != proof.proof_bytes) {
        return Fail(why, "codec_commitment");
    }
    return true;
}

ProductV1 BuildProductV1(
    const std::vector<RCStage3RoleAirProduct>& roles,
    const std::vector<HeavyChildProofV1>& children,
    const uint256& public_fs_seed)
{
    ProductV1 out;
    const auto routes = CanonicalHeavyRoutesV1();
    out.endpoints.reserve(routes.size());

    std::set<uint16_t> required_roles;
    for (const auto& route : routes) {
        required_roles.insert(
            static_cast<uint16_t>(route.role));
    }
    out.required_roles =
        static_cast<uint32_t>(required_roles.size());

    std::set<uint16_t> supplied_roles;
    out.no_duplicate_roles = true;
    for (const auto& role : roles) {
        out.no_duplicate_roles &=
            supplied_roles.insert(
                static_cast<uint16_t>(
                    role.role)).second;
    }
    for (uint16_t role : required_roles) {
        out.supplied_roles +=
            supplied_roles.count(role) != 0;
    }

    std::set<uint16_t> supplied_children;
    out.no_duplicate_children = true;
    for (const auto& child : children) {
        out.no_duplicate_children &=
            supplied_children.insert(
                static_cast<uint16_t>(
                    child.route.endpoint)).second;
    }

    std::vector<exports::StreamChildArtifactV1>
        verified_stream_children;
    for (const auto& route : routes) {
        HeavyInventoryEntryV1 row;
        row.route = route;
        const auto* role = FindRole(roles, route.role);
        const auto* child =
            FindChild(children, route.endpoint);
        row.role_supplied = role != nullptr;
        row.child_supplied = child != nullptr;
        std::array<uint32_t, kRootWordsV1> role_root{};
        std::string why;
        row.role_root_canonical =
            role != nullptr &&
            RoleRoot(*role, route, role_root, &why);
        row.root_matches_role =
            child != nullptr &&
            row.role_root_canonical &&
            child->committed_root == role_root;
        row.split_rap_verified =
            child != nullptr &&
            role != nullptr &&
            row.root_matches_role &&
            VerifyHeavyChildV1(
                *role, *child,
                public_fs_seed, &why);
        if (row.split_rap_verified) {
            row.r0_root = child->r0_root;
            row.proof_bytes = child->proof_bytes;
            out.total_proof_bytes +=
                child->proof_bytes;
            ++out.verified_children;
            RCStage3StreamEndpointClosure closure;
            if (RebuildClosure(
                    route, child->manifest,
                    role_root, public_fs_seed,
                    closure, &why)) {
                verified_stream_children.push_back(
                    {route.endpoint,
                     std::move(closure)});
            } else {
                row.split_rap_verified = false;
                --out.verified_children;
                out.total_proof_bytes -=
                    child->proof_bytes;
            }
        }
        if (!row.role_supplied) {
            row.residual = "required role absent";
        } else if (!row.role_root_canonical) {
            row.residual =
                "role AIR/root invalid or noncanonical";
        } else if (!row.child_supplied) {
            row.residual =
                "proof-owned heavy child absent";
        } else if (!row.root_matches_role) {
            row.residual =
                "child root differs from role authority root";
        } else if (!row.split_rap_verified) {
            row.residual =
                "Q192 Split-RAP child verification failed";
        } else {
            row.residual =
                "native child verified; recursive parent "
                "consumption absent";
        }
        if (!row.split_rap_verified) {
            out.residual_endpoint_ids.push_back(
                static_cast<uint16_t>(route.endpoint));
        }
        out.endpoints.push_back(std::move(row));
    }

    out.exact_inventory =
        out.endpoints.size() == routes.size() &&
        std::equal(
            out.endpoints.begin(), out.endpoints.end(),
            routes.begin(),
            [](const HeavyInventoryEntryV1& item,
               const HeavyRouteV1& route) {
                return item.route == route &&
                    item.route.ordinal + 1U ==
                        static_cast<uint32_t>(
                            item.route.endpoint);
            });
    out.all_required_roles_supplied =
        out.supplied_roles == out.required_roles;
    out.all_children_verified =
        out.verified_children ==
            kHeavyEndpointCountV1 &&
        verified_stream_children.size() ==
            kHeavyEndpointCountV1;

    const auto semantic = exports::BuildProductV1(
        roles, verified_stream_children);
    out.semantic_literal_endpoints =
        semantic.literal_proof_owned_endpoints;
    out.semantic_exports_complete =
        out.all_children_verified &&
        semantic.literal_proof_owned_endpoints ==
            exports::kEndpointCountV1 &&
        semantic.residual_endpoints == 0 &&
        semantic.semantic_ctl_cells.size() ==
            exports::kEndpointCountV1;
    out.recursively_consumed = false;
    out.complete =
        out.exact_inventory &&
        out.no_duplicate_roles &&
        out.no_duplicate_children &&
        out.all_required_roles_supplied &&
        out.all_children_verified &&
        out.semantic_exports_complete;
    out.valid = out.complete;
    out.production_authority = false;
    out.note = out.complete
        ? "all 21 proof-owned heavy children verify locally; "
          "normalized recursive consumption remains absent"
        : "fail-closed heavy-child residuals remain";
    return out;
}

bool ValidateProductV1(
    const ProductV1& product,
    const std::vector<RCStage3RoleAirProduct>& roles,
    const std::vector<HeavyChildProofV1>& children,
    const uint256& public_fs_seed,
    std::string* why)
{
    const ProductV1 rebuilt =
        BuildProductV1(roles, children, public_fs_seed);
    if (!SameInventory(product, rebuilt)) {
        return Fail(why, "inventory_or_transcript");
    }
    if (!product.valid ||
        !product.complete ||
        !product.exact_inventory ||
        !product.no_duplicate_roles ||
        !product.no_duplicate_children ||
        !product.all_required_roles_supplied ||
        !product.all_children_verified ||
        !product.semantic_exports_complete ||
        product.recursively_consumed ||
        product.production_authority ||
        !product.residual_endpoint_ids.empty()) {
        return Fail(why, "incomplete");
    }
    return true;
}

} // namespace matmul::v4::rc::multirow_v11_semantic_heavy
