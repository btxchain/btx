// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_multirow_v11_semantic_exports.h>

#include <matmul/matmul_v4_rc_air_recurse.h>

#include <algorithm>
#include <limits>
#include <set>
#include <utility>

namespace matmul::v4::rc::multirow_v11_semantic_exports {
namespace {

namespace ar = air_recurse;

bool Fail(std::string* why, const std::string& reason)
{
    if (why != nullptr) {
        *why = "stage3:multirow_v11_semantic_exports:" + reason;
    }
    return false;
}

bool IsPow2(uint32_t value)
{
    return value >= 2 && (value & (value - 1U)) == 0;
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

bool SameFp3(const gf::Fp3& a, const gf::Fp3& b)
{
    return gf::Eq(a, b);
}

bool SamePreprocessed(
    const std::vector<
        std::pair<uint32_t, std::vector<gf::Fp3>>>& a,
    const std::vector<
        std::pair<uint32_t, std::vector<gf::Fp3>>>& b)
{
    if (a.size() != b.size()) return false;
    for (uint32_t i = 0; i < a.size(); ++i) {
        if (a[i].first != b[i].first ||
            a[i].second.size() != b[i].second.size()) {
            return false;
        }
        for (uint32_t row = 0; row < a[i].second.size(); ++row) {
            if (!SameFp3(a[i].second[row], b[i].second[row])) {
                return false;
            }
        }
    }
    return true;
}

bool SameConstraintShape(
    const aq::AirConstraintSystem<gf::Fp3>& a,
    const aq::AirConstraintSystem<gf::Fp3>& b)
{
    if (a.n_rows != b.n_rows ||
        a.n_columns != b.n_columns ||
        a.preprocessed_pin_ood != b.preprocessed_pin_ood ||
        a.constraints.size() != b.constraints.size() ||
        !SamePreprocessed(a.preprocessed, b.preprocessed)) {
        return false;
    }
    for (uint32_t i = 0; i < a.constraints.size(); ++i) {
        const auto& x = a.constraints[i];
        const auto& y = b.constraints[i];
        const std::string xn = x.name == nullptr ? "" : x.name;
        const std::string yn = y.name == nullptr ? "" : y.name;
        if (xn != yn ||
            x.kind != y.kind ||
            x.alg_degree != y.alg_degree) {
            return false;
        }
    }
    return true;
}

bool RebuildRoleConstraintSystem(
    RCStage3RelationRole role,
    const std::vector<alg_hash::Digest>& roots,
    uint32_t rows,
    aq::AirConstraintSystem<gf::Fp3>& out,
    std::string* why)
{
    if (!IsPow2(rows)) {
        return Fail(why, "role_rows");
    }
    const uint32_t path_len = rows - 1U;
    if (role == RCStage3RelationRole::EpisodeGemm) {
        return BuildRCStage3EpisodeGemmRoleAirCS(
            roots, path_len, out, why);
    }
    if (role == RCStage3RelationRole::EpisodeWiring) {
        return BuildRCStage3EpisodeWiringRoleAirCS(
            roots, path_len, out, why);
    }
    if (role == RCStage3RelationRole::CoupledGemm) {
        return BuildRCStage3CoupledGemmRoleAirCS(
            roots, path_len, out, why);
    }
    if (RCStage3RoleIsPureStream(role)) {
        return BuildRCStage3PureStreamRoleAirCS(
            role, roots, out, why);
    }
    if (role == RCStage3RelationRole::CoupledExchange ||
        role == RCStage3RelationRole::CoupledBank) {
        return BuildRCStage3CoupledMixedRoleAirCS(
            role, roots, path_len, out, why);
    }
    if (role ==
            RCStage3RelationRole::EpisodeDeterministicBuilder ||
        role == RCStage3RelationRole::EpisodeExtract ||
        role == RCStage3RelationRole::CoupledExtract) {
        return BuildRCStage3NoKernelRoleAirCS(
            role, roots, path_len, out, why);
    }
    if (role == RCStage3RelationRole::CoupledPermutation ||
        role == RCStage3RelationRole::CoupledMix) {
        return BuildRCStage3CoupledScalarRoleAirCS(
            role, roots, path_len, out, why);
    }
    return Fail(why, "unsupported_role");
}

bool StreamLike(RCStage3RelationEndpoint endpoint)
{
    return RCStage3EndpointHasStreamOpening(endpoint) ||
        endpoint ==
            RCStage3RelationEndpoint::EpisodeBuilderSeedChain ||
        endpoint == RCStage3RelationEndpoint::CoupledBankRoot;
}

bool VectorOpening(RCStage3RelationEndpoint endpoint)
{
    return endpoint ==
               RCStage3RelationEndpoint::EpisodeBuilderParams ||
        endpoint == RCStage3RelationEndpoint::EpisodeExtractInput ||
        endpoint == RCStage3RelationEndpoint::EpisodeExtractScale;
}

bool WiredLedger(RCStage3RelationEndpoint endpoint)
{
    switch (endpoint) {
    case RCStage3RelationEndpoint::EpisodeBuilderTrace:
    case RCStage3RelationEndpoint::EpisodeGemmSumcheck:
    case RCStage3RelationEndpoint::EpisodeGemmSignedRange:
    case RCStage3RelationEndpoint::EpisodeWiringTranspose:
    case RCStage3RelationEndpoint::EpisodeWiringResidual:
    case RCStage3RelationEndpoint::EpisodeWiringRoundOrder:
    case RCStage3RelationEndpoint::CoupledGemmSignedRange:
        return true;
    default:
        return false;
    }
}

const char* ModuleFor(ProducerKindV1 kind)
{
    switch (kind) {
    case ProducerKindV1::DirectRelationCell:
        return "matmul_v4_rc_stage3_relation_closure";
    case ProducerKindV1::VectorOpening:
        return "matmul_v4_rc_stage3_relation_closure";
    case ProducerKindV1::WiredLedger:
        return "matmul_v4_rc_stage3_relation_closure";
    case ProducerKindV1::StreamChild:
        return "matmul_v4_rc_stage3_stream_endpoint";
    case ProducerKindV1::Absent:
        return "none";
    }
    return "none";
}

const char* FunctionFor(
    ProducerKindV1 kind,
    RCStage3RelationEndpoint endpoint)
{
    switch (kind) {
    case ProducerKindV1::DirectRelationCell:
        return "BuildRCStage3RelationCtlDirectAliasConstraintSystem";
    case ProducerKindV1::VectorOpening:
        return "BuildRCStage3NoKernelRoleAirCS";
    case ProducerKindV1::WiredLedger:
        if (endpoint ==
                RCStage3RelationEndpoint::
                    EpisodeGemmSignedRange ||
            endpoint ==
                RCStage3RelationEndpoint::
                    CoupledGemmSignedRange) {
            return "BuildRCStage3SignedRangeWiredCloserCS";
        }
        return "BuildRCStage3WiredLeafCloserCS";
    case ProducerKindV1::StreamChild:
        return "RCStage3StreamEndpointClose";
    case ProducerKindV1::Absent:
        return "none";
    }
    return "none";
}

uint32_t ExistingRelationColumn(
    RCStage3RelationEndpoint endpoint)
{
    const auto cells = CurrentRCStage3RelationEndpointCellAudit();
    const auto found = std::find_if(
        cells.begin(), cells.end(),
        [endpoint](const RCStage3RelationEndpointCellAudit& item) {
            return item.endpoint == endpoint;
        });
    if (found == cells.end() ||
        !found->relation_air_cell ||
        !found->same_trace_ctl_alias) {
        return kNoColumnV1;
    }
    return found->relation_column;
}

std::array<uint32_t, kRootWordsV1> ClosureWords(
    const RCStage3StreamEndpointClosure& closure)
{
    return closure.committed_root;
}

const StreamChildArtifactV1* FindStreamChild(
    const std::vector<StreamChildArtifactV1>& children,
    RCStage3RelationEndpoint endpoint)
{
    const auto found = std::find_if(
        children.begin(), children.end(),
        [endpoint](const StreamChildArtifactV1& child) {
            return child.endpoint == endpoint;
        });
    return found == children.end() ? nullptr : &*found;
}

bool StreamChildExecutes(
    const StreamChildArtifactV1& child,
    const std::array<uint32_t, kRootWordsV1>& root_words)
{
    if (!child.closure.ok ||
        child.closure.child_cs.n_columns == 0 ||
        child.closure.bind_cs.n_columns == 0 ||
        child.closure.child_witness.size() !=
            child.closure.child_cs.n_columns ||
        child.closure.bind_witness.size() !=
            child.closure.bind_cs.n_columns ||
        child.closure.family !=
            RCStage3StreamFamilyForEndpoint(child.endpoint) ||
        child.closure.child_violations != 0 ||
        child.closure.bind_violations != 0 ||
        ClosureWords(child.closure) != root_words) {
        return false;
    }
    return
        ar::CountWitnessViolationsOnH(
            child.closure.child_cs,
            child.closure.child_witness) == 0 &&
        ar::CountWitnessViolationsOnH(
            child.closure.bind_cs,
            child.closure.bind_witness) == 0;
}

void AddExportColumns(
    RoleExportProofV1& proof,
    ProofOwnedExportV1& export_row)
{
    const uint32_t rows = proof.cs.n_rows;
    export_row.export_tag_base = proof.cs.n_columns;
    const std::array<uint32_t, 3> tags{
        static_cast<uint32_t>(export_row.route.endpoint),
        static_cast<uint32_t>(export_row.route.role),
        export_row.route.ordinal};
    for (uint32_t tag : tags) {
        const uint32_t export_column = proof.cs.n_columns++;
        const uint32_t expected_column = proof.cs.n_columns++;
        const gf::Fp3 value =
            gf::Fp3::FromFp(gf::FromU64(tag));
        proof.columns.emplace_back(rows, value);
        proof.columns.emplace_back(rows, value);
        proof.cs.preprocessed.push_back(
            {expected_column,
             std::vector<gf::Fp3>(rows, value)});
        proof.cs.constraints.push_back({
            "semantic_exports:route_tag_pin",
            aq::AirKind::kEverywhere,
            1,
            [export_column, expected_column](
                const std::vector<gf::Fp3>& current,
                const std::vector<gf::Fp3>&) {
                return gf::Sub(
                    current[export_column],
                    current[expected_column]);
            }});
    }
    export_row.export_word_base = proof.cs.n_columns;
    for (uint32_t word = 0; word < kRootWordsV1; ++word) {
        proof.columns.emplace_back(
            rows,
            gf::Fp3::FromFp(
                gf::FromU64(export_row.root_words[word])));
        const uint32_t export_column = proof.cs.n_columns++;
        const uint32_t expected_column = proof.cs.n_columns++;
        proof.columns.emplace_back(
            rows,
            gf::Fp3::FromFp(
                gf::FromU64(export_row.root_words[word])));
        proof.cs.preprocessed.push_back(
            {expected_column,
             std::vector<gf::Fp3>(
                 rows,
                 gf::Fp3::FromFp(
                     gf::FromU64(export_row.root_words[word])))});
        proof.cs.constraints.push_back({
            "semantic_exports:root_word_pin",
            aq::AirKind::kEverywhere,
            1,
            [export_column, expected_column](
                const std::vector<gf::Fp3>& current,
                const std::vector<gf::Fp3>&) {
                return gf::Sub(
                    current[export_column],
                    current[expected_column]);
            }});
    }

    /*
     * The expected side above is verifier-owned preprocessing and is OOD
     * pinned by the backend. The following bit decomposition prevents a
     * non-canonical host cell from reaching the backend as x+p and being
     * silently identified with x.
     */
    export_row.export_bits_base = proof.cs.n_columns;
    for (uint32_t word = 0; word < kRootWordsV1; ++word) {
        const uint32_t value_col =
            export_row.export_word_base + 2U * word;
        const uint32_t bit_base = proof.cs.n_columns;
        for (uint32_t bit = 0; bit < kWordBitsV1; ++bit) {
            const uint32_t bit_value =
                (export_row.root_words[word] >> bit) & 1U;
            proof.columns.emplace_back(
                rows,
                gf::Fp3::FromFp(gf::FromU64(bit_value)));
            const uint32_t bit_col = proof.cs.n_columns++;
            proof.cs.constraints.push_back({
                "semantic_exports:root_word_bit_boolean",
                aq::AirKind::kEverywhere,
                2,
                [bit_col](
                    const std::vector<gf::Fp3>& current,
                    const std::vector<gf::Fp3>&) {
                    return gf::Mul(
                        current[bit_col],
                        gf::Sub(
                            current[bit_col],
                            gf::Fp3::One()));
                }});
        }
        proof.cs.constraints.push_back({
            "semantic_exports:root_word_recompose",
            aq::AirKind::kEverywhere,
            1,
            [value_col, bit_base](
                const std::vector<gf::Fp3>& current,
                const std::vector<gf::Fp3>&) {
                gf::Fp3 sum = gf::Fp3::Zero();
                uint64_t weight = 1;
                for (uint32_t bit = 0;
                     bit < kWordBitsV1; ++bit) {
                    sum = gf::Add(
                        sum,
                        gf::Mul(
                            current[bit_base + bit],
                            gf::Fp3::FromFp(
                                gf::FromU64(weight))));
                    weight <<= 1;
                }
                return gf::Sub(current[value_col], sum);
            }});
    }
    proof.cs.preprocessed_pin_ood = true;
    export_row.same_trace_root_equality = true;
    export_row.canonical_u32_limbs = true;
}

RoleExportProofV1 BuildRoleProof(
    const RCStage3RoleAirProduct& artifact,
    const std::array<CanonicalExportRouteV1, kEndpointCountV1>& routes,
    const std::vector<StreamChildArtifactV1>& children)
{
    RoleExportProofV1 out;
    out.role = artifact.role;
    const auto& required =
        RequiredRCStage3RelationEndpoints(artifact.role);
    out.exact_endpoint_order =
        artifact.endpoints == required;
    out.exact_root_count =
        artifact.endpoint_committed_roots.size() ==
            required.size();
    if (!artifact.ok ||
        !out.exact_endpoint_order ||
        !out.exact_root_count ||
        artifact.cs.n_rows == 0 ||
        artifact.witness.size() !=
            artifact.cs.n_columns) {
        out.note = "artifact_shape";
        return out;
    }

    aq::AirConstraintSystem<gf::Fp3> rebuilt;
    std::string why;
    if (!RebuildRoleConstraintSystem(
            artifact.role,
            artifact.endpoint_committed_roots,
            artifact.cs.n_rows, rebuilt, &why) ||
        !SameConstraintShape(artifact.cs, rebuilt)) {
        out.note =
            why.empty() ? "noncanonical_source_cs" : why;
        return out;
    }
    out.source_shape_canonical = true;
    out.source_columns = rebuilt.n_columns;
    out.cs = std::move(rebuilt);
    out.columns = artifact.witness;
    if (ar::CountWitnessViolationsOnH(
            out.cs, out.columns) != 0) {
        out.note = "source_witness";
        return out;
    }

    for (uint32_t i = 0; i < required.size(); ++i) {
        const uint32_t ordinal =
            static_cast<uint32_t>(required[i]) - 1U;
        ProofOwnedExportV1 item;
        item.route = routes[ordinal];
        item.committed_root =
            artifact.endpoint_committed_roots[i];
        item.root_words = RootWords(item.committed_root);
        item.role_air_witness_executed = true;
        item.stream_child_witness_executed =
            item.route.kind != ProducerKindV1::StreamChild;
        if (item.route.kind == ProducerKindV1::StreamChild) {
            const auto* child =
                FindStreamChild(children, item.route.endpoint);
            item.stream_child_witness_executed =
                child != nullptr &&
                StreamChildExecutes(*child, item.root_words);
        }
        if (!item.stream_child_witness_executed) {
            item.residual =
                "heavy stream child absent, invalid, or bound to a "
                "different authority root";
            out.exports.push_back(std::move(item));
            continue;
        }
        AddExportColumns(out, item);
        item.residual =
            "local proof-owned root export executes; normalized "
            "recursive child consumption remains absent";
        out.exports.push_back(std::move(item));
    }
    out.violations =
        ar::CountWitnessViolationsOnH(out.cs, out.columns);
    out.valid = out.violations == 0;
    out.note = out.valid ? "valid" : "export_witness";
    return out;
}

bool RawCanonical(
    const RoleExportProofV1& proof,
    const ProofOwnedExportV1& item)
{
    if (item.export_tag_base == kNoColumnV1 ||
        item.export_word_base == kNoColumnV1 ||
        item.export_bits_base == kNoColumnV1 ||
        item.export_word_base + 2U * kRootWordsV1 >
            proof.columns.size()) {
        return false;
    }
    const std::array<uint32_t, 3> tags{
        static_cast<uint32_t>(item.route.endpoint),
        static_cast<uint32_t>(item.route.role),
        item.route.ordinal};
    for (uint32_t tag = 0; tag < 3; ++tag) {
        const auto& export_column =
            proof.columns[
                item.export_tag_base + 2U * tag];
        const auto& expected_column =
            proof.columns[
                item.export_tag_base + 2U * tag + 1U];
        for (uint32_t row = 0;
             row < export_column.size(); ++row) {
            const gf::Fp3& value = export_column[row];
            const gf::Fp3& expected =
                expected_column[row];
            if (value.c1 != 0 || value.c2 != 0 ||
                value.c0 != tags[tag] ||
                expected.c1 != 0 || expected.c2 != 0 ||
                expected.c0 != tags[tag]) {
                return false;
            }
        }
    }
    for (uint32_t word = 0; word < kRootWordsV1; ++word) {
        const auto& export_column =
            proof.columns[
                item.export_word_base + 2U * word];
        const auto& expected_column =
            proof.columns[
                item.export_word_base +
                2U * word + 1U];
        for (uint32_t row = 0;
             row < export_column.size(); ++row) {
            const gf::Fp3& value = export_column[row];
            const gf::Fp3& expected =
                expected_column[row];
            if (value.c1 != 0 || value.c2 != 0 ||
                value.c0 != item.root_words[word] ||
                expected.c1 != 0 || expected.c2 != 0 ||
                expected.c0 != item.root_words[word]) {
                return false;
            }
        }
    }
    return true;
}

} // namespace

std::array<CanonicalExportRouteV1, kEndpointCountV1>
CanonicalExportRoutesV1()
{
    std::array<CanonicalExportRouteV1, kEndpointCountV1> out{};
    uint32_t ordinal = 0;
    for (const RCStage3RelationRole role :
         RCStage3UnifiedRoleOrder()) {
        for (const RCStage3RelationEndpoint endpoint :
             RequiredRCStage3RelationEndpoints(role)) {
            CanonicalExportRouteV1 route;
            route.endpoint = endpoint;
            route.role = role;
            route.ordinal = ordinal;
            route.relation_column =
                ExistingRelationColumn(endpoint);
            if (route.relation_column != kNoColumnV1) {
                route.kind =
                    ProducerKindV1::DirectRelationCell;
                route.preexisting_literal = true;
            } else if (StreamLike(endpoint)) {
                route.kind = ProducerKindV1::StreamChild;
                route.requires_stream_child = true;
            } else if (VectorOpening(endpoint)) {
                route.kind = ProducerKindV1::VectorOpening;
            } else if (WiredLedger(endpoint)) {
                route.kind = ProducerKindV1::WiredLedger;
            }
            route.producer_module = ModuleFor(route.kind);
            route.producer_function =
                FunctionFor(route.kind, endpoint);
            out[ordinal++] = route;
        }
    }
    return out;
}

ProductV1 BuildProductV1(
    const std::vector<RCStage3RoleAirProduct>& role_artifacts,
    const std::vector<StreamChildArtifactV1>& stream_children)
{
    ProductV1 out;
    const auto routes = CanonicalExportRoutesV1();
    out.endpoints.reserve(routes.size());

    std::set<uint16_t> child_endpoints;
    out.no_duplicate_stream_children = true;
    for (const auto& child : stream_children) {
        out.no_duplicate_stream_children &=
            child_endpoints.insert(
                static_cast<uint16_t>(child.endpoint)).second;
    }
    std::set<uint16_t> roles;
    out.no_duplicate_roles = true;
    for (const auto& artifact : role_artifacts) {
        out.no_duplicate_roles &=
            roles.insert(
                static_cast<uint16_t>(artifact.role)).second;
        out.role_proofs.push_back(
            BuildRoleProof(artifact, routes, stream_children));
    }

    for (const auto& route : routes) {
        InventoryEntryV1 row;
        row.route = route;
        row.literal_proof_owned_export =
            route.preexisting_literal;
        out.preexisting_literal_endpoints +=
            route.preexisting_literal;
        const auto role_found = std::find_if(
            out.role_proofs.begin(), out.role_proofs.end(),
            [&route](const RoleExportProofV1& role) {
                return role.role == route.role;
            });
        if (role_found != out.role_proofs.end()) {
            row.supplied_role_artifact = true;
            row.executed_role_artifact = role_found->valid;
            const auto export_found = std::find_if(
                role_found->exports.begin(),
                role_found->exports.end(),
                [&route](const ProofOwnedExportV1& item) {
                    return item.route.endpoint ==
                        route.endpoint;
                });
            if (export_found != role_found->exports.end()) {
                row.executed_stream_child =
                    export_found
                        ->stream_child_witness_executed;
                const bool newly_literal =
                    role_found->valid &&
                    export_found
                        ->role_air_witness_executed &&
                    export_found
                        ->stream_child_witness_executed &&
                    export_found
                        ->same_trace_root_equality &&
                    export_found
                        ->canonical_u32_limbs &&
                    RawCanonical(
                        *role_found, *export_found);
                row.literal_proof_owned_export |=
                    newly_literal;
                out.newly_executed_export_endpoints +=
                    newly_literal &&
                    !route.preexisting_literal;
                row.residual = export_found->residual;
            }
        }
        if (!row.literal_proof_owned_export &&
            row.residual.empty()) {
            row.residual =
                "no executed role artifact supplied";
        }
        out.literal_proof_owned_endpoints +=
            row.literal_proof_owned_export;
        out.residual_endpoints +=
            !row.literal_proof_owned_export;
        out.endpoints.push_back(std::move(row));
    }

    out.exact_inventory =
        out.endpoints.size() == kEndpointCountV1 &&
        std::all_of(
            out.endpoints.begin(), out.endpoints.end(),
            [](const InventoryEntryV1& item) {
                return static_cast<uint32_t>(
                           item.route.endpoint) ==
                       item.route.ordinal + 1U &&
                    item.route.kind !=
                        ProducerKindV1::Absent;
            });
    for (const RCStage3RelationRole role :
         RCStage3UnifiedRoleOrder()) {
        const bool complete = std::all_of(
            out.endpoints.begin(), out.endpoints.end(),
            [role](const InventoryEntryV1& item) {
                return item.route.role != role ||
                    item.literal_proof_owned_export;
            });
        out.complete_roles += complete;
    }
    out.all_supplied_artifacts_valid =
        out.no_duplicate_roles &&
        out.no_duplicate_stream_children &&
        std::all_of(
            out.role_proofs.begin(),
            out.role_proofs.end(),
            [](const RoleExportProofV1& role) {
                return role.valid;
            });
    out.recursive_consumption_complete = false;
    out.production_authority = false;
    out.semantic_ctl_cells = BuildSemanticCtlCellsV1(out);
    out.note =
        out.exact_inventory && out.all_supplied_artifacts_valid
        ? "valid local export foundation; recursion absent"
        : "incomplete or invalid supplied artifact";
    return out;
}

bool ValidateRoleExportProofV1(
    const RoleExportProofV1& proof,
    std::string* why)
{
    if (!proof.valid ||
        !proof.source_shape_canonical ||
        !proof.exact_endpoint_order ||
        !proof.exact_root_count ||
        proof.source_columns == 0 ||
        proof.columns.size() != proof.cs.n_columns ||
        proof.violations != 0 ||
        ar::CountWitnessViolationsOnH(
            proof.cs, proof.columns) != 0) {
        return Fail(why, "role_proof");
    }
    std::vector<alg_hash::Digest> roots;
    roots.reserve(proof.exports.size());
    for (const auto& item : proof.exports) {
        if (item.root_words != RootWords(item.committed_root)) {
            return Fail(why, "root_limb_metadata");
        }
        roots.push_back(item.committed_root);
    }
    aq::AirConstraintSystem<gf::Fp3> rebuilt;
    if (!RebuildRoleConstraintSystem(
            proof.role, roots, proof.cs.n_rows,
            rebuilt, why) ||
        rebuilt.n_columns != proof.source_columns ||
        proof.source_columns > proof.columns.size()) {
        return Fail(why, "source_rebuild");
    }
    std::vector<std::vector<gf::Fp3>> source_columns(
        proof.columns.begin(),
        proof.columns.begin() + proof.source_columns);
    if (ar::CountWitnessViolationsOnH(
            rebuilt, source_columns) != 0) {
        return Fail(why, "source_root_binding");
    }
    for (const auto& item : proof.exports) {
        const auto& required =
            RequiredRCStage3RelationEndpoints(proof.role);
        const uint32_t local_ordinal =
            static_cast<uint32_t>(&item - proof.exports.data());
        if (local_ordinal >= required.size() ||
            item.route.endpoint != required[local_ordinal] ||
            item.route.role != proof.role ||
            item.route.ordinal + 1U !=
                static_cast<uint32_t>(item.route.endpoint)) {
            return Fail(why, "role_export_order");
        }
        if (item.role_air_witness_executed &&
            item.stream_child_witness_executed &&
            (!item.same_trace_root_equality ||
             !item.canonical_u32_limbs ||
             !RawCanonical(proof, item))) {
            return Fail(why, "role_export");
        }
    }
    return true;
}

bool ValidateProductV1(
    const ProductV1& product,
    std::string* why)
{
    if (product.version != kVersionV1 ||
        !product.exact_inventory ||
        !product.no_duplicate_roles ||
        !product.no_duplicate_stream_children ||
        !product.all_supplied_artifacts_valid ||
        product.endpoints.size() != kEndpointCountV1 ||
        product.preexisting_literal_endpoints != 21 ||
        product.literal_proof_owned_endpoints <
            product.preexisting_literal_endpoints ||
        product.literal_proof_owned_endpoints +
                product.residual_endpoints !=
            kEndpointCountV1 ||
        product.recursive_consumption_complete ||
        product.production_authority) {
        return Fail(why, "product");
    }
    for (const auto& role : product.role_proofs) {
        if (!ValidateRoleExportProofV1(role, why)) {
            return false;
        }
    }
    const auto cells = BuildSemanticCtlCellsV1(product);
    if (cells != product.semantic_ctl_cells ||
        (product.literal_proof_owned_endpoints ==
                 kEndpointCountV1
             ? cells.size() != kEndpointCountV1
             : !cells.empty())) {
        return Fail(why, "semantic_ctl_adapter");
    }
    return true;
}

std::vector<semantic_ctl::EndpointCellsV1>
BuildSemanticCtlCellsV1(const ProductV1& product)
{
    if (product.literal_proof_owned_endpoints !=
        kEndpointCountV1) {
        return {};
    }
    std::vector<semantic_ctl::EndpointCellsV1> out(
        kEndpointCountV1);
    const auto routes = CanonicalExportRoutesV1();
    for (uint32_t i = 0; i < routes.size(); ++i) {
        out[i].endpoint = routes[i].endpoint;
        out[i].role = routes[i].role;
        out[i].occurrence = routes[i].ordinal;
    }
    for (const auto& role : product.role_proofs) {
        if (!role.valid) continue;
        for (const auto& item : role.exports) {
            if (!item.role_air_witness_executed ||
                !item.stream_child_witness_executed ||
                !item.same_trace_root_equality ||
                !item.canonical_u32_limbs ||
                !RawCanonical(role, item)) {
                continue;
            }
            const uint32_t ordinal = item.route.ordinal;
            if (ordinal >= out.size()) return {};
            for (uint32_t word = 0;
                 word < kRootWordsV1; ++word) {
                out[ordinal].source_words[word] =
                    item.root_words[word];
                out[ordinal].consumer_words[word] =
                    item.root_words[word];
            }
        }
    }
    return out;
}

} // namespace matmul::v4::rc::multirow_v11_semantic_exports
