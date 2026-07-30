// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/MIT.

#include <matmul/matmul_v4_rc_stage3_semantic_endpoint_receipt_intake.h>

#include <hash.h>
#include <matmul/matmul_v4_rc_air_recurse.h>
#include <matmul/matmul_v4_rc_gkr_wiring.h>

#include <algorithm>
#include <functional>
#include <limits>
#include <set>

namespace matmul::v4::rc::stage3_semantic_endpoint_receipt_intake {
namespace {

using AirCs = aq::AirConstraintSystem<gf::Fp3>;
using Fp3 = gf::Fp3;

constexpr char MANIFEST_DOMAIN[] =
    "BTX_RC_STAGE3_SEMANTIC_ENDPOINT_RECEIPT_MANIFEST_V1";
constexpr char BINDING_DOMAIN[] =
    "BTX_RC_STAGE3_SEMANTIC_ENDPOINT_RECEIPT_BINDING_V1";
constexpr char PARENT_DOMAIN[] =
    "BTX_RC_STAGE3_SEMANTIC_ENDPOINT_RECEIPT_PARENT_V1";
constexpr char VERIFIED_EVIDENCE_DOMAIN[] =
    "BTX_RC_STAGE3_SEMANTIC_ENDPOINT_VERIFIED_EVIDENCE_V1";

struct AirProduct {
    AirCs cs;
    std::vector<std::vector<Fp3>> columns;
    std::vector<uint32_t> endpoint_ordinals;
    std::array<Fp3, kTerminalLanesV1> terminal{};
    std::array<uint32_t, kTerminalLanesV1> terminal_columns{};
    bool valid{false};
    std::string note;
};

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why =
            "stage3:semantic_endpoint_receipt_intake:" +
            detail;
    }
    return false;
}

void HashFp3(HashWriter& hash, const Fp3& value)
{
    hash << gf::Canonical(value.c0);
    hash << gf::Canonical(value.c1);
    hash << gf::Canonical(value.c2);
}

bool SameFp3(
    const std::array<Fp3, kTerminalLanesV1>& left,
    const std::array<Fp3, kTerminalLanesV1>& right)
{
    for (uint32_t lane = 0; lane < kTerminalLanesV1; ++lane) {
        if (!gf::Eq(left[lane], right[lane])) return false;
    }
    return true;
}

bool CanonicalRaw(const Fp3& value)
{
    return value.c0 < gf::kP &&
        value.c1 < gf::kP &&
        value.c2 < gf::kP;
}

bool CanonicalRaw(
    const exports::RoleExportProofV1& proof)
{
    for (const auto& column : proof.columns) {
        for (const Fp3& value : column) {
            if (!CanonicalRaw(value)) return false;
        }
    }
    return true;
}

std::string ConstraintShapeIssue(const AirCs& cs)
{
    if (cs.n_rows < 2 ||
        (cs.n_rows & (cs.n_rows - 1U)) != 0) {
        return "rows";
    }
    if (cs.n_columns == 0 || cs.constraints.empty()) {
        return "empty";
    }
    for (const auto& constraint : cs.constraints) {
        if (constraint.name == nullptr ||
            constraint.name[0] == '\0' ||
            constraint.alg_degree == 0 ||
            !constraint.eval) {
            return "constraint";
        }
    }
    for (const auto& [column, values] : cs.preprocessed) {
        if (column >= cs.n_columns ||
            values.size() != cs.n_rows) {
            return "preprocessed_shape";
        }
        for (const auto& value : values) {
            if (!CanonicalRaw(value)) {
                return "preprocessed_canonical";
            }
        }
    }
    for (const auto& [column, root] :
         cs.preprocessed_roots) {
        if (column >= cs.n_columns || root.IsNull()) {
            return "preprocessed_root";
        }
    }
    for (const auto& group :
         cs.preprocessed_row_group_roots) {
        if (group.root.IsNull() ||
            group.ordered_columns.empty()) {
            return "preprocessed_group";
        }
    }
    return {};
}

bool ConcreteExport(
    const exports::RoleExportProofV1& role,
    const exports::ProofOwnedExportV1& item)
{
    return role.valid &&
        item.role_air_witness_executed &&
        item.stream_child_witness_executed &&
        item.same_trace_root_equality &&
        item.canonical_u32_limbs &&
        item.export_tag_base != exports::kNoColumnV1 &&
        item.export_word_base != exports::kNoColumnV1 &&
        item.export_bits_base != exports::kNoColumnV1 &&
        item.export_word_base + 2U * kRootWordsV1 <=
            role.cs.n_columns;
}

const exports::RoleExportProofV1* FindRole(
    const exports::ProductV1& product,
    RCStage3RelationRole role)
{
    const auto found = std::find_if(
        product.role_proofs.begin(),
        product.role_proofs.end(),
        [role](const auto& item) {
            return item.role == role;
        });
    return found == product.role_proofs.end()
        ? nullptr : &*found;
}

const exports::ProofOwnedExportV1* FindExport(
    const exports::RoleExportProofV1& role,
    uint32_t ordinal)
{
    const auto found = std::find_if(
        role.exports.begin(), role.exports.end(),
        [ordinal](const auto& item) {
            return item.route.ordinal == ordinal;
        });
    return found == role.exports.end() ? nullptr : &*found;
}

void HashManifestCore(
    HashWriter& hash,
    const ManifestV1& manifest)
{
    hash << MANIFEST_DOMAIN;
    hash << manifest.version;
    hash << manifest.active_bitmap;
    hash << manifest.residual_bitmap;
    hash << manifest.active_endpoints;
    hash << manifest.residual_endpoints;
    hash << manifest.active_roles;
    for (uint32_t ordinal = 0;
         ordinal < manifest.endpoints.size(); ++ordinal) {
        const auto& item = manifest.endpoints[ordinal];
        hash << ordinal;
        hash << static_cast<uint16_t>(item.route.endpoint);
        hash << static_cast<uint16_t>(item.route.role);
        hash << static_cast<uint8_t>(item.route.kind);
        hash << item.present;
        hash << item.receipt_slot;
        if (item.present) {
            for (uint32_t word : item.root_words) hash << word;
        }
    }
}

bool SameManifest(
    const ManifestV1& left,
    const ManifestV1& right)
{
    if (left.version != right.version ||
        left.active_bitmap != right.active_bitmap ||
        left.residual_bitmap != right.residual_bitmap ||
        left.active_endpoints != right.active_endpoints ||
        left.residual_endpoints != right.residual_endpoints ||
        left.active_roles != right.active_roles ||
        left.inventory_commitment !=
            right.inventory_commitment ||
        !(left.challenges == right.challenges) ||
        left.exact_canonical_order !=
            right.exact_canonical_order ||
        left.no_duplicate_roles !=
            right.no_duplicate_roles ||
        left.no_duplicate_stream_children !=
            right.no_duplicate_stream_children ||
        left.all_supplied_role_proofs_valid !=
            right.all_supplied_role_proofs_valid ||
        left.complete_52 != right.complete_52 ||
        left.valid != right.valid) {
        return false;
    }
    for (uint32_t i = 0; i < left.endpoints.size(); ++i) {
        const auto& a = left.endpoints[i];
        const auto& b = right.endpoints[i];
        if (a.route.endpoint != b.route.endpoint ||
            a.route.role != b.route.role ||
            a.route.ordinal != b.route.ordinal ||
            a.route.kind != b.route.kind ||
            a.root_words != b.root_words ||
            a.receipt_slot != b.receipt_slot ||
            a.present != b.present) {
            return false;
        }
    }
    return true;
}

Fp3 Denominator(
    const ManifestV1& manifest,
    uint32_t ordinal,
    uint32_t word,
    uint32_t lane,
    const Fp3& value)
{
    const uint64_t address =
        uint64_t{ordinal} * kRootWordsV1 + word + 1U;
    return gf::Add(
        manifest.challenges.gamma[lane],
        gf::Add(
            value,
            gf::Mul(
                manifest.challenges.alpha[lane],
                Fp3::FromFp(gf::FromU64(address)))));
}

std::array<Fp3, kTerminalLanesV1>
ManifestTerminal(const ManifestV1& manifest)
{
    std::array<Fp3, kTerminalLanesV1> out{};
    for (const auto& item : manifest.endpoints) {
        if (!item.present) continue;
        for (uint32_t word = 0; word < kRootWordsV1; ++word) {
            const Fp3 value =
                Fp3::FromFp(gf::FromU64(item.root_words[word]));
            for (uint32_t lane = 0;
                 lane < kTerminalLanesV1; ++lane) {
                const Fp3 denominator =
                    Denominator(
                        manifest, item.route.ordinal,
                        word, lane, value);
                if (gf::IsZero(denominator)) return {};
                out[lane] = gf::Add(
                    out[lane], gf::Inv(denominator));
            }
        }
    }
    return out;
}

void AddConstraint(
    AirCs& cs,
    const char* name,
    aq::AirKind kind,
    uint32_t degree,
    std::function<Fp3(
        const std::vector<Fp3>&,
        const std::vector<Fp3>&)> eval)
{
    cs.constraints.push_back({
        name, kind, degree, std::move(eval)});
}

AirProduct BuildRoleTerminalProduct(
    const exports::RoleExportProofV1& role,
    const ManifestV1& manifest)
{
    AirProduct out;
    std::string why;
    if (!exports::ValidateRoleExportProofV1(role, &why) ||
        !CanonicalRaw(role) ||
        role.cs.n_rows < 2 ||
        role.columns.size() != role.cs.n_columns) {
        out.note = "role_source:" + why;
        return out;
    }
    out.cs = role.cs;
    out.columns = role.columns;

    std::vector<const exports::ProofOwnedExportV1*> active;
    for (const auto& item : manifest.endpoints) {
        if (!item.present || item.route.role != role.role) continue;
        const auto* source =
            FindExport(role, item.route.ordinal);
        if (source == nullptr ||
            !ConcreteExport(role, *source) ||
            source->root_words != item.root_words) {
            out.note = "role_endpoint_source";
            return out;
        }
        out.endpoint_ordinals.push_back(item.route.ordinal);
        active.push_back(source);
    }
    if (active.empty()) {
        out.note = "role_without_concrete_endpoint";
        return out;
    }

    const uint32_t rows = out.cs.n_rows;
    const uint32_t selector_col = out.cs.n_columns++;
    std::vector<Fp3> selector(rows, Fp3::Zero());
    selector[0] = Fp3::One();
    out.columns.push_back(selector);
    out.cs.preprocessed.push_back(
        {selector_col, selector});
    out.cs.preprocessed_pin_ood = true;

    std::array<std::vector<uint32_t>, kTerminalLanesV1>
        inverse_columns;
    for (const auto* item : active) {
        for (uint32_t word = 0;
             word < kRootWordsV1; ++word) {
            const uint32_t value_col =
                item->export_word_base + 2U * word;
            for (uint32_t lane = 0;
                 lane < kTerminalLanesV1; ++lane) {
                const Fp3 value =
                    out.columns[value_col][0];
                const Fp3 denominator =
                    Denominator(
                        manifest, item->route.ordinal,
                        word, lane, value);
                if (gf::IsZero(denominator)) {
                    out.note = "zero_logup_denominator";
                    return out;
                }
                const uint32_t inverse_col =
                    out.cs.n_columns++;
                std::vector<Fp3> inverse(
                    rows, Fp3::Zero());
                inverse[0] = gf::Inv(denominator);
                out.columns.push_back(std::move(inverse));
                inverse_columns[lane].push_back(
                    inverse_col);
                const Fp3 gamma =
                    manifest.challenges.gamma[lane];
                const Fp3 alpha =
                    manifest.challenges.alpha[lane];
                const uint64_t address =
                    uint64_t{item->route.ordinal} *
                        kRootWordsV1 +
                    word + 1U;
                AddConstraint(
                    out.cs,
                    "semantic_receipt.logup_inverse",
                    aq::AirKind::kEverywhere, 2,
                    [value_col, inverse_col, selector_col,
                     gamma, alpha, address](
                        const auto& cur, const auto&) {
                        const Fp3 denominator =
                            gf::Add(
                                gamma,
                                gf::Add(
                                    cur[value_col],
                                    gf::Mul(
                                        alpha,
                                        Fp3::FromFp(
                                            gf::FromU64(
                                                address)))));
                        return gf::Sub(
                            gf::Mul(
                                denominator,
                                cur[inverse_col]),
                            cur[selector_col]);
                    });
            }
        }
    }

    for (uint32_t lane = 0;
         lane < kTerminalLanesV1; ++lane) {
        Fp3 terminal = Fp3::Zero();
        for (uint32_t inverse_col :
             inverse_columns[lane]) {
            terminal = gf::Add(
                terminal,
                out.columns[inverse_col][0]);
        }
        out.terminal[lane] = terminal;
        const uint32_t terminal_col =
            out.cs.n_columns++;
        out.terminal_columns[lane] = terminal_col;
        std::vector<Fp3> terminal_column(
            rows, terminal);
        out.columns.push_back(terminal_column);
        out.cs.preprocessed.push_back(
            {terminal_col, terminal_column});
        AddConstraint(
            out.cs,
            "semantic_receipt.terminal_sum",
            aq::AirKind::kFirstRow, 1,
            [terminal_col,
             inverses = inverse_columns[lane]](
                const auto& cur, const auto&) {
                Fp3 sum = Fp3::Zero();
                for (uint32_t inverse_col : inverses) {
                    sum = gf::Add(
                        sum, cur[inverse_col]);
                }
                return gf::Sub(
                    cur[terminal_col], sum);
            });
    }
    out.valid =
        air_recurse::CountWitnessViolationsOnH(
            out.cs, out.columns) == 0;
    const std::string shape_issue =
        ConstraintShapeIssue(out.cs);
    out.valid &= shape_issue.empty();
    out.note = out.valid
        ? "proof_owned_dual_fp3_terminal"
        : "role_terminal_constraints:" + shape_issue;
    return out;
}

void HashRoleStatement(
    HashWriter& hash,
    const ManifestV1& manifest,
    RCStage3RelationRole role,
    const std::vector<uint32_t>& endpoint_ordinals,
    const std::array<Fp3, kTerminalLanesV1>& terminal,
    const std::array<uint32_t, kTerminalLanesV1>&
        terminal_columns)
{
    hash << manifest.inventory_commitment;
    hash << static_cast<uint16_t>(role);
    hash << static_cast<uint32_t>(
        endpoint_ordinals.size());
    for (uint32_t ordinal : endpoint_ordinals) {
        hash << ordinal;
        for (uint32_t word :
             manifest.endpoints[ordinal].root_words) {
            hash << word;
        }
    }
    for (uint32_t lane = 0;
         lane < kTerminalLanesV1; ++lane) {
        HashFp3(hash, manifest.challenges.gamma[lane]);
        HashFp3(hash, manifest.challenges.alpha[lane]);
        HashFp3(hash, terminal[lane]);
        hash << terminal_columns[lane];
    }
}

ordinary::PublicBindingV1 BuildRoleBinding(
    const ManifestV1& manifest,
    RCStage3RelationRole role,
    const std::vector<uint32_t>& endpoint_ordinals,
    const std::array<Fp3, kTerminalLanesV1>& terminal,
    const std::array<uint32_t, kTerminalLanesV1>&
        terminal_columns)
{
    const auto tagged =
        [&](const char* label) {
            HashWriter hash;
            hash << BINDING_DOMAIN;
            hash << "role";
            hash << label;
            HashRoleStatement(
                hash, manifest, role,
                endpoint_ordinals, terminal,
                terminal_columns);
            return hash.GetHash();
        };
    ordinary::PublicBindingV1 out;
    out.node_binding = tagged("node");
    out.program_binding = tagged("program");
    out.proof_context_binding = tagged("context");
    out.public_statement_binding = tagged("statement");
    out.fs_seed = tagged("fiat_shamir");
    return out;
}

ordinary::PublicBindingV1 BuildLinkBinding(
    const ManifestV1& manifest,
    const std::vector<uint256>& ordered_receipts,
    const std::array<Fp3, kTerminalLanesV1>& source,
    const std::array<Fp3, kTerminalLanesV1>& consumer)
{
    const auto tagged =
        [&](const char* label) {
            HashWriter hash;
            hash << BINDING_DOMAIN;
            hash << "link";
            hash << label;
            hash << manifest.inventory_commitment;
            hash << static_cast<uint32_t>(
                ordered_receipts.size());
            for (uint32_t slot = 0;
                 slot < ordered_receipts.size(); ++slot) {
                hash << slot;
                hash << ordered_receipts[slot];
            }
            for (uint32_t lane = 0;
                 lane < kTerminalLanesV1; ++lane) {
                HashFp3(hash, source[lane]);
                HashFp3(hash, consumer[lane]);
                hash << lane;
                hash << 2U + lane;
            }
            return hash.GetHash();
        };
    ordinary::PublicBindingV1 out;
    out.node_binding = tagged("node");
    out.program_binding = tagged("program");
    out.proof_context_binding = tagged("context");
    out.public_statement_binding = tagged("statement");
    out.fs_seed = tagged("fiat_shamir");
    return out;
}

AirProduct BuildLinkProduct(
    const ManifestV1& manifest,
    const std::vector<
        std::array<Fp3, kTerminalLanesV1>>& role_terminals)
{
    AirProduct out;
    if (!manifest.valid || role_terminals.empty()) {
        out.note = "link_input";
        return out;
    }
    std::array<Fp3, kTerminalLanesV1> source{};
    for (const auto& terminal : role_terminals) {
        for (uint32_t lane = 0;
             lane < kTerminalLanesV1; ++lane) {
            source[lane] = gf::Add(
                source[lane], terminal[lane]);
        }
    }
    const auto consumer = ManifestTerminal(manifest);
    if (!SameFp3(source, consumer)) {
        out.note = "link_terminal_mismatch";
        return out;
    }
    out.terminal = source;
    out.terminal_columns = {{0, 1}};
    out.cs.n_rows = 2;
    out.cs.n_columns = 5;
    out.cs.preprocessed_pin_ood = true;
    out.columns.assign(
        out.cs.n_columns,
        std::vector<Fp3>(out.cs.n_rows, Fp3::Zero()));
    for (uint32_t lane = 0;
         lane < kTerminalLanesV1; ++lane) {
        out.columns[lane].assign(
            out.cs.n_rows, source[lane]);
        out.columns[2U + lane].assign(
            out.cs.n_rows, consumer[lane]);
        out.cs.preprocessed.push_back(
            {lane, out.columns[lane]});
        out.cs.preprocessed.push_back(
            {2U + lane, out.columns[2U + lane]});
        AddConstraint(
            out.cs,
            "semantic_receipt.link_cancellation",
            aq::AirKind::kEverywhere, 1,
            [lane](const auto& cur, const auto&) {
                return gf::Sub(
                    cur[lane], cur[2U + lane]);
            });
    }
    for (uint32_t row = 0; row < out.cs.n_rows; ++row) {
        out.columns[4][row] =
            gf::Add(
                out.columns[0][row],
                out.columns[1][row]);
    }
    AddConstraint(
        out.cs,
        "semantic_receipt.link_live_witness",
        aq::AirKind::kEverywhere, 1,
        [](const auto& cur, const auto&) {
            return gf::Sub(
                cur[4],
                gf::Add(cur[0], cur[1]));
        });
    out.valid =
        air_recurse::CountWitnessViolationsOnH(
            out.cs, out.columns) == 0;
    out.note = out.valid
        ? "dual_fp3_terminal_cancellation"
        : "link_constraints";
    return out;
}

std::pair<uint256, uint256> ParentBindings(
    const ManifestV1& manifest,
    const std::vector<
        fixedpoint::NarrowRecursiveProofReceiptV1>& children)
{
    if (children.size() < 2) return {};
    HashWriter node;
    node << PARENT_DOMAIN;
    node << "node";
    node << manifest.inventory_commitment;
    HashWriter program;
    program << PARENT_DOMAIN;
    program << "program";
    program << manifest.inventory_commitment;
    for (uint32_t slot = 0; slot < children.size(); ++slot) {
        node << slot;
        node << children[slot].receipt_commitment;
        program << slot;
        program << children[slot].program_binding;
    }
    return {node.GetHash(), program.GetHash()};
}

uint256 ExpectedParentStatement(
    const fixedpoint::FoldBusComposition& node,
    const std::vector<uint256>& child_seeds,
    const uint256& parent_context,
    const fixedpoint::NarrowRecursiveProofReceiptV1& receipt)
{
    if (!node.valid ||
        child_seeds.size() < 2 ||
        parent_context.IsNull() ||
        receipt.proof_commitment.IsNull() ||
        receipt.fs_seed.IsNull()) {
        return {};
    }
    const auto shape =
        narrow_recurse::AssessNarrowNodeFriShape(
            node.hash.valid
                ? uint64_t{node.hash.program.active_rows}
                : uint64_t{node.combined.n_rows});
    if (!shape.representable) return {};
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_MULTI_CHILD_L2_PARENT_STATEMENT_V1";
    hash << static_cast<uint32_t>(child_seeds.size());
    hash << node.combined.n_rows;
    hash << node.combined.n_columns;
    hash << static_cast<uint32_t>(
        node.combined.constraints.size());
    hash << static_cast<uint64_t>(
        node.hash.valid
            ? node.hash.program.active_rows
            : node.combined.n_rows);
    hash << shape.n_lde;
    hash << node.prechallenge_commitment;
    hash <<
        "BTX_RC_STAGE3_MULTI_CHILD_L2_BOUND_CONTEXT_V1";
    hash << parent_context;
    hash << receipt.fs_seed;
    for (const auto& seed : child_seeds) hash << seed;
    hash << receipt.proof_commitment;
    return hash.GetHash();
}

bool VerifyParent(
    const std::vector<
        fixedpoint::NarrowRecursiveProofReceiptV1>& children,
    const std::vector<AirCs>& child_css,
    const std::vector<
        fixedpoint::NarrowRecursiveProofExpectedBindingV2>&
            expected_children,
    const uint256& parent_node_binding,
    const uint256& parent_program_binding,
    const fixedpoint::NarrowRecursiveProofReceiptV1& receipt,
    std::string* why)
{
    if (children.size() < 2 ||
        child_css.size() != children.size() ||
        expected_children.size() != children.size()) {
        return Fail(why, "parent_arity");
    }
    std::vector<fixedpoint::AlgAirProof> proofs;
    std::vector<uint256> seeds;
    proofs.reserve(children.size());
    seeds.reserve(children.size());
    for (uint32_t slot = 0; slot < children.size(); ++slot) {
        std::string child_why;
        if (!fixedpoint::
                ValidateNarrowRecursiveProofReceiptV2(
                    children[slot], child_css[slot],
                    expected_children[slot],
                    &child_why)) {
            return Fail(
                why, "parent_child_" +
                    std::to_string(slot) + ":" +
                    child_why);
        }
        proofs.push_back(children[slot].proof);
        seeds.push_back(children[slot].fs_seed);
    }
    const uint256 context =
        fixedpoint::ComputeNarrowRetainedParentContextV1(
            children, parent_node_binding,
            parent_program_binding);
    const auto node =
        fixedpoint::BuildFoldBusCompositionMulti(
            child_css, proofs, seeds);
    const uint256 parent_seed =
        fixedpoint::ComputeNarrowMultiChildParentFsSeedV1(
            node, seeds, context);
    if (!node.valid || context.IsNull() ||
        parent_seed.IsNull() ||
        receipt.node_binding != parent_node_binding ||
        receipt.program_binding != parent_program_binding ||
        receipt.proof_context_binding != context ||
        receipt.fs_seed != parent_seed ||
        receipt.n_rows != node.combined.n_rows ||
        receipt.n_columns != node.combined.n_columns ||
        receipt.n_constraints !=
            node.combined.constraints.size() ||
        receipt.statement_commitment !=
            ExpectedParentStatement(
                node, seeds, context, receipt)) {
        return Fail(why, "parent_statement");
    }
    std::string parent_why;
    if (!fixedpoint::ValidateNarrowRecursiveProofReceiptV1(
            receipt, node.combined,
            parent_node_binding,
            parent_program_binding,
            &parent_why)) {
        return Fail(
            why, "parent_proof:" + parent_why);
    }
    return true;
}

bool RebuildIntake(
    const std::vector<RCStage3RoleAirProduct>& role_artifacts,
    const std::vector<exports::StreamChildArtifactV1>&
        stream_children,
    const ProofV1& proof,
    std::vector<AirCs>& child_css,
    std::vector<
        fixedpoint::NarrowRecursiveProofExpectedBindingV2>&
        expected_children,
    std::vector<
        fixedpoint::NarrowRecursiveProofReceiptV1>&
        child_receipts,
    std::string* why)
{
    ManifestV1 manifest;
    if (!BuildManifestV1(
            role_artifacts, stream_children,
            manifest, why) ||
        !SameManifest(manifest, proof.manifest) ||
        !proof.exact_no_omission_no_duplicate_intake ||
        !proof.all_ordinary_receipts_verified ||
        proof.canonical_terminal_constraint_bytecode_complete ||
        proof.recursive_child_verifier_constraints_complete ||
        proof.semantic_sites_credited ||
        proof.complete_fixed_point ||
        proof.authority_ready ||
        !proof.construction_valid) {
        return Fail(why, "envelope_or_manifest");
    }
    const auto export_product =
        exports::BuildProductV1(
            role_artifacts, stream_children);
    uint32_t receipt_slot = 0;
    std::vector<std::array<Fp3, kTerminalLanesV1>>
        role_terminals;
    std::vector<uint256> ordered_commitments;
    for (RCStage3RelationRole role :
         RCStage3UnifiedRoleOrder()) {
        const auto* source =
            FindRole(export_product, role);
        if (source == nullptr) continue;
        const bool active = std::any_of(
            manifest.endpoints.begin(),
            manifest.endpoints.end(),
            [role](const auto& item) {
                return item.present &&
                    item.route.role == role;
            });
        if (!active) continue;
        if (receipt_slot >= proof.role_receipts.size()) {
            return Fail(why, "role_receipt_omission");
        }
        const AirProduct expected =
            BuildRoleTerminalProduct(*source, manifest);
        const auto binding =
            BuildRoleBinding(
                manifest, role,
                expected.endpoint_ordinals,
                expected.terminal,
                expected.terminal_columns);
        const auto& claimed =
            proof.role_receipts[receipt_slot];
        if (!expected.valid ||
            claimed.role != role ||
            claimed.endpoint_ordinals !=
                expected.endpoint_ordinals ||
            !SameFp3(
                claimed.terminal,
                expected.terminal) ||
            claimed.terminal_columns !=
                expected.terminal_columns ||
            claimed.binding != binding ||
            !claimed.exact_endpoint_order ||
            !claimed.proof_owned_terminal ||
            claimed.canonical_terminal_constraint_bytecode ||
            !claimed.valid ||
            !ordinary::VerifyV1(
                claimed.ordinary_proof,
                expected.cs, binding, why)) {
            return Fail(
                why, "role_receipt_" +
                    std::to_string(receipt_slot));
        }
        child_css.push_back(expected.cs);
        expected_children.push_back(
            ordinary::BuildExpectedRecursiveBindingV2(
                expected.cs, binding));
        child_receipts.push_back(
            claimed.ordinary_proof.receipt);
        role_terminals.push_back(expected.terminal);
        ordered_commitments.push_back(
            claimed.ordinary_proof
                .receipt.receipt_commitment);
        ++receipt_slot;
    }
    if (receipt_slot != proof.role_receipts.size() ||
        receipt_slot != manifest.active_roles) {
        return Fail(why, "role_receipt_extra_or_duplicate");
    }
    const AirProduct link =
        BuildLinkProduct(manifest, role_terminals);
    const auto link_binding =
        BuildLinkBinding(
            manifest, ordered_commitments,
            link.terminal, ManifestTerminal(manifest));
    if (!link.valid ||
        !SameFp3(
            proof.equality_link.source_terminal,
            link.terminal) ||
        !SameFp3(
            proof.equality_link.consumer_terminal,
            ManifestTerminal(manifest)) ||
        proof.equality_link.binding != link_binding ||
        proof.equality_link.source_terminal_columns !=
            std::array<uint32_t, kTerminalLanesV1>{{0, 1}} ||
        proof.equality_link.consumer_terminal_columns !=
            std::array<uint32_t, kTerminalLanesV1>{{2, 3}} ||
        !proof.equality_link.ordered_receipts_bound ||
        !proof.equality_link
             .dual_fp3_terminal_cancellation ||
        !proof.equality_link.valid ||
        !ordinary::VerifyV1(
            proof.equality_link.ordinary_proof,
            link.cs, link_binding, why)) {
        return Fail(why, "equality_link");
    }
    std::vector<uint256> expected_child_order =
        ordered_commitments;
    expected_child_order.push_back(
        proof.equality_link.ordinary_proof
            .receipt.receipt_commitment);
    if (proof.ordered_child_receipt_commitments !=
        expected_child_order) {
        return Fail(why, "child_receipt_order");
    }
    child_css.push_back(link.cs);
    expected_children.push_back(
        ordinary::BuildExpectedRecursiveBindingV2(
            link.cs, link_binding));
    child_receipts.push_back(
        proof.equality_link.ordinary_proof.receipt);
    return true;
}

} // namespace

bool BuildManifestV1(
    const std::vector<RCStage3RoleAirProduct>& role_artifacts,
    const std::vector<exports::StreamChildArtifactV1>&
        stream_children,
    ManifestV1& out,
    std::string* why)
{
    out = {};
    out.version = kVersionV1;
    const auto routes = exports::CanonicalExportRoutesV1();
    const auto product =
        exports::BuildProductV1(
            role_artifacts, stream_children);
    // Do not use ValidateProductV1 here: that legacy local-export adapter
    // hard-codes a historical count of 21 direct routes, while the canonical
    // route table is intentionally allowed to evolve as real aliases land.
    // This intake validates the immutable 52-order and every supplied role
    // proof directly, and never credits a route-table literal by itself.
    const bool product_shape_valid =
        product.version == exports::kVersionV1 &&
        product.exact_inventory &&
        product.endpoints.size() == kEndpointCountV1 &&
        !product.recursive_consumption_complete &&
        !product.production_authority;
    out.no_duplicate_roles =
        product.no_duplicate_roles;
    out.no_duplicate_stream_children =
        product.no_duplicate_stream_children;
    out.all_supplied_role_proofs_valid =
        product_shape_valid &&
        product.all_supplied_artifacts_valid;
    out.exact_canonical_order =
        product.exact_inventory;

    uint32_t receipt_slot = 0;
    for (RCStage3RelationRole role :
         RCStage3UnifiedRoleOrder()) {
        const auto* proof = FindRole(product, role);
        if (proof == nullptr) continue;
        std::string role_why;
        const bool role_valid =
            exports::ValidateRoleExportProofV1(
                *proof, &role_why) &&
            CanonicalRaw(*proof);
        out.all_supplied_role_proofs_valid &=
            role_valid;
        bool role_active = false;
        for (const auto& item : proof->exports) {
            if (item.route.ordinal >=
                out.endpoints.size()) {
                return Fail(why, "endpoint_ordinal");
            }
            const bool concrete =
                role_valid &&
                ConcreteExport(*proof, item) &&
                !item.route.requires_stream_child;
            if (!concrete) continue;
            auto& endpoint =
                out.endpoints[item.route.ordinal];
            if (endpoint.present) {
                return Fail(why, "duplicate_endpoint");
            }
            endpoint.present = true;
            endpoint.root_words = item.root_words;
            endpoint.receipt_slot = receipt_slot;
            endpoint.residual.clear();
            out.active_bitmap |=
                uint64_t{1} << item.route.ordinal;
            ++out.active_endpoints;
            role_active = true;
        }
        if (role_active) {
            ++receipt_slot;
            ++out.active_roles;
        }
    }

    for (uint32_t ordinal = 0;
         ordinal < out.endpoints.size(); ++ordinal) {
        auto& endpoint = out.endpoints[ordinal];
        endpoint.route = routes[ordinal];
        if (!endpoint.present) {
            endpoint.receipt_slot =
                kNoReceiptSlotV1;
            endpoint.residual =
                endpoint.route.requires_stream_child
                ? "heavy stream child has no verified recursive receipt"
                : "no concrete proof-owned role receipt";
        }
        out.exact_canonical_order &=
            endpoint.route.ordinal == ordinal &&
            static_cast<uint32_t>(
                endpoint.route.endpoint) ==
                ordinal + 1U &&
            endpoint.route.kind !=
                exports::ProducerKindV1::Absent;
    }
    out.active_bitmap &= kEndpointMaskV1;
    out.residual_bitmap =
        kEndpointMaskV1 ^ out.active_bitmap;
    out.residual_endpoints =
        kEndpointCountV1 - out.active_endpoints;
    out.complete_52 =
        out.active_bitmap == kEndpointMaskV1 &&
        out.residual_bitmap == 0 &&
        out.active_endpoints == kEndpointCountV1 &&
        out.residual_endpoints == 0;
    HashWriter manifest_hash;
    HashManifestCore(manifest_hash, out);
    out.inventory_commitment =
        manifest_hash.GetHash();
    if (!out.inventory_commitment.IsNull()) {
        for (uint32_t lane = 0;
             lane < kTerminalLanesV1; ++lane) {
            out.challenges.gamma[lane] =
                WiringChallengeFp3(
                    out.inventory_commitment,
                    "semantic_endpoint_receipt_gamma",
                    0, lane);
            out.challenges.alpha[lane] =
                WiringChallengeFp3(
                    out.inventory_commitment,
                    "semantic_endpoint_receipt_alpha",
                    0, lane);
        }
    }
    out.valid =
        out.exact_canonical_order &&
        out.no_duplicate_roles &&
        out.no_duplicate_stream_children &&
        out.all_supplied_role_proofs_valid &&
        !out.inventory_commitment.IsNull();
    out.note = out.valid
        ? (out.complete_52
            ? "complete concrete 52-endpoint inventory"
            : "partial concrete inventory with explicit residual bitmap")
        : "invalid supplied semantic export product";
    if (!out.valid) {
        return Fail(
            why, "manifest");
    }
    return true;
}

ProofV1 ProveV1(
    const std::vector<RCStage3RoleAirProduct>& role_artifacts,
    const std::vector<exports::StreamChildArtifactV1>&
        stream_children,
    bool prove_parent)
{
    ProofV1 out;
    std::string why;
    if (!BuildManifestV1(
            role_artifacts, stream_children,
            out.manifest, &why) ||
        out.manifest.active_roles == 0 ||
        out.manifest.active_endpoints == 0) {
        out.note = why.empty()
            ? "stage3:semantic_endpoint_receipt_intake:"
              "empty_intake"
            : why;
        return out;
    }
    const auto product =
        exports::BuildProductV1(
            role_artifacts, stream_children);
    std::vector<AirCs> child_css;
    std::vector<
        fixedpoint::NarrowRecursiveProofExpectedBindingV2>
        expected_children;
    std::vector<
        fixedpoint::NarrowRecursiveProofReceiptV1>
        child_receipts;
    std::vector<std::array<Fp3, kTerminalLanesV1>>
        role_terminals;
    std::vector<uint256> ordered_commitments;

    for (RCStage3RelationRole role :
         RCStage3UnifiedRoleOrder()) {
        const auto* source = FindRole(product, role);
        if (source == nullptr) continue;
        const bool active = std::any_of(
            out.manifest.endpoints.begin(),
            out.manifest.endpoints.end(),
            [role](const auto& item) {
                return item.present &&
                    item.route.role == role;
            });
        if (!active) continue;
        const AirProduct terminal_product =
            BuildRoleTerminalProduct(
                *source, out.manifest);
        if (!terminal_product.valid) {
            out.note =
                "stage3:semantic_endpoint_receipt_intake:"
                "role_terminal:" +
                terminal_product.note;
            return out;
        }
        RoleReceiptV1 receipt;
        receipt.role = role;
        receipt.endpoint_ordinals =
            terminal_product.endpoint_ordinals;
        receipt.terminal =
            terminal_product.terminal;
        receipt.terminal_columns =
            terminal_product.terminal_columns;
        receipt.binding =
            BuildRoleBinding(
                out.manifest, role,
                receipt.endpoint_ordinals,
                receipt.terminal,
                receipt.terminal_columns);
        receipt.ordinary_proof =
            ordinary::ProveV1(
                terminal_product.cs,
                terminal_product.columns,
                receipt.binding);
        receipt.exact_endpoint_order = true;
        receipt.proof_owned_terminal = true;
        receipt.canonical_terminal_constraint_bytecode = false;
        receipt.valid =
            receipt.ordinary_proof.valid;
        receipt.note = receipt.valid
            ? "proof-owned role terminal"
            : receipt.ordinary_proof.note;
        if (!receipt.valid) {
            out.note =
                "stage3:semantic_endpoint_receipt_intake:"
                "role_proof:" + receipt.note;
            return out;
        }
        child_css.push_back(terminal_product.cs);
        expected_children.push_back(
            ordinary::BuildExpectedRecursiveBindingV2(
                terminal_product.cs,
                receipt.binding));
        child_receipts.push_back(
            receipt.ordinary_proof.receipt);
        out.ordered_child_receipt_commitments.push_back(
            receipt.ordinary_proof
                .receipt.receipt_commitment);
        role_terminals.push_back(receipt.terminal);
        ordered_commitments.push_back(
            receipt.ordinary_proof
                .receipt.receipt_commitment);
        out.role_receipts.push_back(
            std::move(receipt));
    }

    const AirProduct link =
        BuildLinkProduct(
            out.manifest, role_terminals);
    if (!link.valid) {
        out.note =
            "stage3:semantic_endpoint_receipt_intake:"
            "link:" + link.note;
        return out;
    }
    out.equality_link.source_terminal =
        link.terminal;
    out.equality_link.consumer_terminal =
        ManifestTerminal(out.manifest);
    out.equality_link.binding =
        BuildLinkBinding(
            out.manifest, ordered_commitments,
            out.equality_link.source_terminal,
            out.equality_link.consumer_terminal);
    out.equality_link.ordinary_proof =
        ordinary::ProveV1(
            link.cs, link.columns,
            out.equality_link.binding);
    out.equality_link.ordered_receipts_bound = true;
    out.equality_link.dual_fp3_terminal_cancellation =
        SameFp3(
            out.equality_link.source_terminal,
            out.equality_link.consumer_terminal);
    out.equality_link.valid =
        out.equality_link.ordinary_proof.valid &&
        out.equality_link.ordered_receipts_bound &&
        out.equality_link
            .dual_fp3_terminal_cancellation;
    out.equality_link.note =
        out.equality_link.valid
        ? "ordered receipt cancellation"
        : out.equality_link.ordinary_proof.note;
    if (!out.equality_link.valid) {
        out.note =
            "stage3:semantic_endpoint_receipt_intake:"
            "link_proof";
        return out;
    }
    child_css.push_back(link.cs);
    expected_children.push_back(
        ordinary::BuildExpectedRecursiveBindingV2(
            link.cs, out.equality_link.binding));
    child_receipts.push_back(
        out.equality_link.ordinary_proof.receipt);
    out.ordered_child_receipt_commitments.push_back(
        out.equality_link.ordinary_proof
            .receipt.receipt_commitment);

    const auto parent_bindings =
        ParentBindings(out.manifest, child_receipts);
    out.parent_node_binding =
        parent_bindings.first;
    out.parent_program_binding =
        parent_bindings.second;
    out.parent =
        fixedpoint::ExecuteNarrowRetainedReceiptParentV2(
            child_receipts, child_css,
            expected_children,
            out.parent_node_binding,
            out.parent_program_binding,
            prove_parent);
    out.exact_no_omission_no_duplicate_intake =
        out.role_receipts.size() ==
            out.manifest.active_roles;
    out.all_ordinary_receipts_verified = true;
    out.canonical_terminal_constraint_bytecode_complete =
        false;
    out.normalized_parent_proof_verified =
        prove_parent &&
        out.parent.cryptographically_valid &&
        out.parent.receipt.valid;
    out.recursive_child_verifier_constraints_complete =
        false;
    out.semantic_sites_credited = false;
    out.complete_fixed_point = false;
    out.authority_ready = false;
    out.construction_valid =
        out.exact_no_omission_no_duplicate_intake &&
        out.all_ordinary_receipts_verified &&
        !out.canonical_terminal_constraint_bytecode_complete &&
        (!prove_parent ||
         out.normalized_parent_proof_verified) &&
        !out.recursive_child_verifier_constraints_complete &&
        !out.semantic_sites_credited &&
        !out.complete_fixed_point &&
        !out.authority_ready;
    out.note = out.construction_valid
        ? "stage3:semantic_endpoint_receipt_intake:"
          "concrete receipts joined;"
          "recursive_child_verifier_constraints=false;"
          "semantic_credit=false"
        : "stage3:semantic_endpoint_receipt_intake:"
          "parent_invalid:" + out.parent.note;
    return out;
}

bool VerifyIntakeV1(
    const std::vector<RCStage3RoleAirProduct>& role_artifacts,
    const std::vector<exports::StreamChildArtifactV1>&
        stream_children,
    const ProofV1& proof,
    std::string* why)
{
    if (proof.version != kVersionV1) {
        return Fail(why, "version");
    }
    std::vector<AirCs> child_css;
    std::vector<
        fixedpoint::NarrowRecursiveProofExpectedBindingV2>
        expected;
    std::vector<
        fixedpoint::NarrowRecursiveProofReceiptV1>
        receipts;
    return RebuildIntake(
        role_artifacts, stream_children, proof,
        child_css, expected, receipts, why);
}

bool VerifyV1(
    const std::vector<RCStage3RoleAirProduct>& role_artifacts,
    const std::vector<exports::StreamChildArtifactV1>&
        stream_children,
    const ProofV1& proof,
    std::string* why)
{
    std::vector<AirCs> child_css;
    std::vector<
        fixedpoint::NarrowRecursiveProofExpectedBindingV2>
        expected;
    std::vector<
        fixedpoint::NarrowRecursiveProofReceiptV1>
        receipts;
    if (!RebuildIntake(
            role_artifacts, stream_children, proof,
            child_css, expected, receipts, why) ||
        !proof.normalized_parent_proof_verified) {
        return Fail(why, "intake_or_parent_flag");
    }
    const auto parent_bindings =
        ParentBindings(proof.manifest, receipts);
    if (proof.parent_node_binding !=
            parent_bindings.first ||
        proof.parent_program_binding !=
            parent_bindings.second ||
        !VerifyParent(
            receipts, child_css, expected,
            parent_bindings.first,
            parent_bindings.second,
            proof.parent.receipt, why)) {
        return Fail(why, "parent");
    }
    return true;
}

uint256 ComputeVerifiedRecursiveReceiptEvidenceCommitmentV1(
    const VerifiedRecursiveReceiptEvidenceV1& evidence)
{
    HashWriter hash;
    hash << VERIFIED_EVIDENCE_DOMAIN;
    hash << evidence.version;
    hash << evidence.inventory_commitment;
    hash << evidence.active_bitmap;
    hash << evidence.active_endpoints;
    hash << evidence.residual_endpoints;
    hash << evidence.active_roles;
    for (uint32_t ordinal = 0;
         ordinal < evidence
                       .endpoint_receipt_commitments
                       .size();
         ++ordinal) {
        hash << ordinal;
        hash << evidence
                    .endpoint_receipt_commitments[
                        ordinal];
    }
    hash << static_cast<uint32_t>(
        evidence
            .ordered_child_receipt_commitments
            .size());
    for (const uint256& commitment :
         evidence.ordered_child_receipt_commitments) {
        hash << commitment;
    }
    hash <<
        evidence.normalized_parent_receipt_commitment;
    hash << static_cast<uint8_t>(
        evidence.exact_canonical_inventory);
    hash << static_cast<uint8_t>(
        evidence
            .all_canonical_role_receipts_and_link_verified);
    hash << static_cast<uint8_t>(
        evidence.normalized_parent_proof_verified);
    hash << static_cast<uint8_t>(
        evidence
            .recursive_child_acceptance_constraints_complete);
    hash << static_cast<uint8_t>(
        evidence.complete_52_and_14);
    hash << static_cast<uint8_t>(
        evidence.recursive_credit_eligible);
    return hash.GetHash();
}

bool BuildVerifiedRecursiveReceiptEvidenceV1(
    const std::vector<RCStage3RoleAirProduct>&
        role_artifacts,
    const std::vector<exports::StreamChildArtifactV1>&
        stream_children,
    const ProofV1& proof,
    VerifiedRecursiveReceiptEvidenceV1& out,
    std::string* why)
{
    out = {};
    std::string verify_why;
    if (!VerifyV1(
            role_artifacts, stream_children,
            proof, &verify_why)) {
        return Fail(
            why, "verified_evidence:proof:" +
                verify_why);
    }
    if (!proof.manifest.valid ||
        proof.manifest.inventory_commitment.IsNull() ||
        proof.manifest.active_roles !=
            proof.role_receipts.size() ||
        proof.ordered_child_receipt_commitments.size() !=
            proof.role_receipts.size() + 1U ||
        !proof.parent.receipt.valid ||
        proof.parent.receipt
            .receipt_commitment.IsNull()) {
        return Fail(
            why, "verified_evidence:shape");
    }

    out.inventory_commitment =
        proof.manifest.inventory_commitment;
    out.active_bitmap =
        proof.manifest.active_bitmap;
    out.active_endpoints =
        proof.manifest.active_endpoints;
    out.residual_endpoints =
        proof.manifest.residual_endpoints;
    out.active_roles =
        proof.manifest.active_roles;
    out.ordered_child_receipt_commitments =
        proof.ordered_child_receipt_commitments;
    out.normalized_parent_receipt_commitment =
        proof.parent.receipt.receipt_commitment;

    for (uint32_t ordinal = 0;
         ordinal < proof.manifest.endpoints.size();
         ++ordinal) {
        const auto& endpoint =
            proof.manifest.endpoints[ordinal];
        if (!endpoint.present) {
            if (endpoint.receipt_slot !=
                    kNoReceiptSlotV1) {
                return Fail(
                    why,
                    "verified_evidence:"
                    "residual_receipt_slot");
            }
            continue;
        }
        // A host-executed StreamChildArtifactV1 owns only witness-level
        // child/bind columns.  It is not an ordinary recursive receipt and
        // therefore cannot be mapped to the enclosing role receipt.  Keep
        // this defense in depth even though BuildManifestV1 leaves every
        // such endpoint residual until a specialized child-receipt schema
        // is implemented and verified by the retained parent.
        if (endpoint.route.requires_stream_child) {
            return Fail(
                why,
                "verified_evidence:"
                "stream_child_recursive_receipt_absent");
        }
        if (endpoint.receipt_slot >=
                proof.role_receipts.size()) {
            return Fail(
                why,
                "verified_evidence:"
                "endpoint_receipt_slot");
        }
        const auto& receipt =
            proof.role_receipts[
                endpoint.receipt_slot];
        if (receipt.role != endpoint.route.role ||
            std::find(
                receipt.endpoint_ordinals.begin(),
                receipt.endpoint_ordinals.end(),
                ordinal) ==
                receipt.endpoint_ordinals.end()) {
            return Fail(
                why,
                "verified_evidence:"
                "endpoint_receipt_owner");
        }
        const uint256 commitment =
            receipt.ordinary_proof.receipt
                .receipt_commitment;
        if (commitment.IsNull()) {
            return Fail(
                why,
                "verified_evidence:"
                "endpoint_receipt_commitment");
        }
        out.endpoint_receipt_commitments[
            ordinal] = commitment;
    }

    out.exact_canonical_inventory =
        proof.manifest.exact_canonical_order &&
        proof.manifest.no_duplicate_roles &&
        proof.manifest.no_duplicate_stream_children;
    out
        .all_canonical_role_receipts_and_link_verified =
        proof.exact_no_omission_no_duplicate_intake &&
        proof.all_ordinary_receipts_verified &&
        proof.equality_link.valid &&
        proof.equality_link
            .ordered_receipts_bound &&
        proof.equality_link
            .dual_fp3_terminal_cancellation;
    out.normalized_parent_proof_verified =
        proof.normalized_parent_proof_verified;
    out
        .recursive_child_acceptance_constraints_complete =
        proof
            .recursive_child_verifier_constraints_complete;
    out.complete_52_and_14 =
        proof.manifest.complete_52 &&
        out.active_endpoints ==
            kEndpointCountV1 &&
        out.residual_endpoints == 0 &&
        out.active_roles ==
            kRCStage3RelationClosureRoleCount &&
        proof.role_receipts.size() ==
            kRCStage3RelationClosureRoleCount;
    out.recursive_credit_eligible =
        out.complete_52_and_14 &&
        out.exact_canonical_inventory &&
        out
            .all_canonical_role_receipts_and_link_verified &&
        out.normalized_parent_proof_verified &&
        out
            .recursive_child_acceptance_constraints_complete;
    // VerifyV1 currently rejects any proof which claims executable child
    // acceptance constraints. Until that verifier relation lands, evidence
    // is retained and bound but earns exactly zero recursive credit.
    if (out
            .recursive_child_acceptance_constraints_complete ||
        out.recursive_credit_eligible) {
        return Fail(
            why,
            "verified_evidence:"
            "recursive_acceptance_not_executable");
    }
    out.evidence_commitment =
        ComputeVerifiedRecursiveReceiptEvidenceCommitmentV1(
            out);
    out.valid =
        out.exact_canonical_inventory &&
        out
            .all_canonical_role_receipts_and_link_verified &&
        out.normalized_parent_proof_verified &&
        !out.evidence_commitment.IsNull();
    out.note =
        out.valid
        ? "stage3:semantic_endpoint_receipt_intake:"
          "verified_recursive_receipt_evidence;"
          "recursive_child_acceptance_constraints=false;"
          "recursive_credit=false"
        : "stage3:semantic_endpoint_receipt_intake:"
          "verified_recursive_receipt_evidence_invalid";
    if (!out.valid) {
        out.evidence_commitment.SetNull();
        return Fail(
            why,
            "verified_evidence:invalid");
    }
    if (why != nullptr) *why = out.note;
    return true;
}

bool VerifyRecursiveReceiptEvidenceV1(
    const std::vector<RCStage3RoleAirProduct>&
        role_artifacts,
    const std::vector<exports::StreamChildArtifactV1>&
        stream_children,
    const ProofV1& proof,
    const VerifiedRecursiveReceiptEvidenceV1& claimed,
    std::string* why)
{
    VerifiedRecursiveReceiptEvidenceV1 expected;
    std::string rebuild_why;
    if (!BuildVerifiedRecursiveReceiptEvidenceV1(
            role_artifacts, stream_children,
            proof, expected, &rebuild_why) ||
        claimed != expected ||
        claimed.evidence_commitment.IsNull() ||
        claimed.evidence_commitment !=
            ComputeVerifiedRecursiveReceiptEvidenceCommitmentV1(
                claimed)) {
        return Fail(
            why,
            "verified_evidence:mismatch:" +
                rebuild_why);
    }
    if (why != nullptr) {
        *why =
            "stage3:semantic_endpoint_receipt_intake:"
            "verified_evidence_rebuilt_and_equal";
    }
    return true;
}

} // namespace matmul::v4::rc::stage3_semantic_endpoint_receipt_intake
