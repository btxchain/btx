// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/MIT.

#include <matmul/matmul_v4_rc_stage3_episode_wiring_proof_tape_join.h>

#include <hash.h>

#include <algorithm>
#include <functional>

namespace matmul::v4::rc::stage3_episode_wiring_proof_tape_join {
namespace {

using AirCs = aq::AirConstraintSystem<gf::Fp3>;
using Fp3 = gf::Fp3;

constexpr char BINDING_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_WIRING_PROOF_TAPE_JOIN_BINDING_V1";
constexpr char PARENT_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_WIRING_PROOF_TAPE_JOIN_PARENT_V1";

enum class ChildRole : uint8_t {
    Producer = 1,
    Consumer = 2,
    EqualityLink = 3,
};

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why =
            "stage3:episode_wiring_proof_tape_join:" +
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

void HashStatement(
    HashWriter& hash,
    const StatementV1& statement)
{
    hash << statement.version;
    hash << statement.product_commitment;
    hash << statement.statement_commitment;
    hash << statement.schedule_root;
    hash << statement.proof_wire_root;
    hash << statement.record_count;
    for (uint32_t lane = 0;
         lane < kTerminalLanesV1; ++lane) {
        HashFp3(hash, statement.challenges.gamma[lane]);
        HashFp3(hash, statement.challenges.alpha[lane]);
        HashFp3(hash, statement.producer_terminal[lane]);
        HashFp3(hash, statement.consumer_terminal[lane]);
    }
}

uint256 TaggedHash(
    const char* label,
    ChildRole role,
    const StatementV1& statement,
    const uint256& left = {},
    const uint256& right = {})
{
    HashWriter hash;
    hash << BINDING_DOMAIN;
    hash << label;
    hash << static_cast<uint8_t>(role);
    HashStatement(hash, statement);
    if (!left.IsNull() || !right.IsNull()) {
        hash << left;
        hash << right;
    }
    return hash.GetHash();
}

ordinary::PublicBindingV1 BuildBinding(
    ChildRole role,
    const StatementV1& statement,
    const uint256& left = {},
    const uint256& right = {})
{
    ordinary::PublicBindingV1 out;
    out.node_binding =
        TaggedHash("node", role, statement, left, right);
    out.program_binding =
        TaggedHash("program", role, statement, left, right);
    out.proof_context_binding =
        TaggedHash("context", role, statement, left, right);
    out.public_statement_binding =
        TaggedHash("statement", role, statement, left, right);
    out.fs_seed =
        TaggedHash("fiat_shamir", role, statement, left, right);
    return out;
}

std::pair<uint256, uint256> ParentBindings(
    const StatementV1& statement,
    const std::vector<
        fixedpoint::NarrowRecursiveProofReceiptV1>& children)
{
    if (children.size() != 3) return {};
    HashWriter node;
    node << PARENT_DOMAIN;
    node << "node";
    HashStatement(node, statement);
    HashWriter program;
    program << PARENT_DOMAIN;
    program << "program";
    HashStatement(program, statement);
    for (uint32_t slot = 0; slot < children.size(); ++slot) {
        node << slot;
        node << children[slot].receipt_commitment;
        program << slot;
        program << children[slot].program_binding;
    }
    return {node.GetHash(), program.GetHash()};
}

uint32_t CountViolations(
    const AirCs& cs,
    const std::vector<std::vector<Fp3>>& columns)
{
    if (columns.size() != cs.n_columns) return UINT32_MAX;
    for (const auto& column : columns) {
        if (column.size() != cs.n_rows) return UINT32_MAX;
    }
    uint32_t count = 0;
    std::vector<Fp3> cur(cs.n_columns);
    std::vector<Fp3> next(cs.n_columns);
    for (uint32_t row = 0; row < cs.n_rows; ++row) {
        const uint32_t next_row =
            std::min(row + 1, cs.n_rows - 1);
        for (uint32_t column = 0;
             column < cs.n_columns; ++column) {
            cur[column] = columns[column][row];
            next[column] = columns[column][next_row];
        }
        for (const auto& constraint : cs.constraints) {
            bool applies = false;
            switch (constraint.kind) {
            case aq::AirKind::kEverywhere:
                applies = true;
                break;
            case aq::AirKind::kTransition:
                applies = row + 1 < cs.n_rows;
                break;
            case aq::AirKind::kFirstRow:
                applies = row == 0;
                break;
            case aq::AirKind::kLastRow:
                applies = row + 1 == cs.n_rows;
                break;
            }
            if (applies &&
                !gf::IsZero(
                    constraint.eval(cur, next))) {
                ++count;
            }
        }
    }
    return count;
}

bool SameTerminal(
    const std::array<Fp3, kTerminalLanesV1>& left,
    const std::array<Fp3, kTerminalLanesV1>& right)
{
    for (uint32_t lane = 0;
         lane < kTerminalLanesV1; ++lane) {
        if (!gf::Eq(left[lane], right[lane])) {
            return false;
        }
    }
    return true;
}

uint256 ExpectedParentStatement(
    const fixedpoint::FoldBusComposition& node,
    const std::vector<uint256>& child_seeds,
    const uint256& parent_context,
    const fixedpoint::NarrowRecursiveProofReceiptV1& receipt)
{
    if (!node.valid ||
        child_seeds.size() != 3 ||
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
    for (const auto& seed : child_seeds) {
        hash << seed;
    }
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
    if (children.size() != 3 ||
        child_css.size() != children.size() ||
        expected_children.size() != children.size()) {
        return Fail(why, "verify_parent_arity");
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
                why, "verify_parent_child_" +
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
            node.combined.constraints.size()) {
        return Fail(why, "verify_parent_statement");
    }
    if (receipt.statement_commitment !=
        ExpectedParentStatement(
            node, seeds, context, receipt)) {
        return Fail(why, "verify_parent_statement_commitment");
    }
    std::string parent_why;
    if (!fixedpoint::ValidateNarrowRecursiveProofReceiptV1(
            receipt, node.combined,
            parent_node_binding,
            parent_program_binding,
            &parent_why)) {
        return Fail(
            why, "verify_parent_proof:" + parent_why);
    }
    return true;
}

} // namespace

bool StatementV1::operator==(
    const StatementV1& other) const
{
    return version == other.version &&
        product_commitment == other.product_commitment &&
        statement_commitment == other.statement_commitment &&
        schedule_root == other.schedule_root &&
        proof_wire_root == other.proof_wire_root &&
        record_count == other.record_count &&
        challenges == other.challenges &&
        SameTerminal(
            producer_terminal,
            other.producer_terminal) &&
        SameTerminal(
            consumer_terminal,
            other.consumer_terminal);
}

bool BuildStatementV1(
    const descriptor::ManifestV1& manifest,
    StatementV1& out,
    std::string* why)
{
    out = {};
    const descriptor::ProductV1 producer =
        descriptor::BuildProductV1(manifest);
    descriptor::ChallengesV1 challenges;
    if (!manifest.valid || !producer.valid ||
        manifest.records.empty() ||
        manifest.records.size() > UINT32_MAX ||
        !descriptor::DeriveChallengesV1(
            manifest, challenges)) {
        return Fail(why, "statement_manifest");
    }
    out.version = kVersionV1;
    out.product_commitment =
        manifest.product_commitment;
    out.statement_commitment =
        manifest.statement_commitment;
    out.schedule_root = manifest.schedule_root;
    out.proof_wire_root = manifest.proof_wire_root;
    out.record_count =
        static_cast<uint32_t>(
            manifest.records.size());
    out.challenges = challenges;
    out.producer_terminal =
        producer.source_terminal;
    out.consumer_terminal =
        producer.source_terminal;
    return true;
}

ConsumerV1 BuildAndProveConsumerV1(
    const RCStage3EpisodeWiringProduct& wiring)
{
    descriptor::ManifestV1 manifest;
    std::string why;
    if (!descriptor::BuildManifestV1(
            wiring, manifest, &why)) {
        ConsumerV1 out;
        out.note =
            "stage3:episode_wiring_proof_tape_join:"
            "consumer_manifest:" + why;
        return out;
    }
    return BuildAndProveConsumerManifestV1(manifest);
}

ConsumerV1 BuildAndProveConsumerManifestV1(
    const descriptor::ManifestV1& manifest)
{
    ConsumerV1 out;
    out.manifest = manifest;
    std::string why;
    // Deliberately rebuild from the manifest rather than reusing the producer
    // ProductV1 or its callback-bearing constraint system.
    out.product =
        descriptor::BuildProductV1(out.manifest);
    StatementV1 statement;
    if (!out.product.valid ||
        !BuildStatementV1(
            out.manifest, statement, &why)) {
        out.note =
            "stage3:episode_wiring_proof_tape_join:"
            "consumer_product";
        return out;
    }
    out.binding =
        BuildBinding(ChildRole::Consumer, statement);
    out.ordinary_proof =
        ordinary::ProveV1(
            out.product.cs, out.product.columns,
            out.binding);
    out.exact_canonical_inventory =
        out.manifest.every_verifier_read_classified &&
        out.manifest.canonical_u32_words;
    out.independently_rebuilt_air =
        out.product.valid &&
        out.ordinary_proof.valid;
    // The ordinary child authenticates the exact tape and its equality
    // terminal.  It does not execute AirQuotientVerify as AIR constraints.
    out.legacy_fri_verifier_in_air = false;
    out.valid =
        out.exact_canonical_inventory &&
        out.independently_rebuilt_air &&
        !out.legacy_fri_verifier_in_air;
    out.note = out.valid
        ? "stage3:episode_wiring_proof_tape_join:"
          "consumer_authenticated;"
          "legacy_fri_verifier_in_air=false"
        : "stage3:episode_wiring_proof_tape_join:"
          "consumer_invalid";
    return out;
}

bool VerifyConsumerV1(
    const RCStage3EpisodeWiringProduct& wiring,
    const ConsumerV1& consumer,
    std::string* why)
{
    descriptor::ManifestV1 manifest;
    if (!descriptor::BuildManifestV1(
            wiring, manifest, why)) {
        return Fail(why, "verify_consumer_manifest");
    }
    if (consumer.manifest != manifest ||
        consumer.legacy_fri_verifier_in_air) {
        return Fail(why, "verify_consumer_manifest");
    }
    const auto expected =
        descriptor::BuildProductV1(manifest);
    StatementV1 statement;
    if (!expected.valid ||
        !BuildStatementV1(
            manifest, statement, why)) {
        return Fail(why, "verify_consumer_product");
    }
    const auto binding =
        BuildBinding(ChildRole::Consumer, statement);
    if (consumer.binding != binding ||
        !ordinary::VerifyV1(
            consumer.ordinary_proof,
            expected.cs, binding, why)) {
        return Fail(why, "verify_consumer_ordinary");
    }
    return true;
}

LinkProductV1 BuildLinkProductV1(
    const StatementV1& statement,
    const uint256& producer_receipt_commitment,
    const uint256& consumer_receipt_commitment)
{
    LinkProductV1 out;
    out.statement = statement;
    if (statement.version != kVersionV1 ||
        statement.product_commitment.IsNull() ||
        statement.statement_commitment.IsNull() ||
        statement.schedule_root.IsNull() ||
        statement.proof_wire_root.IsNull() ||
        statement.record_count == 0 ||
        producer_receipt_commitment.IsNull() ||
        consumer_receipt_commitment.IsNull() ||
        producer_receipt_commitment ==
            consumer_receipt_commitment) {
        out.note =
            "stage3:episode_wiring_proof_tape_join:"
            "link_statement";
        return out;
    }
    out.cs.n_rows = 2;
    out.cs.n_columns = 5;
    out.cs.preprocessed_pin_ood = true;
    out.columns.assign(
        out.cs.n_columns,
        std::vector<Fp3>(
            out.cs.n_rows, Fp3::Zero()));
    for (uint32_t lane = 0;
         lane < kTerminalLanesV1; ++lane) {
        out.columns[lane].assign(
            out.cs.n_rows,
            statement.producer_terminal[lane]);
        out.columns[2 + lane].assign(
            out.cs.n_rows,
            statement.consumer_terminal[lane]);
        out.cancellation[lane] =
            gf::Sub(
                statement.producer_terminal[lane],
                statement.consumer_terminal[lane]);
        out.cs.preprocessed.emplace_back(
            lane, out.columns[lane]);
        out.cs.preprocessed.emplace_back(
            2 + lane, out.columns[2 + lane]);
        out.cs.constraints.push_back({
            "wiring_tape_join.terminal_cancellation",
            aq::AirKind::kEverywhere, 1,
            [lane](const auto& cur, const auto&) {
                return gf::Sub(
                    cur[lane], cur[2 + lane]);
            }});
    }
    for (uint32_t row = 0; row < out.cs.n_rows; ++row) {
        out.columns[4][row] =
            gf::Add(
                out.columns[0][row],
                out.columns[1][row]);
    }
    out.cs.constraints.push_back({
        "wiring_tape_join.live_witness",
        aq::AirKind::kEverywhere, 1,
        [](const auto& cur, const auto&) {
            return gf::Sub(
                cur[4],
                gf::Add(cur[0], cur[1]));
        }});
    out.binding =
        BuildBinding(
            ChildRole::EqualityLink, statement,
            producer_receipt_commitment,
            consumer_receipt_commitment);
    out.violations =
        CountViolations(out.cs, out.columns);
    out.all_roots_bound =
        !statement.product_commitment.IsNull() &&
        !statement.statement_commitment.IsNull() &&
        !statement.schedule_root.IsNull() &&
        !statement.proof_wire_root.IsNull();
    out.receipt_pair_bound = true;
    out.dual_fp3_terminal_cancellation =
        gf::IsZero(out.cancellation[0]) &&
        gf::IsZero(out.cancellation[1]);
    out.valid =
        out.violations == 0 &&
        out.all_roots_bound &&
        out.receipt_pair_bound &&
        out.dual_fp3_terminal_cancellation;
    out.note = out.valid
        ? "stage3:episode_wiring_proof_tape_join:"
          "dual_fp3_cancellation"
        : "stage3:episode_wiring_proof_tape_join:"
          "link_violation";
    return out;
}

ProofV1 ProveV1(
    const RCStage3EpisodeWiringProduct& wiring,
    bool prove_parent)
{
    descriptor::ManifestV1 producer_manifest;
    std::string why;
    if (!descriptor::BuildManifestV1(
            wiring, producer_manifest, &why)) {
        ProofV1 out;
        out.note =
            "stage3:episode_wiring_proof_tape_join:"
            "prove_statement:" + why;
        return out;
    }
    return ProveManifestV1(
        producer_manifest, prove_parent);
}

ProofV1 ProveManifestV1(
    const descriptor::ManifestV1& producer_manifest,
    bool prove_parent)
{
    ProofV1 out;
    std::string why;
    if (!BuildStatementV1(
            producer_manifest,
            out.statement, &why)) {
        out.note =
            "stage3:episode_wiring_proof_tape_join:"
            "prove_statement:" + why;
        return out;
    }
    const auto producer_product =
        descriptor::BuildProductV1(
            producer_manifest);
    const auto producer_binding =
        BuildBinding(
            ChildRole::Producer, out.statement);
    out.producer =
        ordinary::ProveV1(
            producer_product.cs,
            producer_product.columns,
            producer_binding);
    out.consumer =
        BuildAndProveConsumerManifestV1(
            producer_manifest);
    if (!out.producer.valid ||
        !out.consumer.valid ||
        out.consumer.manifest != producer_manifest ||
        !SameTerminal(
            out.statement.consumer_terminal,
            out.consumer.product.source_terminal)) {
        out.note =
            "stage3:episode_wiring_proof_tape_join:"
            "prove_children";
        return out;
    }
    const auto link =
        BuildLinkProductV1(
            out.statement,
            out.producer.receipt.receipt_commitment,
            out.consumer.ordinary_proof
                .receipt.receipt_commitment);
    if (!link.valid) {
        out.note = link.note;
        return out;
    }
    out.equality_link =
        ordinary::ProveV1(
            link.cs, link.columns, link.binding);
    if (!out.equality_link.valid) {
        out.note =
            "stage3:episode_wiring_proof_tape_join:"
            "prove_link:" +
            out.equality_link.note;
        return out;
    }

    const std::vector<
        fixedpoint::NarrowRecursiveProofReceiptV1> children{
        out.producer.receipt,
        out.consumer.ordinary_proof.receipt,
        out.equality_link.receipt};
    const std::vector<AirCs> child_css{
        producer_product.cs,
        out.consumer.product.cs,
        link.cs};
    const std::vector<
        fixedpoint::NarrowRecursiveProofExpectedBindingV2>
        expected{
            ordinary::BuildExpectedRecursiveBindingV2(
                producer_product.cs,
                producer_binding),
            ordinary::BuildExpectedRecursiveBindingV2(
                out.consumer.product.cs,
                out.consumer.binding),
            ordinary::BuildExpectedRecursiveBindingV2(
                link.cs, link.binding)};
    const auto parent_bindings =
        ParentBindings(out.statement, children);
    out.parent_node_binding =
        parent_bindings.first;
    out.parent_program_binding =
        parent_bindings.second;
    out.parent =
        fixedpoint::ExecuteNarrowRetainedReceiptParentV2(
            children, child_css, expected,
            out.parent_node_binding,
            out.parent_program_binding,
            prove_parent);
    out.three_ordinary_children_verified = true;
    out.normalized_parent_proof_verified =
        prove_parent &&
        out.parent.cryptographically_valid &&
        out.parent.receipt.valid;
    out.host_composition_authenticated =
        out.normalized_parent_proof_verified;
    out.legacy_fri_verifier_in_parent_air = false;
    out.complete_fixed_point = false;
    out.semantic_sites_credited = false;
    out.authority_ready = false;
    out.construction_valid =
        out.three_ordinary_children_verified &&
        (!prove_parent ||
         out.normalized_parent_proof_verified) &&
        !out.legacy_fri_verifier_in_parent_air &&
        !out.complete_fixed_point &&
        !out.semantic_sites_credited &&
        !out.authority_ready;
    out.note = out.construction_valid
        ? "stage3:episode_wiring_proof_tape_join:"
          "authenticated_parent;"
          "legacy_fri_verifier_in_parent_air=false;"
          "complete_fp=false;semantic_credit=false"
        : "stage3:episode_wiring_proof_tape_join:"
          "parent_invalid:" + out.parent.note;
    return out;
}

bool VerifyV1(
    const RCStage3EpisodeWiringProduct& wiring,
    const ProofV1& proof,
    std::string* why)
{
    descriptor::ManifestV1 manifest;
    if (!descriptor::BuildManifestV1(
            wiring, manifest, why)) {
        return Fail(why, "verify_manifest");
    }
    return VerifyManifestV1(
        manifest, proof, why);
}

bool VerifyManifestV1(
    const descriptor::ManifestV1& manifest,
    const ProofV1& proof,
    std::string* why)
{
    if (proof.version != kVersionV1 ||
        proof.legacy_fri_verifier_in_parent_air ||
        proof.complete_fixed_point ||
        proof.semantic_sites_credited ||
        proof.authority_ready) {
        return Fail(why, "verify_envelope");
    }
    StatementV1 statement;
    if (!BuildStatementV1(
            manifest, statement, why) ||
        !(proof.statement == statement)) {
        return Fail(why, "verify_statement");
    }
    const auto producer_product =
        descriptor::BuildProductV1(manifest);
    const auto producer_binding =
        BuildBinding(
            ChildRole::Producer, statement);
    if (!producer_product.valid ||
        proof.producer.binding != producer_binding ||
        !ordinary::VerifyV1(
            proof.producer,
            producer_product.cs,
            producer_binding, why)) {
        return Fail(why, "verify_children");
    }
    const auto expected_consumer =
        descriptor::BuildProductV1(manifest);
    const auto consumer_binding =
        BuildBinding(
            ChildRole::Consumer, statement);
    if (proof.consumer.manifest != manifest ||
        proof.consumer.legacy_fri_verifier_in_air ||
        !expected_consumer.valid ||
        proof.consumer.binding != consumer_binding ||
        !ordinary::VerifyV1(
            proof.consumer.ordinary_proof,
            expected_consumer.cs,
            consumer_binding, why)) {
        return Fail(why, "verify_consumer");
    }
    const auto link =
        BuildLinkProductV1(
            statement,
            proof.producer.receipt
                .receipt_commitment,
            proof.consumer.ordinary_proof
                .receipt.receipt_commitment);
    if (!link.valid ||
        proof.equality_link.binding != link.binding ||
        !ordinary::VerifyV1(
            proof.equality_link,
            link.cs, link.binding, why)) {
        return Fail(why, "verify_link");
    }
    const std::vector<
        fixedpoint::NarrowRecursiveProofReceiptV1> children{
        proof.producer.receipt,
        proof.consumer.ordinary_proof.receipt,
        proof.equality_link.receipt};
    const std::vector<AirCs> child_css{
        producer_product.cs,
        expected_consumer.cs,
        link.cs};
    const std::vector<
        fixedpoint::NarrowRecursiveProofExpectedBindingV2>
        expected{
            ordinary::BuildExpectedRecursiveBindingV2(
                producer_product.cs,
                producer_binding),
            ordinary::BuildExpectedRecursiveBindingV2(
                expected_consumer.cs,
                consumer_binding),
            ordinary::BuildExpectedRecursiveBindingV2(
                link.cs, link.binding)};
    const auto parent_bindings =
        ParentBindings(statement, children);
    if (proof.parent_node_binding !=
            parent_bindings.first ||
        proof.parent_program_binding !=
            parent_bindings.second ||
        !VerifyParent(
            children, child_css, expected,
            parent_bindings.first,
            parent_bindings.second,
            proof.parent.receipt, why)) {
        return Fail(why, "verify_parent");
    }
    return true;
}

} // namespace matmul::v4::rc::stage3_episode_wiring_proof_tape_join
