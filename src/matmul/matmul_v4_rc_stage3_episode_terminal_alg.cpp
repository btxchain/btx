// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_episode_terminal_alg.h>

#include <hash.h>

#include <algorithm>
#include <array>
#include <utility>

namespace matmul::v4::rc::episode_terminal_alg {
namespace {

using AirCs = aq::AirConstraintSystem<gf::Fp3>;
using Fp3 = gf::Fp3;

constexpr char kProductDomain[] =
    "BTX_RC_STAGE3_EPISODE_TERMINAL_ALG_PRODUCT_V1";
constexpr char kChildDomain[] =
    "BTX_RC_STAGE3_EPISODE_TERMINAL_ALG_CHILD_V1";

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why =
            "stage3:episode_terminal_alg:" +
            detail;
    }
    return false;
}

std::vector<uint8_t> RoundRootBytes(
    const stage3_hash_air::EpisodeDigestManifest& manifest)
{
    std::vector<uint8_t> out;
    out.reserve(manifest.round_roots.size() * 32U);
    for (const auto& root : manifest.round_roots) {
        out.insert(out.end(), root.begin(), root.end());
    }
    return out;
}

std::vector<uint8_t> DigestBytes(const uint256& digest)
{
    return {digest.begin(), digest.end()};
}

std::vector<Fp3> HeaderPublicValues(
    const RCStage3EpisodeHeaderTargetPin& pin)
{
    std::vector<Fp3> out;
    out.reserve(kRCStage3EpisodeHeaderTargetPublicCells);
    for (uint32_t i = 0; i < 4; ++i) {
        out.push_back(Fp3::FromFp(
            static_cast<uint8_t>(
                pin.n_bits >> (8U * i))));
    }
    for (uint8_t byte : pin.header_commitment) {
        out.push_back(Fp3::FromFp(byte));
    }
    for (uint8_t byte : pin.target) {
        out.push_back(Fp3::FromFp(byte));
    }
    return out;
}

struct InstanceV1 {
    ChildKindV1 kind{};
    RCStage3RelationEndpoint endpoint{};
    AirCs cs;
    std::vector<std::vector<Fp3>> columns;
    uint256 public_fs_seed{};
    uint256 source_statement{};
};

uint256 ChildStatement(
    ChildKindV1 kind,
    RCStage3RelationEndpoint endpoint,
    const uint256& statement_commitment,
    const uint256& digest_product_commitment,
    const uint256& digest_endpoint_binding_root,
    const uint256& header_pin_commitment,
    const uint256& public_fs_seed,
    const AirCs& cs)
{
    if (statement_commitment.IsNull() ||
        digest_product_commitment.IsNull() ||
        digest_endpoint_binding_root.IsNull() ||
        header_pin_commitment.IsNull() ||
        public_fs_seed.IsNull() ||
        cs.n_rows < 2 || cs.n_columns == 0 ||
        cs.constraints.empty()) {
        return {};
    }
    HashWriter hash;
    hash << kChildDomain << kVersionV1;
    hash << static_cast<uint8_t>(kind);
    hash << static_cast<uint16_t>(endpoint);
    hash << statement_commitment;
    hash << digest_product_commitment;
    hash << digest_endpoint_binding_root;
    hash << header_pin_commitment;
    hash << public_fs_seed;
    hash << cs.n_rows << cs.n_columns;
    hash << static_cast<uint32_t>(
        cs.constraints.size());
    return hash.GetHash();
}

bool FillVectorColumns(
    const AirCs& cs,
    const std::vector<uint8_t>& values,
    std::vector<std::vector<Fp3>>& out)
{
    if (values.size() > cs.n_rows ||
        cs.n_columns != kRCStage3RootChainColumns) {
        return false;
    }
    out.assign(
        cs.n_columns,
        std::vector<Fp3>(
            cs.n_rows, Fp3::Zero()));
    for (const auto& [column, canonical] :
         cs.preprocessed) {
        if (column >= out.size() ||
            canonical.size() != cs.n_rows) {
            return false;
        }
        out[column] = canonical;
    }
    for (uint32_t row = 0;
         row < values.size(); ++row) {
        const Fp3 value =
            Fp3::FromFp(values[row]);
        out[kRCStage3RootChainValue][row] =
            value;
        out[kRCStage3RootChainExport][row] =
            value;
    }
    return true;
}

bool FillMemoryColumns(
    const AirCs& cs,
    const std::vector<Fp3>& values,
    std::vector<std::vector<Fp3>>& out)
{
    if (values.size() > cs.n_rows ||
        cs.n_columns !=
            kRCStage3EpisodeMemoryColumns) {
        return false;
    }
    out.assign(
        cs.n_columns,
        std::vector<Fp3>(
            cs.n_rows, Fp3::Zero()));
    for (const auto& [column, canonical] :
         cs.preprocessed) {
        if (column >= out.size() ||
            canonical.size() != cs.n_rows) {
            return false;
        }
        out[column] = canonical;
    }
    std::copy(
        values.begin(), values.end(),
        out[kRCStage3EpisodeMemoryValue].begin());
    out[kRCStage3EpisodeMemoryExport] =
        out[kRCStage3EpisodeMemoryValue];
    return true;
}

bool BindDeterministicColumnsForAlg(
    InstanceV1& instance,
    std::string* why)
{
    if (instance.columns.size() !=
            instance.cs.n_columns ||
        instance.cs.n_rows < 2) {
        return Fail(why, "alg_public_column_shape");
    }
    const uint32_t n_coeffs =
        FriNextPow2(std::max(
            instance.cs.n_rows,
            instance.cs.QuotientLen()));
    for (const auto& [column, root] :
         instance.cs.preprocessed_roots) {
        if (column >= instance.columns.size() ||
            root !=
                aq::AirCommittedValuesRoot<
                    Fp3,
                    aq::AirFriBackendAlg<Fp3>>(
                        instance.columns[column],
                        n_coeffs)) {
            return Fail(
                why, "alg_public_root_" +
                    std::to_string(column));
        }
    }

    /*
     * Every V1 terminal witness cell is deterministically rebuilt from the
     * consensus statement and already-verified source products.  A row-wise
     * Alg proof cannot enforce the source products' per-column root pins.
     * Bind the actual row commitment to the complete rebuilt trace through
     * dual-OOD public-column equality instead of silently dropping those
     * pins.  This is verifier-linear and therefore earns no production
     * authority by itself, but it is a sound recursive proof-family bridge.
     */
    instance.cs.preprocessed_roots.clear();
    instance.cs.preprocessed.clear();
    instance.cs.preprocessed.reserve(
        instance.columns.size());
    for (uint32_t column = 0;
         column < instance.columns.size(); ++column) {
        instance.cs.preprocessed.emplace_back(
            column, instance.columns[column]);
    }
    instance.cs.preprocessed_pin_ood = true;
    return true;
}

bool BuildInstances(
    const RCStage3SuccinctProof& statement,
    const digest::ProductV1& digest_product,
    const RCStage3EpisodeHeaderTargetProduct& header_target,
    std::vector<InstanceV1>& out,
    std::string* why)
{
    out.clear();
    const uint256 statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    if (statement_commitment.IsNull() ||
        digest_product.product_commitment.IsNull() ||
        digest_product.endpoint_binding_root.IsNull() ||
        header_target.pin.pin_commitment.IsNull()) {
        return Fail(why, "instance_public_roots");
    }

    const auto add_statement =
        [&](InstanceV1& instance) {
            instance.source_statement =
                ChildStatement(
                    instance.kind,
                    instance.endpoint,
                    statement_commitment,
                    digest_product.product_commitment,
                    digest_product.endpoint_binding_root,
                    header_target.pin.pin_commitment,
                    instance.public_fs_seed,
                    instance.cs);
            return !instance.source_statement.IsNull();
        };

    {
        InstanceV1 instance;
        instance.kind = ChildKindV1::RoundRoots;
        instance.endpoint =
            RCStage3RelationEndpoint::
                EpisodeDigestRoundRoots;
        const auto values =
            RoundRootBytes(digest_product.manifest);
        const auto& pin =
            digest_product.endpoint_root_chain
                .round_roots_pin;
        if (!BuildRCStage3RootChainVectorConstraintSystem(
                pin, values, instance.cs, why) ||
            !FillVectorColumns(
                instance.cs, values,
                instance.columns)) {
            return Fail(why, "round_roots_instance");
        }
        instance.public_fs_seed =
            ComputeRCStage3RootChainVectorSeed(pin);
        if (!add_statement(instance)) {
            return Fail(why, "round_roots_statement");
        }
        out.push_back(std::move(instance));
    }
    {
        InstanceV1 instance;
        instance.kind = ChildKindV1::DigestValue;
        instance.endpoint =
            RCStage3RelationEndpoint::
                EpisodeDigestValue;
        const auto values =
            DigestBytes(
                digest_product.manifest.direct.digest);
        const auto& pin =
            digest_product.endpoint_root_chain
                .digest_pin;
        if (!BuildRCStage3RootChainVectorConstraintSystem(
                pin, values, instance.cs, why) ||
            !FillVectorColumns(
                instance.cs, values,
                instance.columns)) {
            return Fail(why, "digest_instance");
        }
        instance.public_fs_seed =
            ComputeRCStage3RootChainVectorSeed(pin);
        if (!add_statement(instance)) {
            return Fail(why, "digest_statement");
        }
        out.push_back(std::move(instance));
    }
    {
        InstanceV1 instance;
        instance.kind = ChildKindV1::HeaderTarget;
        instance.endpoint =
            RCStage3RelationEndpoint::
                EpisodeDigestHeaderTarget;
        if (!BuildRCStage3EpisodeHeaderTargetConstraintSystem(
                header_target.pin,
                instance.cs, why)) {
            return Fail(why, "header_target_cs");
        }
        instance.columns.assign(
            instance.cs.n_columns,
            std::vector<Fp3>(
                instance.cs.n_rows, Fp3::Zero()));
        for (const auto& [column, canonical] :
             instance.cs.preprocessed) {
            instance.columns[column] = canonical;
        }
        for (uint32_t row = 0;
             row < instance.cs.n_rows; ++row) {
            instance.columns[
                kRCStage3EpisodeHeaderTargetByte][row] =
                Fp3::FromFp(
                    header_target.pin.target.data()[row]);
        }
        instance.public_fs_seed =
            ComputeRCStage3EpisodeHeaderTargetSeed(
                header_target.pin);
        if (!add_statement(instance)) {
            return Fail(why, "header_target_statement");
        }
        out.push_back(std::move(instance));
    }
    {
        InstanceV1 instance;
        instance.kind =
            ChildKindV1::HeaderPublicMemory;
        instance.endpoint =
            RCStage3RelationEndpoint::
                EpisodeDigestHeaderTarget;
        const auto values =
            HeaderPublicValues(header_target.pin);
        const uint32_t n_rows =
            header_target.public_memory_manifest.n_rows;
        std::vector<Fp3> padded_values(
            n_rows, Fp3::Zero());
        if (values.size() > padded_values.size()) {
            return Fail(
                why, "header_memory_value_rows");
        }
        std::copy(
            values.begin(), values.end(),
            padded_values.begin());
        auto alg_root =
            aq::AirCommittedValuesRoot<
                Fp3, aq::AirFriBackendAlg<Fp3>>(
                    padded_values, n_rows);
        auto manifest =
            BuildRCStage3EpisodeSemanticMemoryManifest(
                instance.endpoint,
                statement_commitment,
                values.size(), values.size(),
                0, 1, alg_root, why);
        if (!manifest.has_value() ||
            !BuildRCStage3EpisodeSemanticMemoryConstraintSystem(
                *manifest, instance.cs, why)) {
            return Fail(why, "header_memory_instance");
        }
        const uint32_t n_coeffs =
            FriNextPow2(std::max(
                instance.cs.n_rows,
                instance.cs.QuotientLen()));
        if (n_coeffs != n_rows) {
            alg_root =
                aq::AirCommittedValuesRoot<
                    Fp3,
                    aq::AirFriBackendAlg<Fp3>>(
                        padded_values, n_coeffs);
            manifest =
                BuildRCStage3EpisodeSemanticMemoryManifest(
                    instance.endpoint,
                    statement_commitment,
                    values.size(), values.size(),
                    0, 1, alg_root, why);
            if (!manifest.has_value() ||
                !BuildRCStage3EpisodeSemanticMemoryConstraintSystem(
                    *manifest, instance.cs, why)) {
                return Fail(
                    why,
                    "header_memory_commitment_domain");
            }
        }
        if (
            !FillMemoryColumns(
                instance.cs, values,
                instance.columns)) {
            return Fail(why, "header_memory_instance");
        }
        instance.public_fs_seed =
            ComputeRCStage3EpisodeSemanticMemorySeed(
                *manifest);
        if (!add_statement(instance)) {
            return Fail(why, "header_memory_statement");
        }
        out.push_back(std::move(instance));
    }
    {
        InstanceV1 instance;
        instance.kind = ChildKindV1::DigestPow;
        instance.endpoint =
            RCStage3RelationEndpoint::
                EpisodeDigestPow;
        const auto pin =
            BuildRCStage3EpisodePowPin(
                statement, why);
        if (!pin.has_value() ||
            !BuildRCStage3EpisodePowConstraintSystem(
                *pin, instance.cs, why) ||
            !BuildRCStage3EpisodePowWitness(
                *pin, instance.columns, why)) {
            return Fail(why, "pow_instance");
        }
        instance.public_fs_seed =
            ComputeRCStage3EpisodePowSeed(*pin);
        if (!add_statement(instance)) {
            return Fail(why, "pow_statement");
        }
        out.push_back(std::move(instance));
    }
    if (out.size() != kChildCountV1) {
        out.clear();
        return Fail(why, "instance_count");
    }
    for (auto& instance : out) {
        if (!BindDeterministicColumnsForAlg(
                instance, why)) {
            out.clear();
            return false;
        }
    }
    return true;
}

bool SameChildStatement(
    const ChildProofV1& child,
    const InstanceV1& instance)
{
    return child.kind == instance.kind &&
        child.endpoint == instance.endpoint &&
        child.source_statement ==
            instance.source_statement &&
        child.public_fs_seed ==
            instance.public_fs_seed;
}

} // namespace

uint256 CommitProductV1(const ProductV1& product)
{
    if (product.version != kVersionV1 ||
        product.statement_commitment.IsNull() ||
        product.digest_product_commitment.IsNull() ||
        product.digest_endpoint_binding_root.IsNull() ||
        product.header_target_pin_commitment.IsNull() ||
        product.children.size() != kChildCountV1 ||
        product.normalized_recursive_consumed ||
        product.production_authority) {
        return {};
    }
    HashWriter hash;
    hash << kProductDomain << product.version;
    hash << product.statement_commitment;
    hash << product.digest_product_commitment;
    hash << product.digest_endpoint_binding_root;
    hash << product.header_target_pin_commitment;
    hash << static_cast<uint32_t>(
        product.children.size());
    for (const auto& child : product.children) {
        if (child.source_statement.IsNull() ||
            child.public_fs_seed.IsNull() ||
            child.proof_commitment.IsNull()) {
            return {};
        }
        hash << static_cast<uint8_t>(child.kind);
        hash << static_cast<uint16_t>(
            child.endpoint);
        hash << child.source_statement;
        hash << child.public_fs_seed;
        hash << child.proof_commitment;
    }
    hash << product.normalized_recursive_consumed;
    hash << product.production_authority;
    return hash.GetHash();
}

bool ProveProductV1(
    const RCStage3SuccinctProof& statement,
    const digest::TapeChallengeContextV1& tape_context,
    const digest::ProductV1& digest_product,
    const RCStage3EpisodeHeaderTargetProduct& header_target,
    ProductV1& out,
    std::string* why)
{
    out = {};
    if (!digest::VerifyProductV1(
            statement, tape_context,
            digest_product, why) ||
        !VerifyRCStage3EpisodeHeaderTargetProduct(
            statement,
            statement.public_inputs.header_commitment,
            statement.public_inputs.n_bits,
            statement.public_inputs.target,
            header_target, why)) {
        return Fail(why, "source_products");
    }
    std::vector<InstanceV1> instances;
    if (!BuildInstances(
            statement, digest_product,
            header_target, instances, why)) {
        return false;
    }
    out.statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    out.digest_product_commitment =
        digest_product.product_commitment;
    out.digest_endpoint_binding_root =
        digest_product.endpoint_binding_root;
    out.header_target_pin_commitment =
        header_target.pin.pin_commitment;
    out.children.reserve(instances.size());
    for (const auto& instance : instances) {
        const auto proved =
            aq::AirQuotientProve<
                Fp3, aq::AirFriBackendAlg<Fp3>>(
                    instance.cs,
                    instance.columns,
                    instance.public_fs_seed);
        if (!proved.ok ||
            !proved.division_exact) {
            out = {};
            return Fail(
                why, "prove_child:" +
                    proved.note);
        }
        ChildProofV1 child;
        child.kind = instance.kind;
        child.endpoint = instance.endpoint;
        child.source_statement =
            instance.source_statement;
        child.public_fs_seed =
            instance.public_fs_seed;
        child.proof = proved.proof;
        child.proof_commitment =
            fp::ComputeNormalizedAlgAirProofCommitment(
                child.proof);
        if (child.proof_commitment.IsNull()) {
            out = {};
            return Fail(why, "child_commitment");
        }
        out.children.push_back(std::move(child));
    }
    out.product_commitment =
        CommitProductV1(out);
    if (out.product_commitment.IsNull() ||
        !VerifyProductV1(
            statement, tape_context,
            digest_product, header_target,
            out, why)) {
        out = {};
        return Fail(why, "self_verify");
    }
    return true;
}

bool VerifyProductV1(
    const RCStage3SuccinctProof& statement,
    const digest::TapeChallengeContextV1& tape_context,
    const digest::ProductV1& digest_product,
    const RCStage3EpisodeHeaderTargetProduct& header_target,
    const ProductV1& product,
    std::string* why)
{
    if (!digest::VerifyProductV1(
            statement, tape_context,
            digest_product, why) ||
        !VerifyRCStage3EpisodeHeaderTargetProduct(
            statement,
            statement.public_inputs.header_commitment,
            statement.public_inputs.n_bits,
            statement.public_inputs.target,
            header_target, why)) {
        return Fail(why, "verify_sources");
    }
    if (product.version != kVersionV1 ||
        product.statement_commitment !=
            RCStage3EpisodeStatementCommitment(statement) ||
        product.digest_product_commitment !=
            digest_product.product_commitment ||
        product.digest_endpoint_binding_root !=
            digest_product.endpoint_binding_root ||
        product.header_target_pin_commitment !=
            header_target.pin.pin_commitment ||
        product.children.size() != kChildCountV1 ||
        product.normalized_recursive_consumed ||
        product.production_authority ||
        product.product_commitment.IsNull() ||
        product.product_commitment !=
            CommitProductV1(product)) {
        return Fail(why, "product_envelope");
    }
    std::vector<InstanceV1> instances;
    if (!BuildInstances(
            statement, digest_product,
            header_target, instances, why)) {
        return false;
    }
    for (uint32_t i = 0;
         i < instances.size(); ++i) {
        const auto& child = product.children[i];
        const auto& instance = instances[i];
        const uint256 commitment =
            fp::ComputeNormalizedAlgAirProofCommitment(
                child.proof);
        std::string proof_why;
        if (!SameChildStatement(
                child, instance) ||
            commitment.IsNull() ||
            child.proof_commitment != commitment ||
            !aq::AirQuotientVerify<
                Fp3, aq::AirFriBackendAlg<Fp3>>(
                    instance.cs, child.proof,
                    instance.public_fs_seed,
                    &proof_why)) {
            return Fail(
                why, "child_" +
                    std::to_string(i) + ":" +
                    proof_why);
        }
    }
    if (why != nullptr) {
        *why =
            "stage3:episode_terminal_alg:"
            "five_public_terminal_alg_proofs_verified;"
            "normalized_parent_consumption_open";
    }
    return true;
}

bool BuildRecursiveChildInputsV1(
    const RCStage3SuccinctProof& statement,
    const digest::TapeChallengeContextV1& tape_context,
    const digest::ProductV1& digest_product,
    const RCStage3EpisodeHeaderTargetProduct& header_target,
    const ProductV1& product,
    std::vector<RecursiveChildInputV1>& out,
    std::string* why)
{
    out.clear();
    if (!VerifyProductV1(
            statement, tape_context,
            digest_product, header_target,
            product, why)) {
        return false;
    }
    std::vector<InstanceV1> instances;
    if (!BuildInstances(
            statement, digest_product,
            header_target, instances, why)) {
        return false;
    }
    out.reserve(instances.size());
    for (uint32_t i = 0;
         i < instances.size(); ++i) {
        RecursiveChildInputV1 child;
        child.kind = instances[i].kind;
        child.endpoint = instances[i].endpoint;
        child.cs = std::move(instances[i].cs);
        child.proof = product.children[i].proof;
        child.public_fs_seed =
            instances[i].public_fs_seed;
        child.source_statement =
            instances[i].source_statement;
        out.push_back(std::move(child));
    }
    if (why != nullptr) {
        *why =
            "stage3:episode_terminal_alg:"
            "five_recursive_inputs_rebuilt";
    }
    return true;
}

} // namespace matmul::v4::rc::episode_terminal_alg
