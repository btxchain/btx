// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_SHIELDED_V2_EGRESS_H
#define BTX_SHIELDED_V2_EGRESS_H

#include <consensus/amount.h>
#include <consensus/params.h>
#include <crypto/ml_kem.h>
#include <primitives/transaction.h>
#include <shielded/bridge.h>
#include <shielded/v2_bundle.h>
#include <shielded/v2_proof.h>

#include <optional>
#include <limits>
#include <string>
#include <vector>

namespace shielded::v2 {

struct V2EgressRecipient
{
    uint256 recipient_pk_hash;
    mlkem::PublicKey recipient_kem_pk{};
    CAmount amount{0};

    [[nodiscard]] bool IsValid() const;
};

struct V2EgressStatementTemplate
{
    BridgePlanIds ids;
    uint256 domain_id;
    uint32_t source_epoch{0};
    uint256 data_root;
    BridgeVerifierSetCommitment verifier_set;
    BridgeProofPolicyCommitment proof_policy;

    [[nodiscard]] bool IsValid() const;
};

[[nodiscard]] uint256 ComputeV2EgressOutputBindingDigest(const BridgeBatchStatement& statement);
[[nodiscard]] std::optional<std::vector<OutputDescription>> BuildDeterministicEgressOutputs(
    const BridgeBatchStatement& statement,
    Span<const V2EgressRecipient> recipients,
    std::string& reject_reason);

[[nodiscard]] std::optional<BridgeBatchStatement> BuildV2EgressStatement(
    const V2EgressStatementTemplate& statement_template,
    Span<const V2EgressRecipient> recipients,
    std::string& reject_reason);

struct V2EgressBuildInput
{
    BridgeBatchStatement statement;
    std::vector<BridgeProofDescriptor> proof_descriptors;
    BridgeProofDescriptor imported_descriptor;
    std::vector<BridgeBatchReceipt> signed_receipts;
    std::vector<BridgeVerifierSetProof> signed_receipt_proofs;
    std::vector<BridgeProofReceipt> proof_receipts;
    BridgeProofReceipt imported_receipt;
    std::vector<OutputDescription> outputs;
    std::vector<uint32_t> output_chunk_sizes;
    bool allow_transparent_unwrap{false};

    [[nodiscard]] bool IsValid() const;
};

struct V2EgressBuildResult
{
    CMutableTransaction tx;
    proof::SettlementWitness witness;

    [[nodiscard]] bool IsValid() const;
};

[[nodiscard]] std::optional<V2EgressBuildResult> BuildV2EgressBatchTransaction(
    const CMutableTransaction& tx_template,
    const V2EgressBuildInput& input,
    std::string& reject_reason,
    const Consensus::Params* consensus = nullptr,
    int32_t validation_height = std::numeric_limits<int32_t>::max());

} // namespace shielded::v2

#endif // BTX_SHIELDED_V2_EGRESS_H
