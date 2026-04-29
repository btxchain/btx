// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_SHIELDED_VALIDATION_H
#define BTX_SHIELDED_VALIDATION_H

#include <consensus/params.h>
#include <primitives/transaction.h>
#include <shielded/bundle.h>
#include <shielded/merkle_tree.h>
#include <shielded/nullifier.h>

#include <cstddef>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

class Chainstate;
class CBlockIndex;

namespace shielded::ringct {
struct MatRiCTProof;
} // namespace shielded::ringct

namespace shielded::audit {

struct ProofAuditEntry
{
    uint256 block_hash;
    uint256 txid;
    int32_t height{-1};
    std::string family;
    std::string proof_kind;
    uint64_t verify_units{0};
    bool verified{false};
    std::string reject_reason;
};

struct ProofAuditArchive
{
    std::vector<ProofAuditEntry> entries;
    uint64_t verified_count{0};
    uint64_t failed_count{0};
};

} // namespace shielded::audit

[[nodiscard]] const char* ShieldedV2FamilyName(shielded::v2::TransactionFamily family);

[[nodiscard]] std::string DescribeShieldedV2Context(const CShieldedBundle& bundle);

void LogShieldedV2ContextReject(std::string_view gate, const CShieldedBundle& bundle);

/**
 * Extract deterministic nullifiers bound to ring key images encoded in a
 * serialized MatRiCT proof.
 * Returns std::nullopt and sets reject_reason on failure.
 */
[[nodiscard]] std::optional<std::shared_ptr<const shielded::ringct::MatRiCTProof>> ParseShieldedSpendAuthProof(
    const CShieldedBundle& bundle,
    std::string& reject_reason);

/**
 * Extract deterministic nullifiers from a decoded MatRiCT proof.
 * Returns std::nullopt and sets reject_reason on failure.
 */
[[nodiscard]] std::optional<std::vector<Nullifier>> ExtractShieldedProofBoundNullifiers(
    const shielded::ringct::MatRiCTProof& proof,
    size_t expected_input_count,
    std::string& reject_reason);

/**
 * Decode proof and extract deterministic nullifiers bound to ring key images.
 * Returns std::nullopt and sets reject_reason on failure.
 */
[[nodiscard]] std::optional<std::vector<Nullifier>> ExtractShieldedProofBoundNullifiers(
    const CShieldedBundle& bundle,
    std::string& reject_reason,
    bool reject_rice_codec = false);

/**
 * Extract settlement-anchor digests created by a shielded_v2 settlement-anchor
 * bundle. Returns std::nullopt and sets reject_reason on failure.
 */
[[nodiscard]] std::optional<std::vector<uint256>> ExtractCreatedShieldedSettlementAnchors(
    const CTransaction& tx,
    std::string& reject_reason);

/**
 * Extract netting-manifest ids created by a shielded_v2 rebalance bundle.
 * Returns std::nullopt and sets reject_reason on failure.
 */
[[nodiscard]] std::optional<std::vector<uint256>> ExtractCreatedShieldedNettingManifests(
    const CTransaction& tx,
    std::string& reject_reason);

/**
 * Extract netting-manifest state created by a shielded_v2 rebalance bundle.
 * Returns std::nullopt and sets reject_reason on failure.
 */
[[nodiscard]] std::optional<std::vector<ConfirmedNettingManifestState>> ExtractCreatedShieldedNettingManifestStates(
    const CTransaction& tx,
    int32_t created_height,
    std::string& reject_reason);

[[nodiscard]] bool BuildShieldedProofAuditArchive(const Chainstate& chainstate,
                                                  const CBlockIndex* tip,
                                                  shielded::audit::ProofAuditArchive& archive,
                                                  std::string& error);

/**
 * Shielded bundle proof check queued in parallel similarly to CScriptCheck.
 * Returns std::nullopt on success or a reject reason string on failure.
 */
class CShieldedProofCheck
{
public:
    CShieldedProofCheck(const CTransaction& tx,
                        std::shared_ptr<const shielded::ShieldedMerkleTree> tree_snapshot,
                        std::shared_ptr<const std::map<uint256, smile2::CompactPublicAccount>> smile_public_accounts = {},
                        std::shared_ptr<const std::map<uint256, uint256>> account_leaf_commitments = {},
                        std::shared_ptr<const shielded::ringct::MatRiCTProof> parsed_proof = {});
    CShieldedProofCheck(const CTransaction& tx,
                        const Consensus::Params& consensus,
                        int32_t validation_height,
                        std::shared_ptr<const shielded::ShieldedMerkleTree> tree_snapshot,
                        std::shared_ptr<const std::map<uint256, smile2::CompactPublicAccount>> smile_public_accounts = {},
                        std::shared_ptr<const std::map<uint256, uint256>> account_leaf_commitments = {},
                        std::shared_ptr<const shielded::ringct::MatRiCTProof> parsed_proof = {});
    CShieldedProofCheck(const CShieldedProofCheck&) = delete;
    CShieldedProofCheck& operator=(const CShieldedProofCheck&) = delete;
    CShieldedProofCheck(CShieldedProofCheck&&) = default;
    CShieldedProofCheck& operator=(CShieldedProofCheck&&) = default;

    [[nodiscard]] std::optional<std::string> operator()() const;

    void swap(CShieldedProofCheck& other) noexcept;

private:
    CTransactionRef m_tx;
    const Consensus::Params* m_consensus{nullptr};
    int32_t m_validation_height{std::numeric_limits<int32_t>::max()};
    std::shared_ptr<const shielded::ShieldedMerkleTree> m_tree_snapshot;
    std::shared_ptr<const std::map<uint256, smile2::CompactPublicAccount>> m_smile_public_accounts;
    std::shared_ptr<const std::map<uint256, uint256>> m_account_leaf_commitments;
    std::shared_ptr<const shielded::ringct::MatRiCTProof> m_parsed_proof;
};

/**
 * Spend authorization check for shielded spends.
 * Returns std::nullopt on success or a reject reason string on failure.
 */
class CShieldedSpendAuthCheck
{
public:
    CShieldedSpendAuthCheck() = default;
    CShieldedSpendAuthCheck(const CTransaction& tx,
                            size_t spend_index,
                            std::optional<Nullifier> proof_bound_nullifier = std::nullopt);
    CShieldedSpendAuthCheck(const CShieldedSpendAuthCheck&) = delete;
    CShieldedSpendAuthCheck& operator=(const CShieldedSpendAuthCheck&) = delete;
    CShieldedSpendAuthCheck(CShieldedSpendAuthCheck&&) = default;
    CShieldedSpendAuthCheck& operator=(CShieldedSpendAuthCheck&&) = default;

    [[nodiscard]] std::optional<std::string> operator()() const;

    void swap(CShieldedSpendAuthCheck& other) noexcept;

private:
    CTransactionRef m_tx;
    size_t m_spend_index{0};
    std::optional<Nullifier> m_proof_bound_nullifier;
};

static_assert(std::is_nothrow_move_constructible_v<CShieldedProofCheck>);
static_assert(std::is_nothrow_move_assignable_v<CShieldedProofCheck>);
static_assert(std::is_nothrow_move_constructible_v<CShieldedSpendAuthCheck>);
static_assert(std::is_nothrow_move_assignable_v<CShieldedSpendAuthCheck>);

#endif // BTX_SHIELDED_VALIDATION_H
