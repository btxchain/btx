// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_TEST_UTIL_SHIELDED_ACCOUNT_REGISTRY_TEST_UTIL_H
#define BTX_TEST_UTIL_SHIELDED_ACCOUNT_REGISTRY_TEST_UTIL_H

#include <shielded/account_registry.h>
#include <shielded/v2_send.h>
#include <span.h>

#include <optional>
#include <utility>
#include <vector>

namespace test::shielded {

[[nodiscard]] inline uint256 EffectiveNoteCommitment(const ::shielded::v2::V2SendSpendInput& spend_input)
{
    return spend_input.note_commitment.IsNull() ? spend_input.note.GetCommitment()
                                                : spend_input.note_commitment;
}

[[nodiscard]] inline std::optional<uint256> ComputeAccountLeafCommitment(
    const ::shielded::v2::V2SendSpendInput& spend_input)
{
    if (!spend_input.account_leaf_hint.has_value() || !spend_input.account_leaf_hint->IsValid()) {
        return std::nullopt;
    }
    return ::shielded::registry::ComputeAccountLeafCommitmentFromNote(
        spend_input.note,
        EffectiveNoteCommitment(spend_input),
        *spend_input.account_leaf_hint);
}

[[nodiscard]] inline std::optional<::shielded::registry::ShieldedAccountLeaf> BuildAccountLeaf(
    const ::shielded::v2::V2SendSpendInput& spend_input)
{
    if (!spend_input.account_leaf_hint.has_value() || !spend_input.account_leaf_hint->IsValid()) {
        return std::nullopt;
    }
    return ::shielded::registry::BuildAccountLeafFromNote(spend_input.note,
                                                          EffectiveNoteCommitment(spend_input),
                                                          *spend_input.account_leaf_hint);
}

[[nodiscard]] inline std::optional<::shielded::registry::ShieldedAccountLeaf> BuildDirectAccountLeaf(
    const uint256& note_commitment,
    const smile2::CompactPublicAccount& account)
{
    return ::shielded::registry::BuildShieldedAccountLeaf(account,
                                                          note_commitment,
                                                          ::shielded::registry::AccountDomain::DIRECT_SEND);
}

[[nodiscard]] inline std::optional<std::pair<uint256, ::shielded::registry::ShieldedAccountRegistrySpendWitness>>
MakeSingleLeafRegistryWitness(const ::shielded::registry::ShieldedAccountLeaf& account_leaf)
{
    ::shielded::registry::ShieldedAccountRegistryState registry;
    if (!registry.Append(Span<const ::shielded::registry::ShieldedAccountLeaf>{&account_leaf, 1})) {
        return std::nullopt;
    }
    auto proof = registry.BuildSpendWitness(/*leaf_index=*/0);
    if (!proof.has_value()) {
        return std::nullopt;
    }
    return std::make_pair(registry.Root(), std::move(*proof));
}

[[nodiscard]] inline std::optional<std::pair<uint256, ::shielded::registry::ShieldedAccountRegistrySpendWitness>>
MakeSingleLeafRegistryWitness(const uint256& note_commitment, const smile2::CompactPublicAccount& account)
{
    const auto account_leaf = BuildDirectAccountLeaf(note_commitment, account);
    if (!account_leaf.has_value()) {
        return std::nullopt;
    }
    return MakeSingleLeafRegistryWitness(*account_leaf);
}

[[nodiscard]] inline bool AttachAccountRegistryWitness(
    ::shielded::v2::V2SendSpendInput& spend_input)
{
    const auto account_leaf = BuildAccountLeaf(spend_input);
    if (!account_leaf.has_value()) {
        return false;
    }
    const auto witness = MakeSingleLeafRegistryWitness(*account_leaf);
    if (!witness.has_value()) {
        return false;
    }
    spend_input.account_registry_anchor = witness->first;
    spend_input.account_registry_proof = witness->second;
    return true;
}

[[nodiscard]] inline bool AttachAccountRegistryWitnesses(
    std::vector<::shielded::v2::V2SendSpendInput>& spend_inputs)
{
    if (spend_inputs.empty()) {
        return false;
    }

    std::vector<::shielded::registry::ShieldedAccountLeaf> account_leaves;
    account_leaves.reserve(spend_inputs.size());
    for (const auto& spend_input : spend_inputs) {
        const auto account_leaf = BuildAccountLeaf(spend_input);
        if (!account_leaf.has_value()) {
            return false;
        }
        account_leaves.push_back(*account_leaf);
    }

    ::shielded::registry::ShieldedAccountRegistryState registry;
    if (!registry.Append(Span<const ::shielded::registry::ShieldedAccountLeaf>{account_leaves.data(),
                                                                               account_leaves.size()})) {
        return false;
    }

    const uint256 root = registry.Root();
    if (root.IsNull()) {
        return false;
    }
    for (size_t i = 0; i < spend_inputs.size(); ++i) {
        auto proof = registry.BuildSpendWitness(i);
        if (!proof.has_value()) {
            return false;
        }
        spend_inputs[i].account_registry_anchor = root;
        spend_inputs[i].account_registry_proof = std::move(*proof);
    }
    return true;
}

} // namespace test::shielded

#endif // BTX_TEST_UTIL_SHIELDED_ACCOUNT_REGISTRY_TEST_UTIL_H
