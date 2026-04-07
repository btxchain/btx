// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_WALLET_SHIELDED_PRIVACY_H
#define BITCOIN_WALLET_SHIELDED_PRIVACY_H

#include <shielded/note.h>
#include <policy/feerate.h>
#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <vector>

#include <span.h>

namespace wallet {

[[nodiscard]] bool UseShieldedPrivacyRedesignAtHeight(int32_t height);
[[nodiscard]] bool RedactSensitiveShieldedRpcFieldsAtHeight(int32_t height,
                                                            bool include_sensitive);
[[nodiscard]] bool RequireSensitiveShieldedRpcOptInAtHeight(int32_t height);
[[nodiscard]] bool AllowMixedTransparentShieldedSendAtHeight(int32_t height);
[[nodiscard]] bool AllowTransparentShieldingInDirectSendAtHeight(int32_t height);
[[nodiscard]] const char* GetPostForkCoinbaseShieldingCompatibilityMessage();

[[nodiscard]] uint64_t GetShieldedDecoyTipExclusionWindowForHeight(int32_t height);
[[nodiscard]] CAmount GetShieldedDustThresholdForHeight(const CFeeRate& relay_dust_fee,
                                                        int32_t height);
[[nodiscard]] CAmount GetShieldedMinimumChangeReserveForHeight(const CFeeRate& relay_dust_fee,
                                                               int32_t height);
[[nodiscard]] uint64_t GetShieldedMinimumPrivacyTreeSizeForHeight(size_t ring_size,
                                                                  int32_t height);
[[nodiscard]] size_t GetShieldedHistoricalRingExclusionLimit(size_t ring_size,
                                                             int32_t height);
[[nodiscard]] std::vector<uint64_t> BuildShieldedHistoricalRingExclusions(
    Span<const uint64_t> tip_exclusions,
    Span<const uint64_t> historical_exclusions,
    uint64_t tree_size);
void UpdateShieldedHistoricalRingExclusionCache(std::vector<uint64_t>& cache,
                                                Span<const uint64_t> ring_positions,
                                                Span<const size_t> real_indices,
                                                size_t limit);

[[nodiscard]] uint256 DeriveShieldedSharedRingSeed(Span<const Nullifier> nullifiers,
                                                   Span<const unsigned char> spend_key_material,
                                                   const uint256& build_nonce,
                                                   int32_t height);

[[nodiscard]] std::vector<size_t> ComputeShieldedOutputOrder(size_t recipient_count,
                                                             bool has_change,
                                                             const uint256& build_nonce,
                                                             int32_t height);

} // namespace wallet

#endif // BITCOIN_WALLET_SHIELDED_PRIVACY_H
