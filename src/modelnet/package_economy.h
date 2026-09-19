// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_PACKAGE_ECONOMY_H
#define BITCOIN_MODELNET_PACKAGE_ECONOMY_H

#include <univalue.h>

#include <cstdint>
#include <string>

namespace modelnet {

/** Cached reward/funding labels are observations, never package-core authority. */
struct PackageRewardPreview {
    bool cached_stale{false};
    bool preview_is_observation{true};
    bool controls_spending{false};
    std::string cached_state;
    std::string current_state;
    int64_t automatic_spend_atoms{0};
    UniValue json;
};

bool EvaluatePackageRewardPreview(const UniValue& core, const UniValue& cached_observation,
                                  const UniValue& local_chain, PackageRewardPreview& out,
                                  std::string& err_code, std::string& err);

/**
 * FREE_ONLY acquisition of a model awaiting paid public release.
 * A timer expiry never converts this path to paid. automatic_spend_atoms stays 0.
 */
bool PlanFreeOnlyAwaitingRelease(const UniValue& core, int64_t elapsed_ms, UniValue& out,
                                 std::string& err_code, std::string& err);

int64_t PackageAutomaticSpendAtoms();

/**
 * True when a channel statement would rewrite a signed package core's static
 * model commitments in place. A pointer at a different package_core_id is not
 * a mutation of the already-pinned core.
 */
bool ChannelMutatesStaticCommitments(const UniValue& pinned_core, const UniValue& statement);

/** Credential sentinels: refuse secret-bearing keys (PublicExportKeyForbidden + HF/S3/wallet/distribution). */
bool PackagePortableKeysAllowed(const UniValue& value, std::string& err);

/** True if any string embeds a presigned/capability URL. */
bool PackageContainsPresignedCapability(const UniValue& value);

/** Writer lint: secret keys and embedded presigned capabilities are rejected. */
bool LintPackagePortable(const UniValue& value, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_PACKAGE_ECONOMY_H
