// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_PACKAGE_INSTALL_H
#define BITCOIN_MODELNET_PACKAGE_INSTALL_H

#include <modelnet/types.h>
#include <univalue.h>

#include <string>

namespace modelnet {

struct InstallPlan {
    std::string plan_id_hex;
    Digest48 package_core_id{};
    std::string distribution_id;
    std::string release_version;
    std::string platform;
    std::string artifact_sha384_hex;
    bool trust_required{true};
    UniValue json;
};

/**
 * Never treats package-embedded hashes as software-distributor trust.
 * Independent catalogue + user policy only. Does not install.
 */
bool PlanBtxClientInstall(const UniValue& core, const UniValue& trusted_catalogue,
                           const UniValue& user_policy, InstallPlan& out, std::string& err_code,
                           std::string& err);

/** Traversal, symlink, and duplicate executable names are never staged. */
bool InstallArchiveEntryAllowed(const std::string& rel_path, bool is_symlink, bool is_duplicate_name,
                                std::string& err);
/**
 * Interrupted install: unverified download/promote is purged; a verified
 * stage may resume. Does not mutate a previously installed client.
 */
bool InstallStagingResumeOrPurge(const std::string& phase, bool stage_verified, bool& resume, bool& purge,
                                  std::string& err_code);

} // namespace modelnet

#endif // BITCOIN_MODELNET_PACKAGE_INSTALL_H
