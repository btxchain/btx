// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_ADMIT_PATHS_ADMIT_PATHS_H
#define BITCOIN_MODELNET_ADMIT_PATHS_ADMIT_PATHS_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Closed gate for the admission path names hostmodel, importmodel, seedmodel,
 * watched, demand-seed, peer-follow, cloud-mirror, encrypted-release,
 * bundle-import, package-install, hosted-gateway, direct-api, capability,
 * local-generate, and model-rollout.
 *
 * Note: an empty path returns PATH and stores nothing. An unknown path returns
 * PATH and stores nothing. A known path records the name and returns true.
 * A second note of a recorded name returns NIFDT_REPLAY.
 *
 * Wired stays false for every path. Serve returns false with UNWIRED.
 * Quarantine records that path, and Serve still returns false with QUARANTINE.
 * Release returns NIFDT_UNQUALIFIED. qualified(), release_qualified(), and
 * hardware_qualified() stay false. hosts() and physical_hosts() stay 1.
 * bytes_moved() stays 0. Spend returns NIFDT_AUTOMATIC_SPEND.
 * Vendor and Gpu return NIFDT_ENGINE_ABSENT. launched(), gpu(), and
 * broadcast() stay false.
 * This class opens no socket, starts no process, and moves no bytes.
 */
class AdmitPaths {
public:
    bool Note(const std::string& path, std::string& err);
    bool Wired(const std::string& path) const;
    bool Serve(const std::string& path, std::string& err);
    bool Quarantine(const std::string& path, std::string& err);
    bool Release(std::string& err);
    bool Gpu(std::string& err);
    bool Vendor(std::string& err);
    bool Spend(std::string& err);

    bool noted(const std::string& path) const;
    bool quarantined(const std::string& path) const;

    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    std::vector<std::string> m_noted;
    std::vector<std::string> m_quarantine;
};

} // namespace modelnet

#endif
