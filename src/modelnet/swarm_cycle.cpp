// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cycle.h>

#include <algorithm>

namespace modelnet {

bool SwarmAdmitCohortMember(int64_t now_ms, int64_t lease_until_ms, bool checkpoint_match, bool recipe_match, std::string& err)
{
    if (lease_until_ms <= now_ms) {
        err = "LEASE_EXPIRED";
        return false;
    }
    if (!checkpoint_match || !recipe_match) {
        err = "INCOMPATIBLE";
        return false;
    }
    err.clear();
    return true;
}

bool SwarmBindManifestRoot(SwarmManifestRoot& root, const std::vector<std::string>& verified, std::string& err)
{
    root.bytes_streamed = false;
    if (root.children.empty()) {
        root.usable = false;
        err = "MANIFEST";
        return false;
    }
    bool all = true;
    for (SwarmChildManifest& child : root.children) {
        const bool known = std::find(verified.begin(), verified.end(), child.digest) != verified.end();
        child.verified = known && !child.digest.empty();
        if (!child.verified) all = false;
    }
    root.usable = all;
    if (!all) {
        err = "MANIFEST";
        return false;
    }
    err.clear();
    return true;
}

bool SwarmStartTraining(bool dataset_authorized, bool withdrawn, std::string& err)
{
    if (withdrawn || !dataset_authorized) {
        err = "DATASET";
        return false;
    }
    err.clear();
    return true;
}

bool SwarmAdvanceCycle(SwarmCycle& cycle, const std::string& graduated_id, bool qualified, std::string& err)
{
    if (cycle.parent_id.empty() || graduated_id.empty()) {
        err = "CYCLE";
        return false;
    }
    if (!qualified) {
        err = "UNQUALIFIED";
        return false;
    }
    cycle.parent_id = graduated_id;
    if (cycle.cycle < 1000000) ++cycle.cycle;
    err.clear();
    return true;
}

} // namespace modelnet
