// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_CYCLE_H
#define BTX_MODELNET_SWARM_CYCLE_H

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/** An expired lease or a mismatched checkpoint or recipe admits nobody. */
bool SwarmAdmitCohortMember(int64_t now_ms, int64_t lease_until_ms, bool checkpoint_match, bool recipe_match, std::string& err);

struct SwarmChildManifest {
    std::string digest;
    bool verified{false};
};

struct SwarmManifestRoot {
    std::vector<SwarmChildManifest> children;
    bool usable{false};
    bool bytes_streamed{false};
};

/**
 * Usable only when every child digest is in the verified set. This does not
 * read or stream a checkpoint.
 */
bool SwarmBindManifestRoot(SwarmManifestRoot& root, const std::vector<std::string>& verified, std::string& err);

/** A withdrawn or missing dataset grant does not start training. */
bool SwarmStartTraining(bool dataset_authorized, bool withdrawn, std::string& err);

/**
 * Local cycle record. A qualified graduate becomes the next parent.
 * An unqualified candidate does not. This function does not train.
 */
struct SwarmCycle {
    std::string parent_id;
    int cycle{0};
};

bool SwarmAdvanceCycle(SwarmCycle& cycle, const std::string& graduated_id, bool qualified, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_CYCLE_H
