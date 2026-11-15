// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_LIFECYCLE_H
#define BITCOIN_MODELNET_SWARM_LIFECYCLE_H

#include <util/fs.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

struct SwarmPeer {
    std::string id;
    std::string domain;
    bool authorized{false};
    bool available{false};
    int64_t rtt_us{0};
    int64_t bandwidth_bps{0};
};

/** Up to `near` lowest-RTT authorized peers, then up to `remote` from new domains. */
std::vector<SwarmPeer> SwarmNeighbors(const std::vector<SwarmPeer>& peers, int near = 4, int remote = 2);

struct SwarmDevice {
    bool idle_contribution{false};
    int slots{0};
    int cpu_threads{0};
    int64_t vram_bytes{0};
    int max_steps{0};
    bool battery{false};
    bool thermal_hot{false};
    bool metered{false};
    bool private_prompt_grant{false};
    bool private_data_grant{false};
    bool license_allows_training{false};
};

struct SwarmRoles {
    bool observer{true};
    bool seeder{false};
    bool evaluator{false};
    bool trainer{false};
    bool private_prompts{false};
    bool private_data{false};
    std::string automatic_spend_atoms{"0"};
};

SwarmRoles SwarmEligibleRoles(const SwarmDevice& device);

struct SwarmBudget {
    int active_workers{0};
    int cpu_threads{0};
    int64_t vram_bytes{0};
    int max_steps{0};
    bool drained{true};
    std::string code{"IDLE_OFF"};
};

/** Caps a contribution request. Idle, battery, thermal, or metered drains to zero. */
SwarmBudget SwarmGovern(const SwarmDevice& device, int requested_workers);

/**
 * Device file, roles, and budget from one SwarmGovern call.
 * hardware_threads is the host capability. It is not a grant.
 * A missing device file allows one idle slot and no CPU, VRAM, or training.
 * An empty modeldir uses that missing-file snapshot.
 */
struct SwarmGovernSnapshot {
    SwarmDevice device;
    SwarmRoles roles;
    SwarmBudget budget;
    int hardware_threads{0};
};

bool SwarmLoadGoverned(const fs::path& modeldir, SwarmGovernSnapshot& out, std::string& err);

struct SwarmJoin {
    bool ok{false};
    std::string code;
    std::string artifact_id;
    std::string model_id;
    std::string checkpoint_id;
    std::string lineage_id;
    std::string assurance;
    std::string visibility;
};

/**
 * Join a verified artifact. Without a mapping the lineage is provisional and private.
 * `mapped_visibility` is used only when `mapped_lineage` is a fixed id.
 */
SwarmJoin SwarmJoinLineage(const std::string& artifact_id, const std::string& model_id,
                           const std::string& checkpoint_id, const std::string& mapped_lineage,
                           const std::string& mapped_visibility);

/** An import URL is an origin. It is not a lineage id. */
bool SwarmOriginIsLineage(const std::string& origin_url);

enum class SwarmTimescale { Immediate, Short, Medium, Long };

SwarmTimescale SwarmClassifyTimescale(const std::string& kind);

/** Read optional peers.json and device.json. Write swarm/mesh-state.json. */
bool SwarmRefreshLocalMesh(const fs::path& modeldir, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_LIFECYCLE_H
