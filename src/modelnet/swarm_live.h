// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_LIVE_H
#define BTX_MODELNET_SWARM_LIVE_H

#include <util/fs.h>

#include <string>

namespace modelnet {

/**
 * Read swarm/contribution.json and publish one family per resolved lineage
 * and one cohort per lineage, checkpoint, and recipe. Checkpoint and recipe
 * stay on the published rows. A missing contribution file does nothing and
 * succeeds. An unchanged document is not rewritten. This does not start a
 * thread, take a flag, or spend.
 */
bool SwarmPublishLive(const fs::path& modeldir, std::string& err);

/**
 * Append one public body to swarm/knowledge.json under that kind's array.
 * prompt, repository, and credential are PRIVATE_DATA and write nothing.
 * The file is not a private prompt log.
 */
bool SwarmStorePublicKnowledge(const fs::path& modeldir, const std::string& kind, const std::string& body,
                               std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_LIVE_H
