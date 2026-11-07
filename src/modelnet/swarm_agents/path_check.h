// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_AGENTS_PATH_CHECK_H
#define BTX_MODELNET_SWARM_AGENTS_PATH_CHECK_H

#include <string>

namespace modelnet {

/**
 * True when path is inside sandbox_root.
 * The root must be non-empty and end with '/'. A path that contains
 * ".." or that does not begin with that root is outside.
 * This check does not open the path.
 */
bool SwarmAgentPathInside(const std::string& sandbox_root, const std::string& path);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_AGENTS_PATH_CHECK_H
