// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SANDBOXGATE_PREFIX_H
#define BITCOIN_MODELNET_SWARM_SANDBOXGATE_PREFIX_H

#include <string>

namespace modelnet {

/**
 * Bytewise strict prefix.
 * prefix matches path when path is longer than prefix and the leading bytes
 * are equal. "models/" matches "models/a" and does not match "models".
 * Equality is not a strict prefix. Nothing is normalized and no separator
 * is inserted.
 */
bool SwarmSandboxGateStrictPrefix(const std::string& prefix, const std::string& path);

/**
 * True when path begins with the bytes "private/".
 * A stored grant of that prefix does not make the path allowable.
 */
bool SwarmSandboxGatePrivatePath(const std::string& path);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SANDBOXGATE_PREFIX_H
