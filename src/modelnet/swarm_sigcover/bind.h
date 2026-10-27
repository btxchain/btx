// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SIGCOVER_BIND_H
#define BITCOIN_MODELNET_SWARM_SIGCOVER_BIND_H

#include <modelnet/swarm_sigcover/types.h>

#include <string>

namespace modelnet {

/**
 * Refuse every key, including an empty key.
 * The row pointer is read only. No key is copied onto the row.
 * A covered row stays covered. signed_ok stays false on the book.
 */
bool SwarmSigCoverRefuseBind(const SwarmSigCoverRecord* row, const std::string& key, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SIGCOVER_BIND_H
