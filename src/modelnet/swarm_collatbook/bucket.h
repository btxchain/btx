// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_COLLATBOOK_BUCKET_H
#define BITCOIN_MODELNET_SWARM_COLLATBOOK_BUCKET_H

#include <string>

namespace modelnet {

/**
 * True only for the buckets "escrow" and "collateral".
 * Any other string, including empty, is BUCKET.
 * This does not store a reservation and does not move atoms.
 */
bool SwarmCollatAcceptBucket(const std::string& bucket, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_COLLATBOOK_BUCKET_H
