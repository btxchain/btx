// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_HASHLOCK_BIND_H
#define BITCOIN_MODELNET_SWARM_HASHLOCK_BIND_H

#include <string>
#include <vector>

namespace modelnet {

/**
 * Cross-check the stored digest with SwarmBindPreimage.
 * An offer has no amount, beneficiary, objective, or route, so those
 * fields stay unset. SwarmBindPreimage checks the digest first. A
 * PREIMAGE refusal means the digest does not match and this returns
 * false. A later refusal means the digest matched and the rest of the
 * invoice is not data this plane holds.
 */
bool SwarmHashlockBindAgrees(const std::string& id,
                             const std::vector<unsigned char>& payment_hash,
                             const std::vector<unsigned char>& preimage);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_HASHLOCK_BIND_H
