// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_KVMOVE_COPY_H
#define BITCOIN_MODELNET_SWARM_KVMOVE_COPY_H

#include <modelnet/swarm_kvmove/slot.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Copy a resident page from src onto dst when engine is "memory".
 * Unknown src or dst is PAGE and copies nothing.
 * nixl, mooncake, and rdma are ENGINE_ABSENT and copy nothing.
 * Any other engine name is ENGINE and copies nothing.
 * "memory" copies only when both slots are in KV and the fingerprints are equal.
 * Otherwise the code is NOT_COMPAT and the dst body stays.
 * On success, dst holds a new byte copy of the src body and bytes_copied is
 * that size. On failure bytes_copied is 0 and the book is unchanged.
 */
bool SwarmKvMoveApply(SwarmKvMoveBook& book, const std::string& src, const std::string& dst, const std::string& engine,
                      std::int64_t& bytes_copied, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_KVMOVE_COPY_H
