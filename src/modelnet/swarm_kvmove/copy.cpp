// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvmove/copy.h>

#include <modelnet/swarm_kvmove/bytes.h>
#include <modelnet/swarm_kvmove/codes.h>
#include <modelnet/swarm_kvmove/engine.h>
#include <modelnet/swarm_kvmove/slot.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

bool SwarmKvMoveApply(SwarmKvMoveBook& book, const std::string& src, const std::string& dst, const std::string& engine,
                      std::int64_t& bytes_copied, std::string& err)
{
    bytes_copied = 0;
    SwarmKvMoveSlot* src_row = book.Find(src);
    SwarmKvMoveSlot* dst_row = book.Find(dst);
    if (src_row == nullptr || dst_row == nullptr) {
        err = kSwarmKvMovePage;
        return false;
    }

    const SwarmKvMoveEngineKind kind = SwarmKvMoveClassifyEngine(engine);
    if (kind == SwarmKvMoveEngineKind::Absent) {
        err = kSwarmKvMoveEngineAbsent;
        return false;
    }
    if (kind != SwarmKvMoveEngineKind::Memory) {
        err = kSwarmKvMoveEngine;
        return false;
    }

    // A 4bit slot is family-only, so it is not in KV. Fingerprints that differ,
    // or a dst that is not in KV, are not a copy. Do not promote a 4bit dst.
    if (!src_row->in_kv || !dst_row->in_kv || src_row->fingerprint != dst_row->fingerprint) {
        err = kSwarmKvMoveNotCompat;
        return false;
    }

    // Copy into a fresh buffer first so a move onto the same slot is well defined.
    std::vector<unsigned char> copied = SwarmKvMoveCopyBytes(src_row->body);
    if (copied.empty()) {
        err = kSwarmKvMoveNotCompat;
        return false;
    }
    const std::int64_t n = static_cast<std::int64_t>(copied.size());
    dst_row->body.swap(copied);
    bytes_copied = n;
    err.clear();
    return true;
}

} // namespace modelnet
