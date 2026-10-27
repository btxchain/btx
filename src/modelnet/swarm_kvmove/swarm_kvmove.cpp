// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvmove/swarm_kvmove.h>

#include <modelnet/swarm_kvmove/copy.h>
#include <modelnet/swarm_kvmove/slot.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

bool SwarmKvMove::Put(const std::string& slot, const std::string& fingerprint, const std::string& quantization,
                      const std::vector<unsigned char>& body, std::string& err)
{
    return m_book.Put(slot, fingerprint, quantization, body, err);
}

bool SwarmKvMove::Move(const std::string& src, const std::string& dst, const std::string& engine, std::string& err)
{
    std::int64_t added = 0;
    if (!SwarmKvMoveApply(m_book, src, dst, engine, added, err)) {
        return false;
    }
    m_bytes_moved += added;
    return true;
}

bool SwarmKvMove::in_family(const std::string& slot) const
{
    return m_book.in_family(slot);
}

bool SwarmKvMove::in_kv(const std::string& slot) const
{
    return m_book.in_kv(slot);
}

std::size_t SwarmKvMove::body_size(const std::string& slot) const
{
    return m_book.body_size(slot);
}

const std::vector<unsigned char>& SwarmKvMove::body(const std::string& slot) const
{
    return m_book.body(slot);
}

std::int64_t SwarmKvMove::bytes_moved() const
{
    return m_bytes_moved;
}

bool SwarmKvMove::launched() const
{
    return false;
}

bool SwarmKvMove::gpu() const
{
    return false;
}

} // namespace modelnet
