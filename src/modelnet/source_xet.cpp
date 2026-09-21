// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/source_xet.h>

#include <algorithm>
#include <cstring>

namespace modelnet {

XetByteSource::XetByteSource(std::string locator, std::string cas_root)
    : m_locator(std::move(locator)), m_cas_root(std::move(cas_root))
{
}

void XetByteSource::SetChunkMap(XetChunkMap chunks, std::vector<std::string> order)
{
    m_chunks = std::move(chunks);
    m_order = std::move(order);
    m_size = 0;
    m_pinned = false;
}

bool XetByteSource::Pin(std::string& err)
{
    if (m_cas_root.empty()) {
        err = "xet cas root";
        return false;
    }
    if (m_order.empty()) {
        err = "empty xet reconstruction";
        return false;
    }
    uint64_t size = 0;
    for (const auto& id : m_order) {
        const auto it = m_chunks.find(id);
        if (it == m_chunks.end()) {
            err = "missing xet chunk";
            return false;
        }
        if (size + it->second.size() < size) {
            err = "overflow";
            return false;
        }
        size += it->second.size();
    }
    m_size = size;
    m_pinned = true;
    return true;
}

bool XetByteSource::Read(const ReadExtent& extent, std::vector<unsigned char>& out, uint64_t budget_bytes,
                         std::string& err)
{
    out.clear();
    if (!m_pinned && !Pin(err)) return false;
    if (extent.length > budget_bytes) {
        err = "credit exhausted";
        return false;
    }
    if (extent.offset > m_size || extent.length > m_size - extent.offset) {
        err = "extent";
        return false;
    }
    out.assign(extent.length, 0);
    uint64_t pos = 0;
    const uint64_t end = extent.offset + extent.length;
    for (const auto& id : m_order) {
        const auto& chunk = m_chunks.at(id);
        const uint64_t a = std::max(pos, extent.offset);
        const uint64_t b = std::min(pos + static_cast<uint64_t>(chunk.size()), end);
        if (a < b) {
            const uint64_t n = b - a;
            std::memcpy(out.data() + (a - extent.offset), chunk.data() + (a - pos), static_cast<size_t>(n));
        }
        pos += chunk.size();
    }
    return true;
}

} // namespace modelnet
