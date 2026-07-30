// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_sketch_cache.h>

#include <utility>

namespace matmul {

void MatMulSketchCache::Put(const uint256& block_hash, std::vector<unsigned char> sketch_bytes)
{
    LOCK(m_mutex);
    if (m_max_entries == 0) return; // cache disabled
    auto it = m_entries.find(block_hash);
    if (it != m_entries.end()) {
        it->second = std::move(sketch_bytes);
        return; // keep original FIFO position
    }
    while (m_entries.size() >= m_max_entries && !m_order.empty()) {
        m_entries.erase(m_order.front());
        m_order.pop_front();
    }
    m_entries.emplace(block_hash, std::move(sketch_bytes));
    m_order.push_back(block_hash);
}

bool MatMulSketchCache::Get(const uint256& block_hash, std::vector<unsigned char>& out) const
{
    LOCK(m_mutex);
    const auto it = m_entries.find(block_hash);
    if (it == m_entries.end()) return false;
    out = it->second;
    return true;
}

bool MatMulSketchCache::Have(const uint256& block_hash) const
{
    LOCK(m_mutex);
    return m_entries.count(block_hash) > 0;
}

bool MatMulSketchCache::GetSize(const uint256& block_hash, size_t& size_out) const
{
    LOCK(m_mutex);
    const auto it = m_entries.find(block_hash);
    if (it == m_entries.end()) return false;
    size_out = it->second.size();
    return true;
}

void MatMulSketchCache::Erase(const uint256& block_hash)
{
    LOCK(m_mutex);
    if (m_entries.erase(block_hash) == 0) return;
    for (auto it = m_order.begin(); it != m_order.end(); ++it) {
        if (*it == block_hash) {
            m_order.erase(it);
            break;
        }
    }
}

void MatMulSketchCache::SetCapacity(size_t max_entries)
{
    LOCK(m_mutex);
    m_max_entries = max_entries;
    while (m_entries.size() > m_max_entries && !m_order.empty()) {
        m_entries.erase(m_order.front());
        m_order.pop_front();
    }
    if (m_max_entries == 0) {
        m_entries.clear();
        m_order.clear();
    }
}

size_t MatMulSketchCache::Capacity() const
{
    LOCK(m_mutex);
    return m_max_entries;
}

size_t MatMulSketchCache::Size() const
{
    LOCK(m_mutex);
    return m_entries.size();
}

void MatMulSketchCache::Clear()
{
    LOCK(m_mutex);
    m_entries.clear();
    m_order.clear();
}

MatMulSketchCache& GetMatMulSketchCache()
{
    static MatMulSketchCache g_sketch_cache;
    return g_sketch_cache;
}

} // namespace matmul
