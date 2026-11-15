// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_chunk/nif_chunk.h>

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <limits>
#include <string>

namespace modelnet {

namespace {

/**
 * True when total + bytes fits in int64.
 * bytes is at least 1 on the Accept path. total is the running sum and
 * stays non-negative, so max - total does not overflow.
 */
bool SumFits(int64_t total, int64_t bytes)
{
    if (total < static_cast<int64_t>(0) || bytes < static_cast<int64_t>(1)) {
        return false;
    }
    return bytes <= std::numeric_limits<int64_t>::max() - total;
}

} // namespace

const int64_t* NifChunk::Find(const std::string& chunk_id) const
{
    const auto it = m_chunks.find(chunk_id);
    if (it == m_chunks.end()) {
        return nullptr;
    }
    return &it->second;
}

bool NifChunk::chunk_stored(const std::string& chunk_id) const
{
    return Find(chunk_id) != nullptr;
}

int64_t NifChunk::stored_bytes(const std::string& chunk_id) const
{
    const int64_t* body = Find(chunk_id);
    if (body == nullptr) {
        return static_cast<int64_t>(0);
    }
    return *body;
}

bool NifChunk::Bind(const std::string& state, std::string& err)
{
    if (state.empty()) {
        err = NIF_CHUNK_STATE;
        return false;
    }
    m_bound = true;
    m_state = state;
    err.clear();
    return true;
}

bool NifChunk::Accept(const std::string& chunk_id, const std::string& state, int64_t bytes, std::string& err)
{
    if (!m_bound) {
        err = NIF_CHUNK_STATE;
        return false;
    }
    if (chunk_id.empty()) {
        err = NIF_CHUNK_CHUNK;
        return false;
    }
    if (bytes < static_cast<int64_t>(1)) {
        err = NIF_CHUNK_BYTES;
        return false;
    }
    // Replay is decided before the state comparison. The stored body stays.
    if (Find(chunk_id) != nullptr) {
        err = NIFDT_REPLAY;
        return false;
    }
    if (state != m_state) {
        err = NIF_CHUNK_STALE;
        return false;
    }
    if (!SumFits(m_accepted, bytes)) {
        err = NIF_CHUNK_OVERFLOW;
        return false;
    }
    m_chunks.emplace(chunk_id, bytes);
    m_accepted += bytes;
    err.clear();
    return true;
}

bool NifChunk::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
