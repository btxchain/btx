// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_BLOCK_CHUNK_TRANSPORT_H
#define BITCOIN_NODE_BLOCK_CHUNK_TRANSPORT_H

#include <consensus/consensus.h>
#include <hash.h>
#include <serialize.h>
#include <span.h>
#include <uint256.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <ios>
#include <limits>
#include <string>
#include <utility>
#include <vector>

namespace node {

/** Versioned, explicitly negotiated full-block chunk transport. This is a
 * relay encoding only; it does not alter block serialization or validity. */
static constexpr uint64_t BLOCK_CHUNK_RELAY_VERSION{1};
static constexpr uint32_t BLOCK_CHUNK_SIZE{1U << 20}; // 1 MiB
static constexpr uint64_t BLOCK_CHUNK_MAX_TOTAL_BYTES{MAX_BLOCK_SERIALIZED_SIZE};
static constexpr uint32_t BLOCK_CHUNK_MAX_COUNT{
    static_cast<uint32_t>(1 + (BLOCK_CHUNK_MAX_TOTAL_BYTES - 1) /
                                  BLOCK_CHUNK_SIZE)};
static constexpr uint64_t BLOCK_CHUNK_GLOBAL_MEMORY_BYTES{64ULL << 20};
static constexpr auto BLOCK_CHUNK_STALL_TIMEOUT{std::chrono::minutes{2}};
/** Absolute lifetime prevents a slow-loris source from refreshing the idle
 * timeout with one chunk while retaining a max-block memory reservation for
 * tens of minutes. At the 24 MiB consensus ceiling this still permits an
 * intentionally conservative minimum sustained rate of about 80 KiB/s. */
static constexpr auto BLOCK_CHUNK_MAX_TRANSFER_TIME{std::chrono::minutes{5}};

inline bool BlockChunkTransferExpired(
    std::chrono::steady_clock::time_point started_at,
    std::chrono::steady_clock::time_point last_activity,
    std::chrono::steady_clock::time_point now)
{
    return now < started_at || now < last_activity ||
           now - last_activity > BLOCK_CHUNK_STALL_TIMEOUT ||
           now - started_at > BLOCK_CHUNK_MAX_TRANSFER_TIME;
}

struct BlockChunkManifest {
    uint256 block_hash;
    uint64_t total_size{0};
    uint32_t chunk_size{0};
    uint32_t chunk_count{0};
    uint256 payload_hash;

    SERIALIZE_METHODS(BlockChunkManifest, obj)
    {
        READWRITE(obj.block_hash, obj.total_size, obj.chunk_size,
                  obj.chunk_count, obj.payload_hash);
    }

    bool operator==(const BlockChunkManifest&) const = default;
};

/** One bounded sequential chunk. The custom decoder rejects the declared
 * length before allocating, unlike unconstrained std::vector decoding. */
struct BlockChunkMessage {
    uint256 block_hash;
    uint32_t index{0};
    std::vector<uint8_t> data;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        s << block_hash << index;
        WriteCompactSize(s, data.size());
        if (!data.empty()) s.write(MakeByteSpan(data));
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        s >> block_hash >> index;
        const uint64_t size{ReadCompactSize(s)};
        if (size > BLOCK_CHUNK_SIZE) {
            throw std::ios_base::failure("block chunk exceeds negotiated size");
        }
        data.resize(static_cast<size_t>(size));
        if (!data.empty()) s.read(MakeWritableByteSpan(data));
    }
};

inline bool ValidateBlockChunkManifest(const BlockChunkManifest& manifest,
                                       std::string* error = nullptr)
{
    const auto fail = [&](const char* why) {
        if (error) *error = why;
        return false;
    };
    if (manifest.block_hash.IsNull()) return fail("null block hash");
    if (manifest.total_size == 0 ||
        manifest.total_size > BLOCK_CHUNK_MAX_TOTAL_BYTES) {
        return fail("total size out of range");
    }
    if (manifest.chunk_size != BLOCK_CHUNK_SIZE) {
        return fail("non-canonical chunk size");
    }
    // Overflow-safe ceil(total/chunk).
    const uint64_t expected_count{
        1 + (manifest.total_size - 1) / manifest.chunk_size};
    if (expected_count > BLOCK_CHUNK_MAX_COUNT ||
        manifest.chunk_count != expected_count) {
        return fail("chunk count mismatch");
    }
    return true;
}

enum class BlockChunkAddResult {
    ACCEPTED,
    COMPLETE,
    WRONG_BLOCK,
    WRONG_INDEX,
    WRONG_SIZE,
    HASH_MISMATCH,
};

/** Deterministic sequential assembler. P2P ownership, per-peer concurrency,
 * timeouts, and the global byte reservation are enforced by PeerManager. */
class BlockChunkAssembler final
{
public:
    explicit BlockChunkAssembler(BlockChunkManifest manifest)
        : m_manifest(std::move(manifest))
    {
        m_bytes.reserve(static_cast<size_t>(m_manifest.total_size));
    }

    BlockChunkAddResult Add(const BlockChunkMessage& chunk)
    {
        if (chunk.block_hash != m_manifest.block_hash) {
            return BlockChunkAddResult::WRONG_BLOCK;
        }
        if (chunk.index != m_next_index ||
            chunk.index >= m_manifest.chunk_count) {
            return BlockChunkAddResult::WRONG_INDEX;
        }
        const uint64_t offset{
            static_cast<uint64_t>(chunk.index) * m_manifest.chunk_size};
        const uint64_t remaining{m_manifest.total_size - offset};
        const size_t expected{
            static_cast<size_t>(std::min<uint64_t>(m_manifest.chunk_size,
                                                   remaining))};
        if (chunk.data.size() != expected) {
            return BlockChunkAddResult::WRONG_SIZE;
        }
        m_bytes.insert(m_bytes.end(), chunk.data.begin(), chunk.data.end());
        ++m_next_index;
        if (m_next_index != m_manifest.chunk_count) {
            return BlockChunkAddResult::ACCEPTED;
        }
        if (m_bytes.size() != m_manifest.total_size ||
            Hash(Span<const uint8_t>{m_bytes.data(), m_bytes.size()}) !=
                m_manifest.payload_hash) {
            return BlockChunkAddResult::HASH_MISMATCH;
        }
        return BlockChunkAddResult::COMPLETE;
    }

    const BlockChunkManifest& Manifest() const { return m_manifest; }
    uint32_t NextIndex() const { return m_next_index; }
    const std::vector<uint8_t>& Bytes() const { return m_bytes; }
    std::vector<uint8_t> TakeBytes() { return std::move(m_bytes); }

private:
    BlockChunkManifest m_manifest;
    std::vector<uint8_t> m_bytes;
    uint32_t m_next_index{0};
};

} // namespace node

#endif // BITCOIN_NODE_BLOCK_CHUNK_TRANSPORT_H
