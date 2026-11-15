// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <hash.h>
#include <node/block_chunk_transport.h>
#include <random.h>
#include <streams.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <uint256.h>

#include <cassert>
#include <chrono>
#include <cstdint>
#include <ios>
#include <optional>
#include <string>
#include <vector>

using node::BLOCK_CHUNK_MAX_COUNT;
using node::BLOCK_CHUNK_MAX_TOTAL_BYTES;
using node::BLOCK_CHUNK_SIZE;
using node::BlockChunkAddResult;
using node::BlockChunkAssembler;
using node::BlockChunkManifest;
using node::BlockChunkMessage;

namespace {

BlockChunkMessage ExpectedChunk(const BlockChunkManifest& manifest, const std::vector<uint8_t>& payload, uint32_t index)
{
    BlockChunkMessage chunk;
    chunk.block_hash = manifest.block_hash;
    chunk.index = index;
    const uint64_t offset{uint64_t{index} * manifest.chunk_size};
    const uint64_t end{std::min<uint64_t>(offset + manifest.chunk_size, payload.size())};
    if (offset < end) chunk.data.assign(payload.begin() + offset, payload.begin() + end);
    return chunk;
}

} // namespace

FUZZ_TARGET(block_chunk_transport)
{
    FuzzedDataProvider fdp{buffer.data(), buffer.size()};

    // Wire decoding of both messages, as PeerManager does it.
    DataStream wire{ConsumeRandomLengthByteVector(fdp, 512)};
    try {
        BlockChunkManifest manifest;
        wire >> manifest;
        std::string error;
        if (node::ValidateBlockChunkManifest(manifest, &error)) {
            assert(manifest.total_size > 0 && manifest.total_size <= BLOCK_CHUNK_MAX_TOTAL_BYTES);
            assert(manifest.chunk_size == BLOCK_CHUNK_SIZE);
            assert(manifest.chunk_count <= BLOCK_CHUNK_MAX_COUNT);
            assert(uint64_t{manifest.chunk_count} * manifest.chunk_size >= manifest.total_size);
            assert(uint64_t{manifest.chunk_count - 1} * manifest.chunk_size < manifest.total_size);
        } else {
            assert(!error.empty());
        }
        DataStream again;
        again << manifest;
        BlockChunkManifest decoded;
        again >> decoded;
        assert(decoded == manifest);
    } catch (const std::ios_base::failure&) {
    }
    try {
        BlockChunkMessage chunk;
        wire >> chunk;
        assert(chunk.data.size() <= BLOCK_CHUNK_SIZE);
    } catch (const std::ios_base::failure&) {
    }

    // A transfer: a consistent manifest for a payload, then a mix of the right
    // chunks and peer-chosen ones.
    const uint64_t total{fdp.ConsumeIntegralInRange<uint64_t>(1, 3 * uint64_t{BLOCK_CHUNK_SIZE} + 1)};
    FastRandomContext rng{ConsumeUInt256(fdp)};
    std::vector<uint8_t> payload(total);
    rng.fillrand(MakeWritableByteSpan(payload));
    BlockChunkManifest manifest;
    manifest.block_hash = fdp.ConsumeBool() ? uint256::ONE : ConsumeUInt256(fdp);
    manifest.total_size = total;
    manifest.chunk_size = BLOCK_CHUNK_SIZE;
    manifest.chunk_count = static_cast<uint32_t>(1 + (total - 1) / BLOCK_CHUNK_SIZE);
    manifest.payload_hash = fdp.ConsumeIntegralInRange<int>(0, 7) == 0 ? ConsumeUInt256(fdp) : Hash(payload);
    if (!node::ValidateBlockChunkManifest(manifest)) return;

    BlockChunkAssembler assembler{manifest};
    bool complete{false};
    LIMITED_WHILE(!complete && fdp.remaining_bytes() > 0, 16)
    {
        const uint32_t before_index{assembler.NextIndex()};
        const size_t before_bytes{assembler.Bytes().size()};
        BlockChunkMessage chunk;
        if (fdp.ConsumeBool()) {
            chunk = ExpectedChunk(manifest, payload, before_index);
        } else {
            chunk.block_hash = fdp.ConsumeBool() ? manifest.block_hash : ConsumeUInt256(fdp);
            chunk.index = fdp.ConsumeBool() ? before_index : fdp.ConsumeIntegral<uint32_t>();
            chunk.data = ConsumeRandomLengthByteVector(fdp, 64);
            if (fdp.ConsumeBool()) {
                chunk.data = ExpectedChunk(manifest, payload, before_index).data;
                if (!chunk.data.empty() && fdp.ConsumeBool()) chunk.data[fdp.ConsumeIntegralInRange<size_t>(0, chunk.data.size() - 1)] ^= 1;
            }
        }
        const auto result{assembler.Add(chunk)};
        switch (result) {
        case BlockChunkAddResult::ACCEPTED:
            assert(assembler.NextIndex() == before_index + 1 && assembler.NextIndex() < manifest.chunk_count);
            assert(assembler.Bytes().size() == before_bytes + chunk.data.size());
            break;
        case BlockChunkAddResult::COMPLETE:
            // Only the exact payload completes a transfer.
            assert(assembler.NextIndex() == manifest.chunk_count);
            assert(assembler.Bytes() == payload);
            assert(Hash(assembler.Bytes()) == manifest.payload_hash);
            complete = true;
            break;
        case BlockChunkAddResult::HASH_MISMATCH:
            assert(assembler.NextIndex() == manifest.chunk_count);
            assert(assembler.Bytes() != payload || Hash(payload) != manifest.payload_hash);
            complete = true;
            break;
        case BlockChunkAddResult::WRONG_BLOCK:
        case BlockChunkAddResult::WRONG_INDEX:
        case BlockChunkAddResult::WRONG_SIZE:
            // A rejected chunk leaves the transfer as it was.
            assert(assembler.NextIndex() == before_index);
            assert(assembler.Bytes().size() == before_bytes);
            break;
        }
    }

    const auto t0{std::chrono::steady_clock::time_point{std::chrono::seconds{fdp.ConsumeIntegralInRange<int64_t>(0, 1'000'000)}}};
    const auto t1{t0 + std::chrono::seconds{fdp.ConsumeIntegralInRange<int64_t>(-10, 1'000)}};
    const auto t2{t1 + std::chrono::seconds{fdp.ConsumeIntegralInRange<int64_t>(-10, 1'000)}};
    if (node::BlockChunkTransferExpired(t0, t1, t2)) {
        assert(t2 < t0 || t2 < t1 || t2 - t1 > node::BLOCK_CHUNK_STALL_TIMEOUT || t2 - t0 > node::BLOCK_CHUNK_MAX_TRANSFER_TIME);
    }
}
