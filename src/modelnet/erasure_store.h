// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_ERASURE_STORE_H
#define BITCOIN_MODELNET_ERASURE_STORE_H

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

struct ErasureManifest;

/** Cauchy RS over GF(256). Sufficiency is per stripe, never a global shard count. */
uint8_t GfMul(uint8_t a, uint8_t b);
bool EncodeShards(const std::vector<std::vector<unsigned char>>& data_shards, int n,
                  std::vector<std::vector<unsigned char>>& out, std::string& err);
bool ReconstructShards(const std::vector<std::vector<unsigned char>>& shards,
                        const std::vector<int>& positions, int k, int n,
                        std::vector<std::vector<unsigned char>>& data_out, std::string& err);
/** True iff every stripe has at least k distinct positions. */
bool StripeReconstructable(const std::vector<std::vector<int>>& position_sets, int k);

/**
 * Reconstruct k canonical data shards for one stripe.
 * Refuses unless ErasureManifestReconstructable(man): global n / global shard
 * count is not sufficiency. Requires distinct k positions (man.data_shards),
 * then ReconstructShards. Does not mint a second identity.
 */
bool RepairCanonicalFromShards(const ErasureManifest& man,
                               const std::vector<std::vector<unsigned char>>& shards,
                               const std::vector<int>& positions,
                               std::vector<std::vector<unsigned char>>& data_out,
                               std::string& err,
                               int stripe_index = -1);

/**
 * Per-stripe repair I/O: read shard files, Reconstruct via RepairCanonicalFromShards
 * (global n is still not sufficiency), write concatenated canonical data shards to dest.
 * Bounded by IoExecutor. Does not mint a second identity.
 */
bool RepairStripeFromFiles(const ErasureManifest& man,
                              const std::vector<std::string>& shard_paths,
                              const std::vector<int>& positions,
                              const std::string& dest_path,
                              std::string& err,
                              int stripe_index = -1);

struct TorrentFileMap {
    std::string name;
    uint64_t size{0};
    bool padding{false};
};

struct TorrentSlice {
    std::string name;
    uint64_t file_offset{0};
    uint64_t length{0};
};

bool MapTorrentRange(const std::vector<TorrentFileMap>& files, uint64_t offset, uint64_t length,
                     std::vector<TorrentSlice>& out, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_ERASURE_STORE_H
