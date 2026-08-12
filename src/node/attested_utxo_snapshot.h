// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_NODE_ATTESTED_UTXO_SNAPSHOT_H
#define BTX_NODE_ATTESTED_UTXO_SNAPSHOT_H

#include <matmul/trusted_utxo_snapshot_attestation.h>
#include <span.h>
#include <streams.h>
#include <sync.h>
#include <uint256.h>
#include <util/fs.h>

#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

class Chainstate;

namespace node {

/** Default P2P chunk size for attested UTXO snapshot bodies (1 MiB). */
static constexpr uint32_t ATTESTED_UTXO_SNAPSHOT_CHUNK_SIZE{1u << 20};
/** Reject pathological tiny chunks that amplify request/message overhead. */
static constexpr uint32_t ATTESTED_UTXO_SNAPSHOT_MIN_CHUNK_SIZE{64u << 10};
/** Hard cap on a single chunk (must stay under the 16 MiB P2P message ceiling). */
static constexpr uint32_t ATTESTED_UTXO_SNAPSHOT_MAX_CHUNK_SIZE{4u << 20};
/** Hard upper bound for one fetched snapshot body (512 GiB). */
static constexpr uint64_t ATTESTED_UTXO_SNAPSHOT_MAX_FILE_SIZE{512ULL << 30};
/** Maximum concurrent outbound snapshot transfers served by this node. */
static constexpr size_t ATTESTED_UTXO_SNAPSHOT_MAX_CONCURRENT_TRANSFERS{2};
/** Maximum concurrent transfers served to one peer. */
static constexpr size_t ATTESTED_UTXO_SNAPSHOT_MAX_TRANSFERS_PER_PEER{1};
/** Maximum getutxomanifest requests accepted per peer per minute. */
static constexpr size_t ATTESTED_UTXO_SNAPSHOT_MAX_MANIFEST_REQ_PER_MIN{4};
/** Maximum getutxochunk requests accepted per peer per second. */
static constexpr size_t ATTESTED_UTXO_SNAPSHOT_MAX_CHUNK_REQ_PER_SEC{8};
/** Bound on in-memory bytes reserved for one served chunk response. */
static constexpr size_t ATTESTED_UTXO_SNAPSHOT_MAX_SERVE_BUFFER{
    ATTESTED_UTXO_SNAPSHOT_MAX_CHUNK_SIZE + 256};
/** Manifest wire size cap (signatures + statement). */
static constexpr size_t ATTESTED_UTXO_SNAPSHOT_MAX_MANIFEST_BYTES{64 * 1024};

/**
 * Result of a non-blocking attested dump.
 *
 * The continuous cs_main holds are limited to:
 *   1) ForceFlush of the dirty coins cache + LevelDB cursor open
 *   2) Shielded-state capture into an in-memory buffer
 * The multi-GB coin walk / hash_serialized computation runs WITHOUT cs_main,
 * iterating a LevelDB point-in-time snapshot.
 */
struct AttestedUTXOSnapshotExportResult {
    fs::path path;
    uint256 base_hash;
    int base_height{-1};
    uint64_t coins_written{0};
    uint256 txoutset_hash;
    uint64_t nchaintx{0};
    uint256 shielded_state_pin;
    uint64_t file_size{0};
    uint256 file_hash;
    std::chrono::microseconds max_cs_main_hold{0};
    std::chrono::microseconds flush_hold{0};
    std::chrono::microseconds shielded_hold{0};
};

/**
 * Dump the active tip UTXO set without holding cs_main across the coin walk.
 *
 * Justification: CCoinsViewDB::Cursor() returns a LevelDB snapshot iterator;
 * after ForceFlush + Cursor under a short cs_main critical section, concurrent
 * block connection may mutate the live DB while this iterator remains a
 * consistent point-in-time view (same property stock ComputeUTXOStats relies
 * on once its outer lock is not incorrectly wrapping the walk).
 */
[[nodiscard]] AttestedUTXOSnapshotExportResult CreateAttestedUTXOSnapshot(
    Chainstate& chainstate,
    AutoFile&& afile,
    const fs::path& path,
    const fs::path& tmppath,
    const std::function<void()>& interruption_point);

/** Process-local offer used to serve an already-exported snapshot over P2P. */
struct AttestedUTXOSnapshotOffer {
    uint256 block_hash{};
    int32_t height{-1};
    uint64_t file_size{0};
    uint32_t chunk_size{ATTESTED_UTXO_SNAPSHOT_CHUNK_SIZE};
    uint32_t chunk_count{0};
    uint256 file_hash{}; //!< SHA256d of the full snapshot body
    fs::path snapshot_path{};
    fs::path manifest_path{};
    matmul::trusted::UtxoSnapshotManifest manifest{};
};

/**
 * Register (or replace) the single local offer. Serving does not require being
 * a signer — any node that holds the snapshot file + quorum manifest may offer.
 */
[[nodiscard]] bool OfferAttestedUTXOSnapshot(AttestedUTXOSnapshotOffer offer,
                                             std::string& error);
void ClearAttestedUTXOSnapshotOffer();
[[nodiscard]] std::optional<AttestedUTXOSnapshotOffer> GetAttestedUTXOSnapshotOffer();
[[nodiscard]] bool HasAttestedUTXOSnapshotOffer();

/** Read one chunk from the offered snapshot file (bounded, seek-based). */
[[nodiscard]] bool ReadAttestedUTXOSnapshotChunk(
    const AttestedUTXOSnapshotOffer& offer,
    uint32_t chunk_index,
    std::vector<uint8_t>& out_data,
    uint256& out_chunk_hash,
    std::string& error);

/** SHA256d over a byte span (used for per-chunk and whole-file integrity). */
[[nodiscard]] uint256 AttestedUTXOSnapshotBytesHash(Span<const uint8_t> data);

/** Build an offer from on-disk snapshot + manifest paths. */
[[nodiscard]] bool BuildAttestedUTXOSnapshotOfferFromFiles(
    const fs::path& snapshot_path,
    const fs::path& manifest_path,
    uint32_t chunk_size,
    AttestedUTXOSnapshotOffer& out,
    std::string& error);

/** Hash and size-check a snapshot body against its signed statement. */
[[nodiscard]] bool VerifyAttestedUTXOSnapshotFile(
    const fs::path& snapshot_path,
    const matmul::trusted::UtxoSnapshotStatement& statement,
    std::string& error);

/**
 * Test instrumentation: last CreateAttestedUTXOSnapshot max continuous cs_main
 * hold. Zero when no export has run in this process.
 */
[[nodiscard]] std::chrono::microseconds
AttestedUTXOSnapshotLastMaxCsMainHoldForTest();

} // namespace node

#endif // BTX_NODE_ATTESTED_UTXO_SNAPSHOT_H
