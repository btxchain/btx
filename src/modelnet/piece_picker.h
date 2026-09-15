// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_PIECE_PICKER_H
#define BITCOIN_MODELNET_PIECE_PICKER_H

#include <modelnet/piece_ranges.h>
#include <modelnet/types.h>
#include <univalue.h>

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <tuple>
#include <vector>

namespace modelnet {

/** Local transfer health. Slow is not BanMan; FAILED is local quarantine. */
enum class PeerXferState {
    ACTIVE = 0,
    SLOW = 1,
    SNUBBED = 2,
    FAILED = 3,
};

struct PeerId {
    std::string endpoint;
    std::string service_id;
    std::string netgroup;
};

struct SourceAvailability {
    PeerId peer;
    uint32_t file_index{0};
    uint32_t piece_count{0};
    std::vector<PieceRange> ranges;
    /** 0 = treat as fresh (tests / unknown). */
    int64_t last_update_ms{0};
};

struct PeerMetrics {
    double throughput_bps{0};
    double rtt_ms{100};
    int timeout_count{0};
    int invalid_piece_count{0};
    uint64_t inflight_bytes{0};
    uint64_t completed_pieces{0};
    PeerXferState state{PeerXferState::ACTIVE};
};

struct PieceAssignment {
    std::string endpoint;
    uint32_t file_index{0};
    uint32_t piece_index{0};
    bool endgame_duplicate{false};
};

struct PickConfig {
    uint32_t rng_seed{1};
    int bootstrap_remaining{0};
    int endgame_piece_threshold{4};
    uint64_t endgame_bytes_threshold{uint64_t{4} * PIECE_SIZE};
    int max_duplicate_sources{2};
    uint64_t min_inflight_bytes{PIECE_SIZE};
    uint64_t max_inflight_bytes{uint64_t{8} * PIECE_SIZE};
    uint64_t global_inflight_ceiling{uint64_t{32} * PIECE_SIZE};
    double pipeline_seconds{2.0};
    int64_t now_ms{0};
    int64_t stale_after_ms{60000};
    bool preserve_rare{false};
    int max_assignments{32};
};

struct SwarmSnapshot {
    uint32_t pieces_total{0};
    uint32_t pieces_local{0};
    uint32_t pieces_missing{0};
    int min_piece_sources{0};
    int pieces_with_1_source{0};
    int pieces_with_2_sources{0};
    int complete_sources{0};
    int partial_sources{0};
};

/** Distinct authenticated identity, else netgroup, else endpoint. */
std::string DiversityKey(const PeerId& peer);

bool SourceIsFresh(const SourceAvailability& src, const PickConfig& cfg);
bool SourceHasPiece(const SourceAvailability& src, uint32_t file_index, uint32_t piece_index);

/** Number of currently usable independent sources that advertise the piece. */
int PieceRarity(uint32_t file_index, uint32_t piece_index,
                const std::vector<SourceAvailability>& sources,
                const std::map<std::string, PeerMetrics>& metrics,
                const PickConfig& cfg);

bool EndgameActive(size_t missing_pieces, uint64_t missing_bytes, const PickConfig& cfg);

uint64_t RequestWindowBytes(const PeerMetrics& metrics, const PickConfig& cfg);

PeerXferState ClassifyPeer(const PeerMetrics& metrics);

/** Outstanding (endpoint, file, piece). */
using OutstandingSet = std::set<std::tuple<std::string, uint32_t, uint32_t>>;

/**
 * Rarest-first with partial-completion preference, randomized ties, endgame
 * duplicate cap, and per-peer inflight windows. Never allocates from attacker counts.
 */
std::vector<PieceAssignment> PickRarestFirst(uint32_t file_index,
                                               uint32_t piece_count,
                                               const std::vector<uint32_t>& missing,
                                               const std::vector<SourceAvailability>& sources,
                                               const std::map<std::string, PeerMetrics>& metrics,
                                               const OutstandingSet& outstanding,
                                               const std::set<uint32_t>& local_partial,
                                               const PickConfig& cfg);

/** Cancel other outstanding requests for a piece that just committed. */
std::vector<PieceAssignment> CancelAfterCommit(const OutstandingSet& outstanding,
                                                uint32_t file_index,
                                                uint32_t piece_index,
                                                const std::string& winner_endpoint);

SwarmSnapshot SummarizeSwarm(uint32_t file_index,
                               uint32_t piece_count,
                               const std::vector<uint32_t>& local_have,
                               const std::vector<SourceAvailability>& sources,
                               const std::map<std::string, PeerMetrics>& metrics,
                               const PickConfig& cfg);

const char* ExtinctionLabel(const SwarmSnapshot& snap);

/** Pieces with rarity 1, then 2, that we do not have. Preserve-rare shard fetch. */
std::vector<uint32_t> EndangeredPieces(uint32_t file_index,
                                    uint32_t piece_count,
                                    const std::vector<uint32_t>& local_have,
                                    const std::vector<SourceAvailability>& sources,
                                    const std::map<std::string, PeerMetrics>& metrics,
                                    const PickConfig& cfg);

bool ParseAvailabilitySources(const UniValue& availability_json,
                               const std::string& endpoint,
                               const PeerId& peer,
                               const Digest48& artifact,
                               std::vector<SourceAvailability>& out,
                               std::string& err);

UniValue SwarmSnapshotJson(const SwarmSnapshot& snap);

} // namespace modelnet

#endif // BITCOIN_MODELNET_PIECE_PICKER_H
