// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/piece_picker.h>
#include <modelnet/piece_ranges.h>
#include <modelnet/types.h>

#include <algorithm>
#include <cmath>
#include <limits>
#include <set>
#include <utility>

namespace modelnet {
namespace {

uint32_t XorShift32(uint32_t& state)
{
    if (state == 0) state = 1;
    uint32_t x = state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    state = x;
    return x;
}

bool MetricsFailed(const std::map<std::string, PeerMetrics>& metrics, const std::string& endpoint)
{
    const auto it = metrics.find(endpoint);
    if (it == metrics.end()) return false;
    if (it->second.state == PeerXferState::FAILED) return true;
    return it->second.invalid_piece_count >= 2;
}

double ThroughputOf(const std::map<std::string, PeerMetrics>& metrics, const std::string& endpoint)
{
    const auto it = metrics.find(endpoint);
    if (it == metrics.end()) return 0;
    return it->second.throughput_bps;
}

} // namespace

std::string DiversityKey(const PeerId& peer)
{
    if (!peer.service_id.empty()) return std::string("id:") + peer.service_id;
    if (!peer.netgroup.empty()) return std::string("ng:") + peer.netgroup;
    return std::string("ep:") + peer.endpoint;
}

bool SourceIsFresh(const SourceAvailability& src, const PickConfig& cfg)
{
    if (cfg.now_ms <= 0 || src.last_update_ms == 0) return true;
    if (cfg.now_ms < src.last_update_ms) return true;
    return (cfg.now_ms - src.last_update_ms) <= cfg.stale_after_ms;
}

bool SourceHasPiece(const SourceAvailability& src, uint32_t file_index, uint32_t piece_index)
{
    if (src.file_index != file_index) return false;
    if (!src.ranges.empty()) {
        return RangesCover(src.ranges, file_index, piece_index, src.file_index);
    }
    // Legacy complete seeder: empty ranges mean contiguous 0..piece_count-1
    // when piece_count is a total, or "all pieces" when piece_count is 0.
    if (src.piece_count == 0) return true;
    return piece_index < src.piece_count;
}

int PieceRarity(uint32_t file_index, uint32_t piece_index,
                 const std::vector<SourceAvailability>& sources,
                 const std::map<std::string, PeerMetrics>& metrics,
                 const PickConfig& cfg)
{
    std::set<std::string> keys;
    for (const auto& src : sources) {
        if (!SourceIsFresh(src, cfg)) continue;
        if (MetricsFailed(metrics, src.peer.endpoint)) continue;
        if (!SourceHasPiece(src, file_index, piece_index)) continue;
        keys.insert(DiversityKey(src.peer));
    }
    return static_cast<int>(keys.size());
}

bool EndgameActive(size_t missing_pieces, uint64_t missing_bytes, const PickConfig& cfg)
{
    if (missing_pieces == 0) return false;
    if (missing_pieces <= static_cast<size_t>(std::max(1, cfg.endgame_piece_threshold))) return true;
    return missing_bytes <= cfg.endgame_bytes_threshold;
}

uint64_t RequestWindowBytes(const PeerMetrics& metrics, const PickConfig& cfg)
{
    if (metrics.state == PeerXferState::FAILED || metrics.invalid_piece_count >= 2) return 0;
    uint64_t lo = cfg.min_inflight_bytes ? cfg.min_inflight_bytes : PIECE_SIZE;
    uint64_t hi = cfg.max_inflight_bytes ? cfg.max_inflight_bytes : lo;
    if (hi < lo) hi = lo;
    if (metrics.state == PeerXferState::SNUBBED) return lo;
    double tput = metrics.throughput_bps;
    if (tput < 1.0) tput = 1.0;
    double seconds = cfg.pipeline_seconds > 0.1 ? cfg.pipeline_seconds : 2.0;
    double target = tput * seconds;
    if (metrics.state == PeerXferState::SLOW) target /= 2.0;
    if (target < static_cast<double>(lo)) target = static_cast<double>(lo);
    if (target > static_cast<double>(hi)) target = static_cast<double>(hi);
    if (metrics.timeout_count > 0) {
        target /= (1.0 + static_cast<double>(metrics.timeout_count));
        if (target < static_cast<double>(lo)) target = static_cast<double>(lo);
    }
    if (metrics.invalid_piece_count > 0) {
        target /= 2.0;
        if (target < static_cast<double>(lo)) target = static_cast<double>(lo);
    }
    return static_cast<uint64_t>(target);
}

PeerXferState ClassifyPeer(const PeerMetrics& metrics)
{
    if (metrics.invalid_piece_count >= 2) return PeerXferState::FAILED;
    if (metrics.state == PeerXferState::FAILED) return PeerXferState::FAILED;
    if (metrics.timeout_count >= 4) return PeerXferState::SNUBBED;
    if (metrics.timeout_count >= 2 || (metrics.throughput_bps > 0 && metrics.throughput_bps < 8000)) {
        return PeerXferState::SLOW;
    }
    return PeerXferState::ACTIVE;
}

std::vector<PieceAssignment> PickRarestFirst(uint32_t file_index,
                                               uint32_t piece_count,
                                               const std::vector<uint32_t>& missing,
                                               const std::vector<SourceAvailability>& sources,
                                               const std::map<std::string, PeerMetrics>& metrics,
                                               const OutstandingSet& outstanding,
                                               const std::set<uint32_t>& local_partial,
                                               const PickConfig& cfg)
{
    std::vector<PieceAssignment> out;
    if (piece_count > 0 && missing.size() > piece_count) return out;
    if (cfg.max_assignments <= 0) return out;

    std::vector<uint32_t> need;
    need.reserve(missing.size());
    for (uint32_t p : missing) {
        if (piece_count > 0 && p >= piece_count) continue;
        need.push_back(p);
    }
    if (need.empty()) return out;

    uint32_t rng = cfg.rng_seed ? cfg.rng_seed : 1;
    const uint64_t missing_bytes = static_cast<uint64_t>(need.size()) * PIECE_SIZE;
    const bool endgame = EndgameActive(need.size(), missing_bytes, cfg);

    struct Cand {
        uint32_t piece{0};
        int rarity{0};
        bool partial{false};
        uint32_t tie{0};
    };
    std::vector<Cand> cands;
    cands.reserve(need.size());

    auto shuffle_need = [&]() {
        for (size_t i = need.size(); i > 1; --i) {
            const uint32_t j = XorShift32(rng) % static_cast<uint32_t>(i);
            std::swap(need[i - 1], need[j]);
        }
    };

    if (cfg.bootstrap_remaining > 0) {
        shuffle_need();
        for (uint32_t p : need) {
            Cand c;
            c.piece = p;
            c.rarity = PieceRarity(file_index, p, sources, metrics, cfg);
            if (c.rarity <= 0) continue;
            c.partial = local_partial.count(p) != 0;
            c.tie = XorShift32(rng);
            cands.push_back(c);
            if (static_cast<int>(cands.size()) >= cfg.bootstrap_remaining) break;
        }
    } else {
        for (uint32_t p : need) {
            Cand c;
            c.piece = p;
            c.rarity = PieceRarity(file_index, p, sources, metrics, cfg);
            if (c.rarity <= 0) continue;
            c.partial = local_partial.count(p) != 0;
            c.tie = XorShift32(rng);
            cands.push_back(c);
        }
        std::sort(cands.begin(), cands.end(), [](const Cand& a, const Cand& b) {
            if (a.rarity != b.rarity) return a.rarity < b.rarity;
            if (a.partial != b.partial) return a.partial && !b.partial;
            if (a.tie != b.tie) return a.tie < b.tie;
            return a.piece < b.piece;
        });
        if (cfg.preserve_rare) {
            std::stable_sort(cands.begin(), cands.end(), [](const Cand& a, const Cand& b) {
                const bool a1 = a.rarity == 1;
                const bool b1 = b.rarity == 1;
                if (a1 != b1) return a1 && !b1;
                const bool a2 = a.rarity == 2;
                const bool b2 = b.rarity == 2;
                if (a2 != b2) return a2 && !b2;
                return false;
            });
        }
    }

    std::map<std::string, uint64_t> assigned_bytes;
    std::map<std::string, uint64_t> peer_inflight = {};
    for (const auto& kv : metrics) peer_inflight[kv.first] = kv.second.inflight_bytes;
    uint64_t global = 0;
    for (const auto& kv : metrics) global += kv.second.inflight_bytes;

    auto already_out = [&](const std::string& ep, uint32_t piece) {
        if (outstanding.count(std::make_tuple(ep, file_index, piece))) return true;
        for (const auto& a : out) {
            if (a.endpoint == ep && a.piece_index == piece && a.file_index == file_index) return true;
        }
        return false;
    };

    auto window_of = [&](const std::string& ep) -> uint64_t {
        const auto it = metrics.find(ep);
        PeerMetrics m;
        if (it != metrics.end()) m = it->second;
        return RequestWindowBytes(m, cfg);
    };

    auto pick_sources = [&](uint32_t piece, int rarity) {
        struct Src {
            std::string endpoint;
            double tput{0};
            PeerXferState st{PeerXferState::ACTIVE};
        };
        std::vector<Src> srcs;
        for (const auto& s : sources) {
            if (!SourceIsFresh(s, cfg)) continue;
            if (!SourceHasPiece(s, file_index, piece)) continue;
            if (MetricsFailed(metrics, s.peer.endpoint)) continue;
            Src x;
            x.endpoint = s.peer.endpoint;
            x.tput = ThroughputOf(metrics, s.peer.endpoint);
            const auto it = metrics.find(s.peer.endpoint);
            x.st = it == metrics.end() ? PeerXferState::ACTIVE : it->second.state;
            srcs.push_back(x);
        }
        std::sort(srcs.begin(), srcs.end(), [](const Src& a, const Src& b) {
            if (a.tput != b.tput) return a.tput > b.tput;
            return a.endpoint < b.endpoint;
        });
        (void)rarity;
        return srcs;
    };

    const int dup_cap = std::max(1, std::min(cfg.max_duplicate_sources, 3));

    for (const auto& c : cands) {
        if (static_cast<int>(out.size()) >= cfg.max_assignments) break;
        auto srcs = pick_sources(c.piece, c.rarity);
        if (srcs.empty()) continue;
        const int want = endgame ? dup_cap : 1;
        int got = 0;
        for (const auto& src : srcs) {
            if (got >= want) break;
            if (static_cast<int>(out.size()) >= cfg.max_assignments) break;
            if (already_out(src.endpoint, c.piece)) continue;
            const bool unique_rare = c.rarity == 1;
            if (src.st == PeerXferState::SNUBBED && !unique_rare && !endgame) continue;
            if (!unique_rare && assigned_bytes[src.endpoint] > 0) {
                bool alt_less = false;
                for (const auto& o : srcs) {
                    if (o.endpoint == src.endpoint) continue;
                    if (MetricsFailed(metrics, o.endpoint)) continue;
                    if (assigned_bytes[o.endpoint] < assigned_bytes[src.endpoint]) {
                        alt_less = true;
                        break;
                    }
                }
                if (alt_less) continue;
            }
            const uint64_t win = window_of(src.endpoint);
            const uint64_t inflight = peer_inflight[src.endpoint] + assigned_bytes[src.endpoint];
            if (!unique_rare && win > 0 && inflight + PIECE_SIZE > win) continue;
            if (!unique_rare && cfg.global_inflight_ceiling > 0 &&
                global + PIECE_SIZE > cfg.global_inflight_ceiling) {
                continue;
            }
            PieceAssignment a;
            a.endpoint = src.endpoint;
            a.file_index = file_index;
            a.piece_index = c.piece;
            a.endgame_duplicate = got > 0;
            out.push_back(a);
            assigned_bytes[src.endpoint] += PIECE_SIZE;
            global += PIECE_SIZE;
            ++got;
        }
    }
    return out;
}

std::vector<PieceAssignment> CancelAfterCommit(const OutstandingSet& outstanding,
                                                uint32_t file_index,
                                                uint32_t piece_index,
                                                const std::string& winner_endpoint)
{
    std::vector<PieceAssignment> out;
    for (const auto& t : outstanding) {
        if (std::get<1>(t) != file_index || std::get<2>(t) != piece_index) continue;
        if (std::get<0>(t) == winner_endpoint) continue;
        PieceAssignment a;
        a.endpoint = std::get<0>(t);
        a.file_index = file_index;
        a.piece_index = piece_index;
        a.endgame_duplicate = true;
        out.push_back(a);
    }
    return out;
}

SwarmSnapshot SummarizeSwarm(uint32_t file_index,
                               uint32_t piece_count,
                               const std::vector<uint32_t>& local_have,
                               const std::vector<SourceAvailability>& sources,
                               const std::map<std::string, PeerMetrics>& metrics,
                               const PickConfig& cfg)
{
    SwarmSnapshot s;
    s.pieces_total = piece_count;
    std::set<uint32_t> have(local_have.begin(), local_have.end());
    s.pieces_local = static_cast<uint32_t>(have.size());
    s.pieces_missing = piece_count > s.pieces_local ? piece_count - s.pieces_local : 0;
    int min_r = std::numeric_limits<int>::max();
    for (uint32_t p = 0; p < piece_count; ++p) {
        const int r = PieceRarity(file_index, p, sources, metrics, cfg);
        if (r < min_r) min_r = r;
        if (r == 1) ++s.pieces_with_1_source;
        if (r == 2) ++s.pieces_with_2_sources;
    }
    s.min_piece_sources = piece_count == 0 ? 0 : (min_r == std::numeric_limits<int>::max() ? 0 : min_r);
    for (const auto& src : sources) {
        if (!SourceIsFresh(src, cfg)) continue;
        if (MetricsFailed(metrics, src.peer.endpoint)) continue;
        bool complete = src.piece_count > 0;
        if (complete) {
            for (uint32_t p = 0; p < src.piece_count; ++p) {
                if (!SourceHasPiece(src, src.file_index, p)) {
                    complete = false;
                    break;
                }
            }
        } else if (!src.ranges.empty() && piece_count > 0) {
            complete = true;
            for (uint32_t p = 0; p < piece_count; ++p) {
                if (!SourceHasPiece(src, file_index, p)) {
                    complete = false;
                    break;
                }
            }
        }
        if (complete) ++s.complete_sources;
        else ++s.partial_sources;
    }
    return s;
}

const char* ExtinctionLabel(const SwarmSnapshot& snap)
{
    if (snap.pieces_total == 0) return "EMPTY";
    if (snap.min_piece_sources == 0 && snap.pieces_missing > 0) return "CURRENTLY_UNAVAILABLE";
    if (snap.min_piece_sources == 1) return "FRAGILE";
    return "OK";
}

std::vector<uint32_t> EndangeredPieces(uint32_t file_index,
                                    uint32_t piece_count,
                                    const std::vector<uint32_t>& local_have,
                                    const std::vector<SourceAvailability>& sources,
                                    const std::map<std::string, PeerMetrics>& metrics,
                                    const PickConfig& cfg)
{
    std::set<uint32_t> have(local_have.begin(), local_have.end());
    std::vector<uint32_t> rare1;
    std::vector<uint32_t> rare2;
    for (uint32_t p = 0; p < piece_count; ++p) {
        if (have.count(p)) continue;
        const int r = PieceRarity(file_index, p, sources, metrics, cfg);
        if (r == 1) rare1.push_back(p);
        else if (r == 2) rare2.push_back(p);
    }
    rare1.insert(rare1.end(), rare2.begin(), rare2.end());
    return rare1;
}

bool ParseAvailabilitySources(const UniValue& availability_json,
                               const std::string& endpoint,
                               const PeerId& peer,
                               const Digest48& artifact,
                               std::vector<SourceAvailability>& out,
                               std::string& err)
{
    UniValue models = UniValue(UniValue::VARR);
    if (availability_json.isObject() && availability_json.exists("local") &&
        availability_json["local"].exists("models")) {
        models = availability_json["local"]["models"];
    } else if (availability_json.isObject() && availability_json.exists("models")) {
        models = availability_json["models"];
    } else if (availability_json.isArray()) {
        models = availability_json;
    }
    if (!models.isArray()) {
        err = "availability models";
        return false;
    }
    for (const auto& m : models.getValues()) {
        if (!m.isObject()) continue;
        if (m.exists("artifact_id") && m["artifact_id"].isStr() &&
            m["artifact_id"].get_str() != artifact.Hex()) {
            continue;
        }
        if (!m.exists("files") || !m["files"].isArray()) continue;
        for (const auto& f : m["files"].getValues()) {
            SourceAvailability src;
            src.peer = peer;
            src.peer.endpoint = endpoint;
            src.file_index = f.exists("file_index") ? f["file_index"].getInt<uint32_t>() : 0;
            src.piece_count = f.exists("piece_count") ? f["piece_count"].getInt<uint32_t>() : 0;
            if (f.exists("ranges")) {
                if (!ParsePieceRangesJson(f["ranges"], src.ranges, err)) return false;
                uint32_t covered = 0;
                for (const auto& r : src.ranges) covered += r.count;
                if (src.piece_count == 0) src.piece_count = covered;
            }
            src.last_update_ms = 0;
            out.push_back(std::move(src));
        }
    }
    return true;
}

UniValue SwarmSnapshotJson(const SwarmSnapshot& snap)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("pieces_total", static_cast<int>(snap.pieces_total));
    o.pushKV("pieces_local", static_cast<int>(snap.pieces_local));
    o.pushKV("pieces_missing", static_cast<int>(snap.pieces_missing));
    o.pushKV("min_piece_sources", snap.min_piece_sources);
    o.pushKV("pieces_with_1_source", snap.pieces_with_1_source);
    o.pushKV("pieces_with_2_sources", snap.pieces_with_2_sources);
    o.pushKV("complete_sources", snap.complete_sources);
    o.pushKV("partial_sources", snap.partial_sources);
    o.pushKV("extinction", ExtinctionLabel(snap));
    return o;
}

} // namespace modelnet
