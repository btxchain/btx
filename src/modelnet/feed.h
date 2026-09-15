// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_FEED_H
#define BITCOIN_MODELNET_FEED_H

#include <modelnet/economy.h>
#include <modelnet/release.h>
#include <modelnet/search.h>
#include <univalue.h>
#include <util/fs.h>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace modelnet {

constexpr int FEED_SCHEMA_VERSION = 3;
constexpr int FEED_PAGE_DEFAULT = 50;
constexpr int FEED_PAGE_MAX = 100;
constexpr int64_t FEED_TTL_DEFAULT_MS = 14LL * 86400 * 1000;
constexpr size_t FEED_CAP_DEFAULT = 100000;

enum class FeedMode {
    NEWEST = 0,
    NEW_RELEASE_CAMPAIGNS,
    NEARLY_FUNDED,
    FUNDED_AWAITING_RELEASE,
    JUST_UNLOCKED,
    TRENDING,
    RARE,
    NEW_PUBLISHERS,
    NEW_COLLECTIONS,
    FUNDING_ACTIVITY,
    RECENTLY_AVAILABLE,
};

enum class FeedEventType {
    MODEL_PUBLISHED = 0,
    RELEASE_CAMPAIGN_CREATED,
    RELEASE_FUNDING_CHANGED,
    RELEASE_FUNDED,
    RELEASE_SECRET_DISCLOSED,
    MODEL_UNLOCKED,
    MODEL_BECAME_AVAILABLE,
    MODEL_BECAME_FRAGILE,
    MODEL_METADATA_UPDATED,
    COLLECTION_PUBLISHED,
    PUBLISHER_FIRST_OBSERVED,
};

struct FeedEvent {
    std::string event_id;
    FeedEventType event_type{FeedEventType::MODEL_PUBLISHED};
    int64_t observed_at{0};
    int64_t published_at{0};
    int64_t first_seen_at{0};
    Digest48 model_id;
    std::string release_id;
    uint64_t sequence{0};
    int sources_observed{1};
    bool signed_record{false};
    ModelSearchRecord rec;
    ReleaseCampaign campaign;
    bool has_campaign{false};
};

struct FeedQuery {
    SearchScope scope{SearchScope::NETWORK};
    FeedMode mode{FeedMode::NEWEST};
    int64_t since{0};
    int limit{FEED_PAGE_DEFAULT};
    std::string cursor;
    SearchFilters filters;
    uint64_t since_sequence{0};
};

struct FeedCoverage {
    bool complete{false};
    int connected_peers_queried{0};
    int index_peers_queried{0};
    int responses_received{0};
    int timed_out{0};
    int peers_contributing{0};
    int64_t last_network_refresh{0};
};

const char* FeedModeName(FeedMode m);
bool ParseFeedMode(const std::string& s, FeedMode& out);
const char* FeedEventTypeName(FeedEventType t);
bool ParseFeedEventType(const std::string& s, FeedEventType& out);

std::string MakeFeedEventId(FeedEventType t, const Digest48& model_id, const std::string& release_id,
                            uint64_t metadata_sequence, const std::string& extra);

class FeedStore {
    std::map<std::string, FeedEvent> m_by_id;
    uint64_t m_seq{0};
    size_t m_cap{FEED_CAP_DEFAULT};
    int64_t m_ttl_ms{FEED_TTL_DEFAULT_MS};
    int64_t m_last_refresh{0};
    std::map<std::string, int> m_publisher_models;
    fs::path m_path;

public:
    void SetPath(const fs::path& p) { m_path = p; }
    void SetCap(size_t cap) { m_cap = cap; }
    void SetTtlMs(int64_t ttl) { m_ttl_ms = ttl; }
    uint64_t Sequence() const { return m_seq; }
    size_t Size() const { return m_by_id.size(); }
    int64_t LastRefresh() const { return m_last_refresh; }
    void NoteRefresh(int64_t now_ms) { m_last_refresh = now_ms; }

    bool Note(FeedEvent ev, int64_t now_ms);
    bool NoteSearchRecord(const ModelSearchRecord& r, int64_t now_ms);
    bool NoteCampaign(const ReleaseCampaign& c, int64_t now_ms);
    bool NoteUnlock(const Digest48& model_id, const std::string& release_id, const ModelSearchRecord& r, int64_t now_ms);
    bool NoteFundingChanged(const ReleaseCampaign& c, int64_t now_ms);

    std::vector<FeedEvent> Query(const FeedQuery& q, int64_t now_ms, std::string& next_cursor) const;
    UniValue StatusJson(int public_models, int campaigns, int unreleased, int unlocked, const FeedCoverage& cov) const;
    UniValue EventToJson(const FeedEvent& ev, const ModelEconomyEntry* entry) const;

    bool Save(std::string& err) const;
    bool Load(int64_t now_ms, std::string& err);
    void Expire(int64_t now_ms);
};

UniValue FeedPageJson(const std::vector<FeedEvent>& items, const std::vector<ModelEconomyEntry>& entries,
                       const FeedQuery& q, const FeedCoverage& cov, uint64_t feed_sequence,
                       const std::string& next_cursor);

} // namespace modelnet

#endif // BITCOIN_MODELNET_FEED_H
