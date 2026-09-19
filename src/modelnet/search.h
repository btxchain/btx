// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SEARCH_H
#define BITCOIN_MODELNET_SEARCH_H

#include <modelnet/identity.h>
#include <modelnet/piece_ranges.h>
#include <modelnet/types.h>
#include <span.h>
#include <univalue.h>
#include <util/fs.h>

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace modelnet {

constexpr size_t SEARCH_NAME_MAX = 160;
constexpr size_t SEARCH_ALIAS_MAX = 128;
constexpr size_t SEARCH_ALIASES_MAX = 32;
constexpr size_t SEARCH_TAGS_MAX = 64;
constexpr size_t SEARCH_LANGS_MAX = 64;
constexpr size_t SEARCH_MODALITIES_MAX = 16;
constexpr size_t SEARCH_DESC_MAX = 1024;
constexpr size_t SEARCH_SIGNED_STR_MAX = 4096;
constexpr size_t SEARCH_RECORD_MAX = 16384;
constexpr size_t SEARCH_PAGE_MAX = 100;
constexpr int SEARCH_TTL_DEFAULT = 2;
constexpr int SEARCH_TTL_MAX = 4;
constexpr int SEARCH_FANOUT_MAX = 8;
constexpr int SEARCH_PEER_TIMEOUT_MS = 1500;
constexpr int SEARCH_TERMS_MAX = 16;
constexpr size_t SEARCH_QUERY_BYTES_MAX = 4096;

enum class SearchScope { LOCAL = 0, PEERS = 1, NETWORK = 2, ALL = 3 };
enum class SearchSort {
    RELEVANCE = 0,
    AVAILABILITY,
    NEWEST,
    OLDEST,
    SIZE_ASC,
    SIZE_DESC,
    PROVIDERS,
    RARITY,
    PUBLISHER,
    NAME,
    NEWEST_RELEASES,
    RECENTLY_UNLOCKED,
    NEARLY_FUNDED,
    MOST_FUNDED,
    MOST_FUNDING_NEEDED,
    RAREST_AVAILABLE,
    TRENDING,
};
enum class AvailabilityClass {
    UNKNOWN = 0,
    DEGRADED,
    FRAGILE,
    MEDIUM,
    HIGH,
    EXCELLENT,
};
enum class SearchJobState { RUNNING = 0, COMPLETE, CANCELLED, TIMED_OUT };

struct ModelSearchRecord {
    int schema_version{2};
    int record_version{1};
    Digest48 model_id;
    Digest48 artifact_id;
    std::string btx_uri;
    std::string canonical_name;
    std::string display_name;
    std::vector<std::string> aliases;
    Digest48 publisher_identity;
    std::string publisher_display_name;
    std::string family;
    std::string architecture;
    int64_t parameter_count{0};
    std::string format;
    std::string quantization;
    std::vector<std::string> languages;
    std::vector<std::string> modalities;
    std::vector<std::string> tags;
    std::string short_description;
    uint64_t size_bytes{0};
    int file_count{0};
    int64_t published_at{0};
    int64_t updated_at{0};
    std::string release_id;
    std::string release_state;
    int64_t release_target_atoms{0};
    Hash32 key_hash{};
    uint32_t refund_height{0};
    int64_t campaign_created_at{0};
    Digest48 ciphertext_artifact_id;
    std::string assurance{"KEY_RELEASE_ONLY"};
    uint64_t metadata_sequence{1};
    int64_t expires_at{0};
    Digest48 signer_id;
    std::vector<unsigned char> pubkey;
    std::vector<unsigned char> sig;
    std::string object_kind{"MODEL"};
    std::string bounty_id;
    std::string description;
    std::string network_id;
    bool signed_ok{false};
    bool tombstone{false};
};

struct SearchFilters {
    std::string publisher_id;
    std::string publisher_name;
    std::string family;
    std::string architecture;
    std::string format;
    std::string quantization;
    int64_t min_size_bytes{-1};
    int64_t max_size_bytes{-1};
    int64_t min_parameters{-1};
    int64_t max_parameters{-1};
    std::string license;
    std::vector<std::string> language;
    std::vector<std::string> tags;
    bool public_only{false};
    int min_provider_count{0};
    bool locally_verified{false};
    bool locally_available{false};
    bool pinned{false};
    bool seeded{false};
    std::vector<std::string> lifecycle_state;
    bool funding_only{false};
    bool released_only{false};
    bool unreleased_only{false};
    bool fundable_only{false};
    bool refund_available{false};
    int64_t min_funded_percent{-1};
    int64_t max_funded_percent{-1};
    int64_t max_remaining_atoms{-1};
    int64_t release_created_after{-1};
    int64_t release_created_before{-1};
    int64_t unlocked_after{-1};
    bool ciphertext_available{false};
    int min_ciphertext_provider_count{0};
    std::vector<std::string> modalities;
    std::string object_kind;
};

struct SearchQuery {
    std::string text;
    int limit{50};
    int offset{0};
    SearchScope scope{SearchScope::NETWORK};
    SearchSort sort{SearchSort::RELEVANCE};
    SearchFilters filters;
    std::string cursor;
};

struct ProviderObservation {
    std::string provider_id;
    std::string endpoint;
    bool complete{false};
    bool direct{true};
    bool relayed{false};
    int64_t last_seen_ms{0};
    std::vector<PieceRange> ranges;
    std::string netgroup;
};

struct SwarmHealth {
    int providers_observed{0};
    int providers_complete{0};
    int providers_partial{0};
    int reachable_direct{0};
    int reachable_relay{0};
    uint32_t pieces_total{0};
    uint32_t pieces_local{0};
    int min_piece_sources{0};
    int pieces_with_0_sources{0};
    int pieces_with_1_source{0};
    int pieces_with_2_sources{0};
    bool reconstructable{false};
    bool reconstructable_known{false};
    uint32_t missing_piece_count{0};
    AvailabilityClass klass{AvailabilityClass::UNKNOWN};
    bool fragile{false};
};

struct DirectoryLocalState {
    bool known{false};
    bool downloaded{false};
    bool partial{false};
    bool seeded{false};
    bool pinned{false};
    std::string qualification{"NOT_RUN"};
};

struct SearchHit {
    ModelSearchRecord rec;
    SwarmHealth health;
    DirectoryLocalState local;
    int score{0};
    int sources{1};
    std::vector<std::string> provenance;
};

struct SearchRequest {
    int schema_version{2};
    std::string query_id;
    std::vector<std::string> text_terms;
    SearchFilters filters;
    SearchSort sort_hint{SearchSort::RELEVANCE};
    int limit{25};
    int ttl{SEARCH_TTL_DEFAULT};
    std::string origin_nonce;
};

struct SearchCoverage {
    bool local{true};
    int connected_peers_queried{0};
    int index_peers_queried{0};
    int routing_peers_queried{0};
    int responses_received{0};
    int timed_out{0};
    bool complete{false};
};

struct SearchJob {
    std::string query_id;
    SearchJobState state{SearchJobState::RUNNING};
    SearchQuery q;
    std::vector<SearchHit> hits;
    SearchCoverage coverage;
    int64_t started_ms{0};
    int64_t elapsed_ms{0};
};

const char* SearchScopeName(SearchScope s);
const char* SearchSortName(SearchSort s);
const char* AvailabilityClassName(AvailabilityClass k);
bool ParseSearchScope(const std::string& s, SearchScope& out);
bool ParseSearchSort(const std::string& s, SearchSort& out);

std::string NormalizeSearchText(const std::string& in);
std::vector<std::string> TokenizeSearch(const std::string& in);
bool ValidateSearchRecord(const ModelSearchRecord& r, std::string& err);
/** True when a record carries publisher-authored fields, not just a catalog filename stub. */
bool SearchRecordHasAuthoredMetadata(const ModelSearchRecord& r);
std::vector<unsigned char> SearchRecordPreimageV1(const ModelSearchRecord& r);
std::vector<unsigned char> SearchRecordPreimageV2(const ModelSearchRecord& r);
std::vector<unsigned char> SearchRecordPreimage(const ModelSearchRecord& r);
bool SignSearchRecord(ModelSearchRecord& r, Span<const unsigned char> sk, std::string& err);
bool VerifySearchRecord(const ModelSearchRecord& r, int64_t now_ms, std::string& err);
bool PublisherFieldCoveredByV1(const std::string& field);
UniValue SearchRecordToJson(const ModelSearchRecord& r);
bool SearchRecordFromJson(const UniValue& o, ModelSearchRecord& r, std::string& err);

bool ParseSearchQuery(const UniValue& o, SearchQuery& q, std::string& err);
UniValue AppliedFiltersJson(const SearchFilters& f);

bool UnionCoversAll(uint32_t pieces_total, const std::vector<std::vector<PieceRange>>& providers);
SwarmHealth ComputeSwarmHealth(uint32_t pieces_total, uint32_t pieces_local,
                               const std::vector<ProviderObservation>& obs);
int DiversityAwareProviderScore(const std::vector<ProviderObservation>& obs);
int RelevanceScore(const ModelSearchRecord& r, const std::vector<std::string>& terms);

void SortHits(std::vector<SearchHit>& hits, SearchSort sort);
UniValue SearchResultCard(const SearchHit& h);
UniValue DirectoryEntryJson(const SearchHit& h);
UniValue AvailabilityJson(const SwarmHealth& h);
UniValue PeerCountJson(const SwarmHealth& h);

class SearchIndex {
    std::map<std::string, ModelSearchRecord> m_by_model;
    std::set<std::string> m_hidden;
    std::set<std::string> m_muted_publishers;
    std::map<std::string, int> m_pub_window;
    size_t m_cap{100000};
    std::vector<std::string> m_index_peers;
    uint64_t m_seq{0};

public:
    bool Put(const ModelSearchRecord& r, int64_t now_ms, std::string& err);
    bool Tombstone(const Digest48& model_id, uint64_t seq, int64_t now_ms, std::string& err);
    const ModelSearchRecord* Get(const Digest48& model_id) const;
    const ModelSearchRecord* FindByAlias(const std::string& alias) const;
    std::vector<ModelSearchRecord> List(int64_t updated_after, const std::string& cursor, int limit) const;
    std::vector<SearchHit> Search(const SearchQuery& q, int64_t now_ms) const;
    void Hide(const Digest48& model_id, bool on);
    void MutePublisher(const std::string& publisher_hex, bool on);
    bool Hidden(const Digest48& model_id) const;
    bool Muted(const std::string& publisher_hex) const;
    void AddIndexPeer(const std::string& endpoint);
    void RemoveIndexPeer(const std::string& endpoint);
    std::vector<std::string> IndexPeers() const { return m_index_peers; }
    size_t Size() const { return m_by_model.size(); }
    uint64_t Sequence() const { return m_seq; }
    UniValue ExportSince(uint64_t since, int limit) const;
    UniValue StatusJson() const;
    bool Save(const fs::path& path, std::string& err) const;
    bool Load(const fs::path& path, int64_t now_ms, std::string& err);
    std::vector<ModelSearchRecord> All() const;
    void SetCap(size_t cap) { m_cap = cap; }
    /** Drop records for a new helper dir. Index peers are kept. */
    void Clear();
};

struct QueryDedupe {
    std::set<std::string> seen;
    bool Admit(const std::string& query_id);
};

bool ShouldForwardSearch(int ttl, int hop);
SearchRequest ParseSearchRequest(const UniValue& o, std::string& err);
UniValue SearchResponseJson(const std::string& query_id, const std::string& responder,
                             const std::vector<SearchHit>& hits, bool truncated);

bool SearchPeerTimedOut(int64_t elapsed_ms, int timeout_ms = SEARCH_PEER_TIMEOUT_MS);
void NoteSearchPeerTimeout(SearchCoverage& cov);
void MergeRemoteSearchHits(SearchJob& job, std::vector<SearchHit> extra);
bool SearchHitFromCard(const UniValue& card, SearchHit& out, std::string& err);

class SearchRuntime {
    std::map<std::string, SearchJob> m_jobs;
    SearchIndex* m_idx{nullptr};
    int m_running{0};
    int m_completed{0};

public:
    void Bind(SearchIndex* idx) { m_idx = idx; }
    SearchJob Start(const SearchQuery& q, const std::vector<SearchIndex*>& extras, int64_t now_ms);
    bool Status(const std::string& query_id, SearchJob& out) const;
    bool Cancel(const std::string& query_id);
    bool IsCancelled(const std::string& query_id) const;
    void Finish(SearchJob& job);
    int Running() const { return m_running; }
    int Completed() const { return m_completed; }
};

bool UnsignedCannotOverrideSigned();
bool SearchTouchesMonetaryConsensus();
std::string NewSearchQueryId();

} // namespace modelnet

#endif // BITCOIN_MODELNET_SEARCH_H
