// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_EVENT_JOURNAL_H
#define BITCOIN_MODELNET_EVENT_JOURNAL_H

#include <modelnet/feed.h>
#include <modelnet/search.h>
#include <univalue.h>
#include <util/fs.h>

#include <atomic>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace modelnet {

/** Default retention. Tests pass a small cap to the constructor. */
constexpr size_t MODEL_EVENT_CAP_DEFAULT = 100000;
constexpr size_t MODEL_EVENT_PAGE_MAX = 100;
constexpr int MODEL_EVENT_SCHEMA_VERSION = 1;
constexpr int MODEL_EVENT_WAIT_SLICE_MS = 50;
constexpr int MODEL_EVENT_WAIT_MAX_MS = 24 * 60 * 60 * 1000;

/**
 * Canonical local observation types (operator §8.5) plus CHANNEL_UPDATED.
 *
 * CHANNEL_UPDATED is the signed-channel pointer change (publisher/name:stable|latest|research
 * → btx://). Local unsigned setmodelalias is a different helper convenience and is not this type.
 *
 * These normalize FeedEventType / bounty Event() / catalog availability. They do not replace
 * FeedStore. No piece-level user-facing events.
 */
enum class ModelEventType {
    MODEL_PUBLISHED = 0,
    MODEL_METADATA_UPDATED,
    MODEL_PROVIDER_AVAILABLE,
    MODEL_PROVIDER_LOST,
    MODEL_RECONSTRUCTABLE,
    MODEL_NO_LONGER_RECONSTRUCTABLE,
    RELEASE_CREATED,
    RELEASE_FUNDING_CHANGED,
    RELEASE_FUNDED,
    RELEASE_FUNDING_REVERTED,
    RELEASE_SECRET_DISCLOSED,
    RELEASE_UNLOCKED,
    BOUNTY_CREATED,
    BOUNTY_FUNDING_CHANGED,
    BOUNTY_FUNDED,
    BOUNTY_SUBMISSION_CREATED,
    BOUNTY_AWARDED,
    BOUNTY_AWARD_REVERTED,
    COLLECTION_UPDATED,
    PUBLISHER_RECORD_UPDATED,
    CHANNEL_UPDATED,
};

/** Slim fields so query watches can match without a second discovery index. */
struct EventMatchFields {
    std::string family;
    std::string architecture;
    std::string format;
    std::string quantization;
    std::string publisher_name;
    std::string canonical_name;
    std::string display_name;
    std::string object_kind;
    std::string release_state;
    int64_t parameter_count{-1};
    int64_t size_bytes{-1};
    std::vector<std::string> tags;
    std::vector<std::string> languages;
};

struct ModelEvent {
    std::string event_id;
    uint64_t local_sequence{0};
    ModelEventType event_type{ModelEventType::MODEL_PUBLISHED};
    int64_t observed_at{0};
    std::string object_kind{"MODEL"};
    std::string object_id;
    std::string publisher_id;
    std::string collection_id;
    uint64_t record_sequence{0};
    std::string source{"LOCAL"};
    std::string verification_state{"LOCAL_OBSERVED"};
    std::string old_state;
    std::string new_state;
    std::string model_id;
    std::string release_id;
    std::string bounty_id;
    std::string terms_id;
    UniValue funding{UniValue::VOBJ};
    UniValue provenance{UniValue::VOBJ};
    std::string dedupe_key;
    /** Publisher/card text. Stored only; never shell, RPC, wallet, path, or mandate. */
    std::string untrusted_text;
    EventMatchFields match;
};

struct ObserveResult {
    std::string event_id;
    uint64_t local_sequence{0};
    bool duplicate{false};
};

const char* ModelEventTypeName(ModelEventType t);
bool ParseModelEventType(const std::string& s, ModelEventType& out);
ModelEventType ModelEventTypeFromFeed(FeedEventType t);
bool RevertedEventType(ModelEventType t, ModelEventType& out);

std::string MakeDedupeKey(const std::string& object_id, uint64_t record_sequence, const std::string& transition);
std::string MakeModelEventId(const std::string& dedupe_key);

bool ModelEventFromFeed(const FeedEvent& fe, ModelEvent& out);
bool ModelEventFromSearchRecord(const ModelSearchRecord& r, ModelEvent& out);
bool ModelEventFromBountyEvent(const UniValue& e, ModelEvent& out);

UniValue ModelEventToJson(const ModelEvent& ev);
bool ModelEventFromJson(const UniValue& o, ModelEvent& ev, std::string& err);

/** Strip NULs and cap length. Never interprets the string as a command. */
std::string SanitizeUntrustedEventText(std::string_view in);
/** Always false: untrusted event text must never execute or become RPC/wallet/path/mandate. */
bool EventTextMayBecomeCommand(const std::string& text);
bool EventTextMayBecomeRpc(const std::string& text);
bool EventTextMayBecomePath(const std::string& text);
bool EventTextMayBecomeMandate(const std::string& text);

/**
 * Append-only local journal under modeldir/events/journal.jsonl + seq.
 * Load on construct. Does not replace FeedStore.
 */
class ModelEventJournal
{
    fs::path m_dir;
    fs::path m_journal_path;
    fs::path m_seq_path;
    size_t m_cap{MODEL_EVENT_CAP_DEFAULT};
    uint64_t m_seq{0};
    std::vector<ModelEvent> m_events;
    std::map<std::string, size_t> m_by_id;
    std::map<std::string, size_t> m_by_dedupe;
    mutable std::mutex m_mu;

    void RebuildIndexLocked();
    bool AppendLineLocked(const ModelEvent& ev, std::string& err);
    bool WriteSeqLocked(std::string& err) const;
    bool CompactLocked(std::string& err);
    bool RewriteJournalLocked(std::string& err) const;
    std::vector<ModelEvent> ReplayAfterLocked(uint64_t cursor, size_t limit) const;
    bool LoadLocked(std::string& err);

public:
    explicit ModelEventJournal(fs::path modeldir, size_t cap = MODEL_EVENT_CAP_DEFAULT);
    void SetCap(size_t cap);
    size_t Cap() const;
    uint64_t Cursor() const;
    size_t Size() const;
    fs::path EventsDir() const { return m_dir; }

    /** If dedupe hits, returns existing event_id with duplicate=true; no second logical event. */
    bool Observe(ModelEvent ev, ObserveResult& out, std::string& err);
    /** Emit *_REVERTED for a prior event. Keeps the original. */
    bool ObserveReorgCorrection(const std::string& original_event_id, ObserveResult& out, std::string& err);
    bool ObserveReorgCorrection(const std::string& original_event_id, ModelEventType reverted,
                                 ObserveResult& out, std::string& err);

    std::vector<ModelEvent> ReplayAfter(uint64_t cursor, size_t limit = MODEL_EVENT_PAGE_MAX) const;
    bool Get(const std::string& event_id, ModelEvent& out) const;
    /**
     * Sleep in 50ms slices until events with local_sequence > cursor, timeout, or *stop.
     * Bounded page (100). Does not invoke shell.
     */
    bool WaitAfter(uint64_t cursor, int timeout_ms, std::atomic<bool>* stop, std::vector<ModelEvent>& out,
                    bool& interrupted, std::string& err);
};

void BindModelEventJournal(const fs::path& modeldir, size_t cap = MODEL_EVENT_CAP_DEFAULT);
ModelEventJournal* BoundModelEventJournal();
void SetModelEventListener(void (*fn)(const ModelEvent&));

/** Coordinator ingest. Duplicate observations return true with out.duplicate=true. */
bool JournalObserve(ModelEvent ev, ObserveResult& out, std::string& err);
bool JournalObserve(ModelEventJournal& journal, ModelEvent ev, ObserveResult& out, std::string& err);
bool JournalObserveFeed(const FeedEvent& fe, ObserveResult& out, std::string& err);
bool JournalObserveSearchRecord(const ModelSearchRecord& r, ObserveResult& out, std::string& err);
bool JournalObserveBounty(const UniValue& bounty_event, ObserveResult& out, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_EVENT_JOURNAL_H
