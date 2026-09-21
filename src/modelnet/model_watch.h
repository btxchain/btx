// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_MODEL_WATCH_H
#define BITCOIN_MODELNET_MODEL_WATCH_H

#include <modelnet/event_journal.h>
#include <modelnet/identity.h>
#include <modelnet/search.h>
#include <span.h>
#include <univalue.h>
#include <util/fs.h>

#include <atomic>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Network watches (publisher / collection / query / model).
 * Distinct from the filesystem -modelwatch drop folder (scanmodelwatch / getmodelwatchstatus).
 */
enum class WatchKind {
    PUBLISHER = 0,
    COLLECTION,
    QUERY,
    MODEL,
};

/**
 * Observation is not permission. Default NOTIFY.
 * FREE_DOWNLOAD queues a job id for the coordinator to call existing getmodel FREE_ONLY.
 * PREPARE_FUNDING / FUND_WITH_MANDATE never spend and never touch the wallet here.
 */
enum class ActionPolicy {
    NOTIFY = 0,
    FREE_DOWNLOAD,
    KEEP,
    SEED,
    PREPARE_FUNDING,
    FUND_WITH_MANDATE,
};

struct ModelWatch {
    std::string watch_id;
    WatchKind kind{WatchKind::PUBLISHER};
    ActionPolicy action{ActionPolicy::NOTIFY};
    std::string publisher_id;
    std::string collection_id;
    std::string model_id;
    SearchFilters filters;
    std::string query_text;
    std::string mandate_id;
    int keep_n{0};
    int64_t created_at{0};
};

struct QueuedWatchAction {
    std::string watch_id;
    ActionPolicy action{ActionPolicy::NOTIFY};
    std::string object_id;
    std::string event_id;
    std::string job_id;
    std::string publisher_id;
    std::string mandate_id;
    bool spends{false};
    bool downloads{false};
    bool requires_mandate{false};
};

/**
 * Publisher-signed mutable pointer. Not model identity.
 * Local unsigned setmodelalias remains helper-only and is not a SignedChannel.
 *
 * Channel update emits CHANNEL_UPDATED (not a FeedEventType). Rollback protection
 * rejects a decreasing sequence for the same publisher/name/channel.
 */
struct SignedChannel {
    std::string publisher_id;
    std::string name;
    std::string channel; // stable | latest | research
    std::string target_uri;
    uint64_t sequence{0};
    int64_t expiry{0};
    bool signature_ok{false};
    std::vector<unsigned char> pubkey;
    std::vector<unsigned char> sig;
};

const char* WatchKindName(WatchKind k);
bool ParseWatchKind(const std::string& s, WatchKind& out);
const char* ActionPolicyName(ActionPolicy a);
bool ParseActionPolicy(const std::string& s, ActionPolicy& out);
bool NormalizeChannelName(const std::string& s, std::string& out);

bool SignSignedChannel(SignedChannel& ch, Span<const unsigned char> sk, std::string& err);
bool VerifySignedChannel(const SignedChannel& ch, int64_t now_ms, std::string& err);
std::string ChannelObjectId(const SignedChannel& ch);

UniValue ModelWatchToJson(const ModelWatch& w);
UniValue WatchActionToJson(const QueuedWatchAction& a);
UniValue SignedChannelToJson(const SignedChannel& ch);

/** Every WatchKind, including MODEL, requires VerifiedEnough (SIGNED_OK or CHAIN_OBSERVED). */
bool WatchMatchesEvent(const ModelWatch& watch, const ModelEvent& ev);
bool SearchRecordMatchesWatch(const ModelWatch& watch, const ModelSearchRecord& rec);

class ModelWatchStore
{
    fs::path m_dir;
    fs::path m_watch_path;
    fs::path m_channel_path;
    std::map<std::string, ModelWatch> m_watches;
    std::map<std::string, SignedChannel> m_channels;
    std::vector<QueuedWatchAction> m_actions;
    ModelEventJournal* m_journal{nullptr};
    mutable std::mutex m_mu;

    bool PersistWatchesLocked(std::string& err) const;
    bool PersistChannelsLocked(std::string& err) const;
    bool LoadLocked(std::string& err);
    void EnqueueLocked(const ModelWatch& w, const ModelEvent& ev);

public:
    explicit ModelWatchStore(fs::path modeldir);
    void BindJournal(ModelEventJournal* journal) { m_journal = journal; }

    bool PutWatch(ModelWatch& w, std::string& err);
    bool GetWatch(const std::string& watch_id, ModelWatch& out) const;
    bool RemoveWatch(const std::string& watch_id);
    std::vector<ModelWatch> List() const;
    bool Match(const ModelEvent& ev, const ModelWatch& watch) const { return WatchMatchesEvent(watch, ev); }
    void NoteEvent(const ModelEvent& ev);
    /** Admission gate: FUND_WITH_MANDATE is omitted if the mandate is missing or Revoked(). */
    std::vector<QueuedWatchAction> DrainActions();
    std::vector<QueuedWatchAction> PeekActions() const;

    bool ApplySignedChannel(SignedChannel ch, std::string& err);
    bool GetChannel(const std::string& publisher_id, const std::string& name, const std::string& channel,
                    SignedChannel& out) const;
    std::vector<SignedChannel> ListChannels() const;
};

void BindModelEventLayer(const fs::path& modeldir, size_t cap = MODEL_EVENT_CAP_DEFAULT);
ModelWatchStore* BoundModelWatchStore();

bool IsModelWatchHelperMethod(const std::string& method);
/** Coordinator wires helper.cpp Dispatch + rpc/modelnet.cpp to this. */
bool DispatchModelWatchRpc(const std::string& method, const UniValue& params, UniValue& result,
                           std::string& err_code, std::string& err, std::atomic<bool>* stop);

} // namespace modelnet

#endif // BITCOIN_MODELNET_MODEL_WATCH_H
