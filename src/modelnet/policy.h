// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_POLICY_H
#define BITCOIN_MODELNET_POLICY_H

#include <modelnet/types.h>

#include <univalue.h>

#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <tuple>
#include <vector>

namespace modelnet {

struct PaidPlan {
    int64_t price_atoms{0};
    int64_t fee_atoms{0};
    std::optional<int> total_eta_s;
    bool safe{true};
    bool deliverable{true};
    bool requires_release{false};
};

bool ChoosePlan(RetrievalMode mode,
                const std::optional<int>& free_eta_s,
                const PaidPlan* paid,
                int64_t budget_atoms,
                bool exposure_ok,
                const std::optional<int>& deadline_s,
                int64_t value_per_second_atoms,
                bool approved,
                PlanChoice& out,
                std::string& err);

/** False if any argument is negative, outstanding+additional > ceiling, or the sum overflows MAX_MONEY_ATOMS. */
bool ExposureWithinCeiling(int64_t outstanding_atoms, int64_t additional_atoms, int64_t ceiling);

AclDecision DecideAcl(bool crypto_ok,
                       bool hard_limit_ok,
                       bool local_deny,
                       bool quarantined,
                       bool exact_allow,
                       bool subscribed_deny,
                       bool needs_spend,
                       bool budget_approved);

/** Local reciprocity ledger. Not money, not consensus, not transferable. */
class ReciprocityLedger {
    struct Event {
        std::string peer;
        int64_t bytes{0};
        int64_t when{0};
    };
    std::vector<Event> m_events;
    std::set<std::tuple<std::string, int, int>> m_seen; // artifact,file,piece

public:
    /** ReciprocityLedger never includes, constructs, or writes BanMan/AddrMan. */
    static constexpr bool TOUCHES_BANMAN = false;
    static constexpr bool TOUCHES_ADDRMAN = false;

    bool Received(const std::string& peer,
                  const std::string& artifact,
                  int file,
                  int piece,
                  int64_t nbytes,
                  int64_t when,
                  bool verified,
                  bool needed,
                  bool paid,
                  int observed_sources,
                  bool unsolicited = false);
    /** Third-party/self-reported receipts never mint useful-free credit. */
    bool CreditThirdPartyReceipt(const std::string& peer, int64_t nbytes, int64_t when);
    int64_t Effective(const std::string& peer, int64_t now) const;
    int Weight(const std::string& peer, int64_t now) const;
    UniValue Snapshot() const;
    bool Load(const UniValue& obj, std::string& err);

    bool TouchesBanMan() const { return false; }
    bool TouchesAddrMan() const { return false; }
    bool ClonesCreditOnKeyRotation() const { return false; }
    int64_t AutomaticSpendAtoms() const { return 0; }
};

/** Per-key/day, per-netgroup/hour, and aggregate bootstrap caps. */
class BootstrapLimiter {
    int64_t m_aggregate_cap{0};
    int64_t m_aggregate_used{0};
    std::map<std::string, int64_t> m_key_day;
    std::map<std::string, int64_t> m_group_hour;

public:
    static constexpr int64_t PER_KEY_DAY = int64_t{256} << 20;
    static constexpr int64_t GROUP_HOUR = int64_t{1} << 30;

    explicit BootstrapLimiter(int64_t aggregate_cap_bytes) : m_aggregate_cap(aggregate_cap_bytes) {}
    bool Allow(const std::string& service_id, const std::string& netgroup, int64_t bytes);
};

std::vector<std::string> LaneSequence(const std::map<std::string, int>& backlogs, int quanta);

struct ReciprocityStatus {
    TrustLabel label{TrustLabel::NEW};
    int weight{1};
    int64_t effective_bytes{0};
};

TrustLabel ClassifyPeer(int64_t effective_bytes, int successful_sessions, int invalid_pieces, bool blocked, bool preferred, bool trusted);

enum class SeedMode : uint8_t {
    OFF = 0,
    MANUAL = 1,
    AUTO = 2,
};

const char* SeedModeName(SeedMode mode);
bool SeedModeFromName(const std::string& name, SeedMode& out);

struct PreservationPolicy {
    SeedMode seed_mode{SeedMode::AUTO};
    /** B0 alias of seed_mode==AUTO. Not an independent opt-in; ShouldDemandSeed ignores it. */
    bool seed_upon_download{true};
    double giveback_ratio{1.0};
    int64_t retain_seconds{7 * DAY_SECONDS};
    uint64_t storage_quota_bytes{0};
    uint64_t upload_bps{0};
    bool preserve_rare{false};
    bool allow_encrypted{false};
    /** Pull FREE seeded models announced by catalog contacts (operator
     *  -modelpeer / addmodelnode, plus PEX-learned endpoints). Not the same
     *  as preserve-rare of arbitrary gossip from unknown advertisers. */
    bool follow_configured_peers{true};
};

/** True when the local give-back target/time is met. Never invents download demand. */
bool GiveBackComplete(const PreservationPolicy& p,
                      int64_t useful_served,
                      int64_t useful_received,
                      int64_t started_at,
                      int64_t now);

enum class EvictClass : uint8_t {
    STALE_PARTIAL = 0,
    EXPIRED_CIPHERTEXT = 1,
    FAILED_UNQUALIFIED = 2,
    COMMON_GIVEBACK_DONE = 3,
    COMMON_UNPINNED = 4,
    DEMAND_SEEDED = 5,
    RARE_SEEDED = 6,
    RECENT = 7,
    PINNED = 8,
};

/** Parse 85899345920, 80GiB, 500G. Binary prefixes (1024). Empty/invalid fails. */
bool ParseModelBytes(const std::string& in, uint64_t& out, std::string& err);

/** Demand-seed after an intentional import/retrieve.
 *  True iff quota > 0 and seed_mode==AUTO. FAILED admission refuses.
 *  seed_upon_download is a B0 alias only; it is not a second gate. */
bool ShouldDemandSeed(const PreservationPolicy& p, AdmissionLevel admission);

/** Unsolicited fetch of a model the operator did not request. */
bool MayPreserveFetch(const PreservationPolicy& p, AdmissionLevel admission, bool encrypted,
                       int observed_sources, uint64_t bytes, uint64_t spare_bytes);

/** Fetch a FREE model announced by a catalog contact (-modelpeer, addmodelnode, PEX).
 *  Requires seed=auto, quota, and that the object fits spare space. */
bool MayFollowConfiguredPeer(const PreservationPolicy& p, AdmissionLevel admission, bool encrypted,
                              uint64_t bytes, uint64_t spare_bytes);

struct PreserveCandidate {
    Digest48 model_id;
    uint64_t bytes{0};
    int observed_sources{0};
    AdmissionLevel admission{AdmissionLevel::DISCOVERED};
    bool encrypted{false};
    std::string peer;
};

/** Deterministic preserve-rare jitter: hash(model_id.Hex() || now/300). now==0 uses bucket 0. */
uint64_t PreserveRareJitterScore(const Digest48& model_id, int64_t now);

/** Pick at most one under-replicated qualified public model that fits spare quota.
 *  Primary order: fewer observed_sources, then fewer bytes. Full ties keep first when now==0;
 *  when now!=0 they break with PreserveRareJitterScore (5-minute buckets). */
bool SelectPreserveRare(const std::vector<PreserveCandidate>& observed,
                        const std::set<Digest48>& local,
                        uint64_t spare_bytes,
                        const PreservationPolicy& p,
                        PreserveCandidate& out,
                        int64_t now = 0);

/** Pick one configured-peer catalog object that fits spare quota. Smaller
 *  first so a mixed catalog still drains instead of stalling on one huge item. */
bool SelectPeerFollow(const std::vector<PreserveCandidate>& observed,
                       const std::set<Digest48>& local,
                       uint64_t spare_bytes,
                       const PreservationPolicy& p,
                       PreserveCandidate& out);

struct EvictItem {
    Digest48 model_id;
    Digest48 artifact_id;
    bool pinned{false};
    bool seeded{false};
    int observed_sources{0};
    uint64_t bytes{0};
    bool incomplete{false};
    bool expired_ciphertext{false};
    bool failed_unqualified{false};
    bool giveback_complete{false};
    bool recently_protected{false};
    int64_t last_access_at{0};
};

/** Lower is evicted first. Pinned is never selected. Numeric values for
 *  unpinned-common / rare / seeded / pin stay stable for existing tests. */
int EvictPriority(const EvictItem& item);

UniValue PolicyToJson(const PreservationPolicy& p);
bool PolicyFromJson(const UniValue& obj, PreservationPolicy& p, std::string& err);

constexpr size_t COLLECTION_MAX_ENTRIES = 512;
/** Sort unique; reject >512. Collections never qualify files or load code. */
bool NormalizeCollection(std::vector<Digest48>& ids, std::string& err);

struct AliasMapping {
    std::string slug;
    uint64_t sequence{0};
    Digest48 target;
    uint8_t target_kind{0};
    bool frozen{false};
};

/** Sequence conflict freezes the prior mapping. Alias-to-alias is rejected. */
bool ApplyAlias(AliasMapping& st, uint64_t sequence, uint8_t target_kind, const Digest48& target, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_POLICY_H
