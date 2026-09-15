// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_ECONOMY_H
#define BITCOIN_MODELNET_ECONOMY_H

#include <modelnet/release.h>
#include <modelnet/search.h>
#include <univalue.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace modelnet {

constexpr int ECONOMY_SCHEMA_VERSION = 3;
constexpr int64_t COIN_ATOMS = 100000000;

/** Public API lifecycle labels. Not consensus / not fork-choice. */
enum class ModelLifecycle {
    PUBLIC = 0,
    FUNDING,
    FUNDING_FROZEN,
    FUNDED_AWAITING_RELEASE,
    SECRET_DISCLOSED,
    UNLOCKING,
    PUBLIC_RELEASED,
    REFUND_AVAILABLE,
    RELEASE_EXPIRED,
    UNAVAILABLE,
};

enum class ModelResultType {
    PUBLIC_MODEL = 0,
    RELEASE_CAMPAIGN,
    FUNDED_PENDING_RELEASE,
    JUST_RELEASED_MODEL,
    LOCAL_MODEL,
};

enum class RefundStatus {
    UNKNOWN = 0,
    NOT_MATURE,
    AVAILABLE,
    CLAIM_COMPETING,
    REFUNDED,
};

enum class EconomyAction {
    DOWNLOAD = 0,
    KEEP,
    COPY_URI,
    VIEW_RELEASE,
    FUND_RELEASE,
    WAIT_FOR_UNLOCK,
    CACHE_ENCRYPTED,
    REFUND,
};

/** Chain/wallet observations are distinct from helper/model-plane state. */
struct FundingObservation {
    bool confirmed_known{false};
    bool pending_known{false};
    int64_t confirmed_funded_atoms{0};
    int64_t pending_funded_atoms{0};
    uint32_t chain_height{0};
    bool chain_height_known{false};
    bool wallet_contributor{false};
    bool refund_available_locally{false};
    RefundStatus refund_status{RefundStatus::UNKNOWN};
    std::string claim_txid;
    int64_t reveal_height{0};
    int64_t reveal_time{0};
    std::string funding_source{"UNKNOWN"};
    bool unlocking_locally{false};
    int ciphertext_providers_observed{0};
};

struct ModelEconomyEntry {
    int schema_version{ECONOMY_SCHEMA_VERSION};
    SearchHit hit;
    ReleaseCampaign campaign;
    bool has_campaign{false};
    FundingObservation fund;
    ModelLifecycle lifecycle{ModelLifecycle::UNAVAILABLE};
    ModelResultType result_type{ModelResultType::PUBLIC_MODEL};
    std::vector<EconomyAction> actions;
    bool downloadable_now{false};
    bool downloadable_plaintext{false};
    bool fundable_now{false};
    bool ciphertext_available{false};
    bool ciphertext_cacheable{false};
    bool refund_available_locally{false};
    bool requires_wallet{false};
    bool requires_user_approval{false};
    bool value_known{false};
    int64_t remaining_atoms{0};
    int64_t funded_percent_milli{0};  // 74200 = 74.2%; display only
    int64_t pledged_percent_milli{0};
    bool funded_percent_known{false};
    bool pledged_percent_known{false};
    int64_t first_seen_at{0};
};

const char* ModelLifecycleName(ModelLifecycle s);
bool ParseModelLifecycle(const std::string& s, ModelLifecycle& out);
const char* ModelResultTypeName(ModelResultType t);
const char* RefundStatusName(RefundStatus s);
const char* EconomyActionName(EconomyAction a);

bool LifecycleIsFundable(ModelLifecycle s);
bool LifecycleIsPublic(ModelLifecycle s);

/** Integer-safe display percent: milli = confirmed * 100000 / target (74.2% → 74200). */
bool FundedPercentMilli(int64_t funded_atoms, int64_t target_atoms, int64_t& milli_out);
int64_t RemainingAtoms(int64_t target_atoms, int64_t confirmed_funded_atoms);
double MilliToDisplayPercent(int64_t milli);

ReleaseCampaign CampaignFromSearchRecord(const ModelSearchRecord& r);
ModelLifecycle DeriveLifecycle(const SearchHit& h, const ReleaseCampaign* campaign,
                                const FundingObservation& fund);
ModelResultType ResultTypeFrom(ModelLifecycle s, const DirectoryLocalState& local);
std::vector<EconomyAction> RecommendActions(const ModelEconomyEntry& e);

ModelEconomyEntry ComposeEconomyEntry(const SearchHit& h, const ReleaseCampaign* campaign,
                                       const FundingObservation& fund);

bool MatchesEconomyFilters(const ModelEconomyEntry& e, const SearchFilters& f);
void SortEconomyEntries(std::vector<ModelEconomyEntry>& entries, SearchSort sort);

UniValue EconomyEntryToJson(const ModelEconomyEntry& e);
UniValue EconomyReleaseJson(const ModelEconomyEntry& e);
UniValue EconomyActionsJson(const std::vector<EconomyAction>& actions);
UniValue EconomyLifecycleJson(const ModelEconomyEntry& e);

/** Join search card + economics. Keeps v2 directory keys. */
UniValue EconomySearchCard(const ModelEconomyEntry& e);

/** Join chain/wallet observation onto a schema-3 economy or release JSON object.
 *  Never copies wallet secrets. Remote unsigned "fully funded" claims are ignored. */
void ApplyChainObservationJson(UniValue& card, const UniValue& obs);

bool EconomyTouchesMonetaryConsensus();
int64_t AutomaticSpendAtoms();

} // namespace modelnet

#endif // BITCOIN_MODELNET_ECONOMY_H
