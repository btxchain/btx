// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PAYMESH_H
#define BITCOIN_MODELNET_SWARM_PAYMESH_H

#include <primitives/transaction.h>

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace modelnet {

inline constexpr std::string_view SWARM_SEP_PROTOCOL{"BTX-SEP/1"};
inline constexpr std::string_view SWARM_WALLET_KEY_CUSTODY{"external"};
/** The scheduler never receives a spend key. This stays the string "0". */
inline constexpr std::string_view SWARM_AUTOMATIC_SPEND_ATOMS{"0"};
inline constexpr int SWARM_CLOSE_MARGIN{160};
inline constexpr int64_t SWARM_PPM_TOTAL{1000000};

/** No spend key is ever handed to the scheduler. */
inline bool SwarmSchedulerHasSpendKey() { return false; }

struct SwarmSepManifest {
    std::string protocol{"BTX-SEP/1"};
    std::string network;
    std::string lineage_id;
    std::string checkpoint_id;
    std::string objective_type;
    std::string recipe_id;
    std::string policy_id;
    std::string nonce;
    int policy_epoch{0};
    std::string parent_pool;
    std::string gross_budget_atoms;
    bool conditional_release{false};
    std::string wallet_key_custody{"external"};
    std::string automatic_spend_atoms{"0"};
};

bool SwarmValidateManifest(const SwarmSepManifest& manifest, std::string& err);

/**
 * Pool id for an unchanged epoch. Domain BTX/SwarmPool/1 over the canonical
 * chain, lineage, nonce, objective, and policy. policy_epoch is not an input.
 * Named apart from SwarmPoolId(SwarmPoolCommit) in swarm_economy.
 */
std::string SwarmManifestPoolId(const SwarmSepManifest& manifest, std::string& err);

/**
 * Same pool id when policy_epoch is unchanged. An increased epoch returns a
 * different id: BTX/SwarmPoolEpoch/1 over that pool id plus the epoch decimal.
 * Stored obligations are not moved.
 */
std::string SwarmNextEpoch(const SwarmSepManifest& old_manifest, const SwarmSepManifest& new_manifest, std::string& err);

class SwarmObligationBook {
public:
    /** work_id is unique inside one pool. A second Add does not increase atoms. */
    bool Add(const std::string& pool, const std::string& work_id, int64_t atoms, std::string& err);
    int64_t Atoms(const std::string& pool, const std::string& work_id) const;

private:
    std::map<std::string, std::map<std::string, int64_t>> m_atoms;
};

struct SwarmRewardSplit {
    int64_t rollout_ppm{0};
    int64_t negative_ppm{0};
    int64_t reproduction_ppm{0};
    int64_t evaluation_ppm{0};
    int64_t challenger_ppm{0};
    int64_t milestone_ppm{0};
};

bool SwarmValidateSplit(const SwarmRewardSplit& split, std::string& err);
int64_t SwarmPayShare(int64_t gross, int64_t ppm);
/** True only for milestone 1000000 and every other ppm 0. That split is still a valid contract. */
bool SwarmWinnerTakeAll(const SwarmRewardSplit& split);

/** State check of published, funded, leased, paid, frontier, graduated. Not a broadcast. */
bool SwarmWorkCycle(bool published, bool funded, bool leased, bool paid, bool frontier, bool graduated, std::string& err);

/**
 * In-memory channel template. refund and payout are never broadcast.
 * No spend key is stored.
 */
struct SwarmChannelTx {
    CMutableTransaction refund;
    CMutableTransaction payout;
    bool refund_signed{false};
    bool funded{false};
    int64_t capacity{0};
    int64_t fee_reserve{0};
    int64_t cumulative{0};
    int refund_height{0};
    int sequence{0};
    std::vector<unsigned char> sponsor_pubkey;
    std::vector<unsigned char> worker_pubkey;
};

bool SwarmBuildRefund(SwarmChannelTx& tx, std::string& err);
bool SwarmNoteChannelFunding(SwarmChannelTx& tx, std::string& err);
/**
 * refund_height must match the stored height. The resulting payout is an
 * in-memory CMutableTransaction and is not broadcast.
 */
bool SwarmBuildPayout(SwarmChannelTx& tx, int64_t cumulative, int height, int refund_height, std::string& err);
bool SwarmClaimBeforeRefund(int height, int refund_height);

struct SwarmRevocation {
    int sequence{0};
    std::vector<unsigned char> secret;
    std::string hash_hex;
    bool released{false};
};

SwarmRevocation SwarmNewRevocation(int sequence, unsigned char fill);
bool SwarmSupersede(SwarmRevocation& prior, const SwarmRevocation& next, std::string& err);
std::vector<unsigned char> SwarmRemedyScript(const std::vector<unsigned char>& secret_hash,
                                             const std::vector<unsigned char>& counterparty_pubkey);

struct SwarmRemedyReport {
    std::string action;
    bool secp_penalty{false};
    bool hashlock_remedy{false};
};

SwarmRemedyReport SwarmWatchState(int observed_sequence, int latest_sequence, int height, int refund_height, int margin,
                                  const SwarmRevocation& prior);

struct SwarmInvoice {
    std::string id;
    int64_t amount{0};
    std::string beneficiary;
    std::string objective;
    std::string route_id;
    std::string preimage_hash;
};

bool SwarmBindPreimage(const SwarmInvoice& invoice, const std::vector<unsigned char>& preimage32, std::string& err);
bool SwarmReusePreimage(std::set<std::string>& seen, const std::string& hash, std::string& err);

bool SwarmRouteMargin(int incoming_expiry, int outgoing_expiry, int margin, std::string& err);
bool SwarmForwardAllowed(bool incoming_committed, int64_t liquidity, int64_t amount, int incoming_expiry, int height, int margin,
                         std::string& err);
bool SwarmStopNewWork(int height, int refund_height, int margin);

class SwarmCollateralBook {
public:
    std::string FirstPool(const std::string& outpoint) const;

private:
    friend bool SwarmSameCollateral(SwarmCollateralBook& book, const std::string& pool_a, const std::string& pool_b,
                                    const std::string& outpoint, std::string& err);
    std::map<std::string, std::string> m_first_pool;
};

bool SwarmSameCollateral(SwarmCollateralBook& book, const std::string& pool_a, const std::string& pool_b,
                         const std::string& outpoint, std::string& err);

struct SwarmFiatRecord {
    std::string usd;
    bool converted{false};
    std::string btx_atoms;
    std::string fx_timestamp;
    std::string conversion_cost;
    std::string risk_holder;
    bool usd_is_balance{false};
};

bool SwarmRecordFiat(SwarmFiatRecord& record, std::string& err);

/** "work-payment" is accepted. "profit-share" is refused. */
bool SwarmAcceptInstrument(const std::string& kind, std::string& err);

/** Both true is NOT_TAXABLE and creates no obligation. */
bool SwarmTaxOpenInference(bool open_license, bool local_execution, std::string& err);

/**
 * ceil(closes * bytes_per_close / block_bytes). The three inputs are
 * assumptions. This is not a measured channel size.
 */
int64_t SwarmMassExit(int64_t closes, int64_t bytes_per_close, int64_t block_bytes);

struct SwarmMiningNote {
    int64_t swarm_atoms_per_hour{0};
    int64_t mining_atoms_per_hour{0};
    bool hash_left_mining{false};
};

struct SwarmMiningDisplacementResult {
    int64_t advantage{0};
    bool security_increased{false};
};

SwarmMiningDisplacementResult SwarmMiningDisplacement(const SwarmMiningNote& note);

struct SwarmRecoverySnapshot {
    int pending_jobs{0};
    int64_t earned_atoms{0};
    int channel_sequence{0};
    bool checkpoint_present{false};
    bool payment_plane_present{false};
    bool execution_plane_present{false};
    bool frozen{false};
};

bool SwarmCoordinatorLost(const SwarmRecoverySnapshot& in, SwarmRecoverySnapshot& out, std::string& err);
bool SwarmObsoleteSettlement(int64_t offered_cumulative, int64_t best_cumulative, std::string& err);
int64_t SwarmWorkerDisconnected(int64_t earned_atoms);
bool SwarmConflictingValidators(bool& accepted, std::string& err);
bool SwarmExpiryPressure(int height, int expiry, int margin);
SwarmRecoverySnapshot SwarmReorgExit(SwarmRecoverySnapshot snapshot);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PAYMESH_H
