// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NODE_H
#define BTX_MODELNET_SWARM_NODE_H

#include <modelnet/swarm_records.h>

#include <primitives/transaction.h>
#include <uint256.h>

#include <cstdint>
#include <string>
#include <vector>

class PartiallySignedTransaction;

namespace modelnet {

/** What a stock btxd offers. No startup flag selects this.
 *  seed_public and cpu_evaluate follow the governor snapshot.
 *  hardware_threads is a host capability, not a grant.
 */
struct SwarmBuiltinOffer {
    bool seed_public{false};
    bool cpu_evaluate{false};
    bool gpu_train{false};
    bool private_prompts{false};
    bool startup_flag{false};
    int cpu_threads{0};
    int hardware_threads{0};
    int64_t vram_bytes{0};
    std::string automatic_spend_atoms{"0"};
};

/** Stock snapshot: one idle slot, no authorized CPU threads, no GPU, no spend. */
SwarmBuiltinOffer SwarmDefaultOffer();

/**
 * A verified catalog row joins its lineage family. It enters a training cohort
 * when full-precision quantization, checkpoint, and recipe match that cohort.
 * kv_share stays false unless weights, tokenizer, adapter order, runtime,
 * layout, dtype, positional encoding, and mask are present and equal.
 * A 4-bit row stays in the family. SwarmAssignCohort leaves kv_share false.
 */
struct SwarmCohortDecision {
    bool family{false};
    bool cohort{false};
    bool kv_share{false};
    std::string quantization;
};

SwarmCohortDecision SwarmAssignCohort(const std::string& quantization, const std::string& checkpoint,
                                      const std::string& recipe, const std::string& family_checkpoint,
                                      const std::string& family_recipe);

/**
 * Write lineage, economy identity, family membership, and acquire state for
 * every byte-verified, explicitly complete catalog row, using the observer's
 * lineage and visibility resolver. Checkpoint and recipe stay on the row.
 * Families group by lineage. A cohort also shares checkpoint and recipe.
 * Offers and per-model seed follow the same governor snapshot as the mesh.
 * A missing catalog writes an empty model list. Invalid input fails without
 * replacing the previous snapshot. An unchanged document is not rewritten.
 * This does not broadcast and does not spend.
 */
bool SwarmIntegrateCatalog(const fs::path& modeldir, std::string& err);

/** Remember a verified presence. The same signature a second time is a replay. */
bool SwarmNotePresence(const fs::path& modeldir, const SwarmPresence& presence, int64_t now_ms, std::string& err);

struct SwarmSepPolicy {
    int expiry_height{0};
    std::string backing_manifest;
    std::string liquidity_policy;
    int max_pending{0};
    std::string settlement_policy;
    std::string reward_schedule;
    std::string dispute_policy;
    std::vector<std::string> evidence;
    int quorum{0};
    std::string coordinator_id;
    int64_t spend_limit{0};
    std::string custody{"external"};
};

bool SwarmValidateSepPolicy(const SwarmSepPolicy& policy, std::string& err);

struct SwarmFundingBundle {
    CMutableTransaction funding;
    CMutableTransaction refund;
    bool refund_bound{false};
    bool funded{false};
};

/**
 * 2-of-2 funding output and a refund that spends that outpoint. Funding counts
 * only after the refund is bound to it. Nothing is broadcast.
 */
bool SwarmBuildFunding(const std::vector<unsigned char>& sponsor, const std::vector<unsigned char>& worker,
                       int64_t value, int64_t refund_height, SwarmFundingBundle& out, std::string& err);

/** Wrap the bound refund as a PSBT. Fails when the refund does not spend the funding outpoint. */
bool SwarmRefundPsbt(const SwarmFundingBundle& bundle, PartiallySignedTransaction& psbt, std::string& err);

/**
 * Worker payout spending the same funding outpoint. The cumulative amount goes
 * to the worker and the remainder to the sponsor.
 */
bool SwarmBuildWorkerRedeem(const Txid& funding, int64_t capacity, int64_t previous, int64_t cumulative,
                            int height, int refund_height, const std::vector<unsigned char>& worker_script,
                            const std::vector<unsigned char>& sponsor_script, CMutableTransaction& tx,
                            std::string& err);

/** CTV-bound evaluator threshold. The sponsor refund key is not an argument. */
std::vector<unsigned char> SwarmCtvRelease(const uint256& claimant, uint8_t threshold,
                                           const std::vector<std::vector<unsigned char>>& pubkeys, std::string& err);

struct SwarmClaimFees {
    int64_t claim_fee{0};
    int64_t child_fee{0};
    bool wall_clock_is_confirmation{false};
};

bool SwarmFeeBump(int64_t parent_value, int64_t claim_fee, int64_t child_fee, CMutableTransaction& parent,
                  CMutableTransaction& child, SwarmClaimFees& fees, std::string& err);

/** Drop the failed hop and every hop closer to the sender. */
bool SwarmReleaseUpstream(std::vector<bool>& held, size_t failed_index, std::string& err);

int SwarmIncomingSlack(int hops, int margin_blocks);

struct SwarmFullCost {
    int64_t reward_per_hour{0};
    int64_t accept_ppm{0};
    int64_t expense{0};
    int64_t mining{0};
    int64_t depreciation{0};
    int64_t idle{0};
    int64_t duration{0};
    int64_t settlement_fee{0};
    int64_t fx_risk{0};
    bool backing_verified{false};
    bool payment_demonstrated{false};
    bool terms_signed{false};
};

bool SwarmRankFull(const SwarmFullCost& cost, int64_t& net, std::string& err);

bool SwarmLeaseIsland(const std::string& island_checkpoint, const std::string& island_recipe,
                      const std::string& work_checkpoint, const std::string& work_recipe, std::string& err);

struct SwarmGrants {
    bool download{false};
    bool training{false};
    bool redistribution{false};
};

bool SwarmGrantAllowsTraining(const SwarmGrants& grants);
bool SwarmGrantAllowsRedistribution(const SwarmGrants& grants);

bool SwarmRotateHoldout(const std::string& previous, const std::string& next, bool author_sees, std::string& err);

bool SwarmStoreSpecialistSignal(const fs::path& modeldir, const std::string& kind, const std::string& payload,
                                std::string& err);

struct SwarmPayoutQuote {
    std::string provider_id;
    int64_t atoms{0};
    int64_t fx_unix{0};
    int64_t conversion_cost_atoms{0};
    std::string risk_holder;
    std::string dollars;
    bool usd_is_balance{false};
};

bool SwarmRecordPayoutQuote(const std::string& provider_id, int64_t atoms, int64_t fx_unix,
                            int64_t conversion_cost_atoms, const std::string& risk_holder, const std::string& dollars,
                            SwarmPayoutQuote& out, std::string& err);

bool SwarmModelFileCreatesObligation(bool revenue_manifest_attached);

bool SwarmStoreMiningNote(const fs::path& modeldir, int64_t swarm_atoms_per_hour, int64_t mining_atoms_per_hour,
                          std::string& err);

bool SwarmStoreWatchtower(const fs::path& modeldir, const std::string& action, int64_t sequence,
                          const std::string& secret_hex, std::string& err);
bool SwarmLoadWatchtower(const fs::path& modeldir, std::string& action, int64_t& sequence, std::string& secret_hex,
                         std::string& err);

bool SwarmStoreAudit(const fs::path& modeldir, const std::string& certificate_id, const std::string& economy_id,
                     std::string& err);
bool SwarmLoadAudit(const fs::path& modeldir, std::string& certificate_id, std::string& economy_id,
                    bool& realm_promotion, bool& exact_replay, std::string& err);

} // namespace modelnet

#endif
