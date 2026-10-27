// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_RECORDS_H
#define BITCOIN_MODELNET_SWARM_RECORDS_H

#include <uint256.h>
#include <util/fs.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/** One model family. Ancestry is ordered from the root through this record. */
struct ModelLineage {
    std::string lineage_id;
    std::string parent_lineage;
    std::string architecture;
    std::string license_id;
    bool license_allows_training{false};
    std::vector<std::string> ancestry;
};

/**
 * Mint a lineage id. Refuses an empty architecture or an empty license.
 * A root has an empty parent_lineage. parent_ancestry is the parent's ordered
 * ancestry (empty for a root).
 */
bool SwarmMakeLineage(const std::string& parent_lineage, const std::vector<std::string>& parent_ancestry,
                      const std::string& architecture, const std::string& license_id, bool license_allows_training,
                      ModelLineage& out, std::string& err);

/** True only when the license allows training and the operator granted it. */
bool SwarmLineageAllowsTraining(const ModelLineage& lineage, bool operator_grant);

/** Four swarm networks stored together. automatic_spend_atoms stays "0". */
struct SwarmNetworks {
    struct Family {
        std::string lineage_id;
        std::vector<std::string> member_artifact_ids;
    };
    struct Neighborhood {
        std::vector<std::string> peer_ids;
    };
    struct Cohort {
        std::string checkpoint_id;
        std::string recipe_id;
        std::vector<std::string> member_ids;
        int lease_slots{0};
        int64_t lease_until_ms{0};
    };
    struct Frontier {
        std::vector<std::string> candidate_ids;
    };

    Family family;
    Neighborhood neighborhood;
    Cohort cohort;
    Frontier frontier;
    std::string automatic_spend_atoms{"0"};
};

/** Write modeldir/swarm/networks.json. */
bool SwarmStoreNetworks(const fs::path& modeldir, const SwarmNetworks& networks, std::string& err);

/** Missing file yields an empty record. Unreadable JSON sets NETWORKS_JSON. */
bool SwarmLoadNetworks(const fs::path& modeldir, SwarmNetworks& out, std::string& err);

/**
 * A peer announcement. No field on this record authorizes a spend.
 * claims_checkpoint_only is a checkpoint advertisement, not trust.
 */
struct SwarmPresence {
    std::string peer_id;
    std::string endpoint;
    std::vector<std::string> capabilities;
    std::string trust_domain;
    int64_t expiry_ms{0};
    std::string signature_hex;
    std::vector<unsigned char> pubkey;
    bool claims_checkpoint_only{false};
};

/** Hash covered by the ML-DSA presence signature. */
uint256 SwarmPresenceHash(const SwarmPresence& presence);

/**
 * Reject expiry, a missing signature, a signature that does not verify against
 * pubkey, and a checkpoint-only claim. A non-empty hex string is not enough.
 */
bool SwarmAcceptPresence(const SwarmPresence& presence, int64_t now_ms, std::string& err);

/** One already-known peer that may be used as an extra route. */
struct SwarmRoutePeer {
    std::string id;
    std::string domain;
    bool authorized{false};
    bool available{false};
    int64_t rtt_us{0};
};

/**
 * After a neighborhood has been chosen, up to max_routes additional authorized
 * available peers that are not in `chosen`, ordered by rtt_us then id.
 */
std::vector<SwarmRoutePeer> SwarmFallbackRoutes(const std::vector<SwarmRoutePeer>& peers,
                                                const std::vector<std::string>& chosen, int max_routes);

enum class SwarmAcquireStep { Verify, Join, Load, Use, Offer, Stage, Specialist };

/** Acquire flags. private_prompts stays false. automatic_spend_atoms stays "0". */
struct SwarmAcquireState {
    bool verified{false};
    bool joined{false};
    std::string visibility;
    bool private_prompts{false};
    std::string automatic_spend_atoms{"0"};
    bool discovered_runtime{false};
    bool used{false};
    bool offered{false};
    bool staged{false};
    bool specialist_published{false};
    bool general_replaced{false};
};

/**
 * Advance one acquire step from `prior`. Verify fails closed when unverified
 * and does not join. Specialist publishes a specialist and leaves the general
 * model in place (general_replaced stays false).
 */
SwarmAcquireState SwarmAdvanceAcquire(SwarmAcquireStep step, const SwarmAcquireState& prior, bool verified,
                                      bool visibility_private, bool idle_allowed, bool specialist,
                                      bool generation_passed, std::string& err);

struct SwarmCompat {
    std::string lineage;
    std::string checkpoint;
    std::string quantization;
    std::string recipe;
};

bool SwarmSameFamily(const SwarmCompat& a, const SwarmCompat& b);
bool SwarmKvCompatible(const SwarmCompat& a, const SwarmCompat& b);
bool SwarmTrainCompatible(const SwarmCompat& a, const SwarmCompat& b);

/** Timescale knowledge. kind "prompt" is refused and is never stored. */
struct SwarmKnowledge {
    std::string kind;
    std::string id;
    std::string body_digest;
    std::string visibility;
};

/** Append one record to modeldir/swarm/knowledge.json. */
bool SwarmStoreKnowledge(const fs::path& modeldir, const SwarmKnowledge& record, std::string& err);

/** Missing file yields an empty list. */
bool SwarmLoadKnowledge(const fs::path& modeldir, std::vector<SwarmKnowledge>& out, std::string& err);

/** Records whose visibility is public. Prompt rows are omitted. */
std::vector<SwarmKnowledge> SwarmPublicKnowledge(const std::vector<SwarmKnowledge>& records);

struct SwarmIsland {
    std::string id;
    std::string checkpoint;
    std::string recipe;
    bool local_only{false};
    bool compatible_average{false};
};

/** Exchange only when checkpoint and recipe match and neither island is local. */
bool SwarmMayExchangeUpdates(const SwarmIsland& a, const SwarmIsland& b);

/** New island id. compatible_average is false: a fork is not an average. */
SwarmIsland SwarmForkBranch(const SwarmIsland& parent, const std::string& checkpoint, const std::string& recipe,
                            std::string& err);

/** A merge proposal. method is EVALUATED_MERGE or DISTILL, never an average. */
struct SwarmMergeProposal {
    std::string method;
    bool accepted{false};
    std::string automatic_spend_atoms{"0"};
};

SwarmMergeProposal SwarmProposeMerge(const std::string& method, bool independent_evaluation, std::string& err);

/** A peer that already holds a KV page range. Selection does not move bytes. */
struct SwarmPageHolder {
    std::string peer_id;
    std::string fingerprint;
    int page_start{0};
    int page_end{0};
};

struct SwarmKvSelection {
    std::string peer_id;
    bool bytes_moved{false};
};

/**
 * Peer whose fingerprint matches and whose range covers [page_start, page_end).
 * Lineage is not an input. No holder sets KV_NO_HOLDER and leaves bytes_moved false.
 */
bool SwarmSelectKvHolder(const std::vector<SwarmPageHolder>& holders, const std::string& wanted_fingerprint,
                         int page_start, int page_end, SwarmKvSelection& out, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_RECORDS_H
