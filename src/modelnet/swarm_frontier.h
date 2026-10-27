// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FRONTIER_H
#define BITCOIN_MODELNET_SWARM_FRONTIER_H

#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace modelnet {

/** The only spend value these records expose. There is no spend key. */
inline constexpr char kSwarmAutomaticSpendAtoms[] = "0";

struct SwarmEvalCommitment {
    std::string suite_id;
    std::string holdout_commitment;
    std::string pool_id;
    bool committed_before_score{false};
};

struct SwarmEvalResult {
    std::string candidate_id;
    std::string pool_id;
    int64_t score_ppm{0};
    bool negative{false};
    bool reproducible{false};
};

/** In-memory evaluation log. Several pool ids may be recorded together. */
class SwarmEvalBoard {
public:
    void Append(const SwarmEvalResult& result);
    std::vector<SwarmEvalResult> ForPool(const std::string& pool_id) const;

private:
    std::vector<SwarmEvalResult> m_results;
};

/** SUITE_NOT_PRECOMMITTED, or HOLDOUT_LEAKED when the author can see the holdout. */
bool SwarmBeginEvaluation(const SwarmEvalCommitment& commitment, bool author_sees_holdout, std::string& err);

/** Appends the result, including a negative score. */
bool SwarmRecordResult(SwarmEvalBoard& board, const SwarmEvalResult& result, std::string& err);

std::vector<SwarmEvalResult> SwarmResultsForPool(const SwarmEvalBoard& board, const std::string& pool_id);

struct SwarmFitnessVote {
    std::string voter;
    std::string author;
    bool independent{false};
    bool accepted{false};
};

/**
 * True only when an independent voter who is not the author accepted.
 * err is ACCEPTED or SOLE_AUTHOR.
 */
bool SwarmFitnessChangeAllowed(const std::vector<SwarmFitnessVote>& votes, std::string& err);

struct SwarmChallenge {
    std::string id;
    bool informative{false};
    bool solvable{false};
    bool independent_validation{false};
    bool affects_fitness{false};
};

/** CHALLENGE_UNINFORMATIVE or CHALLENGE_UNVALIDATED. Success sets affects_fitness. */
bool SwarmAcceptChallenge(SwarmChallenge& challenge, std::string& err);

/** BTX/ExperimentManifest/1. data_grant must be true or err is DATA_GRANT. */
std::string SwarmExperimentId(const std::string& parent, const std::string& recipe, bool data_grant, std::string& err);

struct SwarmCandidateRecord {
    std::string id;
    std::string parent;
    std::string recipe;
    std::string weights;
    std::string provenance;
    std::string nonce;
    std::string automatic_spend_atoms{kSwarmAutomaticSpendAtoms};
};

/** id is BTX/CandidateCheckpoint/1 over parent, recipe, weights, and nonce. */
SwarmCandidateRecord SwarmMakeCandidateRecord(const std::string& parent, const std::string& recipe,
                                              const std::string& weights, const std::string& nonce,
                                              const std::string& provenance, std::string& err);

/** BTX/PromotionCertificate/1. Empty evidence or a failed quorum is PROMOTION_EVIDENCE. */
std::string SwarmPromotionId(const std::string& candidate, const std::string& channel,
                             const std::string& evidence_digest, bool quorum_ok, std::string& err);

struct SwarmHead {
    std::string channel;
    std::string candidate;
    int64_t sequence{0};
};

/** Append-only heads. A publish on one channel leaves every other channel in place. */
class SwarmHeadLog {
public:
    void Append(const SwarmHead& head);
    const std::vector<SwarmHead>& Heads() const;

private:
    std::vector<SwarmHead> m_heads;
};

void SwarmPublishHead(SwarmHeadLog& log, const SwarmHead& head);
std::vector<SwarmHead> SwarmVisibleHeads(const SwarmHeadLog& log);

enum class SwarmReleasePolicy { Follow, Pin, Refuse };

/**
 * Active id after a local policy decision.
 * Follow adopts staged when the node is compatible.
 * Pin keeps previous. Refuse keeps previous and sets RELEASE_REFUSED.
 * An incompatible node sets LOCAL_INCOMPATIBLE and does not adopt.
 */
std::string SwarmAdopt(SwarmReleasePolicy policy, const std::string& previous, const std::string& staged_candidate,
                       bool local_compatible, std::string& err);

struct SwarmGradEffect {
    bool quality_graduated{false};
    bool realm_promoted{false};
    bool exact_replay_admitted{false};
};

/** Quality may graduate. Realm promotion and ExactReplay admission stay false. */
SwarmGradEffect SwarmGraduate(bool quality);

/** total_weight <= 0 is INFLUENCE. A share above cap_ppm is INFLUENCE_CAP. */
bool SwarmInfluenceCap(int64_t untrusted_weight, int64_t total_weight, int64_t cap_ppm, std::string& err);

/** True when the score is farther from the median than max_deviation_ppm. */
bool SwarmAnomaly(int64_t score_ppm, int64_t median_ppm, int64_t max_deviation_ppm);

struct SwarmQuarantineSet {
    std::set<std::string> digests;
};

void SwarmQuarantineDigest(SwarmQuarantineSet& quarantine, const std::string& digest);
bool SwarmDigestBlocked(const SwarmQuarantineSet& quarantine, const std::string& digest);

/** False when either regression flag is set. */
bool SwarmSafetyAllowsGraduation(bool safety_regression, bool broad_regression);

/** prompt, repository, and credential are PRIVATE_DATA. Public and synthetic trajectories are allowed. */
bool SwarmContributionKind(const std::string& kind, std::string& err);

/** True only when the download license, the operator grant, and the training clause are all set. */
bool SwarmTrainingGrant(bool download_license, bool operator_grant, bool license_allows_training);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FRONTIER_H
