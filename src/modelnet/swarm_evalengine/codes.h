// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EVALENGINE_CODES_H
#define BITCOIN_MODELNET_SWARM_EVALENGINE_CODES_H

#include <string>

namespace modelnet {

/** Empty experiment id, or the experiment is not open. Nothing is stored. */
inline constexpr char kSwarmEvaluationExperiment[] = "EXPERIMENT";

/** The id, pair, suite, challenge validation, or certificate is already stored. The first stays. */
inline constexpr char kSwarmEvaluationReplay[] = "REPLAY";

/** Empty candidate, unknown experiment on a report, or the candidate is not bound. */
inline constexpr char kSwarmEvaluationCandidate[] = "CANDIDATE";

/** Empty suite id. Nothing is stored. */
inline constexpr char kSwarmEvaluationSuite[] = "SUITE";

/** The experiment has no precommitted suite. The report is not stored. */
inline constexpr char kSwarmEvaluationNotPrecommitted[] = "NOT_PRECOMMITTED";

/** Author and evaluator are the same. Not an accepting report. */
inline constexpr char kSwarmEvaluationSelf[] = "SELF";

/** Author domain and evaluator domain are the same. Not an accepting report. */
inline constexpr char kSwarmEvaluationNotQuorum[] = "NOT_QUORUM";

/** The author can see the holdout. Not an accepting report. */
inline constexpr char kSwarmEvaluationHoldout[] = "HOLDOUT";

/** Safety regression. A regression report is stored. Not an accepting report. */
inline constexpr char kSwarmEvaluationSafety[] = "SAFETY";

/** Broad regression, or promotion of a candidate that has a regression report. */
inline constexpr char kSwarmEvaluationRegression[] = "REGRESSION";

/** Empty challenge id, or the challenge is not stored. */
inline constexpr char kSwarmEvaluationChallenge[] = "CHALLENGE";

/** The challenge is not informative or not solvable. Nothing is stored. */
inline constexpr char kSwarmEvaluationNotChallenge[] = "NOT_CHALLENGE";

/** Validation was not independent. The challenge stays unvalidated. */
inline constexpr char kSwarmEvaluationNotValidated[] = "NOT_VALIDATED";

/** The candidate is not qualified, or it is not promoted. */
inline constexpr char kSwarmEvaluationNotGraduated[] = "NOT_GRADUATED";

/** Channel policy is not follow, pin, or refuse. */
inline constexpr char kSwarmEvaluationPolicy[] = "POLICY";

/** Adopt found no staged head. */
inline constexpr char kSwarmEvaluationNotStaged[] = "NOT_STAGED";

inline constexpr char kSwarmEvaluationPolicyFollow[] = "follow";
inline constexpr char kSwarmEvaluationPolicyPin[] = "pin";
inline constexpr char kSwarmEvaluationPolicyRefuse[] = "refuse";

inline bool SwarmEvaluationRefuse(std::string& err, const char* code)
{
    err = code;
    return false;
}

inline bool SwarmEvaluationAccept(std::string& err)
{
    err.clear();
    return true;
}

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EVALENGINE_CODES_H
