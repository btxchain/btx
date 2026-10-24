// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_frontier.h>

#include <modelnet/swarm_codec.h>

namespace modelnet {

void SwarmEvalBoard::Append(const SwarmEvalResult& result)
{
    m_results.push_back(result);
}

std::vector<SwarmEvalResult> SwarmEvalBoard::ForPool(const std::string& pool_id) const
{
    std::vector<SwarmEvalResult> out;
    for (const SwarmEvalResult& result : m_results) {
        if (result.pool_id == pool_id) out.push_back(result);
    }
    return out;
}

bool SwarmBeginEvaluation(const SwarmEvalCommitment& commitment, bool author_sees_holdout, std::string& err)
{
    if (!commitment.committed_before_score) {
        err = "SUITE_NOT_PRECOMMITTED";
        return false;
    }
    if (author_sees_holdout) {
        err = "HOLDOUT_LEAKED";
        return false;
    }
    err.clear();
    return true;
}

bool SwarmRecordResult(SwarmEvalBoard& board, const SwarmEvalResult& result, std::string& err)
{
    board.Append(result);
    err.clear();
    return true;
}

std::vector<SwarmEvalResult> SwarmResultsForPool(const SwarmEvalBoard& board, const std::string& pool_id)
{
    return board.ForPool(pool_id);
}

bool SwarmFitnessChangeAllowed(const std::vector<SwarmFitnessVote>& votes, std::string& err)
{
    for (const SwarmFitnessVote& vote : votes) {
        if (vote.accepted && vote.independent && vote.voter != vote.author) {
            err = "ACCEPTED";
            return true;
        }
    }
    err = "SOLE_AUTHOR";
    return false;
}

bool SwarmAcceptChallenge(SwarmChallenge& challenge, std::string& err)
{
    if (!challenge.informative || !challenge.solvable) {
        challenge.affects_fitness = false;
        err = "CHALLENGE_UNINFORMATIVE";
        return false;
    }
    if (!challenge.independent_validation) {
        challenge.affects_fitness = false;
        err = "CHALLENGE_UNVALIDATED";
        return false;
    }
    challenge.affects_fitness = true;
    err.clear();
    return true;
}

std::string SwarmExperimentId(const std::string& parent, const std::string& recipe, bool data_grant, std::string& err)
{
    if (!data_grant) {
        err = "DATA_GRANT";
        return {};
    }
    const std::string body = SwarmCanonical({
        {"data_grant", "true"},
        {"parent", parent},
        {"recipe", recipe},
    });
    const std::string id = SwarmDigest("BTX/ExperimentManifest/1", body);
    if (!SwarmFixedId(id)) {
        err = "CANONICAL";
        return {};
    }
    err.clear();
    return id;
}

SwarmCandidateRecord SwarmMakeCandidateRecord(const std::string& parent, const std::string& recipe,
                                              const std::string& weights, const std::string& nonce,
                                              const std::string& provenance, std::string& err)
{
    const std::string body = SwarmCanonical({
        {"nonce", nonce},
        {"parent", parent},
        {"recipe", recipe},
        {"weights", weights},
    });
    const std::string id = SwarmDigest("BTX/CandidateCheckpoint/1", body);
    if (!SwarmFixedId(id)) {
        err = "CANONICAL";
        return {};
    }
    SwarmCandidateRecord record;
    record.id = id;
    record.parent = parent;
    record.recipe = recipe;
    record.weights = weights;
    record.provenance = provenance;
    record.nonce = nonce;
    record.automatic_spend_atoms = kSwarmAutomaticSpendAtoms;
    err.clear();
    return record;
}

std::string SwarmPromotionId(const std::string& candidate, const std::string& channel,
                             const std::string& evidence_digest, bool quorum_ok, std::string& err)
{
    if (evidence_digest.empty() || !quorum_ok) {
        err = "PROMOTION_EVIDENCE";
        return {};
    }
    const std::string body = SwarmCanonical({
        {"candidate", candidate},
        {"channel", channel},
        {"evidence_digest", evidence_digest},
    });
    const std::string id = SwarmDigest("BTX/PromotionCertificate/1", body);
    if (!SwarmFixedId(id)) {
        err = "PROMOTION_EVIDENCE";
        return {};
    }
    err.clear();
    return id;
}

void SwarmHeadLog::Append(const SwarmHead& head)
{
    m_heads.push_back(head);
}

const std::vector<SwarmHead>& SwarmHeadLog::Heads() const
{
    return m_heads;
}

void SwarmPublishHead(SwarmHeadLog& log, const SwarmHead& head)
{
    log.Append(head);
}

std::vector<SwarmHead> SwarmVisibleHeads(const SwarmHeadLog& log)
{
    return log.Heads();
}

std::string SwarmAdopt(SwarmReleasePolicy policy, const std::string& previous, const std::string& staged_candidate,
                       bool local_compatible, std::string& err)
{
    if (!local_compatible) {
        err = "LOCAL_INCOMPATIBLE";
        return previous;
    }
    if (policy == SwarmReleasePolicy::Refuse) {
        err = "RELEASE_REFUSED";
        return previous;
    }
    if (policy == SwarmReleasePolicy::Pin) {
        err.clear();
        return previous;
    }
    err.clear();
    return staged_candidate;
}

SwarmGradEffect SwarmGraduate(bool quality)
{
    SwarmGradEffect effect;
    effect.quality_graduated = quality;
    effect.realm_promoted = false;
    effect.exact_replay_admitted = false;
    return effect;
}

bool SwarmInfluenceCap(int64_t untrusted_weight, int64_t total_weight, int64_t cap_ppm, std::string& err)
{
    if (total_weight <= 0) {
        err = "INFLUENCE";
        return false;
    }
    const __int128 ratio = static_cast<__int128>(untrusted_weight) * 1000000 / static_cast<__int128>(total_weight);
    if (ratio > static_cast<__int128>(cap_ppm)) {
        err = "INFLUENCE_CAP";
        return false;
    }
    err.clear();
    return true;
}

bool SwarmAnomaly(int64_t score_ppm, int64_t median_ppm, int64_t max_deviation_ppm)
{
    const __int128 delta = static_cast<__int128>(score_ppm) - static_cast<__int128>(median_ppm);
    const __int128 magnitude = delta < 0 ? -delta : delta;
    return magnitude > static_cast<__int128>(max_deviation_ppm);
}

void SwarmQuarantineDigest(SwarmQuarantineSet& quarantine, const std::string& digest)
{
    if (!digest.empty()) quarantine.digests.insert(digest);
}

bool SwarmDigestBlocked(const SwarmQuarantineSet& quarantine, const std::string& digest)
{
    return quarantine.digests.count(digest) != 0;
}

bool SwarmSafetyAllowsGraduation(bool safety_regression, bool broad_regression)
{
    if (safety_regression || broad_regression) return false;
    return true;
}

bool SwarmContributionKind(const std::string& kind, std::string& err)
{
    if (kind == "public_trajectory" || kind == "synthetic_trajectory") {
        err.clear();
        return true;
    }
    err = "PRIVATE_DATA";
    return false;
}

bool SwarmTrainingGrant(bool download_license, bool operator_grant, bool license_allows_training)
{
    return download_license && operator_grant && license_allows_training;
}

} // namespace modelnet
