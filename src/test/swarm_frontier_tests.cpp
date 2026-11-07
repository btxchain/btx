// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_codec.h>
#include <modelnet/swarm_frontier.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_frontier_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(holdout_leak_is_refused_and_other_pools_may_begin)
{
    modelnet::SwarmEvalCommitment commitment;
    commitment.suite_id = "suite-1";
    commitment.holdout_commitment = "holdout-commit";
    commitment.pool_id = "pool-a";
    commitment.committed_before_score = true;
    std::string err;
    BOOST_CHECK(!modelnet::SwarmBeginEvaluation(commitment, true, err));
    BOOST_CHECK_EQUAL(err, "HOLDOUT_LEAKED");

    commitment.pool_id = "pool-b";
    BOOST_CHECK(modelnet::SwarmBeginEvaluation(commitment, false, err));
    BOOST_CHECK(err.empty());

    commitment.committed_before_score = false;
    commitment.pool_id = "pool-c";
    BOOST_CHECK(!modelnet::SwarmBeginEvaluation(commitment, false, err));
    BOOST_CHECK_EQUAL(err, "SUITE_NOT_PRECOMMITTED");
}

BOOST_AUTO_TEST_CASE(a_negative_result_is_retained_for_its_pool)
{
    modelnet::SwarmEvalBoard board;
    modelnet::SwarmEvalResult negative;
    negative.candidate_id = "cand-neg";
    negative.pool_id = "pool-a";
    negative.score_ppm = -20;
    negative.negative = true;
    negative.reproducible = true;
    modelnet::SwarmEvalResult other;
    other.candidate_id = "cand-pos";
    other.pool_id = "pool-b";
    other.score_ppm = 40;
    other.negative = false;
    other.reproducible = true;
    std::string err;
    BOOST_CHECK(modelnet::SwarmRecordResult(board, negative, err));
    BOOST_CHECK(modelnet::SwarmRecordResult(board, other, err));
    const std::vector<modelnet::SwarmEvalResult> pool_a = modelnet::SwarmResultsForPool(board, "pool-a");
    BOOST_REQUIRE_EQUAL(pool_a.size(), 1U);
    BOOST_CHECK(pool_a[0].negative);
    BOOST_CHECK_EQUAL(pool_a[0].score_ppm, -20);
    BOOST_CHECK_EQUAL(pool_a[0].candidate_id, "cand-neg");
    BOOST_CHECK(modelnet::SwarmResultsForPool(board, "pool-b").size() == 1U);
}

BOOST_AUTO_TEST_CASE(the_sole_author_cannot_move_fitness)
{
    modelnet::SwarmFitnessVote author;
    author.voter = "author-a";
    author.author = "author-a";
    author.independent = true;
    author.accepted = true;
    std::string err;
    BOOST_CHECK(!modelnet::SwarmFitnessChangeAllowed({author}, err));
    BOOST_CHECK_EQUAL(err, "SOLE_AUTHOR");

    modelnet::SwarmFitnessVote dependent;
    dependent.voter = "voter-b";
    dependent.author = "author-a";
    dependent.independent = false;
    dependent.accepted = true;
    BOOST_CHECK(!modelnet::SwarmFitnessChangeAllowed({author, dependent}, err));
    BOOST_CHECK_EQUAL(err, "SOLE_AUTHOR");

    modelnet::SwarmFitnessVote independent;
    independent.voter = "voter-c";
    independent.author = "author-a";
    independent.independent = true;
    independent.accepted = true;
    BOOST_CHECK(modelnet::SwarmFitnessChangeAllowed({author, independent}, err));
    BOOST_CHECK_EQUAL(err, "ACCEPTED");
}

BOOST_AUTO_TEST_CASE(an_uninformative_challenge_is_refused)
{
    modelnet::SwarmChallenge misleading;
    misleading.id = "challenge-1";
    misleading.informative = false;
    misleading.solvable = true;
    misleading.independent_validation = true;
    misleading.affects_fitness = true;
    std::string err;
    BOOST_CHECK(!modelnet::SwarmAcceptChallenge(misleading, err));
    BOOST_CHECK_EQUAL(err, "CHALLENGE_UNINFORMATIVE");
    BOOST_CHECK(!misleading.affects_fitness);

    modelnet::SwarmChallenge unsolvable = misleading;
    unsolvable.informative = true;
    unsolvable.solvable = false;
    BOOST_CHECK(!modelnet::SwarmAcceptChallenge(unsolvable, err));
    BOOST_CHECK_EQUAL(err, "CHALLENGE_UNINFORMATIVE");

    modelnet::SwarmChallenge unvalidated;
    unvalidated.id = "challenge-2";
    unvalidated.informative = true;
    unvalidated.solvable = true;
    unvalidated.independent_validation = false;
    BOOST_CHECK(!modelnet::SwarmAcceptChallenge(unvalidated, err));
    BOOST_CHECK_EQUAL(err, "CHALLENGE_UNVALIDATED");
    BOOST_CHECK(!unvalidated.affects_fitness);

    modelnet::SwarmChallenge accepted = unvalidated;
    accepted.independent_validation = true;
    BOOST_CHECK(modelnet::SwarmAcceptChallenge(accepted, err));
    BOOST_CHECK(accepted.affects_fitness);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(two_channels_stay_visible)
{
    modelnet::SwarmHeadLog log;
    modelnet::SwarmHead general;
    general.channel = "general/stable";
    general.candidate = "cand-general";
    general.sequence = 3;
    modelnet::SwarmHead code;
    code.channel = "code/stable";
    code.candidate = "cand-code";
    code.sequence = 1;
    modelnet::SwarmPublishHead(log, general);
    modelnet::SwarmPublishHead(log, code);
    const std::vector<modelnet::SwarmHead> heads = modelnet::SwarmVisibleHeads(log);
    BOOST_REQUIRE_EQUAL(heads.size(), 2U);
    BOOST_CHECK_EQUAL(heads[0].channel, "general/stable");
    BOOST_CHECK_EQUAL(heads[0].candidate, "cand-general");
    BOOST_CHECK_EQUAL(heads[1].channel, "code/stable");
    BOOST_CHECK_EQUAL(heads[1].candidate, "cand-code");
}

BOOST_AUTO_TEST_CASE(pin_does_not_adopt_the_staged_candidate)
{
    std::string err;
    BOOST_CHECK_EQUAL(modelnet::SwarmAdopt(modelnet::SwarmReleasePolicy::Pin, "previous", "staged", true, err), "previous");
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(modelnet::SwarmAdopt(modelnet::SwarmReleasePolicy::Follow, "previous", "staged", true, err), "staged");
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(modelnet::SwarmAdopt(modelnet::SwarmReleasePolicy::Refuse, "previous", "staged", true, err), "previous");
    BOOST_CHECK_EQUAL(err, "RELEASE_REFUSED");
    BOOST_CHECK_EQUAL(modelnet::SwarmAdopt(modelnet::SwarmReleasePolicy::Follow, "previous", "staged", false, err), "previous");
    BOOST_CHECK_EQUAL(err, "LOCAL_INCOMPATIBLE");
}

BOOST_AUTO_TEST_CASE(influence_over_the_cap_is_refused)
{
    std::string err;
    BOOST_CHECK(!modelnet::SwarmInfluenceCap(2, 10, 100000, err));
    BOOST_CHECK_EQUAL(err, "INFLUENCE_CAP");
    BOOST_CHECK(!modelnet::SwarmInfluenceCap(1, 0, 1000000, err));
    BOOST_CHECK_EQUAL(err, "INFLUENCE");
    BOOST_CHECK(modelnet::SwarmInfluenceCap(1, 10, 100000, err));
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(a_prompt_contribution_is_refused)
{
    std::string err;
    BOOST_CHECK(!modelnet::SwarmContributionKind("prompt", err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(!modelnet::SwarmContributionKind("repository", err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(!modelnet::SwarmContributionKind("credential", err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(modelnet::SwarmContributionKind("public_trajectory", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(modelnet::SwarmContributionKind("synthetic_trajectory", err));
}

BOOST_AUTO_TEST_CASE(graduation_does_not_promote_a_realm_or_admit_exact_replay)
{
    const modelnet::SwarmGradEffect passed = modelnet::SwarmGraduate(true);
    BOOST_CHECK(passed.quality_graduated);
    BOOST_CHECK(!passed.realm_promoted);
    BOOST_CHECK(!passed.exact_replay_admitted);
    const modelnet::SwarmGradEffect failed = modelnet::SwarmGraduate(false);
    BOOST_CHECK(!failed.quality_graduated);
    BOOST_CHECK(!failed.realm_promoted);
    BOOST_CHECK(!failed.exact_replay_admitted);
}

BOOST_AUTO_TEST_CASE(promotion_ids_are_domain_separated_and_require_evidence)
{
    std::string err;
    BOOST_CHECK(modelnet::SwarmExperimentId("parent-1", "recipe-1", false, err).empty());
    BOOST_CHECK_EQUAL(err, "DATA_GRANT");
    const std::string experiment = modelnet::SwarmExperimentId("parent-1", "recipe-1", true, err);
    BOOST_CHECK(err.empty());
    BOOST_CHECK(modelnet::SwarmFixedId(experiment));
    const std::string experiment_body = modelnet::SwarmCanonical({
        {"data_grant", "true"},
        {"parent", "parent-1"},
        {"recipe", "recipe-1"},
    });
    BOOST_CHECK_EQUAL(experiment, modelnet::SwarmDigest("BTX/ExperimentManifest/1", experiment_body));

    const modelnet::SwarmCandidateRecord record = modelnet::SwarmMakeCandidateRecord(
        "parent-1", "recipe-1", "weights-1", "nonce-1", "provenance-1", err);
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(record.parent, "parent-1");
    BOOST_CHECK_EQUAL(record.recipe, "recipe-1");
    BOOST_CHECK_EQUAL(record.weights, "weights-1");
    BOOST_CHECK_EQUAL(record.provenance, "provenance-1");
    BOOST_CHECK_EQUAL(record.automatic_spend_atoms, "0");
    BOOST_CHECK(modelnet::SwarmFixedId(record.id));
    const std::string candidate_body = modelnet::SwarmCanonical({
        {"nonce", "nonce-1"},
        {"parent", "parent-1"},
        {"recipe", "recipe-1"},
        {"weights", "weights-1"},
    });
    BOOST_CHECK_EQUAL(record.id, modelnet::SwarmDigest("BTX/CandidateCheckpoint/1", candidate_body));

    BOOST_CHECK(modelnet::SwarmPromotionId(record.id, "general/stable", "", true, err).empty());
    BOOST_CHECK_EQUAL(err, "PROMOTION_EVIDENCE");
    BOOST_CHECK(modelnet::SwarmPromotionId(record.id, "general/stable", experiment, false, err).empty());
    BOOST_CHECK_EQUAL(err, "PROMOTION_EVIDENCE");
    const std::string promotion = modelnet::SwarmPromotionId(record.id, "general/stable", experiment, true, err);
    BOOST_CHECK(err.empty());
    BOOST_CHECK(modelnet::SwarmFixedId(promotion));
    const std::string promotion_body = modelnet::SwarmCanonical({
        {"candidate", record.id},
        {"channel", "general/stable"},
        {"evidence_digest", experiment},
    });
    BOOST_CHECK_EQUAL(promotion, modelnet::SwarmDigest("BTX/PromotionCertificate/1", promotion_body));
    BOOST_CHECK(promotion != experiment);
    BOOST_CHECK(promotion != record.id);
}

BOOST_AUTO_TEST_CASE(anomaly_quarantine_safety_and_training_grant)
{
    BOOST_CHECK(modelnet::SwarmAnomaly(200, 10, 50));
    BOOST_CHECK(!modelnet::SwarmAnomaly(40, 10, 50));

    modelnet::SwarmQuarantineSet quarantine;
    const std::string digest(96, 'a');
    BOOST_CHECK(!modelnet::SwarmDigestBlocked(quarantine, digest));
    modelnet::SwarmQuarantineDigest(quarantine, digest);
    BOOST_CHECK(modelnet::SwarmDigestBlocked(quarantine, digest));
    BOOST_CHECK(!modelnet::SwarmDigestBlocked(quarantine, std::string(96, 'b')));

    BOOST_CHECK(modelnet::SwarmSafetyAllowsGraduation(false, false));
    BOOST_CHECK(!modelnet::SwarmSafetyAllowsGraduation(true, false));
    BOOST_CHECK(!modelnet::SwarmSafetyAllowsGraduation(false, true));

    BOOST_CHECK(modelnet::SwarmTrainingGrant(true, true, true));
    BOOST_CHECK(!modelnet::SwarmTrainingGrant(true, true, false));
    BOOST_CHECK(!modelnet::SwarmTrainingGrant(false, true, true));
    BOOST_CHECK(!modelnet::SwarmTrainingGrant(true, false, true));
    BOOST_CHECK_EQUAL(std::string(modelnet::kSwarmAutomaticSpendAtoms), "0");
}

BOOST_AUTO_TEST_SUITE_END()
