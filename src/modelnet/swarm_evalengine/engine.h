// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EVALENGINE_ENGINE_H
#define BITCOIN_MODELNET_SWARM_EVALENGINE_ENGINE_H

#include <modelnet/swarm_evalengine/adoption.h>
#include <modelnet/swarm_evalengine/certificate.h>
#include <modelnet/swarm_evalengine/challenge.h>
#include <modelnet/swarm_evalengine/channel.h>
#include <modelnet/swarm_evalengine/checkpoint.h>
#include <modelnet/swarm_evalengine/manifest.h>
#include <modelnet/swarm_evalengine/plan.h>
#include <modelnet/swarm_evalengine/quiet.h>
#include <modelnet/swarm_evalengine/regression.h>
#include <modelnet/swarm_evalengine/report.h>
#include <modelnet/swarm_evalengine/suite.h>
#include <modelnet/swarm_evalengine/validation.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace modelnet {

/**
 * In-process evaluation records for one candidate population.
 *
 * OpenExperiment stores an experiment manifest and a draft evaluation
 * plan. An empty id is EXPERIMENT and stores nothing. A duplicate id is
 * REPLAY and keeps the first.
 *
 * BindCandidate stores a candidate checkpoint id on an open experiment.
 * An unknown experiment is EXPERIMENT. An empty candidate is CANDIDATE.
 * A second bind of the same pair is REPLAY and keeps the first.
 *
 * CommitSuite stores a precommitted suite and marks the plan
 * precommitted. An unknown experiment is EXPERIMENT. An empty suite is
 * SUITE. A second suite id for that experiment is REPLAY and keeps the
 * first. Reports are refused until the suite exists.
 *
 * Report stores an accepting evaluation report, or a regression report,
 * or nothing. An unknown experiment or an unbound candidate is
 * CANDIDATE and stores nothing. No committed suite is NOT_PRECOMMITTED
 * and stores nothing. author == evaluator is SELF and stores nothing.
 * author_domain == evaluator_domain is NOT_QUORUM and stores nothing.
 * author_sees_holdout is HOLDOUT and stores nothing. safety_regression
 * is SAFETY and stores a regression report. broad_regression is
 * REGRESSION and stores a regression report. SELF, NOT_QUORUM, HOLDOUT,
 * SAFETY, and REGRESSION are not accepting reports. There is no vote
 * percentage.
 *
 * qualified(candidate) is true only when accepting reports for that
 * candidate have at least two distinct evaluators and two distinct
 * evaluator domains, and no regression report is stored for that
 * candidate. A count of reports by itself does not qualify.
 *
 * SubmitChallenge stores an informative solvable challenge and does not
 * move fitness. An empty id is CHALLENGE. informative false or solvable
 * false is NOT_CHALLENGE and stores nothing. A duplicate id is REPLAY.
 *
 * ValidateChallenge marks a stored challenge when independent is true.
 * An unknown id is CHALLENGE. independent false is NOT_VALIDATED and
 * stores nothing. A second validation is REPLAY. fitness_moves() stays
 * false until this returns true. fitness_moves(id) stays false until
 * this returns true for that id.
 *
 * Promote stores a promotion certificate for a qualified candidate with
 * no regression report. Not qualified is NOT_GRADUATED. A stored
 * regression report is REGRESSION even if the candidate had been
 * qualified. A second promote is REPLAY. realm_promoted(),
 * exact_replay_admitted(), and money() stay false. A certificate is
 * not money. Promoting one candidate does not delete another
 * candidate's regression report.
 *
 * Stage policy must be "follow", "pin", or "refuse". Anything else is
 * POLICY. An unpromoted candidate is NOT_GRADUATED. follow of a
 * promoted candidate sets the staged head and does not change the
 * active head. pin and refuse leave both heads unchanged.
 *
 * Adopt with no staged head is NOT_STAGED. Otherwise the previous
 * active head is pushed onto adoption history, active becomes staged,
 * and staged is cleared.
 *
 * This plane does not start a process, train, open a socket, broadcast,
 * spend, or move bytes. launched() stays false. gpu() stays false.
 * bytes_moved() stays 0. atoms_moved() stays 0. automatic_spend() stays
 * "0". broadcast() stays false.
 */
class SwarmEvaluationEngine {
public:
    bool OpenExperiment(const std::string& id, std::string& err);
    bool BindCandidate(const std::string& experiment, const std::string& candidate, std::string& err);
    bool CommitSuite(const std::string& experiment, const std::string& suite, std::string& err);
    bool Report(const std::string& experiment,
                const std::string& candidate,
                const std::string& author,
                const std::string& evaluator,
                const std::string& author_domain,
                const std::string& evaluator_domain,
                bool author_sees_holdout,
                bool safety_regression,
                bool broad_regression,
                std::string& err);
    bool SubmitChallenge(const std::string& id, bool informative, bool solvable, std::string& err);
    bool ValidateChallenge(const std::string& id, bool independent, std::string& err);
    bool Promote(const std::string& candidate, std::string& err);
    bool Stage(const std::string& channel, const std::string& candidate, const std::string& policy, std::string& err);
    bool Adopt(const std::string& channel, std::string& err);

    std::size_t experiment_count() const;
    std::string suite(const std::string& experiment) const;
    std::size_t report_count(const std::string& candidate) const;
    bool qualified(const std::string& candidate) const;
    std::size_t regression_count(const std::string& candidate) const;
    bool challenge_validated(const std::string& id) const;
    bool fitness_moves() const;
    bool fitness_moves(const std::string& id) const;
    bool promoted(const std::string& candidate) const;
    std::string staged(const std::string& channel) const;
    std::string active(const std::string& channel) const;
    std::size_t adoption_count(const std::string& channel) const;
    bool launched() const;
    bool gpu() const;
    std::uint64_t bytes_moved() const;
    std::uint64_t atoms_moved() const;
    std::string automatic_spend() const;
    bool broadcast() const;
    bool realm_promoted() const;
    bool exact_replay_admitted() const;
    bool money() const;

private:
    SwarmEvaluationManifestBook m_manifests;
    SwarmEvaluationCheckpointBook m_checkpoints;
    SwarmEvaluationPlanBook m_plans;
    SwarmEvaluationSuiteBook m_suites;
    SwarmEvaluationReportBook m_reports;
    SwarmEvaluationRegressionBook m_regressions;
    SwarmEvaluationChallengeBook m_challenges;
    SwarmEvaluationValidationBook m_validations;
    SwarmEvaluationCertificateBook m_certificates;
    SwarmEvaluationChannelBook m_channels;
    SwarmEvaluationAdoptionBook m_adoptions;
    SwarmEvaluationQuiet m_quiet;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EVALENGINE_ENGINE_H
