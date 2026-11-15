// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evalengine/engine.h>

#include <modelnet/swarm_evalengine/codes.h>
#include <modelnet/swarm_evalengine/qualify.h>

namespace modelnet {
namespace {

bool KnownPolicy(const std::string& policy)
{
    return policy == kSwarmEvaluationPolicyFollow ||
           policy == kSwarmEvaluationPolicyPin ||
           policy == kSwarmEvaluationPolicyRefuse;
}

SwarmEvaluationReport MakeReport(const std::string& experiment,
                                 const std::string& candidate,
                                 const std::string& author,
                                 const std::string& evaluator,
                                 const std::string& author_domain,
                                 const std::string& evaluator_domain)
{
    SwarmEvaluationReport report;
    report.experiment = experiment;
    report.candidate = candidate;
    report.author = author;
    report.evaluator = evaluator;
    report.author_domain = author_domain;
    report.evaluator_domain = evaluator_domain;
    report.accepting = true;
    return report;
}

SwarmEvaluationRegression MakeRegression(const std::string& experiment,
                                         const std::string& candidate,
                                         const std::string& author,
                                         const std::string& evaluator,
                                         const std::string& author_domain,
                                         const std::string& evaluator_domain,
                                         const char* code)
{
    SwarmEvaluationRegression report;
    report.experiment = experiment;
    report.candidate = candidate;
    report.author = author;
    report.evaluator = evaluator;
    report.author_domain = author_domain;
    report.evaluator_domain = evaluator_domain;
    report.code = code;
    return report;
}

} // namespace

bool SwarmEvaluationEngine::OpenExperiment(const std::string& id, std::string& err)
{
    if (id.empty()) {
        return SwarmEvaluationRefuse(err, kSwarmEvaluationExperiment);
    }
    if (m_manifests.contains(id)) {
        return SwarmEvaluationRefuse(err, kSwarmEvaluationReplay);
    }
    if (!m_manifests.store(id)) {
        return SwarmEvaluationRefuse(err, kSwarmEvaluationExperiment);
    }
    m_plans.open(id);
    return SwarmEvaluationAccept(err);
}

bool SwarmEvaluationEngine::BindCandidate(const std::string& experiment, const std::string& candidate, std::string& err)
{
    if (!m_manifests.contains(experiment)) {
        return SwarmEvaluationRefuse(err, kSwarmEvaluationExperiment);
    }
    if (candidate.empty()) {
        return SwarmEvaluationRefuse(err, kSwarmEvaluationCandidate);
    }
    if (m_checkpoints.bound(experiment, candidate)) {
        return SwarmEvaluationRefuse(err, kSwarmEvaluationReplay);
    }
    if (!m_checkpoints.store(experiment, candidate)) {
        return SwarmEvaluationRefuse(err, kSwarmEvaluationCandidate);
    }
    return SwarmEvaluationAccept(err);
}

bool SwarmEvaluationEngine::CommitSuite(const std::string& experiment, const std::string& suite, std::string& err)
{
    if (!m_manifests.contains(experiment)) {
        return SwarmEvaluationRefuse(err, kSwarmEvaluationExperiment);
    }
    if (suite.empty()) {
        return SwarmEvaluationRefuse(err, kSwarmEvaluationSuite);
    }
    if (m_suites.committed(experiment) || m_plans.precommitted(experiment)) {
        return SwarmEvaluationRefuse(err, kSwarmEvaluationReplay);
    }
    m_plans.open(experiment);
    if (!m_plans.commit(experiment, suite) || !m_suites.store(experiment, suite)) {
        return SwarmEvaluationRefuse(err, kSwarmEvaluationReplay);
    }
    return SwarmEvaluationAccept(err);
}

bool SwarmEvaluationEngine::Report(const std::string& experiment,
                                   const std::string& candidate,
                                   const std::string& author,
                                   const std::string& evaluator,
                                   const std::string& author_domain,
                                   const std::string& evaluator_domain,
                                   bool author_sees_holdout,
                                   bool safety_regression,
                                   bool broad_regression,
                                   std::string& err)
{
    if (!m_manifests.contains(experiment) || !m_checkpoints.bound(experiment, candidate)) {
        return SwarmEvaluationRefuse(err, kSwarmEvaluationCandidate);
    }
    if (!m_plans.precommitted(experiment) || !m_suites.committed(experiment)) {
        return SwarmEvaluationRefuse(err, kSwarmEvaluationNotPrecommitted);
    }
    if (author == evaluator) {
        return SwarmEvaluationRefuse(err, kSwarmEvaluationSelf);
    }
    if (author_domain == evaluator_domain) {
        return SwarmEvaluationRefuse(err, kSwarmEvaluationNotQuorum);
    }
    if (author_sees_holdout) {
        return SwarmEvaluationRefuse(err, kSwarmEvaluationHoldout);
    }
    if (safety_regression) {
        m_regressions.add(MakeRegression(experiment, candidate, author, evaluator, author_domain, evaluator_domain,
                                         kSwarmEvaluationSafety));
        return SwarmEvaluationRefuse(err, kSwarmEvaluationSafety);
    }
    if (broad_regression) {
        m_regressions.add(MakeRegression(experiment, candidate, author, evaluator, author_domain, evaluator_domain,
                                         kSwarmEvaluationRegression));
        return SwarmEvaluationRefuse(err, kSwarmEvaluationRegression);
    }
    m_reports.add(MakeReport(experiment, candidate, author, evaluator, author_domain, evaluator_domain));
    return SwarmEvaluationAccept(err);
}

bool SwarmEvaluationEngine::SubmitChallenge(const std::string& id, bool informative, bool solvable, std::string& err)
{
    if (id.empty()) {
        return SwarmEvaluationRefuse(err, kSwarmEvaluationChallenge);
    }
    if (!informative || !solvable) {
        return SwarmEvaluationRefuse(err, kSwarmEvaluationNotChallenge);
    }
    if (m_challenges.contains(id)) {
        return SwarmEvaluationRefuse(err, kSwarmEvaluationReplay);
    }
    if (!m_challenges.store(id, informative, solvable)) {
        return SwarmEvaluationRefuse(err, kSwarmEvaluationNotChallenge);
    }
    return SwarmEvaluationAccept(err);
}

bool SwarmEvaluationEngine::ValidateChallenge(const std::string& id, bool independent, std::string& err)
{
    if (!m_challenges.contains(id)) {
        return SwarmEvaluationRefuse(err, kSwarmEvaluationChallenge);
    }
    if (m_validations.validated(id)) {
        return SwarmEvaluationRefuse(err, kSwarmEvaluationReplay);
    }
    if (!independent) {
        return SwarmEvaluationRefuse(err, kSwarmEvaluationNotValidated);
    }
    if (!m_validations.mark(id)) {
        return SwarmEvaluationRefuse(err, kSwarmEvaluationReplay);
    }
    return SwarmEvaluationAccept(err);
}

bool SwarmEvaluationEngine::Promote(const std::string& candidate, std::string& err)
{
    if (m_regressions.contains(candidate)) {
        return SwarmEvaluationRefuse(err, kSwarmEvaluationRegression);
    }
    if (!qualified(candidate)) {
        return SwarmEvaluationRefuse(err, kSwarmEvaluationNotGraduated);
    }
    if (m_certificates.contains(candidate)) {
        return SwarmEvaluationRefuse(err, kSwarmEvaluationReplay);
    }
    if (!m_certificates.store(candidate)) {
        return SwarmEvaluationRefuse(err, kSwarmEvaluationReplay);
    }
    return SwarmEvaluationAccept(err);
}

bool SwarmEvaluationEngine::Stage(const std::string& channel,
                                  const std::string& candidate,
                                  const std::string& policy,
                                  std::string& err)
{
    if (!KnownPolicy(policy)) {
        return SwarmEvaluationRefuse(err, kSwarmEvaluationPolicy);
    }
    if (!promoted(candidate)) {
        return SwarmEvaluationRefuse(err, kSwarmEvaluationNotGraduated);
    }
    if (policy == kSwarmEvaluationPolicyFollow) {
        m_channels.set_staged(channel, candidate);
    } else {
        m_channels.set_policy(channel, policy);
    }
    return SwarmEvaluationAccept(err);
}

bool SwarmEvaluationEngine::Adopt(const std::string& channel, std::string& err)
{
    if (!m_channels.has_staged(channel)) {
        return SwarmEvaluationRefuse(err, kSwarmEvaluationNotStaged);
    }
    std::string previous;
    std::string adopted;
    if (!m_channels.adopt_staged(channel, previous, adopted)) {
        return SwarmEvaluationRefuse(err, kSwarmEvaluationNotStaged);
    }
    m_adoptions.push(channel, previous, adopted);
    return SwarmEvaluationAccept(err);
}

std::size_t SwarmEvaluationEngine::experiment_count() const
{
    return m_manifests.size();
}

std::string SwarmEvaluationEngine::suite(const std::string& experiment) const
{
    return m_suites.suite_of(experiment);
}

std::size_t SwarmEvaluationEngine::report_count(const std::string& candidate) const
{
    return m_reports.count_for(candidate);
}

bool SwarmEvaluationEngine::qualified(const std::string& candidate) const
{
    return SwarmEvaluationIsQualified(m_reports, m_regressions, candidate);
}

std::size_t SwarmEvaluationEngine::regression_count(const std::string& candidate) const
{
    return m_regressions.count_for(candidate);
}

bool SwarmEvaluationEngine::challenge_validated(const std::string& id) const
{
    return m_validations.validated(id);
}

bool SwarmEvaluationEngine::fitness_moves() const
{
    return m_validations.any();
}

bool SwarmEvaluationEngine::fitness_moves(const std::string& id) const
{
    return m_validations.validated(id);
}

bool SwarmEvaluationEngine::promoted(const std::string& candidate) const
{
    return m_certificates.contains(candidate);
}

std::string SwarmEvaluationEngine::staged(const std::string& channel) const
{
    return m_channels.staged(channel);
}

std::string SwarmEvaluationEngine::active(const std::string& channel) const
{
    return m_channels.active(channel);
}

std::size_t SwarmEvaluationEngine::adoption_count(const std::string& channel) const
{
    return m_adoptions.count(channel);
}

bool SwarmEvaluationEngine::launched() const
{
    return m_quiet.launched();
}

bool SwarmEvaluationEngine::gpu() const
{
    return m_quiet.gpu();
}

std::uint64_t SwarmEvaluationEngine::bytes_moved() const
{
    return m_quiet.bytes_moved();
}

std::uint64_t SwarmEvaluationEngine::atoms_moved() const
{
    return m_quiet.atoms_moved();
}

std::string SwarmEvaluationEngine::automatic_spend() const
{
    return m_quiet.automatic_spend();
}

bool SwarmEvaluationEngine::broadcast() const
{
    return m_quiet.broadcast();
}

bool SwarmEvaluationEngine::realm_promoted() const
{
    return m_quiet.realm_promoted();
}

bool SwarmEvaluationEngine::exact_replay_admitted() const
{
    return m_quiet.exact_replay_admitted();
}

bool SwarmEvaluationEngine::money() const
{
    return m_quiet.money();
}

} // namespace modelnet
