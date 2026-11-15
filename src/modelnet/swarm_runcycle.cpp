// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_runcycle.h>

#include <modelnet/swarm_executor.h>
#include <modelnet/swarm_frontier.h>
#include <modelnet/swarm_paymesh.h>
#include <modelnet/training_integer.h>

namespace modelnet {

SwarmRunCycle::Job* SwarmRunCycle::Find(const std::string& job_id)
{
    const auto it = m_jobs.find(job_id);
    if (it == m_jobs.end()) return nullptr;
    return &it->second;
}

bool SwarmRunCycle::job_paid(const std::string& job_id) const
{
    const auto it = m_jobs.find(job_id);
    return it != m_jobs.end() && it->second.paid;
}

uint64_t SwarmRunCycle::job_steps(const std::string& job_id) const
{
    const auto it = m_jobs.find(job_id);
    if (it == m_jobs.end()) return 0;
    return it->second.steps;
}

const std::string& SwarmRunCycle::job_state_hash(const std::string& job_id) const
{
    static const std::string empty;
    const auto it = m_jobs.find(job_id);
    if (it == m_jobs.end()) return empty;
    return it->second.state_hash;
}

bool SwarmRunCycle::EnsureBook(std::string& err)
{
    if (m_book_open) {
        err.clear();
        return true;
    }
    if (!m_book.Open(err)) return false;
    m_book_open = true;
    return true;
}

bool SwarmRunCycle::Form(const std::string& node_id, bool modelnet_on, std::string& err)
{
    if (node_id.empty()) {
        err = "NODE";
        return false;
    }
    if (!modelnet_on) {
        err = "HELD";
        return false;
    }
    if (m_formed) {
        err = "REOPEN";
        return false;
    }
    m_node_id = node_id;
    m_formed = true;
    err.clear();
    return true;
}

bool SwarmRunCycle::Admit(const std::string& job_id, int64_t threads, int64_t memory_mib, bool sandbox_present, std::string& err)
{
    if (!m_formed) {
        err = "SESSION";
        return false;
    }
    if (job_id.empty()) {
        err = "JOB";
        return false;
    }
    if (m_jobs.count(job_id) != 0) {
        err = "REPLAY";
        return false;
    }
    SwarmExecutorRequest request;
    request.sandbox_present = sandbox_present;
    request.requested_threads = threads;
    request.requested_mib = memory_mib;
    const SwarmExecutorDecision decision = SwarmAdmitExecutor(request, err);
    if (!decision.admitted || decision.launched) return false;
    Job job;
    job.admitted = true;
    m_jobs.emplace(job_id, job);
    err.clear();
    return true;
}

bool SwarmRunCycle::Experience(const std::string& job_id, const std::string& kind, std::string& err)
{
    Job* job = Find(job_id);
    if (job == nullptr || !job->admitted) {
        err = "JOB";
        return false;
    }
    if (!SwarmContributionKind(kind, err)) return false;
    job->experienced = true;
    return true;
}

bool SwarmRunCycle::TrainJob(const std::string& job_id, std::string& err)
{
    Job* job = Find(job_id);
    if (job == nullptr || !job->experienced) {
        err = "EXPERIENCE";
        return false;
    }
    if (IntegerDataset().size() != 8) {
        err = "PAIRS";
        return false;
    }
    IntegerTrainer trainer;
    if (!trainer.Step(err)) return false;
    if (trainer.State().step != 1 || trainer.State().state_hash.empty()) {
        err = "STEP";
        return false;
    }
    if (!trainer.ReplayMatches(trainer.State(), err)) return false;
    job->steps = trainer.State().step;
    job->state_hash = trainer.State().state_hash;
    job->trained = true;
    return true;
}

bool SwarmRunCycle::Measure(const std::string& job_id, bool author_is_evaluator, bool independent, int64_t score_ppm, std::string& err)
{
    Job* job = Find(job_id);
    if (job == nullptr || !job->trained) {
        err = "TRAIN";
        return false;
    }
    if (author_is_evaluator) {
        err = "NOT_SCORED";
        return false;
    }
    if (!independent) {
        err = "HELD";
        return false;
    }
    if (score_ppm < 0) {
        err = "RANGE";
        return false;
    }
    job->score_ppm = score_ppm;
    job->measured = true;
    err.clear();
    return true;
}

bool SwarmRunCycle::GraduateJob(const std::string& job_id, bool safety_regression, bool broad_regression, std::string& err)
{
    Job* job = Find(job_id);
    if (job == nullptr || !job->measured) {
        err = "MEASURE";
        return false;
    }
    if (!SwarmSafetyAllowsGraduation(safety_regression, broad_regression)) {
        err = "REGRESSION";
        return false;
    }
    const SwarmGradEffect effect = SwarmGraduate(true);
    if (!effect.quality_graduated || effect.realm_promoted || effect.exact_replay_admitted) {
        err = "GRADUATE";
        return false;
    }
    job->graduated = true;
    err.clear();
    return true;
}

bool SwarmRunCycle::AdoptJob(const std::string& job_id, bool local_compatible, std::string& err)
{
    Job* job = Find(job_id);
    if (job == nullptr || !job->graduated) {
        err = "GRADUATE";
        return false;
    }
    const std::string adopted = SwarmAdopt(SwarmReleasePolicy::Follow, m_active, job_id, local_compatible, err);
    if (adopted != job_id) return false;
    m_active = adopted;
    job->adopted = true;
    return true;
}

bool SwarmRunCycle::PayJob(const std::string& job_id, const std::string& beneficiary, int64_t atoms, const uint256& hashlock, const std::vector<unsigned char>& preimage, std::string& err)
{
    Job* job = Find(job_id);
    if (job == nullptr || !job->adopted) {
        err = "ADOPT";
        return false;
    }
    if (job->paid) {
        err = "REPLAY";
        return false;
    }
    if (!EnsureBook(err)) return false;
    if (!m_book.Create(job_id, beneficiary, job_id, atoms, hashlock, err)) return false;
    if (!m_book.Reveal(job_id, preimage, err)) return false;
    if (m_book.MultiHopQualified()) {
        err = "ROUTE";
        return false;
    }
    job->atoms = atoms;
    job->paid = true;
    m_earned += atoms;
    err.clear();
    return true;
}

bool SwarmRunCycle::ContinueFrom(const std::string& parent_id, const std::string& child_id, std::string& err)
{
    const Job* parent = Find(parent_id);
    if (parent == nullptr || !parent->paid || m_active != parent_id) {
        err = "CYCLE";
        return false;
    }
    return Admit(child_id, 1, 1, true, err);
}

bool SwarmRunCycle::Recover(std::string& err)
{
    if (!m_formed) {
        err = "SESSION";
        return false;
    }
    SwarmRecoverySnapshot in;
    in.pending_jobs = static_cast<int>(m_jobs.size());
    in.earned_atoms = m_earned;
    in.checkpoint_present = false;
    for (const auto& item : m_jobs) {
        if (item.second.graduated) in.checkpoint_present = true;
    }
    in.payment_plane_present = m_book_open;
    in.execution_plane_present = m_formed;
    SwarmRecoverySnapshot out;
    if (!SwarmCoordinatorLost(in, out, err)) return false;
    if (out.earned_atoms != m_earned) {
        err = "EARNED";
        return false;
    }
    return true;
}

} // namespace modelnet
