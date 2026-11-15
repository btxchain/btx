// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evolve/generation.h>

#include <utility>

namespace modelnet {

SwarmGeneration::SwarmGeneration(std::string subject, std::string baseline_parent, std::string coordinator_id)
    : m_subject(std::move(subject))
{
    m_measure.SetSubject(m_subject);
    m_recover.SetCoordinator(std::move(coordinator_id));
    std::string err;
    m_lineage.Seed(std::move(baseline_parent), err);
}

bool SwarmGeneration::Experience(const std::string& kind, const std::string& body, std::string& err)
{
    return m_experience.Accept(kind, body, err);
}

bool SwarmGeneration::Train(std::string& err)
{
    if (!m_train.Train(err)) return false;
    m_measure.SetTrained(true);
    return true;
}

bool SwarmGeneration::Measure(const SwarmEvolveScoreReport& report, std::string& err)
{
    m_measure.SetTrained(m_train.Trained());
    m_measure.SetSubject(m_subject);
    return m_measure.Submit(report, err);
}

bool SwarmGeneration::Graduate(const SwarmEvolveGraduateRequest& request, std::string& err)
{
    return m_graduate.Commit(m_measure.Accepted(), m_lineage.Parent(), m_train.StateHash(),
                             static_cast<uint64_t>(m_index), request, err);
}

bool SwarmGeneration::Adopt(std::string& err)
{
    if (!m_graduate.Graduated()) {
        err = "GRADUATE";
        return false;
    }
    if (m_adopted) {
        err = "REPLAY";
        return false;
    }
    if (!m_lineage.Adopt(m_graduate.Id(), err)) return false;
    m_adopted = true;
    m_checkpoint_id = m_graduate.Id();
    return true;
}

bool SwarmGeneration::Average(const std::string& left, const std::string& right, std::string& err)
{
    return m_lineage.Average(left, right, err);
}

bool SwarmGeneration::Continue(std::string& err)
{
    if (m_index != 1) {
        err = "GENERATION";
        return false;
    }
    if (!m_adopted) {
        err = "ADOPT";
        return false;
    }
    m_index = 2;
    m_adopted = false;
    m_experience.Clear();
    m_train.Reset();
    m_measure.Reset();
    m_measure.SetSubject(m_subject);
    m_graduate.Reset();
    err.clear();
    return true;
}

bool SwarmGeneration::Pay(int64_t atoms, std::string& err)
{
    return m_invoice.Record(atoms, err);
}

bool SwarmGeneration::Recover(std::string& err)
{
    const int64_t earned = m_invoice.Earned();
    const bool checkpoint = m_lineage.Seeded() || !m_checkpoint_id.empty();
    const std::string work = m_lineage.Parent().empty() ? std::string("generation") : m_lineage.Parent();
    if (!m_recover.Recover(earned, checkpoint, work, err)) return false;
    if (m_invoice.Earned() != earned || m_recover.BytesMoved() != 0 || m_recover.Mined()) {
        err = "EARNED";
        return false;
    }
    return true;
}

} // namespace modelnet
