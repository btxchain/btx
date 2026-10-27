// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_phase/dt_phase.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool DtPhaseEngine::Successor(DtPhase current, DtPhase& next)
{
    switch (current) {
    case DtPhase::Discovered:
        next = DtPhase::Eligible;
        return true;
    case DtPhase::Eligible:
        next = DtPhase::Reserved;
        return true;
    case DtPhase::Reserved:
        next = DtPhase::Prepared;
        return true;
    case DtPhase::Prepared:
        next = DtPhase::Running;
        return true;
    case DtPhase::Running:
        next = DtPhase::Snapshotting;
        return true;
    case DtPhase::Snapshotting:
        next = DtPhase::CandidateCommitted;
        return true;
    case DtPhase::CandidateCommitted:
        next = DtPhase::Evaluating;
        return true;
    case DtPhase::Evaluating:
        next = DtPhase::Waiting;
        return true;
    case DtPhase::Waiting:
        next = DtPhase::Draining;
        return true;
    case DtPhase::Draining:
    case DtPhase::Revoked:
    case DtPhase::Failed:
    case DtPhase::OutcomeUnknown:
        return false;
    }
    return false;
}

bool DtPhaseEngine::Advance(DtPhase next, int64_t now_ms, int64_t authority_until_ms, bool journal_ok, std::string& err)
{
    if (m_phase == DtPhase::Revoked) {
        err = NIFDT_REVOKED;
        return false;
    }
    if (m_phase == DtPhase::Failed) {
        err = DT_PHASE_FAILED;
        return false;
    }
    // Equality is expired. The requested phase is not stored.
    if (now_ms >= authority_until_ms) {
        err = DT_PHASE_EXPIRED;
        return false;
    }
    if (!journal_ok) {
        err = DT_PHASE_JOURNAL;
        return false;
    }
    DtPhase legal = m_phase;
    if (!Successor(m_phase, legal) || next != legal) {
        err = DT_PHASE_ORDER;
        return false;
    }
    m_phase = next;
    err.clear();
    return true;
}

bool DtPhaseEngine::Fail(std::string& err)
{
    if (m_phase != DtPhase::Running) {
        err = DT_PHASE_ORDER;
        return false;
    }
    m_phase = DtPhase::Failed;
    err.clear();
    return true;
}

bool DtPhaseEngine::Revoke(std::string& err)
{
    m_phase = DtPhase::Revoked;
    err.clear();
    return true;
}

bool DtPhaseEngine::Unknown(std::string& err)
{
    m_phase = DtPhase::OutcomeUnknown;
    err.clear();
    return true;
}

bool DtPhaseEngine::GpuStep(std::string& err)
{
    // No device step is linked. The stored weight and the phase stay.
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

} // namespace modelnet
