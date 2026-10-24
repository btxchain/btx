// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_observe/nif_observe.h>

namespace modelnet {

bool NifObserve::Quiet() const
{
    if (m_life.Find(m_id) != nullptr) return false;
    if (!m_exec.held(m_id).empty()) return false;
    if (m_life.bytes_moved() != static_cast<int64_t>(0)) return false;
    if (m_exec.accepted_bytes() != static_cast<int64_t>(0)) return false;
    if (m_life.launched() || m_exec.launched()) return false;
    if (m_life.gpu() || m_exec.gpu()) return false;
    if (m_life.broadcast() || m_exec.broadcast()) return false;
    if (m_life.automatic_spend() != NIFDT_AUTOMATIC_SPEND) return false;
    if (m_exec.automatic_spend() != NIFDT_AUTOMATIC_SPEND) return false;
    if (!m_life.available() || m_life.validation_affected() || m_life.authority_from_receipt()) return false;
    if (m_exec.buffer_released_early()) return false;
    return true;
}

bool NifObserve::Admit(const std::string& id, std::string& err)
{
    if (id.empty()) {
        err = "REQUEST";
        return false;
    }
    if (m_has) {
        err = NIFDT_REPLAY;
        return false;
    }
    m_id = id;
    m_has = true;
    err.clear();
    return true;
}

bool NifObserve::Tick(int64_t now_ms, std::string& err)
{
    m_ticks += static_cast<int64_t>(1);
    m_now_ms = now_ms;
    const bool quiet = Quiet();
    if (m_has && !m_seen && quiet) {
        m_seen = true;
        m_observed += static_cast<int64_t>(1);
        m_observed_id = m_id;
    }
    err.clear();
    return true;
}

bool NifObserve::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    if (m_life.automatic_spend() != NIFDT_AUTOMATIC_SPEND || m_exec.automatic_spend() != NIFDT_AUTOMATIC_SPEND) {
        return false;
    }
    return false;
}

bool NifObserve::Gpu(std::string& err)
{
    if (m_life.gpu() || m_exec.gpu() || NifDtEngineLinked("deepinfer")) {
        m_gpu = false;
    }
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

int64_t NifObserve::bytes_moved() const
{
    if (m_life.bytes_moved() != static_cast<int64_t>(0)) return static_cast<int64_t>(0);
    if (m_exec.accepted_bytes() != static_cast<int64_t>(0)) return static_cast<int64_t>(0);
    return m_bytes;
}

std::string NifObserve::automatic_spend() const
{
    const std::string life = m_life.automatic_spend();
    if (life != NIFDT_AUTOMATIC_SPEND || m_exec.automatic_spend() != NIFDT_AUTOMATIC_SPEND) {
        return NIFDT_AUTOMATIC_SPEND;
    }
    return life;
}

bool NifObserve::gpu() const
{
    return m_gpu || m_life.gpu() || m_exec.gpu();
}

bool NifObserve::launched() const
{
    return m_life.launched() || m_exec.launched();
}

bool NifObserve::broadcast() const
{
    return m_life.broadcast() || m_exec.broadcast();
}

} // namespace modelnet
