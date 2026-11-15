// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/guard_permit/guard_permit.h>

#include <modelnet/guard_machine.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool GuardPermitEngine::Prepare(const std::string& effect, const std::string& fingerprint, uint64_t generation,
                                int64_t now_ms, GuardPermit& out, std::string& err)
{
    return m_table.Prepare(effect, fingerprint, generation, now_ms, out, err);
}

bool GuardPermitEngine::Execute(const std::string& secret, int64_t now_ms, std::string& err)
{
    std::string receipt_id;
    return m_table.Execute(secret, now_ms, receipt_id, err);
}

void GuardPermitEngine::Pause()
{
    m_table.Pause();
}

void GuardPermitEngine::Resume()
{
    m_table.Resume();
}

bool GuardPermitEngine::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool GuardPermitEngine::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool GuardPermitEngine::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool GuardPermitEngine::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

} // namespace modelnet
