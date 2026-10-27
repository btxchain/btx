// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/replay_check/replay_check.h>

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/training_integer.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool ReplayCheck::Run(uint64_t steps, std::string& err)
{
    if (steps < 1) {
        err = "STEPS";
        return false;
    }
    if (!m_trainer.Run(steps, err)) return false;
    m_stored = m_trainer.State();
    return true;
}

bool ReplayCheck::Check(std::string& err)
{
    return m_trainer.ReplayMatches(m_stored, err);
}

bool ReplayCheck::Tamper(std::string& err)
{
    m_stored.state_hash = "bad";
    return IntegerTrainer::CheckState(m_stored, err);
}

int64_t ReplayCheck::pairs() const
{
    return static_cast<int64_t>(IntegerDataset().size());
}

bool ReplayCheck::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool ReplayCheck::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool ReplayCheck::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
