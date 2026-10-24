// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_flagship/cursor.h>

#include <modelnet/swarm_flagship/inspect.h>
#include <modelnet/swarm_flagship/pass.h>
#include <modelnet/swarm_flagship/record.h>
#include <modelnet/swarm_flagship/rollback.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmFlagshipCursor::Record(const std::string& stage, const std::string& evidence, std::string& err)
{
    return SwarmFlagshipRecord{}.apply(m_ledger, stage, evidence, err);
}

bool SwarmFlagshipCursor::Pass(const std::string& stage, std::string& err) const
{
    return SwarmFlagshipPass{}.apply(stage, err);
}

bool SwarmFlagshipCursor::Rollback(const std::string& stage, std::string& err)
{
    return SwarmFlagshipRollback{}.apply(m_ledger, stage, err);
}

bool SwarmFlagshipCursor::recorded(const std::string& stage) const
{
    return SwarmFlagshipInspect::recorded(m_ledger, stage);
}

std::string SwarmFlagshipCursor::evidence(const std::string& stage) const
{
    return SwarmFlagshipInspect::evidence(m_ledger, stage);
}

std::string SwarmFlagshipCursor::next_stage() const
{
    return SwarmFlagshipInspect::next_stage(m_ledger);
}

bool SwarmFlagshipCursor::passed() const
{
    return m_quiet.passed();
}

bool SwarmFlagshipCursor::gpu_passed() const
{
    return m_quiet.gpu_passed();
}

bool SwarmFlagshipCursor::windows_passed() const
{
    return m_quiet.windows_passed();
}

bool SwarmFlagshipCursor::pay_passed() const
{
    return m_quiet.pay_passed();
}

bool SwarmFlagshipCursor::launched() const
{
    return m_quiet.launched();
}

bool SwarmFlagshipCursor::gpu() const
{
    return m_quiet.gpu();
}

bool SwarmFlagshipCursor::broadcast() const
{
    return m_quiet.broadcast();
}

std::uint64_t SwarmFlagshipCursor::bytes_moved() const
{
    return m_quiet.bytes_moved();
}

std::uint64_t SwarmFlagshipCursor::atoms_moved() const
{
    return m_quiet.atoms_moved();
}

std::string SwarmFlagshipCursor::automatic_spend() const
{
    return m_quiet.automatic_spend();
}

} // namespace modelnet
