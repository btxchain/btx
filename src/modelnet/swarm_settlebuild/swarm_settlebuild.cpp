// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_settlebuild/swarm_settlebuild.h>

#include <modelnet/swarm_settlebuild/claim.h>
#include <modelnet/swarm_settlebuild/refund.h>
#include <modelnet/swarm_settlebuild/settle.h>

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace modelnet {

bool SwarmSettleBuild::BuildClaim(const std::vector<unsigned char>& payment_hash,
                                  const std::vector<unsigned char>& pubkey,
                                  std::string& err)
{
    std::vector<unsigned char> script;
    if (!SwarmSettleBuildMakeClaim(payment_hash, pubkey, script, err)) {
        return false;
    }
    m_claim = std::move(script);
    return true;
}

bool SwarmSettleBuild::BuildRefund(int64_t timeout,
                                   const std::vector<unsigned char>& pubkey,
                                   std::string& err)
{
    std::vector<unsigned char> script;
    if (!SwarmSettleBuildMakeRefund(timeout, pubkey, script, err)) {
        return false;
    }
    m_refund = std::move(script);
    return true;
}

bool SwarmSettleBuild::Settle(std::string& err)
{
    return SwarmSettleBuildRefuseSettle(has_claim(), has_refund(), err);
}

bool SwarmSettleBuild::has_claim() const
{
    return !m_claim.empty();
}

bool SwarmSettleBuild::has_refund() const
{
    return !m_refund.empty();
}

const std::vector<unsigned char>& SwarmSettleBuild::claim_script() const
{
    return m_claim;
}

const std::vector<unsigned char>& SwarmSettleBuild::refund_script() const
{
    return m_refund;
}

bool SwarmSettleBuild::qualified() const
{
    return m_flags.qualified();
}

bool SwarmSettleBuild::broadcast() const
{
    return m_flags.broadcast();
}

bool SwarmSettleBuild::launched() const
{
    return m_flags.launched();
}

bool SwarmSettleBuild::gpu() const
{
    return m_flags.gpu();
}

int64_t SwarmSettleBuild::atoms_moved() const
{
    return m_flags.atoms_moved();
}

std::string SwarmSettleBuild::automatic_spend() const
{
    return m_flags.automatic_spend();
}

bool SwarmSettleBuild::secp_penalty() const
{
    return m_flags.secp_penalty();
}

} // namespace modelnet
