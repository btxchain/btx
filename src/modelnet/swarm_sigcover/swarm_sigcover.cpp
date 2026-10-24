// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sigcover/swarm_sigcover.h>

#include <modelnet/swarm_sigcover/bind.h>
#include <modelnet/swarm_sigcover/claim.h>
#include <modelnet/swarm_sigcover/limits.h>
#include <modelnet/swarm_sigcover/names.h>
#include <modelnet/swarm_sigcover/penalty.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmSigCover::Cover(const std::string& id, bool covers_outputs, std::string& err)
{
    return m_ledger.Cover(id, covers_outputs, err);
}

bool SwarmSigCover::Preimage(const std::string& id, int64_t length, std::string& err)
{
    return m_ledger.Preimage(id, length, err);
}

bool SwarmSigCover::BindKey(const std::string& id, const std::string& key, std::string& err)
{
    if (!SwarmSigCoverIdPresent(id, err)) {
        return false;
    }
    // Find is const. RefuseBind reads the row and stores no key.
    return SwarmSigCoverRefuseBind(m_ledger.Find(id), key, err);
}

bool SwarmSigCover::Claim(const std::string& id, std::string& err)
{
    const bool covered = m_ledger.covered(id);
    const bool preimage_32 = m_ledger.preimage_len(id) == static_cast<int>(kSwarmSigCoverPreimageLen);
    return SwarmSigCoverRefuseClaim(covered, preimage_32, id, err);
}

bool SwarmSigCover::Penalty(const std::string& id, std::string& err)
{
    return SwarmSigCoverRefusePenalty(id, err);
}

bool SwarmSigCover::covered(const std::string& id) const
{
    return m_ledger.covered(id);
}

int SwarmSigCover::preimage_len(const std::string& id) const
{
    return m_ledger.preimage_len(id);
}

bool SwarmSigCover::signed_ok() const
{
    return m_flags.signed_ok();
}

bool SwarmSigCover::secp_penalty() const
{
    return m_flags.secp_penalty();
}

bool SwarmSigCover::broadcast() const
{
    return m_flags.broadcast();
}

bool SwarmSigCover::launched() const
{
    return m_flags.launched();
}

bool SwarmSigCover::gpu() const
{
    return m_flags.gpu();
}

int64_t SwarmSigCover::atoms_moved() const
{
    return m_flags.atoms_moved();
}

std::string SwarmSigCover::automatic_spend() const
{
    return m_flags.automatic_spend();
}

} // namespace modelnet
