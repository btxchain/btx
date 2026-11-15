// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_parentage/swarm_parentage.h>

#include <modelnet/swarm_parentage/claim.h>
#include <modelnet/swarm_parentage/hub.h>
#include <modelnet/swarm_parentage/promote.h>
#include <modelnet/swarm_parentage/trust.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmParentage::Bind(const std::string& checkpoint,
                          const std::string& parent,
                          const std::string& recipe,
                          const std::string& dataset,
                          const std::string& license,
                          std::string& err)
{
    return m_ledger.Bind(checkpoint, parent, recipe, dataset, license, err);
}

bool SwarmParentage::Hub(const std::string& checkpoint, const std::string& card, std::string& err)
{
    return SwarmParentageClassifyHub(checkpoint, card, err);
}

bool SwarmParentage::Claim(const std::string& checkpoint, std::string& err)
{
    return SwarmParentageClassifyClaim(checkpoint, err);
}

bool SwarmParentage::Trust(const std::string& checkpoint, std::string& err)
{
    return SwarmParentageClassifyTrust(m_ledger.bound(checkpoint), err);
}

bool SwarmParentage::Promote(const std::string& checkpoint, std::string& err)
{
    return SwarmParentageClassifyPromote(m_ledger.bound(checkpoint), m_ledger.license_of(checkpoint), err);
}

bool SwarmParentage::bound(const std::string& checkpoint) const
{
    return m_ledger.bound(checkpoint);
}

std::string SwarmParentage::parent_of(const std::string& checkpoint) const
{
    return m_ledger.parent_of(checkpoint);
}

std::string SwarmParentage::recipe_of(const std::string& checkpoint) const
{
    return m_ledger.recipe_of(checkpoint);
}

std::string SwarmParentage::dataset_of(const std::string& checkpoint) const
{
    return m_ledger.dataset_of(checkpoint);
}

std::string SwarmParentage::license_of(const std::string& checkpoint) const
{
    return m_ledger.license_of(checkpoint);
}

bool SwarmParentage::trusted() const
{
    return m_flags.trusted();
}

bool SwarmParentage::realm_promoted() const
{
    return m_flags.realm_promoted();
}

bool SwarmParentage::exact_replay_admitted() const
{
    return m_flags.exact_replay_admitted();
}

bool SwarmParentage::launched() const
{
    return m_flags.launched();
}

bool SwarmParentage::gpu() const
{
    return m_flags.gpu();
}

int64_t SwarmParentage::bytes_moved() const
{
    return m_flags.bytes_moved();
}

} // namespace modelnet
