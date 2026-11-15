// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_wearhold/swarm_wearhold.h>

#include <modelnet/swarm_wearhold/charge.h>
#include <modelnet/swarm_wearhold/meter.h>

namespace modelnet {

bool SwarmWearHold::Measure(int64_t joules, std::string& err)
{
    return SwarmWearHoldMeter{}.Apply(m_book, joules, err);
}

bool SwarmWearHold::Charge(int64_t atoms, std::string& err) const
{
    return SwarmWearHoldCharge{}.Apply(atoms, err);
}

bool SwarmWearHold::measured() const
{
    return m_book.measured();
}

int64_t SwarmWearHold::joules() const
{
    return m_book.joules();
}

bool SwarmWearHold::charged() const
{
    return m_atoms.charged();
}

int64_t SwarmWearHold::atoms_moved() const
{
    return m_atoms.atoms_moved();
}

std::string SwarmWearHold::automatic_spend() const
{
    return m_quiet.automatic_spend();
}

bool SwarmWearHold::broadcast() const
{
    return m_quiet.broadcast();
}

int64_t SwarmWearHold::bytes_moved() const
{
    return m_quiet.bytes_moved();
}

bool SwarmWearHold::gpu() const
{
    return m_quiet.gpu();
}

} // namespace modelnet
