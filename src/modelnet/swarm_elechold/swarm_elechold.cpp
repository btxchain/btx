// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_elechold/swarm_elechold.h>

#include <modelnet/swarm_elechold/charge.h>
#include <modelnet/swarm_elechold/meter.h>

namespace modelnet {

bool SwarmElecHold::Measure(int64_t watt_hours, std::string& err)
{
    return SwarmElecHoldMeter{}.Apply(m_book, watt_hours, err);
}

bool SwarmElecHold::Charge(int64_t atoms, std::string& err) const
{
    return SwarmElecHoldCharge{}.Apply(atoms, err);
}

bool SwarmElecHold::measured() const
{
    return m_book.measured();
}

int64_t SwarmElecHold::watt_hours() const
{
    return m_book.watt_hours();
}

bool SwarmElecHold::charged() const
{
    return m_atoms.charged();
}

int64_t SwarmElecHold::atoms_moved() const
{
    return m_atoms.atoms_moved();
}

std::string SwarmElecHold::automatic_spend() const
{
    return m_quiet.automatic_spend();
}

bool SwarmElecHold::broadcast() const
{
    return m_quiet.broadcast();
}

int64_t SwarmElecHold::bytes_moved() const
{
    return m_quiet.bytes_moved();
}

bool SwarmElecHold::gpu() const
{
    return m_quiet.gpu();
}

} // namespace modelnet
