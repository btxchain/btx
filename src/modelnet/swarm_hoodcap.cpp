// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_hoodcap.h>

namespace modelnet {

bool SwarmHoodCap::Admit(const Offer& offer, std::string& err)
{
    if (offer.node.empty() || offer.domain.empty()) {
        err = "NODE";
        return false;
    }
    if (offer.rtt_ms < 0) {
        err = "RTT";
        return false;
    }
    for (const Admission& admission : m_admissions) {
        if (admission.node == offer.node) {
            err = "REPLAY";
            return false;
        }
    }
    if (offer.known && known_count() == 4) {
        err = "HOOD";
        return false;
    }
    if (!offer.known && new_count() == 2) {
        err = "HOOD";
        return false;
    }
    m_admissions.push_back(Admission{offer.node, offer.known});
    err.clear();
    return true;
}

int SwarmHoodCap::known_count() const
{
    int count = 0;
    for (const Admission& admission : m_admissions) {
        if (admission.known) {
            ++count;
        }
    }
    return count;
}

int SwarmHoodCap::new_count() const
{
    int count = 0;
    for (const Admission& admission : m_admissions) {
        if (!admission.known) {
            ++count;
        }
    }
    return count;
}

bool SwarmHoodCap::bytes_moved() const
{
    return false;
}

} // namespace modelnet
