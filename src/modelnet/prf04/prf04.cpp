// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/prf04/prf04.h>

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/swarm_node.h>
#include <modelnet/swarm_notmandate.h>
#include <modelnet/swarm_settlebuild/swarm_settlebuild.h>

#include <string>

namespace modelnet {
namespace {

bool OfferSpendsZero(std::string& err)
{
    const SwarmBuiltinOffer offer = SwarmDefaultOffer();
    // automatic_spend_atoms stays "0" for a public offer and for any other offer.
    if (offer.seed_public && offer.automatic_spend_atoms != NIFDT_AUTOMATIC_SPEND) {
        err = NIFDT_AUTOMATIC_SPEND;
        return false;
    }
    if (offer.automatic_spend_atoms != NIFDT_AUTOMATIC_SPEND) {
        err = NIFDT_AUTOMATIC_SPEND;
        return false;
    }
    return true;
}

bool SettlementSpendsZero(std::string& err)
{
    SwarmSettleBuild settle;
    if (settle.automatic_spend() != NIFDT_AUTOMATIC_SPEND) {
        err = NIFDT_AUTOMATIC_SPEND;
        return false;
    }
    if (settle.Settle(err) || err != NIFDT_UNQUALIFIED) return false;
    if (settle.qualified() || settle.broadcast() || settle.atoms_moved() != static_cast<int64_t>(0)) {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    return true;
}

bool AbsentMandateRefused(std::string& err)
{
    SwarmNotMandate note;
    const SwarmNotMandateResult result = SwarmNoteNotMandate(note, err);
    if (result.spent || result.broadcast || result.code != "MANDATE" || err != "MANDATE") {
        if (err.empty()) err = "MANDATE";
        return false;
    }
    return true;
}

} // namespace

bool Prf04::Pass(std::string& err)
{
    if (m_done) {
        err.clear();
        return true;
    }
    if (hosts() != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    if (passed() || release_qualified() || gpu_passed() || windows_passed() || hardware_qualified()) {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    if (!OfferSpendsZero(err)) return false;
    if (!SettlementSpendsZero(err)) return false;
    if (!AbsentMandateRefused(err)) return false;
    m_done = true;
    err.clear();
    return true;
}

bool Prf04::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Prf04::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
