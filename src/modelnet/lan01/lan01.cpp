// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/lan01/lan01.h>

#include <modelnet/nifdt_contract/contract.h>

#include <string>

namespace modelnet {

bool Lan01::Observe(const std::string& scenario, bool manual_address, bool internet_up, bool bootstrap_lost, int peers, std::string& err)
{
    if (scenario != "B" && scenario != "C" && scenario != "E") {
        err = "ID";
        return false;
    }
    if (scenario == "B") {
        if (manual_address) {
            // A supplied address is not discovery. peers_discovered stays 0.
            err = "MANUAL";
            return false;
        }
        if (peers < 2) {
            err = NIFDT_UNQUALIFIED;
            return false;
        }
        m_discovered = true;
        m_peers_discovered = peers;
        err.clear();
        return true;
    }
    if (scenario == "C") {
        if (internet_up) {
            err = "ONLINE";
            return false;
        }
        if (peers < 2) {
            err = NIFDT_UNQUALIFIED;
            return false;
        }
        err.clear();
        return true;
    }
    if (!bootstrap_lost) {
        err = "BOOTSTRAP";
        return false;
    }
    if (peers < 1) {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
