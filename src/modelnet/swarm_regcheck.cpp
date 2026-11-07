// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_regcheck.h>

namespace modelnet {

// An isolated check can see a script and a UTXO flag. It mines nothing and broadcasts nothing.
SwarmRegCheckResult SwarmCheckRegtest(const SwarmRegCheck& check, std::string& err)
{
    SwarmRegCheckResult out;
    out.mined = false;
    out.broadcast = false;
    out.blocks = 0;

    if (check.check_id.empty()) {
        out.code = "CHECK";
        err = "CHECK";
        out.script_ok = false;
        return out;
    }
    if (!check.script_present) {
        out.code = "SCRIPT";
        err = "SCRIPT";
        out.script_ok = false;
        return out;
    }
    if (!check.utxo_known) {
        out.code = "UTXO";
        err = "UTXO";
        out.script_ok = false;
        return out;
    }
    if (check.want_mine || check.want_broadcast) {
        out.code = "HELD";
        err = "HELD";
        out.script_ok = true;
        return out;
    }
    out.code = "NOTED";
    err.clear();
    out.script_ok = true;
    return out;
}

} // namespace modelnet
