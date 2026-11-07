// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paytemplate.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmPayTemplateResult SwarmRecordFundingTemplate(const SwarmPayTemplate& pay, std::string& err)
{
    SwarmPayTemplateResult result;
    result.broadcast = false;
    result.mined = false;
    result.atoms = 0;
    if (pay.channel_id.empty()) {
        result.code = "CHANNEL";
        result.broadcast = false;
        result.mined = false;
        result.atoms = 0;
        err = "CHANNEL";
        return result;
    }
    if (!pay.signer) {
        result.code = "SIGNER";
        result.broadcast = false;
        result.mined = false;
        result.atoms = 0;
        err = "SIGNER";
        return result;
    }
    if (pay.atoms < 0) {
        result.code = "RANGE";
        result.broadcast = false;
        result.mined = false;
        result.atoms = 0;
        err = "RANGE";
        return result;
    }
    // A funding template record does not broadcast or mine.
    if (pay.want_broadcast) {
        result.code = "HELD";
        result.broadcast = false;
        result.mined = false;
        result.atoms = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.broadcast = false;
    result.mined = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
