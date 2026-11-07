// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fundscript.h>

#include <pqkey.h>
#include <script/pqm.h>

namespace modelnet {

bool SwarmAssembleFundScript(const std::vector<unsigned char>& sponsor,
                             const std::vector<unsigned char>& worker,
                             int64_t refund_height,
                             SwarmFundScript& out,
                             std::string& err)
{
    out = SwarmFundScript{};
    if (refund_height < 1) {
        err = "REFUND_UNBOUND";
        return false;
    }

    const std::vector<unsigned char> funding = BuildP2MRMultisigScript(
        2, {{PQAlgorithm::ML_DSA_44, sponsor}, {PQAlgorithm::ML_DSA_44, worker}});
    const std::vector<unsigned char> refund =
        BuildP2MRRefundLeaf(refund_height, PQAlgorithm::ML_DSA_44, sponsor);
    if (funding.empty() || refund.empty()) {
        err = "FUNDING_SCRIPT";
        return false;
    }

    int64_t locktime{0};
    PQAlgorithm algo{PQAlgorithm::ML_DSA_44};
    std::vector<unsigned char> pubkey;
    if (!ParseP2MRRefundLeaf(refund, locktime, algo, pubkey) || locktime != refund_height ||
        algo != PQAlgorithm::ML_DSA_44 || pubkey != sponsor) {
        err = "REFUND_UNBOUND";
        return false;
    }

    out.funding_script = funding;
    out.refund_script = refund;
    out.bound = true;
    err.clear();
    return true;
}

} // namespace modelnet
