// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/slice_admit/slice_admit.h>

#include <modelnet/admission_routes.h>
#include <modelnet/model_admission.h>
#include <modelnet/nifdt_contract/contract.h>

#include <string>

namespace modelnet {

bool SliceAdmit::Pass(std::string& err)
{
    std::string code;
    if (!modelnet::LivePathAllowed("slice-admit-open", false, code) || !code.empty()) {
        err = code;
        return false;
    }
    modelnet::Quarantine("slice-admit-hold");
    if (modelnet::LivePathAllowed("slice-admit-hold", false, code) || code != "BTX035_QUARANTINE") {
        err = code;
        return false;
    }
    err.clear();
    return true;
}

bool SliceAdmit::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool SliceAdmit::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
