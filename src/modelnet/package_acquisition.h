// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_PACKAGE_ACQUISITION_H
#define BITCOIN_MODELNET_PACKAGE_ACQUISITION_H

#include <modelnet/package_core.h>
#include <univalue.h>

#include <string>
#include <vector>

namespace modelnet {

struct AcquisitionPlan {
    std::string plan_id_hex;
    Digest48 package_core_id{};
    std::string network;
    std::string variant_id;
    std::vector<std::string> resource_ids;
    std::string destination;
    std::string retrieval_mode{"FREE_ONLY"};
    std::string source_policy{"NATIVE_ONLY"};
    std::string expires_at_ms;
    UniValue json;
};

struct AcquisitionReceipt {
    std::string receipt_id_hex;
    std::string plan_id_hex;
    std::string ready_state;
    UniValue json;
};

/** Plan digest excludes plan_id and later authorization_ref. */
bool PlanBtxAcquisition(const UniValue& core, const UniValue& local_policy, AcquisitionPlan& out,
                        std::string& err_code, std::string& err);
bool AcquisitionPlanDigest(const AcquisitionPlan& plan, Digest48& out, std::string& err);
bool SelectPackageVariant(const UniValue& core, const UniValue& local_obs, std::string& variant_id,
                          std::string& err_code, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_PACKAGE_ACQUISITION_H
