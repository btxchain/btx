// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_PACKAGE_RUNTIME_H
#define BITCOIN_MODELNET_PACKAGE_RUNTIME_H

#include <modelnet/types.h>
#include <univalue.h>

#include <string>
#include <vector>

namespace modelnet {

struct RuntimePlan {
    std::string plan_id_hex;
    Digest48 package_core_id{};
    std::string profile_id;
    std::string adapter_id;
    std::string verified_executable_digest;
    std::string leased_path;
    std::vector<std::string> argv;
    bool executes{false};
    UniValue json;
};

/**
 * Plan only. Rejects arbitrary shell, model-supplied scripts, and unknown
 * adapter flags. Execution requires a separate local authorization.
 */
bool PlanBtxRuntime(const UniValue& core, const UniValue& receipt, const UniValue& trusted_adapter,
                    RuntimePlan& out, std::string& err_code, std::string& err);
bool RuntimeArgvAllowed(const std::string& adapter_id, const std::vector<std::string>& argv,
                       std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_PACKAGE_RUNTIME_H
