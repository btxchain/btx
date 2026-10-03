// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_COMPUTE_ECONOMY_H
#define BITCOIN_MODELNET_COMPUTE_ECONOMY_H

#include <modelnet/types.h>
#include <univalue.h>
#include <util/fs.h>

#include <string>

namespace modelnet {

class ModelCatalog;

void SetPwcChain(const std::string& chain);
std::string PwcChain();
NetworkId PwcNetworkId(const std::string& chain);

bool IsComputeHelperMethod(const std::string& method);
bool DispatchComputeHelperRpc(ModelCatalog& cat, const std::string& method, const UniValue& params,
                              UniValue& result, std::string& err_code, std::string& err);

/** In-process store for unit tests. `dir` is the modeldir (parent of store/). */
bool ComputeEconomySelfTestHook(const fs::path& dir, const std::string& chain, const std::string& method,
                                 const UniValue& params, UniValue& result, std::string& err_code, std::string& err);

} // namespace modelnet

#endif
