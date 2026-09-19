// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// NETWORK-02 costly writes require a caller-scoped idempotency_key.
// Existing native fixtures that predate the gate get a unique key so they
// still exercise the write path. Suites that pin missing-key /
// IDEMPOTENCY_CONFLICT must not use this helper.

#ifndef BITCOIN_TEST_MODELNET_N02_IDEM_H
#define BITCOIN_TEST_MODELNET_N02_IDEM_H

#include <univalue.h>

#include <atomic>
#include <string>

inline bool IsNetwork02CostlyWriteMethodForTests(const std::string& method)
{
    return method == "setcloudstorage" || method == "addmodelstorage" || method == "executemodelimport" ||
           method == "createbtxpackage" || method == "exportbtxbundle" || method == "exportbtxpackage" ||
           method == "preparemodelerasure" || method == "executemodelerasure" ||
           method == "setbootstrapdistributor" || method == "setmodeluploadpolicy" ||
           method == "planmodelstoragemigration" || method == "executemodelstoragemigration" ||
           method == "setmodelswarmhealer" || method == "settorrentsourcepolicy" ||
           method == "setmodeldiscoverypolicy" || method == "setmodelmirror" ||
           method == "setmodelstoragepolicy" || method == "executebtxacquisition";
}

inline UniValue WithN02Idempotency(const std::string& method, UniValue params)
{
    if (!IsNetwork02CostlyWriteMethodForTests(method)) return params;
    static std::atomic<uint64_t> seq{0};
    const auto inject = [&](UniValue o) {
        if (o.isObject() && !o.exists("idempotency_key")) {
            o.pushKV("idempotency_key", method + "-native-" + std::to_string(++seq));
        }
        return o;
    };
    if (params.isArray()) {
        if (params.empty()) {
            UniValue o(UniValue::VOBJ);
            o.pushKV("idempotency_key", method + "-native-" + std::to_string(++seq));
            UniValue arr(UniValue::VARR);
            arr.push_back(o);
            return arr;
        }
        if (params[0].isObject()) {
            UniValue arr(UniValue::VARR);
            arr.push_back(inject(params[0]));
            for (size_t i = 1; i < params.size(); ++i) arr.push_back(params[i]);
            return arr;
        }
        return params;
    }
    if (params.isObject()) return inject(params);
    return params;
}

#endif // BITCOIN_TEST_MODELNET_N02_IDEM_H
