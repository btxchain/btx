// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_OPERATION_BUDGET_H
#define BITCOIN_MODELNET_OPERATION_BUDGET_H

#include <cstdint>
#include <string>

namespace modelnet {

/** Default concurrent cloud ops reservation (spec E.1). */
inline constexpr uint64_t OPERATION_BUDGET_DEFAULT_MAX_OPS = 4;
/** Hard cap on concurrent cloud ops reservations. */
inline constexpr uint64_t OPERATION_BUDGET_MAX_OPS_CAP = 32;

struct OperationBudget {
    uint64_t max_bytes{0};
    uint64_t max_ops{OPERATION_BUDGET_DEFAULT_MAX_OPS};
    bool cancelled{false};
};

struct CancelToken {
    bool cancelled{false};
};

bool Reserve(OperationBudget& budget, uint64_t bytes, uint64_t ops, std::string& err);
void Release(OperationBudget& budget, uint64_t bytes, uint64_t ops);
void Cancel(OperationBudget& budget, CancelToken* token = nullptr);

} // namespace modelnet

#endif // BITCOIN_MODELNET_OPERATION_BUDGET_H
