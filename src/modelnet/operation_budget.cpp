// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/operation_budget.h>

#include <algorithm>
#include <limits>
#include <mutex>
#include <unordered_map>

namespace modelnet {
namespace {

struct BudgetLedger {
    uint64_t reserved_bytes{0};
    uint64_t reserved_ops{0};
};

std::mutex g_budget_mu;
std::unordered_map<const OperationBudget*, BudgetLedger> g_budget_ledgers;

BudgetLedger& Ledger(const OperationBudget& budget)
{
    return g_budget_ledgers[&budget];
}

uint64_t EffectiveMaxOps(const OperationBudget& budget)
{
    uint64_t cap = budget.max_ops == 0 ? OPERATION_BUDGET_DEFAULT_MAX_OPS : budget.max_ops;
    if (cap > OPERATION_BUDGET_MAX_OPS_CAP) cap = OPERATION_BUDGET_MAX_OPS_CAP;
    return cap;
}

uint64_t EffectiveMaxBytes(const OperationBudget& budget)
{
    if (budget.max_bytes == 0) return std::numeric_limits<uint64_t>::max();
    return budget.max_bytes;
}

} // namespace

bool Reserve(OperationBudget& budget, uint64_t bytes, uint64_t ops, std::string& err)
{
    if (budget.cancelled) {
        err = "operation budget cancelled";
        return false;
    }
    if (ops == 0) ops = 1;
    std::lock_guard<std::mutex> lock(g_budget_mu);
    auto& st = Ledger(budget);
    const uint64_t cap_ops = EffectiveMaxOps(budget);
    const uint64_t cap_bytes = EffectiveMaxBytes(budget);
    if (st.reserved_ops + ops > cap_ops) {
        err = "operation budget ops exhausted";
        return false;
    }
    if (st.reserved_bytes + bytes > cap_bytes) {
        err = "operation budget bytes exhausted";
        return false;
    }
    st.reserved_ops += ops;
    st.reserved_bytes += bytes;
    return true;
}

void Release(OperationBudget& budget, uint64_t bytes, uint64_t ops)
{
    if (ops == 0) ops = 1;
    std::lock_guard<std::mutex> lock(g_budget_mu);
    auto it = g_budget_ledgers.find(&budget);
    if (it == g_budget_ledgers.end()) return;
    auto& st = it->second;
    st.reserved_ops = st.reserved_ops >= ops ? st.reserved_ops - ops : 0;
    st.reserved_bytes = st.reserved_bytes >= bytes ? st.reserved_bytes - bytes : 0;
    if (st.reserved_ops == 0 && st.reserved_bytes == 0) {
        g_budget_ledgers.erase(it);
    }
}

void Cancel(OperationBudget& budget, CancelToken* token)
{
    budget.cancelled = true;
    if (token) token->cancelled = true;
    std::lock_guard<std::mutex> lock(g_budget_mu);
    g_budget_ledgers.erase(&budget);
}

} // namespace modelnet
