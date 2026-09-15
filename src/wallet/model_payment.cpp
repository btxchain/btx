// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/model_payment.h>

namespace wallet {

bool ModelPaymentPolicy::CheckQuote(const modelnet::Quote& q, std::string& err) const
{
    if (auto_pay) {
        err = "auto_pay is refused; automatic BTX spend is zero";
        return false;
    }
    if (q.price_atoms <= 0) {
        err = "paid quote required a positive price or use free retrieval";
        return false;
    }
    if (budget_atoms <= 0) {
        err = "automatic BTX spend is zero; explicit approval required";
        return false;
    }
    if (q.price_atoms + q.fee_cap_atoms > budget_atoms) {
        err = "quote exceeds budget including fee cap";
        return false;
    }
    if (q.price_atoms > modelnet::MAX_MONEY_ATOMS) {
        err = "price out of MoneyRange";
        return false;
    }
    return true;
}

} // namespace wallet
