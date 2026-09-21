// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Cognitive Reserve v1.1 pure functions. Not a second ledger or engine.
// automatic_spend_atoms stays 0. No Core v4.

#include <modelnet/hcp.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <functional>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace modelnet {

namespace {

bool ParseDec18(const std::string& s, __int128& out, std::string& err)
{
    out = 0;
    if (s.empty() || s == "+" || s == "-" || s[0] == '+') {
        err = HCP_ERR_EXACT_DECIMAL;
        return false;
    }
    for (char c : s) {
        if (c == 'e' || c == 'E' || c == 'n' || c == 'N' || c == 'i' || c == 'I') {
            err = HCP_ERR_EXACT_DECIMAL;
            return false;
        }
    }
    if (s.find("NaN") != std::string::npos || s.find("Infinity") != std::string::npos) {
        err = HCP_ERR_EXACT_DECIMAL;
        return false;
    }
    const bool neg = s[0] == '-';
    size_t i = neg ? 1 : 0;
    if (i >= s.size()) {
        err = HCP_ERR_EXACT_DECIMAL;
        return false;
    }
    __int128 whole = 0;
    int frac = 0;
    bool seen_dot = false;
    bool any = false;
    for (; i < s.size(); ++i) {
        const char c = s[i];
        if (c == '.') {
            if (seen_dot) {
                err = HCP_ERR_EXACT_DECIMAL;
                return false;
            }
            seen_dot = true;
            continue;
        }
        if (c < '0' || c > '9') {
            err = HCP_ERR_EXACT_DECIMAL;
            return false;
        }
        any = true;
        if (!seen_dot) {
            whole = whole * 10 + (c - '0');
        } else {
            if (frac < 18) {
                whole = whole * 10 + (c - '0');
                ++frac;
            }
        }
    }
    if (!any) {
        err = HCP_ERR_EXACT_DECIMAL;
        return false;
    }
    while (frac < 18) {
        whole *= 10;
        ++frac;
    }
    out = neg ? -whole : whole;
    if (out < 0) {
        err = HCP_ERR_EXACT_DECIMAL;
        return false;
    }
    return true;
}

std::string FormatDec18(__int128 n)
{
    if (n == 0) return "0";
    const bool neg = n < 0;
    if (neg) n = -n;
    std::string frac(18, '0');
    for (int i = 17; i >= 0; --i) {
        frac[i] = static_cast<char>('0' + static_cast<int>(n % 10));
        n /= 10;
    }
    std::string whole = n == 0 ? "0" : "";
    while (n > 0) {
        whole.insert(whole.begin(), static_cast<char>('0' + static_cast<int>(n % 10)));
        n /= 10;
    }
    while (!frac.empty() && frac.back() == '0') frac.pop_back();
    std::string o = (neg ? "-" : "") + whole;
    if (!frac.empty()) o += "." + frac;
    return o;
}

int64_t ClampNonNeg(__int128 n)
{
    if (n < 0) return 0;
    if (n > std::numeric_limits<int64_t>::max()) return std::numeric_limits<int64_t>::max();
    return static_cast<int64_t>(n);
}

} // namespace

int64_t Cr11Capacity(int64_t available, int64_t protected_atoms, int64_t remaining_authority)
{
    if (available < 0) available = 0;
    if (protected_atoms < 0) protected_atoms = 0;
    if (remaining_authority < 0) remaining_authority = 0;
    if (available < protected_atoms) return 0;
    const int64_t slack = available - protected_atoms;
    return slack < remaining_authority ? slack : remaining_authority;
}

bool Cr11ReportingFloorAtoms(const std::string& required_quote, const std::string& price_quote_per_coin, int exponent,
                             int64_t observed_at, int64_t now, int64_t max_age, int haircut_bps, int64_t& out,
                             std::string& err)
{
    out = 0;
    if (exponent < 0 || exponent > 18 || haircut_bps < 0 || haircut_bps >= 10000) {
        err = "INVALID_PRICE_POLICY";
        return false;
    }
    if (observed_at > now || now - observed_at > max_age) {
        err = HCP_ERR_PRICE_STALE;
        return false;
    }
    __int128 need = 0, price = 0;
    if (!ParseDec18(required_quote, need, err) || !ParseDec18(price_quote_per_coin, price, err)) return false;
    if (price <= 0) {
        err = "INVALID_PRICE";
        return false;
    }
    price = price * (10000 - haircut_bps) / 10000;
    if (price <= 0) {
        err = "INVALID_PRICE";
        return false;
    }
    __int128 scale = 1;
    for (int i = 0; i < exponent; ++i) scale *= 10;
    // ceil(need/price * 10^exp) with need,price at 1e18
    __int128 num = need * scale;
    __int128 den = price;
    __int128 q = (num + den - 1) / den;
    out = ClampNonNeg(q);
    return true;
}

bool Cr11Tco(const std::string& annual_tasks, const std::string& service_per_task, int years, const std::string& upfront,
             const std::string& annual_local, bool quality_equivalent, bool inputs_known, UniValue& out,
             std::string& err)
{
    if (!quality_equivalent) {
        err = HCP_ERR_QUALITY;
        return false;
    }
    if (!inputs_known) {
        err = HCP_ERR_INPUT_UNKNOWN;
        return false;
    }
    if (years < 1 || years > 10) {
        err = HCP_ERR_HORIZON;
        return false;
    }
    __int128 tasks = 0, unit = 0, fixed = 0, annual = 0;
    if (!ParseDec18(annual_tasks, tasks, err) || !ParseDec18(service_per_task, unit, err) ||
        !ParseDec18(upfront, fixed, err) || !ParseDec18(annual_local, annual, err)) {
        return false;
    }
    const __int128 scale = 1000000000000000000LL; // 1e18
    const __int128 tasks_whole = tasks / scale;
    const __int128 external = tasks_whole * unit * years;
    const __int128 local = fixed + annual * years;
    out = UniValue(UniValue::VOBJ);
    out.pushKV("external", FormatDec18(external));
    out.pushKV("local", FormatDec18(local));
    out.pushKV("difference", FormatDec18(external - local));
    if (unit > 0 && years > 0) {
        const __int128 be = local * scale / (unit * years);
        out.pushKV("break_even_annual_tasks", FormatDec18(be));
    } else {
        out.pushKV("break_even_annual_tasks", UniValue());
    }
    return true;
}

bool Cr11ValidateDag(const UniValue& legs, std::vector<std::string>& order, std::string& err)
{
    order.clear();
    if (!legs.isArray() || legs.size() == 0 || legs.size() > static_cast<size_t>(HCP_CR11_MAX_LEGS)) {
        err = HCP_ERR_GRAPH_LIMIT;
        return false;
    }
    std::map<std::string, UniValue> by;
    for (size_t i = 0; i < legs.size(); ++i) {
        if (!legs[i].isObject() || !legs[i].exists("leg_id")) {
            err = HCP_ERR_GRAPH_LIMIT;
            return false;
        }
        const std::string id = legs[i]["leg_id"].get_str();
        if (by.count(id)) {
            err = "DUPLICATE_LEG";
            return false;
        }
        by[id] = legs[i];
    }
    std::set<std::string> active, done;
    std::function<bool(const std::string&, int)> visit = [&](const std::string& k, int depth) -> bool {
        if (depth > HCP_CR11_MAX_DEPTH) {
            err = HCP_ERR_GRAPH_DEPTH;
            return false;
        }
        if (!by.count(k)) {
            err = "MISSING_DEPENDENCY";
            return false;
        }
        if (active.count(k)) {
            err = HCP_ERR_GRAPH_CYCLE;
            return false;
        }
        if (done.count(k)) return true;
        active.insert(k);
        if (by[k].exists("depends_on") && by[k]["depends_on"].isArray()) {
            for (size_t i = 0; i < by[k]["depends_on"].size(); ++i) {
                if (!visit(by[k]["depends_on"][i].get_str(), depth + 1)) return false;
            }
        }
        active.erase(k);
        done.insert(k);
        order.push_back(k);
        return true;
    };
    for (const auto& [k, _] : by) {
        if (!visit(k, 1)) return false;
    }
    return true;
}

bool Cr11Approved(const UniValue& decisions, const std::string& entity, const std::string& plan,
                    const std::string& policy_generation, const std::string& rule,
                    const std::set<std::string>& eligible_people, int quorum, const std::string& initiator, int64_t now,
                    bool exclude_initiator, bool veto, std::string& err)
{
    if (quorum < 1 || quorum > 32) {
        err = "INVALID_QUORUM";
        return false;
    }
    std::map<std::string, UniValue> latest;
    std::map<std::string, int64_t> seqs;
    if (!decisions.isArray()) {
        err = HCP_ERR_QUORUM;
        return false;
    }
    for (size_t i = 0; i < decisions.size(); ++i) {
        const UniValue& d = decisions[i];
        if (!d.isObject()) continue;
        const std::string dent = d.exists("entity") ? d["entity"].get_str() : "";
        const std::string dplan = d.exists("plan") ? d["plan"].get_str() : "";
        const std::string dpol = d.exists("policy_generation") ? d["policy_generation"].get_str() : "";
        const std::string drule = d.exists("rule") ? d["rule"].get_str() : "";
        if (dent != entity || dplan != plan || dpol != policy_generation || drule != rule) continue;
        const std::string person = d.exists("person") ? d["person"].get_str() : "";
        if (!eligible_people.count(person)) continue;
        if (exclude_initiator && person == initiator) continue;
        int64_t exp = 0;
        if (d.exists("expires_at")) {
            if (d["expires_at"].isStr()) exp = std::stoll(d["expires_at"].get_str());
            else if (d["expires_at"].isNum()) exp = d["expires_at"].getInt<int64_t>();
        }
        if (exp < now) continue;
        int64_t seq = 0;
        if (d.exists("sequence")) {
            if (d["sequence"].isBool()) {
                err = "INVALID_SEQUENCE";
                return false;
            }
            if (d["sequence"].isNum()) seq = d["sequence"].getInt<int64_t>();
            else if (d["sequence"].isStr()) seq = std::stoll(d["sequence"].get_str());
        }
        if (seq < 0) {
            err = "INVALID_SEQUENCE";
            return false;
        }
        if (seqs.count(person) && seqs[person] == seq) {
            const std::string a = latest[person].write();
            const std::string b = d.write();
            if (a != b) {
                err = "DECISION_EQUIVOCATION";
                return false;
            }
        }
        if (!seqs.count(person) || seq > seqs[person]) {
            latest[person] = d;
            seqs[person] = seq;
        }
    }
    if (veto) {
        for (const auto& [_, d] : latest) {
            const std::string dec = d.exists("decision") ? d["decision"].get_str() : "";
            if (dec == "REJECT") return false;
        }
    }
    int n = 0;
    for (const auto& [_, d] : latest) {
        const std::string dec = d.exists("decision") ? d["decision"].get_str() : "";
        if (dec == "APPROVE") ++n;
    }
    return n >= quorum;
}

} // namespace modelnet
