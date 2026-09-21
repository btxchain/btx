// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Cognitive Reserve Layer v1.2 helpers. Same HcpEngine; not a second product.

#include <modelnet/hcp.h>

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstring>
#include <limits>
#include <utility>

namespace modelnet {

bool Crl12BrandDispatch(const std::string& s)
{
    // String denylist on /layer/ payloads. This is not operational routing
    // isolation: a payload that names a listed brand is rejected even when it
    // is only metadata. It does not inspect adapters, bindings, or settlement
    // paths.
    std::string l;
    l.reserve(s.size());
    for (unsigned char c : s) l.push_back(static_cast<char>(std::tolower(c)));
    static const char* k[] = {"goldman", "blackrock", "coinbase", "binance", "kraken", "fidelity",
                              "jpmorgan", "j.p. morgan", "morgan stanley", "citadel", "bridgewater"};
    for (const char* b : k) {
        if (l.find(b) != std::string::npos) return true;
    }
    return false;
}

bool Crl12FiniteDecimal(const std::string& s, std::string& err)
{
    err.clear();
    if (s.empty()) {
        err = HCP_ERR_NONFINITE;
        return false;
    }
    std::string l;
    for (unsigned char c : s) l.push_back(static_cast<char>(std::tolower(c)));
    if (l.find("nan") != std::string::npos || l.find("inf") != std::string::npos) {
        err = HCP_ERR_NONFINITE;
        return false;
    }
    size_t i = 0;
    if (s[i] == '+' || s[i] == '-') ++i;
    if (i >= s.size()) {
        err = HCP_ERR_NONFINITE;
        return false;
    }
    bool digit = false, dot = false;
    for (; i < s.size(); ++i) {
        if (s[i] >= '0' && s[i] <= '9') {
            digit = true;
            continue;
        }
        if (s[i] == '.' && !dot) {
            dot = true;
            continue;
        }
        err = HCP_ERR_NONFINITE;
        return false;
    }
    if (!digit) {
        err = HCP_ERR_NONFINITE;
        return false;
    }
    return true;
}

namespace {

bool ParseUnsignedDecimalParts(const std::string& s, std::string& digits, int& scale, std::string& err)
{
    if (!Crl12FiniteDecimal(s, err)) return false;
    size_t i = 0;
    if (s[i] == '+') ++i;
    if (s[i] == '-') {
        err = HCP_ERR_NONFINITE;
        return false;
    }
    std::string ip, fp;
    bool dot = false;
    for (; i < s.size(); ++i) {
        if (s[i] == '.') {
            if (dot) {
                err = HCP_ERR_NONFINITE;
                return false;
            }
            dot = true;
            continue;
        }
        (dot ? fp : ip).push_back(s[i]);
    }
    if (ip.empty()) ip = "0";
    scale = static_cast<int>(fp.size());
    digits = ip + fp;
    size_t z = 0;
    while (z + 1 < digits.size() && digits[z] == '0') ++z;
    digits = digits.substr(z);
    return true;
}

std::string AddDigitStrings(std::string a, std::string b)
{
    if (a.size() < b.size()) std::swap(a, b);
    std::string out;
    out.reserve(a.size() + 1);
    int carry = 0;
    int i = static_cast<int>(a.size()) - 1;
    int j = static_cast<int>(b.size()) - 1;
    while (i >= 0 || j >= 0 || carry) {
        int x = carry;
        if (i >= 0) x += a[i--] - '0';
        if (j >= 0) x += b[j--] - '0';
        out.push_back(static_cast<char>('0' + (x % 10)));
        carry = x / 10;
    }
    std::reverse(out.begin(), out.end());
    return out;
}

std::string FormatScaledDigits(std::string digits, int scale)
{
    if (scale < 0) scale = 0;
    if (static_cast<int>(digits.size()) <= scale) {
        digits = std::string(static_cast<size_t>(scale) - digits.size() + 1, '0') + digits;
    }
    if (scale == 0) return digits;
    std::string out = digits.substr(0, digits.size() - static_cast<size_t>(scale)) + "." +
                      digits.substr(digits.size() - static_cast<size_t>(scale));
    while (!out.empty() && out.back() == '0') out.pop_back();
    if (!out.empty() && out.back() == '.') out.pop_back();
    return out.empty() ? "0" : out;
}

} // namespace

bool Crl12AddDecimal(const std::string& a, const std::string& b, std::string& out, std::string& err)
{
    std::string da, db;
    int sa = 0, sb = 0;
    if (!ParseUnsignedDecimalParts(a, da, sa, err) || !ParseUnsignedDecimalParts(b, db, sb, err)) return false;
    const int scale = std::max(sa, sb);
    da.append(static_cast<size_t>(scale - sa), '0');
    db.append(static_cast<size_t>(scale - sb), '0');
    out = FormatScaledDigits(AddDigitStrings(std::move(da), std::move(db)), scale);
    return true;
}

bool Crl12ScaleDecimal(const std::string& a, int64_t numerator, int64_t denominator, std::string& out, std::string& err)
{
    out.clear();
    if (denominator == 0) {
        err = HCP_ERR_NONFINITE;
        return false;
    }
    std::string digits;
    int scale = 0;
    bool neg = false;
    std::string src = a;
    if (!src.empty() && src[0] == '-') {
        neg = true;
        src = src.substr(1);
    }
    if (numerator < 0) {
        neg = !neg;
        numerator = -numerator;
    }
    if (denominator < 0) {
        neg = !neg;
        denominator = -denominator;
    }
    if (numerator > 100000000LL || denominator > 100000000LL) {
        err = HCP_ERR_NONFINITE;
        return false;
    }
    if (!ParseUnsignedDecimalParts(src, digits, scale, err)) return false;
    std::string acc = "0";
    std::string cur = digits;
    int64_t m = numerator;
    while (m > 0) {
        if (m & 1) acc = AddDigitStrings(acc, cur);
        cur = AddDigitStrings(cur, cur);
        m >>= 1;
    }
    // Long division of acc by denominator, producing scale+8 fractional digits.
    const int extra = 8;
    acc.append(static_cast<size_t>(extra), '0');
    std::string quot;
    std::string rem;
    for (char c : acc) {
        rem.push_back(c);
        size_t z = 0;
        while (z + 1 < rem.size() && rem[z] == '0') ++z;
        rem = rem.substr(z);
        int64_t r = 0;
        for (char d : rem) {
            if (r > (std::numeric_limits<int64_t>::max() - (d - '0')) / 10) {
                err = HCP_ERR_NONFINITE;
                return false;
            }
            r = r * 10 + (d - '0');
        }
        const int64_t q = r / denominator;
        r %= denominator;
        quot.push_back(static_cast<char>('0' + q));
        rem = std::to_string(r);
    }
    size_t z = 0;
    while (z + 1 < quot.size() && quot[z] == '0') ++z;
    quot = quot.substr(z);
    std::string formatted = FormatScaledDigits(quot, scale + extra);
    if (neg && formatted != "0") formatted.insert(formatted.begin(), '-');
    out = std::move(formatted);
    return true;
}

std::string Crl12SchemaDigest()
{
#ifdef BTX_CRL12_SCHEMA_SHA384
    return BTX_CRL12_SCHEMA_SHA384;
#else
    return {};
#endif
}

std::string Crl12OperationsDigest()
{
#ifdef BTX_CRL12_OPERATIONS_SHA384
    return BTX_CRL12_OPERATIONS_SHA384;
#else
    return {};
#endif
}

std::string Cr11SchemaDigest()
{
#ifdef BTX_CR11_SCHEMA_SHA384
    return BTX_CR11_SCHEMA_SHA384;
#else
    return {};
#endif
}

std::string Cr11OperationsDigest()
{
#ifdef BTX_CR11_OPERATIONS_SHA384
    return BTX_CR11_OPERATIONS_SHA384;
#else
    return {};
#endif
}

bool Crl12MetricEligible(const std::string& metric_kind, const std::string& mandate, const std::string& asset_kind)
{
    if (asset_kind == "CAPABILITY" || asset_kind == "UTILITY") {
        return metric_kind == "CAPABILITY_COUNT" || metric_kind == "SCENARIO_VALUE";
    }
    if (metric_kind == "AUM") return mandate == "MANAGED";
    if (metric_kind == "AUC") return mandate == "CUSTODY";
    if (metric_kind == "AUA") return mandate == "ADMIN";
    if (metric_kind == "PLATFORM_ASSETS") return mandate == "ADMIN" || mandate == "PLATFORM";
    if (metric_kind == "FINANCIAL_NAV") return mandate == "MANAGED" || mandate == "CUSTODY" || mandate == "OWNER";
    if (metric_kind == "ACTUAL_COST") return mandate == "MANAGED" || mandate == "OWNER";
    if (metric_kind == "CAPABILITY_COUNT") return asset_kind == "CAPABILITY";
    return false;
}

bool Crl12CsvSafe(const std::string& cell, std::string& out)
{
    out = cell;
    if (cell.empty()) return true;
    const char c = cell[0];
    if (c == '=' || c == '+' || c == '-' || c == '@' || c == '\t') {
        out = "'" + cell;
    }
    return true;
}

} // namespace modelnet
