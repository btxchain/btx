// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/package_economy.h>

#include <modelnet/economy.h>
#include <modelnet/package_export.h>

#include <string>

namespace modelnet {
namespace {

constexpr int kMaxJsonDepth = 32;

std::string NormalizeKey(std::string k)
{
    for (char& c : k) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
        if (c == '-') c = '_';
    }
    return k;
}

std::string CompactKey(const std::string& k)
{
    std::string c;
    c.reserve(k.size());
    for (char ch : k) {
        if (ch != '_') c.push_back(ch);
    }
    return c;
}

bool ExtraCredentialSentinel(const std::string& key)
{
    const std::string k = NormalizeKey(key);
    const std::string c = CompactKey(k);
    if (c.find("hftoken") != std::string::npos || c.find("huggingface") != std::string::npos) return true;
    if (c.find("distributiontoken") != std::string::npos || c.find("installtoken") != std::string::npos) {
        return true;
    }
    if (c.find("awsaccesskey") != std::string::npos || c.find("s3access") != std::string::npos) return true;
    if (c.find("awssecret") != std::string::npos || c.find("s3secret") != std::string::npos) return true;
    return false;
}

bool ScanKeys(const UniValue& v, std::string& err, int depth)
{
    if (depth > kMaxJsonDepth) {
        err = "nesting";
        return false;
    }
    if (v.isArray()) {
        for (const auto& e : v.getValues()) {
            if (!ScanKeys(e, err, depth + 1)) return false;
        }
        return true;
    }
    if (!v.isObject()) return true;
    for (const auto& key : v.getKeys()) {
        if (PublicExportKeyForbidden(key) || ExtraCredentialSentinel(key)) {
            err = "secret-bearing key: " + key;
            return false;
        }
        if (!ScanKeys(v[key], err, depth + 1)) return false;
    }
    return true;
}

bool LooksLikePresignedUrl(const std::string& s)
{
    auto has = [&](const char* n) { return s.find(n) != std::string::npos; };
    if (has("X-Amz-Signature") || has("x-amz-signature") || has("X-Amz-Credential") ||
        has("x-amz-credential") || has("X-Amz-Algorithm") || has("x-amz-algorithm")) {
        return true;
    }
    if (has("AWSAccessKeyId") || has("X-Goog-Signature") || has("X-Goog-Credential")) return true;
    if (has("Signature=") && (has("http://") || has("https://") || has("X-Amz-") || has("x-amz-"))) {
        return true;
    }
    return false;
}

bool ScanPresigned(const UniValue& v, int depth)
{
    if (depth > kMaxJsonDepth) return true;
    if (v.isStr()) return LooksLikePresignedUrl(v.get_str());
    if (v.isArray()) {
        for (const auto& e : v.getValues()) {
            if (ScanPresigned(e, depth + 1)) return true;
        }
        return false;
    }
    if (!v.isObject()) return false;
    for (const auto& key : v.getKeys()) {
        const std::string k = NormalizeKey(key);
        const std::string c = CompactKey(k);
        if (c.find("presigned") != std::string::npos) return true;
        if (ScanPresigned(v[key], depth + 1)) return true;
    }
    return false;
}

std::string ObservationState(const UniValue& o)
{
    if (o.isObject() && o.exists("state") && o["state"].isStr()) return o["state"].get_str();
    return {};
}

bool AmountMismatch(const UniValue& cached, const UniValue& local)
{
    auto num = [](const UniValue& o, const char* k, int64_t& out) {
        if (!o.isObject() || !o.exists(k)) return false;
        if (o[k].isNum()) {
            out = o[k].getInt<int64_t>();
            return true;
        }
        if (o[k].isStr()) {
            try {
                out = std::stoll(o[k].get_str());
                return true;
            } catch (...) {
                return false;
            }
        }
        return false;
    };
    int64_t a = 0, b = 0;
    const bool have_a = num(cached, "confirmed_funded_atoms", a) || num(cached, "percent_funded", a);
    const bool have_b = num(local, "confirmed_funded_atoms", b) || num(local, "percent_funded", b);
    return have_a && have_b && a != b;
}

} // namespace

bool EvaluatePackageRewardPreview(const UniValue& core, const UniValue& cached_observation,
                                  const UniValue& local_chain, PackageRewardPreview& out,
                                  std::string& err_code, std::string& err)
{
    out = {};
    out.preview_is_observation = true;
    out.controls_spending = false;
    out.automatic_spend_atoms = PackageAutomaticSpendAtoms();
    err_code.clear();
    err.clear();

    if (core.isObject() && core.exists("automatic_spend_atoms")) {
        if (!core["automatic_spend_atoms"].isNum() ||
            core["automatic_spend_atoms"].getInt<int64_t>() != 0) {
            err_code = "NONCANONICAL_PAYLOAD";
            err = "automatic_spend_atoms must be 0";
            return false;
        }
    }

    out.cached_state = ObservationState(cached_observation);
    out.current_state = ObservationState(local_chain);
    const bool mismatch = (!out.cached_state.empty() && !out.current_state.empty() &&
                           out.cached_state != out.current_state) ||
                          AmountMismatch(cached_observation, local_chain);
    if (mismatch) {
        out.cached_stale = true;
    } else if (!out.cached_state.empty() && out.current_state.empty()) {
        out.cached_stale = true;
        out.current_state = "economic state unknown";
    } else {
        out.cached_stale = false;
        if (out.current_state.empty() && out.cached_state.empty()) {
            out.current_state = "economic state unknown";
        }
    }

    out.json.setObject();
    out.json.pushKV("cached_stale", out.cached_stale);
    out.json.pushKV("preview_is_observation", true);
    out.json.pushKV("controls_spending", false);
    out.json.pushKV("automatic_spend_atoms", out.automatic_spend_atoms);
    if (!out.cached_state.empty()) out.json.pushKV("cached_state", out.cached_state);
    out.json.pushKV("current_state", out.current_state);
    if (cached_observation.isObject() &&
        (cached_observation.exists("percent_funded") || cached_observation.exists("funded_percent"))) {
        out.json.pushKV("cached_percent_funded_ignored", true);
    }
    return true;
}

bool PlanFreeOnlyAwaitingRelease(const UniValue& core, int64_t elapsed_ms, UniValue& out,
                                 std::string& err_code, std::string& err)
{
    out = UniValue(UniValue::VOBJ);
    err_code.clear();
    err.clear();
    std::string mode = "FREE_ONLY";
    if (core.isObject() && core.exists("agent_handoff") && core["agent_handoff"].isObject()) {
        const UniValue& ah = core["agent_handoff"];
        if (ah.exists("acquisition") && ah["acquisition"].isObject()) {
            const UniValue& ac = ah["acquisition"];
            if (ac.exists("retrieval_mode") && ac["retrieval_mode"].isStr()) {
                mode = ac["retrieval_mode"].get_str();
            }
        }
    }
    if (mode != "FREE_ONLY") {
        err_code = "NONCANONICAL_PAYLOAD";
        err = "FREE_ONLY required";
        return false;
    }
    if (core.isObject() && core.exists("automatic_spend_atoms") &&
        (!core["automatic_spend_atoms"].isNum() || core["automatic_spend_atoms"].getInt<int64_t>() != 0)) {
        err_code = "NONCANONICAL_PAYLOAD";
        err = "automatic_spend_atoms must be 0";
        return false;
    }
    (void)elapsed_ms;
    err_code = "WAITING_FOR_PUBLIC_RELEASE";
    out.pushKV("status", "WAITING_FOR_PUBLIC_RELEASE");
    out.pushKV("retrieval_mode", "FREE_ONLY");
    out.pushKV("automatic_spend_atoms", PackageAutomaticSpendAtoms());
    out.pushKV("spent_atoms", 0);
    out.pushKV("converted_to_paid", false);
    out.pushKV("timer_cannot_convert_to_paid", true);
    out.pushKV("funding_option", "explicit_existing_rpc");
    return true;
}

int64_t PackageAutomaticSpendAtoms()
{
    return AutomaticSpendAtoms();
}

bool PackagePortableKeysAllowed(const UniValue& value, std::string& err)
{
    err.clear();
    if (!value.isObject() && !value.isArray()) {
        err = "portable value";
        return false;
    }
    return ScanKeys(value, err, 0);
}

bool PackageContainsPresignedCapability(const UniValue& value)
{
    return ScanPresigned(value, 0);
}

bool LintPackagePortable(const UniValue& value, std::string& err)
{
    if (!PackagePortableKeysAllowed(value, err)) return false;
    if (PackageContainsPresignedCapability(value)) {
        err = "embedded presigned capability";
        return false;
    }
    return true;
}

} // namespace modelnet
