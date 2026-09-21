// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/package_runtime.h>

#include <modelnet/package_core.h>
#include <modelnet/package_pjson.h>
#include <crypto/common.h>
#include <crypto/sha384.h>
#include <util/strencodings.h>
#include <util/time.h>

#include <cstring>
#include <set>
#include <string>
#include <vector>

namespace modelnet {
namespace {

constexpr const char* kRuntimePlanDomain = "BTX/RuntimePlan/v1";
constexpr const char* kLocalCliV1 = "local-cli-v1";

const std::set<std::string> kSchemaKeys{"context_tokens", "gpu_layers", "threads"};

const std::set<std::string> kAllowedFlags{
    "m", "model", "model-path",
    "c", "ctx-size", "context-size", "context", "context-tokens",
    "ngl", "n-gpu-layers", "gpu-layers",
    "t", "threads",
};

const std::set<std::string> kForbiddenCommands{
    "sh", "bash", "dash", "zsh", "csh", "tcsh", "fish", "ksh", "busybox",
    "sudo", "su", "env", "curl", "wget", "ncat", "nc", "ncat.exe",
    "python", "python2", "python3", "perl", "ruby", "node", "nodejs", "php", "lua",
    "osascript", "powershell", "pwsh", "cmd", "cmd.exe", "powershell.exe",
};

const std::set<std::string> kForbiddenParamKeys{
    "trust_remote_code", "trust-remote-code", "trustremotecode",
    "plugins", "plugin", "custom_code", "script", "scripts", "code",
    "cmd", "command", "shell", "sh", "bash", "python", "curl", "env",
    "ld_preload", "ld-preload", "pythonpath", "pythonstartup",
    "extra_argv", "argv", "executable", "executable_path", "preload",
    "remote_code", "hf_token", "token", "api_key", "eval",
};

bool Fail(std::string& err_code, std::string& err, const char* code, const std::string& msg)
{
    err_code = code;
    err = msg.empty() ? code : msg;
    return false;
}

std::string Lower(std::string s)
{
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

std::string Basename(const std::string& path)
{
    const auto pos = path.find_last_of("/\\");
    return pos == std::string::npos ? path : path.substr(pos + 1);
}

bool EndsWith(const std::string& s, const std::string& suf)
{
    return s.size() >= suf.size() && s.compare(s.size() - suf.size(), suf.size(), suf) == 0;
}

bool BoolTrue(const UniValue& o, const char* key)
{
    return o.isObject() && o.exists(key) && o[key].isBool() && o[key].get_bool();
}

bool IsInterpreter(const std::string& token)
{
    const std::string b = Lower(Basename(token));
    if (kForbiddenCommands.count(b)) return true;
    if (b.rfind("python", 0) == 0) return true;
    return false;
}

bool IsScriptPath(const std::string& token)
{
    const std::string b = Lower(Basename(token));
    static const char* const kExt[] = {".py", ".sh", ".bash", ".js", ".mjs", ".pl", ".rb", ".lua",
                                       ".bat", ".ps1", ".cmd", ".pyc", ".ipy", ".ipynb"};
    for (const char* e : kExt) {
        if (EndsWith(b, e)) return true;
    }
    return false;
}

bool HasEnvInterpolation(const std::string& t)
{
    if (t.find('$') != std::string::npos) return true;
    if (t.find('`') != std::string::npos) return true;
    const auto a = t.find('%');
    if (a != std::string::npos) {
        const auto b = t.find('%', a + 1);
        if (b != std::string::npos && b > a + 1) return true;
    }
    return false;
}

bool HasShellMeta(const std::string& t)
{
    if (t.find_first_of(";&|<>\n\r*(){}[]!") != std::string::npos) return true;
    if (t.find("://") != std::string::npos) return true;
    return HasEnvInterpolation(t);
}

bool AllDigits(const std::string& t)
{
    if (t.empty()) return false;
    for (char c : t) {
        if (c < '0' || c > '9') return false;
    }
    return true;
}

std::string FlagName(const std::string& tok, std::string& eq_value, bool& has_eq)
{
    has_eq = false;
    eq_value.clear();
    std::string s = tok;
    while (!s.empty() && s[0] == '-') s.erase(s.begin());
    const auto eq = s.find('=');
    if (eq != std::string::npos) {
        has_eq = true;
        eq_value = s.substr(eq + 1);
        s = s.substr(0, eq);
    }
    for (char& c : s) {
        if (c == '_') c = '-';
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

bool DangerousValue(const std::string& v, std::string& err)
{
    if (HasShellMeta(v)) {
        err = "shell metacharacter or env interpolation";
        return true;
    }
    if (IsScriptPath(v)) {
        err = "model-supplied script";
        return true;
    }
    return false;
}

bool DigestOf(const char* domain, const UniValue& obj, Digest48& out, std::string& err)
{
    std::vector<unsigned char> c;
    if (!EncodePjson1(obj, c, err)) return false;
    std::vector<unsigned char> pre;
    pre.insert(pre.end(), domain, domain + std::strlen(domain));
    pre.push_back(0);
    unsigned char lenle[8];
    WriteLE64(lenle, c.size());
    pre.insert(pre.end(), lenle, lenle + 8);
    pre.insert(pre.end(), c.begin(), c.end());
    CSHA384 hasher;
    hasher.Write(pre.data(), pre.size());
    hasher.Finalize(out.data.data());
    return true;
}

bool WantsExecution(const UniValue& core, const UniValue& receipt, const UniValue& trusted)
{
    if (BoolTrue(core, "executes") || BoolTrue(receipt, "executes") || BoolTrue(trusted, "executes")) return true;
    if (BoolTrue(receipt, "runtime_executed")) return true;
    if (core.isObject() && core.exists("agent_handoff") && core["agent_handoff"].isObject()) {
        const UniValue& ah = core["agent_handoff"];
        if (BoolTrue(ah, "executes")) return true;
        if (ah.exists("runtime_profiles") && ah["runtime_profiles"].isArray()) {
            for (const auto& p : ah["runtime_profiles"].getValues()) {
                if (BoolTrue(p, "executes")) return true;
                if (p.isObject() && p.exists("parameters") && BoolTrue(p["parameters"], "executes")) return true;
            }
        }
    }
    return false;
}

bool ReceiptVerified(const UniValue& receipt)
{
    if (!receipt.isObject()) return false;
    if (!BoolTrue(receipt, "file_bytes_verified")) return false;
    if (!BoolTrue(receipt, "manifest_verified")) return false;
    if (receipt.exists("model_bytes_verified") && !BoolTrue(receipt, "model_bytes_verified")) return false;
    if (receipt.exists("state") && receipt["state"].isStr() && receipt["state"].get_str() != "MODEL_READY") {
        return false;
    }
    return true;
}

std::string LeasedPathOf(const UniValue& receipt)
{
    if (receipt.exists("leased_path") && receipt["leased_path"].isStr() && !receipt["leased_path"].get_str().empty()) {
        return receipt["leased_path"].get_str();
    }
    if (receipt.exists("local_paths") && receipt["local_paths"].isArray() && !receipt["local_paths"].empty() &&
        receipt["local_paths"][0].isStr()) {
        return receipt["local_paths"][0].get_str();
    }
    return {};
}

bool FindTrustedAdapter(const UniValue& trusted, const std::string& adapter_id, UniValue& out)
{
    out = UniValue(UniValue::VOBJ);
    if (trusted.isArray()) {
        for (const auto& item : trusted.getValues()) {
            if (item.isObject() && item.exists("adapter_id") && item["adapter_id"].isStr() &&
                item["adapter_id"].get_str() == adapter_id) {
                out = item;
                return true;
            }
        }
        return false;
    }
    if (!trusted.isObject()) return false;
    if (trusted.exists("adapter_id") && trusted["adapter_id"].isStr()) {
        if (trusted["adapter_id"].get_str() != adapter_id) return false;
        out = trusted;
        return true;
    }
    if (trusted.exists("adapters") && trusted["adapters"].isArray()) {
        return FindTrustedAdapter(trusted["adapters"], adapter_id, out);
    }
    if (trusted.exists(adapter_id) && trusted[adapter_id].isObject()) {
        out = trusted[adapter_id];
        if (!out.exists("adapter_id")) out.pushKV("adapter_id", adapter_id);
        return true;
    }
    return false;
}

bool SelectProfile(const UniValue& core, const UniValue& trusted, UniValue& profile, std::string& err)
{
    profile.setNull();
    if (!core.isObject() || !core.exists("agent_handoff") || !core["agent_handoff"].isObject()) {
        err = "agent_handoff";
        return false;
    }
    const UniValue& ah = core["agent_handoff"];
    if (!ah.exists("runtime_profiles") || !ah["runtime_profiles"].isArray() || ah["runtime_profiles"].empty()) {
        err = "runtime_profiles";
        return false;
    }
    std::string want_profile;
    if (trusted.isObject() && trusted.exists("profile_id") && trusted["profile_id"].isStr()) {
        want_profile = trusted["profile_id"].get_str();
    }
    std::string want_adapter;
    if (trusted.isObject() && trusted.exists("adapter_id") && trusted["adapter_id"].isStr()) {
        want_adapter = trusted["adapter_id"].get_str();
    }
    const auto& profiles = ah["runtime_profiles"].getValues();
    for (const auto& p : profiles) {
        if (!p.isObject() || !p.exists("profile_id") || !p.exists("adapter_id")) continue;
        if (!want_profile.empty() && p["profile_id"].get_str() != want_profile) continue;
        if (!want_adapter.empty() && p["adapter_id"].get_str() != want_adapter) continue;
        profile = p;
        return true;
    }
    for (const auto& p : profiles) {
        if (!p.isObject() || !p.exists("adapter_id") || !p["adapter_id"].isStr()) continue;
        UniValue rec;
        if (FindTrustedAdapter(trusted, p["adapter_id"].get_str(), rec)) {
            profile = p;
            return true;
        }
    }
    err = "no trusted runtime profile";
    return false;
}

bool ParamsAllowed(const UniValue& params, const std::set<std::string>& allowed, std::string& err)
{
    if (params.isNull()) return true;
    if (!params.isObject()) {
        err = "parameters";
        return false;
    }
    for (const auto& k : params.getKeys()) {
        const std::string lk = Lower(k);
        if (kForbiddenParamKeys.count(lk) || kForbiddenParamKeys.count(k)) {
            err = "model custom code parameter";
            return false;
        }
        if (!allowed.count(k)) {
            err = "unknown adapter flag: " + k;
            return false;
        }
        const UniValue& v = params[k];
        if (v.isStr() && (HasShellMeta(v.get_str()) || IsScriptPath(v.get_str()) || IsInterpreter(v.get_str()))) {
            err = "shell or script in parameter value";
            return false;
        }
        if (!v.isNum() && !v.isNull()) {
            err = "adapter-schema values must be integers";
            return false;
        }
    }
    return true;
}

std::string ParentDir(const std::string& path)
{
    const auto pos = path.find_last_of("/\\");
    if (pos == std::string::npos || pos == 0) return "/";
    return path.substr(0, pos);
}

} // namespace

bool RuntimeArgvAllowed(const std::string& adapter_id, const std::vector<std::string>& argv, std::string& err)
{
    err.clear();
    if (IsInterpreter(adapter_id) || IsScriptPath(adapter_id)) {
        err = "adapter_id is not a trusted executable class";
        return false;
    }
    bool saw_interpreter = false;
    size_t i = 0;
    if (!argv.empty() && (argv[0].empty() || argv[0][0] != '-')) {
        if (IsInterpreter(argv[0]) || IsScriptPath(argv[0]) || HasShellMeta(argv[0])) {
            err = "forbidden executable";
            return false;
        }
        saw_interpreter = IsInterpreter(argv[0]);
        i = 1;
    }
    for (const auto& t : argv) {
        if (IsInterpreter(t)) saw_interpreter = true;
    }
    while (i < argv.size()) {
        const std::string& tok = argv[i];
        if (tok.empty() || HasShellMeta(tok)) {
            err = "shell metacharacter, env interpolation, or empty token";
            return false;
        }
        if (tok[0] != '-') {
            err = "stray positional argument";
            return false;
        }
        bool has_eq = false;
        std::string eq_value;
        const std::string name = FlagName(tok, eq_value, has_eq);
        if (name.empty() || !kAllowedFlags.count(name)) {
            err = "unknown adapter flag";
            return false;
        }
        if (saw_interpreter && (name == "c" || name == "e" || name == "eval")) {
            err = "interpreter -c/-e rejected";
            return false;
        }
        auto check_val = [&](const std::string& v) {
            if (DangerousValue(v, err)) return false;
            if (name != "m" && name != "model" && name != "model-path" && !AllDigits(v)) {
                err = "non-integer adapter value";
                return false;
            }
            return true;
        };
        if (has_eq) {
            if (!check_val(eq_value)) return false;
            ++i;
            continue;
        }
        if (i + 1 < argv.size() && (argv[i + 1].empty() || argv[i + 1][0] != '-')) {
            if (!check_val(argv[i + 1])) return false;
            i += 2;
            continue;
        }
        err = "flag missing value";
        return false;
    }
    return true;
}

bool PlanBtxRuntime(const UniValue& core, const UniValue& receipt, const UniValue& trusted_adapter,
                   RuntimePlan& out, std::string& err_code, std::string& err)
{
    out = {};
    out.executes = false;
    err_code.clear();
    err.clear();

    if (WantsExecution(core, receipt, trusted_adapter)) {
        return Fail(err_code, err, "EXECUTION_APPROVAL_REQUIRED", "plan is not execution");
    }
    if (!core.isObject()) {
        return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "core");
    }
    if (!ReceiptVerified(receipt)) {
        return Fail(err_code, err, "MODEL_BYTES_UNVERIFIED", "receipt not verified");
    }
    out.leased_path = LeasedPathOf(receipt);
    if (out.leased_path.empty() || HasShellMeta(out.leased_path) || IsScriptPath(out.leased_path)) {
        return Fail(err_code, err, "MODEL_BYTES_UNVERIFIED", "leased_path");
    }
    if (!PackageCoreId(core, out.package_core_id, err)) {
        return Fail(err_code, err, "UNSUPPORTED_CORE_VERSION", err);
    }
    if (receipt.exists("package_core_id") && receipt["package_core_id"].isStr() &&
        receipt["package_core_id"].get_str() != out.package_core_id.Hex()) {
        return Fail(err_code, err, "MODEL_BYTES_UNVERIFIED", "receipt package_core_id mismatch");
    }

    UniValue profile;
    if (!SelectProfile(core, trusted_adapter, profile, err)) {
        return Fail(err_code, err, "RUNTIME_ADAPTER_UNSUPPORTED", err);
    }
    out.profile_id = profile["profile_id"].get_str();
    out.adapter_id = profile["adapter_id"].get_str();
    // A llama.cpp/ollama/vllm/mlx label in the package is not support.
    UniValue trusted;
    if (!FindTrustedAdapter(trusted_adapter, out.adapter_id, trusted)) {
        return Fail(err_code, err, "RUNTIME_ADAPTER_UNSUPPORTED", out.adapter_id);
    }
    if (!trusted.exists("executable_path") || !trusted["executable_path"].isStr() ||
        trusted["executable_path"].get_str().empty()) {
        return Fail(err_code, err, "RUNTIME_ADAPTER_UNSUPPORTED", "executable_path required of trusted_adapter");
    }
    if (!trusted.exists("verified_executable_digest") || !trusted["verified_executable_digest"].isStr()) {
        return Fail(err_code, err, "RUNTIME_ADAPTER_UNSUPPORTED", "verified_executable_digest");
    }
    Digest48 exe;
    if (!Digest48::FromHex(trusted["verified_executable_digest"].get_str(), exe, err)) {
        return Fail(err_code, err, "RUNTIME_ADAPTER_UNSUPPORTED", "verified_executable_digest");
    }
    const std::string exe_path = trusted["executable_path"].get_str();
    if (HasShellMeta(exe_path) || IsInterpreter(exe_path) || IsScriptPath(exe_path)) {
        return Fail(err_code, err, "RUNTIME_ADAPTER_UNSUPPORTED", "untrusted executable_path");
    }
    const std::string schema =
        trusted.exists("adapter_schema") && trusted["adapter_schema"].isStr() ? trusted["adapter_schema"].get_str() :
        (profile.exists("adapter_schema") && profile["adapter_schema"].isStr() ? profile["adapter_schema"].get_str() :
                                                                               kLocalCliV1);
    if (schema != kLocalCliV1) {
        return Fail(err_code, err, "RUNTIME_ADAPTER_UNSUPPORTED", schema);
    }
    if (profile.exists("executable_path") || profile.exists("command") || profile.exists("argv") ||
        profile.exists("env") || profile.exists("shell") || profile.exists("ld_preload")) {
        return Fail(err_code, err, "RUNTIME_ADAPTER_UNSUPPORTED", "package cannot set executable/shell");
    }
    const std::string mode = profile.exists("mode") && profile["mode"].isStr() ? profile["mode"].get_str() : "CLI";
    if (mode != "CLI" && mode != "LOOPBACK_SERVICE") {
        return Fail(err_code, err, "RUNTIME_ADAPTER_UNSUPPORTED", mode);
    }

    std::set<std::string> allowed = kSchemaKeys;
    if (trusted.exists("allowed_keys") && trusted["allowed_keys"].isArray()) {
        allowed.clear();
        for (const auto& k : trusted["allowed_keys"].getValues()) {
            if (k.isStr()) allowed.insert(k.get_str());
        }
        if (allowed.empty()) allowed = kSchemaKeys;
    }
    UniValue params(UniValue::VOBJ);
    if (profile.exists("parameters")) params = profile["parameters"];
    if (!ParamsAllowed(params, allowed, err)) {
        return Fail(err_code, err, "RUNTIME_ADAPTER_UNSUPPORTED", err);
    }

    out.verified_executable_digest = exe.Hex();
    out.argv = {exe_path, "-m", out.leased_path};
    auto push_int_flag = [&](const char* key, const char* flag) {
        if (!params.exists(key) || !params[key].isNum()) return;
        out.argv.push_back(flag);
        out.argv.push_back(std::to_string(params[key].getInt<int64_t>()));
    };
    push_int_flag("context_tokens", "-c");
    push_int_flag("gpu_layers", "-ngl");
    push_int_flag("threads", "-t");
    if (!RuntimeArgvAllowed(out.adapter_id, out.argv, err)) {
        return Fail(err_code, err, "RUNTIME_ADAPTER_UNSUPPORTED", err);
    }

    const std::string network = core.exists("network") && core["network"].isStr() ? core["network"].get_str() : "REGTEST";
    const int64_t now_ms = TicksSinceEpoch<std::chrono::milliseconds>(NodeClock::now());
    std::string wd = ParentDir(out.leased_path);
    if (trusted.exists("working_directory") && trusted["working_directory"].isStr() &&
        !trusted["working_directory"].get_str().empty()) {
        wd = trusted["working_directory"].get_str();
    }
    const std::string mem = trusted.exists("maximum_memory_bytes") && trusted["maximum_memory_bytes"].isStr() ?
                                trusted["maximum_memory_bytes"].get_str() :
                                "2147483648";
    const int max_s = trusted.exists("maximum_seconds") && trusted["maximum_seconds"].isNum() ?
                          trusted["maximum_seconds"].getInt<int>() :
                          60;
    std::string receipt_id;
    if (receipt.exists("receipt_id") && receipt["receipt_id"].isStr() && receipt["receipt_id"].get_str().size() == 96) {
        receipt_id = receipt["receipt_id"].get_str();
    } else {
        std::string material = out.package_core_id.Hex();
        material += '|';
        material += out.profile_id;
        material += '|';
        material += out.adapter_id;
        unsigned char d[CSHA384::OUTPUT_SIZE];
        CSHA384 hasher;
        hasher.Write(reinterpret_cast<const unsigned char*>(material.data()), material.size());
        hasher.Finalize(d);
        receipt_id = HexStr(Span<const unsigned char>{d, sizeof(d)});
    }

    UniValue resource_ids(UniValue::VARR);
    if (receipt.exists("resource_ids") && receipt["resource_ids"].isArray() && !receipt["resource_ids"].empty()) {
        resource_ids = receipt["resource_ids"];
    } else if (core.exists("resources") && core["resources"].isArray()) {
        for (const auto& r : core["resources"].getValues()) {
            if (r.isObject() && r.exists("id") && r["id"].isStr()) resource_ids.push_back(r["id"].get_str());
        }
    }
    if (resource_ids.empty()) {
        return Fail(err_code, err, "MODEL_BYTES_UNVERIFIED", "resource_ids");
    }

    UniValue json(UniValue::VOBJ);
    json.pushKV("schema_version", 1);
    json.pushKV("package_core_id", out.package_core_id.Hex());
    json.pushKV("network", network);
    json.pushKV("expires_at_ms", std::to_string(now_ms + 3600 * 1000));
    json.pushKV("profile_id", out.profile_id);
    json.pushKV("adapter_id", out.adapter_id);
    json.pushKV("resource_ids", resource_ids);
    json.pushKV("verified_executable_digest", out.verified_executable_digest);
    json.pushKV("executable_path", exe_path);
    json.pushKV("materialization_receipt_id", receipt_id);
    json.pushKV("working_directory", wd);
    json.pushKV("network_policy", mode == "LOOPBACK_SERVICE" ? "LOOPBACK_ONLY" : "NONE");
    json.pushKV("maximum_memory_bytes", mem);
    json.pushKV("maximum_seconds", max_s);
    json.pushKV("executes", false);
    json.pushKV("child_env_inherited", false);
    json.pushKV("inherit_environment", false);
    UniValue argv_json(UniValue::VARR);
    for (const auto& a : out.argv) argv_json.push_back(a);
    json.pushKV("argv", argv_json);
    json.pushKV("leased_path", out.leased_path);

    Digest48 pid;
    if (!DigestOf(kRuntimePlanDomain, json, pid, err)) {
        return Fail(err_code, err, "NONCANONICAL_PAYLOAD", err);
    }
    out.plan_id_hex = pid.Hex();
    json.pushKV("plan_id", out.plan_id_hex);
    out.json = json;
    out.executes = false;
    return true;
}

} // namespace modelnet
