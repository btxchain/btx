// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/capability_sdk.h>

#include <util/fs.h>

#include <cstdlib>
#include <cstring>
#include <fstream>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace modelnet {
namespace {

const char* const kProbeMethods[] = {
    "resolvebtxcapability",       "planbtxcapability",          "ensurebtxcapability",
    "getbtxcapability",            "cancelbtxcapability",       "releasebtxcapability",
    "prefetchbtxcapability",       "sleepbtxcapability",       "wakebtxcapability",
    "getbtxresidency",            "inspectbtxtensormap",      "exportbtxlock",
    "importbtxlock",             "planbtxcapabilityupdate",    "switchbtxcapability",
    "getbtxcapabilityevents",       "getbtxruntimecapabilities",  "getbtxttctrace",
};

struct CliMap {
    const char* verb;
    const char* method;
};

const CliMap kCliMap[] = {
    {"resolve", "resolvebtxcapability"},
    {"plan", "planbtxcapability"},
    {"ensure", "ensurebtxcapability"},
    {"status", "getbtxcapability"},
    {"get", "getbtxcapability"},
    {"cancel", "cancelbtxcapability"},
    {"release", "releasebtxcapability"},
    {"prefetch", "prefetchbtxcapability"},
    {"sleep", "sleepbtxcapability"},
    {"wake", "wakebtxcapability"},
    {"update", "planbtxcapabilityupdate"},
    {"switch", "switchbtxcapability"},
    {"events", "getbtxcapabilityevents"},
    {"capabilities", "getbtxruntimecapabilities"},
    {"ttc", "getbtxttctrace"},
    {"residency", "getbtxresidency"},
    {"inspect-map", "inspectbtxtensormap"},
    {"export-lock", "exportbtxlock"},
    {"import-lock", "importbtxlock"},
};

std::string LowerCopy(std::string s)
{
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

std::string StageForMethod(const std::string& method)
{
    if (method.find("resolve") != std::string::npos || method.find("plan") != std::string::npos) return "resolve";
    if (method.find("ensure") != std::string::npos) return "ensure";
    if (method.find("prefetch") != std::string::npos) return "prefetch";
    if (method.find("sleep") != std::string::npos || method.find("wake") != std::string::npos) return "runtime";
    if (method.find("release") != std::string::npos || method.find("cancel") != std::string::npos) return "lifetime";
    if (method.find("runtime") != std::string::npos) return "runtime";
    return "capability";
}

bool SpendKeyForbidden(const std::string& k)
{
    const std::string low = LowerCopy(k);
    if (low == "automatic_spend_atoms") return false;
    return low.find("spend") != std::string::npos || low == "wallet" || low.find("wallet_") != std::string::npos;
}

int64_t NumOrZero(const UniValue& v)
{
    if (v.isNum()) return v.getInt<int64_t>();
    if (v.isStr()) {
        const char* s = v.get_str().c_str();
        char* end = nullptr;
        const long long n = std::strtoll(s, &end, 10);
        if (end && end != s) return static_cast<int64_t>(n);
    }
    return 0;
}

bool WalkSpend(const UniValue& o, CapabilityError& err)
{
    if (o.isObject()) {
        for (const auto& k : o.getKeys()) {
            if (k == "automatic_spend_atoms" && NumOrZero(o[k]) != 0) {
                err = MakeCapabilityError("PAID_PATH_FORBIDDEN", "automatic_spend_atoms must remain 0", "cli");
                return true;
            }
            if (SpendKeyForbidden(k)) {
                err = MakeCapabilityError("PAID_PATH_FORBIDDEN", k, "cli");
                return true;
            }
            if (WalkSpend(o[k], err)) return true;
        }
    } else if (o.isArray()) {
        for (const auto& e : o.getValues()) {
            if (WalkSpend(e, err)) return true;
        }
    }
    return false;
}

bool LooksLikeWalletPath(const std::string& s)
{
    const std::string low = LowerCopy(s);
    if (low.find("wallet.dat") != std::string::npos) return true;
    if (low.find("/wallets/") != std::string::npos) return true;
    if (low.find("\\wallets\\") != std::string::npos) return true;
    if (low.find("walletdir") != std::string::npos) return true;
    return false;
}

bool WalletPathKeyName(const std::string& k)
{
    const std::string low = LowerCopy(k);
    if (low == "funded_wallet") return false;
    return LooksLikeWalletPath(k);
}

bool StartsWith(const std::string& s, const char* pfx)
{
    const size_t n = std::char_traits<char>::length(pfx);
    return s.size() >= n && s.compare(0, n, pfx) == 0;
}

std::string AfterEq(const std::string& a, const char* pfx)
{
    const size_t n = std::char_traits<char>::length(pfx);
    if (a.size() <= n) return {};
    return a.substr(n);
}

int64_t ParseDeadlineMs(const std::string& s)
{
    if (s.empty()) return 0;
    char* end = nullptr;
    const double v = std::strtod(s.c_str(), &end);
    std::string unit = end ? end : "";
    if (unit == "s" || unit == "sec") return static_cast<int64_t>(v * 1000.0);
    if (unit == "ms") return static_cast<int64_t>(v);
    if (unit == "m" || unit == "min") return static_cast<int64_t>(v * 60000.0);
    return static_cast<int64_t>(v);
}

bool ReadBoundedFile(const std::string& path, std::string& out, std::string& err)
{
    out.clear();
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        err = "cannot open " + path;
        return false;
    }
    char buf[4096];
    while (in) {
        in.read(buf, sizeof(buf));
        const std::streamsize n = in.gcount();
        if (n <= 0) break;
        if (out.size() + static_cast<size_t>(n) > (4u << 20)) {
            err = "PACKAGE_TOO_LARGE";
            out.clear();
            return false;
        }
        out.append(buf, static_cast<size_t>(n));
    }
    return true;
}

UniValue ObjectOrEmpty(const UniValue& params)
{
    if (params.isObject()) return params;
    if (params.isArray() && params.size() > 0 && params[0].isObject()) return params[0];
    UniValue o(UniValue::VOBJ);
    o.pushKV("automatic_spend_atoms", 0);
    return o;
}

std::string RecvLine(int fd)
{
    std::string body;
    char buf[4096];
    while (body.size() < (1u << 20)) {
        pollfd pfd{};
        pfd.fd = fd;
        pfd.events = POLLIN;
        const int pr = ::poll(&pfd, 1, 30000);
        if (pr <= 0) break;
        const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        body.append(buf, static_cast<size_t>(n));
        if (body.find('\n') != std::string::npos) break;
    }
    return body;
}

std::string KvLine(const char* k, const std::string& v)
{
    return std::string(k) + "=" + v + "\n";
}

} // namespace

bool CapabilityErrorRetryable(const std::string& code)
{
    return code == kErrHelperDown || code == kErrTransferStillInFlight || code == kErrStaleGeneration ||
           code == kErrMemoryReservationFailed || code == "HELPER_DOWN";
}

CapabilityError MakeCapabilityError(const std::string& code, const std::string& message, const std::string& method)
{
    CapabilityError e;
    e.code = code.empty() ? "ERROR" : code;
    e.stage = StageForMethod(method);
    e.message = message.empty() ? e.code : message;
    e.retryable = CapabilityErrorRetryable(e.code);
    return e;
}

void ForceZeroSpend(UniValue& o)
{
    if (!o.isObject()) {
        o = UniValue(UniValue::VOBJ);
        o.pushKV("automatic_spend_atoms", 0);
        return;
    }
    if (!o.exists("automatic_spend_atoms")) o.pushKV("automatic_spend_atoms", 0);
}

bool RejectNonzeroSpend(const UniValue& o, CapabilityError& err)
{
    return WalkSpend(o, err);
}

bool JsonContainsWalletPath(const UniValue& v)
{
    if (v.isObject()) {
        for (const auto& k : v.getKeys()) {
            if (WalletPathKeyName(k)) return true;
            const UniValue& val = v[k];
            if (val.isStr() && LooksLikeWalletPath(val.get_str())) return true;
            if (JsonContainsWalletPath(val)) return true;
        }
    } else if (v.isArray()) {
        for (const auto& e : v.getValues()) {
            if (JsonContainsWalletPath(e)) return true;
        }
    } else if (v.isStr()) {
        if (LooksLikeWalletPath(v.get_str())) return true;
    }
    return false;
}

ReadinessHandle ReadinessFromResult(const UniValue& result)
{
    ReadinessHandle h;
    if (!result.isObject()) return h;
    if (result.exists("lease_id") && result["lease_id"].isStr()) h.lease_id = result["lease_id"].get_str();
    if (result.exists("generation") && result["generation"].isStr()) h.generation = result["generation"].get_str();
    return h;
}

std::vector<std::string> CapabilityCliPrimaryCommands()
{
    return {"ensure", "prefetch", "status", "get", "sleep", "wake", "update", "release", "cancel",
            "resolve", "plan", "switch", "events", "ttc", "residency", "inspect-map", "export-lock",
            "import-lock", "capabilities", "help"};
}

std::vector<std::string> RegisteredCapabilityMethods()
{
    std::vector<std::string> out;
    for (const char* m : kProbeMethods) {
        if (IsCapabilityHelperMethod(m)) out.emplace_back(m);
    }
    return out;
}

std::string MapCapabilityCliVerb(const std::string& verb)
{
    if (verb.empty()) return {};
    if (IsCapabilityHelperMethod(verb)) return verb;
    for (const auto& m : kCliMap) {
        if (verb == m.verb && IsCapabilityHelperMethod(m.method)) return m.method;
    }
    return {};
}

std::string CapabilityCliUsage()
{
    std::string u;
    u += "btx-capability — owner-local BTX capability CLI (0.34.8-dev)\n";
    u += "Local resolve/plan/ensure/load only. Never public HTTP.\n";
    u += "Not a remote inference marketplace. automatic_spend_atoms stays 0.\n";
    u += "btx-open remains inspect-only; this binary does not install, spend, or run inference.\n";
    u += "Readiness is lease_id + generation, never a naked filesystem path.\n\n";
    u += "Flags:\n";
    u += "  -capabilitysocket=<path>  unix JSON-RPC (default: <modeldir>/capabilityd.sock)\n";
    u += "  -modeldir=<dir>            catalog directory (never wallet/chainstate)\n";
    u += "  --json                    machine JSON for status/get\n";
    u += "  --spend                   rejected\n\n";
    u += "Primary commands (spec 21.2; mapped only when registered):\n";
    auto line = [&](const char* cli, const char* method, const char* args) {
        if (std::string(cli) == "help" || IsCapabilityHelperMethod(method)) {
            u += "  btx-capability ";
            u += cli;
            u += " ";
            u += args;
            if (std::string(cli) != "help") {
                u += "    # ";
                u += method;
            }
            u += "\n";
        }
    };
    line("ensure", "ensurebtxcapability", "<path.btx|--recipe json|--plan-id ID> [--policy personal] [--ready first-useful-result]");
    line("prefetch", "prefetchbtxcapability", "[--lock <lock>] [--recipe <json>] [--deadline <duration>]");
    line("status", "getbtxcapability", "JOB|LEASE [--json]");
    line("get", "getbtxcapability", "JOB|LEASE [--json]");
    line("sleep", "sleepbtxcapability", "LEASE");
    line("wake", "wakebtxcapability", "LEASE");
    line("update", "planbtxcapabilityupdate", "--preview");
    line("release", "releasebtxcapability", "LEASE");
    line("cancel", "cancelbtxcapability", "JOB");
    line("resolve", "resolvebtxcapability", "...");
    line("plan", "planbtxcapability", "...");
    line("switch", "switchbtxcapability", "OLD NEW");
    line("events", "getbtxcapabilityevents", "");
    line("ttc", "getbtxttctrace", "JOB");
    line("residency", "getbtxresidency", "");
    line("inspect-map", "inspectbtxtensormap", "<hex|{json}>");
    line("export-lock", "exportbtxlock", "<recipe_id|{json}>");
    line("import-lock", "importbtxlock", "<recipe_id|{json}>");
    line("capabilities", "getbtxruntimecapabilities", "");
    line("help", "help", "");
    u += "\nRegistered owner-local methods (IsCapabilityHelperMethod; not invented):\n";
    for (const auto& m : RegisteredCapabilityMethods()) {
        u += "  ";
        u += m;
        u += "\n";
    }
    u += "\nA registered method name may be invoked directly:\n";
    u += "  btx-capability <registered-method> [json-object]\n";
    return u;
}

CapabilityClient::CapabilityClient(ModelCatalog& cat) : m_cat(&cat) {}

CapabilityClient CapabilityClient::UnixSocket(std::string socket_path)
{
    CapabilityClient c;
    c.m_socket = std::move(socket_path);
    return c;
}

bool CallCapabilityUnix(const std::string& socket_path, const std::string& method, const UniValue& params,
                        UniValue& result, CapabilityError& err)
{
    result.setNull();
    if (socket_path.empty()) {
        err = MakeCapabilityError(kErrHelperDown, "capability socket path empty", method);
        return false;
    }
    if (!IsCapabilityHelperMethod(method)) {
        err = MakeCapabilityError("METHOD_NOT_FOUND", method, method);
        return false;
    }
    const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        err = MakeCapabilityError(kErrHelperDown, "unix socket", method);
        return false;
    }
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (socket_path.size() >= sizeof(addr.sun_path)) {
        ::close(fd);
        err = MakeCapabilityError(kErrHelperDown, "unix path too long", method);
        return false;
    }
    std::strncpy(addr.sun_path, socket_path.c_str(), sizeof(addr.sun_path) - 1);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(fd);
        err = MakeCapabilityError(kErrHelperDown, "capabilityd unix connect failed", method);
        return false;
    }
    UniValue req(UniValue::VOBJ);
    req.pushKV("jsonrpc", "1.0");
    req.pushKV("id", "capability");
    req.pushKV("method", method);
    req.pushKV("params", params);
    const std::string wire = req.write() + "\n";
    if (::send(fd, wire.data(), wire.size(), 0) < 0) {
        ::close(fd);
        err = MakeCapabilityError(kErrHelperDown, "unix write", method);
        return false;
    }
    ::shutdown(fd, SHUT_WR);
    const std::string raw = RecvLine(fd);
    ::close(fd);
    UniValue reply;
    if (!reply.read(raw) || !reply.isObject()) {
        err = MakeCapabilityError(kErrHelperDown, "capabilityd reply json", method);
        return false;
    }
    if (reply.exists("error") && !reply["error"].isNull()) {
        const UniValue& e = reply["error"];
        std::string code = e.isObject() && e.exists("code") && e["code"].isStr() ? e["code"].get_str() : "ERROR";
        std::string msg = e.isObject() && e.exists("message") && e["message"].isStr() ? e["message"].get_str() : e.write();
        err = MakeCapabilityError(code, msg, method);
        return false;
    }
    if (reply.exists("result")) result = reply["result"];
    else result.setNull();
    return true;
}

bool CapabilityClient::Call(const std::string& method, const UniValue& params, UniValue& result, CapabilityError& err)
{
    err = {};
    result = UniValue(UniValue::VOBJ);
    if (!IsCapabilityHelperMethod(method)) {
        err = MakeCapabilityError("METHOD_NOT_FOUND", method, method);
        return false;
    }
    UniValue body = ObjectOrEmpty(params);
    ForceZeroSpend(body);
    if (RejectNonzeroSpend(body, err)) return false;

    if (m_cat) {
        std::string code, emsg;
        if (!DispatchCapabilityRpc(*m_cat, method, body, result, code, emsg)) {
            err = MakeCapabilityError(code, emsg, method);
            return false;
        }
    } else {
        if (!CallCapabilityUnix(m_socket, method, body, result, err)) return false;
    }
    if (JsonContainsWalletPath(result)) {
        err = MakeCapabilityError("PRIVACY", "wallet path in capability JSON", method);
        return false;
    }
    if (result.isObject() && result.exists("automatic_spend_atoms") && NumOrZero(result["automatic_spend_atoms"]) != 0) {
        err = MakeCapabilityError("PAID_PATH_FORBIDDEN", "automatic_spend_atoms must remain 0", method);
        return false;
    }
    return true;
}

bool CapabilityClient::Plan(const UniValue& recipe, const UniValue& grant, UniValue& result, CapabilityError& err)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("recipe", recipe);
    o.pushKV("grant", grant);
    ForceZeroSpend(o);
    return Call("planbtxcapability", o, result, err);
}

bool CapabilityClient::Ensure(const std::string& plan_id, const UniValue& grant, ReadinessHandle& handle, UniValue& result,
                                CapabilityError& err)
{
    handle = {};
    UniValue o(UniValue::VOBJ);
    o.pushKV("plan_id", plan_id);
    o.pushKV("grant", grant);
    ForceZeroSpend(o);
    if (!Call("ensurebtxcapability", o, result, err)) return false;
    handle = ReadinessFromResult(result);
    if (!handle.IsReadyReference()) {
        err = MakeCapabilityError("PREMATURE_READY", "readiness handle is lease_id+generation, not a path",
                                   "ensurebtxcapability");
        return false;
    }
    return true;
}

bool CapabilityClient::Get(const std::string& job_or_lease, UniValue& result, CapabilityError& err)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("job_id", job_or_lease);
    o.pushKV("lease_id", job_or_lease);
    ForceZeroSpend(o);
    return Call("getbtxcapability", o, result, err);
}

bool CapabilityClient::Cancel(const std::string& job_id, UniValue& result, CapabilityError& err)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("job_id", job_id);
    ForceZeroSpend(o);
    return Call("cancelbtxcapability", o, result, err);
}

bool CapabilityClient::Release(const std::string& lease_id, UniValue& result, CapabilityError& err)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("lease_id", lease_id);
    ForceZeroSpend(o);
    return Call("releasebtxcapability", o, result, err);
}

bool CapabilityClient::Prefetch(const UniValue& hint, UniValue& result, CapabilityError& err)
{
    UniValue o = hint.isObject() ? hint : UniValue(UniValue::VOBJ);
    ForceZeroSpend(o);
    return Call("prefetchbtxcapability", o, result, err);
}

bool CapabilityClient::Sleep(const std::string& lease_id, UniValue& result, CapabilityError& err)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("lease_id", lease_id);
    ForceZeroSpend(o);
    return Call("sleepbtxcapability", o, result, err);
}

bool CapabilityClient::Wake(const std::string& lease_id, UniValue& result, CapabilityError& err)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("lease_id", lease_id);
    ForceZeroSpend(o);
    return Call("wakebtxcapability", o, result, err);
}

bool CapabilityClient::Events(UniValue& result, CapabilityError& err)
{
    UniValue o(UniValue::VOBJ);
    ForceZeroSpend(o);
    return Call("getbtxcapabilityevents", o, result, err);
}

bool CapabilityClient::Ttc(const std::string& job_id, UniValue& result, CapabilityError& err)
{
    UniValue o(UniValue::VOBJ);
    if (!job_id.empty()) o.pushKV("job_id", job_id);
    ForceZeroSpend(o);
    return Call("getbtxttctrace", o, result, err);
}

bool CapabilityClient::Capabilities(UniValue& result, CapabilityError& err)
{
    UniValue o(UniValue::VOBJ);
    ForceZeroSpend(o);
    return Call("getbtxruntimecapabilities", o, result, err);
}

int RunCapabilityCli(const std::vector<std::string>& args, std::string& out, std::string& err_out)
{
    out.clear();
    err_out.clear();
    std::string socket_flag;
    std::string modeldir = "modelnet-data";
    std::string policy;
    std::string ready;
    std::string recipe_arg;
    std::string plan_id_arg;
    std::string lock_arg;
    std::string deadline;
    std::string verb;
    std::vector<std::string> positionals;
    bool json_out = false;
    bool preview = false;

    size_t i = 0;
    if (!args.empty()) {
        const std::string& a0 = args[0];
        std::string base = a0;
        const auto slash = a0.find_last_of("/\\");
        if (slash != std::string::npos) base = a0.substr(slash + 1);
        if (base.rfind("btx-capability", 0) == 0) i = 1;
    }

    for (; i < args.size(); ++i) {
        const std::string& a = args[i];
        const auto take = [&](std::string& dst) {
            if (i + 1 < args.size()) dst = args[++i];
        };
        if (a == "-help" || a == "-h" || a == "--help" || a == "help") {
            out = CapabilityCliUsage();
            return 0;
        }
        if (a == "-version" || a == "--version") {
            out = "btx-capability 0.34.8-dev\n";
            return 0;
        }
        if (a == "--spend" || a == "-spend" || StartsWith(a, "--spend=") || StartsWith(a, "-spend=")) {
            err_out = "rejected --spend; automatic_spend_atoms stays 0\n";
            return 1;
        }
        if (StartsWith(a, "-capabilitysocket=")) {
            socket_flag = AfterEq(a, "-capabilitysocket=");
            continue;
        }
        if (StartsWith(a, "--capabilitysocket=")) {
            socket_flag = AfterEq(a, "--capabilitysocket=");
            continue;
        }
        if (StartsWith(a, "-modeldir=")) {
            modeldir = AfterEq(a, "-modeldir=");
            continue;
        }
        if (StartsWith(a, "--modeldir=")) {
            modeldir = AfterEq(a, "--modeldir=");
            continue;
        }
        if (a == "--json" || a == "-json") {
            json_out = true;
            continue;
        }
        if (a == "--preview") {
            preview = true;
            continue;
        }
        if (a == "--policy" || a == "-policy") {
            take(policy);
            continue;
        }
        if (StartsWith(a, "--policy=")) {
            policy = AfterEq(a, "--policy=");
            continue;
        }
        if (a == "--ready" || a == "-ready") {
            take(ready);
            continue;
        }
        if (StartsWith(a, "--ready=")) {
            ready = AfterEq(a, "--ready=");
            continue;
        }
        if (a == "--recipe" || a == "-recipe") {
            take(recipe_arg);
            continue;
        }
        if (StartsWith(a, "--recipe=")) {
            recipe_arg = AfterEq(a, "--recipe=");
            continue;
        }
        if (a == "--plan-id" || a == "-plan-id" || a == "--plan_id") {
            take(plan_id_arg);
            continue;
        }
        if (StartsWith(a, "--plan-id=")) {
            plan_id_arg = AfterEq(a, "--plan-id=");
            continue;
        }
        if (StartsWith(a, "--plan_id=")) {
            plan_id_arg = AfterEq(a, "--plan_id=");
            continue;
        }
        if (a == "--lock" || a == "-lock") {
            take(lock_arg);
            continue;
        }
        if (StartsWith(a, "--lock=")) {
            lock_arg = AfterEq(a, "--lock=");
            continue;
        }
        if (a == "--deadline" || a == "-deadline") {
            take(deadline);
            continue;
        }
        if (StartsWith(a, "--deadline=")) {
            deadline = AfterEq(a, "--deadline=");
            continue;
        }
        if (!a.empty() && a[0] == '-') {
            err_out = "unknown argument: " + a + "\n" + CapabilityCliUsage();
            return 1;
        }
        if (verb.empty()) verb = a;
        else positionals.push_back(a);
    }

    if (verb.empty()) {
        err_out = CapabilityCliUsage();
        return 1;
    }
    if (verb == "help") {
        out = CapabilityCliUsage();
        return 0;
    }

    const std::string method = MapCapabilityCliVerb(verb);
    if (method.empty()) {
        err_out = "unknown command (not a registered capability method): " + verb + "\n" + CapabilityCliUsage();
        return 1;
    }

    std::string sock = socket_flag;
    if (sock.empty()) {
        const fs::path md = fs::PathFromString(modeldir);
        sock = fs::PathToString(md / fs::PathFromString("capabilityd.sock"));
    }

    CapabilityClient client = CapabilityClient::UnixSocket(sock);
    UniValue grant(UniValue::VOBJ);
    grant.pushKV("caller", "local");
    grant.pushKV("host_bytes", 8388608);
    grant.pushKV("automatic_spend_atoms", 0);
    if (!policy.empty()) grant.pushKV("policy", policy);

    auto load_recipe = [&](UniValue& recipe, std::string& emsg) -> bool {
        std::string src = recipe_arg;
        if (src.empty() && !positionals.empty()) src = positionals[0];
        if (src.empty()) {
            emsg = "recipe or path.btx required";
            return false;
        }
        if (!src.empty() && src[0] == '{') {
            recipe = UniValue(UniValue::VOBJ);
            if (!recipe.read(src) || !recipe.isObject()) {
                emsg = "NONCANONICAL_PAYLOAD";
                return false;
            }
            return true;
        }
        std::string file;
        if (ReadBoundedFile(src, file, emsg)) {
            recipe = UniValue(UniValue::VOBJ);
            if (recipe.read(file) && recipe.isObject()) return true;
        }
        emsg.clear();
        recipe.setNull();
        return false;
    };

    UniValue params(UniValue::VOBJ);
    ForceZeroSpend(params);
    CapabilityError err;
    UniValue result;

    if (method == "ensurebtxcapability") {
        std::string plan_id = plan_id_arg;
        if (plan_id.empty()) {
            UniValue recipe;
            std::string emsg;
            const bool have_recipe = load_recipe(recipe, emsg);
            UniValue plan_res;
            if (have_recipe) {
                if (!ready.empty()) params.pushKV("readiness_target", ready);
                if (!client.Plan(recipe, grant, plan_res, err)) {
                    err_out = err.code + ": " + err.message + "\n";
                    return 1;
                }
            } else {
                UniValue q(UniValue::VOBJ);
                const std::string path = positionals.empty() ? recipe_arg : positionals[0];
                if (!path.empty()) q.pushKV("path", path);
                q.pushKV("grant", grant);
                ForceZeroSpend(q);
                if (!client.Call("resolvebtxcapability", q, plan_res, err)) {
                    err_out = err.code + ": " + err.message + "\n";
                    return 1;
                }
            }
            if (plan_res.isObject() && plan_res.exists("plan_id") && plan_res["plan_id"].isStr()) {
                plan_id = plan_res["plan_id"].get_str();
            } else if (plan_res.isObject() && plan_res.exists("candidates") && plan_res["candidates"].isArray() &&
                       plan_res["candidates"].size() > 0 && plan_res["candidates"][0].isObject() &&
                       plan_res["candidates"][0].exists("plan_id") && plan_res["candidates"][0]["plan_id"].isStr()) {
                plan_id = plan_res["candidates"][0]["plan_id"].get_str();
            }
        }
        if (plan_id.empty()) {
            err_out = std::string(kErrNoEligibleRecipe) + ": no plan_id\n";
            return 1;
        }
        ReadinessHandle handle;
        if (!client.Ensure(plan_id, grant, handle, result, err)) {
            err_out = err.code + ": " + err.message + "\n";
            return 1;
        }
        if (json_out) {
            out = result.write() + "\n";
            return 0;
        }
        out += KvLine("lease_id", handle.lease_id);
        out += KvLine("generation", handle.generation);
        if (result.exists("job_id") && result["job_id"].isStr()) out += KvLine("job_id", result["job_id"].get_str());
        if (result.exists("achieved") && result["achieved"].isStr()) {
            out += KvLine("achieved", result["achieved"].get_str());
        }
        out += "automatic_spend_atoms=0\n";
        out += "ready_handle=lease_id+generation\n";
        return 0;
    }

    if (method == "prefetchbtxcapability") {
        params.pushKV("grant", grant);
        if (!recipe_arg.empty()) {
            if (recipe_arg[0] == '{') {
                UniValue r;
                if (r.read(recipe_arg) && r.isObject()) params.pushKV("recipe", r);
                else params.pushKV("recipe_id", recipe_arg);
            } else {
                params.pushKV("recipe_id", recipe_arg);
            }
        }
        if (!lock_arg.empty()) params.pushKV("lock", lock_arg);
        if (!deadline.empty()) params.pushKV("deadline_ms", ParseDeadlineMs(deadline));
        if (!client.Prefetch(params, result, err)) {
            err_out = err.code + ": " + err.message + "\n";
            return 1;
        }
        out = result.write() + "\n";
        return 0;
    }

    if (method == "getbtxcapability") {
        const std::string id = positionals.empty() ? "" : positionals[0];
        if (id.empty()) {
            err_out = "status requires JOB|LEASE\n";
            return 1;
        }
        if (!client.Get(id, result, err)) {
            err_out = err.code + ": " + err.message + "\n";
            return 1;
        }
        if (json_out) {
            out = result.write() + "\n";
            return 0;
        }
        out = result.write() + "\n";
        return 0;
    }

    if (method == "sleepbtxcapability" || method == "wakebtxcapability" || method == "releasebtxcapability") {
        const std::string lease = positionals.empty() ? "" : positionals[0];
        if (lease.empty()) {
            err_out = verb + " requires LEASE\n";
            return 1;
        }
        const bool ok = method == "sleepbtxcapability"   ? client.Sleep(lease, result, err) :
                         method == "wakebtxcapability"    ? client.Wake(lease, result, err) :
                                                            client.Release(lease, result, err);
        if (!ok) {
            err_out = err.code + ": " + err.message + "\n";
            return 1;
        }
        out = result.write() + "\n";
        return 0;
    }

    if (method == "planbtxcapabilityupdate") {
        (void)preview;
        params.pushKV("preview", true);
        if (!lock_arg.empty()) params.pushKV("lock_id", lock_arg);
        if (!client.Call(method, params, result, err)) {
            err_out = err.code + ": " + err.message + "\n";
            return 1;
        }
        out = result.write() + "\n";
        return 0;
    }

    if (method == "planbtxcapability" || method == "resolvebtxcapability") {
        UniValue recipe;
        std::string emsg;
        if (!recipe_arg.empty() || (!positionals.empty() && !positionals[0].empty() && positionals[0][0] == '{')) {
            if (!load_recipe(recipe, emsg) && recipe.isNull()) {
                if (!positionals.empty() && positionals[0][0] == '{') {
                    if (!recipe.read(positionals[0]) || !recipe.isObject()) {
                        err_out = "NONCANONICAL_PAYLOAD\n";
                        return 1;
                    }
                }
            }
            if (recipe.isObject()) params.pushKV("recipe", recipe);
        } else if (!positionals.empty()) {
            params.pushKV("path", positionals[0]);
        }
        params.pushKV("grant", grant);
        if (!ready.empty()) params.pushKV("readiness_target", ready);
        if (!client.Call(method, params, result, err)) {
            err_out = err.code + ": " + err.message + "\n";
            return 1;
        }
        out = result.write() + "\n";
        return 0;
    }

    if (method == "getbtxruntimecapabilities") {
        if (!client.Capabilities(result, err)) {
            err_out = err.code + ": " + err.message + "\n";
            return 1;
        }
        out = result.write() + "\n";
        return 0;
    }

    if (!positionals.empty() && !positionals[0].empty() && positionals[0][0] == '{') {
        if (!params.read(positionals[0]) || !params.isObject()) {
            err_out = "NONCANONICAL_PAYLOAD\n";
            return 1;
        }
    } else if (!positionals.empty()) {
        if (method == "cancelbtxcapability") params.pushKV("job_id", positionals[0]);
        else if (method == "switchbtxcapability") {
            params.pushKV("old_lock", positionals[0]);
            if (positionals.size() > 1) params.pushKV("new_lock", positionals[1]);
        } else if (method == "getbtxttctrace") {
            params.pushKV("job_id", positionals[0]);
        } else if (method == "inspectbtxtensormap") {
            params.pushKV("hex", positionals[0]);
        } else if (method == "exportbtxlock" || method == "importbtxlock") {
            params.pushKV("recipe_id", positionals[0]);
        } else {
            params.pushKV("arg", positionals[0]);
        }
    }
    ForceZeroSpend(params);
    if (!client.Call(method, params, result, err)) {
        err_out = err.code + ": " + err.message + "\n";
        return 1;
    }
    out = result.write() + "\n";
    return 0;
}

} // namespace modelnet
