// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/lab_gateway.h>

#include <crypto/sha256.h>

#include <fstream>
#include <sstream>
#include <utility>

namespace modelnet {
namespace {

const char* const ROUTE_ERR = "BTX035_ROUTE";
const char* const SCHEMA_ERR = "BTX035_SCHEMA";
const char* const SCOPE_ERR = "BTX035_SCOPE_DENIED";

std::string Upper(std::string s)
{
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') continue;
        if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
    }
    return s;
}

std::string Lower(std::string s)
{
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

bool Blank(const std::string& s)
{
    for (unsigned char c : s) {
        if (c != ' ' && c != '\t' && c != '\n' && c != '\r') return false;
    }
    return true;
}

std::string PathOnly(std::string path)
{
    const size_t query = path.find('?');
    if (query != std::string::npos) path.erase(query);
    while (path.size() > 1 && path.back() == '/') path.pop_back();
    return path;
}

std::string LastSegment(const std::string& path)
{
    const std::string trimmed = PathOnly(path);
    const size_t slash = trimmed.find_last_of('/');
    if (slash == std::string::npos) return trimmed;
    return trimmed.substr(slash + 1);
}

bool IsWalletName(const std::string& name)
{
    const std::string lower = Lower(name);
    if (lower.find("wallet") != std::string::npos) return true;
    static const char* kExact[] = {
        "sendtoaddress",
        "sendmany",
        "getbalance",
        "getnewaddress",
        "dumpprivkey",
        "importprivkey",
        "listunspent",
        "listtransactions",
        "signrawtransactionwithwallet",
        "getwalletinfo",
        "abandontransaction",
    };
    for (const char* exact : kExact) {
        if (lower == exact) return true;
    }
    return false;
}

bool IsShellToken(const std::string& name)
{
    const std::string lower = Lower(PathOnly(name));
    if (lower.find("shell") != std::string::npos) return true;
    static const char* kExact[] = {"sh", "bash", "dash", "exec", "system", "popen", "/sh", "/bash"};
    for (const char* exact : kExact) {
        if (lower == exact) return true;
    }
    if (lower.find("/bin/sh") != std::string::npos) return true;
    if (lower.find("/bin/bash") != std::string::npos) return true;
    if (lower.find("/bin/dash") != std::string::npos) return true;
    return false;
}

bool IsShellPath(const std::string& raw)
{
    const std::string path = Lower(PathOnly(raw));
    if (IsShellToken(path)) return true;
    if (path.find("..") != std::string::npos) return true;
    static const char* kPrefixes[] = {
        "/home/", "/tmp/", "/etc/", "/usr/", "/var/", "/proc/", "/dev/", "/bin/", "/root/", "/opt/",
    };
    for (const char* prefix : kPrefixes) {
        if (path.rfind(prefix, 0) == 0) return true;
    }
    return false;
}

bool IsRpcPath(const std::string& raw)
{
    const std::string path = Lower(PathOnly(raw));
    return path == "/rpc" || path == "rpc" || path.rfind("/rpc/", 0) == 0 || path.rfind("rpc/", 0) == 0;
}

bool DeniedRoute(const std::string& path)
{
    if (IsRpcPath(path) || IsShellPath(path)) return true;
    if (IsWalletName(path) || IsWalletName(LastSegment(path))) return true;
    if (IsShellToken(LastSegment(path))) return true;
    return false;
}

std::string RouteKey(const std::string& method, const std::string& path)
{
    return Upper(method) + "\n" + path;
}

std::string Dirname(const std::string& path)
{
    const size_t slash = path.find_last_of('/');
    if (slash == std::string::npos) return ".";
    if (slash == 0) return "/";
    return path.substr(0, slash);
}

bool ReadText(const std::string& path, std::string& body)
{
    std::ifstream in(path);
    if (!in) return false;
    std::ostringstream ss;
    ss << in.rdbuf();
    body = ss.str();
    return true;
}

bool SafeSchemaRef(const std::string& ref)
{
    if (ref.empty() || ref.front() == '/') return false;
    if (ref.find("..") != std::string::npos) return false;
    if (ref.find("://") != std::string::npos) return false;
    return true;
}

bool SchemaRequiresIdempotency(const std::string& openapi_dir, const std::string& ref, std::string& err)
{
    if (!SafeSchemaRef(ref)) {
        err = SCHEMA_ERR;
        return false;
    }
    std::string file = ref;
    const size_t hash = file.find('#');
    if (hash != std::string::npos) file.erase(hash);
    if (file.empty()) return false;
    const std::string path = openapi_dir + "/" + file;
    std::string body;
    if (!ReadText(path, body)) {
        err = SCHEMA_ERR;
        return false;
    }
    UniValue schema;
    if (!schema.read(body) || !schema.isObject()) {
        err = SCHEMA_ERR;
        return false;
    }
    const UniValue& required = schema.find_value("required");
    if (!required.isArray()) return false;
    for (size_t i = 0; i < required.size(); ++i) {
        if (required[i].isStr() && required[i].get_str() == "idempotency_key") return true;
    }
    return false;
}

bool ParseOpenApi(const std::string& openapi_path, std::vector<HostedGateway::Route>& routes, std::string& err)
{
    std::string body;
    if (!ReadText(openapi_path, body)) {
        err = SCHEMA_ERR;
        return false;
    }
    UniValue root;
    if (!root.read(body) || !root.isObject()) {
        err = SCHEMA_ERR;
        return false;
    }
    const UniValue& paths = root.find_value("paths");
    if (!paths.isObject()) {
        err = SCHEMA_ERR;
        return false;
    }
    static const char* kHttp[] = {"get", "put", "post", "delete", "options", "head", "patch", "trace"};
    const std::string dir = Dirname(openapi_path);
    const std::vector<std::string>& keys = paths.getKeys();
    const std::vector<UniValue>& values = paths.getValues();
    for (size_t i = 0; i < keys.size(); ++i) {
        if (!values[i].isObject()) continue;
        for (const char* http : kHttp) {
            const UniValue& op = values[i].find_value(http);
            if (!op.isObject()) continue;
            const UniValue& opid = op.find_value("operationId");
            if (!opid.isStr() || opid.get_str().empty()) {
                err = SCHEMA_ERR;
                return false;
            }
            HostedGateway::Route route;
            route.http_method = Upper(http);
            route.path = keys[i];
            route.operation_id = opid.get_str();
            const UniValue& ref = op.find_value("requestBody")
                                      .find_value("content")
                                      .find_value("application/json")
                                      .find_value("schema")
                                      .find_value("$ref");
            if (ref.isStr()) {
                std::string schema_err;
                const bool mutation = SchemaRequiresIdempotency(dir, ref.get_str(), schema_err);
                if (!schema_err.empty()) {
                    err = schema_err;
                    return false;
                }
                route.mutation = mutation;
            }
            routes.push_back(std::move(route));
        }
    }
    if (routes.empty()) {
        err = SCHEMA_ERR;
        return false;
    }
    err.clear();
    return true;
}

UniValue StringArray(const std::vector<std::string>& items)
{
    UniValue arr(UniValue::VARR);
    for (const std::string& item : items) arr.push_back(UniValue{item});
    return arr;
}

void AppendField(std::string& preimage, const std::string& field)
{
    preimage.append(std::to_string(field.size()));
    preimage.push_back(':');
    preimage.append(field);
    preimage.push_back('\n');
}

std::string Hex32(const unsigned char hash[CSHA256::OUTPUT_SIZE])
{
    static const char* kHex = "0123456789abcdef";
    std::string out(CSHA256::OUTPUT_SIZE * 2, '0');
    for (size_t i = 0; i < CSHA256::OUTPUT_SIZE; ++i) {
        out[i * 2] = kHex[hash[i] >> 4];
        out[i * 2 + 1] = kHex[hash[i] & 0x0f];
    }
    return out;
}

bool SensitiveField(const std::string& field)
{
    const std::string lower = Lower(field);
    return lower.find("token") != std::string::npos || lower.find("secret") != std::string::npos ||
           lower.find("password") != std::string::npos || lower.find("bearer") != std::string::npos ||
           lower.find("authorization") != std::string::npos || lower.find("api_key") != std::string::npos ||
           lower.find("apikey") != std::string::npos;
}

bool SecretValue(const AuditEvent& event)
{
    return Lower(event.classification) == "secret" || SensitiveField(event.field);
}

} // namespace

bool HostedGateway::Load(const std::string& openapi_path, std::string& err)
{
    std::vector<Route> parsed;
    if (!ParseOpenApi(openapi_path, parsed, err)) return false;
    routes_ = std::move(parsed);
    by_route_.clear();
    by_operation_.clear();
    for (size_t i = 0; i < routes_.size(); ++i) {
        by_route_[RouteKey(routes_[i].http_method, routes_[i].path)] = i;
        by_operation_[routes_[i].operation_id] = i;
    }
    err.clear();
    return true;
}

bool HostedGateway::HostedRouteAllowed(const std::string& method, const std::string& path) const
{
    if (Blank(method) || Blank(path) || DeniedRoute(path)) return false;
    return by_route_.find(RouteKey(method, path)) != by_route_.end();
}

bool HostedGateway::CheckRoute(const std::string& method, const std::string& path, std::string& err) const
{
    if (!HostedRouteAllowed(method, path)) {
        err = ROUTE_ERR;
        return false;
    }
    err.clear();
    return true;
}

bool HostedGateway::CheckOperationId(const std::string& operation_id, std::string& err) const
{
    if (Blank(operation_id) || IsRpcPath(operation_id) || operation_id == "POST /rpc" ||
        IsShellToken(operation_id) || IsShellPath(operation_id) || IsWalletName(operation_id)) {
        err = ROUTE_ERR;
        return false;
    }
    if (by_operation_.find(operation_id) == by_operation_.end()) {
        err = ROUTE_ERR;
        return false;
    }
    err.clear();
    return true;
}

bool HostedGateway::IsMutation(const std::string& operation_id) const
{
    const auto it = by_operation_.find(operation_id);
    if (it == by_operation_.end()) return false;
    return routes_[it->second].mutation;
}

bool HostedGateway::CheckMutation(const std::string& method, const std::string& path,
                                  const std::string& session_id, const std::string& realm_id,
                                  const std::string& resource_id, const std::string& idempotency_key,
                                  const std::string& expected_state, std::string& err) const
{
    if (!HostedRouteAllowed(method, path)) {
        err = ROUTE_ERR;
        return false;
    }
    const auto it = by_route_.find(RouteKey(method, path));
    if (it == by_route_.end()) {
        err = ROUTE_ERR;
        return false;
    }
    const Route& route = routes_[it->second];
    if (!route.mutation) {
        err.clear();
        return true;
    }
    if (Blank(session_id) || Blank(realm_id) || Blank(resource_id) || Blank(idempotency_key) ||
        Blank(expected_state)) {
        err = SCHEMA_ERR;
        return false;
    }
    err.clear();
    return true;
}

bool MutationAuthorizedByBearer(const std::string& bearer_token, std::string& err)
{
    (void)bearer_token;
    err = SCHEMA_ERR;
    return false;
}

bool RuntimeReceipt(int64_t observed_ms, const std::string& deployment_generation, UniValue& out,
                    std::string& err)
{
    out.clear();
    if (observed_ms < 0 || Blank(deployment_generation)) {
        err = SCHEMA_ERR;
        return false;
    }
    out.setObject();
    out.pushKV("observed_ms", UniValue{observed_ms});
    out.pushKV("deployment_generation", UniValue{deployment_generation});
    err.clear();
    return true;
}

bool InventoryExport(const std::vector<std::string>& desired,
                     const std::optional<std::vector<std::string>>& observed,
                     const std::vector<std::string>& unknown, int64_t observed_ms,
                     const std::string& deployment_generation, UniValue& out, std::string& err)
{
    out.clear();
    if (!observed.has_value()) {
        err = SCHEMA_ERR;
        return false;
    }
    UniValue receipt;
    if (!RuntimeReceipt(observed_ms, deployment_generation, receipt, err)) return false;
    out.setObject();
    out.pushKV("desired", StringArray(desired));
    out.pushKV("observed", StringArray(*observed));
    out.pushKV("unknown", StringArray(unknown));
    out.pushKV("observed_ms", UniValue{observed_ms});
    out.pushKV("deployment_generation", UniValue{deployment_generation});
    out.pushKV("runtime_receipt", receipt);
    err.clear();
    return true;
}

std::string AuditEventId(const AuditEvent& event)
{
    std::string preimage = "BTX035/audit/v1\n";
    AppendField(preimage, event.event_type);
    AppendField(preimage, event.realm_id);
    AppendField(preimage, event.resource_id);
    AppendField(preimage, event.field);
    AppendField(preimage, event.value);
    AppendField(preimage, event.classification);
    CSHA256 sha;
    sha.Write(reinterpret_cast<const unsigned char*>(preimage.data()), preimage.size());
    unsigned char hash[CSHA256::OUTPUT_SIZE];
    sha.Finalize(hash);
    return Hex32(hash);
}

bool ExportAuditEvent(const AuditEvent& event, UniValue& out, std::string& err)
{
    const std::string id = AuditEventId(event);
    out.setObject();
    out.pushKV("id", UniValue{id});
    out.pushKV("event_type", UniValue{event.event_type});
    out.pushKV("realm_id", UniValue{event.realm_id});
    out.pushKV("resource_id", UniValue{event.resource_id});
    out.pushKV("field", UniValue{event.field});
    out.pushKV("value", UniValue{SecretValue(event) ? std::string("REDACTED") : event.value});
    out.pushKV("classification", UniValue{SecretValue(event) ? std::string("secret") : event.classification});
    err.clear();
    return true;
}

bool PrivateAdmissionAdvertisesPublic()
{
    return false;
}

std::string DashboardAssurance(const std::string& mode)
{
    if (mode == "PRIVATE_REBUILDABLE" || mode == "DELEGATED_POLICY_ATTESTED" || mode == "PUBLIC_STRICT") {
        return mode;
    }
    if (Blank(mode)) return "unknown";
    return mode;
}

bool ExportPublic(bool explicit_review, const std::string& public_closure_id, std::string& err)
{
    if (!explicit_review || Blank(public_closure_id)) {
        err = SCOPE_ERR;
        return false;
    }
    err.clear();
    return true;
}

bool HostPathRequiresAdmission(const std::string& path)
{
    const std::string lower = Lower(path);
    static const char* kNeedles[] = {
        "hostmodel", "importmodel", "seedmodel", "demand-seed", "peer-follow",
        "mirror",    "reveal",      "bundle",    "package",
    };
    for (const char* needle : kNeedles) {
        if (lower.find(needle) != std::string::npos) return true;
    }
    return false;
}

bool AdmissionDecision(bool admitted, bool quarantined)
{
    return admitted && !quarantined;
}

} // namespace modelnet
