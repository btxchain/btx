// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Shared HCP/1 native test fixtures. Unique BOOST cases live in per-family TUs.

#ifndef BITCOIN_TEST_MODELNET_HCP_TEST_H
#define BITCOIN_TEST_MODELNET_HCP_TEST_H

#include <modelnet/hcp.h>
#include <modelnet/http_bridge.h>
#include <modelnet/package_pjson.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <memory>
#include <string>
#include <vector>

namespace hcp_test {

inline modelnet::LocalCapabilityGrant OwnerGrant()
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("grant_id", "grant-owner");
    o.pushKV("caller", "owner");
    o.pushKV("expires_at_ms", static_cast<int64_t>(1790000600000));
    o.pushKV("host_bytes", static_cast<int64_t>(64 * 1024 * 1024));
    o.pushKV("automatic_spend_atoms", 0);
    modelnet::LocalCapabilityGrant g;
    std::string code, err;
    BOOST_REQUIRE(modelnet::ParseGrant(o, g, code, err));
    return g;
}

inline modelnet::HcpEnvelope ProfileOf(modelnet::HcpEngine& e)
{
    modelnet::HcpHttpRequest req;
    req.method = "GET";
    req.path = "/profile";
    auto resp = e.Handle(req);
    BOOST_REQUIRE_EQUAL(resp.status, 200);
    UniValue j;
    BOOST_REQUIRE(j.read(resp.body));
    modelnet::HcpEnvelope env;
    std::string err;
    BOOST_REQUIRE(modelnet::ParseHcpEnvelope(j, env, err));
    return env;
}

inline void EnrollSelf(modelnet::HcpEngine& e)
{
    auto env = ProfileOf(e);
    std::string code, err;
    BOOST_REQUIRE(e.EnrollProvider(env, true, code, err));
}

inline std::unique_ptr<modelnet::HcpEngine> Lab(bool funding = false)
{
    auto cfg = funding ? modelnet::HcpFundingLabPreset() : modelnet::HcpWalletlessPreset();
    cfg.automatic_spend_atoms = 0;
    std::string err;
    auto e = modelnet::HcpEngine::Create(cfg, err);
    BOOST_REQUIRE_MESSAGE(e, err);
    EnrollSelf(*e);
    e->PairDevice("device-demo", "account-demo");
    e->SetDeviceNonce("device-demo", "demo-nonce-not-production");
    e->SetLocalGrant(OwnerGrant());
    e->PutAccount("account-demo", 1'000'000);
    e->SeedDemoCatalog();
    return e;
}

inline std::vector<std::string> AllScopes()
{
    return {"catalog:read", "packages:read", "handoffs:create", "devices:enroll", "devices:report",
            "account:read", "quotes:create", "intents:create", "intents:authorize", "intents:submit",
            "intents:cancel", "policies:admin", "subscriptions:write", "events:read", "exports:create",
            "research:publish"};
}

inline std::string Token(modelnet::HcpEngine& e, const std::vector<std::string>& scopes,
                         const std::string& audience = {})
{
    const std::string ver = "pkce-verifier-demo-aaaa";
    const std::string ch = e.LabCreatePkceChallenge(ver);
    const std::string code = e.LabAuthorize("account-demo", "client-demo", "https://app.example/cb", "state-1", ch,
                                              scopes);
    UniValue tok;
    std::string err;
    BOOST_REQUIRE(e.LabToken(code, ver, "https://app.example/cb", e.LabJkt(), audience, tok, err));
    return tok["access_token"].get_str();
}

inline modelnet::HcpHttpRequest AuthReq(modelnet::HcpEngine& e, const std::string& method, const std::string& path,
                                         const std::string& token, const UniValue* body = nullptr)
{
    modelnet::HcpHttpRequest req;
    req.method = method;
    req.path = path;
    req.headers["authorization"] = "Bearer " + token;
    req.headers["dpop"] = e.LabDpop(method, e.Cfg().api_base + path, token);
    if (body) {
        std::vector<unsigned char> raw;
        std::string err;
        BOOST_REQUIRE(modelnet::EncodePjson1(*body, raw, err));
        req.body.assign(raw.begin(), raw.end());
    }
    return req;
}

inline modelnet::HcpEnvelope MakeHandoff(modelnet::HcpEngine& e, const std::string& device,
                                           const std::string& nonce, const std::string& core, const std::string& recipe)
{
    modelnet::HcpEnvelope env;
    env.object_type = modelnet::HCP_TYPE_CAPABILITY_HANDOFF;
    env.body.pushKV("version", 1);
    env.body.pushKV("provider_id", e.Cfg().provider_id);
    env.body.pushKV("account_ref", "account-demo");
    env.body.pushKV("device_id", device);
    UniValue net(UniValue::VOBJ);
    net.pushKV("environment", "REGTEST");
    net.pushKV("genesis_hash", e.Cfg().genesis_hash);
    env.body.pushKV("network", net);
    env.body.pushKV("handoff_id", "handoff-demo");
    env.body.pushKV("client_operation_id", "op-demo-acquire-01");
    env.body.pushKV("request_nonce", nonce);
    env.body.pushKV("issued_at_ms", std::to_string(e.Now()));
    env.body.pushKV("expires_at_ms", std::to_string(e.Now() + 600000));
    UniValue pkg(UniValue::VOBJ);
    pkg.pushKV("package_core_id", core);
    pkg.pushKV("file_sha384",
               "222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222");
    pkg.pushKV("recipe_id", recipe);
    pkg.pushKV("download_url", e.Cfg().api_base + "/packages/" + core);
    env.body.pushKV("package", pkg);
    env.body.pushKV("readiness_target", "RUNTIME_READY");
    UniValue fx(UniValue::VARR);
    fx.push_back("FETCH_METADATA");
    fx.push_back("ACQUIRE_MODEL");
    fx.push_back("PLAN_LOCAL_RUN");
    env.body.pushKV("requested_effects", fx);
    env.body.pushKV("source_hints", UniValue(UniValue::VARR));
    env.body.pushKV("receipt_ref", UniValue());
    env.body.pushKV("reporting_requested", false);
    std::string err;
    BOOST_REQUIRE(e.SignAsProvider(env, err));
    return env;
}

inline const char* kCore =
    "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";
inline const char* kRecipe =
    "333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333";

} // namespace hcp_test

#endif
