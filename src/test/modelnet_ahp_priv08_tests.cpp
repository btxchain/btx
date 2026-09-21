// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// AHP-PRIV-08: privileged unix may return local_paths on execute; public
// surfaces must not.

#include <modelnet/catalog.h>
#include <modelnet/helper.h>
#include <modelnet/http_bridge.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(modelnet_ahp_priv08_tests, BasicTestingSetup)

namespace {

const char* const kPublicUnixMethods[] = {
    "getmodelnetworkinfo",
    "getmodelcryptoinfo",
    "getbtxpackagecapabilities",
    "getsetupstatus",
    "checkmodelsetup",
    "getevaluatedtransport",
    "hello",
};

const char* const kPrivateUnixMethods[] = {
    "ensurebtxcapability",
    "planbtxcapability",
    "executebtxacquisition",
    "planbtxclientinstall",
    "inspectbtxtensormap",
    "hcphealth",
    "hcphandle",
    "accepthcphandoff",
    "applyhcpwalletless",
    "importhcpstate",
    "sethcpreporting",
    "gethcpreadiness",
};

const char* const kPrivateBridgePostDenyPaths[] = {
    "/hcphealth",
    "/hcphandle",
    "/accepthcphandoff",
    "/applyhcpwalletless",
    "/btx/hcp/v1/finance/intents",
};

const char* const kPrivateLocalStateKeys[] = {
    "installation_directory",
    "independent_trust_ref",
    "wallet_seed",
    "hf_token",
    "aws_secret_access_key",
};

UniValue Rpc(const std::string& method)
{
    UniValue req(UniValue::VOBJ);
    req.pushKV("method", method);
    req.pushKV("params", UniValue(UniValue::VARR));
    return req;
}

void CheckNativeCapabilityHttpDenied(modelnet::ModelCatalog& cat, const std::string& path)
{
    modelnet::NativeRequest req;
    req.method = "POST";
    req.path = path;
    req.body = "{}";
    modelnet::NativeResponse resp;
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, req, resp));
    BOOST_CHECK_EQUAL(resp.status, 405);
    UniValue body;
    BOOST_REQUIRE(body.read(resp.body));
    BOOST_REQUIRE(body.isObject());
    BOOST_CHECK(body.exists("public_runtime_rpc"));
    BOOST_CHECK(body["public_runtime_rpc"].isFalse());
    BOOST_REQUIRE(body.exists("automatic_spend_atoms"));
    BOOST_CHECK_EQUAL(body["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_CHECK(!modelnet::JsonLeaksPrivateLocalState(body));
}

} // namespace

BOOST_AUTO_TEST_CASE(ahp_priv_08_unix_public_surface_denylist)
{
    for (const char* method : kPublicUnixMethods) {
        BOOST_CHECK_MESSAGE(modelnet::HelperUnixMethodIsPublicSurface(method), method);
    }
    for (const char* method : kPrivateUnixMethods) {
        BOOST_CHECK_MESSAGE(!modelnet::HelperUnixMethodIsPublicSurface(method), method);
    }

    UniValue leak(UniValue::VOBJ);
    leak.pushKV("local_paths", "/secret");
    BOOST_CHECK(modelnet::JsonLeaksPrivateLocalState(leak));
    for (const char* key : kPrivateLocalStateKeys) {
        UniValue one(UniValue::VOBJ);
        one.pushKV(key, "secret");
        BOOST_CHECK_MESSAGE(modelnet::JsonLeaksPrivateLocalState(one), key);
    }
    UniValue ok(UniValue::VOBJ);
    ok.pushKV("automatic_spend_atoms", 0);
    BOOST_CHECK(!modelnet::JsonLeaksPrivateLocalState(ok));

    const fs::path tmp = m_path_root / "priv08";
    modelnet::ModelCatalog cat{tmp / "cat", 1 << 20};
    for (const char* method : kPublicUnixMethods) {
        UniValue result;
        std::string code, err;
        BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc(method), result, code, err),
                                std::string(method) + " " + err + " [" + code + "]");
        BOOST_CHECK_MESSAGE(!modelnet::JsonLeaksPrivateLocalState(result), method);
        if (result.exists("automatic_spend_atoms")) {
            BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
        }
    }

    modelnet::BrowserBridgeResponse br;
    BOOST_REQUIRE(modelnet::HandleBridgeRequest("GET", "/health", "", br));
    BOOST_CHECK(br.body.find("local_paths") == std::string::npos);
    BOOST_CHECK(br.body.find("wallet_seed") == std::string::npos);
    BOOST_CHECK(br.body.find("hf_token") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(remaining_ahp_priv_08_http_and_capability_surface)
{
    BOOST_CHECK(modelnet::NativeHttpRequiresVerifiedPq1());

    for (const auto& advertised : modelnet::AdvertisedNativeHttpPaths()) {
        BOOST_CHECK_MESSAGE(advertised.find("capability") == std::string::npos, advertised);
        BOOST_CHECK_MESSAGE(advertised.find("btxlock") == std::string::npos, advertised);
        BOOST_CHECK_MESSAGE(advertised.find("tensormap") == std::string::npos, advertised);
    }

    const fs::path tmp = m_path_root / "priv08-http";
    modelnet::ModelCatalog cat{tmp / "cat", 1 << 20};
    CheckNativeCapabilityHttpDenied(cat, "/btx-model/2/ensurebtxcapability");
    CheckNativeCapabilityHttpDenied(cat, "/btx-model/2/planbtxcapability");

    modelnet::BrowserBridgeResponse br;
    BOOST_REQUIRE(modelnet::HandleBridgeRequest("POST", "/ensurebtxcapability", "{}", br));
    BOOST_CHECK_EQUAL(br.http_status, 405);
    for (const char* path : kPrivateBridgePostDenyPaths) {
        BOOST_REQUIRE(modelnet::HandleBridgeRequest("POST", path, "{}", br));
        BOOST_CHECK_EQUAL(br.http_status, 405);
        UniValue body;
        if (body.read(br.body) && body.isObject() && body.exists("automatic_spend_atoms")) {
            BOOST_CHECK_EQUAL(body["automatic_spend_atoms"].getInt<int>(), 0);
        }
    }

    for (const char* method : kPublicUnixMethods) {
        UniValue result;
        std::string code, err;
        BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc(method), result, code, err),
                                std::string(method) + " " + err + " [" + code + "]");
        BOOST_CHECK_MESSAGE(!modelnet::JsonLeaksPrivateLocalState(result), method);
        for (const char* key : kPrivateLocalStateKeys) {
            BOOST_CHECK_MESSAGE(!result.exists(key), std::string(method) + " " + key);
        }
        if (result.exists("automatic_spend_atoms")) {
            BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
