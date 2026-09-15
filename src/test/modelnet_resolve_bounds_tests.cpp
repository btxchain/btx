// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// V11-RESOLVE-03/07/08 router bounds, independent contact, 60s negative cache.
// Typed resolve must not relabel artifact digest as model_id.

#include <crypto/common.h>
#include <modelnet/catalog.h>
#include <modelnet/helper.h>
#include <modelnet/router.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <fstream>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_resolve_bounds_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(resolve_eight_router_four_query_and_independent)
{
    std::vector<std::string> preferred;
    for (int i = 0; i < 10; ++i) preferred.push_back("203.0.113." + std::to_string(i) + ":8443");
    const std::vector<std::string> independent{"198.51.100.9:8443"};
    modelnet::ResolveQueryPlan plan;
    BOOST_REQUIRE(modelnet::PlanRouterQueries(preferred, independent, plan));
    BOOST_CHECK_LE(plan.contacts.size(), static_cast<size_t>(modelnet::MAX_ROUTER_CONTACTS));
    BOOST_CHECK_LE(plan.max_concurrent, modelnet::MAX_CONCURRENT_RESOLVE_QUERIES);
    BOOST_CHECK(plan.reserved_independent);
    bool saw_ind = false;
    for (const auto& c : plan.contacts) {
        if (c == "198.51.100.9:8443") saw_ind = true;
    }
    BOOST_CHECK(saw_ind);

    modelnet::ResolveQueryPlan ip_only;
    BOOST_REQUIRE(modelnet::PlanRouterQueries({"192.0.2.10:1"}, {}, ip_only));
    BOOST_CHECK_EQUAL(ip_only.contacts.size(), 1U);
    BOOST_CHECK(!ip_only.reserved_independent);
}

BOOST_AUTO_TEST_CASE(resolve_negative_ttl_never_does_not_exist)
{
    modelnet::NegativeResolveCache neg;
    modelnet::Digest48 id{};
    id.data[0] = 0xab;
    BOOST_CHECK(!neg.HasIncomplete(0, id, 10));
    neg.RememberIncomplete(0, id, 10);
    BOOST_CHECK(neg.HasIncomplete(0, id, 10));
    BOOST_CHECK(neg.HasIncomplete(0, id, 69));
    BOOST_CHECK(!neg.HasIncomplete(0, id, 70));
    BOOST_CHECK_EQUAL(modelnet::NEGATIVE_RESOLVE_TTL_S, 60);
}

BOOST_AUTO_TEST_CASE(resolve_http_no_artifact_relabel)
{
    const fs::path tmp = m_path_root / "resolve-no-relabel";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    fs::create_directories(tmp / "src");
    std::vector<unsigned char> st(10, 0);
    WriteLE64(st.data(), 2);
    st[8] = '{';
    st[9] = '}';
    {
        std::ofstream out(tmp / "src" / "model.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
    }
    modelnet::CatalogEntry imported;
    std::string err;
    BOOST_REQUIRE(cat.ImportPath(fs::PathToString(tmp / "src"), true, imported, err));

    modelnet::NativeRequest nreq;
    nreq.method = "POST";
    nreq.path = "/btx-model/2/ext/resolve";
    nreq.body = "{\"kind\":1,\"digest48\":\"" + imported.artifact_id.Hex() + "\"}";
    modelnet::NativeResponse nresp;
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
    UniValue art;
    BOOST_REQUIRE(art.read(nresp.body));
    BOOST_CHECK_EQUAL(art["coverage"].get_str(), "incomplete");
    BOOST_CHECK_EQUAL(art["does_not_exist"].get_bool(), false);
    BOOST_REQUIRE(art["ids"].size() >= 1);
    BOOST_CHECK_EQUAL(art["ids"][0].get_str(), imported.artifact_id.Hex());
    BOOST_CHECK(art["ids"][0].get_str() != imported.model_id.Hex());

    nreq.body = "{\"kind\":0,\"digest48\":\"" + imported.artifact_id.Hex() + "\"}";
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
    UniValue as_model;
    BOOST_REQUIRE(as_model.read(nresp.body));
    BOOST_CHECK_EQUAL(as_model["ids"].size(), 0);

    nreq.body = "{\"kind\":0,\"digest48\":\"" + imported.model_id.Hex() + "\"}";
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
    UniValue as_ok;
    BOOST_REQUIRE(as_ok.read(nresp.body));
    BOOST_REQUIRE(as_ok["ids"].size() >= 1);
    BOOST_CHECK_EQUAL(as_ok["ids"][0].get_str(), imported.model_id.Hex());
}

BOOST_AUTO_TEST_CASE(resolve_unix_rpc_matches_http_typed_lookup)
{
    const fs::path tmp = m_path_root / "resolve-unix";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    fs::create_directories(tmp / "src");
    std::vector<unsigned char> st(10, 0);
    WriteLE64(st.data(), 2);
    st[8] = '{';
    st[9] = '}';
    {
        std::ofstream out(tmp / "src" / "model.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
    }
    modelnet::CatalogEntry imported;
    std::string err, code;
    BOOST_REQUIRE(cat.ImportPath(fs::PathToString(tmp / "src"), true, imported, err));

    UniValue req(UniValue::VOBJ);
    UniValue params(UniValue::VARR);
    UniValue query(UniValue::VOBJ);
    query.pushKV("digest48", imported.model_id.Hex());
    query.pushKV("kind", 0);
    params.push_back(query);
    req.pushKV("method", "resolveresource");
    req.pushKV("params", params);
    UniValue result;
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, req, result, code, err));
    BOOST_CHECK_EQUAL(result["coverage"].get_str(), "incomplete");
    BOOST_CHECK_EQUAL(result["does_not_exist"].get_bool(), false);
    BOOST_REQUIRE(result["ids"].size() >= 1);
    BOOST_CHECK_EQUAL(result["ids"][0].get_str(), imported.model_id.Hex());

    UniValue artq(UniValue::VOBJ);
    artq.pushKV("digest48", imported.artifact_id.Hex());
    artq.pushKV("kind", 0);
    UniValue art_params(UniValue::VARR);
    art_params.push_back(artq);
    req.pushKV("params", art_params);
    UniValue as_model;
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, req, as_model, code, err));
    BOOST_CHECK_EQUAL(as_model["ids"].size(), 0);
}

BOOST_AUTO_TEST_CASE(resolve_unsigned_announce_rejected)
{
    const fs::path tmp = m_path_root / "resolve-unsigned";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    modelnet::NativeRequest nreq;
    nreq.method = "POST";
    nreq.path = "/btx-model/2/ext/objects/announce";
    nreq.body = "{\"record_id\":\"" + std::string(96, 'a') + "\",\"kind\":19}";
    modelnet::NativeResponse nresp;
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
    BOOST_CHECK_EQUAL(nresp.status, 400);
}

BOOST_AUTO_TEST_SUITE_END()
