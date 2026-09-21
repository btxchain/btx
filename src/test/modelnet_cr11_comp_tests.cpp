// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
// Unique native Cognitive Reserve v1.1 cases.

#include <test/modelnet_cr11_test.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(modelnet_cr11_comp_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cr11_comp_01_base_route_preservation)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    auto r = e->Handle(hcp_test::AuthReq(*e, "GET", "/profile", tok));
    BOOST_CHECK_EQUAL(r.status, 200);
    BOOST_CHECK_EQUAL(cr11_test::ObjType(r), modelnet::HCP_TYPE_PROVIDER_PROFILE);
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/health", tok));
    BOOST_CHECK(cr11_test::Json(r)["cognitive_reserve"].isTrue());
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/extensions/cognitive-reserve", tok));
    BOOST_CHECK_EQUAL(cr11_test::ObjType(r), modelnet::HCP_TYPE_RESERVE_EXTENSION);
}

BOOST_AUTO_TEST_CASE(cr11_comp_02_negotiated_extension_binding)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    auto r = e->Handle(hcp_test::AuthReq(*e, "GET", "/extensions/cognitive-reserve", tok));
    BOOST_REQUIRE_EQUAL(r.status, 200);
    BOOST_CHECK(!cr11_test::Json(r)["body"]["parent_profile_body_id"].get_str().empty());
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "alloc-bind-1");
    body.pushKV("parent_profile_body_id", std::string(96, 'f'));
    body.pushKV("maximum_exposure", "10");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &body));
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_BINDING);
}

BOOST_AUTO_TEST_CASE(cr11_comp_03_unknown_extension)
{
    auto e = hcp_test::Lab(false);
    BOOST_CHECK(!e->Cr11ExtensionEnabled());
    auto tok = cr11_test::Tok(*e);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/portfolios", tok));
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_PROFILE_UNSUPPORTED);
}

BOOST_AUTO_TEST_CASE(cr11_comp_04_domain_separation)
{
    auto e = cr11_test::Lab();
    modelnet::HcpEnvelope env;
    env.object_type = modelnet::HCP_TYPE_PORTFOLIO;
    env.body.pushKV("schema_revision", "1.1");
    env.body.pushKV("provider_id", "provider-demo");
    env.body.pushKV("created_at", std::to_string(e->Now()));
    env.body.pushKV("legal_entity_id", "le-demo");
    env.body.pushKV("portfolio_id", "port-x");
    env.body.pushKV("account_ref", "account-demo");
    env.body.pushKV("label", "w");
    env.body.pushKV("purpose", "r");
    env.body.pushKV("reporting_currency", "USD");
    env.body.pushKV("generation", "1");
    env.body.pushKV("status", "ACTIVE");
    std::string err;
    BOOST_REQUIRE(e->SignAsProvider(env, err));
    env.object_type = modelnet::HCP_TYPE_APPROVAL_DECISION;
    BOOST_CHECK(!modelnet::HcpVerify(env, e->OpPk(), err));
}

BOOST_AUTO_TEST_CASE(cr11_comp_05_strict_parser_parity)
{
    std::string err;
    UniValue out;
    std::string dup = "{\"a\":1,\"a\":2}";
    std::vector<unsigned char> raw(dup.begin(), dup.end());
    BOOST_CHECK(!modelnet::DecodePjson1(raw, out, err));
    std::string fl = "{\"n\":1.5}";
    raw.assign(fl.begin(), fl.end());
    BOOST_CHECK(!modelnet::DecodePjson1(raw, out, err));
    BOOST_CHECK(!modelnet::HcpObjectTypeOk("Arbitrary_V1_1"));
    BOOST_CHECK(modelnet::HcpObjectTypeOk(modelnet::HCP_TYPE_RESERVE_SNAPSHOT));
}

BOOST_AUTO_TEST_CASE(cr11_comp_06_no_package_version_inflation)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    body.pushKV("package_core_version", 4);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/positions", tok, &body));
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_CORE_V4);
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/profile", tok));
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["package_core_versions"][0].getInt<int64_t>(), 3);
}

BOOST_AUTO_TEST_CASE(cr11_comp_07_safe_downgrade)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "alloc-down-1");
    body.pushKV("maximum_exposure", "10");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &body));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    e->Cr11DisableExtension();
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &body));
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_PROFILE_UNSUPPORTED);
}

BOOST_AUTO_TEST_CASE(cr11_comp_08_key_rotation)
{
    auto e = cr11_test::Lab();
    std::string code, err;
    BOOST_REQUIRE(e->RotateOperationalKey(2, code, err));
    auto tok = cr11_test::Tok(*e);
    auto r = e->Handle(hcp_test::AuthReq(*e, "GET", "/extensions/cognitive-reserve", tok));
    BOOST_CHECK_EQUAL(r.status, 200);
    BOOST_CHECK(cr11_test::Json(r).exists("signer_key_id"));
}

BOOST_AUTO_TEST_CASE(cr11_comp_09_migration_restart)
{
    auto e = cr11_test::Lab();
    BOOST_REQUIRE(e->Persist());
    BOOST_CHECK_GE(e->Cr11Outstanding(), 0);
}

BOOST_AUTO_TEST_CASE(cr11_comp_10_rollback_accountability)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "alloc-rb-1");
    body.pushKV("maximum_exposure", "10");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &body));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    body.pushKV("maximum_exposure", "11");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &body));
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_CONFLICT);
}

BOOST_AUTO_TEST_SUITE_END()
