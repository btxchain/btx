// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
#include <test/modelnet_cr12_test.h>
#include <test/util/setup_common.h>
#include <util/fs.h>
#include <boost/test/unit_test.hpp>

#include <fstream>
#include <iterator>
#include <string>

namespace {

UniValue ReadJsonFile(const fs::path& p)
{
    std::ifstream in(fs::PathToString(p));
    BOOST_REQUIRE_MESSAGE(in.good(), fs::PathToString(p) + " missing");
    const std::string s((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    UniValue o;
    BOOST_REQUIRE(o.read(s));
    return o;
}

fs::path RepoRoot()
{
#ifdef MODELNET_CRL12_PORTAL_PATH
    return fs::PathFromString(MODELNET_CRL12_PORTAL_PATH).parent_path().parent_path().parent_path().parent_path();
#else
    return fs::PathFromString(std::string(__FILE__)).parent_path().parent_path().parent_path();
#endif
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(modelnet_cr12_compat_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cr12_compat_01)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    auto prof = e->Handle(hcp_test::AuthReq(*e, "GET", "/profile", tok));
    BOOST_CHECK_EQUAL(cr12_test::ObjType(prof), modelnet::HCP_TYPE_PROVIDER_PROFILE);
    modelnet::HcpEnvelope env;
    std::string err;
    BOOST_REQUIRE(modelnet::ParseHcpEnvelope(cr12_test::Json(prof), env, err));
    BOOST_CHECK(modelnet::HcpVerify(env, e->RootPk(), err));
    auto r11 = e->Handle(hcp_test::AuthReq(*e, "GET", "/extensions/cognitive-reserve", tok));
    BOOST_CHECK_EQUAL(cr12_test::ObjType(r11), modelnet::HCP_TYPE_RESERVE_EXTENSION);
    BOOST_REQUIRE(modelnet::ParseHcpEnvelope(cr12_test::Json(r11), env, err));
    BOOST_CHECK(modelnet::HcpVerify(env, e->OpPk(), err));
}

BOOST_AUTO_TEST_CASE(cr12_compat_02)
{
    const auto counts = ReadJsonFile(RepoRoot() / "contrib/modelnet/crl12/schemas/contract-counts.json");
    BOOST_CHECK_EQUAL(counts["base_operations"].getInt<int64_t>(), 84);
    BOOST_CHECK_EQUAL(counts["new_operations"].getInt<int64_t>(), 43);
    const auto ops = ReadJsonFile(RepoRoot() / "contrib/modelnet/crl12/schemas/operations-v1.2.json");
    BOOST_CHECK_EQUAL(ops["preserved_contract_operations"].getInt<int64_t>(), 84);
}

BOOST_AUTO_TEST_CASE(cr12_compat_03)
{
    auto e = cr12_test::Lab();
    BOOST_CHECK(e->Cr11ExtensionEnabled());
    BOOST_CHECK(e->Crl12ExtensionEnabled());
    auto tok = cr12_test::Tok(*e);
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "GET", "/extensions/cognitive-reserve", tok)).status, 200);
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "GET", "/extensions/cognitive-reserve/v1.2", tok)).status, 200);
    BOOST_CHECK(e->DualInstancePeerNote()["independent"].isTrue());
}

BOOST_AUTO_TEST_CASE(cr12_compat_04)
{
    auto e = hcp_test::Lab(false);
    BOOST_CHECK(!e->Crl12ExtensionEnabled());
    BOOST_CHECK(!e->Cr11ExtensionEnabled());
    auto tok = cr12_test::Tok(*e);
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/assets", tok))),
                      modelnet::HCP_ERR_PROFILE_UNSUPPORTED);
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "GET", "/profile", tok)).status, 200);
    BOOST_CHECK_EQUAL(e->Cfg().automatic_spend_atoms, 0);
}

BOOST_AUTO_TEST_CASE(cr12_compat_05)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "GET", "/profile", tok)).status, 200);
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "GET", "/extensions/cognitive-reserve", tok)).status, 200);
    UniValue plan(UniValue::VOBJ);
    plan.pushKV("objective", "own-then-run");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/plans", tok, &plan)).status, 201);
    UniValue port(UniValue::VOBJ);
    port.pushKV("portfolio_id", "compat05");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/portfolios", tok, &port)).status, 201);
}

BOOST_AUTO_TEST_CASE(cr12_compat_06)
{
    auto e = cr12_test::Lab();
    e->Crl12SetEnabled(false);
    auto tok = cr12_test::Tok(*e);
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "GET", "/extensions/cognitive-reserve/v1.2", tok))),
                      modelnet::HCP_ERR_PROFILE_UNSUPPORTED);
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/roles", tok))),
                      modelnet::HCP_ERR_PROFILE_UNSUPPORTED);
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "GET", "/extensions/cognitive-reserve", tok)).status, 200);
    UniValue plan(UniValue::VOBJ);
    plan.pushKV("objective", "own-then-run");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/plans", tok, &plan)).status, 201);
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "GET", "/health", tok)).status, 200);
}

BOOST_AUTO_TEST_CASE(cr12_compat_07)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/instructions", tok, &a));
    e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/instructions/" + cr12_test::Body(r)["instruction_id"].get_str() + "/translate", tok));
    std::string code, err;
    auto acc = e->AcceptHandoff(
        hcp_test::MakeHandoff(*e, "device-demo", "demo-nonce-not-production", hcp_test::kCore, hcp_test::kRecipe), code, err);
    BOOST_CHECK(code.empty() || code == modelnet::HCP_ERR_LOCAL_GRANT_REQUIRED);
    (void)acc;
    auto plan = e->PlanLocal(hcp_test::kRecipe, code);
    BOOST_CHECK(!plan["inventory_reported"].isTrue());
    BOOST_CHECK(!e->Cfg().expose_runtime_to_gateway);
}

BOOST_AUTO_TEST_CASE(cr12_compat_08)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "compat08");
    body.pushKV("maximum_exposure", "10");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &body));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string aid = cr12_test::Body(r)["allocation_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid + "/execute", tok));
    BOOST_CHECK_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(cr12_test::Body(r)["state"].get_str(), "HELD");
    BOOST_CHECK(cr12_test::Body(r)["runtime_ready"].isFalse());
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 10);
    BOOST_CHECK_GE(e->NativeHeight(), 0);
}

BOOST_AUTO_TEST_CASE(cr12_compat_09)
{
    auto eng_a = cr12_test::Lab();
    auto eng_b = cr12_test::Lab();
    eng_b->SwitchProvider("provider-b");
    auto tok_a = cr12_test::Tok(*eng_a);
    auto tok_b = cr12_test::Tok(*eng_b);
    UniValue a_role(UniValue::VOBJ);
    a_role.pushKV("role", "PORTFOLIO_ANALYTICS");
    BOOST_CHECK_EQUAL(eng_a->Handle(hcp_test::AuthReq(*eng_a, "POST", "/layer/roles", tok_a, &a_role)).status, 201);
    UniValue b_role(UniValue::VOBJ);
    b_role.pushKV("role", "PORTFOLIO_ANALYTICS");
    BOOST_CHECK_EQUAL(eng_b->Handle(hcp_test::AuthReq(*eng_b, "POST", "/layer/roles", tok_b, &b_role)).status, 201);
    BOOST_CHECK(!modelnet::Crl12BrandDispatch(cr12_test::Body(eng_a->Handle(hcp_test::AuthReq(*eng_a, "GET", "/layer/roles", tok_a))).write()));
}

BOOST_AUTO_TEST_CASE(cr12_compat_10)
{
    BOOST_CHECK(modelnet::HcpObjectTypeOk(modelnet::HCP_TYPE_LAYER_EXTENSION));
    BOOST_CHECK(modelnet::HcpObjectTypeOk(modelnet::HCP_TYPE_PORTFOLIO_INSTRUCTION));
    BOOST_CHECK(modelnet::HcpObjectTypeOk(modelnet::HCP_TYPE_IMPORT_MANIFEST));
    BOOST_CHECK(modelnet::HcpObjectTypeOk(modelnet::HCP_TYPE_CAPITAL_PLAN));
    BOOST_CHECK(modelnet::HcpObjectTypeOk(modelnet::HCP_TYPE_RESERVE_EXTENSION));
    BOOST_CHECK(modelnet::HcpObjectTypeOk(modelnet::HCP_TYPE_ADAPTER_CAPABILITY_MANIFEST));
    BOOST_CHECK(modelnet::HcpObjectTypeOk(modelnet::HCP_TYPE_INSTITUTIONAL_ASSET_RECORD));
    BOOST_CHECK(modelnet::HcpObjectTypeOk(modelnet::HCP_TYPE_RIGHTS_STATEMENT));
    BOOST_CHECK(modelnet::HcpObjectTypeOk(modelnet::HCP_TYPE_INTEROP_RECEIPT));
    BOOST_CHECK(modelnet::HcpObjectTypeOk(modelnet::HCP_TYPE_SCENARIO_DEFINITION));
    BOOST_CHECK(modelnet::HcpObjectTypeOk(modelnet::HCP_TYPE_SCENARIO_RESULT_SPEC));
    BOOST_CHECK(modelnet::HcpObjectTypeOk(modelnet::HCP_TYPE_CONFORMANCE_STATEMENT));
}

BOOST_AUTO_TEST_SUITE_END()
