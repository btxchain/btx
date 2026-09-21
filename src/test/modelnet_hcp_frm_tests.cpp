// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
// HCP-FRM-01 .. HCP-FRM-08 unique native cases.

#include <test/modelnet_hcp_test.h>
#include <test/util/setup_common.h>
#include <modelnet/identity.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(modelnet_hcp_frm_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(hcp_frm_01_canonical_statement_round_trip)
{
    auto e = hcp_test::Lab();
    auto env = hcp_test::ProfileOf(*e);
    std::string err;
    BOOST_REQUIRE(modelnet::HcpVerify(env, e->RootPk(), err));
    modelnet::Digest48 id1, id2;
    BOOST_REQUIRE(modelnet::HcpBodyId(env.object_type, env.body, id1, err));
    std::vector<unsigned char> a, b;
    BOOST_REQUIRE(modelnet::HcpCanonicalBody(env.body, a, err));
    UniValue again;
    BOOST_REQUIRE(modelnet::DecodePjson1(a, again, err));
    BOOST_REQUIRE(modelnet::HcpCanonicalBody(again, b, err));
    BOOST_REQUIRE(a == b);
    BOOST_REQUIRE(modelnet::HcpBodyId(env.object_type, env.body, id2, err));
    BOOST_CHECK(id1 == id2);
    BOOST_CHECK(id1 == env.body_id);
    BOOST_CHECK(env.object_type == modelnet::HCP_TYPE_PROVIDER_PROFILE);
}

BOOST_AUTO_TEST_CASE(hcp_frm_02_parser_differential_rejection)
{
    std::string err;
    UniValue out;
    const std::string dup = "{\"a\":1,\"a\":2}";
    std::vector<unsigned char> raw(dup.begin(), dup.end());
    BOOST_CHECK(!modelnet::DecodePjson1(raw, out, err));
    const std::string fl = "{\"n\":1.5}";
    raw.assign(fl.begin(), fl.end());
    BOOST_CHECK(!modelnet::DecodePjson1(raw, out, err));
    const std::string expn = "{\"n\":1e2}";
    raw.assign(expn.begin(), expn.end());
    BOOST_CHECK(!modelnet::DecodePjson1(raw, out, err));
    const std::string trail = "{\"a\":1}x";
    raw.assign(trail.begin(), trail.end());
    BOOST_CHECK(!modelnet::DecodePjson1(raw, out, err));
    modelnet::HcpEnvelope env;
    BOOST_CHECK(!modelnet::HcpEnvelopeFromBytes(Span<const unsigned char>{raw.data(), raw.size()}, env, err));
}

BOOST_AUTO_TEST_CASE(hcp_frm_03_domain_separation)
{
    auto e = hcp_test::Lab();
    modelnet::HcpEnvelope env;
    env.object_type = modelnet::HCP_TYPE_CAPABILITY_OFFER;
    env.body.pushKV("version", 1);
    env.body.pushKV("provider_id", "provider-demo");
    UniValue net(UniValue::VOBJ);
    net.pushKV("environment", "REGTEST");
    net.pushKV("genesis_hash", e->Cfg().genesis_hash);
    env.body.pushKV("network", net);
    env.body.pushKV("offer_id", "offer-demo");
    env.body.pushKV("issued_at_ms", std::to_string(e->Now()));
    env.body.pushKV("expires_at_ms", std::to_string(e->Now() + 1000));
    env.body.pushKV("package", UniValue(UniValue::VOBJ));
    env.body.pushKV("capability_labels", UniValue(UniValue::VARR));
    env.body.pushKV("evidence_refs", UniValue(UniValue::VARR));
    env.body.pushKV("availability_scope", "LOCAL_OBSERVATION");
    env.body.pushKV("observed_provider_count", UniValue());
    env.body.pushKV("economic_status", "PUBLIC");
    env.body.pushKV("economy_ref", UniValue());
    env.body.pushKV("sponsored", false);
    std::string err;
    BOOST_REQUIRE(e->SignAsProvider(env, err));
    env.object_type = modelnet::HCP_TYPE_FINANCIAL_RECEIPT;
    BOOST_CHECK(!modelnet::HcpVerify(env, e->OpPk(), err));
    UniValue labeled = modelnet::EncodeHcpEnvelope(env);
    labeled.pushKV("object_type", modelnet::HCP_TYPE_FINANCIAL_RECEIPT);
    modelnet::HcpEnvelope parsed;
    BOOST_CHECK(!modelnet::ParseHcpEnvelope(labeled, parsed, err) || err == modelnet::HCP_ERR_BODY_ID_MISMATCH ||
                !modelnet::HcpVerify(parsed, e->OpPk(), err));
}

BOOST_AUTO_TEST_CASE(hcp_frm_04_unknown_provider_self_signature)
{
    auto e = hcp_test::Lab();
    std::vector<unsigned char> pk, sk;
    std::string err;
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(pk, sk, err));
    modelnet::HcpEnvelope env = hcp_test::ProfileOf(*e);
    BOOST_REQUIRE(modelnet::HcpSign(env, sk, "foreign-root", err));
    auto preview = e->PreviewProvider(env);
    BOOST_CHECK(!preview["enrolled"].isTrue());
    BOOST_CHECK(!preview["trusted"].isTrue());
    std::string code;
    BOOST_CHECK(!e->EnrollProvider(env, false, code, err));
    BOOST_CHECK_EQUAL(code, modelnet::HCP_ERR_PROVIDER_UNENROLLED);
}

BOOST_AUTO_TEST_CASE(hcp_frm_05_operational_key_rotation)
{
    auto e = hcp_test::Lab();
    std::string code, err;
    BOOST_REQUIRE(e->RotateOperationalKey(2, code, err));
    BOOST_CHECK(!e->ReplayOldKeyset("op-1", code));
    BOOST_CHECK_EQUAL(code, "KEY_REVOKED");
    BOOST_REQUIRE(e->ReplayOldKeyset("op-2", code));
    code.clear();
    auto env = hcp_test::MakeHandoff(*e, "device-demo", "demo-nonce-not-production", hcp_test::kCore, hcp_test::kRecipe);
    auto acc = e->AcceptHandoff(env, code, err);
    BOOST_REQUIRE_MESSAGE(code.empty(), code + " " + err);
}

BOOST_AUTO_TEST_CASE(hcp_frm_06_origin_rebinding)
{
    auto e = hcp_test::Lab();
    e->RegisterFetch("https://exchange.example/btx/hcp/v1/profile", 302, "https://evil.example/profile", "{}");
    auto f = e->FetchUrl("https://exchange.example/btx/hcp/v1/profile", "Bearer stolen");
    BOOST_CHECK(f["authorization_forwarded"].isFalse() || !f["authorization_forwarded"].isTrue());
    BOOST_CHECK(f["reenrollment_required"].isTrue());
    BOOST_CHECK(f["credential_forwarded"].isFalse() || !f["credential_forwarded"].isTrue());
}

BOOST_AUTO_TEST_CASE(hcp_frm_07_size_and_structural_bounds)
{
    auto e = hcp_test::Lab();
    modelnet::HcpHttpRequest req;
    req.method = "POST";
    req.path = "/capabilities/search";
    req.body.assign(static_cast<size_t>(modelnet::HCP_MAX_BODY_BYTES) + 8, 'a');
    auto resp = e->Handle(req);
    BOOST_CHECK_EQUAL(resp.status, 413);
}

BOOST_AUTO_TEST_CASE(hcp_frm_08_role_separation_across_signatures)
{
    auto e = hcp_test::Lab();
    auto env = hcp_test::ProfileOf(*e);
    BOOST_CHECK(env.object_type != modelnet::HCP_TYPE_FINANCIAL_RECEIPT);
    std::string err;
    BOOST_CHECK(modelnet::HcpVerify(env, e->RootPk(), err));
    BOOST_CHECK(!modelnet::HcpVerify(env, e->OpPk(), err) || env.signer_key_id.find("root") != std::string::npos);
    auto hand = hcp_test::MakeHandoff(*e, "device-demo", "demo-nonce-not-production", hcp_test::kCore, hcp_test::kRecipe);
    BOOST_CHECK(modelnet::HcpVerify(hand, e->OpPk(), err));
}

BOOST_AUTO_TEST_SUITE_END()
