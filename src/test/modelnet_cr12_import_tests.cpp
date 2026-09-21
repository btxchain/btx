// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
#include <test/modelnet_cr12_test.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>

#include <string>

namespace {

std::string TokenFor(modelnet::HcpEngine& e, const std::string& account)
{
    const std::string ver = "pkce-verifier-" + account + "-cr12";
    const std::string ch = e.LabCreatePkceChallenge(ver);
    const std::string code =
        e.LabAuthorize(account, "client-demo", "https://app.example/cb", "state-" + account, ch, cr12_test::Scopes());
    UniValue tok;
    std::string err;
    BOOST_REQUIRE(e.LabToken(code, ver, "https://app.example/cb", e.LabJkt(), "", tok, err));
    return tok["access_token"].get_str();
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(modelnet_cr12_import_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cr12_import_01)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    modelnet::HcpHttpRequest req = hcp_test::AuthReq(*e, "POST", "/institutional/imports/chunks", tok);
    req.body = "hello-chunk";
    auto r = e->Handle(req);
    BOOST_CHECK_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(cr12_test::Json(r)["length"].getInt<int64_t>(), static_cast<int64_t>(req.body.size()));
    BOOST_CHECK(!cr12_test::Json(r)["digest"].get_str().empty());
    UniValue v(UniValue::VOBJ);
    v.pushKV("chunk_id", cr12_test::Json(r)["chunk_id"].get_str());
    v.pushKV("digest", cr12_test::Json(r)["digest"].get_str());
    auto val = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/imports/validate", tok, &v));
    BOOST_CHECK_EQUAL(val.status, 200);
    BOOST_CHECK_EQUAL(cr12_test::ObjType(val), modelnet::HCP_TYPE_IMPORT_MANIFEST);
}

BOOST_AUTO_TEST_CASE(cr12_import_02)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    modelnet::HcpHttpRequest req = hcp_test::AuthReq(*e, "POST", "/institutional/imports/chunks", tok);
    req.body = "hello-chunk";
    auto r = e->Handle(req);
    UniValue v(UniValue::VOBJ);
    v.pushKV("chunk_id", cr12_test::Json(r)["chunk_id"].get_str());
    v.pushKV("digest", std::string(96, '0'));
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/imports/validate", tok, &v))),
                      modelnet::HCP_ERR_CHUNK_DIGEST);
}

BOOST_AUTO_TEST_CASE(cr12_import_03)
{
    auto e = cr12_test::Lab();
    auto tok_a = cr12_test::Tok(*e);
    e->PutAccount("account-b", 777);
    const auto tok_b = TokenFor(*e, "account-b");
    modelnet::HcpHttpRequest req = hcp_test::AuthReq(*e, "POST", "/institutional/imports/chunks", tok_a);
    req.body = "tenant-a-bytes";
    auto staged = e->Handle(req);
    BOOST_REQUIRE_EQUAL(staged.status, 201);
    UniValue v(UniValue::VOBJ);
    v.pushKV("chunk_id", cr12_test::Json(staged)["chunk_id"].get_str());
    v.pushKV("digest", cr12_test::Json(staged)["digest"].get_str());
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/imports/validate", tok_b, &v));
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(r), modelnet::HCP_ERR_CHUNK_NOT_OWNED);
    BOOST_CHECK(r.body.find("tenant-a-bytes") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(cr12_import_04)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue v(UniValue::VOBJ);
    v.pushKV("duplicate_chunk", true);
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/imports/validate", tok, &v)).status, 400);
}

BOOST_AUTO_TEST_CASE(cr12_import_05)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue v(UniValue::VOBJ);
    v.pushKV("row_mismatch", true);
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/imports/validate", tok, &v)).status, 400);
}

BOOST_AUTO_TEST_CASE(cr12_import_06)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue v(UniValue::VOBJ);
    v.pushKV("mapping_digest", std::string(96, 'e'));
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/imports/validate", tok, &v));
    UniValue c(UniValue::VOBJ);
    c.pushKV("mapping_digest", std::string(96, 'f'));
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(
                          *e, "POST", "/institutional/imports/" + cr12_test::Body(r)["import_id"].get_str() + "/commit", tok, &c))),
                      modelnet::HCP_ERR_MAPPING_CAS);
}

BOOST_AUTO_TEST_CASE(cr12_import_07)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue v(UniValue::VOBJ);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/imports/validate", tok, &v));
    const std::string id = cr12_test::Body(r)["import_id"].get_str();
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/imports/" + id + "/commit", tok)).status, 200);
    BOOST_CHECK_EQUAL(cr12_test::Body(e->Handle(hcp_test::AuthReq(*e, "GET", "/institutional/imports/" + id, tok)))["status"].get_str(),
                      "PUBLISHED");
}

BOOST_AUTO_TEST_CASE(cr12_import_08)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue v(UniValue::VOBJ);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/imports/validate", tok, &v));
    const std::string id = cr12_test::Body(r)["import_id"].get_str();
    auto c1 = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/imports/" + id + "/commit", tok));
    auto c2 = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/imports/" + id + "/commit", tok));
    BOOST_CHECK_EQUAL(cr12_test::Body(c1)["generation"].get_str(), cr12_test::Body(c2)["generation"].get_str());
}

BOOST_AUTO_TEST_CASE(cr12_import_09)
{
    std::string safe;
    BOOST_CHECK(modelnet::Crl12CsvSafe("=cmd", safe));
    BOOST_CHECK_EQUAL(safe.front(), '\'');
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("label", "=cmd|'/c calc'!A0");
    BOOST_REQUIRE_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/assets", tok, &a)).status, 201);
    UniValue csv(UniValue::VOBJ);
    csv.pushKV("format", "CSV");
    auto man = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/exports", tok, &csv));
    BOOST_REQUIRE_EQUAL(man.status, 201);
    const std::string eid = cr12_test::Body(man)["export_id"].get_str();
    const std::string cid = cr12_test::Body(man)["chunks"][0]["chunk_id"].get_str();
    auto bytes = e->Handle(hcp_test::AuthReq(*e, "GET", "/institutional/exports/" + eid + "/chunks/" + cid, tok));
    BOOST_CHECK_EQUAL(bytes.status, 200);
    BOOST_CHECK(bytes.body.find("'=cmd") != std::string::npos);
    UniValue jsonl(UniValue::VOBJ);
    jsonl.pushKV("format", "JSONL");
    auto jl = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/exports", tok, &jsonl));
    BOOST_CHECK_EQUAL(cr12_test::ObjType(jl), modelnet::HCP_TYPE_EXPORT_MANIFEST);
}

BOOST_AUTO_TEST_CASE(cr12_import_10)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    const int64_t before = e->AccountAvailable("account-demo");
    UniValue v(UniValue::VOBJ);
    v.pushKV("contains_balance", true);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/imports/validate", tok, &v));
    const std::string id = cr12_test::Body(r)["import_id"].get_str();
    e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/imports/" + id + "/commit", tok));
    BOOST_CHECK_EQUAL(e->AccountAvailable("account-demo"), before);
    BOOST_CHECK(cr12_test::Body(e->Handle(hcp_test::AuthReq(*e, "GET", "/institutional/imports/" + id, tok)))["custody_credit"].isFalse());
}

BOOST_AUTO_TEST_SUITE_END()
