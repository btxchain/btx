// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <crypto/common.h>
#include <modelnet/catalog.h>
#include <modelnet/free_grant.h>
#include <modelnet/helper.h>
#include <modelnet/identity.h>
#include <modelnet/resource_uri.h>
#include <modelnet/model_nat.h>
#include <modelnet/records.h>
#include <modelnet/relay_reserve.h>
#include <modelnet/provider_exchange.h>
#include <modelnet/transport_pq.h>
#include <netbase.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <fstream>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_authz_tests, BasicTestingSetup)

namespace {

modelnet::CatalogEntry ImportTiny(modelnet::ModelCatalog& cat)
{
    const fs::path src = cat.Store().Root().parent_path() / "src";
    fs::create_directories(src);
    std::vector<unsigned char> st(10, 0);
    WriteLE64(st.data(), 2);
    st[8] = '{';
    st[9] = '}';
    {
        std::ofstream out(src / "model.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
    }
    modelnet::CatalogEntry imported;
    std::string err;
    BOOST_REQUIRE(cat.ImportPath(fs::PathToString(src), true, imported, err));
    return imported;
}

} // namespace

BOOST_AUTO_TEST_CASE(hosted_grant_rejects_foreign_key)
{
    const fs::path tmp = m_path_root / "authz-grant";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    const auto imported = ImportTiny(cat);

    std::vector<unsigned char> pk, sk;
    std::string err;
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(pk, sk, err));
    modelnet::FreeGrantParams p;
    p.model_id = imported.model_id;
    p.artifact_id = imported.artifact_id;
    p.file_index = 0;
    p.first_piece = 0;
    p.piece_count = 1;
    p.maximum_bytes = 10;
    modelnet::SignedFreeGrant g;
    BOOST_REQUIRE(modelnet::IssueFreeGrant(p, sk, pk, g, err));

    modelnet::NativeRequest nreq;
    nreq.method = "GET";
    nreq.path = "/btx-model/2/transfers/" + imported.artifact_id.Hex() + "/pieces/0/0";
    nreq.headers = {
        {"X-BTX-Grant-Payload", HexStr(g.payload)},
        {"X-BTX-Grant-Sig", HexStr(g.signature)},
        {"X-BTX-Grant-Pubkey", HexStr(g.pubkey)},
    };
    modelnet::NativeResponse nresp;
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
    BOOST_CHECK_EQUAL(nresp.status, 403);
}

BOOST_AUTO_TEST_CASE(hosted_grant_issue_then_retrieve_then_replay)
{
    const fs::path tmp = m_path_root / "authz-grant-ok";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    const auto imported = ImportTiny(cat);

    modelnet::NativeRequest nreq;
    nreq.method = "POST";
    nreq.path = "/btx-model/2/ext/free/grant";
    UniValue req(UniValue::VOBJ);
    req.pushKV("model_id", imported.model_id.Hex());
    req.pushKV("first_piece", 0);
    req.pushKV("piece_count", 1);
    nreq.body = req.write();
    modelnet::NativeResponse nresp;
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
    BOOST_REQUIRE_EQUAL(nresp.status, 200);
    UniValue gj;
    BOOST_REQUIRE(gj.read(nresp.body));

    nreq = {};
    nreq.method = "GET";
    nreq.path = "/btx-model/2/transfers/" + imported.artifact_id.Hex() + "/pieces/0/0";
    nreq.headers = {
        {"X-BTX-Grant-Payload", gj["payload_hex"].get_str()},
        {"X-BTX-Grant-Sig", gj["sig_hex"].get_str()},
        {"X-BTX-Grant-Pubkey", gj["pubkey_hex"].get_str()},
    };
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
    BOOST_CHECK_EQUAL(nresp.status, 200);

    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
    BOOST_CHECK_EQUAL(nresp.status, 403);
}

BOOST_AUTO_TEST_CASE(typed_record_signer_must_match_key)
{
    std::vector<unsigned char> victim_pk, victim_sk, att_pk, att_sk;
    std::string err;
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(victim_pk, victim_sk, err));
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(att_pk, att_sk, err));
    UniValue body(UniValue::VOBJ);
    modelnet::FillRecordCommon(body, 1, modelnet::ProviderId(victim_pk), 1700000000, 0);
    body.pushKV("display_name", "authz");
    body.pushKV("description", "mismatched signer");
    std::vector<unsigned char> payload, sig;
    modelnet::Digest48 rid;
    BOOST_REQUIRE(modelnet::SignTypedRecord(modelnet::RECORD_IDENTITY_CARD, body, att_sk, payload, sig, rid, err));
    UniValue decoded;
    modelnet::Digest48 got;
    BOOST_CHECK(!modelnet::VerifyTypedRecord(modelnet::RECORD_IDENTITY_CARD, payload, sig, att_pk, 1700000000, decoded, got, err));
    BOOST_CHECK(err.find("identity") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(release_http_is_owner_unix)
{
    const fs::path tmp = m_path_root / "authz-release";
    modelnet::ModelCatalog cat{tmp, 1 << 20};
    modelnet::NativeRequest nreq;
    nreq.method = "POST";
    nreq.path = "/btx-model/2/releases/" + std::string(96, 'a') + "/pledges";
    nreq.body = "{\"amount_atoms\":1}";
    modelnet::NativeResponse nresp;
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
    BOOST_CHECK_EQUAL(nresp.status, 403);
}

BOOST_AUTO_TEST_CASE(relay_connect_requires_reservation_and_public_target)
{
    using namespace modelnet;
    std::string err;
    RelayConnectRequest rr;
    rr.endpoint = "203.0.113.1:29447";
    rr.reservation_id = "rsvp";
    BOOST_CHECK(ValidateRelayConnect(rr, true, err));
    rr.reservation_id.clear();
    BOOST_CHECK(!ValidateRelayConnect(rr, true, err));

    RelayTable tab;
    RelayReservation out;
    BOOST_CHECK(!tab.Reserve("svc", "ng", "192.168.1.9:29447", 0, out, err));
    BOOST_CHECK(tab.Reserve("svc", "ng", "203.0.113.1:29447", 0, out, err));
}

BOOST_AUTO_TEST_CASE(pq1_sigalg_fail_closed)
{
    modelnet::NegotiatedPq1 n;
    n.tls_version = "TLSv1.3";
    n.group = "MLKEM768";
    n.ciphersuite = "TLS_AES_256_GCM_SHA384";
    BOOST_CHECK(!modelnet::IsStrictPq1(n));
    n.sigalg = "mldsa44";
    BOOST_CHECK(modelnet::IsStrictPq1(n));
}

BOOST_AUTO_TEST_CASE(quotes_payment_autonat_report_owner_unix)
{
    const fs::path tmp = m_path_root / "authz-owner";
    modelnet::ModelCatalog cat{tmp, 1 << 20};
    modelnet::NativeRequest nreq;
    modelnet::NativeResponse nresp;
    nreq.method = "POST";
    nreq.path = "/btx-model/2/quotes";
    nreq.body = "{\"model_id\":\"" + std::string(96, 'a') + "\",\"price_atoms\":1}";
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
    BOOST_CHECK_EQUAL(nresp.status, 403);

    nreq.path = "/btx-model/2/transfers/x/payment";
    nreq.body = "{\"txid\":\"aa11bb22\",\"quote_id\":\"q\"}";
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
    BOOST_CHECK_EQUAL(nresp.status, 403);

    nreq.path = "/btx-model/2/ext/autonat/report";
    nreq.body = "{\"ok\":true,\"observer_id\":\"a\",\"observer_netgroup\":\"n1\",\"observed_endpoint\":\"203.0.113.8:29447\"}";
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
    BOOST_CHECK_EQUAL(nresp.status, 403);

    nreq.path = "/btx-model/2/ext/relay/reserve";
    nreq.body = "{\"service_id\":\"svc\",\"netgroup\":\"ng\",\"relay_endpoint\":\"203.0.113.1:29447\"}";
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
    BOOST_CHECK_EQUAL(nresp.status, 403);
}

BOOST_AUTO_TEST_CASE(pex_and_outbound_skip_loopback_and_lan_pex)
{
    using namespace modelnet;
    std::string err;
    BOOST_CHECK(IsForbiddenPexEndpoint("10.0.0.1:29447", err));
    BOOST_CHECK(IsForbiddenPexEndpoint("127.0.0.1:29447", err));
    BOOST_CHECK(!IsForbiddenPexEndpoint("203.0.113.1:29447", err));

    const CService loop = LookupNumeric("127.0.0.1", DEFAULT_MODEL_PORT);
    const CService imds = LookupNumeric("169.254.169.254", DEFAULT_MODEL_PORT);
    const CService lan = LookupNumeric("10.0.0.1", DEFAULT_MODEL_PORT);
    const CService pub = LookupNumeric("203.0.113.1", DEFAULT_MODEL_PORT);
    BOOST_CHECK(IsForbiddenOutboundDialAddr(loop));
    BOOST_CHECK(IsForbiddenOutboundDialAddr(imds));
    BOOST_CHECK(!IsForbiddenOutboundDialAddr(lan));
    BOOST_CHECK(!IsForbiddenOutboundDialAddr(pub));
    BOOST_CHECK(IsForbiddenControlPort(8332));
    BOOST_CHECK(IsForbiddenPexEndpoint("not-a-host.example:29447", err));
}

BOOST_AUTO_TEST_CASE(grant_issue_ignores_client_ttl)
{
    const fs::path tmp = m_path_root / "authz-grant-ttl";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    const auto imported = ImportTiny(cat);
    modelnet::NativeRequest nreq;
    nreq.method = "POST";
    nreq.path = "/btx-model/2/ext/free/grant";
    UniValue req(UniValue::VOBJ);
    req.pushKV("model_id", imported.model_id.Hex());
    req.pushKV("first_piece", 0);
    req.pushKV("piece_count", 1);
    req.pushKV("issued_at", 1);
    req.pushKV("expires_at", 4000000000);
    nreq.body = req.write();
    modelnet::NativeResponse nresp;
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
    BOOST_REQUIRE_EQUAL(nresp.status, 200);
    UniValue gj;
    BOOST_REQUIRE(gj.read(nresp.body));
    const int64_t issued = gj["issued_at"].getInt<int64_t>();
    const int64_t expires = gj["expires_at"].getInt<int64_t>();
    BOOST_CHECK_NE(issued, 1);
    BOOST_CHECK_LE(expires - issued, modelnet::FREE_GRANT_LIFETIME_S);
}

BOOST_AUTO_TEST_CASE(grant_issue_rate_is_not_bypassed_by_replay)
{
    const fs::path tmp = m_path_root / "authz-grant-rate";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    const auto imported = ImportTiny(cat);
    const std::string peer = fs::PathToString(tmp);

    int issued = 0;
    int limited = 0;
    for (int i = 0; i < 33; ++i) {
        modelnet::NativeRequest nreq;
        nreq.method = "POST";
        nreq.path = "/btx-model/2/ext/free/grant";
        nreq.peer_addr = peer;
        UniValue req(UniValue::VOBJ);
        req.pushKV("model_id", imported.model_id.Hex());
        req.pushKV("first_piece", 0);
        req.pushKV("piece_count", 1);
        nreq.body = req.write();
        modelnet::NativeResponse nresp;
        BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
        if (nresp.status == 200) ++issued;
        if (nresp.status == 429) ++limited;
    }
    BOOST_CHECK_EQUAL(issued, 32);
    BOOST_CHECK_EQUAL(limited, 1);
}

BOOST_AUTO_TEST_CASE(encrypted_release_plaintext_not_served_while_not_downloadable)
{
    const fs::path tmp = m_path_root / "authz-release-plaintext";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    const auto imported = ImportTiny(cat);

    std::string uri;
    std::string err;
    BOOST_REQUIRE(modelnet::EncodeResource(modelnet::ResourceKind::MODEL, imported.model_id, uri, err));
    unsigned char secret[32];
    for (int i = 0; i < 32; ++i) secret[i] = static_cast<unsigned char>(i + 9);
    UniValue params(UniValue::VARR);
    params.push_back(uri);
    params.push_back(HexStr(Span{secret, 32}));
    params.push_back(100000);
    UniValue rpc(UniValue::VOBJ);
    rpc.pushKV("method", "createmodelrelease");
    rpc.pushKV("params", params);
    UniValue created;
    std::string code;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, rpc, created, code, err), err);
    BOOST_CHECK(created.exists("release_id"));

    rpc = UniValue(UniValue::VOBJ);
    rpc.pushKV("method", "getmodeleconomyentry");
    UniValue econ_params(UniValue::VARR);
    econ_params.push_back(imported.model_id.Hex());
    rpc.pushKV("params", econ_params);
    UniValue econ;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, rpc, econ, code, err), err);
    BOOST_REQUIRE(econ.exists("downloadable_now") && econ["downloadable_now"].isBool());
    BOOST_CHECK(!econ["downloadable_now"].get_bool());

    modelnet::CatalogEntry after;
    BOOST_REQUIRE(cat.Find(imported.model_id, after));
    BOOST_CHECK(!after.seeded);

    UniValue seed_params(UniValue::VARR);
    seed_params.push_back(imported.model_id.Hex());
    rpc = UniValue(UniValue::VOBJ);
    rpc.pushKV("method", "seedmodel");
    rpc.pushKV("params", seed_params);
    UniValue seeded;
    BOOST_CHECK(!modelnet::DispatchHelperRpc(cat, rpc, seeded, code, err));
    BOOST_CHECK_EQUAL(code, "NOT_DOWNLOADABLE");

    BOOST_REQUIRE(cat.Seed(imported.model_id, true, err));
    modelnet::NativeRequest nreq;
    nreq.method = "POST";
    nreq.path = "/btx-model/2/ext/free/grant";
    nreq.peer_addr = "h8-plaintext-serve";
    UniValue greq(UniValue::VOBJ);
    greq.pushKV("model_id", imported.model_id.Hex());
    greq.pushKV("first_piece", 0);
    greq.pushKV("piece_count", 1);
    nreq.body = greq.write();
    modelnet::NativeResponse nresp;
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
    BOOST_REQUIRE_EQUAL(nresp.status, 200);
    UniValue gj;
    BOOST_REQUIRE(gj.read(nresp.body));

    nreq = {};
    nreq.method = "GET";
    nreq.path = "/btx-model/2/transfers/" + imported.artifact_id.Hex() + "/pieces/0/0";
    nreq.headers = {
        {"X-BTX-Grant-Payload", gj["payload_hex"].get_str()},
        {"X-BTX-Grant-Sig", gj["sig_hex"].get_str()},
        {"X-BTX-Grant-Pubkey", gj["pubkey_hex"].get_str()},
    };
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
    BOOST_CHECK_EQUAL(nresp.status, 404);
    BOOST_CHECK(!nresp.binary);
    BOOST_CHECK(nresp.body.find("NOT_FOUND") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(ext_feed_malformed_fields_do_not_throw)
{
    const fs::path tmp = m_path_root / "authz-feed-types";
    modelnet::ModelCatalog cat{tmp, 1 << 20};
    auto reject = [&](const std::string& body) {
        modelnet::NativeRequest req;
        req.method = "POST";
        req.path = "/btx-model/2/ext/feed";
        req.body = body;
        modelnet::NativeResponse resp;
        BOOST_CHECK_NO_THROW(modelnet::HandleNativeRequest(cat, req, resp));
        BOOST_CHECK_EQUAL(resp.status, 400);
        BOOST_CHECK(resp.body.find("BAD_JSON") != std::string::npos);
    };
    reject("{\"mode\":1}");
    reject("{\"limit\":\"nope\"}");
    reject("{\"cursor\":false}");
    reject("{\"limit\":9999999999999999999}");

    modelnet::NativeRequest ok;
    ok.method = "POST";
    ok.path = "/btx-model/2/ext/feed";
    ok.body = "{}";
    modelnet::NativeResponse resp;
    BOOST_CHECK_NO_THROW(modelnet::HandleNativeRequest(cat, ok, resp));
    BOOST_CHECK_EQUAL(resp.status, 200);
}

BOOST_AUTO_TEST_SUITE_END()
