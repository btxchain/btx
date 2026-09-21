// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <crypto/common.h>
#include <modelnet/catalog.h>
#include <modelnet/free_grant.h>
#include <modelnet/helper.h>
#include <modelnet/identity.h>
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

BOOST_AUTO_TEST_SUITE_END()
