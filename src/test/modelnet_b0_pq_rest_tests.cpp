// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Remaining B0 PQ rows as one case per ID (CSV stays NOT_RUN).
// PQ-15 forged record
// PQ-16 quote/grant replay
// PQ-17 key rotation rollback
// PQ-18 missing PQ provider (fail closed; chain not in this process)
// PQ-20 redirect / conventional HTTPS is not native PQ1
// PQ-22 v1 32-byte model ids are not padded into v2 Digest48

#include <modelnet/catalog.h>
#include <modelnet/free_grant.h>
#include <modelnet/helper.h>
#include <modelnet/http_bridge.h>
#include <modelnet/identity.h>
#include <modelnet/protocol.h>
#include <modelnet/pq1_runtime.h>
#include <modelnet/records.h>
#include <modelnet/resource_uri.h>
#include <modelnet/transfer.h>
#include <modelnet/transport_pq.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <set>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_b0_pq_rest_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(pq_15_forged_record_never_verified)
{
    std::vector<unsigned char> pk, sk;
    std::string err;
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(pk, sk, err));
    UniValue body(UniValue::VOBJ);
    body.pushKV("ext_version", 257);
    body.pushKV("network", std::string(64, '0'));
    body.pushKV("signer_role", 1);
    body.pushKV("signer_id", modelnet::PublisherId(pk).Hex());
    body.pushKV("sequence", 1);
    body.pushKV("issued_at", 1700000000);
    body.pushKV("expires_at", 0);
    body.pushKV("display_name", "pq15");
    body.pushKV("description", "forged-sig fixture");
    std::vector<unsigned char> payload, sig;
    modelnet::Digest48 rid;
    BOOST_REQUIRE(modelnet::SignTypedRecord(modelnet::RECORD_IDENTITY_CARD, body, sk, payload, sig, rid, err));
    UniValue decoded;
    modelnet::Digest48 got;
    BOOST_REQUIRE(modelnet::VerifyTypedRecord(modelnet::RECORD_IDENTITY_CARD, payload, sig, pk, 1700000000, decoded, got, err));
    auto forged = sig;
    BOOST_REQUIRE(!forged.empty());
    forged[0] ^= 0x01;
    BOOST_CHECK(!modelnet::VerifyTypedRecord(modelnet::RECORD_IDENTITY_CARD, payload, forged, pk, 1700000000, decoded, got, err));
    BOOST_CHECK(err.find("signature") != std::string::npos || err.find("bad") != std::string::npos);

    const fs::path tmp = m_path_root / "pq15";
    modelnet::ModelCatalog cat{tmp, 1 << 20};
    modelnet::NativeRequest nreq;
    nreq.method = "POST";
    nreq.path = "/btx-model/2/ext/objects/announce";
    nreq.body = "{\"record_id\":\"" + std::string(96, 'a') + "\",\"kind\":19}";
    modelnet::NativeResponse nresp;
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
    BOOST_CHECK_EQUAL(nresp.status, 400);
}

BOOST_AUTO_TEST_CASE(pq_16_grant_replay_nonce)
{
    std::vector<unsigned char> pk, sk;
    std::string err;
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(pk, sk, err));
    modelnet::FreeGrantParams p;
    p.issued_at = 0;
    p.expires_at = 0;
    p.file_index = 0;
    p.first_piece = 0;
    p.piece_count = 1;
    p.maximum_bytes = 4096;
    p.grant_nonce.data.fill(0xAB);
    p.transfer_id.data.fill(0xCD);
    modelnet::SignedFreeGrant g;
    BOOST_REQUIRE_MESSAGE(modelnet::IssueFreeGrant(p, sk, pk, g, err), err);
    UniValue body;
    BOOST_REQUIRE(modelnet::VerifyFreeGrant(g.payload, g.signature, pk, 0, {}, body, err));
    const std::set<std::string> seen{g.body["grant_nonce"].get_str()};
    modelnet::GrantRejectReason reason{};
    BOOST_REQUIRE(modelnet::RejectExpiredTamperedReplay(g.payload, g.signature, pk, 0, seen, reason, err));
    BOOST_CHECK(reason == modelnet::GrantRejectReason::REPLAY);
    std::vector<modelnet::PaymentJournal> journal;
    modelnet::PaymentJournal j;
    j.txid = "deadbeef";
    j.quote_id = p.grant_nonce.Hex();
    journal.push_back(j);
    BOOST_CHECK(modelnet::DuplicatePayment(journal, "deadbeef"));
}

BOOST_AUTO_TEST_CASE(pq_17_pin_rotation_no_forced_replace)
{
    const fs::path pinfile = m_path_root / "pq17" / "pins.json";
    fs::create_directories(pinfile.parent_path());
    modelnet::Digest48 a{}, b{};
    a.data[0] = 1;
    b.data[0] = 2;
    std::string err;
    BOOST_REQUIRE(modelnet::CheckOrStorePin(pinfile, "192.0.2.9:29447", a, err));
    BOOST_CHECK(!modelnet::CheckOrStorePin(pinfile, "192.0.2.9:29447", b, err));
    BOOST_CHECK(err.find("pin") != std::string::npos);
    BOOST_REQUIRE(modelnet::CheckOrStorePin(pinfile, "192.0.2.9:29447", a, err));
    modelnet::IdentityStore store;
    BOOST_CHECK(!store.RotationCopiesReciprocity());
}

BOOST_AUTO_TEST_CASE(pq_18_missing_pq_fail_closed)
{
    modelnet::Pq1Context pq;
    BOOST_REQUIRE_MESSAGE(pq.Ready(), pq.Error());
    modelnet::NegotiatedPq1 n;
    n.tls_version = "TLSv1.2";
    n.group = "X25519";
    n.ciphersuite = "TLS_AES_128_GCM_SHA256";
    n.sigalg = "ed25519";
    n.ok = true;
    BOOST_CHECK(!modelnet::IsStrictPq1(n));
    n.tls_version = "TLSv1.3";
    n.group = "MLKEM768";
    n.ciphersuite = "TLS_AES_256_GCM_SHA384";
    n.sigalg.clear();
    BOOST_CHECK(!modelnet::IsStrictPq1(n));
    n.sigalg = "mldsa44";
    BOOST_CHECK(modelnet::IsStrictPq1(n));
    const UniValue caps = modelnet::CapabilitiesObject();
    BOOST_CHECK_EQUAL(caps["pq1_http"].get_bool(), true);
}

BOOST_AUTO_TEST_CASE(pq_20_https_not_native_pq1)
{
    modelnet::Resource r;
    std::string err;
    BOOST_CHECK(!modelnet::DecodeResource("https://example.test/model", r, err));
    BOOST_CHECK(!modelnet::DecodeResource("http://192.0.2.9/btx-model/2/hello", r, err));
    modelnet::BrowserBridgeResponse br;
    BOOST_REQUIRE(modelnet::HandleBridgeGet("/open?uri=btx://pqwy06q0q7wwzy70aeq45sxnlvq3mr067yt4jzphzvnfn2c4zc24zxz665zdprf0nwgskvqq9cq365u9n8l25", br));
    BOOST_CHECK(br.body.find("\"native_fallback\":false") != std::string::npos);
    BOOST_CHECK(br.body.find("\"pq_end_to_end\":false") != std::string::npos);
    std::string path;
    BOOST_CHECK(!modelnet::BridgePath("https://evil.test/x", "https://bridge.example.org", path, err));
}

BOOST_AUTO_TEST_CASE(pq_22_v1_32byte_ids_not_padded)
{
    modelnet::Digest48 d;
    std::string err;
    BOOST_CHECK(!modelnet::Digest48::FromHex(std::string(64, 'a'), d, err));
    modelnet::Resource r;
    BOOST_CHECK(!modelnet::DecodeResource(std::string(64, 'a'), r, err));
    BOOST_CHECK(!modelnet::DecodeResource("btx://" + std::string(64, 'a'), r, err));
    modelnet::Hash32 h;
    BOOST_REQUIRE(modelnet::Hash32::FromHex(std::string(64, 'a'), h, err));
    BOOST_CHECK_EQUAL(h.data.size(), 32U);
}

BOOST_AUTO_TEST_SUITE_END()
