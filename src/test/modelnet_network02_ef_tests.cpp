// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// NETWORK-02 Lane E+F: DRR upload scheduler + origin broker.

#include <modelnet/origin_broker.h>
#include <modelnet/upload_scheduler_drr.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(modelnet_network02_ef_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(drr_identity_and_netgroup_are_separate_caps)
{
    using namespace modelnet;
    DrrConfig cfg;
    cfg.admission.slots = 4;
    cfg.admission.per_identity = 1;
    cfg.admission.per_netgroup = 1;
    UploadSchedulerDrr sch{cfg};
    uint64_t a = 0, b = 0;
    std::string err;
    DrrUploadRequest r;
    r.bytes = 1024;
    r.identity = "id-a";
    r.netgroup = "ng-1";
    BOOST_REQUIRE(sch.Enqueue(r, a, err));
    r.identity = "id-b";
    r.netgroup = "ng-1";
    BOOST_REQUIRE(sch.Enqueue(r, b, err));
    sch.RunEpoch();
    DrrSelection s;
    BOOST_REQUIRE(sch.Select(s));
    BOOST_CHECK_EQUAL(s.netgroup, "ng-1");
    BOOST_CHECK(!sch.Select(s));
    BOOST_CHECK_EQUAL(s.reason, "per-netgroup");
    BOOST_CHECK_EQUAL(sch.NetgroupActive("ng-1"), 1);
    BOOST_CHECK_EQUAL(sch.Active(), 1);

    UploadSchedulerDrr sch2{cfg};
    uint64_t c = 0, d = 0;
    r.identity = "id-a";
    r.netgroup = "ng-1";
    BOOST_REQUIRE(sch2.Enqueue(r, c, err));
    r.identity = "id-a";
    r.netgroup = "ng-2";
    BOOST_REQUIRE(sch2.Enqueue(r, d, err));
    sch2.RunEpoch();
    BOOST_REQUIRE(sch2.Select(s));
    BOOST_CHECK_EQUAL(s.identity, "id-a");
    BOOST_CHECK(!sch2.Select(s));
    BOOST_CHECK_EQUAL(s.reason, "per-identity");
    BOOST_CHECK_EQUAL(sch2.IdentityActive("id-a"), 1);
    BOOST_CHECK_EQUAL(sch2.Active(), 1);
}

BOOST_AUTO_TEST_CASE(drr_rare_cannot_starve_newcomer)
{
    using namespace modelnet;
    DrrConfig cfg;
    cfg.admission.slots = 2;
    cfg.reserve_newcomer_normal = true;
    UploadSchedulerDrr sch{cfg};
    uint64_t id = 0;
    std::string err;
    DrrUploadRequest rare;
    rare.bytes = 1024;
    rare.schedule = UploadClass::RARE;
    rare.identity = "rare-a";
    rare.netgroup = "ng-r";
    BOOST_REQUIRE(sch.Enqueue(rare, id, err));
    rare.identity = "rare-b";
    rare.netgroup = "ng-s";
    BOOST_REQUIRE(sch.Enqueue(rare, id, err));
    DrrUploadRequest neu;
    neu.bytes = 1024;
    neu.schedule = UploadClass::NEWCOMER;
    neu.identity = "new-a";
    neu.netgroup = "ng-n";
    BOOST_REQUIRE(sch.Enqueue(neu, id, err));
    sch.RunEpoch();
    DrrSelection s;
    BOOST_REQUIRE(sch.Select(s));
    BOOST_CHECK(s.schedule == UploadClass::NEWCOMER);
}

BOOST_AUTO_TEST_CASE(drr_accounting_not_pick_key)
{
    using namespace modelnet;
    UploadSchedulerDrr sch;
    uint64_t cloud = 0, p2p = 0;
    std::string err;
    DrrUploadRequest r;
    r.bytes = 2048;
    r.identity = "a";
    r.netgroup = "n1";
    r.accounting = HostAccountingClass::CLOUD_PROXIED;
    BOOST_REQUIRE(sch.Enqueue(r, cloud, err));
    r.identity = "b";
    r.netgroup = "n2";
    r.accounting = HostAccountingClass::NATIVE_P2P;
    BOOST_REQUIRE(sch.Enqueue(r, p2p, err));
    sch.RunEpoch();
    DrrSelection first, second;
    BOOST_REQUIRE(sch.Select(first));
    BOOST_REQUIRE(sch.Select(second));
    BOOST_REQUIRE(sch.NoteAcceptedWork(first.request_id, 100, err));
    BOOST_REQUIRE(sch.NoteAcceptedWork(second.request_id, 50, err));
    BOOST_CHECK_EQUAL(sch.AccountedBytes(HostAccountingClass::CLOUD_PROXIED) +
                          sch.AccountedBytes(HostAccountingClass::NATIVE_P2P),
                      150);
    BOOST_CHECK(sch.AccountedBytes(HostAccountingClass::CLOUD_PROXIED) !=
                sch.AccountedBytes(HostAccountingClass::NATIVE_P2P));
}

BOOST_AUTO_TEST_CASE(drr_slow_receiver_and_origin_wait_not_slots)
{
    using namespace modelnet;
    UploadSchedulerDrr sch;
    uint64_t slow = 0, wait = 0, ok = 0;
    std::string err;
    DrrUploadRequest r;
    r.bytes = 1024;
    r.identity = "slow";
    r.netgroup = "ng-a";
    r.receiver_writable = false;
    BOOST_REQUIRE(sch.Enqueue(r, slow, err));
    r.receiver_writable = true;
    r.origin_credit_reserved = false;
    r.identity = "orig";
    r.netgroup = "ng-b";
    BOOST_REQUIRE(sch.Enqueue(r, wait, err));
    r.origin_credit_reserved = true;
    r.identity = "ok";
    r.netgroup = "ng-c";
    BOOST_REQUIRE(sch.Enqueue(r, ok, err));
    sch.RunEpoch();
    DrrSelection s;
    BOOST_REQUIRE(sch.Select(s));
    BOOST_CHECK_EQUAL(s.request_id, ok);
    BOOST_CHECK_EQUAL(sch.Active(), 1);
    BOOST_CHECK_EQUAL(sch.Ready(), 2);
}

BOOST_AUTO_TEST_CASE(origin_broker_native_default_and_direct_gates)
{
    using namespace modelnet;
    OriginBroker broker;
    OriginBrokerRequest req;
    req.artifact_id = "aa";
    req.length_bytes = 1024;
    OriginBrokerOffer offer;
    std::string err;
    BOOST_REQUIRE(broker.Issue(req, 1000, offer, err));
    BOOST_CHECK(offer.mode == OriginMode::NATIVE_PROXY);
    BOOST_CHECK(offer.delivery == OriginDeliveryMode::PROXIED_NATIVE);
    BOOST_CHECK(offer.external_url.empty());
    BOOST_CHECK(offer.native_pq);
    BOOST_CHECK(!OriginJsonHasCredential(broker.PublicJson(offer)));
    std::string legacy_err;
    BOOST_CHECK(OriginOfferAllowed(broker.ToLegacyOffer(offer), legacy_err));

    req.requested_delivery = OriginDeliveryMode::DIRECT_BEST_EFFORT;
    req.requester_allows_external = true;
    BOOST_CHECK(!broker.Issue(req, 1000, offer, err));
    BOOST_CHECK_EQUAL(err, "operator disabled external origin");

    OriginBrokerPolicy pol;
    pol.operator_allows_external = true;
    OriginBroker ext{pol};
    BOOST_CHECK(!ext.Issue(req, 1000, offer, err));
    BOOST_CHECK_EQUAL(err, "external origin requires locator");

    req.locator = "https://example.invalid/obj";
    req.object_generation = "g1";
    BOOST_REQUIRE(ext.Issue(req, 1000, offer, err));
    BOOST_CHECK(offer.bearer_reusable);
    BOOST_CHECK(!PresignedGetIsMeter());
    BOOST_CHECK(!OriginFollowRedirectsAllowed());
    BOOST_CHECK(!OriginJsonHasCredential(ext.PublicJson(offer)));
    BOOST_CHECK(ext.PrivateJson(offer).exists("external_url"));
}

BOOST_AUTO_TEST_CASE(origin_broker_redirect_and_full_ingest)
{
    using namespace modelnet;
    OriginBrokerPolicy pol;
    pol.follow_redirects = true;
    OriginBroker bad{pol};
    OriginBrokerRequest req;
    req.artifact_id = "aa";
    req.length_bytes = 1024;
    OriginBrokerOffer offer;
    std::string err;
    BOOST_CHECK(!bad.Issue(req, 1, offer, err));
    BOOST_CHECK_EQUAL(err, "redirects forbidden");

    OriginBroker ok;
    req.length_bytes = PIECE_SIZE + 1;
    BOOST_CHECK(!ok.Issue(req, 1, offer, err));
    BOOST_CHECK_EQUAL(err, "full ingest not accepted");
    req.requester_accepts_full_ingest = true;
    BOOST_REQUIRE(ok.Issue(req, 1, offer, err));
    BOOST_CHECK(offer.requires_full_ingest);
}

BOOST_AUTO_TEST_SUITE_END()
