// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <bitcoin-build-config.h> // IWYU pragma: keep
#include <modelnet/helper.h>
#include <modelnet/identity.h>
#include <modelnet/model_nat.h>
#include <modelnet/protocol.h>
#include <modelnet/provider_route.h>
#include <modelnet/reachability.h>
#include <modelnet/relay_reserve.h>
#include <test/util/setup_common.h>
#include <util/fs.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_conn_tests, BasicTestingSetup)

namespace {

modelnet::DialbackReport OkReport(const std::string& id, const std::string& ng, const std::string& ep, int64_t now)
{
    modelnet::DialbackReport r;
    r.request_id = "r-" + id;
    r.observer_id = id;
    r.observer_netgroup = ng;
    r.observed_endpoint = ep;
    r.ok = true;
    r.at_ms = now;
    return r;
}

modelnet::ProviderRecord SignedRecord(const modelnet::Digest48& resource, uint64_t seq, int64_t expiry,
                                        const std::string& endpoint, bool complete,
                                        std::vector<unsigned char>& pk, std::vector<unsigned char>& sk)
{
    using namespace modelnet;
    std::string err;
    BOOST_REQUIRE(GenerateMlDsa44(pk, sk, err));
    ProviderRecord r;
    r.resource = resource;
    r.pubkey = pk;
    r.endpoints = {endpoint};
    r.reachability_kind = "direct";
    r.complete = complete;
    r.seq = seq;
    r.expiry_ms = expiry;
    BOOST_REQUIRE(SignProviderRecord(r, Span<const unsigned char>{sk.data(), sk.size()}, err));
    return r;
}

} // namespace

BOOST_AUTO_TEST_CASE(conn_reach_01_to_10)
{
    using namespace modelnet;
    ReachabilityTracker t;
    t.SetListen("203.0.113.8:29447");
    BOOST_CHECK_EQUAL(static_cast<int>(t.State()), static_cast<int>(ReachabilityState::UNKNOWN));
    BOOST_CHECK(!t.MayAdvertiseHost(true));

    DialbackReport one = OkReport("a", "ng-a", "203.0.113.8:29447", 1000);
    t.NoteReport(one, 1000);
    BOOST_CHECK_NE(static_cast<int>(t.State()), static_cast<int>(ReachabilityState::PUBLIC_DIRECT));
    BOOST_CHECK(!t.MayAdvertiseHost(true));

    DialbackReport two = OkReport("b", "ng-b", "203.0.113.8:29447", 1001);
    t.NoteReport(two, 1001);
    BOOST_CHECK_EQUAL(static_cast<int>(t.State()), static_cast<int>(ReachabilityState::PUBLIC_DIRECT));
    BOOST_CHECK(t.MayAdvertiseHost(true));

    ReachabilityTracker failt;
    DialbackReport bad;
    bad.request_id = "x";
    bad.observer_id = "z";
    bad.observer_netgroup = "ng-z";
    bad.ok = false;
    bad.at_ms = 50;
    failt.NoteReport(bad, 50);
    BOOST_CHECK_EQUAL(static_cast<int>(failt.State()), static_cast<int>(ReachabilityState::PRIVATE));

    t.Expire(1001 + 15 * 60 * 1000 + 1);
    BOOST_CHECK_NE(static_cast<int>(t.State()), static_cast<int>(ReachabilityState::PUBLIC_DIRECT));
    BOOST_CHECK(!t.MayAdvertiseHost(true));

    ReachabilityTracker t6;
    t6.NoteReport(OkReport("a", "n1", "[2001:db8::1]:29447", 10), 10);
    t6.NoteReport(OkReport("b", "n2", "[2001:db8::1]:29447", 11), 11);
    BOOST_CHECK_EQUAL(static_cast<int>(t6.State()), static_cast<int>(ReachabilityState::PUBLIC_DIRECT));

    ReachabilityTracker mapped;
    mapped.SetMapped("198.51.100.9:29447");
    mapped.NoteReport(OkReport("a", "n1", "198.51.100.9:29447", 20), 20);
    mapped.NoteReport(OkReport("b", "n2", "198.51.100.9:29447", 21), 21);
    BOOST_CHECK_EQUAL(static_cast<int>(mapped.State()), static_cast<int>(ReachabilityState::PUBLIC_MAPPED));

    ReachabilityTracker epoch;
    epoch.NoteReport(OkReport("a", "n1", "203.0.113.8:29447", 30), 30);
    epoch.NoteReport(OkReport("b", "n2", "203.0.113.8:29447", 31), 31);
    BOOST_CHECK(epoch.MayAdvertiseHost(true));
    epoch.NoteEpoch(2, 40);
    BOOST_CHECK_EQUAL(static_cast<int>(epoch.State()), static_cast<int>(ReachabilityState::DEGRADED));
    BOOST_CHECK(!epoch.MayAdvertiseHost(true));

    ReachabilityTracker obs;
    AddressObservation evil;
    evil.observer_id = "evil";
    evil.observed = "10.0.0.1:8332";
    obs.NoteObservation(evil, 1);
    BOOST_CHECK(!obs.MayAdvertiseHost(true));
    BOOST_CHECK_NE(obs.BestCandidate(), "10.0.0.1:8332");

    ReachabilityTracker lost;
    lost.NoteReport(OkReport("a", "n1", "203.0.113.8:29447", 1), 1);
    lost.NoteReport(OkReport("b", "n2", "203.0.113.8:29447", 2), 2);
    lost.WithdrawHost();
    BOOST_CHECK(!lost.MayAdvertiseHost(true));
}

BOOST_AUTO_TEST_CASE(conn_reach_abuse_and_race)
{
    using namespace modelnet;
    ReachabilityTracker t;
    std::string err;
    BOOST_CHECK(t.ValidateProbeTarget("203.0.113.8:29447", err));
    BOOST_CHECK(!t.ValidateProbeTarget("10.0.0.1:29447", err));
    BOOST_CHECK(!t.ValidateProbeTarget("192.168.1.1:29447", err));
    BOOST_CHECK(!t.ValidateProbeTarget("203.0.113.8:8332", err));
    t.SetLocalTest(true);
    BOOST_CHECK(t.ValidateProbeTarget("10.0.0.1:29447", err));

    DialbackRequest req;
    req.request_id = "id1";
    req.candidate = "203.0.113.8:29447";
    req.requester = "peer-a";
    req.requester_netgroup = "ng";
    req.now_ms = 1000;
    for (int i = 0; i < 5; ++i) {
        req.request_id = "id-" + std::to_string(i);
        req.now_ms = 1000 + i;
        if (i < 4) BOOST_CHECK(t.AdmitProbe(req, err));
        else BOOST_CHECK(!t.AdmitProbe(req, err));
        t.FinishProbe();
    }
    BOOST_CHECK_EQUAL(RaceBounded({"a", "b", "c", "d"}, 3).size(), 3);
    BOOST_CHECK(ConnectionFullyReady(true, true, true));
    BOOST_CHECK(!ConnectionFullyReady(true, true, false));
    BOOST_CHECK(!ConnectionFullyReady(true, false, true));
    BOOST_CHECK(IsRoutingServer(ReachabilityState::PUBLIC_DIRECT));
    BOOST_CHECK(!IsRoutingServer(ReachabilityState::PRIVATE));
    BOOST_CHECK(!IsRoutingServer(ReachabilityState::RELAY_REACHABLE));
}

BOOST_AUTO_TEST_CASE(conn_nat_01_to_09)
{
    using namespace modelnet;
    BOOST_CHECK(!MappingWouldExposeControlPlane(DEFAULT_MODEL_PORT));
    BOOST_CHECK(MappingWouldExposeControlPlane(8332));
    BOOST_CHECK(MappingWouldExposeControlPlane(18443));
    BOOST_CHECK(IsForbiddenControlPort(18766));
    std::string err;
    BOOST_CHECK(IsForbiddenControlEndpoint("1.2.3.4:8332", err));
    BOOST_CHECK(IsForbiddenControlEndpoint("1.2.3.4:18443", err));
    BOOST_CHECK(IsForbiddenControlEndpoint("1.2.3.4:8334", err));

    ModelMapResult loop = AttemptModelPortMap("127.0.0.1:29447", true);
    BOOST_CHECK_EQUAL(static_cast<int>(loop.status), static_cast<int>(ModelNatStatus::LOOPBACK));

    ModelMapResult ctrl = AttemptModelPortMap("0.0.0.0:8332", true);
    BOOST_CHECK_NE(static_cast<int>(ctrl.status), static_cast<int>(ModelNatStatus::MAPPED));
    BOOST_CHECK(!ctrl.error.empty());

    ModelMapResult off = AttemptModelPortMap("0.0.0.0:29447", false);
    BOOST_CHECK_EQUAL(static_cast<int>(off.status), static_cast<int>(ModelNatStatus::DISABLED));

    ModelMapResult failsoft = AttemptModelPortMap("203.0.113.8:29447", true);
    BOOST_CHECK(failsoft.status == ModelNatStatus::UNMAPPED || failsoft.status == ModelNatStatus::MAPPED);
    ReleaseModelPortMap(failsoft);
    BOOST_CHECK(!failsoft.owned_mapping);

    BOOST_CHECK(MappingRenewalDue(3600 * 1000, 0, MODEL_MAP_LIFETIME_MS));
    BOOST_CHECK(!MappingRenewalDue(1000, 0, MODEL_MAP_LIFETIME_MS));

    ReachabilityTracker t;
    t.SetMapped("198.51.100.9:29447");
    BOOST_CHECK(!t.MayAdvertiseHost(true));
}

BOOST_AUTO_TEST_CASE(conn_rly_01_to_10)
{
    using namespace modelnet;
    RelayTable tab;
    RelayReservation a, b;
    std::string err;
    BOOST_CHECK(tab.Reserve("svc-a", "ng1", "203.0.113.1:29447", 1000, a, err));
    BOOST_CHECK(tab.Has(a.reservation_id));
    BOOST_CHECK(tab.Reserve("svc-a", "ng1", "203.0.113.2:29447", 1001, b, err));
    BOOST_CHECK_EQUAL(tab.Size(), 2);
    RelayReservation c;
    BOOST_CHECK(!tab.Reserve("svc-a", "ng1", "203.0.113.3:29447", 1002, c, err));

    RelayTable ttl;
    RelayLimits lim;
    lim.ttl_ms = 50;
    ttl = RelayTable(lim);
    RelayReservation r;
    BOOST_CHECK(ttl.Reserve("svc", "ng", "203.0.113.1:29447", 0, r, err));
    ttl.Expire(51);
    BOOST_CHECK(!ttl.Has(r.reservation_id));
    BOOST_CHECK(!ttl.AllowForward(r.reservation_id, 1, 51, err));

    RelayTable bytes;
    RelayLimits bl;
    bl.byte_ceiling = 100;
    bytes = RelayTable(bl);
    RelayReservation rb;
    BOOST_CHECK(bytes.Reserve("svc", "ng", "203.0.113.1:29447", 0, rb, err));
    BOOST_CHECK(bytes.AllowForward(rb.reservation_id, 80, 1, err));
    bytes.CloseConn(rb.reservation_id);
    BOOST_CHECK(!bytes.AllowForward(rb.reservation_id, 30, 2, err));

    RelayTable conns;
    RelayLimits cl;
    cl.conn_ceiling = 2;
    conns = RelayTable(cl);
    RelayReservation rc;
    BOOST_CHECK(conns.Reserve("svc", "ng", "203.0.113.1:29447", 0, rc, err));
    BOOST_CHECK(conns.AllowForward(rc.reservation_id, 1, 1, err));
    BOOST_CHECK(conns.AllowForward(rc.reservation_id, 1, 2, err));
    BOOST_CHECK(!conns.AllowForward(rc.reservation_id, 1, 3, err));

    RelayTable idle;
    RelayLimits il;
    il.idle_ms = 10;
    idle = RelayTable(il);
    RelayReservation ri;
    BOOST_CHECK(idle.Reserve("svc", "ng", "203.0.113.1:29447", 0, ri, err));
    idle.Expire(11);
    BOOST_CHECK(!idle.Has(ri.reservation_id));

    BOOST_CHECK(PunchIdentityIndependentOfRelay());
    RelayConnectRequest rr;
    rr.endpoint = "203.0.113.1:29447";
    rr.expected_service_id = "aa";
    rr.presented_service_id = "bb";
    BOOST_CHECK(!ValidateRelayConnect(rr, true, err));
    BOOST_CHECK_EQUAL(tab.Alternate("203.0.113.1:29447", "svc-a"), "203.0.113.2:29447");
    BOOST_CHECK_EQUAL(tab.StatusJson()["automatic_spend_atoms"].getInt<int>(), 0);

    RelayReservation priv;
    BOOST_CHECK(!tab.Reserve("svc", "ng", "10.0.0.1:29447", 0, priv, err));
}

BOOST_AUTO_TEST_CASE(conn_hp_01_to_10)
{
    using namespace modelnet;
    PunchPlan plan;
    std::string err;
    BOOST_CHECK(PlanHolePunch({"203.0.113.8:29447"}, {"198.51.100.9:29447"}, 1000, 40, plan, err));
    BOOST_CHECK_GT(plan.attempt_at_ms, 1000);
    BOOST_CHECK_EQUAL(static_cast<int>(RecordPunchAttempt(plan, true, true, true, false)),
                      static_cast<int>(PunchResult::DIRECT_OK));
    BOOST_CHECK(ConnectionFullyReady(true, true, true));
    BOOST_CHECK(!ConnectionFullyReady(true, false, true));

    PunchPlan fail;
    BOOST_CHECK(PlanHolePunch({"a:1"}, {"b:1"}, 0, 10, fail, err));
    BOOST_CHECK_EQUAL(static_cast<int>(RecordPunchAttempt(fail, true, true, false, false)),
                      static_cast<int>(PunchResult::RETRY_LATER));
    BOOST_CHECK_EQUAL(static_cast<int>(RecordPunchAttempt(fail, false, false, false, false)),
                      static_cast<int>(PunchResult::RETRY_LATER));
    BOOST_CHECK_EQUAL(static_cast<int>(RecordPunchAttempt(fail, false, false, false, false)),
                      static_cast<int>(PunchResult::RETAIN_RELAY));
    BOOST_CHECK_EQUAL(static_cast<int>(RecordPunchAttempt(fail, false, false, false, true)),
                      static_cast<int>(PunchResult::RETRY_LATER));
    BOOST_CHECK(PunchIdentityIndependentOfRelay());
}

BOOST_AUTO_TEST_CASE(conn_route_01_to_12)
{
    using namespace modelnet;
    std::vector<unsigned char> pk, sk;
    Digest48 resource;
    resource.data[0] = 0x11;
    std::string err;
    auto rec = SignedRecord(resource, 2, 10'000, "203.0.113.8:29447", true, pk, sk);
    BOOST_CHECK(VerifyProviderRecord(rec, 1, err));
    ProviderCache cache;
    BOOST_CHECK(cache.Put(rec, 1, err));

    ProviderRecord forged = rec;
    if (!forged.sig.empty()) forged.sig[0] ^= 0xff;
    BOOST_CHECK(!VerifyProviderRecord(forged, 1, err));

    ProviderRecord expired = rec;
    BOOST_CHECK(!VerifyProviderRecord(expired, 20'000, err));

    ProviderRecord older = rec;
    older.seq = 1;
    BOOST_CHECK(SignProviderRecord(older, Span<const unsigned char>{sk.data(), sk.size()}, err));
    BOOST_CHECK(!cache.Put(older, 2, err));

    RoutingTable table;
    LookupBudget budget;
    budget.start_ms = 1;
    std::vector<ProviderRecord> found;
    BOOST_CHECK(LookupStep(table, cache, resource, budget, 3, found, err));
    BOOST_CHECK_EQUAL(found.size(), 1);
    BOOST_CHECK_EQUAL(budget.queries, 0);

    LookupBudget explode;
    explode.max_queries = 4;
    explode.start_ms = 0;
    Digest48 missing;
    missing.data[1] = 0x22;
    ProviderCache empty;
    for (int i = 0; i < 8; ++i) {
        std::vector<ProviderRecord> f;
        const bool ok = LookupStep(table, empty, missing, explode, 10, f, err);
        BOOST_CHECK(!ok);
        if (explode.queries >= explode.max_queries) break;
    }
    BOOST_CHECK_LE(explode.queries, explode.max_queries);

    RoutingTable ng;
    Digest48 self;
    ng.SetSelf(self);
    int accepted = 0;
    for (int i = 0; i < 8; ++i) {
        RouteContact c;
        c.id.data[0] = 0x80;
        c.id.data[47] = static_cast<unsigned char>(i + 1);
        c.endpoint = "203.0.113." + std::to_string(i + 1) + ":29447";
        c.netgroup = "same-asn";
        c.last_ok_ms = 1;
        std::string e;
        if (ng.Insert(c, e)) ++accepted;
    }
    BOOST_CHECK_LE(accepted, ROUTE_NETGROUP_CAP);

    cache.Expire(20'000);
    BOOST_CHECK(cache.Get(resource, 20'000).empty());

    PieceRange too_many;
    ProviderRecord fat = rec;
    fat.ranges.assign(PROVIDER_MAX_RANGES + 1, too_many);
    BOOST_CHECK(!VerifyProviderRecord(fat, 1, err));
    BOOST_CHECK(LivePieceRangesRequireDirectQuery());
    BOOST_CHECK(!RoutingTouchesAddrMan());
    BOOST_CHECK(AcceptProviderRecordType("btx-provider-v1"));
    BOOST_CHECK(!AcceptProviderRecordType("ipfs-cid"));
    UniValue bad(UniValue::VOBJ);
    bad.pushKV("type", "generic-put");
    ProviderRecord parsed;
    BOOST_CHECK(!ProviderRecordFromJson(bad, parsed, err));
    BOOST_CHECK(RoutingServerRole(true));
    BOOST_CHECK(!RoutingServerRole(false));
}

BOOST_AUTO_TEST_CASE(conn_boot_01_to_07)
{
    using namespace modelnet;
    RoutingTable table;
    Digest48 self;
    self.data[0] = 0x01;
    table.SetSelf(self);
    RouteContact boot_a;
    boot_a.id.data[1] = 0x0a;
    boot_a.endpoint = "203.0.113.1:29447";
    boot_a.netgroup = "b1";
    boot_a.bootstrap = true;
    boot_a.last_ok_ms = 5;
    RouteContact boot_b = boot_a;
    boot_b.id.data[1] = 0x0b;
    boot_b.endpoint = "203.0.113.2:29447";
    boot_b.netgroup = "b2";
    RouteContact peer;
    peer.id.data[1] = 0x0c;
    peer.endpoint = "203.0.113.3:29447";
    peer.netgroup = "c";
    peer.last_ok_ms = 5;
    std::string err;
    BOOST_CHECK(table.Insert(boot_a, err));
    BOOST_CHECK(table.Insert(boot_b, err));
    BOOST_CHECK(table.Insert(peer, err));
    BOOST_CHECK_EQUAL(table.Size(), 3);
    table.Drop(boot_a.id);
    table.Drop(boot_b.id);
    BOOST_CHECK(BootstrapIndependent(true, table.Size()));

    std::vector<unsigned char> pk, sk;
    Digest48 resource;
    resource.data[2] = 0x33;
    auto rec = SignedRecord(resource, 1, 50'000, "203.0.113.3:29447", true, pk, sk);
    ProviderCache cache;
    BOOST_CHECK(cache.Put(rec, 10, err));
    LookupBudget budget;
    budget.start_ms = 10;
    std::vector<ProviderRecord> found;
    BOOST_CHECK(LookupStep(table, cache, resource, budget, 11, found, err));

    RoutingTable restarted;
    restarted.SetSelf(self);
    LoadPersistedContacts(restarted, table.PersistSubset(), 12, 60'000);
    BOOST_CHECK_GE(restarted.Size(), 1);

    RouteContact stale;
    stale.id.data[1] = 0x99;
    stale.endpoint = "203.0.113.9:29447";
    stale.netgroup = "stale";
    stale.last_ok_ms = 1;
    RoutingTable fresh;
    LoadPersistedContacts(fresh, {stale}, 90LL * 24 * 60 * 60 * 1000, 60'000);
    BOOST_CHECK_EQUAL(fresh.Size(), 0);
    BOOST_CHECK(StaleCacheIsNotAuthority());
}

BOOST_AUTO_TEST_CASE(conn_roam_01_to_09)
{
    using namespace modelnet;
    NetworkEpoch ep;
    ep.NoticeAddressChange("192.0.2.1", "2001:db8::1");
    const uint64_t e1 = ep.epoch;
    ep.NoticeAddressChange("192.0.2.1", "2001:db8::1");
    BOOST_CHECK_EQUAL(ep.epoch, e1);
    ep.NoticeAddressChange("192.0.2.2", "2001:db8::1");
    BOOST_CHECK_GT(ep.epoch, e1);
    ep.NoticeAddressChange("192.0.2.2", "2001:db8::2");
    BOOST_CHECK_GT(ep.epoch, e1 + 1);
    ep.Sleep();
    BOOST_CHECK(ep.asleep);
    const uint64_t before_wake = ep.epoch;
    ep.Wake();
    BOOST_CHECK(!ep.asleep);
    BOOST_CHECK_GT(ep.epoch, before_wake);

    ReachabilityTracker t;
    t.NoteReport(OkReport("a", "n1", "203.0.113.8:29447", 1), 1);
    t.NoteReport(OkReport("b", "n2", "203.0.113.8:29447", 2), 2);
    t.SetRelay("203.0.113.7:29447");
    t.NoteEpoch(ep.epoch, 100);
    BOOST_CHECK_EQUAL(static_cast<int>(t.State()), static_cast<int>(ReachabilityState::DEGRADED));

    RelayTable tab;
    RelayLimits lim;
    lim.ttl_ms = 10;
    tab = RelayTable(lim);
    RelayReservation r;
    std::string err;
    BOOST_CHECK(tab.Reserve("svc", "ng", "203.0.113.7:29447", 0, r, err));
    tab.Expire(11);
    BOOST_CHECK(!tab.Has(r.reservation_id));
}

BOOST_AUTO_TEST_CASE(conn_http_endpoints_and_rpc_fields)
{
    using namespace modelnet;
    const fs::path tmp = m_path_root / "conn-http";
    fs::create_directories(tmp);
    ModelCatalog cat{tmp, 1 << 20};
    NativeRequest req;
    NativeResponse resp;
    req.method = "POST";
    req.path = std::string(MODEL_HTTP_ROOT) + "ext/autonat/probe";
    req.body = "{\"request_id\":\"abc\",\"candidate\":\"10.0.0.1:29447\",\"requester\":\"p\",\"requester_netgroup\":\"n\"}";
    BOOST_CHECK(HandleNativeRequest(cat, req, resp));
    BOOST_CHECK_GE(resp.status, 400);

    req.path = std::string(MODEL_HTTP_ROOT) + "ext/autonat/probe";
    req.body = "{\"request_id\":\"abc2\",\"candidate\":\"203.0.113.8:29447\",\"requester\":\"p2\",\"requester_netgroup\":\"n2\"}";
    BOOST_CHECK(HandleNativeRequest(cat, req, resp));
    BOOST_CHECK_EQUAL(resp.status, 200);

    req.path = std::string(MODEL_HTTP_ROOT) + "ext/relay/reserve";
    req.body = "{\"service_id\":\"svc\",\"netgroup\":\"ng\",\"relay_endpoint\":\"203.0.113.1:29447\"}";
    BOOST_CHECK(HandleNativeRequest(cat, req, resp));
    BOOST_CHECK_EQUAL(resp.status, 403);

    req.path = std::string(MODEL_HTTP_ROOT) + "ext/holepunch";
    req.body = "{\"local\":[\"203.0.113.8:29447\"],\"remote\":[\"198.51.100.9:29447\"],\"rtt_ms\":20,\"direct\":false,\"pq1\":false,\"identity\":false}";
    BOOST_CHECK(HandleNativeRequest(cat, req, resp));
    BOOST_CHECK_EQUAL(resp.status, 200);

    UniValue rpc(UniValue::VOBJ);
    rpc.pushKV("method", "getmodelnetworkinfo");
    rpc.pushKV("params", UniValue(UniValue::VARR));
    UniValue result;
    std::string code, e;
    BOOST_CHECK(DispatchHelperRpc(cat, rpc, result, code, e, nullptr));
    BOOST_CHECK(result.exists("reachability_state"));
    BOOST_CHECK(result.exists("bootstrap_dependency"));
    BOOST_CHECK(result.exists("routing_table_size"));
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_CHECK_EQUAL(result["transport"].get_str(), "pq1");
    BOOST_CHECK(result.exists("quic") && result["quic"].isBool() && !result["quic"].get_bool());
    BOOST_CHECK(result.exists("classical_fallback") && result["classical_fallback"].isBool() &&
                !result["classical_fallback"].get_bool());
}

BOOST_AUTO_TEST_CASE(conn_quic_deferred_pq1_only)
{
    using namespace modelnet;
    BOOST_CHECK(ConnectionFullyReady(true, true, true));
    BOOST_CHECK(!ConnectionFullyReady(true, false, true));
    BOOST_CHECK(!ConnectionFullyReady(true, true, false));
    BOOST_CHECK(!ConnectionFullyReady(false, true, true));
    const fs::path tmp = m_path_root / "conn-quic";
    fs::create_directories(tmp);
    ModelCatalog cat{tmp, 1 << 20};
    UniValue rpc(UniValue::VOBJ);
    rpc.pushKV("method", "getmodelnetworkinfo");
    rpc.pushKV("params", UniValue(UniValue::VARR));
    UniValue result;
    std::string code, e;
    BOOST_CHECK(DispatchHelperRpc(cat, rpc, result, code, e, nullptr));
    BOOST_CHECK_EQUAL(result["transport"].get_str(), "pq1");
    BOOST_CHECK(!result["quic"].get_bool());
    BOOST_CHECK(!result["classical_fallback"].get_bool());
}

BOOST_AUTO_TEST_SUITE_END()
