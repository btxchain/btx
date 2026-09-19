// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// R4 (search / discovery) regressions. Deliberately self-contained: it must
// keep failing if modelnet_convergence_tests.cpp is deleted, retargeted, or
// its routing case is weakened.
//
// Pins, in order:
//   1. RoutingBucketIndex is the leading XOR *bit*, never the first differing
//      byte, over the whole 384-bit keyspace. A byte-based implementation
//      collapses to 48 distinct buckets and fails here.
//   2. ROUTE_BUCKETS == Digest48::SIZE * 8 == 384, and RoutingTable really
//      keeps that many buckets.
//   3. Dynamic query planning: early-stop at the useful target, expand below
//      it, an all-ones ("every peer claims a match") summary set cannot widen
//      fanout past QUERY_PROBE_MAX, and a peer whose summary is stale or
//      unknown still gets probed.
//   4. Delegated routers A/B: an independent contact is reserved only when it
//      is genuinely outside the preferred set.
//   5. LAN classification grants no authority: the browser edge refuses wallet
//      paths and mutating methods no matter where the request came from.

#include <modelnet/http_bridge.h>
#include <modelnet/lan_discovery.h>
#include <modelnet/provider_route.h>
#include <modelnet/query_router.h>
#include <modelnet/router.h>
#include <modelnet/search.h>
#include <modelnet/types.h>
#include <test/util/setup_common.h>
#include <univalue.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <set>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_r4_route_tests, BasicTestingSetup)

namespace {

//! Flip exactly one bit, counting from the MSB of byte 0.
modelnet::Digest48 FlipBit(const modelnet::Digest48& base, size_t bit)
{
    modelnet::Digest48 out = base;
    out.data[bit / 8] ^= static_cast<unsigned char>(0x80 >> (bit % 8));
    return out;
}

modelnet::QueryPeerHint LikelyPeer(int i)
{
    modelnet::QueryPeerHint p;
    p.endpoint = "203.0.113." + std::to_string(i) + ":29447";
    p.netgroup = "ng-likely-" + std::to_string(i);
    p.summary_likely = true;
    p.summary_unknown = false;
    // A hostile peer would also advertise huge throughput. It must not matter.
    p.throughput_bps = 1e12;
    return p;
}

modelnet::QueryPeerHint UnknownPeer(int i)
{
    modelnet::QueryPeerHint p;
    p.endpoint = "198.51.100." + std::to_string(i) + ":29447";
    p.netgroup = "ng-unknown-" + std::to_string(i);
    p.summary_likely = false;
    p.summary_unknown = true;
    return p;
}

} // namespace

BOOST_AUTO_TEST_CASE(r4_bucket_index_is_leading_xor_bit_over_384_bits)
{
    using namespace modelnet;

    BOOST_CHECK_EQUAL(ROUTE_BUCKETS, Digest48::SIZE * 8);
    BOOST_CHECK_EQUAL(ROUTE_BUCKETS, size_t{384});

    const Digest48 self{};

    // Every single-bit difference must map to its own bucket. A first-differing
    // *byte* implementation returns bit/8 here and yields only 48 values.
    std::set<int> seen;
    for (size_t bit = 0; bit < ROUTE_BUCKETS; ++bit) {
        const int idx = RoutingBucketIndex(self, FlipBit(self, bit));
        BOOST_REQUIRE_EQUAL(idx, static_cast<int>(bit));
        seen.insert(idx);
    }
    BOOST_CHECK_EQUAL(seen.size(), ROUTE_BUCKETS);

    // Spot checks that are unambiguous about bit vs byte.
    BOOST_CHECK_EQUAL(RoutingBucketIndex(self, FlipBit(self, 0)), 0);   // byte 0, MSB
    BOOST_CHECK_EQUAL(RoutingBucketIndex(self, FlipBit(self, 7)), 7);   // byte 0, LSB
    BOOST_CHECK_EQUAL(RoutingBucketIndex(self, FlipBit(self, 43)), 43); // byte 5, bit 3
    BOOST_CHECK_EQUAL(RoutingBucketIndex(self, FlipBit(self, 383)), 383);

    // Only the *leading* difference selects the bucket; trailing bits are noise.
    Digest48 noisy = FlipBit(self, 43);
    noisy = FlipBit(noisy, 100);
    noisy = FlipBit(noisy, 383);
    BOOST_CHECK_EQUAL(RoutingBucketIndex(self, noisy), 43);

    // Symmetric in its arguments, like the XOR metric it is derived from.
    BOOST_CHECK_EQUAL(RoutingBucketIndex(FlipBit(self, 43), self), 43);
}

BOOST_AUTO_TEST_CASE(r4_routing_table_has_384_buckets_and_no_byte_collisions)
{
    using namespace modelnet;

    const Digest48 self{};
    RoutingTable table;
    table.SetSelf(self);

    // One peer per single-bit distance. With bit buckets each lands alone, so
    // none of the 384 inserts may hit the k=8 bucket cap.
    for (size_t bit = 0; bit < ROUTE_BUCKETS; ++bit) {
        RouteContact c;
        c.id = FlipBit(self, bit);
        c.endpoint = "192.0.2.1:" + std::to_string(10000 + bit);
        c.netgroup = "ng-" + std::to_string(bit);
        c.last_ok_ms = 1'000;
        std::string err;
        BOOST_REQUIRE_MESSAGE(table.Insert(c, err), "bit " + std::to_string(bit) + ": " + err);
    }
    BOOST_CHECK_EQUAL(table.Size(), ROUTE_BUCKETS);

    const UniValue st = table.StatusJson();
    BOOST_CHECK_EQUAL(st["buckets"].getInt<int>(), static_cast<int>(ROUTE_BUCKETS));
    BOOST_CHECK_EQUAL(st["size"].getInt<int>(), static_cast<int>(ROUTE_BUCKETS));
    // Discovery routing is never monetary AddrMan.
    BOOST_CHECK(!st["addrman"].get_bool());
    BOOST_CHECK(!RoutingTouchesAddrMan());

    // Closest() must order by the XOR metric, so an exact id wins.
    const Digest48 target = FlipBit(self, 43);
    const auto closest = table.Closest(target, 1);
    BOOST_REQUIRE_EQUAL(closest.size(), 1U);
    BOOST_CHECK(closest.front().id == target);

    // Persisted contacts stay bounded and cache is never an authority.
    BOOST_CHECK_LE(table.PersistSubset().size(), 32U);
    BOOST_CHECK(StaleCacheIsNotAuthority());
}

BOOST_AUTO_TEST_CASE(r4_query_summary_never_dumps_catalog)
{
    using namespace modelnet;

    QueryRouter qr;
    BOOST_CHECK_EQUAL(qr.SampleCap(), QUERY_SAMPLE_MAX);

    std::vector<std::string> ids;
    for (int i = 0; i < 500; ++i) ids.push_back("model-" + std::to_string(i));
    const QuerySummary sum = qr.SummarizeIds(ids);
    BOOST_CHECK_EQUAL(sum.hit_count, 500U);
    BOOST_CHECK_EQUAL(sum.sample_ids.size(), QUERY_SAMPLE_MAX);
    BOOST_CHECK_EQUAL(sum.truncated, 500U - static_cast<uint32_t>(QUERY_SAMPLE_MAX));

    // An oversized budget cannot raise the cap.
    QueryBudget greedy;
    greedy.max_sample = 100'000;
    QueryRouter fat{greedy};
    BOOST_CHECK_EQUAL(fat.SampleCap(), QUERY_SAMPLE_MAX);
    BOOST_CHECK_EQUAL(fat.SummarizeIds(ids).sample_ids.size(), QUERY_SAMPLE_MAX);
}

BOOST_AUTO_TEST_CASE(r4_all_ones_summary_cannot_widen_fanout)
{
    using namespace modelnet;

    QueryRouter qr;
    std::vector<QueryPeerHint> peers;
    for (int i = 0; i < 200; ++i) peers.push_back(LikelyPeer(i));

    SearchQuery q; // default scope is NETWORK
    const auto plan = qr.Plan(q, peers, /*unique_useful=*/0);

    BOOST_CHECK(!plan.local_only);
    BOOST_CHECK(plan.expand);
    // Every peer claimed a match. Fanout is still the probe cap, not 200.
    BOOST_CHECK(plan.all_match_capped);
    const size_t fanout = plan.probe_peers.size() + plan.exploration_peers.size();
    BOOST_CHECK_EQUAL(fanout, static_cast<size_t>(QUERY_PROBE_MAX));
    BOOST_CHECK_LE(fanout, static_cast<size_t>(QUERY_PROBE_MAX));
    BOOST_CHECK_LE(plan.remaining_tasks, QUERY_CUMULATIVE_TASKS_MAX);

    // No duplicate endpoint may consume two slots.
    std::set<std::string> uniq(plan.probe_peers.begin(), plan.probe_peers.end());
    uniq.insert(plan.exploration_peers.begin(), plan.exploration_peers.end());
    BOOST_CHECK_EQUAL(uniq.size(), fanout);

    // Advertised throughput is not ranking or monetary authority.
    BOOST_CHECK(!ProviderThroughputIsRankingAuthority());
    BOOST_CHECK_EQUAL(QueryPeerPreference(LikelyPeer(0)), 0);

    // The cumulative cap, when the caller reports its remote tasks, closes the
    // plan rather than starting a fresh round of eight.
    qr.NoteRemoteTasks(QUERY_CUMULATIVE_TASKS_MAX);
    const auto spent = qr.Plan(q, peers, /*unique_useful=*/0);
    BOOST_CHECK_EQUAL(spent.remaining_tasks, 0);
    BOOST_CHECK(spent.probe_peers.empty());
    BOOST_CHECK(spent.exploration_peers.empty());
}

BOOST_AUTO_TEST_CASE(r4_dynamic_query_early_stop_and_expand)
{
    using namespace modelnet;

    QueryRouter qr;
    std::vector<QueryPeerHint> peers;
    for (int i = 0; i < 12; ++i) peers.push_back(LikelyPeer(i));

    SearchQuery q;

    // Enough unique useful results: stop, do not open more remote tasks.
    const auto stop = qr.Plan(q, peers, QUERY_USEFUL_TARGET_DEFAULT);
    BOOST_CHECK(!stop.expand);
    BOOST_CHECK(stop.probe_peers.empty());
    BOOST_CHECK(stop.exploration_peers.empty());

    // One short of the target: expand, still bounded.
    const auto go = qr.Plan(q, peers, QUERY_USEFUL_TARGET_DEFAULT - 1);
    BOOST_CHECK(go.expand);
    BOOST_CHECK(!go.probe_peers.empty());
    BOOST_CHECK_LE(go.probe_peers.size() + go.exploration_peers.size(),
                   static_cast<size_t>(QUERY_PROBE_MAX));

    // scope=LOCAL keeps the query on this node whatever the peers claim.
    SearchQuery local = q;
    local.scope = SearchScope::LOCAL;
    const auto only_local = qr.Plan(local, peers, 0);
    BOOST_CHECK(only_local.local_only);
    BOOST_CHECK(only_local.probe_peers.empty());
    BOOST_CHECK(only_local.exploration_peers.empty());

    // Cancellation is honoured by both planning and forwarding.
    BOOST_CHECK(qr.ShouldForward(SEARCH_TTL_DEFAULT, 1));
    qr.Cancel();
    BOOST_CHECK(qr.Cancelled());
    BOOST_CHECK(qr.Plan(q, peers, 0).local_only);
    BOOST_CHECK(!qr.ShouldForward(SEARCH_TTL_DEFAULT, 1));
}

BOOST_AUTO_TEST_CASE(r4_stale_or_unknown_summary_still_gets_probed)
{
    using namespace modelnet;

    QueryRouter qr;
    SearchQuery q;

    // No usable summary anywhere: a stale/absent summary must not silence the
    // query. Every slot becomes exploration.
    std::vector<QueryPeerHint> blind;
    for (int i = 0; i < 3; ++i) blind.push_back(UnknownPeer(i));
    const auto dark = qr.Plan(q, blind, 0);
    BOOST_CHECK(dark.expand);
    BOOST_CHECK(dark.probe_peers.empty());
    BOOST_CHECK_EQUAL(dark.exploration_peers.size(), 3U);
    BOOST_CHECK(!dark.all_match_capped);

    // Mixed: peers with a positive summary must not crowd out exploration
    // entirely, otherwise a stale positive summary pins the query forever.
    std::vector<QueryPeerHint> mixed;
    for (int i = 0; i < 16; ++i) mixed.push_back(LikelyPeer(i));
    for (int i = 0; i < 4; ++i) mixed.push_back(UnknownPeer(i));
    const auto plan = qr.Plan(q, mixed, 0);
    BOOST_CHECK(plan.expand);
    BOOST_CHECK(!plan.exploration_peers.empty());
    BOOST_CHECK(!plan.probe_peers.empty());
    BOOST_CHECK_EQUAL(plan.probe_peers.size() + plan.exploration_peers.size(),
                      static_cast<size_t>(QUERY_PROBE_MAX));

    // A saturated peer sorts behind an unknown one, which sorts behind a
    // positive summary. Saturation is never a reason to exceed the cap.
    QueryPeerHint sat = LikelyPeer(99);
    sat.saturated = true;
    BOOST_CHECK_EQUAL(QueryPeerPreference(sat), 2);
    BOOST_CHECK_EQUAL(QueryPeerPreference(UnknownPeer(0)), 1);
}

BOOST_AUTO_TEST_CASE(r4_delegated_routers_reserve_a_genuinely_independent_slot)
{
    using namespace modelnet;

    // A/B: a router outside the preferred community is reserved and reachable.
    std::vector<std::string> preferred;
    for (int i = 0; i < 4; ++i) preferred.push_back("203.0.113." + std::to_string(i) + ":8443");
    ResolveQueryPlan ab;
    BOOST_REQUIRE(PlanRouterQueries(preferred, {"198.51.100.9:8443"}, ab));
    BOOST_CHECK(ab.reserved_independent);
    BOOST_CHECK_LE(ab.contacts.size(), static_cast<size_t>(MAX_ROUTER_CONTACTS));
    BOOST_CHECK_LE(ab.max_concurrent, MAX_CONCURRENT_RESOLVE_QUERIES);
    bool saw_independent = false;
    for (const auto& c : ab.contacts) {
        if (c == "198.51.100.9:8443") saw_independent = true;
    }
    BOOST_CHECK(saw_independent);

    // Over-full preferred list: still eight contacts, four concurrent, and the
    // independent contact survives the trim.
    std::vector<std::string> many;
    for (int i = 0; i < 40; ++i) many.push_back("203.0.113." + std::to_string(i) + ":8443");
    ResolveQueryPlan trimmed;
    BOOST_REQUIRE(PlanRouterQueries(many, {"198.51.100.9:8443"}, trimmed));
    BOOST_CHECK_EQUAL(trimmed.contacts.size(), static_cast<size_t>(MAX_ROUTER_CONTACTS));
    BOOST_CHECK_EQUAL(trimmed.max_concurrent, MAX_CONCURRENT_RESOLVE_QUERIES);
    BOOST_CHECK(trimmed.reserved_independent);
    saw_independent = false;
    for (const auto& c : trimmed.contacts) {
        if (c == "198.51.100.9:8443") saw_independent = true;
    }
    BOOST_CHECK(saw_independent);

    // An "independent" contact drawn from the preferred set is not diversity.
    // This is the shape the live typed-resolve path passes (peers.back()), so
    // reserved_independent must stay false rather than claim a second lane.
    ResolveQueryPlan fake;
    BOOST_REQUIRE(PlanRouterQueries(preferred, {preferred.back()}, fake));
    BOOST_CHECK(!fake.reserved_independent);
    BOOST_CHECK_EQUAL(fake.contacts.size(), preferred.size());

    // A miss is never "the model does not exist", and the negative answer
    // expires within 60 seconds.
    NegativeResolveCache neg;
    Digest48 id{};
    id.data[0] = 0x11;
    BOOST_CHECK(!neg.HasIncomplete(1, id, 1'000));
    neg.RememberIncomplete(1, id, 1'000);
    BOOST_CHECK(neg.HasIncomplete(1, id, 1'000));
    BOOST_CHECK(neg.HasIncomplete(1, id, 1'000 + NEGATIVE_RESOLVE_TTL_S - 1));
    BOOST_CHECK(!neg.HasIncomplete(1, id, 1'000 + NEGATIVE_RESOLVE_TTL_S));
    // A different record kind is a different question.
    BOOST_CHECK(!neg.HasIncomplete(2, id, 1'000));
}

BOOST_AUTO_TEST_CASE(r4_lan_discovery_grants_no_wallet_authority)
{
    using namespace modelnet;

    // Classification only.
    BOOST_CHECK(EndpointLooksLan("192.168.1.5:29447"));
    BOOST_CHECK(EndpointLooksLan("10.1.2.3:29447"));
    BOOST_CHECK(EndpointLooksLan("172.16.0.1:29447"));
    BOOST_CHECK(EndpointLooksLan("172.31.255.254:29447"));
    BOOST_CHECK(EndpointLooksLan("peer.local:8443"));
    BOOST_CHECK(EndpointLooksLan("[fe80::1]:29447"));
    BOOST_CHECK(!EndpointLooksLan("172.32.0.1:29447"));
    BOOST_CHECK(!EndpointLooksLan("203.0.113.7:29447"));
    BOOST_CHECK(!EndpointLooksLan(""));

    // Preference is an ordering hint, not a privilege, and not symmetric.
    BOOST_CHECK(PreferLanPeer("10.0.0.5:29447", "203.0.113.9:29447"));
    BOOST_CHECK(!PreferLanPeer("203.0.113.9:29447", "10.0.0.5:29447"));
    BOOST_CHECK(!PreferLanPeer("10.0.0.5:29447", "192.168.0.9:29447"));

    // Being on the LAN is not consensus power and needs no public address.
    BOOST_CHECK(!DelegatedRoutingMutatesConsensus());
    BOOST_CHECK(!LanDiscoveryRequiresPublicAddress());

    // The browser edge a LAN client would reach serves no wallet surface.
    BrowserBridgeResponse out;
    BOOST_REQUIRE(HandleBridgeRequest("GET", "/wallet/balance", "", out));
    BOOST_CHECK_EQUAL(out.http_status, 403);
    BOOST_CHECK(!out.ok);

    BOOST_REQUIRE(HandleBridgeRequest("GET", "/api/v1/dumpprivkey", "", out));
    BOOST_CHECK_EQUAL(out.http_status, 403);

    BOOST_REQUIRE(HandleBridgeRequest(
        "POST", "/api/v1/", R"({"method":"sendtoaddress","params":[]})", out));
    BOOST_CHECK_EQUAL(out.http_status, 405);

    // Even a harmless-looking mutation is refused: read-only edge.
    BOOST_REQUIRE(HandleBridgeRequest("POST", "/health", "{}", out));
    BOOST_CHECK_EQUAL(out.http_status, 405);

    // And every served body discloses that there is no wallet behind it.
    BOOST_REQUIRE(HandleBridgeRequest("GET", "/health", "", out));
    BOOST_CHECK_EQUAL(out.http_status, 200);
    UniValue body;
    BOOST_REQUIRE(body.read(out.body));
    BOOST_REQUIRE(body.isObject());
    BOOST_CHECK(!body["wallet"].get_bool());
    BOOST_CHECK_EQUAL(body["bind_default"].get_str(), "127.0.0.1");
}

BOOST_AUTO_TEST_SUITE_END()
