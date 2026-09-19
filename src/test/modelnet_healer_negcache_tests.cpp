// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Two properties that no existing suite pins by value.
//
// 1. The swarm healer acquires an endangered *range*. `setmodelswarmhealer`
//    and EndangeredPieces are asserted against the exact piece indices they
//    return, not against the `whole_model: false` flag, which proves nothing
//    on its own. Pieces that enough independent sources already hold, pieces
//    that belong to another artifact, and pieces nobody advertises at all are
//    each excluded for a different reason.
//
// 2. The local negative cache behaves like RecentlyFailed: a timeout, a
//    DONT_HAVE answer and a refusal each suppress one peer for one piece or
//    one transfer; a newer *signed* availability record lifts a suppression
//    that a forged or replayed record cannot; and none of it ever leaves the
//    node as a global bad-peer verdict.

#include <bitcoin-build-config.h> // IWYU pragma: keep
#include <modelnet/catalog.h>
#include <modelnet/helper.h>
#include <test/modelnet_n02_idem.h>
#include <modelnet/identity.h>
#include <modelnet/piece_picker.h>
#include <modelnet/piece_ranges.h>
#include <modelnet/provider_route.h>
#include <modelnet/router.h>
#include <modelnet/transfer_session.h>
#include <modelnet/types.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_healer_negcache_tests, BasicTestingSetup)

namespace {

constexpr int64_t kBaseMs = 1'700'000'000'000;

modelnet::Digest48 ArtifactId(unsigned char tag)
{
    modelnet::Digest48 d{};
    d.data[0] = tag;
    d.data[47] = tag;
    return d;
}

UniValue RangeObj(uint32_t first, uint32_t count)
{
    UniValue r(UniValue::VOBJ);
    r.pushKV("first", static_cast<int64_t>(first));
    r.pushKV("count", static_cast<int64_t>(count));
    return r;
}

/** One availability entry in the shape ParseAvailabilitySources accepts. */
UniValue ModelEntry(const std::string& artifact_hex, uint32_t piece_count, const std::vector<UniValue>& ranges)
{
    UniValue rs(UniValue::VARR);
    for (const auto& r : ranges) rs.push_back(r);
    UniValue file(UniValue::VOBJ);
    file.pushKV("file_index", 0);
    file.pushKV("piece_count", static_cast<int64_t>(piece_count));
    file.pushKV("ranges", rs);
    UniValue files(UniValue::VARR);
    files.push_back(file);
    UniValue model(UniValue::VOBJ);
    model.pushKV("artifact_id", artifact_hex);
    model.pushKV("files", files);
    return model;
}

UniValue HealerCall(modelnet::ModelCatalog& cat, const UniValue& arg)
{
    UniValue params(UniValue::VARR);
    params.push_back(WithN02Idempotency("setmodelswarmhealer", arg));
    UniValue req(UniValue::VOBJ);
    req.pushKV("method", "setmodelswarmhealer");
    req.pushKV("params", params);
    UniValue result(UniValue::VOBJ);
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, req, result, code, err), err);
    return result;
}

std::vector<uint32_t> Indices(const UniValue& arr)
{
    std::vector<uint32_t> out;
    BOOST_REQUIRE(arr.isArray());
    for (const auto& v : arr.getValues()) out.push_back(v.getInt<uint32_t>());
    return out;
}

modelnet::SourceAvailability Seeder(const std::string& endpoint, const std::string& netgroup,
                                     uint32_t piece_count, const std::vector<modelnet::PieceRange>& ranges,
                                     int64_t last_update_ms = 0)
{
    modelnet::SourceAvailability s;
    s.peer.endpoint = endpoint;
    s.peer.netgroup = netgroup;
    s.file_index = 0;
    s.piece_count = piece_count;
    s.ranges = ranges;
    s.last_update_ms = last_update_ms;
    return s;
}

std::vector<modelnet::PieceRange> Run(uint32_t first, uint32_t count)
{
    modelnet::PieceRange r;
    r.first = first;
    r.count = count;
    return {r};
}

std::vector<uint32_t> Iota(uint32_t n)
{
    std::vector<uint32_t> v;
    v.reserve(n);
    for (uint32_t i = 0; i < n; ++i) v.push_back(i);
    return v;
}

modelnet::ProviderRecord SignedAvailability(const modelnet::Digest48& resource, const std::string& endpoint,
                                             uint64_t seq, int64_t expiry_ms,
                                             const std::vector<modelnet::PieceRange>& ranges,
                                             const std::vector<unsigned char>& pk,
                                             const std::vector<unsigned char>& sk)
{
    using namespace modelnet;
    ProviderRecord r;
    r.resource = resource;
    r.pubkey = pk;
    r.endpoints = {endpoint};
    r.reachability_kind = "direct";
    r.complete = false;
    r.ranges = ranges;
    r.seq = seq;
    r.expiry_ms = expiry_ms;
    std::string err;
    BOOST_REQUIRE_MESSAGE(SignProviderRecord(r, Span<const unsigned char>{sk.data(), sk.size()}, err), err);
    return r;
}

int AssignmentsTo(const std::vector<modelnet::PieceAssignment>& picks, const std::string& endpoint)
{
    int n = 0;
    for (const auto& a : picks) {
        if (a.endpoint == endpoint) ++n;
    }
    return n;
}

} // namespace

// The healer RPC parses the peer's advertised runs and returns only the pieces
// that run covers. Pieces 0-7, 12-39 and 42-63 are missing from the answer
// because no source advertises them (rarity 0: the healer cannot preserve what
// nobody holds), and 20-23 are missing because that run belongs to a different
// artifact_id than the one the caller asked about.
BOOST_AUTO_TEST_CASE(healer_endangered_answer_is_the_advertised_run_not_the_whole_model)
{
    using namespace modelnet;
    const fs::path tmp = m_path_root / "healer-run";
    ModelCatalog cat{tmp / "cat", 1 << 20};

    const Digest48 wanted = ArtifactId(0xa1);
    const Digest48 decoy = ArtifactId(0xb2);
    BOOST_REQUIRE(wanted != decoy);

    UniValue models(UniValue::VARR);
    models.push_back(ModelEntry(wanted.Hex(), 64, {RangeObj(8, 4), RangeObj(40, 2)}));
    models.push_back(ModelEntry(decoy.Hex(), 64, {RangeObj(20, 4)}));
    UniValue availability(UniValue::VOBJ);
    availability.pushKV("models", models);

    UniValue arg(UniValue::VOBJ);
    arg.pushKV("artifact_id", wanted.Hex());
    arg.pushKV("file_index", 0);
    arg.pushKV("piece_count", 64);
    arg.pushKV("endpoint", "203.0.113.7:29447");
    arg.pushKV("availability", availability);

    const UniValue result = HealerCall(cat, arg);
    const auto endangered = Indices(result["endangered"]);

    const std::vector<uint32_t> expect{8, 9, 10, 11, 40, 41};
    BOOST_CHECK_EQUAL_COLLECTIONS(endangered.begin(), endangered.end(), expect.begin(), expect.end());
    BOOST_CHECK_EQUAL(endangered.size(), 6U);
    BOOST_CHECK_LT(endangered.size(), 64U);

    const std::set<uint32_t> got(endangered.begin(), endangered.end());
    for (uint32_t p = 20; p < 24; ++p) BOOST_CHECK_EQUAL(got.count(p), 0U);

    // Listing a range is not repairing it: without shards the healer reports no
    // repair, and it never claims global n as sufficiency.
    BOOST_CHECK(result["healer"].get_bool());
    BOOST_CHECK(!result["whole_model"].get_bool());
    BOOST_CHECK(!result["repair_executed"].get_bool());
    BOOST_CHECK(!result["global_n_is_sufficiency"].get_bool());
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
}

// The RPC surface takes no local-residency input: helper_network02 calls
// EndangeredPieces with an empty have vector. A caller that passes its own
// have list gets the identical answer back, so the range is derived from
// advertised availability alone and the caller must subtract what it holds.
BOOST_AUTO_TEST_CASE(healer_rpc_range_ignores_a_caller_supplied_have_list)
{
    using namespace modelnet;
    const fs::path tmp = m_path_root / "healer-have";
    ModelCatalog cat{tmp / "cat", 1 << 20};

    const Digest48 wanted = ArtifactId(0xc3);
    UniValue models(UniValue::VARR);
    models.push_back(ModelEntry(wanted.Hex(), 16, {RangeObj(4, 3)}));
    UniValue availability(UniValue::VOBJ);
    availability.pushKV("models", models);

    UniValue arg(UniValue::VOBJ);
    arg.pushKV("artifact_id", wanted.Hex());
    arg.pushKV("piece_count", 16);
    arg.pushKV("endpoint", "203.0.113.8:29447");
    arg.pushKV("availability", availability);

    const auto plain = Indices(HealerCall(cat, arg)["endangered"]);
    const std::vector<uint32_t> expect{4, 5, 6};
    BOOST_CHECK_EQUAL_COLLECTIONS(plain.begin(), plain.end(), expect.begin(), expect.end());

    UniValue have(UniValue::VARR);
    have.push_back(4);
    have.push_back(5);
    UniValue with_have = arg;
    with_have.pushKV("have", have);
    with_have.pushKV("local_have", have);

    const auto again = Indices(HealerCall(cat, with_have)["endangered"]);
    BOOST_CHECK_EQUAL_COLLECTIONS(again.begin(), again.end(), plain.begin(), plain.end());
}

// Library level, where have is expressible. Rarity decides membership and
// ordering: sole-source pieces first, then two-source pieces. Pieces held by
// three independent sources are safe and pieces held by none are already gone;
// neither is queued.
BOOST_AUTO_TEST_CASE(healer_range_is_rarity_one_then_two_minus_what_is_resident)
{
    using namespace modelnet;
    const std::vector<SourceAvailability> srcs{
        Seeder("a:1", "ng-a", 8, Run(0, 6)),
        Seeder("b:1", "ng-b", 8, Run(2, 4)),
        Seeder("c:1", "ng-c", 8, Run(4, 2)),
    };
    PickConfig cfg;
    cfg.preserve_rare = true;

    BOOST_REQUIRE_EQUAL(PieceRarity(0, 1, srcs, {}, cfg), 1);
    BOOST_REQUIRE_EQUAL(PieceRarity(0, 3, srcs, {}, cfg), 2);
    BOOST_REQUIRE_EQUAL(PieceRarity(0, 4, srcs, {}, cfg), 3);
    BOOST_REQUIRE_EQUAL(PieceRarity(0, 6, srcs, {}, cfg), 0);

    const auto all = EndangeredPieces(0, 8, {}, srcs, {}, cfg);
    const std::vector<uint32_t> expect_all{0, 1, 2, 3};
    BOOST_CHECK_EQUAL_COLLECTIONS(all.begin(), all.end(), expect_all.begin(), expect_all.end());

    const auto partial = EndangeredPieces(0, 8, {1, 3}, srcs, {}, cfg);
    const std::vector<uint32_t> expect_partial{0, 2};
    BOOST_CHECK_EQUAL_COLLECTIONS(partial.begin(), partial.end(), expect_partial.begin(), expect_partial.end());
}

// A source this node has locally quarantined stops counting toward rarity, so
// pieces that looked safe behind three advertisers become endangered. The
// healer's range therefore widens from local transfer health, not from any
// peer's claim about another peer.
BOOST_AUTO_TEST_CASE(healer_range_widens_when_local_quarantine_drops_two_of_three_sources)
{
    using namespace modelnet;
    const std::vector<SourceAvailability> srcs{
        Seeder("a:1", "ng-a", 8, Run(0, 6)),
        Seeder("b:1", "ng-b", 8, Run(2, 4)),
        Seeder("c:1", "ng-c", 8, Run(4, 2)),
    };
    PickConfig cfg;
    cfg.preserve_rare = true;

    const auto before = EndangeredPieces(0, 8, {}, srcs, {}, cfg);
    const std::vector<uint32_t> expect_before{0, 1, 2, 3};
    BOOST_CHECK_EQUAL_COLLECTIONS(before.begin(), before.end(), expect_before.begin(), expect_before.end());

    std::map<std::string, PeerMetrics> metrics;
    metrics["b:1"].invalid_piece_count = 2;              // two bad pieces: local quarantine
    metrics["c:1"].state = PeerXferState::FAILED;        // refused / unusable for this transfer

    BOOST_CHECK_EQUAL(PieceRarity(0, 4, srcs, metrics, cfg), 1);
    const auto after = EndangeredPieces(0, 8, {}, srcs, metrics, cfg);
    const std::vector<uint32_t> expect_after{0, 1, 2, 3, 4, 5};
    BOOST_CHECK_EQUAL_COLLECTIONS(after.begin(), after.end(), expect_after.begin(), expect_after.end());
}

// DONT_HAVE is a per-(peer, piece) answer. When one peer drops a piece from its
// advertised runs the piece moves to the remaining peer; when the last peer
// drops it the piece simply has no source and the other seven stay scheduled;
// when any peer advertises it again the piece is schedulable immediately. A
// negative answer never becomes "this piece does not exist".
BOOST_AUTO_TEST_CASE(negcache_dont_have_narrows_one_peer_and_never_retires_the_piece)
{
    using namespace modelnet;
    const Digest48 artifact = ArtifactId(0xd4);
    const std::string ep_a = "198.51.100.10:29447";
    const std::string ep_b = "198.51.100.11:29447";

    auto parse = [&](const std::string& endpoint, const std::vector<UniValue>& ranges) {
        UniValue models(UniValue::VARR);
        models.push_back(ModelEntry(artifact.Hex(), 8, ranges));
        UniValue body(UniValue::VOBJ);
        body.pushKV("models", models);
        PeerId pid;
        pid.endpoint = endpoint;
        pid.netgroup = endpoint;
        std::vector<SourceAvailability> out;
        std::string err;
        BOOST_REQUIRE_MESSAGE(ParseAvailabilitySources(body, endpoint, pid, artifact, out, err, kBaseMs), err);
        BOOST_REQUIRE_EQUAL(out.size(), 1U);
        return out[0];
    };

    PickConfig cfg;
    cfg.now_ms = kBaseMs;
    cfg.max_assignments = 32;
    cfg.global_inflight_ceiling = uint64_t{128} * PIECE_SIZE;
    std::map<std::string, PeerMetrics> metrics;
    metrics[ep_a].throughput_bps = 1e9;
    metrics[ep_b].throughput_bps = 1e9;
    const auto missing = Iota(8);
    BOOST_REQUIRE(!EndgameActive(missing.size(), uint64_t{8} * PIECE_SIZE, cfg));

    std::vector<SourceAvailability> srcs{parse(ep_a, {RangeObj(0, 8)}), parse(ep_b, {RangeObj(0, 8)})};
    BOOST_REQUIRE_EQUAL(PieceRarity(0, 3, srcs, metrics, cfg), 2);

    // B answers DONT_HAVE for piece 3 by re-advertising without it.
    srcs[1] = parse(ep_b, {RangeObj(0, 3), RangeObj(4, 4)});
    BOOST_CHECK(!SourceHasPiece(srcs[1], 0, 3));
    BOOST_CHECK_EQUAL(PieceRarity(0, 3, srcs, metrics, cfg), 1);
    auto picks = PickRarestFirst(0, 8, missing, srcs, metrics, {}, {}, cfg);
    BOOST_CHECK_EQUAL(picks.size(), 8U);
    int served_3 = 0;
    for (const auto& a : picks) {
        if (a.piece_index != 3) continue;
        ++served_3;
        BOOST_CHECK_EQUAL(a.endpoint, ep_a);
    }
    BOOST_CHECK_EQUAL(served_3, 1);

    // A says DONT_HAVE too. Piece 3 has no source, and only piece 3 is affected.
    srcs[0] = parse(ep_a, {RangeObj(0, 3), RangeObj(4, 4)});
    BOOST_CHECK_EQUAL(PieceRarity(0, 3, srcs, metrics, cfg), 0);
    picks = PickRarestFirst(0, 8, missing, srcs, metrics, {}, {}, cfg);
    std::set<uint32_t> scheduled;
    for (const auto& a : picks) scheduled.insert(a.piece_index);
    BOOST_CHECK_EQUAL(scheduled.count(3), 0U);
    BOOST_CHECK_EQUAL(scheduled.size(), 7U);

    // The suppression is the answer, not a verdict: re-advertising restores it.
    srcs[1] = parse(ep_b, {RangeObj(0, 8)});
    BOOST_CHECK_EQUAL(PieceRarity(0, 3, srcs, metrics, cfg), 1);
    picks = PickRarestFirst(0, 8, {3}, srcs, metrics, {}, {}, cfg);
    BOOST_REQUIRE_EQUAL(picks.size(), 1U);
    BOOST_CHECK_EQUAL(picks[0].endpoint, ep_b);
}

// A timeout streak is recorded on the peer, releases its credit, and shrinks
// its window, but TransferSession never writes the classification back into
// PeerMetrics::state. Until a caller does, the timed-out peer keeps drawing
// ordinary work; once it does, the peer is skipped for every piece that has an
// alternative and is still used when it is the only source.
BOOST_AUTO_TEST_CASE(negcache_timeout_streak_suppresses_a_peer_only_once_classified)
{
    using namespace modelnet;
    const std::string ep_slow = "snub.example:29447";
    const std::string ep_good = "good.example:29447";

    CreditBroker broker{uint64_t{32} * PIECE_SIZE};
    std::map<std::string, PeerMetrics> live;
    {
        TransferSession sess(broker);
        for (uint32_t i = 0; i < 4; ++i) {
            uint64_t rid = 0;
            std::string err;
            BOOST_REQUIRE_MESSAGE(sess.ReserveAndQueue(ep_slow, 0, i, PIECE_SIZE, rid, err), err);
            sess.NoteSent(rid);
            sess.NoteFailed(rid);
        }
        live = sess.Metrics();
    }
    BOOST_REQUIRE_EQUAL(live[ep_slow].timeout_count, 4);
    BOOST_CHECK_EQUAL(live[ep_slow].inflight_bytes, 0U);
    BOOST_CHECK_EQUAL(broker.Reserved(), 0U);
    BOOST_CHECK_EQUAL(static_cast<int>(live[ep_slow].state), static_cast<int>(PeerXferState::ACTIVE));
    BOOST_CHECK_EQUAL(static_cast<int>(ClassifyPeer(live[ep_slow])), static_cast<int>(PeerXferState::SNUBBED));

    PickConfig cfg;
    cfg.max_assignments = 32;
    cfg.global_inflight_ceiling = uint64_t{128} * PIECE_SIZE;

    PeerMetrics fast;
    fast.throughput_bps = 1e9;
    PeerMetrics stalled = fast;
    stalled.timeout_count = 4;
    BOOST_CHECK_EQUAL(RequestWindowBytes(fast, cfg), cfg.max_inflight_bytes);
    BOOST_CHECK_LT(RequestWindowBytes(stalled, cfg), RequestWindowBytes(fast, cfg));
    BOOST_CHECK_GE(RequestWindowBytes(stalled, cfg), cfg.min_inflight_bytes);

    const std::vector<SourceAvailability> srcs{
        Seeder(ep_good, "ng-good", 8, Run(0, 8)),
        Seeder(ep_slow, "ng-slow", 8, Run(0, 8)),
    };
    const auto missing = Iota(8);
    BOOST_REQUIRE(!EndgameActive(missing.size(), uint64_t{8} * PIECE_SIZE, cfg));

    std::map<std::string, PeerMetrics> raw;
    raw[ep_good] = fast;
    raw[ep_slow] = stalled;
    const auto unclassified = PickRarestFirst(0, 8, missing, srcs, raw, {}, {}, cfg);
    BOOST_CHECK_GE(AssignmentsTo(unclassified, ep_slow), 1);

    std::map<std::string, PeerMetrics> classified = raw;
    for (auto& kv : classified) kv.second.state = ClassifyPeer(kv.second);
    BOOST_REQUIRE_EQUAL(static_cast<int>(classified[ep_slow].state), static_cast<int>(PeerXferState::SNUBBED));
    BOOST_REQUIRE_EQUAL(static_cast<int>(classified[ep_good].state), static_cast<int>(PeerXferState::ACTIVE));

    const auto after = PickRarestFirst(0, 8, missing, srcs, classified, {}, {}, cfg);
    BOOST_CHECK_EQUAL(AssignmentsTo(after, ep_slow), 0);
    BOOST_CHECK_GE(AssignmentsTo(after, ep_good), 1);
    // The healthy peer does not inherit the snubbed peer's share: the balancer
    // keeps deferring to a peer it will then skip, so most of the file stays
    // unscheduled in this pass.
    BOOST_CHECK_LT(after.size(), missing.size());

    // Snubbing is not a ban. As sole source the peer is still asked.
    const std::vector<SourceAvailability> only_slow{srcs[1]};
    const auto sole = PickRarestFirst(0, 8, {3}, only_slow, classified, {}, {}, cfg);
    BOOST_REQUIRE_EQUAL(sole.size(), 1U);
    BOOST_CHECK_EQUAL(sole[0].endpoint, ep_slow);
}

// A stale advertisement is suppressed rather than believed, and only a record
// that verifies and moves the sequence forward brings the source back. A
// forged signature and a replayed older sequence both fail to lift it.
BOOST_AUTO_TEST_CASE(negcache_only_a_newer_signed_record_lifts_a_stale_source)
{
    using namespace modelnet;
    const Digest48 resource = ArtifactId(0xe5);
    const std::string endpoint = "198.51.100.20:29447";

    PickConfig cfg;
    cfg.now_ms = kBaseMs;
    cfg.max_assignments = 16;
    cfg.global_inflight_ceiling = uint64_t{64} * PIECE_SIZE;

    std::vector<SourceAvailability> stale{
        Seeder(endpoint, "ng-stale", 4, Run(0, 4), kBaseMs - 2 * cfg.stale_after_ms)};
    BOOST_REQUIRE(!SourceIsFresh(stale[0], cfg));
    BOOST_CHECK_EQUAL(PieceRarity(0, 2, stale, {}, cfg), 0);
    BOOST_CHECK(PickRarestFirst(0, 4, Iota(4), stale, {}, {}, {}, cfg).empty());
    BOOST_CHECK(EndangeredPieces(0, 4, {}, stale, {}, cfg).empty());

    std::vector<unsigned char> pk, sk;
    std::string err;
    BOOST_REQUIRE_MESSAGE(GenerateMlDsa44(pk, sk, err), err);
    const auto fresh_rec = SignedAvailability(resource, endpoint, 7, kBaseMs + 3'600'000, Run(0, 4), pk, sk);
    BOOST_REQUIRE_MESSAGE(VerifyProviderRecord(fresh_rec, kBaseMs, err), err);

    ProviderCache cache;
    BOOST_REQUIRE_MESSAGE(cache.Put(fresh_rec, kBaseMs, err), err);
    BOOST_REQUIRE_EQUAL(cache.Get(resource, kBaseMs).size(), 1U);

    ProviderRecord forged = fresh_rec;
    forged.seq = 8;
    BOOST_REQUIRE(!forged.sig.empty());
    forged.sig[0] ^= 0xff;
    BOOST_CHECK(!cache.Put(forged, kBaseMs, err));
    BOOST_CHECK_EQUAL(err, "bad signature");

    const auto replayed = SignedAvailability(resource, endpoint, 6, kBaseMs + 3'600'000, Run(0, 4), pk, sk);
    BOOST_CHECK(!cache.Put(replayed, kBaseMs, err));
    BOOST_CHECK_EQUAL(err, "sequence rollback");

    const auto accepted = cache.Get(resource, kBaseMs);
    BOOST_REQUIRE_EQUAL(accepted.size(), 1U);
    BOOST_CHECK_EQUAL(accepted[0].seq, 7U);

    // The accepted record is what re-enters the picker, carrying the signer's
    // identity that a bare endpoint observation cannot supply.
    std::vector<SourceAvailability> revived{Seeder(accepted[0].endpoints.at(0), "ng-stale", 4,
                                                    accepted[0].ranges, kBaseMs)};
    revived[0].peer.service_id = accepted[0].service_id.Hex();
    BOOST_REQUIRE(SourceIsFresh(revived[0], cfg));
    BOOST_CHECK_EQUAL(PieceRarity(0, 2, revived, {}, cfg), 1);

    const auto picks = PickRarestFirst(0, 4, Iota(4), revived, {}, {}, {}, cfg);
    BOOST_REQUIRE_EQUAL(picks.size(), 4U);
    for (const auto& a : picks) BOOST_CHECK_EQUAL(a.endpoint, endpoint);

    const auto endangered = EndangeredPieces(0, 4, {}, revived, {}, cfg);
    const std::vector<uint32_t> expect{0, 1, 2, 3};
    BOOST_CHECK_EQUAL_COLLECTIONS(endangered.begin(), endangered.end(), expect.begin(), expect.end());
}

// The resolve-side negative entry is keyed by (kind, digest). It names no peer,
// so the peer that returned the incomplete answer is not suppressed for any
// other content and no other peer is suppressed for this content. It is bounded
// by the TTL measured from the most recent failure, and accepting a newer
// signed record does not clear it early: there is no invalidation hook, only
// expiry.
BOOST_AUTO_TEST_CASE(negcache_resolve_miss_is_content_keyed_and_expiry_bounded)
{
    using namespace modelnet;
    const Digest48 wanted = ArtifactId(0xf6);
    const Digest48 other = ArtifactId(0x17);
    constexpr uint8_t kind = 1;
    constexpr int64_t t0 = 1000;

    NegativeResolveCache neg;
    neg.RememberIncomplete(kind, wanted, t0);
    BOOST_CHECK(neg.HasIncomplete(kind, wanted, t0));
    BOOST_CHECK(!neg.HasIncomplete(kind + 1, wanted, t0));
    BOOST_CHECK(!neg.HasIncomplete(kind, other, t0));

    BOOST_CHECK(neg.HasIncomplete(kind, wanted, t0 + NEGATIVE_RESOLVE_TTL_S - 1));
    BOOST_CHECK(!neg.HasIncomplete(kind, wanted, t0 + NEGATIVE_RESOLVE_TTL_S));

    // A second incomplete answer re-arms the same bounded window; it does not
    // accumulate into a permanent "no such model".
    neg.RememberIncomplete(kind, wanted, t0 + 30);
    BOOST_CHECK(neg.HasIncomplete(kind, wanted, t0 + 30 + NEGATIVE_RESOLVE_TTL_S - 1));
    BOOST_CHECK(!neg.HasIncomplete(kind, wanted, t0 + 30 + NEGATIVE_RESOLVE_TTL_S));

    std::vector<unsigned char> pk, sk;
    std::string err;
    BOOST_REQUIRE_MESSAGE(GenerateMlDsa44(pk, sk, err), err);
    const auto rec = SignedAvailability(wanted, "198.51.100.30:29447", 1, kBaseMs + 60'000, Run(0, 2), pk, sk);
    ProviderCache cache;
    BOOST_REQUIRE_MESSAGE(cache.Put(rec, kBaseMs, err), err);
    BOOST_CHECK(neg.HasIncomplete(kind, wanted, t0 + 31));
}

// Nothing about a locally failed peer is published, and the local verdict does
// not censor what that peer publishes. There is no bad-peer record type to
// gossip, the provider record carries no reputation field, and the verdict dies
// with the transfer that formed it.
BOOST_AUTO_TEST_CASE(negcache_local_verdict_is_never_a_published_bad_peer_record)
{
    using namespace modelnet;
    const Digest48 resource = ArtifactId(0x28);
    const std::string endpoint = "198.51.100.40:29447";

    PickConfig cfg;
    cfg.max_assignments = 8;
    cfg.global_inflight_ceiling = uint64_t{64} * PIECE_SIZE;
    const std::vector<SourceAvailability> srcs{Seeder(endpoint, "ng-quarantined", 4, Run(0, 4))};
    std::map<std::string, PeerMetrics> quarantined;
    quarantined[endpoint].state = PeerXferState::FAILED;

    BOOST_CHECK_EQUAL(RequestWindowBytes(quarantined[endpoint], cfg), 0U);
    BOOST_CHECK_EQUAL(PieceRarity(0, 0, srcs, quarantined, cfg), 0);
    BOOST_CHECK(PickRarestFirst(0, 4, Iota(4), srcs, quarantined, {}, {}, cfg).empty());

    // The same peer's signed record is still accepted and still served from the
    // cache: a local transfer verdict is not a reason to drop its records.
    std::vector<unsigned char> pk, sk;
    std::string err;
    BOOST_REQUIRE_MESSAGE(GenerateMlDsa44(pk, sk, err), err);
    const auto rec = SignedAvailability(resource, endpoint, 3, kBaseMs + 600'000, Run(0, 4), pk, sk);
    ProviderCache cache;
    BOOST_REQUIRE_MESSAGE(cache.Put(rec, kBaseMs, err), err);
    BOOST_CHECK_EQUAL(cache.Get(resource, kBaseMs).size(), 1U);

    const UniValue json = ProviderRecordToJson(rec);
    const std::vector<std::string> keys = json.getKeys();
    const std::set<std::string> present(keys.begin(), keys.end());
    const std::set<std::string> expect{"type", "resource", "service_id", "endpoints", "reachability_kind",
                                       "complete", "ranges", "seq", "expiry_ms", "pubkey", "sig",
                                       "inference", "generic_dht"};
    BOOST_CHECK(present == expect);
    for (const std::string& banned : {"ban", "bad", "fail", "snub", "verdict", "score", "reputation"}) {
        for (const std::string& k : keys) BOOST_CHECK_EQUAL(k.find(banned), std::string::npos);
    }

    // There is no record type in which a bad-peer claim could travel.
    BOOST_CHECK(AcceptProviderRecordType(json["type"].get_str()));
    BOOST_CHECK(!AcceptProviderRecordType("btx-badpeer-v1"));
    UniValue forged_type = json;
    forged_type.pushKV("type", "btx-badpeer-v1");
    ProviderRecord parsed;
    BOOST_CHECK(!ProviderRecordFromJson(forged_type, parsed, err));
    BOOST_CHECK_EQUAL(err, "unknown record type");

    // The verdict is per-transfer state, not a process-wide peer store: a new
    // session starts with no memory of the previous one's failures.
    CreditBroker broker{uint64_t{8} * PIECE_SIZE};
    {
        TransferSession first(broker);
        uint64_t rid = 0;
        BOOST_REQUIRE_MESSAGE(first.ReserveAndQueue(endpoint, 0, 0, PIECE_SIZE, rid, err), err);
        first.NoteSent(rid);
        first.NoteFailed(rid);
        BOOST_REQUIRE_EQUAL(first.Metrics()[endpoint].timeout_count, 1);
    }
    TransferSession second(broker);
    BOOST_CHECK(second.Metrics().empty());
}

BOOST_AUTO_TEST_SUITE_END()
