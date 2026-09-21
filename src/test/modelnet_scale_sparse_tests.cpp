// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Sparse SCALE evidence: want-list / query sample caps without 10M files
// or 400GiB bodies. Live 10M catalog lab remains NOT_RUN.

#include <modelnet/helper.h>
#include <modelnet/index_reconcile.h>
#include <modelnet/query_router.h>
#include <test/util/setup_common.h>
#include <univalue.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_scale_sparse_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(scale_sparse_want_list_caps_without_10m_files)
{
    using namespace modelnet;
    std::vector<std::string> missing;
    missing.reserve(400);
    for (int i = 0; i < 400; ++i) missing.push_back(std::string("id-") + std::to_string(i));
    const auto bounded = BoundedWantList(missing);
    BOOST_CHECK_EQUAL(bounded.size(), RECONCILE_WANT_MAX);
    BOOST_CHECK_EQUAL(bounded.front(), "id-0");
    BOOST_CHECK_EQUAL(bounded.back(), "id-255");

    IndexReconciler rec;
    std::vector<std::string> local;
    local.reserve(300);
    for (int i = 0; i < 300; ++i) local.push_back(std::string("L") + std::to_string(i));
    GossipDigest remote;
    remote.catalog_digest_hex = "00";
    remote.entry_count = 10'000'000u;
    const auto divided = rec.Compare(local, remote);
    BOOST_CHECK(divided.status == ReconcileStatus::DIVIDE);
    BOOST_CHECK(!ReconcileDigestAuthorizesInsert());

    std::vector<std::string> remote_ids;
    remote_ids.reserve(400);
    for (int i = 0; i < 400; ++i) remote_ids.push_back(std::string("R") + std::to_string(i));
    const auto sets = rec.CompareSets(/*local_ids=*/{}, remote_ids);
    BOOST_CHECK(sets.status == ReconcileStatus::WANT);
    BOOST_CHECK(sets.want_truncated);
    BOOST_CHECK_EQUAL(sets.want_ids.size(), RECONCILE_WANT_MAX);

    QueryRouter router;
    std::vector<std::string> ids;
    for (int i = 0; i < 64; ++i) ids.push_back(std::string("Q") + std::to_string(i));
    const QuerySummary sum = router.SummarizeIds(ids);
    BOOST_CHECK_EQUAL(sum.sample_ids.size(), QUERY_SAMPLE_MAX);
    BOOST_CHECK(sum.truncated);
    BOOST_CHECK_EQUAL(sum.hit_count, 64U);

    const GossipDigest huge = MakeCatalogDigest(local);
    BOOST_CHECK_EQUAL(huge.entry_count, 300u);
    BOOST_CHECK(huge.entry_count != 10'000'000u);
}

BOOST_AUTO_TEST_CASE(scale_sparse_evaluated_transport_10m_not_run)
{
    const fs::path tmp = m_path_root / "scale-sparse-cat";
    modelnet::ModelCatalog cat{tmp, 1 << 20};
    UniValue req(UniValue::VOBJ);
    req.pushKV("method", "getevaluatedtransport");
    req.pushKV("params", UniValue(UniValue::VARR));
    UniValue result;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, req, result, code, err), err);
    BOOST_CHECK_EQUAL(result["catalog_10m"].get_str(), "NOT_RUN");
    BOOST_CHECK_EQUAL(result["utp"].get_str(), "NONSHIPPING");
    BOOST_CHECK(!result["quic"].get_bool());
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
