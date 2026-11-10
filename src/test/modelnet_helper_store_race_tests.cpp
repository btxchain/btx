// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/catalog.h>
#include <modelnet/helper.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_helper_store_race_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(concurrent_store_rpcs_keep_every_change)
{
    // createmodelidentity, setmodelmirror and setmodelrule read
    // identities.json / mirror.json / acl.json, add one entry and write the
    // file back. The helper serves RPCs on more than one worker, so calls run
    // at the same time; none may drop another call's entry.
    const fs::path dir = m_path_root / "helper-store-race";
    modelnet::ModelCatalog cat{dir, 8 << 20};
    const auto call = [&](const std::string& method, const UniValue& params, UniValue& result) {
        UniValue rpc(UniValue::VOBJ);
        rpc.pushKV("method", method);
        rpc.pushKV("params", params);
        std::string code, err;
        return modelnet::DispatchHelperRpc(cat, rpc, result, code, err);
    };
    // RunModelDaemon binds the event layer before the workers serve calls;
    // DispatchHelperRpc only binds it on first use. Do one call first, as
    // the helper does at start.
    UniValue warmup(UniValue::VOBJ);
    BOOST_REQUIRE(call("listmodelrules", UniValue(UniValue::VARR), warmup));
    constexpr int THREADS{4};
    constexpr int CALLS{8};
    std::mutex mu;
    std::set<std::string> created;
    std::atomic<int> failed{0};
    std::vector<std::thread> threads;
    for (int t = 0; t < THREADS; ++t) {
        threads.emplace_back([&, t] {
            for (int i = 0; i < CALLS; ++i) {
                UniValue label(UniValue::VARR);
                label.push_back("race-" + std::to_string(t) + "-" + std::to_string(i));
                UniValue id(UniValue::VOBJ);
                if (!call("createmodelidentity", label, id) || !id["id"].isStr()) {
                    ++failed;
                    continue;
                }
                std::lock_guard<std::mutex> lock(mu);
                created.insert(id["id"].get_str());
            }
            for (int i = 0; i < CALLS; ++i) {
                UniValue sel(UniValue::VOBJ);
                sel.pushKV("query", "race-" + std::to_string(t) + "-" + std::to_string(i));
                sel.pushKV("idempotency_key", "race-mirror-" + std::to_string(t) + "-" + std::to_string(i));
                UniValue params(UniValue::VARR);
                params.push_back(sel);
                UniValue result(UniValue::VOBJ);
                if (!call("setmodelmirror", params, result)) ++failed;
            }
            for (int i = 0; i < CALLS; ++i) {
                UniValue rule(UniValue::VOBJ);
                rule.pushKV("name", "race-" + std::to_string(t) + "-" + std::to_string(i));
                rule.pushKV("action", "deny");
                UniValue params(UniValue::VARR);
                params.push_back(rule);
                UniValue result(UniValue::VOBJ);
                if (!call("setmodelrule", params, result)) ++failed;
            }
        });
    }
    for (auto& th : threads) th.join();
    BOOST_REQUIRE_EQUAL(failed.load(), 0);
    BOOST_REQUIRE_EQUAL(created.size(), size_t{THREADS * CALLS});

    UniValue listed(UniValue::VOBJ);
    BOOST_REQUIRE(call("listmodelidentities", UniValue(UniValue::VARR), listed));
    std::set<std::string> listed_ids;
    if (listed["identities"].isArray()) {
        for (const auto& i : listed["identities"].getValues()) listed_ids.insert(i["id"].get_str());
    }
    size_t missing{0};
    for (const auto& id : created) missing += listed_ids.count(id) == 0;
    BOOST_CHECK_MESSAGE(missing == 0, "identities reported as created but not listed: " + std::to_string(missing) +
                                          " of " + std::to_string(created.size()));

    UniValue rules(UniValue::VOBJ);
    BOOST_REQUIRE(call("listmodelrules", UniValue(UniValue::VARR), rules));
    const size_t listed_rules{rules["rules"].isArray() ? rules["rules"].size() : 0};
    BOOST_CHECK_MESSAGE(listed_rules == size_t{THREADS * CALLS},
                        "rules listed " + std::to_string(listed_rules) + " of " + std::to_string(THREADS * CALLS));

    UniValue mirror(UniValue::VOBJ);
    BOOST_REQUIRE(call("getmodelmirror", UniValue(UniValue::VARR), mirror));
    const size_t listed_selectors{mirror["selectors"].isArray() ? mirror["selectors"].size() : 0};
    BOOST_CHECK_MESSAGE(listed_selectors == size_t{THREADS * CALLS},
                        "mirror selectors listed " + std::to_string(listed_selectors) + " of " + std::to_string(THREADS * CALLS));
}

BOOST_AUTO_TEST_SUITE_END()
