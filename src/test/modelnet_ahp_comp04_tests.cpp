// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// AHP-COMP-04: isolated monetary node with helper down. Not production btxd.

#include <modelnet/helper.h>
#include <rpc/request.h>
#include <rpc/server.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <stdexcept>
#include <string>

namespace {

struct Comp04Setup : public TestingSetup {
    static TestOpts BuildOpts()
    {
        TestOpts opts;
        opts.extra_args = {"-nomodelnet"};
        return opts;
    }
    Comp04Setup() : TestingSetup{ChainType::REGTEST, BuildOpts()} {}

    UniValue CallRPC(const std::string& method, UniValue params = UniValue{UniValue::VARR})
    {
        JSONRPCRequest request;
        request.context = &m_node;
        request.strMethod = method;
        request.params = std::move(params);
        if (RPCIsInWarmup(nullptr)) SetRPCWarmupFinished();
        return tableRPC.execute(request);
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(modelnet_ahp_comp04_tests, Comp04Setup)

BOOST_AUTO_TEST_CASE(ahp_comp_04_helper_down)
{
    const fs::path missing = m_path_root / "no-such-modeld.sock";
    UniValue unix_result;
    std::string unix_err;
    BOOST_CHECK(!modelnet::CallUnixRpc(missing, "executebtxacquisition", UniValue(UniValue::VARR), unix_result, unix_err));
    BOOST_CHECK(unix_err.find("not running") != std::string::npos || unix_err.find("unix") != std::string::npos);

    BOOST_CHECK_NO_THROW(CallRPC("getblockcount"));
    BOOST_CHECK_NO_THROW(CallRPC("getblockchaininfo"));

    const UniValue info = CallRPC("getmodelnetworkinfo");
    BOOST_REQUIRE(info.isObject());
    BOOST_CHECK_EQUAL(info["automatic_spend_atoms"].getInt<int>(), 0);
    if (info.exists("helper_ready") && info["helper_ready"].isBool()) {
        BOOST_CHECK(!info["helper_ready"].get_bool());
    }

    UniValue params(UniValue::VARR);
    UniValue o(UniValue::VOBJ);
    o.pushKV("plan_id", std::string(96, 'a'));
    params.push_back(o);
    bool threw = false;
    try {
        (void)CallRPC("executebtxacquisition", params);
    } catch (const UniValue& e) {
        threw = true;
        const std::string msg = e.exists("message") ? e["message"].get_str() : e.write();
        BOOST_CHECK(msg.find("helper") != std::string::npos || msg.find("unavailable") != std::string::npos);
    } catch (const std::exception& e) {
        threw = true;
        const std::string msg = e.what();
        BOOST_CHECK(msg.find("helper") != std::string::npos || msg.find("unavailable") != std::string::npos);
    }
    BOOST_CHECK(threw);
}

BOOST_AUTO_TEST_SUITE_END()
