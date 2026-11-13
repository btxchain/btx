// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/bounty.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <fstream>
#include <string>

#ifndef WIN32
#include <csignal>
#include <sys/wait.h>
#include <unistd.h>
#endif

BOOST_FIXTURE_TEST_SUITE(modelnet_bounty_eval_tests, BasicTestingSetup)

#ifndef WIN32
// A finished evaluation job keeps the pid of its exited child, and the bounty
// store saves it. Cancelling that job later must not signal the pid: the
// system may have given it to an unrelated process. A sleeping child of this
// test stands in for that process.
BOOST_AUTO_TEST_CASE(cancel_leaves_a_finished_job_and_its_old_pid_alone)
{
    const pid_t other = fork();
    BOOST_REQUIRE(other >= 0);
    if (other == 0) {
        for (;;) pause();
    }

    const fs::path dir = m_path_root / "bounty-eval-cancel";
    fs::create_directories(dir);
    {
        std::ofstream f{dir / "bounty-store.json"};
        f << R"({"seq":1,"epoch":0,"eval_jobs":{"done":{"job_id":"done","state":"COMPLETE","pass":true,"pid":)"
          << other << "}}}";
    }
    modelnet::BountyStore store;
    store.Bind(dir, modelnet::NetworkId{});

    UniValue params(UniValue::VARR);
    params.push_back("done");
    UniValue result;
    std::string code;
    std::string err;
    BOOST_CHECK(store.Dispatch("cancelbountyevaluation", params, result, code, err));
    BOOST_CHECK_EQUAL(result["state"].get_str(), "COMPLETE");
    BOOST_REQUIRE(store.Dispatch("getbountyevaluationjob", params, result, code, err));
    BOOST_CHECK_EQUAL(result["state"].get_str(), "COMPLETE");

    // Still running (and still our child): waitpid() has nothing to reap yet.
    const pid_t reaped = waitpid(other, nullptr, WNOHANG);
    BOOST_CHECK_EQUAL(reaped, 0);
    if (reaped == 0) {
        kill(other, SIGKILL);
        waitpid(other, nullptr, 0);
    }
}
#endif

BOOST_AUTO_TEST_SUITE_END()
