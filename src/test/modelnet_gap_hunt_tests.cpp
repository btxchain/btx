// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Gap hunt (audit/skipped-and-partial-2026-09-17.md). Replaces assertions that
// could not fail with assertions that pin real production branches:
//   * Cr11Capacity clamp/floor arms. Every existing direct call passes
//     non-negative arguments with available >= protected, and the engine
//     comparisons use Cr11Capacity itself as the expected value, so a broken
//     clamp would agree with them.
//   * ParseModelBytes rejection arms behind -modelstorageautocap,
//     -modelfreespacereserve and -modeluploadlimit. Existing coverage is
//     accept-only plus "" and "not-a-budget".
// No hardware, no wallet, no network: nothing here is NOT_RUN gated.

#include <modelnet/firstrun.h>
#include <modelnet/hcp.h>
#include <modelnet/policy.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <limits>
#include <string>

BOOST_FIXTURE_TEST_SUITE(modelnet_gap_hunt_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(gap_hunt_cr11_capacity_clamps_negative_inputs)
{
    // Each argument is clamped independently before the subtraction, so a
    // negative can never widen capacity nor underflow the slack.
    BOOST_CHECK_EQUAL(modelnet::Cr11Capacity(-1, 400, 250), 0);
    BOOST_CHECK_EQUAL(modelnet::Cr11Capacity(1000, -400, 250), 250);
    BOOST_CHECK_EQUAL(modelnet::Cr11Capacity(1000, 400, -250), 0);
    BOOST_CHECK_EQUAL(modelnet::Cr11Capacity(-1, -1, -1), 0);

    // Clamping must happen before available - protected_atoms; subtracting
    // first would overflow rather than return 0.
    constexpr int64_t kMin = std::numeric_limits<int64_t>::min();
    constexpr int64_t kMax = std::numeric_limits<int64_t>::max();
    BOOST_CHECK_EQUAL(modelnet::Cr11Capacity(kMin, kMax, 250), 0);
    BOOST_CHECK_EQUAL(modelnet::Cr11Capacity(kMin, kMin, kMin), 0);
}

BOOST_AUTO_TEST_CASE(gap_hunt_cr11_capacity_floors_at_zero_and_slack_can_bind)
{
    // Protected capital above the balance yields no capacity, and an exactly
    // protected balance yields no capacity either.
    BOOST_CHECK_EQUAL(modelnet::Cr11Capacity(300, 400, 250), 0);
    BOOST_CHECK_EQUAL(modelnet::Cr11Capacity(400, 400, 250), 0);

    // Slack is the binding constraint here; remaining authority is elsewhere.
    BOOST_CHECK_EQUAL(modelnet::Cr11Capacity(500, 400, 250), 100);
    BOOST_CHECK_EQUAL(modelnet::Cr11Capacity(900, 400, 250), 250);

    // Zero remaining authority is a hard stop regardless of slack.
    BOOST_CHECK_EQUAL(modelnet::Cr11Capacity(1000000, 0, 0), 0);
}

BOOST_AUTO_TEST_CASE(gap_hunt_parse_model_bytes_rejects_overflow_and_unknown_unit)
{
    uint64_t out = 12345;
    std::string err;

    // Digit accumulation overflow.
    out = 12345;
    err.clear();
    BOOST_CHECK(!modelnet::ParseModelBytes("99999999999999999999999", out, err));
    BOOST_CHECK(!err.empty());
    BOOST_CHECK_EQUAL(out, 12345u); // untouched on failure

    // Unit multiplication overflow: the mantissa itself fits in uint64_t.
    err.clear();
    BOOST_CHECK(!modelnet::ParseModelBytes("18446744073709551615G", out, err));
    BOOST_CHECK(!err.empty());

    // Unrecognised unit must fail closed, not silently mean bytes.
    err.clear();
    BOOST_CHECK(!modelnet::ParseModelBytes("80ZiB", out, err));
    BOOST_CHECK(!err.empty());

    // A size must start with a digit; no signs, no bare units.
    err.clear();
    BOOST_CHECK(!modelnet::ParseModelBytes("-1", out, err));
    err.clear();
    BOOST_CHECK(!modelnet::ParseModelBytes("+80GiB", out, err));
    err.clear();
    BOOST_CHECK(!modelnet::ParseModelBytes("GiB", out, err));
}

BOOST_AUTO_TEST_CASE(gap_hunt_parse_model_bytes_accepts_separators_and_case)
{
    uint64_t out = 0;
    std::string err;

    // Spaces and underscores are stripped, and units are case-insensitive.
    BOOST_REQUIRE_MESSAGE(modelnet::ParseModelBytes("80 GiB", out, err), err);
    BOOST_CHECK_EQUAL(out, 80ULL << 30);
    BOOST_REQUIRE_MESSAGE(modelnet::ParseModelBytes("80_GiB", out, err), err);
    BOOST_CHECK_EQUAL(out, 80ULL << 30);
    BOOST_REQUIRE_MESSAGE(modelnet::ParseModelBytes("80gIb", out, err), err);
    BOOST_CHECK_EQUAL(out, 80ULL << 30);

    BOOST_REQUIRE_MESSAGE(modelnet::ParseModelBytes("2TiB", out, err), err);
    BOOST_CHECK_EQUAL(out, 2ULL << 40);
    BOOST_REQUIRE_MESSAGE(modelnet::ParseModelBytes("80b", out, err), err);
    BOOST_CHECK_EQUAL(out, 80u);
}

BOOST_AUTO_TEST_CASE(gap_hunt_parse_storage_budget_agrees_on_rejection)
{
    // The first-run wrapper must not be more permissive than the policy parser
    // it delegates to. Existing coverage only compares the accepting path.
    const char* rejected[] = {"", "not-a-budget", "-1", "GiB", "80ZiB",
                              "99999999999999999999999", "18446744073709551615G"};
    for (const char* token : rejected) {
        uint64_t via_storage = 7;
        uint64_t via_policy = 7;
        std::string serr;
        std::string perr;
        const bool s_ok = modelnet::ParseStorageBudget(token, via_storage, serr);
        const bool p_ok = modelnet::ParseModelBytes(token, via_policy, perr);
        BOOST_CHECK_MESSAGE(!s_ok, std::string("ParseStorageBudget accepted ") + token);
        BOOST_CHECK_MESSAGE(s_ok == p_ok, std::string("parsers disagree on ") + token);
    }
}

BOOST_AUTO_TEST_SUITE_END()
