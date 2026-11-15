// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_flatcap.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_flatcap_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_manifest)
{
    modelnet::SwarmFlatCap manifest;
    manifest.manifest_id.clear();
    manifest.want_raise = false;
    std::string err;
    const modelnet::SwarmFlatCapResult result = modelnet::SwarmKeepFlatCap(manifest, err);
    BOOST_CHECK_EQUAL(result.code, "MANIFEST");
    BOOST_CHECK_EQUAL(err, "MANIFEST");
    BOOST_CHECK(!result.raised);
    BOOST_CHECK_EQUAL(result.bytes, 16384);
}

BOOST_AUTO_TEST_CASE(want_raise_held)
{
    modelnet::SwarmFlatCap manifest;
    manifest.manifest_id = "manifest-1";
    manifest.want_raise = true;
    std::string err;
    const modelnet::SwarmFlatCapResult result = modelnet::SwarmKeepFlatCap(manifest, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK(!result.raised);
    BOOST_CHECK_EQUAL(result.bytes, 16384);
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmFlatCap manifest;
    manifest.manifest_id = "manifest-2";
    manifest.want_raise = false;
    std::string err = "stale";
    const modelnet::SwarmFlatCapResult result = modelnet::SwarmKeepFlatCap(manifest, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!result.raised);
    BOOST_CHECK_EQUAL(result.bytes, 16384);
}

BOOST_AUTO_TEST_SUITE_END()
