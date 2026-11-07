// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_continue/nif_continue.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(nif_continue_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(exact_move_rejects_mismatch_and_remote)
{
    modelnet::NifContinue cont;
    std::string err;
    const std::vector<unsigned char> body{1, 2, 3, 4};
    BOOST_CHECK(cont.Bind("model-a", "runtime-a", "realm-a", modelnet::NifExactness::ExactReproducible, err));
    BOOST_CHECK(cont.Move(body, "model-a", "runtime-a", "realm-a", modelnet::NifExactness::ExactReproducible, err));
    BOOST_CHECK(cont.received() == body);
    BOOST_CHECK_EQUAL(cont.bytes_moved(), static_cast<int64_t>(4));

    const int64_t kept = cont.bytes_moved();
    BOOST_CHECK(!cont.Move(body, "model-b", "runtime-a", "realm-a", modelnet::NifExactness::ExactReproducible, err));
    BOOST_CHECK_EQUAL(err, "COMPAT");
    BOOST_CHECK_EQUAL(cont.bytes_moved(), kept);

    BOOST_CHECK(!cont.Move(body, "model-a", "runtime-a", "realm-a", modelnet::NifExactness::ApproximateExperimental, err));
    BOOST_CHECK_EQUAL(err, "APPROXIMATE");
    BOOST_CHECK(!cont.approximate_called_exact());
    BOOST_CHECK_EQUAL(cont.bytes_moved(), kept);

    BOOST_CHECK(!cont.Remote("nixl", err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(cont.bytes_moved(), kept);
    BOOST_CHECK(!cont.all_rank_qualified());
    BOOST_CHECK(!cont.gpu());
    BOOST_CHECK_EQUAL(cont.automatic_spend(), "0");
}

BOOST_AUTO_TEST_SUITE_END()
