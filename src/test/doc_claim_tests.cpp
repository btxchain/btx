// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/doc_claim/doc_claim.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::DocClaim& eng)
{
    std::string err;
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.advertised());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(doc_claim_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(forbidden_sentence)
{
    modelnet::DocClaim eng;
    std::string err = "stale";
    const std::string honest = "A local sentence is stored for this surface.";

    BOOST_CHECK(!eng.Claim("readme", "release qualified", err));
    BOOST_CHECK_EQUAL(err, modelnet::DOC_CLAIM_CLAIM);
    BOOST_CHECK_EQUAL(err, "CLAIM");
    BOOST_CHECK(!eng.stored("readme"));
    BOOST_CHECK(eng.text("readme").empty());

    BOOST_CHECK(!eng.Claim("rpc", "production ready", err));
    BOOST_CHECK_EQUAL(err, "CLAIM");
    BOOST_CHECK(!eng.stored("rpc"));

    BOOST_CHECK(!eng.Claim("build", "gpu passed", err));
    BOOST_CHECK_EQUAL(err, modelnet::DOC_CLAIM_CLAIM);
    BOOST_CHECK(!eng.stored("build"));
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.gpu());

    BOOST_CHECK(!eng.Claim("recovery", "windows passed", err));
    BOOST_CHECK_EQUAL(err, "CLAIM");
    BOOST_CHECK(!eng.stored("recovery"));
    BOOST_CHECK(!eng.windows_passed());

    BOOST_CHECK(!eng.Claim("operator", "The note says release qualified for this tree.", err));
    BOOST_CHECK_EQUAL(err, "CLAIM");
    BOOST_CHECK(!eng.stored("operator"));

    BOOST_CHECK(eng.Claim("readme", honest, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.stored("readme"));
    BOOST_CHECK_EQUAL(eng.text("readme"), honest);
    BOOST_CHECK(!eng.Claim("readme", "This build is production ready today.", err));
    BOOST_CHECK_EQUAL(err, modelnet::DOC_CLAIM_CLAIM);
    BOOST_CHECK_EQUAL(eng.text("readme"), honest);
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(honest_sentence)
{
    modelnet::DocClaim eng;
    std::string err = "stale";
    const std::string first = "A local sentence is stored for this surface.";
    const std::string second = "A later sentence does not replace the first.";

    BOOST_CHECK(!eng.Claim("public", first, err));
    BOOST_CHECK_EQUAL(err, modelnet::DOC_CLAIM_SURFACE);
    BOOST_CHECK_EQUAL(err, "SURFACE");
    BOOST_CHECK(!eng.stored("public"));
    BOOST_CHECK(!eng.Claim("", first, err));
    BOOST_CHECK_EQUAL(err, "SURFACE");
    BOOST_CHECK(!eng.stored(""));

    BOOST_CHECK(!eng.Claim("readme", "", err));
    BOOST_CHECK_EQUAL(err, modelnet::DOC_CLAIM_TEXT);
    BOOST_CHECK_EQUAL(err, "TEXT");
    BOOST_CHECK(!eng.stored("readme"));
    BOOST_CHECK(eng.text("readme").empty());

    BOOST_CHECK(eng.Claim("readme", first, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.stored("readme"));
    BOOST_CHECK_EQUAL(eng.text("readme"), first);
    BOOST_CHECK(!eng.Claim("readme", second, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text("readme"), first);
    BOOST_CHECK(!eng.stored("rpc"));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.advertised());
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(release_unqualified_after_five_surfaces)
{
    modelnet::DocClaim eng;
    std::string err = "stale";
    const char* surfaces[] = {"readme", "rpc", "build", "recovery", "operator"};
    const std::string sentences[] = {
        "Readme records a local sentence.",
        "Rpc records a local sentence.",
        "Build records a local sentence.",
        "Recovery records a local sentence.",
        "Operator records a local sentence.",
    };

    for (int i = 0; i < 5; ++i) {
        BOOST_CHECK(eng.Claim(surfaces[i], sentences[i], err));
        BOOST_CHECK(err.empty());
        BOOST_CHECK(eng.stored(surfaces[i]));
        BOOST_CHECK_EQUAL(eng.text(surfaces[i]), sentences[i]);
    }

    BOOST_CHECK(!eng.Claim("readme", "A second readme sentence.", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(eng.text("readme"), sentences[0]);

    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.advertised());
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(eng.stored("readme"));
    BOOST_CHECK(eng.stored("rpc"));
    BOOST_CHECK(eng.stored("build"));
    BOOST_CHECK(eng.stored("recovery"));
    BOOST_CHECK(eng.stored("operator"));
    BOOST_CHECK_EQUAL(eng.text("operator"), sentences[4]);
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
