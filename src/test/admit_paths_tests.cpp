// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/admit_paths/admit_paths.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

const char* const kPaths[] = {
    "hostmodel",
    "importmodel",
    "seedmodel",
    "watched",
    "demand-seed",
    "peer-follow",
    "cloud-mirror",
    "encrypted-release",
    "bundle-import",
    "package-install",
    "hosted-gateway",
    "direct-api",
    "capability",
    "local-generate",
    "model-rollout",
};

void Idle(modelnet::AdmitPaths& eng)
{
    std::string err;
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK(!eng.Wired("hostmodel"));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(admit_paths_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_and_unknown_are_path)
{
    modelnet::AdmitPaths eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Note("", err));
    BOOST_CHECK_EQUAL(err, "PATH");
    BOOST_CHECK(!eng.noted(""));
    BOOST_CHECK(!eng.Note("", err));
    BOOST_CHECK_EQUAL(err, "PATH");
    BOOST_CHECK(!eng.noted(""));

    BOOST_CHECK(!eng.Note("mirror", err));
    BOOST_CHECK_EQUAL(err, "PATH");
    BOOST_CHECK(!eng.noted("mirror"));
    BOOST_CHECK(!eng.Note("package", err));
    BOOST_CHECK_EQUAL(err, "PATH");
    BOOST_CHECK(!eng.Note("bundle", err));
    BOOST_CHECK_EQUAL(err, "PATH");
    BOOST_CHECK(!eng.Note("reveal", err));
    BOOST_CHECK_EQUAL(err, "PATH");
    BOOST_CHECK(!eng.Note("unhostmodel", err));
    BOOST_CHECK_EQUAL(err, "PATH");
    BOOST_CHECK(!eng.noted("unhostmodel"));

    BOOST_CHECK(!eng.Quarantine("", err));
    BOOST_CHECK_EQUAL(err, "PATH");
    BOOST_CHECK(!eng.quarantined(""));
    BOOST_CHECK(!eng.Quarantine("mirror", err));
    BOOST_CHECK_EQUAL(err, "PATH");
    BOOST_CHECK(!eng.quarantined("mirror"));

    BOOST_CHECK(!eng.Serve("", err));
    BOOST_CHECK_EQUAL(err, "UNWIRED");
    BOOST_CHECK(!eng.Serve("mirror", err));
    BOOST_CHECK_EQUAL(err, "UNWIRED");
    BOOST_CHECK(!eng.Wired(""));
    BOOST_CHECK(!eng.Wired("mirror"));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(known_paths_note_then_serve_unwired)
{
    modelnet::AdmitPaths eng;
    std::string err = "stale";
    for (const char* path : kPaths) {
        BOOST_CHECK(eng.Note(path, err));
        BOOST_CHECK(err.empty());
        BOOST_CHECK(eng.noted(path));
        BOOST_CHECK(!eng.Wired(path));
        BOOST_CHECK(!eng.quarantined(path));
        BOOST_CHECK(!eng.Serve(path, err));
        BOOST_CHECK_EQUAL(err, "UNWIRED");
        BOOST_CHECK(!eng.Note(path, err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
        BOOST_CHECK_EQUAL(err, "REPLAY");
        BOOST_CHECK(eng.noted(path));
        BOOST_CHECK(!eng.Wired(path));
        BOOST_CHECK(!eng.Serve(path, err));
        BOOST_CHECK_EQUAL(err, "UNWIRED");
        BOOST_CHECK(!eng.launched());
        BOOST_CHECK(!eng.gpu());
        BOOST_CHECK(!eng.broadcast());
        BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
        BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
        BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    }
    BOOST_CHECK(eng.noted("hostmodel"));
    BOOST_CHECK(eng.noted("importmodel"));
    BOOST_CHECK(eng.noted("seedmodel"));
    BOOST_CHECK(eng.noted("watched"));
    BOOST_CHECK(eng.noted("demand-seed"));
    BOOST_CHECK(eng.noted("peer-follow"));
    BOOST_CHECK(eng.noted("cloud-mirror"));
    BOOST_CHECK(eng.noted("encrypted-release"));
    BOOST_CHECK(eng.noted("bundle-import"));
    BOOST_CHECK(eng.noted("package-install"));
    BOOST_CHECK(eng.noted("hosted-gateway"));
    BOOST_CHECK(eng.noted("direct-api"));
    BOOST_CHECK(eng.noted("capability"));
    BOOST_CHECK(eng.noted("local-generate"));
    BOOST_CHECK(eng.noted("model-rollout"));
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(quarantine_keeps_serve_closed)
{
    modelnet::AdmitPaths eng;
    std::string err = "stale";
    for (const char* path : kPaths) {
        BOOST_CHECK(eng.Note(path, err));
        BOOST_CHECK(err.empty());
        BOOST_CHECK(!eng.Serve(path, err));
        BOOST_CHECK_EQUAL(err, "UNWIRED");
        BOOST_CHECK(eng.Quarantine(path, err));
        BOOST_CHECK(err.empty());
        BOOST_CHECK(eng.quarantined(path));
        BOOST_CHECK(eng.noted(path));
        BOOST_CHECK(!eng.Wired(path));
        BOOST_CHECK(!eng.Serve(path, err));
        BOOST_CHECK_EQUAL(err, "QUARANTINE");
        BOOST_CHECK(!eng.Quarantine(path, err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
        BOOST_CHECK_EQUAL(err, "REPLAY");
        BOOST_CHECK(eng.quarantined(path));
        BOOST_CHECK(!eng.Serve(path, err));
        BOOST_CHECK_EQUAL(err, "QUARANTINE");
        BOOST_CHECK(!eng.Wired(path));
        BOOST_CHECK(!eng.launched());
        BOOST_CHECK(!eng.gpu());
        BOOST_CHECK(!eng.broadcast());
        BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
        BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    }
    BOOST_CHECK(eng.quarantined("hostmodel"));
    BOOST_CHECK(eng.quarantined("model-rollout"));
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(quarantine_before_note_still_blocks_serve)
{
    modelnet::AdmitPaths eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Serve("capability", err));
    BOOST_CHECK_EQUAL(err, "UNWIRED");
    BOOST_CHECK(eng.Quarantine("capability", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.quarantined("capability"));
    BOOST_CHECK(!eng.noted("capability"));
    BOOST_CHECK(!eng.Serve("capability", err));
    BOOST_CHECK_EQUAL(err, "QUARANTINE");
    BOOST_CHECK(eng.Note("capability", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.noted("capability"));
    BOOST_CHECK(!eng.Serve("capability", err));
    BOOST_CHECK_EQUAL(err, "QUARANTINE");
    BOOST_CHECK(!eng.Wired("capability"));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
