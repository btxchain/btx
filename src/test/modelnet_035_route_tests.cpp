// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/admission_routes.h>
#include <modelnet/model_admission.h>
#include <modelnet/training_evidence.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_035_route_tests, BasicTestingSetup)

namespace {

const std::string kRng = "rng-frozen";
const std::string kOptimizer = "opt-frozen";
const std::string kCursor = "cursor-frozen";

modelnet::Interval Edge(uint64_t start, uint64_t end, std::string start_state, std::string end_state, std::string ancestry)
{
    modelnet::Interval interval;
    interval.start_inclusive = start;
    interval.end_exclusive = end;
    interval.start_state = std::move(start_state);
    interval.end_state = std::move(end_state);
    interval.profile = "EXACT_CHECKS";
    interval.rng = kRng;
    interval.optimizer = kOptimizer;
    interval.data_cursor = kCursor;
    interval.ancestry = std::move(ancestry);
    interval.publisher_only = false;
    return interval;
}

modelnet::StrictAdmissionRecord TwoRootRecord()
{
    modelnet::StrictAdmissionRecord record;
    record.assurance = modelnet::Assurance::PUBLIC_STRICT;
    record.total = 8;
    record.start_state = "S0";
    record.final_state = "SF";
    record.intervals = {Edge(0, 8, "S0", "SF", "root-a"), Edge(0, 8, "S0", "SF", "root-b")};
    record.independent_roots = {"root-a", "root-b"};
    record.owner_authorized = false;
    return record;
}

} // namespace

BOOST_AUTO_TEST_CASE(quarantine_blocks_serve_despite_hash_match)
{
    const std::string id = "btx035-route-quarantine";
    const modelnet::StrictAdmissionRecord record = TwoRootRecord();
    const modelnet::AdmissionResult would_serve = modelnet::Admit(
        record.assurance, true, record.intervals, record.total, record.start_state, record.final_state,
        record.independent_roots, record.owner_authorized);
    BOOST_CHECK(would_serve.ServeAllowed());

    modelnet::RegisterStrictModel(id, record);
    modelnet::Quarantine(id);

    std::string admission;
    BOOST_CHECK(!modelnet::RouteMayServe(id, true, admission));
    BOOST_CHECK_EQUAL(admission, "BTX035_QUARANTINE");
    BOOST_CHECK(!modelnet::RouteMayGenerate(id, true, admission));
    BOOST_CHECK_EQUAL(admission, "BTX035_QUARANTINE");
    BOOST_CHECK(!modelnet::RouteMayServe(id, false, admission));
    BOOST_CHECK_EQUAL(admission, "BTX035_QUARANTINE");
}

BOOST_AUTO_TEST_CASE(hash_only_strict_registration_blocks_serve)
{
    const std::string id = "btx035-route-hash-only";
    modelnet::StrictAdmissionRecord record;
    record.assurance = modelnet::Assurance::PUBLIC_STRICT;
    record.total = 8;
    record.start_state = "S0";
    record.final_state = "SF";
    record.intervals = {Edge(0, 8, "S0", "SF", "only-root")};
    record.independent_roots = {"only-root"};

    const modelnet::AdmissionResult denied = modelnet::Admit(
        record.assurance, true, record.intervals, record.total, record.start_state, record.final_state,
        record.independent_roots, record.owner_authorized);
    BOOST_CHECK(!denied.ServeAllowed());
    BOOST_CHECK_EQUAL(denied.code, "BTX035_REPLAY");

    modelnet::RegisterStrictModel(id, record);
    std::string admission = "stale";
    BOOST_CHECK(!modelnet::RouteMayServe(id, true, admission));
    BOOST_CHECK_EQUAL(admission, "BTX035_REPLAY");
    BOOST_CHECK(!modelnet::RouteMayGenerate(id, true, admission));
    BOOST_CHECK_EQUAL(admission, "BTX035_REPLAY");
}

BOOST_AUTO_TEST_CASE(two_root_serve_allowed_may_serve)
{
    const std::string id = "btx035-route-two-root";
    const modelnet::StrictAdmissionRecord record = TwoRootRecord();
    const modelnet::AdmissionResult admitted = modelnet::Admit(
        record.assurance, true, record.intervals, record.total, record.start_state, record.final_state,
        record.independent_roots, record.owner_authorized);
    BOOST_CHECK(admitted.admitted);
    BOOST_CHECK(admitted.ServeAllowed());
    BOOST_CHECK(admitted.code.empty());

    modelnet::RegisterStrictModel(id, record);
    std::string admission = "stale";
    BOOST_CHECK(modelnet::RouteMayServe(id, true, admission));
    BOOST_CHECK(admission.empty());
    BOOST_CHECK(modelnet::RouteMayGenerate(id, true, admission));
    BOOST_CHECK(admission.empty());

    BOOST_CHECK(!modelnet::RouteMayServe(id, false, admission));
    BOOST_CHECK_EQUAL(admission, "BTX035_BYTE_HASH_MISMATCH");
}

BOOST_AUTO_TEST_CASE(unregistered_legacy_id_stays_allowed)
{
    const std::string id = "btx035-route-unregistered";
    std::string admission = "stale";
    BOOST_CHECK(modelnet::RouteMayServe(id, true, admission));
    BOOST_CHECK(admission.empty());
    BOOST_CHECK(modelnet::RouteMayGenerate(id, false, admission));
    BOOST_CHECK(admission.empty());
}

BOOST_AUTO_TEST_CASE(research_only_registration_never_serves)
{
    const std::string id = "btx035-route-research";
    modelnet::StrictAdmissionRecord record = TwoRootRecord();
    record.assurance = modelnet::Assurance::RESEARCH_ONLY;
    record.owner_authorized = true;

    const modelnet::AdmissionResult research = modelnet::Admit(
        record.assurance, true, record.intervals, record.total, record.start_state, record.final_state,
        record.independent_roots, record.owner_authorized);
    BOOST_CHECK(research.research_execution_permit);
    BOOST_CHECK(!research.ServeAllowed());

    modelnet::RegisterStrictModel(id, std::move(record));
    std::string admission = "stale";
    BOOST_CHECK(!modelnet::RouteMayServe(id, true, admission));
    BOOST_CHECK(admission.empty());
    BOOST_CHECK(!modelnet::RouteMayGenerate(id, true, admission));
    BOOST_CHECK(admission.empty());
}

BOOST_AUTO_TEST_SUITE_END()
