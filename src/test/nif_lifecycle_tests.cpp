// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_lifecycle/codes.h>
#include <modelnet/nif_lifecycle/nif_lifecycle.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

modelnet::NifRequestRecord SampleRequest()
{
    modelnet::NifRequestRecord request;
    request.principal = "principal-1";
    request.receiver = "receiver-1";
    request.realm = "realm-1";
    request.generation = "generation-1";
    request.runtime_image = "runtime-image-1";
    request.commitment = "commitment-text";
    request.attempt = "attempt-1";
    request.epoch = 7;
    request.ceiling_bytes = 64;
    request.lease_until_ms = 99;
    request.cancelled = true;
    request.output_ceiling = 8;
    request.accepted_output = "out";
    request.economic_contract = "contract-1";
    return request;
}

void ExpectRecord(const modelnet::NifRequestRecord& got, const modelnet::NifRequestRecord& request)
{
    BOOST_CHECK_EQUAL(got.principal, request.principal);
    BOOST_CHECK_EQUAL(got.receiver, request.receiver);
    BOOST_CHECK_EQUAL(got.realm, request.realm);
    BOOST_CHECK_EQUAL(got.generation, request.generation);
    BOOST_CHECK_EQUAL(got.runtime_image, request.runtime_image);
    BOOST_CHECK_EQUAL(got.commitment, request.commitment);
    BOOST_CHECK_EQUAL(got.attempt, request.attempt);
    BOOST_CHECK_EQUAL(got.epoch, request.epoch);
    BOOST_CHECK_EQUAL(got.ceiling_bytes, request.ceiling_bytes);
    BOOST_CHECK_EQUAL(got.lease_until_ms, request.lease_until_ms);
    BOOST_CHECK_EQUAL(got.cancelled, request.cancelled);
    BOOST_CHECK_EQUAL(got.output_ceiling, request.output_ceiling);
    BOOST_CHECK_EQUAL(got.accepted_output, request.accepted_output);
    BOOST_CHECK_EQUAL(got.economic_contract, request.economic_contract);
}

void ExpectQuiet(const modelnet::NifLifecycle& life)
{
    BOOST_CHECK(!life.launched());
    BOOST_CHECK(!life.gpu());
    BOOST_CHECK(!life.broadcast());
    BOOST_CHECK(!life.authority_from_receipt());
    BOOST_CHECK(!life.validation_affected());
    BOOST_CHECK_EQUAL(life.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(life.bytes_moved(), static_cast<int64_t>(0));
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(nif_lifecycle_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(admit_stores_the_request)
{
    modelnet::NifLifecycle life;
    const modelnet::NifRequestRecord request = SampleRequest();
    std::string err = "prior";

    BOOST_REQUIRE(life.Admit(m_path_root, request, false, err));
    BOOST_CHECK(err.empty());
    const modelnet::NifRequestRecord* got = life.Find(request.attempt);
    BOOST_REQUIRE(got != nullptr);
    ExpectRecord(*got, request);
    BOOST_CHECK(life.available());
    ExpectQuiet(life);
}

BOOST_AUTO_TEST_CASE(second_admit_is_replay)
{
    modelnet::NifLifecycle life;
    const modelnet::NifRequestRecord request = SampleRequest();
    std::string err = "prior";

    BOOST_REQUIRE(life.Admit(m_path_root, request, false, err));
    modelnet::NifRequestRecord again = request;
    again.principal = "other-principal";
    again.commitment = "other-commitment";
    BOOST_CHECK(!life.Admit(m_path_root, again, false, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    const modelnet::NifRequestRecord* got = life.Find(request.attempt);
    BOOST_REQUIRE(got != nullptr);
    ExpectRecord(*got, request);

    modelnet::NifLifecycle loaded;
    BOOST_REQUIRE(loaded.Reload(m_path_root, request.attempt, err));
    const modelnet::NifRequestRecord* stored = loaded.Find(request.attempt);
    BOOST_REQUIRE(stored != nullptr);
    ExpectRecord(*stored, request);
    ExpectQuiet(life);
}

BOOST_AUTO_TEST_CASE(reload_reconstructs_the_record)
{
    modelnet::NifLifecycle life;
    const modelnet::NifRequestRecord request = SampleRequest();
    std::string err = "prior";

    BOOST_REQUIRE(life.Admit(m_path_root, request, false, err));

    modelnet::NifLifecycle loaded;
    BOOST_REQUIRE(loaded.Reload(m_path_root, request.attempt, err));
    BOOST_CHECK(err.empty());
    const modelnet::NifRequestRecord* got = loaded.Find(request.attempt);
    BOOST_REQUIRE(got != nullptr);
    ExpectRecord(*got, request);
    ExpectQuiet(loaded);
}

BOOST_AUTO_TEST_CASE(missing_journal_leaves_the_record_empty)
{
    modelnet::NifLifecycle life;
    std::string err = "prior";

    BOOST_CHECK(!life.Reload(m_path_root, "attempt-missing", err));
    BOOST_CHECK_EQUAL(err, modelnet::kNifLifecycleJournal);
    BOOST_CHECK(life.Find("attempt-missing") == nullptr);
    ExpectQuiet(life);
}

BOOST_AUTO_TEST_CASE(revocation_blocks_the_next_chunk)
{
    modelnet::NifLifecycle life;
    modelnet::NifRequestRecord request = SampleRequest();
    request.attempt = "attempt-chunk";
    request.commitment = "ab";
    request.accepted_output.clear();
    request.cancelled = false;
    std::string err = "prior";

    BOOST_CHECK(!life.ReleaseChunk("attempt-unknown", false, err));
    BOOST_CHECK_EQUAL(err, modelnet::kNifLifecycleAttempt);
    BOOST_CHECK(life.Find("attempt-unknown") == nullptr);

    BOOST_REQUIRE(life.Admit(m_path_root, request, false, err));
    BOOST_REQUIRE(life.ReleaseChunk(request.attempt, false, err));
    BOOST_CHECK(err.empty());
    const modelnet::NifRequestRecord* first = life.Find(request.attempt);
    BOOST_REQUIRE(first != nullptr);
    BOOST_CHECK_EQUAL(first->accepted_output, "a");

    BOOST_CHECK(!life.ReleaseChunk(request.attempt, true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REVOKED);
    const modelnet::NifRequestRecord* blocked = life.Find(request.attempt);
    BOOST_REQUIRE(blocked != nullptr);
    BOOST_CHECK_EQUAL(blocked->accepted_output, "a");

    BOOST_REQUIRE(life.ReleaseChunk(request.attempt, false, err));
    BOOST_CHECK(err.empty());
    const modelnet::NifRequestRecord* next = life.Find(request.attempt);
    BOOST_REQUIRE(next != nullptr);
    BOOST_CHECK_EQUAL(next->accepted_output, "ab");
    ExpectQuiet(life);
}

BOOST_AUTO_TEST_CASE(crash_leaves_validation_unaffected)
{
    modelnet::NifLifecycle life;
    BOOST_CHECK(life.available());
    BOOST_CHECK(!life.validation_affected());

    life.NoteCrash();

    BOOST_CHECK(!life.available());
    BOOST_CHECK(!life.validation_affected());
    ExpectQuiet(life);
}

BOOST_AUTO_TEST_CASE(receipt_does_not_admit)
{
    modelnet::NifLifecycle life;
    const modelnet::NifRequestRecord request = SampleRequest();
    std::string err = "prior";

    BOOST_CHECK(!life.Admit(m_path_root, request, true, err));
    BOOST_CHECK_EQUAL(err, modelnet::kNifLifecycleReceipt);
    BOOST_CHECK(life.Find(request.attempt) == nullptr);
    BOOST_CHECK(!life.authority_from_receipt());

    modelnet::NifLifecycle loaded;
    BOOST_CHECK(!loaded.Reload(m_path_root, request.attempt, err));
    BOOST_CHECK_EQUAL(err, modelnet::kNifLifecycleJournal);
    BOOST_CHECK(loaded.Find(request.attempt) == nullptr);
    ExpectQuiet(life);
}

BOOST_AUTO_TEST_CASE(empty_attempt_stores_nothing)
{
    modelnet::NifLifecycle life;
    modelnet::NifRequestRecord request = SampleRequest();
    request.attempt.clear();
    std::string err = "prior";

    BOOST_CHECK(!life.Admit(m_path_root, request, false, err));
    BOOST_CHECK_EQUAL(err, modelnet::kNifLifecycleAttempt);
    BOOST_CHECK(life.Find(request.attempt) == nullptr);
    ExpectQuiet(life);
}

BOOST_AUTO_TEST_SUITE_END()
