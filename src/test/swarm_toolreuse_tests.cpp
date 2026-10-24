// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_toolreuse.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_toolreuse_tests, BasicTestingSetup)

static const std::string kDigest(96, 'a');
static const std::string kOtherDigest = std::string(95, 'b') + "c";

static modelnet::SwarmToolRecord PublicRow()
{
    modelnet::SwarmToolRecord row;
    row.tool_id = "read_file";
    row.arg_digest = kDigest;
    row.tenant = "tenant-a";
    row.body = "file-bytes";
    row.public_result = true;
    return row;
}

BOOST_AUTO_TEST_CASE(empty_fields_are_tool)
{
    modelnet::SwarmToolBook book;
    std::string err = "prior";
    modelnet::SwarmToolRecord row = PublicRow();
    row.tool_id.clear();
    BOOST_CHECK(!book.Store(row, err));
    BOOST_CHECK_EQUAL(err, "TOOL");

    row = PublicRow();
    row.body.clear();
    BOOST_CHECK(!book.Store(row, err));
    BOOST_CHECK_EQUAL(err, "TOOL");

    const modelnet::SwarmToolReuse reuse = book.Reuse("", kDigest, "tenant-a", err);
    BOOST_CHECK(!reuse.reused);
    BOOST_CHECK(!reuse.executed);
    BOOST_CHECK(!reuse.bytes_moved);
    BOOST_CHECK(reuse.body.empty());
    BOOST_CHECK_EQUAL(reuse.code, "TOOL");
    BOOST_CHECK_EQUAL(err, "TOOL");
}

BOOST_AUTO_TEST_CASE(uppercase_digest_is_tool)
{
    modelnet::SwarmToolBook book;
    std::string err;
    modelnet::SwarmToolRecord row = PublicRow();
    row.arg_digest = std::string(96, 'A');
    BOOST_CHECK(!book.Store(row, err));
    BOOST_CHECK_EQUAL(err, "TOOL");

    const modelnet::SwarmToolReuse reuse = book.Reuse("read_file", row.arg_digest, "tenant-a", err);
    BOOST_CHECK(!reuse.reused);
    BOOST_CHECK(reuse.body.empty());
    BOOST_CHECK_EQUAL(reuse.code, "TOOL");
    BOOST_CHECK(!reuse.bytes_moved);
}

BOOST_AUTO_TEST_CASE(private_credential_and_unmarked_are_private_data)
{
    modelnet::SwarmToolBook book;
    std::string err;
    modelnet::SwarmToolRecord row = PublicRow();
    row.private_data = true;
    BOOST_CHECK(!book.Store(row, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");

    row = PublicRow();
    row.credential = true;
    BOOST_CHECK(!book.Store(row, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");

    row = PublicRow();
    row.public_result = false;
    BOOST_CHECK(!book.Store(row, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");

    const modelnet::SwarmToolReuse reuse = book.Reuse("read_file", kDigest, "tenant-a", err);
    BOOST_CHECK(!reuse.reused);
    BOOST_CHECK(reuse.body.empty());
    BOOST_CHECK_EQUAL(reuse.code, "TOOL_ABSENT");
    BOOST_CHECK_EQUAL(err, "TOOL_ABSENT");
    BOOST_CHECK(!reuse.executed);
    BOOST_CHECK(!reuse.bytes_moved);
}

BOOST_AUTO_TEST_CASE(executable_is_code_refused)
{
    modelnet::SwarmToolBook book;
    std::string err;
    modelnet::SwarmToolRecord row = PublicRow();
    row.executable = true;
    BOOST_CHECK(!book.Store(row, err));
    BOOST_CHECK_EQUAL(err, "CODE_REFUSED");

    const modelnet::SwarmToolReuse reuse = book.Reuse(row.tool_id, row.arg_digest, row.tenant, err);
    BOOST_CHECK(!reuse.reused);
    BOOST_CHECK(reuse.body.empty());
    BOOST_CHECK_EQUAL(err, "TOOL_ABSENT");
}

BOOST_AUTO_TEST_CASE(same_key_reuses_body_without_execution_or_transfer)
{
    modelnet::SwarmToolBook book;
    std::string err = "prior";
    BOOST_CHECK(book.Store(PublicRow(), err));
    BOOST_CHECK(err.empty());

    const modelnet::SwarmToolReuse reuse = book.Reuse("read_file", kDigest, "tenant-a", err);
    BOOST_CHECK(reuse.reused);
    BOOST_CHECK(!reuse.executed);
    BOOST_CHECK(!reuse.bytes_moved);
    BOOST_CHECK_EQUAL(reuse.body, "file-bytes");
    BOOST_CHECK_EQUAL(reuse.code, "OK");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(other_tenant_and_other_digest_are_absent)
{
    modelnet::SwarmToolBook book;
    std::string err;
    BOOST_REQUIRE(book.Store(PublicRow(), err));

    const modelnet::SwarmToolReuse other_tenant = book.Reuse("read_file", kDigest, "tenant-b", err);
    BOOST_CHECK(!other_tenant.reused);
    BOOST_CHECK(other_tenant.body.empty());
    BOOST_CHECK_EQUAL(other_tenant.code, "TOOL_ABSENT");
    BOOST_CHECK_EQUAL(err, "TOOL_ABSENT");
    BOOST_CHECK(!other_tenant.bytes_moved);

    const modelnet::SwarmToolReuse other_digest = book.Reuse("read_file", kOtherDigest, "tenant-a", err);
    BOOST_CHECK(!other_digest.reused);
    BOOST_CHECK(other_digest.body.empty());
    BOOST_CHECK_EQUAL(other_digest.code, "TOOL_ABSENT");
}

BOOST_AUTO_TEST_CASE(changed_body_conflicts_and_first_body_stays)
{
    modelnet::SwarmToolBook book;
    std::string err;
    BOOST_REQUIRE(book.Store(PublicRow(), err));

    modelnet::SwarmToolRecord again = PublicRow();
    again.body = "other-bytes";
    BOOST_CHECK(!book.Store(again, err));
    BOOST_CHECK_EQUAL(err, "CONFLICT");

    BOOST_CHECK(book.Store(PublicRow(), err));
    BOOST_CHECK(err.empty());

    const modelnet::SwarmToolReuse reuse = book.Reuse("read_file", kDigest, "tenant-a", err);
    BOOST_CHECK(reuse.reused);
    BOOST_CHECK_EQUAL(reuse.body, "file-bytes");
    BOOST_CHECK(!reuse.executed);
    BOOST_CHECK(!reuse.bytes_moved);
    BOOST_CHECK_EQUAL(reuse.code, "OK");
}

BOOST_AUTO_TEST_SUITE_END()
