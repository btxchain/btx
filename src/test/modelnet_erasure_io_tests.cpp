// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// NETWORK-02 §15 per-stripe repair I/O. Global n is not sufficiency.
// Live WAN / 64-80 profile remain NONSHIPPING.

#include <crypto/hex_base.h>
#include <crypto/sha384.h>
#include <modelnet/erasure_manifest.h>
#include <modelnet/erasure_store.h>
#include <modelnet/io_executor.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <fstream>
#include <iterator>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_erasure_io_tests, BasicTestingSetup)

namespace {

modelnet::ErasureManifest MakeMan(int k, int n, const std::vector<std::vector<int>>& position_sets)
{
    modelnet::ErasureManifest m;
    m.profile = "test-k-n-io";
    m.data_shards = k;
    m.total_shards = n;
    m.shard_bytes = 4096;
    m.stripe_count = position_sets.size();
    m.final_real_piece_count = k;
    for (size_t i = 0; i < position_sets.size(); ++i) {
        modelnet::ErasureStripe s;
        s.stripe_index = static_cast<uint32_t>(i);
        s.positions = position_sets[i];
        m.stripes.push_back(std::move(s));
    }
    return m;
}

std::vector<unsigned char> Shard4096(unsigned char tag)
{
    return std::vector<unsigned char>(4096, tag);
}

std::string Sha384Hex(const std::vector<unsigned char>& bytes)
{
    unsigned char digest[CSHA384::OUTPUT_SIZE];
    CSHA384 hasher;
    hasher.Write(bytes.data(), bytes.size());
    hasher.Finalize(digest);
    return HexStr(Span<const unsigned char>{digest, CSHA384::OUTPUT_SIZE});
}

void WriteFile(const fs::path& p, const std::vector<unsigned char>& bytes)
{
    std::ofstream out(fs::PathToString(p), std::ios::binary);
    BOOST_REQUIRE(out);
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    BOOST_REQUIRE(out);
}

} // namespace

BOOST_AUTO_TEST_CASE(erasure_io_repair_stripe_from_files_sha384)
{
    using namespace modelnet;
    const fs::path tmp = m_path_root / "erasure-io";
    fs::create_directories(tmp);

    const auto data0 = Shard4096(0x11);
    const auto data1 = Shard4096(0x22);
    std::vector<std::vector<unsigned char>> coded;
    std::string err;
    BOOST_REQUIRE(EncodeShards({data0, data1}, 4, coded, err));
    BOOST_REQUIRE_EQUAL(coded.size(), 4U);

    WriteFile(tmp / "s0.bin", coded[0]);
    WriteFile(tmp / "s2.bin", coded[2]);

    const auto man = MakeMan(2, 4, {{0, 2}, {1, 3}});
    BOOST_CHECK(ErasureManifestReconstructable(man));

    const fs::path dest = tmp / "repaired.bin";
    BOOST_REQUIRE_MESSAGE(RepairStripeFromFiles(man,
                                                 {fs::PathToString(tmp / "s0.bin"), fs::PathToString(tmp / "s2.bin")},
                                                 {0, 2}, fs::PathToString(dest), err, 0),
                          err);

    std::ifstream in(fs::PathToString(dest), std::ios::binary);
    BOOST_REQUIRE(in);
    std::vector<unsigned char> got((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    std::vector<unsigned char> want = data0;
    want.insert(want.end(), data1.begin(), data1.end());
    BOOST_CHECK(got == want);
    BOOST_CHECK_EQUAL(Sha384Hex(got), Sha384Hex(want));
    WriteFile(dest, std::vector<unsigned char>(100, 0x00));
    BOOST_REQUIRE_MESSAGE(RepairStripeFromFiles(man,
                                                 {fs::PathToString(tmp / "s0.bin"), fs::PathToString(tmp / "s2.bin")},
                                                 {0, 2}, fs::PathToString(dest), err, 0),
                          err);
    std::ifstream in2(fs::PathToString(dest), std::ios::binary);
    BOOST_REQUIRE(in2);
    std::vector<unsigned char> got2((std::istreambuf_iterator<char>(in2)), std::istreambuf_iterator<char>());
    BOOST_CHECK(got2 == want);
}

BOOST_AUTO_TEST_CASE(erasure_io_global_n_is_not_sufficiency)
{
    using namespace modelnet;
    const fs::path tmp = m_path_root / "erasure-io-global";
    fs::create_directories(tmp);
    const auto data0 = Shard4096(0x33);
    const auto data1 = Shard4096(0x44);
    std::vector<std::vector<unsigned char>> coded;
    std::string err;
    BOOST_REQUIRE(EncodeShards({data0, data1}, 4, coded, err));
    WriteFile(tmp / "s0.bin", coded[0]);
    WriteFile(tmp / "s2.bin", coded[2]);

    const auto man = MakeMan(2, 4, {{0, 1, 2, 3}, {0}});
    BOOST_CHECK(!ErasureManifestReconstructable(man));
    BOOST_CHECK(!RepairStripeFromFiles(man,
                                      {fs::PathToString(tmp / "s0.bin"), fs::PathToString(tmp / "s2.bin")},
                                      {0, 2}, fs::PathToString(tmp / "nope.bin"), err));
    BOOST_CHECK(err.find("global n is not sufficiency") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(erasure_io_executor_bounds_reconstruct)
{
    using namespace modelnet;
    IoExecutor io(1);
    std::string err;
    BOOST_REQUIRE(io.Submit(err));
    BOOST_CHECK(!io.Submit(err));
    io.Complete();
    std::vector<std::vector<unsigned char>> data{{1, 2, 3, 4}, {5, 6, 7, 8}};
    std::vector<std::vector<unsigned char>> coded;
    BOOST_REQUIRE(io.Submit(err));
    BOOST_REQUIRE(EncodeShards(data, 4, coded, err));
    io.Complete();
    std::vector<std::vector<unsigned char>> rec;
    BOOST_REQUIRE(io.Submit(err));
    BOOST_REQUIRE(ReconstructShards({coded[0], coded[2]}, {0, 2}, 2, 4, rec, err));
    io.Complete();
    BOOST_REQUIRE_EQUAL(rec.size(), 2);
    BOOST_CHECK(rec[0] == data[0]);
    BOOST_CHECK(rec[1] == data[1]);
    BOOST_CHECK(!io.StatusJson()["io_uring"].get_bool());
}

BOOST_AUTO_TEST_SUITE_END()
