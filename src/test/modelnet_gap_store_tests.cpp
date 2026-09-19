// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// N-06  PutVerifiedPiece must not treat an existing .piece as verified.
// N-06  GetPiece must refuse files larger than PIECE_SIZE without unbounded reads.

#include <modelnet/store.h>
#include <test/util/setup_common.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <fstream>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_gap_store_tests, BasicTestingSetup)

namespace {

fs::path PiecePath(const modelnet::ModelStore& store, const modelnet::Digest48& artifact,
                   uint32_t file_index, uint32_t piece_index)
{
    return store.Root() / fs::PathFromString("artifacts") / fs::PathFromString(artifact.Hex()) /
           fs::PathFromString(std::to_string(file_index)) /
           fs::PathFromString(std::to_string(piece_index) + ".piece");
}

void WriteBytes(const fs::path& path, const std::vector<unsigned char>& bytes)
{
    fs::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    BOOST_REQUIRE(out);
    if (!bytes.empty()) {
        out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    }
    out.flush();
    BOOST_REQUIRE(out);
}

} // namespace

BOOST_AUTO_TEST_CASE(put_verified_piece_rejects_truncated_garbage_existing)
{
    const fs::path tmp = m_path_root / fs::PathFromString("n06-put");
    modelnet::ModelStore store{tmp, /*quota*/ 1 << 20};
    modelnet::Digest48 art{};
    art.data[0] = 0x06;
    const std::vector<unsigned char> good{'n', '0', '6', '-', 'p', 'i', 'e', 'c', 'e'};
    const auto leaf = modelnet::ChunkLeaf(0, good);
    const fs::path piece = PiecePath(store, art, 0, 0);
    std::string err;

    WriteBytes(piece, std::vector<unsigned char>{'g', 'a', 'r', 'b'});
    BOOST_CHECK(!store.PutVerifiedPiece(art, 0, 0, good, leaf, err));
    BOOST_CHECK(!err.empty());

    err.clear();
    WriteBytes(piece, std::vector<unsigned char>(good.size(), 'x'));
    BOOST_CHECK(!store.PutVerifiedPiece(art, 0, 0, good, leaf, err));
    BOOST_CHECK(!err.empty());

    std::error_code ec;
    std::filesystem::remove(piece, ec);
    err.clear();
    BOOST_REQUIRE_MESSAGE(store.PutVerifiedPiece(art, 0, 0, good, leaf, err), err);
    err.clear();
    BOOST_REQUIRE_MESSAGE(store.PutVerifiedPiece(art, 0, 0, good, leaf, err), err);
    std::vector<unsigned char> got;
    BOOST_REQUIRE(store.GetPiece(art, 0, 0, got, err));
    BOOST_CHECK(got == good);
}

BOOST_AUTO_TEST_CASE(get_piece_rejects_8mib_planted_file)
{
    const fs::path tmp = m_path_root / fs::PathFromString("n06-get");
    modelnet::ModelStore store{tmp, /*quota*/ 1 << 20};
    modelnet::Digest48 art{};
    art.data[0] = 0x16;
    const fs::path piece = PiecePath(store, art, 0, 0);
    fs::create_directories(piece.parent_path());
    {
        std::ofstream out(piece, std::ios::binary | std::ios::trunc);
        BOOST_REQUIRE(out);
        out.seekp(static_cast<std::streamoff>(8 * modelnet::MIB - 1));
        out.put('\0');
        BOOST_REQUIRE(out);
    }
    std::error_code ec;
    const auto planted = std::filesystem::file_size(piece, ec);
    BOOST_REQUIRE(!ec);
    BOOST_REQUIRE_EQUAL(static_cast<uint64_t>(planted), uint64_t{8} * modelnet::MIB);

    std::vector<unsigned char> out;
    std::string err;
    BOOST_CHECK(!store.GetPiece(art, 0, 0, out, err));
    BOOST_CHECK(!err.empty());
    BOOST_CHECK(out.empty());
}

BOOST_AUTO_TEST_SUITE_END()
