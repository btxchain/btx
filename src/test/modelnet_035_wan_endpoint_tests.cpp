// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/realm_channel.h>
#include <crypto/hex_base.h>
#include <crypto/sha384.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_035_wan_endpoint_tests, BasicTestingSetup)

namespace {

std::string FileText(const fs::path& path)
{
    std::ifstream in(path);
    std::string text;
    char buf[256];
    while (in.read(buf, sizeof(buf)) || in.gcount() > 0) {
        text.append(buf, static_cast<std::size_t>(in.gcount()));
    }
    return text;
}

std::string Sha384Hex(const std::string& text)
{
    CSHA384 hasher;
    if (!text.empty()) {
        hasher.Write(reinterpret_cast<const unsigned char*>(text.data()), text.size());
    }
    unsigned char out[CSHA384::OUTPUT_SIZE];
    hasher.Finalize(out);
    return HexStr(Span<const unsigned char>(out, CSHA384::OUTPUT_SIZE));
}

void WriteFile(const fs::path& path, const std::string& body)
{
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    BOOST_REQUIRE(out);
    out << body;
    BOOST_REQUIRE(out);
}

void PutOctal(char* dest, std::size_t width, uint64_t value)
{
    std::memset(dest, 0, width);
    if (width == 0) return;
    for (std::size_t i = width - 1; i-- > 0;) {
        dest[i] = static_cast<char>('0' + static_cast<unsigned>(value & 7u));
        value >>= 3;
    }
}

unsigned HeaderSum(const char* header)
{
    unsigned sum = 0;
    for (std::size_t i = 0; i < 512; ++i) {
        const unsigned char byte = (i >= 148 && i < 156) ? static_cast<unsigned char>(' ') : static_cast<unsigned char>(header[i]);
        sum += byte;
    }
    return sum;
}

void PutChecksum(char* header)
{
    for (int i = 148; i < 156; ++i) header[i] = ' ';
    unsigned sum = HeaderSum(header);
    for (int i = 5; i >= 0; --i) {
        header[148 + i] = static_cast<char>('0' + (sum & 7u));
        sum >>= 3;
    }
    header[154] = '\0';
    header[155] = ' ';
}

struct RawMember {
    std::string name;
    char typeflag{'0'};
    std::string data;
    uint64_t declared_size{0};
    bool header_only{false};
};

void WriteRawTar(const fs::path& path, const std::vector<RawMember>& members, bool end_blocks)
{
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    BOOST_REQUIRE(out);
    for (const RawMember& member : members) {
        std::array<char, 512> header{};
        BOOST_REQUIRE(member.name.size() <= 100);
        std::memcpy(header.data(), member.name.data(), member.name.size());
        PutOctal(header.data() + 100, 8, member.typeflag == '5' ? 0755u : 0644u);
        PutOctal(header.data() + 108, 8, 0);
        PutOctal(header.data() + 116, 8, 0);
        const uint64_t size = member.header_only ? member.declared_size : member.data.size();
        PutOctal(header.data() + 124, 12, size);
        PutOctal(header.data() + 136, 12, 0);
        header[156] = member.typeflag;
        std::memcpy(header.data() + 257, "ustar", 5);
        header[262] = '\0';
        header[263] = '0';
        header[264] = '0';
        PutOctal(header.data() + 329, 8, 0);
        PutOctal(header.data() + 337, 8, 0);
        PutChecksum(header.data());
        out.write(header.data(), static_cast<std::streamsize>(header.size()));
        if (!member.header_only) {
            out.write(member.data.data(), static_cast<std::streamsize>(member.data.size()));
            const std::size_t pad = (512 - (member.data.size() % 512)) % 512;
            if (pad != 0) {
                std::array<char, 512> zeros{};
                out.write(zeros.data(), static_cast<std::streamsize>(pad));
            }
        }
    }
    if (end_blocks) {
        std::array<char, 1024> zeros{};
        out.write(zeros.data(), static_cast<std::streamsize>(zeros.size()));
    }
    BOOST_REQUIRE(out);
}

uint64_t ParseOctal(const char* data, std::size_t width)
{
    uint64_t value = 0;
    bool digits = false;
    for (std::size_t i = 0; i < width; ++i) {
        const unsigned char c = static_cast<unsigned char>(data[i]);
        if (c == '\0' || c == ' ') {
            if (digits) break;
            continue;
        }
        if (c < '0' || c > '7') return 0;
        digits = true;
        value = (value << 3) + static_cast<uint64_t>(c - '0');
    }
    return value;
}

struct ListedMember {
    std::string name;
    char typeflag{0};
    std::string data;
};

struct TarListing {
    std::vector<ListedMember> members;
    bool ended{false};
};

TarListing ListTar(const fs::path& path)
{
    TarListing listing;
    std::ifstream in(path, std::ios::binary);
    BOOST_REQUIRE(in);
    int zero_blocks = 0;
    while (zero_blocks < 2) {
        char header[512];
        in.read(header, 512);
        if (in.gcount() != 512) break;
        bool all_zero = true;
        for (char byte : header) {
            if (byte != 0) {
                all_zero = false;
                break;
            }
        }
        if (all_zero) {
            ++zero_blocks;
            continue;
        }
        zero_blocks = 0;
        ListedMember member;
        member.typeflag = header[156];
        std::size_t name_len = 0;
        while (name_len < 100 && header[name_len] != '\0') ++name_len;
        std::size_t prefix_len = 0;
        while (prefix_len < 155 && header[345 + prefix_len] != '\0') ++prefix_len;
        member.name.assign(header, name_len);
        if (prefix_len != 0) member.name = std::string(header + 345, prefix_len) + "/" + member.name;
        const uint64_t size = ParseOctal(header + 124, 12);
        member.data.resize(static_cast<std::size_t>(size));
        if (size != 0) {
            in.read(member.data.data(), static_cast<std::streamsize>(size));
            BOOST_REQUIRE_EQUAL(static_cast<std::uint64_t>(in.gcount()), size);
        }
        const uint64_t pad = (512 - (size % 512)) % 512;
        if (pad != 0) {
            std::array<char, 512> junk{};
            in.read(junk.data(), static_cast<std::streamsize>(pad));
            BOOST_REQUIRE_EQUAL(static_cast<std::uint64_t>(in.gcount()), pad);
        }
        listing.members.push_back(std::move(member));
    }
    listing.ended = zero_blocks == 2;
    return listing;
}

} // namespace

BOOST_AUTO_TEST_CASE(endpoint_lifecycle_states)
{
    modelnet::RealmRollout roll;
    std::string err;
    const std::array<const char*, 10> states = {
        "DISCOVERED", "FETCHING", "STAGED", "VERIFIED", "CANARY",
        "ACTIVE", "PAUSED", "FAILED", "ROLLED_BACK", "UNKNOWN",
    };
    for (const char* state : states) {
        const std::string endpoint = std::string("ep-") + state;
        BOOST_REQUIRE(roll.ObserveEndpoint(endpoint, state, err));
        BOOST_CHECK(err.empty());
        BOOST_CHECK_EQUAL(roll.EndpointState(endpoint), state);
    }

    const std::array<const char*, 5> rejected = {"HEALTHY", "UNHEALTHY", "OFFLINE", "verified", ""};
    for (const char* state : rejected) {
        BOOST_CHECK(!roll.ObserveEndpoint("ghost", state, err));
        BOOST_CHECK_EQUAL(err, "BTX035_OBSERVE");
        BOOST_CHECK(roll.EndpointState("ghost").empty());
    }
    BOOST_CHECK(!roll.ObserveEndpoint("", "UNKNOWN", err));
    BOOST_CHECK_EQUAL(err, "BTX035_OBSERVE");

    BOOST_REQUIRE(roll.Observe("fleet-1", "HEALTHY", err));
    BOOST_REQUIRE(roll.ObserveEndpoint("fleet-1", "DISCOVERED", err));
    BOOST_CHECK_EQUAL(roll.FleetStatus().healthy, 1);
    BOOST_CHECK_EQUAL(roll.FleetStatus().unhealthy, 0);
    BOOST_CHECK_EQUAL(roll.FleetStatus().unknown, 0);
    BOOST_CHECK_EQUAL(roll.EndpointState("fleet-1"), "DISCOVERED");

    BOOST_CHECK(!roll.MarkVerified("missing", err));
    BOOST_CHECK_EQUAL(err, "BTX035_OBSERVE");
    BOOST_CHECK(!roll.MarkActive("missing", err));
    BOOST_CHECK_EQUAL(err, "BTX035_HEALTH");

    BOOST_REQUIRE(roll.ObserveEndpoint("edge", "DISCOVERED", err));
    BOOST_CHECK(!roll.MarkTransportComplete("edge", "VERIFIED", err));
    BOOST_CHECK_EQUAL(err, "BTX035_OBSERVE");
    BOOST_CHECK_EQUAL(roll.EndpointState("edge"), "DISCOVERED");
    BOOST_CHECK(!roll.MarkTransportComplete("edge", "ACTIVE", err));
    BOOST_CHECK_EQUAL(err, "BTX035_OBSERVE");
    BOOST_CHECK_EQUAL(roll.EndpointState("edge"), "DISCOVERED");
    BOOST_CHECK(!roll.MarkTransportComplete("edge", "DISCOVERED", err));
    BOOST_CHECK_EQUAL(err, "BTX035_OBSERVE");
    BOOST_CHECK_EQUAL(roll.EndpointState("edge"), "DISCOVERED");
    BOOST_CHECK(!roll.MarkTransportComplete("new-edge", "VERIFIED", err));
    BOOST_CHECK(roll.EndpointState("new-edge").empty());
    BOOST_CHECK(!roll.MarkTransportComplete("new-edge", "ACTIVE", err));
    BOOST_CHECK(roll.EndpointState("new-edge").empty());

    BOOST_REQUIRE(roll.MarkTransportComplete("edge", "FETCHING", err));
    BOOST_CHECK_EQUAL(roll.EndpointState("edge"), "FETCHING");
    BOOST_CHECK(!roll.MarkActive("edge", err));
    BOOST_CHECK_EQUAL(err, "BTX035_HEALTH");
    BOOST_CHECK_EQUAL(roll.EndpointState("edge"), "FETCHING");
    BOOST_REQUIRE(roll.MarkTransportComplete("edge", "STAGED", err));
    BOOST_CHECK_EQUAL(roll.EndpointState("edge"), "STAGED");
    BOOST_CHECK(!roll.MarkActive("edge", err));
    BOOST_CHECK_EQUAL(err, "BTX035_HEALTH");
    BOOST_CHECK_EQUAL(roll.EndpointState("edge"), "STAGED");

    BOOST_REQUIRE(roll.MarkVerified("edge", err));
    BOOST_CHECK_EQUAL(roll.EndpointState("edge"), "VERIFIED");
    BOOST_REQUIRE(roll.MarkActive("edge", err));
    BOOST_CHECK_EQUAL(roll.EndpointState("edge"), "ACTIVE");

    BOOST_REQUIRE(roll.ObserveEndpoint("canary-edge", "CANARY", err));
    BOOST_REQUIRE(roll.MarkActive("canary-edge", err));
    BOOST_CHECK_EQUAL(roll.EndpointState("canary-edge"), "ACTIVE");

    BOOST_REQUIRE(roll.ObserveEndpoint("paused-edge", "PAUSED", err));
    BOOST_CHECK(!roll.MarkActive("paused-edge", err));
    BOOST_CHECK_EQUAL(err, "BTX035_HEALTH");
    BOOST_CHECK_EQUAL(roll.EndpointState("paused-edge"), "PAUSED");
    BOOST_REQUIRE(roll.ObserveEndpoint("silent-edge", "UNKNOWN", err));
    BOOST_CHECK(!roll.MarkActive("silent-edge", err));
    BOOST_CHECK_EQUAL(err, "BTX035_HEALTH");
    BOOST_CHECK_EQUAL(roll.EndpointState("silent-edge"), "UNKNOWN");
}

BOOST_AUTO_TEST_CASE(generation_pointer_and_readers)
{
    modelnet::RealmRollout roll;
    std::string err;
    const fs::path not_created = m_path_root / "gen-a";
    BOOST_CHECK(!roll.StageGeneration("..", m_path_root / "should-not", err));
    BOOST_CHECK_EQUAL(err, "BTX035_PATH_UNSAFE");
    BOOST_CHECK(!fs::exists(m_path_root / "should-not"));
    BOOST_CHECK(!roll.StageGeneration("", {}, err));
    BOOST_CHECK_EQUAL(err, "BTX035_POLICY");

    BOOST_REQUIRE(roll.StageGeneration("gen-a", {}, err));
    BOOST_CHECK(roll.GenerationStaged("gen-a"));
    BOOST_CHECK(!fs::exists(not_created));
    BOOST_CHECK(!roll.GenerationStaged("gen-b"));
    BOOST_CHECK(!roll.ActivateGeneration("missing", true, true, err));
    BOOST_CHECK_EQUAL(err, "BTX035_POLICY");
    BOOST_CHECK(roll.ActiveGeneration().empty());

    const fs::path on_disk = m_path_root / "gen-b-dir";
    BOOST_REQUIRE(roll.StageGeneration("gen-b", on_disk, err));
    BOOST_CHECK(fs::is_directory(on_disk));
    BOOST_CHECK(!roll.ActivateGeneration("gen-a", false, true, err));
    BOOST_CHECK_EQUAL(err, "BTX035_HEALTH");
    BOOST_CHECK(roll.ActiveGeneration().empty());
    BOOST_CHECK(roll.PreviousGeneration().empty());
    BOOST_CHECK(!roll.ActivateGeneration("gen-a", true, false, err));
    BOOST_CHECK_EQUAL(err, "BTX035_HEALTH");
    BOOST_CHECK(roll.ActiveGeneration().empty());

    BOOST_REQUIRE(roll.ActivateGeneration("gen-a", true, true, err));
    BOOST_CHECK_EQUAL(roll.ActiveGeneration(), "gen-a");
    BOOST_CHECK(roll.PreviousGeneration().empty());
    BOOST_REQUIRE(roll.RetainReader("session-1", "gen-a", err));
    BOOST_CHECK(!roll.RetainReader("", "gen-a", err));
    BOOST_CHECK_EQUAL(err, "BTX035_POLICY");

    BOOST_REQUIRE(roll.ActivateGeneration("gen-b", true, true, err));
    BOOST_CHECK_EQUAL(roll.ActiveGeneration(), "gen-b");
    BOOST_CHECK_EQUAL(roll.PreviousGeneration(), "gen-a");
    const std::vector<std::string> readers = roll.ReadersOf(roll.PreviousGeneration());
    BOOST_REQUIRE_EQUAL(readers.size(), std::size_t{1});
    BOOST_CHECK_EQUAL(readers.at(0), "session-1");
    BOOST_CHECK(roll.ReadersOf("gen-b").empty());

    BOOST_CHECK(!roll.ActivateGeneration("gen-a", true, true, err));
    BOOST_CHECK_EQUAL(err, "BTX035_ROLLBACK");
    BOOST_CHECK_EQUAL(roll.ActiveGeneration(), "gen-b");
    BOOST_CHECK_EQUAL(roll.PreviousGeneration(), "gen-a");
    const std::vector<std::string> still = roll.ReadersOf("gen-a");
    BOOST_REQUIRE_EQUAL(still.size(), std::size_t{1});
    BOOST_CHECK_EQUAL(still.at(0), "session-1");

    const fs::path later = m_path_root / "gen-a-later";
    BOOST_REQUIRE(roll.StageGeneration("gen-a", later, err));
    BOOST_CHECK(fs::is_directory(later));
    BOOST_CHECK(!roll.ActivateGeneration("gen-a", false, false, err));
    BOOST_CHECK_EQUAL(err, "BTX035_ROLLBACK");
    BOOST_CHECK_EQUAL(roll.ActiveGeneration(), "gen-b");
    BOOST_CHECK_EQUAL(roll.PreviousGeneration(), "gen-a");
    const std::vector<std::string> drained = roll.ReadersOf(roll.PreviousGeneration());
    BOOST_REQUIRE_EQUAL(drained.size(), std::size_t{1});
    BOOST_CHECK_EQUAL(drained.at(0), "session-1");
}

BOOST_AUTO_TEST_CASE(frozen_target_merkle_root)
{
    modelnet::RealmRollout roll;
    std::string err;
    BOOST_CHECK(roll.StatusRoot().empty());
    BOOST_CHECK(!roll.AddDevice("z", err));
    BOOST_CHECK_EQUAL(err, "BTX035_POLICY");
    BOOST_CHECK(roll.FreezeTargetSet({"a", ""}, err).empty());
    BOOST_CHECK_EQUAL(err, "BTX035_POLICY");
    BOOST_CHECK(roll.StatusRoot().empty());
    BOOST_CHECK(!roll.FrozenTarget("a"));

    const std::string expected = Sha384Hex("a\nb");
    const std::string root = roll.FreezeTargetSet({"b", "a", "a"}, err);
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(root, expected);
    BOOST_CHECK_EQUAL(root.size(), std::size_t{96});
    BOOST_CHECK_EQUAL(roll.StatusRoot(), expected);
    BOOST_CHECK(roll.FrozenTarget("a"));
    BOOST_CHECK(roll.FrozenTarget("b"));
    BOOST_CHECK(!roll.FrozenTarget("c"));
    BOOST_CHECK(roll.LateEnrollment().empty());

    BOOST_REQUIRE(roll.AddDevice("c", err));
    BOOST_CHECK_EQUAL(roll.StatusRoot(), expected);
    BOOST_CHECK(!roll.FrozenTarget("c"));
    BOOST_CHECK(roll.FrozenTarget("a"));
    const std::vector<std::string> late = roll.LateEnrollment();
    BOOST_REQUIRE_EQUAL(late.size(), std::size_t{1});
    BOOST_CHECK_EQUAL(late.at(0), "c");

    BOOST_REQUIRE(roll.AddDevice("a", err));
    BOOST_CHECK_EQUAL(roll.LateEnrollment().size(), std::size_t{1});
    BOOST_CHECK_EQUAL(roll.StatusRoot(), expected);

    BOOST_CHECK_EQUAL(roll.FreezeTargetSet({"b", "a"}, err), expected);
    BOOST_CHECK(roll.FreezeTargetSet({"a", "b", "c"}, err).empty());
    BOOST_CHECK_EQUAL(err, "BTX035_POLICY");
    BOOST_CHECK_EQUAL(roll.StatusRoot(), expected);
    BOOST_CHECK(!roll.FrozenTarget("c"));
    BOOST_CHECK_EQUAL(roll.LateEnrollment().at(0), "c");
}

BOOST_AUTO_TEST_CASE(snapshot_does_not_invent_sequence)
{
    modelnet::RealmRollout roll;
    std::string err;
    BOOST_REQUIRE(roll.PublishChannel("realm", 0, "h0", err));
    BOOST_REQUIRE(roll.PublishChannel("realm", 1, "h1", err));
    BOOST_REQUIRE(roll.PublishChannel("realm", 2, "h2", err));
    BOOST_REQUIRE(roll.AdvanceRing("realm", "policy", "policy", 0, err));
    BOOST_CHECK(!roll.RestoreBackup(1, 2, err));
    BOOST_CHECK_EQUAL(err, "BTX035_ROLLBACK");
    BOOST_CHECK_EQUAL(roll.CurrentSequence(), static_cast<int64_t>(2));

    BOOST_CHECK(!roll.ReplaceLocalSnapshot("realm", 1, "old-body", err));
    BOOST_CHECK_EQUAL(err, "BTX035_ROLLBACK");
    BOOST_CHECK_EQUAL(roll.ChannelSequence("realm"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(roll.ChannelBody("realm"), "h2");
    BOOST_CHECK_EQUAL(roll.CurrentSequence(), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(roll.RingGeneration("realm"), static_cast<int64_t>(1));

    BOOST_REQUIRE(roll.ReplaceLocalSnapshot("realm", 2, "snap-2", err));
    BOOST_CHECK_EQUAL(roll.ChannelSequence("realm"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(roll.ChannelBody("realm"), "snap-2");
    BOOST_CHECK_EQUAL(roll.RingGeneration("realm"), static_cast<int64_t>(1));

    BOOST_REQUIRE(roll.ReplaceLocalSnapshot("realm", 6, "snap-6", err));
    BOOST_CHECK_EQUAL(roll.ChannelSequence("realm"), static_cast<int64_t>(6));
    BOOST_CHECK_EQUAL(roll.ChannelBody("realm"), "snap-6");
    BOOST_CHECK_EQUAL(roll.RingGeneration("realm"), static_cast<int64_t>(1));
    BOOST_CHECK(!roll.PublishChannel("realm", 6, "again", err));
    BOOST_CHECK_EQUAL(err, "BTX035_STALE");
    BOOST_CHECK_EQUAL(roll.ChannelSequence("realm"), static_cast<int64_t>(6));
    BOOST_REQUIRE(roll.PublishChannel("realm", 7, "next", err));
    BOOST_CHECK_EQUAL(roll.ChannelSequence("realm"), static_cast<int64_t>(7));

    modelnet::RealmRollout restored;
    BOOST_REQUIRE(restored.ReplaceLocalSnapshot("realm", 4, "from-backup", err));
    BOOST_CHECK_EQUAL(restored.ChannelSequence("realm"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(restored.ChannelBody("realm"), "from-backup");
    BOOST_CHECK_EQUAL(restored.RingGeneration("realm"), static_cast<int64_t>(0));
    BOOST_CHECK(!restored.PublishChannel("realm", 3, "back", err));
    BOOST_CHECK_EQUAL(err, "BTX035_ROLLBACK");
    BOOST_CHECK_EQUAL(restored.ChannelSequence("realm"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(restored.ChannelBody("realm"), "from-backup");
    BOOST_REQUIRE(restored.PublishChannel("realm", 5, "after", err));
    BOOST_CHECK_EQUAL(restored.ChannelSequence("realm"), static_cast<int64_t>(5));
    BOOST_CHECK(!restored.ReplaceLocalSnapshot("realm", -1, "nope", err));
    BOOST_CHECK_EQUAL(err, "BTX035_ROLLBACK");
    BOOST_CHECK_EQUAL(restored.ChannelSequence("realm"), static_cast<int64_t>(5));
    BOOST_CHECK(!restored.ReplaceLocalSnapshot("", 5, "x", err));
    BOOST_CHECK_EQUAL(err, "BTX035_REALM");
}

BOOST_AUTO_TEST_CASE(portable_archive_entries)
{
    modelnet::RealmRollout roll;
    std::string err;
    const fs::path tree = m_path_root / "wan-tree";
    const fs::path nested = tree / "nested";
    BOOST_REQUIRE(fs::create_directories(nested));
    WriteFile(tree / "b.txt", "beta");
    WriteFile(nested / "c.txt", "cee");

    const fs::path archive = m_path_root / "wan.tar";
    BOOST_REQUIRE(roll.WritePortableArchive(tree, archive, err));
    const TarListing listing = ListTar(archive);
    BOOST_CHECK(listing.ended);
    BOOST_REQUIRE_EQUAL(listing.members.size(), 4U);
    BOOST_CHECK_EQUAL(listing.members[0].name, "b.txt");
    BOOST_CHECK_EQUAL(listing.members[0].typeflag, '0');
    BOOST_CHECK_EQUAL(listing.members[0].data, "beta");
    BOOST_CHECK_EQUAL(listing.members[1].name, "manifest");
    BOOST_CHECK_EQUAL(listing.members[1].typeflag, '0');
    BOOST_CHECK_EQUAL(listing.members[1].data, "b.txt\nnested\nnested/c.txt\n");
    BOOST_CHECK_EQUAL(listing.members[2].name, "nested/");
    BOOST_CHECK_EQUAL(listing.members[2].typeflag, '5');
    BOOST_CHECK_EQUAL(listing.members[3].name, "nested/c.txt");
    BOOST_CHECK_EQUAL(listing.members[3].typeflag, '0');
    BOOST_CHECK_EQUAL(listing.members[3].data, "cee");
    for (const ListedMember& member : listing.members) {
        BOOST_CHECK(member.typeflag == '0' || member.typeflag == '5');
        BOOST_CHECK(member.name.empty() || member.name.front() != '/');
        BOOST_CHECK(member.name.find("..") == std::string::npos);
    }
    BOOST_CHECK_EQUAL(fs::file_size(archive) % 512, 0);

    std::vector<std::string> paths;
    BOOST_REQUIRE(roll.ReadPortableArchive(archive, paths, err));
    BOOST_REQUIRE_EQUAL(paths.size(), 3U);
    BOOST_CHECK_EQUAL(paths[0], "b.txt");
    BOOST_CHECK_EQUAL(paths[1], "nested");
    BOOST_CHECK_EQUAL(paths[2], "nested/c.txt");

    const fs::path empty = m_path_root / "wan-empty";
    BOOST_REQUIRE(fs::create_directories(empty));
    const fs::path empty_tar = m_path_root / "empty.tar";
    BOOST_REQUIRE(roll.WritePortableArchive(empty, empty_tar, err));
    paths = {"stale"};
    BOOST_REQUIRE(roll.ReadPortableArchive(empty_tar, paths, err));
    BOOST_CHECK(paths.empty());

    const fs::path bad = m_path_root / "wan-bad";
    BOOST_REQUIRE(fs::create_directories(bad));
    WriteFile(bad / "ok.txt", "x");
    fs::create_symlink("outside", bad / "link");
    const fs::path kept = m_path_root / "kept.tar";
    WriteFile(kept, "keep-me");
    BOOST_CHECK(!roll.WritePortableArchive(bad, kept, err));
    BOOST_CHECK_EQUAL(err, "BTX035_PATH_UNSAFE");
    BOOST_CHECK_EQUAL(FileText(kept), "keep-me");

    const fs::path devdir = m_path_root / "wan-dev";
    BOOST_REQUIRE(fs::create_directories(devdir));
    const fs::path node = devdir / "node";
    BOOST_REQUIRE(mkfifo(node.c_str(), 0644) == 0);
    const fs::path devtar = m_path_root / "dev.tar";
    BOOST_CHECK(!roll.WritePortableArchive(devdir, devtar, err));
    BOOST_CHECK_EQUAL(err, "BTX035_PATH_UNSAFE");
    BOOST_CHECK(!fs::exists(devtar));

    const fs::path link_root = m_path_root / "tree-link";
    fs::create_symlink(tree, link_root);
    const fs::path link_tar = m_path_root / "link.tar";
    BOOST_CHECK(!roll.WritePortableArchive(link_root, link_tar, err));
    BOOST_CHECK_EQUAL(err, "BTX035_PATH_UNSAFE");
    BOOST_CHECK(!fs::exists(link_tar));

    const fs::path clash = m_path_root / "wan-manifest-clash";
    BOOST_REQUIRE(fs::create_directories(clash));
    WriteFile(clash / "manifest", "nope");
    const fs::path clash_tar = m_path_root / "clash.tar";
    BOOST_CHECK(!roll.WritePortableArchive(clash, clash_tar, err));
    BOOST_CHECK_EQUAL(err, "BTX035_PATH_UNSAFE");
    BOOST_CHECK(!fs::exists(clash_tar));

    const fs::path nul_tar = m_path_root / "nul.tar";
    WriteRawTar(nul_tar,
                {RawMember{"a.txt", '\0', "hi", 0, false}, RawMember{"manifest", '0', "a.txt\n", 0, false}},
                true);
    paths = {"stale"};
    BOOST_REQUIRE(roll.ReadPortableArchive(nul_tar, paths, err));
    BOOST_REQUIRE_EQUAL(paths.size(), 1U);
    BOOST_CHECK_EQUAL(paths[0], "a.txt");

    const fs::path abs_tar = m_path_root / "abs.tar";
    WriteRawTar(abs_tar, {RawMember{"/etc/passwd", '0', "", 0, false}}, false);
    paths = {"stale"};
    BOOST_CHECK(!roll.ReadPortableArchive(abs_tar, paths, err));
    BOOST_CHECK_EQUAL(err, "BTX035_PATH_UNSAFE");
    BOOST_CHECK(paths.empty());

    const fs::path dot_tar = m_path_root / "dotdot.tar";
    WriteRawTar(dot_tar, {RawMember{"../esc", '0', "", 0, false}}, false);
    BOOST_CHECK(!roll.ReadPortableArchive(dot_tar, paths, err));
    BOOST_CHECK_EQUAL(err, "BTX035_PATH_UNSAFE");
    BOOST_CHECK(paths.empty());

    const fs::path sym_tar = m_path_root / "sym.tar";
    WriteRawTar(sym_tar, {RawMember{"link", '2', "", 0, false}}, false);
    BOOST_CHECK(!roll.ReadPortableArchive(sym_tar, paths, err));
    BOOST_CHECK_EQUAL(err, "BTX035_PATH_UNSAFE");

    const fs::path dev_tar = m_path_root / "devnode.tar";
    WriteRawTar(dev_tar, {RawMember{"devnode", '4', "", 0, false}}, false);
    BOOST_CHECK(!roll.ReadPortableArchive(dev_tar, paths, err));
    BOOST_CHECK_EQUAL(err, "BTX035_PATH_UNSAFE");

    const fs::path dup_tar = m_path_root / "dup.tar";
    WriteRawTar(dup_tar,
                {RawMember{"a.txt", '0', "", 0, false}, RawMember{"a.txt", '0', "", 0, false}},
                false);
    BOOST_CHECK(!roll.ReadPortableArchive(dup_tar, paths, err));
    BOOST_CHECK_EQUAL(err, "BTX035_PATH_UNSAFE");

    const fs::path order_tar = m_path_root / "order.tar";
    WriteRawTar(order_tar,
                {RawMember{"b.txt", '0', "", 0, false}, RawMember{"a.txt", '0', "", 0, false}},
                false);
    BOOST_CHECK(!roll.ReadPortableArchive(order_tar, paths, err));
    BOOST_CHECK_EQUAL(err, "BTX035_BUNDLE");

    const fs::path big_tar = m_path_root / "big.tar";
    WriteRawTar(big_tar,
                {RawMember{"big.bin", '0', "", modelnet::RealmRollout::kPortableArchiveBudget + 1, true}},
                false);
    BOOST_CHECK(!roll.ReadPortableArchive(big_tar, paths, err));
    BOOST_CHECK_EQUAL(err, "BTX035_LIMIT_EXCEEDED");
    BOOST_CHECK(paths.empty());
}

BOOST_AUTO_TEST_CASE(bandwidth_caps_and_window)
{
    modelnet::BandwidthBudget unset;
    std::string err;
    BOOST_CHECK(!unset.AdmitFetch("site-a", "dev-1", 1, err));
    BOOST_CHECK_EQUAL(err, "BTX035_LIMIT_EXCEEDED");
    BOOST_CHECK_EQUAL(unset.AdmittedGlobal(), static_cast<uint64_t>(0));

    modelnet::BandwidthBudget paused_first;
    BOOST_REQUIRE(paused_first.SetDeploymentPaused(true, err));
    BOOST_CHECK(paused_first.WindowPaused());
    BOOST_CHECK(!paused_first.AdmitFetch("site-a", "dev-1", 1, err));
    BOOST_CHECK_EQUAL(err, "BTX035_PAUSED");
    BOOST_CHECK_EQUAL(paused_first.AdmittedGlobal(), static_cast<uint64_t>(0));

    modelnet::BandwidthBudget budget;
    BOOST_REQUIRE(budget.SetCaps(100, 60, 40, err));
    BOOST_REQUIRE(budget.AdmitFetch("site-a", "dev-1", 40, err));
    BOOST_CHECK_EQUAL(budget.AdmittedGlobal(), static_cast<uint64_t>(40));
    BOOST_CHECK_EQUAL(budget.AdmittedSite("site-a"), static_cast<uint64_t>(40));
    BOOST_CHECK_EQUAL(budget.AdmittedDevice("dev-1"), static_cast<uint64_t>(40));

    BOOST_CHECK(!budget.AdmitFetch("site-a", "dev-1", 1, err));
    BOOST_CHECK_EQUAL(err, "BTX035_LIMIT_EXCEEDED");
    BOOST_CHECK_EQUAL(budget.AdmittedDevice("dev-1"), static_cast<uint64_t>(40));
    BOOST_CHECK_EQUAL(budget.AdmittedSite("site-a"), static_cast<uint64_t>(40));
    BOOST_CHECK_EQUAL(budget.AdmittedGlobal(), static_cast<uint64_t>(40));

    BOOST_CHECK(!budget.AdmitFetch("site-a", "dev-2", 21, err));
    BOOST_CHECK_EQUAL(err, "BTX035_LIMIT_EXCEEDED");
    BOOST_CHECK_EQUAL(budget.AdmittedDevice("dev-2"), static_cast<uint64_t>(0));
    BOOST_CHECK_EQUAL(budget.AdmittedSite("site-a"), static_cast<uint64_t>(40));
    BOOST_CHECK_EQUAL(budget.AdmittedGlobal(), static_cast<uint64_t>(40));

    BOOST_REQUIRE(budget.AdmitFetch("site-b", "dev-3", 40, err));
    BOOST_CHECK_EQUAL(budget.AdmittedGlobal(), static_cast<uint64_t>(80));
    BOOST_CHECK_EQUAL(budget.AdmittedSite("site-b"), static_cast<uint64_t>(40));
    BOOST_CHECK(!budget.AdmitFetch("site-c", "dev-4", 21, err));
    BOOST_CHECK_EQUAL(err, "BTX035_LIMIT_EXCEEDED");
    BOOST_CHECK_EQUAL(budget.AdmittedGlobal(), static_cast<uint64_t>(80));
    BOOST_CHECK_EQUAL(budget.AdmittedSite("site-c"), static_cast<uint64_t>(0));
    BOOST_CHECK_EQUAL(budget.AdmittedDevice("dev-4"), static_cast<uint64_t>(0));

    BOOST_REQUIRE(budget.SetDeploymentPaused(true, err));
    BOOST_CHECK(!budget.AdmitFetch("site-c", "dev-4", 20, err));
    BOOST_CHECK_EQUAL(err, "BTX035_PAUSED");
    BOOST_CHECK_EQUAL(budget.AdmittedGlobal(), static_cast<uint64_t>(80));
    BOOST_CHECK_EQUAL(budget.AdmittedDevice("dev-4"), static_cast<uint64_t>(0));

    BOOST_REQUIRE(budget.SetDeploymentPaused(false, err));
    BOOST_CHECK(!budget.WindowPaused());
    BOOST_REQUIRE(budget.AdmitFetch("site-c", "dev-4", 20, err));
    BOOST_CHECK_EQUAL(budget.AdmittedGlobal(), static_cast<uint64_t>(100));
    BOOST_CHECK_EQUAL(budget.AdmittedSite("site-c"), static_cast<uint64_t>(20));
    BOOST_CHECK_EQUAL(budget.AdmittedDevice("dev-4"), static_cast<uint64_t>(20));
    BOOST_CHECK(!budget.AdmitFetch("site-c", "dev-4", 1, err));
    BOOST_CHECK_EQUAL(err, "BTX035_LIMIT_EXCEEDED");
    BOOST_CHECK_EQUAL(budget.AdmittedGlobal(), static_cast<uint64_t>(100));
}

BOOST_AUTO_TEST_SUITE_END()
