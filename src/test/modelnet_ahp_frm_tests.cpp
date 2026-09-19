// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// AHP-FRM-01 .. AHP-FRM-12 native framing cases (Lane A 01-04/10 + Lane H remainder).
// Expected core_id from python3 reference/btx_package.py only — not native PASS.
// Bundle JSON uses BTXPKG_BUNDLE_FLAGS; PJSON1 packages keep flags=0.
// Coordinator owns CMakeLists.txt. No ninja in this lane.

#include <crypto/common.h>
#include <crypto/sha384.h>
#include <modelnet/crypto.h>
#include <modelnet/package_bundle.h>
#include <modelnet/package_core.h>
#include <modelnet/package_export.h>
#include <modelnet/package_pjson.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <fstream>
#include <iterator>
#include <limits>
#include <string>
#include <utility>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_ahp_frm_tests, BasicTestingSetup)

namespace {

constexpr const char* MODEL_AGENT_CORE_ID =
    "73e72380ef4959614ec34e0796a12d59bf4abf483c044b55b66c167d6bb6670db8ec3dd7d26d0e455a072288606e7b58";
constexpr const char* LEGACY_V1_CORE_ID =
    "a5a8601792b3eba3a5bb0dce11fc57b91aaa86549d40bf4d7d980c410924710174482281c7266a51b7c94ed7fc728b2a";

fs::path AgentPackageDir()
{
#ifdef MODELNET_AHP_FIXTURE_DIR
    return fs::PathFromString(MODELNET_AHP_FIXTURE_DIR);
#else
    return fs::PathFromString(std::string{__FILE__}).parent_path() / "data" / "agent-package";
#endif
}

std::vector<unsigned char> ReadBytes(const fs::path& p)
{
    std::ifstream in{p, std::ios::binary};
    BOOST_REQUIRE_MESSAGE(in, fs::PathToString(p));
    const std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    return std::vector<unsigned char>(raw.begin(), raw.end());
}

UniValue ReadJson(const fs::path& p)
{
    std::ifstream in{p};
    BOOST_REQUIRE_MESSAGE(in, fs::PathToString(p));
    const std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    UniValue v;
    BOOST_REQUIRE(v.read(raw));
    return v;
}

std::vector<unsigned char> HeaderWithLength(uint64_t n, uint32_t flags = 0)
{
    std::vector<unsigned char> h(68, 0);
    std::memcpy(h.data(), modelnet::BTXPKG_MAGIC, 8);
    WriteLE32(h.data() + 8, flags);
    WriteLE64(h.data() + 12, n);
    return h;
}

std::vector<unsigned char> FrameUtf8(const std::string& body)
{
    unsigned char digest[48];
    CSHA384 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(body.data()), body.size());
    hasher.Finalize(digest);
    std::vector<unsigned char> out(68 + body.size());
    std::memcpy(out.data(), modelnet::BTXPKG_MAGIC, 8);
    WriteLE32(out.data() + 8, 0);
    WriteLE64(out.data() + 12, body.size());
    std::memcpy(out.data() + 20, digest, 48);
    if (!body.empty()) {
        std::memcpy(out.data() + 68, body.data(), body.size());
    }
    return out;
}

UniValue NestArrays(int wraps)
{
    UniValue v(UniValue::VARR);
    for (int i = 0; i < wraps; ++i) {
        UniValue outer(UniValue::VARR);
        outer.push_back(v);
        v = std::move(outer);
    }
    return v;
}

} // namespace

BOOST_AUTO_TEST_CASE(ahp_frm_01_header_golden)
{
    const fs::path dir = AgentPackageDir();
    const auto golden = ReadBytes(dir / "model-agent.btx");
    BOOST_REQUIRE_GE(golden.size(), 68u);
    BOOST_CHECK_EQUAL(golden.size(), 5643u);

    UniValue payload = ReadJson(dir / "model-agent.json");
    std::vector<unsigned char> encoded;
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::EncodeBtxPackage(payload, encoded, err), err);
    BOOST_REQUIRE_EQUAL(encoded.size(), golden.size());
    BOOST_CHECK(std::equal(encoded.begin(), encoded.begin() + 68, golden.begin()));
    BOOST_CHECK(encoded == golden);

    BOOST_CHECK_EQUAL(std::memcmp(golden.data(), modelnet::BTXPKG_MAGIC, 8), 0);
    BOOST_CHECK_EQUAL(ReadLE32(golden.data() + 8), 0u);
    const uint64_t n = ReadLE64(golden.data() + 12);
    BOOST_CHECK_EQUAL(n, golden.size() - 68);
    BOOST_CHECK_EQUAL(golden[68], static_cast<unsigned char>('{'));

    modelnet::DecodedBtxPackage dec;
    BOOST_REQUIRE_MESSAGE(modelnet::DecodeBtxPackage(golden, dec, err), err);
    BOOST_CHECK_EQUAL(dec.flags, 0u);
    BOOST_CHECK_EQUAL(dec.payload_len, n);
    BOOST_CHECK_EQUAL(dec.core_version, 2);
    BOOST_CHECK_EQUAL(dec.package_core_id.Hex(), MODEL_AGENT_CORE_ID);
    BOOST_CHECK(std::equal(dec.frame_sha384.data.begin(), dec.frame_sha384.data.end(), golden.begin() + 20));

    modelnet::Digest48 cid;
    BOOST_REQUIRE_MESSAGE(modelnet::PackageCoreId(dec.core, cid, err), err);
    BOOST_CHECK_EQUAL(cid.Hex(), MODEL_AGENT_CORE_ID);

    modelnet::DecodedBtxPackage parsed;
    BOOST_REQUIRE_MESSAGE(modelnet::ParseAgentPackageFile(golden, parsed, err), err);
    BOOST_CHECK_EQUAL(parsed.package_core_id.Hex(), MODEL_AGENT_CORE_ID);
    BOOST_CHECK(parsed.core.exists("agent_handoff"));

    std::vector<unsigned char> canon;
    BOOST_REQUIRE_MESSAGE(modelnet::EncodePjson1(dec.core, canon, err), err);
    const auto domain = modelnet::DomainHash(modelnet::PACKAGE_CORE_V2_DOMAIN, canon);
    BOOST_CHECK(domain != dec.package_core_id);

    std::vector<unsigned char> bundle;
    BOOST_REQUIRE_MESSAGE(modelnet::EncodeBtxBundle(payload, bundle, err), err);
    BOOST_CHECK(bundle != encoded);
    BOOST_REQUIRE_GE(bundle.size(), 12U);
    BOOST_CHECK_EQUAL(ReadLE32(bundle.data() + 8), modelnet::BTXPKG_BUNDLE_FLAGS);
    BOOST_CHECK_EQUAL(ReadLE32(encoded.data() + 8), modelnet::BTXPKG_CORE_FLAGS);
    UniValue as_bundle;
    BOOST_REQUIRE_MESSAGE(modelnet::DecodeBtxBundle(bundle, as_bundle, err), err);
    BOOST_CHECK(!modelnet::DecodeBtxBundle(golden, as_bundle, err));
    BOOST_CHECK_EQUAL(err, "conflicting dual body");
}

BOOST_AUTO_TEST_CASE(ahp_frm_02_truncation_trailing)
{
    const auto golden = ReadBytes(AgentPackageDir() / "model-agent.btx");
    const size_t n = golden.size();
    const size_t cuts[] = {0, 1, 7, 8, 11, 12, 19, 20, 67, 68, 69, n / 2, n - 1};
    for (size_t cut : cuts) {
        if (cut >= n) continue;
        std::vector<unsigned char> slice(golden.begin(), golden.begin() + static_cast<std::ptrdiff_t>(cut));
        modelnet::DecodedBtxPackage dec;
        std::string err;
        BOOST_CHECK_MESSAGE(!modelnet::DecodeBtxPackage(slice, dec, err), cut);
        BOOST_CHECK(dec.err_code == "BAD_PACKAGE_MAGIC" || dec.err_code == "PACKAGE_TOO_LARGE" ||
                    dec.err_code == "NONCANONICAL_PAYLOAD");
        BOOST_CHECK(!dec.core.exists("agent_handoff"));
        BOOST_CHECK(!modelnet::ParseAgentPackageFile(slice, dec, err));
    }
    auto trailing = golden;
    trailing.push_back(0x00);
    modelnet::DecodedBtxPackage dec;
    std::string err;
    BOOST_CHECK(!modelnet::DecodeBtxPackage(trailing, dec, err));
    BOOST_CHECK_EQUAL(dec.err_code, "BAD_PACKAGE_MAGIC");
    BOOST_CHECK(!dec.core.exists("documents"));

    auto flagged = golden;
    WriteLE32(flagged.data() + 8, 1);
    BOOST_CHECK(!modelnet::DecodeBtxPackage(flagged, dec, err));
    BOOST_CHECK_EQUAL(dec.err_code, "BAD_PACKAGE_MAGIC");
}

BOOST_AUTO_TEST_CASE(ahp_frm_03_length_bomb)
{
    auto bomb = HeaderWithLength(std::numeric_limits<uint64_t>::max());
    modelnet::DecodedBtxPackage dec;
    std::string err;
    BOOST_CHECK(!modelnet::DecodeBtxPackage(bomb, dec, err));
    BOOST_CHECK_EQUAL(dec.err_code, "PACKAGE_TOO_LARGE");
    BOOST_CHECK(!dec.payload.isObject());
    BOOST_CHECK(!modelnet::ParseAgentPackageFile(bomb, dec, err));
    BOOST_CHECK_EQUAL(dec.err_code, "PACKAGE_TOO_LARGE");

    bomb = HeaderWithLength(modelnet::BTX_PACKAGE_MAX_PAYLOAD + 1);
    BOOST_CHECK(!modelnet::DecodeBtxPackage(bomb, dec, err));
    BOOST_CHECK_EQUAL(dec.err_code, "PACKAGE_TOO_LARGE");

    // Tiny actual bytes with a huge claimed length must not allocate n.
    bomb.resize(76);
    WriteLE64(bomb.data() + 12, std::numeric_limits<uint64_t>::max());
    BOOST_CHECK(!modelnet::DecodeBtxPackage(bomb, dec, err));
    BOOST_CHECK_EQUAL(dec.err_code, "PACKAGE_TOO_LARGE");

    UniValue bundle_out;
    bomb = HeaderWithLength(std::numeric_limits<uint64_t>::max(), modelnet::BTXPKG_BUNDLE_FLAGS);
    BOOST_CHECK(!modelnet::DecodeBtxBundle(bomb, bundle_out, err));
    BOOST_CHECK_EQUAL(err, "flags/size/trailing");
    bomb.resize(76);
    WriteLE64(bomb.data() + 12, std::numeric_limits<uint64_t>::max());
    BOOST_CHECK(!modelnet::DecodeBtxBundle(bomb, bundle_out, err));
    BOOST_CHECK_EQUAL(err, "flags/size/trailing");
}

BOOST_AUTO_TEST_CASE(ahp_frm_04_digest_corruption)
{
    auto corrupted = ReadBytes(AgentPackageDir() / "model-agent.btx");
    BOOST_REQUIRE_GT(corrupted.size(), 68u);
    corrupted[68] ^= 0x01;
    modelnet::DecodedBtxPackage dec;
    std::string err;
    BOOST_CHECK(!modelnet::DecodeBtxPackage(corrupted, dec, err));
    BOOST_CHECK_EQUAL(dec.err_code, "NONCANONICAL_PAYLOAD");
    BOOST_CHECK(!dec.payload.isObject());
    BOOST_CHECK(!dec.core.exists("documents"));
    BOOST_CHECK(!dec.core.exists("agent_handoff"));
    BOOST_CHECK(!modelnet::ParseAgentPackageFile(corrupted, dec, err));
}

BOOST_AUTO_TEST_CASE(ahp_frm_10_core_v1_compatibility)
{
    const fs::path dir = AgentPackageDir();
    const auto golden = ReadBytes(dir / "legacy-core-v1.btx");
    BOOST_REQUIRE_GE(golden.size(), 68u);

    UniValue payload = ReadJson(dir / "legacy-core-v1.json");
    std::vector<unsigned char> encoded;
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::EncodeBtxPackage(payload, encoded, err), err);
    BOOST_CHECK(encoded == golden);

    modelnet::DecodedBtxPackage dec;
    BOOST_REQUIRE_MESSAGE(modelnet::DecodeBtxPackage(golden, dec, err), err);
    BOOST_CHECK_EQUAL(dec.core_version, 1);
    BOOST_CHECK(!dec.core.exists("agent_handoff"));
    BOOST_CHECK(!dec.core.exists("documents"));

    modelnet::DecodedBtxPackage parsed;
    BOOST_REQUIRE_MESSAGE(modelnet::ParseAgentPackageFile(golden, parsed, err), err);
    BOOST_CHECK_EQUAL(parsed.core_version, 1);
    BOOST_CHECK(!parsed.core.exists("agent_handoff"));

    std::string code;
    BOOST_CHECK(!modelnet::ValidateAgentPackageCore(parsed.core, code, err));
    BOOST_CHECK_EQUAL(code, "UNSUPPORTED_CORE_VERSION");

    modelnet::Digest48 cid;
    BOOST_REQUIRE_MESSAGE(modelnet::PackageCoreId(parsed.core, cid, err), err);
    BOOST_CHECK(!cid.IsNull());
    BOOST_CHECK_EQUAL(cid.Hex(), parsed.package_core_id.Hex());
    BOOST_CHECK_EQUAL(cid.Hex(), LEGACY_V1_CORE_ID);
}

BOOST_AUTO_TEST_CASE(ahp_frm_05_canonical_number_language)
{
    const char* bad[] = {
        "{\"x\":1.0}",
        "{\"x\":1e1}",
        "{\"x\":1E2}",
        "{\"x\":NaN}",
        "{\"x\":Infinity}",
        "{\"x\":-Infinity}",
        "{\"x\":-0}",
        "{\"x\":9007199254740992}",
    };
    for (const char* raw : bad) {
        UniValue parsed;
        std::string err;
        const auto span =
            Span<const unsigned char>{reinterpret_cast<const unsigned char*>(raw), std::strlen(raw)};
        BOOST_CHECK_MESSAGE(!modelnet::DecodePjson1(span, parsed, err),
                            std::string("AHP-FRM-05: must reject ") + raw);
        auto framed = FrameUtf8(raw);
        modelnet::DecodedBtxPackage dec;
        BOOST_CHECK_MESSAGE(!modelnet::DecodeBtxPackage(framed, dec, err),
                            std::string("AHP-FRM-05 framed reject ") + raw);
        BOOST_CHECK(!dec.core.exists("documents"));
    }

    const auto golden = ReadBytes(AgentPackageDir() / "model-agent.btx");
    modelnet::DecodedBtxPackage pkg;
    std::string err;
    BOOST_REQUIRE(modelnet::DecodeBtxPackage(golden, pkg, err));
    BOOST_REQUIRE(pkg.core.exists("resources"));
    BOOST_REQUIRE_GT(pkg.core["resources"].size(), 0U);
    const UniValue& size = pkg.core["resources"][0]["size_bytes"];
    BOOST_REQUIRE_MESSAGE(size.isStr(), "AHP-FRM-05: size_bytes stays a decimal string");
    BOOST_CHECK_EQUAL(size.get_str(), "1048576");
}

BOOST_AUTO_TEST_CASE(ahp_frm_06_duplicate_and_unknown_fields)
{
    const char dup[] = "{\"x\":1,\"x\":2}";
    UniValue parsed;
    std::string err;
    BOOST_CHECK(!modelnet::DecodePjson1(
        Span<const unsigned char>{reinterpret_cast<const unsigned char*>(dup), sizeof(dup) - 1}, parsed, err));

    const auto golden = ReadBytes(AgentPackageDir() / "model-agent.btx");
    modelnet::DecodedBtxPackage pkg;
    BOOST_REQUIRE(modelnet::DecodeBtxPackage(golden, pkg, err));
    UniValue core = pkg.core;
    core.pushKV("installer_script", "echo hi");
    std::string code;
    BOOST_CHECK(!modelnet::ValidateAgentPackageCore(core, code, err));
    BOOST_CHECK_EQUAL(code, "NONCANONICAL_PAYLOAD");
}

BOOST_AUTO_TEST_CASE(ahp_frm_07_unicode_preservation)
{
    UniValue composed(UniValue::VOBJ);
    composed.pushKV("x", "é");
    UniValue decomposed(UniValue::VOBJ);
    decomposed.pushKV("x", "e\u0301");
    std::vector<unsigned char> a, b;
    std::string err;
    BOOST_REQUIRE(modelnet::EncodePjson1(composed, a, err));
    BOOST_REQUIRE(modelnet::EncodePjson1(decomposed, b, err));
    BOOST_CHECK_MESSAGE(a != b, "AHP-FRM-07: NFC and NFD retain distinct byte identities");
    UniValue round;
    BOOST_REQUIRE(modelnet::DecodePjson1(a, round, err));
    std::vector<unsigned char> again;
    BOOST_REQUIRE(modelnet::EncodePjson1(round, again, err));
    BOOST_CHECK(modelnet::Pjson1Equals(a, again));

    const char surr[] = "{\"x\":\"\\ud800\"}";
    UniValue u;
    BOOST_CHECK(!modelnet::DecodePjson1(
        Span<const unsigned char>{reinterpret_cast<const unsigned char*>(surr), sizeof(surr) - 1}, u, err));
    std::string mal = "{\"x\":\"";
    mal.push_back(static_cast<char>(0xff));
    mal += "\"}";
    BOOST_CHECK(!modelnet::DecodePjson1(
        Span<const unsigned char>{reinterpret_cast<const unsigned char*>(mal.data()), mal.size()}, u, err));
}

BOOST_AUTO_TEST_CASE(ahp_frm_08_depth_and_node_limits)
{
    std::string err;
    std::vector<unsigned char> depth32, depth33;
    BOOST_REQUIRE_MESSAGE(modelnet::EncodePjson1(NestArrays(32), depth32, err), err);
    BOOST_CHECK_MESSAGE(!modelnet::EncodePjson1(NestArrays(33), depth33, err),
                        "AHP-FRM-08: depth 33 must fail closed");
    UniValue decoded;
    // Spec max depth is 32. Fail closed if DecodePjson1 still uses bounty depth 16.
    BOOST_CHECK_MESSAGE(modelnet::DecodePjson1(depth32, decoded, err),
                        "AHP-FRM-08: depth 32 must be accepted by native PJSON1: " + err);

    UniValue ok_nodes(UniValue::VARR);
    for (int i = 0; i < 65535; ++i) ok_nodes.push_back(i % 2);
    UniValue over_nodes(UniValue::VARR);
    for (int i = 0; i < 65536; ++i) over_nodes.push_back(0);
    std::vector<unsigned char> nodes;
    BOOST_CHECK_MESSAGE(modelnet::EncodePjson1(ok_nodes, nodes, err),
                        "AHP-FRM-08: 65536 nodes (root+65535) must encode: " + err);
    BOOST_CHECK_MESSAGE(!modelnet::EncodePjson1(over_nodes, nodes, err),
                        "AHP-FRM-08: 65537 nodes must fail closed");
}

BOOST_AUTO_TEST_CASE(ahp_frm_09_canonical_serializer_parity)
{
    const auto golden = ReadBytes(AgentPackageDir() / "model-agent.btx");
    modelnet::DecodedBtxPackage pkg;
    std::string err;
    BOOST_REQUIRE(modelnet::DecodeBtxPackage(golden, pkg, err));
    std::vector<unsigned char> native;
    BOOST_REQUIRE_MESSAGE(modelnet::EncodeBtxPackage(pkg.payload, native, err), err);
    BOOST_CHECK_MESSAGE(native == golden, "AHP-FRM-09: native encode must match independent .btx vector");
    modelnet::Digest48 id;
    BOOST_REQUIRE(modelnet::PackageCoreId(pkg.core, id, err));
    BOOST_CHECK_EQUAL(id.Hex(), MODEL_AGENT_CORE_ID);

    const std::string pretty = pkg.payload.write(2);
    BOOST_REQUIRE(pretty.find('\n') != std::string::npos || pretty.find(' ') != std::string::npos);
    auto framed = FrameUtf8(pretty);
    modelnet::DecodedBtxPackage dec;
    BOOST_CHECK_MESSAGE(!modelnet::DecodeBtxPackage(framed, dec, err),
                        "AHP-FRM-09: pretty JSON must be rejected");
}

BOOST_AUTO_TEST_CASE(ahp_frm_11_core_v2_on_legacy_client)
{
    const auto v2 = ReadBytes(AgentPackageDir() / "model-agent.btx");
    const auto v1 = ReadBytes(AgentPackageDir() / "legacy-core-v1.btx");
    modelnet::DecodedBtxPackage updated;
    std::string err;
    BOOST_REQUIRE(modelnet::DecodeBtxPackage(v2, updated, err));
    BOOST_CHECK_EQUAL(updated.core_version, 2);
    std::string code;
    BOOST_REQUIRE_MESSAGE(modelnet::ValidateAgentPackageCore(updated.core, code, err), err);
    BOOST_REQUIRE(updated.core.exists("agent_handoff"));
    BOOST_REQUIRE(updated.core.exists("documents"));

    modelnet::DecodedBtxPackage legacy_pkg;
    BOOST_REQUIRE(modelnet::DecodeBtxPackage(v1, legacy_pkg, err));
    BOOST_CHECK(!modelnet::ValidateAgentPackageCore(legacy_pkg.core, code, err));
    BOOST_CHECK_EQUAL(code, "UNSUPPORTED_CORE_VERSION");

    UniValue forced = updated.core;
    forced.pushKV("version", 1);
    modelnet::Digest48 forced_id;
    if (modelnet::PackageCoreId(forced, forced_id, err)) {
        BOOST_CHECK_NE(forced_id.Hex(), updated.package_core_id.Hex());
    }
    BOOST_CHECK_NE(updated.package_core_id.Hex(), LEGACY_V1_CORE_ID);

    UniValue mag_in(UniValue::VOBJ);
    mag_in.pushKV("uri", "btx://model/test");
    mag_in.pushKV("copy_text", "btx://model/test");
    UniValue mag;
    BOOST_REQUIRE(modelnet::EncodeMagnetAnalog(mag_in, mag, err));
    BOOST_REQUIRE_EQUAL(mag["schema_version"].getInt<int>(), 2);
    BOOST_CHECK(!mag.exists("documents"));
    BOOST_CHECK(!mag.exists("agent_handoff"));
}

BOOST_AUTO_TEST_CASE(ahp_frm_12_critical_extension_collision)
{
    const auto bytes = ReadBytes(AgentPackageDir() / "model-agent.btx");
    modelnet::DecodedBtxPackage pkg;
    std::string err;
    BOOST_REQUIRE(modelnet::DecodeBtxPackage(bytes, pkg, err));
    UniValue ex = pkg.core["critical_extensions"];
    ex.push_back("UNKNOWN_CRITICAL");
    UniValue core = pkg.core;
    core.pushKV("critical_extensions", ex);
    std::string code;
    BOOST_CHECK(!modelnet::ValidateAgentPackageCore(core, code, err));
    BOOST_CHECK_EQUAL(code, "UNSUPPORTED_CRITICAL_EXTENSION");

    std::vector<unsigned char> canon;
    BOOST_REQUIRE(modelnet::EncodePjson1(pkg.core, canon, err));
    const auto hashed = modelnet::DomainHash(modelnet::PACKAGE_CORE_V2_DOMAIN, canon);
    BOOST_CHECK_NE(hashed.Hex(), pkg.package_core_id.Hex());
    BOOST_CHECK_EQUAL(pkg.package_core_id.Hex(), MODEL_AGENT_CORE_ID);
    BOOST_CHECK_EQUAL(static_cast<int>(modelnet::PackageCoreVersion::V2), 2);
}

BOOST_AUTO_TEST_SUITE_END()
