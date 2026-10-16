// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/lab_wire.h>
#include <univalue.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>

#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_035_wire_limit_tests, BasicTestingSetup)

namespace {

const char* SpecRoot()
{
    const char* spec = std::getenv("BTX035_SPEC");
    return spec == nullptr ? "" : spec;
}
const char* const kKind0 =
    "btx://pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0ae2uf";
const char* const kKind15 =
    "btx://p04w46h2at4w46h2at4w46h2at4w46h2at4w46h2at4w46h2at4w46h2at4w46h2at4w46h2at4w46kd5pzuz";

std::string Hex96(char c)
{
    return std::string(96, c);
}

std::string Upper(std::string s)
{
    for (char& ch : s) {
        if (ch >= 'a' && ch <= 'z') ch = static_cast<char>(ch - 'a' + 'A');
    }
    return s;
}

UniValue AsciiArray(int count, size_t len, char fill)
{
    UniValue arr(UniValue::VARR);
    const std::string item(len, fill);
    for (int i = 0; i < count; ++i) arr.push_back(item);
    return arr;
}

UniValue Ref(const std::string& kind, const std::string& digest)
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("kind", kind);
    obj.pushKV("digest48", digest);
    return obj;
}

} // namespace

BOOST_AUTO_TEST_CASE(wire003_canonical_json_and_wrapper_limits)
{
    std::string err;
    UniValue small(UniValue::VOBJ);
    small.pushKV("k", "v");
    BOOST_CHECK(modelnet::AcceptCanonicalEnvelope(small, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(modelnet::AcceptCompactJson(small.write(0, 0), err));
    BOOST_CHECK(err.empty());

    // 24 strings of 8187 bytes: canonical encoding is 196613 (> 196608) and
    // compact JSON is 196561 (<= 196608).
    const UniValue canon_over = AsciiArray(24, 8187, 'a');
    std::vector<unsigned char> canon;
    BOOST_REQUIRE(modelnet::CanonicalEncode(canon_over, canon, err));
    BOOST_CHECK(canon.size() > modelnet::CANONICAL_MAX_ENVELOPE_V11);
    const std::string canon_over_json = canon_over.write(0, 0);
    BOOST_CHECK(canon_over_json.size() <= modelnet::CANONICAL_MAX_ENVELOPE_V11);
    BOOST_CHECK(!modelnet::AcceptCanonicalEnvelope(canon_over, err));
    BOOST_CHECK_EQUAL(err, "BTX035_LIMIT_EXCEEDED");
    BOOST_CHECK(modelnet::AcceptCompactJson(canon_over_json, err));
    BOOST_CHECK(err.empty());

    // 12 strings of 8192 quotes: compact JSON escapes each quote, so JSON is
    // 196645 bytes while the canonical encoding stays under the envelope budget.
    const UniValue json_over = AsciiArray(12, 8192, '"');
    canon.clear();
    BOOST_REQUIRE(modelnet::CanonicalEncode(json_over, canon, err));
    BOOST_CHECK(canon.size() <= modelnet::CANONICAL_MAX_ENVELOPE_V11);
    const std::string json_over_text = json_over.write(0, 0);
    BOOST_CHECK(json_over_text.size() > modelnet::CANONICAL_MAX_ENVELOPE_V11);
    BOOST_CHECK(modelnet::AcceptCanonicalEnvelope(json_over, err));
    BOOST_CHECK(!modelnet::AcceptCompactJson(json_over_text, err));
    BOOST_CHECK_EQUAL(err, "BTX035_LIMIT_EXCEEDED");

    const std::string exact(std::string("\"") + std::string(modelnet::CANONICAL_MAX_ENVELOPE_V11 - 2, 'b') + "\"");
    BOOST_CHECK_EQUAL(exact.size(), modelnet::CANONICAL_MAX_ENVELOPE_V11);
    BOOST_CHECK(modelnet::AcceptCompactJson(exact, err));
    const std::string too_big(std::string("\"") + std::string(modelnet::CANONICAL_MAX_ENVELOPE_V11 - 1, 'c') + "\"");
    BOOST_CHECK(too_big.size() > modelnet::CANONICAL_MAX_ENVELOPE_V11);
    BOOST_CHECK(!modelnet::AcceptCompactJson(too_big, err));
    BOOST_CHECK_EQUAL(err, "BTX035_LIMIT_EXCEEDED");
    BOOST_CHECK(!modelnet::AcceptCompactJson("{", err));
    BOOST_CHECK_EQUAL(err, "BTX035_NONCANONICAL");

    BOOST_CHECK(modelnet::AcceptTransportWrapper(too_big, err));
    BOOST_CHECK(err.empty());
    const std::string wrapper_max(modelnet::CANONICAL_MAX_ENVELOPE, 'w');
    BOOST_CHECK_EQUAL(wrapper_max.size(), modelnet::CANONICAL_MAX_ENVELOPE);
    BOOST_CHECK(modelnet::AcceptTransportWrapper(wrapper_max, err));
    BOOST_CHECK(!modelnet::AcceptTransportWrapper(wrapper_max + "w", err));
    BOOST_CHECK_EQUAL(err, "BTX035_LIMIT_EXCEEDED");
}

BOOST_AUTO_TEST_CASE(wire003_manifest_rejected_whole_accepted_as_pages)
{
    std::string err;
    const std::string at_budget(modelnet::CANONICAL_MAX_ENVELOPE_V11, 'm');
    BOOST_CHECK_EQUAL(at_budget.size(), modelnet::CANONICAL_MAX_ENVELOPE_V11);
    BOOST_CHECK(modelnet::AcceptManifestBlob(at_budget, err));
    BOOST_CHECK(err.empty());

    const std::string over = at_budget + "x";
    BOOST_CHECK(!modelnet::AcceptManifestBlob(over, err));
    BOOST_CHECK_EQUAL(err, "BTX035_LIMIT_EXCEEDED");

    std::vector<std::string> pages;
    BOOST_CHECK(modelnet::SplitManifestPages(over, pages, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(pages.size(), 4u);
    std::string joined;
    for (const std::string& page : pages) {
        BOOST_CHECK(!page.empty());
        BOOST_CHECK(page.size() <= modelnet::MANIFEST_PAGE_BYTES);
        BOOST_CHECK(page.size() <= modelnet::CANONICAL_MAX_ENVELOPE_V11);
        BOOST_CHECK(modelnet::AcceptManifestBlob(page, err));
        BOOST_CHECK(err.empty());
        joined += page;
    }
    BOOST_CHECK_EQUAL(pages[0].size(), modelnet::MANIFEST_PAGE_BYTES);
    BOOST_CHECK_EQUAL(joined, over);

    pages.clear();
    BOOST_CHECK(modelnet::SplitManifestPages(at_budget, pages, err));
    BOOST_CHECK_EQUAL(pages.size(), 3u);
    for (const std::string& page : pages) {
        BOOST_CHECK_EQUAL(page.size(), modelnet::MANIFEST_PAGE_BYTES);
    }
}

BOOST_AUTO_TEST_CASE(wire004_canonical_uri_and_legacy_alias)
{
    std::string err;
    BOOST_CHECK(modelnet::CanonicalOutputUri(kKind0, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(modelnet::CanonicalOutputUri(kKind15, err));

    const std::string upper = Upper(kKind0);
    BOOST_CHECK(!modelnet::CanonicalOutputUri(upper, err));
    BOOST_CHECK_EQUAL(err, "BTX035_NONCANONICAL");
    BOOST_CHECK(!modelnet::CanonicalOutputUri(std::string(kKind0) + "?q=1", err));
    BOOST_CHECK_EQUAL(err, "BTX035_NONCANONICAL");
    BOOST_CHECK(!modelnet::CanonicalOutputUri(std::string(kKind0) + "#frag", err));
    BOOST_CHECK_EQUAL(err, "BTX035_NONCANONICAL");
    BOOST_CHECK(!modelnet::CanonicalOutputUri(std::string(kKind0) + "/", err));
    BOOST_CHECK_EQUAL(err, "BTX035_NONCANONICAL");
    BOOST_CHECK(!modelnet::CanonicalOutputUri(std::string(kKind0) + ".json", err));
    BOOST_CHECK_EQUAL(err, "BTX035_NONCANONICAL");
    BOOST_CHECK(!modelnet::CanonicalOutputUri(std::string(kKind15) + ".bin", err));
    BOOST_CHECK_EQUAL(err, "BTX035_NONCANONICAL");

    std::string canonical;
    BOOST_CHECK(modelnet::ParseLegacyInputUri(kKind0, canonical, err));
    BOOST_CHECK_EQUAL(canonical, kKind0);
    BOOST_CHECK(modelnet::ParseLegacyInputUri(upper + "/", canonical, err));
    BOOST_CHECK_EQUAL(canonical, kKind0);
    BOOST_CHECK(modelnet::ParseLegacyInputUri(std::string("btx:") + std::string(kKind0).substr(6), canonical, err));
    BOOST_CHECK_EQUAL(canonical, kKind0);
    BOOST_CHECK(modelnet::ParseLegacyInputUri(std::string(kKind15).substr(6), canonical, err));
    BOOST_CHECK_EQUAL(canonical, kKind15);
    BOOST_CHECK(modelnet::CanonicalOutputUri(canonical, err));

    canonical = "stale";
    BOOST_CHECK(!modelnet::ParseLegacyInputUri(std::string(kKind0) + ".json", canonical, err));
    BOOST_CHECK(canonical.empty());
    BOOST_CHECK_EQUAL(err, "BTX035_NONCANONICAL");
    BOOST_CHECK(!modelnet::ParseLegacyInputUri(std::string(kKind0) + "?x=1", canonical, err));
    BOOST_CHECK(canonical.empty());
    BOOST_CHECK(!modelnet::ParseLegacyInputUri(std::string(kKind0) + "#f", canonical, err));
    BOOST_CHECK(canonical.empty());
}

BOOST_AUTO_TEST_CASE(rev003_registry_kinds_and_resource_ref)
{
    if (std::getenv("BTX035_SPEC") == nullptr) {
        BOOST_TEST_MESSAGE("BTX035_SPEC is unset; skipping rev003_registry_kinds_and_resource_ref");
        return;
    }
    std::string err;
    UniValue registry;
    std::ifstream in(std::string(SpecRoot()) + "/schemas/resource_registry.json", std::ios::binary);
    BOOST_REQUIRE(in.good());
    std::stringstream ss;
    ss << in.rdbuf();
    BOOST_REQUIRE(registry.read(ss.str()));
    const UniValue& refs = registry["resource_refs"];
    BOOST_REQUIRE(refs.isArray());
    BOOST_REQUIRE_EQUAL(refs.size(), 16u);
    for (size_t i = 0; i < refs.size(); ++i) {
        std::string name;
        const int wire = refs[i]["wire_kind"].getInt<int>();
        BOOST_CHECK_EQUAL(wire, static_cast<int>(i));
        BOOST_CHECK(modelnet::RegistryWireKind(SpecRoot(), wire, name, err));
        BOOST_CHECK_EQUAL(name, refs[i]["kind"].get_str());
        BOOST_CHECK(err.empty());
    }
    std::string record_kind;
    BOOST_CHECK(modelnet::RegistryWireKind(SpecRoot(), 15, record_kind, err));
    BOOST_CHECK_EQUAL(record_kind, "RECORD");
    BOOST_CHECK(!modelnet::RegistryWireKind("spec/does-not-exist", 0, record_kind, err));
    BOOST_CHECK_EQUAL(err, "BTX035_SCHEMA");

    const std::string digest = Hex96('a');
    modelnet::ResourceRef out;
    BOOST_CHECK(modelnet::ParseResourceRef(Ref("MODEL", digest), out, err, SpecRoot()));
    BOOST_CHECK_EQUAL(out.kind, "MODEL");
    BOOST_CHECK_EQUAL(out.digest48, digest);
    BOOST_CHECK(out.record_type.empty());

    UniValue with_type = Ref("MODEL", digest);
    with_type.pushKV("record_type", "DatasetSnapshot");
    BOOST_CHECK(!modelnet::ParseResourceRef(with_type, out, err, SpecRoot()));
    BOOST_CHECK(out.kind.empty());
    BOOST_CHECK_EQUAL(err, "BTX035_SCHEMA");

    BOOST_CHECK(!modelnet::ParseResourceRef(Ref("RECORD", digest), out, err, SpecRoot()));
    BOOST_CHECK_EQUAL(err, "BTX035_SCHEMA");

    UniValue record = Ref("RECORD", digest);
    record.pushKV("record_type", "DatasetSnapshot");
    BOOST_CHECK(modelnet::ParseResourceRef(record, out, err, SpecRoot()));
    BOOST_CHECK_EQUAL(out.kind, "RECORD");
    BOOST_CHECK_EQUAL(out.record_type, "DatasetSnapshot");
    BOOST_CHECK_EQUAL(out.digest48, digest);

    const UniValue& descriptors = registry["record_descriptors"];
    BOOST_REQUIRE(descriptors.isArray());
    BOOST_REQUIRE(!descriptors.empty());
    for (const UniValue& row : descriptors.getValues()) {
        UniValue typed = Ref("RECORD", digest);
        typed.pushKV("record_type", row["record_type"].get_str());
        BOOST_CHECK(modelnet::ParseResourceRef(typed, out, err, SpecRoot()));
        BOOST_CHECK_EQUAL(out.record_type, row["record_type"].get_str());
        BOOST_CHECK_EQUAL(out.kind, "RECORD");
    }

    UniValue fake = Ref("RECORD", digest);
    fake.pushKV("record_type", "NotARealRecordType");
    BOOST_CHECK(!modelnet::ParseResourceRef(fake, out, err, SpecRoot()));
    BOOST_CHECK_EQUAL(err, "BTX035_SCHEMA");

    BOOST_CHECK(!modelnet::ParseResourceRef(Ref("DATASET", digest), out, err, SpecRoot()));
    BOOST_CHECK(out.kind.empty());
    BOOST_CHECK_EQUAL(err, "BTX035_SCHEMA");
    BOOST_CHECK(!modelnet::ParseResourceRef(Ref("GIT_SNAPSHOT", digest), out, err, SpecRoot()));
    BOOST_CHECK(!modelnet::ParseResourceRef(Ref("ENVIRONMENT", digest), out, err, SpecRoot()));
    BOOST_CHECK(!modelnet::ParseResourceRef(Ref("RESEARCH_CAPSULE", digest), out, err, SpecRoot()));
    BOOST_CHECK_EQUAL(err, "BTX035_SCHEMA");
    BOOST_CHECK(!modelnet::ParseResourceRef(Ref("model", digest), out, err, SpecRoot()));
    BOOST_CHECK(!modelnet::ParseResourceRef(Ref("MODEL", Hex96('A')), out, err, SpecRoot()));
    BOOST_CHECK_EQUAL(err, "BTX035_SCHEMA");

    UniValue extra = Ref("ARTIFACT", digest);
    extra.pushKV("note", "nope");
    BOOST_CHECK(!modelnet::ParseResourceRef(extra, out, err, SpecRoot()));
    BOOST_CHECK_EQUAL(err, "BTX035_OBJECT_KEYS");

    std::string canonical_kind;
    std::string record_type;
    BOOST_CHECK(modelnet::ParseLegacyKindAlias(SpecRoot(), "DATASET", canonical_kind, record_type, err));
    BOOST_CHECK_EQUAL(canonical_kind, "RECORD");
    BOOST_CHECK_EQUAL(record_type, "DatasetSnapshot");
    UniValue from_alias = Ref(canonical_kind, digest);
    from_alias.pushKV("record_type", record_type);
    BOOST_CHECK(modelnet::ParseResourceRef(from_alias, out, err, SpecRoot()));
    BOOST_CHECK_EQUAL(out.kind, "RECORD");
    BOOST_CHECK_EQUAL(out.record_type, "DatasetSnapshot");

    BOOST_CHECK(!modelnet::ParseLegacyKindAlias(SpecRoot(), "MODEL", canonical_kind, record_type, err));
    BOOST_CHECK(canonical_kind.empty());
    BOOST_CHECK_EQUAL(err, "BTX035_SCHEMA");
    BOOST_CHECK(modelnet::ParseResourceRef(Ref("MODEL", digest), out, err, SpecRoot()));
    BOOST_CHECK_EQUAL(out.kind, "MODEL");
    BOOST_CHECK(out.record_type.empty());
}

BOOST_AUTO_TEST_CASE(rev004_payload_topology)
{
    const std::string self = Hex96('a');
    const std::string earlier = Hex96('b');
    const std::string future = Hex96('c');
    std::string err;

    UniValue known_only(UniValue::VOBJ);
    known_only.pushKV("parent", earlier);
    known_only.pushKV("label", "ok");
    BOOST_CHECK(modelnet::PayloadTopology(self, known_only, {earlier}, err));
    BOOST_CHECK(err.empty());

    UniValue nested(UniValue::VARR);
    nested.push_back(earlier);
    UniValue wrapped(UniValue::VOBJ);
    wrapped.pushKV("refs", nested);
    BOOST_CHECK(modelnet::PayloadTopology(self, wrapped, {earlier}, err));

    UniValue owns(UniValue::VOBJ);
    owns.pushKV("parent", earlier);
    owns.pushKV("self", self);
    BOOST_CHECK(!modelnet::PayloadTopology(self, owns, {earlier, self}, err));
    BOOST_CHECK_EQUAL(err, "BTX035_RECORD_ID");

    UniValue later(UniValue::VOBJ);
    UniValue inner(UniValue::VOBJ);
    inner.pushKV("id", future);
    later.pushKV("child", inner);
    BOOST_CHECK(!modelnet::PayloadTopology(self, later, {earlier}, err));
    BOOST_CHECK_EQUAL(err, "BTX035_RECORD_ID");

    BOOST_CHECK(modelnet::PayloadTopology(self, later, {earlier, future}, err));
    BOOST_CHECK(err.empty());

    UniValue not_object(UniValue::VARR);
    BOOST_CHECK(!modelnet::PayloadTopology(self, not_object, {earlier}, err));
    BOOST_CHECK_EQUAL(err, "BTX035_RECORD_ID");
}

BOOST_AUTO_TEST_SUITE_END()
