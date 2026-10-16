// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_LAB_WIRE_H
#define BITCOIN_MODELNET_LAB_WIRE_H

#include <modelnet/canonical_codec.h>

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace modelnet {

/**
 * Manifest page payload budget. Each page is at most this many bytes, which is
 * below the v1.1 envelope budget (three full pages equal CANONICAL_MAX_ENVELOPE_V11).
 * A manifest larger than the envelope is rejected as one blob and admitted only
 * as these pages.
 */
constexpr size_t MANIFEST_PAGE_BYTES = 65536;
static_assert(MANIFEST_PAGE_BYTES <= CANONICAL_MAX_ENVELOPE_V11);
static_assert(MANIFEST_PAGE_BYTES * 3 == CANONICAL_MAX_ENVELOPE_V11);

/** Canonical bytes of `value` must be <= CANONICAL_MAX_ENVELOPE_V11 (196608). */
bool AcceptCanonicalEnvelope(const UniValue& value, std::string& err);

/**
 * Compact UTF-8 JSON document. Byte length above CANONICAL_MAX_ENVELOPE_V11
 * fails with BTX035_LIMIT_EXCEEDED. A shorter document that is not UTF-8 JSON
 * fails with BTX035_NONCANONICAL.
 */
bool AcceptCompactJson(std::string_view utf8, std::string& err);

/**
 * Transport wrapper body, excluding the 4-byte big-endian length prefix.
 * The cap is CANONICAL_MAX_ENVELOPE (262144), not the 196608 envelope budget.
 */
bool AcceptTransportWrapper(std::string_view body, std::string& err);

/** One manifest blob. Larger than the v1.1 envelope budget fails with BTX035_LIMIT_EXCEEDED. */
bool AcceptManifestBlob(std::string_view blob, std::string& err);

/**
 * Split `blob` into pages of at most MANIFEST_PAGE_BYTES. Each page is at most
 * the envelope budget. An empty blob yields no pages.
 */
bool SplitManifestPages(std::string_view blob, std::vector<std::string>& pages, std::string& err);

/**
 * Canonical publication URI: lowercase `btx://` plus an 85-character bech32m
 * token (91 characters), version 1, kind 0..15. Rejects any uppercase byte,
 * '?', '#', a trailing '/', and a trailing extension suffix. That suffix is a
 * final path segment ending in '.' plus 1..8 ASCII letters or digits, for
 * example `.json` or `.bin`. Failures set BTX035_NONCANONICAL.
 */
bool CanonicalOutputUri(std::string_view uri, std::string& err);

/**
 * Legacy input aliases: upper-case `BTX://`, a `btx:` prefix, a bare 85-character
 * token, and one trailing '/'. On success `canonical` is the lowercase `btx://`
 * publication and is unchanged from that form. Query, fragment, and extension
 * suffixes are rejected rather than stripped.
 */
bool ParseLegacyInputUri(std::string_view text, std::string& canonical, std::string& err);

/** Typed ResourceRef. `record_type` is empty unless `kind` is RECORD. */
struct ResourceRef {
    std::string kind;
    std::string digest48;
    std::string record_type;
};

/**
 * Wire-kind name from schemas/resource_registry.json. `spec_path` is the spec
 * package root, or the registry file itself. Empty uses the private v1.1 package.
 * Kinds 0..14 are the file's baseline names. Kind 15 is RECORD.
 */
bool RegistryWireKind(const std::string& spec_path, int wire_kind, std::string& name, std::string& err);

/**
 * Closed `{kind,digest48}` ref, plus `record_type` only when kind is RECORD.
 * Digest is 96 lowercase hex. A kind string that is not a registry wire kind,
 * including a semantic role, is rejected. `spec_path` is optional as in RegistryWireKind.
 */
bool ParseResourceRef(const UniValue& value, ResourceRef& out, std::string& err, const std::string& spec_path = {});

/**
 * Semantic role from the registry's semantic_aliases. On success `canonical_kind`
 * is RECORD and `record_type` is the mapped descriptor. The role is not a wire kind.
 * A baseline wire kind such as MODEL is not rewritten.
 */
bool ParseLegacyKindAlias(const std::string& spec_path, std::string_view alias, std::string& canonical_kind,
                          std::string& record_type, std::string& err);

/**
 * Topological payload check. `known_ids` are already constructed earlier record
 * ids. Returns false with BTX035_RECORD_ID when `payload` contains `record_id`
 * or any other 96-lowercase-hex id that is not in `known_ids`.
 */
bool PayloadTopology(const std::string& record_id, const UniValue& payload, const std::vector<std::string>& known_ids,
                     std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_LAB_WIRE_H
