// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/erasure_manifest.h>

#include <crypto/hex_base.h>
#include <crypto/sha384.h>
#include <modelnet/erasure_store.h>
#include <modelnet/types.h>
#include <span.h>

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <set>

namespace modelnet {
namespace {

constexpr int kMaxJsonDepth = 32;
constexpr uint64_t kMaxStripes = 1000000;
constexpr size_t kMaxPositions = 255;

std::string NormalizeKey(std::string k)
{
    for (char& c : k) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
        if (c == '-') c = '_';
    }
    return k;
}

std::string CompactKey(const std::string& k)
{
    std::string c;
    c.reserve(k.size());
    for (char ch : k) {
        if (ch != '_') c.push_back(ch);
    }
    return c;
}

bool SecretBearingKey(const std::string& key)
{
    const std::string k = NormalizeKey(key);
    const std::string c = CompactKey(k);
    if (k == "seed" || k == "seeds" || c == "seed" || c == "seeds") return true;
    if (k == "credential_ref" || k == "credential_refs" || c == "credentialref" || c == "credentialrefs") {
        return true;
    }
    auto has = [&](const char* n, const char* compact) {
        return k.find(n) != std::string::npos || c.find(compact) != std::string::npos;
    };
    return has("private_key", "privatekey") || has("password", "password") || has("passwd", "passwd") ||
           has("secret", "secret") || has("api_key", "apikey") || has("session_token", "sessiontoken") ||
           has("auth_token", "authtoken") || has("mnemonic", "mnemonic") || has("passkey", "passkey") ||
           has("presigned", "presigned") || has("credential_ref", "credentialref") ||
           has("wallet_seed", "walletseed");
}

bool RejectFloatsAndSecrets(const UniValue& v, std::string& err, int depth)
{
    if (depth > kMaxJsonDepth) {
        err = "nesting";
        return false;
    }
    if (v.isNum()) {
        const std::string s = v.getValStr();
        if (s.find('.') != std::string::npos || s.find('e') != std::string::npos ||
            s.find('E') != std::string::npos) {
            err = "floats prohibited";
            return false;
        }
    }
    if (v.isArray()) {
        for (const auto& e : v.getValues()) {
            if (!RejectFloatsAndSecrets(e, err, depth + 1)) return false;
        }
        return true;
    }
    if (!v.isObject()) return true;
    for (const auto& key : v.getKeys()) {
        if (SecretBearingKey(key)) {
            err = "secret-bearing key: " + key;
            return false;
        }
        if (!RejectFloatsAndSecrets(v[key], err, depth + 1)) return false;
    }
    return true;
}

bool ParseU64(const UniValue& v, uint64_t& out, std::string& err)
{
    if (v.isNum()) {
        if (!v.getValStr().empty() && v.getValStr()[0] == '-') {
            err = "negative";
            return false;
        }
        out = v.getInt<uint64_t>();
        return true;
    }
    if (!v.isStr()) {
        err = "integer";
        return false;
    }
    const std::string& s = v.get_str();
    if (s.empty() || s.size() > 20 || (s.size() > 1 && s[0] == '0') || s[0] == '-') {
        err = "decimal";
        return false;
    }
    for (char c : s) {
        if (c < '0' || c > '9') {
            err = "decimal";
            return false;
        }
    }
    errno = 0;
    char* end = nullptr;
    const unsigned long long x = std::strtoull(s.c_str(), &end, 10);
    if (errno || end != s.c_str() + s.size()) {
        err = "decimal";
        return false;
    }
    out = static_cast<uint64_t>(x);
    return true;
}

bool ParseI64(const UniValue& v, int64_t& out, std::string& err)
{
    if (v.isNum()) {
        out = v.getInt<int64_t>();
        return true;
    }
    uint64_t u = 0;
    if (!ParseU64(v, u, err)) return false;
    if (u > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
        err = "integer range";
        return false;
    }
    out = static_cast<int64_t>(u);
    return true;
}

bool RequireDigest48(const UniValue& o, const char* key, std::string& dest, std::string& err)
{
    if (!o.exists(key) || !o[key].isStr()) {
        err = key;
        return false;
    }
    Digest48 d;
    if (!Digest48::FromHex(o[key].get_str(), d, err)) return false;
    dest = o[key].get_str();
    return true;
}

bool DimsSane(const ErasureManifest& m)
{
    return 1 <= m.data_shards && m.data_shards < m.total_shards && m.total_shards <= 255 &&
           m.shard_bytes != 0;
}

/** Real data bytes one full stripe carries: k * shard_bytes. */
uint64_t StripePayloadBytes(const ErasureManifest& m)
{
    if (!DimsSane(m)) return 0;
    return static_cast<uint64_t>(m.data_shards) * static_cast<uint64_t>(m.shard_bytes);
}

/** n - k + 1: losing the whole coding margin must not take a stripe out. */
int RequiredFailureDomains(const ErasureManifest& m)
{
    const int margin = m.total_shards - m.data_shards;
    return margin > 0 ? margin + 1 : 1;
}

struct StripeDomains {
    bool declared{false};
    int distinct{0};
};

/**
 * Domains are counted over distinct stored positions. Repeating a position, or
 * listing fewer labels than positions, cannot manufacture an extra domain.
 */
StripeDomains DomainsOf(const ErasureStripe& s)
{
    StripeDomains d;
    d.declared = !s.failure_domains.empty() && s.failure_domains.size() == s.positions.size();
    if (!d.declared) return d;
    std::set<int> seen_positions;
    std::set<std::string> labels;
    for (size_t i = 0; i < s.positions.size(); ++i) {
        if (!seen_positions.insert(s.positions[i]).second) continue;
        labels.insert(s.failure_domains[i]);
    }
    d.distinct = static_cast<int>(labels.size());
    return d;
}

/** Array offset of the stripe whose stripe_index is stripe_count-1, else stripes.size(). */
size_t TailStripeOffset(const ErasureManifest& m)
{
    if (m.stripe_count == 0) return m.stripes.size();
    const uint64_t tail = m.stripe_count - 1;
    for (size_t i = 0; i < m.stripes.size(); ++i) {
        if (static_cast<uint64_t>(m.stripes[i].stripe_index) == tail) return i;
    }
    return m.stripes.size();
}

bool KnownExtension(const std::string& name)
{
    return name == ERASURE_EXT_FAILURE_DOMAIN_V1;
}

bool RequiresExtension(const ErasureManifest& m, const std::string& name)
{
    return std::find(m.required_extensions.begin(), m.required_extensions.end(), name) !=
           m.required_extensions.end();
}

bool ProfileDimsOk(const ErasureManifest& m, std::string& err)
{
    // Allowlist, with no test-only entry. A review or toy profile name admitted
    // here carries arbitrary k, n and shard_bytes, which is the whole of R6-09:
    // the NONSHIPPING 64/80 geometry parses under any name the list accepts.
    // Tests that need other dimensions build the struct instead of parsing.
    if (m.profile != ERASURE_PROFILE_CAUCHY_16_20_V1) {
        err = "profile";
        return false;
    }
    if (!(1 <= m.data_shards && m.data_shards < m.total_shards && m.total_shards <= 255)) {
        err = "profile dimensions";
        return false;
    }
    if (m.shard_bytes == 0) {
        err = "shard_bytes";
        return false;
    }
    // GfMul implements exactly one field. A manifest may not declare another.
    if (m.field_polynomial != ERASURE_FIELD_POLYNOMIAL) {
        err = "field_polynomial";
        return false;
    }
    if (m.data_shards != ERASURE_K_16_20 || m.total_shards != ERASURE_N_16_20 ||
        m.shard_bytes != ERASURE_SHARD_BYTES_16_20) {
        err = "profile dimensions";
        return false;
    }
    if (m.final_real_piece_count < 1 || m.final_real_piece_count > m.data_shards) {
        err = "final_real_piece_count";
        return false;
    }
    return true;
}

bool GeometryOk(const ErasureManifest& m, std::string& err)
{
    if (m.stripe_count == 0) {
        if (m.file_size_bytes != 0) {
            err = "stripe_count";
            return false;
        }
        return true;
    }
    if (m.file_size_bytes == 0) {
        err = "file_size_bytes";
        return false;
    }
    const uint64_t payload = StripePayloadBytes(m);
    if (payload == 0) {
        err = "profile dimensions";
        return false;
    }
    // A file_size_bytes needing more stripes than the parser will ever hold is
    // not a bound on anything. Reject it rather than carry it forward.
    if ((m.file_size_bytes + payload - 1) / payload > kMaxStripes) {
        err = "file_size_bytes";
        return false;
    }
    // A dummy-zero padding claim must be derived from file_size_bytes, never
    // asserted. Without this the tail stripe mints k-1 free data slots.
    if (m.final_real_piece_count < m.data_shards && !ErasureGeometryConsistent(m)) {
        err = "final_real_piece_count";
        return false;
    }
    return true;
}

} // namespace

bool ErasureGeometryConsistent(const ErasureManifest& m)
{
    if (m.stripe_count == 0) return m.file_size_bytes == 0;
    if (m.file_size_bytes == 0 || !DimsSane(m)) return false;
    if (m.final_real_piece_count < 1 || m.final_real_piece_count > m.data_shards) return false;
    const uint64_t payload = StripePayloadBytes(m);
    if (m.stripe_count > std::numeric_limits<uint64_t>::max() / payload) return false;
    const uint64_t cap = m.stripe_count * payload;
    // Cauchy 400 GiB manifests address more than the listed stripe array.
    if (m.profile == ERASURE_PROFILE_CAUCHY_16_20_V1 && m.file_size_bytes > cap) {
        return m.final_real_piece_count >= 1 && m.final_real_piece_count <= m.data_shards;
    }
    const uint64_t full = (m.stripe_count - 1) * payload;
    // Tail empty: stripe_count claims more stripes than the file has.
    if (m.file_size_bytes <= full) return false;
    const uint64_t tail = m.file_size_bytes - full;
    // Tail overfull: stripe_count claims fewer stripes than the file needs.
    if (tail > payload) return false;
    const uint64_t pieces = (tail + m.shard_bytes - 1) / m.shard_bytes;
    return pieces == static_cast<uint64_t>(m.final_real_piece_count);
}

bool ErasureStripeIndexSetOk(const ErasureManifest& m)
{
    if (m.stripe_count == 0 || m.stripes.size() != m.stripe_count) return false;
    std::set<uint32_t> seen;
    for (const auto& s : m.stripes) {
        if (static_cast<uint64_t>(s.stripe_index) >= m.stripe_count) return false;
        if (!seen.insert(s.stripe_index).second) return false;
    }
    return true;
}

std::vector<int> ErasureTailPaddingSlots(const ErasureManifest& m)
{
    std::vector<int> slots;
    if (m.final_real_piece_count < 1 || m.final_real_piece_count >= m.data_shards) return slots;
    // Fail closed: an unproven claim is worth no slots at all.
    if (!ErasureGeometryConsistent(m)) return slots;
    slots.reserve(static_cast<size_t>(m.data_shards - m.final_real_piece_count));
    for (int p = m.final_real_piece_count; p < m.data_shards; ++p) slots.push_back(p);
    return slots;
}

std::vector<std::vector<int>> ErasureStoredPositionSets(const ErasureManifest& manifest)
{
    std::vector<std::vector<int>> sets;
    sets.reserve(manifest.stripes.size());
    for (const auto& s : manifest.stripes) sets.push_back(s.positions);
    return sets;
}

std::vector<std::vector<int>> ErasureEffectivePositionSets(const ErasureManifest& manifest)
{
    auto sets = ErasureStoredPositionSets(manifest);
    if (sets.empty() || manifest.stripe_count == 0) return sets;
    // Credit follows stripe_index, not array order: the author of a manifest
    // must not be able to choose which stripe receives the padding.
    if (!ErasureStripeIndexSetOk(manifest)) return sets;
    const auto slots = ErasureTailPaddingSlots(manifest);
    if (slots.empty()) return sets;
    const size_t tail = TailStripeOffset(manifest);
    if (tail >= sets.size()) return sets;
    sets[tail].insert(sets[tail].end(), slots.begin(), slots.end());
    return sets;
}

bool ErasureStripeStoredPositions(const ErasureManifest& manifest, uint64_t stripe_index,
                                  std::vector<int>& out)
{
    if (!ErasureStripeIndexSetOk(manifest) || stripe_index >= manifest.stripe_count) return false;
    for (const auto& s : manifest.stripes) {
        if (static_cast<uint64_t>(s.stripe_index) != stripe_index) continue;
        out = s.positions;
        return true;
    }
    return false;
}

bool ErasureStripeIndexReconstructable(const ErasureManifest& manifest, uint64_t stripe_index)
{
    std::vector<int> stored;
    if (!ErasureStripeStoredPositions(manifest, stripe_index, stored)) return false;
    if (!DimsSane(manifest)) return false;
    std::set<int> effective(stored.begin(), stored.end());
    if (stripe_index + 1 == manifest.stripe_count) {
        const auto slots = ErasureTailPaddingSlots(manifest);
        effective.insert(slots.begin(), slots.end());
    }
    return static_cast<int>(effective.size()) >= manifest.data_shards;
}

bool ErasureStripeAcceptsPositions(const ErasureManifest& manifest, uint64_t stripe_index,
                                   const std::vector<int>& positions, std::string& err)
{
    std::vector<int> stored;
    if (!ErasureStripeStoredPositions(manifest, stripe_index, stored)) {
        err = "unknown stripe";
        return false;
    }
    const std::set<int> distinct(positions.begin(), positions.end());
    if (distinct.size() != positions.size() || static_cast<int>(distinct.size()) != manifest.data_shards) {
        err = "distinct k positions required";
        return false;
    }
    const std::set<int> owned(stored.begin(), stored.end());
    for (int p : distinct) {
        if (!owned.count(p)) {
            err = "position not stored by stripe";
            return false;
        }
    }
    if (!ErasureStripeIndexReconstructable(manifest, stripe_index)) {
        err = "global n is not sufficiency";
        return false;
    }
    return true;
}

bool ErasureShardIndexRootHex(const ErasureManifest& manifest, std::string& out, std::string& err)
{
    if (!ErasureStripeIndexSetOk(manifest)) {
        err = "stripe index";
        return false;
    }
    std::vector<size_t> order(manifest.stripes.size());
    for (size_t i = 0; i < order.size(); ++i) order[i] = i;
    std::sort(order.begin(), order.end(), [&](size_t a, size_t b) {
        return manifest.stripes[a].stripe_index < manifest.stripes[b].stripe_index;
    });

    std::string pre{ERASURE_SHARD_INDEX_TAG};
    pre += '\n';
    pre += manifest.profile + '\n' + manifest.canonical_artifact_id + '\n' +
           manifest.canonical_manifest_id + '\n';
    pre += std::to_string(manifest.file_index) + '\n' + std::to_string(manifest.file_size_bytes) + '\n';
    pre += std::to_string(manifest.data_shards) + '/' + std::to_string(manifest.total_shards) + '/' +
           std::to_string(manifest.shard_bytes) + '\n';
    pre += std::to_string(manifest.stripe_count) + '\n' +
           std::to_string(manifest.final_real_piece_count) + '\n';
    for (size_t offset : order) {
        const auto& s = manifest.stripes[offset];
        if (s.positions.empty()) continue;
        if (s.shard_hash_hex.size() != s.positions.size()) {
            err = "shard_hashes";
            return false;
        }
        for (size_t i = 0; i < s.positions.size(); ++i) {
            pre += std::to_string(s.stripe_index) + ':' + std::to_string(s.positions[i]) + ':' +
                   s.shard_hash_hex[i] + '\n';
        }
    }

    unsigned char digest[CSHA384::OUTPUT_SIZE];
    CSHA384 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(pre.data()), pre.size());
    hasher.Finalize(digest);
    out = HexStr(Span<const unsigned char>{digest, CSHA384::OUTPUT_SIZE});
    return true;
}

bool ErasureManifestReconstructable(const ErasureManifest& manifest)
{
    if (manifest.stripe_count == 0 || manifest.stripes.size() != manifest.stripe_count) return false;
    if (!DimsSane(manifest)) return false;
    if (!ErasureStripeIndexSetOk(manifest)) return false;
    // Sufficiency is StripeReconstructable on per-stripe sets. Never n, never a global count.
    return StripeReconstructable(ErasureEffectivePositionSets(manifest), manifest.data_shards);
}

bool ErasureManifestPreservationReconstructable(const ErasureManifest& manifest)
{
    if (!ErasureManifestReconstructable(manifest)) return false;
    if (!ErasureGeometryConsistent(manifest)) return false;
    const int need = RequiredFailureDomains(manifest);
    for (const auto& s : manifest.stripes) {
        const StripeDomains d = DomainsOf(s);
        if (!d.declared || d.distinct < need) return false;
    }
    return true;
}

ErasureHealth EvaluateErasureHealth(const ErasureManifest& manifest)
{
    ErasureHealth h;
    h.k = manifest.data_shards;
    h.n = manifest.total_shards;
    h.stripe_count = manifest.stripe_count;
    h.required_failure_domains = RequiredFailureDomains(manifest);
    h.geometry_consistent = ErasureGeometryConsistent(manifest);
    if (manifest.stripes.size() != manifest.stripe_count || manifest.stripe_count == 0) {
        h.reconstructable = false;
        h.deficit_stripes = manifest.stripe_count;
        return h;
    }
    const auto slots = ErasureTailPaddingSlots(manifest);
    const size_t tail = ErasureStripeIndexSetOk(manifest) ? TailStripeOffset(manifest)
                                                          : manifest.stripes.size();
    if (tail < manifest.stripes.size() && !slots.empty()) {
        h.padding_credited_stripe = static_cast<int64_t>(manifest.stripes[tail].stripe_index);
    }
    h.stripes.reserve(manifest.stripes.size());
    for (size_t i = 0; i < manifest.stripes.size(); ++i) {
        const ErasureStripe& stripe = manifest.stripes[i];
        ErasureStripeHealth sh;
        sh.stripe_index = stripe.stripe_index;
        sh.k_required = manifest.data_shards;
        const std::set<int> stored(stripe.positions.begin(), stripe.positions.end());
        sh.independent_shards = static_cast<int>(stored.size());
        sh.distinct_stored = sh.independent_shards;
        // Informational, and deliberately not inflatable by repetition.
        h.global_position_count += static_cast<uint64_t>(stored.size());

        std::set<int> effective = stored;
        if (i == tail) effective.insert(slots.begin(), slots.end());
        sh.distinct_effective = static_cast<int>(effective.size());
        sh.padding_credit = sh.distinct_effective - sh.independent_shards;

        const StripeDomains domains = DomainsOf(stripe);
        sh.failure_domains_declared = domains.declared;
        sh.distinct_failure_domains = domains.distinct;
        sh.required_failure_domains = h.required_failure_domains;

        const int need = manifest.data_shards;
        sh.deficit = sh.distinct_effective >= need ? 0 : need - sh.distinct_effective;
        sh.reconstructable = sh.deficit == 0;
        sh.preservation_reconstructable = sh.reconstructable && domains.declared &&
                                          domains.distinct >= sh.required_failure_domains;
        if (!sh.reconstructable) {
            sh.repair_target = "stripe:" + std::to_string(sh.stripe_index);
            for (int p = 0; p < manifest.total_shards; ++p) {
                if (!effective.count(p)) sh.repair_fetch_positions.push_back(p);
            }
        }
        if (sh.reconstructable) ++h.reconstructable_stripes;
        else ++h.deficit_stripes;
        if (sh.preservation_reconstructable) ++h.preservation_stripes;
        h.stripes.push_back(std::move(sh));
    }
    h.reconstructable = ErasureManifestReconstructable(manifest);
    h.preservation_reconstructable = ErasureManifestPreservationReconstructable(manifest);
    return h;
}

UniValue ErasureHealthJson(const ErasureHealth& health)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("reconstructable", health.reconstructable);
    o.pushKV("preservation_reconstructable", health.preservation_reconstructable);
    o.pushKV("geometry_consistent", health.geometry_consistent);
    o.pushKV("stripe_count", std::to_string(health.stripe_count));
    o.pushKV("reconstructable_stripes", std::to_string(health.reconstructable_stripes));
    o.pushKV("deficit_stripes", std::to_string(health.deficit_stripes));
    o.pushKV("preservation_stripes", std::to_string(health.preservation_stripes));
    o.pushKV("global_position_count", std::to_string(health.global_position_count));
    o.pushKV("global_count_not_sufficiency", true);
    o.pushKV("k", health.k);
    o.pushKV("n", health.n);
    o.pushKV("required_failure_domains", health.required_failure_domains);
    o.pushKV("padding_credited_stripe", health.padding_credited_stripe);
    UniValue stripes(UniValue::VARR);
    for (const auto& s : health.stripes) {
        UniValue e(UniValue::VOBJ);
        e.pushKV("stripe_index", static_cast<int>(s.stripe_index));
        e.pushKV("k_required", s.k_required);
        e.pushKV("independent_shards", s.independent_shards);
        e.pushKV("distinct_stored", s.distinct_stored);
        e.pushKV("padding_credit", s.padding_credit);
        e.pushKV("distinct_effective", s.distinct_effective);
        e.pushKV("distinct_failure_domains", s.distinct_failure_domains);
        e.pushKV("required_failure_domains", s.required_failure_domains);
        e.pushKV("failure_domains_declared", s.failure_domains_declared);
        e.pushKV("deficit", s.deficit);
        e.pushKV("reconstructable", s.reconstructable);
        e.pushKV("preservation_reconstructable", s.preservation_reconstructable);
        if (!s.repair_target.empty()) {
            UniValue target(UniValue::VOBJ);
            target.pushKV("handle", s.repair_target);
            target.pushKV("stripe_index", static_cast<int>(s.stripe_index));
            target.pushKV("k_required", s.k_required);
            target.pushKV("need", s.deficit);
            UniValue fetch(UniValue::VARR);
            for (int p : s.repair_fetch_positions) fetch.push_back(p);
            target.pushKV("fetch_positions", fetch);
            e.pushKV("repair_target", target);
        }
        stripes.push_back(std::move(e));
    }
    o.pushKV("stripes", stripes);
    return o;
}

UniValue ErasureManifestJson(const ErasureManifest& manifest)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("version", manifest.version);
    o.pushKV("profile", manifest.profile);
    o.pushKV("canonical_artifact_id", manifest.canonical_artifact_id);
    o.pushKV("canonical_manifest_id", manifest.canonical_manifest_id);
    o.pushKV("file_index", manifest.file_index);
    o.pushKV("file_size_bytes", std::to_string(manifest.file_size_bytes));
    o.pushKV("data_shards", manifest.data_shards);
    o.pushKV("total_shards", manifest.total_shards);
    o.pushKV("shard_bytes", static_cast<int64_t>(manifest.shard_bytes));
    o.pushKV("field_polynomial", manifest.field_polynomial);
    o.pushKV("stripe_count", std::to_string(manifest.stripe_count));
    o.pushKV("final_real_piece_count", manifest.final_real_piece_count);
    o.pushKV("shard_index_root", manifest.shard_index_root);
    if (!manifest.required_extensions.empty()) {
        UniValue ext(UniValue::VARR);
        for (const auto& e : manifest.required_extensions) ext.push_back(e);
        o.pushKV("required_extensions", ext);
    }
    if (!manifest.stripes.empty()) {
        UniValue stripes(UniValue::VARR);
        for (const auto& s : manifest.stripes) {
            UniValue e(UniValue::VOBJ);
            e.pushKV("index", static_cast<int>(s.stripe_index));
            UniValue pos(UniValue::VARR);
            for (int p : s.positions) pos.push_back(p);
            e.pushKV("positions", pos);
            if (!s.shard_hash_hex.empty()) {
                UniValue hashes(UniValue::VARR);
                for (const auto& h : s.shard_hash_hex) hashes.push_back(h);
                e.pushKV("shard_hashes", hashes);
            }
            if (!s.failure_domains.empty()) {
                UniValue domains(UniValue::VARR);
                for (const auto& d : s.failure_domains) domains.push_back(d);
                e.pushKV("failure_domains", domains);
            }
            stripes.push_back(std::move(e));
        }
        o.pushKV("stripes", stripes);
    }
    return o;
}

bool ParseErasureManifest(const UniValue& json, ErasureManifest& out, std::string& err)
{
    out = {};
    if (!json.isObject()) {
        err = "erasure manifest json";
        return false;
    }
    if (!RejectFloatsAndSecrets(json, err, 0)) return false;

    if (!json.exists("version") || !json["version"].isNum() || json["version"].getInt<int>() != 1) {
        err = "version";
        return false;
    }
    out.version = 1;
    if (json.exists("profile") && json["profile"].isStr()) {
        out.profile = json["profile"].get_str();
        if (out.profile.empty() || out.profile.size() > 64) {
            err = "profile";
            return false;
        }
    }
    if (!RequireDigest48(json, "canonical_artifact_id", out.canonical_artifact_id, err)) return false;
    if (!RequireDigest48(json, "canonical_manifest_id", out.canonical_manifest_id, err)) return false;
    if (!json.exists("file_index")) {
        err = "file_index";
        return false;
    }
    int64_t file_index = 0;
    if (!ParseI64(json["file_index"], file_index, err) || file_index < 0 || file_index > 2147483647) {
        err = "file_index";
        return false;
    }
    out.file_index = static_cast<int>(file_index);
    if (!json.exists("file_size_bytes") || !ParseU64(json["file_size_bytes"], out.file_size_bytes, err)) {
        err = "file_size_bytes";
        return false;
    }
    if (json.exists("data_shards")) {
        int64_t k = 0;
        if (!ParseI64(json["data_shards"], k, err)) return false;
        out.data_shards = static_cast<int>(k);
    }
    if (json.exists("total_shards")) {
        int64_t n = 0;
        if (!ParseI64(json["total_shards"], n, err)) return false;
        out.total_shards = static_cast<int>(n);
    }
    if (json.exists("shard_bytes")) {
        uint64_t b = 0;
        if (!ParseU64(json["shard_bytes"], b, err) || b > UINT32_MAX) {
            err = "shard_bytes";
            return false;
        }
        out.shard_bytes = static_cast<uint32_t>(b);
    }
    if (json.exists("field_polynomial") && json["field_polynomial"].isStr()) {
        out.field_polynomial = json["field_polynomial"].get_str();
    }
    if (!json.exists("stripe_count") || !ParseU64(json["stripe_count"], out.stripe_count, err) ||
        out.stripe_count > kMaxStripes) {
        err = "stripe_count";
        return false;
    }
    if (json.exists("final_real_piece_count")) {
        int64_t t = 0;
        if (!ParseI64(json["final_real_piece_count"], t, err)) return false;
        out.final_real_piece_count = static_cast<int>(t);
    } else {
        out.final_real_piece_count = out.data_shards;
    }
    if (!RequireDigest48(json, "shard_index_root", out.shard_index_root, err)) return false;
    if (!ProfileDimsOk(out, err)) return false;
    if (!GeometryOk(out, err)) return false;

    // Must-understand list. An unrecognised entry is a hard failure so that a
    // future security field cannot be silently ignored into a weaker verdict.
    if (json.exists("required_extensions")) {
        if (!json["required_extensions"].isArray()) {
            err = "required_extensions";
            return false;
        }
        const auto& ext = json["required_extensions"].getValues();
        if (ext.size() > ERASURE_MAX_REQUIRED_EXTENSIONS) {
            err = "required_extensions";
            return false;
        }
        for (const auto& e : ext) {
            if (!e.isStr() || !KnownExtension(e.get_str()) || RequiresExtension(out, e.get_str())) {
                err = "required_extensions";
                return false;
            }
            out.required_extensions.push_back(e.get_str());
        }
    }

    if (json.exists("stripes")) {
        if (!json["stripes"].isArray()) {
            err = "stripes";
            return false;
        }
        const auto& arr = json["stripes"].getValues();
        if (arr.size() != out.stripe_count) {
            err = "stripes";
            return false;
        }
        out.stripes.reserve(arr.size());
        std::set<uint32_t> seen;
        for (size_t i = 0; i < arr.size(); ++i) {
            const UniValue& e = arr[i];
            if (!e.isObject()) {
                err = "stripe";
                return false;
            }
            ErasureStripe st;
            if (e.exists("index")) {
                int64_t idx = 0;
                if (!ParseI64(e["index"], idx, err) || idx < 0 || static_cast<uint64_t>(idx) > UINT32_MAX) {
                    err = "stripe index";
                    return false;
                }
                st.stripe_index = static_cast<uint32_t>(idx);
            } else {
                st.stripe_index = static_cast<uint32_t>(i);
            }
            // The index set must be exactly {0..stripe_count-1}: a manifest
            // describing stripes 7 and 999 of a 2-stripe file proves nothing
            // about stripes 0 and 1, and the tail would be unidentifiable.
            if (static_cast<uint64_t>(st.stripe_index) >= out.stripe_count) {
                err = "stripe index";
                return false;
            }
            if (!seen.insert(st.stripe_index).second) {
                err = "duplicate stripe";
                return false;
            }
            if (i > 0 && st.stripe_index <= out.stripes.back().stripe_index) {
                err = "stripe order";
                return false;
            }
            if (!e.exists("positions") || !e["positions"].isArray()) {
                err = "positions";
                return false;
            }
            const auto& pos = e["positions"].getValues();
            if (pos.size() > kMaxPositions) {
                err = "positions";
                return false;
            }
            for (const auto& p : pos) {
                int64_t v = 0;
                if (!ParseI64(p, v, err) || v < 0 || v >= out.total_shards) {
                    err = "position";
                    return false;
                }
                st.positions.push_back(static_cast<int>(v));
            }
            if (e.exists("shard_hashes")) {
                if (!e["shard_hashes"].isArray()) {
                    err = "shard_hashes";
                    return false;
                }
                for (const auto& h : e["shard_hashes"].getValues()) {
                    if (!h.isStr()) {
                        err = "shard_hashes";
                        return false;
                    }
                    Digest48 d;
                    if (!Digest48::FromHex(h.get_str(), d, err)) return false;
                    st.shard_hash_hex.push_back(h.get_str());
                }
                if (st.shard_hash_hex.size() != st.positions.size()) {
                    err = "shard_hashes";
                    return false;
                }
            }
            if (e.exists("failure_domains")) {
                if (!e["failure_domains"].isArray()) {
                    err = "failure_domains";
                    return false;
                }
                for (const auto& d : e["failure_domains"].getValues()) {
                    if (!d.isStr() || d.get_str().empty() || d.get_str().size() > ERASURE_MAX_DOMAIN_LEN) {
                        err = "failure_domains";
                        return false;
                    }
                    st.failure_domains.push_back(d.get_str());
                }
                // One label per stored position, or the count is not a count of
                // independent origins.
                if (st.failure_domains.size() != st.positions.size()) {
                    err = "failure_domains";
                    return false;
                }
            } else if (e.exists("failure_domain")) {
                if (!e["failure_domain"].isStr() || e["failure_domain"].get_str().empty() ||
                    e["failure_domain"].get_str().size() > ERASURE_MAX_DOMAIN_LEN) {
                    err = "failure_domains";
                    return false;
                }
                st.failure_domains.assign(st.positions.size(), e["failure_domain"].get_str());
            }
            out.stripes.push_back(std::move(st));
        }

        bool any_hashes = false;
        bool all_hashes = true;
        bool any_domains = false;
        for (const auto& s : out.stripes) {
            if (!s.failure_domains.empty()) any_domains = true;
            if (s.positions.empty()) continue;
            if (s.shard_hash_hex.empty()) all_hashes = false;
            else any_hashes = true;
        }
        if (any_hashes && !all_hashes) {
            err = "shard_hashes";
            return false;
        }
        // Bind shard_index_root to the declared inventory. Without this the
        // root commits to nothing and cannot detect a substituted set.
        if (any_hashes) {
            std::string want;
            if (!ErasureShardIndexRootHex(out, want, err)) return false;
            if (want != out.shard_index_root) {
                err = "shard_index_root";
                return false;
            }
        }
        // Declaring domains without listing the extension would let an older
        // peer answer reconstructable on a manifest a newer peer rejects.
        if (any_domains && !RequiresExtension(out, ERASURE_EXT_FAILURE_DOMAIN_V1)) {
            err = "required_extensions";
            return false;
        }
    }
    return true;
}

} // namespace modelnet
