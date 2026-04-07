// Copyright (c) 2018-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/descriptor.h>

#include <crypto/hmac_sha512.h>
#include <crypto/common.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <key_io.h>
#include <policy/settings.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/miniscript.h>
#include <script/parsing.h>
#include <script/pqm.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <uint256.h>

#include <common/args.h>
#include <pq/pq_keyderivation.h>
#include <span.h>
#include <util/bip32.h>
#include <util/check.h>
#include <util/strencodings.h>
#include <util/vector.h>

#include <algorithm>
#include <array>
#include <limits>
#include <memory>
#include <numeric>
#include <optional>
#include <set>
#include <string>
#include <vector>

using util::Split;

namespace {

////////////////////////////////////////////////////////////////////////////
// Checksum                                                               //
////////////////////////////////////////////////////////////////////////////

// This section implements a checksum algorithm for descriptors with the
// following properties:
// * Mistakes in a descriptor string are measured in "symbol errors". The higher
//   the number of symbol errors, the harder it is to detect:
//   * An error substituting a character from 0123456789()[],'/*abcdefgh@:$%{} for
//     another in that set always counts as 1 symbol error.
//     * Note that hex encoded keys are covered by these characters. Xprvs and
//       xpubs use other characters too, but already have their own checksum
//       mechanism.
//     * Function names like "multi()" use other characters, but mistakes in
//       these would generally result in an unparsable descriptor.
//   * A case error always counts as 1 symbol error.
//   * Any other 1 character substitution error counts as 1 or 2 symbol errors.
// * Any 1 symbol error is always detected.
// * Any 2 or 3 symbol error in a descriptor of up to 49154 characters is always detected.
// * Any 4 symbol error in a descriptor of up to 507 characters is always detected.
// * Any 5 symbol error in a descriptor of up to 77 characters is always detected.
// * Is optimized to minimize the chance a 5 symbol error in a descriptor up to 387 characters is undetected
// * Random errors have a chance of 1 in 2**40 of being undetected.
//
// These properties are achieved by expanding every group of 3 (non checksum) characters into
// 4 GF(32) symbols, over which a cyclic code is defined.

/*
 * Interprets c as 8 groups of 5 bits which are the coefficients of a degree 8 polynomial over GF(32),
 * multiplies that polynomial by x, computes its remainder modulo a generator, and adds the constant term val.
 *
 * This generator is G(x) = x^8 + {30}x^7 + {23}x^6 + {15}x^5 + {14}x^4 + {10}x^3 + {6}x^2 + {12}x + {9}.
 * It is chosen to define an cyclic error detecting code which is selected by:
 * - Starting from all BCH codes over GF(32) of degree 8 and below, which by construction guarantee detecting
 *   3 errors in windows up to 19000 symbols.
 * - Taking all those generators, and for degree 7 ones, extend them to degree 8 by adding all degree-1 factors.
 * - Selecting just the set of generators that guarantee detecting 4 errors in a window of length 512.
 * - Selecting one of those with best worst-case behavior for 5 errors in windows of length up to 512.
 *
 * The generator and the constants to implement it can be verified using this Sage code:
 *   B = GF(2) # Binary field
 *   BP.<b> = B[] # Polynomials over the binary field
 *   F_mod = b**5 + b**3 + 1
 *   F.<f> = GF(32, modulus=F_mod, repr='int') # GF(32) definition
 *   FP.<x> = F[] # Polynomials over GF(32)
 *   E_mod = x**3 + x + F.fetch_int(8)
 *   E.<e> = F.extension(E_mod) # Extension field definition
 *   alpha = e**2743 # Choice of an element in extension field
 *   for p in divisors(E.order() - 1): # Verify alpha has order 32767.
 *       assert((alpha**p == 1) == (p % 32767 == 0))
 *   G = lcm([(alpha**i).minpoly() for i in [1056,1057,1058]] + [x + 1])
 *   print(G) # Print out the generator
 *   for i in [1,2,4,8,16]: # Print out {1,2,4,8,16}*(G mod x^8), packed in hex integers.
 *       v = 0
 *       for coef in reversed((F.fetch_int(i)*(G % x**8)).coefficients(sparse=True)):
 *           v = v*32 + coef.integer_representation()
 *       print("0x%x" % v)
 */
uint64_t PolyMod(uint64_t c, int val)
{
    uint8_t c0 = c >> 35;
    c = ((c & 0x7ffffffff) << 5) ^ val;
    if (c0 & 1) c ^= 0xf5dee51989;
    if (c0 & 2) c ^= 0xa9fdca3312;
    if (c0 & 4) c ^= 0x1bab10e32d;
    if (c0 & 8) c ^= 0x3706b1677a;
    if (c0 & 16) c ^= 0x644d626ffd;
    return c;
}

std::string DescriptorChecksum(const Span<const char>& span)
{
    /** A character set designed such that:
     *  - The most common 'unprotected' descriptor characters (hex, keypaths) are in the first group of 32.
     *  - Case errors cause an offset that's a multiple of 32.
     *  - As many alphabetic characters are in the same group (while following the above restrictions).
     *
     * If p(x) gives the position of a character c in this character set, every group of 3 characters
     * (a,b,c) is encoded as the 4 symbols (p(a) & 31, p(b) & 31, p(c) & 31, (p(a) / 32) + 3 * (p(b) / 32) + 9 * (p(c) / 32).
     * This means that changes that only affect the lower 5 bits of the position, or only the higher 2 bits, will just
     * affect a single symbol.
     *
     * As a result, within-group-of-32 errors count as 1 symbol, as do cross-group errors that don't affect
     * the position within the groups.
     */
    static const std::string INPUT_CHARSET =
        "0123456789()[],'/*abcdefgh@:$%{}"
        "IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~"
        "ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";

    /** The character set for the checksum itself (same as bech32). */
    static const std::string CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    uint64_t c = 1;
    int cls = 0;
    int clscount = 0;
    for (auto ch : span) {
        auto pos = INPUT_CHARSET.find(ch);
        if (pos == std::string::npos) return "";
        c = PolyMod(c, pos & 31); // Emit a symbol for the position inside the group, for every character.
        cls = cls * 3 + (pos >> 5); // Accumulate the group numbers
        if (++clscount == 3) {
            // Emit an extra symbol representing the group numbers, for every 3 characters.
            c = PolyMod(c, cls);
            cls = 0;
            clscount = 0;
        }
    }
    if (clscount > 0) c = PolyMod(c, cls);
    for (int j = 0; j < 8; ++j) c = PolyMod(c, 0); // Shift further to determine the checksum.
    c ^= 1; // Prevent appending zeroes from not affecting the checksum.

    std::string ret(8, ' ');
    for (int j = 0; j < 8; ++j) ret[j] = CHECKSUM_CHARSET[(c >> (5 * (7 - j))) & 31];
    return ret;
}

////////////////////////////////////////////////////////////////////////////
// Internal representation                                                //
////////////////////////////////////////////////////////////////////////////

typedef std::vector<uint32_t> KeyPath;

/** Interface for public key objects in descriptors. */
struct PubkeyProvider
{
protected:
    //! Index of this key expression in the descriptor
    //! E.g. If this PubkeyProvider is key1 in multi(2, key1, key2, key3), then m_expr_index = 0
    uint32_t m_expr_index;

public:
    explicit PubkeyProvider(uint32_t exp_index) : m_expr_index(exp_index) {}

    virtual ~PubkeyProvider() = default;

    uint32_t GetExprIndex() const { return m_expr_index; }

    /** Compare two public keys represented by this provider.
     * Used by the Miniscript descriptors to check for duplicate keys in the script.
     */
    bool operator<(PubkeyProvider& other) const {
        CPubKey a, b;
        SigningProvider dummy;
        KeyOriginInfo dummy_info;

        GetPubKey(0, dummy, a, dummy_info);
        other.GetPubKey(0, dummy, b, dummy_info);

        return a < b;
    }

    /** Derive a public key.
     *  read_cache is the cache to read keys from (if not nullptr)
     *  write_cache is the cache to write keys to (if not nullptr)
     *  Caches are not exclusive but this is not tested. Currently we use them exclusively
     */
    virtual bool GetPubKey(int pos, const SigningProvider& arg, CPubKey& key, KeyOriginInfo& info, const DescriptorCache* read_cache = nullptr, DescriptorCache* write_cache = nullptr) const = 0;

    /** Whether this represent multiple public keys at different positions. */
    virtual bool IsRange() const = 0;

    /** Get the size of the generated public key(s) in bytes (33 or 65). */
    virtual size_t GetSize() const = 0;

    enum class StringType {
        PUBLIC,
        COMPAT // string calculation that mustn't change over time to stay compatible with previous software versions
    };

    /** Get the descriptor string form. */
    virtual std::string ToString(StringType type=StringType::PUBLIC) const = 0;

    /** Get the descriptor string form including private data (if available in arg). */
    virtual bool ToPrivateString(const SigningProvider& arg, std::string& out) const = 0;

    /** Get the descriptor string form with the xpub at the last hardened derivation,
     *  and always use h for hardened derivation.
     */
    virtual bool ToNormalizedString(const SigningProvider& arg, std::string& out, const DescriptorCache* cache = nullptr) const = 0;

    /** Derive a private key, if private data is available in arg. */
    virtual bool GetPrivKey(int pos, const SigningProvider& arg, CKey& key) const = 0;

    /** Return the non-extended public key for this PubkeyProvider, if it has one. */
    virtual std::optional<CPubKey> GetRootPubKey() const = 0;
    /** Return the extended public key for this PubkeyProvider, if it has one. */
    virtual std::optional<CExtPubKey> GetRootExtPubKey() const = 0;

    /** Whether this provider derives PQ keys natively (without ECDSA). */
    virtual bool IsPQNative() const { return false; }

    /** Make a deep copy of this PubkeyProvider */
    virtual std::unique_ptr<PubkeyProvider> Clone() const = 0;
};

class OriginPubkeyProvider final : public PubkeyProvider
{
    KeyOriginInfo m_origin;
    std::unique_ptr<PubkeyProvider> m_provider;
    bool m_apostrophe;

    std::string OriginString(StringType type, bool normalized=false) const
    {
        // If StringType==COMPAT, always use the apostrophe to stay compatible with previous versions
        bool use_apostrophe = (!normalized && m_apostrophe) || type == StringType::COMPAT;
        return HexStr(m_origin.fingerprint) + FormatHDKeypath(m_origin.path, use_apostrophe);
    }

public:
    OriginPubkeyProvider(uint32_t exp_index, KeyOriginInfo info, std::unique_ptr<PubkeyProvider> provider, bool apostrophe) : PubkeyProvider(exp_index), m_origin(std::move(info)), m_provider(std::move(provider)), m_apostrophe(apostrophe) {}
    bool GetPubKey(int pos, const SigningProvider& arg, CPubKey& key, KeyOriginInfo& info, const DescriptorCache* read_cache = nullptr, DescriptorCache* write_cache = nullptr) const override
    {
        if (!m_provider->GetPubKey(pos, arg, key, info, read_cache, write_cache)) return false;
        std::copy(std::begin(m_origin.fingerprint), std::end(m_origin.fingerprint), info.fingerprint);
        info.path.insert(info.path.begin(), m_origin.path.begin(), m_origin.path.end());
        return true;
    }
    bool IsRange() const override { return m_provider->IsRange(); }
    size_t GetSize() const override { return m_provider->GetSize(); }
    std::string ToString(StringType type) const override { return "[" + OriginString(type) + "]" + m_provider->ToString(type); }
    bool ToPrivateString(const SigningProvider& arg, std::string& ret) const override
    {
        std::string sub;
        if (!m_provider->ToPrivateString(arg, sub)) return false;
        ret = "[" + OriginString(StringType::PUBLIC) + "]" + std::move(sub);
        return true;
    }
    bool ToNormalizedString(const SigningProvider& arg, std::string& ret, const DescriptorCache* cache) const override
    {
        std::string sub;
        if (!m_provider->ToNormalizedString(arg, sub, cache)) return false;
        // If m_provider is a BIP32PubkeyProvider, we may get a string formatted like a OriginPubkeyProvider
        // In that case, we need to strip out the leading square bracket and fingerprint from the substring,
        // and append that to our own origin string.
        if (sub[0] == '[') {
            sub = sub.substr(9);
            ret = "[" + OriginString(StringType::PUBLIC, /*normalized=*/true) + std::move(sub);
        } else {
            ret = "[" + OriginString(StringType::PUBLIC, /*normalized=*/true) + "]" + std::move(sub);
        }
        return true;
    }
    bool GetPrivKey(int pos, const SigningProvider& arg, CKey& key) const override
    {
        return m_provider->GetPrivKey(pos, arg, key);
    }
    std::optional<CPubKey> GetRootPubKey() const override
    {
        return m_provider->GetRootPubKey();
    }
    std::optional<CExtPubKey> GetRootExtPubKey() const override
    {
        return m_provider->GetRootExtPubKey();
    }
    std::unique_ptr<PubkeyProvider> Clone() const override
    {
        return std::make_unique<OriginPubkeyProvider>(m_expr_index, m_origin, m_provider->Clone(), m_apostrophe);
    }
};

/** An object representing a parsed constant public key in a descriptor. */
class ConstPubkeyProvider final : public PubkeyProvider
{
    CPubKey m_pubkey;
    bool m_xonly;

public:
    ConstPubkeyProvider(uint32_t exp_index, const CPubKey& pubkey, bool xonly) : PubkeyProvider(exp_index), m_pubkey(pubkey), m_xonly(xonly) {}
    bool GetPubKey(int pos, const SigningProvider& arg, CPubKey& key, KeyOriginInfo& info, const DescriptorCache* read_cache = nullptr, DescriptorCache* write_cache = nullptr) const override
    {
        key = m_pubkey;
        info.path.clear();
        CKeyID keyid = m_pubkey.GetID();
        std::copy(keyid.begin(), keyid.begin() + sizeof(info.fingerprint), info.fingerprint);
        return true;
    }
    bool IsRange() const override { return false; }
    size_t GetSize() const override { return m_pubkey.size(); }
    std::string ToString(StringType type) const override { return m_xonly ? HexStr(m_pubkey).substr(2) : HexStr(m_pubkey); }
    bool ToPrivateString(const SigningProvider& arg, std::string& ret) const override
    {
        CKey key;
        if (!GetPrivKey(/*pos=*/0, arg, key)) return false;
        ret = EncodeSecret(key);
        return true;
    }
    bool ToNormalizedString(const SigningProvider& arg, std::string& ret, const DescriptorCache* cache) const override
    {
        ret = ToString(StringType::PUBLIC);
        return true;
    }
    bool GetPrivKey(int pos, const SigningProvider& arg, CKey& key) const override
    {
        return m_xonly ? arg.GetKeyByXOnly(XOnlyPubKey(m_pubkey), key) :
                         arg.GetKey(m_pubkey.GetID(), key);
    }
    std::optional<CPubKey> GetRootPubKey() const override
    {
        return m_pubkey;
    }
    std::optional<CExtPubKey> GetRootExtPubKey() const override
    {
        return std::nullopt;
    }
    std::unique_ptr<PubkeyProvider> Clone() const override
    {
        return std::make_unique<ConstPubkeyProvider>(m_expr_index, m_pubkey, m_xonly);
    }
};

enum class DeriveType {
    NO,
    UNHARDENED,
    HARDENED,
};

/** An object representing a parsed extended public key in a descriptor. */
class BIP32PubkeyProvider final : public PubkeyProvider
{
    // Root xpub, path, and final derivation step type being used, if any
    CExtPubKey m_root_extkey;
    KeyPath m_path;
    DeriveType m_derive;
    // Whether ' or h is used in harded derivation
    bool m_apostrophe;

    bool GetExtKey(const SigningProvider& arg, CExtKey& ret) const
    {
        CKey key;
        if (!arg.GetKey(m_root_extkey.pubkey.GetID(), key)) return false;
        ret.nDepth = m_root_extkey.nDepth;
        std::copy(m_root_extkey.vchFingerprint, m_root_extkey.vchFingerprint + sizeof(ret.vchFingerprint), ret.vchFingerprint);
        ret.nChild = m_root_extkey.nChild;
        ret.chaincode = m_root_extkey.chaincode;
        ret.key = key;
        return true;
    }

    // Derives the last xprv
    bool GetDerivedExtKey(const SigningProvider& arg, CExtKey& xprv, CExtKey& last_hardened) const
    {
        if (!GetExtKey(arg, xprv)) return false;
        for (auto entry : m_path) {
            if (!xprv.Derive(xprv, entry)) return false;
            if (entry >> 31) {
                last_hardened = xprv;
            }
        }
        return true;
    }

    bool IsHardened() const
    {
        if (m_derive == DeriveType::HARDENED) return true;
        for (auto entry : m_path) {
            if (entry >> 31) return true;
        }
        return false;
    }

public:
    BIP32PubkeyProvider(uint32_t exp_index, const CExtPubKey& extkey, KeyPath path, DeriveType derive, bool apostrophe) : PubkeyProvider(exp_index), m_root_extkey(extkey), m_path(std::move(path)), m_derive(derive), m_apostrophe(apostrophe) {}
    bool IsRange() const override { return m_derive != DeriveType::NO; }
    size_t GetSize() const override { return 33; }
    bool GetPubKey(int pos, const SigningProvider& arg, CPubKey& key_out, KeyOriginInfo& final_info_out, const DescriptorCache* read_cache = nullptr, DescriptorCache* write_cache = nullptr) const override
    {
        // Info of parent of the to be derived pubkey
        KeyOriginInfo parent_info;
        CKeyID keyid = m_root_extkey.pubkey.GetID();
        std::copy(keyid.begin(), keyid.begin() + sizeof(parent_info.fingerprint), parent_info.fingerprint);
        parent_info.path = m_path;

        // Info of the derived key itself which is copied out upon successful completion
        KeyOriginInfo final_info_out_tmp = parent_info;
        if (m_derive == DeriveType::UNHARDENED) final_info_out_tmp.path.push_back((uint32_t)pos);
        if (m_derive == DeriveType::HARDENED) final_info_out_tmp.path.push_back(((uint32_t)pos) | 0x80000000L);

        // Derive keys or fetch them from cache
        CExtPubKey final_extkey = m_root_extkey;
        CExtPubKey parent_extkey = m_root_extkey;
        CExtPubKey last_hardened_extkey;
        bool der = true;
        if (read_cache) {
            if (!read_cache->GetCachedDerivedExtPubKey(m_expr_index, pos, final_extkey)) {
                if (m_derive == DeriveType::HARDENED) return false;
                // Try to get the derivation parent
                if (!read_cache->GetCachedParentExtPubKey(m_expr_index, parent_extkey)) return false;
                final_extkey = parent_extkey;
                if (m_derive == DeriveType::UNHARDENED) der = parent_extkey.Derive(final_extkey, pos);
            }
        } else if (IsHardened()) {
            CExtKey xprv;
            CExtKey lh_xprv;
            if (!GetDerivedExtKey(arg, xprv, lh_xprv)) return false;
            parent_extkey = xprv.Neuter();
            if (m_derive == DeriveType::UNHARDENED) der = xprv.Derive(xprv, pos);
            if (m_derive == DeriveType::HARDENED) der = xprv.Derive(xprv, pos | 0x80000000UL);
            final_extkey = xprv.Neuter();
            if (lh_xprv.key.IsValid()) {
                last_hardened_extkey = lh_xprv.Neuter();
            }
        } else {
            for (auto entry : m_path) {
                if (!parent_extkey.Derive(parent_extkey, entry)) return false;
            }
            final_extkey = parent_extkey;
            if (m_derive == DeriveType::UNHARDENED) der = parent_extkey.Derive(final_extkey, pos);
            assert(m_derive != DeriveType::HARDENED);
        }
        if (!der) return false;

        final_info_out = final_info_out_tmp;
        key_out = final_extkey.pubkey;

        if (write_cache) {
            // Only cache parent if there is any unhardened derivation
            if (m_derive != DeriveType::HARDENED) {
                write_cache->CacheParentExtPubKey(m_expr_index, parent_extkey);
                // Cache last hardened xpub if we have it
                if (last_hardened_extkey.pubkey.IsValid()) {
                    write_cache->CacheLastHardenedExtPubKey(m_expr_index, last_hardened_extkey);
                }
            } else if (final_info_out.path.size() > 0) {
                write_cache->CacheDerivedExtPubKey(m_expr_index, pos, final_extkey);
            }
        }

        return true;
    }
    std::string ToString(StringType type, bool normalized) const
    {
        // If StringType==COMPAT, always use the apostrophe to stay compatible with previous versions
        const bool use_apostrophe = (!normalized && m_apostrophe) || type == StringType::COMPAT;
        std::string ret = EncodeExtPubKey(m_root_extkey) + FormatHDKeypath(m_path, /*apostrophe=*/use_apostrophe);
        if (IsRange()) {
            ret += "/*";
            if (m_derive == DeriveType::HARDENED) ret += use_apostrophe ? '\'' : 'h';
        }
        return ret;
    }
    std::string ToString(StringType type=StringType::PUBLIC) const override
    {
        return ToString(type, /*normalized=*/false);
    }
    bool ToPrivateString(const SigningProvider& arg, std::string& out) const override
    {
        CExtKey key;
        if (!GetExtKey(arg, key)) return false;
        out = EncodeExtKey(key) + FormatHDKeypath(m_path, /*apostrophe=*/m_apostrophe);
        if (IsRange()) {
            out += "/*";
            if (m_derive == DeriveType::HARDENED) out += m_apostrophe ? '\'' : 'h';
        }
        return true;
    }
    bool ToNormalizedString(const SigningProvider& arg, std::string& out, const DescriptorCache* cache) const override
    {
        if (m_derive == DeriveType::HARDENED) {
            out = ToString(StringType::PUBLIC, /*normalized=*/true);

            return true;
        }
        // Step backwards to find the last hardened step in the path
        int i = (int)m_path.size() - 1;
        for (; i >= 0; --i) {
            if (m_path.at(i) >> 31) {
                break;
            }
        }
        // Either no derivation or all unhardened derivation
        if (i == -1) {
            out = ToString();
            return true;
        }
        // Get the path to the last hardened stup
        KeyOriginInfo origin;
        int k = 0;
        for (; k <= i; ++k) {
            // Add to the path
            origin.path.push_back(m_path.at(k));
        }
        // Build the remaining path
        KeyPath end_path;
        for (; k < (int)m_path.size(); ++k) {
            end_path.push_back(m_path.at(k));
        }
        // Get the fingerprint
        CKeyID id = m_root_extkey.pubkey.GetID();
        std::copy(id.begin(), id.begin() + 4, origin.fingerprint);

        CExtPubKey xpub;
        CExtKey lh_xprv;
        // If we have the cache, just get the parent xpub
        if (cache != nullptr) {
            cache->GetCachedLastHardenedExtPubKey(m_expr_index, xpub);
        }
        if (!xpub.pubkey.IsValid()) {
            // Cache miss, or nor cache, or need privkey
            CExtKey xprv;
            if (!GetDerivedExtKey(arg, xprv, lh_xprv)) return false;
            xpub = lh_xprv.Neuter();
        }
        assert(xpub.pubkey.IsValid());

        // Build the string
        std::string origin_str = HexStr(origin.fingerprint) + FormatHDKeypath(origin.path);
        out = "[" + origin_str + "]" + EncodeExtPubKey(xpub) + FormatHDKeypath(end_path);
        if (IsRange()) {
            out += "/*";
            assert(m_derive == DeriveType::UNHARDENED);
        }
        return true;
    }
    bool GetPrivKey(int pos, const SigningProvider& arg, CKey& key) const override
    {
        CExtKey extkey;
        CExtKey dummy;
        if (!GetDerivedExtKey(arg, extkey, dummy)) return false;
        if (m_derive == DeriveType::UNHARDENED && !extkey.Derive(extkey, pos)) return false;
        if (m_derive == DeriveType::HARDENED && !extkey.Derive(extkey, pos | 0x80000000UL)) return false;
        key = extkey.key;
        return true;
    }
    std::optional<CPubKey> GetRootPubKey() const override
    {
        return std::nullopt;
    }
    std::optional<CExtPubKey> GetRootExtPubKey() const override
    {
        return m_root_extkey;
    }
    std::unique_ptr<PubkeyProvider> Clone() const override
    {
        return std::make_unique<BIP32PubkeyProvider>(m_expr_index, m_root_extkey, m_path, m_derive, m_apostrophe);
    }
};

/** PQ-native HD key provider — derives PQ keys directly from a 32-byte master seed via HKDF.
 *
 *  Descriptor syntax: pqhd(fingerprint/coin_typeh/accounth/change/ *)
 *  Private form:      pqhd(hexseed/coin_typeh/accounth/change/ *)
 *
 *  The seed is NEVER exposed in public ToString() — only a 4-byte fingerprint is shown.
 */
class PQHDPubkeyProvider final : public PubkeyProvider
{
    std::array<unsigned char, 32> m_seed;         // PQ master seed (secret)
    std::array<unsigned char, 4>  m_fingerprint;  // First 4 bytes of SHA256(seed)
    bool m_has_seed{false};
    uint32_t m_coin_type;
    uint32_t m_account;
    uint32_t m_change;
    // Range derivation is always implied (/* suffix)

    void ComputeFingerprintFromSeed()
    {
        std::array<unsigned char, 32> hash{};
        CSHA256().Write(m_seed.data(), m_seed.size()).Finalize(hash.data());
        std::copy(hash.begin(), hash.begin() + 4, m_fingerprint.begin());
    }

public:
    PQHDPubkeyProvider(uint32_t exp_index,
                       const std::array<unsigned char, 32>& seed,
                       uint32_t coin_type, uint32_t account, uint32_t change)
        : PubkeyProvider(exp_index), m_seed(seed), m_has_seed(true),
          m_coin_type(coin_type), m_account(account), m_change(change)
    {
        ComputeFingerprintFromSeed();
    }

    PQHDPubkeyProvider(uint32_t exp_index,
                       const std::array<unsigned char, 4>& fingerprint,
                       uint32_t coin_type, uint32_t account, uint32_t change)
        : PubkeyProvider(exp_index), m_fingerprint(fingerprint), m_has_seed(false),
          m_coin_type(coin_type), m_account(account), m_change(change)
    {
    }

    bool IsPQNative() const override { return true; }

    /** Derive a PQ seed for a given position and algorithm. */
    [[maybe_unused]] std::array<unsigned char, 32> GetPQSeed(int pos, PQAlgorithm algo) const
    {
        if (!m_has_seed) return {};
        return pq::DerivePQSeedFromBIP39(m_seed, algo, m_coin_type, m_account, m_change, static_cast<uint32_t>(pos));
    }

    /** Derive a PQ key for a given position and algorithm. */
    std::optional<CPQKey> GetPQKey(int pos, PQAlgorithm algo) const
    {
        if (!m_has_seed) return std::nullopt;
        return pq::DerivePQKeyFromBIP39(m_seed, algo, m_coin_type, m_account, m_change, static_cast<uint32_t>(pos));
    }

    const std::array<unsigned char, 32>& GetSeed() const { return m_seed; }
    const std::array<unsigned char, 4>& GetFingerprint() const { return m_fingerprint; }
    /** Inject seed after deserialization from DB (fingerprint-only form). */
    void SetSeed(const std::array<unsigned char, 32>& seed) { m_seed = seed; m_has_seed = true; ComputeFingerprintFromSeed(); }
    bool HasSeed() const { return m_has_seed; }
    [[maybe_unused]] uint32_t GetCoinType() const { return m_coin_type; }
    [[maybe_unused]] uint32_t GetAccount() const { return m_account; }
    [[maybe_unused]] uint32_t GetChange() const { return m_change; }

    bool IsRange() const override { return true; }
    size_t GetSize() const override { return 33; } // Dummy — PQ keys are large but this satisfies the interface

    bool GetPubKey(int pos, const SigningProvider& arg, CPubKey& key, KeyOriginInfo& info,
                   const DescriptorCache* read_cache = nullptr, DescriptorCache* write_cache = nullptr) const override
    {
        // PQ-native providers don't produce secp256k1 pubkeys.
        // Return a deterministic dummy CPubKey so the descriptor framework doesn't choke.
        // The actual PQ pubkey derivation happens in MRDescriptor::MakeScripts/ExpandPrivateImpl.
        std::array<unsigned char, 32> seed_hash{};
        CSHA256 hasher;
        if (m_has_seed) {
            hasher.Write(m_seed.data(), m_seed.size());
        } else {
            hasher.Write(m_fingerprint.data(), m_fingerprint.size());
        }
        hasher.Write(reinterpret_cast<const unsigned char*>(&pos), sizeof(pos)).Finalize(seed_hash.data());
        // Build a synthetic compressed pubkey (0x02 prefix + 32 bytes)
        unsigned char buf[33];
        buf[0] = 0x02;
        std::copy(seed_hash.begin(), seed_hash.end(), buf + 1);
        key.Set(buf, buf + 33);

        std::copy(m_fingerprint.begin(), m_fingerprint.end(), info.fingerprint);
        info.path = {87U | 0x80000000U, m_coin_type | 0x80000000U, m_account | 0x80000000U, m_change, static_cast<uint32_t>(pos)};
        return true;
    }

    std::string ToString(StringType type=StringType::PUBLIC) const override
    {
        // Public form: show fingerprint only, never the seed
        return strprintf("pqhd(%s/%uh/%uh/%u/*)",
                         HexStr(m_fingerprint), m_coin_type, m_account, m_change);
    }

    bool ToPrivateString(const SigningProvider& arg, std::string& out) const override
    {
        if (!m_has_seed) return false;
        // Private form: include the full hex seed (only when explicitly requested)
        out = strprintf("pqhd(%s/%uh/%uh/%u/*)",
                        HexStr(m_seed), m_coin_type, m_account, m_change);
        return true;
    }

    bool ToNormalizedString(const SigningProvider& arg, std::string& out, const DescriptorCache* cache) const override
    {
        out = ToString();
        return true;
    }

    bool GetPrivKey(int pos, const SigningProvider& arg, CKey& key) const override
    {
        // PQ-native provider doesn't produce ECDSA private keys
        return false;
    }

    std::optional<CPubKey> GetRootPubKey() const override { return std::nullopt; }
    std::optional<CExtPubKey> GetRootExtPubKey() const override { return std::nullopt; }

    std::unique_ptr<PubkeyProvider> Clone() const override
    {
        if (m_has_seed) {
            return std::make_unique<PQHDPubkeyProvider>(m_expr_index, m_seed, m_coin_type, m_account, m_change);
        }
        return std::make_unique<PQHDPubkeyProvider>(m_expr_index, m_fingerprint, m_coin_type, m_account, m_change);
    }
};

/** Base class for all Descriptor implementations. */
class DescriptorImpl : public Descriptor
{
protected:
    //! Public key arguments for this descriptor (size 1 for PK, PKH, WPKH; any size for WSH and Multisig).
    const std::vector<std::unique_ptr<PubkeyProvider>> m_pubkey_args;
    //! The string name of the descriptor function.
    const std::string m_name;

    //! The sub-descriptor arguments (empty for everything but SH and WSH).
    //! In doc/descriptors.m this is referred to as SCRIPT expressions sh(SCRIPT)
    //! and wsh(SCRIPT), and distinct from KEY expressions and ADDR expressions.
    //! Subdescriptors can only ever generate a single script.
    const std::vector<std::unique_ptr<DescriptorImpl>> m_subdescriptor_args;

    //! Return a serialization of anything except pubkey and script arguments, to be prepended to those.
    virtual std::string ToStringExtra() const { return ""; }

    /** A helper function to construct the scripts for this descriptor.
     *
     *  This function is invoked once by ExpandHelper.
     *
     *  @param pubkeys The evaluations of the m_pubkey_args field.
     *  @param scripts The evaluations of m_subdescriptor_args (one for each m_subdescriptor_args element).
     *  @param out A FlatSigningProvider to put scripts or public keys in that are necessary to the solver.
     *             The origin info of the provided pubkeys is automatically added.
     *  @return A vector with scriptPubKeys for this descriptor.
     */
    virtual std::vector<CScript> MakeScripts(int pos, const SigningProvider& arg, const std::vector<CPubKey>& pubkeys, Span<const CScript> scripts, FlatSigningProvider& out, const DescriptorCache* read_cache, DescriptorCache* write_cache) const = 0;

    /** Hook for descriptor-specific secret key expansion. Called by ExpandPrivate(). */
    virtual void ExpandPrivateImpl(int, const SigningProvider&, FlatSigningProvider&) const {}

public:
    DescriptorImpl(std::vector<std::unique_ptr<PubkeyProvider>> pubkeys, const std::string& name) : m_pubkey_args(std::move(pubkeys)), m_name(name), m_subdescriptor_args() {}
    DescriptorImpl(std::vector<std::unique_ptr<PubkeyProvider>> pubkeys, std::unique_ptr<DescriptorImpl> script, const std::string& name) : m_pubkey_args(std::move(pubkeys)), m_name(name), m_subdescriptor_args(Vector(std::move(script))) {}
    DescriptorImpl(std::vector<std::unique_ptr<PubkeyProvider>> pubkeys, std::vector<std::unique_ptr<DescriptorImpl>> scripts, const std::string& name) : m_pubkey_args(std::move(pubkeys)), m_name(name), m_subdescriptor_args(std::move(scripts)) {}

    enum class StringType
    {
        PUBLIC,
        PRIVATE,
        NORMALIZED,
        COMPAT, // string calculation that mustn't change over time to stay compatible with previous software versions
    };

    // NOLINTNEXTLINE(misc-no-recursion)
    bool IsSolvable() const override
    {
        for (const auto& arg : m_subdescriptor_args) {
            if (!arg->IsSolvable()) return false;
        }
        return true;
    }

    // NOLINTNEXTLINE(misc-no-recursion)
    bool IsRange() const final
    {
        for (const auto& pubkey : m_pubkey_args) {
            if (pubkey->IsRange()) return true;
        }
        for (const auto& arg : m_subdescriptor_args) {
            if (arg->IsRange()) return true;
        }
        return false;
    }

    // NOLINTNEXTLINE(misc-no-recursion)
    virtual bool ToStringSubScriptHelper(const SigningProvider* arg, std::string& ret, const StringType type, const DescriptorCache* cache = nullptr) const
    {
        size_t pos = 0;
        for (const auto& scriptarg : m_subdescriptor_args) {
            if (pos++) ret += ",";
            std::string tmp;
            if (!scriptarg->ToStringHelper(arg, tmp, type, cache)) return false;
            ret += tmp;
        }
        return true;
    }

    // NOLINTNEXTLINE(misc-no-recursion)
    virtual bool ToStringHelper(const SigningProvider* arg, std::string& out, const StringType type, const DescriptorCache* cache = nullptr) const
    {
        std::string extra = ToStringExtra();
        size_t pos = extra.size() > 0 ? 1 : 0;
        std::string ret = m_name + "(" + extra;
        for (const auto& pubkey : m_pubkey_args) {
            if (pos++) ret += ",";
            std::string tmp;
            switch (type) {
                case StringType::NORMALIZED:
                    if (!pubkey->ToNormalizedString(*arg, tmp, cache)) return false;
                    break;
                case StringType::PRIVATE:
                    if (!pubkey->ToPrivateString(*arg, tmp)) return false;
                    break;
                case StringType::PUBLIC:
                    tmp = pubkey->ToString();
                    break;
                case StringType::COMPAT:
                    tmp = pubkey->ToString(PubkeyProvider::StringType::COMPAT);
                    break;
            }
            ret += tmp;
        }
        std::string subscript;
        if (!ToStringSubScriptHelper(arg, subscript, type, cache)) return false;
        if (pos && subscript.size()) ret += ',';
        out = std::move(ret) + std::move(subscript) + ")";
        return true;
    }

    std::string ToString(bool compat_format) const final
    {
        std::string ret;
        ToStringHelper(nullptr, ret, compat_format ? StringType::COMPAT : StringType::PUBLIC);
        return AddChecksum(ret);
    }

    bool ToPrivateString(const SigningProvider& arg, std::string& out) const override
    {
        bool ret = ToStringHelper(&arg, out, StringType::PRIVATE);
        out = AddChecksum(out);
        return ret;
    }

    bool ToNormalizedString(const SigningProvider& arg, std::string& out, const DescriptorCache* cache) const override final
    {
        bool ret = ToStringHelper(&arg, out, StringType::NORMALIZED, cache);
        out = AddChecksum(out);
        return ret;
    }

    // NOLINTNEXTLINE(misc-no-recursion)
    bool ExpandHelper(int pos, const SigningProvider& arg, const DescriptorCache* read_cache, std::vector<CScript>& output_scripts, FlatSigningProvider& out, DescriptorCache* write_cache) const
    {
        std::vector<std::pair<CPubKey, KeyOriginInfo>> entries;
        entries.reserve(m_pubkey_args.size());

        // Construct temporary data in `entries`, `subscripts`, and `subprovider` to avoid producing output in case of failure.
        for (const auto& p : m_pubkey_args) {
            entries.emplace_back();
            if (!p->GetPubKey(pos, arg, entries.back().first, entries.back().second, read_cache, write_cache)) return false;
        }
        std::vector<CScript> subscripts;
        FlatSigningProvider subprovider;
        for (const auto& subarg : m_subdescriptor_args) {
            std::vector<CScript> outscripts;
            if (!subarg->ExpandHelper(pos, arg, read_cache, outscripts, subprovider, write_cache)) return false;
            assert(outscripts.size() == 1);
            subscripts.emplace_back(std::move(outscripts[0]));
        }
        out.Merge(std::move(subprovider));

        std::vector<CPubKey> pubkeys;
        pubkeys.reserve(entries.size());
        for (auto& entry : entries) {
            pubkeys.push_back(entry.first);
            out.origins.emplace(entry.first.GetID(), std::make_pair<CPubKey, KeyOriginInfo>(CPubKey(entry.first), std::move(entry.second)));
        }

        output_scripts = MakeScripts(pos, arg, pubkeys, Span{subscripts}, out, read_cache, write_cache);
        if (output_scripts.empty()) return false;
        return true;
    }

    bool Expand(int pos, const SigningProvider& provider, std::vector<CScript>& output_scripts, FlatSigningProvider& out, DescriptorCache* write_cache = nullptr) const final
    {
        return ExpandHelper(pos, provider, nullptr, output_scripts, out, write_cache);
    }

    bool ExpandFromCache(int pos, const DescriptorCache& read_cache, std::vector<CScript>& output_scripts, FlatSigningProvider& out) const final
    {
        return ExpandHelper(pos, DUMMY_SIGNING_PROVIDER, &read_cache, output_scripts, out, nullptr);
    }

    // NOLINTNEXTLINE(misc-no-recursion)
    void ExpandPrivate(int pos, const SigningProvider& provider, FlatSigningProvider& out) const final
    {
        for (const auto& p : m_pubkey_args) {
            CKey key;
            if (!p->GetPrivKey(pos, provider, key)) continue;
            out.keys.emplace(key.GetPubKey().GetID(), key);
        }
        for (const auto& arg : m_subdescriptor_args) {
            arg->ExpandPrivate(pos, provider, out);
        }
        ExpandPrivateImpl(pos, provider, out);
    }

    std::optional<OutputType> GetOutputType() const override { return std::nullopt; }

    std::optional<int64_t> ScriptSize() const override { return {}; }

    /** A helper for MaxSatisfactionWeight.
     *
     * @param use_max_sig Whether to assume ECDSA signatures will have a high-r.
     * @return The maximum size of the satisfaction in raw bytes (with no witness meaning).
     */
    virtual std::optional<int64_t> MaxSatSize(bool use_max_sig) const { return {}; }

    std::optional<int64_t> MaxSatisfactionWeight(bool) const override { return {}; }

    std::optional<int64_t> MaxSatisfactionElems() const override { return {}; }

    // NOLINTNEXTLINE(misc-no-recursion)
    void GetPubKeys(std::set<CPubKey>& pubkeys, std::set<CExtPubKey>& ext_pubs) const override
    {
        for (const auto& p : m_pubkey_args) {
            std::optional<CPubKey> pub = p->GetRootPubKey();
            if (pub) pubkeys.insert(*pub);
            std::optional<CExtPubKey> ext_pub = p->GetRootExtPubKey();
            if (ext_pub) ext_pubs.insert(*ext_pub);
        }
        for (const auto& arg : m_subdescriptor_args) {
            arg->GetPubKeys(pubkeys, ext_pubs);
        }
    }

    // NOLINTNEXTLINE(misc-no-recursion)
    void InjectPQSeed(Span<const unsigned char> seed) override
    {
        assert(seed.size() == 32);
        std::array<unsigned char, 32> seed_arr;
        std::copy(seed.begin(), seed.end(), seed_arr.begin());
        for (const auto& p : m_pubkey_args) {
            auto* pqhd = dynamic_cast<PQHDPubkeyProvider*>(p.get());
            if (pqhd && !pqhd->HasSeed()) {
                pqhd->SetSeed(seed_arr);
            }
        }
        for (const auto& arg : m_subdescriptor_args) {
            arg->InjectPQSeed(seed);
        }
    }

    std::optional<std::array<unsigned char, 32>> ExtractPQSeed() const override
    {
        for (const auto& p : m_pubkey_args) {
            auto* pqhd = dynamic_cast<PQHDPubkeyProvider*>(p.get());
            if (pqhd && pqhd->HasSeed()) {
                return pqhd->GetSeed();
            }
        }
        for (const auto& arg : m_subdescriptor_args) {
            auto result = arg->ExtractPQSeed();
            if (result) return result;
        }
        return std::nullopt;
    }

    // NOLINTNEXTLINE(misc-no-recursion)
    std::vector<std::pair<std::array<unsigned char, 4>, std::array<unsigned char, 32>>> ExtractAllPQSeeds() const override
    {
        std::vector<std::pair<std::array<unsigned char, 4>, std::array<unsigned char, 32>>> result;
        std::set<std::array<unsigned char, 4>> seen;
        for (const auto& p : m_pubkey_args) {
            auto* pqhd = dynamic_cast<PQHDPubkeyProvider*>(p.get());
            if (pqhd && pqhd->HasSeed() && seen.insert(pqhd->GetFingerprint()).second) {
                result.emplace_back(pqhd->GetFingerprint(), pqhd->GetSeed());
            }
        }
        for (const auto& arg : m_subdescriptor_args) {
            for (auto& entry : arg->ExtractAllPQSeeds()) {
                if (seen.insert(entry.first).second) {
                    result.push_back(std::move(entry));
                }
            }
        }
        return result;
    }

    // NOLINTNEXTLINE(misc-no-recursion)
    void InjectPQSeedByFingerprint(const std::array<unsigned char, 4>& fingerprint, Span<const unsigned char> seed) override
    {
        assert(seed.size() == 32);
        std::array<unsigned char, 32> seed_arr;
        std::copy(seed.begin(), seed.end(), seed_arr.begin());
        for (const auto& p : m_pubkey_args) {
            auto* pqhd = dynamic_cast<PQHDPubkeyProvider*>(p.get());
            if (pqhd && !pqhd->HasSeed() && pqhd->GetFingerprint() == fingerprint) {
                pqhd->SetSeed(seed_arr);
            }
        }
        for (const auto& arg : m_subdescriptor_args) {
            arg->InjectPQSeedByFingerprint(fingerprint, seed);
        }
    }

    virtual std::unique_ptr<DescriptorImpl> Clone() const = 0;
};

/** A parsed addr(A) descriptor. */
class AddressDescriptor final : public DescriptorImpl
{
    const CTxDestination m_destination;
protected:
    std::string ToStringExtra() const override { return EncodeDestination(m_destination); }
    std::vector<CScript> MakeScripts(int, const SigningProvider&, const std::vector<CPubKey>&, Span<const CScript>, FlatSigningProvider&, const DescriptorCache*, DescriptorCache*) const override { return Vector(GetScriptForDestination(m_destination)); }
public:
    AddressDescriptor(CTxDestination destination) : DescriptorImpl({}, "addr"), m_destination(std::move(destination)) {}
    bool IsSolvable() const final { return false; }

    std::optional<OutputType> GetOutputType() const override
    {
        return OutputTypeFromDestination(m_destination);
    }
    bool IsSingleType() const final { return true; }
    bool ToPrivateString(const SigningProvider& arg, std::string& out) const final { return false; }

    std::optional<int64_t> ScriptSize() const override { return GetScriptForDestination(m_destination).size(); }
    std::unique_ptr<DescriptorImpl> Clone() const override
    {
        return std::make_unique<AddressDescriptor>(m_destination);
    }
};

/** A parsed raw(H) descriptor. */
class RawDescriptor final : public DescriptorImpl
{
    const CScript m_script;
protected:
    std::string ToStringExtra() const override { return HexStr(m_script); }
    std::vector<CScript> MakeScripts(int, const SigningProvider&, const std::vector<CPubKey>&, Span<const CScript>, FlatSigningProvider&, const DescriptorCache*, DescriptorCache*) const override { return Vector(m_script); }
public:
    RawDescriptor(CScript script) : DescriptorImpl({}, "raw"), m_script(std::move(script)) {}
    bool IsSolvable() const final { return false; }

    std::optional<OutputType> GetOutputType() const override
    {
        CTxDestination dest;
        ExtractDestination(m_script, dest);
        return OutputTypeFromDestination(dest);
    }
    bool IsSingleType() const final { return true; }
    bool ToPrivateString(const SigningProvider& arg, std::string& out) const final { return false; }

    std::optional<int64_t> ScriptSize() const override { return m_script.size(); }

    std::unique_ptr<DescriptorImpl> Clone() const override
    {
        return std::make_unique<RawDescriptor>(m_script);
    }
};

/** A parsed pk(P) descriptor. */
class PKDescriptor final : public DescriptorImpl
{
private:
    const bool m_xonly;
protected:
    std::vector<CScript> MakeScripts(int, const SigningProvider&, const std::vector<CPubKey>& keys, Span<const CScript>, FlatSigningProvider& out, const DescriptorCache*, DescriptorCache*) const override
    {
        CKeyID id = keys[0].GetID();
        out.pubkeys.emplace(id, keys[0]);

        if (m_xonly) {
            CScript script = CScript() << ToByteVector(XOnlyPubKey(keys[0])) << OP_CHECKSIG;
            return Vector(std::move(script));
        } else {
            return Vector(GetScriptForRawPubKey(keys[0]));
        }
    }
public:
    PKDescriptor(std::unique_ptr<PubkeyProvider> prov, bool xonly = false) : DescriptorImpl(Vector(std::move(prov)), "pk"), m_xonly(xonly) {}
    bool IsSingleType() const final { return true; }

    std::optional<int64_t> ScriptSize() const override {
        return 1 + (m_xonly ? 32 : m_pubkey_args[0]->GetSize()) + 1;
    }

    std::optional<int64_t> MaxSatSize(bool use_max_sig) const override {
        const auto ecdsa_sig_size = use_max_sig ? 72 : 71;
        return 1 + (m_xonly ? 65 : ecdsa_sig_size);
    }

    std::optional<int64_t> MaxSatisfactionWeight(bool use_max_sig) const override {
        return *MaxSatSize(use_max_sig) * WITNESS_SCALE_FACTOR;
    }

    std::optional<int64_t> MaxSatisfactionElems() const override { return 1; }

    std::unique_ptr<DescriptorImpl> Clone() const override
    {
        return std::make_unique<PKDescriptor>(m_pubkey_args.at(0)->Clone(), m_xonly);
    }
};

/** A parsed pkh(P) descriptor. */
class PKHDescriptor final : public DescriptorImpl
{
protected:
    std::vector<CScript> MakeScripts(int, const SigningProvider&, const std::vector<CPubKey>& keys, Span<const CScript>, FlatSigningProvider& out, const DescriptorCache*, DescriptorCache*) const override
    {
        CKeyID id = keys[0].GetID();
        out.pubkeys.emplace(id, keys[0]);
        return Vector(GetScriptForDestination(PKHash(id)));
    }
public:
    PKHDescriptor(std::unique_ptr<PubkeyProvider> prov) : DescriptorImpl(Vector(std::move(prov)), "pkh") {}
    std::optional<OutputType> GetOutputType() const override { return OutputType::LEGACY; }
    bool IsSingleType() const final { return true; }

    std::optional<int64_t> ScriptSize() const override { return 1 + 1 + 1 + 20 + 1 + 1; }

    std::optional<int64_t> MaxSatSize(bool use_max_sig) const override {
        const auto sig_size = use_max_sig ? 72 : 71;
        return 1 + sig_size + 1 + m_pubkey_args[0]->GetSize();
    }

    std::optional<int64_t> MaxSatisfactionWeight(bool use_max_sig) const override {
        return *MaxSatSize(use_max_sig) * WITNESS_SCALE_FACTOR;
    }

    std::optional<int64_t> MaxSatisfactionElems() const override { return 2; }

    std::unique_ptr<DescriptorImpl> Clone() const override
    {
        return std::make_unique<PKHDescriptor>(m_pubkey_args.at(0)->Clone());
    }
};

/** A parsed wpkh(P) descriptor. */
class WPKHDescriptor final : public DescriptorImpl
{
protected:
    std::vector<CScript> MakeScripts(int, const SigningProvider&, const std::vector<CPubKey>& keys, Span<const CScript>, FlatSigningProvider& out, const DescriptorCache*, DescriptorCache*) const override
    {
        CKeyID id = keys[0].GetID();
        out.pubkeys.emplace(id, keys[0]);
        return Vector(GetScriptForDestination(WitnessV0KeyHash(id)));
    }
public:
    WPKHDescriptor(std::unique_ptr<PubkeyProvider> prov) : DescriptorImpl(Vector(std::move(prov)), "wpkh") {}
    std::optional<OutputType> GetOutputType() const override { return OutputType::BECH32; }
    bool IsSingleType() const final { return true; }

    std::optional<int64_t> ScriptSize() const override { return 1 + 1 + 20; }

    std::optional<int64_t> MaxSatSize(bool use_max_sig) const override {
        const auto sig_size = use_max_sig ? 72 : 71;
        return (1 + sig_size + 1 + 33);
    }

    std::optional<int64_t> MaxSatisfactionWeight(bool use_max_sig) const override {
        return MaxSatSize(use_max_sig);
    }

    std::optional<int64_t> MaxSatisfactionElems() const override { return 2; }

    std::unique_ptr<DescriptorImpl> Clone() const override
    {
        return std::make_unique<WPKHDescriptor>(m_pubkey_args.at(0)->Clone());
    }
};

/** A parsed combo(P) descriptor. */
class ComboDescriptor final : public DescriptorImpl
{
protected:
    std::vector<CScript> MakeScripts(int, const SigningProvider&, const std::vector<CPubKey>& keys, Span<const CScript>, FlatSigningProvider& out, const DescriptorCache*, DescriptorCache*) const override
    {
        std::vector<CScript> ret;
        CKeyID id = keys[0].GetID();
        out.pubkeys.emplace(id, keys[0]);
        ret.emplace_back(GetScriptForRawPubKey(keys[0])); // P2PK
        ret.emplace_back(GetScriptForDestination(PKHash(id))); // P2PKH
        if (keys[0].IsCompressed()) {
            CScript p2wpkh = GetScriptForDestination(WitnessV0KeyHash(id));
            out.scripts.emplace(CScriptID(p2wpkh), p2wpkh);
            ret.emplace_back(p2wpkh);
            ret.emplace_back(GetScriptForDestination(ScriptHash(p2wpkh))); // P2SH-P2WPKH
        }
        return ret;
    }
public:
    ComboDescriptor(std::unique_ptr<PubkeyProvider> prov) : DescriptorImpl(Vector(std::move(prov)), "combo") {}
    bool IsSingleType() const final { return false; }
    std::unique_ptr<DescriptorImpl> Clone() const override
    {
        return std::make_unique<ComboDescriptor>(m_pubkey_args.at(0)->Clone());
    }
};

/** A parsed multi(...) or sortedmulti(...) descriptor */
class MultisigDescriptor final : public DescriptorImpl
{
    const int m_threshold;
    const bool m_sorted;
protected:
    std::string ToStringExtra() const override { return strprintf("%i", m_threshold); }
    std::vector<CScript> MakeScripts(int, const SigningProvider&, const std::vector<CPubKey>& keys, Span<const CScript>, FlatSigningProvider&, const DescriptorCache*, DescriptorCache*) const override {
        if (m_sorted) {
            std::vector<CPubKey> sorted_keys(keys);
            std::sort(sorted_keys.begin(), sorted_keys.end());
            return Vector(GetScriptForMultisig(m_threshold, sorted_keys));
        }
        return Vector(GetScriptForMultisig(m_threshold, keys));
    }
public:
    MultisigDescriptor(int threshold, std::vector<std::unique_ptr<PubkeyProvider>> providers, bool sorted = false) : DescriptorImpl(std::move(providers), sorted ? "sortedmulti" : "multi"), m_threshold(threshold), m_sorted(sorted) {}
    bool IsSingleType() const final { return true; }

    std::optional<int64_t> ScriptSize() const override {
        const auto n_keys = m_pubkey_args.size();
        auto op = [](int64_t acc, const std::unique_ptr<PubkeyProvider>& pk) { return acc + 1 + pk->GetSize();};
        const auto pubkeys_size{std::accumulate(m_pubkey_args.begin(), m_pubkey_args.end(), int64_t{0}, op)};
        return 1 + BuildScript(n_keys).size() + BuildScript(m_threshold).size() + pubkeys_size;
    }

    std::optional<int64_t> MaxSatSize(bool use_max_sig) const override {
        const auto sig_size = use_max_sig ? 72 : 71;
        return (1 + (1 + sig_size) * m_threshold);
    }

    std::optional<int64_t> MaxSatisfactionWeight(bool use_max_sig) const override {
        return *MaxSatSize(use_max_sig) * WITNESS_SCALE_FACTOR;
    }

    std::optional<int64_t> MaxSatisfactionElems() const override { return 1 + m_threshold; }

    std::unique_ptr<DescriptorImpl> Clone() const override
    {
        std::vector<std::unique_ptr<PubkeyProvider>> providers;
        providers.reserve(m_pubkey_args.size());
        for (const auto& arg : m_pubkey_args) {
            providers.push_back(arg->Clone());
        }
        return std::make_unique<MultisigDescriptor>(m_threshold, std::move(providers), m_sorted);
    }
};

/** A parsed (sorted)multi_a(...) descriptor. Always uses x-only pubkeys. */
class MultiADescriptor final : public DescriptorImpl
{
    const int m_threshold;
    const bool m_sorted;
protected:
    std::string ToStringExtra() const override { return strprintf("%i", m_threshold); }
    std::vector<CScript> MakeScripts(int, const SigningProvider&, const std::vector<CPubKey>& keys, Span<const CScript>, FlatSigningProvider&, const DescriptorCache*, DescriptorCache*) const override {
        CScript ret;
        std::vector<XOnlyPubKey> xkeys;
        xkeys.reserve(keys.size());
        for (const auto& key : keys) xkeys.emplace_back(key);
        if (m_sorted) std::sort(xkeys.begin(), xkeys.end());
        ret << ToByteVector(xkeys[0]) << OP_CHECKSIG;
        for (size_t i = 1; i < keys.size(); ++i) {
            ret << ToByteVector(xkeys[i]) << OP_CHECKSIGADD;
        }
        ret << m_threshold << OP_NUMEQUAL;
        return Vector(std::move(ret));
    }
public:
    MultiADescriptor(int threshold, std::vector<std::unique_ptr<PubkeyProvider>> providers, bool sorted = false) : DescriptorImpl(std::move(providers), sorted ? "sortedmulti_a" : "multi_a"), m_threshold(threshold), m_sorted(sorted) {}
    bool IsSingleType() const final { return true; }

    std::optional<int64_t> ScriptSize() const override {
        const auto n_keys = m_pubkey_args.size();
        return (1 + 32 + 1) * n_keys + BuildScript(m_threshold).size() + 1;
    }

    std::optional<int64_t> MaxSatSize(bool use_max_sig) const override {
        return (1 + 65) * m_threshold + (m_pubkey_args.size() - m_threshold);
    }

    std::optional<int64_t> MaxSatisfactionElems() const override { return m_pubkey_args.size(); }

    std::unique_ptr<DescriptorImpl> Clone() const override
    {
        std::vector<std::unique_ptr<PubkeyProvider>> providers;
        providers.reserve(m_pubkey_args.size());
        for (const auto& arg : m_pubkey_args) {
            providers.push_back(arg->Clone());
        }
        return std::make_unique<MultiADescriptor>(m_threshold, std::move(providers), m_sorted);
    }
};

/** A parsed sh(...) descriptor. */
class SHDescriptor final : public DescriptorImpl
{
protected:
    std::vector<CScript> MakeScripts(int, const SigningProvider&, const std::vector<CPubKey>&, Span<const CScript> scripts, FlatSigningProvider& out, const DescriptorCache*, DescriptorCache*) const override
    {
        auto ret = Vector(GetScriptForDestination(ScriptHash(scripts[0])));
        if (ret.size()) out.scripts.emplace(CScriptID(scripts[0]), scripts[0]);
        return ret;
    }

    bool IsSegwit() const { return m_subdescriptor_args[0]->GetOutputType() == OutputType::BECH32; }

public:
    SHDescriptor(std::unique_ptr<DescriptorImpl> desc) : DescriptorImpl({}, std::move(desc), "sh") {}

    std::optional<OutputType> GetOutputType() const override
    {
        assert(m_subdescriptor_args.size() == 1);
        if (IsSegwit()) return OutputType::P2SH_SEGWIT;
        return OutputType::LEGACY;
    }
    bool IsSingleType() const final { return true; }

    std::optional<int64_t> ScriptSize() const override { return 1 + 1 + 20 + 1; }

    std::optional<int64_t> MaxSatisfactionWeight(bool use_max_sig) const override {
        if (const auto sat_size = m_subdescriptor_args[0]->MaxSatSize(use_max_sig)) {
            if (const auto subscript_size = m_subdescriptor_args[0]->ScriptSize()) {
                // The subscript is never witness data.
                const auto subscript_weight = (1 + *subscript_size) * WITNESS_SCALE_FACTOR;
                // The weight depends on whether the inner descriptor is satisfied using the witness stack.
                if (IsSegwit()) return subscript_weight + *sat_size;
                return subscript_weight + *sat_size * WITNESS_SCALE_FACTOR;
            }
        }
        return {};
    }

    std::optional<int64_t> MaxSatisfactionElems() const override {
        if (const auto sub_elems = m_subdescriptor_args[0]->MaxSatisfactionElems()) return 1 + *sub_elems;
        return {};
    }

    std::unique_ptr<DescriptorImpl> Clone() const override
    {
        return std::make_unique<SHDescriptor>(m_subdescriptor_args.at(0)->Clone());
    }
};

/** A parsed wsh(...) descriptor. */
class WSHDescriptor final : public DescriptorImpl
{
protected:
    std::vector<CScript> MakeScripts(int, const SigningProvider&, const std::vector<CPubKey>&, Span<const CScript> scripts, FlatSigningProvider& out, const DescriptorCache*, DescriptorCache*) const override
    {
        auto ret = Vector(GetScriptForDestination(WitnessV0ScriptHash(scripts[0])));
        if (ret.size()) out.scripts.emplace(CScriptID(scripts[0]), scripts[0]);
        return ret;
    }
public:
    WSHDescriptor(std::unique_ptr<DescriptorImpl> desc) : DescriptorImpl({}, std::move(desc), "wsh") {}
    std::optional<OutputType> GetOutputType() const override { return OutputType::BECH32; }
    bool IsSingleType() const final { return true; }

    std::optional<int64_t> ScriptSize() const override { return 1 + 1 + 32; }

    std::optional<int64_t> MaxSatSize(bool use_max_sig) const override {
        if (const auto sat_size = m_subdescriptor_args[0]->MaxSatSize(use_max_sig)) {
            if (const auto subscript_size = m_subdescriptor_args[0]->ScriptSize()) {
                return GetSizeOfCompactSize(*subscript_size) + *subscript_size + *sat_size;
            }
        }
        return {};
    }

    std::optional<int64_t> MaxSatisfactionWeight(bool use_max_sig) const override {
        return MaxSatSize(use_max_sig);
    }

    std::optional<int64_t> MaxSatisfactionElems() const override {
        if (const auto sub_elems = m_subdescriptor_args[0]->MaxSatisfactionElems()) return 1 + *sub_elems;
        return {};
    }

    std::unique_ptr<DescriptorImpl> Clone() const override
    {
        return std::make_unique<WSHDescriptor>(m_subdescriptor_args.at(0)->Clone());
    }
};

/** A parsed tr(...) descriptor. */
class TRDescriptor final : public DescriptorImpl
{
    std::vector<int> m_depths;
protected:
    std::vector<CScript> MakeScripts(int, const SigningProvider&, const std::vector<CPubKey>& keys, Span<const CScript> scripts, FlatSigningProvider& out, const DescriptorCache*, DescriptorCache*) const override
    {
        TaprootBuilder builder;
        assert(m_depths.size() == scripts.size());
        for (size_t pos = 0; pos < m_depths.size(); ++pos) {
            builder.Add(m_depths[pos], scripts[pos], TAPROOT_LEAF_TAPSCRIPT);
        }
        if (!builder.IsComplete()) return {};
        assert(keys.size() == 1);
        XOnlyPubKey xpk(keys[0]);
        if (!xpk.IsFullyValid()) return {};
        builder.Finalize(xpk);
        WitnessV1Taproot output = builder.GetOutput();
        out.tr_trees[output] = builder;
        out.pubkeys.emplace(keys[0].GetID(), keys[0]);
        return Vector(GetScriptForDestination(output));
    }
    bool ToStringSubScriptHelper(const SigningProvider* arg, std::string& ret, const StringType type, const DescriptorCache* cache = nullptr) const override
    {
        if (m_depths.empty()) return true;
        std::vector<bool> path;
        for (size_t pos = 0; pos < m_depths.size(); ++pos) {
            if (pos) ret += ',';
            while ((int)path.size() <= m_depths[pos]) {
                if (path.size()) ret += '{';
                path.push_back(false);
            }
            std::string tmp;
            if (!m_subdescriptor_args[pos]->ToStringHelper(arg, tmp, type, cache)) return false;
            ret += tmp;
            while (!path.empty() && path.back()) {
                if (path.size() > 1) ret += '}';
                path.pop_back();
            }
            if (!path.empty()) path.back() = true;
        }
        return true;
    }
public:
    TRDescriptor(std::unique_ptr<PubkeyProvider> internal_key, std::vector<std::unique_ptr<DescriptorImpl>> descs, std::vector<int> depths) :
        DescriptorImpl(Vector(std::move(internal_key)), std::move(descs), "tr"), m_depths(std::move(depths))
    {
        assert(m_subdescriptor_args.size() == m_depths.size());
    }
    std::optional<OutputType> GetOutputType() const override { return OutputType::BECH32M; }
    bool IsSingleType() const final { return true; }

    std::optional<int64_t> ScriptSize() const override { return 1 + 1 + 32; }

    std::optional<int64_t> MaxSatisfactionWeight(bool use_max_sig) const override {
        int64_t max_weight = 1 + 65; // key path spend
        for (size_t pos = 0; pos < m_subdescriptor_args.size(); ++pos) {
            const auto sat_size = m_subdescriptor_args[pos]->MaxSatSize(use_max_sig);
            const auto script_size = m_subdescriptor_args[pos]->ScriptSize();
            if (!sat_size || !script_size) return {};

            const int64_t control_block_size = 33 + (32 * m_depths[pos]);
            const int64_t script_path_weight =
                *sat_size +
                GetSizeOfCompactSize(*script_size) + *script_size +
                GetSizeOfCompactSize(control_block_size) + control_block_size;
            max_weight = std::max(max_weight, script_path_weight);
        }
        return max_weight;
    }

    std::optional<int64_t> MaxSatisfactionElems() const override {
        int64_t max_elems = 1; // key path spend
        for (const auto& subdesc : m_subdescriptor_args) {
            const auto sub_elems = subdesc->MaxSatisfactionElems();
            if (!sub_elems) return {};
            max_elems = std::max<int64_t>(max_elems, *sub_elems + 2); // script + control block
        }
        return max_elems;
    }

    std::unique_ptr<DescriptorImpl> Clone() const override
    {
        std::vector<std::unique_ptr<DescriptorImpl>> subdescs;
        subdescs.reserve(m_subdescriptor_args.size());
        for (const auto& subdesc : m_subdescriptor_args) {
            subdescs.push_back(subdesc->Clone());
        }
        return std::make_unique<TRDescriptor>(m_pubkey_args.at(0)->Clone(), std::move(subdescs), m_depths);
    }
};

/* We instantiate Miniscript here with a simple integer as key type.
 * The value of these key integers are an index in the
 * DescriptorImpl::m_pubkey_args vector.
 */

/**
 * The context for converting a Miniscript descriptor into a Script.
 */
class ScriptMaker {
    //! Keys contained in the Miniscript (the evaluation of DescriptorImpl::m_pubkey_args).
    const std::vector<CPubKey>& m_keys;
    //! The script context we're operating within (Tapscript or P2WSH).
    const miniscript::MiniscriptContext m_script_ctx;

    //! Get the ripemd160(sha256()) hash of this key.
    //! Any key that is valid in a descriptor serializes as 32 bytes within a Tapscript context. So we
    //! must not hash the sign-bit byte in this case.
    uint160 GetHash160(uint32_t key) const {
        if (miniscript::IsTapscript(m_script_ctx)) {
            return Hash160(XOnlyPubKey{m_keys[key]});
        }
        return m_keys[key].GetID();
    }

public:
    ScriptMaker(const std::vector<CPubKey>& keys LIFETIMEBOUND, const miniscript::MiniscriptContext script_ctx) : m_keys(keys), m_script_ctx{script_ctx} {}

    std::vector<unsigned char> ToPKBytes(uint32_t key) const {
        // In Tapscript keys always serialize as x-only, whether an x-only key was used in the descriptor or not.
        if (!miniscript::IsTapscript(m_script_ctx)) {
            return {m_keys[key].begin(), m_keys[key].end()};
        }
        const XOnlyPubKey xonly_pubkey{m_keys[key]};
        return {xonly_pubkey.begin(), xonly_pubkey.end()};
    }

    std::vector<unsigned char> ToPKHBytes(uint32_t key) const {
        auto id = GetHash160(key);
        return {id.begin(), id.end()};
    }
};

/**
 * The context for converting a Miniscript descriptor to its textual form.
 */
class StringMaker {
    //! To convert private keys for private descriptors.
    const SigningProvider* m_arg;
    //! Keys contained in the Miniscript (a reference to DescriptorImpl::m_pubkey_args).
    const std::vector<std::unique_ptr<PubkeyProvider>>& m_pubkeys;
    //! Whether to serialize keys as private or public.
    bool m_private;

public:
    StringMaker(const SigningProvider* arg LIFETIMEBOUND, const std::vector<std::unique_ptr<PubkeyProvider>>& pubkeys LIFETIMEBOUND, bool priv)
        : m_arg(arg), m_pubkeys(pubkeys), m_private(priv) {}

    std::optional<std::string> ToString(uint32_t key) const
    {
        std::string ret;
        if (m_private) {
            if (!m_pubkeys[key]->ToPrivateString(*m_arg, ret)) return {};
        } else {
            ret = m_pubkeys[key]->ToString();
        }
        return ret;
    }
};

class MiniscriptDescriptor final : public DescriptorImpl
{
private:
    miniscript::NodeRef<uint32_t> m_node;

protected:
    std::vector<CScript> MakeScripts(int, const SigningProvider&, const std::vector<CPubKey>& keys, Span<const CScript>,
                                     FlatSigningProvider& provider, const DescriptorCache*, DescriptorCache*) const override
    {
        const auto script_ctx{m_node->GetMsCtx()};
        for (const auto& key : keys) {
            if (miniscript::IsTapscript(script_ctx)) {
                provider.pubkeys.emplace(Hash160(XOnlyPubKey{key}), key);
            } else {
                provider.pubkeys.emplace(key.GetID(), key);
            }
        }
        return Vector(m_node->ToScript(ScriptMaker(keys, script_ctx)));
    }

public:
    MiniscriptDescriptor(std::vector<std::unique_ptr<PubkeyProvider>> providers, miniscript::NodeRef<uint32_t> node)
        : DescriptorImpl(std::move(providers), "?"), m_node(std::move(node)) {}

    bool ToStringHelper(const SigningProvider* arg, std::string& out, const StringType type,
                        const DescriptorCache* cache = nullptr) const override
    {
        if (const auto res = m_node->ToString(StringMaker(arg, m_pubkey_args, type == StringType::PRIVATE))) {
            out = *res;
            return true;
        }
        return false;
    }

    bool IsSolvable() const override { return true; }
    bool IsSingleType() const final { return true; }

    std::optional<int64_t> ScriptSize() const override { return m_node->ScriptSize(); }

    std::optional<int64_t> MaxSatSize(bool) const override {
        // For Miniscript we always assume high-R ECDSA signatures.
        return m_node->GetWitnessSize();
    }

    std::optional<int64_t> MaxSatisfactionElems() const override {
        return m_node->GetStackSize();
    }

    std::unique_ptr<DescriptorImpl> Clone() const override
    {
        std::vector<std::unique_ptr<PubkeyProvider>> providers;
        providers.reserve(m_pubkey_args.size());
        for (const auto& arg : m_pubkey_args) {
            providers.push_back(arg->Clone());
        }
        return std::make_unique<MiniscriptDescriptor>(std::move(providers), m_node->Clone());
    }
};

/** A parsed rawtr(...) descriptor. */
class RawTRDescriptor final : public DescriptorImpl
{
protected:
    std::vector<CScript> MakeScripts(int, const SigningProvider&, const std::vector<CPubKey>& keys, Span<const CScript>, FlatSigningProvider&, const DescriptorCache*, DescriptorCache*) const override
    {
        assert(keys.size() == 1);
        XOnlyPubKey xpk(keys[0]);
        if (!xpk.IsFullyValid()) return {};
        WitnessV1Taproot output{xpk};
        return Vector(GetScriptForDestination(output));
    }
public:
    RawTRDescriptor(std::unique_ptr<PubkeyProvider> output_key) : DescriptorImpl(Vector(std::move(output_key)), "rawtr") {}
    std::optional<OutputType> GetOutputType() const override { return OutputType::BECH32M; }
    bool IsSingleType() const final { return true; }

    std::optional<int64_t> ScriptSize() const override { return 1 + 1 + 32; }

    std::optional<int64_t> MaxSatisfactionWeight(bool) const override {
        // We can't know whether there is a script path, so assume key path spend.
        return 1 + 65;
    }

    std::optional<int64_t> MaxSatisfactionElems() const override {
        // See above, we assume keypath spend.
        return 1;
    }

    std::unique_ptr<DescriptorImpl> Clone() const override
    {
        return std::make_unique<RawTRDescriptor>(m_pubkey_args.at(0)->Clone());
    }
};

enum class MRLeafType {
    CHECKSIG,
    MULTISIG_PQ,
    CLTV_MULTISIG_PQ,
    CSV_MULTISIG_PQ,
    HTLC,
    REFUND,
    CTV_ONLY,
    CTV_CHECKSIG,
    CTV_MULTISIG_PQ,
    CSFS_ONLY,
    CSFS_VERIFY_CHECKSIG,
};

struct MRLeafSpec {
    MRLeafType type{MRLeafType::CHECKSIG};
    PQAlgorithm algo{PQAlgorithm::ML_DSA_44};
    int provider_index{-1};
    std::vector<unsigned char> fixed_pubkey;
    uint8_t multisig_threshold{0};
    bool multisig_sorted{false};
    std::vector<PQAlgorithm> multisig_algos;
    std::vector<int> multisig_provider_indices;
    std::vector<std::vector<unsigned char>> multisig_fixed_pubkeys;
    std::vector<unsigned char> htlc_hash160;
    int64_t locktime{0};
    int64_t sequence{0};

    uint256 ctv_hash{};

    PQAlgorithm csfs_algo{PQAlgorithm::ML_DSA_44};
    int csfs_provider_index{-1};
    std::vector<unsigned char> csfs_fixed_pubkey;
};

std::vector<unsigned char> DummyP2MRPubkey(PQAlgorithm algo)
{
    if (algo == PQAlgorithm::ML_DSA_44) return std::vector<unsigned char>(MLDSA44_PUBKEY_SIZE, 0);
    if (algo == PQAlgorithm::SLH_DSA_128S) return std::vector<unsigned char>(SLHDSA128S_PUBKEY_SIZE, 0);
    return {};
}

bool LeafUsesPrimaryKey(const MRLeafSpec& leaf)
{
    return leaf.type == MRLeafType::CHECKSIG ||
           leaf.type == MRLeafType::REFUND ||
           leaf.type == MRLeafType::CTV_CHECKSIG ||
           leaf.type == MRLeafType::CSFS_VERIFY_CHECKSIG;
}

bool LeafUsesMultisigKeys(const MRLeafSpec& leaf)
{
    return leaf.type == MRLeafType::MULTISIG_PQ ||
           leaf.type == MRLeafType::CLTV_MULTISIG_PQ ||
           leaf.type == MRLeafType::CSV_MULTISIG_PQ ||
           leaf.type == MRLeafType::CTV_MULTISIG_PQ;
}

bool LeafUsesCSFSKey(const MRLeafSpec& leaf)
{
    return leaf.type == MRLeafType::HTLC ||
           leaf.type == MRLeafType::CSFS_ONLY ||
           leaf.type == MRLeafType::CSFS_VERIFY_CHECKSIG;
}

std::vector<unsigned char> BuildP2MRLeafScript(
    const MRLeafSpec& leaf,
    Span<const unsigned char> primary_pubkey,
    Span<const unsigned char> csfs_pubkey,
    const std::vector<std::pair<PQAlgorithm, std::vector<unsigned char>>>& multisig_pubkeys)
{
    switch (leaf.type) {
    case MRLeafType::CHECKSIG:
        return BuildP2MRScript(leaf.algo, primary_pubkey);
    case MRLeafType::MULTISIG_PQ:
        return BuildP2MRMultisigScript(leaf.multisig_threshold, multisig_pubkeys);
    case MRLeafType::CLTV_MULTISIG_PQ:
        return BuildP2MRCLTVMultisigScript(leaf.locktime, leaf.multisig_threshold, multisig_pubkeys);
    case MRLeafType::CSV_MULTISIG_PQ:
        return BuildP2MRCSVMultisigScript(leaf.sequence, leaf.multisig_threshold, multisig_pubkeys);
    case MRLeafType::HTLC:
        return BuildP2MRHTLCLeaf(leaf.htlc_hash160, leaf.csfs_algo, csfs_pubkey);
    case MRLeafType::REFUND:
        return BuildP2MRRefundLeaf(leaf.locktime, leaf.algo, primary_pubkey);
    case MRLeafType::CTV_ONLY:
        return BuildP2MRCTVScript(leaf.ctv_hash);
    case MRLeafType::CTV_CHECKSIG:
        return BuildP2MRCTVChecksigScript(leaf.ctv_hash, leaf.algo, primary_pubkey);
    case MRLeafType::CTV_MULTISIG_PQ:
        return BuildP2MRMultisigCTVScript(leaf.ctv_hash, leaf.multisig_threshold, multisig_pubkeys);
    case MRLeafType::CSFS_ONLY:
        return BuildP2MRCSFSScript(leaf.csfs_algo, csfs_pubkey);
    case MRLeafType::CSFS_VERIFY_CHECKSIG:
        return BuildP2MRDelegationScript(leaf.csfs_algo, csfs_pubkey, leaf.algo, primary_pubkey);
    }
    assert(false);
}

static int64_t GetP2MRWitnessElementSize(size_t payload_size)
{
    return GetSizeOfCompactSize(payload_size) + static_cast<int64_t>(payload_size);
}

static bool BuildDummyP2MRLeafScript(const MRLeafSpec& leaf, std::vector<unsigned char>& leaf_script)
{
    std::vector<unsigned char> primary_pubkey = leaf.fixed_pubkey;
    std::vector<unsigned char> csfs_pubkey = leaf.csfs_fixed_pubkey;
    std::vector<std::pair<PQAlgorithm, std::vector<unsigned char>>> multisig_pubkeys;
    if (LeafUsesPrimaryKey(leaf) && primary_pubkey.empty()) {
        primary_pubkey = DummyP2MRPubkey(leaf.algo);
    }
    if (LeafUsesMultisigKeys(leaf)) {
        if (leaf.multisig_algos.size() != leaf.multisig_provider_indices.size() ||
            leaf.multisig_algos.size() != leaf.multisig_fixed_pubkeys.size()) {
            return false;
        }
        multisig_pubkeys.reserve(leaf.multisig_algos.size());
        for (size_t key_pos = 0; key_pos < leaf.multisig_algos.size(); ++key_pos) {
            std::vector<unsigned char> key = leaf.multisig_fixed_pubkeys[key_pos];
            if (key.empty()) {
                key = DummyP2MRPubkey(leaf.multisig_algos[key_pos]);
                if (!key.empty()) {
                    key[0] ^= static_cast<unsigned char>(key_pos + 1);
                }
            }
            multisig_pubkeys.emplace_back(leaf.multisig_algos[key_pos], std::move(key));
        }
        if (leaf.multisig_sorted) {
            std::sort(multisig_pubkeys.begin(), multisig_pubkeys.end(), [](const auto& lhs, const auto& rhs) {
                return lhs.second < rhs.second;
            });
        }
    }
    if (LeafUsesCSFSKey(leaf) && csfs_pubkey.empty()) {
        csfs_pubkey = DummyP2MRPubkey(leaf.csfs_algo);
    }

    leaf_script = BuildP2MRLeafScript(leaf, primary_pubkey, csfs_pubkey, multisig_pubkeys);
    return !leaf_script.empty();
}

static std::vector<int64_t> GetP2MRMerklePathDepths(size_t leaf_count)
{
    std::vector<int64_t> path_depths(leaf_count, 0);
    std::vector<std::vector<size_t>> level_indices(leaf_count);
    for (size_t i = 0; i < leaf_count; ++i) {
        level_indices[i].push_back(i);
    }

    while (level_indices.size() > 1) {
        std::vector<std::vector<size_t>> next_indices;
        next_indices.reserve((level_indices.size() + 1) / 2);
        for (size_t i = 0; i < level_indices.size(); i += 2) {
            if (i + 1 < level_indices.size()) {
                for (const size_t idx : level_indices[i]) ++path_depths[idx];
                for (const size_t idx : level_indices[i + 1]) ++path_depths[idx];

                std::vector<size_t> merged = std::move(level_indices[i]);
                merged.insert(merged.end(), level_indices[i + 1].begin(), level_indices[i + 1].end());
                next_indices.push_back(std::move(merged));
            } else {
                next_indices.push_back(std::move(level_indices[i]));
            }
        }
        level_indices = std::move(next_indices);
    }

    return path_depths;
}

static std::optional<int64_t> GetP2MRLeafMaxSatSize(const MRLeafSpec& leaf, int64_t control_block_size)
{
    std::vector<unsigned char> leaf_script;
    if (!BuildDummyP2MRLeafScript(leaf, leaf_script)) return {};

    const int64_t script_push_size = GetP2MRWitnessElementSize(leaf_script.size());
    const int64_t control_push_size = GetP2MRWitnessElementSize(control_block_size);
    auto checksig_leaf_size = [&](PQAlgorithm algo) -> int64_t {
        return GetP2MRWitnessElementSize(GetPQSignatureSize(algo)) + script_push_size + control_push_size;
    };

    switch (leaf.type) {
    case MRLeafType::CHECKSIG:
    case MRLeafType::REFUND:
    case MRLeafType::CTV_CHECKSIG:
        return checksig_leaf_size(leaf.algo);
    case MRLeafType::MULTISIG_PQ:
    case MRLeafType::CLTV_MULTISIG_PQ:
    case MRLeafType::CSV_MULTISIG_PQ:
    case MRLeafType::CTV_MULTISIG_PQ: {
        if (leaf.multisig_algos.size() != leaf.multisig_provider_indices.size() ||
            leaf.multisig_algos.size() != leaf.multisig_fixed_pubkeys.size()) {
            return {};
        }
        if (leaf.multisig_threshold == 0 || leaf.multisig_threshold > leaf.multisig_algos.size()) return {};

        std::vector<size_t> sig_sizes;
        sig_sizes.reserve(leaf.multisig_algos.size());
        for (const PQAlgorithm algo : leaf.multisig_algos) {
            sig_sizes.push_back(GetPQSignatureSize(algo));
        }
        std::sort(sig_sizes.begin(), sig_sizes.end(), std::greater<size_t>());

        int64_t sat_size{0};
        for (size_t i = 0; i < sig_sizes.size(); ++i) {
            sat_size += GetP2MRWitnessElementSize(i < leaf.multisig_threshold ? sig_sizes[i] : 0);
        }
        return sat_size + script_push_size + control_push_size;
    }
    case MRLeafType::CTV_ONLY:
        return script_push_size + control_push_size;
    case MRLeafType::HTLC:
    case MRLeafType::CSFS_ONLY:
    case MRLeafType::CSFS_VERIFY_CHECKSIG:
        return {};
    }
    assert(false);
}

static std::optional<int64_t> GetP2MRLeafMaxSatElems(const MRLeafSpec& leaf)
{
    switch (leaf.type) {
    case MRLeafType::CHECKSIG:
    case MRLeafType::REFUND:
    case MRLeafType::CTV_CHECKSIG:
        return 3;
    case MRLeafType::MULTISIG_PQ:
    case MRLeafType::CLTV_MULTISIG_PQ:
    case MRLeafType::CSV_MULTISIG_PQ:
    case MRLeafType::CTV_MULTISIG_PQ:
        if (leaf.multisig_algos.size() != leaf.multisig_provider_indices.size() ||
            leaf.multisig_algos.size() != leaf.multisig_fixed_pubkeys.size()) {
            return {};
        }
        return static_cast<int64_t>(leaf.multisig_algos.size()) + 2;
    case MRLeafType::CTV_ONLY:
        return 2;
    case MRLeafType::HTLC:
    case MRLeafType::CSFS_ONLY:
        return 4;
    case MRLeafType::CSFS_VERIFY_CHECKSIG:
        return 5;
    }
    assert(false);
}

class MRDescriptor final : public DescriptorImpl
{
private:
    std::vector<MRLeafSpec> m_leaf_specs;
    std::vector<std::string> m_leaf_exprs;

protected:
    std::string ToStringExtra() const override
    {
        std::string ret;
        for (size_t i = 0; i < m_leaf_exprs.size(); ++i) {
            if (i) ret += ",";
            ret += m_leaf_exprs[i];
        }
        return ret;
    }

    bool ToStringHelper(const SigningProvider* arg, std::string& out, const StringType type, const DescriptorCache* cache = nullptr) const override
    {
        auto render_provider = [&](int provider_index, std::string& provider_out) -> bool {
            if (provider_index < 0 || static_cast<size_t>(provider_index) >= m_pubkey_args.size()) return false;
            const auto& provider = m_pubkey_args[provider_index];
            switch (type) {
            case StringType::NORMALIZED:
                if (arg == nullptr) return false;
                return provider->ToNormalizedString(*arg, provider_out, cache);
            case StringType::PRIVATE:
                if (arg == nullptr) return false;
                return provider->ToPrivateString(*arg, provider_out);
            case StringType::PUBLIC:
                provider_out = provider->ToString();
                return true;
            case StringType::COMPAT:
                provider_out = provider->ToString(PubkeyProvider::StringType::COMPAT);
                return true;
            }
            return false;
        };

        auto render_key = [&](PQAlgorithm algo, int provider_index, const std::vector<unsigned char>& fixed_pubkey, std::string& key_out) -> bool {
            if (!fixed_pubkey.empty()) {
                key_out = algo == PQAlgorithm::ML_DSA_44
                    ? HexStr(fixed_pubkey)
                    : strprintf("pk_slh(%s)", HexStr(fixed_pubkey));
                return true;
            }
            std::string provider_str;
            if (!render_provider(provider_index, provider_str)) return false;
            key_out = algo == PQAlgorithm::ML_DSA_44
                ? provider_str
                : strprintf("pk_slh(%s)", provider_str);
            return true;
        };

        std::string ret = "mr(";
        for (size_t i = 0; i < m_leaf_specs.size(); ++i) {
            if (i) ret += ",";
            const auto& leaf = m_leaf_specs[i];
            std::string key_expr;
            std::string csfs_key_expr;
            switch (leaf.type) {
            case MRLeafType::CHECKSIG:
                if (!render_key(leaf.algo, leaf.provider_index, leaf.fixed_pubkey, key_expr)) return false;
                ret += key_expr;
                break;
            case MRLeafType::MULTISIG_PQ:
            case MRLeafType::CLTV_MULTISIG_PQ:
            case MRLeafType::CSV_MULTISIG_PQ:
            case MRLeafType::CTV_MULTISIG_PQ: {
                if (leaf.multisig_algos.empty() ||
                    leaf.multisig_algos.size() != leaf.multisig_provider_indices.size() ||
                    leaf.multisig_algos.size() != leaf.multisig_fixed_pubkeys.size()) {
                    return false;
                }
                std::vector<std::string> key_exprs;
                key_exprs.reserve(leaf.multisig_algos.size());
                for (size_t key_pos = 0; key_pos < leaf.multisig_algos.size(); ++key_pos) {
                    std::string rendered_key;
                    if (!render_key(
                            leaf.multisig_algos[key_pos],
                            leaf.multisig_provider_indices[key_pos],
                            leaf.multisig_fixed_pubkeys[key_pos],
                            rendered_key)) {
                        return false;
                    }
                    key_exprs.push_back(std::move(rendered_key));
                }
                std::string fn_name;
                switch (leaf.type) {
                case MRLeafType::MULTISIG_PQ:
                    fn_name = leaf.multisig_sorted ? "sortedmulti_pq" : "multi_pq";
                    ret += strprintf("%s(%u", fn_name, leaf.multisig_threshold);
                    break;
                case MRLeafType::CLTV_MULTISIG_PQ:
                    fn_name = leaf.multisig_sorted ? "cltv_sortedmulti_pq" : "cltv_multi_pq";
                    ret += strprintf("%s(%lld,%u", fn_name, static_cast<long long>(leaf.locktime), leaf.multisig_threshold);
                    break;
                case MRLeafType::CSV_MULTISIG_PQ:
                    fn_name = leaf.multisig_sorted ? "csv_sortedmulti_pq" : "csv_multi_pq";
                    ret += strprintf("%s(%lld,%u", fn_name, static_cast<long long>(leaf.sequence), leaf.multisig_threshold);
                    break;
                case MRLeafType::CTV_MULTISIG_PQ:
                    fn_name = leaf.multisig_sorted ? "ctv_sortedmulti_pq" : "ctv_multi_pq";
                    ret += strprintf("%s(%s,%u", fn_name, HexStr(leaf.ctv_hash), leaf.multisig_threshold);
                    break;
                default:
                    assert(false);
                }
                for (const auto& rendered_key : key_exprs) {
                    ret += "," + rendered_key;
                }
                ret += ")";
                break;
            }
            case MRLeafType::HTLC:
                if (!render_key(leaf.csfs_algo, leaf.csfs_provider_index, leaf.csfs_fixed_pubkey, csfs_key_expr)) return false;
                ret += strprintf("htlc(%s,%s)", HexStr(leaf.htlc_hash160), csfs_key_expr);
                break;
            case MRLeafType::REFUND:
                if (!render_key(leaf.algo, leaf.provider_index, leaf.fixed_pubkey, key_expr)) return false;
                ret += strprintf("refund(%lld,%s)", static_cast<long long>(leaf.locktime), key_expr);
                break;
            case MRLeafType::CTV_ONLY:
                ret += strprintf("ctv(%s)", HexStr(leaf.ctv_hash));
                break;
            case MRLeafType::CTV_CHECKSIG:
                if (!render_key(leaf.algo, leaf.provider_index, leaf.fixed_pubkey, key_expr)) return false;
                ret += strprintf("ctv_pk(%s,%s)", HexStr(leaf.ctv_hash), key_expr);
                break;
            case MRLeafType::CSFS_ONLY:
                if (!render_key(leaf.csfs_algo, leaf.csfs_provider_index, leaf.csfs_fixed_pubkey, csfs_key_expr)) return false;
                ret += strprintf("csfs(%s)", csfs_key_expr);
                break;
            case MRLeafType::CSFS_VERIFY_CHECKSIG:
                if (!render_key(leaf.csfs_algo, leaf.csfs_provider_index, leaf.csfs_fixed_pubkey, csfs_key_expr)) return false;
                if (!render_key(leaf.algo, leaf.provider_index, leaf.fixed_pubkey, key_expr)) return false;
                ret += strprintf("csfs_pk(%s,%s)", csfs_key_expr, key_expr);
                break;
            }
        }
        ret += ")";
        out = std::move(ret);
        return true;
    }

    void ExpandPrivateImpl(int pos, const SigningProvider& provider, FlatSigningProvider& out) const override
    {
        auto add_private_key = [&](PQAlgorithm algo, int provider_index, const std::vector<unsigned char>& fixed_pubkey) {
            if (!fixed_pubkey.empty()) return;
            if (provider_index < 0 || static_cast<size_t>(provider_index) >= m_pubkey_args.size()) return;

            const auto* pqhd = dynamic_cast<const PQHDPubkeyProvider*>(m_pubkey_args[provider_index].get());
            if (!pqhd) return;
            auto pq_key_opt = pqhd->GetPQKey(pos, algo);
            if (!pq_key_opt) return;
            CPQKey pq_key = std::move(*pq_key_opt);
            std::vector<unsigned char> pq_pubkey = pq_key.GetPubKey();
            if (pq_pubkey.empty()) return;
            out.pq_keys[pq_pubkey] = std::move(pq_key);
        };

        for (const auto& leaf : m_leaf_specs) {
            if (LeafUsesPrimaryKey(leaf)) {
                add_private_key(leaf.algo, leaf.provider_index, leaf.fixed_pubkey);
            }
            if (LeafUsesMultisigKeys(leaf)) {
                for (size_t key_pos = 0; key_pos < leaf.multisig_algos.size(); ++key_pos) {
                    add_private_key(
                        leaf.multisig_algos[key_pos],
                        leaf.multisig_provider_indices[key_pos],
                        leaf.multisig_fixed_pubkeys[key_pos]);
                }
            }
            if (LeafUsesCSFSKey(leaf)) {
                add_private_key(leaf.csfs_algo, leaf.csfs_provider_index, leaf.csfs_fixed_pubkey);
            }
        }
    }

    std::vector<CScript> MakeScripts(int pos, const SigningProvider& arg, const std::vector<CPubKey>&, Span<const CScript>, FlatSigningProvider& out, const DescriptorCache* read_cache, DescriptorCache* write_cache) const override
    {
        std::vector<uint256> leaf_hashes;
        std::vector<std::vector<unsigned char>> leaf_scripts;
        leaf_hashes.reserve(m_leaf_specs.size());
        leaf_scripts.reserve(m_leaf_specs.size());

        auto derive_pubkey = [&](PQAlgorithm algo, int provider_index, const std::vector<unsigned char>& fixed_pubkey, std::vector<unsigned char>& out_pubkey) -> bool {
            if (!fixed_pubkey.empty()) {
                out_pubkey = fixed_pubkey;
                return true;
            }
            if (provider_index < 0 || static_cast<size_t>(provider_index) >= m_pubkey_args.size()) {
                return false;
            }
            const uint32_t key_exp_index = m_pubkey_args[provider_index]->GetExprIndex();
            if (read_cache) {
                return read_cache->GetCachedDerivedPQPubKey(algo, key_exp_index, pos, out_pubkey);
            }

            const auto* pqhd = dynamic_cast<const PQHDPubkeyProvider*>(m_pubkey_args[provider_index].get());
            if (!pqhd) return false;
            auto pq_key_opt = pqhd->GetPQKey(pos, algo);
            if (!pq_key_opt) return false;
            CPQKey pq_key = std::move(*pq_key_opt);
            out_pubkey = pq_key.GetPubKey();
            if (out_pubkey.empty()) return false;
            if (write_cache) {
                write_cache->CacheDerivedPQPubKey(algo, key_exp_index, pos, out_pubkey);
            }
            return true;
        };

        for (const auto& leaf : m_leaf_specs) {
            std::vector<unsigned char> primary_pubkey;
            std::vector<unsigned char> csfs_pubkey;
            std::vector<std::pair<PQAlgorithm, std::vector<unsigned char>>> multisig_pubkeys;
            if (LeafUsesPrimaryKey(leaf) && !derive_pubkey(leaf.algo, leaf.provider_index, leaf.fixed_pubkey, primary_pubkey)) {
                return {};
            }
            if (LeafUsesMultisigKeys(leaf)) {
                if (leaf.multisig_algos.size() != leaf.multisig_provider_indices.size() ||
                    leaf.multisig_algos.size() != leaf.multisig_fixed_pubkeys.size()) {
                    return {};
                }
                multisig_pubkeys.reserve(leaf.multisig_algos.size());
                for (size_t key_pos = 0; key_pos < leaf.multisig_algos.size(); ++key_pos) {
                    std::vector<unsigned char> derived_key;
                    if (!derive_pubkey(
                            leaf.multisig_algos[key_pos],
                            leaf.multisig_provider_indices[key_pos],
                            leaf.multisig_fixed_pubkeys[key_pos],
                            derived_key)) {
                        return {};
                    }
                    multisig_pubkeys.emplace_back(leaf.multisig_algos[key_pos], std::move(derived_key));
                }
                if (leaf.multisig_sorted) {
                    std::sort(multisig_pubkeys.begin(), multisig_pubkeys.end(), [](const auto& lhs, const auto& rhs) {
                        return lhs.second < rhs.second;
                    });
                }
            }
            if (LeafUsesCSFSKey(leaf) && !derive_pubkey(leaf.csfs_algo, leaf.csfs_provider_index, leaf.csfs_fixed_pubkey, csfs_pubkey)) {
                return {};
            }

            const std::vector<unsigned char> leaf_script = BuildP2MRLeafScript(leaf, primary_pubkey, csfs_pubkey, multisig_pubkeys);
            if (leaf_script.empty()) return {};
            leaf_scripts.push_back(leaf_script);
            leaf_hashes.push_back(ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script));
        }

        const uint256 merkle_root = ComputeP2MRMerkleRoot(leaf_hashes);
        P2MRSpendData spenddata;
        std::vector<std::vector<uint256>> merkle_paths(leaf_hashes.size());
        std::vector<uint256> level_hashes = leaf_hashes;
        std::vector<std::vector<size_t>> level_indices(leaf_hashes.size());
        for (size_t i = 0; i < level_indices.size(); ++i) {
            level_indices[i].push_back(i);
        }
        while (level_hashes.size() > 1) {
            std::vector<uint256> next_hashes;
            std::vector<std::vector<size_t>> next_indices;
            next_hashes.reserve((level_hashes.size() + 1) / 2);
            next_indices.reserve((level_hashes.size() + 1) / 2);
            for (size_t i = 0; i < level_hashes.size(); i += 2) {
                if (i + 1 < level_hashes.size()) {
                    next_hashes.push_back(ComputeP2MRBranchHash(level_hashes[i], level_hashes[i + 1]));
                    for (const size_t idx : level_indices[i]) {
                        merkle_paths[idx].push_back(level_hashes[i + 1]);
                    }
                    for (const size_t idx : level_indices[i + 1]) {
                        merkle_paths[idx].push_back(level_hashes[i]);
                    }
                    std::vector<size_t> merged = std::move(level_indices[i]);
                    merged.insert(merged.end(), level_indices[i + 1].begin(), level_indices[i + 1].end());
                    next_indices.push_back(std::move(merged));
                } else {
                    next_hashes.push_back(level_hashes[i]);
                    next_indices.push_back(std::move(level_indices[i]));
                }
            }
            level_hashes = std::move(next_hashes);
            level_indices = std::move(next_indices);
        }

        for (size_t i = 0; i < leaf_scripts.size(); ++i) {
            std::vector<unsigned char> control;
            control.reserve(P2MR_CONTROL_BASE_SIZE + merkle_paths[i].size() * P2MR_CONTROL_NODE_SIZE);
            control.push_back(P2MR_LEAF_VERSION);
            for (const uint256& hash : merkle_paths[i]) {
                control.insert(control.end(), hash.begin(), hash.end());
            }
            spenddata.scripts[leaf_scripts[i]].insert(std::move(control));
        }
        out.p2mr_spends[WitnessV2P2MR{merkle_root}].Merge(std::move(spenddata));

        CScript script_pubkey;
        script_pubkey << OP_2 << ToByteVector(merkle_root);
        return Vector(script_pubkey);
    }

public:
    MRDescriptor(std::vector<std::unique_ptr<PubkeyProvider>> providers, std::vector<MRLeafSpec> leaf_specs, std::vector<std::string> leaf_exprs)
        : DescriptorImpl(std::move(providers), "mr"), m_leaf_specs(std::move(leaf_specs)), m_leaf_exprs(std::move(leaf_exprs))
    {
        assert(!m_leaf_specs.empty());
        assert(m_leaf_specs.size() == m_leaf_exprs.size());
    }

    std::optional<OutputType> GetOutputType() const override { return OutputType::P2MR; }
    bool IsSingleType() const final { return true; }

    std::optional<int64_t> ScriptSize() const override { return 1 + 1 + 32; }
    std::optional<int64_t> MaxSatSize(bool) const override
    {
        if (m_leaf_specs.empty()) return {};

        const std::vector<int64_t> merkle_depths = GetP2MRMerklePathDepths(m_leaf_specs.size());
        int64_t max_sat_size{0};
        for (size_t i = 0; i < m_leaf_specs.size(); ++i) {
            const int64_t control_block_size = P2MR_CONTROL_BASE_SIZE + merkle_depths[i] * P2MR_CONTROL_NODE_SIZE;
            const auto sat_size = GetP2MRLeafMaxSatSize(m_leaf_specs[i], control_block_size);
            if (!sat_size) return {};
            max_sat_size = std::max(max_sat_size, *sat_size);
        }
        return max_sat_size;
    }

    std::optional<int64_t> MaxSatisfactionWeight(bool use_max_sig) const override
    {
        return MaxSatSize(use_max_sig);
    }

    std::optional<int64_t> MaxSatisfactionElems() const override
    {
        int64_t max_elems{0};
        for (const auto& leaf : m_leaf_specs) {
            const auto elems = GetP2MRLeafMaxSatElems(leaf);
            if (!elems) return {};
            max_elems = std::max(max_elems, *elems);
        }
        return max_elems;
    }

    std::unique_ptr<DescriptorImpl> Clone() const override
    {
        std::vector<std::unique_ptr<PubkeyProvider>> providers;
        providers.reserve(m_pubkey_args.size());
        for (const auto& provider : m_pubkey_args) {
            providers.emplace_back(provider->Clone());
        }
        return std::make_unique<MRDescriptor>(std::move(providers), m_leaf_specs, m_leaf_exprs);
    }
};

////////////////////////////////////////////////////////////////////////////
// Parser                                                                 //
////////////////////////////////////////////////////////////////////////////

enum class ParseScriptContext {
    TOP,     //!< Top-level context (script goes directly in scriptPubKey)
    P2SH,    //!< Inside sh() (script becomes P2SH redeemScript)
    P2WPKH,  //!< Inside wpkh() (no script, pubkey only)
    P2WSH,   //!< Inside wsh() (script becomes v0 witness script)
    P2TR,    //!< Inside tr() (either internal key, or BIP342 script leaf)
};

bool IsP2MROnlyTapscriptOpcode(opcodetype opcode)
{
    return opcode == OP_CHECKSIG_MLDSA ||
           opcode == OP_CHECKSIG_SLHDSA ||
           opcode == OP_CHECKSIGFROMSTACK ||
           opcode == OP_CHECKSIGADD_MLDSA ||
           opcode == OP_CHECKSIGADD_SLHDSA ||
           opcode == OP_CHECKSIG_FALCON ||
           opcode == OP_CHECKSIGADD_FALCON ||
           opcode == OP_CHECKSIGFROMSTACK_FALCON;
}

bool ScriptContainsP2MROnlyOpcodes(const CScript& script)
{
    CScript::const_iterator pc = script.begin();
    opcodetype opcode;
    while (script.GetOp(pc, opcode)) {
        if (IsP2MROnlyTapscriptOpcode(opcode)) return true;
    }
    return false;
}

bool RejectP2MROnlyOpcodesInTaproot(const CScript& script, const DescriptorParseOptions& options, std::string& error)
{
    if (options.allow_p2tr_op_success) return true;
    if (!ScriptContainsP2MROnlyOpcodes(script)) return true;
    error = "tr() tapscript leaf contains P2MR-only OP_SUCCESS opcode; pass allow_op_success=true to override";
    return false;
}

std::optional<uint32_t> ParseKeyPathNum(Span<const char> elem, bool& apostrophe, std::string& error)
{
    bool hardened = false;
    if (elem.size() > 0) {
        const char last = elem[elem.size() - 1];
        if (last == '\'' || last == 'h') {
            elem = elem.first(elem.size() - 1);
            hardened = true;
            apostrophe = last == '\'';
        }
    }
    uint32_t p;
    if (!ParseUInt32(std::string(elem.begin(), elem.end()), &p)) {
        error = strprintf("Key path value '%s' is not a valid uint32", std::string(elem.begin(), elem.end()));
        return std::nullopt;
    } else if (p > 0x7FFFFFFFUL) {
        error = strprintf("Key path value %u is out of range", p);
        return std::nullopt;
    }

    return std::make_optional<uint32_t>(p | (((uint32_t)hardened) << 31));
}

/**
 * Parse a key path, being passed a split list of elements (the first element is ignored because it is always the key).
 *
 * @param[in] split BIP32 path string, using either ' or h for hardened derivation
 * @param[out] out Vector of parsed key paths
 * @param[out] apostrophe only updated if hardened derivation is found
 * @param[out] error parsing error message
 * @param[in] allow_multipath Allows the parsed path to use the multipath specifier
 * @returns false if parsing failed
 **/
[[nodiscard]] bool ParseKeyPath(const std::vector<Span<const char>>& split, std::vector<KeyPath>& out, bool& apostrophe, std::string& error, bool allow_multipath)
{
    KeyPath path;
    std::optional<size_t> multipath_segment_index;
    std::vector<uint32_t> multipath_values;
    std::unordered_set<uint32_t> seen_multipath;

    for (size_t i = 1; i < split.size(); ++i) {
        const Span<const char>& elem = split[i];

        // Check if element contain multipath specifier
        if (!elem.empty() && elem.front() == '<' && elem.back() == '>') {
            if (!allow_multipath) {
                error = strprintf("Key path value '%s' specifies multipath in a section where multipath is not allowed", std::string(elem.begin(), elem.end()));
                return false;
            }
            if (multipath_segment_index) {
                error = "Multiple multipath key path specifiers found";
                return false;
            }

            // Parse each possible value
            std::vector<Span<const char>> nums = Split(Span(elem.begin()+1, elem.end()-1), ";");
            if (nums.size() < 2) {
                error = "Multipath key path specifiers must have at least two items";
                return false;
            }

            for (const auto& num : nums) {
                const auto& op_num = ParseKeyPathNum(num, apostrophe, error);
                if (!op_num) return false;
                auto [_, inserted] = seen_multipath.insert(*op_num);
                if (!inserted) {
                    error = strprintf("Duplicated key path value %u in multipath specifier", *op_num);
                    return false;
                }
                multipath_values.emplace_back(*op_num);
            }

            path.emplace_back(); // Placeholder for multipath segment
            multipath_segment_index = path.size()-1;
        } else {
            const auto& op_num = ParseKeyPathNum(elem, apostrophe, error);
            if (!op_num) return false;
            path.emplace_back(*op_num);
        }
    }

    if (!multipath_segment_index) {
        out.emplace_back(std::move(path));
    } else {
        // Replace the multipath placeholder with each value while generating paths
        for (size_t i = 0; i < multipath_values.size(); i++) {
            KeyPath branch_path = path;
            branch_path[*multipath_segment_index] = multipath_values[i];
            out.emplace_back(std::move(branch_path));
        }
    }
    return true;
}

/** Try to parse a pqhd(...) PQ-native HD key provider.
 *  Format: pqhd(hexseed/coin_typeh/accounth/change/ *)
 *  or:     pqhd(fingerprint/coin_typeh/accounth/change/ *)   (public form)
 */
std::unique_ptr<PubkeyProvider> ParsePQHD(uint32_t key_exp_index, const Span<const char>& sp, std::string& error)
{
    Span<const char> inner = sp;
    if (!script::Func("pqhd", inner)) return nullptr;

    auto split = Split(inner, '/');
    // Expect: hexseed_or_fp / coin_typeh / accounth / change / *
    if (split.size() != 5) {
        error = "pqhd() requires exactly 4 path components plus * (e.g. pqhd(seed/0h/0h/0/*))";
        return nullptr;
    }
    // Last component must be "*"
    std::string last(split[4].begin(), split[4].end());
    if (last != "*") {
        error = "pqhd() path must end with /*";
        return nullptr;
    }
    // Parse hex seed (64 hex chars = 32 bytes) or fingerprint (8 hex chars)
    std::string seed_hex(split[0].begin(), split[0].end());
    std::array<unsigned char, 32> seed{};
    std::array<unsigned char, 4> fingerprint{};
    bool has_seed = false;
    if (IsHex(seed_hex) && seed_hex.size() == 64) {
        std::vector<unsigned char> seed_bytes = ParseHex(seed_hex);
        std::copy(seed_bytes.begin(), seed_bytes.end(), seed.begin());
        has_seed = true;
    } else if (IsHex(seed_hex) && seed_hex.size() == 8) {
        // Fingerprint-only (public/DB-persisted form) — zero seed, provider is derivation-incapable
        // Wallet loading injects the real seed from WritePQDescriptorSeed.
        std::vector<unsigned char> fp_bytes = ParseHex(seed_hex);
        std::copy(fp_bytes.begin(), fp_bytes.end(), fingerprint.begin());
    } else {
        error = "pqhd() first argument must be a 32-byte hex seed (64 hex chars) or 4-byte fingerprint (8 hex chars)";
        return nullptr;
    }

    // Parse coin_type (hardened)
    bool dummy_apos = false;
    auto coin_type_opt = ParseKeyPathNum(split[1], dummy_apos, error);
    if (!coin_type_opt) return nullptr;
    uint32_t coin_type_raw = *coin_type_opt;
    if (!(coin_type_raw & 0x80000000U)) {
        error = "pqhd() coin_type must be hardened (e.g. 0h)";
        return nullptr;
    }
    uint32_t coin_type = coin_type_raw & 0x7FFFFFFFU;

    // Parse account (hardened)
    auto account_opt = ParseKeyPathNum(split[2], dummy_apos, error);
    if (!account_opt) return nullptr;
    uint32_t account_raw = *account_opt;
    if (!(account_raw & 0x80000000U)) {
        error = "pqhd() account must be hardened (e.g. 0h)";
        return nullptr;
    }
    uint32_t account = account_raw & 0x7FFFFFFFU;

    // Parse change (unhardened)
    auto change_opt = ParseKeyPathNum(split[3], dummy_apos, error);
    if (!change_opt) return nullptr;
    uint32_t change_raw = *change_opt;
    if (change_raw & 0x80000000U) {
        error = "pqhd() change must not be hardened";
        return nullptr;
    }
    uint32_t change = change_raw;

    if (has_seed) {
        return std::make_unique<PQHDPubkeyProvider>(key_exp_index, seed, coin_type, account, change);
    }
    return std::make_unique<PQHDPubkeyProvider>(key_exp_index, fingerprint, coin_type, account, change);
}

/** Parse a public key that excludes origin information. */
std::vector<std::unique_ptr<PubkeyProvider>> ParsePubkeyInner(uint32_t key_exp_index, const Span<const char>& sp, ParseScriptContext ctx, FlatSigningProvider& out, bool& apostrophe, std::string& error)
{
    std::vector<std::unique_ptr<PubkeyProvider>> ret;

    // Try PQ-native HD provider first
    std::string pqhd_error;
    auto pqhd = ParsePQHD(key_exp_index, sp, pqhd_error);
    if (pqhd) {
        ret.emplace_back(std::move(pqhd));
        return ret;
    }
    // If ParsePQHD matched pqhd( but had bad args, propagate its error
    if (!pqhd_error.empty()) {
        error = std::move(pqhd_error);
        return {};
    }
    // Otherwise it wasn't a pqhd() expression — continue with normal parsing

    bool permit_uncompressed = ctx == ParseScriptContext::TOP || ctx == ParseScriptContext::P2SH;
    auto split = Split(sp, '/');
    std::string str(split[0].begin(), split[0].end());
    if (str.size() == 0) {
        error = "No key provided";
        return {};
    }
    if (split.size() == 1) {
        if (IsHex(str)) {
            std::vector<unsigned char> data = ParseHex(str);
            CPubKey pubkey(data);
            if (pubkey.IsValid() && !pubkey.IsValidNonHybrid()) {
                error = "Hybrid public keys are not allowed";
                return {};
            }
            if (pubkey.IsFullyValid()) {
                if (permit_uncompressed || pubkey.IsCompressed()) {
                    ret.emplace_back(std::make_unique<ConstPubkeyProvider>(key_exp_index, pubkey, false));
                    return ret;
                } else {
                    error = "Uncompressed keys are not allowed";
                    return {};
                }
            } else if (data.size() == 32 && ctx == ParseScriptContext::P2TR) {
                unsigned char fullkey[33] = {0x02};
                std::copy(data.begin(), data.end(), fullkey + 1);
                pubkey.Set(std::begin(fullkey), std::end(fullkey));
                if (pubkey.IsFullyValid()) {
                    ret.emplace_back(std::make_unique<ConstPubkeyProvider>(key_exp_index, pubkey, true));
                    return ret;
                }
            }
            error = strprintf("Pubkey '%s' is invalid", str);
            return {};
        }
        CKey key = DecodeSecret(str);
        if (key.IsValid()) {
            if (permit_uncompressed || key.IsCompressed()) {
                CPubKey pubkey = key.GetPubKey();
                out.keys.emplace(pubkey.GetID(), key);
                ret.emplace_back(std::make_unique<ConstPubkeyProvider>(key_exp_index, pubkey, ctx == ParseScriptContext::P2TR));
                return ret;
            } else {
                error = "Uncompressed keys are not allowed";
                return {};
            }
        }
    }
    CExtKey extkey = DecodeExtKey(str);
    CExtPubKey extpubkey = DecodeExtPubKey(str);
    if (!extkey.key.IsValid() && !extpubkey.pubkey.IsValid()) {
        error = strprintf("key '%s' is not valid", str);
        return {};
    }
    std::vector<KeyPath> paths;
    DeriveType type = DeriveType::NO;
    if (std::ranges::equal(split.back(), Span{"*"}.first(1))) {
        split.pop_back();
        type = DeriveType::UNHARDENED;
    } else if (std::ranges::equal(split.back(), Span{"*'"}.first(2)) || std::ranges::equal(split.back(), Span{"*h"}.first(2))) {
        apostrophe = std::ranges::equal(split.back(), Span{"*'"}.first(2));
        split.pop_back();
        type = DeriveType::HARDENED;
    }
    if (!ParseKeyPath(split, paths, apostrophe, error, /*allow_multipath=*/true)) return {};
    if (extkey.key.IsValid()) {
        extpubkey = extkey.Neuter();
        out.keys.emplace(extpubkey.pubkey.GetID(), extkey.key);
    }
    for (auto& path : paths) {
        ret.emplace_back(std::make_unique<BIP32PubkeyProvider>(key_exp_index, extpubkey, std::move(path), type, apostrophe));
    }
    return ret;
}

/** Parse a public key including origin information (if enabled). */
std::vector<std::unique_ptr<PubkeyProvider>> ParsePubkey(uint32_t key_exp_index, const Span<const char>& sp, ParseScriptContext ctx, FlatSigningProvider& out, std::string& error)
{
    std::vector<std::unique_ptr<PubkeyProvider>> ret;
    auto origin_split = Split(sp, ']');
    if (origin_split.size() > 2) {
        error = "Multiple ']' characters found for a single pubkey";
        return {};
    }
    // This is set if either the origin or path suffix contains a hardened derivation.
    bool apostrophe = false;
    if (origin_split.size() == 1) {
        return ParsePubkeyInner(key_exp_index, origin_split[0], ctx, out, apostrophe, error);
    }
    if (origin_split[0].empty() || origin_split[0][0] != '[') {
        error = strprintf("Key origin start '[ character expected but not found, got '%c' instead",
                          origin_split[0].empty() ? /** empty, implies split char */ ']' : origin_split[0][0]);
        return {};
    }
    auto slash_split = Split(origin_split[0].subspan(1), '/');
    if (slash_split[0].size() != 8) {
        error = strprintf("Fingerprint is not 4 bytes (%u characters instead of 8 characters)", slash_split[0].size());
        return {};
    }
    std::string fpr_hex = std::string(slash_split[0].begin(), slash_split[0].end());
    if (!IsHex(fpr_hex)) {
        error = strprintf("Fingerprint '%s' is not hex", fpr_hex);
        return {};
    }
    auto fpr_bytes = ParseHex(fpr_hex);
    KeyOriginInfo info;
    static_assert(sizeof(info.fingerprint) == 4, "Fingerprint must be 4 bytes");
    assert(fpr_bytes.size() == 4);
    std::copy(fpr_bytes.begin(), fpr_bytes.end(), info.fingerprint);
    std::vector<KeyPath> path;
    if (!ParseKeyPath(slash_split, path, apostrophe, error, /*allow_multipath=*/false)) return {};
    info.path = path.at(0);
    auto providers = ParsePubkeyInner(key_exp_index, origin_split[1], ctx, out, apostrophe, error);
    if (providers.empty()) return {};
    ret.reserve(providers.size());
    for (auto& prov : providers) {
        ret.emplace_back(std::make_unique<OriginPubkeyProvider>(key_exp_index, info, std::move(prov), apostrophe));
    }
    return ret;
}

std::unique_ptr<PubkeyProvider> InferPubkey(const CPubKey& pubkey, ParseScriptContext ctx, const SigningProvider& provider)
{
    // Key cannot be hybrid
    if (!pubkey.IsValidNonHybrid()) {
        return nullptr;
    }
    // Uncompressed is only allowed in TOP and P2SH contexts
    if (ctx != ParseScriptContext::TOP && ctx != ParseScriptContext::P2SH && !pubkey.IsCompressed()) {
        return nullptr;
    }
    std::unique_ptr<PubkeyProvider> key_provider = std::make_unique<ConstPubkeyProvider>(0, pubkey, false);
    KeyOriginInfo info;
    if (provider.GetKeyOrigin(pubkey.GetID(), info)) {
        return std::make_unique<OriginPubkeyProvider>(0, std::move(info), std::move(key_provider), /*apostrophe=*/false);
    }
    return key_provider;
}

std::unique_ptr<PubkeyProvider> InferXOnlyPubkey(const XOnlyPubKey& xkey, ParseScriptContext ctx, const SigningProvider& provider)
{
    CPubKey pubkey{xkey.GetEvenCorrespondingCPubKey()};
    std::unique_ptr<PubkeyProvider> key_provider = std::make_unique<ConstPubkeyProvider>(0, pubkey, true);
    KeyOriginInfo info;
    if (provider.GetKeyOriginByXOnly(xkey, info)) {
        return std::make_unique<OriginPubkeyProvider>(0, std::move(info), std::move(key_provider), /*apostrophe=*/false);
    }
    return key_provider;
}

/**
 * The context for parsing a Miniscript descriptor (either from Script or from its textual representation).
 */
struct KeyParser {
    //! The Key type is an index in DescriptorImpl::m_pubkey_args
    using Key = uint32_t;
    //! Must not be nullptr if parsing from string.
    FlatSigningProvider* m_out;
    //! Must not be nullptr if parsing from Script.
    const SigningProvider* m_in;
    //! List of multipath expanded keys contained in the Miniscript.
    mutable std::vector<std::vector<std::unique_ptr<PubkeyProvider>>> m_keys;
    //! Used to detect key parsing errors within a Miniscript.
    mutable std::string m_key_parsing_error;
    //! The script context we're operating within (Tapscript or P2WSH).
    const miniscript::MiniscriptContext m_script_ctx;
    //! The number of keys that were parsed before starting to parse this Miniscript descriptor.
    uint32_t m_offset;

    KeyParser(FlatSigningProvider* out LIFETIMEBOUND, const SigningProvider* in LIFETIMEBOUND,
              miniscript::MiniscriptContext ctx, uint32_t offset = 0)
        : m_out(out), m_in(in), m_script_ctx(ctx), m_offset(offset) {}

    bool KeyCompare(const Key& a, const Key& b) const {
        return *m_keys.at(a).at(0) < *m_keys.at(b).at(0);
    }

    ParseScriptContext ParseContext() const {
        switch (m_script_ctx) {
            case miniscript::MiniscriptContext::P2WSH: return ParseScriptContext::P2WSH;
            case miniscript::MiniscriptContext::TAPSCRIPT: return ParseScriptContext::P2TR;
            case miniscript::MiniscriptContext::P2MR: return ParseScriptContext::P2WSH;
        }
        assert(false);
        return ParseScriptContext::P2WSH;
    }

    template<typename I> std::optional<Key> FromString(I begin, I end) const
    {
        assert(m_out);
        Key key = m_keys.size();
        auto pk = ParsePubkey(m_offset + key, {&*begin, &*end}, ParseContext(), *m_out, m_key_parsing_error);
        if (pk.empty()) return {};
        m_keys.emplace_back(std::move(pk));
        return key;
    }

    std::optional<std::string> ToString(const Key& key) const
    {
        return m_keys.at(key).at(0)->ToString();
    }

    template<typename I> std::optional<Key> FromPKBytes(I begin, I end) const
    {
        assert(m_in);
        Key key = m_keys.size();
        if (miniscript::IsTapscript(m_script_ctx) && end - begin == 32) {
            XOnlyPubKey pubkey;
            std::copy(begin, end, pubkey.begin());
            if (auto pubkey_provider = InferXOnlyPubkey(pubkey, ParseContext(), *m_in)) {
                m_keys.emplace_back();
                m_keys.back().push_back(std::move(pubkey_provider));
                return key;
            }
        } else if (!miniscript::IsTapscript(m_script_ctx)) {
            CPubKey pubkey(begin, end);
            if (auto pubkey_provider = InferPubkey(pubkey, ParseContext(), *m_in)) {
                m_keys.emplace_back();
                m_keys.back().push_back(std::move(pubkey_provider));
                return key;
            }
        }
        return {};
    }

    template<typename I> std::optional<Key> FromPKHBytes(I begin, I end) const
    {
        assert(end - begin == 20);
        assert(m_in);
        uint160 hash;
        std::copy(begin, end, hash.begin());
        CKeyID keyid(hash);
        CPubKey pubkey;
        if (m_in->GetPubKey(keyid, pubkey)) {
            if (auto pubkey_provider = InferPubkey(pubkey, ParseContext(), *m_in)) {
                Key key = m_keys.size();
                m_keys.emplace_back();
                m_keys.back().push_back(std::move(pubkey_provider));
                return key;
            }
        }
        return {};
    }

    miniscript::MiniscriptContext MsContext() const {
        return m_script_ctx;
    }
};

/** Parse a script in a particular context. */
// NOLINTNEXTLINE(misc-no-recursion)
std::vector<std::unique_ptr<DescriptorImpl>> ParseScript(uint32_t& key_exp_index, Span<const char>& sp, ParseScriptContext ctx, FlatSigningProvider& out, std::string& error, const DescriptorParseOptions& options)
{
    using namespace script;
    Assume(ctx == ParseScriptContext::TOP || ctx == ParseScriptContext::P2SH || ctx == ParseScriptContext::P2WSH || ctx == ParseScriptContext::P2TR);
    std::vector<std::unique_ptr<DescriptorImpl>> ret;
    auto expr = Expr(sp);
    if (Func("pk", expr)) {
        auto pubkeys = ParsePubkey(key_exp_index, expr, ctx, out, error);
        if (pubkeys.empty()) {
            error = strprintf("pk(): %s", error);
            return {};
        }
        ++key_exp_index;
        for (auto& pubkey : pubkeys) {
            ret.emplace_back(std::make_unique<PKDescriptor>(std::move(pubkey), ctx == ParseScriptContext::P2TR));
        }
        return ret;
    }
    if ((ctx == ParseScriptContext::TOP || ctx == ParseScriptContext::P2SH || ctx == ParseScriptContext::P2WSH) && Func("pkh", expr)) {
        auto pubkeys = ParsePubkey(key_exp_index, expr, ctx, out, error);
        if (pubkeys.empty()) {
            error = strprintf("pkh(): %s", error);
            return {};
        }
        ++key_exp_index;
        for (auto& pubkey : pubkeys) {
            ret.emplace_back(std::make_unique<PKHDescriptor>(std::move(pubkey)));
        }
        return ret;
    }
    if (ctx == ParseScriptContext::TOP && Func("combo", expr)) {
        auto pubkeys = ParsePubkey(key_exp_index, expr, ctx, out, error);
        if (pubkeys.empty()) {
            error = strprintf("combo(): %s", error);
            return {};
        }
        ++key_exp_index;
        for (auto& pubkey : pubkeys) {
            ret.emplace_back(std::make_unique<ComboDescriptor>(std::move(pubkey)));
        }
        return ret;
    } else if (Func("combo", expr)) {
        error = "Can only have combo() at top level";
        return {};
    }
    const bool multi = Func("multi", expr);
    const bool sortedmulti = !multi && Func("sortedmulti", expr);
    const bool multi_a = !(multi || sortedmulti) && Func("multi_a", expr);
    const bool sortedmulti_a = !(multi || sortedmulti || multi_a) && Func("sortedmulti_a", expr);
    if (((ctx == ParseScriptContext::TOP || ctx == ParseScriptContext::P2SH || ctx == ParseScriptContext::P2WSH) && (multi || sortedmulti)) ||
        (ctx == ParseScriptContext::P2TR && (multi_a || sortedmulti_a))) {
        auto threshold = Expr(expr);
        uint32_t thres;
        std::vector<std::vector<std::unique_ptr<PubkeyProvider>>> providers; // List of multipath expanded pubkeys
        if (!ParseUInt32(std::string(threshold.begin(), threshold.end()), &thres)) {
            error = strprintf("Multi threshold '%s' is not valid", std::string(threshold.begin(), threshold.end()));
            return {};
        }
        size_t script_size = 0;
        size_t max_providers_len = 0;
        while (expr.size()) {
            if (!Const(",", expr)) {
                error = strprintf("Multi: expected ',', got '%c'", expr[0]);
                return {};
            }
            auto arg = Expr(expr);
            auto pks = ParsePubkey(key_exp_index, arg, ctx, out, error);
            if (pks.empty()) {
                error = strprintf("Multi: %s", error);
                return {};
            }
            script_size += pks.at(0)->GetSize() + 1;
            max_providers_len = std::max(max_providers_len, pks.size());
            providers.emplace_back(std::move(pks));
            key_exp_index++;
        }
        if ((multi || sortedmulti) && (providers.empty() || providers.size() > MAX_PUBKEYS_PER_MULTISIG)) {
            error = strprintf("Cannot have %u keys in multisig; must have between 1 and %d keys, inclusive", providers.size(), MAX_PUBKEYS_PER_MULTISIG);
            return {};
        } else if ((multi_a || sortedmulti_a) && (providers.empty() || providers.size() > MAX_PUBKEYS_PER_MULTI_A)) {
            error = strprintf("Cannot have %u keys in multi_a; must have between 1 and %d keys, inclusive", providers.size(), MAX_PUBKEYS_PER_MULTI_A);
            return {};
        } else if (thres < 1) {
            error = strprintf("Multisig threshold cannot be %d, must be at least 1", thres);
            return {};
        } else if (thres > providers.size()) {
            error = strprintf("Multisig threshold cannot be larger than the number of keys; threshold is %d but only %u keys specified", thres, providers.size());
            return {};
        }
        if (ctx == ParseScriptContext::TOP) {
            if (providers.size() > 3) {
                error = strprintf("Cannot have %u pubkeys in bare multisig; only at most 3 pubkeys", providers.size());
                return {};
            }
        }
        if (ctx == ParseScriptContext::P2SH) {
            // This limits the maximum number of compressed pubkeys to 15.
            if (script_size + 3 > MAX_SCRIPT_ELEMENT_SIZE) {
                error = strprintf("P2SH script is too large, %d bytes is larger than %d bytes", script_size + 3, MAX_SCRIPT_ELEMENT_SIZE);
                return {};
            }
        }

        // Make sure all vecs are of the same length, or exactly length 1
        // For length 1 vectors, clone key providers until vector is the same length
        for (auto& vec : providers) {
            if (vec.size() == 1) {
                for (size_t i = 1; i < max_providers_len; ++i) {
                    vec.emplace_back(vec.at(0)->Clone());
                }
            } else if (vec.size() != max_providers_len) {
                error = strprintf("multi(): Multipath derivation paths have mismatched lengths");
                return {};
            }
        }

        // Build the final descriptors vector
        for (size_t i = 0; i < max_providers_len; ++i) {
            // Build final pubkeys vectors by retrieving the i'th subscript for each vector in subscripts
            std::vector<std::unique_ptr<PubkeyProvider>> pubs;
            pubs.reserve(providers.size());
            for (auto& pub : providers) {
                pubs.emplace_back(std::move(pub.at(i)));
            }
            if (multi || sortedmulti) {
                ret.emplace_back(std::make_unique<MultisigDescriptor>(thres, std::move(pubs), sortedmulti));
            } else {
                ret.emplace_back(std::make_unique<MultiADescriptor>(thres, std::move(pubs), sortedmulti_a));
            }
        }
        return ret;
    } else if (multi || sortedmulti) {
        error = "Can only have multi/sortedmulti at top level, in sh(), or in wsh()";
        return {};
    } else if (multi_a || sortedmulti_a) {
        error = "Can only have multi_a/sortedmulti_a inside tr()";
        return {};
    }
    if ((ctx == ParseScriptContext::TOP || ctx == ParseScriptContext::P2SH) && Func("wpkh", expr)) {
        auto pubkeys = ParsePubkey(key_exp_index, expr, ParseScriptContext::P2WPKH, out, error);
        if (pubkeys.empty()) {
            error = strprintf("wpkh(): %s", error);
            return {};
        }
        key_exp_index++;
        for (auto& pubkey : pubkeys) {
            ret.emplace_back(std::make_unique<WPKHDescriptor>(std::move(pubkey)));
        }
        return ret;
    } else if (Func("wpkh", expr)) {
        error = "Can only have wpkh() at top level or inside sh()";
        return {};
    }
    if (ctx == ParseScriptContext::TOP && Func("sh", expr)) {
        auto descs = ParseScript(key_exp_index, expr, ParseScriptContext::P2SH, out, error, options);
        if (descs.empty() || expr.size()) return {};
        std::vector<std::unique_ptr<DescriptorImpl>> ret;
        ret.reserve(descs.size());
        for (auto& desc : descs) {
            ret.push_back(std::make_unique<SHDescriptor>(std::move(desc)));
        }
        return ret;
    } else if (Func("sh", expr)) {
        error = "Can only have sh() at top level";
        return {};
    }
    if ((ctx == ParseScriptContext::TOP || ctx == ParseScriptContext::P2SH) && Func("wsh", expr)) {
        auto descs = ParseScript(key_exp_index, expr, ParseScriptContext::P2WSH, out, error, options);
        if (descs.empty() || expr.size()) return {};
        for (auto& desc : descs) {
            ret.emplace_back(std::make_unique<WSHDescriptor>(std::move(desc)));
        }
        return ret;
    } else if (Func("wsh", expr)) {
        error = "Can only have wsh() at top level or inside sh()";
        return {};
    }
    if (ctx == ParseScriptContext::TOP && Func("addr", expr)) {
        CTxDestination dest = DecodeDestination(std::string(expr.begin(), expr.end()));
        if (!IsValidDestination(dest)) {
            error = "Address is not valid";
            return {};
        }
        ret.emplace_back(std::make_unique<AddressDescriptor>(std::move(dest)));
        return ret;
    } else if (Func("addr", expr)) {
        error = "Can only have addr() at top level";
        return {};
    }
    if (ctx == ParseScriptContext::TOP && Func("mr", expr)) {
        struct ParsedMRKey {
            PQAlgorithm algo;
            int provider_index;
            std::vector<unsigned char> fixed_pubkey;
            std::string rendered;
        };

        auto parse_mr_xpub_provider = [&](Span<const char> arg,
                                          std::vector<std::unique_ptr<PubkeyProvider>>& providers,
                                          int& provider_index,
                                          std::string& provider_str) -> bool {
            auto parsed = ParsePubkey(key_exp_index, arg, ParseScriptContext::TOP, out, error);
            if (parsed.empty()) return false;
            if (parsed.size() != 1) {
                error = "mr(): multipath derivation is not supported";
                return false;
            }
            // Fresh-chain strict mode: only PQ-native derivation providers are allowed.
            if (!parsed[0]->IsPQNative()) {
                error = "mr(): key must be a pqhd() provider";
                return false;
            }

            provider_index = static_cast<int>(providers.size());
            providers.emplace_back(std::move(parsed[0]));
            ++key_exp_index;
            provider_str = providers.back()->ToString();
            return true;
        };

        auto parse_mr_key = [&](Span<const char> arg,
                                std::vector<std::unique_ptr<PubkeyProvider>>& providers,
                                ParsedMRKey& key_out) -> bool {
            auto key_expr = arg;
            const bool is_slh = Func("pk_slh", key_expr);
            if (is_slh && key_expr.empty()) {
                error = "mr(): pk_slh() key must not be empty";
                return false;
            }

            const PQAlgorithm algo = is_slh ? PQAlgorithm::SLH_DSA_128S : PQAlgorithm::ML_DSA_44;
            const size_t expected_size = is_slh ? SLHDSA128S_PUBKEY_SIZE : MLDSA44_PUBKEY_SIZE;
            const Span<const char> key_body = is_slh ? key_expr : arg;
            const std::string key_str(key_body.begin(), key_body.end());
            if (IsHex(key_str)) {
                std::vector<unsigned char> key = ParseHex(key_str);
                if (key.size() != expected_size) {
                    error = is_slh
                        ? strprintf("mr(): SLH-DSA key must be %u bytes, got %u bytes", SLHDSA128S_PUBKEY_SIZE, key.size())
                        : strprintf("mr(): ML-DSA key must be %u bytes, got %u bytes", MLDSA44_PUBKEY_SIZE, key.size());
                    return false;
                }
                key_out.algo = algo;
                key_out.provider_index = -1;
                key_out.fixed_pubkey = std::move(key);
                key_out.rendered = is_slh ? strprintf("pk_slh(%s)", HexStr(key_out.fixed_pubkey)) : HexStr(key_out.fixed_pubkey);
                return true;
            }

            int provider_index = -1;
            std::string provider_str;
            if (!parse_mr_xpub_provider(key_body, providers, provider_index, provider_str)) {
                error = is_slh ? "mr(): pk_slh() key must be hex or pqhd()" : "mr(): key must be an ML-DSA hex key or pqhd()";
                return false;
            }
            key_out.algo = algo;
            key_out.provider_index = provider_index;
            key_out.fixed_pubkey.clear();
            key_out.rendered = is_slh ? strprintf("pk_slh(%s)", provider_str) : provider_str;
            return true;
        };

        auto parse_ctv_hash = [&](Span<const char> arg, uint256& hash_out, std::string& hash_hex_out) -> bool {
            const std::string hash_hex(arg.begin(), arg.end());
            if (!IsHex(hash_hex) || hash_hex.size() != 64) {
                error = "mr(): ctv hash must be 32-byte hex";
                return false;
            }
            const std::vector<unsigned char> hash_bytes = ParseHex(hash_hex);
            if (hash_bytes.size() != uint256::size()) {
                error = "mr(): ctv hash must be 32-byte hex";
                return false;
            }
            hash_out = uint256{hash_bytes};
            hash_hex_out = HexStr(hash_bytes);
            return true;
        };

        auto parse_hash160 = [&](Span<const char> arg, std::vector<unsigned char>& hash_out, std::string& hash_hex_out) -> bool {
            const std::string hash_hex(arg.begin(), arg.end());
            if (!IsHex(hash_hex) || hash_hex.size() != uint160::size() * 2) {
                error = "mr(): htlc hash must be 20-byte hex";
                return false;
            }
            const std::vector<unsigned char> hash_bytes = ParseHex(hash_hex);
            if (hash_bytes.size() != uint160::size()) {
                error = "mr(): htlc hash must be 20-byte hex";
                return false;
            }
            hash_out = hash_bytes;
            hash_hex_out = HexStr(hash_bytes);
            return true;
        };

        auto check_leaf_policy_size = [&](const MRLeafSpec& leaf) -> bool {
            std::vector<unsigned char> leaf_script;
            if (!BuildDummyP2MRLeafScript(leaf, leaf_script)) {
                if (LeafUsesMultisigKeys(leaf)) {
                    error = "mr(): invalid multisig key metadata";
                } else {
                    error = "mr(): failed to build leaf script";
                }
                return false;
            }
            if (leaf_script.empty()) {
                error = "mr(): failed to build leaf script";
                return false;
            }
            const size_t max_leaf_size = (leaf.type == MRLeafType::MULTISIG_PQ ||
                                          leaf.type == MRLeafType::CLTV_MULTISIG_PQ ||
                                          leaf.type == MRLeafType::CSV_MULTISIG_PQ ||
                                          leaf.type == MRLeafType::CTV_MULTISIG_PQ)
                ? static_cast<size_t>(MAX_P2MR_SCRIPT_SIZE)
                : static_cast<size_t>(g_script_size_policy_limit);
            if (leaf_script.size() > max_leaf_size) {
                error = strprintf("mr(): leaf script size %u exceeds policy limit %u", leaf_script.size(), max_leaf_size);
                return false;
            }
            return true;
        };

        auto append_leaf = [&](MRLeafSpec leaf,
                               std::string leaf_expr,
                               std::vector<MRLeafSpec>& leaf_specs,
                               std::vector<std::string>& leaf_exprs) -> bool {
            if (!check_leaf_policy_size(leaf)) return false;
            leaf_specs.push_back(std::move(leaf));
            leaf_exprs.push_back(std::move(leaf_expr));
            return true;
        };

        auto parse_leaf_expr = [&](Span<const char> arg,
                                   std::vector<std::unique_ptr<PubkeyProvider>>& providers,
                                   std::vector<MRLeafSpec>& leaf_specs,
                                   std::vector<std::string>& leaf_exprs) -> bool {
            auto parse_multisig_body = [&](Span<const char>& expr,
                                           const std::string& func_name,
                                           uint32_t& threshold,
                                           std::vector<ParsedMRKey>& parsed_keys) -> bool {
                const auto threshold_arg = Expr(expr);
                if (threshold_arg.empty()) {
                    error = strprintf("mr(): %s() requires a threshold argument", func_name);
                    return false;
                }

                if (!ParseUInt32(std::string(threshold_arg.begin(), threshold_arg.end()), &threshold)) {
                    error = strprintf("mr(): multisig threshold '%s' is not valid",
                                      std::string(threshold_arg.begin(), threshold_arg.end()));
                    return false;
                }

                while (expr.size()) {
                    if (!Const(",", expr)) {
                        error = strprintf("mr(): expected ',' in %s(), got '%c'", func_name, expr[0]);
                        return false;
                    }
                    const auto key_arg = Expr(expr);
                    if (key_arg.empty()) {
                        error = strprintf("mr(): empty key argument in %s()", func_name);
                        return false;
                    }
                    ParsedMRKey key;
                    if (!parse_mr_key(key_arg, providers, key)) return false;
                    parsed_keys.push_back(std::move(key));
                }

                if (parsed_keys.size() < 2) {
                    error = strprintf("mr(): %s() requires at least 2 keys", func_name);
                    return false;
                }
                if (parsed_keys.size() > MAX_PQ_PUBKEYS_PER_MULTISIG) {
                    error = strprintf("mr(): cannot have %u keys in multisig; max is %u",
                                      parsed_keys.size(), MAX_PQ_PUBKEYS_PER_MULTISIG);
                    return false;
                }
                if (threshold < 1) {
                    error = "mr(): multisig threshold must be at least 1";
                    return false;
                }
                if (threshold > parsed_keys.size()) {
                    error = strprintf("mr(): multisig threshold %u exceeds key count %u",
                                      threshold, parsed_keys.size());
                    return false;
                }
                std::set<std::pair<PQAlgorithm, std::string>> unique_multisig_keys;
                for (const auto& parsed_key : parsed_keys) {
                    if (!unique_multisig_keys.emplace(parsed_key.algo, parsed_key.rendered).second) {
                        error = strprintf("mr(): %s() contains duplicate keys", func_name);
                        return false;
                    }
                }
                return true;
            };

            auto populate_multisig_spec = [&](MRLeafSpec& spec,
                                              MRLeafType type,
                                              bool sorted,
                                              uint32_t threshold,
                                              std::vector<ParsedMRKey>& parsed_keys) {
                spec.type = type;
                spec.multisig_threshold = static_cast<uint8_t>(threshold);
                spec.multisig_sorted = sorted;
                spec.multisig_algos.reserve(parsed_keys.size());
                spec.multisig_provider_indices.reserve(parsed_keys.size());
                spec.multisig_fixed_pubkeys.reserve(parsed_keys.size());
                for (auto& parsed_key : parsed_keys) {
                    spec.multisig_algos.push_back(parsed_key.algo);
                    spec.multisig_provider_indices.push_back(parsed_key.provider_index);
                    spec.multisig_fixed_pubkeys.push_back(std::move(parsed_key.fixed_pubkey));
                }
            };

            auto leaf_expr = arg;
            if (Func("ctv", leaf_expr)) {
                uint256 ctv_hash;
                std::string ctv_hex;
                if (!parse_ctv_hash(leaf_expr, ctv_hash, ctv_hex)) return false;
                MRLeafSpec spec;
                spec.type = MRLeafType::CTV_ONLY;
                spec.ctv_hash = ctv_hash;
                return append_leaf(std::move(spec), strprintf("ctv(%s)", ctv_hex), leaf_specs, leaf_exprs);
            }

            leaf_expr = arg;
            if (Func("ctv_pk", leaf_expr)) {
                const auto ctv_arg = Expr(leaf_expr);
                if (ctv_arg.empty()) {
                    error = "mr(): ctv_pk() requires a template hash argument";
                    return false;
                }
                if (!Const(",", leaf_expr)) {
                    error = "mr(): ctv_pk() missing key argument";
                    return false;
                }
                const auto key_arg = Expr(leaf_expr);
                if (key_arg.empty()) {
                    error = "mr(): ctv_pk() key argument is empty";
                    return false;
                }
                if (!leaf_expr.empty()) {
                    error = "mr(): ctv_pk() has unexpected trailing data";
                    return false;
                }

                uint256 ctv_hash;
                std::string ctv_hex;
                if (!parse_ctv_hash(ctv_arg, ctv_hash, ctv_hex)) return false;
                ParsedMRKey signer_key;
                if (!parse_mr_key(key_arg, providers, signer_key)) return false;

                MRLeafSpec spec;
                spec.type = MRLeafType::CTV_CHECKSIG;
                spec.ctv_hash = ctv_hash;
                spec.algo = signer_key.algo;
                spec.provider_index = signer_key.provider_index;
                spec.fixed_pubkey = std::move(signer_key.fixed_pubkey);
                return append_leaf(std::move(spec), strprintf("ctv_pk(%s,%s)", ctv_hex, signer_key.rendered), leaf_specs, leaf_exprs);
            }

            leaf_expr = arg;
            const bool multi_pq = Func("multi_pq", leaf_expr);
            const bool sortedmulti_pq = !multi_pq && Func("sortedmulti_pq", leaf_expr);
            if (multi_pq || sortedmulti_pq) {
                uint32_t threshold{0};
                std::vector<ParsedMRKey> parsed_keys;
                const std::string func_name = sortedmulti_pq ? "sortedmulti_pq" : "multi_pq";
                if (!parse_multisig_body(leaf_expr, func_name, threshold, parsed_keys)) return false;

                MRLeafSpec spec;
                populate_multisig_spec(spec, MRLeafType::MULTISIG_PQ, sortedmulti_pq, threshold, parsed_keys);
                std::string rendered = strprintf("%s(%u", func_name, threshold);
                for (const auto& parsed_key : parsed_keys) {
                    rendered += "," + parsed_key.rendered;
                }
                rendered += ")";
                return append_leaf(std::move(spec), std::move(rendered), leaf_specs, leaf_exprs);
            }

            leaf_expr = arg;
            const bool ctv_multi_pq = Func("ctv_multi_pq", leaf_expr);
            const bool ctv_sortedmulti_pq = !ctv_multi_pq && Func("ctv_sortedmulti_pq", leaf_expr);
            if (ctv_multi_pq || ctv_sortedmulti_pq) {
                const auto ctv_arg = Expr(leaf_expr);
                if (ctv_arg.empty()) {
                    error = strprintf("mr(): %s() requires a template hash argument",
                                      ctv_sortedmulti_pq ? "ctv_sortedmulti_pq" : "ctv_multi_pq");
                    return false;
                }
                if (!Const(",", leaf_expr)) {
                    error = strprintf("mr(): %s() missing threshold argument",
                                      ctv_sortedmulti_pq ? "ctv_sortedmulti_pq" : "ctv_multi_pq");
                    return false;
                }

                uint256 ctv_hash;
                std::string ctv_hex;
                if (!parse_ctv_hash(ctv_arg, ctv_hash, ctv_hex)) return false;

                uint32_t threshold{0};
                std::vector<ParsedMRKey> parsed_keys;
                const std::string func_name = ctv_sortedmulti_pq ? "ctv_sortedmulti_pq" : "ctv_multi_pq";
                if (!parse_multisig_body(leaf_expr, func_name, threshold, parsed_keys)) return false;

                MRLeafSpec spec;
                spec.ctv_hash = ctv_hash;
                populate_multisig_spec(spec, MRLeafType::CTV_MULTISIG_PQ, ctv_sortedmulti_pq, threshold, parsed_keys);
                std::string rendered = strprintf("%s(%s,%u", func_name, ctv_hex, threshold);
                for (const auto& parsed_key : parsed_keys) {
                    rendered += "," + parsed_key.rendered;
                }
                rendered += ")";
                return append_leaf(std::move(spec), std::move(rendered), leaf_specs, leaf_exprs);
            }

            leaf_expr = arg;
            const bool cltv_multi_pq = Func("cltv_multi_pq", leaf_expr);
            const bool cltv_sortedmulti_pq = !cltv_multi_pq && Func("cltv_sortedmulti_pq", leaf_expr);
            if (cltv_multi_pq || cltv_sortedmulti_pq) {
                const auto locktime_arg = Expr(leaf_expr);
                if (locktime_arg.empty()) {
                    error = strprintf("mr(): %s() requires a locktime argument",
                                      cltv_sortedmulti_pq ? "cltv_sortedmulti_pq" : "cltv_multi_pq");
                    return false;
                }
                if (!Const(",", leaf_expr)) {
                    error = strprintf("mr(): %s() missing threshold argument",
                                      cltv_sortedmulti_pq ? "cltv_sortedmulti_pq" : "cltv_multi_pq");
                    return false;
                }

                const auto locktime{ToIntegral<int64_t>(std::string_view(locktime_arg.data(), locktime_arg.size()))};
                if (!locktime.has_value() || *locktime < 0 || *locktime > std::numeric_limits<uint32_t>::max()) {
                    error = strprintf("mr(): cltv locktime '%s' is not valid",
                                      std::string(locktime_arg.begin(), locktime_arg.end()));
                    return false;
                }

                uint32_t threshold{0};
                std::vector<ParsedMRKey> parsed_keys;
                const std::string func_name = cltv_sortedmulti_pq ? "cltv_sortedmulti_pq" : "cltv_multi_pq";
                if (!parse_multisig_body(leaf_expr, func_name, threshold, parsed_keys)) return false;

                MRLeafSpec spec;
                spec.locktime = *locktime;
                populate_multisig_spec(spec, MRLeafType::CLTV_MULTISIG_PQ, cltv_sortedmulti_pq, threshold, parsed_keys);
                std::string rendered = strprintf("%s(%lld,%u", func_name, static_cast<long long>(*locktime), threshold);
                for (const auto& parsed_key : parsed_keys) {
                    rendered += "," + parsed_key.rendered;
                }
                rendered += ")";
                return append_leaf(std::move(spec), std::move(rendered), leaf_specs, leaf_exprs);
            }

            leaf_expr = arg;
            const bool csv_multi_pq = Func("csv_multi_pq", leaf_expr);
            const bool csv_sortedmulti_pq = !csv_multi_pq && Func("csv_sortedmulti_pq", leaf_expr);
            if (csv_multi_pq || csv_sortedmulti_pq) {
                const auto sequence_arg = Expr(leaf_expr);
                if (sequence_arg.empty()) {
                    error = strprintf("mr(): %s() requires a sequence argument",
                                      csv_sortedmulti_pq ? "csv_sortedmulti_pq" : "csv_multi_pq");
                    return false;
                }
                if (!Const(",", leaf_expr)) {
                    error = strprintf("mr(): %s() missing threshold argument",
                                      csv_sortedmulti_pq ? "csv_sortedmulti_pq" : "csv_multi_pq");
                    return false;
                }

                const auto sequence{ToIntegral<int64_t>(std::string_view(sequence_arg.data(), sequence_arg.size()))};
                if (!sequence.has_value() ||
                    *sequence < 1 ||
                    *sequence >= static_cast<int64_t>(CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG)) {
                    error = strprintf("mr(): csv sequence '%s' is not valid",
                                      std::string(sequence_arg.begin(), sequence_arg.end()));
                    return false;
                }

                uint32_t threshold{0};
                std::vector<ParsedMRKey> parsed_keys;
                const std::string func_name = csv_sortedmulti_pq ? "csv_sortedmulti_pq" : "csv_multi_pq";
                if (!parse_multisig_body(leaf_expr, func_name, threshold, parsed_keys)) return false;

                MRLeafSpec spec;
                spec.sequence = *sequence;
                populate_multisig_spec(spec, MRLeafType::CSV_MULTISIG_PQ, csv_sortedmulti_pq, threshold, parsed_keys);
                std::string rendered = strprintf("%s(%lld,%u", func_name, static_cast<long long>(*sequence), threshold);
                for (const auto& parsed_key : parsed_keys) {
                    rendered += "," + parsed_key.rendered;
                }
                rendered += ")";
                return append_leaf(std::move(spec), std::move(rendered), leaf_specs, leaf_exprs);
            }

            leaf_expr = arg;
            if (Func("htlc", leaf_expr)) {
                const auto hash_arg = Expr(leaf_expr);
                if (hash_arg.empty()) {
                    error = "mr(): htlc() missing hash160 argument";
                    return false;
                }
                if (!Const(",", leaf_expr)) {
                    error = "mr(): htlc() missing oracle key argument";
                    return false;
                }
                const auto oracle_arg = Expr(leaf_expr);
                if (oracle_arg.empty()) {
                    error = "mr(): htlc() oracle key argument is empty";
                    return false;
                }
                if (!leaf_expr.empty()) {
                    error = "mr(): htlc() has unexpected trailing data";
                    return false;
                }
                std::vector<unsigned char> hash160;
                std::string hash_hex;
                if (!parse_hash160(hash_arg, hash160, hash_hex)) return false;
                ParsedMRKey oracle_key;
                if (!parse_mr_key(oracle_arg, providers, oracle_key)) return false;

                MRLeafSpec spec;
                spec.type = MRLeafType::HTLC;
                spec.htlc_hash160 = std::move(hash160);
                spec.csfs_algo = oracle_key.algo;
                spec.csfs_provider_index = oracle_key.provider_index;
                spec.csfs_fixed_pubkey = std::move(oracle_key.fixed_pubkey);
                return append_leaf(std::move(spec), strprintf("htlc(%s,%s)", hash_hex, oracle_key.rendered), leaf_specs, leaf_exprs);
            }

            leaf_expr = arg;
            if (Func("refund", leaf_expr)) {
                const auto timeout_arg = Expr(leaf_expr);
                if (timeout_arg.empty()) {
                    error = "mr(): refund() missing timeout argument";
                    return false;
                }
                if (!Const(",", leaf_expr)) {
                    error = "mr(): refund() missing spender key argument";
                    return false;
                }
                const auto signer_arg = Expr(leaf_expr);
                if (signer_arg.empty()) {
                    error = "mr(): refund() spender key argument is empty";
                    return false;
                }
                if (!leaf_expr.empty()) {
                    error = "mr(): refund() has unexpected trailing data";
                    return false;
                }

                const auto timeout{ToIntegral<int64_t>(std::string_view(timeout_arg.data(), timeout_arg.size()))};
                if (!timeout.has_value() || *timeout < 0 || *timeout > std::numeric_limits<uint32_t>::max()) {
                    error = strprintf("mr(): refund timeout '%s' is not valid", std::string(timeout_arg.begin(), timeout_arg.end()));
                    return false;
                }

                ParsedMRKey signer_key;
                if (!parse_mr_key(signer_arg, providers, signer_key)) return false;

                MRLeafSpec spec;
                spec.type = MRLeafType::REFUND;
                spec.locktime = *timeout;
                spec.algo = signer_key.algo;
                spec.provider_index = signer_key.provider_index;
                spec.fixed_pubkey = std::move(signer_key.fixed_pubkey);
                return append_leaf(std::move(spec), strprintf("refund(%lld,%s)", static_cast<long long>(*timeout), signer_key.rendered), leaf_specs, leaf_exprs);
            }

            leaf_expr = arg;
            if (Func("csfs", leaf_expr)) {
                ParsedMRKey csfs_key;
                if (!parse_mr_key(leaf_expr, providers, csfs_key)) return false;

                MRLeafSpec spec;
                spec.type = MRLeafType::CSFS_ONLY;
                spec.csfs_algo = csfs_key.algo;
                spec.csfs_provider_index = csfs_key.provider_index;
                spec.csfs_fixed_pubkey = std::move(csfs_key.fixed_pubkey);
                return append_leaf(std::move(spec), strprintf("csfs(%s)", csfs_key.rendered), leaf_specs, leaf_exprs);
            }

            leaf_expr = arg;
            if (Func("csfs_pk", leaf_expr)) {
                const auto csfs_arg = Expr(leaf_expr);
                if (csfs_arg.empty()) {
                    error = "mr(): csfs_pk() missing oracle key argument";
                    return false;
                }
                if (!Const(",", leaf_expr)) {
                    error = "mr(): csfs_pk() missing spender key argument";
                    return false;
                }
                const auto signer_arg = Expr(leaf_expr);
                if (signer_arg.empty()) {
                    error = "mr(): csfs_pk() spender key argument is empty";
                    return false;
                }
                if (!leaf_expr.empty()) {
                    error = "mr(): csfs_pk() has unexpected trailing data";
                    return false;
                }

                ParsedMRKey csfs_key;
                if (!parse_mr_key(csfs_arg, providers, csfs_key)) return false;
                ParsedMRKey signer_key;
                if (!parse_mr_key(signer_arg, providers, signer_key)) return false;

                MRLeafSpec spec;
                spec.type = MRLeafType::CSFS_VERIFY_CHECKSIG;
                spec.csfs_algo = csfs_key.algo;
                spec.csfs_provider_index = csfs_key.provider_index;
                spec.csfs_fixed_pubkey = std::move(csfs_key.fixed_pubkey);
                spec.algo = signer_key.algo;
                spec.provider_index = signer_key.provider_index;
                spec.fixed_pubkey = std::move(signer_key.fixed_pubkey);
                return append_leaf(std::move(spec), strprintf("csfs_pk(%s,%s)", csfs_key.rendered, signer_key.rendered), leaf_specs, leaf_exprs);
            }

            ParsedMRKey checksig_key;
            if (!parse_mr_key(arg, providers, checksig_key)) return false;
            MRLeafSpec spec;
            spec.type = MRLeafType::CHECKSIG;
            spec.algo = checksig_key.algo;
            spec.provider_index = checksig_key.provider_index;
            spec.fixed_pubkey = std::move(checksig_key.fixed_pubkey);
            return append_leaf(std::move(spec), checksig_key.rendered, leaf_specs, leaf_exprs);
        };

        auto parse_backup_tree = [&](auto&& self,
                                     Span<const char> arg,
                                     std::vector<std::unique_ptr<PubkeyProvider>>& providers,
                                     std::vector<MRLeafSpec>& leaf_specs,
                                     std::vector<std::string>& leaf_exprs) -> bool {
            if (arg.empty()) {
                error = "mr(): empty backup tree expression";
                return false;
            }
            if ((arg.front() == '{') != (arg.back() == '}')) {
                error = "mr(): malformed backup tree braces";
                return false;
            }
            if (arg.front() == '{' && arg.back() == '}') {
                auto inner = arg.subspan(1, arg.size() - 2);
                if (inner.empty()) {
                    error = "mr(): empty braces in backup tree";
                    return false;
                }

                const auto left = Expr(inner);
                if (left.empty()) {
                    error = "mr(): empty branch in backup tree";
                    return false;
                }
                if (inner.empty()) {
                    return self(self, left, providers, leaf_specs, leaf_exprs);
                }

                if (!Const(",", inner)) {
                    error = strprintf("mr(): expected ',' in backup tree, got '%c'", inner[0]);
                    return false;
                }
                const auto right = Expr(inner);
                if (right.empty()) {
                    error = "mr(): missing right branch in backup tree";
                    return false;
                }
                if (!inner.empty()) {
                    error = strprintf("mr(): unexpected trailing token '%c' in backup tree", inner[0]);
                    return false;
                }
                if (!self(self, left, providers, leaf_specs, leaf_exprs)) return false;
                return self(self, right, providers, leaf_specs, leaf_exprs);
            }
            return parse_leaf_expr(arg, providers, leaf_specs, leaf_exprs);
        };

        const auto primary_arg = Expr(expr);
        if (primary_arg.empty()) {
            error = "mr(): missing primary leaf argument";
            return {};
        }

        std::vector<std::unique_ptr<PubkeyProvider>> providers;
        std::vector<MRLeafSpec> leaf_specs;
        std::vector<std::string> leaf_exprs;
        if (!parse_leaf_expr(primary_arg, providers, leaf_specs, leaf_exprs)) return {};

        if (expr.size()) {
            if (!Const(",", expr)) {
                error = strprintf("mr(): expected ',', got '%c'", expr[0]);
                return {};
            }
            const auto backup_arg = Expr(expr);
            if (!parse_backup_tree(parse_backup_tree, backup_arg, providers, leaf_specs, leaf_exprs)) return {};
        }
        if (expr.size()) {
            error = strprintf("mr(): unexpected trailing token '%c'", expr[0]);
            return {};
        }

        ret.emplace_back(std::make_unique<MRDescriptor>(std::move(providers), std::move(leaf_specs), std::move(leaf_exprs)));
        return ret;
    } else if (Func("mr", expr)) {
        error = "Can only have mr() at top level";
        return {};
    }
    if (ctx == ParseScriptContext::TOP && Func("tr", expr)) {
        auto arg = Expr(expr);
        auto internal_keys = ParsePubkey(key_exp_index, arg, ParseScriptContext::P2TR, out, error);
        if (internal_keys.empty()) {
            error = strprintf("tr(): %s", error);
            return {};
        }
        size_t max_providers_len = internal_keys.size();
        ++key_exp_index;
        std::vector<std::vector<std::unique_ptr<DescriptorImpl>>> subscripts; //!< list of multipath expanded script subexpressions
        std::vector<int> depths; //!< depth in the tree of each subexpression (same length subscripts)
        if (expr.size()) {
            if (!Const(",", expr)) {
                error = strprintf("tr: expected ',', got '%c'", expr[0]);
                return {};
            }
            /** The path from the top of the tree to what we're currently processing.
             * branches[i] == false: left branch in the i'th step from the top; true: right branch.
             */
            std::vector<bool> branches;
            // Loop over all provided scripts. In every iteration exactly one script will be processed.
            // Use a do-loop because inside this if-branch we expect at least one script.
            do {
                // First process all open braces.
                while (Const("{", expr)) {
                    branches.push_back(false); // new left branch
                    if (branches.size() > TAPROOT_CONTROL_MAX_NODE_COUNT) {
                        error = strprintf("tr() supports at most %i nesting levels", TAPROOT_CONTROL_MAX_NODE_COUNT);
                        return {};
                    }
                }
                // Process the actual script expression.
                auto sarg = Expr(expr);
                subscripts.emplace_back(ParseScript(key_exp_index, sarg, ParseScriptContext::P2TR, out, error, options));
                if (subscripts.back().empty()) return {};
                max_providers_len = std::max(max_providers_len, subscripts.back().size());
                depths.push_back(branches.size());
                // Process closing braces; one is expected for every right branch we were in.
                while (branches.size() && branches.back()) {
                    if (!Const("}", expr)) {
                        error = strprintf("tr(): expected '}' after script expression");
                        return {};
                    }
                    branches.pop_back(); // move up one level after encountering '}'
                }
                // If after that, we're at the end of a left branch, expect a comma.
                if (branches.size() && !branches.back()) {
                    if (!Const(",", expr)) {
                        error = strprintf("tr(): expected ',' after script expression");
                        return {};
                    }
                    branches.back() = true; // And now we're in a right branch.
                }
            } while (branches.size());
            // After we've explored a whole tree, we must be at the end of the expression.
            if (expr.size()) {
                error = strprintf("tr(): expected ')' after script expression");
                return {};
            }
        }
        assert(TaprootBuilder::ValidDepths(depths));

        // Make sure all vecs are of the same length, or exactly length 1
        // For length 1 vectors, clone subdescs until vector is the same length
        for (auto& vec : subscripts) {
            if (vec.size() == 1) {
                for (size_t i = 1; i < max_providers_len; ++i) {
                    vec.emplace_back(vec.at(0)->Clone());
                }
            } else if (vec.size() != max_providers_len) {
                error = strprintf("tr(): Multipath subscripts have mismatched lengths");
                return {};
            }
        }

        if (internal_keys.size() > 1 && internal_keys.size() != max_providers_len) {
            error = strprintf("tr(): Multipath internal key mismatches multipath subscripts lengths");
            return {};
        }

        while (internal_keys.size() < max_providers_len) {
            internal_keys.emplace_back(internal_keys.at(0)->Clone());
        }

        // Build the final descriptors vector
        for (size_t i = 0; i < max_providers_len; ++i) {
            // Build final subscripts vectors by retrieving the i'th subscript for each vector in subscripts
            std::vector<std::unique_ptr<DescriptorImpl>> this_subs;
            this_subs.reserve(subscripts.size());
            for (auto& subs : subscripts) {
                this_subs.emplace_back(std::move(subs.at(i)));
            }
            ret.emplace_back(std::make_unique<TRDescriptor>(std::move(internal_keys.at(i)), std::move(this_subs), depths));
        }
        return ret;


    } else if (Func("tr", expr)) {
        error = "Can only have tr at top level";
        return {};
    }
    if (ctx == ParseScriptContext::TOP && Func("rawtr", expr)) {
        auto arg = Expr(expr);
        if (expr.size()) {
            error = strprintf("rawtr(): only one key expected.");
            return {};
        }
        auto output_keys = ParsePubkey(key_exp_index, arg, ParseScriptContext::P2TR, out, error);
        if (output_keys.empty()) {
            error = strprintf("rawtr(): %s", error);
            return {};
        }
        ++key_exp_index;
        for (auto& pubkey : output_keys) {
            ret.emplace_back(std::make_unique<RawTRDescriptor>(std::move(pubkey)));
        }
        return ret;
    } else if (Func("rawtr", expr)) {
        error = "Can only have rawtr at top level";
        return {};
    }
    if ((ctx == ParseScriptContext::TOP || ctx == ParseScriptContext::P2TR) && Func("raw", expr)) {
        std::string str(expr.begin(), expr.end());
        if (!IsHex(str)) {
            error = "Raw script is not hex";
            return {};
        }
        auto bytes = ParseHex(str);
        CScript raw_script(bytes.begin(), bytes.end());
        if (ctx == ParseScriptContext::P2TR &&
            !RejectP2MROnlyOpcodesInTaproot(raw_script, options, error)) {
            return {};
        }
        ret.emplace_back(std::make_unique<RawDescriptor>(std::move(raw_script)));
        return ret;
    } else if (Func("raw", expr)) {
        error = "Can only have raw() at top level or inside tr()";
        return {};
    }
    // Process miniscript expressions.
    {
        const auto script_ctx{ctx == ParseScriptContext::P2WSH ? miniscript::MiniscriptContext::P2WSH : miniscript::MiniscriptContext::TAPSCRIPT};
        KeyParser parser(/*out = */&out, /* in = */nullptr, /* ctx = */script_ctx, key_exp_index);
        auto node = miniscript::FromString(std::string(expr.begin(), expr.end()), parser);
        if (parser.m_key_parsing_error != "") {
            error = std::move(parser.m_key_parsing_error);
            return {};
        }
        if (node) {
            if (ctx != ParseScriptContext::P2WSH && ctx != ParseScriptContext::P2TR) {
                error = "Miniscript expressions can only be used in wsh or tr.";
                return {};
            }
            if (!node->IsSane() || node->IsNotSatisfiable()) {
                // Try to find the first insane sub for better error reporting.
                auto insane_node = node.get();
                if (const auto sub = node->FindInsaneSub()) insane_node = sub;
                if (const auto str = insane_node->ToString(parser)) error = *str;
                if (!insane_node->IsValid()) {
                    error += " is invalid";
                } else if (!node->IsSane()) {
                    error += " is not sane";
                    if (!insane_node->IsNonMalleable()) {
                        error += ": malleable witnesses exist";
                    } else if (insane_node == node.get() && !insane_node->NeedsSignature()) {
                        error += ": witnesses without signature exist";
                    } else if (!insane_node->CheckTimeLocksMix()) {
                        error += ": contains mixes of timelocks expressed in blocks and seconds";
                    } else if (!insane_node->CheckDuplicateKey()) {
                        error += ": contains duplicate public keys";
                    } else if (!insane_node->ValidSatisfactions()) {
                        error += ": needs witnesses that may exceed resource limits";
                    }
                } else {
                    error += " is not satisfiable";
                }
                return {};
            }
            // A signature check is required for a miniscript to be sane. Therefore no sane miniscript
            // may have an empty list of public keys.
            CHECK_NONFATAL(!parser.m_keys.empty());
            key_exp_index += parser.m_keys.size();
            // Make sure all vecs are of the same length, or exactly length 1
            // For length 1 vectors, clone subdescs until vector is the same length
            size_t num_multipath = std::max_element(parser.m_keys.begin(), parser.m_keys.end(),
                    [](const std::vector<std::unique_ptr<PubkeyProvider>>& a, const std::vector<std::unique_ptr<PubkeyProvider>>& b) {
                        return a.size() < b.size();
                    })->size();

            for (auto& vec : parser.m_keys) {
                if (vec.size() == 1) {
                    for (size_t i = 1; i < num_multipath; ++i) {
                        vec.emplace_back(vec.at(0)->Clone());
                    }
                } else if (vec.size() != num_multipath) {
                    error = strprintf("Miniscript: Multipath derivation paths have mismatched lengths");
                    return {};
                }
            }

            // Build the final descriptors vector
            for (size_t i = 0; i < num_multipath; ++i) {
                // Build final pubkeys vectors by retrieving the i'th subscript for each vector in subscripts
                std::vector<std::unique_ptr<PubkeyProvider>> pubs;
                pubs.reserve(parser.m_keys.size());
                for (auto& pub : parser.m_keys) {
                    pubs.emplace_back(std::move(pub.at(i)));
                }
                ret.emplace_back(std::make_unique<MiniscriptDescriptor>(std::move(pubs), node->Clone()));
            }
            return ret;
        }
    }
    if (ctx == ParseScriptContext::P2SH) {
        error = "A function is needed within P2SH";
        return {};
    } else if (ctx == ParseScriptContext::P2WSH) {
        error = "A function is needed within P2WSH";
        return {};
    }
    error = strprintf("'%s' is not a valid descriptor function", std::string(expr.begin(), expr.end()));
    return {};
}

std::unique_ptr<DescriptorImpl> InferMultiA(const CScript& script, ParseScriptContext ctx, const SigningProvider& provider)
{
    auto match = MatchMultiA(script);
    if (!match) return {};
    std::vector<std::unique_ptr<PubkeyProvider>> keys;
    keys.reserve(match->second.size());
    for (const auto keyspan : match->second) {
        if (keyspan.size() != 32) return {};
        auto key = InferXOnlyPubkey(XOnlyPubKey{keyspan}, ctx, provider);
        if (!key) return {};
        keys.push_back(std::move(key));
    }
    return std::make_unique<MultiADescriptor>(match->first, std::move(keys));
}

// NOLINTNEXTLINE(misc-no-recursion)
std::unique_ptr<DescriptorImpl> InferScript(const CScript& script, ParseScriptContext ctx, const SigningProvider& provider)
{
    if (ctx == ParseScriptContext::P2TR && script.size() == 34 && script[0] == 32 && script[33] == OP_CHECKSIG) {
        XOnlyPubKey key{Span{script}.subspan(1, 32)};
        return std::make_unique<PKDescriptor>(InferXOnlyPubkey(key, ctx, provider), true);
    }

    if (ctx == ParseScriptContext::P2TR) {
        auto ret = InferMultiA(script, ctx, provider);
        if (ret) return ret;
    }

    std::vector<std::vector<unsigned char>> data;
    TxoutType txntype = Solver(script, data);

    if (txntype == TxoutType::PUBKEY && (ctx == ParseScriptContext::TOP || ctx == ParseScriptContext::P2SH || ctx == ParseScriptContext::P2WSH)) {
        CPubKey pubkey(data[0]);
        if (auto pubkey_provider = InferPubkey(pubkey, ctx, provider)) {
            return std::make_unique<PKDescriptor>(std::move(pubkey_provider));
        }
    }
    if (txntype == TxoutType::PUBKEYHASH && (ctx == ParseScriptContext::TOP || ctx == ParseScriptContext::P2SH || ctx == ParseScriptContext::P2WSH)) {
        uint160 hash(data[0]);
        CKeyID keyid(hash);
        CPubKey pubkey;
        if (provider.GetPubKey(keyid, pubkey)) {
            if (auto pubkey_provider = InferPubkey(pubkey, ctx, provider)) {
                return std::make_unique<PKHDescriptor>(std::move(pubkey_provider));
            }
        }
    }
    if (txntype == TxoutType::WITNESS_V0_KEYHASH && (ctx == ParseScriptContext::TOP || ctx == ParseScriptContext::P2SH)) {
        uint160 hash(data[0]);
        CKeyID keyid(hash);
        CPubKey pubkey;
        if (provider.GetPubKey(keyid, pubkey)) {
            if (auto pubkey_provider = InferPubkey(pubkey, ParseScriptContext::P2WPKH, provider)) {
                return std::make_unique<WPKHDescriptor>(std::move(pubkey_provider));
            }
        }
    }
    if (txntype == TxoutType::MULTISIG && (ctx == ParseScriptContext::TOP || ctx == ParseScriptContext::P2SH || ctx == ParseScriptContext::P2WSH)) {
        bool ok = true;
        std::vector<std::unique_ptr<PubkeyProvider>> providers;
        for (size_t i = 1; i + 1 < data.size(); ++i) {
            CPubKey pubkey(data[i]);
            if (auto pubkey_provider = InferPubkey(pubkey, ctx, provider)) {
                providers.push_back(std::move(pubkey_provider));
            } else {
                ok = false;
                break;
            }
        }
        if (ok) return std::make_unique<MultisigDescriptor>((int)data[0][0], std::move(providers));
    }
    if (txntype == TxoutType::SCRIPTHASH && ctx == ParseScriptContext::TOP) {
        uint160 hash(data[0]);
        CScriptID scriptid(hash);
        CScript subscript;
        if (provider.GetCScript(scriptid, subscript)) {
            auto sub = InferScript(subscript, ParseScriptContext::P2SH, provider);
            if (sub) return std::make_unique<SHDescriptor>(std::move(sub));
        }
    }
    if (txntype == TxoutType::WITNESS_V0_SCRIPTHASH && (ctx == ParseScriptContext::TOP || ctx == ParseScriptContext::P2SH)) {
        CScriptID scriptid{RIPEMD160(data[0])};
        CScript subscript;
        if (provider.GetCScript(scriptid, subscript)) {
            auto sub = InferScript(subscript, ParseScriptContext::P2WSH, provider);
            if (sub) return std::make_unique<WSHDescriptor>(std::move(sub));
        }
    }
    if (txntype == TxoutType::WITNESS_V1_TAPROOT && ctx == ParseScriptContext::TOP) {
        // Extract x-only pubkey from output.
        XOnlyPubKey pubkey;
        std::copy(data[0].begin(), data[0].end(), pubkey.begin());
        // Request spending data.
        TaprootSpendData tap;
        if (provider.GetTaprootSpendData(pubkey, tap)) {
            // If found, convert it back to tree form.
            auto tree = InferTaprootTree(tap, pubkey);
            if (tree) {
                // If that works, try to infer subdescriptors for all leaves.
                bool ok = true;
                std::vector<std::unique_ptr<DescriptorImpl>> subscripts; //!< list of script subexpressions
                std::vector<int> depths; //!< depth in the tree of each subexpression (same length subscripts)
                for (const auto& [depth, script, leaf_ver] : *tree) {
                    std::unique_ptr<DescriptorImpl> subdesc;
                    if (leaf_ver == TAPROOT_LEAF_TAPSCRIPT) {
                        subdesc = InferScript(CScript(script.begin(), script.end()), ParseScriptContext::P2TR, provider);
                    }
                    if (!subdesc) {
                        ok = false;
                        break;
                    } else {
                        subscripts.push_back(std::move(subdesc));
                        depths.push_back(depth);
                    }
                }
                if (ok) {
                    auto key = InferXOnlyPubkey(tap.internal_key, ParseScriptContext::P2TR, provider);
                    return std::make_unique<TRDescriptor>(std::move(key), std::move(subscripts), std::move(depths));
                }
            }
        }
        // If the above doesn't work, construct a rawtr() descriptor with just the encoded x-only pubkey.
        if (pubkey.IsFullyValid()) {
            auto key = InferXOnlyPubkey(pubkey, ParseScriptContext::P2TR, provider);
            if (key) {
                return std::make_unique<RawTRDescriptor>(std::move(key));
            }
        }
    }

    if (ctx == ParseScriptContext::P2WSH || ctx == ParseScriptContext::P2TR) {
        const auto script_ctx{ctx == ParseScriptContext::P2WSH ? miniscript::MiniscriptContext::P2WSH : miniscript::MiniscriptContext::TAPSCRIPT};
        KeyParser parser(/* out = */nullptr, /* in = */&provider, /* ctx = */script_ctx);
        auto node = miniscript::FromScript(script, parser);
        if (node && node->IsSane()) {
            std::vector<std::unique_ptr<PubkeyProvider>> keys;
            keys.reserve(parser.m_keys.size());
            for (auto& key : parser.m_keys) {
                keys.emplace_back(std::move(key.at(0)));
            }
            return std::make_unique<MiniscriptDescriptor>(std::move(keys), std::move(node));
        }
    }

    // The following descriptors are all top-level only descriptors.
    // So if we are not at the top level, return early.
    if (ctx != ParseScriptContext::TOP) return nullptr;

    CTxDestination dest;
    if (ExtractDestination(script, dest)) {
        if (GetScriptForDestination(dest) == script) {
            return std::make_unique<AddressDescriptor>(std::move(dest));
        }
    }

    return std::make_unique<RawDescriptor>(script);
}


} // namespace

/** Check a descriptor checksum, and update desc to be the checksum-less part. */
bool CheckChecksum(Span<const char>& sp, bool require_checksum, std::string& error, std::string* out_checksum = nullptr)
{
    auto check_split = Split(sp, '#');
    if (check_split.size() > 2) {
        error = "Multiple '#' symbols";
        return false;
    }
    if (check_split.size() == 1 && require_checksum){
        error = "Missing checksum";
        return false;
    }
    if (check_split.size() == 2) {
        if (check_split[1].size() != 8) {
            error = strprintf("Expected 8 character checksum, not %u characters", check_split[1].size());
            return false;
        }
    }
    auto checksum = DescriptorChecksum(check_split[0]);
    if (checksum.empty()) {
        error = "Invalid characters in payload";
        return false;
    }
    if (check_split.size() == 2) {
        if (!std::equal(checksum.begin(), checksum.end(), check_split[1].begin())) {
            error = strprintf("Provided checksum '%s' does not match computed checksum '%s'", std::string(check_split[1].begin(), check_split[1].end()), checksum);
            return false;
        }
    }
    if (out_checksum) *out_checksum = std::move(checksum);
    sp = check_split[0];
    return true;
}

std::vector<std::unique_ptr<Descriptor>> Parse(const std::string& descriptor, FlatSigningProvider& out, std::string& error, bool require_checksum)
{
    return Parse(descriptor, out, error, require_checksum, DescriptorParseOptions{});
}

std::vector<std::unique_ptr<Descriptor>> Parse(const std::string& descriptor, FlatSigningProvider& out, std::string& error, bool require_checksum, const DescriptorParseOptions& options)
{
    Span<const char> sp{descriptor};
    if (!CheckChecksum(sp, require_checksum, error)) return {};
    uint32_t key_exp_index = 0;
    auto ret = ParseScript(key_exp_index, sp, ParseScriptContext::TOP, out, error, options);
    if (sp.size() == 0 && !ret.empty()) {
        std::vector<std::unique_ptr<Descriptor>> descs;
        descs.reserve(ret.size());
        for (auto& r : ret) {
            descs.emplace_back(std::unique_ptr<Descriptor>(std::move(r)));
        }
        return descs;
    }
    return {};
}

std::string GetDescriptorChecksum(const std::string& descriptor)
{
    std::string ret;
    std::string error;
    Span<const char> sp{descriptor};
    if (!CheckChecksum(sp, false, error, &ret)) return "";
    return ret;
}

std::string AddChecksum(const std::string& str) { return str + "#" + DescriptorChecksum(str); }

std::unique_ptr<Descriptor> InferDescriptor(const CScript& script, const SigningProvider& provider)
{
    return InferScript(script, ParseScriptContext::TOP, provider);
}

uint256 DescriptorID(const Descriptor& desc)
{
    std::string desc_str = desc.ToString(/*compat_format=*/true);
    uint256 id;
    CSHA256().Write((unsigned char*)desc_str.data(), desc_str.size()).Finalize(id.begin());
    return id;
}

void DescriptorCache::CacheParentExtPubKey(uint32_t key_exp_pos, const CExtPubKey& xpub)
{
    m_parent_xpubs[key_exp_pos] = xpub;
}

void DescriptorCache::CacheDerivedExtPubKey(uint32_t key_exp_pos, uint32_t der_index, const CExtPubKey& xpub)
{
    auto& xpubs = m_derived_xpubs[key_exp_pos];
    xpubs[der_index] = xpub;
}

void DescriptorCache::CacheLastHardenedExtPubKey(uint32_t key_exp_pos, const CExtPubKey& xpub)
{
    m_last_hardened_xpubs[key_exp_pos] = xpub;
}

bool DescriptorCache::GetCachedParentExtPubKey(uint32_t key_exp_pos, CExtPubKey& xpub) const
{
    const auto& it = m_parent_xpubs.find(key_exp_pos);
    if (it == m_parent_xpubs.end()) return false;
    xpub = it->second;
    return true;
}

bool DescriptorCache::GetCachedDerivedExtPubKey(uint32_t key_exp_pos, uint32_t der_index, CExtPubKey& xpub) const
{
    const auto& key_exp_it = m_derived_xpubs.find(key_exp_pos);
    if (key_exp_it == m_derived_xpubs.end()) return false;
    const auto& der_it = key_exp_it->second.find(der_index);
    if (der_it == key_exp_it->second.end()) return false;
    xpub = der_it->second;
    return true;
}

bool DescriptorCache::GetCachedLastHardenedExtPubKey(uint32_t key_exp_pos, CExtPubKey& xpub) const
{
    const auto& it = m_last_hardened_xpubs.find(key_exp_pos);
    if (it == m_last_hardened_xpubs.end()) return false;
    xpub = it->second;
    return true;
}

void DescriptorCache::CacheDerivedPQPubKey(PQAlgorithm algo, uint32_t key_exp_pos, uint32_t der_index, Span<const unsigned char> pubkey)
{
    PQPubKeyExprMap& map = (algo == PQAlgorithm::ML_DSA_44) ? m_pq_pubkeys_mldsa : m_pq_pubkeys_slh;
    map[key_exp_pos][der_index] = std::vector<unsigned char>(pubkey.begin(), pubkey.end());
}

bool DescriptorCache::GetCachedDerivedPQPubKey(PQAlgorithm algo, uint32_t key_exp_pos, uint32_t der_index, std::vector<unsigned char>& pubkey) const
{
    const PQPubKeyExprMap& map = (algo == PQAlgorithm::ML_DSA_44) ? m_pq_pubkeys_mldsa : m_pq_pubkeys_slh;
    const auto& key_exp_it = map.find(key_exp_pos);
    if (key_exp_it == map.end()) return false;
    const auto& der_it = key_exp_it->second.find(der_index);
    if (der_it == key_exp_it->second.end()) return false;
    pubkey = der_it->second;
    return true;
}

DescriptorCache DescriptorCache::MergeAndDiff(const DescriptorCache& other)
{
    DescriptorCache diff;
    for (const auto& parent_xpub_pair : other.GetCachedParentExtPubKeys()) {
        CExtPubKey xpub;
        if (GetCachedParentExtPubKey(parent_xpub_pair.first, xpub)) {
            if (xpub != parent_xpub_pair.second) {
                throw std::runtime_error(std::string(__func__) + ": New cached parent xpub does not match already cached parent xpub");
            }
            continue;
        }
        CacheParentExtPubKey(parent_xpub_pair.first, parent_xpub_pair.second);
        diff.CacheParentExtPubKey(parent_xpub_pair.first, parent_xpub_pair.second);
    }
    for (const auto& derived_xpub_map_pair : other.GetCachedDerivedExtPubKeys()) {
        for (const auto& derived_xpub_pair : derived_xpub_map_pair.second) {
            CExtPubKey xpub;
            if (GetCachedDerivedExtPubKey(derived_xpub_map_pair.first, derived_xpub_pair.first, xpub)) {
                if (xpub != derived_xpub_pair.second) {
                    throw std::runtime_error(std::string(__func__) + ": New cached derived xpub does not match already cached derived xpub");
                }
                continue;
            }
            CacheDerivedExtPubKey(derived_xpub_map_pair.first, derived_xpub_pair.first, derived_xpub_pair.second);
            diff.CacheDerivedExtPubKey(derived_xpub_map_pair.first, derived_xpub_pair.first, derived_xpub_pair.second);
        }
    }
    for (const auto& lh_xpub_pair : other.GetCachedLastHardenedExtPubKeys()) {
        CExtPubKey xpub;
        if (GetCachedLastHardenedExtPubKey(lh_xpub_pair.first, xpub)) {
            if (xpub != lh_xpub_pair.second) {
                throw std::runtime_error(std::string(__func__) + ": New cached last hardened xpub does not match already cached last hardened xpub");
            }
            continue;
        }
        CacheLastHardenedExtPubKey(lh_xpub_pair.first, lh_xpub_pair.second);
        diff.CacheLastHardenedExtPubKey(lh_xpub_pair.first, lh_xpub_pair.second);
    }

    for (PQAlgorithm algo : {PQAlgorithm::ML_DSA_44, PQAlgorithm::SLH_DSA_128S}) {
        for (const auto& key_exp_pair : other.GetCachedDerivedPQPubKeys(algo)) {
            for (const auto& der_pair : key_exp_pair.second) {
                std::vector<unsigned char> existing;
                if (GetCachedDerivedPQPubKey(algo, key_exp_pair.first, der_pair.first, existing)) {
                    if (existing != der_pair.second) {
                        throw std::runtime_error(std::string(__func__) + ": New cached derived PQ pubkey does not match already cached derived PQ pubkey");
                    }
                    continue;
                }
                CacheDerivedPQPubKey(algo, key_exp_pair.first, der_pair.first, der_pair.second);
                diff.CacheDerivedPQPubKey(algo, key_exp_pair.first, der_pair.first, der_pair.second);
            }
        }
    }
    return diff;
}

ExtPubKeyMap DescriptorCache::GetCachedParentExtPubKeys() const
{
    return m_parent_xpubs;
}

std::unordered_map<uint32_t, ExtPubKeyMap> DescriptorCache::GetCachedDerivedExtPubKeys() const
{
    return m_derived_xpubs;
}

ExtPubKeyMap DescriptorCache::GetCachedLastHardenedExtPubKeys() const
{
    return m_last_hardened_xpubs;
}

PQPubKeyExprMap DescriptorCache::GetCachedDerivedPQPubKeys(PQAlgorithm algo) const
{
    return (algo == PQAlgorithm::ML_DSA_44) ? m_pq_pubkeys_mldsa : m_pq_pubkeys_slh;
}
