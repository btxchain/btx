// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_NIF_TEXT_NIF_TEXT_H
#define BITCOIN_MODELNET_NIF_TEXT_NIF_TEXT_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/** Text refused the exact string "<eos>". It is a look-alike, not id 1. */
inline constexpr char NIF_TEXT_LOOKALIKE[] = "LOOKALIKE";

/** Text refused an empty string. Nothing is appended. */
inline constexpr char NIF_TEXT_TEXT[] = "TEXT";

/** A call did not end on a UTF-8 codepoint boundary. Nothing is appended. */
inline constexpr char NIF_TEXT_BOUNDARY[] = "BOUNDARY";

/**
 * Special-token identity and a committed UTF-8 text stream.
 *
 * Special returns true only for id 1. No other id is special.
 *
 * Text maps the exact string "<eos>" to a look-alike and returns false
 * with LOOKALIKE. That path sets id() to 0. It does not return id 1 and
 * it does not append. Any other non-empty text returns true, leaves id()
 * at 0, and appends the text to the committed stream. Empty text is TEXT
 * and appends nothing.
 *
 * PushUtf8 appends a complete UTF-8 sequence from this call only. A
 * leading continuation byte, or a multibyte lead without all of its
 * continuation bytes in this call, is BOUNDARY and appends nothing. The
 * bytes 0xC3 0xA9 (U+00E9) are one complete character and append. A later
 * call may commit the next character. An incomplete call does not replay
 * bytes already accepted.
 *
 * Split that ends in the middle of a codepoint is BOUNDARY and does not
 * grow committed_bytes(). A split that is a complete sequence appends.
 *
 * committed_bytes() counts only accepted bytes. launched(), gpu(), and
 * broadcast() stay false. automatic_spend() is NIFDT_AUTOMATIC_SPEND
 * ("0"). This class opens no socket and holds no spend key.
 */
class NifText {
public:
    bool Special(int64_t id) const;
    bool Text(const std::string& s, std::string& err);
    bool PushUtf8(const std::vector<unsigned char>& bytes, std::string& err);
    bool Split(const std::vector<unsigned char>& bytes, std::string& err);

    int64_t id() const { return m_id; }
    const std::string& lookalike() const { return m_lookalike; }
    const std::string& committed() const { return m_committed; }
    int64_t committed_bytes() const { return static_cast<int64_t>(m_committed.size()); }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    bool AcceptUtf8(const std::vector<unsigned char>& bytes, std::string& err);

    std::string m_committed;
    std::string m_lookalike;
    int64_t m_id{0};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_NIF_TEXT_NIF_TEXT_H
