// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DECODE_OUTPUT_H
#define BITCOIN_MODELNET_SWARM_DECODE_OUTPUT_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Bytes appended by a memory Pull.
 * text() starts empty. tokens() starts at 0.
 * append_byte adds one caller-supplied byte and increments tokens() by 1.
 * A stored prompt is not copied here until that byte is appended.
 * At most 8 bytes are accepted.
 */
class SwarmDecodeOutput {
public:
    const std::string& text() const;
    int64_t tokens() const;

    /**
     * Append one byte and increment tokens() by 1.
     * Refuses when tokens() is already at the 8-byte cap, or when tokens()
     * does not match text().size(). On refusal text() and tokens() stay as they were.
     */
    bool append_byte(char byte);

private:
    std::string m_text;
    int64_t m_tokens{0};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DECODE_OUTPUT_H
