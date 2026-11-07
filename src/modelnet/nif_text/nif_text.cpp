// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_text/nif_text.h>

#include <cstddef>
#include <string>
#include <vector>

namespace modelnet {
namespace {

bool IsContinuation(unsigned char byte)
{
    return (byte & 0xC0) == 0x80;
}

int SequenceLength(unsigned char lead)
{
    if ((lead & 0x80) == 0) {
        return 1;
    }
    if ((lead & 0xE0) == 0xC0) {
        return 2;
    }
    if ((lead & 0xF0) == 0xE0) {
        return 3;
    }
    if ((lead & 0xF8) == 0xF0) {
        return 4;
    }
    return 0;
}

/**
 * True when every byte belongs to a character that both starts and ends
 * inside this buffer. A leading continuation, an invalid lead, or a
 * multibyte lead short of its continuation bytes is incomplete.
 */
bool Utf8SequenceComplete(const std::vector<unsigned char>& bytes)
{
    std::size_t i = 0;
    while (i < bytes.size()) {
        const unsigned char lead = bytes[i];
        if (IsContinuation(lead)) {
            return false;
        }
        const int length = SequenceLength(lead);
        if (length <= 0) {
            return false;
        }
        if (i + static_cast<std::size_t>(length) > bytes.size()) {
            return false;
        }
        for (int n = 1; n < length; ++n) {
            if (!IsContinuation(bytes[i + static_cast<std::size_t>(n)])) {
                return false;
            }
        }
        i += static_cast<std::size_t>(length);
    }
    return true;
}

} // namespace

bool NifText::Special(int64_t id) const
{
    return id == static_cast<int64_t>(1);
}

bool NifText::Text(const std::string& s, std::string& err)
{
    if (s.empty()) {
        err = NIF_TEXT_TEXT;
        return false;
    }
    if (s == "<eos>") {
        m_id = static_cast<int64_t>(0);
        m_lookalike = s;
        err = NIF_TEXT_LOOKALIKE;
        return false;
    }
    m_id = static_cast<int64_t>(0);
    m_committed.append(s);
    err.clear();
    return true;
}

bool NifText::AcceptUtf8(const std::vector<unsigned char>& bytes, std::string& err)
{
    if (!Utf8SequenceComplete(bytes)) {
        err = NIF_TEXT_BOUNDARY;
        return false;
    }
    m_committed.insert(m_committed.end(), bytes.begin(), bytes.end());
    err.clear();
    return true;
}

bool NifText::PushUtf8(const std::vector<unsigned char>& bytes, std::string& err)
{
    return AcceptUtf8(bytes, err);
}

bool NifText::Split(const std::vector<unsigned char>& bytes, std::string& err)
{
    return AcceptUtf8(bytes, err);
}

} // namespace modelnet
