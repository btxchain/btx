// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_image/nif_image.h>

#include <modelnet/nifdt_contract/contract.h>

#include <string>

namespace {

bool LowerHex64(const std::string& digest)
{
    if (digest.size() != 64) return false;
    for (const char ch : digest) {
        const bool digit = ch >= '0' && ch <= '9';
        const bool lower = ch >= 'a' && ch <= 'f';
        if (!digit && !lower) return false;
    }
    return true;
}

} // namespace

namespace modelnet {

bool NifImage::Bind(const std::string& digest, const std::string& software_authority, const std::string& model_authority, std::string& err)
{
    if (!LowerHex64(digest)) {
        err = NIF_IMAGE_DIGEST;
        return false;
    }
    if (software_authority.empty() || software_authority == model_authority) {
        err = NIF_IMAGE_AUTHORITY;
        return false;
    }
    m_pins.push_back(digest);
    m_current = digest;
    err.clear();
    return true;
}

bool NifImage::Rollback(std::string& err)
{
    if (m_pins.size() < 2) {
        err = NIF_IMAGE_EMPTY;
        return false;
    }
    m_pins.pop_back();
    m_current = m_pins.back();
    err.clear();
    return true;
}

bool NifImage::Download(const std::string& url, std::string& err)
{
    static_cast<void>(url);
    err = NIF_IMAGE_DOWNLOAD;
    return false;
}

bool NifImage::Execute(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

} // namespace modelnet
