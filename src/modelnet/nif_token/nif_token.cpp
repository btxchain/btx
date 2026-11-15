// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_token/nif_token.h>

#include <string>

namespace modelnet {

bool NifToken::Bind(const std::string& tokenizer, const std::string& grammar, const std::string& sampler, std::string& err)
{
    if (tokenizer.empty()) {
        err = NIF_TOKEN_TOKENIZER;
        return false;
    }
    if (grammar.empty()) {
        err = NIF_TOKEN_GRAMMAR;
        return false;
    }
    if (sampler.empty()) {
        err = NIF_TOKEN_SAMPLER;
        return false;
    }
    m_tokenizer = tokenizer;
    m_grammar = grammar;
    m_sampler = sampler;
    m_bound = true;
    m_continued = false;
    err.clear();
    return true;
}

bool NifToken::Continue(const std::string& tokenizer, const std::string& grammar, const std::string& sampler, std::string& err)
{
    if (!m_bound || tokenizer != m_tokenizer || grammar != m_grammar || sampler != m_sampler) {
        err = NIF_TOKEN_COMPAT;
        return false;
    }
    if (m_continued) {
        err = NIFDT_REPLAY;
        return false;
    }
    m_continued = true;
    m_continuations += static_cast<int64_t>(1);
    err.clear();
    return true;
}

bool NifToken::Approximate(std::string& err)
{
    err = NIF_TOKEN_APPROXIMATE;
    return false;
}

bool NifToken::Remote(const std::string& engine, std::string& err)
{
    if (!NifDtEngineLinked(engine)) {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    err = "ENGINE";
    return false;
}

} // namespace modelnet
