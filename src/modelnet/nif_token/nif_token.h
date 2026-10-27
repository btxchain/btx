// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_NIF_TOKEN_NIF_TOKEN_H
#define BITCOIN_MODELNET_NIF_TOKEN_NIF_TOKEN_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

/** Bind refused an empty tokenizer. Nothing is stored. */
inline constexpr char NIF_TOKEN_TOKENIZER[] = "TOKENIZER";

/** Bind refused an empty grammar. Nothing is stored. */
inline constexpr char NIF_TOKEN_GRAMMAR[] = "GRAMMAR";

/** Bind refused an empty sampler. Nothing is stored. */
inline constexpr char NIF_TOKEN_SAMPLER[] = "SAMPLER";

/** Continue saw a triple that is not the bound triple. No bytes move. */
inline constexpr char NIF_TOKEN_COMPAT[] = "COMPAT";

/** Approximate is not an exact continuation. */
inline constexpr char NIF_TOKEN_APPROXIMATE[] = "APPROXIMATE";

/**
 * Bound tokenizer, grammar, and sampler.
 *
 * Bind stores one triple. An empty tokenizer is TOKENIZER, an empty
 * grammar is GRAMMAR, and an empty sampler is SAMPLER. A refused Bind
 * stores nothing and leaves a previous triple in place.
 *
 * Continue returns true only when all three equal the bound values.
 * A mismatch is COMPAT and moves no bytes. bytes_moved() stays 0.
 * A match records one continuation and continuations() becomes 1.
 * A second match of that same triple is NIFDT_REPLAY and does not
 * increment continuations().
 *
 * Approximate returns false with APPROXIMATE.
 * approximate_called_exact() stays false.
 *
 * Remote for an engine NifDtEngineLinked rejects, including nixl,
 * mooncake, and rdma, returns false with NIFDT_ENGINE_ABSENT.
 * bytes_moved() stays 0. Any other name is ENGINE and also moves nothing.
 *
 * launched(), gpu(), and broadcast() stay false. automatic_spend() is
 * NIFDT_AUTOMATIC_SPEND ("0"). all_rank_qualified() stays false.
 * This class opens no socket and holds no spend key.
 */
class NifToken {
public:
    bool Bind(const std::string& tokenizer, const std::string& grammar, const std::string& sampler, std::string& err);
    bool Continue(const std::string& tokenizer, const std::string& grammar, const std::string& sampler, std::string& err);
    bool Approximate(std::string& err);
    bool Remote(const std::string& engine, std::string& err);

    const std::string& tokenizer() const { return m_tokenizer; }
    const std::string& grammar() const { return m_grammar; }
    const std::string& sampler() const { return m_sampler; }
    int64_t continuations() const { return m_continuations; }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    bool approximate_called_exact() const { return false; }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool all_rank_qualified() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    std::string m_tokenizer;
    std::string m_grammar;
    std::string m_sampler;
    bool m_bound{false};
    bool m_continued{false};
    int64_t m_continuations{0};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_NIF_TOKEN_NIF_TOKEN_H
