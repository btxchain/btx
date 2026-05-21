// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UNDO_H
#define BITCOIN_UNDO_H

#include <coins.h>
#include <compressor.h>
#include <consensus/consensus.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <shielded/nullifier.h>

#include <ios>
#include <set>
#include <stdint.h>
#include <vector>

/** Formatter for undo information for a CTxIn
 *
 *  Contains the prevout's CTxOut being spent, and its metadata as well
 *  (coinbase or not, height). The serialization contains a dummy value of
 *  zero. This is compatible with older versions which expect to see
 *  the transaction version there.
 */
struct TxInUndoFormatter
{
    template<typename Stream>
    void Ser(Stream &s, const Coin& txout) {
        ::Serialize(s, VARINT(txout.nHeight * uint32_t{2} + txout.fCoinBase ));
        if (txout.nHeight > 0) {
            // Required to maintain compatibility with older undo format.
            ::Serialize(s, (unsigned char)0);
        }
        ::Serialize(s, Using<TxOutCompression>(txout.out));
    }

    template<typename Stream>
    void Unser(Stream &s, Coin& txout) {
        uint32_t nCode = 0;
        ::Unserialize(s, VARINT(nCode));
        txout.nHeight = nCode >> 1;
        txout.fCoinBase = nCode & 1;
        if (txout.nHeight > 0) {
            // Old versions stored the version number for the last spend of
            // a transaction's outputs. Non-final spends were indicated with
            // height = 0.
            unsigned int nVersionDummy;
            ::Unserialize(s, VARINT(nVersionDummy));
        }
        ::Unserialize(s, Using<TxOutCompression>(txout.out));
    }
};

/** Undo information for a CTransaction */
class CTxUndo
{
public:
    // undo information for all txins
    std::vector<Coin> vprevout;

    SERIALIZE_METHODS(CTxUndo, obj) { READWRITE(Using<VectorFormatter<TxInUndoFormatter>>(obj.vprevout)); }
};

/** Undo information for a CBlock */
class CBlockUndo
{
public:
    static constexpr uint32_t SHIELDED_SETTLEMENT_ANCHOR_UNDO_MAGIC{0x42545855}; // "BTXU"
    static constexpr uint8_t SHIELDED_SETTLEMENT_ANCHOR_UNDO_VERSION{1};

    std::vector<CTxUndo> vtxundo; // for all but the coinbase
    std::vector<ConfirmedSettlementAnchorState> consumed_settlement_anchor_states;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ::Serialize(s, vtxundo);
        if (!consumed_settlement_anchor_states.empty()) {
            ::Serialize(s, SHIELDED_SETTLEMENT_ANCHOR_UNDO_MAGIC);
            ::Serialize(s, SHIELDED_SETTLEMENT_ANCHOR_UNDO_VERSION);
            ::Serialize(s, consumed_settlement_anchor_states);
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, vtxundo);
        consumed_settlement_anchor_states.clear();
        if (s.empty()) {
            return;
        }

        uint32_t magic{0};
        uint8_t version{0};
        ::Unserialize(s, magic);
        ::Unserialize(s, version);
        if (magic != SHIELDED_SETTLEMENT_ANCHOR_UNDO_MAGIC ||
            version != SHIELDED_SETTLEMENT_ANCHOR_UNDO_VERSION) {
            throw std::ios_base::failure("CBlockUndo unsupported shielded undo extension");
        }

        ::Unserialize(s, consumed_settlement_anchor_states);
        std::set<uint256> seen_anchors;
        for (const auto& anchor_state : consumed_settlement_anchor_states) {
            if (!anchor_state.IsValid() || !seen_anchors.insert(anchor_state.anchor).second) {
                throw std::ios_base::failure("CBlockUndo invalid consumed settlement-anchor metadata");
            }
        }
        if (!s.empty()) {
            throw std::ios_base::failure("CBlockUndo trailing bytes");
        }
    }
};

#endif // BITCOIN_UNDO_H
