// Copyright (c) 2026 The VAQYRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_VALIDATION_INTERNAL_H
#define BITCOIN_VALIDATION_INTERNAL_H

#include <consensus/amount.h>
#include <consensus/validation.h>
#include <primitives/block.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/chaintype.h>

#include <exception>
#include <optional>
#include <utility>

namespace validation_internal {

inline std::optional<CAmount> AddBlockFee(CAmount accumulated_fees, CAmount tx_fee, CAmount max_money)
{
    if (accumulated_fees < 0 || tx_fee < 0 || max_money < 0 ||
        accumulated_fees > max_money || tx_fee > max_money - accumulated_fees) {
        return std::nullopt;
    }
    return accumulated_fees + tx_fee;
}

inline std::optional<CAmount> AddSnapshotCoinAmount(CAmount accumulated_amount, CAmount coin_amount, CAmount max_money)
{
    if (accumulated_amount < 0 || coin_amount < 0 || max_money < 0 ||
        accumulated_amount > max_money || coin_amount > max_money - accumulated_amount) {
        return std::nullopt;
    }
    return accumulated_amount + coin_amount;
}

inline bool ShouldEnforceBIP30OnDisconnect(ChainType chain_type, int height, const uint256& block_hash)
{
    return chain_type == ChainType::MAIN ||
           chain_type == ChainType::VAQYRON_TESTNET ||
           !((height == 91722 && block_hash == uint256{"00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e"}) ||
             (height == 91812 && block_hash == uint256{"00000000000af0aed4792b1acee3d966af36cf5def14935db8de83d6f9306f2f"}));
}

template <typename PowCheck>
bool CheckProofOfWorkIfRequested(
    const CBlockHeader& header,
    BlockValidationState& state,
    bool requested,
    PowCheck&& pow_check)
{
    if (!requested) return true;

    try {
        if (!std::forward<PowCheck>(pow_check)(header)) {
            return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "high-hash", "proof of work failed");
        }
    } catch (const std::exception& e) {
        return state.Error(strprintf("proof of work computation failed: %s", e.what()));
    }
    return true;
}

} // namespace validation_internal

#endif // BITCOIN_VALIDATION_INTERNAL_H
