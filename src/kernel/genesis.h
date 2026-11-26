// Copyright (c) 2026-present The VAQYRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_KERNEL_GENESIS_H
#define BITCOIN_KERNEL_GENESIS_H

#include <primitives/block.h>
#include <primitives/transaction.h>

#include <cstdint>
#include <string_view>

namespace kernel {

std::string_view VaqyronGenesisMessage();
std::string_view VaqyronGenesisMarker();

/** Construct the frozen VAQYRON genesis coinbase transaction. */
CTransactionRef CreateVaqyronGenesisTransaction();

/** Construct a VAQYRON genesis block with explicit header fields, without mining. */
CBlock CreateVaqyronGenesisBlock(uint32_t time, uint32_t nonce, uint32_t bits,
                                int32_t version);

} // namespace kernel

#endif // BITCOIN_KERNEL_GENESIS_H
