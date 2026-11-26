// Copyright (c) 2026-present The VAQYRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <kernel/genesis.h>

#include <consensus/merkle.h>
#include <script/script.h>

#include <string_view>
#include <utility>
#include <vector>

namespace kernel {
namespace {

constexpr std::string_view GENESIS_MESSAGE{"VAQYRON - Independent Proof-of-Work Network - 2026"};
constexpr std::string_view GENESIS_MARKER{"VAQYRON genesis marker v1"};

} // namespace

std::string_view VaqyronGenesisMessage()
{
    return GENESIS_MESSAGE;
}

std::string_view VaqyronGenesisMarker()
{
    return GENESIS_MARKER;
}

CTransactionRef CreateVaqyronGenesisTransaction()
{
    CMutableTransaction tx;
    tx.version = 1;
    tx.vin.emplace_back();
    tx.vin[0].prevout.SetNull();
    tx.vin[0].scriptSig =
        CScript() << std::vector<unsigned char>(VaqyronGenesisMessage().begin(), VaqyronGenesisMessage().end());
    tx.vout.emplace_back(
        0, CScript() << OP_RETURN << std::vector<unsigned char>(VaqyronGenesisMarker().begin(), VaqyronGenesisMarker().end()));
    tx.nLockTime = 0;
    return MakeTransactionRef(std::move(tx));
}

CBlock CreateVaqyronGenesisBlock(uint32_t time, uint32_t nonce, uint32_t bits,
                                int32_t version)
{
    CBlock genesis;
    genesis.nTime = time;
    genesis.nNonce = nonce;
    genesis.nBits = bits;
    genesis.nVersion = version;
    genesis.hashPrevBlock.SetNull();
    genesis.vtx.emplace_back(CreateVaqyronGenesisTransaction());
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

} // namespace kernel
