// Copyright (c) 2026-present The VAQYRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <arith_uint256.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <streams.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <util/translation.h>

#include <charconv>
#include <cstdint>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

const TranslateFn G_TRANSLATION_FUN{nullptr};

namespace {

constexpr uint32_t TESTNET_GENESIS_TIME{1791460800};
constexpr uint32_t TESTNET_GENESIS_BITS{0x207fffff};
constexpr int32_t TESTNET_GENESIS_VERSION{1};
constexpr std::string_view TESTNET_GENESIS_MESSAGE{
    "VAQYRON TESTNET - Independent Proof-of-Work Network - 2026-10-08"};
constexpr std::string_view TESTNET_GENESIS_MARKER{"VAQYRON TESTNET genesis marker v1"};

uint32_t ParseUint32(std::string_view value, std::string_view name)
{
    uint64_t parsed{0};
    const auto [end, error]{std::from_chars(value.data(), value.data() + value.size(), parsed)};
    if (error != std::errc{} || end != value.data() + value.size() ||
        parsed > std::numeric_limits<uint32_t>::max()) {
        throw std::invalid_argument{std::string{name} + " must be an unsigned 32-bit decimal integer"};
    }
    return static_cast<uint32_t>(parsed);
}

CBlock CreateTestnetGenesisBlock(uint32_t nonce)
{
    CMutableTransaction coinbase;
    coinbase.version = TESTNET_GENESIS_VERSION;
    coinbase.vin.emplace_back();
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig =
        CScript() << std::vector<unsigned char>(
                         TESTNET_GENESIS_MESSAGE.begin(), TESTNET_GENESIS_MESSAGE.end());
    coinbase.vout.emplace_back(
        0, CScript() << OP_RETURN
                     << std::vector<unsigned char>(
                            TESTNET_GENESIS_MARKER.begin(), TESTNET_GENESIS_MARKER.end()));

    CBlock block;
    block.nVersion = TESTNET_GENESIS_VERSION;
    block.hashPrevBlock.SetNull();
    block.nTime = TESTNET_GENESIS_TIME;
    block.nBits = TESTNET_GENESIS_BITS;
    block.nNonce = nonce;
    block.vtx.emplace_back(MakeTransactionRef(std::move(coinbase)));
    block.hashMerkleRoot = BlockMerkleRoot(block);
    return block;
}

void PrintUsage()
{
    std::cerr << "Usage: vaqyron-testnet-genesis-search --start-nonce <uint32> --end-nonce <uint32>\n";
}

} // namespace

int main(int argc, char* argv[])
{
    try {
        if (argc != 5 || argv[1] != std::string_view{"--start-nonce"} ||
            argv[3] != std::string_view{"--end-nonce"}) {
            PrintUsage();
            return 2;
        }

        const uint32_t start_nonce{ParseUint32(argv[2], "--start-nonce")};
        const uint32_t end_nonce{ParseUint32(argv[4], "--end-nonce")};
        if (start_nonce > end_nonce) {
            throw std::invalid_argument{"starting nonce must not exceed ending nonce"};
        }

        Consensus::Params consensus{};
        consensus.powLimit = uint256{"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.fPowUseYespower = true;
        const auto target{DeriveTarget(TESTNET_GENESIS_BITS, consensus.powLimit)};
        if (!target) throw std::runtime_error{"testnet genesis target is invalid"};

        std::cout << "CHAIN: vaqyron-testnet\n"
                  << "GENESIS MESSAGE: " << TESTNET_GENESIS_MESSAGE << '\n'
                  << "OP_RETURN MARKER: " << TESTNET_GENESIS_MARKER << '\n'
                  << "VERSION: " << TESTNET_GENESIS_VERSION << '\n'
                  << "POW ALGORITHM: yespower YESPOWER_1_0\n"
                  << "N: 2048\n"
                  << "r: 16\n"
                  << "PERSONALIZATION: VAQYRON:pow:yespower:v1\n"
                  << "CANDIDATE INTERPRETATION: raw digest byte 0 is least-significant\n"
                  << "nTime: " << TESTNET_GENESIS_TIME << " (2026-10-08 12:00:00 UTC)\n"
                  << "nBits: 0x" << std::hex << TESTNET_GENESIS_BITS << std::dec << '\n'
                  << "TARGET: " << target->GetHex() << '\n'
                  << "POW LIMIT: " << consensus.powLimit.GetHex() << '\n'
                  << "SEARCH RANGE: " << start_nonce << ".." << end_nonce << '\n'
                  << "TIMESTAMP MUTATION: disabled\n"
                  << "NONCE WRAP: disabled\n";

        uint64_t checked{0};
        uint32_t found_nonce{0};
        CBlock found_block;
        uint256 found_digest;
        for (uint64_t nonce{start_nonce}; nonce <= end_nonce; ++nonce) {
            CBlock candidate{CreateTestnetGenesisBlock(static_cast<uint32_t>(nonce))};
            const uint256 digest{GetPoWDigest(candidate)};
            ++checked;
            if (UintToArith256(digest) <= *target) {
                found_nonce = static_cast<uint32_t>(nonce);
                found_block = std::move(candidate);
                found_digest = digest;
                break;
            }
        }

        if (found_block.vtx.empty()) {
            std::cout << "RESULT: NOT FOUND\nCANDIDATES EVALUATED: " << checked << '\n';
            return 1;
        }

        std::vector<unsigned char> serialized_transaction;
        VectorWriter{serialized_transaction, 0, TX_NO_WITNESS(*found_block.vtx[0])};
        std::vector<unsigned char> serialized_header;
        VectorWriter{serialized_header, 0, found_block.GetBlockHeader()};
        const arith_uint256 pow_integer{UintToArith256(found_digest)};
        std::cout << "RESULT: FOUND\n"
                  << "NONCE: " << found_nonce << '\n'
                  << "CANDIDATES EVALUATED: " << checked << '\n'
                  << "GENESIS TRANSACTION: " << HexStr(serialized_transaction) << '\n'
                  << "GENESIS TXID: " << found_block.vtx[0]->GetHash().GetHex() << '\n'
                  << "CANONICAL 80-BYTE HEADER: " << HexStr(serialized_header) << '\n'
                  << "MERKLE ROOT: " << found_block.hashMerkleRoot.GetHex() << '\n'
                  << "POW_DIGEST (raw): "
                  << HexStr(std::vector<unsigned char>(found_digest.begin(), found_digest.end())) << '\n'
                  << "Candidate-A POW_INTEGER: " << pow_integer.GetHex() << '\n'
                  << "TARGET: " << target->GetHex() << '\n'
                  << "SHA256d BLOCK_ID: " << found_block.GetHash().GetHex() << '\n'
                  << "POW_INTEGER <= TARGET: true\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Testnet genesis generator failure: " << error.what() << '\n';
        return 2;
    }
}
