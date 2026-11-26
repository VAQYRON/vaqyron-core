// Copyright (c) 2026-present The VAQYRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <consensus/merkle.h>
#include <chain.h>
#include <chainparams.h>
#include <kernel/genesis.h>
#include <node/miner.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>
#include <util/time.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(genesis_tests, BasicTestingSetup)

namespace {

struct MockTimeReset {
    ~MockTimeReset() { SetMockTime(0); }
};

std::vector<std::byte> SerializeTransaction(const CTransaction& tx)
{
    DataStream stream{};
    stream << TX_NO_WITNESS(tx);
    return {stream.begin(), stream.end()};
}

std::vector<std::byte> SerializeHeader(const CBlockHeader& header)
{
    DataStream stream{};
    stream << header;
    return {stream.begin(), stream.end()};
}

} // namespace

BOOST_AUTO_TEST_CASE(vaqyron_genesis_transaction_is_frozen_and_unspendable)
{
    const CTransactionRef tx{kernel::CreateVaqyronGenesisTransaction()};

    BOOST_CHECK_EQUAL(tx->version, 1U);
    BOOST_CHECK_EQUAL(tx->nLockTime, 0U);
    BOOST_REQUIRE_EQUAL(tx->vin.size(), 1U);
    BOOST_CHECK(tx->vin[0].prevout.IsNull());
    BOOST_CHECK_EQUAL(tx->vin[0].nSequence, 0xffffffffU);
    BOOST_CHECK(tx->vin[0].scriptWitness.IsNull());
    BOOST_CHECK_EQUAL(
        HexStr(tx->vin[0].scriptSig),
        "3256415159524f4e202d20496e646570656e64656e742050726f6f662d6f662d576f726b204e6574776f726b202d2032303236");

    BOOST_REQUIRE_EQUAL(tx->vout.size(), 1U);
    BOOST_CHECK_EQUAL(tx->vout[0].nValue, 0);
    BOOST_CHECK(tx->vout[0].scriptPubKey.IsUnspendable());
    BOOST_CHECK_EQUAL(HexStr(tx->vout[0].scriptPubKey),
                      "6a1956415159524f4e2067656e65736973206d61726b6572207631");
}

BOOST_AUTO_TEST_CASE(vaqyron_genesis_block_construction_is_deterministic)
{
    constexpr uint32_t time{1'760'000'000};
    constexpr uint32_t nonce{0x12345678};
    constexpr uint32_t bits{0x1d00ffff};
    constexpr int32_t version{1};

    const CBlock first{kernel::CreateVaqyronGenesisBlock(time, nonce, bits, version)};
    const CBlock repeated{kernel::CreateVaqyronGenesisBlock(time, nonce, bits, version)};

    BOOST_REQUIRE_EQUAL(first.vtx.size(), 1U);
    BOOST_REQUIRE_EQUAL(repeated.vtx.size(), 1U);
    BOOST_CHECK(SerializeTransaction(*first.vtx[0]) == SerializeTransaction(*repeated.vtx[0]));
    BOOST_CHECK_EQUAL(first.vtx[0]->GetHash(), repeated.vtx[0]->GetHash());
    BOOST_CHECK_EQUAL(first.hashMerkleRoot, repeated.hashMerkleRoot);
    BOOST_CHECK_EQUAL(first.hashMerkleRoot, BlockMerkleRoot(first));
    BOOST_CHECK(SerializeHeader(first.GetBlockHeader()) == SerializeHeader(repeated.GetBlockHeader()));
    BOOST_CHECK_EQUAL(first.GetHash(), repeated.GetHash());

    BOOST_CHECK_EQUAL(first.nTime, time);
    BOOST_CHECK_EQUAL(first.nNonce, nonce);
    BOOST_CHECK_EQUAL(first.nBits, bits);
    BOOST_CHECK_EQUAL(first.nVersion, version);
    BOOST_CHECK(first.hashPrevBlock.IsNull());
}

BOOST_AUTO_TEST_CASE(vaqyron_genesis_header_changes_do_not_change_transaction_or_merkle_root)
{
    const CBlock original{kernel::CreateVaqyronGenesisBlock(1000, 7, 0x1d00ffff, 1)};
    const CBlock changed_nonce{kernel::CreateVaqyronGenesisBlock(1000, 8, 0x1d00ffff, 1)};
    const CBlock changed_time{kernel::CreateVaqyronGenesisBlock(1001, 7, 0x1d00ffff, 1)};

    BOOST_CHECK(SerializeTransaction(*original.vtx[0]) == SerializeTransaction(*changed_nonce.vtx[0]));
    BOOST_CHECK(SerializeTransaction(*original.vtx[0]) == SerializeTransaction(*changed_time.vtx[0]));
    BOOST_CHECK_EQUAL(original.vtx[0]->GetHash(), changed_nonce.vtx[0]->GetHash());
    BOOST_CHECK_EQUAL(original.vtx[0]->GetHash(), changed_time.vtx[0]->GetHash());
    BOOST_CHECK_EQUAL(original.hashMerkleRoot, changed_nonce.hashMerkleRoot);
    BOOST_CHECK_EQUAL(original.hashMerkleRoot, changed_time.hashMerkleRoot);

    BOOST_CHECK(SerializeHeader(original.GetBlockHeader()) != SerializeHeader(changed_nonce.GetBlockHeader()));
    BOOST_CHECK(SerializeHeader(original.GetBlockHeader()) != SerializeHeader(changed_time.GetBlockHeader()));
    BOOST_CHECK(original.GetHash() != changed_nonce.GetHash());
    BOOST_CHECK(original.GetHash() != changed_time.GetHash());
}

BOOST_AUTO_TEST_CASE(vaqyron_mainnet_genesis_matches_verified_candidate_and_remains_pending)
{
    const auto params{CChainParams::Main()};
    const CBlock& genesis{params->GenesisBlock()};

    BOOST_CHECK_EQUAL(params->GetChainTypeString(), "main");
    BOOST_CHECK(params->IsVaqyronMainGenesisPending());
    BOOST_REQUIRE_EQUAL(genesis.vtx.size(), 1U);
    BOOST_CHECK_EQUAL(genesis.nVersion, 1);
    BOOST_CHECK(genesis.hashPrevBlock.IsNull());
    BOOST_CHECK_EQUAL(genesis.nTime, 1791363600U);
    BOOST_CHECK_EQUAL(genesis.nBits, 0x1d00ffffU);
    BOOST_CHECK_EQUAL(genesis.nNonce, 2110375208U);
    BOOST_REQUIRE_EQUAL(genesis.vtx[0]->vin.size(), 1U);
    BOOST_CHECK(genesis.vtx[0]->vin[0].prevout.IsNull());
    BOOST_REQUIRE_EQUAL(genesis.vtx[0]->vout.size(), 1U);
    BOOST_CHECK_EQUAL(genesis.vtx[0]->vout[0].nValue, 0);
    BOOST_CHECK(genesis.vtx[0]->vout[0].scriptPubKey.IsUnspendable());
    BOOST_CHECK_EQUAL(
        genesis.hashMerkleRoot,
        uint256{"401fa2348ee8a6a333e8e40f0b402c14da6887c244f1c1138fd818d581b9736e"});
    BOOST_CHECK_EQUAL(
        genesis.GetHash(),
        uint256{"6632757c19c74eadb7605077994de2de96625cc6abab68f94f303e55fa3fe4e4"});
    BOOST_CHECK_EQUAL(params->GetConsensus().hashGenesisBlock, genesis.GetHash());
    BOOST_CHECK_EQUAL(genesis.hashMerkleRoot, BlockMerkleRoot(genesis));
    BOOST_CHECK(CheckProofOfWork(genesis, params->GetConsensus()));
}

BOOST_AUTO_TEST_CASE(vaqyron_testnet_genesis_matches_verified_candidate)
{
    const auto params{CChainParams::VaqyronTestNet()};
    const CBlock& genesis{params->GenesisBlock()};

    BOOST_CHECK_EQUAL(params->GetChainTypeString(), "vaqyron-testnet");
    BOOST_CHECK(!params->IsVaqyronTestnetGenesisPending());
    BOOST_REQUIRE_EQUAL(genesis.vtx.size(), 1U);
    BOOST_CHECK_EQUAL(genesis.nVersion, 1);
    BOOST_CHECK(genesis.hashPrevBlock.IsNull());
    BOOST_CHECK_EQUAL(genesis.nTime, 1791460800U);
    BOOST_CHECK_EQUAL(genesis.nBits, 0x207fffffU);
    BOOST_CHECK_EQUAL(genesis.nNonce, 0U);

    DataStream transaction_stream{};
    transaction_stream << TX_NO_WITNESS(*genesis.vtx[0]);
    BOOST_CHECK_EQUAL(
        HexStr(transaction_stream),
        "01000000010000000000000000000000000000000000000000000000000000000000000000"
        "ffffffff414056415159524f4e20544553544e4554202d20496e646570656e64656e742050"
        "726f6f662d6f662d576f726b204e6574776f726b202d20323032362d31302d3038ffffffff"
        "010000000000000000236a2156415159524f4e20544553544e45542067656e65736973206d"
        "61726b657220763100000000");

    BOOST_CHECK_EQUAL(
        genesis.hashMerkleRoot,
        uint256{"e7193ffd84a3492d43c7d591d9a9fabe45bc82da68d6767be4a43413d87ed048"});
    BOOST_CHECK_EQUAL(genesis.hashMerkleRoot, BlockMerkleRoot(genesis));

    DataStream header_stream{};
    header_stream << genesis.GetBlockHeader();
    BOOST_CHECK_EQUAL(
        HexStr(header_stream),
        "010000000000000000000000000000000000000000000000000000000000000000000000"
        "48d07ed81334a4e47b76d668da82bc45befaa9d991d5c7432d49a384fd3f19e7c085c76a"
        "ffff7f2000000000");
    BOOST_CHECK_EQUAL(
        genesis.GetHash(),
        uint256{"e4bccdb17adaa76a26e23f67f21062674d30f4476493dfb5f8cf297dc523ef97"});
    BOOST_CHECK_EQUAL(params->GetConsensus().hashGenesisBlock, genesis.GetHash());
    BOOST_CHECK(CheckProofOfWork(genesis, params->GetConsensus()));
}

BOOST_AUTO_TEST_CASE(vaqyron_testnet_first_child_header_uses_genesis_tip)
{
    const auto params{CChainParams::VaqyronTestNet()};
    const CBlock& genesis{params->GenesisBlock()};
    const auto& consensus{params->GetConsensus()};
    const CBlockIndex genesis_index{genesis.GetBlockHeader()};
    CBlockHeader child;
    child.hashPrevBlock = genesis.GetHash();
    child.nTime = genesis.nTime;
    MockTimeReset reset_mock_time;

    SetMockTime(genesis.nTime + consensus.nPowTargetSpacing);
    node::UpdateTime(&child, consensus, &genesis_index);

    BOOST_CHECK_EQUAL(child.hashPrevBlock, genesis.GetHash());
    BOOST_CHECK_EQUAL(genesis_index.nHeight + 1, 1);
    BOOST_CHECK_EQUAL(child.nTime, genesis.nTime + consensus.nPowTargetSpacing);
    BOOST_CHECK_GT(child.nTime, genesis_index.GetMedianTimePast());
    BOOST_CHECK_EQUAL(child.nBits, genesis.nBits);
    BOOST_CHECK_EQUAL(GetNextWorkRequired(&genesis_index, &child, consensus), genesis.nBits);
}

BOOST_AUTO_TEST_SUITE_END()
