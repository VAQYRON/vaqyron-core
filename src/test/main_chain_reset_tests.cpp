// Copyright (c) 2026-present The VAQYRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chain.h>
#include <chainparams.h>
#include <chainparamsbase.h>
#include <coins.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <deploymentstatus.h>
#include <node/blockstorage.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>
#include <undo.h>
#include <validation.h>
#include <validation_internal.h>
#include <versionbits.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(main_chain_reset_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(vaqyron_main_has_no_inherited_bootstrap_or_trust_data)
{
    const auto main{CChainParams::Main()};
    const Consensus::Params& consensus{main->GetConsensus()};

    BOOST_CHECK(main->DNSSeeds().empty());
    BOOST_CHECK(main->FixedSeeds().empty());
    BOOST_CHECK(consensus.nMinimumChainWork.IsNull());
    BOOST_CHECK(consensus.defaultAssumeValid.IsNull());
    BOOST_CHECK(main->GetAvailableSnapshotHeights().empty());
    BOOST_CHECK(!main->AssumeutxoForHeight(840'000).has_value());
    BOOST_CHECK_EQUAL(main->TxData().nTime, 0);
    BOOST_CHECK_EQUAL(main->TxData().tx_count, 0);
    BOOST_CHECK_EQUAL(main->TxData().dTxRate, 0);
    BOOST_CHECK(consensus.script_flag_exceptions.empty());
    BOOST_CHECK_EQUAL(main->AssumedBlockchainSize(), 0);
    BOOST_CHECK_EQUAL(main->AssumedChainStateSize(), 0);

    BOOST_CHECK_EQUAL(main->MessageStart()[0], 0xdc);
    BOOST_CHECK_EQUAL(main->MessageStart()[1], 0x56);
    BOOST_CHECK_EQUAL(main->MessageStart()[2], 0x27);
    BOOST_CHECK_EQUAL(main->MessageStart()[3], 0x4a);
    BOOST_CHECK_EQUAL(main->GetDefaultPort(), 29733);
    BOOST_CHECK_EQUAL(main->Bech32HRP(), "vqrn");
    BOOST_CHECK_EQUAL(CreateBaseChainParams(ChainType::MAIN)->RPCPort(), 29732);
}

BOOST_AUTO_TEST_CASE(vaqyron_main_activations_follow_candidate_height_policy)
{
    const auto main{CChainParams::Main()};
    const Consensus::Params& consensus{main->GetConsensus()};
    VersionBitsCache cache;

    BOOST_CHECK_EQUAL(consensus.BIP34Height, 1);
    BOOST_CHECK(consensus.BIP34Hash.IsNull());
    BOOST_CHECK_EQUAL(consensus.BIP65Height, 1);
    BOOST_CHECK_EQUAL(consensus.BIP66Height, 1);
    BOOST_CHECK_EQUAL(consensus.CSVHeight, 1);
    BOOST_CHECK_EQUAL(consensus.SegwitHeight, 1);

    const std::array<Consensus::BuriedDeployment, 5> buried_deployments{
        Consensus::DEPLOYMENT_HEIGHTINCB,
        Consensus::DEPLOYMENT_CLTV,
        Consensus::DEPLOYMENT_DERSIG,
        Consensus::DEPLOYMENT_CSV,
        Consensus::DEPLOYMENT_SEGWIT,
    };
    for (const auto deployment : buried_deployments) {
        BOOST_CHECK(!DeploymentActiveAfter(nullptr, consensus, deployment, cache));
        BOOST_CHECK(!DeploymentActiveAt(CBlockIndex{}, consensus, deployment, cache));
    }

    const uint256 genesis_hash{main->GenesisBlock().GetHash()};
    CBlockIndex genesis{main->GenesisBlock()};
    genesis.phashBlock = &genesis_hash;
    genesis.nHeight = 0;
    CBlockIndex block1;
    block1.pprev = &genesis;
    block1.nHeight = 1;
    CBlockIndex block2;
    block2.pprev = &block1;
    block2.nHeight = 2;

    for (const auto deployment : buried_deployments) {
        BOOST_CHECK(DeploymentActiveAfter(&genesis, consensus, deployment, cache));
        BOOST_CHECK(DeploymentActiveAt(block1, consensus, deployment, cache));
        BOOST_CHECK(DeploymentActiveAfter(&block1, consensus, deployment, cache));
        BOOST_CHECK(DeploymentActiveAt(block2, consensus, deployment, cache));
    }

    const auto& taproot{consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT]};
    BOOST_CHECK_EQUAL(taproot.nStartTime, Consensus::BIP9Deployment::ALWAYS_ACTIVE);
    BOOST_CHECK_EQUAL(taproot.nTimeout, Consensus::BIP9Deployment::NO_TIMEOUT);
    BOOST_CHECK_EQUAL(taproot.min_activation_height, 0);
    BOOST_CHECK(DeploymentActiveAfter(nullptr, consensus, Consensus::DEPLOYMENT_TAPROOT, cache));
    BOOST_CHECK(DeploymentActiveAt(genesis, consensus, Consensus::DEPLOYMENT_TAPROOT, cache));
    BOOST_CHECK(DeploymentActiveAfter(&genesis, consensus, Consensus::DEPLOYMENT_TAPROOT, cache));
    BOOST_CHECK(DeploymentActiveAt(block1, consensus, Consensus::DEPLOYMENT_TAPROOT, cache));
    BOOST_CHECK(DeploymentActiveAfter(&block1, consensus, Consensus::DEPLOYMENT_TAPROOT, cache));
    BOOST_CHECK(DeploymentActiveAt(block2, consensus, Consensus::DEPLOYMENT_TAPROOT, cache));

    BOOST_CHECK(consensus.script_flag_exceptions.empty());
    BOOST_CHECK(DeploymentEnabled(consensus, Consensus::DEPLOYMENT_TAPROOT));
    BOOST_CHECK_EQUAL(consensus.MinBIP9WarningHeight, 0);
}

BOOST_AUTO_TEST_CASE(monetary_policy_parameters_are_chain_scoped)
{
    const auto check_monetary_policy = [](const Consensus::Params& consensus, CAmount subsidy, CAmount max_money) {
        BOOST_CHECK_EQUAL(consensus.nInitialSubsidy, subsidy);
        BOOST_CHECK_EQUAL(consensus.nMaxMoney, max_money);
    };

    check_monetary_policy(CChainParams::Main()->GetConsensus(), 12 * COIN, 24000000 * COIN);
    check_monetary_policy(CChainParams::VaqyronTestNet()->GetConsensus(), 12 * COIN, 24000000 * COIN);
    check_monetary_policy(CChainParams::TestNet()->GetConsensus(), 50 * COIN, 21000000 * COIN);
    check_monetary_policy(CChainParams::TestNet4()->GetConsensus(), 50 * COIN, 21000000 * COIN);
    check_monetary_policy(CChainParams::SigNet({})->GetConsensus(), 50 * COIN, 21000000 * COIN);
    check_monetary_policy(CChainParams::RegTest({})->GetConsensus(), 50 * COIN, 21000000 * COIN);
}

BOOST_AUTO_TEST_CASE(bitcoin_bip30_history_exceptions_do_not_apply_to_main)
{
    SelectParams(ChainType::MAIN);

    const std::array<std::pair<int, uint256>, 2> repeated_blocks{{
        {91842, uint256{"00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec"}},
        {91880, uint256{"00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721"}},
    }};
    for (const auto& [height, hash] : repeated_blocks) {
        CBlockIndex index;
        index.nHeight = height;
        index.phashBlock = &hash;
        BOOST_CHECK(!IsBIP30Repeat(index));
    }

    BOOST_CHECK(!IsBIP30Unspendable(
        uint256{"00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e"}, 91722));
    BOOST_CHECK(!IsBIP30Unspendable(
        uint256{"00000000000af0aed4792b1acee3d966af36cf5def14935db8de83d6f9306f2f"}, 91812));

    SelectParams(ChainType::TESTNET);
    for (const auto& [height, hash] : repeated_blocks) {
        CBlockIndex index;
        index.nHeight = height;
        index.phashBlock = &hash;
        BOOST_CHECK(IsBIP30Repeat(index));
    }
    BOOST_CHECK(IsBIP30Unspendable(
        uint256{"00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e"}, 91722));
}

BOOST_AUTO_TEST_CASE(bitcoin_bip30_history_exceptions_do_not_apply_to_vaqyron_testnet)
{
    SelectParams(ChainType::VAQYRON_TESTNET);

    const std::array<std::pair<int, uint256>, 2> repeated_blocks{{
        {91842, uint256{"00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec"}},
        {91880, uint256{"00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721"}},
    }};
    for (const auto& [height, hash] : repeated_blocks) {
        CBlockIndex index;
        index.nHeight = height;
        index.phashBlock = &hash;
        BOOST_CHECK(!IsBIP30Repeat(index));
    }

    BOOST_CHECK(!IsBIP30Unspendable(
        uint256{"00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e"}, 91722));
    BOOST_CHECK(!IsBIP30Unspendable(
        uint256{"00000000000af0aed4792b1acee3d966af36cf5def14935db8de83d6f9306f2f"}, 91812));
}

// Decision-only coverage; this does not exercise DisconnectBlock rollback.
BOOST_AUTO_TEST_CASE(disconnect_bip30_exception_policy_is_chain_scoped)
{
    const std::array<std::pair<int, uint256>, 2> historical_blocks{{
        {91722, uint256{"00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e"}},
        {91812, uint256{"00000000000af0aed4792b1acee3d966af36cf5def14935db8de83d6f9306f2f"}},
    }};
    const std::array<ChainType, 2> vaqyron_chains{
        ChainType::MAIN,
        ChainType::VAQYRON_TESTNET,
    };
    const std::array<ChainType, 4> bitcoin_chains{
        ChainType::TESTNET,
        ChainType::TESTNET4,
        ChainType::SIGNET,
        ChainType::REGTEST,
    };

    for (const auto& [height, hash] : historical_blocks) {
        for (const ChainType chain_type : vaqyron_chains) {
            BOOST_CHECK(validation_internal::ShouldEnforceBIP30OnDisconnect(chain_type, height, hash));
        }
        for (const ChainType chain_type : bitcoin_chains) {
            BOOST_CHECK(!validation_internal::ShouldEnforceBIP30OnDisconnect(chain_type, height, hash));
        }
    }

    for (const ChainType chain_type : {ChainType::MAIN, ChainType::VAQYRON_TESTNET,
                                       ChainType::TESTNET, ChainType::TESTNET4,
                                       ChainType::SIGNET, ChainType::REGTEST}) {
        BOOST_CHECK(validation_internal::ShouldEnforceBIP30OnDisconnect(chain_type, 91723, uint256{}));
    }
}

BOOST_AUTO_TEST_CASE(non_main_chain_parameters_remain_legacy)
{
    const auto testnet{CChainParams::TestNet()};
    BOOST_CHECK_EQUAL(testnet->GetDefaultPort(), 18333);
    BOOST_CHECK_EQUAL(testnet->GetConsensus().BIP34Height, 21111);
    BOOST_CHECK_EQUAL(testnet->GetConsensus().BIP65Height, 581885);
    BOOST_CHECK(!testnet->DNSSeeds().empty());
    BOOST_CHECK(!testnet->FixedSeeds().empty());
    BOOST_CHECK(!testnet->GetConsensus().nMinimumChainWork.IsNull());
    BOOST_CHECK_EQUAL(testnet->Bech32HRP(), "tb");

    const auto testnet4{CChainParams::TestNet4()};
    BOOST_CHECK_EQUAL(testnet4->GetDefaultPort(), 48333);
    BOOST_CHECK_EQUAL(testnet4->GetConsensus().BIP34Height, 1);
    BOOST_CHECK_EQUAL(testnet4->GetConsensus().nPowTargetSpacing, 600);
    BOOST_CHECK(!testnet4->DNSSeeds().empty());
    BOOST_CHECK(!testnet4->FixedSeeds().empty());
    BOOST_CHECK_EQUAL(testnet4->Bech32HRP(), "tb");

    const auto signet{CChainParams::SigNet({})};
    BOOST_CHECK_EQUAL(signet->GetDefaultPort(), 38333);
    BOOST_CHECK_EQUAL(signet->GetConsensus().BIP34Height, 1);
    BOOST_CHECK(!signet->DNSSeeds().empty());
    BOOST_CHECK(!signet->FixedSeeds().empty());
    BOOST_CHECK(!signet->GetConsensus().nMinimumChainWork.IsNull());
    BOOST_CHECK_EQUAL(signet->Bech32HRP(), "tb");

    const auto regtest{CChainParams::RegTest({})};
    BOOST_CHECK_EQUAL(regtest->GetDefaultPort(), 18444);
    BOOST_CHECK_EQUAL(regtest->GetConsensus().BIP34Height, 1);
    BOOST_CHECK_EQUAL(regtest->GetConsensus().SegwitHeight, 0);
    BOOST_CHECK_EQUAL(regtest->GetConsensus().nPowTargetSpacing, 600);
    BOOST_CHECK_EQUAL(regtest->DNSSeeds().size(), 1);
    BOOST_CHECK(regtest->FixedSeeds().empty());
    BOOST_CHECK(regtest->GetConsensus().nMinimumChainWork.IsNull());
    BOOST_CHECK_EQUAL(regtest->Bech32HRP(), "bcrt");
}

BOOST_AUTO_TEST_SUITE_END()

struct MainBIP30TestingSetup : TestingSetup {
    MainBIP30TestingSetup() :
        TestingSetup{ChainType::MAIN, TestOpts{.setup_net = false}}
    {
    }
};

struct SyntheticDisconnectBlock
{
    CBlock block;
    CBlockIndex* previous;
    CBlockIndex* child;
    COutPoint spent_outpoint;
    COutPoint coinbase_outpoint;
    COutPoint spend_outpoint;
    uint256 child_hash;
};

static SyntheticDisconnectBlock MakeSyntheticDisconnectBlock(
    MainBIP30TestingSetup& setup,
    CCoinsViewCache& view,
    bool omit_spend_output,
    bool corrupt_undo_context)
{
    ChainstateManager& chainman{*Assert(setup.m_node.chainman)};
    Chainstate& chainstate{chainman.ActiveChainstate()};
    node::BlockManager& blockman{chainman.m_blockman};

    CBlockIndex* previous;
    CBlockIndex* child;
    CBlockIndex* alternate_previous{nullptr};
    {
        LOCK(cs_main);
        CBlockIndex* genesis{chainman.ActiveChain().Tip()};
        BOOST_REQUIRE(genesis);
        BOOST_REQUIRE_EQUAL(genesis->nHeight, 0);

        previous = blockman.InsertBlockIndex(uint256{0x51});
        BOOST_REQUIRE(previous);
        previous->pprev = genesis;
        previous->nHeight = 1;
        previous->nTime = genesis->GetBlockTime() + 1;
        previous->nBits = genesis->nBits;

        if (corrupt_undo_context) {
            alternate_previous = blockman.InsertBlockIndex(uint256{0x52});
            BOOST_REQUIRE(alternate_previous);
            alternate_previous->pprev = genesis;
            alternate_previous->nHeight = 1;
        }
    }

    const COutPoint spent_outpoint{Txid::FromUint256(uint256{0x53}), 0};
    CMutableTransaction coinbase;
    coinbase.vin.emplace_back();
    coinbase.vin[0].scriptSig = CScript{} << 1 << OP_0;
    coinbase.vout.emplace_back(3 * COIN, CScript{} << OP_TRUE);

    CMutableTransaction spend;
    spend.vin.emplace_back(spent_outpoint, CScript{} << OP_TRUE);
    spend.vout.emplace_back(2 * COIN, CScript{} << OP_TRUE);

    CBlock block;
    block.nVersion = 1;
    block.hashPrevBlock = previous->GetBlockHash();
    block.nTime = previous->GetBlockTime() + 1;
    block.nBits = previous->nBits;
    block.vtx = {MakeTransactionRef(coinbase), MakeTransactionRef(spend)};
    block.hashMerkleRoot = BlockMerkleRoot(block);

    const uint256 child_hash{block.GetHash()};
    const FlatFilePos block_pos{blockman.WriteBlock(block, /*nHeight=*/2)};
    BOOST_REQUIRE(!block_pos.IsNull());

    CBlockUndo undo;
    undo.vtxundo.emplace_back();
    undo.vtxundo.back().vprevout.emplace_back(
        Coin{CTxOut{1 * COIN, CScript{} << OP_TRUE}, /*nHeight=*/1, /*fCoinBase=*/false});

    {
        LOCK(cs_main);
        child = blockman.InsertBlockIndex(child_hash);
        BOOST_REQUIRE(child);
        child->pprev = previous;
        child->nHeight = 2;
        child->nFile = block_pos.nFile;
        child->nDataPos = block_pos.nPos;
        child->nStatus |= BLOCK_HAVE_DATA;
        child->nVersion = block.nVersion;
        child->hashMerkleRoot = block.hashMerkleRoot;
        child->nTime = block.nTime;
        child->nBits = block.nBits;
        child->nNonce = block.nNonce;

        BlockValidationState state;
        BOOST_REQUIRE(blockman.WriteBlockUndo(undo, state, *child));
        BOOST_REQUIRE(child->nStatus & BLOCK_HAVE_UNDO);

        CBlockUndo read_undo;
        BOOST_REQUIRE(blockman.ReadBlockUndo(read_undo, *child));
        BOOST_REQUIRE_EQUAL(read_undo.vtxundo.size(), 1);
        BOOST_REQUIRE_EQUAL(read_undo.vtxundo[0].vprevout.size(), 1);

        if (corrupt_undo_context) {
            child->pprev = alternate_previous;
        }
    }

    const COutPoint coinbase_outpoint{block.vtx[0]->GetHash(), 0};
    const COutPoint spend_outpoint{block.vtx[1]->GetHash(), 0};
    view.SetBestBlock(child_hash);
    view.AddCoin(coinbase_outpoint, Coin{block.vtx[0]->vout[0], 2, true}, /*possible_overwrite=*/false);
    if (!omit_spend_output) {
        view.AddCoin(spend_outpoint, Coin{block.vtx[1]->vout[0], 2, false}, /*possible_overwrite=*/false);
    }

    return {std::move(block), previous, child, spent_outpoint, coinbase_outpoint, spend_outpoint, child_hash};
}

BOOST_FIXTURE_TEST_SUITE(main_bip30_disconnect_tests, MainBIP30TestingSetup)

BOOST_AUTO_TEST_CASE(main_disconnect_block_restores_utxo_from_disk_undo)
{
    Chainstate& chainstate{m_node.chainman->ActiveChainstate()};
    CCoinsViewCache view{&chainstate.CoinsTip()};
    const SyntheticDisconnectBlock fixture{MakeSyntheticDisconnectBlock(
        *this, view, /*omit_spend_output=*/false, /*corrupt_undo_context=*/false)};

    BOOST_REQUIRE(view.HaveCoin(fixture.coinbase_outpoint));
    BOOST_REQUIRE(view.HaveCoin(fixture.spend_outpoint));
    BOOST_CHECK(!view.HaveCoin(fixture.spent_outpoint));

    DisconnectResult result;
    {
        LOCK(cs_main);
        result = chainstate.DisconnectBlock(fixture.block, fixture.child, view);
    }

    BOOST_CHECK(result == DISCONNECT_OK);
    BOOST_CHECK(!view.HaveCoin(fixture.coinbase_outpoint));
    BOOST_CHECK(!view.HaveCoin(fixture.spend_outpoint));
    BOOST_REQUIRE(view.HaveCoin(fixture.spent_outpoint));
    const Coin& restored{view.AccessCoin(fixture.spent_outpoint)};
    BOOST_CHECK_EQUAL(restored.out.nValue, 1 * COIN);
    BOOST_CHECK(restored.out.scriptPubKey == (CScript{} << OP_TRUE));
    BOOST_CHECK_EQUAL(restored.nHeight, 1);
    BOOST_CHECK(!restored.fCoinBase);
    BOOST_CHECK_EQUAL(view.GetBestBlock(), fixture.previous->GetBlockHash());
}

BOOST_AUTO_TEST_CASE(main_disconnect_block_reports_unclean_missing_output)
{
    Chainstate& chainstate{m_node.chainman->ActiveChainstate()};
    CCoinsViewCache view{&chainstate.CoinsTip()};
    const SyntheticDisconnectBlock fixture{MakeSyntheticDisconnectBlock(
        *this, view, /*omit_spend_output=*/true, /*corrupt_undo_context=*/false)};

    BOOST_REQUIRE(view.HaveCoin(fixture.coinbase_outpoint));
    BOOST_CHECK(!view.HaveCoin(fixture.spend_outpoint));

    DisconnectResult result;
    {
        LOCK(cs_main);
        result = chainstate.DisconnectBlock(fixture.block, fixture.child, view);
    }

    BOOST_CHECK(result == DISCONNECT_UNCLEAN);
    BOOST_CHECK(!view.HaveCoin(fixture.coinbase_outpoint));
    BOOST_CHECK(!view.HaveCoin(fixture.spend_outpoint));
    BOOST_REQUIRE(view.HaveCoin(fixture.spent_outpoint));
    const Coin& restored{view.AccessCoin(fixture.spent_outpoint)};
    BOOST_CHECK_EQUAL(restored.out.nValue, 1 * COIN);
    BOOST_CHECK_EQUAL(restored.nHeight, 1);
    BOOST_CHECK(!restored.fCoinBase);
    BOOST_CHECK_EQUAL(view.GetBestBlock(), fixture.previous->GetBlockHash());
}

BOOST_AUTO_TEST_CASE(main_disconnect_block_rejects_wrong_undo_checksum_context)
{
    Chainstate& chainstate{m_node.chainman->ActiveChainstate()};
    CCoinsViewCache view{&chainstate.CoinsTip()};
    const SyntheticDisconnectBlock fixture{MakeSyntheticDisconnectBlock(
        *this, view, /*omit_spend_output=*/false, /*corrupt_undo_context=*/true)};

    BOOST_REQUIRE(view.HaveCoin(fixture.coinbase_outpoint));
    BOOST_REQUIRE(view.HaveCoin(fixture.spend_outpoint));
    BOOST_CHECK(!view.HaveCoin(fixture.spent_outpoint));
    BOOST_CHECK_EQUAL(view.GetBestBlock(), fixture.child_hash);

    DisconnectResult result;
    {
        LOCK(cs_main);
        result = chainstate.DisconnectBlock(fixture.block, fixture.child, view);
    }

    BOOST_CHECK(result == DISCONNECT_FAILED);
    BOOST_CHECK(view.HaveCoin(fixture.coinbase_outpoint));
    BOOST_CHECK(view.HaveCoin(fixture.spend_outpoint));
    BOOST_CHECK(!view.HaveCoin(fixture.spent_outpoint));
    BOOST_CHECK_EQUAL(view.GetBestBlock(), fixture.child_hash);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(main_bip30_connectblock_tests, MainBIP30TestingSetup)

BOOST_AUTO_TEST_CASE(main_connectblock_rejects_duplicate_unspent_txid)
{
    const CChainParams& params{m_node.chainman->GetParams()};
    BOOST_REQUIRE(params.GetChainType() == ChainType::MAIN);

    const std::array<std::pair<int, uint256>, 2> repeated_blocks{{
        {91842, uint256{"00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec"}},
        {91880, uint256{"00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721"}},
    }};
    for (const auto& [height, hash] : repeated_blocks) {
        CBlockIndex index;
        index.nHeight = height;
        index.phashBlock = &hash;
        BOOST_CHECK(!IsBIP30Repeat(index));
    }

    const uint256 first_historical_unspendable_hash{
        "00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e"};
    const uint256 second_historical_unspendable_hash{
        "00000000000af0aed4792b1acee3d966af36cf5def14935db8de83d6f9306f2f"};
    BOOST_CHECK(!IsBIP30Unspendable(first_historical_unspendable_hash, 91722));
    BOOST_CHECK(!IsBIP30Unspendable(second_historical_unspendable_hash, 91812));

    Chainstate& chainstate{m_node.chainman->ActiveChainstate()};
    CBlockIndex* previous{m_node.chainman->ActiveChain().Tip()};
    BOOST_REQUIRE(previous);
    BOOST_REQUIRE_EQUAL(previous->nHeight, 0);

    CMutableTransaction coinbase;
    coinbase.vin.emplace_back();
    coinbase.vin[0].scriptSig = CScript{} << 1 << OP_0;
    coinbase.vout.emplace_back(0, CScript{} << OP_TRUE);

    CMutableTransaction duplicate;
    duplicate.vin.emplace_back(COutPoint{Txid::FromUint256(uint256{1}), 0}, CScript{} << OP_TRUE);
    duplicate.vout.emplace_back(0, CScript{} << OP_TRUE);
    const CTransactionRef duplicate_tx{MakeTransactionRef(duplicate)};
    const COutPoint existing_outpoint{duplicate_tx->GetHash(), 0};

    CBlock block;
    block.nVersion = 1;
    block.hashPrevBlock = previous->GetBlockHash();
    block.hashMerkleRoot = uint256{};
    block.nTime = previous->GetBlockTime() + 1;
    block.nBits = previous->nBits;
    block.vtx = {MakeTransactionRef(coinbase), duplicate_tx};
    block.hashMerkleRoot = BlockMerkleRoot(block);

    const uint256 block_hash{block.GetHash()};
    CBlockIndex block_index{block};
    block_index.pprev = previous;
    block_index.nHeight = previous->nHeight + 1;
    block_index.phashBlock = &block_hash;

    CCoinsViewCache view{&chainstate.CoinsTip()};
    view.SetBestBlock(previous->GetBlockHash());
    view.AddCoin(existing_outpoint, Coin{CTxOut{1, CScript{} << OP_TRUE}, 0, false}, false);
    BOOST_REQUIRE(view.HaveCoin(existing_outpoint));

    BlockValidationState state;
    bool connected;
    {
        LOCK(cs_main);
        connected = chainstate.ConnectBlock(block, state, &block_index, view, /*fJustCheck=*/true);
    }

    BOOST_CHECK(!connected);
    BOOST_CHECK(state.IsInvalid());
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-BIP30");
    BOOST_CHECK_EQUAL(state.GetDebugMessage(), "tried to overwrite transaction");
}

BOOST_AUTO_TEST_CASE(main_connectblock_disconnect_roundtrip_writes_and_reads_undo)
{
    ChainstateManager& chainman{*Assert(m_node.chainman)};
    Chainstate& chainstate{chainman.ActiveChainstate()};
    node::BlockManager& blockman{chainman.m_blockman};

    CBlockIndex* previous;
    {
        LOCK(cs_main);
        CBlockIndex* genesis{chainman.ActiveChain().Tip()};
        BOOST_REQUIRE(genesis);
        BOOST_REQUIRE_EQUAL(genesis->nHeight, 0);
        previous = blockman.InsertBlockIndex(uint256{0x62});
        BOOST_REQUIRE(previous);
        previous->pprev = genesis;
        previous->nHeight = 1;
        previous->nTime = genesis->GetBlockTime() + 1;
        previous->nBits = genesis->nBits;
    }

    const COutPoint spent_outpoint{Txid::FromUint256(uint256{0x61}), 0};
    const Coin original_coin{CTxOut{1 * COIN, CScript{} << OP_TRUE}, 1, false};

    CMutableTransaction coinbase;
    coinbase.vin.emplace_back();
    coinbase.vin[0].scriptSig = CScript{} << 2 << OP_0;
    coinbase.vout.emplace_back(3 * COIN, CScript{} << OP_TRUE);

    CMutableTransaction spend;
    spend.vin.emplace_back(spent_outpoint, CScript{} << OP_TRUE);
    spend.vout.emplace_back(1 * COIN, CScript{} << OP_TRUE);

    CBlock block;
    block.nVersion = 1;
    block.hashPrevBlock = previous->GetBlockHash();
    block.nTime = previous->GetBlockTime() + 1;
    block.nBits = previous->nBits;
    block.vtx = {MakeTransactionRef(coinbase), MakeTransactionRef(spend)};
    block.hashMerkleRoot = BlockMerkleRoot(block);

    const uint256 block_hash{block.GetHash()};
    const COutPoint coinbase_outpoint{block.vtx[0]->GetHash(), 0};
    const COutPoint spend_outpoint{block.vtx[1]->GetHash(), 0};
    const FlatFilePos block_pos{blockman.WriteBlock(block, /*nHeight=*/2)};
    BOOST_REQUIRE(!block_pos.IsNull());

    CBlockIndex* child;
    {
        LOCK(cs_main);
        child = blockman.InsertBlockIndex(block_hash);
        BOOST_REQUIRE(child);
        child->pprev = previous;
        child->nHeight = 2;
        child->nFile = block_pos.nFile;
        child->nDataPos = block_pos.nPos;
        child->nStatus |= BLOCK_HAVE_DATA;
        child->nVersion = block.nVersion;
        child->hashMerkleRoot = block.hashMerkleRoot;
        child->nTime = block.nTime;
        child->nBits = block.nBits;
        child->nNonce = block.nNonce;
    }

    CCoinsViewCache view{&chainstate.CoinsTip()};
    view.SetBestBlock(previous->GetBlockHash());
    view.AddCoin(spent_outpoint, Coin{original_coin}, /*possible_overwrite=*/false);
    BOOST_REQUIRE(view.HaveCoin(spent_outpoint));
    BOOST_CHECK_EQUAL(view.AccessCoin(spent_outpoint).out.nValue, original_coin.out.nValue);
    BOOST_CHECK(view.AccessCoin(spent_outpoint).out.scriptPubKey == original_coin.out.scriptPubKey);
    BOOST_CHECK_EQUAL(view.AccessCoin(spent_outpoint).nHeight, original_coin.nHeight);
    BOOST_CHECK_EQUAL(view.AccessCoin(spent_outpoint).fCoinBase, original_coin.fCoinBase);
    BOOST_CHECK(!view.HaveCoin(coinbase_outpoint));
    BOOST_CHECK(!view.HaveCoin(spend_outpoint));

    BlockValidationState state;
    bool connected;
    {
        LOCK(cs_main);
        connected = chainstate.ConnectBlock(block, state, child, view, /*fJustCheck=*/false);
    }
    BOOST_REQUIRE_MESSAGE(connected, state.ToString());
    BOOST_CHECK(state.IsValid());
    BOOST_CHECK_EQUAL(view.GetBestBlock(), block_hash);
    BOOST_CHECK(!view.HaveCoin(spent_outpoint));

    BOOST_REQUIRE(view.HaveCoin(coinbase_outpoint));
    BOOST_REQUIRE(view.HaveCoin(spend_outpoint));
    BOOST_CHECK_EQUAL(view.AccessCoin(coinbase_outpoint).out.nValue, 3 * COIN);
    BOOST_CHECK(view.AccessCoin(coinbase_outpoint).fCoinBase);
    BOOST_CHECK_EQUAL(view.AccessCoin(spend_outpoint).out.nValue, 1 * COIN);
    BOOST_CHECK(!view.AccessCoin(spend_outpoint).fCoinBase);

    CBlockUndo generated_undo;
    BOOST_REQUIRE(blockman.ReadBlockUndo(generated_undo, *child));
    BOOST_REQUIRE_EQUAL(generated_undo.vtxundo.size(), 1);
    BOOST_REQUIRE_EQUAL(generated_undo.vtxundo[0].vprevout.size(), 1);
    const Coin& undo_coin{generated_undo.vtxundo[0].vprevout[0]};
    BOOST_CHECK_EQUAL(undo_coin.out.nValue, original_coin.out.nValue);
    BOOST_CHECK(undo_coin.out.scriptPubKey == original_coin.out.scriptPubKey);
    BOOST_CHECK_EQUAL(undo_coin.nHeight, original_coin.nHeight);
    BOOST_CHECK_EQUAL(undo_coin.fCoinBase, original_coin.fCoinBase);

    DisconnectResult result;
    {
        LOCK(cs_main);
        result = chainstate.DisconnectBlock(block, child, view);
    }

    BOOST_REQUIRE(result == DISCONNECT_OK);
    BOOST_CHECK(view.HaveCoin(spent_outpoint));
    const Coin& restored_coin{view.AccessCoin(spent_outpoint)};
    BOOST_CHECK_EQUAL(restored_coin.out.nValue, original_coin.out.nValue);
    BOOST_CHECK(restored_coin.out.scriptPubKey == original_coin.out.scriptPubKey);
    BOOST_CHECK_EQUAL(restored_coin.nHeight, original_coin.nHeight);
    BOOST_CHECK_EQUAL(restored_coin.fCoinBase, original_coin.fCoinBase);
    BOOST_CHECK(!view.HaveCoin(coinbase_outpoint));
    BOOST_CHECK(!view.HaveCoin(spend_outpoint));
    BOOST_CHECK_EQUAL(view.GetBestBlock(), previous->GetBlockHash());
}

BOOST_AUTO_TEST_SUITE_END()
