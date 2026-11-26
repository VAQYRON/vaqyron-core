// Copyright (c) 2014-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/tx_verify.h>
#include <core_io.h>
#include <hash.h>
#include <net.h>
#include <primitives/transaction.h>
#include <signet.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <validation.h>
#include <validation_internal.h>

#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(validation_tests, TestingSetup)

static void TestBlockSubsidyHalvings(const Consensus::Params& consensusParams)
{
    int maxHalvings = 64;
    CAmount nInitialSubsidy = consensusParams.nInitialSubsidy;

    CAmount nPreviousSubsidy = nInitialSubsidy * 2; // for height == 0
    BOOST_CHECK_EQUAL(nPreviousSubsidy, nInitialSubsidy * 2);
    for (int nHalvings = 0; nHalvings < maxHalvings; nHalvings++) {
        int nHeight = nHalvings * consensusParams.nSubsidyHalvingInterval;
        CAmount nSubsidy = GetBlockSubsidy(nHeight, consensusParams);
        BOOST_CHECK(nSubsidy <= nInitialSubsidy);
        BOOST_CHECK_EQUAL(nSubsidy, nPreviousSubsidy / 2);
        nPreviousSubsidy = nSubsidy;
    }
    BOOST_CHECK_EQUAL(GetBlockSubsidy(maxHalvings * consensusParams.nSubsidyHalvingInterval, consensusParams), 0);
}

static void TestBlockSubsidyHalvings(int nSubsidyHalvingInterval, CAmount nInitialSubsidy)
{
    Consensus::Params consensusParams;
    consensusParams.nSubsidyHalvingInterval = nSubsidyHalvingInterval;
    consensusParams.nInitialSubsidy = nInitialSubsidy;
    TestBlockSubsidyHalvings(consensusParams);
}

static void TestBlockSubsidyFirstHalvingBoundaries(const Consensus::Params& consensusParams)
{
    const int halving_height{consensusParams.nSubsidyHalvingInterval};
    const CAmount initial_subsidy{consensusParams.nInitialSubsidy};
    const CAmount halved_subsidy{initial_subsidy / 2};

    BOOST_CHECK_EQUAL(GetBlockSubsidy(0, consensusParams), initial_subsidy);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(halving_height - 1, consensusParams), initial_subsidy);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(halving_height, consensusParams), halved_subsidy);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(halving_height + 1, consensusParams), halved_subsidy);
}

BOOST_AUTO_TEST_CASE(block_subsidy_test)
{
    for (const ChainType chain_type : {
             ChainType::MAIN,
             ChainType::VAQYRON_TESTNET,
             ChainType::TESTNET,
             ChainType::TESTNET4,
             ChainType::SIGNET,
             ChainType::REGTEST,
         }) {
        const auto chain_params{CreateChainParams(*m_node.args, chain_type)};
        TestBlockSubsidyHalvings(chain_params->GetConsensus());
        TestBlockSubsidyFirstHalvingBoundaries(chain_params->GetConsensus());
    }

    const auto vaqyron_testnet_params{CreateChainParams(*m_node.args, ChainType::VAQYRON_TESTNET)};
    const auto& vaqyron_testnet_consensus{vaqyron_testnet_params->GetConsensus()};
    // Height 0 is the scheduled subsidy; the Genesis coinbase output remains zero.
    BOOST_CHECK_EQUAL(GetBlockSubsidy(0, vaqyron_testnet_consensus), 12 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1, vaqyron_testnet_consensus), 12 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(999999, vaqyron_testnet_consensus), 12 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1000000, vaqyron_testnet_consensus), 6 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1000001, vaqyron_testnet_consensus), 6 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1999999, vaqyron_testnet_consensus), 6 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(2000000, vaqyron_testnet_consensus), 3 * COIN);

    TestBlockSubsidyHalvings(150, 12 * COIN); // Synthetic regtest interval
    TestBlockSubsidyHalvings(1000, 12 * COIN); // Synthetic interval
}

BOOST_AUTO_TEST_CASE(check_tx_inputs_money_range)
{
    struct InputCheckResult {
        bool valid;
        CAmount fee;
        std::string reject_reason;
    };

    auto check_inputs = [](const std::vector<CAmount>& input_values, CAmount output_value, CAmount max_money) {
        CCoinsView coins_view;
        CCoinsViewCache inputs{&coins_view};
        CMutableTransaction mutable_tx;
        const Txid funding_txid{Txid::FromUint256(uint256::ONE)};

        for (size_t i = 0; i < input_values.size(); ++i) {
            const COutPoint outpoint{funding_txid, static_cast<uint32_t>(i)};
            mutable_tx.vin.emplace_back(outpoint);
            inputs.AddCoin(outpoint, Coin{CTxOut{input_values[i], CScript{}}, 0, false}, false);
        }
        mutable_tx.vout.emplace_back(output_value, CScript{});
        const CTransaction tx{std::move(mutable_tx)};

        TxValidationState state;
        CAmount fee{0};
        const bool valid{Consensus::CheckTxInputs(tx, state, inputs, COINBASE_MATURITY + 1, max_money, fee)};
        return InputCheckResult{valid, fee, state.GetRejectReason()};
    };

    const std::vector<std::pair<ChainType, CAmount>> chain_limits{
        {ChainType::MAIN, 24000000 * COIN},
        {ChainType::VAQYRON_TESTNET, 24000000 * COIN},
        {ChainType::TESTNET, 21000000 * COIN},
        {ChainType::TESTNET4, 21000000 * COIN},
        {ChainType::SIGNET, 21000000 * COIN},
        {ChainType::REGTEST, 21000000 * COIN},
    };

    for (const auto& [chain_type, expected_max_money] : chain_limits) {
        const auto chain_params{CreateChainParams(*m_node.args, chain_type)};
        const CAmount max_money{chain_params->GetConsensus().nMaxMoney};
        BOOST_CHECK_EQUAL(max_money, expected_max_money);

        CMutableTransaction max_output_mutable;
        max_output_mutable.vout.emplace_back(max_money, CScript{});
        const CTransaction max_output_tx{std::move(max_output_mutable)};
        BOOST_CHECK_EQUAL(max_output_tx.GetValueOut(max_money), max_money);
        BOOST_CHECK_THROW(max_output_tx.GetValueOut(max_money - 1), std::runtime_error);

        const auto max_individual{check_inputs({max_money}, 0, max_money)};
        BOOST_CHECK(max_individual.valid);
        BOOST_CHECK_EQUAL(max_individual.fee, max_money);

        const auto over_limit_individual{check_inputs({max_money + 1}, 0, max_money)};
        BOOST_CHECK(!over_limit_individual.valid);
        BOOST_CHECK_EQUAL(over_limit_individual.reject_reason, "bad-txns-inputvalues-outofrange");

        const CAmount first_input{max_money / 2};
        const CAmount second_input{max_money - first_input};
        const auto max_accumulated{check_inputs({first_input, second_input}, 0, max_money)};
        BOOST_CHECK(max_accumulated.valid);
        BOOST_CHECK_EQUAL(max_accumulated.fee, max_money);

        const auto over_limit_accumulated{check_inputs({first_input, second_input + 1}, 0, max_money)};
        BOOST_CHECK(!over_limit_accumulated.valid);
        BOOST_CHECK_EQUAL(over_limit_accumulated.reject_reason, "bad-txns-inputvalues-outofrange");

        const auto negative_input{check_inputs({-2}, 0, max_money)};
        BOOST_CHECK(!negative_input.valid);
        BOOST_CHECK_EQUAL(negative_input.reject_reason, "bad-txns-inputvalues-outofrange");

        const auto overflow_sensitive_input{check_inputs({std::numeric_limits<CAmount>::max(), 1}, 0, max_money)};
        BOOST_CHECK(!overflow_sensitive_input.valid);
        BOOST_CHECK_EQUAL(overflow_sensitive_input.reject_reason, "bad-txns-inputvalues-outofrange");

        // A fee above max_money is unreachable once nonnegative inputs are capped at max_money.
        const auto attempted_over_limit_fee{check_inputs({max_money, 1}, 0, max_money)};
        BOOST_CHECK(!attempted_over_limit_fee.valid);
        BOOST_CHECK_EQUAL(attempted_over_limit_fee.reject_reason, "bad-txns-inputvalues-outofrange");
    }
}

BOOST_AUTO_TEST_CASE(block_fee_accumulation_money_range)
{
    const std::vector<std::pair<ChainType, CAmount>> chain_limits{
        {ChainType::MAIN, 24000000 * COIN},
        {ChainType::VAQYRON_TESTNET, 24000000 * COIN},
        {ChainType::TESTNET, 21000000 * COIN},
        {ChainType::TESTNET4, 21000000 * COIN},
        {ChainType::SIGNET, 21000000 * COIN},
        {ChainType::REGTEST, 21000000 * COIN},
    };

    for (const auto& [chain_type, expected_max_money] : chain_limits) {
        const auto chain_params{CreateChainParams(*m_node.args, chain_type)};
        const CAmount max_money{chain_params->GetConsensus().nMaxMoney};
        BOOST_CHECK_EQUAL(max_money, expected_max_money);

        const auto exact_limit{validation_internal::AddBlockFee(max_money - 1, 1, max_money)};
        BOOST_REQUIRE(exact_limit.has_value());
        BOOST_CHECK_EQUAL(*exact_limit, max_money);

        BOOST_CHECK(!validation_internal::AddBlockFee(max_money, 1, max_money));
        BOOST_CHECK(!validation_internal::AddBlockFee(0, max_money + 1, max_money));

        const auto overflow_sensitive{validation_internal::AddBlockFee(
            std::numeric_limits<CAmount>::max(), 1, std::numeric_limits<CAmount>::max())};
        BOOST_CHECK(!overflow_sensitive);
    }
}

BOOST_AUTO_TEST_CASE(snapshot_money_range)
{
    const std::vector<std::pair<ChainType, CAmount>> chain_limits{
        {ChainType::MAIN, 24000000 * COIN},
        {ChainType::VAQYRON_TESTNET, 24000000 * COIN},
        {ChainType::TESTNET, 21000000 * COIN},
        {ChainType::TESTNET4, 21000000 * COIN},
        {ChainType::SIGNET, 21000000 * COIN},
        {ChainType::REGTEST, 21000000 * COIN},
    };

    for (const auto& [chain_type, expected_max_money] : chain_limits) {
        const auto chain_params{CreateChainParams(*m_node.args, chain_type)};
        const CAmount max_money{chain_params->GetConsensus().nMaxMoney};
        BOOST_CHECK_EQUAL(max_money, expected_max_money);

        const auto zero_amount{validation_internal::AddSnapshotCoinAmount(0, 0, max_money)};
        BOOST_REQUIRE(zero_amount.has_value());
        BOOST_CHECK_EQUAL(*zero_amount, 0);

        const auto valid_amount{validation_internal::AddSnapshotCoinAmount(0, COIN, max_money)};
        BOOST_REQUIRE(valid_amount.has_value());
        BOOST_CHECK_EQUAL(*valid_amount, COIN);

        const auto exact_limit{validation_internal::AddSnapshotCoinAmount(0, max_money, max_money)};
        BOOST_REQUIRE(exact_limit.has_value());
        BOOST_CHECK_EQUAL(*exact_limit, max_money);

        const auto exact_cumulative_limit{validation_internal::AddSnapshotCoinAmount(max_money - 1, 1, max_money)};
        BOOST_REQUIRE(exact_cumulative_limit.has_value());
        BOOST_CHECK_EQUAL(*exact_cumulative_limit, max_money);

        BOOST_CHECK(!validation_internal::AddSnapshotCoinAmount(0, max_money + 1, max_money));
        BOOST_CHECK(!validation_internal::AddSnapshotCoinAmount(max_money - 1, 2, max_money));
        BOOST_CHECK(!validation_internal::AddSnapshotCoinAmount(0, -1, max_money));

        const CAmount max_amount{std::numeric_limits<CAmount>::max()};
        BOOST_CHECK(!validation_internal::AddSnapshotCoinAmount(max_amount, 1, max_amount));
    }
}

BOOST_AUTO_TEST_CASE(coinbase_output_total_chain_money_range)
{
    const std::vector<std::pair<ChainType, CAmount>> chain_limits{
        {ChainType::MAIN, 24000000 * COIN},
        {ChainType::VAQYRON_TESTNET, 24000000 * COIN},
        {ChainType::TESTNET, 21000000 * COIN},
        {ChainType::TESTNET4, 21000000 * COIN},
        {ChainType::SIGNET, 21000000 * COIN},
        {ChainType::REGTEST, 21000000 * COIN},
    };

    for (const auto& [chain_type, expected_max_money] : chain_limits) {
        const auto chain_params{CreateChainParams(*m_node.args, chain_type)};
        const CAmount max_money{chain_params->GetConsensus().nMaxMoney};
        BOOST_CHECK_EQUAL(max_money, expected_max_money);

        CMutableTransaction coinbase_mutable;
        coinbase_mutable.vout.emplace_back(max_money, CScript{});
        const CTransaction coinbase_at_limit{std::move(coinbase_mutable)};
        BOOST_CHECK_EQUAL(coinbase_at_limit.GetValueOut(max_money), max_money);

        CMutableTransaction over_limit_mutable;
        over_limit_mutable.vout.emplace_back(max_money + 1, CScript{});
        const CTransaction coinbase_over_limit{std::move(over_limit_mutable)};
        BOOST_CHECK_THROW(coinbase_over_limit.GetValueOut(max_money), std::runtime_error);
    }
}

BOOST_AUTO_TEST_CASE(subsidy_limit_test)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    CAmount nSum = 0;
    for (int nHeight = 0; nHeight < 64000000; nHeight += 1000) {
        CAmount nSubsidy = GetBlockSubsidy(nHeight, chainParams->GetConsensus());
        BOOST_CHECK(nSubsidy <= 12 * COIN);
        nSum += nSubsidy * 1000;
        BOOST_CHECK(MoneyRange(nSum));
    }
    BOOST_CHECK_EQUAL(nSum, CAmount{2399999990000000});
}

BOOST_AUTO_TEST_CASE(signet_parse_tests)
{
    ArgsManager signet_argsman;
    signet_argsman.ForceSetArg("-signetchallenge", "51"); // set challenge to OP_TRUE
    const auto signet_params = CreateChainParams(signet_argsman, ChainType::SIGNET);
    CBlock block;
    BOOST_CHECK(signet_params->GetConsensus().signet_challenge == std::vector<uint8_t>{OP_TRUE});
    CScript challenge{OP_TRUE};

    // empty block is invalid
    BOOST_CHECK(!SignetTxs::Create(block, challenge));
    BOOST_CHECK(!CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // no witness commitment
    CMutableTransaction cb;
    cb.vout.emplace_back(0, CScript{});
    block.vtx.push_back(MakeTransactionRef(cb));
    block.vtx.push_back(MakeTransactionRef(cb)); // Add dummy tx to exercise merkle root code
    BOOST_CHECK(!SignetTxs::Create(block, challenge));
    BOOST_CHECK(!CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // no header is treated valid
    std::vector<uint8_t> witness_commitment_section_141{0xaa, 0x21, 0xa9, 0xed};
    for (int i = 0; i < 32; ++i) {
        witness_commitment_section_141.push_back(0xff);
    }
    cb.vout.at(0).scriptPubKey = CScript{} << OP_RETURN << witness_commitment_section_141;
    block.vtx.at(0) = MakeTransactionRef(cb);
    BOOST_CHECK(SignetTxs::Create(block, challenge));
    BOOST_CHECK(CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // no data after header, valid
    std::vector<uint8_t> witness_commitment_section_325{0xec, 0xc7, 0xda, 0xa2};
    cb.vout.at(0).scriptPubKey = CScript{} << OP_RETURN << witness_commitment_section_141 << witness_commitment_section_325;
    block.vtx.at(0) = MakeTransactionRef(cb);
    BOOST_CHECK(SignetTxs::Create(block, challenge));
    BOOST_CHECK(CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // Premature end of data, invalid
    witness_commitment_section_325.push_back(0x01);
    witness_commitment_section_325.push_back(0x51);
    cb.vout.at(0).scriptPubKey = CScript{} << OP_RETURN << witness_commitment_section_141 << witness_commitment_section_325;
    block.vtx.at(0) = MakeTransactionRef(cb);
    BOOST_CHECK(!SignetTxs::Create(block, challenge));
    BOOST_CHECK(!CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // has data, valid
    witness_commitment_section_325.push_back(0x00);
    cb.vout.at(0).scriptPubKey = CScript{} << OP_RETURN << witness_commitment_section_141 << witness_commitment_section_325;
    block.vtx.at(0) = MakeTransactionRef(cb);
    BOOST_CHECK(SignetTxs::Create(block, challenge));
    BOOST_CHECK(CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // Extraneous data, invalid
    witness_commitment_section_325.push_back(0x00);
    cb.vout.at(0).scriptPubKey = CScript{} << OP_RETURN << witness_commitment_section_141 << witness_commitment_section_325;
    block.vtx.at(0) = MakeTransactionRef(cb);
    BOOST_CHECK(!SignetTxs::Create(block, challenge));
    BOOST_CHECK(!CheckSignetBlockSolution(block, signet_params->GetConsensus()));
}

//! Test retrieval of valid assumeutxo values.
BOOST_AUTO_TEST_CASE(test_assumeutxo)
{
    const auto params = CreateChainParams(*m_node.args, ChainType::REGTEST);

    // These heights don't have assumeutxo configurations associated, per the contents
    // of kernel/chainparams.cpp.
    std::vector<int> bad_heights{0, 100, 111, 115, 209, 211};

    for (auto empty : bad_heights) {
        const auto out = params->AssumeutxoForHeight(empty);
        BOOST_CHECK(!out);
    }

    const auto out110_opt = params->AssumeutxoForHeight(110); BOOST_REQUIRE(out110_opt.has_value()); const auto out110 = *out110_opt;
    BOOST_CHECK_EQUAL(out110.hash_serialized.ToString(), "b952555c8ab81fec46f3d4253b7af256d766ceb39fb7752b9d18cdf4a0141327");
    BOOST_CHECK_EQUAL(out110.m_chain_tx_count, 111U);

    const auto out110_2_opt = params->AssumeutxoForBlockhash(uint256{"6affe030b7965ab538f820a56ef56c8149b7dc1d1c144af57113be080db7c397"}); BOOST_REQUIRE(out110_2_opt.has_value()); const auto out110_2 = *out110_2_opt;
    BOOST_CHECK_EQUAL(out110_2.hash_serialized.ToString(), "b952555c8ab81fec46f3d4253b7af256d766ceb39fb7752b9d18cdf4a0141327");
    BOOST_CHECK_EQUAL(out110_2.m_chain_tx_count, 111U);
}

BOOST_AUTO_TEST_CASE(block_malleation)
{
    // Test utilities that calls `IsBlockMutated` and then clears the validity
    // cache flags on `CBlock`.
    auto is_mutated = [](CBlock& block, bool check_witness_root) {
        bool mutated{IsBlockMutated(block, check_witness_root)};
        block.fChecked = false;
        block.m_checked_witness_commitment = false;
        block.m_checked_merkle_root = false;
        return mutated;
    };
    auto is_not_mutated = [&is_mutated](CBlock& block, bool check_witness_root) {
        return !is_mutated(block, check_witness_root);
    };

    // Test utilities to create coinbase transactions and insert witness
    // commitments.
    //
    // Note: this will not include the witness stack by default to avoid
    // triggering the "no witnesses allowed for blocks that don't commit to
    // witnesses" rule when testing other malleation vectors.
    auto create_coinbase_tx = [](bool include_witness = false) {
        CMutableTransaction coinbase;
        coinbase.vin.resize(1);
        if (include_witness) {
            coinbase.vin[0].scriptWitness.stack.resize(1);
            coinbase.vin[0].scriptWitness.stack[0] = std::vector<unsigned char>(32, 0x00);
        }

        coinbase.vout.resize(1);
        coinbase.vout[0].scriptPubKey.resize(MINIMUM_WITNESS_COMMITMENT);
        coinbase.vout[0].scriptPubKey[0] = OP_RETURN;
        coinbase.vout[0].scriptPubKey[1] = 0x24;
        coinbase.vout[0].scriptPubKey[2] = 0xaa;
        coinbase.vout[0].scriptPubKey[3] = 0x21;
        coinbase.vout[0].scriptPubKey[4] = 0xa9;
        coinbase.vout[0].scriptPubKey[5] = 0xed;

        auto tx = MakeTransactionRef(coinbase);
        assert(tx->IsCoinBase());
        return tx;
    };
    auto insert_witness_commitment = [](CBlock& block, uint256 commitment) {
        assert(!block.vtx.empty() && block.vtx[0]->IsCoinBase() && !block.vtx[0]->vout.empty());

        CMutableTransaction mtx{*block.vtx[0]};
        CHash256().Write(commitment).Write(std::vector<unsigned char>(32, 0x00)).Finalize(commitment);
        memcpy(&mtx.vout[0].scriptPubKey[6], commitment.begin(), 32);
        block.vtx[0] = MakeTransactionRef(mtx);
    };

    {
        CBlock block;

        // Empty block is expected to have merkle root of 0x0.
        BOOST_CHECK(block.vtx.empty());
        block.hashMerkleRoot = uint256{1};
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        block.hashMerkleRoot = uint256{};
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));

        // Block with a single coinbase tx is mutated if the merkle root is not
        // equal to the coinbase tx's hash.
        block.vtx.push_back(create_coinbase_tx());
        BOOST_CHECK(block.vtx[0]->GetHash().ToUint256() != block.hashMerkleRoot);
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        block.hashMerkleRoot = block.vtx[0]->GetHash().ToUint256();
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));

        // Block with two transactions is mutated if the merkle root does not
        // match the double sha256 of the concatenation of the two transaction
        // hashes.
        block.vtx.push_back(MakeTransactionRef(CMutableTransaction{}));
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        HashWriter hasher;
        hasher.write(block.vtx[0]->GetHash());
        hasher.write(block.vtx[1]->GetHash());
        block.hashMerkleRoot = hasher.GetHash();
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));

        // Block with two transactions is mutated if any node is duplicate.
        {
            block.vtx[1] = block.vtx[0];
            HashWriter hasher;
            hasher.write(block.vtx[0]->GetHash());
            hasher.write(block.vtx[1]->GetHash());
            block.hashMerkleRoot = hasher.GetHash();
            BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        }

        // Blocks with 64-byte coinbase transactions are not considered mutated
        block.vtx.clear();
        {
            CMutableTransaction mtx;
            mtx.vin.resize(1);
            mtx.vout.resize(1);
            mtx.vout[0].scriptPubKey.resize(4);
            block.vtx.push_back(MakeTransactionRef(mtx));
            block.hashMerkleRoot = block.vtx.back()->GetHash().ToUint256();
            assert(block.vtx.back()->IsCoinBase());
            assert(GetSerializeSize(TX_NO_WITNESS(block.vtx.back())) == 64);
        }
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));
    }

    {
        // Test merkle root malleation

        // Pseudo code to mine transactions tx{1,2,3}:
        //
        // ```
        // loop {
        //   tx1 = random_tx()
        //   tx2 = random_tx()
        //   tx3 = deserialize_tx(txid(tx1) || txid(tx2));
        //   if serialized_size_without_witness(tx3) == 64 {
        //     print(hex(tx3))
        //     break
        //   }
        // }
        // ```
        //
        // The `random_tx` function used to mine the txs below simply created
        // empty transactions with a random version field.
        CMutableTransaction tx1;
        BOOST_CHECK(DecodeHexTx(tx1, "ff204bd0000000000000", /*try_no_witness=*/true, /*try_witness=*/false));
        CMutableTransaction tx2;
        BOOST_CHECK(DecodeHexTx(tx2, "8ae53c92000000000000", /*try_no_witness=*/true, /*try_witness=*/false));
        CMutableTransaction tx3;
        BOOST_CHECK(DecodeHexTx(tx3, "cdaf22d00002c6a7f848f8ae4d30054e61dcf3303d6fe01d282163341f06feecc10032b3160fcab87bdfe3ecfb769206ef2d991b92f8a268e423a6ef4d485f06", /*try_no_witness=*/true, /*try_witness=*/false));
        {
            // Verify that double_sha256(txid1||txid2) == txid3
            HashWriter hasher;
            hasher.write(tx1.GetHash());
            hasher.write(tx2.GetHash());
            assert(hasher.GetHash() == tx3.GetHash().ToUint256());
            // Verify that tx3 is 64 bytes in size (without witness).
            assert(GetSerializeSize(TX_NO_WITNESS(tx3)) == 64);
        }

        CBlock block;
        block.vtx.push_back(MakeTransactionRef(tx1));
        block.vtx.push_back(MakeTransactionRef(tx2));
        uint256 merkle_root = block.hashMerkleRoot = BlockMerkleRoot(block);
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));

        // Mutate the block by replacing the two transactions with one 64-byte
        // transaction that serializes into the concatenation of the txids of
        // the transactions in the unmutated block.
        block.vtx.clear();
        block.vtx.push_back(MakeTransactionRef(tx3));
        BOOST_CHECK(!block.vtx.back()->IsCoinBase());
        BOOST_CHECK(BlockMerkleRoot(block) == merkle_root);
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
    }

    {
        CBlock block;
        block.vtx.push_back(create_coinbase_tx(/*include_witness=*/true));
        {
            CMutableTransaction mtx;
            mtx.vin.resize(1);
            mtx.vin[0].scriptWitness.stack.resize(1);
            mtx.vin[0].scriptWitness.stack[0] = {0};
            block.vtx.push_back(MakeTransactionRef(mtx));
        }
        block.hashMerkleRoot = BlockMerkleRoot(block);
        // Block with witnesses is considered mutated if the witness commitment
        // is not validated.
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        // Block with invalid witness commitment is considered mutated.
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/true));

        // Block with valid commitment is not mutated
        {
            auto commitment{BlockWitnessMerkleRoot(block)};
            insert_witness_commitment(block, commitment);
            block.hashMerkleRoot = BlockMerkleRoot(block);
        }
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/true));

        // Malleating witnesses should be caught by `IsBlockMutated`.
        {
            CMutableTransaction mtx{*block.vtx[1]};
            assert(!mtx.vin[0].scriptWitness.stack[0].empty());
            ++mtx.vin[0].scriptWitness.stack[0][0];
            block.vtx[1] = MakeTransactionRef(mtx);
        }
        // Without also updating the witness commitment, the merkle root should
        // not change when changing one of the witnesses.
        BOOST_CHECK(block.hashMerkleRoot == BlockMerkleRoot(block));
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/true));
        {
            auto commitment{BlockWitnessMerkleRoot(block)};
            insert_witness_commitment(block, commitment);
            block.hashMerkleRoot = BlockMerkleRoot(block);
        }
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/true));

        // Test malleating the coinbase witness reserved value
        {
            CMutableTransaction mtx{*block.vtx[0]};
            mtx.vin[0].scriptWitness.stack.resize(0);
            block.vtx[0] = MakeTransactionRef(mtx);
            block.hashMerkleRoot = BlockMerkleRoot(block);
        }
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/true));
    }
}

BOOST_AUTO_TEST_SUITE_END()
