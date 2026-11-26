// Copyright (c) 2026-present The VAQYRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <addresstype.h>
#include <base58.h>
#include <bech32.h>
#include <chainparams.h>
#include <chainparamsbase.h>
#include <common/args.h>
#include <init.h>
#include <key.h>
#include <key_io.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>
#include <util/fs_helpers.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <string>
#include <tuple>
#include <vector>

#ifdef WIN32
#include <shlobj.h>
#endif

#ifdef WIN32
static constexpr auto VAQYRON_DATA_DIR_NAME = "VAQYRON";
#elif defined(__APPLE__)
static constexpr auto VAQYRON_DATA_DIR_NAME = "VAQYRON";
#else
static constexpr auto VAQYRON_DATA_DIR_NAME = ".vaqyron";
#endif

BOOST_FIXTURE_TEST_SUITE(network_identity_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(vaqyron_main_network_identity)
{
    SelectParams(ChainType::MAIN);

    BOOST_CHECK(Params().MessageStart() == (MessageStartChars{0xdc, 0x56, 0x27, 0x4a}));
    BOOST_CHECK_EQUAL(Params().GetDefaultPort(), 29733);
    BOOST_CHECK_EQUAL(BaseParams().RPCPort(), 29732);
    BOOST_CHECK(Params().MessageStart() != (MessageStartChars{0xf9, 0xbe, 0xb4, 0xd9}));

    BOOST_CHECK_EQUAL(Params().GetDefaultPort() + 1, 29734);
    BOOST_CHECK_EQUAL(Params().Bech32HRP(), "vqrn");
    BOOST_CHECK(Params().Base58Prefix(CChainParams::PUBKEY_ADDRESS) == (std::vector<unsigned char>{0xce, 0xa2, 0xfe, 0x51}));
    BOOST_CHECK(Params().Base58Prefix(CChainParams::SCRIPT_ADDRESS) == (std::vector<unsigned char>{0x54, 0x58, 0xaa, 0x97}));
    BOOST_CHECK(Params().Base58Prefix(CChainParams::SECRET_KEY) == (std::vector<unsigned char>{0x5c, 0x7d, 0xde, 0x4f}));
    BOOST_CHECK(Params().Base58Prefix(CChainParams::EXT_PUBLIC_KEY) == (std::vector<unsigned char>{0x64, 0xfc, 0xa3, 0x82}));
    BOOST_CHECK(Params().Base58Prefix(CChainParams::EXT_SECRET_KEY) == (std::vector<unsigned char>{0x8c, 0x3b, 0x90, 0xd9}));
}

BOOST_AUTO_TEST_CASE(vaqyron_testnet_network_identity)
{
    const auto testnet{CChainParams::VaqyronTestNet()};
    BOOST_CHECK_EQUAL(ChainTypeToString(testnet->GetChainType()), "vaqyron-testnet");
    BOOST_CHECK(testnet->MessageStart() == (MessageStartChars{0x56, 0x51, 0x54, 0x31}));
    BOOST_CHECK_EQUAL(testnet->GetDefaultPort(), 39733);
    BOOST_CHECK_EQUAL(CreateBaseChainParams(ChainType::VAQYRON_TESTNET)->RPCPort(), 39732);
    BOOST_CHECK_EQUAL(testnet->Bech32HRP(), "tvqrn");
    BOOST_CHECK(testnet->Base58Prefix(CChainParams::PUBKEY_ADDRESS) == (std::vector<unsigned char>{0x42}));
    BOOST_CHECK(testnet->Base58Prefix(CChainParams::SCRIPT_ADDRESS) == (std::vector<unsigned char>{0x43}));
    BOOST_CHECK(testnet->Base58Prefix(CChainParams::SECRET_KEY) == (std::vector<unsigned char>{0x44}));
    BOOST_CHECK(testnet->Base58Prefix(CChainParams::EXT_PUBLIC_KEY) ==
                (std::vector<unsigned char>{0x56, 0x51, 0x54, 0x50}));
    BOOST_CHECK(testnet->Base58Prefix(CChainParams::EXT_SECRET_KEY) ==
                (std::vector<unsigned char>{0x56, 0x51, 0x54, 0x51}));
    BOOST_CHECK(testnet->DNSSeeds().empty());
    BOOST_CHECK(testnet->FixedSeeds().empty());
    BOOST_CHECK(!testnet->IsVaqyronTestnetGenesisPending());
    BOOST_CHECK(!testnet->GenesisBlock().IsNull());
    BOOST_CHECK_EQUAL(VAQYRON_TESTNET_PROPOSED_GENESIS_NBITS, 0x207fffffU);
    BOOST_CHECK_EQUAL(GetNetworkForMagic(testnet->MessageStart()).value(), ChainType::VAQYRON_TESTNET);

    for (const ChainType other : {ChainType::MAIN, ChainType::TESTNET, ChainType::TESTNET4,
                                  ChainType::SIGNET, ChainType::REGTEST}) {
        const auto other_params{other == ChainType::MAIN ? CChainParams::Main() :
                                other == ChainType::TESTNET ? CChainParams::TestNet() :
                                other == ChainType::TESTNET4 ? CChainParams::TestNet4() :
                                other == ChainType::SIGNET ? CChainParams::SigNet({}) :
                                CChainParams::RegTest({})};
        BOOST_CHECK(testnet->MessageStart() != other_params->MessageStart());
        BOOST_CHECK(testnet->GetDefaultPort() != other_params->GetDefaultPort());
    }
}

BOOST_AUTO_TEST_CASE(vaqyron_main_address_encodings_round_trip)
{
    SelectParams(ChainType::MAIN);

    uint160 hash;
    hash.begin()[0] = 0x42;
    const PKHash p2pkh{hash};
    const ScriptHash p2sh{hash};
    const std::string p2pkh_address{EncodeDestination(p2pkh)};
    const std::string p2sh_address{EncodeDestination(p2sh)};
    BOOST_CHECK(IsValidDestination(DecodeDestination(p2pkh_address)));
    BOOST_CHECK(DecodeDestination(p2pkh_address) == CTxDestination{p2pkh});
    BOOST_CHECK(DecodeDestination(p2sh_address) == CTxDestination{p2sh});

    std::array<unsigned char, 32> secret_bytes{};
    secret_bytes.back() = 1;
    CKey secret;
    secret.Set(secret_bytes.begin(), secret_bytes.end(), true);
    BOOST_REQUIRE(secret.IsValid());
    const std::string wif{EncodeSecret(secret)};
    BOOST_CHECK(DecodeSecret(wif).IsValid());
    BOOST_CHECK(DecodeSecret(wif) == secret);

    std::array<std::byte, 32> seed{};
    for (size_t i = 0; i < seed.size(); ++i) seed[i] = std::byte(i + 1);
    CExtKey ext_secret;
    ext_secret.SetSeed(seed);
    const std::string ext_secret_string{EncodeExtKey(ext_secret)};
    const CExtKey decoded_ext_secret{DecodeExtKey(ext_secret_string)};
    BOOST_CHECK(decoded_ext_secret.key.IsValid());
    BOOST_CHECK(EncodeExtKey(decoded_ext_secret) == ext_secret_string);
    const std::string ext_public_string{EncodeExtPubKey(ext_secret.Neuter())};
    BOOST_CHECK(DecodeExtPubKey(ext_public_string).pubkey.IsValid());
    BOOST_CHECK(EncodeExtPubKey(DecodeExtPubKey(ext_public_string)) == ext_public_string);

    const WitnessV0KeyHash witness_v0{hash};
    const CTxDestination witness_v0_destination{witness_v0};
    const std::string witness_v0_address{EncodeDestination(witness_v0_destination)};
    BOOST_CHECK(witness_v0_address.starts_with("vqrn1"));
    BOOST_CHECK(DecodeDestination(witness_v0_address) == witness_v0_destination);

    const WitnessUnknown witness_v2{2, std::vector<unsigned char>(32, 0x2a)};
    const CTxDestination witness_v2_destination{witness_v2};
    const std::string witness_v2_address{EncodeDestination(witness_v2_destination)};
    BOOST_CHECK(witness_v2_address.starts_with("vqrn1"));
    BOOST_CHECK(DecodeDestination(witness_v2_address) == witness_v2_destination);
}

BOOST_AUTO_TEST_CASE(vaqyron_testnet_address_encodings_round_trip_and_isolation)
{
    uint160 hash;
    hash.begin()[0] = 0x42;
    const PKHash p2pkh{hash};
    const ScriptHash p2sh{hash};

    std::array<unsigned char, 32> secret_bytes{};
    secret_bytes.back() = 1;
    CKey secret;
    secret.Set(secret_bytes.begin(), secret_bytes.end(), true);
    BOOST_REQUIRE(secret.IsValid());

    std::array<std::byte, 32> seed{};
    seed[0] = std::byte{1};
    CExtKey ext_secret;
    ext_secret.SetSeed(seed);

    SelectParams(ChainType::MAIN);
    const std::string main_p2pkh{EncodeDestination(p2pkh)};
    const std::string main_wif{EncodeSecret(secret)};
    const std::string main_ext_private{EncodeExtKey(ext_secret)};

    SelectParams(ChainType::VAQYRON_TESTNET);
    const std::string testnet_p2pkh{EncodeDestination(p2pkh)};
    const std::string testnet_p2sh{EncodeDestination(CTxDestination{p2sh})};
    const std::string testnet_wif{EncodeSecret(secret)};
    const std::string testnet_ext_private{EncodeExtKey(ext_secret)};
    const std::string testnet_ext_public{EncodeExtPubKey(ext_secret.Neuter())};
    const std::string testnet_witness{EncodeDestination(CTxDestination{WitnessV0KeyHash{hash}})};

    BOOST_CHECK(IsValidDestination(DecodeDestination(testnet_p2pkh)));
    BOOST_CHECK(DecodeDestination(testnet_p2pkh) == CTxDestination{p2pkh});
    BOOST_CHECK(DecodeDestination(testnet_p2sh) == CTxDestination{p2sh});
    BOOST_CHECK(DecodeSecret(testnet_wif) == secret);
    BOOST_CHECK(DecodeExtKey(testnet_ext_private).key == ext_secret.key);
    BOOST_CHECK(DecodeExtPubKey(testnet_ext_public).pubkey == ext_secret.Neuter().pubkey);
    BOOST_CHECK(testnet_witness.starts_with("tvqrn1"));
    BOOST_CHECK(DecodeDestination(testnet_witness) == CTxDestination{WitnessV0KeyHash{hash}});
    BOOST_CHECK(!IsValidDestination(DecodeDestination(main_p2pkh)));
    BOOST_CHECK(!DecodeSecret(main_wif).IsValid());
    BOOST_CHECK(!DecodeExtKey(main_ext_private).key.IsValid());

    SelectParams(ChainType::MAIN);
    BOOST_CHECK(!IsValidDestination(DecodeDestination(testnet_p2pkh)));
    BOOST_CHECK(!IsValidDestination(DecodeDestination(testnet_witness)));
}

BOOST_AUTO_TEST_CASE(bitcoin_main_encodings_are_not_vaqyron_main)
{
    SelectParams(ChainType::MAIN);

    uint160 hash;
    hash.begin()[0] = 0x42;
    std::vector<unsigned char> bitcoin_p2pkh{0x00};
    bitcoin_p2pkh.insert(bitcoin_p2pkh.end(), hash.begin(), hash.end());
    BOOST_CHECK(!IsValidDestination(DecodeDestination(EncodeBase58Check(bitcoin_p2pkh))));

    std::vector<unsigned char> bitcoin_p2sh{0x05};
    bitcoin_p2sh.insert(bitcoin_p2sh.end(), hash.begin(), hash.end());
    BOOST_CHECK(!IsValidDestination(DecodeDestination(EncodeBase58Check(bitcoin_p2sh))));

    std::array<unsigned char, 32> secret_bytes{};
    secret_bytes.back() = 1;
    std::vector<unsigned char> bitcoin_wif{0x80};
    bitcoin_wif.insert(bitcoin_wif.end(), secret_bytes.begin(), secret_bytes.end());
    bitcoin_wif.push_back(1);
    BOOST_CHECK(!DecodeSecret(EncodeBase58Check(bitcoin_wif)).IsValid());

    std::array<std::byte, 32> seed{};
    seed[0] = std::byte{1};
    CExtKey ext_secret;
    ext_secret.SetSeed(seed);
    std::array<unsigned char, BIP32_EXTKEY_SIZE> ext_payload{};
    ext_secret.Encode(ext_payload.data());
    std::vector<unsigned char> bitcoin_xprv{0x04, 0x88, 0xad, 0xe4};
    bitcoin_xprv.insert(bitcoin_xprv.end(), ext_payload.begin(), ext_payload.end());
    BOOST_CHECK(!DecodeExtKey(EncodeBase58Check(bitcoin_xprv)).key.IsValid());

    ext_secret.Neuter().Encode(ext_payload.data());
    std::vector<unsigned char> bitcoin_xpub{0x04, 0x88, 0xb2, 0x1e};
    bitcoin_xpub.insert(bitcoin_xpub.end(), ext_payload.begin(), ext_payload.end());
    BOOST_CHECK(!DecodeExtPubKey(EncodeBase58Check(bitcoin_xpub)).pubkey.IsValid());

    std::vector<unsigned char> witness_data{0};
    ConvertBits<8, 5, true>([&](unsigned char value) { witness_data.push_back(value); }, hash.begin(), hash.end());
    const std::string bitcoin_bech32{bech32::Encode(bech32::Encoding::BECH32, "bc", witness_data)};
    BOOST_CHECK(!IsValidDestination(DecodeDestination(bitcoin_bech32)));
}

BOOST_AUTO_TEST_CASE(non_main_address_encodings_are_not_vaqyron_main)
{
    uint160 hash;
    hash.begin()[0] = 0x42;
    const PKHash p2pkh{hash};
    const ScriptHash p2sh{hash};

    std::array<unsigned char, 32> secret_bytes{};
    secret_bytes.back() = 1;
    CKey secret;
    secret.Set(secret_bytes.begin(), secret_bytes.end(), true);
    BOOST_REQUIRE(secret.IsValid());

    std::array<std::byte, 32> seed{};
    for (size_t i = 0; i < seed.size(); ++i) seed[i] = std::byte(i + 1);
    CExtKey ext_secret;
    ext_secret.SetSeed(seed);

    const WitnessV0KeyHash witness{hash};
    const CTxDestination witness_destination{witness};
    const std::array networks{
        std::tuple{ChainType::TESTNET, "tb"},
        std::tuple{ChainType::TESTNET4, "tb"},
        std::tuple{ChainType::SIGNET, "tb"},
        std::tuple{ChainType::REGTEST, "bcrt"},
        std::tuple{ChainType::VAQYRON_TESTNET, "tvqrn"},
    };

    SelectParams(ChainType::MAIN);
    const auto main_params{CreateChainParams(*m_node.args, ChainType::MAIN)};
    const auto main_hrp{main_params->Bech32HRP()};

    for (const auto& [chain, expected_hrp] : networks) {
        SelectParams(chain);
        const auto foreign_params{CreateChainParams(*m_node.args, chain)};

        BOOST_CHECK_EQUAL(foreign_params->Bech32HRP(), expected_hrp);
        BOOST_CHECK(foreign_params->Base58Prefix(CChainParams::PUBKEY_ADDRESS) !=
                    main_params->Base58Prefix(CChainParams::PUBKEY_ADDRESS));
        BOOST_CHECK(foreign_params->Base58Prefix(CChainParams::SCRIPT_ADDRESS) !=
                    main_params->Base58Prefix(CChainParams::SCRIPT_ADDRESS));
        BOOST_CHECK(foreign_params->Base58Prefix(CChainParams::SECRET_KEY) !=
                    main_params->Base58Prefix(CChainParams::SECRET_KEY));
        BOOST_CHECK(foreign_params->Base58Prefix(CChainParams::EXT_PUBLIC_KEY) !=
                    main_params->Base58Prefix(CChainParams::EXT_PUBLIC_KEY));
        BOOST_CHECK(foreign_params->Base58Prefix(CChainParams::EXT_SECRET_KEY) !=
                    main_params->Base58Prefix(CChainParams::EXT_SECRET_KEY));
        BOOST_CHECK(foreign_params->Bech32HRP() != main_hrp);

        const std::string p2pkh_address{EncodeDestination(p2pkh)};
        const std::string p2sh_address{EncodeDestination(p2sh)};
        const std::string wif{EncodeSecret(secret)};
        const std::string ext_private{EncodeExtKey(ext_secret)};
        const std::string ext_public{EncodeExtPubKey(ext_secret.Neuter())};
        const std::string witness_address{EncodeDestination(witness_destination)};

        BOOST_CHECK(witness_address.starts_with(std::string{expected_hrp} + "1"));

        SelectParams(ChainType::MAIN);
        BOOST_CHECK(!IsValidDestination(DecodeDestination(p2pkh_address)));
        BOOST_CHECK(!IsValidDestination(DecodeDestination(p2sh_address)));
        BOOST_CHECK(!DecodeSecret(wif).IsValid());
        BOOST_CHECK(!DecodeExtKey(ext_private).key.IsValid());
        BOOST_CHECK(!DecodeExtPubKey(ext_public).pubkey.IsValid());
        BOOST_CHECK(!IsValidDestination(DecodeDestination(witness_address)));
    }

    // The test-family Base58 versions are intentionally shared. Testnet,
    // testnet4, and signet also share "tb"; regtest uses "bcrt". The checks
    // above compare each encoding to VAQYRON MAIN, not to another test chain.
    SelectParams(ChainType::MAIN);
}

BOOST_AUTO_TEST_CASE(vaqyron_storage_and_non_main_defaults)
{
    const fs::path data_dir{GetDefaultDataDir()};
    BOOST_CHECK_EQUAL(fs::PathToString(data_dir.filename()), VAQYRON_DATA_DIR_NAME);
#ifdef WIN32
    BOOST_CHECK(data_dir == GetSpecialFolderPath(CSIDL_LOCAL_APPDATA) / "VAQYRON");
#elif defined(__APPLE__)
    const char* home = std::getenv("HOME");
    const fs::path home_path = (home == nullptr || *home == '\0') ? fs::path{"/"} : fs::path{home};
    BOOST_CHECK(data_dir == home_path / "Library" / "Application Support" / "VAQYRON");
#else
    const char* home = std::getenv("HOME");
    const fs::path home_path = (home == nullptr || *home == '\0') ? fs::path{"/"} : fs::path{home};
    BOOST_CHECK(data_dir == home_path / ".vaqyron");
#endif
    BOOST_CHECK_EQUAL(VAQYRON_CONF_FILENAME, "vaqyron.conf");

    ArgsManager args;
    SetupServerArgs(args);
    const std::string help{args.GetHelpMessage()};
    BOOST_CHECK(help.find("default: vaqyron.conf") != std::string::npos);
    BOOST_CHECK(help.find("default: vaqyrond.pid") != std::string::npos);
    BOOST_CHECK(help.find("127.0.0.1:29734=onion") != std::string::npos);
    BOOST_CHECK(help.find("127.0.0.1:39734=onion") != std::string::npos);

    for (const auto& [chain, p2p, rpc] : {
             std::tuple{ChainType::TESTNET, 18333, 18332},
             std::tuple{ChainType::TESTNET4, 48333, 48332},
             std::tuple{ChainType::SIGNET, 38333, 38332},
             std::tuple{ChainType::REGTEST, 18444, 18443},
             std::tuple{ChainType::VAQYRON_TESTNET, 39733, 39732},
         }) {
        SelectParams(chain);
        BOOST_CHECK_EQUAL(Params().GetDefaultPort(), p2p);
        BOOST_CHECK_EQUAL(BaseParams().RPCPort(), rpc);
    }
}

BOOST_AUTO_TEST_CASE(network_specific_data_directories_do_not_alias_main)
{
    ArgsManager args;
    args.ForceSetArg("-datadir", fs::PathToString(m_path_root));
    const fs::path expected_main_base{fs::absolute(m_path_root)};

    SelectBaseParams(ChainType::MAIN);
    args.ClearPathCache();
    const fs::path main_base{args.GetDataDirBase()};
    const fs::path main_net{args.GetDataDirNet()};
    BOOST_CHECK(main_base == expected_main_base);
    BOOST_CHECK(main_net == main_base);
    BOOST_CHECK_EQUAL(fs::PathToString(GetDefaultDataDir().filename()), VAQYRON_DATA_DIR_NAME);

    const std::array networks{
        std::pair{ChainType::TESTNET, "testnet3"},
        std::pair{ChainType::TESTNET4, "testnet4"},
        std::pair{ChainType::SIGNET, "signet"},
        std::pair{ChainType::REGTEST, "regtest"},
        std::pair{ChainType::VAQYRON_TESTNET, "vaqyron-testnet"},
    };
    std::vector<fs::path> network_paths;
    for (const auto& [chain, expected_subdirectory] : networks) {
        SelectBaseParams(chain);
        args.ClearPathCache();
        const fs::path network_base{args.GetDataDirBase()};
        const fs::path network_path{args.GetDataDirNet()};

        BOOST_CHECK_EQUAL(network_base, main_base);
        BOOST_CHECK(network_path != main_net);
        BOOST_CHECK_EQUAL(
            fs::PathToString(network_path.lexically_relative(network_base)),
            expected_subdirectory);
        BOOST_CHECK(std::find(network_paths.begin(), network_paths.end(), network_path) ==
                    network_paths.end());
        network_paths.push_back(network_path);
    }

    // GetDataDirNet only derives paths; these checks must not create storage.
    BOOST_CHECK(fs::is_directory(m_path_root));
    for (const auto& network_path : network_paths) {
        BOOST_CHECK(!fs::exists(network_path));
    }
    SelectBaseParams(ChainType::MAIN);
}

BOOST_AUTO_TEST_SUITE_END()
