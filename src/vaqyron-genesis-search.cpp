// Copyright (c) 2026-present The VAQYRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <arith_uint256.h>
#include <consensus/params.h>
#include <kernel/genesis.h>
#include <kernel/genesis_search.h>
#include <pow.h>
#include <streams.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <util/translation.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

const TranslateFn G_TRANSLATION_FUN{nullptr};

namespace {

constexpr uint32_t AUTHORIZED_NTIME{1791363600};
constexpr uint32_t MAX_SEARCH_WORKERS{4};

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

std::tm UtcTime(std::time_t value)
{
    std::tm result{};
#ifdef _WIN32
    if (gmtime_s(&result, &value) != 0) throw std::runtime_error{"cannot convert nTime to UTC"};
#else
    if (gmtime_r(&value, &result) == nullptr) throw std::runtime_error{"cannot convert nTime to UTC"};
#endif
    return result;
}

std::string RawHex(const uint256& value)
{
    const std::vector<unsigned char> bytes{value.begin(), value.end()};
    return HexStr(bytes);
}

void PrintUsage()
{
    std::cerr << "Usage: vaqyron-genesis-search --time <unix-nTime> "
                 "--start-nonce <uint32> --end-nonce <uint32> "
                 "[--checkpoint <file>]\n";
}

uint32_t DefaultWorkerCount()
{
    const unsigned int logical_processors{std::thread::hardware_concurrency()};
    if (logical_processors <= 1) return 1;
    return std::min<uint32_t>(MAX_SEARCH_WORKERS, logical_processors - 1);
}

} // namespace

int main(int argc, char* argv[])
{
    try {
        if (argc != 7 && argc != 9) {
            PrintUsage();
            return 2;
        }

        std::array<std::string_view, 3> names{"--time", "--start-nonce", "--end-nonce"};
        std::array<uint32_t, 3> values{};
        for (size_t i{0}; i < names.size(); ++i) {
            if (argv[1 + 2 * i] != names[i]) {
                PrintUsage();
                return 2;
            }
            values[i] = ParseUint32(argv[2 + 2 * i], names[i]);
        }

        std::string checkpoint_path;
        if (argc == 9) {
            if (std::string_view{argv[7]} != "--checkpoint" || argv[8][0] == '\0') {
                PrintUsage();
                return 2;
            }
            checkpoint_path = argv[8];
        }

        const kernel::GenesisSearchOptions options{
            .time = values[0],
            .start_nonce = values[1],
            .end_nonce = values[2],
            .worker_count = DefaultWorkerCount(),
            .checkpoint_path = checkpoint_path,
        };
        if (options.time != AUTHORIZED_NTIME) {
            throw std::invalid_argument{"authorized genesis search must use nTime 1791363600"};
        }

        Consensus::Params consensus{};
        consensus.powLimit = uint256{"00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.fPowUseYespower = true;
        constexpr uint32_t bits{kernel::VAQYRON_GENESIS_NBITS};
        const auto target{DeriveTarget(bits, consensus.powLimit)};
        if (!target) throw std::runtime_error{"frozen genesis target is invalid"};
        const auto worker_ranges{kernel::PartitionGenesisSearchRange(
            options.start_nonce, options.end_nonce, options.worker_count)};

        const std::time_t timestamp{static_cast<std::time_t>(options.time)};
        const std::tm utc_timestamp{UtcTime(timestamp)};
        std::cout << "GENESIS MESSAGE: " << kernel::VaqyronGenesisMessage() << '\n'
                  << "OP_RETURN MARKER: " << kernel::VaqyronGenesisMarker() << '\n'
                  << "VERSION: " << kernel::VAQYRON_GENESIS_VERSION << '\n'
                  << "POW ALGORITHM: yespower YESPOWER_1_0\n"
                  << "N: 2048\n"
                  << "r: 16\n"
                  << "PERSONALIZATION: VAQYRON:pow:yespower:v1\n"
                  << "CANDIDATE INTERPRETATION: raw digest byte 0 is least-significant\n"
                  << "nTime: " << options.time << '\n'
                  << "nTime UTC: " << std::put_time(&utc_timestamp, "%Y-%m-%d %H:%M:%S UTC") << '\n'
                  << "nBits: 0x" << std::hex << bits << std::dec << '\n'
                  << "TARGET: " << target->GetHex() << '\n'
                  << "SEARCH START NONCE: " << options.start_nonce << '\n'
                  << "SEARCH END NONCE: " << options.end_nonce << '\n'
                  << "SEARCH WORKERS: " << worker_ranges.size() << '\n'
                  << "RANGE ALLOCATION: contiguous non-overlapping\n"
                  << "YESPOWER SCRATCH ESTIMATE: approximately 4 MiB per worker\n"
                  << "TIMESTAMP MUTATION: disabled\n"
                  << "NONCE WRAP: disabled\n";
        for (const auto& range : worker_ranges) {
            std::cout << "WORKER RANGE " << range.worker_index << ": "
                      << range.start_nonce << ".." << range.end_nonce << '\n';
        }

        const kernel::GenesisSearchResult result{kernel::SearchVaqyronGenesis(
            options,
            consensus,
            {},
            [](const kernel::GenesisSearchProgress& progress) {
                std::cerr << "Progress: worker=" << progress.worker_index
                          << " range=" << progress.worker_start_nonce << ".."
                          << progress.worker_end_nonce
                          << " nonce=" << progress.current_nonce
                          << " candidates=" << progress.candidates_checked
                          << " elapsed_seconds=" << std::fixed << std::setprecision(1)
                          << progress.elapsed_seconds
                          << " candidates_per_second=" << progress.candidates_per_second << '\n';
            })};

        std::vector<unsigned char> serialized_transaction;
        VectorWriter{serialized_transaction, 0, TX_NO_WITNESS(*result.last_block.vtx[0])};
        std::vector<unsigned char> serialized_header;
        VectorWriter{serialized_header, 0, result.last_block.GetBlockHeader()};
        const arith_uint256 pow_integer{UintToArith256(result.last_pow_digest)};
        const bool meets_target{pow_integer <= result.target};

        std::cout << "RESULT: " << (result.found ? "FOUND" : "NOT FOUND") << '\n'
                  << "NONCE: " << result.nonce << '\n'
                  << "CANDIDATES EVALUATED: " << result.candidates_checked << '\n'
                  << "GENESIS TRANSACTION: " << HexStr(serialized_transaction) << '\n'
                  << "GENESIS TXID: " << result.last_block.vtx[0]->GetHash().GetHex() << '\n'
                  << "CANONICAL 80-BYTE HEADER: " << HexStr(serialized_header) << '\n'
                  << "MERKLE ROOT: " << result.last_block.hashMerkleRoot.GetHex() << '\n'
                  << "POW_DIGEST (raw): " << RawHex(result.last_pow_digest) << '\n'
                  << "Candidate-A POW_INTEGER: " << pow_integer.GetHex() << '\n'
                  << "TARGET: " << result.target.GetHex() << '\n'
                  << "SHA256d BLOCK_ID: " << result.last_block.GetHash().GetHex() << '\n'
                  << "POW_INTEGER <= TARGET: " << (meets_target ? "true" : "false") << '\n'
                  << "WORKERS USED: " << result.worker_count << '\n'
                  << "ELAPSED SECONDS: " << std::fixed << std::setprecision(3)
                  << result.elapsed_seconds << '\n'
                  << "CANDIDATES PER SECOND: " << result.candidates_per_second << '\n';
        return result.found ? 0 : 1;
    } catch (const std::exception& error) {
        std::cerr << "Local genesis generator failure: " << error.what() << '\n';
        return 2;
    }
}
