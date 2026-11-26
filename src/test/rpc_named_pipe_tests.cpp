// Copyright (c) 2026-present The VAQYRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifdef WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#endif

#include <rpc/rpc_named_pipe.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <any>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <future>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#ifdef WIN32
#include <windows.h>
#include <sddl.h>
#endif

#ifdef WIN32
namespace {

std::atomic<std::uint32_t> g_pipe_fixture_counter{0};

struct TestPipePair {
    std::wstring name;
    HANDLE server{INVALID_HANDLE_VALUE};
    HANDLE client{INVALID_HANDLE_VALUE};

    ~TestPipePair()
    {
        if (client != INVALID_HANDLE_VALUE) CloseHandle(client);
        if (server != INVALID_HANDLE_VALUE) CloseHandle(server);
    }
};

HANDLE CreateTestPipeInstance(std::wstring& name, DWORD buffer_size)
{
    const auto suffix = std::to_wstring(GetCurrentProcessId()) + L"-" +
        std::to_wstring(g_pipe_fixture_counter.fetch_add(1));
    name = L"\\\\.\\pipe\\vaqyron-stage1-test-" + suffix;

    HANDLE token{nullptr};
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return INVALID_HANDLE_VALUE;
    DWORD token_size{0};
    GetTokenInformation(token, TokenUser, nullptr, 0, &token_size);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || token_size == 0) {
        CloseHandle(token);
        return INVALID_HANDLE_VALUE;
    }
    std::vector<unsigned char> token_buffer(token_size);
    if (!GetTokenInformation(token, TokenUser, token_buffer.data(), token_size, &token_size)) {
        CloseHandle(token);
        return INVALID_HANDLE_VALUE;
    }
    CloseHandle(token);

    LPWSTR user_sid{nullptr};
    if (!ConvertSidToStringSidW(
            reinterpret_cast<TOKEN_USER*>(token_buffer.data())->User.Sid, &user_sid)) {
        return INVALID_HANDLE_VALUE;
    }
    const std::wstring sddl = std::wstring{L"D:P(A;;GA;;;"} + user_sid + L")";
    LocalFree(user_sid);

    PSECURITY_DESCRIPTOR descriptor{nullptr};
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) {
        return INVALID_HANDLE_VALUE;
    }
    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.lpSecurityDescriptor = descriptor;
    attributes.bInheritHandle = FALSE;
    HANDLE pipe = CreateNamedPipeW(name.c_str(),
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1, buffer_size, buffer_size, 0, &attributes);
    LocalFree(descriptor);
    return pipe;
}

bool ConnectTestPipePair(TestPipePair& pair, vaqyron::rpc::PipeDeadline deadline = {})
{
    if (deadline == vaqyron::rpc::PipeDeadline{}) {
        deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    }
    pair.server = CreateTestPipeInstance(pair.name, 64);
    if (pair.server == INVALID_HANDLE_VALUE) return false;
    HANDLE stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!stop_event) return false;

    std::atomic<bool> connected{false};
    std::string error;
    std::thread connector([&] {
        connected.store(vaqyron::rpc::detail::ConnectPipeWithDeadline(
            pair.server, stop_event, deadline, error));
    });
    pair.client = CreateFileW(pair.name.c_str(), GENERIC_READ | GENERIC_WRITE, 0,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (pair.client == INVALID_HANDLE_VALUE) SetEvent(stop_event);
    connector.join();
    CloseHandle(stop_event);
    return pair.client != INVALID_HANDLE_VALUE && connected.load();
}

} // namespace
#endif

BOOST_FIXTURE_TEST_SUITE(rpc_named_pipe_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(default_pipe_mode_preserves_console_behavior)
{
    vaqyron::rpc::NamedPipeConfig config;
    bool pipe_only{true};
    std::string error;
    BOOST_CHECK(!config.enabled);
    BOOST_CHECK_EQUAL(config.request_timeout_ms, 30000);
    BOOST_CHECK(vaqyron::rpc::ValidatePipeMode(false, false, false, false, pipe_only, error));
    BOOST_CHECK(!pipe_only);

    vaqyron::rpc::RpcNamedPipeServer server{config};
    BOOST_CHECK(!server.Start(m_node, error));
    BOOST_CHECK(!server.IsRunning());
}

BOOST_AUTO_TEST_CASE(pipe_mode_requires_service_mode_testnet_and_no_http)
{
    bool pipe_only{false};
    std::string error;
    BOOST_CHECK(!vaqyron::rpc::ValidatePipeMode(true, false, true, false, pipe_only, error));
    BOOST_CHECK(!pipe_only);
    BOOST_CHECK(!vaqyron::rpc::ValidatePipeMode(false, true, true, false, pipe_only, error));
    BOOST_CHECK(!vaqyron::rpc::ValidatePipeMode(true, true, false, false, pipe_only, error));
    BOOST_CHECK(!vaqyron::rpc::ValidatePipeMode(true, true, true, true, pipe_only, error));
#ifdef WIN32
    BOOST_CHECK(vaqyron::rpc::ValidatePipeMode(true, true, true, false, pipe_only, error));
    BOOST_CHECK(pipe_only);
#else
    BOOST_CHECK(!vaqyron::rpc::ValidatePipeMode(true, true, true, false, pipe_only, error));
#endif
}

BOOST_AUTO_TEST_CASE(frame_size_boundaries_are_checked)
{
    std::string error;
    BOOST_CHECK(vaqyron::rpc::ValidatePipeFrameSize(1, 16, error));
    BOOST_CHECK(vaqyron::rpc::ValidatePipeFrameSize(16, 16, error));
    BOOST_CHECK(!vaqyron::rpc::ValidatePipeFrameSize(0, 16, error));
    BOOST_CHECK(!vaqyron::rpc::ValidatePipeFrameSize(17, 16, error));
    BOOST_CHECK(!vaqyron::rpc::ValidatePipeFrameSize(1, 0, error));
    BOOST_CHECK(vaqyron::rpc::ValidatePipeFrameSize(1024 * 1024, 1024 * 1024, error));
    BOOST_CHECK(!vaqyron::rpc::ValidatePipeFrameSize(1024 * 1024 + 1, 1024 * 1024, error));
}

BOOST_AUTO_TEST_CASE(fragmented_io_uses_one_absolute_deadline)
{
    using namespace std::chrono;
    const auto start = vaqyron::rpc::PipeDeadline{} + seconds{100};
    const auto deadline = start + milliseconds{vaqyron::rpc::DEFAULT_PIPE_REQUEST_TIMEOUT_MS};
    BOOST_CHECK_EQUAL(vaqyron::rpc::RemainingPipeTimeoutMs(deadline, start), 30000);
    BOOST_CHECK_EQUAL(vaqyron::rpc::RemainingPipeTimeoutMs(deadline, start + seconds{7}), 23000);
    BOOST_CHECK_EQUAL(vaqyron::rpc::RemainingPipeTimeoutMs(deadline, start + seconds{29}), 1000);
    BOOST_CHECK_EQUAL(vaqyron::rpc::RemainingPipeTimeoutMs(deadline, deadline), 0);
}

BOOST_AUTO_TEST_CASE(dispatch_admission_rejects_at_or_after_the_absolute_deadline)
{
    using namespace std::chrono;
    using vaqyron::rpc::PipeDeadline;
    const PipeDeadline deadline = PipeDeadline{} + seconds{100};
    const std::string message{
        R"({"jsonrpc":"2.0","method":"uptime","params":[],"id":1})"};

    for (const auto offset : {milliseconds{-1}, milliseconds{0}, milliseconds{1}}) {
        const PipeDeadline now = deadline + offset;
        int calls{0};
        std::string response;
        std::string error;
        const bool processed = vaqyron::rpc::DispatchRpcMessage(
            message, {}, [&](const JSONRPCRequest&) {
                ++calls;
                return UniValue{UniValue::VNUM, "1"};
            }, response, error, [&] {
                return vaqyron::rpc::detail::IsPipeDeadlineActive(deadline, now);
            });

        BOOST_CHECK_EQUAL(processed, offset < milliseconds{0});
        BOOST_CHECK_EQUAL(calls, offset < milliseconds{0} ? 1 : 0);
        if (offset >= milliseconds{0}) {
            BOOST_CHECK(response.empty());
            BOOST_CHECK(error.find("deadline expired") != std::string::npos);
        }
    }
}

BOOST_AUTO_TEST_CASE(deadline_expiry_after_frame_read_blocks_handler_admission)
{
    using namespace std::chrono;
    const auto deadline = vaqyron::rpc::PipeDeadline{} + seconds{100};
    auto now = deadline - milliseconds{1};
    BOOST_CHECK_EQUAL(vaqyron::rpc::RemainingPipeTimeoutMs(deadline, now), 1);
    BOOST_CHECK(vaqyron::rpc::detail::IsPipeDeadlineActive(deadline, now));
    int calls{0};
    std::string response;
    std::string error;
    now = deadline;
    BOOST_CHECK(!vaqyron::rpc::detail::IsPipeDeadlineActive(deadline, now));

    const bool processed = vaqyron::rpc::DispatchRpcMessage(
        R"({"jsonrpc":"2.0","method":"uptime","params":[],"id":1})", {},
        [&](const JSONRPCRequest&) {
            ++calls;
            return UniValue{UniValue::VNUM, "1"};
        }, response, error, [&] {
            return vaqyron::rpc::detail::IsPipeDeadlineActive(deadline, now);
        });

    BOOST_CHECK(!processed);
    BOOST_CHECK_EQUAL(calls, 0);
    BOOST_CHECK(response.empty());
}

BOOST_AUTO_TEST_CASE(late_handler_completion_does_not_initiate_response_write)
{
    using namespace std::chrono;
    const auto deadline = vaqyron::rpc::PipeDeadline{} + seconds{100};
    auto now = deadline - milliseconds{1};
    int writes{0};
    int calls{0};
    std::string response;
    std::string error;

    const bool processed = vaqyron::rpc::DispatchRpcMessage(
        R"({"jsonrpc":"2.0","method":"uptime","params":[],"id":1})", {},
        [&](const JSONRPCRequest&) {
            ++calls;
            now = deadline;
            return UniValue{UniValue::VNUM, "1"};
        }, response, error, [&] {
            return vaqyron::rpc::detail::IsPipeDeadlineActive(deadline, now);
        });

    BOOST_CHECK(processed);
    BOOST_CHECK_EQUAL(calls, 1);
    if (vaqyron::rpc::detail::ShouldWritePipeResponse(processed, false, deadline, now)) {
        ++writes;
    }
    BOOST_CHECK_EQUAL(writes, 0);
}

BOOST_AUTO_TEST_CASE(client_token_sid_and_pid_policy_rejects_missing_or_mismatched_values)
{
    std::string error;
    BOOST_CHECK(!vaqyron::rpc::ValidateClientIdentity(
        L"S-1-5-80-2", L"", L"S-1-5-80-2", 7, error));
    BOOST_CHECK(!vaqyron::rpc::ValidateClientIdentity(
        L"S-1-5-80-2", L"S-1-5-80-2", L"S-1-5-80-2", 0, error));
    BOOST_CHECK(!vaqyron::rpc::ValidateClientIdentity(
        L"S-1-5-80-2", L"S-1-5-80-3", L"S-1-5-80-3", 7, error));
    BOOST_CHECK(!vaqyron::rpc::ValidateClientIdentity(
        L"S-1-5-80-2", L"S-1-5-80-2", L"S-1-5-80-3", 7, error));
    BOOST_CHECK(vaqyron::rpc::ValidateClientIdentity(
        L"S-1-5-80-2", L"S-1-5-80-2", L"S-1-5-80-2", 7, error));
}

BOOST_AUTO_TEST_CASE(only_preflight_methods_are_allowed)
{
    const std::vector<std::string> expected{"validateaddress", "uptime"};
    BOOST_CHECK(vaqyron::rpc::AllowedRpcMethods() == expected);
    BOOST_CHECK(vaqyron::rpc::IsRpcMethodAllowed("uptime"));
    BOOST_CHECK(vaqyron::rpc::IsRpcMethodAllowed("validateaddress"));
    BOOST_CHECK(!vaqyron::rpc::IsRpcMethodAllowed("getblock"));
    BOOST_CHECK(!vaqyron::rpc::IsRpcMethodAllowed("getblockhash"));
    BOOST_CHECK(!vaqyron::rpc::IsRpcMethodAllowed("getblockheader"));
    BOOST_CHECK(!vaqyron::rpc::IsRpcMethodAllowed("getblockchaininfo"));
    BOOST_CHECK(!vaqyron::rpc::IsRpcMethodAllowed("getdifficulty"));
    BOOST_CHECK(!vaqyron::rpc::IsRpcMethodAllowed("getnetworkinfo"));
    BOOST_CHECK(!vaqyron::rpc::IsRpcMethodAllowed("getrawmempool"));
    BOOST_CHECK(!vaqyron::rpc::IsRpcMethodAllowed("getmininginfo"));
    BOOST_CHECK(!vaqyron::rpc::IsRpcMethodAllowed("getchaintips"));
    BOOST_CHECK(!vaqyron::rpc::IsRpcMethodAllowed("getbestblockhash"));
    BOOST_CHECK(!vaqyron::rpc::IsRpcMethodAllowed("getconnectioncount"));
    BOOST_CHECK(!vaqyron::rpc::IsRpcMethodAllowed("getblocktemplate"));
    BOOST_CHECK(!vaqyron::rpc::IsRpcMethodAllowed("submitblock"));
    BOOST_CHECK(!vaqyron::rpc::IsRpcMethodAllowed("sendtoaddress"));
    BOOST_CHECK(!vaqyron::rpc::IsRpcMethodAllowed("dumpwallet"));
    BOOST_CHECK(!vaqyron::rpc::IsRpcMethodAllowed("walletpassphrase"));
    BOOST_CHECK(!vaqyron::rpc::IsRpcMethodAllowed("stop"));
    BOOST_CHECK(!vaqyron::rpc::IsRpcMethodAllowed("getrpcinfo"));
}

BOOST_AUTO_TEST_CASE(unauthorized_methods_are_rejected_before_dispatch)
{
    for (const auto& method : {"getblocktemplate", "submitblock", "sendtoaddress",
             "dumpwallet", "walletpassphrase", "stop", "getrpcinfo", "getblockchaininfo"}) {
        int calls{0};
        std::string response;
        std::string error;
        const std::string message =
            R"({"jsonrpc":"2.0","method":")" + std::string{method} +
            R"(","params":[],"id":1})";

        BOOST_CHECK(vaqyron::rpc::DispatchRpcMessage(message, {}, [&](const JSONRPCRequest&) {
            ++calls;
            return UniValue{UniValue::VSTR, "unexpected dispatch"};
        }, response, error));
        BOOST_CHECK_EQUAL(calls, 0);
        BOOST_CHECK(response.find("Method is not available") != std::string::npos);
    }
}

BOOST_AUTO_TEST_CASE(long_poll_requests_are_rejected_before_dispatch)
{
    int calls{0};
    std::string response;
    std::string error;
    const std::string message{
        R"({"jsonrpc":"2.0","method":"getblocktemplate","params":[{"longpollid":"tip"}],"id":3})"};

    BOOST_CHECK(vaqyron::rpc::DispatchRpcMessage(message, {}, [&](const JSONRPCRequest&) {
        ++calls;
        return UniValue{UniValue::VSTR, "unexpected dispatch"};
    }, response, error));
    BOOST_CHECK_EQUAL(calls, 0);
    BOOST_CHECK(response.find("Method is not available") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(allowlisted_method_is_parsed_and_dispatched_with_context)
{
    int context_marker{42};
    int calls{0};
    std::string response;
    std::string error;
    const std::string message{
        R"({"jsonrpc":"2.0","method":"uptime","params":[],"id":2})"};

    BOOST_CHECK(vaqyron::rpc::DispatchRpcMessage(message, &context_marker,
        [&](const JSONRPCRequest& request) {
            ++calls;
            BOOST_CHECK(std::any_cast<int*>(request.context) == &context_marker);
            return UniValue{UniValue::VSTR, "dispatched"};
        }, response, error));
    BOOST_CHECK_EQUAL(calls, 1);
    BOOST_CHECK_EQUAL(response, "\"dispatched\"");
}

BOOST_AUTO_TEST_CASE(malformed_notification_and_batch_requests_are_rejected)
{
    std::string response;
    std::string error;
    int calls{0};
    const auto dispatch = [&](const JSONRPCRequest&) {
        ++calls;
        return UniValue{UniValue::VSTR, "unexpected dispatch"};
    };

    BOOST_CHECK(!vaqyron::rpc::DispatchRpcMessage("not-json", {}, dispatch, response, error));
    BOOST_CHECK(vaqyron::rpc::DispatchRpcMessage("[]", {}, dispatch, response, error));
    BOOST_CHECK(response.find("Batch requests are not supported") != std::string::npos);
    BOOST_CHECK(vaqyron::rpc::DispatchRpcMessage(
        R"({"jsonrpc":"2.0","method":"uptime","params":[]})", {}, dispatch, response, error));
    BOOST_CHECK(response.find("Notifications are not supported") != std::string::npos);
    BOOST_CHECK_EQUAL(calls, 0);
}

BOOST_AUTO_TEST_CASE(pipe_shutdown_is_idempotent_without_a_listener)
{
    vaqyron::rpc::NamedPipeConfig config;
    vaqyron::rpc::RpcNamedPipeServer server{config};
    BOOST_CHECK(server.Stop());
    BOOST_CHECK(server.Stop());
    BOOST_CHECK(!server.IsRunning());
}

BOOST_AUTO_TEST_CASE(registry_rejects_start_while_stop_callback_owns_worker)
{
    vaqyron::rpc::detail::PipeRegistryStateMachine registry;
    BOOST_REQUIRE(registry.Start([] { return true; }));

    std::promise<void> stop_entered;
    std::promise<void> release_stop;
    const auto release = release_stop.get_future().share();
    std::thread stopping([&] {
        registry.Stop([&] {
            stop_entered.set_value();
            release.wait();
        });
    });
    stop_entered.get_future().wait();
    BOOST_CHECK(registry.state() == vaqyron::rpc::detail::PipeRegistryState::Stopping);

    auto starting = std::async(std::launch::async, [&] {
        return registry.Start([] { return true; });
    });
    const bool start_returned_during_stop =
        starting.wait_for(std::chrono::seconds{1}) == std::future_status::ready;
    release_stop.set_value();
    stopping.join();
    BOOST_CHECK(start_returned_during_stop);
    BOOST_CHECK(!starting.get());
    BOOST_CHECK(registry.state() == vaqyron::rpc::detail::PipeRegistryState::Stopped);
}

BOOST_AUTO_TEST_CASE(dispatch_remains_synchronous_until_handler_returns)
{
    std::mutex mutex;
    std::condition_variable condition;
    bool entered{false};
    bool release{false};
    std::atomic<bool> completed{false};
    std::string response;
    std::string error;

    std::thread dispatch([&] {
        vaqyron::rpc::DispatchRpcMessage(
            R"({"jsonrpc":"2.0","method":"uptime","params":[],"id":1})", {},
            [&](const JSONRPCRequest&) {
                std::unique_lock lock{mutex};
                entered = true;
                condition.notify_all();
                condition.wait(lock, [&] { return release; });
                return UniValue{UniValue::VNUM, "1"};
            }, response, error);
        completed.store(true);
    });
    {
        std::unique_lock lock{mutex};
        condition.wait(lock, [&] { return entered; });
        BOOST_CHECK(!completed.load());
        release = true;
    }
    condition.notify_all();
    dispatch.join();
    BOOST_CHECK(completed.load());
}

#ifdef WIN32
BOOST_AUTO_TEST_CASE(fragmented_request_and_response_share_one_deadline)
{
    using namespace std::chrono;
    const auto deadline = steady_clock::now() + milliseconds{
        vaqyron::rpc::DEFAULT_PIPE_REQUEST_TIMEOUT_MS};
    TestPipePair pair;
    BOOST_REQUIRE(ConnectTestPipePair(pair, deadline));
    HANDLE stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    BOOST_REQUIRE(stop_event);

    std::array<char, 8> request{};
    std::atomic<bool> read_result{false};
    std::string read_error;
    std::thread reader([&] {
        read_result.store(vaqyron::rpc::detail::TransferPipeWithDeadline(
            pair.server, stop_event, deadline, request.data(),
            static_cast<std::uint32_t>(request.size()), true, read_error));
    });
    const char request_first[] = {'r', 'e', 'q', '1'};
    const char request_second[] = {'r', 'e', 'q', '2'};
    DWORD transferred{0};
    const bool wrote_first = WriteFile(
        pair.client, request_first, sizeof(request_first), &transferred, nullptr) != FALSE;
    if (wrote_first) {
        Sleep(100);
        if (!WriteFile(pair.client, request_second, sizeof(request_second), &transferred, nullptr)) {
            SetEvent(stop_event);
        }
    } else {
        SetEvent(stop_event);
    }
    reader.join();
    BOOST_CHECK(wrote_first);
    BOOST_CHECK(read_result.load());
    const std::string received_request(request.data(), request.size());
    BOOST_CHECK_EQUAL(received_request, "req1req2");

    char response[] = "resp1234";
    std::atomic<bool> write_result{false};
    std::string write_error;
    std::thread writer([&] {
        write_result.store(vaqyron::rpc::detail::TransferPipeWithDeadline(
            pair.server, stop_event, deadline, response,
            static_cast<std::uint32_t>(sizeof(response) - 1), false, write_error));
    });
    Sleep(100);
    std::array<char, 4> response_first{};
    const bool read_first = ReadFile(pair.client, response_first.data(),
        static_cast<DWORD>(response_first.size()), &transferred, nullptr) != FALSE;
    std::array<char, 4> response_second{};
    bool read_second{false};
    if (read_first) {
        Sleep(100);
        read_second = ReadFile(pair.client, response_second.data(),
            static_cast<DWORD>(response_second.size()), &transferred, nullptr) != FALSE;
    } else {
        SetEvent(stop_event);
    }
    writer.join();
    BOOST_CHECK(read_first);
    BOOST_CHECK(read_second);
    BOOST_CHECK(write_result.load());
    const std::string received_response =
        std::string(response_first.data(), response_first.size()) +
        std::string(response_second.data(), response_second.size());
    BOOST_CHECK_EQUAL(received_response, "resp1234");
    CloseHandle(stop_event);
}

BOOST_AUTO_TEST_CASE(pending_connect_read_and_write_are_cancelled_before_return)
{
    using namespace std::chrono;
    HANDLE stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    BOOST_REQUIRE(stop_event);

    std::wstring pipe_name;
    HANDLE pending_pipe = CreateTestPipeInstance(pipe_name, 64);
    BOOST_REQUIRE(pending_pipe != INVALID_HANDLE_VALUE);
    std::atomic<bool> connect_result{true};
    std::string connect_error;
    std::thread connector([&] {
        connect_result.store(vaqyron::rpc::detail::ConnectPipeWithDeadline(
            pending_pipe, stop_event, steady_clock::now() + seconds{30}, connect_error));
    });
    Sleep(50);
    BOOST_CHECK(SetEvent(stop_event));
    connector.join();
    BOOST_CHECK(!connect_result.load());
    CloseHandle(pending_pipe);
    CloseHandle(stop_event);

    TestPipePair read_pair;
    BOOST_REQUIRE(ConnectTestPipePair(read_pair));
    stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    BOOST_REQUIRE(stop_event);
    std::atomic<bool> read_result{true};
    std::atomic<bool> read_finished{false};
    char byte{0};
    std::string read_error;
    std::thread reader([&] {
        read_result.store(vaqyron::rpc::detail::TransferPipeWithDeadline(
            read_pair.server, stop_event, steady_clock::now() + seconds{30},
            &byte, 1, true, read_error));
        read_finished.store(true);
    });
    Sleep(50);
    BOOST_CHECK(!read_finished.load());
    BOOST_CHECK(SetEvent(stop_event));
    reader.join();
    BOOST_CHECK(!read_result.load());
    CloseHandle(stop_event);

    TestPipePair write_pair;
    BOOST_REQUIRE(ConnectTestPipePair(write_pair));
    stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    BOOST_REQUIRE(stop_event);
    std::vector<unsigned char> payload(8 * 1024 * 1024, 0x5a);
    std::atomic<bool> write_result{true};
    std::atomic<bool> write_finished{false};
    std::string write_error;
    std::thread writer([&] {
        write_result.store(vaqyron::rpc::detail::TransferPipeWithDeadline(
            write_pair.server, stop_event, steady_clock::now() + seconds{30},
            payload.data(), static_cast<std::uint32_t>(payload.size()), false, write_error));
        write_finished.store(true);
    });
    Sleep(50);
    BOOST_CHECK(!write_finished.load());
    BOOST_CHECK(SetEvent(stop_event));
    writer.join();
    BOOST_CHECK(!write_result.load());
    CloseHandle(stop_event);
}

BOOST_AUTO_TEST_CASE(protected_pipe_dacl_contains_only_the_two_service_sids)
{
    const std::wstring core_sid{L"S-1-5-80-1-2-3-4-5"};
    const std::wstring miner_sid{L"S-1-5-80-1-2-3-4-6"};
    void* descriptor{nullptr};
    std::string error;

    BOOST_REQUIRE(vaqyron::rpc::BuildProtectedPipeSecurityDescriptor(
        core_sid, miner_sid, descriptor, error));
    BOOST_CHECK(vaqyron::rpc::ValidateProtectedPipeSecurityDescriptor(
        descriptor, core_sid, miner_sid, error));
    vaqyron::rpc::FreePipeSecurityDescriptor(descriptor);
}

BOOST_AUTO_TEST_CASE(protected_pipe_dacl_rejects_missing_and_well_known_broad_sids)
{
    void* descriptor{nullptr};
    std::string error;
    BOOST_CHECK(!vaqyron::rpc::BuildProtectedPipeSecurityDescriptor(
        L"", L"S-1-5-80-1-2-3-4-6", descriptor, error));
    BOOST_CHECK(!vaqyron::rpc::BuildProtectedPipeSecurityDescriptor(
        L"S-1-5-80-1-2-3-4-5", L"S-1-1-0", descriptor, error));
    BOOST_CHECK(!vaqyron::rpc::BuildProtectedPipeSecurityDescriptor(
        L"S-1-5-80-1-2-3-4-5", L"S-1-5-11", descriptor, error));
}

BOOST_AUTO_TEST_CASE(win32_pipe_fixture_creates_and_closes_a_protected_pipe_handle)
{
    const std::wstring core_sid{L"S-1-5-80-1-2-3-4-5"};
    const std::wstring miner_sid{L"S-1-5-80-1-2-3-4-6"};
    void* descriptor{nullptr};
    std::string error;
    BOOST_REQUIRE(vaqyron::rpc::BuildProtectedPipeSecurityDescriptor(
        core_sid, miner_sid, descriptor, error));

    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.lpSecurityDescriptor = descriptor;
    attributes.bInheritHandle = FALSE;
    const std::wstring pipe_name = L"\\\\.\\pipe\\vaqyron-test-fixture-" +
        std::to_wstring(GetCurrentProcessId());
    HANDLE pipe = CreateNamedPipeW(pipe_name.c_str(),
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1, 64, 64, 1000, &attributes);
    const bool created = pipe != INVALID_HANDLE_VALUE;
    if (created) BOOST_CHECK(CloseHandle(pipe));
    vaqyron::rpc::FreePipeSecurityDescriptor(descriptor);
    BOOST_REQUIRE(created);
}
#endif

BOOST_AUTO_TEST_SUITE_END()
