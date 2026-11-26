// Copyright (c) 2026-present The VAQYRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <rpc/rpc_named_pipe.h>

#include <chainparams.h>
#include <common/args.h>
#include <logging.h>
#include <node/context.h>
#include <rpc/protocol.h>
#include <rpc/server.h>
#include <util/chaintype.h>
#include <winservice.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <limits>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#ifdef WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <sddl.h>
#endif

namespace vaqyron::rpc {

namespace {

constexpr wchar_t PIPE_NAME[] = L"\\\\.\\pipe\\vaqyron-testnet-rpc-v1";
constexpr wchar_t CORE_ACCOUNT[] = L"NT SERVICE\\VAQYRONTestnetCoreDev";
constexpr wchar_t MINER_ACCOUNT[] = L"NT SERVICE\\VAQYRONMinerDev";
constexpr std::size_t MAX_FRAME_SIZE = 1024 * 1024;
constexpr unsigned int MAX_REQUEST_TIMEOUT_MS = DEFAULT_PIPE_REQUEST_TIMEOUT_MS;
constexpr std::uint32_t IO_COMPLETION_POLL_MS = 2000;

std::wstring WidenAscii(const std::string& value)
{
    return {value.begin(), value.end()};
}

#ifdef WIN32
constexpr DWORD PIPE_CLIENT_ACCESS = FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE;

bool SidToText(PSID sid, std::wstring& text);

bool ResolveAccountSid(const std::wstring& account, std::wstring& sid_text, std::string& error)
{
    DWORD sid_size{0};
    DWORD domain_size{0};
    SID_NAME_USE sid_type{};
    LookupAccountNameW(nullptr, account.c_str(), nullptr, &sid_size, nullptr, &domain_size, &sid_type);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || sid_size == 0) {
        error = "Required Windows service account is unavailable";
        return false;
    }

    std::vector<unsigned char> sid(sid_size);
    std::vector<wchar_t> domain(domain_size);
    if (!LookupAccountNameW(nullptr, account.c_str(), sid.data(), &sid_size,
            domain.data(), &domain_size, &sid_type)) {
        error = "Required Windows service account could not be resolved";
        return false;
    }

    LPWSTR text{nullptr};
    if (!ConvertSidToStringSidW(sid.data(), &text)) {
        error = "Unable to format the resolved Windows service identity";
        return false;
    }
    sid_text = text;
    LocalFree(text);
    error.clear();
    return true;
}

bool VerifyServiceSidConfigured(const wchar_t* service_name, std::string& error)
{
    SC_HANDLE manager{OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT)};
    if (!manager) {
        error = "Unable to inspect the local Service Control Manager";
        return false;
    }
    SC_HANDLE service{OpenServiceW(manager, service_name, SERVICE_QUERY_CONFIG)};
    if (!service) {
        CloseServiceHandle(manager);
        error = "Required Windows service identity is not provisioned";
        return false;
    }

    DWORD required_size{0};
    QueryServiceConfig2W(service, SERVICE_CONFIG_SERVICE_SID_INFO, nullptr, 0, &required_size);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || required_size < sizeof(SERVICE_SID_INFO)) {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
        error = "Unable to inspect the required Windows service SID configuration";
        return false;
    }
    std::vector<unsigned char> buffer(required_size);
    const bool queried = QueryServiceConfig2W(service, SERVICE_CONFIG_SERVICE_SID_INFO,
        buffer.data(), required_size, &required_size) != FALSE;
    const DWORD sid_type = queried ?
        reinterpret_cast<const SERVICE_SID_INFO*>(buffer.data())->dwServiceSidType :
        SERVICE_SID_TYPE_NONE;
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    if (!queried || sid_type == SERVICE_SID_TYPE_NONE) {
        error = "Required Windows service is not configured to use its service SID";
        return false;
    }
    error.clear();
    return true;
}

bool IsForbiddenSid(PSID sid)
{
    for (const WELL_KNOWN_SID_TYPE type : {
             WinWorldSid,
             WinBuiltinUsersSid,
             WinAnonymousSid,
             WinAuthenticatedUserSid,
         }) {
        DWORD size{SECURITY_MAX_SID_SIZE};
        std::array<unsigned char, SECURITY_MAX_SID_SIZE> storage{};
        if (CreateWellKnownSid(type, nullptr, storage.data(), &size) &&
            EqualSid(sid, storage.data())) {
            return true;
        }
    }
    return false;
}

bool IsServiceSid(PSID sid)
{
    const SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
    return IsValidSid(sid) &&
        std::memcmp(GetSidIdentifierAuthority(sid), &nt_authority, sizeof(nt_authority)) == 0 &&
        *GetSidSubAuthorityCount(sid) == 6 &&
        *GetSidSubAuthority(sid, 0) == SECURITY_SERVICE_ID_BASE_RID;
}

bool ReadServiceSidMembership(HANDLE token, PSID expected_sid, std::wstring& membership_sid)
{
    DWORD size{0};
    GetTokenInformation(token, TokenGroups, nullptr, 0, &size);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || size == 0) return false;
    std::vector<unsigned char> buffer(size);
    if (!GetTokenInformation(token, TokenGroups, buffer.data(), size, &size)) return false;

    const auto* groups = reinterpret_cast<const TOKEN_GROUPS*>(buffer.data());
    for (DWORD index{0}; index < groups->GroupCount; ++index) {
        const SID_AND_ATTRIBUTES& group = groups->Groups[index];
        if ((group.Attributes & SE_GROUP_ENABLED) != 0 &&
            (group.Attributes & SE_GROUP_USE_FOR_DENY_ONLY) == 0 &&
            EqualSid(group.Sid, expected_sid)) {
            return SidToText(group.Sid, membership_sid);
        }
    }
    return false;
}

bool SidToText(PSID sid, std::wstring& text)
{
    LPWSTR sid_text{nullptr};
    if (!ConvertSidToStringSidW(sid, &sid_text)) return false;
    text = sid_text;
    LocalFree(sid_text);
    return true;
}

bool VerifyClientIdentity(HANDLE pipe, const std::wstring& expected_sid, bool& fatal_error,
    std::string& error)
{
    fatal_error = false;
    ULONG client_pid{0};
    if (!GetNamedPipeClientProcessId(pipe, &client_pid) || client_pid == 0) {
        error = "Unable to identify the connected pipe client process";
        return false;
    }

    PSID expected{nullptr};
    if (!ConvertStringSidToSidW(expected_sid.c_str(), &expected)) {
        error = "Configured Miner service SID is invalid";
        return false;
    }

    bool authenticated{false};
    if (!ImpersonateNamedPipeClient(pipe)) {
        LocalFree(expected);
        error = "Unable to impersonate the connected pipe client";
        return false;
    }

    HANDLE impersonation_token{nullptr};
    std::wstring impersonated_sid_text;
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &impersonation_token) &&
        ReadServiceSidMembership(impersonation_token, expected, impersonated_sid_text)) {
        HANDLE process{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, client_pid)};
        HANDLE process_token{nullptr};
        std::wstring process_sid_text;
        if (process && OpenProcessToken(process, TOKEN_QUERY, &process_token) &&
            ReadServiceSidMembership(process_token, expected, process_sid_text)) {
            authenticated = ValidateClientIdentity(
                expected_sid, impersonated_sid_text, process_sid_text, client_pid, error);
        }
        if (process_token) CloseHandle(process_token);
        if (process) CloseHandle(process);
    }

    const BOOL reverted{RevertToSelf()};
    if (impersonation_token) CloseHandle(impersonation_token);
    LocalFree(expected);
    if (!reverted) {
        fatal_error = true;
        error = "Unable to revert the pipe client impersonation token";
        return false;
    }
    if (!authenticated) {
        error = "Connected pipe client identity verification failed";
        return false;
    }
    error.clear();
    return true;
}

void DrainCancelledOperation(HANDLE pipe, OVERLAPPED& operation, DWORD& transferred)
{
    bool wait_failure_logged{false};
    for (;;) {
        DWORD completed{0};
        if (GetOverlappedResult(pipe, &operation, &completed, FALSE)) {
            transferred = completed;
            return;
        }
        if (GetLastError() != ERROR_IO_INCOMPLETE) {
            transferred = completed;
            return;
        }

        if (WaitForSingleObject(operation.hEvent, IO_COMPLETION_POLL_MS) == WAIT_FAILED) {
            if (!wait_failure_logged) {
                LogError("Unable to wait for cancelled Named Pipe I/O completion (error %lu)",
                    GetLastError());
                wait_failure_logged = true;
            }
            Sleep(50);
        }
    }
}

void CancelAndDrainOperation(HANDLE pipe, OVERLAPPED& operation, DWORD& transferred)
{
    if (!CancelIoEx(pipe, &operation)) {
        const DWORD error = GetLastError();
        if (error != ERROR_NOT_FOUND) {
            LogError("Unable to cancel a Named Pipe operation (error %lu)", error);
        }
    }
    DrainCancelledOperation(pipe, operation, transferred);
}

bool Transfer(HANDLE pipe, HANDLE stop_event, PipeDeadline deadline, void* data,
    DWORD size, bool read, std::string& error)
{
    auto* bytes = static_cast<unsigned char*>(data);
    DWORD offset{0};
    while (offset < size) {
        const DWORD wait_timeout = RemainingPipeTimeoutMs(deadline, std::chrono::steady_clock::now());
        if (wait_timeout == 0) {
            error = "Named Pipe request deadline expired";
            return false;
        }
        OVERLAPPED operation{};
        operation.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!operation.hEvent) {
            error = "Unable to create a pipe I/O event";
            return false;
        }

        DWORD transferred{0};
        const BOOL immediate = read ?
            ReadFile(pipe, bytes + offset, size - offset, &transferred, &operation) :
            WriteFile(pipe, bytes + offset, size - offset, &transferred, &operation);
        DWORD io_error{NO_ERROR};
        if (!immediate) io_error = GetLastError();

        bool succeeded{immediate != FALSE};
        if (!immediate && io_error == ERROR_IO_PENDING) {
            HANDLE waits[]{stop_event, operation.hEvent};
            const DWORD wait_result = WaitForMultipleObjects(2, waits, FALSE, wait_timeout);
            if (wait_result == WAIT_OBJECT_0) {
                CancelAndDrainOperation(pipe, operation, transferred);
                succeeded = false;
                error = "Named Pipe operation cancelled";
            } else if (wait_result == WAIT_OBJECT_0 + 1) {
                succeeded = GetOverlappedResult(pipe, &operation, &transferred, FALSE) != FALSE;
                if (!succeeded && GetLastError() == ERROR_IO_INCOMPLETE) {
                    CancelAndDrainOperation(pipe, operation, transferred);
                }
            } else {
                CancelAndDrainOperation(pipe, operation, transferred);
                succeeded = false;
                error = wait_result == WAIT_TIMEOUT ? "Named Pipe operation timed out" :
                    "Named Pipe operation wait failed";
            }
        } else if (!immediate) {
            error = "Named Pipe I/O failed";
        }

        CloseHandle(operation.hEvent);
        if (!succeeded || transferred == 0) {
            if (error.empty()) error = "Named Pipe operation failed or the connection closed";
            return false;
        }
        offset += transferred;
        if (RemainingPipeTimeoutMs(deadline, std::chrono::steady_clock::now()) == 0) {
            error = "Named Pipe request deadline expired";
            return false;
        }
    }
    return true;
}

HANDLE CreatePipeInstance(void* security_descriptor, std::string& error)
{
    SECURITY_ATTRIBUTES security_attributes{};
    security_attributes.nLength = sizeof(security_attributes);
    security_attributes.lpSecurityDescriptor = security_descriptor;
    security_attributes.bInheritHandle = FALSE;

    HANDLE pipe = CreateNamedPipeW(
        PIPE_NAME,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1,
        static_cast<DWORD>(MAX_FRAME_SIZE + sizeof(uint32_t)),
        static_cast<DWORD>(MAX_FRAME_SIZE + sizeof(uint32_t)),
        MAX_REQUEST_TIMEOUT_MS,
        &security_attributes);
    if (pipe == INVALID_HANDLE_VALUE) {
        error = "Unable to create the protected local Named Pipe";
    }
    return pipe;
}

bool ConnectPipe(HANDLE pipe, HANDLE stop_event, PipeDeadline deadline, std::string& error)
{
    if (RemainingPipeTimeoutMs(deadline, std::chrono::steady_clock::now()) == 0) {
        error = "Named Pipe connection attempt timed out";
        return false;
    }
    OVERLAPPED operation{};
    operation.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!operation.hEvent) {
        error = "Unable to create a pipe connection event";
        return false;
    }

    BOOL connected{ConnectNamedPipe(pipe, &operation)};
    DWORD connect_error{connected ? NO_ERROR : GetLastError()};
    if (connected) {
        CloseHandle(operation.hEvent);
        if (RemainingPipeTimeoutMs(deadline, std::chrono::steady_clock::now()) == 0) {
            error = "Named Pipe connection attempt timed out";
            return false;
        }
        return true;
    }
    if (!connected && connect_error == ERROR_PIPE_CONNECTED) {
        CloseHandle(operation.hEvent);
        if (RemainingPipeTimeoutMs(deadline, std::chrono::steady_clock::now()) == 0) {
            error = "Named Pipe connection attempt timed out";
            return false;
        }
        return true;
    }
    if (!connected && connect_error != ERROR_IO_PENDING) {
        CloseHandle(operation.hEvent);
        error = "Named Pipe connection failed";
        return false;
    }

    HANDLE waits[]{stop_event, operation.hEvent};
    const DWORD wait_timeout = RemainingPipeTimeoutMs(deadline, std::chrono::steady_clock::now());
    const DWORD wait_result = WaitForMultipleObjects(2, waits, FALSE, wait_timeout);
    bool success{false};
    if (wait_result == WAIT_OBJECT_0) {
        DWORD ignored{0};
        CancelAndDrainOperation(pipe, operation, ignored);
        error = "Named Pipe connection cancelled";
    } else if (wait_result == WAIT_OBJECT_0 + 1) {
        DWORD ignored{0};
        success = GetOverlappedResult(pipe, &operation, &ignored, FALSE) != FALSE;
        const DWORD completion_error = success ? NO_ERROR : GetLastError();
        if (!success && completion_error == ERROR_IO_INCOMPLETE) {
            CancelAndDrainOperation(pipe, operation, ignored);
            error = "Named Pipe connection completion is still pending";
        } else if (!success && completion_error == ERROR_PIPE_CONNECTED) {
            success = true;
        } else if (!success && completion_error != ERROR_PIPE_CONNECTED) {
            error = "Named Pipe connection failed";
        }
    } else {
        DWORD ignored{0};
        CancelAndDrainOperation(pipe, operation, ignored);
        error = wait_result == WAIT_TIMEOUT ? "Named Pipe connection attempt timed out" :
            "Named Pipe connection wait failed";
    }
    CloseHandle(operation.hEvent);
    if (success && RemainingPipeTimeoutMs(deadline, std::chrono::steady_clock::now()) == 0) {
        error = "Named Pipe connection attempt timed out";
        return false;
    }
    return success;
}

#endif

} // namespace

#ifdef WIN32
namespace detail {

bool ConnectPipeWithDeadline(void* pipe, void* stop_event, PipeDeadline deadline, std::string& error)
{
    return ConnectPipe(static_cast<HANDLE>(pipe), static_cast<HANDLE>(stop_event), deadline, error);
}

bool TransferPipeWithDeadline(void* pipe, void* stop_event, PipeDeadline deadline, void* data,
    std::uint32_t size, bool read, std::string& error)
{
    return Transfer(static_cast<HANDLE>(pipe), static_cast<HANDLE>(stop_event),
        deadline, data, static_cast<DWORD>(size), read, error);
}

} // namespace detail
#endif

bool IsPipeFeatureEnabled(const ArgsManager& args)
{
    return args.GetBoolArg("-rpcnamedpipe", false);
}

bool ValidatePipeMode(bool enabled, bool service_mode, bool testnet, bool http_requested,
    bool& pipe_only, std::string& error)
{
    pipe_only = false;
    if (!enabled && !service_mode) {
        error.clear();
        return true;
    }
    if (!enabled || !service_mode) {
        error = "Windows service mode and Named Pipe RPC must be enabled together";
        return false;
    }
    if (!testnet) {
        error = "Named Pipe RPC is restricted to VAQYRON TESTNET";
        return false;
    }
#ifndef WIN32
    error = "Windows Named Pipe RPC is unsupported on this platform";
    return false;
#endif
    if (http_requested) {
        error = "HTTP RPC options are incompatible with pipe-only mode";
        return false;
    }
    pipe_only = true;
    error.clear();
    return true;
}

bool ValidatePipeFrameSize(std::size_t frame_size, std::size_t maximum, std::string& error)
{
    if (frame_size == 0 || maximum == 0 || frame_size > maximum) {
        error = "Named Pipe frame length is outside the configured limit";
        return false;
    }
    error.clear();
    return true;
}

unsigned int RemainingPipeTimeoutMs(PipeDeadline deadline, PipeDeadline now)
{
    if (now >= deadline) return 0;
    const auto remaining = deadline - now;
    auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(remaining);
    if (std::chrono::duration_cast<PipeDeadline::duration>(milliseconds) < remaining) {
        milliseconds += std::chrono::milliseconds{1};
    }
    return static_cast<unsigned int>(std::min<std::int64_t>(
        milliseconds.count(), std::numeric_limits<unsigned int>::max()));
}

bool ValidateClientIdentity(const std::wstring& expected_sid, const std::wstring& impersonated_token_sid,
    const std::wstring& process_token_sid, std::uint32_t client_pid, std::string& error)
{
    if (expected_sid.empty() || impersonated_token_sid.empty() || process_token_sid.empty()) {
        error = "Expected service SID or connected client token SID is missing";
        return false;
    }
    if (client_pid == 0) {
        error = "Connected client PID is invalid";
        return false;
    }
    if (impersonated_token_sid != expected_sid || process_token_sid != impersonated_token_sid) {
        error = "Connected client token identity does not match the expected Miner service SID";
        return false;
    }
    error.clear();
    return true;
}

bool IsRpcMethodAllowed(const std::string& method)
{
    static const std::vector<std::string> allowed{
        "validateaddress",
        "uptime",
    };
    return std::find(allowed.begin(), allowed.end(), method) != allowed.end();
}

namespace {

bool IsLongPollRequest(const JSONRPCRequest& request)
{
    if (request.params.isObject()) return request.params.exists("longpollid");
    if (request.params.isArray() && request.params.size() > 0) {
        const UniValue& options = request.params[0];
        return options.isObject() && options.exists("longpollid");
    }
    return false;
}

} // namespace

std::vector<std::string> AllowedRpcMethods()
{
    return {
        "validateaddress",
        "uptime",
    };
}

bool DispatchRpcMessage(const std::string& message, const std::any& context,
    const RpcDispatchCallback& dispatch, std::string& response, std::string& error,
    const RpcDispatchAdmission& admit_dispatch)
{
    UniValue request_value;
    if (!request_value.read(message)) {
        error = "Malformed JSON-RPC request";
        return false;
    }
    if (request_value.isArray()) {
        response = JSONRPCReplyObj(NullUniValue,
            JSONRPCError(RPC_INVALID_REQUEST, "Batch requests are not supported"),
            std::nullopt, JSONRPCVersion::V2).write();
        error.clear();
        return true;
    }

    JSONRPCRequest request;
    try {
        request.parse(request_value);
        if (!request.id.has_value()) {
            response = JSONRPCReplyObj(NullUniValue,
                JSONRPCError(RPC_INVALID_REQUEST, "Notifications are not supported"),
                std::nullopt, request.m_json_version).write();
            error.clear();
            return true;
        }
        if (!IsRpcMethodAllowed(request.strMethod)) {
            response = JSONRPCReplyObj(NullUniValue,
                JSONRPCError(RPC_METHOD_NOT_FOUND, "Method is not available on the Miner endpoint"),
                request.id, request.m_json_version).write();
            error.clear();
            return true;
        }
        if (request.strMethod == "getblocktemplate" && IsLongPollRequest(request)) {
            response = JSONRPCReplyObj(NullUniValue,
                JSONRPCError(RPC_INVALID_PARAMETER, "Long polling is not available on the Miner endpoint"),
                request.id, request.m_json_version).write();
            error.clear();
            return true;
        }

        request.context = context;
        if (admit_dispatch && !admit_dispatch()) {
            response.clear();
            error = "Named Pipe request deadline expired before RPC dispatch";
            return false;
        }
        response = dispatch(request).write();
        error.clear();
        return true;
    } catch (UniValue& rpc_error) {
        response = JSONRPCReplyObj(NullUniValue, std::move(rpc_error),
            request.id, request.m_json_version).write();
        error.clear();
        return true;
    } catch (const std::exception& exception) {
        response = JSONRPCReplyObj(NullUniValue,
            JSONRPCError(RPC_MISC_ERROR, exception.what()), request.id, request.m_json_version).write();
        error.clear();
        return true;
    }
}

namespace detail {

bool IsPipeDeadlineActive(PipeDeadline deadline, PipeDeadline now) noexcept
{
    return now < deadline;
}

bool ShouldWritePipeResponse(bool processed, bool stopping, PipeDeadline deadline,
    PipeDeadline now) noexcept
{
    return processed && !stopping && IsPipeDeadlineActive(deadline, now);
}

} // namespace detail

bool BuildProtectedPipeSecurityDescriptor(const std::wstring& core_sid, const std::wstring& miner_sid,
    void*& descriptor, std::string& error)
{
    descriptor = nullptr;
#ifdef WIN32
    PSID core{nullptr};
    PSID miner{nullptr};
    if (!ConvertStringSidToSidW(core_sid.c_str(), &core) ||
        !ConvertStringSidToSidW(miner_sid.c_str(), &miner)) {
        if (core) LocalFree(core);
        if (miner) LocalFree(miner);
        error = "Required service SID is invalid";
        return false;
    }
    if (!IsServiceSid(core) || !IsServiceSid(miner) ||
        IsForbiddenSid(core) || IsForbiddenSid(miner) || EqualSid(core, miner)) {
        LocalFree(core);
        LocalFree(miner);
        error = "Pipe DACL identities are not an allowed distinct service pair";
        return false;
    }

    LPWSTR core_text{nullptr};
    LPWSTR miner_text{nullptr};
    const bool formatted = ConvertSidToStringSidW(core, &core_text) &&
        ConvertSidToStringSidW(miner, &miner_text);
    LocalFree(core);
    LocalFree(miner);
    if (!formatted) {
        if (core_text) LocalFree(core_text);
        if (miner_text) LocalFree(miner_text);
        error = "Unable to format service SIDs for the pipe DACL";
        return false;
    }

    const std::wstring sddl = std::wstring{L"D:P(A;;0x00100003;;;"} + core_text +
        L")(A;;0x00100003;;;" + miner_text + L")";
    LocalFree(core_text);
    LocalFree(miner_text);
    PSECURITY_DESCRIPTOR security_descriptor{nullptr};
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.c_str(), SDDL_REVISION_1, &security_descriptor, nullptr)) {
        error = "Unable to construct the protected pipe DACL";
        return false;
    }
    if (!ValidateProtectedPipeSecurityDescriptor(security_descriptor, core_sid, miner_sid, error)) {
        LocalFree(security_descriptor);
        return false;
    }
    descriptor = security_descriptor;
    error.clear();
    return true;
#else
    (void)core_sid;
    (void)miner_sid;
    error = "Windows Named Pipe security descriptors are unsupported on this platform";
    return false;
#endif
}

bool ValidateProtectedPipeSecurityDescriptor(void* descriptor, const std::wstring& core_sid,
    const std::wstring& miner_sid, std::string& error)
{
#ifdef WIN32
    auto* security_descriptor = static_cast<PSECURITY_DESCRIPTOR>(descriptor);
    if (!security_descriptor || !IsValidSecurityDescriptor(security_descriptor)) {
        error = "Pipe security descriptor is invalid";
        return false;
    }

    SECURITY_DESCRIPTOR_CONTROL control{};
    DWORD revision{0};
    BOOL dacl_present{FALSE};
    BOOL dacl_defaulted{FALSE};
    PACL dacl{nullptr};
    if (!GetSecurityDescriptorControl(security_descriptor, &control, &revision) ||
        !(control & SE_DACL_PROTECTED) ||
        !GetSecurityDescriptorDacl(security_descriptor, &dacl_present, &dacl, &dacl_defaulted) ||
        !dacl_present || !dacl || dacl_defaulted || dacl->AceCount != 2) {
        error = "Pipe security descriptor must contain a protected, explicit two-entry DACL";
        return false;
    }

    PSID expected_core{nullptr};
    PSID expected_miner{nullptr};
    if (!ConvertStringSidToSidW(core_sid.c_str(), &expected_core) ||
        !ConvertStringSidToSidW(miner_sid.c_str(), &expected_miner)) {
        if (expected_core) LocalFree(expected_core);
        if (expected_miner) LocalFree(expected_miner);
        error = "Expected pipe DACL service SID is invalid";
        return false;
    }
    if (!IsServiceSid(expected_core) || !IsServiceSid(expected_miner) ||
        IsForbiddenSid(expected_core) || IsForbiddenSid(expected_miner) ||
        EqualSid(expected_core, expected_miner)) {
        LocalFree(expected_core);
        LocalFree(expected_miner);
        error = "Expected pipe DACL identities must be distinct service SIDs";
        return false;
    }

    bool found_core{false};
    bool found_miner{false};
    bool valid{true};
    for (DWORD index{0}; index < dacl->AceCount; ++index) {
        void* raw_ace{nullptr};
        if (!GetAce(dacl, index, &raw_ace)) {
            valid = false;
            break;
        }
        auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw_ace);
        if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE || ace->Header.AceFlags != 0 ||
            ace->Mask != PIPE_CLIENT_ACCESS) {
            valid = false;
            break;
        }
        PSID sid{&ace->SidStart};
        if (EqualSid(sid, expected_core)) found_core = true;
        else if (EqualSid(sid, expected_miner)) found_miner = true;
        else valid = false;
    }
    LocalFree(expected_core);
    LocalFree(expected_miner);
    if (!valid || !found_core || !found_miner) {
        error = "Pipe DACL does not grant only the expected Core and Miner service identities";
        return false;
    }
    error.clear();
    return true;
#else
    (void)descriptor;
    (void)core_sid;
    (void)miner_sid;
    error = "Windows Named Pipe security descriptor validation is unsupported on this platform";
    return false;
#endif
}

void FreePipeSecurityDescriptor(void* descriptor)
{
#ifdef WIN32
    if (descriptor) LocalFree(descriptor);
#else
    (void)descriptor;
#endif
}

struct RpcNamedPipeServer::Impl {
    explicit Impl(NamedPipeConfig value) : config{std::move(value)} {}

    NamedPipeConfig config;
    node::NodeContext* node{nullptr};
    std::atomic<bool> running{false};
    std::atomic<bool> stopping{false};
#ifdef WIN32
    HANDLE stop_event{nullptr};
    HANDLE active_pipe{nullptr};
    void* security_descriptor{nullptr};
    std::wstring core_sid;
    std::wstring miner_sid;
    std::mutex handle_mutex;
    std::thread worker;

    HANDLE CreateInstance(std::string& error)
    {
        return CreatePipeInstance(security_descriptor, error);
    }

    void SetActivePipe(HANDLE pipe)
    {
        std::lock_guard lock{handle_mutex};
        active_pipe = pipe;
    }

    void CloseActivePipe(HANDLE pipe)
    {
        std::lock_guard lock{handle_mutex};
        if (active_pipe == pipe) active_pipe = nullptr;
        CloseHandle(pipe);
    }

    bool ReadFrame(HANDLE pipe, PipeDeadline deadline, std::string& message, std::string& error)
    {
        std::array<unsigned char, sizeof(uint32_t)> header{};
        if (!Transfer(pipe, stop_event, deadline, header.data(),
                static_cast<DWORD>(header.size()), true, error)) {
            return false;
        }
        const uint32_t length = static_cast<uint32_t>(header[0]) |
            (static_cast<uint32_t>(header[1]) << 8) |
            (static_cast<uint32_t>(header[2]) << 16) |
            (static_cast<uint32_t>(header[3]) << 24);
        if (!ValidatePipeFrameSize(length, config.max_frame_size, error)) return false;
        message.resize(length);
        return Transfer(pipe, stop_event, deadline, message.data(), length, true, error);
    }

    bool WriteFrame(HANDLE pipe, PipeDeadline deadline, const std::string& message, std::string& error)
    {
        if (!ValidatePipeFrameSize(message.size(), config.max_frame_size, error)) {
            error = "Named Pipe response exceeds the configured frame limit";
            return false;
        }
        if (message.size() > std::numeric_limits<uint32_t>::max()) {
            error = "Named Pipe response exceeds the frame length encoding";
            return false;
        }
        const uint32_t length = static_cast<uint32_t>(message.size());
        std::array<unsigned char, sizeof(uint32_t)> header{
            static_cast<unsigned char>(length & 0xff),
            static_cast<unsigned char>((length >> 8) & 0xff),
            static_cast<unsigned char>((length >> 16) & 0xff),
            static_cast<unsigned char>((length >> 24) & 0xff),
        };
        return Transfer(pipe, stop_event, deadline, header.data(),
                   static_cast<DWORD>(header.size()), false, error) &&
            Transfer(pipe, stop_event, deadline,
                const_cast<char*>(message.data()), static_cast<DWORD>(length), false, error);
    }

    void Run(HANDLE pipe)
    {
        bool fatal_error{false};
        while (pipe != INVALID_HANDLE_VALUE && !stopping.load()) {
            SetActivePipe(pipe);
            std::string error;
            const PipeDeadline deadline = std::chrono::steady_clock::now() +
                std::chrono::milliseconds{config.request_timeout_ms};
            const bool connected = ConnectPipe(pipe, stop_event, deadline, error);
            if (connected && !stopping.load()) {
                bool identity_fatal{false};
                const bool authenticated = VerifyClientIdentity(pipe, miner_sid, identity_fatal, error);
                if (identity_fatal) {
                    fatal_error = true;
                    stopping.store(true);
                    if (node) vaqyron::winservice::RequestServiceShutdown(*node);
                } else if (authenticated && !stopping.load() &&
                    RemainingPipeTimeoutMs(deadline, std::chrono::steady_clock::now()) != 0) {
                    std::string request;
                    if (!stopping.load() && ReadFrame(pipe, deadline, request, error) &&
                        detail::IsPipeDeadlineActive(deadline, std::chrono::steady_clock::now()) &&
                        !stopping.load()) {
                        std::string response;
                        const bool processed = DispatchRpcMessage(
                            request, std::any{node}, [](const JSONRPCRequest& rpc_request) {
                                return JSONRPCExec(rpc_request, true);
                            }, response, error, [&deadline] {
                                return detail::IsPipeDeadlineActive(
                                    deadline, std::chrono::steady_clock::now());
                            });
                        if (detail::ShouldWritePipeResponse(
                                processed, stopping.load(), deadline, std::chrono::steady_clock::now())) {
                            WriteFrame(pipe, deadline, response, error);
                        }
                    }
                }
            }
            if (connected) DisconnectNamedPipe(pipe);
            CloseActivePipe(pipe);
            pipe = INVALID_HANDLE_VALUE;
            if (stopping.load()) break;
            pipe = CreateInstance(error);
            if (pipe == INVALID_HANDLE_VALUE) {
                LogError("Named Pipe listener stopped: %s", error);
                break;
            }
        }
        if (pipe != INVALID_HANDLE_VALUE) {
            std::lock_guard lock{handle_mutex};
            if (active_pipe == pipe) active_pipe = nullptr;
            CloseHandle(pipe);
        }
        running.store(false);
        if (fatal_error) {
            LogError("Named Pipe identity cleanup failed; Core shutdown was requested");
        } else if (!stopping.load() && node && node->shutdown_request) {
            LogError("Named Pipe listener exited unexpectedly; requesting Core shutdown");
            vaqyron::winservice::RequestServiceShutdown(*node);
        }
    }
#endif
};

RpcNamedPipeServer::RpcNamedPipeServer(NamedPipeConfig config)
    : impl_{std::make_unique<Impl>(std::move(config))}
{
}

RpcNamedPipeServer::~RpcNamedPipeServer()
{
    Stop();
}

namespace {

detail::PipeRegistryStateMachine g_named_pipe_registry;
std::unique_ptr<RpcNamedPipeServer> g_named_pipe_server;

} // namespace

bool RpcNamedPipeServer::Start(node::NodeContext& node, std::string& error)
{
    auto& impl = *impl_;
    if (!impl.config.enabled || !impl.config.service_mode || impl.config.allow_http_fallback) {
        error = "Named Pipe RPC requires explicit service mode and prohibits HTTP fallback";
        return false;
    }
    if (impl.config.core_account != "NT SERVICE\\VAQYRONTestnetCoreDev" ||
        impl.config.miner_account != "NT SERVICE\\VAQYRONMinerDev") {
        error = "Named Pipe RPC service identities do not match the approved Core and Miner principals";
        return false;
    }
    if (Params().GetChainType() != ChainType::VAQYRON_TESTNET) {
        error = "Named Pipe RPC is restricted to VAQYRON TESTNET";
        return false;
    }
    if (impl.config.max_frame_size == 0 || impl.config.max_frame_size > MAX_FRAME_SIZE ||
        impl.config.request_timeout_ms == 0 ||
        impl.config.request_timeout_ms > MAX_REQUEST_TIMEOUT_MS) {
        error = "Named Pipe frame or timeout configuration is invalid";
        return false;
    }

#ifdef WIN32
    if (!ResolveAccountSid(CORE_ACCOUNT, impl.core_sid, error) ||
        !ResolveAccountSid(MINER_ACCOUNT, impl.miner_sid, error)) {
        return false;
    }

    if (!VerifyServiceSidConfigured(L"VAQYRONMinerDev", error)) return false;

    if (!vaqyron::winservice::VerifyCurrentProcessServiceIdentity(
            WidenAscii(impl.config.core_account), error)) {
        return false;
    }

    impl.security_descriptor = nullptr;
    if (!BuildProtectedPipeSecurityDescriptor(impl.core_sid, impl.miner_sid,
            impl.security_descriptor, error)) {
        return false;
    }
    impl.stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!impl.stop_event) {
        FreePipeSecurityDescriptor(impl.security_descriptor);
        impl.security_descriptor = nullptr;
        error = "Unable to create the Named Pipe shutdown event";
        return false;
    }
    HANDLE first_pipe = impl.CreateInstance(error);
    if (first_pipe == INVALID_HANDLE_VALUE) {
        CloseHandle(impl.stop_event);
        impl.stop_event = nullptr;
        FreePipeSecurityDescriptor(impl.security_descriptor);
        impl.security_descriptor = nullptr;
        return false;
    }

    impl.node = &node;
    impl.stopping.store(false);
    impl.running.store(true);
    try {
        impl.worker = std::thread([&impl, first_pipe] { impl.Run(first_pipe); });
    } catch (const std::exception&) {
        impl.running.store(false);
        CloseHandle(first_pipe);
        CloseHandle(impl.stop_event);
        impl.stop_event = nullptr;
        FreePipeSecurityDescriptor(impl.security_descriptor);
        impl.security_descriptor = nullptr;
        error = "Unable to start the Named Pipe listener thread";
        return false;
    }
    error.clear();
    return true;
#else
    (void)node;
    error = "Windows Named Pipe RPC is unsupported on this platform";
    return false;
#endif
}

bool RpcNamedPipeServer::Stop()
{
    auto& impl = *impl_;
#ifdef WIN32
    if (!impl.stopping.exchange(true)) {
        if (impl.stop_event && !SetEvent(impl.stop_event)) {
            LogError("Unable to signal the Named Pipe listener stop event (error %lu)", GetLastError());
        }
        {
            std::lock_guard lock{impl.handle_mutex};
            if (impl.active_pipe && !CancelIoEx(impl.active_pipe, nullptr)) {
                const DWORD error = GetLastError();
                if (error != ERROR_NOT_FOUND) {
                    LogError("Unable to cancel active Named Pipe I/O (error %lu)", error);
                }
            }
        }
    }
    if (impl.worker.joinable()) impl.worker.join();
    impl.running.store(false);
    if (impl.stop_event) {
        CloseHandle(impl.stop_event);
        impl.stop_event = nullptr;
    }
    if (impl.security_descriptor) {
        FreePipeSecurityDescriptor(impl.security_descriptor);
        impl.security_descriptor = nullptr;
    }
#else
    impl.running.store(false);
#endif
    return true;
}

bool RpcNamedPipeServer::IsRunning() const
{
    return impl_->running.load();
}

bool StartRpcNamedPipe(node::NodeContext& node, const NamedPipeConfig& config, std::string& error)
{
    try {
        const bool started = g_named_pipe_registry.Start([&] {
            auto candidate = std::make_unique<RpcNamedPipeServer>(config);
            if (!candidate->Start(node, error)) return false;
            g_named_pipe_server = std::move(candidate);
            return true;
        });
        if (!started && error.empty()) {
            error = "Named Pipe RPC is already starting, running, or stopping";
        }
        return started;
    } catch (const std::exception& exception) {
        error = "Unable to initialize the Named Pipe listener: " + std::string{exception.what()};
        return false;
    }
}

void StopRpcNamedPipe()
{
    g_named_pipe_registry.Stop([] {
        std::unique_ptr<RpcNamedPipeServer> server = std::move(g_named_pipe_server);
        if (server) server->Stop();
    });
}

bool IsRpcNamedPipeRunning()
{
    return g_named_pipe_registry.IsRunning([] {
        return g_named_pipe_server && g_named_pipe_server->IsRunning();
    });
}

} // namespace vaqyron::rpc
