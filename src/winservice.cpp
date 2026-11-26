// Copyright (c) 2026-present The VAQYRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <winservice.h>

#include <chainparams.h>
#include <common/args.h>
#include <logging.h>
#include <node/context.h>

#include <cstdlib>
#include <cwchar>
#include <exception>
#include <limits>
#include <mutex>
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

namespace vaqyron::winservice {

void ServiceProgressTracker::BeginPendingStatus() noexcept
{
    reported_milestones_ = 0;
    checkpoint_ = 1;
}

bool ServiceProgressTracker::RecordCompletedMilestone(ServiceProgressMilestone milestone) noexcept
{
    const auto index = static_cast<std::uint8_t>(milestone);
    if (index >= std::numeric_limits<std::uint64_t>::digits) return false;
    const std::uint64_t bit = std::uint64_t{1} << index;
    if ((reported_milestones_ & bit) != 0 ||
        checkpoint_ == std::numeric_limits<std::uint32_t>::max()) {
        return false;
    }
    reported_milestones_ |= bit;
    ++checkpoint_;
    return true;
}

void ServiceProgressTracker::RollbackMilestone(ServiceProgressMilestone milestone,
    std::uint32_t checkpoint) noexcept
{
    const auto index = static_cast<std::uint8_t>(milestone);
    if (index >= std::numeric_limits<std::uint64_t>::digits) return;
    const std::uint64_t bit = std::uint64_t{1} << index;
    if ((reported_milestones_ & bit) == 0) return;
    reported_milestones_ &= ~bit;
    checkpoint_ = checkpoint;
}

std::uint32_t ServiceProgressTracker::checkpoint() const noexcept
{
    return checkpoint_;
}

std::uint32_t ServiceProgressTracker::HeartbeatCheckpoint() const noexcept
{
    return checkpoint_;
}

namespace {

#ifdef WIN32
constexpr wchar_t SERVICE_NAME_W[] = L"VAQYRONTestnetCoreDev";
constexpr wchar_t CORE_ACCOUNT_W[] = L"NT SERVICE\\VAQYRONTestnetCoreDev";
constexpr DWORD SERVICE_WAIT_HINT_MS = 30000;
constexpr DWORD SERVICE_PROGRESS_INTERVAL_MS = 2000;

struct ServiceHost {
    node::NodeContext* node{nullptr};
    const ArgsManager* args{nullptr};
    const CoreServiceRunner* run_core{nullptr};
    SERVICE_STATUS_HANDLE status_handle{nullptr};
    SERVICE_STATUS status{};
    HANDLE status_event{nullptr};
    std::mutex status_mutex;
    ServiceProgressTracker progress;
    std::atomic<bool> status_monitor_stop{false};
    std::atomic<bool> stop_requested{false};
    std::atomic<bool> shutdown_signalled{false};
    std::atomic<bool> running_reported{false};
    int exit_code{EXIT_FAILURE};
};

std::atomic<ServiceHost*> g_service_host{nullptr};

bool ReportStatusLocked(ServiceHost& host, DWORD state, DWORD win32_exit_code = NO_ERROR,
    DWORD service_exit_code = 0)
{
    if (state == SERVICE_RUNNING && !CanReportServiceRunning(host.stop_requested)) return true;
    const SERVICE_STATUS previous_status = host.status;
    const DWORD previous_state = previous_status.dwCurrentState;
    host.status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    host.status.dwCurrentState = state;
    host.status.dwWin32ExitCode = win32_exit_code;
    host.status.dwServiceSpecificExitCode = service_exit_code;
    host.status.dwWaitHint = state == SERVICE_STOP_PENDING ? SERVICE_WAIT_HINT_MS :
        state == SERVICE_START_PENDING ? SERVICE_WAIT_HINT_MS : 0;
    const bool pending = state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING;
    host.status.dwCheckPoint = pending ?
        (previous_state == state ? host.progress.checkpoint() : 1) : 0;
    host.status.dwControlsAccepted = state == SERVICE_RUNNING ?
        SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0;
    if (!host.status_handle) {
        host.status = previous_status;
        LogError("Unable to report Windows service status without a registered status handle");
        return false;
    }
    if (!SetServiceStatus(host.status_handle, &host.status)) {
        const DWORD error = GetLastError();
        host.status = previous_status;
        LogError("Unable to report Windows service status (error %lu)", error);
        return false;
    }
    if (pending && previous_state != state) host.progress.BeginPendingStatus();
    return true;
}

bool ReportStatus(ServiceHost& host, DWORD state, DWORD win32_exit_code = NO_ERROR,
    DWORD service_exit_code = 0)
{
    std::lock_guard lock{host.status_mutex};
    return ReportStatusLocked(host, state, win32_exit_code, service_exit_code);
}

bool LatchStopAndReportPending(ServiceHost& host, bool& already_stopped)
{
    std::lock_guard lock{host.status_mutex};
    already_stopped = host.status.dwCurrentState == SERVICE_STOPPED;
    if (already_stopped) {
        host.stop_requested.store(true);
        return true;
    }
    const bool already_requested = host.stop_requested.exchange(true);
    if (already_requested &&
        host.status.dwCurrentState == SERVICE_STOP_PENDING) {
        return true;
    }
    return ReportStatusLocked(host, SERVICE_STOP_PENDING);
}

void ReportPendingProgress(ServiceHost& host, ServiceProgressMilestone milestone)
{
    std::lock_guard lock{host.status_mutex};
    if (!host.status_handle ||
        (host.status.dwCurrentState != SERVICE_START_PENDING &&
         host.status.dwCurrentState != SERVICE_STOP_PENDING)) {
        return;
    }
    const DWORD previous_checkpoint = host.progress.checkpoint();
    if (!host.progress.RecordCompletedMilestone(milestone)) return;
    host.status.dwCheckPoint = host.progress.checkpoint();
    if (!SetServiceStatus(host.status_handle, &host.status)) {
        const DWORD error = GetLastError();
        host.progress.RollbackMilestone(milestone, previous_checkpoint);
        host.status.dwCheckPoint = previous_checkpoint;
        LogError("Unable to report completed Windows service milestone (error %lu)", error);
    }
}

void ReportPendingHeartbeat(ServiceHost& host)
{
    std::lock_guard lock{host.status_mutex};
    if (!host.status_handle ||
        (host.status.dwCurrentState != SERVICE_START_PENDING &&
         host.status.dwCurrentState != SERVICE_STOP_PENDING)) {
        return;
    }
    host.status.dwCheckPoint = host.progress.HeartbeatCheckpoint();
    if (!SetServiceStatus(host.status_handle, &host.status)) {
        const DWORD error = GetLastError();
        LogError("Unable to refresh Windows service pending status (error %lu)", error);
    }
}

void WINAPI ServiceStatusMonitor(ServiceHost* host)
{
    for (;;) {
        if (host->status_monitor_stop.load()) return;
        const DWORD wait_result = WaitForSingleObject(host->status_event, SERVICE_PROGRESS_INTERVAL_MS);
        if (wait_result == WAIT_OBJECT_0) return;
        if (wait_result == WAIT_TIMEOUT) {
            if (host->status_monitor_stop.load()) return;
            ReportPendingHeartbeat(*host);
            continue;
        }
        LogError("Windows service status monitor wait failed (error %lu)", GetLastError());
        return;
    }
}

bool RequestCoreShutdownOnce(ServiceHost& host)
{
    bool already_stopped{false};
    const bool status_reported = LatchStopAndReportPending(host, already_stopped);
    if (!already_stopped && host.node && host.node->shutdown_request) {
        RequestShutdownOnce(host.shutdown_signalled, [&host] { host.node->shutdown_request(); });
    }
    return status_reported;
}

DWORD WINAPI ServiceControlHandler(DWORD control, DWORD, LPVOID, LPVOID context)
{
    auto& host = *static_cast<ServiceHost*>(context);
    if (control == SERVICE_CONTROL_INTERROGATE) {
        std::lock_guard lock{host.status_mutex};
        if (host.status_handle && !SetServiceStatus(host.status_handle, &host.status)) {
            const DWORD error = GetLastError();
            LogError("Unable to re-report Windows service status (error %lu)", error);
            return error;
        }
        return NO_ERROR;
    }
    if (control != SERVICE_CONTROL_STOP && control != SERVICE_CONTROL_SHUTDOWN) {
        return ERROR_CALL_NOT_IMPLEMENTED;
    }

    const bool status_reported = RequestCoreShutdownOnce(host);
    return status_reported ? NO_ERROR : ERROR_SERVICE_REQUEST_TIMEOUT;
}

void WINAPI ServiceMain(DWORD argc, LPWSTR* argv)
{
    ServiceHost* host_ptr = g_service_host.load();
    if (!host_ptr) return;
    ServiceHost& host = *host_ptr;
    host.status_handle = RegisterServiceCtrlHandlerExW(SERVICE_NAME_W, ServiceControlHandler, &host);
    if (!host.status_handle) {
        return;
    }

    if (!ReportStatus(host, SERVICE_START_PENDING)) {
        host.exit_code = EXIT_FAILURE;
        return;
    }
    if (argc < 1 || !argv || !argv[0] || _wcsicmp(argv[0], SERVICE_NAME_W) != 0) {
        ReportStatus(host, SERVICE_STOPPED, ERROR_INVALID_NAME, 1);
        host.exit_code = EXIT_FAILURE;
        return;
    }

    ServiceConfig config;
    config.enabled = IsServiceModeEnabled(*host.args);
    config.pipe_enabled = host.args->GetBoolArg("-rpcnamedpipe", false);
    config.shutdown_notify_configured = host.args->IsArgSet("-shutdownnotify");
    const bool valid_chain = host.args->GetChainType() == ChainType::VAQYRON_TESTNET;
    config.testnet = valid_chain;
    std::string error;
    if (!valid_chain) {
        error = "Windows service mode is restricted to VAQYRON TESTNET";
    } else {
        config.identity_verified = VerifyCurrentProcessServiceIdentity(CORE_ACCOUNT_W, error);
    }
    if (!valid_chain || !ValidateServiceConfig(config, error)) {
        LogError("Windows service startup refused: %s", error.empty() ? "unsupported chain or service configuration" : error);
        ReportStatus(host, SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, 1);
        host.exit_code = EXIT_FAILURE;
        return;
    }

    if (host.stop_requested.load()) {
        ReportStatus(host, SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, 2);
        host.exit_code = EXIT_FAILURE;
        return;
    }

    host.status_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!host.status_event) {
        ReportStatus(host, SERVICE_STOPPED, GetLastError(), 2);
        host.exit_code = EXIT_FAILURE;
        return;
    }
    std::thread status_monitor;
    bool core_runner_invoked{false};
    bool core_runner_returned{false};
    try {
        status_monitor = std::thread(ServiceStatusMonitor, &host);
        ReportPendingProgress(host, ServiceProgressMilestone::StatusMonitorStarted);
        core_runner_invoked = true;
        host.exit_code = (*host.run_core)([&host] {
            if (host.stop_requested.load()) {
                RequestCoreShutdownOnce(host);
                return true;
            }
            if (!host.running_reported.exchange(true)) {
                if (!ReportStatus(host, SERVICE_RUNNING)) return false;
            }
            if (host.stop_requested.load()) RequestCoreShutdownOnce(host);
            return true;
        });
        core_runner_returned = true;
    } catch (const std::exception& e) {
        LogError("Windows service execution failed: %s", e.what());
        host.exit_code = EXIT_FAILURE;
    } catch (...) {
        LogError("Windows service execution failed with an unknown exception");
        host.exit_code = EXIT_FAILURE;
    }
    host.status_monitor_stop.store(true);
    if (!SetEvent(host.status_event)) {
        LogError("Unable to signal the Windows service status monitor (error %lu)", GetLastError());
    }
    if (status_monitor.joinable()) status_monitor.join();
    CloseHandle(host.status_event);
    host.status_event = nullptr;

    if (core_runner_returned || !core_runner_invoked) {
        ReportStatus(host, SERVICE_STOPPED,
            host.exit_code == EXIT_SUCCESS ? NO_ERROR : ERROR_SERVICE_SPECIFIC_ERROR,
            host.exit_code == EXIT_SUCCESS ? 0 : 1);
    } else {
        bool already_stopped{false};
        LatchStopAndReportPending(host, already_stopped);
        LogError("Core cleanup completion was not confirmed; retaining pending service status");
    }
}
#endif

} // namespace

std::string DefaultServiceName()
{
    return "VAQYRONTestnetCoreDev";
}

std::string ServiceStateName(ServiceLifecycleState state)
{
    switch (state) {
    case ServiceLifecycleState::Uninitialized: return "Uninitialized";
    case ServiceLifecycleState::Starting: return "Starting";
    case ServiceLifecycleState::Running: return "Running";
    case ServiceLifecycleState::StopPending: return "StopPending";
    case ServiceLifecycleState::Stopped: return "Stopped";
    case ServiceLifecycleState::Failed: return "Failed";
    }
    return "Unknown";
}

bool IsWindowsServiceSupported()
{
#ifdef WIN32
    return true;
#else
    return false;
#endif
}

bool IsServiceModeEnabled(const ArgsManager& args)
{
    return args.GetBoolArg("-winservice", false);
}

bool CanReportServiceRunning(const std::atomic<bool>& stop_requested)
{
    return !stop_requested.load();
}

bool RequestShutdownOnce(std::atomic<bool>& shutdown_requested,
    const std::function<void()>& request_shutdown)
{
    if (shutdown_requested.exchange(true)) return false;
    request_shutdown();
    return true;
}

bool ValidateServiceConfig(const ServiceConfig& config, std::string& error)
{
    if (!config.enabled) {
        error = "Service mode is disabled";
        return false;
    }
    if (!IsWindowsServiceSupported()) {
        error = "Windows service mode is unsupported on this platform";
        return false;
    }
    if (!config.pipe_enabled) {
        error = "Windows service mode requires the named-pipe RPC endpoint";
        return false;
    }
    if (config.service_name != DefaultServiceName()) {
        error = "Unexpected Windows service name";
        return false;
    }
    if (!config.testnet) {
        error = "Windows service mode is restricted to VAQYRON TESTNET";
        return false;
    }
    if (!config.identity_verified) {
        error = "Windows service process identity is not verified";
        return false;
    }
    if (config.shutdown_notify_configured) {
        error = "Windows service mode rejects -shutdownnotify because bounded completion is not guaranteed";
        return false;
    }
    error.clear();
    return true;
}

bool ValidateServiceIdentity(const std::wstring& expected_sid, const std::wstring& actual_token_sid,
    std::string& error)
{
    if (expected_sid.empty() || actual_token_sid.empty()) {
        error = "Expected service SID or process token SID is missing";
        return false;
    }
    if (expected_sid != actual_token_sid) {
        error = "Core process token SID does not match the expected service SID";
        return false;
    }
    error.clear();
    return true;
}

bool HandleServiceStopRequest(std::atomic<bool>& stop_requested,
    const std::function<bool()>& report_stop_pending, const std::function<void()>& request_shutdown)
{
    if (stop_requested.exchange(true)) return true;
    const bool status_reported = report_stop_pending();
    request_shutdown();
    return status_reported;
}

void ReportServiceProgress(ServiceProgressMilestone milestone)
{
#ifdef WIN32
    if (ServiceHost* host = g_service_host.load()) ReportPendingProgress(*host, milestone);
#endif
}

void RequestServiceShutdown(node::NodeContext& node)
{
#ifdef WIN32
    if (ServiceHost* host = g_service_host.load(); host && host->node == &node) {
        RequestCoreShutdownOnce(*host);
        return;
    }
#endif
    if (node.shutdown_request) node.shutdown_request();
}

bool VerifyCurrentProcessServiceIdentity(const std::wstring& expected_account, std::string& error)
{
#ifdef WIN32
    DWORD sid_size{0};
    DWORD domain_size{0};
    SID_NAME_USE sid_type{};
    LookupAccountNameW(nullptr, expected_account.c_str(), nullptr, &sid_size, nullptr, &domain_size, &sid_type);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || sid_size == 0) {
        error = "Expected Windows service identity is unavailable";
        return false;
    }

    std::vector<unsigned char> expected_sid(sid_size);
    std::vector<wchar_t> domain(domain_size);
    if (!LookupAccountNameW(nullptr, expected_account.c_str(), expected_sid.data(), &sid_size,
            domain.data(), &domain_size, &sid_type)) {
        error = "Expected Windows service identity could not be resolved";
        return false;
    }

    HANDLE token{nullptr};
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        error = "Unable to inspect the Core process token";
        return false;
    }
    DWORD token_size{0};
    GetTokenInformation(token, TokenGroups, nullptr, 0, &token_size);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || token_size == 0) {
        CloseHandle(token);
        error = "Unable to read the Core process token groups";
        return false;
    }

    std::vector<unsigned char> token_buffer(token_size);
    const bool token_read = GetTokenInformation(
        token, TokenGroups, token_buffer.data(), token_size, &token_size) != 0;
    CloseHandle(token);
    if (!token_read) {
        error = "Unable to read the Core process token groups";
        return false;
    }

    const auto* groups = reinterpret_cast<const TOKEN_GROUPS*>(token_buffer.data());
    bool has_service_sid{false};
    for (DWORD index{0}; index < groups->GroupCount; ++index) {
        const SID_AND_ATTRIBUTES& group = groups->Groups[index];
        if ((group.Attributes & SE_GROUP_ENABLED) != 0 &&
            (group.Attributes & SE_GROUP_USE_FOR_DENY_ONLY) == 0 &&
            EqualSid(group.Sid, expected_sid.data())) {
            has_service_sid = true;
            break;
        }
    }
    if (!has_service_sid) {
        error = "Core process token does not contain the expected enabled service SID";
        return false;
    }

    LPWSTR expected_sid_text{nullptr};
    if (!ConvertSidToStringSidW(expected_sid.data(), &expected_sid_text)) {
        if (expected_sid_text) LocalFree(expected_sid_text);
        error = "Unable to format the expected Core service SID";
        return false;
    }
    const bool matches = ValidateServiceIdentity(expected_sid_text, expected_sid_text, error);
    LocalFree(expected_sid_text);
    return matches;
#else
    (void)expected_account;
    error = "Windows service identity verification is unsupported on this platform";
    return false;
#endif
}

int RunWindowsService(node::NodeContext& node, const ArgsManager& args, const CoreServiceRunner& run_core)
{
#ifdef WIN32
    if (!IsServiceModeEnabled(args) || !args.GetBoolArg("-rpcnamedpipe", false) ||
        args.GetChainType() != ChainType::VAQYRON_TESTNET) {
        LogError("Windows service mode requires explicit pipe opt-in on VAQYRON TESTNET");
        return EXIT_FAILURE;
    }

    ServiceHost host;
    host.node = &node;
    host.args = &args;
    host.run_core = &run_core;
    g_service_host.store(&host);

    SERVICE_TABLE_ENTRYW service_table[] = {
        {const_cast<LPWSTR>(SERVICE_NAME_W), ServiceMain},
        {nullptr, nullptr},
    };
    if (!StartServiceCtrlDispatcherW(service_table)) {
        const DWORD error = GetLastError();
        LogError("Unable to connect to the Windows Service Control Manager (error %lu)", error);
        g_service_host.store(nullptr);
        return EXIT_FAILURE;
    }
    g_service_host.store(nullptr);
    return host.exit_code;
#else
    (void)node;
    (void)args;
    (void)run_core;
    LogError("Windows service mode is unsupported on this platform");
    return EXIT_FAILURE;
#endif
}

WinServiceController::WinServiceController(ServiceConfig config)
    : config_(std::move(config))
{
}

ServiceLifecycleState WinServiceController::state() const
{
    return state_.load();
}

bool WinServiceController::IsRunning() const
{
    return state() == ServiceLifecycleState::Running;
}

bool WinServiceController::IsStopping() const
{
    return state() == ServiceLifecycleState::StopPending || stop_requested_.load();
}

bool WinServiceController::IsFailed() const
{
    return state() == ServiceLifecycleState::Failed;
}

bool WinServiceController::Start()
{
    {
        std::lock_guard lock{lifecycle_mutex_};
        if (state_.load() != ServiceLifecycleState::Uninitialized) return false;
        state_.store(ServiceLifecycleState::Starting);
    }

    std::string error;
    if (!ValidateServiceConfig(config_, error)) {
        std::lock_guard lock{lifecycle_mutex_};
        if (state_.load() == ServiceLifecycleState::Starting) {
            state_.store(ServiceLifecycleState::Failed);
        }
        return false;
    }
    std::lock_guard lock{lifecycle_mutex_};
    if (state_.load() != ServiceLifecycleState::Starting || stop_requested_.load()) return false;
    state_.store(ServiceLifecycleState::Running);
    return true;
}

bool WinServiceController::RequestStop()
{
    std::lock_guard lock{lifecycle_mutex_};
    const auto current = state_.load();
    if (current == ServiceLifecycleState::Starting || current == ServiceLifecycleState::Running) {
        stop_requested_.store(true);
        state_.store(ServiceLifecycleState::StopPending);
        return true;
    }
    return current == ServiceLifecycleState::StopPending || current == ServiceLifecycleState::Stopped;
}

bool WinServiceController::CompleteStop()
{
    std::lock_guard lock{lifecycle_mutex_};
    const auto current = state_.load();
    if (current == ServiceLifecycleState::Stopped) return true;
    if (current != ServiceLifecycleState::StopPending) return false;
    stop_requested_.store(true);
    state_.store(ServiceLifecycleState::Stopped);
    return true;
}

bool WinServiceController::Fail()
{
    std::lock_guard lock{lifecycle_mutex_};
    if (state_.load() == ServiceLifecycleState::Stopped) return false;
    state_.store(ServiceLifecycleState::Failed);
    return true;
}

bool WinServiceController::Cancel()
{
    if (!RequestStop()) {
        return state() == ServiceLifecycleState::Stopped;
    }
    return CompleteStop();
}

bool WinServiceController::Reset()
{
    std::lock_guard lock{lifecycle_mutex_};
    auto current = state_.load();
    if (current != ServiceLifecycleState::Stopped && current != ServiceLifecycleState::Failed &&
        current != ServiceLifecycleState::Uninitialized) {
        return false;
    }
    stop_requested_.store(false);
    state_.store(ServiceLifecycleState::Uninitialized);
    return true;
}

} // namespace vaqyron::winservice
