// Copyright (c) 2026-present The VAQYRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <test/util/setup_common.h>
#include <init.h>
#include <winservice.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <string>
#include <thread>

namespace {

vaqyron::winservice::ServiceConfig ValidTestnetServiceConfig()
{
    vaqyron::winservice::ServiceConfig config;
    config.enabled = true;
    config.pipe_enabled = true;
    config.testnet = true;
    config.identity_verified = true;
    return config;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(winservice_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(service_lifecycle_reports_running_and_stop_pending)
{
    vaqyron::winservice::WinServiceController controller{ValidTestnetServiceConfig()};
    BOOST_REQUIRE(controller.Start());
    BOOST_CHECK_EQUAL(controller.state(), vaqyron::winservice::ServiceLifecycleState::Running);
    BOOST_CHECK(!controller.CompleteStop());

    BOOST_CHECK(controller.RequestStop());
    BOOST_CHECK(controller.IsStopping());
    BOOST_CHECK_EQUAL(controller.state(), vaqyron::winservice::ServiceLifecycleState::StopPending);
    BOOST_CHECK(controller.RequestStop());
    BOOST_CHECK(controller.CompleteStop());
    BOOST_CHECK(controller.CompleteStop());
    BOOST_CHECK_EQUAL(controller.state(), vaqyron::winservice::ServiceLifecycleState::Stopped);
}

BOOST_AUTO_TEST_CASE(service_stop_during_startup_blocks_running_transition)
{
    std::atomic<bool> stop_requested{false};
    BOOST_CHECK(vaqyron::winservice::CanReportServiceRunning(stop_requested));

    int shutdown_requests{0};
    BOOST_CHECK(vaqyron::winservice::HandleServiceStopRequest(
        stop_requested, [] { return true; }, [&] { ++shutdown_requests; }));
    BOOST_CHECK(!vaqyron::winservice::CanReportServiceRunning(stop_requested));
    BOOST_CHECK_EQUAL(shutdown_requests, 1);
}

BOOST_AUTO_TEST_CASE(completed_service_milestones_advance_checkpoint_once)
{
    using vaqyron::winservice::ServiceProgressMilestone;
    vaqyron::winservice::ServiceProgressTracker progress;
    progress.BeginPendingStatus();
    BOOST_CHECK_EQUAL(progress.checkpoint(), 1);

    BOOST_CHECK(progress.RecordCompletedMilestone(ServiceProgressMilestone::ChainstateLoaded));
    const auto completed_checkpoint = progress.checkpoint();
    BOOST_CHECK_EQUAL(completed_checkpoint, 2);
    BOOST_CHECK(!progress.RecordCompletedMilestone(ServiceProgressMilestone::ChainstateLoaded));
    BOOST_CHECK_EQUAL(progress.checkpoint(), completed_checkpoint);

    BOOST_CHECK_EQUAL(progress.HeartbeatCheckpoint(), completed_checkpoint);
    BOOST_CHECK_EQUAL(progress.HeartbeatCheckpoint(), completed_checkpoint);
    BOOST_CHECK_EQUAL(progress.checkpoint(), completed_checkpoint);
    progress.BeginPendingStatus();
    BOOST_CHECK_EQUAL(progress.checkpoint(), 1);
    BOOST_CHECK(progress.RecordCompletedMilestone(ServiceProgressMilestone::ChainstateLoaded));
}

BOOST_AUTO_TEST_CASE(service_start_fails_closed_for_invalid_configuration)
{
    auto config = ValidTestnetServiceConfig();
    config.identity_verified = false;
    vaqyron::winservice::WinServiceController controller{config};

    BOOST_CHECK(!controller.Start());
    BOOST_CHECK(controller.IsFailed());
    BOOST_CHECK_EQUAL(controller.state(), vaqyron::winservice::ServiceLifecycleState::Failed);
}

BOOST_AUTO_TEST_CASE(service_requires_explicit_pipe_and_testnet_configuration)
{
    std::string error;
    auto no_pipe = ValidTestnetServiceConfig();
    no_pipe.pipe_enabled = false;
    BOOST_CHECK(!vaqyron::winservice::ValidateServiceConfig(no_pipe, error));
    BOOST_CHECK(error.find("named-pipe") != std::string::npos);

    auto wrong_chain = ValidTestnetServiceConfig();
    wrong_chain.testnet = false;
    error.clear();
    BOOST_CHECK(!vaqyron::winservice::ValidateServiceConfig(wrong_chain, error));
    BOOST_CHECK(error.find("TESTNET") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(service_mode_rejects_unbounded_shutdownnotify)
{
    auto config = ValidTestnetServiceConfig();
    config.shutdown_notify_configured = true;
    std::string error;
    BOOST_CHECK(!vaqyron::winservice::ValidateServiceConfig(config, error));
    BOOST_CHECK(error.find("-shutdownnotify") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(service_identity_policy_fails_closed_for_missing_or_wrong_sid)
{
    std::string error;
    BOOST_CHECK(!vaqyron::winservice::ValidateServiceIdentity(L"", L"S-1-5-80-1", error));
    BOOST_CHECK(!vaqyron::winservice::ValidateServiceIdentity(
        L"S-1-5-80-1", L"S-1-5-80-2", error));
    BOOST_CHECK(vaqyron::winservice::ValidateServiceIdentity(
        L"S-1-5-80-1", L"S-1-5-80-1", error));
}

BOOST_AUTO_TEST_CASE(service_stop_handler_reports_and_requests_shutdown_once)
{
    std::atomic<bool> stop_requested{false};
    int status_reports{0};
    int shutdown_requests{0};
    const auto report_stop_pending = [&] {
        ++status_reports;
        return true;
    };
    const auto request_shutdown = [&] { ++shutdown_requests; };

    BOOST_CHECK(vaqyron::winservice::HandleServiceStopRequest(
        stop_requested, report_stop_pending, request_shutdown));
    BOOST_CHECK(vaqyron::winservice::HandleServiceStopRequest(
        stop_requested, report_stop_pending, request_shutdown));
    BOOST_CHECK_EQUAL(status_reports, 1);
    BOOST_CHECK_EQUAL(shutdown_requests, 1);
}

BOOST_AUTO_TEST_CASE(service_stop_handler_requests_shutdown_even_if_status_update_fails)
{
    std::atomic<bool> stop_requested{false};
    int shutdown_requests{0};

    BOOST_CHECK(!vaqyron::winservice::HandleServiceStopRequest(
        stop_requested, [] { return false; }, [&] { ++shutdown_requests; }));
    BOOST_CHECK_EQUAL(shutdown_requests, 1);
}

BOOST_AUTO_TEST_CASE(core_shutdown_signal_is_owned_and_sent_once)
{
    std::atomic<bool> requested{false};
    std::atomic<int> signals{0};
    const auto request = [&] { signals.fetch_add(1); };
    std::thread first([&] {
        vaqyron::winservice::RequestShutdownOnce(requested, request);
    });
    std::thread second([&] {
        vaqyron::winservice::RequestShutdownOnce(requested, request);
    });
    first.join();
    second.join();
    BOOST_CHECK_EQUAL(signals.load(), 1);
}

BOOST_AUTO_TEST_CASE(cancel_and_reset_are_idempotent_after_start)
{
    vaqyron::winservice::WinServiceController controller{ValidTestnetServiceConfig()};
    BOOST_REQUIRE(controller.Start());
    BOOST_CHECK(controller.Cancel());
    BOOST_CHECK_EQUAL(controller.state(), vaqyron::winservice::ServiceLifecycleState::Stopped);
    BOOST_CHECK(controller.Reset());
    BOOST_CHECK_EQUAL(controller.state(), vaqyron::winservice::ServiceLifecycleState::Uninitialized);
}

BOOST_AUTO_TEST_CASE(service_mode_is_opt_in)
{
    ArgsManager args;
    SetupServerArgs(args);
    BOOST_CHECK(!vaqyron::winservice::IsServiceModeEnabled(args));
    BOOST_CHECK(!args.GetBoolArg("-rpcnamedpipe", false));
}

BOOST_AUTO_TEST_CASE(service_platform_guard_matches_build_platform)
{
#ifdef WIN32
    BOOST_CHECK(vaqyron::winservice::IsWindowsServiceSupported());
#else
    BOOST_CHECK(!vaqyron::winservice::IsWindowsServiceSupported());
#endif
}

BOOST_AUTO_TEST_SUITE_END()
