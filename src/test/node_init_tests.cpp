// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <init.h>
#include <interfaces/init.h>
#include <node/context.h>
#include <rpc/server.h>

#include <boost/test/unit_test.hpp>
#include <test/util/setup_common.h>

#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>

using node::NodeContext;

//! Like BasicTestingSetup, but using regtest network instead of mainnet.
struct InitTestSetup : BasicTestingSetup {
    InitTestSetup() : BasicTestingSetup{ChainType::REGTEST} {}
};

BOOST_FIXTURE_TEST_SUITE(node_init_tests, InitTestSetup)

BOOST_AUTO_TEST_CASE(pending_vaqyron_main_genesis_blocks_startup)
{
    const auto main{CChainParams::Main()};
    BOOST_CHECK(main->IsVaqyronMainGenesisPending());

    ArgsManager args;
    SetupServerArgs(args);
    args.ForceSetArg("-allow-pending-genesis", "1");

    SelectParams(ChainType::MAIN);
    const bool startup_allowed{AppInitParameterInteraction(args)};
    SelectParams(ChainType::REGTEST);

    BOOST_CHECK(!startup_allowed);
    BOOST_CHECK(args.GetHelpMessage().find("-allow-pending-genesis") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(non_main_networks_do_not_have_pending_vaqyron_genesis)
{
    BOOST_CHECK(!CChainParams::TestNet()->IsVaqyronMainGenesisPending());
    BOOST_CHECK(!CChainParams::TestNet4()->IsVaqyronMainGenesisPending());
    BOOST_CHECK(!CChainParams::SigNet({})->IsVaqyronMainGenesisPending());
    BOOST_CHECK(!CChainParams::RegTest({})->IsVaqyronMainGenesisPending());
    BOOST_CHECK(AppInitParameterInteraction(*m_node.args));
}

BOOST_AUTO_TEST_CASE(finalized_vaqyron_testnet_genesis_allows_parameter_interaction)
{
    const auto testnet{CChainParams::VaqyronTestNet()};
    BOOST_CHECK(!testnet->IsVaqyronTestnetGenesisPending());
    BOOST_CHECK(!testnet->IsVaqyronMainGenesisPending());

    SelectParams(ChainType::VAQYRON_TESTNET);
    const bool parameter_interaction_succeeded{AppInitParameterInteraction(*m_node.args)};
    SelectParams(ChainType::REGTEST);

    BOOST_CHECK(parameter_interaction_succeeded);
}

//! Custom implementation of interfaces::Init for testing.
class TestInit : public interfaces::Init
{
public:
    TestInit(NodeContext& node) : m_node(node)
    {
        InitContext(m_node);
        m_node.init = this;
    }
    std::unique_ptr<interfaces::Chain> makeChain() override { return interfaces::MakeChain(m_node); }
    std::unique_ptr<interfaces::WalletLoader> makeWalletLoader(interfaces::Chain& chain) override
    {
        return MakeWalletLoader(chain, *Assert(m_node.args));
    }
    NodeContext& m_node;
};

BOOST_AUTO_TEST_CASE(init_test)
{
    // Clear state set by BasicTestingSetup that AppInitMain assumes is unset.
    LogInstance().DisconnectTestLogger();
    m_node.args->SetConfigFilePath({});

    // Prevent the test from trying to listen on ports 8332 and 8333.
    m_node.args->ForceSetArg("-server", "0");
    m_node.args->ForceSetArg("-listen", "0");

    // Run through initialization and shutdown code.
    TestInit init{m_node};
    BOOST_CHECK(AppInitInterfaces(m_node));
    BOOST_CHECK(AppInitMain(m_node));
    Interrupt(m_node);
    Shutdown(m_node);
}

BOOST_AUTO_TEST_CASE(cleanup_coordinator_is_single_owner_and_reentrant)
{
    node::CleanupCoordinator coordinator;
    int interrupt_calls{0};
    int shutdown_calls{0};
    node::CleanupResult reentrant_result{node::CleanupResult::COMPLETE};

    BOOST_CHECK(coordinator.RunInterrupt([&] {
        ++interrupt_calls;
        reentrant_result = coordinator.RunInterrupt([] {});
    }) == node::CleanupResult::COMPLETE);
    BOOST_CHECK(reentrant_result == node::CleanupResult::IN_PROGRESS);
    BOOST_CHECK(coordinator.RunShutdown([&] { ++shutdown_calls; }) == node::CleanupResult::COMPLETE);
    BOOST_CHECK(coordinator.RunInterrupt([&] { ++interrupt_calls; }) == node::CleanupResult::COMPLETE);
    BOOST_CHECK(coordinator.RunShutdown([&] { ++shutdown_calls; }) == node::CleanupResult::COMPLETE);
    BOOST_CHECK_EQUAL(interrupt_calls, 1);
    BOOST_CHECK_EQUAL(shutdown_calls, 1);
    BOOST_CHECK(coordinator.Snapshot().state == node::CleanupState::CLEANUP_COMPLETE);
}

BOOST_AUTO_TEST_CASE(cleanup_coordinator_classifies_phase_exceptions)
{
    node::CleanupCoordinator interrupt_coordinator;
    BOOST_CHECK(interrupt_coordinator.RunInterrupt([] { throw std::runtime_error{"interrupt"}; }) ==
        node::CleanupResult::INCOMPLETE);
    auto snapshot = interrupt_coordinator.Snapshot();
    BOOST_CHECK(snapshot.state == node::CleanupState::CLEANUP_INCOMPLETE);
    BOOST_CHECK(snapshot.failing_phase == node::CleanupPhase::INTERRUPT);
    BOOST_CHECK(interrupt_coordinator.RunShutdown([] {}) == node::CleanupResult::INCOMPLETE);

    node::CleanupCoordinator shutdown_coordinator;
    BOOST_CHECK(shutdown_coordinator.RunInterrupt([] {}) == node::CleanupResult::COMPLETE);
    BOOST_CHECK(shutdown_coordinator.RunShutdown([] { throw std::runtime_error{"shutdown"}; }) ==
        node::CleanupResult::INCOMPLETE);
    snapshot = shutdown_coordinator.Snapshot();
    BOOST_CHECK(snapshot.state == node::CleanupState::CLEANUP_INCOMPLETE);
    BOOST_CHECK(snapshot.failing_phase == node::CleanupPhase::SHUTDOWN);
}

BOOST_AUTO_TEST_CASE(concurrent_cleanup_callers_share_the_owner_result)
{
    node::CleanupCoordinator coordinator;
    std::mutex mutex;
    std::condition_variable changed;
    bool action_started{false};
    bool release_action{false};
    std::atomic<int> action_calls{0};
    auto resource = std::make_shared<int>(42);
    std::weak_ptr<int> resource_lifetime{resource};
    int resource_value{0};
    node::CleanupResult owner_result{node::CleanupResult::INCOMPLETE};
    node::CleanupResult observer_result{node::CleanupResult::INCOMPLETE};

    std::thread owner{[&, keep_alive = resource] {
        owner_result = coordinator.RunInterrupt([&, keep_alive] {
            ++action_calls;
            resource_value = *keep_alive;
            std::unique_lock lock{mutex};
            action_started = true;
            changed.notify_all();
            changed.wait(lock, [&] { return release_action; });
        });
    }};
    {
        std::unique_lock lock{mutex};
        changed.wait(lock, [&] { return action_started; });
    }

    std::thread observer{[&] {
        observer_result = coordinator.RunInterrupt([&] { ++action_calls; });
    }};
    const auto blocked_snapshot = coordinator.Snapshot();
    resource.reset();
    const bool resource_retained_while_blocked = !resource_lifetime.expired();
    {
        std::lock_guard lock{mutex};
        release_action = true;
    }
    changed.notify_all();
    owner.join();
    observer.join();

    BOOST_CHECK(blocked_snapshot.state == node::CleanupState::INTERRUPTING);
    BOOST_CHECK(owner_result == node::CleanupResult::COMPLETE);
    BOOST_CHECK(observer_result == node::CleanupResult::COMPLETE);
    BOOST_CHECK_EQUAL(action_calls.load(), 1);
    BOOST_CHECK(resource_retained_while_blocked);
    BOOST_CHECK(resource_lifetime.expired());
    BOOST_CHECK_EQUAL(resource_value, 42);
}

BOOST_AUTO_TEST_SUITE_END()
