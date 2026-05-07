/**
 * @file SnmpServerTests.cpp
 * @brief Unit and integration tests for SnmpServer.
 *
 * Test groups
 * ───────────
 * I.  Lifecycle tests (no real snmpd) — construction, destruction, config
 *     API, and stop-without-start safety.  These never call start(), so they
 *     are safe to run anywhere.
 *
 * II. Integration tests (SNMP_INTEGRATION_TESTS=1, snmpd with AgentX) —
 *     start the subagent, register handlers, and verify GET/SET round-trips
 *     through snmpd.
 *
 *     Prerequisites:
 *       - snmpd running with `master agentx` in snmpd.conf.
 *       - The process must have write permission to /var/agentx/master (or
 *         run as root / in the `snmp` group).
 *       - snmpget / snmpset from the net-snmp-utils package:
 *           sudo apt install snmp
 *
 *     Enable:
 *       SNMP_INTEGRATION_TESTS=1 ctest --preset native-debug -R SNFSnmpServerTests
 *
 * NOTE (net-snmp constraint): init_agent() is called via std::call_once —
 * only one SnmpServer can be started per process.  Integration tests that
 * call start() share a single SnmpServer instance through a module-level
 * fixture to respect this constraint.
 */

#include <gtest/gtest.h>

#include <SNFSnmpServer/SnmpServer.h>
#include <SNFSnmpServer/SnmpMibTree.h>
#include <SNFSnmpServer/SnmpTrapSink.h>

#include <SNFCore/Application.h>
#include <SNFCore/EventLoop.h>
#include <SNFSnmp/SnmpOid.h>
#include <SNFSnmp/SnmpTypes.h>
#include <SNFSnmp/SnmpValue.h>
#include <SNFSnmp/SnmpVarBind.h>
#include <SNFSnmp/SnmpV3Credentials.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <string>
#include <thread>

using namespace snf;
using namespace std::chrono_literals;

// ── Helpers ───────────────────────────────────────────────────────────────────

namespace {

bool integrationTestsEnabled()
{
    const char* v = std::getenv("SNMP_INTEGRATION_TESTS");
    return v && std::string(v) == "1";
}

bool snmpgetAvailable()
{
    return system("which snmpget > /dev/null 2>&1") == 0;
}

bool snmpsetAvailable()
{
    return system("which snmpset > /dev/null 2>&1") == 0;
}

// Pump the current-thread EventLoop for up to @p timeout or until @p pred.
bool pumpUntil(Application& app,
               const std::function<bool()>& pred,
               std::chrono::milliseconds timeout = 3s)
{
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (EventLoop* loop = app.getOrCreateCurrentThreadEventLoop())
            loop->runPendingWork();
        if (pred())
            return true;
        std::this_thread::sleep_for(5ms);
    }
    if (EventLoop* loop = app.getOrCreateCurrentThreadEventLoop())
        loop->runPendingWork();
    return pred();
}

// Run a shell command and capture stdout.
std::string runCommand(const std::string& cmd)
{
    std::string result;
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return result;
    char buf[256];
    while (fgets(buf, sizeof(buf), pipe))
        result += buf;
    pclose(pipe);
    return result;
}

// Write a temporary MIB definition file; caller must unlink.
std::string writeTempMib(const std::string& content)
{
    const std::string path = "/tmp/snf_server_test.mib";
    std::ofstream f(path, std::ios::trunc);
    f << content;
    return path;
}

void removeTempMib()
{
    std::remove("/tmp/snf_server_test.mib");
}

// OIDs reserved for SnmpServer integration tests (separate subtree from the
// pass-persist OIDs used by SnmpV3SessionTests at 1.3.6.1.4.1.99999.1.x.0).
constexpr const char* LIVE_INT_OID  = "1.3.6.1.4.1.99999.2.1.0";
constexpr const char* LIVE_STR_OID  = "1.3.6.1.4.1.99999.2.2.0";

// Credentials matching the existing test snmpd instance.
constexpr const char* SNF_USER      = "testuser";
constexpr const char* SNF_AUTH_PASS = "authpass";
constexpr const char* SNF_PRIV_PASS = "privpass";

SnmpV3Credentials makeTrapCreds()
{
    SnmpV3Credentials c;
    c.username       = SNF_USER;
    c.securityLevel  = SnmpSecurityLevel::AuthPriv;
    c.authProtocol   = SnmpAuthProtocol::SHA1;
    c.authPassphrase = SNF_AUTH_PASS;
    c.privProtocol   = SnmpPrivProtocol::AES128;
    c.privPassphrase = SNF_PRIV_PASS;
    return c;
}

} // namespace

// ══════════════════════════════════════════════════════════════════════════════
// I. LIFECYCLE TESTS
// ══════════════════════════════════════════════════════════════════════════════

// Construction and destruction without start() must not crash.
TEST(SnmpServerTests, constructAndDestroyWithoutStart)
{
    Application* app = new Application(0, nullptr);
    auto* server = new SnmpServer();
    EXPECT_NE(server, nullptr);
    delete server;
    delete app;
}

// isRunning() must be false before start().
TEST(SnmpServerTests, isRunningFalseBeforeStart)
{
    Application* app = new Application(0, nullptr);
    auto* server = new SnmpServer();
    EXPECT_FALSE(server->isRunning());
    delete server;
    delete app;
}

// stop() on a never-started server must not crash.
TEST(SnmpServerTests, stopWithoutStartIsSafe)
{
    Application* app = new Application(0, nullptr);
    auto* server = new SnmpServer();
    server->stop();
    EXPECT_FALSE(server->isRunning());
    delete server;
    delete app;
}

// loadMib() with a valid file returns true.
TEST(SnmpServerTests, loadMibValidFile)
{
    const std::string path = writeTempMib(
        "1.3.6.1.4.1.99999.1.1.0  INTEGER  RW  myInt  \"Integer\"\n"
        "1.3.6.1.4.1.99999.1.2.0  STRING   RO  myStr  \"String\"\n");

    Application* app = new Application(0, nullptr);
    auto* server = new SnmpServer();
    EXPECT_TRUE(server->loadMib(path));
    delete server;
    delete app;
    removeTempMib();
}

// loadMib() with a non-existent file returns false.
TEST(SnmpServerTests, loadMibNonExistentFile)
{
    Application* app = new Application(0, nullptr);
    auto* server = new SnmpServer();
    EXPECT_FALSE(server->loadMib("/tmp/does_not_exist.mib"));
    delete server;
    delete app;
}

// loadMib() with a malformed file returns false.
TEST(SnmpServerTests, loadMibMalformedFile)
{
    const std::string path = writeTempMib(
        "1.3.6.1.4.1.99999.1.1.0  BADTYPE  RO  myNode  \"Node\"\n");

    Application* app = new Application(0, nullptr);
    auto* server = new SnmpServer();
    EXPECT_FALSE(server->loadMib(path));
    delete server;
    delete app;
    removeTempMib();
}

// Registering read-only handlers by OID before start() must not crash.
TEST(SnmpServerTests, registerReadOnlyByOidBeforeStart)
{
    Application* app = new Application(0, nullptr);
    auto* server = new SnmpServer();
    server->registerReadOnly(
        SnmpOid(LIVE_INT_OID),
        []() { return SnmpValue::fromInteger32(42); });
    EXPECT_FALSE(server->isRunning()); // still not started
    delete server;
    delete app;
}

// Registering read-write handlers by OID before start() must not crash.
TEST(SnmpServerTests, registerReadWriteByOidBeforeStart)
{
    Application* app = new Application(0, nullptr);
    auto* server = new SnmpServer();
    server->registerReadWrite(
        SnmpOid(LIVE_INT_OID),
        []() { return SnmpValue::fromInteger32(0); },
        [](const SnmpValue&) { return true; });
    EXPECT_FALSE(server->isRunning());
    delete server;
    delete app;
}

// Registering by symbolic name after loadMib() must not crash.
TEST(SnmpServerTests, registerByNameAfterLoadMib)
{
    const std::string path = writeTempMib(
        "1.3.6.1.4.1.99999.1.1.0  INTEGER  RW  myInt  \"Integer\"\n");

    Application* app = new Application(0, nullptr);
    auto* server = new SnmpServer();
    ASSERT_TRUE(server->loadMib(path));

    server->registerReadWrite(
        "myInt",
        []() { return SnmpValue::fromInteger32(7); },
        [](const SnmpValue&) { return true; });

    EXPECT_FALSE(server->isRunning());
    delete server;
    delete app;
    removeTempMib();
}

// addTrapSink() before start() must not crash.
TEST(SnmpServerTests, addTrapSinkBeforeStart)
{
    Application* app = new Application(0, nullptr);
    auto* server = new SnmpServer();
    SnmpTrapSink sink;
    sink.host        = "127.0.0.1";
    sink.port        = 162;
    sink.credentials = makeTrapCreds();
    server->addTrapSink(sink);
    EXPECT_FALSE(server->isRunning());
    delete server;
    delete app;
}

// setMasterSocket() before start() must not crash.
TEST(SnmpServerTests, setMasterSocketBeforeStart)
{
    Application* app = new Application(0, nullptr);
    auto* server = new SnmpServer();
    server->setMasterSocket("/tmp/custom_agentx.sock");
    EXPECT_FALSE(server->isRunning());
    delete server;
    delete app;
}

// errorOccurred signal must be connectable without issues.
TEST(SnmpServerTests, errorOccurredSignalIsConnectable)
{
    Application* app = new Application(0, nullptr);
    auto* server = new SnmpServer();
    std::string lastErr;
    server->errorOccurred.connect([&lastErr](const std::string& msg) {
        lastErr = msg;
    });
    EXPECT_TRUE(lastErr.empty());
    delete server;
    delete app;
}

// ══════════════════════════════════════════════════════════════════════════════
// II. INTEGRATION TESTS
// ══════════════════════════════════════════════════════════════════════════════
//
// All tests in this group share a single module-level SnmpServer because
// net-snmp calls init_agent() only once per process.
//
// Run with:
//   SNMP_INTEGRATION_TESTS=1 ctest --preset native-debug -R SNFSnmpServerTests

namespace {

// State shared across live tests.
struct LiveAgentState
{
    Application*  app    = nullptr;
    SnmpServer*   server = nullptr;
    bool          ready  = false;

    // Handler counters / captured values (accessed from owner thread only).
    std::atomic<int>  getterCallCount{0};
    std::atomic<int>  setterCallCount{0};
    std::atomic<int32_t> setterLastValue{0};
};

LiveAgentState* g_live = nullptr;

} // namespace

// Fixture that starts (and keeps alive) the subagent for all live tests.
class SnmpServerLiveFixture : public ::testing::Test
{
protected:
    static void SetUpTestSuite()
    {
        if (!integrationTestsEnabled()) return;
        if (!snmpgetAvailable())        return;

        g_live = new LiveAgentState();
        g_live->app    = new Application(0, nullptr);
        g_live->server = new SnmpServer();

        // Register handlers.
        g_live->server->registerReadWrite(
            SnmpOid(LIVE_INT_OID),
            [&]() {
                g_live->getterCallCount.fetch_add(1, std::memory_order_relaxed);
                return SnmpValue::fromInteger32(77);
            },
            [&](const SnmpValue& v) {
                g_live->setterLastValue.store(v.toInt32(), std::memory_order_relaxed);
                g_live->setterCallCount.fetch_add(1, std::memory_order_relaxed);
                return true;
            });

        g_live->server->registerReadOnly(
            SnmpOid(LIVE_STR_OID),
            []() { return SnmpValue::fromOctetString("hello"); });

        // Connect error signal.
        g_live->server->errorOccurred.connect([](const std::string& msg) {
            std::fprintf(stderr, "[SnmpServer live] error: %s\n", msg.c_str());
        });

        // Start.
        if (g_live->server->start()) {
            g_live->ready = true;
            // Give AgentX time to register with snmpd.
            pumpUntil(*g_live->app,
                      []() { return false; }, // pump for fixed duration
                      1s);
        }
    }

    static void TearDownTestSuite()
    {
        if (!g_live) return;
        if (g_live->server) {
            g_live->server->stop();
            delete g_live->server;
        }
        delete g_live->app;
        delete g_live;
        g_live = nullptr;
    }

    bool skipLive() const
    {
        if (!integrationTestsEnabled()) return true;
        if (!g_live || !g_live->ready) return true;
        return false;
    }

    void skipReason() const
    {
        if (!integrationTestsEnabled())
            GTEST_SKIP() << "set SNMP_INTEGRATION_TESTS=1 to run";
        else
            GTEST_SKIP() << "SnmpServer::start() failed — "
                            "check snmpd master agentx config and /var/agentx/master permissions";
    }
};

// The subagent starts successfully and isRunning() becomes true.
TEST_F(SnmpServerLiveFixture, startSucceedsAndIsRunning)
{
    if (skipLive()) { skipReason(); return; }
    EXPECT_TRUE(g_live->server->isRunning());
}

// snmpget returns the value supplied by the getter lambda.
TEST_F(SnmpServerLiveFixture, getReturnsGetterValue)
{
    if (skipLive()) { skipReason(); return; }
    if (!snmpgetAvailable()) GTEST_SKIP() << "snmpget not found in PATH";

    const int prevCalls = g_live->getterCallCount.load();

    // Use SNMPv2c with community 'public' (as configured in test snmpd.conf).
    const std::string cmd =
        "snmpget -v2c -c public 127.0.0.1 " + std::string(LIVE_INT_OID) +
        " 2>&1";
    const std::string out = runCommand(cmd);

    // Pump to let Timer fire handler callbacks.
    pumpUntil(*g_live->app,
              [&]() {
                  return g_live->getterCallCount.load() > prevCalls;
              },
              2s);

    EXPECT_NE(out.find("77"), std::string::npos)
        << "snmpget output did not contain '77': " << out;
}

// snmpget on the read-only string OID returns the correct string.
TEST_F(SnmpServerLiveFixture, getReadOnlyStringReturnsValue)
{
    if (skipLive()) { skipReason(); return; }
    if (!snmpgetAvailable()) GTEST_SKIP() << "snmpget not found in PATH";

    const std::string cmd =
        "snmpget -v2c -c public 127.0.0.1 " + std::string(LIVE_STR_OID) +
        " 2>&1";
    const std::string out = runCommand(cmd);

    EXPECT_NE(out.find("hello"), std::string::npos)
        << "snmpget output did not contain 'hello': " << out;
}

// snmpset calls the setter lambda with the correct value.
TEST_F(SnmpServerLiveFixture, setCallsSetterWithCorrectValue)
{
    if (skipLive()) { skipReason(); return; }
    if (!snmpsetAvailable()) GTEST_SKIP() << "snmpset not found in PATH";

    const int prevSetterCalls = g_live->setterCallCount.load();

    const std::string cmd =
        "snmpset -v2c -c private 127.0.0.1 " + std::string(LIVE_INT_OID) +
        " i 999 2>&1";
    runCommand(cmd);

    // Pump the loop so the SET handler fires.
    bool called = pumpUntil(*g_live->app,
                            [&]() {
                                return g_live->setterCallCount.load() > prevSetterCalls;
                            },
                            2s);

    EXPECT_TRUE(called) << "setter was not called within timeout";
    EXPECT_EQ(g_live->setterLastValue.load(), 999)
        << "setter did not receive value 999";
}

// sendTrap() with no sinks returns true (no-op, nothing to send).
TEST_F(SnmpServerLiveFixture, sendTrapNoSinksReturnsTrue)
{
    if (skipLive()) { skipReason(); return; }

    const bool ok = g_live->server->sendTrap(SnmpOid(LIVE_INT_OID));
    EXPECT_TRUE(ok);
}
