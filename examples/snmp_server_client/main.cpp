/**
 * @file main.cpp
 * @brief SNMP client for the snmp_server example.
 *
 * This example demonstrates how to use SNFSnmp to read and write OIDs exposed
 * by the device server started by the @c snmp_server example.
 *
 * Operation sequence
 * ──────────────────
 *  1. Multi-GET   — reads at once: quectelStatus, quectelRsrp, nordicRsrp,
 *                   gnssFixStatus and clockTime.
 *  2. SET nordicBand — writes a new value (NB_BAND_NEW).
 *  3. GET nordicBand — confirms that the server stored the change.
 *  4. SET clockTime  — writes a custom timestamp.
 *  5. WALK           — traverses the full tree 1.3.6.1.4.1.99998.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * Prerequisites
 * ──────────────────────────────────────────────────────────────────────────
 *  - snmpd running with `master agentx` in /etc/snmp/snmpd.conf and
 *    v3 credentials configured:
 *
 *      createUser testuser SHA authpass AES privpass
 *      rwuser     testuser priv
 *
 *  - The snmp_server process running on the same machine.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * Usage
 * ──────────────────────────────────────────────────────────────────────────
 *  # Terminal 1:
 *  cd build/debug/examples/snmp_server && ./snmp_server
 *
 *  # Terminal 2:
 *  cd build/debug/examples/snmp_server_client && ./snmp_server_client
 * ──────────────────────────────────────────────────────────────────────────
 */

#include <SNFCore/Application.h>
#include <SNFCore/EventLoop.h>
#include <SNFCore/Timer.h>
#include <SNFSnmp/SnmpOid.h>
#include <SNFSnmp/SnmpTypes.h>
#include <SNFSnmp/SnmpV3Config.h>
#include <SNFSnmp/SnmpV3Credentials.h>
#include <SNFSnmp/SnmpV3Session.h>
#include <SNFSnmp/SnmpValue.h>
#include <SNFSnmp/SnmpVarBind.h>

#include <chrono>
#include <iostream>
#include <string>
#include <vector>

using namespace snf;
using namespace std::chrono_literals;

// ─── Configuration ───────────────────────────────────────────────────────────

static constexpr const char* AGENT_HOST      = "127.0.0.1";
static constexpr uint16_t    AGENT_PORT      = 161;
static constexpr const char* USERNAME        = "testuser";
static constexpr const char* AUTH_PASSPHRASE = "authpass";
static constexpr const char* PRIV_PASSPHRASE = "privpass";

// New Nordic band value to write.
static constexpr int NB_BAND_NEW = 3;

// Timestamp to write to clockTime.
static constexpr const char* CLOCK_TIME_NEW = "2026-01-01T00:00:00Z";

// OIDs from the snmp_server example.
namespace OID {
    // Quectel
    static const SnmpOid quectelStatus          ("1.3.6.1.4.1.99998.1.1.1.0");
    static const SnmpOid quectelRsrp            ("1.3.6.1.4.1.99998.1.1.7.0");
    // Nordic
    static const SnmpOid nordicRsrp             ("1.3.6.1.4.1.99998.1.2.5.0");
    static const SnmpOid nordicBand             ("1.3.6.1.4.1.99998.1.2.4.0");
    // GNSS
    static const SnmpOid gnssFixStatus          ("1.3.6.1.4.1.99998.3.2.0");
    // Clock
    static const SnmpOid clockTime              ("1.3.6.1.4.1.99998.4.2.0");
    // Root of the complete device tree.
    static const SnmpOid deviceRoot             ("1.3.6.1.4.1.99998");
}

// ─── Display helpers ─────────────────────────────────────────────────────────

namespace {

void printSeparator(const std::string& title)
{
    std::cout << "\n╔══ " << title << " ══\n";
}

void printVarBinds(const std::vector<SnmpVarBind>& vbs)
{
    for (const auto& vb : vbs)
        std::cout << "  " << vb.oid.toString()
                  << "  =  " << vb.value.toDisplayString() << '\n';
}

void stopLoop()
{
    if (EventLoop* loop = Application::instance()->getOrCreateCurrentThreadEventLoop())
        loop->post([loop]() { loop->stop(); });
}

} // namespace

// ─── Operation sequence ────────────────────────────────────────────────────────────────────

// The client executes five steps in sequence, each triggered upon receiving
// the signal from the previous step.  The class encapsulates state to avoid
// mutable global variables.

class DeviceClient
{
public:
    explicit DeviceClient(SnmpV3Session* session)
        : m_session(session)
    {
        connectSignals();
    }

    // Starts the sequence with the initial multi-GET.
    void run()
    {
        printSeparator("Step 1 of 5 — Multi-GET");
        std::cout << "  Reading quectelStatus, quectelRsrp, nordicRsrp, "
                     "gnssFixStatus, clockTime...\n";

        m_session->get({
            OID::quectelStatus,
            OID::quectelRsrp,
            OID::nordicRsrp,
            OID::gnssFixStatus,
            OID::clockTime,
        });
    }

private:
    void connectSignals()
    {
        // getResult — different behaviour depending on the current step.
        m_session->getResult.connect([this](const std::vector<SnmpVarBind>& vbs) {
            onGetResult(vbs);
        });

        // setResult — always advances to the confirmation read step.
        m_session->setResult.connect([this]() {
            onSetResult();
        });

        // walkResult — final step: prints the full tree and exits.
        m_session->walkResult.connect([](const std::vector<SnmpVarBind>& vbs) {
            printSeparator("Step 5 of 5 — WALK tree 1.3.6.1.4.1.99998");
            std::cout << "  " << vbs.size() << " objects found:\n";
            printVarBinds(vbs);
            std::cout << "\nClient completed successfully.\n";
            stopLoop();
        });

        // Any error: print and stop.
        m_session->errorOccurred.connect([](const std::string& msg) {
            std::cerr << "\n[SNMP error] " << msg
                      << "\nIs snmp_server running?\n";
            stopLoop();
        });
    }

    void onGetResult(const std::vector<SnmpVarBind>& vbs)
    {
        printVarBinds(vbs);
        m_getStep++;

        if (m_getStep == 1) {
            // Step 1 done → Step 2: SET nordicBand.
            printSeparator("Step 2 of 5 — SET nordicBand");
            std::cout << "  Writing nordicBand = " << NB_BAND_NEW << "...\n";

            SnmpVarBind vb;
            vb.oid   = OID::nordicBand;
            vb.value = SnmpValue::fromInteger32(NB_BAND_NEW);
            m_session->set(vb);
        }
        else if (m_getStep == 2) {
            // Step 3 done → Step 4: SET clockTime.
            printSeparator("Step 4 of 5 — SET clockTime");
            std::cout << "  Writing clockTime = \"" << CLOCK_TIME_NEW << "\"...\n";

            SnmpVarBind vb;
            vb.oid   = OID::clockTime;
            vb.value = SnmpValue::fromOctetString(CLOCK_TIME_NEW);
            m_session->set(vb);
        }
        else if (m_getStep == 3) {
            // Step 4 done → Step 5: WALK tree.
            printSeparator("Step 5 of 5 — WALK tree 1.3.6.1.4.1.99998");
            std::cout << "  Traversing the complete device tree...\n";
            m_session->walk(OID::deviceRoot);
        }
    }

    void onSetResult()
    {
        m_setStep++;

        if (m_setStep == 1) {
            // SET nordicBand OK → Step 3: GET nordicBand to confirm.
            printSeparator("Step 3 of 5 — GET nordicBand (confirmation read)");
            std::cout << "  Reading nordicBand to verify the change...\n";
            m_session->get(OID::nordicBand);
        }
        else if (m_setStep == 2) {
            // SET clockTime OK → read clockTime to confirm.
            std::cout << "  SET clockTime accepted — reading back...\n";
            m_session->get(OID::clockTime);
        }
    }

    SnmpV3Session* m_session;
    int            m_getStep = 0;
    int            m_setStep = 0;
};

// ─── main ─────────────────────────────────────────────────────────────────────

int main()
{
    Application app(0, nullptr);

    // ── SNMPv3 session ───────────────────────────────────────────────────────
    SnmpV3Config cfg;
    cfg.host    = AGENT_HOST;
    cfg.port    = AGENT_PORT;
    cfg.timeout = 5s;
    cfg.retries = 1;

    SnmpV3Credentials creds;
    creds.username       = USERNAME;
    creds.securityLevel  = SnmpSecurityLevel::AuthPriv;
    creds.authProtocol   = SnmpAuthProtocol::SHA1;
    creds.authPassphrase = AUTH_PASSPHRASE;
    creds.privProtocol   = SnmpPrivProtocol::AES128;
    creds.privPassphrase = PRIV_PASSPHRASE;

    auto* session = new SnmpV3Session();
    session->setConfig(cfg);
    session->setCredentials(creds);

    // ── 30 s watchdog ────────────────────────────────────────────────────────────────────
    auto* watchdog = new Timer();
    watchdog->setSingleShot(true);
    watchdog->timeout.connect([]() {
        std::cerr << "\n[Timeout] Sequence did not complete within 30 seconds.\n";
        stopLoop();
    });
    watchdog->start(30s);

    // ── Start client ────────────────────────────────────────────────────────────────────
    std::cout << "Connecting to " << AGENT_HOST << ':' << AGENT_PORT
              << "  (SNMPv3 AuthPriv, user=" << USERNAME << ")\n";

    DeviceClient client(session);
    client.run();

    app.run();
    return 0;
}
