/**
 * @file main.cpp
 * @brief Complete example of an SNMP AgentX server (SNFSnmpServer).
 *
 * This example starts an AgentX subagent that exposes the device MIB defined
 * in @c my-device.mib.  The subagent connects to a running snmpd master agent
 * and answers GET/SET requests from any SNMP manager.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * What this example does
 * ──────────────────────────────────────────────────────────────────────────
 *  1. Loads the MIB from @c my-device.mib (copied next to the binary).
 *  2. Registers getters/setters for each OID.
 *  3. Starts the subagent (connects to the AgentX socket of the snmpd master).
 *  4. Every 5 seconds simulates signal variation (RSRP).
 *  5. Sends a TRAP when the Quectel modem status changes.
 *  6. Stops cleanly on SIGINT (Ctrl-C).
 *
 * ──────────────────────────────────────────────────────────────────────────
 * Prerequisites
 * ──────────────────────────────────────────────────────────────────────────
 *  1. snmpd installed and running with AgentX enabled.
 *
 *     Add to /etc/snmp/snmpd.conf:
 *
 *       master agentx
 *       agentXSocket /var/agentx/master
 *
 *       # Read access (public community)
 *       rocommunity public  default
 *
 *       # Write access from localhost only
 *       rwcommunity private 127.0.0.1
 *
 *     Restart:  sudo systemctl restart snmpd
 *
 *  2. The process must have write permission on /var/agentx/master.
 *     Easiest in development:  sudo chmod 777 /var/agentx/master
 *     Or add your user to the snmp group:  sudo usermod -aG snmp $USER
 *
 *  3. To test from the command line (snmp package):
 *
 *       snmpget  -v2c -c public  127.0.0.1  1.3.6.1.4.1.99998.1.1.7.0
 *       snmpset  -v2c -c private 127.0.0.1  1.3.6.1.4.1.99998.1.2.4.0 i 3
 *       snmpwalk -v2c -c public  127.0.0.1  1.3.6.1.4.1.99998
 *
 * ──────────────────────────────────────────────────────────────────────────
 * How to extend the MIB
 * ──────────────────────────────────────────────────────────────────────────
 *  1. Edit my-device.mib: add a line with the OID, type, access and name.
 *  2. In DeviceState add the corresponding state field.
 *  3. Call registerReadOnly() / registerReadWrite() in registerHandlers().
 *  4. Recompile.
 * ──────────────────────────────────────────────────────────────────────────
 */

#include <SNFCore/Application.h>
#include <SNFCore/EventLoop.h>
#include <SNFCore/Timer.h>
#include <SNFSnmp/SnmpOid.h>
#include <SNFSnmp/SnmpTypes.h>
#include <SNFSnmp/SnmpValue.h>
#include <SNFSnmp/SnmpVarBind.h>
#include <SNFSnmp/SnmpV3Credentials.h>
#include <SNFSnmpServer/SnmpServer.h>
#include <SNFSnmpServer/SnmpTrapSink.h>

#include <chrono>
#include <csignal>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <string>

using namespace snf;
using namespace std::chrono_literals;

// ─── Configuration ───────────────────────────────────────────────────────────

// AgentX socket of the snmpd master.
static constexpr const char* AGENTX_SOCKET = "/var/agentx/master";

// MIB definition file (relative to the binary directory in build,
// or an absolute path when running from another directory).
static constexpr const char* MIB_FILE = "my-device.mib";

// Notification OID "quectelStatusChanged".
// SNMPv2 convention: enterprise.0.specificTrapNumber
static constexpr const char* TRAP_OID_QUECTEL_STATUS = "1.3.6.1.4.1.99998.0.1";

// ─── Simulated device state ──────────────────────────────────────────────────

struct DeviceState
{
    // ── Quectel 5G ──
    int         quectelStatus           = 1;      // 1=connected 2=disconnected
    int         quectelRegistrationState= 1;      // 1=home
    std::string quectelPlmn             = "21407";
    int         quectelCellId           = 0x1A2B;
    int         quectelTac              = 0x0100;
    int         quectelRat              = 2;      // 2=NR-SA
    int         quectelRsrp             = -85;    // dBm
    int         quectelRsrq             = -10;    // dB
    int         quectelSinr             = 15;     // dB

    // ── Nordic nRF91 ──
    int         nordicRegistrationState = 1;      // 1=home
    std::string nordicPlmn              = "21407";
    int         nordicCellId            = 0x3C4D;
    int         nordicBand              = 20;
    int         nordicRsrp              = -92;    // dBm
    int         nordicSnr               = 8;      // dB

    // ── SIM slot 1 (Quectel) ──
    std::string sim1Iccid               = "89340150100041015234";
    int         sim1Type                = 1;      // 1=physical
    int         sim1Present             = 1;      // present
    int         sim1BoundModem          = 1;      // quectel
    int         sim1Status              = 1;      // ok

    // ── SIM slot 2 (Nordic) ──
    std::string sim2Iccid               = "89340150100041015235";
    int         sim2Type                = 1;
    int         sim2Present             = 1;
    int         sim2BoundModem          = 2;      // nordic
    int         sim2Status              = 1;      // ok

    // ── GNSS ──
    int         gnssSource              = 1;      // 1=quectel
    int         gnssFixStatus           = 2;      // 2=fix3D
    int         gnssTimeValid           = 1;      // valid
    int         gnssSatellitesUsed      = 8;

    // ── Clock ──
    int         clockSource             = 1;      // 1=gnss
    std::string clockTime               = "2025-04-21T10:30:00Z";
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

namespace {

// Returns the current system time as an ISO 8601 timestamp.
std::string nowIso8601()
{
    const std::time_t t = std::time(nullptr);
    std::tm utc{};
    gmtime_r(&t, &utc);
    std::ostringstream ss;
    ss << std::put_time(&utc, "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

} // namespace

// ─── Handler registration ────────────────────────────────────────────────────

// Registers all MIB OIDs with the SnmpServer.
// Getters always read from the live DeviceState object; setters write back to it.
//
// Note: lambdas capture 'state' by reference; DeviceState outlives the
// entire main(), so this is safe.
void registerHandlers(SnmpServer& server, DeviceState& state)
{
    // ── Quectel 5G ──────────────────────────────────────────────────────────
    server.registerReadOnly("quectelStatus",
        [&]{ return SnmpValue::fromInteger32(state.quectelStatus); });

    server.registerReadOnly("quectelRegistrationState",
        [&]{ return SnmpValue::fromInteger32(state.quectelRegistrationState); });

    server.registerReadOnly("quectelPlmn",
        [&]{ return SnmpValue::fromOctetString(state.quectelPlmn); });

    server.registerReadOnly("quectelCellId",
        [&]{ return SnmpValue::fromInteger32(state.quectelCellId); });

    server.registerReadOnly("quectelTac",
        [&]{ return SnmpValue::fromInteger32(state.quectelTac); });

    server.registerReadOnly("quectelRat",
        [&]{ return SnmpValue::fromInteger32(state.quectelRat); });

    server.registerReadOnly("quectelRsrp",
        [&]{ return SnmpValue::fromInteger32(state.quectelRsrp); });

    server.registerReadOnly("quectelRsrq",
        [&]{ return SnmpValue::fromInteger32(state.quectelRsrq); });

    server.registerReadOnly("quectelSinr",
        [&]{ return SnmpValue::fromInteger32(state.quectelSinr); });

    // ── Nordic nRF91 ─────────────────────────────────────────────────────────
    server.registerReadOnly("nordicRegistrationState",
        [&]{ return SnmpValue::fromInteger32(state.nordicRegistrationState); });

    server.registerReadOnly("nordicPlmn",
        [&]{ return SnmpValue::fromOctetString(state.nordicPlmn); });

    server.registerReadOnly("nordicCellId",
        [&]{ return SnmpValue::fromInteger32(state.nordicCellId); });

    server.registerReadWrite("nordicBand",
        [&]{
            std::cout << "[GET] nordicBand = " << state.nordicBand << "\n";
            return SnmpValue::fromInteger32(state.nordicBand);
        },
        [&](const SnmpValue& v) {
            const int band = v.toInt32();
            if (band < 1 || band > 71) {
                std::cerr << "[SET] nordicBand: invalid value " << band << "\n";
                return false;
            }
            std::cout << "[SET] nordicBand = " << band << "\n";
            state.nordicBand = band;
            return true;
        });

    server.registerReadOnly("nordicRsrp",
        [&]{ return SnmpValue::fromInteger32(state.nordicRsrp); });

    server.registerReadOnly("nordicSnr",
        [&]{ return SnmpValue::fromInteger32(state.nordicSnr); });

    // ── SIM slot 1 ───────────────────────────────────────────────────────────
    server.registerReadOnly("simSlotIndex1",
        []{ return SnmpValue::fromInteger32(1); });

    server.registerReadOnly("simType1",
        [&]{ return SnmpValue::fromInteger32(state.sim1Type); });

    server.registerReadOnly("simIccid1",
        [&]{ return SnmpValue::fromOctetString(state.sim1Iccid); });

    server.registerReadOnly("simPresent1",
        [&]{ return SnmpValue::fromInteger32(state.sim1Present); });

    server.registerReadOnly("simBoundModem1",
        [&]{ return SnmpValue::fromInteger32(state.sim1BoundModem); });

    server.registerReadOnly("simStatus1",
        [&]{ return SnmpValue::fromInteger32(state.sim1Status); });

    // ── SIM slot 2 ───────────────────────────────────────────────────────────
    server.registerReadOnly("simSlotIndex2",
        []{ return SnmpValue::fromInteger32(2); });

    server.registerReadOnly("simType2",
        [&]{ return SnmpValue::fromInteger32(state.sim2Type); });

    server.registerReadOnly("simIccid2",
        [&]{ return SnmpValue::fromOctetString(state.sim2Iccid); });

    server.registerReadOnly("simPresent2",
        [&]{ return SnmpValue::fromInteger32(state.sim2Present); });

    server.registerReadOnly("simBoundModem2",
        [&]{ return SnmpValue::fromInteger32(state.sim2BoundModem); });

    server.registerReadOnly("simStatus2",
        [&]{ return SnmpValue::fromInteger32(state.sim2Status); });

    // ── GNSS ─────────────────────────────────────────────────────────────────
    server.registerReadWrite("gnssSource",
        [&]{
            std::cout << "[GET] gnssSource = " << state.gnssSource << "\n";
            return SnmpValue::fromInteger32(state.gnssSource);
        },
        [&](const SnmpValue& v) {
            const int src = v.toInt32();
            if (src < 1 || src > 3) return false;
            std::cout << "[SET] gnssSource = " << src << "\n";
            state.gnssSource = src;
            return true;
        });

    server.registerReadOnly("gnssFixStatus",
        [&]{ return SnmpValue::fromInteger32(state.gnssFixStatus); });

    server.registerReadOnly("gnssTimeValid",
        [&]{ return SnmpValue::fromInteger32(state.gnssTimeValid); });

    server.registerReadOnly("gnssSatellitesUsed",
        [&]{ return SnmpValue::fromInteger32(state.gnssSatellitesUsed); });

    // ── Clock ────────────────────────────────────────────────────────────────
    server.registerReadWrite("clockSource",
        [&]{
            std::cout << "[GET] clockSource = " << state.clockSource << "\n";
            return SnmpValue::fromInteger32(state.clockSource);
        },
        [&](const SnmpValue& v) {
            const int src = v.toInt32();
            if (src < 1 || src > 3) return false;
            std::cout << "[SET] clockSource = " << src << "\n";
            state.clockSource = src;
            return true;
        });

    server.registerReadWrite("clockTime",
        [&]{
            std::cout << "[GET] clockTime = " << state.clockTime << "\n";
            return SnmpValue::fromOctetString(state.clockTime);
        },
        [&](const SnmpValue& v) {
            const std::string t = v.toString();
            std::cout << "[SET] clockTime = \"" << t << "\"\n";
            state.clockTime = t;
            return true;
        });
}

// ─── main ─────────────────────────────────────────────────────────────────────

int main()
{
    Application app(0, nullptr);

    // ── Device state (lives on the main() stack) ─────────────────────────────
    DeviceState state;

    // ── SNMP server ──────────────────────────────────────────────────────────
    auto* server = new SnmpServer();
    server->setMasterSocket(AGENTX_SOCKET);

    server->errorOccurred.connect([](const std::string& msg) {
        std::cerr << "[snmp_server] Error: " << msg << "\n";
    });

    // Load the MIB.
    if (!server->loadMib(MIB_FILE)) {
        std::cerr << "[snmp_server] Failed to load " << MIB_FILE
                  << ". Make sure you run the binary from its build directory.\n";
        delete server;
        return 1;
    }

    // Register handlers.
    registerHandlers(*server, state);

    // Start the subagent.
    if (!server->start()) {
        std::cerr << "[snmp_server] Failed to connect to the AgentX master at "
                  << AGENTX_SOCKET << ".\n"
                  << "Check that snmpd is running with 'master agentx' "
                  "in its configuration.\n";
        delete server;
        return 1;
    }

    std::cout << "[snmp_server] Subagent started. Socket: " << AGENTX_SOCKET << "\n"
              << "[snmp_server] MIB tree: 1.3.6.1.4.1.99998\n"
              << "[snmp_server] Ctrl-C to stop.\n\n";

    // ── Simulation timer (every 5 s) ─────────────────────────────────────────
    std::mt19937 rng(42);
    std::uniform_int_distribution<int> jitter(-3, 3);
    std::uniform_int_distribution<int> eventDice(0, 29); // prob ~1/30 por tick

    int prevQuectelStatus = state.quectelStatus;

    auto* simTimer = new Timer();
    simTimer->setInterval(5s);
    simTimer->timeout.connect([&] {
        // Simulate signal variation.
        state.quectelRsrp  = std::max(-140, std::min(-44, state.quectelRsrp  + jitter(rng)));
        state.quectelSinr  = std::max(-20,  std::min(30,  state.quectelSinr  + jitter(rng)));
        state.nordicRsrp   = std::max(-140, std::min(-44, state.nordicRsrp   + jitter(rng)));
        state.nordicSnr    = std::max(-20,  std::min(30,  state.nordicSnr    + jitter(rng)));

        // Simulate GNSS satellites.
        state.gnssSatellitesUsed = std::max(0, std::min(16,
            state.gnssSatellitesUsed + (jitter(rng) > 1 ? 1 : (jitter(rng) < -1 ? -1 : 0))));

        // Update system time to wall-clock time.
        state.clockTime = nowIso8601();

        // Simulate occasional Quectel modem disconnect/reconnect.
        if (eventDice(rng) == 0) {
            state.quectelStatus = (state.quectelStatus == 1) ? 2 : 1;
            state.quectelRegistrationState = (state.quectelStatus == 1) ? 1 : 0;
        }

        // Send TRAP if status changed.
        if (state.quectelStatus != prevQuectelStatus) {
            const char* newStatus = (state.quectelStatus == 1) ? "CONNECTED" : "DISCONNECTED";
            std::cout << "[TRAP] quectelStatus -> " << newStatus << "\n";

            SnmpVarBind statusVb;
            statusVb.oid   = SnmpOid("1.3.6.1.4.1.99998.1.1.1.0");
            statusVb.value = SnmpValue::fromInteger32(state.quectelStatus);

            server->sendTrap(SnmpOid(TRAP_OID_QUECTEL_STATUS), {statusVb});
            prevQuectelStatus = state.quectelStatus;
        }
    });
    simTimer->start();

    // ── SIGINT signal → clean stop ───────────────────────────────────────────
    // The signal is converted to an event-loop event via a classic pipe.
    static bool g_quit = false;
    std::signal(SIGINT, [](int) { g_quit = true; });

    EventLoop* loop = app.getOrCreateCurrentThreadEventLoop();
    while (!g_quit) {
        loop->runPendingWork();
        std::this_thread::sleep_for(10ms);
    }

    std::cout << "\n[snmp_server] Stopping...\n";
    server->stop();

    return 0;
}
