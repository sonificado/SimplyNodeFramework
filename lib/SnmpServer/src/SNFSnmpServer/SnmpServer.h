#pragma once

/**
 * @file SnmpServer.h
 * @brief SNMPv3 AgentX subagent integrated with the SNF event loop.
 * @ingroup SNFSnmpServer
 */

#include "SNFSnmpServer/SnmpMibTree.h"
#include "SNFSnmpServer/SnmpTrapSink.h"

#include <SNFCore/Connection.h>
#include <SNFCore/Node.h>
#include <SNFSnmp/SnmpOid.h>
#include <SNFSnmp/SnmpTypes.h>
#include <SNFSnmp/SnmpVarBind.h>
#include <SNFSnmp/SnmpValue.h>

#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace snf {

class Timer;

/**
 * @brief Per-OID handler state.  Defined in SnmpServer.cpp to keep
 *        net-snmp headers out of this public header.
 */
struct SnmpHandlerEntry;

/**
 * @class SnmpServer
 * @ingroup SNFSnmpServer
 * @brief SNMPv3 AgentX subagent that exposes a configurable MIB tree and
 *        integrates with the SNF event loop without spawning extra threads.
 *
 * `SnmpServer` connects to a running snmpd master agent via the AgentX
 * protocol (Unix domain socket, default @c /var/agentx/master) and registers
 * user-supplied getter and setter lambdas for individual OIDs.
 *
 * GET / SET requests from any SNMP manager are received by snmpd, forwarded
 * over the AgentX session to this process, and turned into synchronous calls
 * to the registered lambdas — all on the owner thread.
 *
 * **Typical usage:**
 * @code
 * // 1. Load OID metadata from a definition file.
 * auto* server = new snf::SnmpServer();
 * server->loadMib("/etc/snmp/my-device.mib");
 *
 * // 2. Register lambdas for each managed object.
 * server->registerReadWrite("sensorTemp",
 *     []() { return snf::SnmpValue::fromInteger32(currentTemp()); },
 *     [](const snf::SnmpValue& v) { setTemp(v.toInt32()); return true; });
 *
 * server->registerReadOnly("uptime",
 *     []() { return snf::SnmpValue::fromTimeTicks(getUptimeTicks()); });
 *
 * // 3. Configure trap destination and start.
 * snf::SnmpTrapSink sink;
 * sink.host = "192.168.1.100";
 * sink.credentials = myCredentials;
 * server->addTrapSink(sink);
 *
 * if (!server->start()) {
 *     std::cerr << "Server failed to start\n";
 *     return;
 * }
 *
 * // 4. Send traps from anywhere on the owner thread.
 * server->sendTrap(snf::SnmpOid("1.3.6.1.4.1.99999.1.0.1"));
 * @endcode
 *
 * **Prerequisites:**
 * - snmpd must be running with `master agentx` in @c /etc/snmp/snmpd.conf.
 * - The process must have write permission to the AgentX socket (default
 *   @c /var/agentx/master, typically only accessible by root or the @c snmp
 *   group).
 *
 * **Limitations (v1):**
 * - Only one `SnmpServer` instance per process (net-snmp stores agent state
 *   globally).
 * - Calling `start()` after `stop()` is not supported; create a fresh instance.
 */
class SnmpServer : public Node
{
public:
    explicit SnmpServer(Node* parent = nullptr);
    ~SnmpServer() override;

    // ── Configuration — must be called before start() ─────────────────────

    /**
     * @brief Sets the Unix domain socket path of the AgentX master agent.
     *
     * Defaults to @c /var/agentx/master. Override only when snmpd is
     * configured with a different @c agentXSocket path.
     */
    void setMasterSocket(const std::string& unixSocketPath);

    /**
     * @brief Loads OID metadata from a definition file.
     *
     * After a successful load, `registerReadOnly()` and `registerReadWrite()`
     * can be called using symbolic names instead of raw OIDs.
     *
     * @return @c true on success, @c false on parse / IO error (details in
     *         @c errorOccurred).
     */
    bool loadMib(const std::string& filePath);

    // ── Handler registration ───────────────────────────────────────────────

    /**
     * @brief Registers a read-only handler by OID.
     *
     * @p getter is called on the owner thread whenever a GET or GETNEXT
     * request arrives for @p oid.
     */
    void registerReadOnly(const SnmpOid&                   oid,
                          std::function<SnmpValue()>        getter);

    /**
     * @brief Registers a read-only handler by symbolic MIB name.
     *
     * Looks up the OID in the MIB tree loaded by `loadMib()`.
     * @p name must match exactly the @c NAME field in the definition file.
     */
    void registerReadOnly(const std::string&               name,
                          std::function<SnmpValue()>        getter);

    /**
     * @brief Registers a read-write handler by OID.
     *
     * @p getter is called for GET requests.
     * @p setter is called for SET requests and must return @c true on success
     * or @c false to signal a @c genErr to the requesting manager.
     */
    void registerReadWrite(const SnmpOid&                         oid,
                           std::function<SnmpValue()>              getter,
                           std::function<bool(const SnmpValue&)>   setter);

    /**
     * @brief Registers a read-write handler by symbolic MIB name.
     *
     * Looks up the OID in the MIB tree loaded by `loadMib()`.
     */
    void registerReadWrite(const std::string&                     name,
                           std::function<SnmpValue()>              getter,
                           std::function<bool(const SnmpValue&)>   setter);

    // ── Trap sinks ─────────────────────────────────────────────────────────

    /**
     * @brief Adds an SNMP manager that should receive TRAPs sent by
     *        `sendTrap()`.
     */
    void addTrapSink(const SnmpTrapSink& sink);

    // ── Lifecycle ──────────────────────────────────────────────────────────

    /**
     * @brief Opens the AgentX connection and starts serving GET/SET requests.
     *
     * All handlers must be registered before `start()`.
     *
     * @return @c true on success; @c false if the connection to the master
     *         agent could not be established (details in @c errorOccurred).
     */
    bool start();

    /**
     * @brief Stops the AgentX session and the event-loop poll timer.
     *
     * After `stop()` this instance is permanently deactivated.  Create a new
     * `SnmpServer` if you need to reconnect.
     */
    void stop();

    /** @brief Returns @c true while the server is connected and polling. */
    bool isRunning() const noexcept;

    // ── Trap sending ───────────────────────────────────────────────────────

    /**
     * @brief Sends an SNMPv3 TRAP2 PDU to every configured trap sink.
     *
     * Must be called from the owner thread.
     *
     * @param trapOid       The OID identifying the trap type (snmpTrapOID.0).
     * @param extraVarbinds Additional variable bindings appended after the
     *                      mandatory sysUpTime.0 and snmpTrapOID.0.
     * @return @c true if all sinks were reached; @c false if at least one
     *         failed (details in @c errorOccurred).
     */
    bool sendTrap(const SnmpOid&                   trapOid,
                  const std::vector<SnmpVarBind>&  extraVarbinds = {});

    // ── Signals ────────────────────────────────────────────────────────────

    /**
     * @brief Emitted on the owner thread when a non-recoverable error occurs.
     *
     * Examples: `start()` failure, trap-send failure.
     */
    Signal<std::string> errorOccurred;

    void update() override {}

protected:
    void onAboutToMoveToThread(EventLoop* newLoop) override;
    void onMovedToThread(EventLoop* oldLoop)       override;

private:
    void doRegisterEntry(SnmpHandlerEntry* entry);
    void onPollTick();

    std::string               m_masterSocket = "/var/agentx/master";
    SnmpMibTree               m_mibTree;
    std::vector<SnmpTrapSink> m_trapSinks;

    std::vector<std::unique_ptr<SnmpHandlerEntry>> m_handlers;

    Timer* m_pollTimer = nullptr;
    bool   m_running   = false;
};

} // namespace snf
