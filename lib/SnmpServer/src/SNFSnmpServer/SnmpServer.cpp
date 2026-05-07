/**
 * @file SnmpServer.cpp
 * @ingroup SNFSnmpServer
 *
 * Implementation notes
 * ────────────────────
 * Threading model
 * ───────────────
 * No background threads are created.  A 50 ms repeating `Timer` calls
 * `agent_check_and_process(0)` on the owner thread.  That function does a
 * non-blocking `select()` over the AgentX Unix-domain socket, processes any
 * waiting PDUs, and calls `snmp_timeout()` + `run_alarms()`.  GET/SET handler
 * lambdas are therefore invoked synchronously on the owner thread.
 *
 * Global agent initialisation
 * ───────────────────────────
 * `netsnmp_ds_set_boolean(…, NETSNMP_DS_AGENT_ROLE, SUB_AGENT)` and
 * `init_agent()` mutate process-global net-snmp state and must each be called
 * exactly once.  A `std::once_flag` guards this.  `init_master_agent()` opens
 * the AgentX connection and may be retried, but in v1 we do not retry — the
 * user should check `start()` return value and adopt their own retry policy.
 *
 * Handler registration
 * ────────────────────
 * Each OID is registered as a "scalar instance" via
 * `netsnmp_register_instance()`.  The per-OID `HandlerEntry` (owning the
 * getter/setter lambdas) is stored in `handler->myvoid`; the static
 * `handlerCallback` function dispatches MODE_GET / MODE_SET_ACTION to the
 * appropriate lambda.
 *
 * Trap sending
 * ────────────
 * For each `SnmpTrapSink`, a fresh SNMPv3 session is opened (same key-
 * derivation as `SnmpV3Session`), a `SNMP_MSG_TRAP2` PDU is built with the
 * standard sysUpTime.0 and snmpTrapOID.0 varbinds prepended, and `snmp_send()`
 * fires it.
 */

// net-snmp agent headers MUST come before all other headers.
// Order matters: config → base manager includes → agent includes.
#include <net-snmp/net-snmp-config.h>               // NOLINT
#include <net-snmp/net-snmp-includes.h>             // NOLINT
#include <net-snmp/agent/net-snmp-agent-includes.h> // NOLINT

// SHA-256/512 length constants may be missing on older distributions.
#ifdef NETSNMP_DRAFT_BLUMENTHAL_AES_04
#  ifndef USM_AUTH_PROTO_SHA256_LEN
#    define USM_AUTH_PROTO_SHA256_LEN OID_LENGTH(usmHMAC192SHA256AuthProtocol)
#  endif
#  ifndef USM_AUTH_PROTO_SHA512_LEN
#    define USM_AUTH_PROTO_SHA512_LEN OID_LENGTH(usmHMAC384SHA512AuthProtocol)
#  endif
#  ifndef USM_PRIV_PROTO_AES256_LEN
#    define USM_PRIV_PROTO_AES256_LEN OID_LENGTH(usmAES256PrivProtocol)
#  endif
#endif

#include "SNFSnmpServer/SnmpServer.h"

#include <SNFCore/NodePtr.h>
#include <SNFCore/Timer.h>
#include <SNFSnmp/SnmpV3Credentials.h>

#include <arpa/inet.h>

#include <cstring>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

namespace snf {

// ══════════════════════════════════════════════════════════════════════════════
// Internal types — not exposed in header
// ══════════════════════════════════════════════════════════════════════════════

struct SnmpHandlerEntry
{
    std::string  name;   // used as net-snmp handler registration name
    SnmpOid      oid;
    SnmpAccess   access  = SnmpAccess::ReadOnly;
    std::function<SnmpValue()>            getter;
    std::function<bool(const SnmpValue&)> setter; // nullptr for ReadOnly
    void*        registration = nullptr; // opaque netsnmp_handler_registration*
};

// ══════════════════════════════════════════════════════════════════════════════
// File-local helpers
// ══════════════════════════════════════════════════════════════════════════════
namespace {

// ── Global agent init (once per process) ─────────────────────────────────────

std::once_flag g_agentInitFlag;

void snmpAgentGlobalInit()
{
    std::call_once(g_agentInitFlag, [] {
        netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID,
                               NETSNMP_DS_AGENT_ROLE,
                               1 /* sub-agent role */);
        init_agent("SNFSnmpServer");
        // init_snmp() completes full SNMP subsystem initialisation (auth,
        // engine-ID, config reading, MIB internals, agentx callbacks).
        // Must be called AFTER init_agent() and BEFORE init_master_agent().
        init_snmp("SNFSnmpServer");
    });
}

// ── Auth / priv protocol helpers (duplicated from SnmpV3Session.cpp) ─────────

struct AuthInfo { const oid* proto; std::size_t protoLen; };
struct PrivInfo { const oid* proto; std::size_t protoLen; };

AuthInfo authInfoFor(SnmpAuthProtocol p)
{
    switch (p) {
        case SnmpAuthProtocol::MD5:
            return { usmHMACMD5AuthProtocol,  USM_AUTH_PROTO_MD5_LEN };
        case SnmpAuthProtocol::SHA1:
            return { usmHMACSHA1AuthProtocol, USM_AUTH_PROTO_SHA_LEN };
        case SnmpAuthProtocol::SHA256:
#ifdef NETSNMP_DRAFT_BLUMENTHAL_AES_04
            return { usmHMAC192SHA256AuthProtocol, USM_AUTH_PROTO_SHA256_LEN };
#else
            return { usmHMACSHA1AuthProtocol, USM_AUTH_PROTO_SHA_LEN };
#endif
        case SnmpAuthProtocol::SHA512:
#ifdef NETSNMP_DRAFT_BLUMENTHAL_AES_04
            return { usmHMAC384SHA512AuthProtocol, USM_AUTH_PROTO_SHA512_LEN };
#else
            return { usmHMACSHA1AuthProtocol, USM_AUTH_PROTO_SHA_LEN };
#endif
        default:
            return { usmNoAuthProtocol, USM_AUTH_PROTO_NOAUTH_LEN };
    }
}

PrivInfo privInfoFor(SnmpPrivProtocol p)
{
    switch (p) {
        case SnmpPrivProtocol::DES:
            return { usmDESPrivProtocol,  USM_PRIV_PROTO_DES_LEN };
        case SnmpPrivProtocol::AES128:
            return { usmAESPrivProtocol,  USM_PRIV_PROTO_AES_LEN };
        case SnmpPrivProtocol::AES256:
#ifdef NETSNMP_DRAFT_BLUMENTHAL_AES_04
            return { usmAES256PrivProtocol, USM_PRIV_PROTO_AES256_LEN };
#else
            return { usmAESPrivProtocol, USM_PRIV_PROTO_AES_LEN };
#endif
        default:
            return { usmNoPrivProtocol, USM_PRIV_PROTO_NOPRIV_LEN };
    }
}

// ── OID conversion ─────────────────────────────────────────────────────────

std::vector<oid> toNetSnmpOid(const SnmpOid& snmpOid)
{
    const auto& comps = snmpOid.components();
    return std::vector<oid>(comps.begin(), comps.end());
}

// ── Value → varbind setter (used in GET handler) ──────────────────────────

void setVarValue(netsnmp_variable_list* var, const SnmpValue& val)
{
    switch (val.type()) {
        case SnmpValueType::Integer32: {
            long v = static_cast<long>(val.toInt32());
            snmp_set_var_typed_value(var, ASN_INTEGER,
                                     reinterpret_cast<u_char*>(&v), sizeof(v));
            break;
        }
        case SnmpValueType::Counter32: {
            u_long v = static_cast<u_long>(val.toUint32());
            snmp_set_var_typed_value(var, ASN_COUNTER,
                                     reinterpret_cast<u_char*>(&v), sizeof(v));
            break;
        }
        case SnmpValueType::Gauge32: {
            u_long v = static_cast<u_long>(val.toUint32());
            snmp_set_var_typed_value(var, ASN_GAUGE,
                                     reinterpret_cast<u_char*>(&v), sizeof(v));
            break;
        }
        case SnmpValueType::TimeTicks: {
            u_long v = static_cast<u_long>(val.toUint32());
            snmp_set_var_typed_value(var, ASN_TIMETICKS,
                                     reinterpret_cast<u_char*>(&v), sizeof(v));
            break;
        }
        case SnmpValueType::Counter64: {
            struct counter64 c64 = {};
            const auto v64 = val.toCounter64();
            c64.high = static_cast<u_long>(v64 >> 32);
            c64.low  = static_cast<u_long>(v64 & 0xFFFFFFFFULL);
            snmp_set_var_typed_value(var, ASN_COUNTER64,
                                     reinterpret_cast<u_char*>(&c64),
                                     sizeof(c64));
            break;
        }
        case SnmpValueType::OctetString: {
            const auto& bytes = val.toBytes();
            snmp_set_var_typed_value(var, ASN_OCTET_STR,
                                     bytes.data(),
                                     static_cast<size_t>(bytes.size()));
            break;
        }
        case SnmpValueType::Opaque: {
            const auto& bytes = val.toBytes();
            snmp_set_var_typed_value(var, ASN_OPAQUE,
                                     bytes.data(),
                                     static_cast<size_t>(bytes.size()));
            break;
        }
        case SnmpValueType::IpAddress: {
            in_addr_t addr = 0;
            inet_pton(AF_INET, val.toString().c_str(), &addr);
            snmp_set_var_typed_value(var, ASN_IPADDRESS,
                                     reinterpret_cast<u_char*>(&addr), 4);
            break;
        }
        case SnmpValueType::ObjectIdentifier: {
            const auto netOid = toNetSnmpOid(val.toOid());
            snmp_set_var_typed_value(var, ASN_OBJECT_ID,
                                     reinterpret_cast<const u_char*>(netOid.data()),
                                     netOid.size() * sizeof(oid));
            break;
        }
        default:
            snmp_set_var_typed_value(var, ASN_NULL, nullptr, 0);
            break;
    }
}

// ── Varbind → SnmpValue parser (used in SET handler) ─────────────────────

SnmpValue parseVarBind(const netsnmp_variable_list* vb)
{
    if (!vb) return {};
    switch (vb->type) {
        case ASN_INTEGER:
            return SnmpValue::fromInteger32(
                static_cast<std::int32_t>(*vb->val.integer));
        case ASN_COUNTER:
            return SnmpValue::fromCounter32(
                static_cast<std::uint32_t>(*vb->val.integer));
        case ASN_GAUGE:
            return SnmpValue::fromGauge32(
                static_cast<std::uint32_t>(*vb->val.integer));
        case ASN_TIMETICKS:
            return SnmpValue::fromTimeTicks(
                static_cast<std::uint32_t>(*vb->val.integer));
        case ASN_COUNTER64: {
            const std::uint64_t v =
                (static_cast<std::uint64_t>(vb->val.counter64->high) << 32) |
                 static_cast<std::uint64_t>(vb->val.counter64->low);
            return SnmpValue::fromCounter64(v);
        }
        case ASN_OCTET_STR:
            return SnmpValue::fromOctetString(
                std::vector<std::uint8_t>(vb->val.string,
                                          vb->val.string + vb->val_len));
        case ASN_IPADDRESS: {
            char ipbuf[INET_ADDRSTRLEN] = {};
            inet_ntop(AF_INET, vb->val.string, ipbuf, sizeof(ipbuf));
            return SnmpValue::fromIpAddress(ipbuf);
        }
        case ASN_OBJECT_ID: {
            std::vector<std::uint32_t> comps(
                vb->val.objid,
                vb->val.objid + vb->val_len / sizeof(oid));
            return SnmpValue::fromObjectIdentifier(SnmpOid(std::move(comps)));
        }
        default:
            return {};
    }
}

// ── Per-OID handler callback (called by net-snmp on the owner thread) ───────

static int handlerCallback(netsnmp_mib_handler*          handler,
                            netsnmp_handler_registration* /*reginfo*/,
                            netsnmp_agent_request_info*   reqinfo,
                            netsnmp_request_info*         requests)
{
    auto* entry = static_cast<SnmpHandlerEntry*>(handler->myvoid);
    if (!entry) return SNMP_ERR_GENERR;

    for (netsnmp_request_info* req = requests; req; req = req->next) {
        switch (reqinfo->mode) {
            case MODE_GET: {
                if (!entry->getter) {
                    netsnmp_set_request_error(reqinfo, req, SNMP_ERR_NOSUCHNAME);
                    break;
                }
                SnmpValue val = entry->getter();
                setVarValue(req->requestvb, val);
                break;
            }

            case MODE_SET_RESERVE1:
                // First SET pass: reject if this handler is read-only.
                if (!entry->setter) {
                    netsnmp_set_request_error(reqinfo, req, SNMP_ERR_NOTWRITABLE);
                }
                break;

            case MODE_SET_ACTION: {
                // Second SET pass: apply the new value.
                SnmpValue newVal = parseVarBind(req->requestvb);
                if (entry->setter && !entry->setter(newVal)) {
                    netsnmp_set_request_error(reqinfo, req, SNMP_ERR_GENERR);
                }
                break;
            }

            case MODE_SET_RESERVE2:
            case MODE_SET_COMMIT:
            case MODE_SET_FREE:
            case MODE_SET_UNDO:
                // No multi-phase transactional semantics needed for scalars.
                break;

            default:
                break;
        }
    }
    return SNMP_ERR_NOERROR;
}

// ── Open a manager session for trap sending ─────────────────────────────────

netsnmp_session* openManagerSession(const std::string& host,
                                     uint16_t           port,
                                     const SnmpV3Credentials& creds,
                                     std::string& errOut)
{
    // Peer: "udp:host:port"
    const std::string peerName = "udp:" + host + ":" + std::to_string(port);

    netsnmp_session tmpl = {};
    snmp_sess_init(&tmpl);
    tmpl.version  = SNMP_VERSION_3;
    tmpl.retries  = 0;
    tmpl.timeout  = 2'000'000L; // 2 s in µs
    tmpl.peername = const_cast<char*>(peerName.c_str());

    tmpl.securityName    = const_cast<char*>(creds.username.c_str());
    tmpl.securityNameLen = creds.username.size();

    switch (creds.securityLevel) {
        case SnmpSecurityLevel::NoAuthNoPriv:
            tmpl.securityLevel = SNMP_SEC_LEVEL_NOAUTH;    break;
        case SnmpSecurityLevel::AuthNoPriv:
            tmpl.securityLevel = SNMP_SEC_LEVEL_AUTHNOPRIV; break;
        case SnmpSecurityLevel::AuthPriv:
            tmpl.securityLevel = SNMP_SEC_LEVEL_AUTHPRIV;  break;
    }

    if (creds.securityLevel != SnmpSecurityLevel::NoAuthNoPriv &&
        creds.authProtocol  != SnmpAuthProtocol::None) {
        const auto auth = authInfoFor(creds.authProtocol);
        tmpl.securityAuthProto    = const_cast<oid*>(auth.proto);
        tmpl.securityAuthProtoLen = auth.protoLen;
        tmpl.securityAuthKeyLen   = USM_AUTH_KU_LEN;

        if (generate_Ku(tmpl.securityAuthProto,
                        static_cast<u_int>(tmpl.securityAuthProtoLen),
                        reinterpret_cast<u_char*>(
                            const_cast<char*>(creds.authPassphrase.c_str())),
                        creds.authPassphrase.size(),
                        tmpl.securityAuthKey,
                        &tmpl.securityAuthKeyLen) != SNMPERR_SUCCESS) {
            errOut = "Failed to derive auth key for trap sink user: " + creds.username;
            return nullptr;
        }
    }

    if (creds.securityLevel == SnmpSecurityLevel::AuthPriv &&
        creds.privProtocol  != SnmpPrivProtocol::None) {
        const auto priv = privInfoFor(creds.privProtocol);
        const auto auth = authInfoFor(creds.authProtocol);
        tmpl.securityPrivProto    = const_cast<oid*>(priv.proto);
        tmpl.securityPrivProtoLen = priv.protoLen;
        tmpl.securityPrivKeyLen   = USM_PRIV_KU_LEN;

        if (generate_Ku(const_cast<oid*>(auth.proto),
                        static_cast<u_int>(auth.protoLen),
                        reinterpret_cast<u_char*>(
                            const_cast<char*>(creds.privPassphrase.c_str())),
                        creds.privPassphrase.size(),
                        tmpl.securityPrivKey,
                        &tmpl.securityPrivKeyLen) != SNMPERR_SUCCESS) {
            errOut = "Failed to derive priv key for trap sink user: " + creds.username;
            return nullptr;
        }
    }

    netsnmp_session* ss = snmp_open(&tmpl);
    if (!ss) {
        char* errstr = nullptr;
        int   liberr = 0, syserr = 0;
        snmp_error(&tmpl, &liberr, &syserr, &errstr);
        errOut = errstr ? std::string(errstr) : "snmp_open() failed";
        SNMP_FREE(errstr);
        return nullptr;
    }
    return ss;
}

} // anonymous namespace

// ══════════════════════════════════════════════════════════════════════════════
// SnmpServer
// ══════════════════════════════════════════════════════════════════════════════

SnmpServer::SnmpServer(Node* parent)
    : Node(parent)
{
}

// Defined here (not defaulted in the header) so that the compiler sees the
// complete SnmpHandlerEntry type when destroying unique_ptr<SnmpHandlerEntry>.
SnmpServer::~SnmpServer()
{
    stop();
}

// ── Configuration ──────────────────────────────────────────────────────────

void SnmpServer::setMasterSocket(const std::string& unixSocketPath)
{
    m_masterSocket = unixSocketPath;
}

bool SnmpServer::loadMib(const std::string& filePath)
{
    std::string err;
    m_mibTree = SnmpMibTree::fromFile(filePath, &err);
    if (!err.empty()) {
        errorOccurred.emit(err);
        return false;
    }
    return true;
}

// ── Handler registration ───────────────────────────────────────────────────

void SnmpServer::registerReadOnly(const SnmpOid&            oid,
                                   std::function<SnmpValue()> getter)
{
    auto entry = std::make_unique<SnmpHandlerEntry>();
    entry->name   = "snf_ro_" + oid.toString();
    entry->oid    = oid;
    entry->access = SnmpAccess::ReadOnly;
    entry->getter = std::move(getter);

    if (m_running)
        doRegisterEntry(entry.get());

    m_handlers.push_back(std::move(entry));
}

void SnmpServer::registerReadOnly(const std::string&         name,
                                   std::function<SnmpValue()> getter)
{
    const SnmpMibNode* node = m_mibTree.find(name);
    if (!node) {
        errorOccurred.emit(
            "registerReadOnly: MIB node '" + name + "' not found. "
            "Call loadMib() before registering by name.");
        return;
    }
    registerReadOnly(node->oid, std::move(getter));
}

void SnmpServer::registerReadWrite(const SnmpOid&                        oid,
                                    std::function<SnmpValue()>             getter,
                                    std::function<bool(const SnmpValue&)>  setter)
{
    auto entry = std::make_unique<SnmpHandlerEntry>();
    entry->name   = "snf_rw_" + oid.toString();
    entry->oid    = oid;
    entry->access = SnmpAccess::ReadWrite;
    entry->getter = std::move(getter);
    entry->setter = std::move(setter);

    if (m_running)
        doRegisterEntry(entry.get());

    m_handlers.push_back(std::move(entry));
}

void SnmpServer::registerReadWrite(const std::string&                    name,
                                    std::function<SnmpValue()>             getter,
                                    std::function<bool(const SnmpValue&)>  setter)
{
    const SnmpMibNode* node = m_mibTree.find(name);
    if (!node) {
        errorOccurred.emit(
            "registerReadWrite: MIB node '" + name + "' not found. "
            "Call loadMib() before registering by name.");
        return;
    }
    registerReadWrite(node->oid, std::move(getter), std::move(setter));
}

// ── Trap sinks ─────────────────────────────────────────────────────────────

void SnmpServer::addTrapSink(const SnmpTrapSink& sink)
{
    m_trapSinks.push_back(sink);
}

// ── Lifecycle ──────────────────────────────────────────────────────────────

bool SnmpServer::start()
{
    if (m_running)
        return true;

    // NETSNMP_DS_AGENT_X_SOCKET must be set BEFORE init_agent() (called
    // inside snmpAgentGlobalInit).  init_agent() registers the AgentX
    // connect callback and reads this value at that point; setting it
    // afterwards results in a [NIL] socket and a failed connection.
    netsnmp_ds_set_string(NETSNMP_DS_APPLICATION_ID,
                          NETSNMP_DS_AGENT_X_SOCKET,
                          m_masterSocket.c_str());

    snmpAgentGlobalInit();

    // Register all handlers BEFORE calling init_master_agent().
    // This is the canonical AgentX subagent pattern: net-snmp queues the
    // AgentX Register PDUs and sends them as part of the initial session
    // establishment (Open PDU exchange) that follows.
    for (auto& entry : m_handlers)
        doRegisterEntry(entry.get());

    if (init_master_agent() != 0) {
        errorOccurred.emit(
            "Failed to open AgentX connection to master at '" + m_masterSocket +
            "'. Ensure snmpd is running with 'master agentx' in snmpd.conf "
            "and that this process has write permission to the socket.");
        return false;
    }

    // Start a 50 ms repeating timer that drives the agent's event loop
    // non-blockingly on the owner thread.
    m_pollTimer = new Timer(this);
    m_pollTimer->setInterval(50);
    m_pollTimer->timeout.connect([this]() { onPollTick(); });
    m_pollTimer->start();

    m_running = true;
    return true;
}

void SnmpServer::stop()
{
    if (!m_running)
        return;

    m_running = false;

    if (m_pollTimer) {
        m_pollTimer->stop();
        delete m_pollTimer;
        m_pollTimer = nullptr;
    }

    snmp_shutdown("SNFSnmpServer");
}

bool SnmpServer::isRunning() const noexcept
{
    return m_running;
}

// ── Per-OID registration with net-snmp ─────────────────────────────────────

void SnmpServer::doRegisterEntry(SnmpHandlerEntry* entry)
{
    if (!entry || entry->registration)
        return; // already registered

    auto netOid = toNetSnmpOid(entry->oid);

    // netsnmp_register_scalar() / netsnmp_register_read_only_scalar() expect
    // the BASE OID (without the trailing instance .0).  They inject a
    // scalar_handler that appends .0 internally and matches the full OID.
    // netsnmp_register_instance() must NOT be used for RW objects because it
    // always injects read_only_handler, which unconditionally rejects SETs.
    if (!netOid.empty() && netOid.back() == 0)
        netOid.pop_back();

    const int access = (entry->access == SnmpAccess::ReadWrite)
                        ? HANDLER_CAN_RWRITE
                        : HANDLER_CAN_RONLY;

    netsnmp_handler_registration* reg =
        netsnmp_create_handler_registration(
            entry->name.c_str(),
            &handlerCallback,
            netOid.data(),
            static_cast<size_t>(netOid.size()),
            access);

    if (!reg) {
        errorOccurred.emit(
            "Failed to create handler registration for OID " +
            entry->oid.toString());
        return;
    }

    // Store our HandlerEntry in the leaf handler node (our callback).
    // After netsnmp_register_scalar() injects scalar_handler in front of our
    // handler, the chain becomes: scalar_handler -> our_handler.  When
    // scalar_handler dispatches via netsnmp_call_next_handler(), our callback
    // receives 'handler = our_handler' so handler->myvoid is correct.
    reg->handler->myvoid = static_cast<void*>(entry);

    // Use scalar registration:
    //   RW: netsnmp_register_scalar()            — no read_only injection
    //   RO: netsnmp_register_read_only_scalar()  — injects read_only_handler
    const int rc = (entry->access == SnmpAccess::ReadWrite)
                    ? netsnmp_register_scalar(reg)
                    : netsnmp_register_read_only_scalar(reg);

    if (rc != MIB_REGISTERED_OK) {
        errorOccurred.emit(
            "Failed to register OID " + entry->oid.toString() +
            " (netsnmp error " + std::to_string(rc) + ")");
        netsnmp_handler_registration_free(reg);
        return;
    }

    entry->registration = static_cast<void*>(reg);
}

// ── Poll tick ──────────────────────────────────────────────────────────────

void SnmpServer::onPollTick()
{
    // Non-blocking: performs one round of select() + snmp_read() +
    // snmp_timeout() + run_alarms() over the AgentX socket.
    agent_check_and_process(0);
}

// ── Trap sending ───────────────────────────────────────────────────────────

bool SnmpServer::sendTrap(const SnmpOid&                  trapOid,
                           const std::vector<SnmpVarBind>& extraVarbinds)
{
    if (m_trapSinks.empty())
        return true;

    bool allOk = true;

    for (const auto& sink : m_trapSinks) {
        std::string err;
        netsnmp_session* ss =
            openManagerSession(sink.host, sink.port, sink.credentials, err);
        if (!ss) {
            errorOccurred.emit("sendTrap: " + err);
            allOk = false;
            continue;
        }

        netsnmp_pdu* pdu = snmp_pdu_create(SNMP_MSG_TRAP2);

        // Varbind 0: sysUpTime.0 (TimeTicks, value 0 — sufficient for most receivers)
        static const oid sysUpTimeOid[] = {1, 3, 6, 1, 2, 1, 1, 3, 0};
        snmp_add_var(pdu, sysUpTimeOid, OID_LENGTH(sysUpTimeOid), 't', "0");

        // Varbind 1: snmpTrapOID.0 (OID value = trapOid)
        static const oid snmpTrapOidOid[] = {1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0};
        const std::string trapOidStr = trapOid.toString();
        snmp_add_var(pdu, snmpTrapOidOid, OID_LENGTH(snmpTrapOidOid),
                     'o', trapOidStr.c_str());

        // User-supplied varbinds.
        for (const auto& vb : extraVarbinds) {
            const auto netOid  = toNetSnmpOid(vb.oid);
            const char typeChar = vb.value.netSnmpTypeChar();
            const std::string valStr = vb.value.toNetSnmpString();
            snmp_add_var(pdu, netOid.data(), netOid.size(),
                         typeChar, valStr.c_str());
        }

        if (!snmp_send(ss, pdu)) {
            snmp_free_pdu(pdu);
            errorOccurred.emit(
                "sendTrap: snmp_send() failed for sink " +
                sink.host + ":" + std::to_string(sink.port));
            allOk = false;
        }
        // pdu ownership transferred to the session on success; don't free.

        snmp_close(ss);
    }

    return allOk;
}

// ── Thread migration ────────────────────────────────────────────────────────

void SnmpServer::onAboutToMoveToThread(EventLoop* /*newLoop*/)
{
    // agent_check_and_process is driven by the Timer; nothing to un-register
    // from the EventLoop directly.  The Timer handles its own migration.
}

void SnmpServer::onMovedToThread(EventLoop* /*oldLoop*/)
{
    // Nothing to re-register; the Timer will re-arm itself on the new thread.
}

} // namespace snf
