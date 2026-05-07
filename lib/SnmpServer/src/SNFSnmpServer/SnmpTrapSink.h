#pragma once

/**
 * @file SnmpTrapSink.h
 * @brief Destination for outbound SNMPv3 TRAP PDUs.
 * @ingroup SNFSnmpServer
 */

#include <SNFSnmp/SnmpV3Credentials.h>

#include <cstdint>
#include <string>

namespace snf {

/**
 * @struct SnmpTrapSink
 * @ingroup SNFSnmpServer
 * @brief Identifies the SNMP manager (trap receiver) that should receive
 *        TRAPs and INFORMs emitted by an `SnmpServer`.
 *
 * Add one or more sinks via `SnmpServer::addTrapSink()` before calling
 * `SnmpServer::sendTrap()`.
 *
 * @code
 * snf::SnmpTrapSink sink;
 * sink.host              = "192.168.1.100";
 * sink.port              = 162;
 * sink.credentials.username       = "trapUser";
 * sink.credentials.securityLevel  = snf::SnmpSecurityLevel::AuthPriv;
 * sink.credentials.authProtocol   = snf::SnmpAuthProtocol::SHA1;
 * sink.credentials.authPassphrase = "authSecret";
 * sink.credentials.privProtocol   = snf::SnmpPrivProtocol::AES128;
 * sink.credentials.privPassphrase = "privSecret";
 *
 * server->addTrapSink(sink);
 * @endcode
 */
struct SnmpTrapSink
{
    /** @brief IP address or hostname of the trap receiver. */
    std::string host;

    /** @brief UDP port of the trap receiver (default: 162). */
    uint16_t port = 162;

    /** @brief SNMPv3 USM credentials used to sign/encrypt the outbound PDU. */
    SnmpV3Credentials credentials;
};

} // namespace snf
