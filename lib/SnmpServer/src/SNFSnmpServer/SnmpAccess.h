#pragma once

/**
 * @file SnmpAccess.h
 * @brief Access mode for an SNMP MIB node.
 * @ingroup SNFSnmpServer
 */

namespace snf {

/**
 * @enum SnmpAccess
 * @ingroup SNFSnmpServer
 * @brief Describes whether an OID is read-only or read-write.
 */
enum class SnmpAccess {
    ReadOnly,  ///< Agent accepts GET / GETNEXT, rejects SET.
    ReadWrite, ///< Agent accepts GET, GETNEXT, and SET.
};

} // namespace snf
