#pragma once

/**
 * @file SnmpMibTree.h
 * @brief In-memory collection of MIB node definitions loaded from a text file.
 * @ingroup SNFSnmpServer
 */

#include "SNFSnmpServer/SnmpMibNode.h"

#include <SNFSnmp/SnmpOid.h>

#include <cstddef>
#include <string>
#include <vector>

namespace snf {

/**
 * @class SnmpMibTree
 * @ingroup SNFSnmpServer
 * @brief Holds the set of OID definitions that describe the agent's MIB tree.
 *
 * Load an MIB definition file with `SnmpMibTree::fromFile()`.  The file uses a
 * simple line-oriented text format:
 *
 * @code{.unparsed}
 * # Lines beginning with '#' are comments.
 * # Format: <OID>  <TYPE>  <ACCESS>  <NAME>  "<DESCRIPTION>"
 * #
 * # Supported TYPEs : INTEGER  COUNTER32  GAUGE32  TIMETICKS  COUNTER64
 * #                   STRING   IPADDRESS  OID
 * # Supported ACCESS: RO (read-only)  RW (read-write)
 * # DESCRIPTION is optional and must be enclosed in double quotes.
 *
 * 1.3.6.1.4.1.99999.1.1.0  INTEGER   RW  sensorTemp    "Temperature in Celsius"
 * 1.3.6.1.4.1.99999.1.2.0  STRING    RO  deviceName    "Device name"
 * 1.3.6.1.4.1.99999.1.3.0  COUNTER32 RO  rxPackets     "Received packet count"
 * 1.3.6.1.4.1.99999.1.4.0  GAUGE32   RO  signalLevel   "Signal strength (dBm)"
 * 1.3.6.1.4.1.99999.1.5.0  IPADDRESS RW  gatewayAddr   "Default gateway"
 * @endcode
 *
 * After loading, individual nodes can be retrieved by OID or by name for use
 * with `SnmpServer::registerReadOnly()` / `SnmpServer::registerReadWrite()`.
 *
 * @code
 * snf::SnmpMibTree tree = snf::SnmpMibTree::fromFile("/etc/snmp/my-device.mib");
 * server->loadMib("/etc/snmp/my-device.mib");
 *
 * // Look up by symbolic name
 * const auto* node = tree.find("sensorTemp");
 * if (node) std::cout << node->oid.toString() << '\n';
 * @endcode
 */
class SnmpMibTree
{
public:
    SnmpMibTree() = default;

    /**
     * @brief Parses @p filePath and returns the populated tree.
     *
     * On success the returned tree contains all valid nodes.
     * On failure (file not found, parse error) the returned tree is empty and
     * @p errorOut (if non-null) receives a human-readable message.
     */
    static SnmpMibTree fromFile(const std::string& filePath,
                                 std::string*       errorOut = nullptr);

    /** @brief Returns all nodes in file order. */
    const std::vector<SnmpMibNode>& nodes() const noexcept;

    /**
     * @brief Returns a pointer to the node whose OID equals @p oid, or
     *        @c nullptr if not found.
     */
    const SnmpMibNode* find(const SnmpOid& oid) const;

    /**
     * @brief Returns a pointer to the node whose symbolic @p name matches, or
     *        @c nullptr if not found.
     */
    const SnmpMibNode* find(const std::string& name) const;

    /** @brief Returns @c true when no nodes have been loaded. */
    bool empty() const noexcept;

    /** @brief Returns the number of loaded nodes. */
    std::size_t size() const noexcept;

private:
    std::vector<SnmpMibNode> m_nodes;
};

} // namespace snf
