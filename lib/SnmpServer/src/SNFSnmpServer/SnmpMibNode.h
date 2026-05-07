#pragma once

/**
 * @file SnmpMibNode.h
 * @brief Metadata for a single OID entry in an SnmpMibTree.
 * @ingroup SNFSnmpServer
 */

#include "SNFSnmpServer/SnmpAccess.h"

#include <SNFSnmp/SnmpOid.h>
#include <SNFSnmp/SnmpTypes.h>

#include <string>

namespace snf {

/**
 * @struct SnmpMibNode
 * @ingroup SNFSnmpServer
 * @brief Describes one leaf OID in the agent's MIB tree.
 *
 * A `SnmpMibNode` is typically populated by `SnmpMibTree::fromFile()` when
 * loading an OID definition file. It records the OID, its SNMP type, access
 * level, a short name used for handler lookup, and an optional description.
 *
 * @code
 * // Nodes can also be created in code:
 * snf::SnmpMibNode node;
 * node.oid         = snf::SnmpOid("1.3.6.1.4.1.99999.1.1.0");
 * node.name        = "sensorTemp";
 * node.type        = snf::SnmpValueType::Integer32;
 * node.access      = snf::SnmpAccess::ReadWrite;
 * node.description = "Temperature reading in degrees Celsius";
 * @endcode
 */
struct SnmpMibNode
{
    /** @brief Dotted-decimal OID of the managed object instance. */
    SnmpOid oid;

    /**
     * @brief Short symbolic name used for handler lookup, e.g. @c "sensorTemp".
     * Must be unique within the tree.
     */
    std::string name;

    /** @brief SNMP value type (INTEGER, OCTET STRING, Counter32, etc.). */
    SnmpValueType type = SnmpValueType::Integer32;

    /** @brief Whether the object is read-only or read-write. */
    SnmpAccess access = SnmpAccess::ReadOnly;

    /** @brief Human-readable description (optional). */
    std::string description;
};

} // namespace snf
