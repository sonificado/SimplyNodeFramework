/**
 * @file SnmpMibTree.cpp
 * @ingroup SNFSnmpServer
 */

#include "SNFSnmpServer/SnmpMibTree.h"

#include <SNFSnmp/SnmpOid.h>
#include <SNFSnmp/SnmpTypes.h>

#include <exception>
#include <fstream>
#include <map>
#include <sstream>
#include <string>

namespace snf {

// ── Type / access string maps ──────────────────────────────────────────────

namespace {

const std::map<std::string, SnmpValueType> k_typeMap = {
    { "INTEGER",   SnmpValueType::Integer32        },
    { "COUNTER32", SnmpValueType::Counter32        },
    { "GAUGE32",   SnmpValueType::Gauge32          },
    { "TIMETICKS", SnmpValueType::TimeTicks        },
    { "COUNTER64", SnmpValueType::Counter64        },
    { "STRING",    SnmpValueType::OctetString      },
    { "IPADDRESS", SnmpValueType::IpAddress        },
    { "OID",       SnmpValueType::ObjectIdentifier },
};

const std::map<std::string, SnmpAccess> k_accessMap = {
    { "RO", SnmpAccess::ReadOnly  },
    { "RW", SnmpAccess::ReadWrite },
};

// Upper-case a string in-place.
void toUpper(std::string& s)
{
    for (auto& c : s)
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
}

} // anonymous namespace

// ── SnmpMibTree::fromFile ──────────────────────────────────────────────────

SnmpMibTree SnmpMibTree::fromFile(const std::string& filePath,
                                   std::string*       errorOut)
{
    SnmpMibTree tree;

    std::ifstream file(filePath);
    if (!file.is_open()) {
        if (errorOut)
            *errorOut = "Cannot open MIB definition file: " + filePath;
        return tree;
    }

    std::string line;
    int lineNo = 0;

    while (std::getline(file, line)) {
        ++lineNo;

        // Strip '\r' for Windows line endings.
        if (!line.empty() && line.back() == '\r')
            line.pop_back();

        // Skip blank lines and comments.
        const auto firstNonSpace = line.find_first_not_of(" \t");
        if (firstNonSpace == std::string::npos) continue;
        if (line[firstNonSpace] == '#')          continue;

        // Extract mandatory tokens: OID  TYPE  ACCESS  NAME
        std::istringstream iss(line);
        std::string oidStr, typeStr, accessStr, name;
        iss >> oidStr >> typeStr >> accessStr >> name;

        if (oidStr.empty() || typeStr.empty() || accessStr.empty() || name.empty()) {
            if (errorOut) {
                *errorOut = "Line " + std::to_string(lineNo) +
                            ": expected '<OID> <TYPE> <ACCESS> <NAME> [\"<DESC>\"]'";
            }
            return SnmpMibTree{};
        }

        // Parse OID — SnmpOid constructor throws on non-numeric components.
        SnmpOid oid;
        try {
            oid = SnmpOid(oidStr);
        } catch (const std::exception&) {
            if (errorOut)
                *errorOut = "Line " + std::to_string(lineNo) +
                            ": invalid OID '" + oidStr + "'";
            return SnmpMibTree{};
        }
        if (!oid.isValid()) {
            if (errorOut)
                *errorOut = "Line " + std::to_string(lineNo) +
                            ": invalid OID '" + oidStr + "'";
            return SnmpMibTree{};
        }

        // Parse TYPE (case-insensitive).
        toUpper(typeStr);
        const auto typeIt = k_typeMap.find(typeStr);
        if (typeIt == k_typeMap.end()) {
            if (errorOut)
                *errorOut = "Line " + std::to_string(lineNo) +
                            ": unknown type '" + typeStr +
                            "'. Supported: INTEGER COUNTER32 GAUGE32 TIMETICKS "
                            "COUNTER64 STRING IPADDRESS OID";
            return SnmpMibTree{};
        }

        // Parse ACCESS (case-insensitive).
        toUpper(accessStr);
        const auto accessIt = k_accessMap.find(accessStr);
        if (accessIt == k_accessMap.end()) {
            if (errorOut)
                *errorOut = "Line " + std::to_string(lineNo) +
                            ": unknown access '" + accessStr +
                            "'. Supported: RO RW";
            return SnmpMibTree{};
        }

        // Optional quoted description.
        std::string description;
        const auto qOpen = line.find('"');
        if (qOpen != std::string::npos) {
            const auto qClose = line.find('"', qOpen + 1);
            if (qClose != std::string::npos)
                description = line.substr(qOpen + 1, qClose - qOpen - 1);
        }

        tree.m_nodes.push_back({ oid, name, typeIt->second,
                                  accessIt->second, description });
    }

    return tree;
}

// ── Accessors ──────────────────────────────────────────────────────────────

const std::vector<SnmpMibNode>& SnmpMibTree::nodes() const noexcept
{
    return m_nodes;
}

const SnmpMibNode* SnmpMibTree::find(const SnmpOid& oid) const
{
    for (const auto& node : m_nodes)
        if (node.oid == oid) return &node;
    return nullptr;
}

const SnmpMibNode* SnmpMibTree::find(const std::string& name) const
{
    for (const auto& node : m_nodes)
        if (node.name == name) return &node;
    return nullptr;
}

bool SnmpMibTree::empty() const noexcept
{
    return m_nodes.empty();
}

std::size_t SnmpMibTree::size() const noexcept
{
    return m_nodes.size();
}

} // namespace snf
