#include <gtest/gtest.h>

#include <SNFSnmpServer/SnmpMibTree.h>
#include <SNFSnmpServer/SnmpMibNode.h>
#include <SNFSnmpServer/SnmpAccess.h>
#include <SNFSnmp/SnmpOid.h>
#include <SNFSnmp/SnmpTypes.h>

#include <cstdio>
#include <fstream>
#include <string>

using namespace snf;

// ── Fixture helpers ────────────────────────────────────────────────────────

namespace {

// Write content to a temp file and return the path.
std::string writeTempMib(const std::string& content)
{
    const std::string path = "/tmp/snf_mib_test.mib";
    std::ofstream f(path, std::ios::trunc);
    f << content;
    return path;
}

void removeTempMib()
{
    std::remove("/tmp/snf_mib_test.mib");
}

} // namespace

// ── Construction ──────────────────────────────────────────────────────────

TEST(SnmpMibTreeTests, defaultTreeIsEmpty)
{
    SnmpMibTree tree;
    EXPECT_TRUE(tree.empty());
    EXPECT_EQ(tree.size(), 0u);
    EXPECT_TRUE(tree.nodes().empty());
}

// ── Valid file parsing ─────────────────────────────────────────────────────

TEST(SnmpMibTreeTests, parseValidFile)
{
    const std::string path = writeTempMib(
        "# My Device MIB\n"
        "1.3.6.1.4.1.99999.1.1.0  INTEGER   RW  sensorTemp   \"Temperature\"\n"
        "1.3.6.1.4.1.99999.1.2.0  STRING    RO  deviceName   \"Device name\"\n"
        "1.3.6.1.4.1.99999.1.3.0  COUNTER32 RO  rxPackets    \"RX count\"\n"
        "1.3.6.1.4.1.99999.1.4.0  GAUGE32   RO  signalLevel  \"Signal\"\n"
        "1.3.6.1.4.1.99999.1.5.0  TIMETICKS RO  uptime       \"Uptime\"\n"
        "1.3.6.1.4.1.99999.1.6.0  COUNTER64 RO  byteCount    \"Bytes\"\n"
        "1.3.6.1.4.1.99999.1.7.0  IPADDRESS RW  gwAddress    \"Gateway\"\n"
        "1.3.6.1.4.1.99999.1.8.0  OID       RO  trapTemplate \"Trap OID\"\n");

    std::string err;
    SnmpMibTree tree = SnmpMibTree::fromFile(path, &err);
    removeTempMib();

    EXPECT_TRUE(err.empty()) << "Unexpected parse error: " << err;
    EXPECT_EQ(tree.size(), 8u);
    EXPECT_FALSE(tree.empty());
}

TEST(SnmpMibTreeTests, parsedTypesAreCorrect)
{
    const std::string path = writeTempMib(
        "1.3.6.1.4.1.99999.1.1.0  INTEGER   RW  intNode    \"Int\"\n"
        "1.3.6.1.4.1.99999.1.2.0  STRING    RO  strNode    \"Str\"\n"
        "1.3.6.1.4.1.99999.1.3.0  COUNTER32 RO  ctr32Node  \"Ctr32\"\n"
        "1.3.6.1.4.1.99999.1.4.0  GAUGE32   RO  g32Node    \"Gauge32\"\n"
        "1.3.6.1.4.1.99999.1.5.0  TIMETICKS RO  ttNode     \"TT\"\n"
        "1.3.6.1.4.1.99999.1.6.0  COUNTER64 RO  ctr64Node  \"Ctr64\"\n"
        "1.3.6.1.4.1.99999.1.7.0  IPADDRESS RW  ipNode     \"IP\"\n"
        "1.3.6.1.4.1.99999.1.8.0  OID       RO  oidNode    \"OID\"\n");

    SnmpMibTree tree = SnmpMibTree::fromFile(path);
    removeTempMib();

    ASSERT_EQ(tree.size(), 8u);

    const auto& nodes = tree.nodes();
    EXPECT_EQ(nodes[0].type, SnmpValueType::Integer32);
    EXPECT_EQ(nodes[1].type, SnmpValueType::OctetString);
    EXPECT_EQ(nodes[2].type, SnmpValueType::Counter32);
    EXPECT_EQ(nodes[3].type, SnmpValueType::Gauge32);
    EXPECT_EQ(nodes[4].type, SnmpValueType::TimeTicks);
    EXPECT_EQ(nodes[5].type, SnmpValueType::Counter64);
    EXPECT_EQ(nodes[6].type, SnmpValueType::IpAddress);
    EXPECT_EQ(nodes[7].type, SnmpValueType::ObjectIdentifier);
}

TEST(SnmpMibTreeTests, parsedAccessIsCorrect)
{
    const std::string path = writeTempMib(
        "1.3.6.1.4.1.99999.1.1.0  INTEGER  RO  readOnly   \"RO node\"\n"
        "1.3.6.1.4.1.99999.1.2.0  STRING   RW  readWrite  \"RW node\"\n");

    SnmpMibTree tree = SnmpMibTree::fromFile(path);
    removeTempMib();

    ASSERT_EQ(tree.size(), 2u);
    EXPECT_EQ(tree.nodes()[0].access, SnmpAccess::ReadOnly);
    EXPECT_EQ(tree.nodes()[1].access, SnmpAccess::ReadWrite);
}

TEST(SnmpMibTreeTests, namesAndOidsParsedCorrectly)
{
    const std::string path = writeTempMib(
        "1.3.6.1.4.1.99999.1.1.0  INTEGER  RW  myNode  \"My node\"\n");

    SnmpMibTree tree = SnmpMibTree::fromFile(path);
    removeTempMib();

    ASSERT_EQ(tree.size(), 1u);
    EXPECT_EQ(tree.nodes()[0].name, "myNode");
    EXPECT_EQ(tree.nodes()[0].oid, SnmpOid("1.3.6.1.4.1.99999.1.1.0"));
}

TEST(SnmpMibTreeTests, descriptionParsedFromQuotes)
{
    const std::string path = writeTempMib(
        "1.3.6.1.4.1.99999.1.1.0  INTEGER  RO  myNode  \"Temperature in Celsius\"\n");

    SnmpMibTree tree = SnmpMibTree::fromFile(path);
    removeTempMib();

    ASSERT_EQ(tree.size(), 1u);
    EXPECT_EQ(tree.nodes()[0].description, "Temperature in Celsius");
}

TEST(SnmpMibTreeTests, optionalDescriptionCanBeOmitted)
{
    const std::string path = writeTempMib(
        "1.3.6.1.4.1.99999.1.1.0  INTEGER  RO  myNode\n");

    SnmpMibTree tree = SnmpMibTree::fromFile(path);
    removeTempMib();

    ASSERT_EQ(tree.size(), 1u);
    EXPECT_TRUE(tree.nodes()[0].description.empty());
}

// ── Comments and blank lines ───────────────────────────────────────────────

TEST(SnmpMibTreeTests, commentsAndBlankLinesAreSkipped)
{
    const std::string path = writeTempMib(
        "# This is a comment\n"
        "\n"
        "   \n"
        "# Another comment\n"
        "1.3.6.1.4.1.99999.1.1.0  INTEGER  RO  theNode  \"Node\"\n"
        "\n"
        "# Trailing comment\n");

    SnmpMibTree tree = SnmpMibTree::fromFile(path);
    removeTempMib();

    EXPECT_EQ(tree.size(), 1u);
}

TEST(SnmpMibTreeTests, windowsLineEndingsHandled)
{
    const std::string path = writeTempMib(
        "1.3.6.1.4.1.99999.1.1.0  INTEGER  RO  nodeA  \"A\"\r\n"
        "1.3.6.1.4.1.99999.1.2.0  STRING   RW  nodeB  \"B\"\r\n");

    SnmpMibTree tree = SnmpMibTree::fromFile(path);
    removeTempMib();

    EXPECT_EQ(tree.size(), 2u);
}

// ── Lookup methods ─────────────────────────────────────────────────────────

TEST(SnmpMibTreeTests, findByOidReturnsCorrectNode)
{
    const std::string path = writeTempMib(
        "1.3.6.1.4.1.99999.1.1.0  INTEGER  RO  nodeA  \"A\"\n"
        "1.3.6.1.4.1.99999.1.2.0  STRING   RW  nodeB  \"B\"\n");

    SnmpMibTree tree = SnmpMibTree::fromFile(path);
    removeTempMib();

    const auto* n = tree.find(SnmpOid("1.3.6.1.4.1.99999.1.2.0"));
    ASSERT_NE(n, nullptr);
    EXPECT_EQ(n->name, "nodeB");
    EXPECT_EQ(n->type, SnmpValueType::OctetString);
}

TEST(SnmpMibTreeTests, findByOidReturnsNullptrForUnknown)
{
    const std::string path = writeTempMib(
        "1.3.6.1.4.1.99999.1.1.0  INTEGER  RO  nodeA  \"A\"\n");

    SnmpMibTree tree = SnmpMibTree::fromFile(path);
    removeTempMib();

    EXPECT_EQ(tree.find(SnmpOid("1.3.6.1.4.1.99999.9.9.0")), nullptr);
}

TEST(SnmpMibTreeTests, findByNameReturnsCorrectNode)
{
    const std::string path = writeTempMib(
        "1.3.6.1.4.1.99999.1.1.0  INTEGER  RO  nodeA  \"A\"\n"
        "1.3.6.1.4.1.99999.1.2.0  STRING   RW  nodeB  \"B\"\n");

    SnmpMibTree tree = SnmpMibTree::fromFile(path);
    removeTempMib();

    const auto* n = tree.find("nodeA");
    ASSERT_NE(n, nullptr);
    EXPECT_EQ(n->oid, SnmpOid("1.3.6.1.4.1.99999.1.1.0"));
    EXPECT_EQ(n->access, SnmpAccess::ReadOnly);
}

TEST(SnmpMibTreeTests, findByNameReturnsNullptrForUnknown)
{
    const std::string path = writeTempMib(
        "1.3.6.1.4.1.99999.1.1.0  INTEGER  RO  nodeA  \"A\"\n");

    SnmpMibTree tree = SnmpMibTree::fromFile(path);
    removeTempMib();

    EXPECT_EQ(tree.find("nonExistent"), nullptr);
}

// ── Error cases ────────────────────────────────────────────────────────────

TEST(SnmpMibTreeTests, nonExistentFileFails)
{
    std::string err;
    SnmpMibTree tree = SnmpMibTree::fromFile("/tmp/does_not_exist.mib", &err);
    EXPECT_TRUE(tree.empty());
    EXPECT_FALSE(err.empty());
}

TEST(SnmpMibTreeTests, unknownTypeFails)
{
    const std::string path = writeTempMib(
        "1.3.6.1.4.1.99999.1.1.0  BADTYPE  RO  myNode  \"Node\"\n");

    std::string err;
    SnmpMibTree tree = SnmpMibTree::fromFile(path, &err);
    removeTempMib();

    EXPECT_TRUE(tree.empty());
    EXPECT_FALSE(err.empty());
    EXPECT_NE(err.find("BADTYPE"), std::string::npos);
}

TEST(SnmpMibTreeTests, unknownAccessFails)
{
    const std::string path = writeTempMib(
        "1.3.6.1.4.1.99999.1.1.0  INTEGER  XX  myNode  \"Node\"\n");

    std::string err;
    SnmpMibTree tree = SnmpMibTree::fromFile(path, &err);
    removeTempMib();

    EXPECT_TRUE(tree.empty());
    EXPECT_FALSE(err.empty());
}

TEST(SnmpMibTreeTests, invalidOidFails)
{
    const std::string path = writeTempMib(
        "this.is.not.valid  INTEGER  RO  myNode  \"Node\"\n");

    std::string err;
    SnmpMibTree tree = SnmpMibTree::fromFile(path, &err);
    removeTempMib();

    EXPECT_TRUE(tree.empty());
    EXPECT_FALSE(err.empty());
}

TEST(SnmpMibTreeTests, incompleteLineFails)
{
    const std::string path = writeTempMib(
        "1.3.6.1.4.1.99999.1.1.0  INTEGER\n"); // missing ACCESS and NAME

    std::string err;
    SnmpMibTree tree = SnmpMibTree::fromFile(path, &err);
    removeTempMib();

    EXPECT_TRUE(tree.empty());
    EXPECT_FALSE(err.empty());
}

// ── Case-insensitive type / access parsing ─────────────────────────────────

TEST(SnmpMibTreeTests, typeIsCaseInsensitive)
{
    const std::string path = writeTempMib(
        "1.3.6.1.4.1.99999.1.1.0  integer  rw  myNode  \"Node\"\n");

    SnmpMibTree tree = SnmpMibTree::fromFile(path);
    removeTempMib();

    EXPECT_EQ(tree.size(), 1u);
    EXPECT_EQ(tree.nodes()[0].type, SnmpValueType::Integer32);
    EXPECT_EQ(tree.nodes()[0].access, SnmpAccess::ReadWrite);
}
