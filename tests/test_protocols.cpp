// tests/test_protocols.cpp
#include "protocols/protocols.hpp"
#include <gtest/gtest.h>
#include <vector>

// ---------- EthernetView ----------

TEST(EthernetViewTest, ParsesValidHeader) {
  std::vector<uint8_t> frame = {// dst MAC
                                0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                                // src MAC
                                0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
                                // EtherType = 0x0800 (IPv4)
                                0x08, 0x00,
                                // payload (arbitrary, not parsed at this layer)
                                0xDE, 0xAD, 0xBE, 0xEF};

  EthernetView eth(frame.data(), frame.size());
  ASSERT_TRUE(eth.isValid());
  EXPECT_EQ(eth.dstMac(), "00:11:22:33:44:55");
  EXPECT_EQ(eth.srcMac(), "aa:bb:cc:dd:ee:ff");
  EXPECT_EQ(eth.etherType(), 0x0800);
  EXPECT_EQ(eth.payloadLen(), 4u);
}

TEST(EthernetViewTest, TruncatedFrameIsInvalid) {
  std::vector<uint8_t> frame = {0x00, 0x11, 0x22}; // way too short
  EthernetView eth(frame.data(), frame.size());
  EXPECT_FALSE(eth.isValid());
}

// ---------- IPv4View ----------

TEST(IPv4ViewTest, ParsesMinimalHeaderNoOptions) {
  std::vector<uint8_t> ip = {0x45, // version=4, IHL=5 (20 bytes, no options)
                             0x00, // DSCP/ECN
                             0x00, 0x28, // total length = 40
                             0x00, 0x00, // identification
                             0x00, 0x00, // flags + fragment offset
                             0x40,       // TTL = 64
                             0x06,       // protocol = TCP
                             0x00,
                             0x00, // header checksum (not validated by us yet)
                             0xC0, 0xA8, 0x00, 0x01, // src = 192.168.0.1
                             0xC0, 0xA8, 0x00, 0x02, // dst = 192.168.0.2
                             // payload starts here
                             0x01, 0x02, 0x03, 0x04};

  IPv4View v(ip.data(), ip.size());
  ASSERT_TRUE(v.isValid());
  EXPECT_EQ(v.version(), 4);
  EXPECT_EQ(v.ihl(), 5);
  EXPECT_EQ(v.headerLength(), 20u);
  EXPECT_EQ(v.totalLength(), 40);
  EXPECT_EQ(v.ttl(), 64);
  EXPECT_EQ(v.protocol(), 6);
  EXPECT_EQ(v.srcIP(), "192.168.0.1");
  EXPECT_EQ(v.dstIP(), "192.168.0.2");
  EXPECT_EQ(v.payloadLen(), 4u);
}

TEST(IPv4ViewTest, ParsesHeaderWithOptions) {
  std::vector<uint8_t> ip = {
      0x46, // IHL=6 -> 24-byte header (4 bytes of options)
      0x00, 0x00, 0x2C, 0x00, 0x00, 0x00, 0x00, 0x40,
      0x11, // protocol = UDP
      0x00, 0x00, 0x0A, 0x00, 0x00, 0x01, 0x0A, 0x00, 0x00, 0x02, 0x01, 0x02,
      0x03, 0x04, // 4 bytes of "options" (contents
                  // don't matter here)
      0xFF, 0xFF  // payload
  };

  IPv4View v(ip.data(), ip.size());
  ASSERT_TRUE(v.isValid());
  EXPECT_EQ(v.ihl(), 6);
  EXPECT_EQ(v.headerLength(), 24u);
  // payload must start AFTER the options, not at a hardcoded offset 20
  EXPECT_EQ(v.payloadLen(), 2u);
  EXPECT_EQ(v.payload()[0], 0xFF);
}

TEST(IPv4ViewTest, RejectsHeaderShorterThanMinimum) {
  std::vector<uint8_t> ip = {0x45, 0x00, 0x00, 0x28}; // only 4 bytes total
  IPv4View v(ip.data(), ip.size());
  EXPECT_FALSE(v.isValid());
}

TEST(IPv4ViewTest, RejectsIHLClaimingMoreBytesThanAvailable) {
  // IHL says 6 (24 bytes) but we only provide the 20-byte minimum
  // this is the "lying header" case: a packet claiming options exist
  // that were never actually captured (truncation or corruption).
  std::vector<uint8_t> ip = {
      0x46, // IHL = 6 -> claims 24 bytes
      0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00,
      0x00, 0xC0, 0xA8, 0x00, 0x01, 0xC0, 0xA8, 0x00, 0x02
      // buffer ends at 20 bytes -- 4 short of what IHL claims
  };

  IPv4View v(ip.data(), ip.size());
  EXPECT_FALSE(v.isValid()); // must catch this, not silently underflow later
}

// ---------- TCPView ----------

TEST(TCPViewTest, ParsesHeaderAndFlags) {
  std::vector<uint8_t> tcp = {
      0x1F, 0x90,             // src port = 8080
      0x00, 0x50,             // dst port = 80
      0x00, 0x00, 0x00, 0x01, // seq = 1
      0x00, 0x00, 0x00, 0x00, // ack = 0
      0x50,       // data offset=5 (20 bytes, high nibble), reserved=0
      0x02,       // flags = SYN only
      0xFF, 0xFF, // window
      0x00, 0x00, // checksum
      0x00, 0x00, // urgent pointer
      0x99        // payload byte
  };

  TCPView v(tcp.data(), tcp.size());
  ASSERT_TRUE(v.isValid());
  EXPECT_EQ(v.srcPort(), 8080);
  EXPECT_EQ(v.dstPort(), 80);
  EXPECT_EQ(v.seqNum(), 1u);
  EXPECT_EQ(v.dataOffset(), 5);
  EXPECT_EQ(v.headerLength(), 20u);
  EXPECT_TRUE(v.flagSYN());
  EXPECT_FALSE(v.flagACK());
  EXPECT_EQ(v.payloadLen(), 1u);
}

TEST(TCPViewTest, RejectsTruncatedHeader) {
  std::vector<uint8_t> tcp = {0x1F, 0x90, 0x00, 0x50}; // only 4 bytes
  TCPView v(tcp.data(), tcp.size());
  EXPECT_FALSE(v.isValid());
}

// ---------- UDPView ----------

TEST(UDPViewTest, ParsesHeader) {
  std::vector<uint8_t> udp = {
      0x00, 0x35,            // src port = 53 (DNS)
      0x1F, 0x90,            // dst port = 8080
      0x00, 0x0C,            // length = 12 (8 header + 4 payload)
      0x00, 0x00,            // checksum
      0xAB, 0xCD, 0xEF, 0x01 // payload
  };

  UDPView v(udp.data(), udp.size());
  ASSERT_TRUE(v.isValid());
  EXPECT_EQ(v.srcPort(), 53);
  EXPECT_EQ(v.dstPort(), 8080);
  EXPECT_EQ(v.length(), 12);
  EXPECT_EQ(v.payloadLen(), 4u);
}

// ---------- Full chain: Ethernet -> IPv4 -> TCP ----------

TEST(ProtocolChainTest, FullEthernetIPv4TCPFrame) {
  std::vector<uint8_t> frame = {
      // Ethernet (14 bytes)
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
      0x08, 0x00,
      // IPv4 (20 bytes, no options)
      0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00,
      0xC0, 0xA8, 0x00, 0x01, 0xC0, 0xA8, 0x00, 0x02,
      // TCP (20 bytes, no options)
      0x1F, 0x90, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
      0x50, 0x18, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00};

  EthernetView eth(frame.data(), frame.size());
  ASSERT_TRUE(eth.isValid());
  ASSERT_EQ(eth.etherType(), 0x0800);

  IPv4View ip(eth.payload(), eth.payloadLen());
  ASSERT_TRUE(ip.isValid());
  ASSERT_EQ(ip.protocol(), 6);

  TCPView tcp(ip.payload(), ip.payloadLen());
  ASSERT_TRUE(tcp.isValid());
  EXPECT_EQ(tcp.srcPort(), 8080);
  EXPECT_EQ(tcp.dstPort(), 80);
  EXPECT_TRUE(tcp.flagACK()); // flags byte 0x18 = PSH+ACK
}
