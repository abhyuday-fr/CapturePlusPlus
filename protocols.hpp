#ifndef PROTOCOLS_HPP
#define PROTOCOLS_HPP

#include <arpa/inet.h> // ntohs, ntohl
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

class EthernetView {
public:
  static constexpr size_t kHeaderLen = 14;

  EthernetView(const uint8_t *data, size_t len) : data_(data), len_(len) {}

  bool isValid() const { return data_ != nullptr && len_ >= kHeaderLen; }

  std::string srcMac() const { return macToString(data_ + 6); }
  std::string dstMac() const { return macToString(data_ + 0); }

  // EtherType is 2 bytes
  uint16_t etherType() const {
    uint16_t raw;
    std::memcpy(&raw, data_ + 12, 2);
    return ntohs(raw);
  }

  const uint8_t *payload() const { return data_ + kHeaderLen; }
  size_t payloadLen() const { return len_ - kHeaderLen; }

private:
  static std::string macToString(const uint8_t *mac) {
    char buf[18];
    std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0],
                  mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buf;
  }

  const uint8_t *data_;
  size_t len_;
};

class IPv4View {
public:
  static constexpr size_t kMinHeaderLen = 20;

  IPv4View(const uint8_t *data, size_t len) : data_(data), len_(len) {}

  bool isValid() const {
    if (data_ == nullptr || len_ < kMinHeaderLen)
      return false;
    return len_ >= headerLength(); // headerLength() reads IHL
  }

  uint8_t version() const { return (data_[0] >> 4) & 0x0F; }
  uint8_t ihl() const { return data_[0] & 0x0F; }
  size_t headerLength() const { return static_cast<size_t>(ihl()) * 4; }

  uint16_t totalLength() const { return readU16(2); }
  uint8_t ttl() const { return data_[8]; }
  uint8_t protocol() const { return data_[9]; }

  std::string srcIP() const { return ipToString(data_ + 12); }
  std::string dstIP() const { return ipToString(data_ + 16); }

  const uint8_t *payload() const { return data_ + headerLength(); }
  size_t payloadLen() const {
    size_t hdr = headerLength();
    return hdr <= len_ ? len_ - hdr : 0;
  }

private:
  uint16_t readU16(size_t offset) const {
    uint16_t raw;
    std::memcpy(&raw, data_ + offset, 2);
    return ntohs(raw);
  }

  static std::string ipToString(const uint8_t *ip) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
    return buf;
  }

  const uint8_t *data_;
  size_t len_;
};

class TCPView {
public:
  static constexpr size_t kMinHeaderLen = 20;

  TCPView(const uint8_t *data, size_t len) : data_(data), len_(len) {}

  bool isValid() const {
    if (data_ == nullptr || len_ < kMinHeaderLen)
      return false;
    return len_ >= headerLength();
  }

  uint16_t srcPort() const { return readU16(0); }
  uint16_t dstPort() const { return readU16(2); }
  uint32_t seqNum() const { return readU32(4); }
  uint32_t ackNum() const { return readU32(8); }

  // Data Offset lives in the HIGH 4 bits of byte 12
  // same shift pattern as IP's IHL, just top nibble instead of bottom.
  uint8_t dataOffset() const { return (data_[12] >> 4) & 0x0F; }
  size_t headerLength() const { return static_cast<size_t>(dataOffset()) * 4; }

  uint8_t flags() const { return data_[13]; }
  bool flagSYN() const { return flags() & 0x02; }
  bool flagACK() const { return flags() & 0x10; }
  bool flagFIN() const { return flags() & 0x01; }
  bool flagRST() const { return flags() & 0x04; }

  const uint8_t *payload() const { return data_ + headerLength(); }
  size_t payloadLen() const {
    size_t hdr = headerLength();
    return hdr <= len_ ? len_ - hdr : 0;
  }

private:
  uint16_t readU16(size_t offset) const {
    uint16_t raw;
    std::memcpy(&raw, data_ + offset, 2);
    return ntohs(raw);
  }
  uint32_t readU32(size_t offset) const {
    uint32_t raw;
    std::memcpy(&raw, data_ + offset, 4);
    return ntohl(raw);
  }

  const uint8_t *data_;
  size_t len_;
};

class UDPView {
public:
  static constexpr size_t kHeaderLen = 8;

  UDPView(const uint8_t *data, size_t len) : data_(data), len_(len) {}

  bool isValid() const { return data_ != nullptr && len_ >= kHeaderLen; }

  uint16_t srcPort() const { return readU16(0); }
  uint16_t dstPort() const { return readU16(2); }
  uint16_t length() const { return readU16(4); } // header + payload, per spec

  const uint8_t *payload() const { return data_ + kHeaderLen; }
  size_t payloadLen() const { return len_ - kHeaderLen; }

private:
  uint16_t readU16(size_t offset) const {
    uint16_t raw;
    std::memcpy(&raw, data_ + offset, 2);
    return ntohs(raw);
  }

  const uint8_t *data_;
  size_t len_;
};

#endif
