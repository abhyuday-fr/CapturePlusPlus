#include "packet_capture.hpp"
#include "protocols.hpp"
#include <cstdio>
#include <cstring>
#include <pcap/pcap.h>
#include <sys/types.h>

PacketCapture::PacketCapture(pcap *handle) : handle_(handle) {}

PacketCapture::PacketCapture(PacketCapture &&other) noexcept
    : handle_(other.handle_) {
  other.handle_ = nullptr;
}

PacketCapture &PacketCapture::operator=(PacketCapture &&other) noexcept {
  if (this != &other) {
    if (handle_)
      pcap_close(handle_);
    handle_ = other.handle_;
    other.handle_ = nullptr;
  }
  return *this;
}

PacketCapture::~PacketCapture() {
  if (handle_)
    pcap_close(handle_);
}

std::optional<PacketCapture>
PacketCapture::openLive(const std::string &interface, std::string &errOut,
                        int snaplen, bool promiscuous, int timeoutMs) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle = pcap_open_live(interface.c_str(), snaplen,
                                  promiscuous ? 1 : 0, timeoutMs, errbuf);
  if (!handle) {
    errOut = errbuf;
    return std::nullopt;
  }
  return PacketCapture(handle);
}

std::optional<PacketCapture>
PacketCapture::openOffline(const std::string &pcapFile, std::string &errOut) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle = pcap_open_offline(pcapFile.c_str(), errbuf);
  if (!handle) {
    errOut = errbuf;
    return std::nullopt;
  }
  return PacketCapture(handle);
}

void PacketCapture::trampoline(u_char *user, const pcap_pkthdr *header,
                               const u_char *bytes) {
  auto *self = reinterpret_cast<PacketCapture *>(user);
  self->onPacket(header, bytes);
}

bool PacketCapture::run(int count) {
  int result = pcap_loop(handle_, count, &PacketCapture::trampoline,
                         reinterpret_cast<u_char *>(this));
  return result == 0;
}

void PacketCapture::onPacket(const pcap_pkthdr *header, const u_char *bytes) {
  EthernetView eth(bytes, header->caplen);
  if (!eth.isValid()) {
    std::printf("[truncated ethernet frame]\n");
    return;
  }

  std::printf("Eth: %s -> %s  type=0x%04x\n", eth.srcMac().c_str(),
              eth.dstMac().c_str(), eth.etherType());

  if (eth.etherType() != 0x0800) {
    std::printf("  (non-IPv4, skipping)\n\n");
    return;
  }

  IPv4View ip(eth.payload(), eth.payloadLen());
  if (!ip.isValid()) {
    std::printf("  [truncated/invalid IPv4 header]\n\n");
    return;
  }

  std::printf("  IPv4: %s -> %s  proto=%u ttl=%u\n", ip.srcIP().c_str(),
              ip.dstIP().c_str(), ip.protocol(), ip.ttl());

  if (ip.protocol() == 6) {
    TCPView tcp(ip.payload(), ip.payloadLen());
    if (!tcp.isValid()) {
      std::printf("    [truncated/invalid TCP header]\n\n");
      return;
    }
    std::printf("    TCP: %u -> %u  seq=%u flags=%s%s%s%s\n\n", tcp.srcPort(),
                tcp.dstPort(), tcp.seqNum(), tcp.flagSYN() ? "S" : "",
                tcp.flagACK() ? "A" : "", tcp.flagFIN() ? "F" : "",
                tcp.flagRST() ? "R" : "");
  } else if (ip.protocol() == 17) {
    UDPView udp(ip.payload(), ip.payloadLen());
    if (!udp.isValid()) {
      std::printf("    [truncated/invalid UDP header]\n\n");
      return;
    }
    std::printf("    UDP: %u -> %u  len=%u\n\n", udp.srcPort(), udp.dstPort(),
                udp.length());
  } else {
    std::printf("    (protocol %u, not dissected yet)\n\n", ip.protocol());
  }
}
