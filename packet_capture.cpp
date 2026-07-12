#include "packet_capture.hpp"
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
  std::printf("---- packet: caplen=%u len=%u ----\n", header->caplen,
              header->len);
  for (uint32_t i = 0; i < header->caplen; ++i) {
    std::printf("%02x ", bytes[i]);
    if ((i + 1) % 16 == 0)
      std::printf("\n");
  }
  std::printf("\n\n");
}
