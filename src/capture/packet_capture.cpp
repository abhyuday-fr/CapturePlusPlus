#include "packet_capture.hpp"
#include <pcap/pcap.h>
#include <sys/types.h>

PacketCapture::PacketCapture(pcap *handle)
    : handle_(handle), linkType_(pcap_datalink(handle)) {}

PacketCapture::PacketCapture(PacketCapture &&other) noexcept
    : handle_(other.handle_), linkType_(other.linkType_) {
  other.handle_ = nullptr;
  other.linkType_ = -1;
}

PacketCapture &PacketCapture::operator=(PacketCapture &&other) noexcept {
  if (this != &other) {
    if (handle_)
      pcap_close(handle_);
    handle_ = other.handle_;
    linkType_ = other.linkType_;
    other.handle_ = nullptr;
    other.linkType_ = -1;
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

bool PacketCapture::run(PacketQueue *queue, int count) {
  queue_ = queue;
  int result = pcap_loop(handle_, count, &PacketCapture::trampoline,
                         reinterpret_cast<u_char *>(this));
  queue_ = nullptr; // don't leave a dangling pointer
  return result == 0;
}

void PacketCapture::stop() {
  if (handle_) {
    pcap_breakloop(handle_);
  }
}

void PacketCapture::onPacket(const pcap_pkthdr *header, const u_char *bytes) {
  if (!queue_) {
    return;
  }

  CapturedPacket packet;
  packet.bytes.assign(bytes, bytes + header->caplen);
  packet.capLen = header->caplen;
  packet.origLen = header->len;

  queue_->push(std::move(packet));
}
