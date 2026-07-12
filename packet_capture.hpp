#ifndef PACKET_CAPTURE_HPP
#define PACKET_CAPTURE_HPP

#include <cstdint>
#include <optional>
#include <pcap.h>
#include <pcap/pcap.h>
#include <string>
#include <sys/types.h>

class PacketCapture {
public:
  static std::optional<PacketCapture>
  openLive(const std::string &interface, std::string &errOut,
           int snaplen = 65535, bool promiscuous = true, int timeoutMs = 1000);

  static std::optional<PacketCapture> openOffline(const std::string &pcapFile,
                                                  std::string &errout);

  // not copyable
  PacketCapture(const PacketCapture &) = delete;
  PacketCapture &operator=(const PacketCapture &) = delete;

  // movable
  PacketCapture(PacketCapture &&other) noexcept;
  PacketCapture &operator=(PacketCapture &&other) noexcept;

  ~PacketCapture();

  bool run(int count = -1);

private:
  // private constructor, only factories are allowed to have one
  explicit PacketCapture(pcap_t *handle);

  // trampoline is the actual function pointer we hand to pcap_loop
  static void trampoline(u_char *user, const pcap_pkthdr *header,
                         const u_char *bytes);

  // per-packet work, hex dump for now
  void onPacket(const pcap_pkthdr *header, const u_char *bytes);

  pcap_t *handle_ = nullptr;
};

#endif
