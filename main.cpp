#include "packet_capture.hpp"
#include "packet_queue.hpp"
#include "protocols.hpp"

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

namespace {
PacketCapture *g_capture = nullptr;
std::atomic<bool> g_shutdownRequested{false};

void signalHandler(int) {
  g_shutdownRequested.store(true);
  if (g_capture) {
    g_capture->stop();
  }
}

void printUsage(const char *prog) {
  std::fprintf(
      stderr,
      "Usage:\n"
      "  %s -i <interface> [-c <count>]   Capture live from an interface\n"
      "  %s -r <file.pcap>  [-c <count>]  Replay packets from a pcap file\n"
      "\n"
      "  -c <count>   Number of packets to capture (default: -1, "
      "unlimited/EOF)\n",
      prog, prog);
}

void dissectAndPrint(const CapturedPacket &pkt) {
  EthernetView eth(pkt.bytes.data(), pkt.bytes.size());
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
} // dissectAndPrint
} // namespace

int main(int argc, char **argv) {

  std::string interface;
  std::string pcapFile;
  int count = -1;

  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
      interface = argv[++i];
    } else if (std::strcmp(argv[i], "-r") == 0 && i + 1 < argc) {
      pcapFile = argv[++i];
    } else if (std::strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
      count = std::atoi(argv[++i]);
    } else {
      printUsage(argv[0]);
      return 1;
    }
  }

  if (interface.empty() == pcapFile.empty()) {
    // both set, or neither set -- exactly one mode must be chosen
    std::fprintf(stderr, "Error: specify exactly one of -i or -r\n\n");
    printUsage(argv[0]);
    return 1;
  }

  std::string err;
  auto capture = interface.empty() ? PacketCapture::openOffline(pcapFile, err)
                                   : PacketCapture::openLive(interface, err);

  if (!capture) {
    std::fprintf(stderr, "Failed to open capture: %s\n", err.c_str());
    return 1;
  }

  if (capture->linkType() != DLT_EN10MB) {
    std::fprintf(
        stderr,
        "Error: unsupported link-layer type %d (expected "
        "DLT_EN10MB/Ethernet).\n"
        "Hint: if this is a pcap file captured with 'tcpdump -i any', try\n"
        "recapturing on a specific interface instead.\nyou can get interface "
        "by running `ip add` and see which one is UP\n",
        capture->linkType());
    return 1;
  }

  g_capture = &(*capture);
  std::signal(SIGINT, signalHandler);

  PacketQueue queue;
  std::atomic<bool> captureRunning{true};

  std::thread captureThread([&]() {
    capture->run(&queue, count);
    captureRunning.store(false);
  });

  std::printf("Capturing... (Ctrl+C to stop)\n\n");

  std::vector<CapturedPacket> batch;
  while (true) {
    batch.clear();
    bool gotData = queue.drainInto(batch, std::chrono::milliseconds(150));

    for (const auto &pkt : batch) {
      dissectAndPrint(pkt);
    }

    if (!captureRunning.load() && !gotData) {
      break;
    }
  }

  captureThread.join();
  std::printf("Capture stopped.\n");
  return 0;
}
