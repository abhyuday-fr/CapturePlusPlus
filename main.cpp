#include "packet_capture.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

namespace {
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
} // printUsage
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

  std::printf("Starting capture (count=%d)...\n\n", count);

  if (!capture->run(count)) {
    std::fprintf(stderr, "pcap_loop reported an error\n");
    return 1;
  }

  return 0;
}
