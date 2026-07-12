#include "capture/packet_capture.hpp"
#include "ui/app.hpp"

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

namespace {

PacketCapture *g_capture = nullptr;

void signalHandler(int) {
  if (g_capture)
    g_capture->stop();
}

void printUsage(const char *prog) {
  std::fprintf(stderr,
               "Usage:\n"
               "  %s -i <interface> [-c <count>]\n"
               "  %s -r <file.pcap>  [-c <count>]\n",
               prog, prog);
}

} // namespace

int main(int argc, char **argv) {
  std::string interface, pcapFile;
  int count = -1;

  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "-i") == 0 && i + 1 < argc)
      interface = argv[++i];
    else if (std::strcmp(argv[i], "-r") == 0 && i + 1 < argc)
      pcapFile = argv[++i];
    else if (std::strcmp(argv[i], "-c") == 0 && i + 1 < argc)
      count = std::atoi(argv[++i]);
    else {
      printUsage(argv[0]);
      return 1;
    }
  }

  if (interface.empty() == pcapFile.empty()) {
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
    std::fprintf(stderr, "Error: unsupported link-layer type %d\n",
                 capture->linkType());
    return 1;
  }

  g_capture = &(*capture);
  std::signal(SIGINT, signalHandler);

  return runApp(*capture, count);
}
