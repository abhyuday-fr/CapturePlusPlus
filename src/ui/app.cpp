#include "ui/app.hpp"
#include "capture/packet_queue.hpp"
#include "protocols/protocols.hpp"

#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

using namespace ftxui;

namespace {

std::string summarize(const CapturedPacket &pkt) {
  EthernetView eth(pkt.bytes.data(), pkt.bytes.size());
  if (!eth.isValid())
    return "[truncated ethernet frame]";

  if (eth.etherType() != 0x0800) {
    char buf[64];
    std::snprintf(buf, sizeof(buf), "eth type=0x%04x (not IPv4)",
                  eth.etherType());
    return buf;
  }

  IPv4View ip(eth.payload(), eth.payloadLen());
  if (!ip.isValid())
    return "[invalid IPv4 header]";

  char buf[160];
  if (ip.protocol() == 6) {
    TCPView tcp(ip.payload(), ip.payloadLen());
    if (!tcp.isValid())
      return "[invalid TCP header]";
    std::snprintf(
        buf, sizeof(buf), "TCP  %-15s:%-5u -> %-15s:%-5u  seq=%u %s%s%s%s",
        ip.srcIP().c_str(), tcp.srcPort(), ip.dstIP().c_str(), tcp.dstPort(),
        tcp.seqNum(), tcp.flagSYN() ? "S" : "", tcp.flagACK() ? "A" : "",
        tcp.flagFIN() ? "F" : "", tcp.flagRST() ? "R" : "");
  } else if (ip.protocol() == 17) {
    UDPView udp(ip.payload(), ip.payloadLen());
    if (!udp.isValid())
      return "[invalid UDP header]";
    std::snprintf(buf, sizeof(buf), "UDP  %-15s:%-5u -> %-15s:%-5u  len=%u",
                  ip.srcIP().c_str(), udp.srcPort(), ip.dstIP().c_str(),
                  udp.dstPort(), udp.length());
  } else {
    std::snprintf(buf, sizeof(buf), "IPv4 %-15s -> %-15s  proto=%u",
                  ip.srcIP().c_str(), ip.dstIP().c_str(), ip.protocol());
  }
  return buf;
}

} // namespace

int runApp(PacketCapture &capture, int count) {
  PacketQueue queue;
  std::atomic<bool> captureRunning{true};
  std::atomic<bool> shutdownRequested{false};

  std::thread captureThread([&]() {
    capture.run(&queue, count);
    captureRunning.store(false);
  });

  auto screen = ScreenInteractive::Fullscreen();

  // Mutated ONLY inside the CatchEvent handler below, which always runs
  // on FTXUI's own thread -- see the design note from our last discussion
  // on why this doesn't need its own mutex.
  std::vector<std::string> lines;
  std::vector<CapturedPacket> packets;
  int selected = 0;

  auto menu = Menu(&lines, &selected);

  auto layout = Renderer(menu, [&] {
    return vbox({
               text("CapturePlusPlus  |  packets: " +
                    std::to_string(lines.size())) |
                   bold,
               separator(),
               menu->Render() | vscroll_indicator | frame | flex,
           }) |
           border;
  });

  auto rootComponent = CatchEvent(layout, [&](Event event) {
    if (event == Event::Custom) {
      std::vector<CapturedPacket> batch;
      while (queue.drainInto(batch, std::chrono::milliseconds(0))) {
        for (auto &pkt : batch) {
          lines.push_back(summarize(pkt));
          packets.push_back(std::move(pkt));
        }
        batch.clear();
      }
      return true;
    }
    if (event == Event::Character('q')) {
      screen.Exit();
      return true;
    }
    return false;
  });

  std::thread tickerThread([&]() {
    while (!shutdownRequested.load()) {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      screen.PostEvent(Event::Custom);
    }
  });

  screen.Loop(rootComponent);

  shutdownRequested.store(true);
  capture.stop();
  captureThread.join();
  tickerThread.join();

  return 0;
}
