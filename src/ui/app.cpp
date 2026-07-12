#include "ui/app.hpp"
#include "capture/packet_queue.hpp"
#include "protocols/protocols.hpp"

#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

using namespace ftxui;

namespace {

std::string dissectTransport(uint8_t proto, const std::string &srcIP,
                             const std::string &dstIP, const uint8_t *payload,
                             size_t payloadLen) {
  char buf[160];
  if (proto == 6) {
    TCPView tcp(payload, payloadLen);
    if (!tcp.isValid())
      return "[invalid TCP header]";
    std::snprintf(
        buf, sizeof(buf), "TCP  %-39s:%-5u -> %-39s:%-5u  seq=%u %s%s%s%s",
        srcIP.c_str(), tcp.srcPort(), dstIP.c_str(), tcp.dstPort(),
        tcp.seqNum(), tcp.flagSYN() ? "S" : "", tcp.flagACK() ? "A" : "",
        tcp.flagFIN() ? "F" : "", tcp.flagRST() ? "R" : "");
  } else if (proto == 17) {
    UDPView udp(payload, payloadLen);
    if (!udp.isValid())
      return "[invalid UDP header]";
    std::snprintf(buf, sizeof(buf), "UDP  %-39s:%-5u -> %-39s:%-5u  len=%u",
                  srcIP.c_str(), udp.srcPort(), dstIP.c_str(), udp.dstPort(),
                  udp.length());
  } else {
    std::snprintf(buf, sizeof(buf),
                  "%-39s -> %-39s  next/proto=%u (not dissected)",
                  srcIP.c_str(), dstIP.c_str(), proto);
  }
  return buf;
}

std::string summarize(const CapturedPacket &pkt) {
  EthernetView eth(pkt.bytes.data(), pkt.bytes.size());
  if (!eth.isValid())
    return "[truncated ethernet frame]";

  if (eth.etherType() == 0x0800) {
    IPv4View ip(eth.payload(), eth.payloadLen());
    if (!ip.isValid())
      return "[invalid IPv4 header]";
    return dissectTransport(ip.protocol(), ip.srcIP(), ip.dstIP(), ip.payload(),
                            ip.payloadLen());
  }

  if (eth.etherType() == 0x86DD) {
    IPv6View ip(eth.payload(), eth.payloadLen());
    if (!ip.isValid())
      return "[invalid IPv6 header]";
    return dissectTransport(ip.nextHeader(), ip.srcIP(), ip.dstIP(),
                            ip.payload(), ip.payloadLen());
  }

  char buf[64];
  std::snprintf(buf, sizeof(buf), "eth type=0x%04x (unsupported)",
                eth.etherType());
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

  // Mutated ONLY inside the CatchEvent handler below, which always runs on
  // FTXUI's own thread
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

  bool autoFollow = true;

  auto rootComponent = CatchEvent(layout, [&](Event event) {
    if (event == Event::Custom) {
      std::vector<CapturedPacket> batch;
      bool gotData = queue.drainInto(batch, std::chrono::milliseconds(0));
      if (gotData) {
        for (auto &pkt : batch) {
          lines.push_back(summarize(pkt));
          packets.push_back(std::move(pkt));
        }
        if (autoFollow) {
          selected = static_cast<int>(lines.size()) - 1;
        }
      }
      return true;
    }

    // Manual navigation disengages auto-follow -- otherwise the view would
    // keep yanking the user back to the bottom mid-inspection.
    if (event == Event::ArrowUp || event == Event::ArrowDown ||
        event == Event::PageUp || event == Event::PageDown) {
      autoFollow = false;
      return false; // still let Menu handle the actual movement
    }
    if (event == Event::End) {
      autoFollow = true;
      selected = static_cast<int>(lines.size()) - 1;
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
