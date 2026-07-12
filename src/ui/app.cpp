#include "ui/app.hpp"
#include "capture/packet_queue.hpp"
#include "protocols/protocols.hpp"

#include <ftxui/component/component.hpp>
#include <ftxui/component/component_options.hpp>
#include <ftxui/component/event.hpp>
#include <ftxui/component/mouse.hpp>
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

// Renders offset/hex/ascii rows, 16 bytes per row -- standard hex-viewer shape.
Element hexDump(const std::vector<uint8_t> &bytes) {
  Elements rows;
  const size_t bytesPerRow = 16;

  for (size_t offset = 0; offset < bytes.size(); offset += bytesPerRow) {
    std::string hexPart;
    std::string asciiPart;
    for (size_t i = 0; i < bytesPerRow; ++i) {
      if (offset + i < bytes.size()) {
        char buf[4];
        std::snprintf(buf, sizeof(buf), "%02x ", bytes[offset + i]);
        hexPart += buf;
        uint8_t c = bytes[offset + i];
        asciiPart += (c >= 32 && c < 127) ? static_cast<char>(c) : '.';
      } else {
        hexPart += "   ";
      }
    }
    char offsetBuf[8];
    std::snprintf(offsetBuf, sizeof(offsetBuf), "%04zx", offset);
    rows.push_back(hbox({
        text(std::string(offsetBuf) + "  "),
        text(hexPart),
        text("  " + asciiPart),
    }));
  }

  return vbox(std::move(rows));
}

// Structured field-by-field breakdown for the detail pane. Duplicates the
// dissection branching in dissectTransport/summarize above -- a known,
// deliberate tradeoff for now; a shared "dissect into fields" helper is a
// reasonable future refactor once both consumers' needs stabilize.
Element renderPacketDetail(const CapturedPacket &pkt) {
  Elements sections;

  EthernetView eth(pkt.bytes.data(), pkt.bytes.size());
  if (!eth.isValid()) {
    sections.push_back(text("[truncated ethernet frame]"));
    return vbox(std::move(sections));
  }

  sections.push_back(text("Ethernet") | bold);
  sections.push_back(text("  Src MAC: " + eth.srcMac()));
  sections.push_back(text("  Dst MAC: " + eth.dstMac()));
  char etBuf[32];
  std::snprintf(etBuf, sizeof(etBuf), "  EtherType: 0x%04x", eth.etherType());
  sections.push_back(text(etBuf));
  sections.push_back(separator());

  auto describeTransport = [&](uint8_t proto, const uint8_t *payload,
                               size_t payloadLen) {
    char buf[64];
    if (proto == 6) {
      TCPView tcp(payload, payloadLen);
      if (!tcp.isValid()) {
        sections.push_back(text("[invalid TCP header]"));
        return;
      }
      sections.push_back(text("TCP") | bold);
      std::snprintf(buf, sizeof(buf), "  Src Port: %u", tcp.srcPort());
      sections.push_back(text(buf));
      std::snprintf(buf, sizeof(buf), "  Dst Port: %u", tcp.dstPort());
      sections.push_back(text(buf));
      std::snprintf(buf, sizeof(buf), "  Seq: %u", tcp.seqNum());
      sections.push_back(text(buf));
      std::snprintf(buf, sizeof(buf), "  Ack: %u", tcp.ackNum());
      sections.push_back(text(buf));
      std::string flags;
      if (tcp.flagSYN())
        flags += "SYN ";
      if (tcp.flagACK())
        flags += "ACK ";
      if (tcp.flagFIN())
        flags += "FIN ";
      if (tcp.flagRST())
        flags += "RST ";
      sections.push_back(
          text("  Flags: " + (flags.empty() ? std::string("-") : flags)));
    } else if (proto == 17) {
      UDPView udp(payload, payloadLen);
      if (!udp.isValid()) {
        sections.push_back(text("[invalid UDP header]"));
        return;
      }
      sections.push_back(text("UDP") | bold);
      std::snprintf(buf, sizeof(buf), "  Src Port: %u", udp.srcPort());
      sections.push_back(text(buf));
      std::snprintf(buf, sizeof(buf), "  Dst Port: %u", udp.dstPort());
      sections.push_back(text(buf));
      std::snprintf(buf, sizeof(buf), "  Length: %u", udp.length());
      sections.push_back(text(buf));
    } else {
      std::snprintf(buf, sizeof(buf), "Protocol %u not dissected", proto);
      sections.push_back(text(buf));
    }
  };

  if (eth.etherType() == 0x0800) {
    IPv4View ip(eth.payload(), eth.payloadLen());
    if (!ip.isValid()) {
      sections.push_back(text("[invalid IPv4 header]"));
    } else {
      sections.push_back(text("IPv4") | bold);
      sections.push_back(text("  Src IP: " + ip.srcIP()));
      sections.push_back(text("  Dst IP: " + ip.dstIP()));
      char buf[32];
      std::snprintf(buf, sizeof(buf), "  TTL: %u", ip.ttl());
      sections.push_back(text(buf));
      std::snprintf(buf, sizeof(buf), "  Protocol: %u", ip.protocol());
      sections.push_back(text(buf));
      sections.push_back(separator());
      describeTransport(ip.protocol(), ip.payload(), ip.payloadLen());
    }
  } else if (eth.etherType() == 0x86DD) {
    IPv6View ip(eth.payload(), eth.payloadLen());
    if (!ip.isValid()) {
      sections.push_back(text("[invalid IPv6 header]"));
    } else {
      sections.push_back(text("IPv6") | bold);
      sections.push_back(text("  Src IP: " + ip.srcIP()));
      sections.push_back(text("  Dst IP: " + ip.dstIP()));
      char buf[32];
      std::snprintf(buf, sizeof(buf), "  Hop Limit: %u", ip.hopLimit());
      sections.push_back(text(buf));
      std::snprintf(buf, sizeof(buf), "  Next Header: %u", ip.nextHeader());
      sections.push_back(text(buf));
      sections.push_back(separator());
      describeTransport(ip.nextHeader(), ip.payload(), ip.payloadLen());
    }
  }

  sections.push_back(separator());
  sections.push_back(text("Raw Bytes") | bold);
  sections.push_back(hexDump(pkt.bytes));

  return vbox(std::move(sections));
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

  std::vector<std::string> lines;
  std::vector<CapturedPacket> packets;
  int selected = 0;
  bool autoFollow = true;
  bool showDetail = false;

  // Double-right-click detection state -- see note in the event handler
  // about terminal emulators possibly intercepting right-click entirely.
  auto lastRightClickTime = std::chrono::steady_clock::now();
  int lastRightClickX = -1;
  int lastRightClickY = -1;

  MenuOption menuOption;
  menuOption.entries_option.transform = [](EntryState state) {
    Element e = text(state.label);

    // 1. Check the label string to determine the protocol
    // 2. Apply a light color decorator based on what we find
    if (state.label.find("TCP") == 0) {
      e = e | color(Color::CyanLight);
    } else if (state.label.find("UDP") == 0) {
      e = e | color(Color::YellowLight);
    } else if (state.label.find("IPv6") != std::string::npos) {
      // Searching anywhere in the string in case it's formatted differently
      e = e | color(Color::MagentaLight);
    } else if (state.label.find("IPv4") != std::string::npos) {
      e = e | color(Color::GreenLight);
    } else if (state.label.find("eth") == 0 ||
               state.label.find("Ethernet") != std::string::npos) {
      e = e | color(Color::White); // Default for basic ethernet frames
    }

    // Apply the selection highlight
    if (state.active) {
      // When inverted is applied to colored text in FTXUI,
      // it usually turns the background into that color and the text dark,
      // which creates a very clean highlight effect!
      e = e | bold | inverted;
    }

    return e;
  };

  auto menu = Menu(&lines, &selected, menuOption);

  auto layout = Renderer(menu, [&] {
    Element listPane = vbox({
                           text("CapturePlusPlus  |  packets: " +
                                std::to_string(lines.size())) |
                               bold,
                           separator(),
                           menu->Render() | vscroll_indicator | frame | flex,
                       }) |
                       border;

    bool haveSelection = !packets.empty() && selected >= 0 &&
                         selected < static_cast<int>(packets.size());

    if (!showDetail || !haveSelection) {
      return listPane;
    }

    Element detailPane = renderPacketDetail(packets[selected]) |
                         vscroll_indicator | frame | border;

    return vbox({
        listPane | flex,
        detailPane | size(HEIGHT, EQUAL, 15),
    });
  });

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

    if (event.is_mouse()) {
      const auto &m = event.mouse();

      if (m.button == Mouse::WheelUp || m.button == Mouse::WheelDown) {
        autoFollow = false;
        return false; // let Menu/frame still perform the actual scroll
      }

      if (m.button == Mouse::Right && m.motion == Mouse::Released) {
        auto now = std::chrono::steady_clock::now();
        bool samePlace = (m.x == lastRightClickX && m.y == lastRightClickY);
        bool fast =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                now - lastRightClickTime) < std::chrono::milliseconds(400);
        if (samePlace && fast) {
          showDetail = !showDetail;
        }
        lastRightClickTime = now;
        lastRightClickX = m.x;
        lastRightClickY = m.y;
        return true;
      }

      return false;
    }

    if (event == Event::ArrowUp || event == Event::ArrowDown ||
        event == Event::PageUp || event == Event::PageDown) {
      autoFollow = false;
      return false;
    }
    if (event == Event::End) {
      autoFollow = true;
      selected = static_cast<int>(lines.size()) - 1;
      return true;
    }

    if (event == Event::Return) {
      showDetail = !showDetail;
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
