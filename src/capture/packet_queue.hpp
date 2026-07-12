#ifndef PACKET_QUEUE_HPP
#define PACKET_QUEUE_HPP

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <mutex>
#include <vector>

struct CapturedPacket {
  std::vector<uint8_t> bytes;
  uint32_t capLen = 0;
  uint32_t origLen = 0;
};

class PacketQueue {
public:
  void push(CapturedPacket packet);

  // Waits up to `timeout` for at least one packet, then drains everything
  // currently available into `out`. Returns false if the wait timed out with
  // nothing to drain
  bool
  drainInto(std::vector<CapturedPacket> &out,
            std::chrono::milliseconds timout = std::chrono::milliseconds(150));

private:
  std::mutex mutex_;
  std::condition_variable cv_;
  std::deque<CapturedPacket> queue_;
};

#endif
