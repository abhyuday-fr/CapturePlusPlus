#include "packet_queue.hpp"

void PacketQueue::push(CapturedPacket packet) {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    queue_.push_back(std::move(packet));
  }
  cv_.notify_one();
}

bool PacketQueue::drainInto(std::vector<CapturedPacket> &out,
                            std::chrono::milliseconds timeout) {
  std::unique_lock<std::mutex> lock(mutex_);

  bool hasData =
      cv_.wait_for(lock, timeout, [this] { return !queue_.empty(); });

  if (!hasData) {
    return false; // timed out, nothing to drain
  }

  while (!queue_.empty()) { // drain everything currently queued
    out.push_back(std::move(queue_.front()));
    queue_.pop_front();
  }

  return true;
}
