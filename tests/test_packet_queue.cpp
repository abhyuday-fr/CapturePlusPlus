#include "packet_queue.hpp"
#include <chrono>
#include <gtest/gtest.h>
#include <thread>

namespace {
CapturedPacket makePacket(uint8_t marker) {
  CapturedPacket p;
  p.bytes = {marker};
  p.capLen = 1;
  p.origLen = 1;
  return p;
}
} // namespace

TEST(PacketQueueTest, DrainReturnsFalseOnEmptyTimeout) {
  PacketQueue q;
  std::vector<CapturedPacket> out;
  bool got = q.drainInto(out, std::chrono::milliseconds(50));
  EXPECT_FALSE(got);
  EXPECT_TRUE(out.empty());
}

TEST(PacketQueueTest, DrainReturnsAllPushedPacketsInOrder) {
  PacketQueue q;
  q.push(makePacket(1));
  q.push(makePacket(2));
  q.push(makePacket(3));

  std::vector<CapturedPacket> out;
  bool got = q.drainInto(out, std::chrono::milliseconds(50));

  ASSERT_TRUE(got);
  ASSERT_EQ(out.size(), 3u);
  EXPECT_EQ(out[0].bytes[0], 1);
  EXPECT_EQ(out[1].bytes[0], 2);
  EXPECT_EQ(out[2].bytes[0], 3);
}

TEST(PacketQueueTest, DrainEmptiesQueueSoSecondDrainTimesOut) {
  PacketQueue q;
  q.push(makePacket(1));

  std::vector<CapturedPacket> first;
  ASSERT_TRUE(q.drainInto(first, std::chrono::milliseconds(50)));
  ASSERT_EQ(first.size(), 1u);

  std::vector<CapturedPacket> second;
  bool got = q.drainInto(second, std::chrono::milliseconds(50));
  EXPECT_FALSE(got); // queue should be empty now
}

TEST(PacketQueueTest, DrainWakesUpWhenPacketArrivesFromAnotherThread) {
  PacketQueue q;
  std::vector<CapturedPacket> out;

  std::thread producer([&q] {
    std::this_thread::sleep_for(std::chrono::milliseconds(30));
    q.push(makePacket(42));
  });

  auto start = std::chrono::steady_clock::now();
  bool got = q.drainInto(out, std::chrono::milliseconds(500));
  auto elapsed = std::chrono::steady_clock::now() - start;

  producer.join();

  ASSERT_TRUE(got);
  ASSERT_EQ(out.size(), 1u);
  EXPECT_EQ(out[0].bytes[0], 42);

  EXPECT_LT(elapsed, std::chrono::milliseconds(200));
}
