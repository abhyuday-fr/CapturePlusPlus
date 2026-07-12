#include "capture/packet_capture.hpp"
#include <gtest/gtest.h>
#include <string>

namespace {
std::string fixture(const std::string &name) {
  return std::string(FIXTURES_DIR) + "/" + name;
}
} // namespace

TEST(PacketCaptureTest, OpenOfflineValidFileSucceeds) {
  std::string err;
  auto capture = PacketCapture::openOffline(fixture("sample.pcap"), err);
  ASSERT_TRUE(capture.has_value()) << "Failed to open: " << err;
}

TEST(PacketCaptureTest, OpenOfflineMissingFileFails) {
  std::string err;
  auto capture =
      PacketCapture::openOffline(fixture("does_not_exist.pcap"), err);
  EXPECT_FALSE(capture.has_value());
  EXPECT_FALSE(err.empty());
}

TEST(PacketCaptureTest, RunOnOfflineFileSucceeds) {
  std::string err;
  auto capture = PacketCapture::openOffline(fixture("sample.pcap"), err);
  ASSERT_TRUE(capture.has_value());
  EXPECT_TRUE(capture->run(nullptr, -1));
}

TEST(PacketCaptureTest, MoveConstructorTransfersOwnership) {
  std::string err;
  auto capture = PacketCapture::openOffline(fixture("sample.pcap"), err);
  ASSERT_TRUE(capture.has_value());

  PacketCapture moved(std::move(*capture));
  EXPECT_TRUE(moved.run(nullptr, -1));
}

TEST(PacketCaptureTest, OfflineFixtureReportsEthernetLinkType) {
  std::string err;
  auto capture = PacketCapture::openOffline(fixture("sample.pcap"), err);
  ASSERT_TRUE(capture.has_value());
  EXPECT_EQ(capture->linkType(), DLT_EN10MB);
}
