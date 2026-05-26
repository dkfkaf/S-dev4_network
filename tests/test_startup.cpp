#include <gtest/gtest.h>
#include <string>
#include <vector>
#include "startup.h"

TEST(ParseChannels, EmptyInput) {
    EXPECT_TRUE(parseChannelsFromIwPhyInfo("").empty());
}

TEST(ParseChannels, SingleChannel) {
    const std::string in = "        * 2412 MHz [1] (20.0 dBm)\n";
    EXPECT_EQ(parseChannelsFromIwPhyInfo(in), std::vector<int>({1}));
}

TEST(ParseChannels, Multiple24GhzChannels) {
    const std::string in =
        "        * 2412 MHz [1] (20.0 dBm)\n"
        "        * 2417 MHz [2] (20.0 dBm)\n"
        "        * 2462 MHz [11] (20.0 dBm)\n";
    EXPECT_EQ(parseChannelsFromIwPhyInfo(in), std::vector<int>({1, 2, 11}));
}

TEST(ParseChannels, BothBands24And5Ghz) {
    const std::string in =
        "        * 2412 MHz [1] (20.0 dBm)\n"
        "        * 2462 MHz [11] (20.0 dBm)\n"
        "        * 5180 MHz [36] (17.0 dBm)\n"
        "        * 5825 MHz [165] (30.0 dBm)\n";
    EXPECT_EQ(parseChannelsFromIwPhyInfo(in), std::vector<int>({1, 11, 36, 165}));
}

TEST(ParseChannels, DisabledChannelsExcluded) {
    const std::string in =
        "        * 2412 MHz [1] (20.0 dBm)\n"
        "        * 5180 MHz [36] (disabled)\n"
        "        * 5200 MHz [40] (20.0 dBm)\n";
    EXPECT_EQ(parseChannelsFromIwPhyInfo(in), std::vector<int>({1, 40}));
}

TEST(ParseChannels, MalformedLinesSkipped) {
    const std::string in =
        "garbage line\n"
        "        * 2412 MHz [1] (20.0 dBm)\n"
        "other text\n"
        "  * incomplete\n"
        "        * 2462 MHz [11] (20.0 dBm)\n";
    EXPECT_EQ(parseChannelsFromIwPhyInfo(in), std::vector<int>({1, 11}));
}

TEST(ParseChannels, RealisticIwPhyInfoExcerpt) {
    // 실제 `iw phy phy0 info` 출력에서 발췌한 형태
    const std::string in =
        "Wiphy phy0\n"
        "    max # scan SSIDs: 4\n"
        "    Band 1:\n"
        "        Frequencies:\n"
        "            * 2412 MHz [1] (20.0 dBm)\n"
        "            * 2417 MHz [2] (20.0 dBm)\n"
        "            * 2422 MHz [3] (20.0 dBm)\n"
        "            * 2467 MHz [12] (disabled)\n"
        "            * 2472 MHz [13] (disabled)\n"
        "            * 2484 MHz [14] (disabled)\n";
    EXPECT_EQ(parseChannelsFromIwPhyInfo(in), std::vector<int>({1, 2, 3}));
}
