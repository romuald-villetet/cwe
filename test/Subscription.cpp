#include "cwe.h"
#include "gtest.h"

using CWE::Subscription;

typedef Subscription<uint8_t, unsigned char> Subscribe;

class TestSubsribe : public Subscribe {
 public:
  using Subscribe::Subscription;

  bool operator==(const TestSubsribe &rhs) const {
    return mask == rhs.mask;
  }

  bool operator!=(const TestSubsribe &rhs) const {
    return !(rhs.mask == mask);
  }
};

/**
 * Subscription tests
 */
TEST(Subscription, subribeToGroup) {
  const uint8_t testSize = 8;
  const uint8_t testData[testSize][2] = {
      {0, 1},    // + 00000001 = 00000001
      {1, 3},    // + 00000010 = 00000011
      {2, 7},    // + 00000100 = 00000111
      {3, 15},   // + 00001000 = 00001111
      {4, 31},   // + 00010000 = 00011111
      {5, 63},   // + 00100000 = 00111111
      {6, 127},  // + 01000000 = 01111111
      {7, 255},  // + 10000000 = 11111111
  };

  TestSubsribe s1; // 00000000

  for (uint8_t a = 0; a < testSize; a++) {
    TestSubsribe r(testData[a][1]);
    s1.subscribeToGroup(testData[a][0]);
    EXPECT_EQ(s1, r);
  }
}

TEST(Subscription, subscribe) {
  const uint8_t testSize = 4;
  const uint8_t testData[testSize][3] = {
      {82, 3, 83},     // 01010010 | 00000011 = 01010011
      {96, 34, 98},    // 01100000 | 00100010 = 01100010
      {255, 255, 255}, // 11111111 | 11111111 = 11111111
      {0, 0, 0},       // 00000000 | 00000000 = 00000000
  };

  for (uint8_t a = 0; a < testSize; a++) {
    TestSubsribe s1(testData[a][0]);
    TestSubsribe r(testData[a][2]);

    s1.subscribe(testData[a][1]);

    EXPECT_EQ(s1, r);
  }
}

TEST(Subscription, unSubribeFromGroup) {
  const uint8_t testSize = 8;
  const uint8_t testData[testSize][2] = {
      {7, 127}, // - 10000000 = 01111111
      {6, 63},  // - 01000000 = 00111111
      {5, 31},  // - 00100000 = 00011111
      {4, 15},  // - 00010000 = 00001111
      {3, 7},   // - 00001000 = 00000111
      {2, 3},   // - 00000100 = 00000011
      {1, 1},   // - 00000010 = 00000001
      {0, 0},   // - 00000001 = 00000000
  };

  TestSubsribe s1(255); // 11111111

  for (uint8_t a = 0; a < testSize; a++) {
    TestSubsribe r(testData[a][1]);
    s1.unSubscribeFromGroup(testData[a][0]);
    EXPECT_EQ(s1, r);
  }
}

TEST(Subscription, unsubscribe) {
  const uint8_t testSize = 2;
  const uint8_t testData[testSize][3] = {
      {82, 3, 80},  // 01010010 - 00000011 = 01010000
      {96, 34, 64}, // 01100000 - 00100010 = 01000000
  };

  for (uint8_t a = 0; a < testSize; a++) {
    TestSubsribe s1(testData[a][0]);
    TestSubsribe r(testData[a][2]);

    s1.unSubscribe(testData[a][1]);

    EXPECT_EQ(s1, r);
  }
}

TEST(Subscription, accepts) {
  const uint8_t testSize = 8;
  const uint8_t testData[testSize][3] = {
      {82, 3, false},   // 01010010 & 00000011 = false
      {13, 67, false},  // 00001101 & 01000011 = false
      {87, 85, true},   // 01010111 & 01010101 = true
      {0, 0, true},     // 00000000 & 00000000 = true
      {0, 1, false},    // 00000000 & 00000001 = false
      {177, 23, false}, // 10110001 & 00010111 = false
      {189, 133, true}, // 10111101 & 10000101 = true
      {255, 255, true}, // 11111111 & 11111111 = true
  };

  for (uint8_t a = 0; a < testSize; a++) {
    TestSubsribe s1(testData[a][0]);
    TestSubsribe s2(testData[a][1]);


    // Test all "accepts" methods.
    EXPECT_EQ(s1.accepts(s2), (const bool) testData[a][2]);
  }
}
