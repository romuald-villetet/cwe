#include "cwe.h"
#include "gtest.h"

using CWE::CommandPool;
using CWE::Command;

struct Counter {

  Counter() {
    counter++;
  }
  static void reset() { counter = 0;  }
  static std::atomic<unsigned int> counter;
};

std::atomic<unsigned int> Counter::counter(0);

class CountCommand : public Command<CountCommand> {
 public:

  using Command::Command;

 protected:

  void execute()
  {
    if (isRange()) {
      for (unsigned int i = start; i < end ; i++) {
        Counter count;
      }
    }
    else {
      Counter count;
    }
  }
};

TEST(CommandPool, default) {
  CommandPool<> pool;
  pool.waitUntilDone();
}

/**
 * CommandPool tests
 */
TEST(CommandPool, addCommand_maxRange) {

  CommandPool<> pool;
  pool.addCommand(new CountCommand(0, (unsigned int) -1));
  pool.waitUntilDone();

  EXPECT_EQ(Counter::counter.load(), (unsigned int) -1);
  Counter::reset();
}

TEST(CommandPool, addCommand_minRange) {

  CommandPool<> pool;
  pool.addCommand(new CountCommand(0, 1));
  pool.waitUntilDone();

  EXPECT_EQ(Counter::counter.load(), 1);
  Counter::reset();
}

TEST(CommandPool, addCommand_single) {

  CommandPool<> pool;
  pool.addCommand(new CountCommand());
  pool.waitUntilDone();

  EXPECT_EQ(Counter::counter.load(), 1);
  Counter::reset();
}
