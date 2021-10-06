#include "cwe.h"
#include "gtest.h"

using CWE::CommandPool;
using CWE::Command;
using CWE::BaseCommand;

struct Counter {
  Counter() {
    counter++;
  }
  static void reset() { counter = 0; }
  static std::atomic<unsigned int> counter;
};

std::atomic<unsigned int> Counter::counter(0);

class CountCommand : public Command<CountCommand> {
 public:
  using Command::Command;

 protected:
  void execute() {
    if (isRange() == true) {
      for (auto i = start; i < end; i++) {
        Counter count;
      }
    } else {
      Counter count;
    }
  }
};

class RecursiveCountCommand : public Command<RecursiveCountCommand> {
 public:
  using Command::Command;

 protected:
  void execute() {
    if (isRange()) {
      for (auto i = start; i < end; i++) {
        Counter count;
        addCommand(new CountCommand());
      }
    } else {
      Counter count;
      addCommand(new CountCommand());
    }
  }
};

TEST(CommandPool, waitUntilDone) {
  CommandPool<> pool;
  pool.waitUntilDone();
}

TEST(CommandPool, addCommand_16Range) {
  CommandPool<> pool;
  pool.addCommand(new CountCommand(0, UINT16_MAX));
  pool.waitUntilDone();

  EXPECT_EQ(Counter::counter.load(), (uint32_t) UINT16_MAX);
  Counter::reset();
}

TEST(CommandPool, addCommand_minRange) {
  CommandPool<> pool;
  pool.addCommand(new CountCommand(0, 1));
  pool.waitUntilDone();

  EXPECT_EQ(Counter::counter.load(), (uint32_t) 1);
  Counter::reset();
}

TEST(CommandPool, addCommand_single) {
  CommandPool<> pool;
  pool.addCommand(new CountCommand());
  pool.waitUntilDone();

  EXPECT_EQ(Counter::counter.load(), (uint32_t) 1);
  Counter::reset();
}

TEST(CommandPool, addCommand_recursive) {
  CommandPool<> pool;
  pool.addCommand(new RecursiveCountCommand(0, 10, 1));
  pool.waitUntilDone();

  EXPECT_EQ(Counter::counter.load(), (uint32_t) 20);
  Counter::reset();

  pool.addCommand(new RecursiveCountCommand());
  pool.waitUntilDone();
  EXPECT_EQ(Counter::counter.load(), (uint32_t) 2);
  Counter::reset();
}

TEST(CommandPool, addCommand_notAccepted) {
  CommandPool<> pool;
  BaseCommand<> *command = new RecursiveCountCommand(0, 10, 1);
  command->subscribeToGroup(1);
  EXPECT_EQ(pool.addCommand(command), false);

  pool.waitUntilDone();
  EXPECT_EQ(Counter::counter.load(), (uint32_t) 0);
  Counter::reset();
}