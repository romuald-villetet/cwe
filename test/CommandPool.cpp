#include "cwe.h"
#include "gtest.h"

using CWE::CommandPool;

TEST(CommandPool, default) {
  CommandPool<> pool;
  pool.waitUntilDone();
}
