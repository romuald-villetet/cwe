#include "cwe.h"
#include "gtest.h"

using CWE::CommandPartitioner;
using CWE::PartitionScheme;
using CWE::Part;

TEST(CommandPartitioner, distributed_range_no_minsize) {
  CommandPartitioner *partitioner = new CommandPartitioner();

  PartitionScheme expectedResult;
  expectedResult.emplace_back(Part(0, 50, 0, 50));
  expectedResult.emplace_back(Part(50, 100, 1, 50));

  PartitionScheme result = partitioner->partition({0, 1}, 0, 100, 0);

  EXPECT_EQ(expectedResult, result);
}

TEST(CommandPartitioner, distributed_range_minsize) {
  CommandPartitioner *partitioner = new CommandPartitioner();

  PartitionScheme expectedResult;
  expectedResult.emplace_back(Part(0, 10, 0, 10));
  expectedResult.emplace_back(Part(10, 20, 1, 10));
  expectedResult.emplace_back(Part(20, 30, 0, 10));
  expectedResult.emplace_back(Part(30, 40, 1, 10));
  expectedResult.emplace_back(Part(40, 50, 0, 10));
  expectedResult.emplace_back(Part(50, 60, 1, 10));
  expectedResult.emplace_back(Part(60, 70, 0, 10));
  expectedResult.emplace_back(Part(70, 80, 1, 10));
  expectedResult.emplace_back(Part(80, 90, 0, 10));
  expectedResult.emplace_back(Part(90, 100, 1, 10));

  PartitionScheme result = partitioner->partition({0, 1}, 0, 100, 10);

  EXPECT_EQ(expectedResult, result);
}

TEST(CommandPartitioner, not_distributed_range) {
  CommandPartitioner *partitioner = new CommandPartitioner();

  PartitionScheme expectedResult;
  expectedResult.emplace_back(Part(0, 100, 0, 100));

  PartitionScheme result = partitioner->partition({0, 1, 2, 3, 4}, 0, 100, 100);

  EXPECT_EQ(expectedResult, result);
}

TEST(CommandPartitioner, not_range) {
  CommandPartitioner *partitioner = new CommandPartitioner();

  PartitionScheme expectedResult;
  expectedResult.emplace_back(Part(0, 1, 0, 1));

  PartitionScheme result = partitioner->partition({0, 1, 2, 3, 4}, 0, 1);

  EXPECT_EQ(expectedResult, result);
}