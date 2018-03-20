#ifndef COREWORKSENGINE_CWE_H
#define COREWORKSENGINE_CWE_H

#include <thread>
#include <vector>
#include <cstdint>
#include <functional>
#include <algorithm>
#include <chrono>
#include <iostream>
#include <bitset>
#include <math.h>
#include <random>

// @todo make these ourselves.
#include "../external/MPMCQueue/MPMCQueue.h"
//#include "../external/microprofile/microprofile.h"
//#include "../external/microprofile/microprofile.cpp"

namespace CWE {

// Threads
const auto getThreadId = std::this_thread::get_id;
typedef std::thread::id ThreadId;
const auto main_thread_id = std::this_thread::get_id();
const auto hardware_concurrency = std::thread::hardware_concurrency();
typedef std::vector<std::thread *> Threads;

// Limits
const auto uint8_t_max = std::numeric_limits<uint8_t>::max();

// Subscription
template<typename type>
class Subscription {
 public:

  Subscription() : mask(0) {};

  bool accepts(Subscription &subscription) {
    return (subscription.mask == 0) ? (subscription.mask == this->mask) : (subscription.mask & this->mask)
        == subscription.mask;
  }

  void subscribe(type &mask) {
    this->mask = this->mask | mask;
  }

  void unSubscribe(type mask) {
    for (int a = 0; a < sizeof(type) * 8; a++) {
      if (mask & (1 << a)) {
        if ((this->mask & (1 << a))) {
          this->mask &= ~(1 << a);
        }
      }
    }
  }

 private:
  type mask;

};

typedef Subscription<std::bitset<uint8_t_max>> default_subscription;

// CommandPoolInterface
template<typename T>
class CommandPoolInterface {
 public:

  virtual bool addCommand(T command) = 0;
  virtual void waitUntilDone() = 0;
  virtual bool isDone() = 0;
};

// Command
class BaseCommand : public default_subscription {
 public:

  explicit BaseCommand(uintmax_t index = 0) : start(index), end(index), minsize(0), pool(nullptr) {}

  BaseCommand(uintmax_t start, uintmax_t end, uintmax_t minsize = 0)
      : start(start), end(end), minsize(minsize), pool(nullptr) {}

  virtual ~BaseCommand() = default;

  uintmax_t size() {
    return end - start;
  }

  bool isRange() {
    return size() != 0;
  }

  bool addCommand(BaseCommand *command) {
    assert(pool != nullptr);
    command->pool = pool;

    return pool->addCommand(command);
  }

  virtual void execute() = 0;

  virtual BaseCommand *clone() const = 0;

  uintmax_t start;
  uintmax_t end;
  uintmax_t minsize;
  CommandPoolInterface<BaseCommand *> *pool;
};

// Template for a copy construction cloneable command
template<typename Derived>
class Command : public BaseCommand {
 public:

  using BaseCommand::BaseCommand;

  BaseCommand *clone() const override {
    return new Derived(static_cast<Derived const &>(*this));
  }
};

// Queue adapter interface
template<typename T>
class QueueAdapterInterface {
 public:
  virtual bool tryPop(T &item) = 0;
  virtual bool tryEmplace(T &item) = 0;
  virtual void emplace(T &item) = 0;
  virtual void pop(T &item) = 0;
};

// Queue adapter for lock free MPMCQueue.
template<typename T>
class MPMCQueueAdapter : public rigtorp::MPMCQueue<T>, QueueAdapterInterface<T> {
 public:
  MPMCQueueAdapter() : rigtorp::MPMCQueue<T>() {};

  bool tryPop(T &item) override {
    return this->try_pop(item);
  };

  bool tryEmplace(T &item) override {
    return this->try_emplace(item);
  }

  void emplace(T &item) override {
    rigtorp::MPMCQueue<T>::emplace(item);
  }

  void pop(T &item) override {
    rigtorp::MPMCQueue<T>::pop(item);
  }
};

// Part
struct Part {

  Part(uintmax_t begin, uintmax_t end, uintmax_t threadIndex, uintmax_t minSize)
      : begin(begin), end(end), threadIndex(threadIndex), minSize(minSize) {};

  uintmax_t begin;
  uintmax_t end;
  uintmax_t threadIndex;
  uintmax_t minSize;
};

// PartitionScheme
typedef std::vector<Part> PartitionScheme;

// CommandPartitioner
class CommandPartitioner {
 public:

  CommandPartitioner() = default;

  virtual PartitionScheme partition(std::vector<uint8_t> threads, uintmax_t start, uintmax_t end, uintmax_t minSize = 0) {

    uint8_t threadSize = (uint8_t) threads.size();
    PartitionScheme parts;
    uintmax_t range = end - start;

    assert(threadSize != 0);

    if (range != 0) {

      uint8_t thread = 0;

      if (minSize == 0 && range == 1) {
        minSize = 1;
      } else if (minSize == 0) {
        minSize = range / threadSize;
      }

      auto part = (uintmax_t) floor(range / minSize);
      auto leftOver = range % minSize;

      for (uintmax_t a = 0; a < part; a++) {
        parts.emplace_back(Part(start, start + minSize, threads[thread % threadSize], minSize));
        start += minSize;
        thread++;
      }

      if (leftOver != 0) {
        parts.emplace_back(Part(range - leftOver, range, threads[thread % threadSize], minSize));
      }
    } else {

      std::uniform_int_distribution<unsigned long long int> distribution(0, threads.size() - 1);
      parts.emplace_back(Part(start, end, threads[distribution(generator)], minSize));
    }

    return parts;
  }

 private:
  static std::default_random_engine generator;
};

std::default_random_engine CommandPartitioner::generator = std::default_random_engine{};

// CommandPool
template<
    uint8_t n = 0,
    bool mainAsWorker = true,
    bool steal = false,
    class Partitioner = CommandPartitioner,
    template<typename> class Atom = std::atomic,
    template<typename> class QueueAdapter = MPMCQueueAdapter,
    class subscription = default_subscription
>
class CommandPool : public CommandPoolInterface<BaseCommand *> {

 public:

  CommandPool() : numOfThreads(n), runningThreads(0), partitioner() {

    if (numOfThreads == 0) {
      numOfThreads = hardware_concurrency;
    }

    stop.resize(numOfThreads);
    stop.reserve(numOfThreads);
    threads.reserve(numOfThreads);
    queue.reserve(numOfThreads);

    for (uint8_t b = 0; b < numOfThreads; b++) {
      QueueAdapterInterface<BaseCommand *> *adapter = (QueueAdapterInterface<BaseCommand *> *) new QueueAdapter<BaseCommand *>();
      queue.push_back(adapter);
    }

    for (uint8_t a = mainAsWorker; a < numOfThreads; a++) {
      threads.push_back(new std::thread(&CommandPool::consume, this, a - mainAsWorker));
    }

    while (runningThreads.load() != (numOfThreads - mainAsWorker)) {
    }
  };

  ~CommandPool() {

    stop.assign(numOfThreads, true);

    for (uint8_t a = 0 ; a < numOfThreads - mainAsWorker;  a++) {
      threads[a]->join();
    }

    while (runningThreads.load() != 0) {
    }

    threads.clear();
  }

  void waitUntilDone() {
    auto ready = false;
    if (getThreadId() == main_thread_id) {
      while (!ready) {
        if (mainAsWorker)
          consume(0);
        ready = isDone();
      }
    }
  }

  bool addCommand(BaseCommand *command) {

    if (command->pool == nullptr) {
      command->pool = this;
    }

    std::vector<uint8_t> result;
    for (uint8_t a = 0; a < subscriptions.size(); a++) {
      if (subscriptions[a].accepts(*command)) {
        result.push_back(a);
      };
    }

    PartitionScheme scheme = partitioner.partition(result, command->start, command->end, command->minsize);
    BaseCommand *clonedCommand;

    for (auto &it : scheme) {
      clonedCommand = command->clone();
      clonedCommand->start = it.begin;
      clonedCommand->end = it.end;
      clonedCommand->minsize = it.minSize;
      work++;
      queue[it.threadIndex]->emplace(clonedCommand);
    }

    delete command;

    return true;
  }

 private:

  int consume(uint8_t a) {
    runningThreads++;
    while (!stop[a]) {

      BaseCommand *item;

      if (!queue[a]->tryPop(item)) {
        if (getThreadId() != main_thread_id) {
          continue;
        }
        break;
      }

      item->execute();
      delete item;
      work--;
    }
    runningThreads--;
    return 0;
  }

  bool isDone() {
    return work.load() == 0;
  }

  CommandPool(const CommandPool &other) = delete;
  CommandPool &operator=(const CommandPool &) = delete;

  uint8_t numOfThreads;
  Atom<uint32_t> work;
  Atom<uint8_t> runningThreads;
  std::vector<std::thread *> threads;
  std::vector<bool> stop;
  std::vector<QueueAdapterInterface<BaseCommand *> *> queue;
  std::vector<subscription> subscriptions;
  Partitioner partitioner;

};
}
#endif //COREWORKSENGINE_CWE_H
