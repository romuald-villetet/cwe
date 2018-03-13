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

// @todo make these ourselves.
#include "../external/MPMCQueue/MPMCQueue.h"
#include "../external/microprofile/microprofile.h"
#include "../external/microprofile/microprofile.cpp"

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
  bool accepts(type &mask) {
    return (mask == 0) ? (mask == this->mask) : (mask & this->mask) == mask;
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

// Command
class Command;

// Queue adapter interface
template<typename T>
class QueueAdapterInterface {
 public:
  virtual bool tryPop(T &item) = 0;
  virtual bool tryEmplace(T &item) = 0;
};

// Queue adapter for MPMCQueue.
template<typename T>
class MPMCQueueAdapter : public rigtorp::MPMCQueue<T>, QueueAdapterInterface<T> {
 public:
  MPMCQueueAdapter() : rigtorp::MPMCQueue<T>(4096) {};

  bool tryPop(T &item) override {
    return this->try_pop(item);
  };

  bool tryEmplace(T &item) override {
    return this->try_emplace(item);
  }
};

// CommandPool
template<
    uint8_t n = 0,
    bool mainAsWorker = true,
    bool steal = false,
    template<typename> class Atom = std::atomic,
    template<typename> class QueueAdapter = MPMCQueueAdapter,
    class subscription = default_subscription
>
class CommandPool {

 public:

  CommandPool() : numOfThreads(n), runningThreads(0) {

    if (numOfThreads == 0) {
      numOfThreads = hardware_concurrency;
    }

    stop.resize(numOfThreads);
    threads.reserve(numOfThreads);
    for (uint8_t a = mainAsWorker; a < numOfThreads; a++) {
      threads[a] = new std::thread(&CommandPool::consume, this, a);
    }

    for (uint8_t b = 0; b < numOfThreads; b++) {
      queue.push_back((QueueAdapterInterface<Command *> *) new QueueAdapter<Command *>());
    }

    while (runningThreads.load() != (numOfThreads - mainAsWorker)) {
    }
  };

  ~CommandPool() {

    for (uint8_t a = mainAsWorker; a < numOfThreads; a++) {
      stop[a] = true;
      threads[a]->join();
    }

    threads.clear();
    stop.clear();
  }

  void waitUntilfinished() {
    auto ready = false;
    if (getThreadId() == main_thread_id) {
      while (!ready) {
        if (mainAsWorker)
          consume(0);
        ready = work.load() == 0;
      }
    }
  }

 private:

  int consume(uint8_t a) {
    runningThreads++;
    while (stop[a] == false) {

    }
    runningThreads--;
    return 0;
  }

  CommandPool(const CommandPool &other) = delete;
  CommandPool &operator=(const CommandPool &) = delete;

  uint8_t numOfThreads;
  Atom<uint32_t> work;
  Atom<uint8_t> runningThreads;
  std::vector<std::thread *> threads;
  std::vector<bool> stop;
  std::vector<QueueAdapterInterface<Command *> *> queue;
  std::vector<subscription> subscriptions;

};
}
#endif //COREWORKSENGINE_CWE_H
