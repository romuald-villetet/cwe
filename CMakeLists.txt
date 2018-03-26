cmake_minimum_required(VERSION 3.2)
project(CWE)

set(CMAKE_EXPORT_COMPILE_COMMANDS "true")
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
SET(COVERAGE OFF CACHE BOOL "Coverage")

find_package(Threads REQUIRED)

add_executable(tests test/Main.cpp external/gtest/gtest-all.cc test/Subscription.cpp test/CommandPartitioner.cpp test/CommandPool.cpp)
target_link_libraries(tests PUBLIC ${CMAKE_THREAD_LIBS_INIT})
target_include_directories(
  tests PUBLIC
  src/
  external/gtest
)

if (COVERAGE)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O0")
  target_compile_options(tests PRIVATE --coverage)
  target_link_libraries(tests PRIVATE --coverage)
endif()

enable_testing()
add_test(tests tests)
