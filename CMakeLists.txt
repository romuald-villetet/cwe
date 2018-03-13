cmake_minimum_required(VERSION 3.2)
project(CWE)

set(CMAKE_EXPORT_COMPILE_COMMANDS "true")
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Threads REQUIRED)

add_executable(tests tests/main.cpp tests/dev.cpp external/gtest/gtest-all.cc )
target_link_libraries(tests ${CMAKE_THREAD_LIBS_INIT})
target_include_directories(
  tests PUBLIC
  src/
  external/gtest
)

enable_testing()
add_test(tests tests)
