cmake_minimum_required(VERSION 3.2)
project(CWE)

set(CMAKE_EXPORT_COMPILE_COMMANDS "true")
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if (NOT MSVC)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -pedantic")
endif()

find_package(Threads REQUIRED)

add_executable(tests tests/Main.cpp external/gtest/gtest-all.cc )
target_link_libraries(tests ${CMAKE_THREAD_LIBS_INIT})
target_include_directories(
  tests PUBLIC
  external/gtest
)

enable_testing()
add_test(tests tests)
