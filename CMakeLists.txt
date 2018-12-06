cmake_minimum_required(VERSION 3.2)
project(CWE)

set(CMAKE_EXPORT_COMPILE_COMMANDS "true")
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
SET(COVERAGE OFF CACHE BOOL "Coverage")
set(PROFILE ON CACHE BOOL "true")
set(EXTRA_SRC)

if(MSVC)
  add_definitions(-DGTEST_HAS_TR1_TUPLE=0)
  if(CMAKE_CXX_FLAGS MATCHES "/W[0-4]")
    string(REGEX REPLACE "/W[0-4]" "/W4" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
  else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4")
  endif()

elseif(CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wno-long-long -pedantic")
endif()

find_package(Threads REQUIRED)

IF (PROFILE)
  ADD_DEFINITIONS( -DPROFILE)
  set(EXTRA_SRC ${EXTRA_SRC} external/microprofile/microprofile.cpp)
ENDIF (PROFILE)

add_executable(tests test/Main.cpp external/gtest/gtest-all.cc test/Subscription.cpp test/CommandPartitioner.cpp test/CommandPool.cpp ${EXTRA_SRC})
target_link_libraries(tests PUBLIC ${CMAKE_THREAD_LIBS_INIT})
target_include_directories(
  tests PUBLIC
  src/
  external/gtest
)

if(WIN32 AND PROFILE)
  target_link_libraries(tests wsock32 ws2_32)
endif()

if (COVERAGE)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O0")
  target_compile_options(tests PRIVATE --coverage)
  target_link_libraries(tests PRIVATE --coverage)
endif ()

enable_testing()
add_test(tests tests)
