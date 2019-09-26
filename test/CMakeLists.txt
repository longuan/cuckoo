
cmake_minimum_required( VERSION 2.8 )

project( test )

add_executable(test_process test_process.c)

SET(LIBTEST_SRC libtest.h libtest.c)
add_library(testlib SHARED ${LIBTEST_SRC})
