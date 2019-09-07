
cmake_minimum_required( VERSION 2.8 )

project( cuckoo )

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/build/bin)

message(STATUS "Project Directory: ${PROJECT_SOURCE_DIR}")

# set(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/build/lib)
# link_directories(${PROJECT_SOURCE_DIR}/build/lib)
# include_directories(${PROJECT_SOURCE_DIR}/include)

add_subdirectory(src)
