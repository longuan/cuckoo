

aux_source_directory(. SRC_FILES)

set(CMAKE_VERBOSE_MAKEFILE ON)

# set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ../build/)
message(STATUS "generate ELF into ${PROJECT_SOURCE_DIR}/build/bin/cuckoo")
add_executable(cuckoo ${SRC_FILES})
TARGET_LINK_LIBRARIES(cuckoo dl)
