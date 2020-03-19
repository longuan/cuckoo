
cmake_minimum_required( VERSION 2.8 )

project( cuckoo )

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/build/bin)

message(STATUS "Project Directory: ${PROJECT_SOURCE_DIR}")

# set(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/build/lib)
# link_directories(${PROJECT_SOURCE_DIR}/build/lib)
include_directories(${PROJECT_SOURCE_DIR}/include)

# aux_source_directory(. SRC_FILES)
set(COMMON_FILES 
    ${PROJECT_SOURCE_DIR}/src/utils.c 
    ${PROJECT_SOURCE_DIR}/src/maps.c 
    ${PROJECT_SOURCE_DIR}/src/main.c 
    ${PROJECT_SOURCE_DIR}/src/inject.c 
    ${PROJECT_SOURCE_DIR}/src/cuckoo.c
)

set(CMAKE_VERBOSE_MAKEFILE ON)

# set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ../build/)

if(ARCH STREQUAL x86)
    set(SRC_FILES 
        ${COMMON_FILES} 
        ./src/shellcode32.c 
        ./src/library32.c
    )
    # add_compile_options(-m32)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m32")
elseif(ARCH STREQUAL x64)
    set(SRC_FILES 
        ${COMMON_FILES} 
        ./src/shellcode.c 
        ./src/library.c
    )
else()
    MESSAGE(FATAL_ERROR  "cmake . -DARCH={arch}.  arch is x86 or x64")
endif()

message(STATUS "generate ELF into ${PROJECT_SOURCE_DIR}/build/bin/cuckoo")

add_executable(cuckoo ${SRC_FILES})
TARGET_LINK_LIBRARIES(cuckoo dl)
