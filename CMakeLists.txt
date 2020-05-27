
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
    ${PROJECT_SOURCE_DIR}/src/main.c 
    ${PROJECT_SOURCE_DIR}/src/inject.c 
)

# set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")


# set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ../build/)


if(ARCH STREQUAL x86)
    set(SRC_FILES 
        ${COMMON_FILES} 
        ${PROJECT_SOURCE_DIR}/src/shellcode32.c 
        ${PROJECT_SOURCE_DIR}/src/library32.c
        ${PROJECT_SOURCE_DIR}/src/elfinject32.c
    )
    # add_compile_options(-m32)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m32")
elseif(ARCH STREQUAL x64)
    set(SRC_FILES 
        ${COMMON_FILES} 
        ${PROJECT_SOURCE_DIR}/src/shellcode64.c 
        ${PROJECT_SOURCE_DIR}/src/library64.c
        ${PROJECT_SOURCE_DIR}/src/elfinject64.c
    )
else()
    message(FATAL_ERROR  "cmake . -DARCH={arch}.  arch is x86 or x64")
endif()

message(STATUS "generate ELF into ${PROJECT_SOURCE_DIR}/build/bin/cuckoo")

add_executable(cuckoo ${SRC_FILES})
TARGET_LINK_LIBRARIES(cuckoo dl)
