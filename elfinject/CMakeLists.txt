cmake_minimum_required(VERSION 3.13.4)

project(elf_inject C)
SET(GCC_COVERAGE_LINK_FLAGS "-lelf")

add_executable(${PROJECT_NAME} "elfinject.c")

target_link_libraries(${PROJECT_NAME}
    PUBLIC
        "/usr/lib/x86_64-linux-gnu/libelf.so"    
)