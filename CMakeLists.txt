cmake_minimum_required(VERSION 3.13.4)

# Set standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

project(binary_study)

option(loader_test "build loader_demo" OFF)
option(capstone_test "build capstone" OFF)
option(pin_test "build pin" OFF)

add_subdirectory("inc")

if(loader_test)
    add_executable(${PROJECT_NAME} "4/loader_demo.cc")
    target_link_libraries(${PROJECT_NAME}
        PUBLIC
            loader
    )
endif()

if(capstone_test)
    add_subdirectory("8")
endif()

if(pin_test)
    add_subdirectory("9")
endif()