cmake_minimum_required(VERSION 3.13.4)

# Set standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

project(loader_demo)

add_subdirectory("inc")

add_executable(${PROJECT_NAME} "4/loader_demo.cc")

target_link_libraries(${PROJECT_NAME}
    PUBLIC
        loader
)