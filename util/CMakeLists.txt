project(util)

find_library(capstonl capstone REQUIRED)

if(${capstonl}) # or: if(${myglewlib} STREQUAL myglewlib-NOTFOUND) -> 모든 상황에서 일치하지 않으므로 사용 x
    message(FATAL_ERROR "no capston, sad day")
else()
    message(STATUS "capston found! as ${capstonl}")
endif()

find_library(tritonl triton REQUIRED)

if(${tritonl}) # or: if(${myglewlib} STREQUAL myglewlib-NOTFOUND) -> 모든 상황에서 일치하지 않으므로 사용 x
    message(FATAL_ERROR "no triton, sad day")
else()
    message(STATUS "triton found! as ${tritonl}")
endif()

add_library(${PROJECT_NAME} "disasm_util.cc" "triton_util.cc")

set_target_properties(${PROJECT_NAME} PROPERTIES PUBLIC_HEADER "disasm_util.h;triton_util.h")

# specify the include directory for the library
target_include_directories(${PROJECT_NAME} 
    PUBLIC 
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(${PROJECT_NAME}
    PUBLIC
        ${capstonl}
        ${tritonl}
)