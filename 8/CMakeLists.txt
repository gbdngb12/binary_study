project(capstone_disas)

find_library(capstonef capstone REQUIRED)

if(${capstonef}) # or: if(${myglewlib} STREQUAL myglewlib-NOTFOUND) -> 모든 상황에서 일치하지 않으므로 사용 x
    message(FATAL_ERROR "no capstone, sad day")
else()
    message(STATUS "capstone found! as ${capstonef}")
endif()

add_executable(${PROJECT_NAME} "capstone_disas.cc")

target_link_libraries(${PROJECT_NAME}
    PUBLIC
        loader
        ${capstonef}
)

project(capstone_recursive)
