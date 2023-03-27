project(backward_slicing)


add_executable(${PROJECT_NAME} "backword_slicing.cc")

target_link_libraries(${PROJECT_NAME}
    PUBLIC
        ${util}
)