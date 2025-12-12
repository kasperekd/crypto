cmake_minimum_required(VERSION 3.10)
project(FiatShamirCpp)

set(CMAKE_CXX_STANDARD 17)

set(OpenGL_GL_PREFERENCE GLVND)

find_package(Threads REQUIRED)
find_package(Boost REQUIRED COMPONENTS random)
find_package(nlohmann_json REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(ZMQ REQUIRED libzmq)
find_package(glfw3 REQUIRED)
find_package(OpenGL REQUIRED)

set(IMGUI_DIR "imgui")
if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${IMGUI_DIR})
    message(FATAL_ERROR "Папка 'imgui' не найдена! Убедитесь, что она лежит рядом с CMakeLists.txt")
endif()

file(GLOB IMGUI_SOURCES 
    "${IMGUI_DIR}/imgui.cpp" 
    "${IMGUI_DIR}/imgui_draw.cpp" 
    "${IMGUI_DIR}/imgui_tables.cpp" 
    "${IMGUI_DIR}/imgui_widgets.cpp"
    "${IMGUI_DIR}/backends/imgui_impl_glfw.cpp"
    "${IMGUI_DIR}/backends/imgui_impl_opengl3.cpp"
)

add_executable(FiatShamirCpp main.cpp ${IMGUI_SOURCES})

target_include_directories(FiatShamirCpp PRIVATE 
    ${IMGUI_DIR} 
    ${IMGUI_DIR}/backends
    ${ZMQ_INCLUDE_DIRS}
)

target_link_libraries(FiatShamirCpp PRIVATE 
    nlohmann_json::nlohmann_json
    Boost::random
    ${ZMQ_LIBRARIES}
    glfw
    OpenGL::GL
    Threads::Threads 
    ${CMAKE_DL_LIBS} 
)