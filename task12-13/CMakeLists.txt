cmake_minimum_required(VERSION 3.15)
project(CryptoProtocols)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Поиск зависимостей
find_package(Boost REQUIRED COMPONENTS system)
find_package(OpenGL REQUIRED)
find_package(glfw3 REQUIRED)

# Добавление ImGui как субмодуля
set(IMGUI_DIR external/imgui)

# Создание статической библиотеки ImGui
add_library(imgui STATIC
    ${IMGUI_DIR}/imgui.cpp
    ${IMGUI_DIR}/imgui_demo.cpp
    ${IMGUI_DIR}/imgui_draw.cpp
    ${IMGUI_DIR}/imgui_tables.cpp
    ${IMGUI_DIR}/imgui_widgets.cpp
    ${IMGUI_DIR}/backends/imgui_impl_glfw.cpp
    ${IMGUI_DIR}/backends/imgui_impl_opengl3.cpp
)

target_include_directories(imgui PUBLIC
    ${IMGUI_DIR}
    ${IMGUI_DIR}/backends
)

# Основной исполняемый файл
add_executable(${PROJECT_NAME}
    src/main.cpp
    src/mental_poker.cpp
    src/blind_voting.cpp
    src/gui.cpp
)

# Подключение заголовочных файлов
target_include_directories(${PROJECT_NAME} PRIVATE
    src/
    ${IMGUI_DIR}
    ${IMGUI_DIR}/backends
    ${Boost_INCLUDE_DIRS}
)

# Линковка библиотек
target_link_libraries(${PROJECT_NAME}
    imgui
    glfw
    OpenGL::GL
    ${Boost_LIBRARIES}
    ${CMAKE_DL_LIBS}
)

# Компиляторские флаги
if(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE /W4)
else()
    target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -O2)
endif()

# Linux специфичные библиотеки
if(UNIX AND NOT APPLE)
    target_link_libraries(${PROJECT_NAME} X11 Xi Xrandr Xxf86vm Xinerama Xcursor rt m dl)
endif()
