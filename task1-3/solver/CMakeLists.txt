add_executable(solver main.cpp)

target_link_libraries(solver PRIVATE bignum)

# auto-discover task*.cpp and build each as executable linked with crypto_lib
file(GLOB TASK_SOURCES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "task*.cpp")
foreach(task_src ${TASK_SOURCES})
	get_filename_component(task_name ${task_src} NAME_WE)
	add_executable(${task_name} ${task_src})
	target_include_directories(${task_name} PRIVATE ${CMAKE_SOURCE_DIR}/crypto_lib/include)
	target_link_libraries(${task_name} PRIVATE crypto_lib)
endforeach()

if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
	target_compile_options(solver PRIVATE --coverage -O0)
	target_link_options(solver PRIVATE --coverage)
endif()