
file(GLOB TASK_SOURCES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "task*.cpp")
foreach(task_src ${TASK_SOURCES})
	get_filename_component(task_name ${task_src} NAME_WE)
	add_executable(${task_name} ${task_src})
	target_include_directories(${task_name} PRIVATE ${CMAKE_SOURCE_DIR}/crypto_lib_boost/include)
	target_link_libraries(${task_name} PRIVATE crypto_lib_boost)
endforeach()
