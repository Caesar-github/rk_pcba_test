project(RK_PCBA)

message(${PROJECT_SOURCE_DIR})
message(${PROJECT_BINARY_DIR})

set(INSTALL_TARGET_DIR /data)

set(SRC_LIST 
	echo_audio_play_test.c
	echo_audio_record_test.c
	echo_audio_test.c
	echo_bt_test.c
	echo_cpu_test.c
	echo_ddr_test.c
	echo_discovery.c
	echo_emmc_test.c
	echo_key_test.c
	echo_led_test.c
	echo_rotary_test.c
	echo_rtc_test.c
	echo_wlan_test.c
)

foreach(obj_source ${SRC_LIST})
	STRING( REGEX REPLACE "(.*)(\\..*)$" "\\1" obj_target ${obj_source} )
add_executable( ${obj_target} ${obj_source} )
install(TARGETS ${obj_target} DESTINATION ${INSTALL_TARGET_DIR})
endforeach(obj_source)

set(SRC_LIST uevent/echo_uevent_detect.c)
add_executable( echo_uevent_detect ${SRC_LIST} )

set(SRC_LIST echo_pcbatest_server.c cJSON/cJSON.c)
include_directories(cJSON)
link_libraries(m)
add_executable( echo_pcbatest_server ${SRC_LIST} )

set(SRC_LIST write_storage.c rk_vendor_storage/rk_vendor_storage.c )
include_directories("./rk_vendor_storage" "./")
add_executable( write_storage ${SRC_LIST} )

MESSAGE(${CMAKE_CURRENT_SOURCE_DIR} "==CMAKE_CURRENT_SOURCE_DIR=")
MESSAGE(${CMAKE_STRIP}  "== CMAKE_STRIP")
MESSAGE(${CMAKE_C_COMPILER} "==CMAKE_C_COMPILER")

install(TARGETS echo_uevent_detect write_storage echo_pcbatest_server DESTINATION ${INSTALL_TARGET_DIR})
