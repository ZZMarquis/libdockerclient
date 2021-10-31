set(CURL_HOME /opt/third/curl)

message("CURL_HOME:${CURL_HOME}")

include_directories(${CURL_HOME}/include
        ${CMAKE_SOURCE_DIR}/libdockerclient)

link_directories(${CURL_HOME}/lib)

set(TEST_DEPEND_LIBS dockerclient curl)

file(GLOB TEST_SRC_LIST main.c)
add_executable(dockerclient_test ${TEST_SRC_LIST})
target_link_libraries(dockerclient_test ${TEST_DEPEND_LIBS})
set_target_properties(dockerclient_test PROPERTIES FOLDER "test")