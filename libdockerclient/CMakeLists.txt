set(CURL_HOME /opt/third/curl)

include_directories(${CURL_HOME}/include)

link_directories(${CURL_HOME}/lib)

set(DEPEND_LIBS curl)
file(GLOB SRC_LIST *.c *.h)
add_library(dockerclient STATIC ${SRC_LIST})
target_link_libraries(dockerclient ${DEPEND_LIBS})
set_target_properties(dockerclient PROPERTIES FOLDER "libdockerclient")