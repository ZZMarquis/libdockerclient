#ifndef LIBDOCKERCLIENT_DOCKER_CLIENT_H
#define LIBDOCKERCLIENT_DOCKER_CLIENT_H

#include "curl/curl.h"

CURLcode get(
        const char *url,
        const char *unix_sock_path,
        int conn_timeout,
        int read_timeout,
        const char **req_headers,
        unsigned int req_headers_count,
        unsigned char **resp_body,
        unsigned int *resp_body_len,
        unsigned char **resp_headers,
        unsigned int *resp_headers_len
);

#endif //LIBDOCKERCLIENT_DOCKER_CLIENT_H
