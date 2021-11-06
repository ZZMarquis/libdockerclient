//
// Created by zlj on 2021/11/6.
//

#ifndef LIBDOCKERCLIENT_HTTP_UTILS_H
#define LIBDOCKERCLIENT_HTTP_UTILS_H

typedef struct _dc_http_header {
    char *key;
    char *value;
} dc_http_header;

typedef struct _dc_http_headers {
    dc_http_header **headers;
    int size;
} dc_http_headers;

dc_http_headers *dc_parse_http_headers(const char *headers_str);

char *dc_get_http_header(dc_http_headers *headers, const char *key);

void dc_print_http_headers(dc_http_headers *headers);

void dc_free_http_headers(dc_http_headers *headers);

#endif //LIBDOCKERCLIENT_HTTP_UTILS_H
