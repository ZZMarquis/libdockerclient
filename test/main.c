#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "docker_client.h"
#include "http_utils.h"

int main() {
    CURLcode res;
    unsigned char *resp_body;
    unsigned int resp_body_len;
    unsigned char *resp_headers;
    unsigned int resp_headers_len;
    dc_http_headers *headers = NULL;
    dc_ping_result *ping_result = NULL;
    dc_info *info = NULL;

    res = get("http://127.0.0.1:2375/_ping", NULL, 30, 30, NULL, 0, &resp_body, &resp_body_len, &resp_headers,
              &resp_headers_len);
//    res = get("http://localhost/_ping", "/var/run/docker.sock", 30, 30, NULL, 0, &resp_body, &resp_body_len, &resp_headers, &resp_headers_len);
    if (CURLE_OK != res) {
        printf("curl error:%d", res);
    } else {
        if (NULL == resp_body) {
            printf("resp_body is null\n");
        } else {
            printf("%s\n", resp_body);
            free(resp_body);
        }
        if (NULL == resp_headers) {
            printf("resp_headers is null\n");
        } else {
            printf("%s\n", resp_headers);
            printf("---------------\n");
            headers = dc_parse_http_headers(resp_headers);
            dc_print_http_headers(headers);
            dc_free_http_headers(headers);
            free(resp_headers);
        }
    }

    ping_result  = dc_ping("http://127.0.0.1:2375/_ping");
    free_ping_result(ping_result);

    info = dc_get_info("http://127.0.0.1:2375/v1.41/info");
    if (NULL != info) {
        dc_free_info(info);
        info = NULL;
    }

    return 0;
}


