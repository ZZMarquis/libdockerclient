#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "docker_client.h"

int main() {
    CURLcode res;
    unsigned char *resp_body;
    unsigned int resp_body_len;
    unsigned char *resp_headers;
    unsigned int resp_headers_len;
    char *resp_headers_str;

    res = get("http://127.0.0.1:2375/_ping",NULL, 30, 30, NULL, 0, &resp_body, &resp_body_len, &resp_headers, &resp_headers_len);
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
            resp_headers_str = (char *)calloc(resp_headers_len + 1, sizeof(char ));
            memcpy(resp_headers_str, resp_headers, resp_headers_len);
            printf("%s\n", resp_headers_str);
            free(resp_headers);
        }
    }

    return 0;
}


