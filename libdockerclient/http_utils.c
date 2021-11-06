#include "http_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static void _free_http_header(dc_http_header *header) {
    if (NULL != header) {
        if (NULL != header->key) {
            free(header->key);
            header->key = NULL;
        }
        if (NULL != header->value) {
            free(header->value);
            header->value = NULL;
        }
        free(header);
    }
}

static dc_http_header *_parse_htte_header(const char *header_str) {
    int ret = 0;
    int key_len = 0;
    int value_len = 0;
    dc_http_header *header = NULL;
    char *tmp = NULL;

    if (NULL == header_str) {
        return NULL;
    }
    tmp = strchr(header_str, ':');
    if (NULL == tmp) {
        return NULL;
    }
    header = (dc_http_header *) calloc(1, sizeof(dc_http_header));
    if (NULL == header) {
        return NULL;
    }

    key_len = tmp - header_str;
    header->key = (char *) calloc(key_len + 1, sizeof(char));
    if (NULL == header->key) {
        goto end;
    }
    memcpy(header->key, header_str, key_len);
    header->key[key_len] = '\0';

    // 跳过冒号后面的空白字符
    ++tmp;
    while (isspace(*tmp)) {
        ++tmp;
    }
    value_len = header_str + strlen(header_str) - tmp;
    header->value = (char *) calloc(value_len + 1, sizeof(char));
    if (NULL == header->value) {
        goto end;
    }
    memcpy(header->value, tmp, value_len);
    header->value[value_len] = '\0';

    ret = 1;

    end:
    if (!ret) {
        _free_http_header(header);
        header = NULL;
    }
    return header;
}

dc_http_headers *dc_parse_http_headers(const char *headers_str) {
    int ret = 0;
    int i = 0;
    size_t headers_str_len = 0;
    dc_http_headers *headers = NULL;
    dc_http_header *tmp_header = NULL;
    char *token = NULL;
    char *tmp_header_str = NULL;


    if (NULL == headers_str) {
        return NULL;
    }
    headers = (dc_http_headers *) calloc(1, sizeof(dc_http_headers));
    if (NULL == headers) {
        return NULL;
    }
    headers->size = 0;

    headers_str_len = strlen(headers_str);
    tmp_header_str = calloc(1, headers_str_len + 1);
    if (NULL == tmp_header_str) {
        return NULL;
    }
    // 要复制一份原字符串来做切割，因为strtok函数会改变原字符串
    memcpy(tmp_header_str, headers_str, headers_str_len);
    tmp_header_str[headers_str_len] = '\0';

    token = strtok(tmp_header_str, "\r\n");
    while (token != NULL) {
        ++headers->size;
        token = strtok(NULL, "\r\n");
    }
    if (0 == headers->size) {
        return headers;
    }

    headers->headers = (dc_http_header **) calloc(headers->size, sizeof(dc_http_header *));
    if (NULL == headers->headers) {
        goto end;
    }
    i = 0;
    // 要复制一份原字符串来做切割，因为strtok函数会改变原字符串
    memcpy(tmp_header_str, headers_str, headers_str_len);
    tmp_header_str[headers_str_len] = '\0';
    token = strtok(tmp_header_str, "\r\n");
    while (token != NULL) {
        tmp_header = _parse_htte_header(token);
        if (NULL != tmp_header) {
            headers->headers[i++] = tmp_header;
        }
        token = strtok(NULL, "\r\n");
    }

    ret = 1;

    end:
    if (!ret) {
        dc_free_http_headers(headers);
        headers = NULL;
        free(tmp_header_str);
    }
    return headers;
}

char *dc_get_http_header(dc_http_headers *headers, const char *key) {
    int i = 0;
    if (NULL == key) {
        return NULL;
    }
    if (NULL != headers) {
        if (NULL != headers->headers && headers->size > 0) {
            for (i = 0; i < headers->size; ++i) {
                if (NULL == headers->headers[i]
                    || NULL == headers->headers[i]->key) {
                    continue;
                }
                if (NULL != headers->headers[i]->key && 0 == strcmp(headers->headers[i]->key, key)) {
                    return headers->headers[i]->value;
                }
            }
        }
    }
    return NULL;
}

void dc_print_http_headers(dc_http_headers *headers) {
    int i = 0;
    if (NULL != headers) {
        if (NULL != headers->headers && headers->size > 0) {
            for (i = 0; i < headers->size; ++i) {
                if (NULL == headers->headers[i]
                    || NULL == headers->headers[i]->key
                    || NULL == headers->headers[i]->value) {
                    continue;
                }
                printf("%s: %s\n", headers->headers[i]->key, headers->headers[i]->value);
            }
        }
    }
}

void dc_free_http_headers(dc_http_headers *headers) {
    int i = 0;
    if (NULL != headers) {
        if (NULL != headers->headers && headers->size > 0) {
            for (i = 0; i < headers->size; ++i) {
                _free_http_header(headers->headers[i]);
                headers->headers[i] = NULL;
            }
        }
        if (NULL != headers->headers) {
            free(headers->headers);
            headers->headers = NULL;
        }
        free(headers);
    }
}
