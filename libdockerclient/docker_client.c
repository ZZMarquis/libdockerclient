#include "docker_client.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "curl/curl.h"

typedef struct _data_buff {
    unsigned int size;
    void *buff;
} data_buff;

// https://www.cnblogs.com/heluan/p/10177475.html
size_t _get_resp_data(void *ptr, size_t size, size_t nmemb, void *stream) {
    size_t real_size = size * nmemb;
    data_buff *buff_ptr = (data_buff *) stream;

    if (stream == NULL || ptr == NULL || size == 0) {
        return 0;
    }

    if (0 == buff_ptr->size) {
        buff_ptr->buff = (void *) calloc(real_size, 1);
        if (NULL == buff_ptr->buff) {
            // calloc failed
            return 0;
        }
        memcpy(buff_ptr->buff, ptr, real_size);
        buff_ptr->size = real_size;
    } else {
        buff_ptr->buff = (void *) realloc(buff_ptr->buff, buff_ptr->size + real_size);
        if (NULL == buff_ptr->buff) {
            // realloc failed
            return 0;
        }
        memcpy(buff_ptr->buff + buff_ptr->size, ptr, real_size);
        buff_ptr->size += real_size;
    }
    return real_size;
}

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
) {
    CURL *curl = NULL;
    CURLcode res = CURLE_OK;
    struct curl_slist *headers = NULL;
    data_buff resp_body_buff = {0};
    data_buff resp_headers_buff = {0};
    int i = 0;

    curl = curl_easy_init();
    if (NULL == curl) {
        return CURLE_FAILED_INIT;
    }

    // set params
    curl_easy_setopt(curl, CURLOPT_URL, url);
    if (NULL != unix_sock_path) {
        curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, unix_sock_path);
    }
    curl_easy_setopt(curl, CURLOPT_POST, 0); // get reqest
    //构建HTTP报文头
    if (req_headers_count > 0) {
        for (i = 0; i < req_headers_count; ++i) {
            headers = curl_slist_append(headers, req_headers[i]);
        }
        if (NULL != headers) {
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        }
    }

    // if want to use https
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);

    curl_easy_setopt(curl, CURLOPT_VERBOSE, 0);
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, NULL);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, _get_resp_data);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *) &resp_body_buff);
    if (NULL != resp_headers && NULL != resp_headers_len) {
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, _get_resp_data);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void *) &resp_headers_buff);
    }
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, conn_timeout);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, read_timeout);
    // start request
    res = curl_easy_perform(curl);

    if (headers != NULL) {
        curl_slist_free_all(headers); //free the list again
    }
    // release curl
    curl_easy_cleanup(curl);

    *resp_body = resp_body_buff.buff;
    *resp_body_len = resp_body_buff.size;
    if (NULL != resp_headers && NULL != resp_headers_len) {
        *resp_headers = resp_headers_buff.buff;
        *resp_headers_len = resp_headers_buff.size;
    }
    return res;
}

