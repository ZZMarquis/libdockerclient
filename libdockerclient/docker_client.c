#include "docker_client.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "curl/curl.h"

#include "cJSON.h"
#include "http_utils.h"

typedef struct _data_buff {
    unsigned int size;
    void *buff;
} data_buff;

// https://www.cnblogs.com/heluan/p/10177475.html
static size_t _get_resp_data(void *ptr, size_t size, size_t nmemb, void *stream) {
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

static void _calloc_and_cpy_str(char **dst, char *src) {
    int src_len = 0;
    if (NULL == src) {
        return;
    }
    src_len = strlen(src);
    *dst = (char *) calloc(src_len + 1, sizeof(char));
    if (NULL == *dst) {
        return;
    }
    memcpy(*dst, src, src_len);
    (*dst)[src_len] = '\0';
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

    *resp_body_len = resp_body_buff.size;
    if (NULL != resp_body_buff.buff && resp_body_buff.size > 0) {
        *resp_body = (unsigned char *) calloc(resp_body_buff.size + 1, sizeof(unsigned char));
        memcpy(*resp_body, resp_body_buff.buff, resp_body_buff.size);
        (*resp_body)[resp_body_buff.size] = '\0';
    } else {
        *resp_body = NULL;
    }
    if (NULL != resp_headers && NULL != resp_headers_len) {
        *resp_headers_len = resp_headers_buff.size;
        if (NULL != resp_headers_buff.buff && resp_headers_buff.size > 0) {
            *resp_headers = (unsigned char *) calloc(resp_headers_buff.size + 1, sizeof(unsigned char));
            memcpy(*resp_headers, resp_headers_buff.buff, resp_headers_buff.size);
            (*resp_headers)[resp_headers_buff.size] = '\0';
        } else {
            *resp_headers = NULL;
        }
    }

    if (NULL != resp_body_buff.buff) {
        free(resp_body_buff.buff);
        resp_body_buff.buff = NULL;
    }
    if (NULL != resp_headers_buff.buff) {
        free(resp_headers_buff.buff);
        resp_headers_buff.buff = NULL;
    }
    return res;
}

dc_ping_result *dc_ping(char *url) {
    int ret = 0;
    CURLcode res;
    unsigned char *resp_body;
    unsigned int resp_body_len;
    unsigned char *resp_headers;
    unsigned int resp_headers_len;
    dc_http_headers *headers = NULL;
    dc_ping_result *result = NULL;

    res = get(url, NULL, 30, 30, NULL, 0, &resp_body, &resp_body_len, &resp_headers,
              &resp_headers_len);
    if (CURLE_OK != res) {
        return NULL;
    }

//    _ping接口返回示例：
//    HTTP/1.1 200 OK
//    Api-Version: 1.41
//    Cache-Control: no-cache, no-store, must-revalidate
//    Docker-Experimental: false
//    Ostype: linux
//    Pragma: no-cache
//    Server: Docker/20.10.8 (linux)
//    Date: Sat, 06 Nov 2021 19:10:08 GMT
//    Content-Length: 2
//    Content-Type: text/plain; charset=utf-8
    headers = dc_parse_http_headers((const char *) resp_headers);
    if (NULL == headers) {
        goto end;
    }
    result = (dc_ping_result *) calloc(1, sizeof(dc_ping_result));
    if (NULL == result) {
        goto end;
    }
    _calloc_and_cpy_str(&result->api_version, dc_get_http_header(headers, "Api-Version"));
    _calloc_and_cpy_str(&result->docker_experimental, dc_get_http_header(headers, "Docker-Experimental"));
    _calloc_and_cpy_str(&result->os_type, dc_get_http_header(headers, "Ostype"));
    _calloc_and_cpy_str(&result->server, dc_get_http_header(headers, "Server"));

    ret = 1;

    end:
    if (!ret) {
        free_ping_result(result);
        result = NULL;
    }
    if (NULL != resp_body) {
        free(resp_body);
    }
    if (NULL != resp_headers) {
        free(resp_headers);
    }
    if (NULL != headers) {
        dc_free_http_headers(headers);
    }
    return result;
}

void free_ping_result(dc_ping_result *result) {
    if (NULL != result) {
        if (NULL != result->api_version) {
            free(result->api_version);
            result->api_version = NULL;
        }
        if (NULL != result->docker_experimental) {
            free(result->docker_experimental);
            result->docker_experimental = NULL;
        }
        if (NULL != result->os_type) {
            free(result->os_type);
            result->os_type = NULL;
        }
        if (NULL != result->server) {
            free(result->server);
            result->server = NULL;
        }
        free(result);
    }
}

void dc_free_str_array(dc_str_array *obj) {
    int i = 0;
    if (NULL == obj) {
        return;
    }
    if (NULL != obj->str_array && obj->array_size > 0) {
        for (i = 0; i < obj->array_size; ++i) {
            if (NULL == obj->str_array[i]) {
                continue;
            }
            free(obj->str_array[i]);
            obj->str_array[i] = NULL;
        }
        free(obj->str_array);
        obj->str_array = NULL;
    }
    free(obj);
}

void dc_free_key_values(dc_key_values *obj) {
    int i = 0;
    if (NULL == obj) {
        return;
    }
    if (NULL != obj->key) {
        free(obj->key);
        obj->key = NULL;
    }
    if (NULL != obj->values && obj->values_count > 0) {
        for (i = 0; i < obj->values_count; ++i) {
            if (NULL == obj->values[i]) {
                continue;
            }
            free(obj->values[i]);
            obj->values[i] = NULL;
        }
        free(obj->values);
        obj->values = NULL;
    }
    free(obj);
}

void dc_free_index_config(dc_index_config *obj) {
    int i = 0;
    if (NULL == obj) {
        return;
    }
    if (NULL != obj->mirrors && obj->mirrors_count > 0) {
        for (i = 0; i < obj->mirrors_count; ++i) {
            if (NULL == obj->mirrors[i]) {
                continue;
            }
            free(obj->mirrors[i]);
            obj->mirrors[i] = NULL;
        }
        free(obj->mirrors);
        obj->mirrors = NULL;
    }
    if (NULL != obj->name) {
        free(obj->name);
        obj->name = NULL;
    }
    free(obj);
}

void dc_free_key_index_config(dc_key_index_config *obj) {
    int i = 0;
    if (NULL == obj) {
        return;
    }
    if (NULL != obj->key) {
        free(obj->key);
        obj->key = NULL;
    }
    if (NULL != obj->index_configs && obj->index_configs_count > 0) {
        for (i = 0; i < obj->index_configs_count; ++i) {
            if (NULL == obj->index_configs[i]) {
                continue;
            }
            dc_free_index_config(obj->index_configs[i]);
            obj->index_configs[i] = NULL;
        }
        free(obj->index_configs);
        obj->index_configs = NULL;
    }
    free(obj);
}

void dc_free_registry_config(dc_registry_config *obj) {
    int i = 0;
    if (NULL == obj) {
        return;
    }
    if (NULL != obj->index_configs && obj->index_configs_count > 0) {
        for (i = 0; i < obj->index_configs_count; ++i) {
            if (NULL == obj->index_configs[i]) {
                continue;
            }
            free(obj->index_configs[i]);
            obj->index_configs[i] = NULL;
        }
        free(obj->index_configs);
        obj->index_configs = NULL;
    }
    if (NULL != obj->insecure_registry_cidrs && obj->insecure_registry_cidrs_count > 0) {
        for (i = 0; i < obj->insecure_registry_cidrs_count; ++i) {
            if (NULL == obj->insecure_registry_cidrs[i]) {
                continue;
            }
            free(obj->insecure_registry_cidrs[i]);
            obj->insecure_registry_cidrs[i] = NULL;
        }
        free(obj->insecure_registry_cidrs);
        obj->insecure_registry_cidrs = NULL;
    }
    free(obj);
}

static void _calloc_and_cpy_str_from_json(char **dst, cJSON *item, const char *key) {
    cJSON *sub = NULL;
    sub = cJSON_GetObjectItem(item, key);
    if (NULL == sub) {
        return;
    }
    if (!cJSON_IsString(sub)) {
        return;
    }
    _calloc_and_cpy_str(dst, cJSON_GetStringValue(sub));
}

static int _get_int_from_json(cJSON *item, const char *key) {
    cJSON *sub = NULL;
    sub = cJSON_GetObjectItem(item, key);
    if (NULL == sub) {
        return 0;
    }
    if (!cJSON_IsNumber(sub)) {
        return 0;
    }
    return sub->valueint;
}

static int _get_json_array_size(cJSON *item, const char *key) {
    cJSON *sub = NULL;
    sub = cJSON_GetObjectItem(item, key);
    if (NULL == sub) {
        return 0;
    }
    if (!cJSON_IsArray(sub)) {
        return 0;
    }
    return cJSON_GetArraySize(sub);
}

static void _parse_json_str_array(cJSON *array, dc_str_array **obj) {
    int ret = 0;
    int i = 0;
    size_t str_len = 0;
    cJSON *str_item = NULL;
    if (NULL == array || !cJSON_IsArray(array)) {
        *obj = NULL;
        return;
    }
    *obj = (dc_str_array *)calloc(1, sizeof(dc_str_array));
    if (NULL == *obj) {
        return;
    }
    (*obj)->array_size = cJSON_GetArraySize(array);
    (*obj)->str_array = (char **)calloc((*obj)->array_size, sizeof(char *));
    if (NULL == (*obj)->str_array) {
        goto end;
    }
    for (i = 0; i < (*obj)->array_size; ++i) {
        str_item = cJSON_GetArrayItem(array, i);
        if (NULL == str_item || !cJSON_IsString(str_item)) {
            continue;
        }
        str_len = strlen(str_item->valuestring);
        (*obj)->str_array[i] = (char *) calloc(str_len + 1, sizeof(char));
        if (NULL == (*obj)->str_array[i]) {
            continue;
        }
        memcpy((*obj)->str_array[i], str_item->valuestring, str_len);
        (*obj)->str_array[i][str_len] = '\0';
    }

    ret = 1;

    end:
    if (!ret) {
        dc_free_str_array(*obj);
        *obj = NULL;
    }
}

dc_info *dc_get_info(char *url) {
    int ret = 0;
    int i = 0;
    CURLcode res;
    unsigned char *resp_body;
    unsigned int resp_body_len;
    dc_info *info = NULL;
    cJSON *root = NULL;
    cJSON *tmp = NULL;
    cJSON *array = NULL;

    res = get(url, NULL, 30, 30, NULL, 0, &resp_body, &resp_body_len, NULL, NULL);
    if (CURLE_OK != res) {
        return NULL;
    }
    if (NULL == resp_body || 0 >= resp_body_len) {
        return NULL;
    }

    root = cJSON_Parse((char *) resp_body);
    if (NULL == root) {
        goto end;
    }

    info = (dc_info *) calloc(1, sizeof(dc_info));
    if (NULL == info) {
        goto end;
    }

    _calloc_and_cpy_str_from_json(&info->id, root, "ID");
    info->containers = _get_int_from_json(root, "Containers");
    info->containers_running = _get_int_from_json(root, "ContainersRunning");
    info->containers_paused = _get_int_from_json(root, "ContainersPaused");
    info->containers_stopped = _get_int_from_json(root, "ContainersStopped");
    info->images = _get_int_from_json(root, "Images");
    _calloc_and_cpy_str_from_json(&info->driver, root, "Driver");
    info->driver_statuses_count = _get_json_array_size(root, "DriverStatus");
    if (info->driver_statuses_count > 0) {
        array = cJSON_GetObjectItem(root, "DriverStatus");
        info->driver_statuses = (dc_str_array **) calloc(info->driver_statuses_count, sizeof(dc_str_array *));
        for (i = 0;  i< info->driver_statuses_count; ++i) {
            tmp = cJSON_GetArrayItem(array, i);
            if (NULL == tmp || !cJSON_IsArray(tmp)) {
                continue;
            }
            _parse_json_str_array(tmp, &(info->driver_statuses[i]));
        }
    }


    ret = 1;

    end:
    if (!ret) {
        // TODO free dc_info
        info = NULL;
    }
    if (NULL != resp_body) {
        free(resp_body);
    }
    if (NULL != root) {
        cJSON_free(root);
    }
    return info;
}