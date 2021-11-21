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

CURLcode get(const char *url, const char *unix_sock_path, int conn_timeout, int read_timeout, const char **req_headers,
             unsigned int req_headers_count, unsigned char **resp_body, unsigned int *resp_body_len,
             unsigned char **resp_headers, unsigned int *resp_headers_len) {
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

    res = get(url, NULL, 30, 30, NULL, 0, &resp_body, &resp_body_len, &resp_headers, &resp_headers_len);
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
    dc_free_str_array(obj->mirrors);
    obj->mirrors = NULL;
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
    dc_free_index_config(obj->index_config);
    obj->index_config = NULL;
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
    dc_free_str_array(obj->insecure_registry_cidrs);
    obj->insecure_registry_cidrs = NULL;
    free(obj);
}

void dc_free_peer_node(dc_peer_node *obj) {
    if (NULL == obj) {
        return;
    }
    if (NULL != obj->node_id) {
        free(obj->node_id);
        obj->node_id = NULL;
    }
    if (NULL != obj->addr) {
        free(obj->addr);
        obj->addr = NULL;
    }
    free(obj);
}

void dc_free_swarm_dispatcher_config(dc_swarm_dispatcher_config *obj) {
    if (NULL == obj) {
        return;
    }
    free(obj);
}

void dc_free_swarm_orchestration(dc_swarm_orchestration *obj) {
    if (NULL == obj) {
        return;
    }
    free(obj);
}

void dc_free_key_value(dc_key_value *obj) {
    if (NULL == obj) {
        return;
    }
    if (NULL != obj->key) {
        free(obj->key);
        obj->key = NULL;
    }
    if (NULL != obj->value) {
        free(obj->value);
        obj->value = NULL;
    }
    free(obj);
}

void dc_free_external_ca(dc_external_ca *obj) {
    int i = 0;
    if (NULL == obj) {
        return;
    }
    if (NULL != obj->url) {
        free(obj->url);
        obj->url = NULL;
    }
    if (NULL != obj->options && obj->options_count > 0) {
        for (i = 0; i < obj->options_count; ++i) {
            if (NULL == obj->options[i]) {
                continue;
            }
            dc_free_key_value(obj->options[i]);
            obj->options[i] = NULL;
        }
        free(obj->options);
        obj->options = NULL;
    }
    if (NULL != obj->protocol) {
        free(obj->protocol);
        obj->protocol = NULL;
    }
    free(obj);
}

void dc_free_swarm_ca_config(dc_swarm_ca_config *obj) {
    int i = 0;
    if (NULL == obj) {
        return;
    }
    if (NULL != obj->external_ca_list && obj->external_ca_count > 0) {
        for (i = 0; i < obj->external_ca_count; ++i) {
            if (NULL == obj->external_ca_list[i]) {
                continue;
            }
            dc_free_external_ca(obj->external_ca_list[i]);
            obj->external_ca_list[i] = NULL;
        }
        free(obj->external_ca_list);
        obj->external_ca_list = NULL;
    }
    free(obj);
}

void dc_free_swarm_raft_config(dc_swarm_raft_config *obj) {
    if (NULL == obj) {
        return;
    }
    free(obj);
}

void dc_free_driver(dc_driver *obj) {
    int i = 0;
    if (NULL == obj) {
        return;
    }
    if (NULL != obj->name) {
        free(obj->name);
        obj->name = NULL;
    }
    if (NULL != obj->options && obj->options_count > 0) {
        for (i = 0; i < obj->options_count; ++i) {
            if (NULL == obj->options[i]) {
                continue;
            }
            dc_free_key_value(obj->options[i]);
            obj->options[i] = NULL;
        }
        free(obj->options);
        obj->options = NULL;
    }
    free(obj);
}

void dc_free_task_defaults(dc_task_defaults *obj) {
    if (NULL == obj) {
        return;
    }
    if (NULL != obj->log_driver) {
        dc_free_driver(obj->log_driver);
        obj->log_driver = NULL;
    }
    free(obj);
}

void dc_free_swarm_spec(dc_swarm_spec *obj) {
    if (NULL == obj) {
        return;
    }
    if (NULL != obj->name) {
        free(obj->name);
        obj->name = NULL;
    }
    if (NULL != obj->ca_config) {
        dc_free_swarm_ca_config(obj->ca_config);
        obj->ca_config = NULL;
    }
    if (NULL != obj->dispatcher) {
        dc_free_swarm_dispatcher_config(obj->dispatcher);
        obj->dispatcher = NULL;
    }
    if (NULL != obj->orchestration) {
        dc_free_swarm_orchestration(obj->orchestration);
        obj->orchestration = NULL;
    }
    if (NULL != obj->raft) {
        dc_free_swarm_raft_config(obj->raft);
        obj->raft = NULL;
    }
    if (NULL != obj->task_defaults) {
        dc_free_task_defaults(obj->task_defaults);
        obj->task_defaults = NULL;
    }
    free(obj);
}

void dc_free_resource_version(dc_resource_version *obj) {
    if (NULL == obj) {
        return;
    }
    free(obj);
}

void dc_free_cluster_info(dc_cluster_info *obj) {
    if (NULL == obj) {
        return;
    }
    if (NULL != obj->version) {
        dc_free_resource_version(obj->version);
        obj->version = NULL;
    }
    if (NULL != obj->id) {
        free(obj->id);
        obj->id = NULL;
    }
    if (NULL != obj->created_at) {
        free(obj->created_at);
        obj->created_at = NULL;
    }
    if (NULL != obj->spec) {
        dc_free_swarm_spec(obj->spec);
        obj->spec = NULL;
    }
    if (NULL != obj->update_at) {
        free(obj->update_at);
        obj->update_at = NULL;
    }
    free(obj);
}

void dc_free_swarm_info(dc_swarm_info *obj) {
    int i = 0;
    if (NULL == obj) {
        return;
    }
    if (NULL != obj->node_id) {
        free(obj->node_id);
        obj->node_id = NULL;
    }
    if (NULL != obj->local_node_statel) {
        free(obj->local_node_statel);
        obj->local_node_statel = NULL;
    }
    if (NULL != obj->node_addr) {
        free(obj->node_addr);
        obj->node_addr = NULL;
    }
    if (NULL != obj->cluster_info) {
        dc_free_cluster_info(obj->cluster_info);
        obj->cluster_info = NULL;
    }
    if (NULL != obj->error) {
        free(obj->error);
        obj->error = NULL;
    }
    if (NULL != obj->remote_managers && obj->remote_managers_count > 0) {
        for (i = 0; i < obj->remote_managers_count; ++i) {
            if (NULL == obj->remote_managers[i]) {
                continue;
            }
            dc_free_peer_node(obj->remote_managers[i]);
            obj->remote_managers[i] = NULL;
        }
        free(obj->remote_managers);
        obj->remote_managers = NULL;
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

static DC_BOOL _get_bool_from_json(cJSON *item, const char *key) {
    cJSON *sub = NULL;
    sub = cJSON_GetObjectItem(item, key);
    if (NULL == sub) {
        return DC_FALSE;
    }
    if (!cJSON_IsBool(sub)) {
        return DC_FALSE;
    }
    if (sub->valueint) {
        return DC_TRUE;
    } else {
        return DC_FALSE;
    }
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
    *obj = (dc_str_array *) calloc(1, sizeof(dc_str_array));
    if (NULL == *obj) {
        return;
    }
    (*obj)->array_size = cJSON_GetArraySize(array);
    (*obj)->str_array = (char **) calloc((*obj)->array_size, sizeof(char *));
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

static int _get_json_sub_object_count(cJSON *item, const char *key) {
    int count = 0;
    cJSON *child = NULL;
    if (NULL == item || !cJSON_IsObject(item)) {
        return 0;
    }
    item = cJSON_GetObjectItem(item, key);
    if (NULL == item) {
        return 0;
    }
    child = item->child;
    if (NULL == child) {
        return 0;
    }
    do {
        ++count;
        child = child->next;
    } while (NULL != child);
    return count;
}

static void _parse_json_str_array_for_key_values(cJSON *array, dc_key_values *obj) {
    int i = 0;
    size_t str_len = 0;
    cJSON *str_item = NULL;
    if (NULL == array || !cJSON_IsArray(array)) {
        obj->values = NULL;
        return;
    }
    obj->values_count = cJSON_GetArraySize(array);
    obj->values = (char **) calloc(obj->values_count, sizeof(char *));
    if (NULL == obj->values) {
        return;
    }
    for (i = 0; i < obj->values_count; ++i) {
        str_item = cJSON_GetArrayItem(array, i);
        if (NULL == str_item || !cJSON_IsString(str_item)) {
            continue;
        }
        str_len = strlen(str_item->valuestring);
        obj->values[i] = (char *) calloc(str_len + 1, sizeof(char));
        if (NULL == obj->values[i]) {
            continue;
        }
        memcpy(obj->values[i], str_item->valuestring, str_len);
        obj->values[i][str_len] = '\0';
    }
}

static void _get_key_values_list_from_json(cJSON *item, const char *key, dc_key_values ***list, int list_len) {
    int ret = 0;
    int i = 0;
    cJSON *child = NULL;
    if (NULL == item || NULL == list || !cJSON_IsObject(item)) {
        return;
    }
    item = cJSON_GetObjectItem(item, key);
    if (NULL == item) {
        return;
    }
    *list = (dc_key_values **) calloc(list_len, sizeof(dc_key_values *));
    if (NULL == *list) {
        return;
    }
    child = item->child;
    if (NULL == child) {
        return;
    }
    do {
        (*list)[i] = (dc_key_values *) calloc(1, sizeof(dc_key_values));
        if (NULL == (*list)[i]) {
            goto end;
        }
        _calloc_and_cpy_str(&(*list)[i]->key, child->string);
        _parse_json_str_array_for_key_values(child, (*list)[i]);
        ++i;
        child = child->next;
    } while (child != NULL && i < list_len);

    ret = 1;

    end:
    if (!ret) {
        if (NULL != *list) {
            for (i = 0; i < list_len; ++i) {
                dc_free_key_values((*list)[i]);
            }
        }
    }
}

static void _get_key_index_configs_from_json(cJSON *item, const char *key, dc_key_index_config **list, int list_len) {
    int ret = 0;
    int i = 0;
    cJSON *child = NULL;
    if (NULL == item || NULL == list || !cJSON_IsObject(item)) {
        return;
    }
    item = cJSON_GetObjectItem(item, key);
    if (NULL == item) {
        return;
    }
    child = item->child;
    if (NULL == child) {
        return;
    }
    do {
        list[i] = (dc_key_index_config *) calloc(1, sizeof(dc_key_index_config));
        if (NULL == list[i]) {
            goto end;
        }
        _calloc_and_cpy_str(&list[i]->key, child->string);
        list[i]->index_config = (dc_index_config *) calloc(1, sizeof(dc_index_config));
        if (NULL == list[i]->index_config) {
            goto end;
        }
        _calloc_and_cpy_str_from_json(&list[i]->index_config->name, child, "Name");
        list[i]->index_config->official = _get_bool_from_json(child, "Official");
        list[i]->index_config->secure = _get_bool_from_json(child, "Secure");
        _parse_json_str_array(cJSON_GetObjectItem(child, "Mirrors"), &list[i]->index_config->mirrors);
        ++i;
        child = child->next;
    } while (child != NULL && i < list_len);

    ret = 1;

    end:
    if (!ret) {
        for (i = 0; i < list_len; ++i) {
            dc_free_key_index_config(list[i]);
        }
    }
}

static void _parse_registry_config(cJSON *item, const char *key, dc_registry_config **registry_config) {
    int ret = 0;
    int i = 0;
    cJSON *sub = NULL;
    if (NULL == item || NULL == registry_config) {
        return;
    }
    sub = cJSON_GetObjectItem(item, key);
    if (NULL == sub) {
        return;
    }

    *registry_config = (dc_registry_config *) calloc(1, sizeof(dc_registry_config));
    if (NULL == *registry_config) {
        return;
    }
    (*registry_config)->index_configs_count = _get_json_sub_object_count(item, key);
    (*registry_config)->index_configs = (dc_key_index_config **) calloc((*registry_config)->index_configs_count,
                                                                        sizeof(dc_key_index_config *));
    if (NULL == (*registry_config)->index_configs) {
        goto end;
    }
    _get_key_index_configs_from_json(sub, "IndexConfigs", (*registry_config)->index_configs,
                                     (*registry_config)->index_configs_count);
    _parse_json_str_array(cJSON_GetObjectItem(sub, "InsecureRegistryCIDRs"),
                          &(*registry_config)->insecure_registry_cidrs);

    ret = 1;

    end:
    if (!ret) {
        dc_free_registry_config(*registry_config);
    }
}

static void _parse_peer_node_list(cJSON *array, dc_peer_node ***list, int list_len) {
    int ret = 0;
    int i = 0;
    dc_peer_node **tmp_list = NULL;
    cJSON *arr_item = NULL;
    if (NULL == array || !cJSON_IsArray(array) || NULL == list || list_len <= 0) {
        return;
    }

    *list = (dc_peer_node **) calloc(list_len, sizeof(dc_peer_node *));
    tmp_list = *list;
    if (NULL == tmp_list) {
        goto end;
    }
    for (i = 0; i < list_len; ++i) {
        tmp_list[i] = (dc_peer_node *) calloc(1, sizeof(dc_peer_node));
        if (NULL == tmp_list[i]) {
            goto end;
        }
        arr_item = cJSON_GetArrayItem(array, i);
        _calloc_and_cpy_str_from_json(&tmp_list[i]->node_id, arr_item, "NodeID");
        _calloc_and_cpy_str_from_json(&tmp_list[i]->node_id, arr_item, "Addr");
    }

    ret = 1;

    end:
    if (!ret) {
        if (NULL != tmp_list) {
            for (i = 0; i < list_len; ++i) {
                if (NULL != tmp_list[i]) {
                    dc_free_peer_node(tmp_list[i]);
                    tmp_list[i] = NULL;
                }
            }
            free(*list);
            *list = NULL;
        }
    }
}

static void _parse_json_obj_for_key_value_list(cJSON *item, const char *key, dc_key_value ***list, int *list_len) {
    int ret = 0;
    int i = 0;
    cJSON *sub = NULL;
    cJSON *child = NULL;
    dc_key_value **tmp_list = NULL;
    if (NULL == item || NULL == list || NULL == list_len) {
        return;
    }
    sub = cJSON_GetObjectItem(item, key);
    if (NULL == sub || !cJSON_IsObject(sub)) {
        return;
    }

    child = sub->child;
    if (NULL == child) {
        return;
    }
    *list_len = 0;
    do {
        ++(*list_len);
        child = child->next;
    } while (NULL != child);

    if ((*list_len) > 0) {
        *list = (dc_key_value **) calloc(*list_len, sizeof(dc_key_value *));
        tmp_list = *list;
        if (NULL == tmp_list) {
            goto end;
        }

        child = sub->child;
        do {
            tmp_list[i] = (dc_key_value *) calloc(1, sizeof(dc_key_value));
            if (NULL == tmp_list[i]) {
                goto end;
            }
            if (cJSON_IsString(child)) {
                _calloc_and_cpy_str(&tmp_list[i]->key, child->string);
                _calloc_and_cpy_str(&tmp_list[i]->value, child->valuestring);
            }
            child = child->next;
        } while (NULL != child);
    }

    ret = 1;

    end:
    if (!ret) {
        if (NULL != *list) {
            for (i = 0; i < *list_len; ++i) {
                if (NULL == tmp_list[i]) {
                    dc_free_key_value(tmp_list[i]);
                    tmp_list[i] = NULL;
                }
            }
            free(*list);
            *list = NULL;
        }
    }
}

static void _parse_task_defaults(cJSON *item, const char *key, dc_task_defaults **task_defaults) {
    int ret = 0;
    cJSON *sub = NULL;
    cJSON *log_driver = NULL;
    cJSON *tmp = NULL;
    if (NULL == item || NULL == task_defaults) {
        return;
    }
    sub = cJSON_GetObjectItem(item, key);
    if (NULL == sub || !cJSON_IsObject(sub)) {
        return;
    }

    *task_defaults = (dc_task_defaults *) calloc(1, sizeof(dc_task_defaults));
    if (NULL != *task_defaults) {
        return;
    }

    log_driver = cJSON_GetObjectItem(sub, "LogDriver");
    if (NULL != log_driver) {
        (*task_defaults)->log_driver = (dc_driver *) calloc(1, sizeof(dc_driver));
        if (NULL == (*task_defaults)->log_driver) {
            goto end;
        }
        _calloc_and_cpy_str_from_json(&(*task_defaults)->log_driver->name, log_driver, "Name");
        _parse_json_obj_for_key_value_list(log_driver, "Options", &(*task_defaults)->log_driver->options,
                                           &(*task_defaults)->log_driver->options_count);
    }

    ret = 1;

    end:
    if (!ret) {
        if (NULL != *task_defaults) {
            dc_free_task_defaults(*task_defaults);
            *task_defaults = NULL;
        }
    }
}

static void _parse_swarm_ca_config(cJSON *item, const char *key, dc_swarm_ca_config **ca_config) {
    int ret = 0;
    int i = 0;
    cJSON *sub = NULL;
    cJSON *ca_arr = NULL;
    cJSON *tmp = NULL;
    if (NULL == item || NULL == ca_config) {
        return;
    }
    sub = cJSON_GetObjectItem(item, key);
    if (NULL == sub || !cJSON_IsObject(sub)) {
        return;
    }

    *ca_config = (dc_swarm_ca_config *) calloc(1, sizeof(dc_swarm_ca_config));
    if (NULL != *ca_config) {
        return;
    }

    (*ca_config)->node_cert_expiry = _get_int_from_json(sub, "NodeCertExpiry");
    ca_arr = cJSON_GetObjectItem(sub, "ExternalCAs");
    if (NULL != ca_arr) {
        (*ca_config)->external_ca_count = cJSON_GetArraySize(ca_arr);
        if ((*ca_config)->external_ca_count > 0) {
            (*ca_config)->external_ca_list = (dc_external_ca **) calloc((*ca_config)->external_ca_count, sizeof(dc_external_ca *));
            if (NULL == (*ca_config)->external_ca_list) {
                goto end;
            }
            for (i = 0; i < (*ca_config)->external_ca_count; ++i) {
                tmp = cJSON_GetArrayItem(sub, i);
                if (NULL == tmp) {
                    continue;
                }
                (*ca_config)->external_ca_list[i] = (dc_external_ca *) calloc(1, sizeof(dc_external_ca));
                _calloc_and_cpy_str_from_json(&(*ca_config)->external_ca_list[i]->protocol, tmp, "Protocol");
                _calloc_and_cpy_str_from_json(&(*ca_config)->external_ca_list[i]->url, tmp, "URL");
                _parse_json_obj_for_key_value_list(tmp, "Options", &(*ca_config)->external_ca_list[i]->options, &(*ca_config)->external_ca_list[i]->options_count);
            }
        }
    }

    end:
    if (!ret) {
        if (NULL != *ca_config) {
            dc_free_swarm_ca_config(*ca_config);
            *ca_config = NULL;
        }
    }
}


static void _parse_swarm_spec(cJSON *item, const char *key, dc_swarm_spec **swarm_spec) {
    int ret = 0;
    cJSON *sub = NULL;
    cJSON *tmp = NULL;
    if (NULL == item || NULL == swarm_spec) {
        return;
    }
    sub = cJSON_GetObjectItem(item, key);
    if (NULL == sub || !cJSON_IsObject(sub)) {
        return;
    }

    *swarm_spec = (dc_swarm_spec *) calloc(1, sizeof(dc_swarm_spec));
    if (NULL == *swarm_spec) {
        return;
    }

    _calloc_and_cpy_str_from_json(&(*swarm_spec)->name, sub, "Name");
    tmp = cJSON_GetObjectItem(sub, "Dispatcher");
    if (NULL != tmp) {
        (*swarm_spec)->dispatcher = (dc_swarm_dispatcher_config *) calloc(1, sizeof(dc_swarm_dispatcher_config));
        if (NULL == (*swarm_spec)->dispatcher) {
            goto end;
        }
        (*swarm_spec)->dispatcher->heartbeat_period = _get_int_from_json(tmp, "HeartbeatPeriod");
    }
    tmp = cJSON_GetObjectItem(sub, "Orchestration");
    if (NULL != tmp) {
        (*swarm_spec)->orchestration = (dc_swarm_orchestration *) calloc(1, sizeof(dc_swarm_orchestration));
        if (NULL == (*swarm_spec)->orchestration) {
            goto end;
        }
        (*swarm_spec)->orchestration->task_history_rentention_limit = _get_int_from_json(tmp,
                                                                                         "TaskHistoryRetentionLimit");
    }
    tmp = cJSON_GetObjectItem(sub, "Raft");
    if (NULL != tmp) {
        (*swarm_spec)->raft = (dc_swarm_raft_config *) calloc(1, sizeof(dc_swarm_raft_config));
        if (NULL == (*swarm_spec)->raft) {
            goto end;
        }
        (*swarm_spec)->raft->log_entries_for_slow_followers = _get_int_from_json(tmp, "LogEntriesForSlowFollowers");
        (*swarm_spec)->raft->heartbeat_tick = _get_int_from_json(tmp, "HeartbeatTick");
        (*swarm_spec)->raft->snapshot_interval = _get_int_from_json(tmp, "SnapshotInterval");
        (*swarm_spec)->raft->election_tick = _get_int_from_json(tmp, "ElectionTick");
    }
    _parse_task_defaults(sub, "TaskDefaults", &(*swarm_spec)->task_defaults);
    _parse_swarm_ca_config(sub, "CAConfig", &(*swarm_spec)->ca_config);

    ret = 1;

    end:
    if (!ret) {
        if (NULL != *swarm_spec) {
            dc_free_swarm_spec(*swarm_spec);
            *swarm_spec = NULL;
        }
    }
}

static void _parse_cluster_info(cJSON *item, const char *key, dc_cluster_info **cluster_info) {
    int ret = 0;
    cJSON *sub = NULL;
    cJSON *tmp = NULL;
    if (NULL == item || NULL == cluster_info) {
        return;
    }
    sub = cJSON_GetObjectItem(item, key);
    if (NULL == sub) {
        return;
    }

    *cluster_info = (dc_cluster_info *) calloc(1, sizeof(cluster_info));
    if (NULL == *cluster_info) {
        return;
    }

    _calloc_and_cpy_str_from_json(&(*cluster_info)->created_at, sub, "CreatedAt");
    _calloc_and_cpy_str_from_json(&(*cluster_info)->update_at, sub, "UpdatedAt");
    _calloc_and_cpy_str_from_json(&(*cluster_info)->id, sub, "ID");
    tmp = cJSON_GetObjectItem(sub, "Version");
    if (NULL != tmp) {
        (*cluster_info)->version = (dc_resource_version *) calloc(1, sizeof(dc_resource_version));
        if (NULL == (*cluster_info)->version) {
            goto end;
        }
        (*cluster_info)->version->index = _get_int_from_json(tmp, "Index");
    }
    _parse_swarm_spec(sub, "Spec", &(*cluster_info)->spec);

    ret = 1;

    end:
    if (!ret) {
        if (NULL != *cluster_info) {
            dc_free_cluster_info(*cluster_info);
            *cluster_info = NULL;
        }
    }
}

static void _parse_swarm_info(cJSON *item, const char *key, dc_swarm_info **swarm_info) {
    int ret = 0;
    int i = 0;
    cJSON *sub = NULL;
    cJSON *array = NULL;
    cJSON *arr_item = NULL;
    if (NULL == item || NULL == swarm_info) {
        return;
    }
    sub = cJSON_GetObjectItem(item, key);
    if (NULL == sub) {
        return;
    }

    *swarm_info = (dc_swarm_info *) calloc(1, sizeof(swarm_info));
    if (NULL == *swarm_info) {
        return;
    }

    _calloc_and_cpy_str_from_json(&(*swarm_info)->node_id, sub, "NodeID");
    _calloc_and_cpy_str_from_json(&(*swarm_info)->node_addr, sub, "NodeAddr");
    _calloc_and_cpy_str_from_json(&(*swarm_info)->local_node_statel, sub, "LocalNodeState");
    _calloc_and_cpy_str_from_json(&(*swarm_info)->error, sub, "Error");
    (*swarm_info)->nodes = _get_int_from_json(sub, "Nodes");
    (*swarm_info)->managers = _get_int_from_json(sub, "Managers");
    array = cJSON_GetObjectItem(sub, "RemoteManagers");
    if (NULL != array) {
        (*swarm_info)->remote_managers_count = cJSON_GetArraySize(array);
        _parse_peer_node_list(array, &(*swarm_info)->remote_managers, (*swarm_info)->remote_managers_count);
    }
    _parse_cluster_info(sub, "ClusterInfo", &(*swarm_info)->cluster_info);

    ret = 1;

    end:
    if (!ret) {
        if (NULL != *swarm_info) {
            dc_free_swarm_info(*swarm_info);
            *swarm_info = NULL;
        }
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
    info->cpu_cfs_period = _get_bool_from_json(root, "CpuCfsPeriod");
    info->cpu_cfs_quota = _get_bool_from_json(root, "CpuCfsQuota");
    info->cpu_shares = _get_bool_from_json(root, "CPUShares");
    info->cpu_set = _get_bool_from_json(root, "CPUSet");
    info->debug = _get_bool_from_json(root, "Debug");
    _calloc_and_cpy_str_from_json(&info->discovery_backend, root, "DiscoveryBackend");
    _calloc_and_cpy_str_from_json(&info->docker_root_dir, root, "DockerRootDir");
    _calloc_and_cpy_str_from_json(&info->driver, root, "Driver");
    info->driver_statuses_count = _get_json_array_size(root, "DriverStatus");
    if (info->driver_statuses_count > 0) {
        array = cJSON_GetObjectItem(root, "DriverStatus");
        info->driver_statuses = (dc_str_array **) calloc(info->driver_statuses_count, sizeof(dc_str_array *));
        for (i = 0; i < info->driver_statuses_count; ++i) {
            tmp = cJSON_GetArrayItem(array, i);
            if (NULL == tmp || !cJSON_IsArray(tmp)) {
                continue;
            }
            _parse_json_str_array(tmp, &(info->driver_statuses[i]));
        }
    }
    info->plugins_count = _get_json_sub_object_count(root, "Plugins");
    _get_key_values_list_from_json(root, "Plugins", &info->plugins, info->plugins_count);
    _calloc_and_cpy_str_from_json(&info->execution_driver, root, "ExecutionDriver");
    _calloc_and_cpy_str_from_json(&info->logging_driver, root, "LoggingDriver");
    info->experimental_build = _get_bool_from_json(root, "ExperimentalBuild");
    _calloc_and_cpy_str_from_json(&info->http_proxy, root, "HttpProxy");
    _calloc_and_cpy_str_from_json(&info->https_proxy, root, "HttpsProxy");
    _calloc_and_cpy_str_from_json(&info->id, root, "ID");
    info->ipv4_forwarding = _get_bool_from_json(root, "IPv4Forwarding");
    info->bridge_nf_iptables - _get_bool_from_json(root, "BridgeNfIptables");
    info->bridge_nf_ip6tables = _get_bool_from_json(root, "BridgeNfIp6tables");
    info->images = _get_int_from_json(root, "Images");
    _calloc_and_cpy_str_from_json(&info->index_server_address, root, "IndexServerAddress");
    _calloc_and_cpy_str_from_json(&info->init_path, root, "InitPath");
    _calloc_and_cpy_str_from_json(&info->init_sha1, root, "InitSha1");
    _calloc_and_cpy_str_from_json(&info->kernel_version, root, "KernelVersion");
    _parse_json_str_array(cJSON_GetObjectItem(root, "Labels"), &info->labels);
    info->memory_limit = _get_bool_from_json(root, "MemoryLimit");
    info->mem_total = _get_int_from_json(root, "MemTotal");
    _calloc_and_cpy_str_from_json(&info->name, root, "Name");
    info->n_cpu = _get_int_from_json(root, "NCPU");
    info->n_events_listener = _get_int_from_json(root, "NEventsListener");
    info->n_fd = _get_int_from_json(root, "NFd");
    info->n_goroutines = _get_int_from_json(root, "NGoroutines");
    _calloc_and_cpy_str_from_json(&info->no_proxy, root, "NoProxy");
    info->oom_kill_disable = _get_bool_from_json(root, "OomKillDisable");
    _calloc_and_cpy_str_from_json(&info->os_type, root, "OSType");
    info->oom_score_adj = _get_int_from_json(root, "OomScoreAdj");
    _calloc_and_cpy_str_from_json(&info->operating_system, root, "OperatingSystem");
    _parse_registry_config(root, "RegistryConfig", &info->registry_config);
    _parse_json_str_array(cJSON_GetObjectItem(root, "Sockets"), &info->sockets);
    info->swap_limit = _get_bool_from_json(root, "SwapLimit");
    _calloc_and_cpy_str_from_json(&info->system_time, root, "SystemTime");
    _calloc_and_cpy_str_from_json(&info->server_version, root, "ServerVersion");
    _calloc_and_cpy_str_from_json(&info->cluster_store, root, "ClusterStore");
    _calloc_and_cpy_str_from_json(&info->cluster_advertise, root, "ClusterAdvertise");
    _parse_swarm_info(root, "Swarm", &info->swarm);
    _calloc_and_cpy_str_from_json(&info->isolation, root, "Isolation");
    _parse_json_str_array(cJSON_GetObjectItem(root, "SecurityOptions"), &info->security_options);

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
