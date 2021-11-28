#ifndef LIBDOCKERCLIENT_DOCKER_CLIENT_H
#define LIBDOCKERCLIENT_DOCKER_CLIENT_H

#pragma pack(4)

#include "curl/curl.h"
#include "dc_defines.h"

CURLcode get(const char *url, const char *unix_sock_path, int conn_timeout, int read_timeout, const char **req_headers,
             unsigned int req_headers_count, unsigned char **resp_body, unsigned int *resp_body_len,
             unsigned char **resp_headers, unsigned int *resp_headers_len);

typedef struct _dc_ping_result {
    char *api_version;
    char *docker_experimental;
    char *os_type;
    char *server;
} dc_ping_result;

dc_ping_result *dc_ping(char *url);

void free_ping_result(dc_ping_result *result);

// TODO /info API return response body
//{"ID":"COG4:SUFM:BLOS:AXVV:AZ27:63ON:WORM:O25X:DB53:D262:T25W:CBKL","Containers":0,"ContainersRunning":0,"ContainersPaused":0,"ContainersStopped":0,"Images":1,"Driver":"overlay2","DriverStatus":[["Backing Filesystem","extfs"],["Supports d_type","true"],["Native Overlay Diff","true"],["userxattr","false"]],"Plugins":{"Volume":["local"],"Network":["bridge","host","ipvlan","macvlan","null","overlay"],"Authorization":null,"Log":["awslogs","fluentd","gcplogs","gelf","journald","json-file","local","logentries","splunk","syslog"]},"MemoryLimit":true,"SwapLimit":true,"KernelMemory":true,"KernelMemoryTCP":true,"CpuCfsPeriod":true,"CpuCfsQuota":true,"CPUShares":true,"CPUSet":true,"PidsLimit":true,"IPv4Forwarding":true,"BridgeNfIptables":true,"BridgeNfIp6tables":true,"Debug":false,"NFd":26,"OomKillDisable":true,"NGoroutines":35,"SystemTime":"2021-11-07T03:22:14.269472931+08:00","LoggingDriver":"json-file","CgroupDriver":"cgroupfs","CgroupVersion":"1","NEventsListener":0,"KernelVersion":"5.11.0-38-generic","OperatingSystem":"Ubuntu 21.04","OSVersion":"21.04","OSType":"linux","Architecture":"x86_64","IndexServerAddress":"https://index.docker.io/v1/","RegistryConfig":{"AllowNondistributableArtifactsCIDRs":[],"AllowNondistributableArtifactsHostnames":[],"InsecureRegistryCIDRs":["127.0.0.0/8"],"IndexConfigs":{"docker.io":{"Name":"docker.io","Mirrors":[],"Secure":true,"Official":true}},"Mirrors":[]},"NCPU":4,"MemTotal":10406965248,"GenericResources":null,"DockerRootDir":"/var/lib/docker","HttpProxy":"","HttpsProxy":"","NoProxy":"","Name":"zljpc","Labels":[],"ExperimentalBuild":false,"ServerVersion":"20.10.8","Runtimes":{"io.containerd.runc.v2":{"path":"runc"},"io.containerd.runtime.v1.linux":{"path":"runc"},"runc":{"path":"runc"}},"DefaultRuntime":"runc","Swarm":{"NodeID":"","NodeAddr":"","LocalNodeState":"inactive","ControlAvailable":false,"Error":"","RemoteManagers":null},"LiveRestoreEnabled":false,"Isolation":"","InitBinary":"docker-init","ContainerdCommit":{"ID":"e25210fe30a0a703442421b0f60afac609f950a3","Expected":"e25210fe30a0a703442421b0f60afac609f950a3"},"RuncCommit":{"ID":"v1.0.1-0-g4144b63","Expected":"v1.0.1-0-g4144b63"},"InitCommit":{"ID":"de40ad0","Expected":"de40ad0"},"SecurityOptions":["name=apparmor","name=seccomp,profile=default"],"Warnings":["WARNING: API is accessible on http://0.0.0.0:2375 without encryption.\n         Access to the remote API is equivalent to root access on the host. Refer\n         to the 'Docker daemon attack surface' section in the documentation for\n         more information: https://docs.docker.com/go/attack-surface/"]}

typedef struct _dc_str_array {
    char **str_array;
    int array_size;
} dc_str_array;

void dc_free_str_array(dc_str_array *obj);

typedef struct _dc_key_values {
    char *key;
    char **values;
    int values_count;
} dc_key_values;

void dc_free_key_values(dc_key_values *obj);

typedef struct _dc_index_config {
    dc_str_array *mirrors;
    char *name;
    DC_BOOL official;
    DC_BOOL secure;
} dc_index_config;

void dc_free_index_config(dc_index_config *obj);

typedef struct _dc_key_index_config {
    char *key;
    dc_index_config *index_config;
} dc_key_index_config;

void dc_free_key_index_config(dc_key_index_config *obj);

typedef struct _dc_registry_config {
    dc_key_index_config **index_configs;
    int index_configs_count;
    dc_str_array *insecure_registry_cidrs;
} dc_registry_config;

void dc_free_registry_config(dc_registry_config *obj);

typedef struct _dc_peer_node {
    char *node_id;
    char *addr;
} dc_peer_node;

void dc_free_peer_node(dc_peer_node *obj);

typedef struct _dc_swarm_dispatcher_config {
    int64_t heartbeat_period;
} dc_swarm_dispatcher_config;

void dc_free_swarm_dispatcher_config(dc_swarm_dispatcher_config *obj);

typedef struct _dc_swarm_orchestration {
    int task_history_rentention_limit;
} dc_swarm_orchestration;

void dc_free_swarm_orchestration(dc_swarm_orchestration *obj);

typedef struct _dc_key_value {
    char *key;
    char *value;
} dc_key_value;

void dc_free_key_value(dc_key_value *obj);

typedef struct _dc_external_ca {
    char *protocol;
    char *url;
    dc_key_value **options;
    int options_count;
} dc_external_ca;

void dc_free_external_ca(dc_external_ca *obj);

typedef struct _dc_swarm_ca_config {
    int64_t node_cert_expiry;
    dc_external_ca **external_ca_list;
    int external_ca_count;
} dc_swarm_ca_config;

void dc_free_swarm_ca_config(dc_swarm_ca_config *obj);

typedef struct _dc_swarm_raft_config {
    int64_t log_entries_for_slow_followers;
    int heartbeat_tick;
    int64_t snapshot_interval;
    int election_tick;
} dc_swarm_raft_config;

void dc_free_swarm_raft_config(dc_swarm_raft_config *obj);

typedef struct _dc_driver {
    char *name;
    dc_key_value **options;
    int options_count;
} dc_driver;

void dc_free_driver(dc_driver *obj);

typedef struct _dc_task_defaults {
    dc_driver *log_driver;
} dc_task_defaults;

void dc_free_task_defaults(dc_task_defaults *obj);

typedef struct _dc_swarm_spec {
    dc_swarm_dispatcher_config *dispatcher;
    dc_swarm_orchestration *orchestration;
    dc_swarm_ca_config *ca_config;
    dc_swarm_raft_config *raft;
    dc_task_defaults *task_defaults;
    char *name;
} dc_swarm_spec;

void dc_free_swarm_spec(dc_swarm_spec *obj);

typedef struct _dc_resource_version {
    int64_t index;
} dc_resource_version;

void dc_free_resource_version(dc_resource_version *obj);

typedef struct _dc_cluster_info {
    char *created_at;
    dc_swarm_spec *spec;
    char *id;
    char *update_at;
    dc_resource_version *version;
} dc_cluster_info;

void dc_free_cluster_info(dc_cluster_info *obj);

typedef struct _dc_swarm_info {
    char *node_id;
    char *node_addr;
    char *local_node_statel;
    char *error;
    DC_BOOL control_available;
    dc_peer_node **remote_managers;
    int remote_managers_count;
    int nodes;
    int managers;
    dc_cluster_info *cluster_info;
} dc_swarm_info;

void dc_free_swarm_info(dc_swarm_info *obj);

typedef struct _dc_info {
    char *architecture;
    int containers;
    int containers_stopped;
    int containers_paused;
    int containers_running;
    DC_BOOL cpu_cfs_period;
    DC_BOOL cpu_cfs_quota;
    DC_BOOL cpu_shares;
    DC_BOOL cpu_set;
    DC_BOOL debug;
    char *discovery_backend;
    char *docker_root_dir;
    char *driver;
    dc_str_array **driver_statuses;
    int driver_statuses_count;
    dc_key_values **plugins;
    int plugins_count;
    char *execution_driver;
    char *logging_driver;
    DC_BOOL experimental_build;
    char *http_proxy;
    char *https_proxy;
    char *id;
    DC_BOOL ipv4_forwarding;
    DC_BOOL bridge_nf_iptables;
    DC_BOOL bridge_nf_ip6tables;
    int images;
    char *index_server_address;
    char *init_path;
    char *init_sha1;
    char *kernel_version;
    dc_str_array *labels;
    DC_BOOL memory_limit;
    int64_t mem_total;
    char *name;
    int n_cpu;
    int n_events_listener;
    int n_fd;
    int n_goroutines;
    char *no_proxy;
    DC_BOOL oom_kill_disable;
    char *os_type;
    int oom_score_adj;
    char *operating_system;
    dc_registry_config *registry_config;
    dc_str_array *sockets;
    DC_BOOL swap_limit;
    char *system_time;
    char *server_version;
    char *cluster_store;
    char *cluster_advertise;
    dc_swarm_info *swarm;
    char *isolation;
    dc_str_array *security_options;
} dc_info;

dc_info *dc_get_info(char *url);

void dc_free_info(dc_info *obj);

#pragma pack()

#endif //LIBDOCKERCLIENT_DOCKER_CLIENT_H
