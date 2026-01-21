// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef unsigned int u32;
typedef unsigned long long u64;
typedef unsigned short u16;
typedef signed int s32;

struct file_event {
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 gid;
    char comm[16];
    char path[256];
    u32 flags;
    u32 result;
    u64 timestamp;
};

struct network_event {
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 gid;
    char comm[16];
    u32 protocol;  // 0=TCP, 1=UDP
    u32 local_ip;
    u32 local_port;
    u32 remote_ip;
    u32 remote_port;
    u32 result;
    u64 timestamp;
};

// BPF maps для передачи событий в userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 0);
} file_events_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 0);
} network_events_map SEC(".maps");

// Map для фильтрации по PID (tgid для лучшей поддержки контейнеров)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u32);
} monitored_pids SEC(".maps");

// хелпер для получения информации о процессе
static inline void get_process_info(struct file_event *event) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->gid = (bpf_get_current_uid_gid() >> 32) & 0xFFFFFFFF;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->timestamp = bpf_ktime_get_ns();
    
    // Устанавливаем в 0, можно будет получить через /proc в userspace
    event->ppid = 0;
}

// хелпер для сетевых событий
static inline void get_network_process_info(struct network_event *event) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->gid = (bpf_get_current_uid_gid() >> 32) & 0xFFFFFFFF;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->timestamp = bpf_ktime_get_ns();
    
    // PPID получить сложно без полного определения task_struct
    event->ppid = 0;
}

// для доступа к аргументам tracepoint
struct trace_event_raw_sys_enter {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    long id;
    unsigned long args[6];
};

// Tracepoint для sys_enter_open
SEC("tracepoint/syscalls/sys_enter_open")
int tracepoint_sys_enter_open(void *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tgid = (u32)pid_tgid; // Thread Group ID для фильтрации контейнеров
    
    // Проверяем, отслеживается ли этот PID (используем tgid для лучшей поддержки контейнеров)
    u32 *monitored = bpf_map_lookup_elem(&monitored_pids, &tgid);
    if (!monitored) {
        // Также проверяем по pid на случай, если добавили по pid
        monitored = bpf_map_lookup_elem(&monitored_pids, &pid);
        if (!monitored) {
            return 0;
        }
    }

    struct file_event event = {};
    get_process_info(&event);
    
    struct trace_event_raw_sys_enter *tp_ctx = (struct trace_event_raw_sys_enter *)ctx;
    u64 args[6];
    bpf_probe_read_kernel(args, sizeof(args), &tp_ctx->args);
    
    // args[0] - pathname (char*)
    // args[1] - flags (int)
    char *pathname = (char *)args[0];
    if (pathname) {
        bpf_probe_read_user_str(&event.path, sizeof(event.path), pathname);
    }
    event.flags = (u32)args[1];
    
    bpf_perf_event_output(ctx, &file_events_map, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint_sys_enter_openat(void *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tgid = (u32)pid_tgid;
    
    /* поиск по process ID (верхние 32 бита) */
    u32 *monitored = bpf_map_lookup_elem(&monitored_pids, &pid);
    if (!monitored) {
        monitored = bpf_map_lookup_elem(&monitored_pids, &tgid);
        if (!monitored) {
            return 0;
        }
    }

    struct file_event event = {};
    get_process_info(&event);
    
    struct trace_event_raw_sys_enter *tp_ctx = (struct trace_event_raw_sys_enter *)ctx;
    u64 args[6];
    bpf_probe_read_kernel(args, sizeof(args), &tp_ctx->args);
    
    // args[0] - dfd (int)
    // args[1] - pathname (char*)
    // args[2] - flags (int)
    char *pathname = (char *)args[1];
    if (pathname) {
        bpf_probe_read_user_str(&event.path, sizeof(event.path), pathname);
    }
    event.flags = (u32)args[2];
    
    bpf_perf_event_output(ctx, &file_events_map, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int tracepoint_sys_enter_read(void *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tgid = (u32)pid_tgid;
    
    u32 *monitored = bpf_map_lookup_elem(&monitored_pids, &pid);
    if (!monitored) {
        monitored = bpf_map_lookup_elem(&monitored_pids, &tgid);
        if (!monitored) {
            return 0;
        }
    }

    struct file_event event = {};
    get_process_info(&event);
    
    struct trace_event_raw_sys_enter *tp_ctx = (struct trace_event_raw_sys_enter *)ctx;
    u64 args[6];
    bpf_probe_read_kernel(args, sizeof(args), &tp_ctx->args);
    
    // args[0] - fd (unsigned int)
    // args[2] - count (size_t)
    event.flags = (u32)args[0]; // fd
    event.result = (u32)args[2]; // count

    // Для read путь получить сложно, тут стаб
    __builtin_memcpy(event.path, "[read]", 7);
    
    bpf_perf_event_output(ctx, &file_events_map, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int tracepoint_sys_enter_write(void *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tgid = (u32)pid_tgid;
    
    u32 *monitored = bpf_map_lookup_elem(&monitored_pids, &pid);
    if (!monitored) {
        monitored = bpf_map_lookup_elem(&monitored_pids, &tgid);
        if (!monitored) {
            return 0;
        }
    }

    struct file_event event = {};
    get_process_info(&event);
    
    struct trace_event_raw_sys_enter *tp_ctx = (struct trace_event_raw_sys_enter *)ctx;
    u64 args[6];
    bpf_probe_read_kernel(args, sizeof(args), &tp_ctx->args);
    
    // args[0] - fd (unsigned int)
    // args[2] - count (size_t)
    event.flags = (u32)args[0]; // fd
    event.result = (u32)args[2]; // count

    __builtin_memcpy(event.path, "[write]", 8);
    
    bpf_perf_event_output(ctx, &file_events_map, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint_sys_enter_connect(void *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tgid = (u32)pid_tgid;
    
    u32 *monitored = bpf_map_lookup_elem(&monitored_pids, &pid);
    if (!monitored) {
        monitored = bpf_map_lookup_elem(&monitored_pids, &tgid);
        if (!monitored) {
            return 0;
        }
    }

    struct network_event event = {};
    get_network_process_info(&event);
    event.protocol = 0; // TCP по умолчанию
    
    struct trace_event_raw_sys_enter *tp_ctx = (struct trace_event_raw_sys_enter *)ctx;
    u64 args[6];
    bpf_probe_read_kernel(args, sizeof(args), &tp_ctx->args);
    
    // args[0] - fd (int)
    // args[1] - uservaddr (struct sockaddr*)
    // args[2] - addrlen (int)
    void *addr_ptr = (void *)args[1];
    if (addr_ptr) {
        // чтение sa_family для определения типа адреса
        u16 family = 0;
        bpf_probe_read_user(&family, sizeof(family), addr_ptr);
        
        if (family == 2) { // AF_INET
            struct sockaddr_in sin = {};
            bpf_probe_read_user(&sin, sizeof(sin), addr_ptr);
            
            // конвертация из network byte order
            event.remote_ip = __builtin_bswap32(sin.sin_addr.s_addr);
            event.remote_port = __builtin_bswap16(sin.sin_port);
        }
    }
    
    bpf_perf_event_output(ctx, &network_events_map, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept4")
int tracepoint_sys_enter_accept4(void *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tgid = (u32)pid_tgid;
    
    u32 *monitored = bpf_map_lookup_elem(&monitored_pids, &pid);
    if (!monitored) {
        monitored = bpf_map_lookup_elem(&monitored_pids, &tgid);
        if (!monitored) {
            return 0;
        }
    }

    struct network_event event = {};
    get_network_process_info(&event);
    event.protocol = 0; // TCP
    
    bpf_perf_event_output(ctx, &network_events_map, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int tracepoint_sys_enter_sendto(void *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tgid = (u32)pid_tgid;
    
    u32 *monitored = bpf_map_lookup_elem(&monitored_pids, &pid);
    if (!monitored) {
        monitored = bpf_map_lookup_elem(&monitored_pids, &tgid);
        if (!monitored) {
            return 0;
        }
    }

    struct network_event event = {};
    get_network_process_info(&event);
    event.protocol = 0; // TCP по умолчанию
    
    struct trace_event_raw_sys_enter *tp_ctx = (struct trace_event_raw_sys_enter *)ctx;
    u64 args[6];
    bpf_probe_read_kernel(args, sizeof(args), &tp_ctx->args);
    
    // args[0] - fd (int)
    // args[4] - dest_addr (struct sockaddr*)
    void *addr_ptr = (void *)args[4];
    if (addr_ptr) {
        u16 family = 0;
        bpf_probe_read_user(&family, sizeof(family), addr_ptr);
        
        if (family == 2) { // AF_INET
            struct sockaddr_in sin = {};
            bpf_probe_read_user(&sin, sizeof(sin), addr_ptr);
            event.remote_ip = __builtin_bswap32(sin.sin_addr.s_addr);
            event.remote_port = __builtin_bswap16(sin.sin_port);
        }
    }
    
    bpf_perf_event_output(ctx, &network_events_map, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}

// Tracepoint для sys_enter_recvfrom
SEC("tracepoint/syscalls/sys_enter_recvfrom")
int tracepoint_sys_enter_recvfrom(void *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tgid = (u32)pid_tgid;
    
    u32 *monitored = bpf_map_lookup_elem(&monitored_pids, &pid);
    if (!monitored) {
        monitored = bpf_map_lookup_elem(&monitored_pids, &tgid);
        if (!monitored) {
            return 0;
        }
    }

    struct network_event event = {};
    get_network_process_info(&event);
    event.protocol = 0; // TCP
    
    bpf_perf_event_output(ctx, &network_events_map, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}

char _license[] SEC("license") = "GPL";
