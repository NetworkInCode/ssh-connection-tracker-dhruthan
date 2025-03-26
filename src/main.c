#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <net/if.h>
#include <errno.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/pkt_cls.h>
#include "ssh_tracker.h"

#define MAX_ENTRIES 1024

static void print_stats(int map_fd, int interval) 
{
    struct connection_info info;
    struct connection_key keys[MAX_ENTRIES];
    int key_count = 0;
    
    while (1) 
    {
        printf("\n=== SSH Connection Stats (Interval: %ds) ===\n", interval);
        printf("Timestamp: %s", ctime(&(time_t){time(NULL)}));
        
        printf("%-15s %-5s %-10s %-15s\n", "Client IP", "Port", "Duration(s)", "Failed Attempts");
        printf("----------------------------------------\n");
        
        int active_connections = 0;
        struct connection_key prev_key = {0}, curr_key;
        
        if (bpf_map_get_next_key(map_fd, NULL, &curr_key) == 0) {
            do 
            {
                keys[key_count] = curr_key;
                key_count++;
                prev_key = curr_key;
            } while (key_count < MAX_ENTRIES && bpf_map_get_next_key(map_fd, &prev_key, &curr_key) == 0);
        }
        
        for (int i = 0; i < key_count; i++) 
        {
            int is_duplicate = 0;
            
            for (int j = 0; j < i; j++) {
                if (keys[i].client_ip == keys[j].client_ip && keys[i].client_port == keys[j].client_port) 
                {
                    is_duplicate = 1;
                    break;
                }
            }
            if (is_duplicate) continue;
            
            if (bpf_map_lookup_elem(map_fd, &keys[i], &info) == 0) 
            {
                active_connections++;
                
                struct timespec ts;
                clock_gettime(CLOCK_MONOTONIC, &ts);
                __u64 now_ns = ts.tv_sec * 1000000000LL + ts.tv_nsec;
                __u64 duration_ns = now_ns - info.start_time;
                long duration_s = duration_ns / 1000000000LL;
                
                char ip_str[16];
                
                snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d",
                        info.client_ip & 0xFF, (info.client_ip >> 8) & 0xFF,
                        (info.client_ip >> 16) & 0xFF, (info.client_ip >> 24) & 0xFF);
                        
                printf("%-15s %-5d %-10ld %-15d\n",
                       ip_str, info.client_port, duration_s, info.failed_attempts);
            }
        }
        
        if (active_connections == 0) {
            printf("No active connections\n");
        }
        
        printf("\nTotal active SSH connections: %d\n", active_connections);
        key_count = 0;
        sleep(interval);
    }
}

int main(int argc, char *argv[]) 
{
    int interval = 5;
    int opt;
    while ((opt = getopt(argc, argv, "i:")) != -1) 
    {
        switch (opt) 
        {
            case 'i':
                interval = atoi(optarg);
                if (interval <= 0) {
                    fprintf(stderr, "Interval must be positive\n");
                    return 1;
                }
                break;
                
            default:
                fprintf(stderr, "Usage: %s [-i interval_seconds]\n", argv[0]);
                return 1;
        }
    }

    struct bpf_object *obj;
    int prog_fd, map_fd;
    
    struct bpf_object_open_opts opts = {
        .sz = sizeof(struct bpf_object_open_opts),
        .btf_custom_path = NULL,
        .relaxed_maps = 1,
    };
    obj = bpf_object__open_file("bpf_prog.o", &opts);
    
    if (libbpf_get_error(obj)) 
    {
        fprintf(stderr, "Error opening BPF object: %s\n", strerror(errno));
        return 1;
    }
    
    if (bpf_object__load(obj)) 
    {
        fprintf(stderr, "Error loading BPF program: %s\n", strerror(errno));
        return 1;
    }
    
    prog_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "ssh_tracker"));
    
    if (prog_fd < 0) 
    {
        fprintf(stderr, "Error finding program 'ssh_tracker'\n");
        return 1;
    }
    
    map_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "connection_map"));
    
    if (map_fd < 0) 
    {
        fprintf(stderr, "Error finding map 'connection_map'\n");
        return 1;
    }
    
    int ifindex = if_nametoindex("lo"); // Interface can be changed here, I gave it loopback to test ssh to localhost
    if (!ifindex) 
    {
        fprintf(stderr, "Error: Interface 'lo' not found\n");
        return 1;
    }
    printf("Attaching TC to interface index %d (lo) for ingress and egress\n", ifindex);


    // Ingress hook
    struct bpf_tc_hook ingress_hook = {
        .sz = sizeof(struct bpf_tc_hook),
        .ifindex = ifindex,
        .attach_point = BPF_TC_INGRESS,
    };
    
    int ingress_ret = bpf_tc_hook_create(&ingress_hook);
    
    if (ingress_ret < 0 && ingress_ret != -EEXIST) 
    {
        fprintf(stderr, "Error creating ingress TC hook: %s\n", strerror(-ingress_ret));
        return 1;
    }
    
    struct bpf_tc_opts ingress_opts = {
        .sz = sizeof(struct bpf_tc_opts),
        .prog_fd = prog_fd,
    };
    
    if (bpf_tc_attach(&ingress_hook, &ingress_opts) < 0) 
    {
        fprintf(stderr, "Error attaching TC program to ingress: %s\n", strerror(errno));
        return 1;
    }



    // Egress hook
    struct bpf_tc_hook egress_hook = {
        .sz = sizeof(struct bpf_tc_hook),
        .ifindex = ifindex,
        .attach_point = BPF_TC_EGRESS,
    };
    
    int egress_ret = bpf_tc_hook_create(&egress_hook);
    if (egress_ret < 0 && egress_ret != -EEXIST) 
    {
        fprintf(stderr, "Error creating egress TC hook: %s\n", strerror(-egress_ret));
        return 1;
    }
    
    struct bpf_tc_opts egress_opts = {
        .sz = sizeof(struct bpf_tc_opts),
        .prog_fd = prog_fd,
    };
    
    if (bpf_tc_attach(&egress_hook, &egress_opts) < 0) 
    {
        fprintf(stderr, "Error attaching TC program to egress: %s\n", strerror(errno));
        return 1;
    }

    printf("SSH Connection Tracker started. Press Ctrl+C to stop.\n");
    print_stats(map_fd, interval);
    
    return 0;
}
