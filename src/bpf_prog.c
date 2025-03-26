#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include "ssh_tracker.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct connection_key);
    __type(value, struct connection_info);
} connection_map SEC(".maps");

SEC("classifier")


int ssh_tracker(struct __sk_buff *skb) 
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    
    if (data + sizeof(*eth) > data_end) 
    {
        bpf_printk("Dropped: Ethernet header too short");
        return TC_ACT_OK;
    }

    if (eth->h_proto != __constant_htons(ETH_P_IP)) 
    {
        bpf_printk("Dropped: Not IP");
        return TC_ACT_OK;
    }

    struct iphdr *ip = data + sizeof(*eth);
    
    if ((void *)ip + sizeof(*ip) > data_end) 
    {
        bpf_printk("Dropped: IP header too short");
        return TC_ACT_OK;
    }

    if (ip->protocol != IPPROTO_TCP) 
    {
        bpf_printk("Dropped: Not TCP");
        return TC_ACT_OK;
    }

    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    
    if ((void *)tcp + sizeof(*tcp) > data_end) 
    {
        bpf_printk("Dropped: TCP header too short");
        return TC_ACT_OK;
    }

    struct connection_key key = {
        .client_ip = ip->saddr,
        .client_port = tcp->source
    };

    if (tcp->dest == __constant_htons(22) && tcp->syn && !tcp->ack) 
    {
        bpf_printk("New SSH connection: IP=%u, Port=%u", key.client_ip, key.client_port);
        
        struct connection_info new_info = {
            .client_ip = ip->saddr,
            .client_port = tcp->source,
            .start_time = bpf_ktime_get_ns(),
            .failed_attempts = 0
        };
        
        int ret = bpf_map_update_elem(&connection_map, &key, &new_info, BPF_ANY);
        
        if (ret == 0) {
            bpf_printk("Map updated: IP=%u, Port=%u", key.client_ip, key.client_port);
        } 
        
        else {
            bpf_printk("Map update failed: %d", ret);
        }
    }

    if (tcp->fin || tcp->rst) 
    {
        bpf_printk("Connection ending: IP=%u, Port=%u", key.client_ip, key.client_port);
        bpf_printk("FIN=%u, RST=%u", tcp->fin, tcp->rst);
        int ret = bpf_map_delete_elem(&connection_map, &key);
        
        if (ret == 0) 
        {
            bpf_printk("Map entry deleted: IP=%u, Port=%u", key.client_ip, key.client_port);
        } 
        
        else 
        {
            bpf_printk("Map delete failed: %d", ret);
        }
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
