#ifndef SSH_TRACKER_H
#define SSH_TRACKER_H

#include <linux/types.h>

struct connection_key {
    __u32 client_ip;
    __u16 client_port;
};

struct connection_info {
    __u32 client_ip;
    __u16 client_port;
    __u64 start_time;
    __u32 failed_attempts;
};

#endif /* SSH_TRACKER_H */
