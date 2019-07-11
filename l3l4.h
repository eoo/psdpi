#ifndef L3L4_H
#define L3L4_H
#include <stdint.h>
#include <arpa/inet.h>

#define L3_IPV6_LENGTH 4 // 4 x uint32_t 

typedef struct l3_ipv4 {
    uint32_t ip;
} l3_ipv4_t;

typedef struct l3_ipv6 {
    uint32_t ip[L3_IPV6_LENGTH];        // could also use __uint128_t, Reqirements :  gcc 4.1+ and  64bit system
} l3_ipv6_t;

typedef enum l3_version {
   l3_not_set = 0,
   l3_ip_v4 = 4,
   l3_ip_v6 = 6
} l3_version_t;

typedef struct l3_address {
    l3_version_t version;
    union l3_add {
        l3_ipv4_t v4;
        l3_ipv6_t v6;
    } un;
} l3_address_t;

typedef uint16_t l4_port_t;
typedef uint8_t l4_proto_t;

typedef struct l3l4_quin {
    l3_address_t src_ip;
    l3_address_t dst_ip;
    l4_port_t src_port;
    l4_port_t dst_port;
    l4_proto_t proto;
} l3l4_quin_t;

extern void l3l4_quin_init(l3l4_quin_t *quin);
extern uint32_t l3l4_quin_compare(l3l4_quin_t *q1, l3l4_quin_t *q2);

#endif
