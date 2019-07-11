#ifndef PSETH_H
#define PSETH_H

#include <stdint.h>

#define PS_ETH_TYPE_OFFSET 12
#define PS_ETH_TYPE_INDEX 65536

#define PS_ETH_TYPE_IPV4 0x0800
#define PS_ETH_TYPE_IPV6 0x86DD

typedef uint16_t eth_type_t;

typedef uint64_t eth_type_counter_t;

typedef struct eth_stats {
    eth_type_counter_t eth_type[PS_ETH_TYPE_INDEX]; // uint64_t eth_type[65536];
} eth_stats_t;

extern void ps_eth_stats_init(eth_stats_t *stats);
extern void ps_eth_stats_print(eth_stats_t *stats);
extern eth_type_t ps_parse_eth(eth_stats_t *stats, const uint8_t * packet);

#endif