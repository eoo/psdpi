#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "ps_eth.h"

void ps_eth_stats_init(eth_stats_t *stats) {

    // initialize the array to zero
    memset((void *)stats, 0, PS_ETH_TYPE_INDEX); 
}

eth_type_t ps_parse_eth(eth_stats_t *stats, const uint8_t * packet) {
    uint16_t eth_type;

    // extract the Ethernet type
    eth_type = (uint16_t)*(uint16_t*)&packet[PS_ETH_TYPE_OFFSET];
    
    // use the ethernet type as an index to the stats
    (stats->eth_type[eth_type])++;

    return (eth_type);
}

void ps_eth_stats_print(eth_stats_t *stats) {
    int i;

    // initialize the array to zero
    for (i = 0; i < PS_ETH_TYPE_INDEX; i++) {
        if (stats->eth_type[i] != 0) {
            printf("Ethernet Type = 0x%04x Packets = %lu\n", 
                               ntohs(i), stats->eth_type[i]);
        }
    }
}

