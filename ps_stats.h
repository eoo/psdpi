#ifndef PSSTATS_H
#define PSSTATS_H

#include <stdint.h>

typedef struct ps_stats {
    uint64_t packets;    
    uint64_t bytes;    
} ps_stats_t;

extern void ps_stats_init(ps_stats_t *stats);

#endif


