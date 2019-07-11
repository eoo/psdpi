#include "ps_stats.h"

void ps_stats_init(ps_stats_t *stats) {
    stats->packets = 0;
    stats->bytes = 0;
}

