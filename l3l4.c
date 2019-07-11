#include <stdint.h>
#include "l3l4.h"

static void l3_address_init(l3_address_t *l3_add);
static uint32_t l3_address_compare(l3_address_t *l3a1, l3_address_t *l3a2);

static void l3_address_init(l3_address_t *l3_add) {
    l3_add->version = l3_not_set;
    // ipv6 address has 4 uint32_t values and is biggest 
    // possible union member so set to 0
    l3_add->un.v6.ip[0] = 0; // also zeros l3_add->un.v4.ip
    l3_add->un.v6.ip[1] = 0;
    l3_add->un.v6.ip[2] = 0;
    l3_add->un.v6.ip[3] = 0;
}

static uint32_t l3_address_compare(l3_address_t *l3a1, l3_address_t *l3a2) {
    uint32_t l3a_cmp = 1; // 1 == NOT equal by default

    if (l3a1->version == l3a2->version) {
        if (l3a1->version == l3_ip_v4) {
            if (l3a1->un.v4.ip == l3a2->un.v4.ip)
                l3a_cmp = 0;
        }
        else if (l3a1->version == l3_ip_v6) {
            if (    (l3a1->un.v6.ip[0] == l3a2->un.v6.ip[0])
                 && (l3a1->un.v6.ip[1] == l3a2->un.v6.ip[1])
                 && (l3a1->un.v6.ip[2] == l3a2->un.v6.ip[2])
                 && (l3a1->un.v6.ip[3] == l3a2->un.v6.ip[3])    )
                l3a_cmp = 0;
        }
    }
    return l3a_cmp;
}

void l3l4_quin_init(l3l4_quin_t *quin) {
    l3_address_init(&quin->src_ip);
    l3_address_init(&quin->dst_ip);
    quin->src_port = 0;
    quin->dst_port = 0;
    quin->proto = 0;
}

uint32_t l3l4_quin_compare(l3l4_quin_t *q1, l3l4_quin_t *q2) {
    uint32_t quin_cmp = 1; // 1 == NOT equal by default

    // start the compare, bottom up with the simple
    // fast compares
    if (q1->proto == q2->proto) {
        // protocols are the same, check next!
        // of l4 ports, check src_port first as it is more
        // likely to be different (e.g. 34176) than the
        // dst port (e.g. http port 80) - idea is to fail compare
        // as early (fast) as possible if they are anyway not the same
        if (    (q1->src_port == q2->src_port) 
             && (q1->dst_port == q2->dst_port)   ) {
            if (    (0 == l3_address_compare(&q1->src_ip, &q2->src_ip))
                 && (0 == l3_address_compare(&q1->dst_ip, &q2->dst_ip))    )
                quin_cmp = 0;
        }
    }
    return quin_cmp;
}

