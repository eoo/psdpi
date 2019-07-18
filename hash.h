#ifndef HASH_H
#define HASH_H
#include <stdint.h>
#include "l3l4.h"
#include "ps_stats.h"

#define HASH_BUCKETS_MAX 10
#define HASH_TABLE_SIZE 65636

/*
** ht_key_t is defined to be a 32 bit unsigned int and holds the result
** of caculating a hash over a ht_key_value_t
*/
// Do we have to use CRC to generate the key for the quintuple?
// We can use any method to generate the key but crc 32 gives good 
// distribution. Initially we will use simple OR'ing.
typedef uint32_t ht_key_t;  

typedef struct ht_entry {
    ht_key_t    key;   // hash key
    l3l4_quin_t value; // value basis for hash key
    ps_stats_t  stats; // statistics counters for flow
    struct ht_entry *next;  //next entry
} ht_entry_t;

typedef struct ht_bucket {
    uint16_t   entries;  // number of entries in bucket
    uint8_t    filled;   // set to 1 if this entry is filled
    uint64_t collisions; // number of collisions for this bucket
    ht_entry_t entry;    // first entry in bucket

} ht_bucket_t;

typedef enum ht_ret {
    ht_ret_ok = 0,
    ht_bucket_full = 1
} ht_ret_t;

typedef struct ht_table {
    uint16_t entries;   // number of entries in table
    uint64_t collisions; // number of table collisions
    ht_bucket_t bucket[HASH_TABLE_SIZE];
} ht_table_t;

extern void ht_init(ht_table_t *ht);
extern void ht_print(ht_table_t *ht);
extern ht_ret_t ht_add(ht_table_t *ht, l3l4_quin_t *quin, uint16_t packet_len);

extern uint32_t compute_hash(l3l4_quin_t *quin);


#endif
