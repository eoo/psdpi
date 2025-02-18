#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include "hash.h"
#include "ps_stats.h"

static void clear_bucket(ht_bucket_t * bucket);
static uint32_t compute_hash(l3l4_quin_t *quin);
static uint8_t already_present(ht_table_t * ht, ht_key_t key, l3l4_quin_t * quin);

static void ht_entry_init(ht_entry_t * entry) {
    entry->key = 0;
    entry->next = (ht_entry_t *)0;
    l3l4_quin_init(&entry->value);
    ps_stats_init(&entry->stats);
}

static void ht_bucket_init(ht_bucket_t *bucket) {
    bucket->entries = 0;
    bucket->filled = 0;
    bucket->collisions = 0;
    ht_entry_init(&bucket->entry);
}

void ht_init(ht_table_t *ht) {
    uint32_t i;

    ht->entries = 0;   // number of entries in table
    ht->collisions = 0; // number of table collisions

    for (i = 0; i < HASH_TABLE_SIZE; i++) {
        ht_bucket_init(&ht->bucket[i]);
    }
}

void ht_print(ht_table_t *ht) {

    int i;
    printf("Total Entries in Hash Table : %d\n", ht->entries); 
    for(i = 0; i < HASH_TABLE_SIZE; i++)
    {   
        ht_bucket_t * bucket = &(ht->bucket[i]);
        
        if(bucket->entries != 0)
        {   
            ht_entry_t * entry = &bucket->entry;

            printf("Src Port : %d\t", ntohs(entry->value.src_port));
            printf("Dst Port : %d\t", ntohs(entry->value.dst_port));
            printf("Packets : ");
            printf("%" PRIu64 "\n", entry->stats.packets);
        }
    }
}

static uint8_t already_present(ht_table_t * ht, ht_key_t key, l3l4_quin_t * quin)    //returns 0 if not present, and the index in linked list if present
{
    uint16_t index = key % HASH_TABLE_SIZE;
    ht_bucket_t * bucket = &ht->bucket[index];
    uint8_t present = 0;

    //if no entries
    if(bucket->entries == 0 )       return present;

    //check first entry
    //if(bucket->entry.key == key)    present = 1;
    if(!l3l4_quin_compare(quin, &(bucket->entry.value))) present = 1;

    //check rest of entries
    ht_entry_t * entry = &bucket->entry;
    int i;
    for(i = 1; i < bucket->entries; i++)
    {   
        entry =  entry->next;
        //if(entry->key == key)       present = i+1;
        if(!l3l4_quin_compare(quin, &(entry->value)))       present = i+1;

    }

    return present;
}

ht_ret_t ht_add(ht_table_t *ht, l3l4_quin_t *quin, uint16_t packet_len) {
    
    ht_key_t key = compute_hash(quin);
    uint16_t index = key % HASH_TABLE_SIZE;
    ht_bucket_t * bucket = &ht->bucket[index];

    uint8_t present = already_present(ht, key, quin); // if key not present returns 0, else returns its index in the linked list

    if(present)
    {   
        ht_entry_t * entry = &(bucket->entry);
        int i;
        for(i = 1; i < present; i++)
            entry = entry->next;

        entry->stats.packets++;
        entry->stats.bytes += packet_len;

        printf("Updating previous entry with hash key %" PRIu32 "\n",key);
    } 
    

    else if(!bucket->filled)
    {   
        
        if(bucket->entries == 0)    //update first Entry
        {
            ht_entry_t * entry = &(bucket->entry);
            entry->key = key;
            entry->stats.packets = 1;
            entry->stats.bytes = packet_len;
            entry->next = 0; //NULL POINTER
            entry->value = *quin;
        }

        else                        //create new entry and add to end of list
        {
            //create new entry
            ht_entry_t * temp;
            temp = (ht_entry_t *)malloc(sizeof(ht_entry_t));
            temp->key = key;
            l3l4_quin_init(&temp->value);
            temp->value = *quin;   
            temp->stats.packets = 1;
            temp->stats.bytes = packet_len;
            temp->next = 0;  //NULL pointer
            
            //add entry to the end of list
            ht_entry_t * entry = &(bucket->entry);
            int i;
            for(i = 1; i < bucket->entries; i++)
                entry = entry->next;

            entry->next = temp;
        }

        ht->entries++;
        bucket->entries++;
        if(bucket->entries == 10) bucket->filled = 1;
        printf("Creating new entry with hash key %" PRIu32 "\n",key);
    }
    else
    {
        printf("All buckets filled at index %" PRIu16 "\n", index);
    }



    ht_ret_t ht_ret = ht_ret_ok;
    return ht_ret;
}


static uint32_t compute_hash(l3l4_quin_t *quin)
{   
    uint32_t result;

    uint32_t temp[4];

    temp[0] = quin->src_ip.un.v6.ip[0] | quin->dst_ip.un.v6.ip[0]; 
    temp[1] = quin->src_ip.un.v6.ip[1] | quin->dst_ip.un.v6.ip[1];
    temp[2] = quin->src_ip.un.v6.ip[2] | quin->dst_ip.un.v6.ip[2];
    temp[3] = quin->src_ip.un.v6.ip[3] | quin->dst_ip.un.v6.ip[3];

    result = crc32buf((char *)temp, 16);

    uint16_t temp2 = quin->src_port | quin->dst_port;
    result += crc32buf((char *)&temp2, 2);

    uint8_t temp3 = quin->proto;
    result += crc32buf((char *)&temp3, 1);

    printf("Comuted Hash: %" PRIu32 "\n",result);
    return result;
}


void ht_clear(ht_table_t * ht)
{   int i;
    for(i = 0; i < HASH_TABLE_SIZE; i++)
    {
        clear_bucket(&ht->bucket[i]);
    }

    ht_init(ht);
}

static void clear_bucket(ht_bucket_t * bucket)
{   
    int entries,i;
    ht_entry_t * entry = &bucket->entry;
    entry = entry->next;
    ht_entry_t * temp = entry;

        //free all the memory
        while( entry != NULL )
        {   
            temp = entry->next;
            free(entry);
            entry = temp;
        }

    return;
}