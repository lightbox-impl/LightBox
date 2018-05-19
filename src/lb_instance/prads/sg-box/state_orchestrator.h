#ifndef STATE_ORCHESTRATOR_H
#define STATE_ORCHESTRATOR_H

#include <stdint.h>
#include <time.h>

#include "sgbox_config.h"

#include "sgx_tcrypto.h"

typedef struct flow_id_t {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
    uint8_t  padding[3];
} flow_id;

struct hash_entry_t;

typedef struct state_entry_t {
    // unencrypted in enclave
    // encrypted in host
    flow_id               id;
    // store hash of flow id to avoid duplicate calculation
    uint32_t              hash;
    // real state data
    char                  state[STATE_ENTRY_DATA_SIZE];
    // physical anchor in state_cache
    int                   state_cache_idx;

    // flow reset/end, and timeout
    time_t                last_pkt_time;
    int                   to_end;

    // used to implement LRU in state_cache
    // or, fast lookup in state_repo
    struct state_entry_t *prev;
    struct state_entry_t *next;

    // 128-bit AES-GCM mac
    sgx_aes_gcm_128bit_tag_t mac;

    // the lookup entry this state_entry belongs to, ugly trick
    struct hash_entry_t  *lkup_entry;
} state_entry;

/* Hash table for fast lookup */
typedef struct hash_entry_t {
    int                 idx;
    void                *data;
    struct hash_entry_t *next;
    struct hash_entry_t *prev;
} hash_entry;

#define FLOW_CMP_CLIENT(f1, f2) \
                       (f1->src_ip   == f2->src_ip && \
                        f1->src_port == f2->src_port && \
                        f1->dst_ip   == f2->dst_ip && \
                        f1->dst_port == f2->dst_port)

#define FLOW_CMP_SERVER(f1, f2) \
                       (f1->src_ip   == f2->dst_ip && \
                        f1->src_port == f2->dst_port && \
                        f1->dst_ip   == f2->src_ip && \
                        f1->dst_port == f2->src_port)

#define LKUP_HASH(fid) \
                   ((fid->src_ip + fid->dst_ip + fid->src_port + fid->dst_port + fid->proto) % LKUP_BUCKET_SIZE)
#endif