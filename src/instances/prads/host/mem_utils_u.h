#ifndef MEM_UTILS_U_H
#define MEM_UTILS_U_H

#include "sgx_urts.h"

// #include "../../lb_instance/prads/prads_host/prads.h"

typedef struct mem_pool_node_t {
    void *pool;
    struct mem_pool_node_t *next;
} mem_pool_node;

void mem_util_init_pools();

void mem_util_free_pools();


#endif