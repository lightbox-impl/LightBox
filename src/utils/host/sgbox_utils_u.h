#ifndef SGBOX_UTILS_U_H
#define SGBOX_UTILS_U_H

#include "sgx_urts.h"

#include "../prads/prads.h"

typedef struct mem_pool_node_t {
    void *pool;
    struct mem_pool_node_t *next;
} mem_pool_node;

void sgbox_init_mem_pools();

void sgbox_free_mem_pools();


#endif