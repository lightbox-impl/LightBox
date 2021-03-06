#include "mem_utils_u.h"

#include "prads_core/prads.h"
#include <stdlib.h>

#define MEM_POOL_CAPACITY 1000000

mem_pool_node os_asset_pool;
mem_pool_node serv_asset_pool;
mem_pool_node asset_pool;

void mem_util_init_pools() {
    os_asset_pool.pool = calloc(MEM_POOL_CAPACITY, sizeof(os_asset));
    os_asset_pool.next = 0;

    serv_asset_pool.pool = calloc(MEM_POOL_CAPACITY, sizeof(serv_asset));
    serv_asset_pool.next = 0;

    asset_pool.pool = calloc(MEM_POOL_CAPACITY, sizeof(asset));
    asset_pool.next = 0;
}

void free_mem_pool(mem_pool_node *pool) {
    while (pool) {
        mem_pool_node *tmp = pool;
        pool = pool->next;
        free(tmp);
    }
}

void mem_util_free_pools() {
    free_mem_pool(&os_asset_pool);
    free_mem_pool(&serv_asset_pool);
    free_mem_pool(&asset_pool);
}

void *ocall_calloc(int size) {
    mem_pool_node *last_node;
    mem_pool_node *new_node = (mem_pool_node *)malloc(sizeof(mem_pool_node));
    new_node->next = 0;
    switch (size) {
        case sizeof(os_asset):
            last_node = &os_asset_pool;
            new_node->pool = calloc(MEM_POOL_CAPACITY, sizeof(os_asset));
            printf("[*] New memory pool for os_asset allocated\n");
            break;
        case sizeof(serv_asset):
            last_node = &serv_asset_pool;
            new_node->pool = calloc(MEM_POOL_CAPACITY, sizeof(serv_asset));
            printf("[*] New memory pool for serv_asset allocated\n");
            break;
        case sizeof(asset):
            last_node = &asset_pool;
            new_node->pool = calloc(MEM_POOL_CAPACITY, sizeof(asset));
            printf("[*] New memory pool for asset allocated\n");
            break;
        default:
            printf("[*] Invalid mem_util allocation in host");
            abort();
    }

    while (last_node->next)
        last_node = last_node->next;
    last_node->next = new_node;

    return new_node->pool;
}

void ocall_free(void *ptr) {
    free(ptr);
}
