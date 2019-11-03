#include "mem_utils_t.h"

#include "prads_edge_t.h"
#include "prads_core/prads.h"

// from lb_core
#include <lb_utils_t.h>

#define MEM_POOL_CAPACITY 1000000

os_asset *os_asset_pool;
serv_asset *serv_asset_pool;
asset *asset_pool;

int os_asset_allocated;
int serv_asset_allocated;
int asset_allocated;

void *mem_util_calloc(int size) {
    // add ocall status checking?
    switch (size) {
        case sizeof(os_asset) :
            if (unlikely(os_asset_allocated == MEM_POOL_CAPACITY)) {
                ocall_calloc((void **)&os_asset_pool, sizeof(os_asset));
                os_asset_allocated = 0;
            }
            return &os_asset_pool[os_asset_allocated++];
        case sizeof(serv_asset) :
            if (unlikely(serv_asset_allocated == MEM_POOL_CAPACITY)) {
                ocall_calloc((void **)&serv_asset_pool, sizeof(serv_asset));
                serv_asset_allocated = 0;
            }
            return &serv_asset_pool[serv_asset_allocated++];
        case sizeof(asset) :
            if (unlikely(asset_allocated == MEM_POOL_CAPACITY)) {
                ocall_calloc((void **)&asset_pool, sizeof(asset));
                asset_allocated = 0;
            }
            return &asset_pool[asset_allocated++];
        default:
            eprintf("[*] Invalid mem_utils allocation in enclave!\n");
            return 0;
    }
}

void mem_util_free(void *ptr) {
    // never free in current timeout setting
    //ocall_free(ptr);
}
