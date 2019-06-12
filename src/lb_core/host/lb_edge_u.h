#ifndef LB_EDGE_U_H__
#define LB_EDGE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_lb_etap_in, (uint8_t** batch));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_state_store_alloc, (void** store_new));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_state_store_free, (void* item));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_lb_log, (int round, int pkt_count, double delay, double tput, int flow));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_get_time, (int* second, int* nanosecond));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sleep, (long int time_ns));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_random, (uint32_t* r));

sgx_status_t ecall_auth_enc(sgx_enclave_id_t eid, int* retval, uint8_t* src, int src_len, uint8_t* dst, uint8_t* mac);
sgx_status_t ecall_init_aes_gcm(sgx_enclave_id_t eid);
sgx_status_t ecall_etap_start(sgx_enclave_id_t eid, double* retval, int record_size, int record_per_batch);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
