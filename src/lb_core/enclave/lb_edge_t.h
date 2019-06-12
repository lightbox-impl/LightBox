#ifndef LB_EDGE_T_H__
#define LB_EDGE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

int ecall_auth_enc(uint8_t* src, int src_len, uint8_t* dst, uint8_t* mac);
void ecall_init_aes_gcm();
double ecall_etap_start(int record_size, int record_per_batch);

sgx_status_t SGX_CDECL ocall_lb_etap_in(uint8_t** batch);
sgx_status_t SGX_CDECL ocall_state_store_alloc(void** store_new);
sgx_status_t SGX_CDECL ocall_state_store_free(void* item);
sgx_status_t SGX_CDECL ocall_lb_log(int round, int pkt_count, double delay, double tput, int flow);
sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL ocall_get_time(int* second, int* nanosecond);
sgx_status_t SGX_CDECL ocall_sleep(long int time_ns);
sgx_status_t SGX_CDECL ocall_random(uint32_t* r);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
