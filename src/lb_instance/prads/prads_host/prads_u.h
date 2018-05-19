#ifndef PRADS_U_H__
#define PRADS_U_H__

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

void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_get_time, (int* second, int* nanosecond));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sleep, (long int time_ns));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_random, (uint32_t* r));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_secure_state_swap, (void* _bundled_state, void* _bundled_id, int* is_server, int bundle_size));
void* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_calloc, (int size));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_free, (void* ptr));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_log_flush_full, (void* buffer, int buf_len));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_lb_etap_in, (uint8_t** batch));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_state_store_alloc, (void** store_new));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_state_store_free, (void* item));
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));

sgx_status_t ecall_prads_initialize(sgx_enclave_id_t eid, int* retval, void* global_config, int _nets, void* _network, void* _os_asset_pool, void* _serv_asset_pool, void* _asset_pool);
sgx_status_t ecall_prads_gameover(sgx_enclave_id_t eid);
sgx_status_t ecall_prads_cxtrackerid(sgx_enclave_id_t eid, uint64_t* retval);
sgx_status_t ecall_secure_ferry(sgx_enclave_id_t eid, void* pheader, void* packet, int ferry_len, int ferry_unit, uint8_t* ferry_mac, int* miss_count, int* bundle_count, int* state_count);
sgx_status_t ecall_naive_process(sgx_enclave_id_t eid, void* pheader, void* packet, int packet_len, uint8_t* mac, int* state_count);
sgx_status_t ecall_auth_enc(sgx_enclave_id_t eid, int* retval, uint8_t* src, int src_len, uint8_t* dst, uint8_t* mac);
sgx_status_t ecall_sync_expiration(sgx_enclave_id_t eid, int expired_state_count);
sgx_status_t ecall_check_expiration(sgx_enclave_id_t eid, long int wall_time);
sgx_status_t ecall_log_flush_timeout(sgx_enclave_id_t eid, void* out_buffer, int buf_len);
sgx_status_t ecall_init_aes_gcm(sgx_enclave_id_t eid);
sgx_status_t ecall_test_mb(sgx_enclave_id_t eid);
sgx_status_t ecall_etap_start(sgx_enclave_id_t eid, double* retval, int record_size, int record_per_batch);
sgx_status_t ecall_state_test(sgx_enclave_id_t eid);
sgx_status_t ecall_lb_prads_init(sgx_enclave_id_t eid, void* global_config, int _nets, void* _network, void* _os_asset_pool, void* _serv_asset_pool, void* _asset_pool);
sgx_status_t ecall_lb_prads_run(sgx_enclave_id_t eid);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
