#ifndef PRADS_T_H__
#define PRADS_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


int ecall_prads_initialize(void* global_config, int _nets, void* _network, void* _os_asset_pool, void* _serv_asset_pool, void* _asset_pool);
void ecall_prads_gameover();
uint64_t ecall_prads_cxtrackerid();
void ecall_secure_ferry(void* pheader, void* packet, int ferry_len, int ferry_unit, uint8_t* ferry_mac, int* miss_count, int* bundle_count, int* state_count);
void ecall_naive_process(void* pheader, void* packet, int packet_len, uint8_t* mac, int* state_count);
int ecall_auth_enc(uint8_t* src, int src_len, uint8_t* dst, uint8_t* mac);
void ecall_sync_expiration(int expired_state_count);
void ecall_check_expiration(long int wall_time);
void ecall_log_flush_timeout(void* out_buffer, int buf_len);
void ecall_init_aes_gcm();
void ecall_test_mb();
double ecall_etap_start(int record_size, int record_per_batch);
void ecall_state_test();
void ecall_lb_prads_init(void* global_config, int _nets, void* _network, void* _os_asset_pool, void* _serv_asset_pool, void* _asset_pool);
void ecall_lb_prads_run();

sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL ocall_get_time(int* second, int* nanosecond);
sgx_status_t SGX_CDECL ocall_sleep(long int time_ns);
sgx_status_t SGX_CDECL ocall_random(uint32_t* r);
sgx_status_t SGX_CDECL ocall_secure_state_swap(void* _bundled_state, void* _bundled_id, int* is_server, int bundle_size);
sgx_status_t SGX_CDECL ocall_calloc(void** retval, int size);
sgx_status_t SGX_CDECL ocall_free(void* ptr);
sgx_status_t SGX_CDECL ocall_log_flush_full(void* buffer, int buf_len);
sgx_status_t SGX_CDECL ocall_lb_etap_in(uint8_t** batch);
sgx_status_t SGX_CDECL ocall_state_store_alloc(void** store_new);
sgx_status_t SGX_CDECL ocall_state_store_free(void* item);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
