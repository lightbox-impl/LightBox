#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

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

void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string2, (const char* str));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_get_time2, (int* second, int* nanosecond));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_get_data, (int data_id, char** val, int* len));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_read_dir, (char* dirPaht, char** allFiles, int* fileCount, int subfile));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_file_size, (char* filePath, int* len));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_read_file, (char* filePath, char** out, int* len, int pos));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_write_file, (char* filePath, char* src, int len, int append));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_malloc, (void** pointer, int size));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_free, (void* pointer));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_del, (void* pointer, int isArray));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_rand, (int* rand_num, int mod));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sfbpf_compile, (int snaplen_arg, int linktype_arg, char* program, const char* buf, int optimize, int mask));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sfbpf_filter, (const char* pc, const char* p, int wirelen, int buflen));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sfbpf_freecode, (char* program));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pcap_init, (char* filename));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pcap_next, (char** pkt, char* pcap_pkthdr));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_load_config, (const char* filename, char* g_config));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_dfc_init, (char** pattern_pool, int** pattern_length, int* size));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_lb_etap_in, (uint8_t** batch));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_state_store_alloc, (void** store_new));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_state_store_free, (void* item));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_lb_log, (int round, int pkt_count, double delay, double tput, int flow));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_get_time, (int* second, int* nanosecond));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sleep, (long int time_ns));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_random, (uint32_t* r));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));

sgx_status_t ecall_test(sgx_enclave_id_t eid);
sgx_status_t ecall_mos_test(sgx_enclave_id_t eid, const char* config_file_path);
sgx_status_t ecall_auth_enc(sgx_enclave_id_t eid, int* retval, uint8_t* src, int src_len, uint8_t* dst, uint8_t* mac);
sgx_status_t ecall_init_aes_gcm(sgx_enclave_id_t eid);
sgx_status_t ecall_etap_start(sgx_enclave_id_t eid, double* retval, int record_size, int record_per_batch);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
