#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void ecall_test();
void ecall_mos_test(const char* config_file_path);
int ecall_auth_enc(uint8_t* src, int src_len, uint8_t* dst, uint8_t* mac);
void ecall_init_aes_gcm();
double ecall_etap_start(int record_size, int record_per_batch);

sgx_status_t SGX_CDECL ocall_print_string2(const char* str);
sgx_status_t SGX_CDECL ocall_get_time2(int* second, int* nanosecond);
sgx_status_t SGX_CDECL ocall_get_data(int data_id, char** val, int* len);
sgx_status_t SGX_CDECL ocall_read_dir(char* dirPaht, char** allFiles, int* fileCount, int subfile);
sgx_status_t SGX_CDECL ocall_file_size(char* filePath, int* len);
sgx_status_t SGX_CDECL ocall_read_file(char* filePath, char** out, int* len, int pos);
sgx_status_t SGX_CDECL ocall_write_file(char* filePath, char* src, int len, int append);
sgx_status_t SGX_CDECL ocall_malloc(void** pointer, int size);
sgx_status_t SGX_CDECL ocall_free(void* pointer);
sgx_status_t SGX_CDECL ocall_del(void* pointer, int isArray);
sgx_status_t SGX_CDECL ocall_rand(int* rand_num, int mod);
sgx_status_t SGX_CDECL ocall_sfbpf_compile(int* retval, int snaplen_arg, int linktype_arg, char* program, const char* buf, int optimize, int mask);
sgx_status_t SGX_CDECL ocall_sfbpf_filter(int* retval, const char* pc, const char* p, int wirelen, int buflen);
sgx_status_t SGX_CDECL ocall_sfbpf_freecode(char* program);
sgx_status_t SGX_CDECL ocall_pcap_init(char* filename);
sgx_status_t SGX_CDECL ocall_pcap_next(char** pkt, char* pcap_pkthdr);
sgx_status_t SGX_CDECL ocall_load_config(const char* filename, char* g_config);
sgx_status_t SGX_CDECL ocall_dfc_init(char** pattern_pool, int** pattern_length, int* size);
sgx_status_t SGX_CDECL ocall_lb_etap_in(uint8_t** batch);
sgx_status_t SGX_CDECL ocall_state_store_alloc(void** store_new);
sgx_status_t SGX_CDECL ocall_state_store_free(void* item);
sgx_status_t SGX_CDECL ocall_lb_log(int round, int pkt_count, double delay, double tput, int flow);
sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL ocall_get_time(int* second, int* nanosecond);
sgx_status_t SGX_CDECL ocall_sleep(long int time_ns);
sgx_status_t SGX_CDECL ocall_random(uint32_t* r);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
