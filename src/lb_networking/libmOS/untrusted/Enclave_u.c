#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_mos_test_t {
	char* ms_config_file_path;
	size_t ms_config_file_path_len;
} ms_ecall_mos_test_t;

typedef struct ms_ecall_auth_enc_t {
	int ms_retval;
	uint8_t* ms_src;
	int ms_src_len;
	uint8_t* ms_dst;
	uint8_t* ms_mac;
} ms_ecall_auth_enc_t;

typedef struct ms_ecall_etap_start_t {
	double ms_retval;
	int ms_record_size;
	int ms_record_per_batch;
} ms_ecall_etap_start_t;

typedef struct ms_ocall_print_string2_t {
	char* ms_str;
} ms_ocall_print_string2_t;

typedef struct ms_ocall_get_time2_t {
	int* ms_second;
	int* ms_nanosecond;
} ms_ocall_get_time2_t;

typedef struct ms_ocall_get_data_t {
	int ms_data_id;
	char** ms_val;
	int* ms_len;
} ms_ocall_get_data_t;

typedef struct ms_ocall_read_dir_t {
	char* ms_dirPaht;
	char** ms_allFiles;
	int* ms_fileCount;
	int ms_subfile;
} ms_ocall_read_dir_t;

typedef struct ms_ocall_file_size_t {
	char* ms_filePath;
	int* ms_len;
} ms_ocall_file_size_t;

typedef struct ms_ocall_read_file_t {
	char* ms_filePath;
	char** ms_out;
	int* ms_len;
	int ms_pos;
} ms_ocall_read_file_t;

typedef struct ms_ocall_write_file_t {
	char* ms_filePath;
	char* ms_src;
	int ms_len;
	int ms_append;
} ms_ocall_write_file_t;

typedef struct ms_ocall_malloc_t {
	void** ms_pointer;
	int ms_size;
} ms_ocall_malloc_t;

typedef struct ms_ocall_free_t {
	void* ms_pointer;
} ms_ocall_free_t;

typedef struct ms_ocall_del_t {
	void* ms_pointer;
	int ms_isArray;
} ms_ocall_del_t;

typedef struct ms_ocall_rand_t {
	int* ms_rand_num;
	int ms_mod;
} ms_ocall_rand_t;

typedef struct ms_ocall_sfbpf_compile_t {
	int ms_retval;
	int ms_snaplen_arg;
	int ms_linktype_arg;
	char* ms_program;
	char* ms_buf;
	int ms_optimize;
	int ms_mask;
} ms_ocall_sfbpf_compile_t;

typedef struct ms_ocall_sfbpf_filter_t {
	int ms_retval;
	char* ms_pc;
	char* ms_p;
	int ms_wirelen;
	int ms_buflen;
} ms_ocall_sfbpf_filter_t;

typedef struct ms_ocall_sfbpf_freecode_t {
	char* ms_program;
} ms_ocall_sfbpf_freecode_t;

typedef struct ms_ocall_pcap_init_t {
	char* ms_filename;
} ms_ocall_pcap_init_t;

typedef struct ms_ocall_pcap_next_t {
	char** ms_pkt;
	char* ms_pcap_pkthdr;
} ms_ocall_pcap_next_t;

typedef struct ms_ocall_load_config_t {
	char* ms_filename;
	char* ms_g_config;
} ms_ocall_load_config_t;

typedef struct ms_ocall_dfc_init_t {
	char** ms_pattern_pool;
	int** ms_pattern_length;
	int* ms_size;
} ms_ocall_dfc_init_t;

typedef struct ms_ocall_lb_etap_in_t {
	uint8_t** ms_batch;
} ms_ocall_lb_etap_in_t;

typedef struct ms_ocall_state_store_alloc_t {
	void** ms_store_new;
} ms_ocall_state_store_alloc_t;

typedef struct ms_ocall_state_store_free_t {
	void* ms_item;
} ms_ocall_state_store_free_t;

typedef struct ms_ocall_lb_log_t {
	int ms_round;
	int ms_pkt_count;
	double ms_delay;
	double ms_tput;
	int ms_flow;
} ms_ocall_lb_log_t;

typedef struct ms_ocall_print_string_t {
	char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_get_time_t {
	int* ms_second;
	int* ms_nanosecond;
} ms_ocall_get_time_t;

typedef struct ms_ocall_sleep_t {
	long int ms_time_ns;
} ms_ocall_sleep_t;

typedef struct ms_ocall_random_t {
	uint32_t* ms_r;
} ms_ocall_random_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	void* ms_waiter;
	void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL Enclave_ocall_print_string2(void* pms)
{
	ms_ocall_print_string2_t* ms = SGX_CAST(ms_ocall_print_string2_t*, pms);
	ocall_print_string2((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_get_time2(void* pms)
{
	ms_ocall_get_time2_t* ms = SGX_CAST(ms_ocall_get_time2_t*, pms);
	ocall_get_time2(ms->ms_second, ms->ms_nanosecond);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_get_data(void* pms)
{
	ms_ocall_get_data_t* ms = SGX_CAST(ms_ocall_get_data_t*, pms);
	ocall_get_data(ms->ms_data_id, ms->ms_val, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_read_dir(void* pms)
{
	ms_ocall_read_dir_t* ms = SGX_CAST(ms_ocall_read_dir_t*, pms);
	ocall_read_dir(ms->ms_dirPaht, ms->ms_allFiles, ms->ms_fileCount, ms->ms_subfile);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_file_size(void* pms)
{
	ms_ocall_file_size_t* ms = SGX_CAST(ms_ocall_file_size_t*, pms);
	ocall_file_size(ms->ms_filePath, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_read_file(void* pms)
{
	ms_ocall_read_file_t* ms = SGX_CAST(ms_ocall_read_file_t*, pms);
	ocall_read_file(ms->ms_filePath, ms->ms_out, ms->ms_len, ms->ms_pos);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_write_file(void* pms)
{
	ms_ocall_write_file_t* ms = SGX_CAST(ms_ocall_write_file_t*, pms);
	ocall_write_file(ms->ms_filePath, ms->ms_src, ms->ms_len, ms->ms_append);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_malloc(void* pms)
{
	ms_ocall_malloc_t* ms = SGX_CAST(ms_ocall_malloc_t*, pms);
	ocall_malloc(ms->ms_pointer, ms->ms_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_free(void* pms)
{
	ms_ocall_free_t* ms = SGX_CAST(ms_ocall_free_t*, pms);
	ocall_free(ms->ms_pointer);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_del(void* pms)
{
	ms_ocall_del_t* ms = SGX_CAST(ms_ocall_del_t*, pms);
	ocall_del(ms->ms_pointer, ms->ms_isArray);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_rand(void* pms)
{
	ms_ocall_rand_t* ms = SGX_CAST(ms_ocall_rand_t*, pms);
	ocall_rand(ms->ms_rand_num, ms->ms_mod);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sfbpf_compile(void* pms)
{
	ms_ocall_sfbpf_compile_t* ms = SGX_CAST(ms_ocall_sfbpf_compile_t*, pms);
	ms->ms_retval = ocall_sfbpf_compile(ms->ms_snaplen_arg, ms->ms_linktype_arg, ms->ms_program, (const char*)ms->ms_buf, ms->ms_optimize, ms->ms_mask);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sfbpf_filter(void* pms)
{
	ms_ocall_sfbpf_filter_t* ms = SGX_CAST(ms_ocall_sfbpf_filter_t*, pms);
	ms->ms_retval = ocall_sfbpf_filter((const char*)ms->ms_pc, (const char*)ms->ms_p, ms->ms_wirelen, ms->ms_buflen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sfbpf_freecode(void* pms)
{
	ms_ocall_sfbpf_freecode_t* ms = SGX_CAST(ms_ocall_sfbpf_freecode_t*, pms);
	ocall_sfbpf_freecode(ms->ms_program);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pcap_init(void* pms)
{
	ms_ocall_pcap_init_t* ms = SGX_CAST(ms_ocall_pcap_init_t*, pms);
	ocall_pcap_init(ms->ms_filename);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pcap_next(void* pms)
{
	ms_ocall_pcap_next_t* ms = SGX_CAST(ms_ocall_pcap_next_t*, pms);
	ocall_pcap_next(ms->ms_pkt, ms->ms_pcap_pkthdr);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_load_config(void* pms)
{
	ms_ocall_load_config_t* ms = SGX_CAST(ms_ocall_load_config_t*, pms);
	ocall_load_config((const char*)ms->ms_filename, ms->ms_g_config);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_dfc_init(void* pms)
{
	ms_ocall_dfc_init_t* ms = SGX_CAST(ms_ocall_dfc_init_t*, pms);
	ocall_dfc_init(ms->ms_pattern_pool, ms->ms_pattern_length, ms->ms_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_lb_etap_in(void* pms)
{
	ms_ocall_lb_etap_in_t* ms = SGX_CAST(ms_ocall_lb_etap_in_t*, pms);
	ocall_lb_etap_in(ms->ms_batch);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_state_store_alloc(void* pms)
{
	ms_ocall_state_store_alloc_t* ms = SGX_CAST(ms_ocall_state_store_alloc_t*, pms);
	ocall_state_store_alloc(ms->ms_store_new);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_state_store_free(void* pms)
{
	ms_ocall_state_store_free_t* ms = SGX_CAST(ms_ocall_state_store_free_t*, pms);
	ocall_state_store_free(ms->ms_item);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_lb_log(void* pms)
{
	ms_ocall_lb_log_t* ms = SGX_CAST(ms_ocall_lb_log_t*, pms);
	ocall_lb_log(ms->ms_round, ms->ms_pkt_count, ms->ms_delay, ms->ms_tput, ms->ms_flow);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_get_time(void* pms)
{
	ms_ocall_get_time_t* ms = SGX_CAST(ms_ocall_get_time_t*, pms);
	ocall_get_time(ms->ms_second, ms->ms_nanosecond);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sleep(void* pms)
{
	ms_ocall_sleep_t* ms = SGX_CAST(ms_ocall_sleep_t*, pms);
	ocall_sleep(ms->ms_time_ns);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_random(void* pms)
{
	ms_ocall_random_t* ms = SGX_CAST(ms_ocall_random_t*, pms);
	ocall_random(ms->ms_r);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall((const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall((const void*)ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall((const void*)ms->ms_waiter, (const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall((const void**)ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[30];
} ocall_table_Enclave = {
	30,
	{
		(void*)Enclave_ocall_print_string2,
		(void*)Enclave_ocall_get_time2,
		(void*)Enclave_ocall_get_data,
		(void*)Enclave_ocall_read_dir,
		(void*)Enclave_ocall_file_size,
		(void*)Enclave_ocall_read_file,
		(void*)Enclave_ocall_write_file,
		(void*)Enclave_ocall_malloc,
		(void*)Enclave_ocall_free,
		(void*)Enclave_ocall_del,
		(void*)Enclave_ocall_rand,
		(void*)Enclave_ocall_sfbpf_compile,
		(void*)Enclave_ocall_sfbpf_filter,
		(void*)Enclave_ocall_sfbpf_freecode,
		(void*)Enclave_ocall_pcap_init,
		(void*)Enclave_ocall_pcap_next,
		(void*)Enclave_ocall_load_config,
		(void*)Enclave_ocall_dfc_init,
		(void*)Enclave_ocall_lb_etap_in,
		(void*)Enclave_ocall_state_store_alloc,
		(void*)Enclave_ocall_state_store_free,
		(void*)Enclave_ocall_lb_log,
		(void*)Enclave_ocall_print_string,
		(void*)Enclave_ocall_get_time,
		(void*)Enclave_ocall_sleep,
		(void*)Enclave_ocall_random,
		(void*)Enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)Enclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t ecall_test(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_mos_test(sgx_enclave_id_t eid, const char* config_file_path)
{
	sgx_status_t status;
	ms_ecall_mos_test_t ms;
	ms.ms_config_file_path = (char*)config_file_path;
	ms.ms_config_file_path_len = config_file_path ? strlen(config_file_path) + 1 : 0;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_auth_enc(sgx_enclave_id_t eid, int* retval, uint8_t* src, int src_len, uint8_t* dst, uint8_t* mac)
{
	sgx_status_t status;
	ms_ecall_auth_enc_t ms;
	ms.ms_src = src;
	ms.ms_src_len = src_len;
	ms.ms_dst = dst;
	ms.ms_mac = mac;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_init_aes_gcm(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_etap_start(sgx_enclave_id_t eid, double* retval, int record_size, int record_per_batch)
{
	sgx_status_t status;
	ms_ecall_etap_start_t ms;
	ms.ms_record_size = record_size;
	ms.ms_record_per_batch = record_per_batch;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

