#include "prads_u.h"
#include <errno.h>

typedef struct ms_ecall_prads_initialize_t {
	int ms_retval;
	void* ms_global_config;
	int ms__nets;
	void* ms__network;
	void* ms__os_asset_pool;
	void* ms__serv_asset_pool;
	void* ms__asset_pool;
} ms_ecall_prads_initialize_t;

typedef struct ms_ecall_prads_cxtrackerid_t {
	uint64_t ms_retval;
} ms_ecall_prads_cxtrackerid_t;

typedef struct ms_ecall_secure_ferry_t {
	void* ms_pheader;
	void* ms_packet;
	int ms_ferry_len;
	int ms_ferry_unit;
	uint8_t* ms_ferry_mac;
	int* ms_miss_count;
	int* ms_bundle_count;
	int* ms_state_count;
} ms_ecall_secure_ferry_t;

typedef struct ms_ecall_naive_process_t {
	void* ms_pheader;
	void* ms_packet;
	int ms_packet_len;
	uint8_t* ms_mac;
	int* ms_state_count;
} ms_ecall_naive_process_t;

typedef struct ms_ecall_auth_enc_t {
	int ms_retval;
	uint8_t* ms_src;
	int ms_src_len;
	uint8_t* ms_dst;
	uint8_t* ms_mac;
} ms_ecall_auth_enc_t;

typedef struct ms_ecall_sync_expiration_t {
	int ms_expired_state_count;
} ms_ecall_sync_expiration_t;

typedef struct ms_ecall_check_expiration_t {
	long int ms_wall_time;
} ms_ecall_check_expiration_t;

typedef struct ms_ecall_log_flush_timeout_t {
	void* ms_out_buffer;
	int ms_buf_len;
} ms_ecall_log_flush_timeout_t;

typedef struct ms_ecall_etap_start_t {
	double ms_retval;
	int ms_record_size;
	int ms_record_per_batch;
} ms_ecall_etap_start_t;

typedef struct ms_ecall_lb_prads_init_t {
	void* ms_global_config;
	int ms__nets;
	void* ms__network;
	void* ms__os_asset_pool;
	void* ms__serv_asset_pool;
	void* ms__asset_pool;
} ms_ecall_lb_prads_init_t;

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

typedef struct ms_ocall_secure_state_swap_t {
	void* ms__bundled_state;
	void* ms__bundled_id;
	int* ms_is_server;
	int ms_bundle_size;
} ms_ocall_secure_state_swap_t;

typedef struct ms_ocall_calloc_t {
	void* ms_retval;
	int ms_size;
} ms_ocall_calloc_t;

typedef struct ms_ocall_free_t {
	void* ms_ptr;
} ms_ocall_free_t;

typedef struct ms_ocall_log_flush_full_t {
	void* ms_buffer;
	int ms_buf_len;
} ms_ocall_log_flush_full_t;

typedef struct ms_ocall_lb_etap_in_t {
	uint8_t** ms_batch;
} ms_ocall_lb_etap_in_t;

typedef struct ms_ocall_state_store_alloc_t {
	void** ms_store_new;
} ms_ocall_state_store_alloc_t;

typedef struct ms_ocall_state_store_free_t {
	void* ms_item;
} ms_ocall_state_store_free_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

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

static sgx_status_t SGX_CDECL prads_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL prads_ocall_get_time(void* pms)
{
	ms_ocall_get_time_t* ms = SGX_CAST(ms_ocall_get_time_t*, pms);
	ocall_get_time(ms->ms_second, ms->ms_nanosecond);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL prads_ocall_sleep(void* pms)
{
	ms_ocall_sleep_t* ms = SGX_CAST(ms_ocall_sleep_t*, pms);
	ocall_sleep(ms->ms_time_ns);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL prads_ocall_random(void* pms)
{
	ms_ocall_random_t* ms = SGX_CAST(ms_ocall_random_t*, pms);
	ocall_random(ms->ms_r);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL prads_ocall_secure_state_swap(void* pms)
{
	ms_ocall_secure_state_swap_t* ms = SGX_CAST(ms_ocall_secure_state_swap_t*, pms);
	ocall_secure_state_swap(ms->ms__bundled_state, ms->ms__bundled_id, ms->ms_is_server, ms->ms_bundle_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL prads_ocall_calloc(void* pms)
{
	ms_ocall_calloc_t* ms = SGX_CAST(ms_ocall_calloc_t*, pms);
	ms->ms_retval = ocall_calloc(ms->ms_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL prads_ocall_free(void* pms)
{
	ms_ocall_free_t* ms = SGX_CAST(ms_ocall_free_t*, pms);
	ocall_free(ms->ms_ptr);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL prads_ocall_log_flush_full(void* pms)
{
	ms_ocall_log_flush_full_t* ms = SGX_CAST(ms_ocall_log_flush_full_t*, pms);
	ocall_log_flush_full(ms->ms_buffer, ms->ms_buf_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL prads_ocall_lb_etap_in(void* pms)
{
	ms_ocall_lb_etap_in_t* ms = SGX_CAST(ms_ocall_lb_etap_in_t*, pms);
	ocall_lb_etap_in(ms->ms_batch);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL prads_ocall_state_store_alloc(void* pms)
{
	ms_ocall_state_store_alloc_t* ms = SGX_CAST(ms_ocall_state_store_alloc_t*, pms);
	ocall_state_store_alloc(ms->ms_store_new);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL prads_ocall_state_store_free(void* pms)
{
	ms_ocall_state_store_free_t* ms = SGX_CAST(ms_ocall_state_store_free_t*, pms);
	ocall_state_store_free(ms->ms_item);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL prads_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL prads_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall((const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL prads_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall((const void*)ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL prads_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall((const void*)ms->ms_waiter, (const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL prads_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall((const void**)ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[16];
} ocall_table_prads = {
	16,
	{
		(void*)prads_ocall_print_string,
		(void*)prads_ocall_get_time,
		(void*)prads_ocall_sleep,
		(void*)prads_ocall_random,
		(void*)prads_ocall_secure_state_swap,
		(void*)prads_ocall_calloc,
		(void*)prads_ocall_free,
		(void*)prads_ocall_log_flush_full,
		(void*)prads_ocall_lb_etap_in,
		(void*)prads_ocall_state_store_alloc,
		(void*)prads_ocall_state_store_free,
		(void*)prads_sgx_oc_cpuidex,
		(void*)prads_sgx_thread_wait_untrusted_event_ocall,
		(void*)prads_sgx_thread_set_untrusted_event_ocall,
		(void*)prads_sgx_thread_setwait_untrusted_events_ocall,
		(void*)prads_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t ecall_prads_initialize(sgx_enclave_id_t eid, int* retval, void* global_config, int _nets, void* _network, void* _os_asset_pool, void* _serv_asset_pool, void* _asset_pool)
{
	sgx_status_t status;
	ms_ecall_prads_initialize_t ms;
	ms.ms_global_config = global_config;
	ms.ms__nets = _nets;
	ms.ms__network = _network;
	ms.ms__os_asset_pool = _os_asset_pool;
	ms.ms__serv_asset_pool = _serv_asset_pool;
	ms.ms__asset_pool = _asset_pool;
	status = sgx_ecall(eid, 0, &ocall_table_prads, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_prads_gameover(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 1, &ocall_table_prads, NULL);
	return status;
}

sgx_status_t ecall_prads_cxtrackerid(sgx_enclave_id_t eid, uint64_t* retval)
{
	sgx_status_t status;
	ms_ecall_prads_cxtrackerid_t ms;
	status = sgx_ecall(eid, 2, &ocall_table_prads, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_secure_ferry(sgx_enclave_id_t eid, void* pheader, void* packet, int ferry_len, int ferry_unit, uint8_t* ferry_mac, int* miss_count, int* bundle_count, int* state_count)
{
	sgx_status_t status;
	ms_ecall_secure_ferry_t ms;
	ms.ms_pheader = pheader;
	ms.ms_packet = packet;
	ms.ms_ferry_len = ferry_len;
	ms.ms_ferry_unit = ferry_unit;
	ms.ms_ferry_mac = ferry_mac;
	ms.ms_miss_count = miss_count;
	ms.ms_bundle_count = bundle_count;
	ms.ms_state_count = state_count;
	status = sgx_ecall(eid, 3, &ocall_table_prads, &ms);
	return status;
}

sgx_status_t ecall_naive_process(sgx_enclave_id_t eid, void* pheader, void* packet, int packet_len, uint8_t* mac, int* state_count)
{
	sgx_status_t status;
	ms_ecall_naive_process_t ms;
	ms.ms_pheader = pheader;
	ms.ms_packet = packet;
	ms.ms_packet_len = packet_len;
	ms.ms_mac = mac;
	ms.ms_state_count = state_count;
	status = sgx_ecall(eid, 4, &ocall_table_prads, &ms);
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
	status = sgx_ecall(eid, 5, &ocall_table_prads, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_sync_expiration(sgx_enclave_id_t eid, int expired_state_count)
{
	sgx_status_t status;
	ms_ecall_sync_expiration_t ms;
	ms.ms_expired_state_count = expired_state_count;
	status = sgx_ecall(eid, 6, &ocall_table_prads, &ms);
	return status;
}

sgx_status_t ecall_check_expiration(sgx_enclave_id_t eid, long int wall_time)
{
	sgx_status_t status;
	ms_ecall_check_expiration_t ms;
	ms.ms_wall_time = wall_time;
	status = sgx_ecall(eid, 7, &ocall_table_prads, &ms);
	return status;
}

sgx_status_t ecall_log_flush_timeout(sgx_enclave_id_t eid, void* out_buffer, int buf_len)
{
	sgx_status_t status;
	ms_ecall_log_flush_timeout_t ms;
	ms.ms_out_buffer = out_buffer;
	ms.ms_buf_len = buf_len;
	status = sgx_ecall(eid, 8, &ocall_table_prads, &ms);
	return status;
}

sgx_status_t ecall_init_aes_gcm(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 9, &ocall_table_prads, NULL);
	return status;
}

sgx_status_t ecall_test_mb(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 10, &ocall_table_prads, NULL);
	return status;
}

sgx_status_t ecall_etap_start(sgx_enclave_id_t eid, double* retval, int record_size, int record_per_batch)
{
	sgx_status_t status;
	ms_ecall_etap_start_t ms;
	ms.ms_record_size = record_size;
	ms.ms_record_per_batch = record_per_batch;
	status = sgx_ecall(eid, 11, &ocall_table_prads, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_state_test(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 12, &ocall_table_prads, NULL);
	return status;
}

sgx_status_t ecall_lb_prads_init(sgx_enclave_id_t eid, void* global_config, int _nets, void* _network, void* _os_asset_pool, void* _serv_asset_pool, void* _asset_pool)
{
	sgx_status_t status;
	ms_ecall_lb_prads_init_t ms;
	ms.ms_global_config = global_config;
	ms.ms__nets = _nets;
	ms.ms__network = _network;
	ms.ms__os_asset_pool = _os_asset_pool;
	ms.ms__serv_asset_pool = _serv_asset_pool;
	ms.ms__asset_pool = _asset_pool;
	status = sgx_ecall(eid, 13, &ocall_table_prads, &ms);
	return status;
}

sgx_status_t ecall_lb_prads_run(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 14, &ocall_table_prads, NULL);
	return status;
}

