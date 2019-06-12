#include "lb_edge_u.h"
#include <errno.h>

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

static sgx_status_t SGX_CDECL lb_edge_ocall_lb_etap_in(void* pms)
{
	ms_ocall_lb_etap_in_t* ms = SGX_CAST(ms_ocall_lb_etap_in_t*, pms);
	ocall_lb_etap_in(ms->ms_batch);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL lb_edge_ocall_state_store_alloc(void* pms)
{
	ms_ocall_state_store_alloc_t* ms = SGX_CAST(ms_ocall_state_store_alloc_t*, pms);
	ocall_state_store_alloc(ms->ms_store_new);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL lb_edge_ocall_state_store_free(void* pms)
{
	ms_ocall_state_store_free_t* ms = SGX_CAST(ms_ocall_state_store_free_t*, pms);
	ocall_state_store_free(ms->ms_item);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL lb_edge_ocall_lb_log(void* pms)
{
	ms_ocall_lb_log_t* ms = SGX_CAST(ms_ocall_lb_log_t*, pms);
	ocall_lb_log(ms->ms_round, ms->ms_pkt_count, ms->ms_delay, ms->ms_tput, ms->ms_flow);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL lb_edge_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL lb_edge_ocall_get_time(void* pms)
{
	ms_ocall_get_time_t* ms = SGX_CAST(ms_ocall_get_time_t*, pms);
	ocall_get_time(ms->ms_second, ms->ms_nanosecond);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL lb_edge_ocall_sleep(void* pms)
{
	ms_ocall_sleep_t* ms = SGX_CAST(ms_ocall_sleep_t*, pms);
	ocall_sleep(ms->ms_time_ns);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL lb_edge_ocall_random(void* pms)
{
	ms_ocall_random_t* ms = SGX_CAST(ms_ocall_random_t*, pms);
	ocall_random(ms->ms_r);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[8];
} ocall_table_lb_edge = {
	8,
	{
		(void*)lb_edge_ocall_lb_etap_in,
		(void*)lb_edge_ocall_state_store_alloc,
		(void*)lb_edge_ocall_state_store_free,
		(void*)lb_edge_ocall_lb_log,
		(void*)lb_edge_ocall_print_string,
		(void*)lb_edge_ocall_get_time,
		(void*)lb_edge_ocall_sleep,
		(void*)lb_edge_ocall_random,
	}
};
sgx_status_t ecall_auth_enc(sgx_enclave_id_t eid, int* retval, uint8_t* src, int src_len, uint8_t* dst, uint8_t* mac)
{
	sgx_status_t status;
	ms_ecall_auth_enc_t ms;
	ms.ms_src = src;
	ms.ms_src_len = src_len;
	ms.ms_dst = dst;
	ms.ms_mac = mac;
	status = sgx_ecall(eid, 0, &ocall_table_lb_edge, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_init_aes_gcm(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 1, &ocall_table_lb_edge, NULL);
	return status;
}

sgx_status_t ecall_etap_start(sgx_enclave_id_t eid, double* retval, int record_size, int record_per_batch)
{
	sgx_status_t status;
	ms_ecall_etap_start_t ms;
	ms.ms_record_size = record_size;
	ms.ms_record_per_batch = record_per_batch;
	status = sgx_ecall(eid, 2, &ocall_table_lb_edge, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

