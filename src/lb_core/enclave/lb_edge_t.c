#include "lb_edge_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


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

static sgx_status_t SGX_CDECL sgx_ecall_auth_enc(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_auth_enc_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_auth_enc_t* ms = SGX_CAST(ms_ecall_auth_enc_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_src = ms->ms_src;
	uint8_t* _tmp_dst = ms->ms_dst;
	uint8_t* _tmp_mac = ms->ms_mac;



	ms->ms_retval = ecall_auth_enc(_tmp_src, ms->ms_src_len, _tmp_dst, _tmp_mac);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_init_aes_gcm(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_init_aes_gcm();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_etap_start(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_etap_start_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_etap_start_t* ms = SGX_CAST(ms_ecall_etap_start_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = ecall_etap_start(ms->ms_record_size, ms->ms_record_per_batch);


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[3];
} g_ecall_table = {
	3,
	{
		{(void*)(uintptr_t)sgx_ecall_auth_enc, 0},
		{(void*)(uintptr_t)sgx_ecall_init_aes_gcm, 0},
		{(void*)(uintptr_t)sgx_ecall_etap_start, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[8][3];
} g_dyn_entry_table = {
	8,
	{
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_lb_etap_in(uint8_t** batch)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_batch = 8;

	ms_ocall_lb_etap_in_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_lb_etap_in_t);
	void *__tmp = NULL;

	void *__tmp_batch = NULL;
	ocalloc_size += (batch != NULL && sgx_is_within_enclave(batch, _len_batch)) ? _len_batch : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_lb_etap_in_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_lb_etap_in_t));

	if (batch != NULL && sgx_is_within_enclave(batch, _len_batch)) {
		ms->ms_batch = (uint8_t**)__tmp;
		__tmp_batch = __tmp;
		memset(__tmp_batch, 0, _len_batch);
		__tmp = (void *)((size_t)__tmp + _len_batch);
	} else if (batch == NULL) {
		ms->ms_batch = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
		if (batch) memcpy((void*)batch, __tmp_batch, _len_batch);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_state_store_alloc(void** store_new)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_store_new = 8;

	ms_ocall_state_store_alloc_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_state_store_alloc_t);
	void *__tmp = NULL;

	void *__tmp_store_new = NULL;
	ocalloc_size += (store_new != NULL && sgx_is_within_enclave(store_new, _len_store_new)) ? _len_store_new : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_state_store_alloc_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_state_store_alloc_t));

	if (store_new != NULL && sgx_is_within_enclave(store_new, _len_store_new)) {
		ms->ms_store_new = (void**)__tmp;
		__tmp_store_new = __tmp;
		memset(__tmp_store_new, 0, _len_store_new);
		__tmp = (void *)((size_t)__tmp + _len_store_new);
	} else if (store_new == NULL) {
		ms->ms_store_new = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (store_new) memcpy((void*)store_new, __tmp_store_new, _len_store_new);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_state_store_free(void* item)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_state_store_free_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_state_store_free_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_state_store_free_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_state_store_free_t));

	ms->ms_item = SGX_CAST(void*, item);
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_lb_log(int round, int pkt_count, double delay, double tput, int flow)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_lb_log_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_lb_log_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_lb_log_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_lb_log_t));

	ms->ms_round = round;
	ms->ms_pkt_count = pkt_count;
	ms->ms_delay = delay;
	ms->ms_tput = tput;
	ms->ms_flow = flow;
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;

	ocalloc_size += (str != NULL && sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));

	if (str != NULL && sgx_is_within_enclave(str, _len_str)) {
		ms->ms_str = (char*)__tmp;
		memcpy(__tmp, str, _len_str);
		__tmp = (void *)((size_t)__tmp + _len_str);
	} else if (str == NULL) {
		ms->ms_str = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_get_time(int* second, int* nanosecond)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_second = 8;
	size_t _len_nanosecond = 8;

	ms_ocall_get_time_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_get_time_t);
	void *__tmp = NULL;

	void *__tmp_second = NULL;
	void *__tmp_nanosecond = NULL;
	ocalloc_size += (second != NULL && sgx_is_within_enclave(second, _len_second)) ? _len_second : 0;
	ocalloc_size += (nanosecond != NULL && sgx_is_within_enclave(nanosecond, _len_nanosecond)) ? _len_nanosecond : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_get_time_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_get_time_t));

	if (second != NULL && sgx_is_within_enclave(second, _len_second)) {
		ms->ms_second = (int*)__tmp;
		__tmp_second = __tmp;
		memset(__tmp_second, 0, _len_second);
		__tmp = (void *)((size_t)__tmp + _len_second);
	} else if (second == NULL) {
		ms->ms_second = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (nanosecond != NULL && sgx_is_within_enclave(nanosecond, _len_nanosecond)) {
		ms->ms_nanosecond = (int*)__tmp;
		__tmp_nanosecond = __tmp;
		memset(__tmp_nanosecond, 0, _len_nanosecond);
		__tmp = (void *)((size_t)__tmp + _len_nanosecond);
	} else if (nanosecond == NULL) {
		ms->ms_nanosecond = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (second) memcpy((void*)second, __tmp_second, _len_second);
		if (nanosecond) memcpy((void*)nanosecond, __tmp_nanosecond, _len_nanosecond);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sleep(long int time_ns)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sleep_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sleep_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sleep_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sleep_t));

	ms->ms_time_ns = time_ns;
	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_random(uint32_t* r)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_r = 4;

	ms_ocall_random_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_random_t);
	void *__tmp = NULL;

	void *__tmp_r = NULL;
	ocalloc_size += (r != NULL && sgx_is_within_enclave(r, _len_r)) ? _len_r : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_random_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_random_t));

	if (r != NULL && sgx_is_within_enclave(r, _len_r)) {
		ms->ms_r = (uint32_t*)__tmp;
		__tmp_r = __tmp;
		memset(__tmp_r, 0, _len_r);
		__tmp = (void *)((size_t)__tmp + _len_r);
	} else if (r == NULL) {
		ms->ms_r = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(7, ms);

	if (status == SGX_SUCCESS) {
		if (r) memcpy((void*)r, __tmp_r, _len_r);
	}
	sgx_ocfree();
	return status;
}

