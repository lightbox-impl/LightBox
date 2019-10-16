#include "prads_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

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

static sgx_status_t SGX_CDECL sgx_ecall_prads_initialize(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_prads_initialize_t));
	ms_ecall_prads_initialize_t* ms = SGX_CAST(ms_ecall_prads_initialize_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_global_config = ms->ms_global_config;
	void* _tmp__network = ms->ms__network;
	void* _tmp__os_asset_pool = ms->ms__os_asset_pool;
	void* _tmp__serv_asset_pool = ms->ms__serv_asset_pool;
	void* _tmp__asset_pool = ms->ms__asset_pool;


	ms->ms_retval = ecall_prads_initialize(_tmp_global_config, ms->ms__nets, _tmp__network, _tmp__os_asset_pool, _tmp__serv_asset_pool, _tmp__asset_pool);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_prads_gameover(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_prads_gameover();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_prads_cxtrackerid(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_prads_cxtrackerid_t));
	ms_ecall_prads_cxtrackerid_t* ms = SGX_CAST(ms_ecall_prads_cxtrackerid_t*, pms);
	sgx_status_t status = SGX_SUCCESS;


	ms->ms_retval = ecall_prads_cxtrackerid();


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_secure_ferry(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_secure_ferry_t));
	ms_ecall_secure_ferry_t* ms = SGX_CAST(ms_ecall_secure_ferry_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_pheader = ms->ms_pheader;
	void* _tmp_packet = ms->ms_packet;
	uint8_t* _tmp_ferry_mac = ms->ms_ferry_mac;
	size_t _len_ferry_mac = 16;
	uint8_t* _in_ferry_mac = NULL;
	int* _tmp_miss_count = ms->ms_miss_count;
	size_t _len_miss_count = 4;
	int* _in_miss_count = NULL;
	int* _tmp_bundle_count = ms->ms_bundle_count;
	size_t _len_bundle_count = 4;
	int* _in_bundle_count = NULL;
	int* _tmp_state_count = ms->ms_state_count;
	size_t _len_state_count = 4;
	int* _in_state_count = NULL;

	CHECK_UNIQUE_POINTER(_tmp_ferry_mac, _len_ferry_mac);
	CHECK_UNIQUE_POINTER(_tmp_miss_count, _len_miss_count);
	CHECK_UNIQUE_POINTER(_tmp_bundle_count, _len_bundle_count);
	CHECK_UNIQUE_POINTER(_tmp_state_count, _len_state_count);

	if (_tmp_ferry_mac != NULL && _len_ferry_mac != 0) {
		_in_ferry_mac = (uint8_t*)malloc(_len_ferry_mac);
		if (_in_ferry_mac == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_ferry_mac, _tmp_ferry_mac, _len_ferry_mac);
	}
	if (_tmp_miss_count != NULL && _len_miss_count != 0) {
		if ((_in_miss_count = (int*)malloc(_len_miss_count)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_miss_count, 0, _len_miss_count);
	}
	if (_tmp_bundle_count != NULL && _len_bundle_count != 0) {
		if ((_in_bundle_count = (int*)malloc(_len_bundle_count)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_bundle_count, 0, _len_bundle_count);
	}
	if (_tmp_state_count != NULL && _len_state_count != 0) {
		if ((_in_state_count = (int*)malloc(_len_state_count)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_state_count, 0, _len_state_count);
	}
	ecall_secure_ferry(_tmp_pheader, _tmp_packet, ms->ms_ferry_len, ms->ms_ferry_unit, _in_ferry_mac, _in_miss_count, _in_bundle_count, _in_state_count);
err:
	if (_in_ferry_mac) free(_in_ferry_mac);
	if (_in_miss_count) {
		memcpy(_tmp_miss_count, _in_miss_count, _len_miss_count);
		free(_in_miss_count);
	}
	if (_in_bundle_count) {
		memcpy(_tmp_bundle_count, _in_bundle_count, _len_bundle_count);
		free(_in_bundle_count);
	}
	if (_in_state_count) {
		memcpy(_tmp_state_count, _in_state_count, _len_state_count);
		free(_in_state_count);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_naive_process(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_naive_process_t));
	ms_ecall_naive_process_t* ms = SGX_CAST(ms_ecall_naive_process_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_pheader = ms->ms_pheader;
	void* _tmp_packet = ms->ms_packet;
	uint8_t* _tmp_mac = ms->ms_mac;
	size_t _len_mac = 16;
	uint8_t* _in_mac = NULL;
	int* _tmp_state_count = ms->ms_state_count;
	size_t _len_state_count = 4;
	int* _in_state_count = NULL;

	CHECK_UNIQUE_POINTER(_tmp_mac, _len_mac);
	CHECK_UNIQUE_POINTER(_tmp_state_count, _len_state_count);

	if (_tmp_mac != NULL && _len_mac != 0) {
		_in_mac = (uint8_t*)malloc(_len_mac);
		if (_in_mac == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_mac, _tmp_mac, _len_mac);
	}
	if (_tmp_state_count != NULL && _len_state_count != 0) {
		if ((_in_state_count = (int*)malloc(_len_state_count)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_state_count, 0, _len_state_count);
	}
	ecall_naive_process(_tmp_pheader, _tmp_packet, ms->ms_packet_len, _in_mac, _in_state_count);
err:
	if (_in_mac) free(_in_mac);
	if (_in_state_count) {
		memcpy(_tmp_state_count, _in_state_count, _len_state_count);
		free(_in_state_count);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_auth_enc(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_auth_enc_t));
	ms_ecall_auth_enc_t* ms = SGX_CAST(ms_ecall_auth_enc_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_src = ms->ms_src;
	uint8_t* _tmp_dst = ms->ms_dst;
	uint8_t* _tmp_mac = ms->ms_mac;


	ms->ms_retval = ecall_auth_enc(_tmp_src, ms->ms_src_len, _tmp_dst, _tmp_mac);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_sync_expiration(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_sync_expiration_t));
	ms_ecall_sync_expiration_t* ms = SGX_CAST(ms_ecall_sync_expiration_t*, pms);
	sgx_status_t status = SGX_SUCCESS;


	ecall_sync_expiration(ms->ms_expired_state_count);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_check_expiration(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_check_expiration_t));
	ms_ecall_check_expiration_t* ms = SGX_CAST(ms_ecall_check_expiration_t*, pms);
	sgx_status_t status = SGX_SUCCESS;


	ecall_check_expiration(ms->ms_wall_time);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_log_flush_timeout(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_log_flush_timeout_t));
	ms_ecall_log_flush_timeout_t* ms = SGX_CAST(ms_ecall_log_flush_timeout_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_out_buffer = ms->ms_out_buffer;
	int _tmp_buf_len = ms->ms_buf_len;
	size_t _len_out_buffer = _tmp_buf_len;
	void* _in_out_buffer = NULL;

	CHECK_UNIQUE_POINTER(_tmp_out_buffer, _len_out_buffer);

	if (_tmp_out_buffer != NULL && _len_out_buffer != 0) {
		if ((_in_out_buffer = (void*)malloc(_len_out_buffer)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_out_buffer, 0, _len_out_buffer);
	}
	ecall_log_flush_timeout(_in_out_buffer, _tmp_buf_len);
err:
	if (_in_out_buffer) {
		memcpy(_tmp_out_buffer, _in_out_buffer, _len_out_buffer);
		free(_in_out_buffer);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_init_aes_gcm(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_init_aes_gcm();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_test_mb(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_test_mb();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_etap_start(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_etap_start_t));
	ms_ecall_etap_start_t* ms = SGX_CAST(ms_ecall_etap_start_t*, pms);
	sgx_status_t status = SGX_SUCCESS;


	ms->ms_retval = ecall_etap_start(ms->ms_record_size, ms->ms_record_per_batch);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_state_test(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_state_test();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_lb_prads_init(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_lb_prads_init_t));
	ms_ecall_lb_prads_init_t* ms = SGX_CAST(ms_ecall_lb_prads_init_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_global_config = ms->ms_global_config;
	void* _tmp__network = ms->ms__network;
	void* _tmp__os_asset_pool = ms->ms__os_asset_pool;
	void* _tmp__serv_asset_pool = ms->ms__serv_asset_pool;
	void* _tmp__asset_pool = ms->ms__asset_pool;


	ecall_lb_prads_init(_tmp_global_config, ms->ms__nets, _tmp__network, _tmp__os_asset_pool, _tmp__serv_asset_pool, _tmp__asset_pool);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_lb_prads_run(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_lb_prads_run();
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[15];
} g_ecall_table = {
	15,
	{
		{(void*)(uintptr_t)sgx_ecall_prads_initialize, 0},
		{(void*)(uintptr_t)sgx_ecall_prads_gameover, 0},
		{(void*)(uintptr_t)sgx_ecall_prads_cxtrackerid, 0},
		{(void*)(uintptr_t)sgx_ecall_secure_ferry, 0},
		{(void*)(uintptr_t)sgx_ecall_naive_process, 0},
		{(void*)(uintptr_t)sgx_ecall_auth_enc, 0},
		{(void*)(uintptr_t)sgx_ecall_sync_expiration, 0},
		{(void*)(uintptr_t)sgx_ecall_check_expiration, 0},
		{(void*)(uintptr_t)sgx_ecall_log_flush_timeout, 0},
		{(void*)(uintptr_t)sgx_ecall_init_aes_gcm, 0},
		{(void*)(uintptr_t)sgx_ecall_test_mb, 0},
		{(void*)(uintptr_t)sgx_ecall_etap_start, 0},
		{(void*)(uintptr_t)sgx_ecall_state_test, 0},
		{(void*)(uintptr_t)sgx_ecall_lb_prads_init, 0},
		{(void*)(uintptr_t)sgx_ecall_lb_prads_run, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[16][15];
} g_dyn_entry_table = {
	16,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


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
		__tmp = (void *)((size_t)__tmp + _len_str);
		memcpy((void*)ms->ms_str, str, _len_str);
	} else if (str == NULL) {
		ms->ms_str = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(0, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_get_time(int* second, int* nanosecond)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_second = 4;
	size_t _len_nanosecond = 4;

	ms_ocall_get_time_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_get_time_t);
	void *__tmp = NULL;

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
		__tmp = (void *)((size_t)__tmp + _len_second);
		memset(ms->ms_second, 0, _len_second);
	} else if (second == NULL) {
		ms->ms_second = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (nanosecond != NULL && sgx_is_within_enclave(nanosecond, _len_nanosecond)) {
		ms->ms_nanosecond = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_nanosecond);
		memset(ms->ms_nanosecond, 0, _len_nanosecond);
	} else if (nanosecond == NULL) {
		ms->ms_nanosecond = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(1, ms);

	if (second) memcpy((void*)second, ms->ms_second, _len_second);
	if (nanosecond) memcpy((void*)nanosecond, ms->ms_nanosecond, _len_nanosecond);

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
	status = sgx_ocall(2, ms);


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
		__tmp = (void *)((size_t)__tmp + _len_r);
		memset(ms->ms_r, 0, _len_r);
	} else if (r == NULL) {
		ms->ms_r = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(3, ms);

	if (r) memcpy((void*)r, ms->ms_r, _len_r);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_secure_state_swap(void* _bundled_state, void* _bundled_id, int* is_server, int bundle_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len__bundled_state = bundle_size * 512;
	size_t _len__bundled_id = bundle_size * 16;
	size_t _len_is_server = bundle_size * 4;

	ms_ocall_secure_state_swap_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_secure_state_swap_t);
	void *__tmp = NULL;

	ocalloc_size += (_bundled_state != NULL && sgx_is_within_enclave(_bundled_state, _len__bundled_state)) ? _len__bundled_state : 0;
	ocalloc_size += (_bundled_id != NULL && sgx_is_within_enclave(_bundled_id, _len__bundled_id)) ? _len__bundled_id : 0;
	ocalloc_size += (is_server != NULL && sgx_is_within_enclave(is_server, _len_is_server)) ? _len_is_server : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_secure_state_swap_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_secure_state_swap_t));

	if (_bundled_state != NULL && sgx_is_within_enclave(_bundled_state, _len__bundled_state)) {
		ms->ms__bundled_state = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len__bundled_state);
		memcpy(ms->ms__bundled_state, _bundled_state, _len__bundled_state);
	} else if (_bundled_state == NULL) {
		ms->ms__bundled_state = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (_bundled_id != NULL && sgx_is_within_enclave(_bundled_id, _len__bundled_id)) {
		ms->ms__bundled_id = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len__bundled_id);
		memcpy(ms->ms__bundled_id, _bundled_id, _len__bundled_id);
	} else if (_bundled_id == NULL) {
		ms->ms__bundled_id = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (is_server != NULL && sgx_is_within_enclave(is_server, _len_is_server)) {
		ms->ms_is_server = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_is_server);
		memset(ms->ms_is_server, 0, _len_is_server);
	} else if (is_server == NULL) {
		ms->ms_is_server = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_bundle_size = bundle_size;
	status = sgx_ocall(4, ms);

	if (_bundled_state) memcpy((void*)_bundled_state, ms->ms__bundled_state, _len__bundled_state);
	if (is_server) memcpy((void*)is_server, ms->ms_is_server, _len_is_server);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_calloc(void** retval, int size)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_calloc_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_calloc_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_calloc_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_calloc_t));

	ms->ms_size = size;
	status = sgx_ocall(5, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_free(void* ptr)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_free_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_free_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_free_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_free_t));

	ms->ms_ptr = SGX_CAST(void*, ptr);
	status = sgx_ocall(6, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_log_flush_full(void* buffer, int buf_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buffer = buf_len;

	ms_ocall_log_flush_full_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_log_flush_full_t);
	void *__tmp = NULL;

	ocalloc_size += (buffer != NULL && sgx_is_within_enclave(buffer, _len_buffer)) ? _len_buffer : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_log_flush_full_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_log_flush_full_t));

	if (buffer != NULL && sgx_is_within_enclave(buffer, _len_buffer)) {
		ms->ms_buffer = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buffer);
		memcpy(ms->ms_buffer, buffer, _len_buffer);
	} else if (buffer == NULL) {
		ms->ms_buffer = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_buf_len = buf_len;
	status = sgx_ocall(7, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_lb_etap_in(uint8_t** batch)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_batch = 8;

	ms_ocall_lb_etap_in_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_lb_etap_in_t);
	void *__tmp = NULL;

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
		__tmp = (void *)((size_t)__tmp + _len_batch);
		memset(ms->ms_batch, 0, _len_batch);
	} else if (batch == NULL) {
		ms->ms_batch = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(8, ms);

	if (batch) memcpy((void*)batch, ms->ms_batch, _len_batch);

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
		__tmp = (void *)((size_t)__tmp + _len_store_new);
		memset(ms->ms_store_new, 0, _len_store_new);
	} else if (store_new == NULL) {
		ms->ms_store_new = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(9, ms);

	if (store_new) memcpy((void*)store_new, ms->ms_store_new, _len_store_new);

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
	status = sgx_ocall(10, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(*cpuinfo);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	ocalloc_size += (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) ? _len_cpuinfo : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));

	if (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		memset(ms->ms_cpuinfo, 0, _len_cpuinfo);
	} else if (cpuinfo == NULL) {
		ms->ms_cpuinfo = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(11, ms);

	if (cpuinfo) memcpy((void*)cpuinfo, ms->ms_cpuinfo, _len_cpuinfo);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));

	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(12, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	status = sgx_ocall(13, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(14, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(*waiters);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) ? _len_waiters : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));

	if (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) {
		ms->ms_waiters = (void**)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		memcpy((void*)ms->ms_waiters, waiters, _len_waiters);
	} else if (waiters == NULL) {
		ms->ms_waiters = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(15, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

