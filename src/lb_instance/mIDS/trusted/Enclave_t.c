#include "Enclave_t.h"

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

static sgx_status_t SGX_CDECL sgx_ecall_test(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_test();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_mos_test(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_mos_test_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_mos_test_t* ms = SGX_CAST(ms_ecall_mos_test_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_config_file_path = ms->ms_config_file_path;
	size_t _len_config_file_path = ms->ms_config_file_path_len ;
	char* _in_config_file_path = NULL;

	CHECK_UNIQUE_POINTER(_tmp_config_file_path, _len_config_file_path);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_config_file_path != NULL && _len_config_file_path != 0) {
		_in_config_file_path = (char*)malloc(_len_config_file_path);
		if (_in_config_file_path == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_config_file_path, _tmp_config_file_path, _len_config_file_path);
		_in_config_file_path[_len_config_file_path - 1] = '\0';
		if (_len_config_file_path != strlen(_in_config_file_path) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ecall_mos_test((const char*)_in_config_file_path);
err:
	if (_in_config_file_path) free((void*)_in_config_file_path);

	return status;
}

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
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[5];
} g_ecall_table = {
	5,
	{
		{(void*)(uintptr_t)sgx_ecall_test, 0},
		{(void*)(uintptr_t)sgx_ecall_mos_test, 0},
		{(void*)(uintptr_t)sgx_ecall_auth_enc, 0},
		{(void*)(uintptr_t)sgx_ecall_init_aes_gcm, 0},
		{(void*)(uintptr_t)sgx_ecall_etap_start, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[30][5];
} g_dyn_entry_table = {
	30,
	{
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print_string2(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string2_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string2_t);
	void *__tmp = NULL;

	ocalloc_size += (str != NULL && sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string2_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string2_t));

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
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_get_time2(int* second, int* nanosecond)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_second = 8;
	size_t _len_nanosecond = 8;

	ms_ocall_get_time2_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_get_time2_t);
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
	ms = (ms_ocall_get_time2_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_get_time2_t));

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
	
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (second) memcpy((void*)second, __tmp_second, _len_second);
		if (nanosecond) memcpy((void*)nanosecond, __tmp_nanosecond, _len_nanosecond);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_get_data(int data_id, char** val, int* len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_val = sizeof(char*);
	size_t _len_len = sizeof(int);

	ms_ocall_get_data_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_get_data_t);
	void *__tmp = NULL;

	void *__tmp_val = NULL;
	void *__tmp_len = NULL;
	ocalloc_size += (val != NULL && sgx_is_within_enclave(val, _len_val)) ? _len_val : 0;
	ocalloc_size += (len != NULL && sgx_is_within_enclave(len, _len_len)) ? _len_len : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_get_data_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_get_data_t));

	ms->ms_data_id = data_id;
	if (val != NULL && sgx_is_within_enclave(val, _len_val)) {
		ms->ms_val = (char**)__tmp;
		__tmp_val = __tmp;
		memset(__tmp_val, 0, _len_val);
		__tmp = (void *)((size_t)__tmp + _len_val);
	} else if (val == NULL) {
		ms->ms_val = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (len != NULL && sgx_is_within_enclave(len, _len_len)) {
		ms->ms_len = (int*)__tmp;
		__tmp_len = __tmp;
		memset(__tmp_len, 0, _len_len);
		__tmp = (void *)((size_t)__tmp + _len_len);
	} else if (len == NULL) {
		ms->ms_len = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (val) memcpy((void*)val, __tmp_val, _len_val);
		if (len) memcpy((void*)len, __tmp_len, _len_len);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_read_dir(char* dirPaht, char** allFiles, int* fileCount, int subfile)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_dirPaht = dirPaht ? strlen(dirPaht) + 1 : 0;
	size_t _len_allFiles = sizeof(char*);
	size_t _len_fileCount = sizeof(int);

	ms_ocall_read_dir_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_read_dir_t);
	void *__tmp = NULL;

	void *__tmp_allFiles = NULL;
	void *__tmp_fileCount = NULL;
	ocalloc_size += (dirPaht != NULL && sgx_is_within_enclave(dirPaht, _len_dirPaht)) ? _len_dirPaht : 0;
	ocalloc_size += (allFiles != NULL && sgx_is_within_enclave(allFiles, _len_allFiles)) ? _len_allFiles : 0;
	ocalloc_size += (fileCount != NULL && sgx_is_within_enclave(fileCount, _len_fileCount)) ? _len_fileCount : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_read_dir_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_read_dir_t));

	if (dirPaht != NULL && sgx_is_within_enclave(dirPaht, _len_dirPaht)) {
		ms->ms_dirPaht = (char*)__tmp;
		memcpy(__tmp, dirPaht, _len_dirPaht);
		__tmp = (void *)((size_t)__tmp + _len_dirPaht);
	} else if (dirPaht == NULL) {
		ms->ms_dirPaht = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (allFiles != NULL && sgx_is_within_enclave(allFiles, _len_allFiles)) {
		ms->ms_allFiles = (char**)__tmp;
		__tmp_allFiles = __tmp;
		memset(__tmp_allFiles, 0, _len_allFiles);
		__tmp = (void *)((size_t)__tmp + _len_allFiles);
	} else if (allFiles == NULL) {
		ms->ms_allFiles = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (fileCount != NULL && sgx_is_within_enclave(fileCount, _len_fileCount)) {
		ms->ms_fileCount = (int*)__tmp;
		__tmp_fileCount = __tmp;
		memset(__tmp_fileCount, 0, _len_fileCount);
		__tmp = (void *)((size_t)__tmp + _len_fileCount);
	} else if (fileCount == NULL) {
		ms->ms_fileCount = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_subfile = subfile;
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (allFiles) memcpy((void*)allFiles, __tmp_allFiles, _len_allFiles);
		if (fileCount) memcpy((void*)fileCount, __tmp_fileCount, _len_fileCount);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_file_size(char* filePath, int* len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_filePath = filePath ? strlen(filePath) + 1 : 0;
	size_t _len_len = sizeof(int);

	ms_ocall_file_size_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_file_size_t);
	void *__tmp = NULL;

	void *__tmp_len = NULL;
	ocalloc_size += (filePath != NULL && sgx_is_within_enclave(filePath, _len_filePath)) ? _len_filePath : 0;
	ocalloc_size += (len != NULL && sgx_is_within_enclave(len, _len_len)) ? _len_len : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_file_size_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_file_size_t));

	if (filePath != NULL && sgx_is_within_enclave(filePath, _len_filePath)) {
		ms->ms_filePath = (char*)__tmp;
		memcpy(__tmp, filePath, _len_filePath);
		__tmp = (void *)((size_t)__tmp + _len_filePath);
	} else if (filePath == NULL) {
		ms->ms_filePath = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (len != NULL && sgx_is_within_enclave(len, _len_len)) {
		ms->ms_len = (int*)__tmp;
		__tmp_len = __tmp;
		memset(__tmp_len, 0, _len_len);
		__tmp = (void *)((size_t)__tmp + _len_len);
	} else if (len == NULL) {
		ms->ms_len = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (len) memcpy((void*)len, __tmp_len, _len_len);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_read_file(char* filePath, char** out, int* len, int pos)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_filePath = filePath ? strlen(filePath) + 1 : 0;
	size_t _len_out = sizeof(char*);
	size_t _len_len = sizeof(int);

	ms_ocall_read_file_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_read_file_t);
	void *__tmp = NULL;

	void *__tmp_out = NULL;
	void *__tmp_len = NULL;
	ocalloc_size += (filePath != NULL && sgx_is_within_enclave(filePath, _len_filePath)) ? _len_filePath : 0;
	ocalloc_size += (out != NULL && sgx_is_within_enclave(out, _len_out)) ? _len_out : 0;
	ocalloc_size += (len != NULL && sgx_is_within_enclave(len, _len_len)) ? _len_len : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_read_file_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_read_file_t));

	if (filePath != NULL && sgx_is_within_enclave(filePath, _len_filePath)) {
		ms->ms_filePath = (char*)__tmp;
		memcpy(__tmp, filePath, _len_filePath);
		__tmp = (void *)((size_t)__tmp + _len_filePath);
	} else if (filePath == NULL) {
		ms->ms_filePath = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (out != NULL && sgx_is_within_enclave(out, _len_out)) {
		ms->ms_out = (char**)__tmp;
		__tmp_out = __tmp;
		memset(__tmp_out, 0, _len_out);
		__tmp = (void *)((size_t)__tmp + _len_out);
	} else if (out == NULL) {
		ms->ms_out = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (len != NULL && sgx_is_within_enclave(len, _len_len)) {
		ms->ms_len = (int*)__tmp;
		__tmp_len = __tmp;
		memcpy(__tmp_len, len, _len_len);
		__tmp = (void *)((size_t)__tmp + _len_len);
	} else if (len == NULL) {
		ms->ms_len = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_pos = pos;
	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (out) memcpy((void*)out, __tmp_out, _len_out);
		if (len) memcpy((void*)len, __tmp_len, _len_len);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_write_file(char* filePath, char* src, int len, int append)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_filePath = filePath ? strlen(filePath) + 1 : 0;
	size_t _len_src = len;

	ms_ocall_write_file_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_write_file_t);
	void *__tmp = NULL;

	ocalloc_size += (filePath != NULL && sgx_is_within_enclave(filePath, _len_filePath)) ? _len_filePath : 0;
	ocalloc_size += (src != NULL && sgx_is_within_enclave(src, _len_src)) ? _len_src : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_write_file_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_write_file_t));

	if (filePath != NULL && sgx_is_within_enclave(filePath, _len_filePath)) {
		ms->ms_filePath = (char*)__tmp;
		memcpy(__tmp, filePath, _len_filePath);
		__tmp = (void *)((size_t)__tmp + _len_filePath);
	} else if (filePath == NULL) {
		ms->ms_filePath = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (src != NULL && sgx_is_within_enclave(src, _len_src)) {
		ms->ms_src = (char*)__tmp;
		memcpy(__tmp, src, _len_src);
		__tmp = (void *)((size_t)__tmp + _len_src);
	} else if (src == NULL) {
		ms->ms_src = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_len = len;
	ms->ms_append = append;
	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_malloc(void** pointer, int size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pointer = sizeof(void*);

	ms_ocall_malloc_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_malloc_t);
	void *__tmp = NULL;

	void *__tmp_pointer = NULL;
	ocalloc_size += (pointer != NULL && sgx_is_within_enclave(pointer, _len_pointer)) ? _len_pointer : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_malloc_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_malloc_t));

	if (pointer != NULL && sgx_is_within_enclave(pointer, _len_pointer)) {
		ms->ms_pointer = (void**)__tmp;
		__tmp_pointer = __tmp;
		memset(__tmp_pointer, 0, _len_pointer);
		__tmp = (void *)((size_t)__tmp + _len_pointer);
	} else if (pointer == NULL) {
		ms->ms_pointer = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_size = size;
	status = sgx_ocall(7, ms);

	if (status == SGX_SUCCESS) {
		if (pointer) memcpy((void*)pointer, __tmp_pointer, _len_pointer);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_free(void* pointer)
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

	ms->ms_pointer = SGX_CAST(void*, pointer);
	status = sgx_ocall(8, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_del(void* pointer, int isArray)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_del_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_del_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_del_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_del_t));

	ms->ms_pointer = SGX_CAST(void*, pointer);
	ms->ms_isArray = isArray;
	status = sgx_ocall(9, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_rand(int* rand_num, int mod)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_rand_num = sizeof(int);

	ms_ocall_rand_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_rand_t);
	void *__tmp = NULL;

	void *__tmp_rand_num = NULL;
	ocalloc_size += (rand_num != NULL && sgx_is_within_enclave(rand_num, _len_rand_num)) ? _len_rand_num : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_rand_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_rand_t));

	if (rand_num != NULL && sgx_is_within_enclave(rand_num, _len_rand_num)) {
		ms->ms_rand_num = (int*)__tmp;
		__tmp_rand_num = __tmp;
		memset(__tmp_rand_num, 0, _len_rand_num);
		__tmp = (void *)((size_t)__tmp + _len_rand_num);
	} else if (rand_num == NULL) {
		ms->ms_rand_num = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_mod = mod;
	status = sgx_ocall(10, ms);

	if (status == SGX_SUCCESS) {
		if (rand_num) memcpy((void*)rand_num, __tmp_rand_num, _len_rand_num);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sfbpf_compile(int* retval, int snaplen_arg, int linktype_arg, char* program, const char* buf, int optimize, int mask)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_program = 24;
	size_t _len_buf = buf ? strlen(buf) + 1 : 0;

	ms_ocall_sfbpf_compile_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sfbpf_compile_t);
	void *__tmp = NULL;

	void *__tmp_program = NULL;
	ocalloc_size += (program != NULL && sgx_is_within_enclave(program, _len_program)) ? _len_program : 0;
	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sfbpf_compile_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sfbpf_compile_t));

	ms->ms_snaplen_arg = snaplen_arg;
	ms->ms_linktype_arg = linktype_arg;
	if (program != NULL && sgx_is_within_enclave(program, _len_program)) {
		ms->ms_program = (char*)__tmp;
		__tmp_program = __tmp;
		memset(__tmp_program, 0, _len_program);
		__tmp = (void *)((size_t)__tmp + _len_program);
	} else if (program == NULL) {
		ms->ms_program = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (char*)__tmp;
		memcpy(__tmp, buf, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_optimize = optimize;
	ms->ms_mask = mask;
	status = sgx_ocall(11, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (program) memcpy((void*)program, __tmp_program, _len_program);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sfbpf_filter(int* retval, const char* pc, const char* p, int wirelen, int buflen)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pc = 8;
	size_t _len_p = buflen;

	ms_ocall_sfbpf_filter_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sfbpf_filter_t);
	void *__tmp = NULL;

	ocalloc_size += (pc != NULL && sgx_is_within_enclave(pc, _len_pc)) ? _len_pc : 0;
	ocalloc_size += (p != NULL && sgx_is_within_enclave(p, _len_p)) ? _len_p : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sfbpf_filter_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sfbpf_filter_t));

	if (pc != NULL && sgx_is_within_enclave(pc, _len_pc)) {
		ms->ms_pc = (char*)__tmp;
		memcpy(__tmp, pc, _len_pc);
		__tmp = (void *)((size_t)__tmp + _len_pc);
	} else if (pc == NULL) {
		ms->ms_pc = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (p != NULL && sgx_is_within_enclave(p, _len_p)) {
		ms->ms_p = (char*)__tmp;
		memcpy(__tmp, p, _len_p);
		__tmp = (void *)((size_t)__tmp + _len_p);
	} else if (p == NULL) {
		ms->ms_p = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_wirelen = wirelen;
	ms->ms_buflen = buflen;
	status = sgx_ocall(12, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sfbpf_freecode(char* program)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_program = 24;

	ms_ocall_sfbpf_freecode_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sfbpf_freecode_t);
	void *__tmp = NULL;

	ocalloc_size += (program != NULL && sgx_is_within_enclave(program, _len_program)) ? _len_program : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sfbpf_freecode_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sfbpf_freecode_t));

	if (program != NULL && sgx_is_within_enclave(program, _len_program)) {
		ms->ms_program = (char*)__tmp;
		memcpy(__tmp, program, _len_program);
		__tmp = (void *)((size_t)__tmp + _len_program);
	} else if (program == NULL) {
		ms->ms_program = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(13, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pcap_init(char* filename)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_filename = sizeof(char);

	ms_ocall_pcap_init_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pcap_init_t);
	void *__tmp = NULL;

	ocalloc_size += (filename != NULL && sgx_is_within_enclave(filename, _len_filename)) ? _len_filename : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pcap_init_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pcap_init_t));

	if (filename != NULL && sgx_is_within_enclave(filename, _len_filename)) {
		ms->ms_filename = (char*)__tmp;
		memcpy(__tmp, filename, _len_filename);
		__tmp = (void *)((size_t)__tmp + _len_filename);
	} else if (filename == NULL) {
		ms->ms_filename = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(14, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pcap_next(char** pkt, char* pcap_pkthdr)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pkt = sizeof(char*);
	size_t _len_pcap_pkthdr = 24;

	ms_ocall_pcap_next_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pcap_next_t);
	void *__tmp = NULL;

	void *__tmp_pkt = NULL;
	void *__tmp_pcap_pkthdr = NULL;
	ocalloc_size += (pkt != NULL && sgx_is_within_enclave(pkt, _len_pkt)) ? _len_pkt : 0;
	ocalloc_size += (pcap_pkthdr != NULL && sgx_is_within_enclave(pcap_pkthdr, _len_pcap_pkthdr)) ? _len_pcap_pkthdr : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pcap_next_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pcap_next_t));

	if (pkt != NULL && sgx_is_within_enclave(pkt, _len_pkt)) {
		ms->ms_pkt = (char**)__tmp;
		__tmp_pkt = __tmp;
		memset(__tmp_pkt, 0, _len_pkt);
		__tmp = (void *)((size_t)__tmp + _len_pkt);
	} else if (pkt == NULL) {
		ms->ms_pkt = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (pcap_pkthdr != NULL && sgx_is_within_enclave(pcap_pkthdr, _len_pcap_pkthdr)) {
		ms->ms_pcap_pkthdr = (char*)__tmp;
		__tmp_pcap_pkthdr = __tmp;
		memset(__tmp_pcap_pkthdr, 0, _len_pcap_pkthdr);
		__tmp = (void *)((size_t)__tmp + _len_pcap_pkthdr);
	} else if (pcap_pkthdr == NULL) {
		ms->ms_pcap_pkthdr = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(15, ms);

	if (status == SGX_SUCCESS) {
		if (pkt) memcpy((void*)pkt, __tmp_pkt, _len_pkt);
		if (pcap_pkthdr) memcpy((void*)pcap_pkthdr, __tmp_pcap_pkthdr, _len_pcap_pkthdr);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_load_config(const char* filename, char* g_config)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_filename = filename ? strlen(filename) + 1 : 0;
	size_t _len_g_config = 40;

	ms_ocall_load_config_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_load_config_t);
	void *__tmp = NULL;

	void *__tmp_g_config = NULL;
	ocalloc_size += (filename != NULL && sgx_is_within_enclave(filename, _len_filename)) ? _len_filename : 0;
	ocalloc_size += (g_config != NULL && sgx_is_within_enclave(g_config, _len_g_config)) ? _len_g_config : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_load_config_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_load_config_t));

	if (filename != NULL && sgx_is_within_enclave(filename, _len_filename)) {
		ms->ms_filename = (char*)__tmp;
		memcpy(__tmp, filename, _len_filename);
		__tmp = (void *)((size_t)__tmp + _len_filename);
	} else if (filename == NULL) {
		ms->ms_filename = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (g_config != NULL && sgx_is_within_enclave(g_config, _len_g_config)) {
		ms->ms_g_config = (char*)__tmp;
		__tmp_g_config = __tmp;
		memset(__tmp_g_config, 0, _len_g_config);
		__tmp = (void *)((size_t)__tmp + _len_g_config);
	} else if (g_config == NULL) {
		ms->ms_g_config = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(16, ms);

	if (status == SGX_SUCCESS) {
		if (g_config) memcpy((void*)g_config, __tmp_g_config, _len_g_config);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_dfc_init(char** pattern_pool, int** pattern_length, int* size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pattern_pool = sizeof(char*);
	size_t _len_pattern_length = sizeof(int*);
	size_t _len_size = sizeof(int);

	ms_ocall_dfc_init_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_dfc_init_t);
	void *__tmp = NULL;

	void *__tmp_pattern_pool = NULL;
	void *__tmp_pattern_length = NULL;
	void *__tmp_size = NULL;
	ocalloc_size += (pattern_pool != NULL && sgx_is_within_enclave(pattern_pool, _len_pattern_pool)) ? _len_pattern_pool : 0;
	ocalloc_size += (pattern_length != NULL && sgx_is_within_enclave(pattern_length, _len_pattern_length)) ? _len_pattern_length : 0;
	ocalloc_size += (size != NULL && sgx_is_within_enclave(size, _len_size)) ? _len_size : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_dfc_init_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_dfc_init_t));

	if (pattern_pool != NULL && sgx_is_within_enclave(pattern_pool, _len_pattern_pool)) {
		ms->ms_pattern_pool = (char**)__tmp;
		__tmp_pattern_pool = __tmp;
		memset(__tmp_pattern_pool, 0, _len_pattern_pool);
		__tmp = (void *)((size_t)__tmp + _len_pattern_pool);
	} else if (pattern_pool == NULL) {
		ms->ms_pattern_pool = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (pattern_length != NULL && sgx_is_within_enclave(pattern_length, _len_pattern_length)) {
		ms->ms_pattern_length = (int**)__tmp;
		__tmp_pattern_length = __tmp;
		memset(__tmp_pattern_length, 0, _len_pattern_length);
		__tmp = (void *)((size_t)__tmp + _len_pattern_length);
	} else if (pattern_length == NULL) {
		ms->ms_pattern_length = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (size != NULL && sgx_is_within_enclave(size, _len_size)) {
		ms->ms_size = (int*)__tmp;
		__tmp_size = __tmp;
		memset(__tmp_size, 0, _len_size);
		__tmp = (void *)((size_t)__tmp + _len_size);
	} else if (size == NULL) {
		ms->ms_size = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(17, ms);

	if (status == SGX_SUCCESS) {
		if (pattern_pool) memcpy((void*)pattern_pool, __tmp_pattern_pool, _len_pattern_pool);
		if (pattern_length) memcpy((void*)pattern_length, __tmp_pattern_length, _len_pattern_length);
		if (size) memcpy((void*)size, __tmp_size, _len_size);
	}
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
	
	status = sgx_ocall(18, ms);

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
	
	status = sgx_ocall(19, ms);

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
	status = sgx_ocall(20, ms);

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
	status = sgx_ocall(21, ms);

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
	
	status = sgx_ocall(22, ms);

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
	
	status = sgx_ocall(23, ms);

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
	status = sgx_ocall(24, ms);

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
	
	status = sgx_ocall(25, ms);

	if (status == SGX_SUCCESS) {
		if (r) memcpy((void*)r, __tmp_r, _len_r);
	}
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
	status = sgx_ocall(26, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
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
	status = sgx_ocall(27, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
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
	status = sgx_ocall(28, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

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
		memcpy(__tmp, waiters, _len_waiters);
		__tmp = (void *)((size_t)__tmp + _len_waiters);
	} else if (waiters == NULL) {
		ms->ms_waiters = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(29, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

