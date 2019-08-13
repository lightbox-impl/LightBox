#include "lb_edge_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


typedef struct ms_dummy_func_t {
	int ms_d;
} ms_dummy_func_t;

typedef struct ms_ocall_sfbpf_compile_t {
	int ms_pkt_hdr_len;
	struct sfbpf_program* ms_fcode;
	struct sfbpf_program* ms_filter;
	int ms_optimize;
} ms_ocall_sfbpf_compile_t;

typedef struct ms_ocall_sfbpf_filter_t {
	struct sfbpf_program* ms_fcode;
	char* ms_p;
	unsigned int ms_wirelen;
	unsigned int ms_buflen;
	int* ms_ret;
} ms_ocall_sfbpf_filter_t;

static sgx_status_t SGX_CDECL sgx_dummy_func(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_dummy_func_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_dummy_func_t* ms = SGX_CAST(ms_dummy_func_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	dummy_func(ms->ms_d);


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[1];
} g_ecall_table = {
	1,
	{
		{(void*)(uintptr_t)sgx_dummy_func, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[2][1];
} g_dyn_entry_table = {
	2,
	{
		{0, },
		{0, },
	}
};


sgx_status_t SGX_CDECL ocall_sfbpf_compile(int pkt_hdr_len, struct sfbpf_program* fcode, struct sfbpf_program* filter, int optimize)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_fcode = sizeof(struct sfbpf_program);
	size_t _len_filter = sizeof(struct sfbpf_program);

	ms_ocall_sfbpf_compile_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sfbpf_compile_t);
	void *__tmp = NULL;

	void *__tmp_fcode = NULL;
	void *__tmp_filter = NULL;

	CHECK_ENCLAVE_POINTER(fcode, _len_fcode);
	CHECK_ENCLAVE_POINTER(filter, _len_filter);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (fcode != NULL) ? _len_fcode : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (filter != NULL) ? _len_filter : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sfbpf_compile_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sfbpf_compile_t));
	ocalloc_size -= sizeof(ms_ocall_sfbpf_compile_t);

	ms->ms_pkt_hdr_len = pkt_hdr_len;
	if (fcode != NULL) {
		ms->ms_fcode = (struct sfbpf_program*)__tmp;
		__tmp_fcode = __tmp;
		if (memcpy_s(__tmp_fcode, ocalloc_size, fcode, _len_fcode)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_fcode);
		ocalloc_size -= _len_fcode;
	} else {
		ms->ms_fcode = NULL;
	}
	
	if (filter != NULL) {
		ms->ms_filter = (struct sfbpf_program*)__tmp;
		__tmp_filter = __tmp;
		if (memcpy_s(__tmp_filter, ocalloc_size, filter, _len_filter)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_filter);
		ocalloc_size -= _len_filter;
	} else {
		ms->ms_filter = NULL;
	}
	
	ms->ms_optimize = optimize;
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
		if (fcode) {
			if (memcpy_s((void*)fcode, _len_fcode, __tmp_fcode, _len_fcode)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (filter) {
			if (memcpy_s((void*)filter, _len_filter, __tmp_filter, _len_filter)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sfbpf_filter(struct sfbpf_program* fcode, char* p, unsigned int wirelen, unsigned int buflen, int* ret)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_fcode = sizeof(struct sfbpf_program);
	size_t _len_p = sizeof(char);
	size_t _len_ret = sizeof(int);

	ms_ocall_sfbpf_filter_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sfbpf_filter_t);
	void *__tmp = NULL;

	void *__tmp_fcode = NULL;
	void *__tmp_p = NULL;
	void *__tmp_ret = NULL;

	CHECK_ENCLAVE_POINTER(fcode, _len_fcode);
	CHECK_ENCLAVE_POINTER(p, _len_p);
	CHECK_ENCLAVE_POINTER(ret, _len_ret);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (fcode != NULL) ? _len_fcode : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (p != NULL) ? _len_p : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (ret != NULL) ? _len_ret : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sfbpf_filter_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sfbpf_filter_t));
	ocalloc_size -= sizeof(ms_ocall_sfbpf_filter_t);

	if (fcode != NULL) {
		ms->ms_fcode = (struct sfbpf_program*)__tmp;
		__tmp_fcode = __tmp;
		if (memcpy_s(__tmp_fcode, ocalloc_size, fcode, _len_fcode)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_fcode);
		ocalloc_size -= _len_fcode;
	} else {
		ms->ms_fcode = NULL;
	}
	
	if (p != NULL) {
		ms->ms_p = (char*)__tmp;
		__tmp_p = __tmp;
		if (_len_p % sizeof(*p) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp_p, ocalloc_size, p, _len_p)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_p);
		ocalloc_size -= _len_p;
	} else {
		ms->ms_p = NULL;
	}
	
	ms->ms_wirelen = wirelen;
	ms->ms_buflen = buflen;
	if (ret != NULL) {
		ms->ms_ret = (int*)__tmp;
		__tmp_ret = __tmp;
		if (_len_ret % sizeof(*ret) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp_ret, ocalloc_size, ret, _len_ret)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_ret);
		ocalloc_size -= _len_ret;
	} else {
		ms->ms_ret = NULL;
	}
	
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (fcode) {
			if (memcpy_s((void*)fcode, _len_fcode, __tmp_fcode, _len_fcode)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (p) {
			if (memcpy_s((void*)p, _len_p, __tmp_p, _len_p)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (ret) {
			if (memcpy_s((void*)ret, _len_ret, __tmp_ret, _len_ret)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

