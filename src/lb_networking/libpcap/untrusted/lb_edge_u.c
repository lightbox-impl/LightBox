#include "lb_edge_u.h"
#include <errno.h>

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

static sgx_status_t SGX_CDECL lb_edge_ocall_sfbpf_compile(void* pms)
{
	ms_ocall_sfbpf_compile_t* ms = SGX_CAST(ms_ocall_sfbpf_compile_t*, pms);
	ocall_sfbpf_compile(ms->ms_pkt_hdr_len, ms->ms_fcode, ms->ms_filter, ms->ms_optimize);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL lb_edge_ocall_sfbpf_filter(void* pms)
{
	ms_ocall_sfbpf_filter_t* ms = SGX_CAST(ms_ocall_sfbpf_filter_t*, pms);
	ocall_sfbpf_filter(ms->ms_fcode, ms->ms_p, ms->ms_wirelen, ms->ms_buflen, ms->ms_ret);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[2];
} ocall_table_lb_edge = {
	2,
	{
		(void*)lb_edge_ocall_sfbpf_compile,
		(void*)lb_edge_ocall_sfbpf_filter,
	}
};
sgx_status_t dummy_func(sgx_enclave_id_t eid, int d)
{
	sgx_status_t status;
	ms_dummy_func_t ms;
	ms.ms_d = d;
	status = sgx_ecall(eid, 0, &ocall_table_lb_edge, &ms);
	return status;
}

