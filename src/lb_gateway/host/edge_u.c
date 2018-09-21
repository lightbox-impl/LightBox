#include "edge_u.h"
#include <errno.h>

typedef struct ms_ecall_auth_enc_t {
	int ms_retval;
	uint8_t* ms_src;
	int ms_src_len;
	uint8_t* ms_dst;
	uint8_t* ms_mac;
} ms_ecall_auth_enc_t;

typedef struct ms_ocall_print_string_t {
	char* ms_str;
} ms_ocall_print_string_t;

static sgx_status_t SGX_CDECL edge_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_edge = {
	1,
	{
		(void*)edge_ocall_print_string,
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
	status = sgx_ecall(eid, 0, &ocall_table_edge, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_init_aes_gcm(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 1, &ocall_table_edge, NULL);
	return status;
}

