#ifndef LB_EDGE_T_H__
#define LB_EDGE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "bpf/sfbpf.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void dummy_func(int d);

sgx_status_t SGX_CDECL ocall_sfbpf_compile(int pkt_hdr_len, struct sfbpf_program* fcode, struct sfbpf_program* filter, int optimize);
sgx_status_t SGX_CDECL ocall_sfbpf_filter(struct sfbpf_program* fcode, char* p, unsigned int wirelen, unsigned int buflen, int* ret);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
