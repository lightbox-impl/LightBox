#ifndef LB_EDGE_U_H__
#define LB_EDGE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "bpf/sfbpf.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_SFBPF_COMPILE_DEFINED__
#define OCALL_SFBPF_COMPILE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sfbpf_compile, (int pkt_hdr_len, struct sfbpf_program* fcode, struct sfbpf_program* filter, int optimize));
#endif
#ifndef OCALL_SFBPF_FILTER_DEFINED__
#define OCALL_SFBPF_FILTER_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sfbpf_filter, (struct sfbpf_program* fcode, char* p, unsigned int wirelen, unsigned int buflen, int* ret));
#endif

sgx_status_t dummy_func(sgx_enclave_id_t eid, int d);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
