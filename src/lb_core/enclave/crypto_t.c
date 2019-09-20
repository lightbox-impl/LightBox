#include "crypto_t.h"

#include "sgx_trts.h"  // sgx_read_rand

#include "utils_t.h"

/* #include "../common/lb_config.h" */
#include "lb_config.h"

#include <string.h>

sgx_aes_gcm_128bit_key_t p_key;
sgx_aes_gcm_128bit_tag_t p_out_mac = {0};
#define NIST_IV_LEN 12
const uint8_t p_iv[NIST_IV_LEN] = {0};

void init_aes_gcm() {
	// draw_rand(&p_key, sizeof(p_key));
	memcpy(&p_key, DUMMY_KEY, sizeof(p_key));
}

int auth_enc(void *src, int src_len, void *dst, void *out_mac) {
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = sgx_rijndael128GCM_encrypt(
	    &p_key, src, src_len, dst, p_iv, NIST_IV_LEN, 0,
	    0,  // no additional authentication data
	    out_mac);
	if (ret == SGX_SUCCESS) {
		return 1;
	} else {
		eprintf("[*] auth_enc error: %x\n", ret);
		return 0;
	}
}

int veri_dec(void *src, int src_len, void *dst, const void *in_mac) {
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = sgx_rijndael128GCM_decrypt(
	    &p_key, src, src_len, dst, p_iv, NIST_IV_LEN, 0,
	    0,  // no additional authentication data
	    in_mac);
	if (ret == SGX_SUCCESS) {
		return 1;
	} else {
		eprintf("[*] veri_dec error: %x\n", ret);
		return 0;
	}
}

void draw_rand(void *r, int len) {
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = sgx_read_rand((uint8_t *)r, len);
}

int ecall_init_aes_gcm() { init_aes_gcm(); }

// for secure ferry simulation
int ecall_auth_enc(uint8_t *src, int src_len, uint8_t *dst, uint8_t *mac) {
	return auth_enc(src, src_len, dst, (sgx_aes_gcm_128bit_tag_t *)mac);
}

// for secure ferry simulation
// int ecall_veri_dec(uint8_t *src, int src_len, uint8_t *dst, const uint8_t
// *mac) { 	return veri_dec(src, src_len, dst, (sgx_aes_gcm_128bit_tag_t
// *)mac);
//}
