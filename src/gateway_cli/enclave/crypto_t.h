#ifndef CRYPTO_T_H
#define CRYPTO_T_H

#include "sgx_tcrypto.h"

void init_aes_gcm();

int auth_enc(void *src, int src_len, void *dst, void *out_mac);

int veri_dec(void *src, int src_len, void *dst, const void *in_mac);

void draw_rand(void *r, int len);

#endif