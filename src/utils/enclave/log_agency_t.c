#include "log_agency_t.h"

#include "../../sg-box/sgbox_config.h"
#include "crypto_t.h"

#include "../enclave_utils.h"
#include "../prads_t.h"

#include <string.h>

uint8_t *buffer = 0;
int buffer_size = 0;
int flush_count = 0;
sgx_aes_gcm_128bit_tag_t dummy_mac;


void init_logging_agency() {
    buffer = malloc(LOG_BUFFER_CAPACITY);
    buffer_size = 0;
    flush_count = 0;
}

void close_logging_agency() {
    eprintf("[*] Logging agency: %d flushes in total!\n", flush_count);
    free(buffer);
}

void log_to_buffer(void *entry, int len){
    if ((buffer_size+len) > LOG_BUFFER_CAPACITY) {
        auth_enc(buffer, LOG_BUFFER_CAPACITY, buffer, &dummy_mac);
        sgx_status_t ret = ocall_log_flush_full(buffer, LOG_BUFFER_CAPACITY);
        if (ret != SGX_SUCCESS) {
            eprintf("[*] Failed to flush full logging buffer!\n");
        }
        buffer_size = 0;
        ++flush_count;
    }
    memcpy(buffer+buffer_size, entry, len);
    buffer_size += len;
}

void ecall_log_flush_timeout(void *out_buffer, int useless) {
    auth_enc(buffer, LOG_BUFFER_CAPACITY, buffer, &dummy_mac);
    memcpy(out_buffer, buffer, LOG_BUFFER_CAPACITY);

    buffer_size = 0;
    ++flush_count;
}