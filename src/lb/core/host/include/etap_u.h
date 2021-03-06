#ifndef LB_NET_U_H
#define LB_NET_U_H

#include <stdint.h>

typedef struct {
	/* TLS */
	int record_size;
	int record_per_batch;
} etap_param_t;

void etap_network_init();

void etap_network_deinit();

int etap_testrun();

void ocall_lb_etap_in(uint8_t **batch);

void ocall_get_rtt(uint64_t * rtt_enclave);

void gateway_init(int rec_size, int rec_per_bat);

void gateway_deinit();

#endif
