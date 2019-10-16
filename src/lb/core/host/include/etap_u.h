#ifndef LB_NET_U_H
#define LB_NET_U_H

#include <stdint.h>

typedef struct {
	/* TLS */
	int record_size;
	int record_per_batch;
} etap_param_t;

void etap_init();

void etap_deinit();

int etap_testrun();

void ocall_lb_etap_in(uint8_t **batch);

void gateway_init(int rec_size, int rec_per_bat);

void gateway_deinit();

#endif
