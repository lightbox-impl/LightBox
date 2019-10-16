
#include "Enclave.h"
// #include "Enclave_t.h"

#include <cstring> //strlen

extern "C"
{
#include "../src/lb/core/enclave/include/state_mgmt_t.h"
#include "../src/lb/core/enclave/include/etap_t.h"


void ecall_mb()
{
	//lightbox init
	init_state_mgmt();
	poll_driver_t* pd = poll_driver_init();

	uint8_t pkt_buffer[2048];
	int size;
	timeval_t ts;

	while (1) {
		if (pd->read_pkt == NULL) printf("pd is null\n");
		printf("line 31 ecall\n");
		pd->read_pkt(pkt_buffer, &size, &ts, pd->etap);
		printf("line 33\n");
		// pd->write_pkt(pkt_buffer, size, ts, pd->etap);
	}

}
}
