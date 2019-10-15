
#include "Enclave.h"
// #include "Enclave_t.h"

#include <cstring> //strlen

extern "C"
{
#include "../src/lb/core/enclave/include/state_mgmt_t.h"
#include "../src/lb/core/enclave/include/etap_t.h"


extern etap_controller_t* etap_controller_instance;

void ecall_mb()
{
	//lightbox init
	init_state_mgmt();
	etap_controller_instance = etap_controller_init(0, 0);

	uint8_t pkt_buffer[2048];
	int size;
	timeval_t ts;
	
	poll_driver_t* pd = etap_controller_instance->pd;
	while (1) {
		pd->read_pkt(pkt_buffer, &size, &ts);
		pd->write_pkt(pkt_buffer, size, ts);
	}

}
}
