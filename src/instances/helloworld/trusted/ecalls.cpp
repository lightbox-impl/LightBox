
#include "Enclave.h"
// #include "Enclave_t.h"

#include <cstring>  //strlen

extern "C" {
#include "../src/lb/core/enclave/include/etap_t.h"
#include "../src/lb/core/enclave/include/state_mgmt_t.h"

void ecall_mb() {
    // lightbox init
    init_state_mgmt();
    poll_driver_t* pd = poll_driver_init(0);

    uint8_t pkt_buffer[9000];
    int size = 0;
    timeval_t ts = {0, 0};
    ;

    while (1) {
	pd->read_pkt(pkt_buffer, &size, &ts, pd->etap);
	pd->write_pkt(pkt_buffer, size, ts, pd->etap);
    }
}
}
