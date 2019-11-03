#include "crypto_t.h"
#include "etap_t.h"
#include "rx_ring_opt.h"
#include "state_mgmt_t.h"
#include "lb_utils_t.h"

#include "lb_core_edge_t.h"

#include <stdlib.h>
#include <string.h>

extern etap_controller_t* etap_controller_instance;

static inline void control_variable_init(rx_ring_data_t* dp) {
	/* shared control variables */
	dp->read = 0;
	dp->write = 0;
	/* consumers local variables */
	dp->localWrite = 0;
	dp->nextRead = 0;
	dp->rBatch = 0;
	/* producer local variables */
	dp->localRead = 0;
	dp->nextWrite = 0;
	dp->wBatch = 0;
}

uint8_t* current_batch_memory_pool;

double ecall_etap_sendto_next_box(int lbn_record_size,
				  int lbn_record_per_batch) {
	rx_ring_t* handle = etap_controller_instance->tx_ring_instance;
	/* rx_ring_data_t* dataPtr = handle->rData; */

	// Initialize all control variables to 0
	control_variable_init(handle->rData);

	int batch_size = (lbn_record_size + MAC_SIZE) * lbn_record_per_batch;
	current_batch_memory_pool = malloc(batch_size);

	while (1) {
		/* eprintf("prepared batch\n"); */
			prepare_batch(handle, lbn_record_size, lbn_record_per_batch);
			/* eprintf("sending\n"); */
            ocall_lb_etap_out(&current_batch_memory_pool); 
	}
}

void prepare_batch(rx_ring_t* handle, int lbn_record_size,
		   int lbn_record_per_batch) {
	uint8_t* current_batch_position = current_batch_memory_pool;

	static uint8_t pkt[9000];
	static int size;
	static timeval_t ts;
	int pkt_and_ts_size;
	uint16_t sized_pkt_size;
	static uint8_t sized_pkt[9000];
	/* int current_record_free_space_remain = lbn_record_size; */
	static uint16_t sized_pkt_remain_from_last_record = 0;

	for (int record_index = 0; record_index < lbn_record_per_batch;
	     record_index++) {

		uint8_t* record = current_batch_position;
		int current_record_free_space_remain = lbn_record_size;
		if (sized_pkt_remain_from_last_record > 0) {
			memcpy(current_batch_position,
			       sized_pkt + sized_pkt_size -
				   sized_pkt_remain_from_last_record,
			       sized_pkt_remain_from_last_record);
			current_batch_position +=
			    sized_pkt_remain_from_last_record;
			current_record_free_space_remain -=
			    sized_pkt_remain_from_last_record;
		}

		while (1) {
			handle->read_pkt(pkt, &size, &ts, handle->rData);
			// TODO maybe add some pkt empty checking later, now
			// we'll just be blocked at read_pkt();
			pkt_and_ts_size = sizeof(ts) + size;
			sized_pkt_size =
			    pkt_and_ts_size + sizeof(pkt_and_ts_size);

			// Making sized_pkt
			// 1) add pkt and ts sizes
			memcpy(sized_pkt, &pkt_and_ts_size,
			       sizeof(pkt_and_ts_size));
			// 2) pkt timestamp
			memcpy(sized_pkt + sizeof(pkt_and_ts_size), &ts,
			       sizeof(ts));
			// 3) pkt itself
			memcpy(sized_pkt + sizeof(pkt_and_ts_size) + sizeof(ts), pkt,
			       size);

			/* eprintf("copied one while loop\n"); */
			if (current_record_free_space_remain > sized_pkt_size) {
				/* eprintf("entered if\n"); */
				memcpy(current_batch_position, sized_pkt,
				       sized_pkt_size);
				current_batch_position += sized_pkt_size;
				current_record_free_space_remain -=
				    sized_pkt_size;
				/* eprintf("end if\n"); */
			} else {
				if (current_record_free_space_remain >=
				    sizeof(sized_pkt_size)) {
					sized_pkt_remain_from_last_record =
					    sized_pkt_size -
					    current_record_free_space_remain;
					memcpy(
					    current_batch_position, sized_pkt,
					    current_record_free_space_remain);
					current_batch_position +=
					    current_record_free_space_remain;
					current_record_free_space_remain = 0;
				} else {
					sized_pkt_remain_from_last_record = 0;
					current_batch_position +=
					    current_record_free_space_remain;
				}
				break;
			}
		}

		int ret = auth_enc(record, lbn_record_size, record, current_batch_position);

		/* if (!ret) exit(1); */
		current_batch_position += MAC_SIZE;
	}



}
