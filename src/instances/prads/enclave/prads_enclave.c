#include "sgx_trts.h"
#include "sgx_tcrypto.h"

#include "prads_core/prads.h"
#include "prads_core/assets.h"
#include "prads_core/config.h"
#include "prads_core/cxt.h"
#include "prads_core/servicefp/servicefp.h"

#include "mem_utils_t.h"

// from lb_libpcap
#include <pcap_t.h>

#include <lb_config.h>
#include <lb_type.h>
#include <lb_utils_t.h>

// #include "log_agency_t.h"

// TODO: trivial to move inside enclave
globalconfig* config;
int nets;
fmask *network;

extern int call_times;
extern uint64_t cxtrackerid;
extern int total_state_count;

extern os_asset *os_asset_pool;
extern serv_asset *serv_asset_pool;
extern asset *asset_pool;

int ecall_prads_initialize(void* global_config, int _nets, void* _network,
                           void* _os_asset_pool, void* _serv_asset_pool, void *_asset_pool) {
  config = global_config;

  nets = _nets;
  network = _network;
  
  os_asset_pool = _os_asset_pool;
  serv_asset_pool = _serv_asset_pool;
  asset_pool = _asset_pool;

  cxt_init();

  init_services();

  // init_logging_agency();

  eprintf("flow-related data structure size %d %d %d \n", sizeof(state_entry_t), sizeof(flow_state_t), sizeof(connection));

  return 0;
}

void ecall_lb_prads_run() {
    pcap_t* handle = pcap_create(NULL, NULL);
    pcap_loop(handle, -1, got_packet, NULL);
    return;
}

void ecall_prads_gameover() {
  clear_asset_list();

  // close_logging_agency();
}

uint64_t ecall_prads_cxtrackerid() {
    return cxtrackerid;
    //return call_times;
}
