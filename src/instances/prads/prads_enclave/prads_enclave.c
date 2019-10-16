#include "sgx_trts.h"
#include "sgx_tcrypto.h"

#include "prads/prads.h"
#include "prads/assets.h"
#include "prads/config.h"
#include "prads/cxt.h"
#include "prads/servicefp/servicefp.h"

#include "enclave_utils.h"

#include "../sg-box/state_orchestrator_t.h"
#include "sg-box/crypto_t.h"
#include "sg-box/log_agency_t.h"

// TODO: trivial to move from host to enclave
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

  eprintf("flow_id %d\n", sizeof(flow_id));
  eprintf("state_entry %d\n", sizeof(state_entry));
  eprintf("connection %d\n", sizeof(connection));
  eprintf("pheader %d\n", sizeof(pcap_pkthdr));

  eprintf("os_asset %d\n", sizeof(os_asset));
  eprintf("serv_asset %d\n", sizeof(serv_asset));
  eprintf("asset %d\n", sizeof(asset));

  init_orchestrator();

  init_logging_agency();

  return 0;
}

void ecall_prads_gameover() {
  //end_sessions();
  clear_asset_list();
  //end_all_sessions();
  //del_known_services();

  close_orchestrator();

  close_logging_agency();
}

uint64_t ecall_prads_cxtrackerid() {
    return cxtrackerid;
    //return call_times;
}
