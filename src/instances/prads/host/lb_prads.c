#include <assert.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>

#include <pcap.h> // used by config.h

#include "mem_utils_u.h"
#include "sgx_urts.h"
#include "prads_edge_u.h"
#include "prads_core/prads.h"
#include "prads_core/config.h"
#include <lightbox.h>

extern globalconfig config;
extern sgx_enclave_id_t global_eid;

// #include <time.h>
// void ocall_get_time(int *second, int *nanosecond)
// {
//     struct timespec wall_clock;
//     clock_gettime(CLOCK_REALTIME, &wall_clock);
//     *second = wall_clock.tv_sec;
//     *nanosecond = wall_clock.tv_nsec;
// }

// void ocall_sleep(long time_ns)
// {
// 	static struct timespec ts = { 0, 0 };
// 	static struct timespec rem;
// 	ts.tv_nsec = time_ns;
// 	nanosleep(&ts, &rem);
// }

// void ocall_random(uint32_t *r)
// {
// 	uint32_t rlt = rand()%UINT32_MAX;
// 	*r = rlt;
// }

extern int nets;
extern fmask network[MAX_NETS];
extern mem_pool_node os_asset_pool;
extern mem_pool_node serv_asset_pool;
extern mem_pool_node asset_pool;
void init_prads_enclave()
{
#if LightBox==1
  mem_util_init_pools();
#endif

  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  int rlt = -1;
  ret = ecall_prads_initialize(global_eid, &rlt, &config, nets, network,
                               os_asset_pool.pool, serv_asset_pool.pool, asset_pool.pool);
 if (ret != SGX_SUCCESS || rlt==-1) {
   printf("[*] PRADS initialization inside enclave fails...\n");
   printf("[*] Enter a character before exit ...\n");
   getchar();
   abort();
 }
 
 printf("[*] PRADS initialization inside enclave succeeds! \n");
 // printf("[*] LightBox is %s!\n", (LightBox == 1) ? "enabled" : "disabled");
 // if(LightBox==1)
 //   printf("[*] Cache size %dM!\n", STATE_CACHE_CAPACITY*STATE_ENTRY_SIZE/1024/1024);
 // printf("[*] Log agency is %s!\n", (LOG_AGENCY == 1) ? "enabled" : "disabled");
 // if(LOG_AGENCY==1)
 //   printf("[*] Logging at %dms timeout!\n", LOG_FLUSH_TIMEOUT);
}

void pcre_patterns()
{
	static char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	
}

void stop_prads(int sig) {
  printf("[*] Stopping Prads ...\n");

  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  /* Collect stats maintained inside enclave*/
  printf("[*] Collecting stats inside enclave ...\n");
  uint64_t cxtrackerid = 0;
  ret = ecall_prads_cxtrackerid(global_eid, &cxtrackerid);
  if (ret != SGX_SUCCESS || cxtrackerid == 0) {
    printf("[*] Fail to collect some stats from enclave ...\n");
  }
  
  /* Clear prads inside encalve */
  ret = ecall_prads_gameover(global_eid);
  if (ret != SGX_SUCCESS ) {
    printf("[*] Fail to close up prads inside enclave, but it's okay as we are tearing down the entire enclave ...\n");
  }

  /* Destroy the enclave */
  sgx_destroy_enclave(global_eid);

  printf("[*] Prads Enclave successfully returned.\n");

  /* Clean prads buffer outside enclave */
  game_over(cxtrackerid);

#if LightBox==1
  mem_util_free_pools();
#endif

  // fclose(batch_latency_logger);
}

//void report_prads_state(int sig) {
//  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
//  int cxt_count = 0;
//  ret = ecall_prads_states(global_eid, &cxt_count);
//  if (ret != SGX_SUCCESS ) {
//    printf("[*] Fail to collect stats from enclave ...\n");
//  }
//  printf("[*] Number of concurrently tracked flows: %d \n", cxt_count);
//}

void prads_init(int argc, char *argv[])
{
  /* Initialize PRADS outside enclave */
  init_prads_host(argc, argv);

  /* Initialize PRADS inside enclave */
  init_prads_enclave(); 
}

void prads_deinit()
{
  stop_prads(SIGQUIT);
}

void *prads_main_loop(void *useless)
{
    printf("%s started \n", __func__);

    sgx_status_t ret = ecall_lb_prads_run(global_eid);
    if (ret != SGX_SUCCESS) {
        printf("[*] ecall_lb_lwids_run fail!\n");
        pthread_exit(NULL);
    }

    printf("%s finished \n", __func__);
}

int lb_prads_main(int argc, char *argv[])
{
  signal(SIGTERM, stop_prads);
  signal(SIGQUIT, stop_prads);
  signal(SIGTSTP, stop_prads); // Ctrl + z
  signal(SIGINT, stop_prads); // Ctrl + c

  prads_init(argc, argv);

  /* Start of Lightbox instance */
  lb_init();

  lb_run(prads_main_loop);

  lb_deinit();
  /* End of Lightbox */

  prads_deinit();
}

