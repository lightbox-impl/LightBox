#include <assert.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#ifndef TRUE
# define TRUE 1
#endif

#ifndef FALSE
# define FALSE 0
#endif

# define MAX_PATH FILENAME_MAX

# define TOKEN_FILENAME   "enclave.token"
# define ENCLAVE_FILENAME "enclave.signed.so"

#include "sgx_urts.h"
#include "prads_u.h"

#include "prads.h"
#include "config.h"
#include "sys_func.h"
#if SGBOX==1
#include "sg-box/state_orchestrator.h"
#endif
#if LOG_AGENCY==1
#include "sg-box/log_agency_u.h"
#endif

/***********  PRADS - G L O B A L S ***********/
extern globalconfig config;

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
  sgx_status_t err;
  const char *msg;
  const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
  {
    SGX_ERROR_UNEXPECTED,
    "Unexpected error occurred.",
    NULL
  },
  {
    SGX_ERROR_INVALID_PARAMETER,
    "Invalid parameter.",
    NULL
  },
  {
    SGX_ERROR_OUT_OF_MEMORY,
    "Out of memory.",
    NULL
  },
  {
    SGX_ERROR_ENCLAVE_LOST,
    "Power transition occurred.",
    "Please refer to the sample \"PowerTransition\" for details."
  },
  {
    SGX_ERROR_INVALID_ENCLAVE,
    "Invalid enclave image.",
    NULL
  },
  {
    SGX_ERROR_INVALID_ENCLAVE_ID,
    "Invalid enclave identification.",
    NULL
  },
  {
    SGX_ERROR_INVALID_SIGNATURE,
    "Invalid enclave signature.",
    NULL
  },
  {
    SGX_ERROR_OUT_OF_EPC,
    "Out of EPC memory.",
    NULL
  },
  {
    SGX_ERROR_NO_DEVICE,
    "Invalid SGX device.",
    "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
  },
  {
    SGX_ERROR_MEMORY_MAP_CONFLICT,
    "Memory map conflicted.",
    NULL
  },
  {
    SGX_ERROR_INVALID_METADATA,
    "Invalid enclave metadata.",
    NULL
  },
  {
    SGX_ERROR_DEVICE_BUSY,
    "SGX device was busy.",
    NULL
  },
  {
    SGX_ERROR_INVALID_VERSION,
    "Enclave version was invalid.",
    NULL
  },
  {
    SGX_ERROR_INVALID_ATTRIBUTE,
    "Enclave was not authorized.",
    NULL
  },
  {
    SGX_ERROR_ENCLAVE_FILE_ACCESS,
    "Can't open enclave file.",
    NULL
  },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
  size_t idx = 0;
  size_t ttl = sizeof sgx_errlist / sizeof sgx_errlist[0];

  for (idx = 0; idx < ttl; idx++) {
    if (ret == sgx_errlist[idx].err) {
      if (NULL != sgx_errlist[idx].sug)
        printf("Info: %s\n", sgx_errlist[idx].sug);
      printf("Error: %s\n", sgx_errlist[idx].msg);
      break;
    }
  }

  if (idx == ttl)
    printf("Error: Unexpected error occurred.\n");
}

/* Initialize the enclave:
*   Step 1: try to retrieve the launch token saved by last transaction
*   Step 2: call sgx_create_enclave to initialize an enclave instance
*   Step 3: save the launch token if it is updated
*/
int initialize_enclave(void)
{
  char token_path[MAX_PATH] = { '\0' };
  sgx_launch_token_t token = { 0 };
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  int updated = 0;

  /* Step 1: try to retrieve the launch token saved by last transaction
  *         if there is no token, then create a new one.
  */
  /* try to get the token saved in $HOME */
  const char *home_dir = getpwuid(getuid())->pw_dir;

  if (home_dir != NULL &&
    (strlen(home_dir) + strlen("/") + sizeof(TOKEN_FILENAME) + 1) <= MAX_PATH) {
    /* compose the token path */
    strncpy(token_path, home_dir, strlen(home_dir));
    strncat(token_path, "/", strlen("/"));
    strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME) + 1);
  }
  else {
    /* if token path is too long or $HOME is NULL */
    strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
  }

  FILE *fp = fopen(token_path, "rb");
  if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
    printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
  }

  if (fp != NULL) {
    /* read the token from saved file */
    size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
    if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
      /* if token is invalid, clear the buffer */
      memset(&token, 0x0, sizeof(sgx_launch_token_t));
      printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
    }
  }
  /* Step 2: call sgx_create_enclave to initialize an enclave instance */
  /* Debug Support: set 2nd parameter to 1 */
  ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
  if (ret != SGX_SUCCESS) {
    print_error_message(ret);
    if (fp != NULL) fclose(fp);
    return -1;
  }
  printf("Enclave id : %lu\n", global_eid);

  /* Step 3: save the launch token if it is updated */
  if (updated == FALSE || fp == NULL) {
    /* if the token is not updated, or file handler is invalid, do not perform saving */
    if (fp != NULL) fclose(fp);
    return 0;
  }

  /* reopen the file with write capablity */
  fp = freopen(token_path, "wb", fp);
  if (fp == NULL) return 0;
  size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
  if (write_num != sizeof(sgx_launch_token_t))
    printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
  fclose(fp);
  return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
  /* Proxy/Bridge will check the length and null-terminate
  * the input string to prevent buffer overflow.
  */
  printf("%s", str);
}

#include <time.h>
void ocall_get_time(int *second, int *nanosecond)
{
    struct timespec wall_clock;
    clock_gettime(CLOCK_REALTIME, &wall_clock);
    *second = wall_clock.tv_sec;
    *nanosecond = wall_clock.tv_nsec;
}

void ocall_sleep(long time_ns)
{
	static struct timespec ts = { 0, 0 };
	static struct timespec rem;
	ts.tv_nsec = time_ns;
	nanosleep(&ts, &rem);
}

void ocall_random(uint32_t *r)
{
	uint32_t rlt = rand()%UINT32_MAX;
	*r = rlt;
}

/* timing */
static struct timespec start_time, end_time;
#define timer_start clock_gettime(CLOCK_REALTIME, &start_time)
#define timer_end   clock_gettime(CLOCK_REALTIME, &end_time)
//long inline time_elapsed_in_us(const struct timespec *start, const struct timespec *end) {
//  return (end->tv_sec - start->tv_sec) * 1000000.0 +
//         (end->tv_nsec - start->tv_nsec) / 1000.0;
//}
//long inline time_elapsed_in_ms(const struct timespec *start, const struct timespec *end) {
//    return (end->tv_sec - start->tv_sec) * 1000.0 +
//           (end->tv_nsec - start->tv_nsec) / 1000000.0;
//}

/* Traffic buffers */
struct pcap_pkthdr pheader_buffer[FERRY_UNIT];
uint8_t ferry[FERRY_UNIT][MAX_PACKET_LEN];
int ferried_count = 0;
uint8_t ferry_mac[16] = { 0 };
int ferry_len = 0;

uint8_t naive_packets[FERRY_UNIT][MAX_PACKET_LEN];
uint8_t naive_mac[FERRY_UNIT][16];

#define ferry_ready ferried_count == FERRY_UNIT

#define add_packet_to_ferry(pheader, packet)      \
          pheader_buffer[ferried_count] = *pheader; \
          memcpy(ferry[ferried_count], packet, pheader->caplen); \
          ++ferried_count

#define clear_ferry ferried_count = 0

#define ferry_parameter pheader_buffer, ferry, ferry_len, FERRY_UNIT, ferry_mac

int batch_id = 0;
FILE *batch_latency_logger;
time_t expr_check_time; // low precision
struct timespec log_check_time = { .tv_sec = 0, .tv_nsec = 0 }; // high precision
void on_packet_arrival(u_char * useless, const struct pcap_pkthdr *pheader,
                       const u_char * packet)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    struct timespec check_time;
    clock_gettime(CLOCK_REALTIME, &check_time);

    if ((pheader->ts.tv_sec - expr_check_time) > EXPR_CHECK_TIMEOUT) {
    //if ((check_time.tv_sec - expr_check_time) > EXPR_CHECK_TIMEOUT) {
        /*if (last_check_time != 0) {
            printf(" [%d - %d] \n", last_check_time, pheader->ts.tv_sec);
        }*/
        //last_check_time = pheader->ts;
        expr_check_time = pheader->ts.tv_sec;
#if SGBOX==1
        int expired_count = end_sessions(expr_check_time);
        ret = ecall_sync_expiration(global_eid, expired_count);
        if (ret != SGX_SUCCESS) {
            printf("[*] Fail to sync expiration checking result!\n");
        }
#else
        ret = ecall_check_expiration(global_eid, expr_check_time);
        if (ret != SGX_SUCCESS) {
            printf("[*] Fail to check flow expiration!\n");
        }
#endif
    }

    add_packet_to_ferry(pheader, packet);
    ferry_len += pheader->caplen; // record true packet length for our trick

    if (ferry_ready) {
        ++batch_id;
        //if(batch_id%1000 == 0)
            printf("Batch %d ", batch_id);
    
        // secure ferry trick
        int auth_enc_rlt;

//#if SGBOX==1
//        ret = ecall_auth_enc(global_eid, &auth_enc_rlt, &ferry[0][0], ferry_len, &ferry[0][0], ferry_mac);
//        if (ret != SGX_SUCCESS) {
//            printf("[*] Fail to encrypt ferry!\n");
//            abort();
//        }
//        if (!auth_enc_rlt) {
//            printf("[*] auth_enc fail!\n");
//            abort();
//        }
//#else
        int i;
//        for (i = 0; i < FERRY_UNIT; ++i) {
//            ret = ecall_auth_enc(global_eid, &auth_enc_rlt, &ferry[i][0], pheader_buffer[i].caplen, &naive_packets[i][0], &naive_mac[i]);
//            if (ret != SGX_SUCCESS) {
//                printf("[*] Fail to encrypt ferry!\n");
//                abort();
//            }
//            if (!auth_enc_rlt) {
//                printf("[*] auth_enc fail!\n");
//                abort();
//            }
//        }
//#endif

        // collect stats
        int miss_count = 0;
        int bundle_count = 0;
        int state_count = 0;

        timer_start;
#if SGBOX==1
        // when SG-BOX is enabled the state_count is only appproximation of the real number
        ret = ecall_secure_ferry(global_eid, ferry_parameter, &miss_count, &bundle_count, &state_count);
        if (ret != SGX_SUCCESS) {
            printf("[*] Failed to process batch!\n");
        }
        clear_ferry;
#if LOG_AGENCY==1
        /*if (time_elapsed_in_us(&log_check_time, &check_time) / 1000 > LOG_FLUSH_TIMEOUT) {
            log_check_time = check_time;
            log_flush_timeout();
        }*/
#endif
#else
        for (i = 0; i < FERRY_UNIT; ++i) {
            ret = ecall_naive_process(global_eid, 
                                      &pheader_buffer[i], &ferry[i][0], pheader_buffer[i].caplen, &naive_mac[i],
                                      &state_count);
            if (ret != SGX_SUCCESS) {
                printf("[*] Fail to process packet!\n");
                abort();
            }
        }
        clear_ferry;
#endif
        timer_end;

        state_count = config.log_start_flow_threshold + 1;
        /* logging */
        if (ret == SGX_SUCCESS && state_count > config.log_start_flow_threshold) {
            /*fprintf(batch_latency_logger, "%d\t%d\t%d\t%d\t%d\n", 
                    batch_id, time_elapsed_in_us(&start_time, &end_time), 
                    state_count, miss_count, bundle_count);*/
        }
    
        //if (batch_id % 1000 == 0)
            //printf("finished in %dus! %d flows under tracking\n", time_elapsed_in_us(&start_time, &end_time), state_count);

        if (state_count > TEST_MAX_STATE_COUNT) {
            printf("[*] Test finished with %d flows!\n", state_count);
            pcap_breakloop(config.handle);
        }
        ferry_len = 0;  
    }
}

extern int nets;
extern fmask network[MAX_NETS];
#include "utils/host/sgbox_utils_u.h"
extern mem_pool_node os_asset_pool;
extern mem_pool_node serv_asset_pool;
extern mem_pool_node asset_pool;
void init_prads_enclave()
{
  if (initialize_enclave() < 0) {
    printf("[*] Enclave initialization fails ...\n");
    printf("[*] Enter a character before exit ...\n");
    getchar();
    abort();
  }
  printf("[*] Enclave initialization succeeds! \n");

//#if SGBOX==1
//  sgbox_init_mem_pools();
//#endif
//
//  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
//  int rlt = -1;
//  ret = ecall_prads_initialize(global_eid, &rlt, &config, nets, network,
//                               os_asset_pool.pool, serv_asset_pool.pool, asset_pool.pool);
//  if (ret != SGX_SUCCESS || rlt==-1) {
//    printf("[*] PRADS initialization inside enclave fails...\n");
//    printf("[*] Enter a character before exit ...\n");
//    getchar();
//    abort();
//  }
//  
//  printf("[*] PRADS initialization inside enclave succeeds! \n");
//  printf("[*] SGBOX is %s!\n", (SGBOX == 1) ? "enabled" : "disabled");
//  if(SGBOX==1)
//    printf("[*] Cache size %dM!\n", STATE_CACHE_CAPACITY*STATE_ENTRY_SIZE/1024/1024);
//  printf("[*] Log agency is %s!\n", (LOG_AGENCY == 1) ? "enabled" : "disabled");
//  if(LOG_AGENCY==1)
//    printf("[*] Logging at %dms timeout!\n", LOG_FLUSH_TIMEOUT);
}

//void etap_throughput_benchmark();
//void etap_throughput_realtrace();

//void test_aes_gcm_trick();
//void simple_test_server();
//void simple_test_client();
//void test_lb_prads_real();
void lb_state_test();
void lb_prads_test();

void pcre_patterns()
{
	static char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	
}

// main loop
void start_prads()
{
  /*olog("[*] Sniffing...\n");
  pcap_loop(config.handle, TEST_MAX_PKT_COUNT, on_packet_arrival, NULL);
  printf("[*] No more packets! Loop ended!\n");*/
  
	//etap_throughput_benchmark();
	//etap_throughput_realtrace();
	//etap_test_live();
	//test_aes_gcm_trick();
	//simple_test_server();
	//simple_test_client();

	//lb_state_test();
	lb_prads_test();
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

#if SGBOX==1
  sgbox_free_mem_pools();
#endif

  fclose(batch_latency_logger);
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

void lb_prads_test_done(int);
/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
  (void)(argc);
  (void)(argv);

  signal(SIGTERM, stop_prads);
  signal(SIGQUIT, stop_prads);
  signal(SIGTSTP, stop_prads); // Ctrl + z
  signal(SIGINT, lb_prads_test_done); // Ctrl + c
  //signal(SIGALRM, set_end_sessions);
  //signal(SIGUSR1, set_end_sessions);

  /* Initialize PRADS outside enclave */
  init_prads_main(argc, argv);

  /* Initialize the enclave and PRADS inside it*/
  init_prads_enclave(); 

  /* Run PRADS main loop */
  start_prads();

  //stop_prads(SIGQUIT);
  return 0;
}

