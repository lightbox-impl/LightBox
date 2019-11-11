#include "lightbox.h"

#include "lb_core_edge_u.h"

#include <sgx_urts.h>

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

extern sgx_enclave_id_t global_eid;

extern etap_param_t etap_args;

pthread_t mb_trd;

FILE *out;

void lb_init()
{
    out = fopen("lb_log.txt", "wb");

    /* etap */
    etap_network_init();

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int etap_ctrl_init_ret = -1;
    ret = ecall_etap_controller_init(global_eid, &etap_ctrl_init_ret, 0, 0);
    if (ret != SGX_SUCCESS) {
        printf("[*] ecall_etap_controller_init fail! %x\n", ret);
    }
    else{
        printf("[*] ecall_etap_controller_init success!\n");
    }

    /* AES_GCM keys */
    ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_init_aes_gcm(global_eid);
    if (ret != SGX_SUCCESS) {
        printf("[*] ecall_init_aes_gcm fail with error %d\n", ret);
        exit(1);
    }
}

void lb_deinit()
{
    fclose(out);

    /* etap module */
    etap_network_deinit();

    pthread_kill(mb_trd, SIGKILL);
}

/* etap */
void *etap_thread(void *tput)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    // now default CAIDA mode ...
    ret = ecall_etap_start(global_eid, tput, etap_args.record_size, etap_args.record_per_batch);
    //TODO: refactor the test mode selection logic, may roll back to previous version
// #if CAIDA == 1
//     ret = ecall_etap_start(global_eid, tput, etap_args.record_size, etap_args.record_per_batch);
// #elif LIVE == 1
//     ret = ecall_etap_start_live(global_eid, tput, etap_args.record_size, etap_args.record_per_batch);
// #elif MICRO == 1
//     ret = ecall_etap_start_micro(global_eid, tput, etap_args.record_size, etap_args.record_per_batch);
// #else
//     printf("Error test mode!\n");
//     abort();
// #endif
    if (ret != SGX_SUCCESS) {
        printf("[*] ecall_etap_start fail! %x\n", ret);
    }

    pthread_exit(NULL);
}

/* test... */
void lb_run(mb_fun_t mb_entry)
{
    /* run mb thread */
    pthread_create(&mb_trd, NULL, mb_entry, NULL);

    /* run etap thread */
    // loop for test cases where multiple rounds of transmission are needed.
    while (etap_testrun()) {
        pthread_t etap_trd;

        // rely on etap_thread to report test stats
        double tput;
        int rc = pthread_create(&etap_trd, NULL, etap_thread, &tput);
        if (rc) {
            printf("Fail to create thread %lu\n!", etap_trd);
            exit(1);
        }

        rc = pthread_join(etap_trd, NULL);
        if (rc) {
            printf("Fail to join thread %lu\n!", etap_trd);
            exit(1);
        }
    }

    lb_deinit();
}

void ocall_lb_log(int round, int pkt_count, double delay, double tput, int flow)
{
    fprintf(out, "round %d - pkt %d - delay %f - tput %f - flow %d\n", round, pkt_count, delay, tput, flow);
}