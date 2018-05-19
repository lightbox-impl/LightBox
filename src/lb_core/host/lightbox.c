#include "lightbox.h"

#include "lb_edge_u.h"

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
    etap_init();

    /* AES_GCM keys */
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
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
    etap_deinit();

    pthread_kill(mb_trd, SIGKILL);
}

/* etap */
void *etap_thread(void *tput)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    //double rlt = 0;
    ret = ecall_etap_start(global_eid, tput, etap_args.record_size, etap_args.record_per_batch);
    if (ret != SGX_SUCCESS) {
        printf("[*] etap_thread fail! %x\n", ret);
        pthread_exit(NULL);
    }
    pthread_exit(NULL);
}

/* test... */
void lb_run(mb_fun_t mb_thread)
{
    /* run mb thread */
    pthread_create(&mb_trd, NULL, mb_thread, NULL);

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