#include "../common/lwids_type.h"

#include "lwids_edge_u.h"
#include <host/include/lightbox.h>

#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>

extern sgx_enclave_id_t global_eid;

exp_data_t exp_data;
lwids_param_t lwids_param;

void lwids_deinit(int sig)
{
    sgx_status_t ret = ecall_lwids_deinit(global_eid);
    if (ret != SGX_SUCCESS) {
        printf("[*] ecall_lwids_deinit fail with error %d\n", ret);
        pthread_exit(NULL);
    }

    lb_deinit();
}

int lwids_default_config()
{
    lwids_param.pattern_count = 10;
    lwids_param.num_round = 10;
    lwids_param.round_size = 1000000;
    lwids_param.is_caida = 0;
}

int lwids_init(int argc, char *argv[])
{
    printf("Initializing lwIDS ... \n");
    memset(&exp_data, 0, sizeof(exp_data));

    lwids_default_config();

    /* parameters parsing */
    if (argc < 4)
    {
        fprintf(stderr, "Some default options will be used\n\n");
        fprintf(stderr, "+ Options:\n");
        fprintf(stderr, "\t-p | Pattern count\n");
        fprintf(stderr, "\t-r | Round size\n");
        fprintf(stderr, "\t-n | Number of round\n");
        fprintf(stderr, "\t-c | Use CAIDA trace\n");
        //exit(1);
    }
    int c;
    while (1)
    {
        int option_index = 0;

        if ((c = getopt(argc, argv, "p:r:n:c")) < 0)
            break;

        switch (c)
        {
        case 'p':
            lwids_param.pattern_count = atoi(optarg);
            fprintf(stderr, "[i] pattern count: %d\n", lwids_param.pattern_count);
            break;
        case 'r':
            lwids_param.round_size = atoi(optarg);
            fprintf(stderr, "[i] round size: %d\n", lwids_param.round_size);
            break;
        case 'n':
            lwids_param.num_round = atoi(optarg);
            fprintf(stderr, "[i] number of rounds: %d\n", lwids_param.num_round);
            break;
        case 'c':
            lwids_param.is_caida = 1;
            fprintf(stderr, "[i] using CAIDA trace\n");
            break;
        default :
            fprintf(stderr, "[i] unrecognized argument: %s!\n", optarg);
        }
    }

    signal(SIGINT, &lwids_deinit);
    signal(SIGTERM, &lwids_deinit);

    /* Initialization counterpart within enclave */
    sgx_status_t ret = ecall_lwids_init(global_eid, &lwids_param, &exp_data);
    if (ret != SGX_SUCCESS) {
        printf("[*] ecall_lwids_init fail! with error %d\n", ret);
        pthread_exit(NULL);
    }
}

void *lwids_main_loop(void *useless)
{
    sgx_status_t ret = ecall_lb_lwids_run(global_eid);
    if (ret != SGX_SUCCESS) {
        printf("[*] ecall_lb_lwids_run fail!\n");
        pthread_exit(NULL);
    }
}

#if MSG64==0
int lwids_main(int argc, char *argv[])
{
    lwids_init(argc, argv);

    /* Start of Lightbox instance */
    lb_init();

    lb_run(lwids_main_loop);

    lb_deinit();
    /* End of Lightbox */

    lwids_deinit(SIGTERM);
}
#else
#include <pcap.h>
pcap_t *pcap_handle;
typedef struct {
    uint8_t data[MAX_FRAME_SIZE];
} packet_t;

#include <netinet/ip.h>
int lwids_main(int argc, char *argv[])
{
    /* lb_lwIDS init without LightBox networking module */
    lwids_init(argc, argv);

    /* pcap init */
    char errbuf[PCAP_ERRBUF_SIZE];
    if ((pcap_handle = pcap_open_live("eth0", MAX_FRAME_SIZE, 0, 500, errbuf)) == NULL) {
        printf("[!] Error pcap_open_live: %s \n", errbuf);
        exit(1);
    }
    struct bpf_program  cfilter;
    const char bpff[] = "dst host 10.0.0.12";
    if ((pcap_compile(pcap_handle, &cfilter, bpff, 1, 0)) == -1) {
        printf("[*] Error pcap_compile user_filter: %s\n", pcap_geterr(pcap_handle));
        exit(1);
    }

    if (pcap_setfilter(pcap_handle, &cfilter)) {
        printf("[*] Unable to set pcap filter!  %s", pcap_geterr(pcap_handle));
    }
    pcap_freecode(&cfilter);

    /* start testing */
    packet_t *pkt_buffer = 0;
    struct pcap_pkthdr *pkt_hdr = 0;
    unsigned long long total_byte = 0;
    int buf_idx = 0;

    pkt_buffer = calloc(TEST_ITVL, sizeof(*pkt_buffer));
    pkt_hdr = calloc(TEST_ITVL, sizeof(*pkt_hdr));

    const unsigned char	*crt_pkt = 0;
    struct pcap_pkthdr crt_hdr;
    
    while (1) {
        while (1) {
            crt_pkt = pcap_next(pcap_handle, &crt_hdr);
            if (!crt_pkt)
                continue;

            memcpy(pkt_buffer[buf_idx].data, crt_pkt, crt_hdr.caplen);
            memcpy(&pkt_hdr[buf_idx], &crt_hdr, sizeof(struct pcap_pkthdr));
            ++buf_idx;
            total_byte += crt_hdr.caplen;

            if (buf_idx == TEST_ITVL) {
                sgx_status_t ret = ecall_process_test_round(global_eid, pkt_buffer, pkt_hdr);
                if (ret != SGX_SUCCESS) {
                    printf("[*] ecall_process_test_round fail with error %d\n", ret);
                    exit(1);
                }

                buf_idx = 0;
                total_byte = 0;
            }
        }
    }
}
#endif
