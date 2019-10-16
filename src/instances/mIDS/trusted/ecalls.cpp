
#include "Enclave.h"
#include "Enclave_t.h"
#include "dfc/dfc_adaptor.h"

#include <cstring> //strlen

void ecall_test()
{
	// begin test ocall printf
	printf("Begin test.\n");

	// test ocall time
	etime st, et;
	getTime(&st);
	printf("Timeing.\n");
	getTime(&et);
	printf("ocall print line use %d us.\n", diffTime(&st, &et));
	printf("current time is %lds, %ldns.\n", et.s, et.ns);

	// test ocall get data
	char* data;
	int len;
	ocall_get_data(1, &data, &len);
	
	printf("get data no.1 is \"%s\", len %d.\n", data, len);

	// test free data
	ocall_del(data, 0);

	// test get dir
	const int EACH_FILE_NAME_BUFFER_SIZE = 256;
	char* fileName = "./trusted/sgx";
	printf("List dir %s: \n", fileName);
	ocall_read_dir(fileName, &data, &len, 0);
	for (int i = 0; i < len; i++)
	{
		printf("%s\n", data + i * EACH_FILE_NAME_BUFFER_SIZE);
	}
	ocall_del(data, 1);

	// test file size
	fileName = "./trusted/ecalls.cpp";
	ocall_file_size(fileName, &len);
	printf("file \"%s\", len is %d.\n", fileName, len);

	// test file io
	printf("Test file io. We will load \"hi.txt\" if it exist, output it, \n\t\tthen, append one line \"hello!\" to it.\n");
	fileName = "./hi.txt";
	len = 0;
	ocall_read_file(fileName, &data, &len, 0);
	if (len > 0)
	{
		printf("print \"hi.txt\" context, size %d . \n", len);
		int strLen;
		char* strPos = data;
		while (len > 0)
		{
			strLen = strlen(strPos);
			printf("%s", strPos);
			len -= strLen + 1;
			if (len >= 2)
			{
				strPos += strLen + 1;
			}
			else
			{
				len = 0;
			}
		}
		ocall_free(data);
	}

	data = "hello!\n";
	ocall_write_file(fileName, data, 8, 1);
	printf("write file end.\n");

	// test rand
	printf("rand 0~4 20 times.\n");
	for (int i = 0; i < 20; i++)
	{
		int rnd;
		ocall_rand(&rnd, 5);
		printf("%d ", rnd);
	}
	printf("\n");

	printf("test dfc\n");
	char* pattern_pool = 0;
	int* pattern_length_pool = 0;
	int pattern_count = 0;

	ocall_dfc_init(&pattern_pool, &pattern_length_pool, &pattern_count);

	DFCAdaptor dfcAdp;

	getTime(&st);
	dfcAdp.init((unsigned char*)pattern_pool, pattern_length_pool, pattern_count);
	getTime(&et);
	printf("dfc init use %d us.\n", diffTime(&st, &et));


	unsigned char buffer[4096];

	getTime(&st);
	dfcAdp.process(buffer, sizeof(buffer));
	getTime(&et);
	printf("dfc process use %d us.\n", diffTime(&st, &et));
	


	printf("End test.\n");

	return;
}

extern "C"
{
#include "src/include/sgx/sgxFunc.h"
#include "src/include/mos_api.h"
#include "src/include/mtcp.h"
#include "src/include/tcp_stream.h"

#include "../src/lb/core/enclave/include/state_mgmt_t.h"
#include "../src/lb/core/enclave/include/etap_t.h"
}


int errno;
#define EXIT_WITH_ERROR(f, m...) {printf("Ecall error [%10s:%4d]: %s\n", __FUNCTION__, __LINE__, f);}

int DoCallTimes = 0;
int DoDfcTimes = 0;
//int DoPktSize = 0;
long long DoDfcSize = 0;
static int DoPktCount = 0;

DFCAdaptor dfcAdp;
mtcp_manager_t mtcp;

static void
ApplyDfcPerFlow(mctx_t mctx, int msock, int side,
	uint64_t events, filter_arg_t *arg)
{

	if (!mtcp)
	{
		mtcp = GetMTCPManager(mctx);
	}

	//struct tcp_stream * stream = mtcp->msmap[msock].monitor_stream->stream;

	////DoPktSize += stream->recv_pkt_size + stream->pair_stream->recv_pkt_size;
	////stream->recv_pkt_size = 0;
	////stream->pair_stream->recv_pkt_size = 0;
	//DoPktCount += stream->recv_pkt_count + stream->pair_stream->recv_pkt_count;
	//stream->recv_pkt_count = 0;
	//stream->pair_stream->recv_pkt_count = 0;

	const int len = 8200;
	static char buffer[len];

	//struct pkt_info p;
	//if (mtcp_getlastpkt(mctx, msock, side, &p) >= 0)
	//{
	//	totalPktCount += 1;
	//	totalPktSize += p.eth_len + 24;
	//}
	DoCallTimes += 1; 

	// the len is big enought to read all data in one times.
	ssize_t size;
	size = mtcp_peek(mctx, msock, side, buffer, len);
	//ssize_t size = mtcp_read(mctx, msock, buffer, len);
	if (size > 0)
	{
		dfcAdp.process((uint8_t*)buffer, len);
		DoDfcTimes += 1;
		DoDfcSize += size;
	}
	else if (size < 0)
	{
		//printf("peek failed. \n");
	}

	//const int printPktLoop = 1000000;

	//static etime beg = { 0,0 };
	//static etime end = { 0,0 };
	//if (beg.s)
	//{
	//	ocall_get_time2((int*)&beg.s, (int*)&beg.ns);
	//	ocall_get_time2((int*)&end.s, (int*)&end.ns);
	//}

	//if (DoPktCount > printPktLoop)
	//{

	//	static char* fileName = "./pkt_delay.csv";
	//	static char str[128];
	//	static long long totalCount = 0;

	//	ocall_get_time2((int*)&end.s, (int*)&end.ns);
	//	totalCount += DoPktCount;

	//	snprintf(str, 128, "Total,%lld,Delay,%d,us gap is,%d\n", totalCount, diffTime(&beg, &end), DoPktCount);

	//	printf(str);
	//	ocall_write_file(fileName, str, strlen(str), 1);

	//	//printf("DFC Avg-ThroughPut:%lf Mbps/s, #Flow:%d, #Recall:%d, DFC_Pkt:%d\n"
	//	//	, (DoPktSize)*8.0 / 1000/1000/diffTime(&beg, &end)*1000*1000, mtcp->flow_cnt, DoCallTimes, DoPktCount);

	//	beg = end;
	//	DoCallTimes = 0;
	//	//DoDfcTimes = 0;
	//	DoPktCount = 0;
	//	//DoPktSize = 0;
	//}




	//printf("call ApplyDfcPerFlow, ThroughPut:%d, DoDfcTimes:%d, size:%d, res:%d\n", CallTimes, DoDfcTimes, DoDfcSize, DfcResCount);
}

extern long sys_mem_allocated;
static void
PrintThrouthPut(mctx_t mctx, int sock, int side,
	uint64_t events, filter_arg_t *arg)
{
	if (!mtcp)
	{
		mtcp = GetMTCPManager(mctx);
	}

	if (false)
	{
		printf("tcp value %d is mtcp->g_sender->control_list_cnt\n", mtcp->g_sender->control_list_cnt);
		printf("tcp value %d is mtcp->g_sender->send_list_cnt\n", mtcp->g_sender->send_list_cnt);
		printf("tcp value %d is mtcp->g_sender->ack_list_cnt\n", mtcp->g_sender->ack_list_cnt);
		printf("tcp value %d is mtcp->rto_list_cnt\n", mtcp->rto_list_cnt);
		printf("tcp value %d is mtcp->timewait_list_cnt\n", mtcp->timewait_list_cnt);
		printf("tcp value %d is mtcp->timeout_list_cnt\n", mtcp->timeout_list_cnt);
		printf("tcp value %d is mtcp->num_msp)\n", mtcp->num_msp);
		printf("tcp value %d is mtcp->num_esp\n", mtcp->num_esp);
		printf("tcp value %d is mtcp->s_index\n", mtcp->s_index);
		printf("tcp value %d is mtcp->flow_cnt\n", mtcp->flow_cnt);
	}
	//printf("TIMER #Flow:%d Mem: %fMB\n" ,  mtcp->flow_cnt, sys_mem_allocated/1024.0/1024.0);


	//printf("TIMER Avg-ThroughPut:%lf Mbps/s, #Flow:%d, #Recall:%d, #DFC:%d, DFC_Pkt:%d\n"
	//	, (DoPktSize)*8.0/1000/1000, mtcp->flow_cnt, DoCallTimes, DoDfcTimes, DoPktCount);
	//
	//DoCallTimes = 0;
	//DoDfcTimes = 0;
	//DoPktCount = 0;
	//DoPktSize = 0;

	struct timeval tv_1sec = { /* 1 second */
		.tv_sec = 10,
		.tv_usec = 0
	};

	if (mtcp_settimer(mctx, sock, &tv_1sec, PrintThrouthPut))
		EXIT_WITH_ERROR("mtcp_settimer() error\n");
}


extern etap_controller_t* etap_controller_instance;

int mOsIDS(const char* config_file_path)
{
#if LightBox == 1
	//lightbox init
	init_state_mgmt();
	etap_controller_instance = etap_controller_init(0, 0);
#endif


	//TRACE_CONFIG("Test TRACE_CONFIG ok.\n");
	//TRACE_ERROR("Test TRACE_ERROR ok.\n");
	//TRACE_INFO("Test TRACE_INFO ok.\n");
	//TRACE_FUNC("TRACE_FUNC1", "Test TRACE_FUNC ok.\n");
	printf("tcp_stream size is %d\n", sizeof(struct tcp_stream));
    printf("tcp_send_vars is %d\n", sizeof(struct tcp_send_vars));
    printf("tcp_recv_vars is %d\n", sizeof(struct tcp_recv_vars));


	char* fname = "./trusted/mos.conf";

	int ret = mtcp_init(fname);
	if (ret)
		EXIT_WITH_ERROR("Failed to initialize mtcp.\n");

	struct mtcp_conf mcfg;
	mtcp_getconf(&mcfg);
	mcfg.num_cores = 1;
	mtcp_setconf(&mcfg);

	/* populate local mos-specific mcfg struct for later usage */
	mtcp_getconf(&mcfg);

	mctx_t mctx;         /* per-thread mos context */
	int mon_listener;    /* listening socket for flow monitoring */

	struct timeval tv_1sec = { /* 5 second */
		.tv_sec = 5,
		.tv_usec = 0
	};

	mctx = mtcp_create_context(0);

	/* create socket  */
	mon_listener = mtcp_socket(mctx, AF_INET, MOS_SOCK_MONITOR_STREAM, 0);

	if (mon_listener < 0)
		EXIT_WITH_ERROR("Failed to create monitor listening socket!\n");

	//if (mtcp_register_callback(mctx, mon_listener, 
	//	MOS_ON_PKT_IN,  
	//	MOS_HK_RCV, 
	//	ApplyDfcPerFlow) < 0)
	//	EXIT_WITH_ERROR("Failed to register callback func!\n");

	//if (mtcp_register_callback(mctx, mon_listener, 
	//	MOS_ON_CONN_END,
	//	MOS_HK_RCV, 
	//	ApplyDfcPerFlow) < 0)
	//	EXIT_WITH_ERROR("Failed to register callback func!\n");

	if (mtcp_register_callback(mctx, mon_listener,
		MOS_ON_ERROR,
		MOS_NULL,
		ApplyDfcPerFlow) < 0)
		EXIT_WITH_ERROR("Failed to register callback func!\n");

	/* CPU 0 is in charge of printing stats */
	if (mtcp_settimer(mctx, mon_listener,
			&tv_1sec, PrintThrouthPut))
		EXIT_WITH_ERROR("Failed to register timer callback func!\n"); 

	/* Prepare dfc adaptor*/
	char* pattern_pool = 0;
	int* pattern_length_pool = 0;
	int pattern_count = 0;
	ocall_dfc_init(&pattern_pool, &pattern_length_pool, &pattern_count);
	dfcAdp.init((unsigned char*)pattern_pool, pattern_length_pool, pattern_count);

	RunMainLoop(0);

	/* wait for the TCP thread to finish */
	mtcp_app_join(mctx);

	/* close the monitoring socket */
	mtcp_close(mctx, mon_listener);

	/* tear down */
	mtcp_destroy_context(mctx);
	mtcp_destroy();

	return EXIT_SUCCESS;
}


void ecall_mos_test(const char* config_file_path)
{
	mOsIDS(config_file_path);
}
