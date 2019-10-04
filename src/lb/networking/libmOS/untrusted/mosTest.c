#include "stdio.h"
#include "stdlib.h"

#include "include/mos_api.h"

int errno;
#define EXIT_WITH_ERROR(f, m...) {                                 \
		fprintf(stderr, "[%10s:%4d] errno: %u" f, __FUNCTION__, __LINE__, errno, ##m); \
	exit(EXIT_FAILURE);                                            \
}


struct thread_context
{
	mctx_t mctx;         /* per-thread mos context */
	int mon_listener;    /* listening socket for flow monitoring */
};

static int SYNnum = 0;
static int APPnum = 0;


static bool
CatchInitSYN(mctx_t mctx, int sockid,
	int side, uint64_t events, filter_arg_t *arg)
{
	
	struct pkt_info p;

	if (mtcp_getlastpkt(mctx, sockid, side, &p) < 0)
		EXIT_WITH_ERROR("Failed to get packet context!!!\n");

	fprintf(stdout, "call CatchInitSYN, %d\n", SYNnum++);
	//return (p.tcph->syn && !p.tcph->ack);
	return true;
}


static void
ApplyActionPerFlow(mctx_t mctx, int msock, int side,
	uint64_t events, filter_arg_t *arg)

{

	fprintf(stdout, "call ApplyActionPerFlow, %d\n", APPnum++);
	///* this function is called at the first SYN */
	//struct pkt_info p;
	//int opt;

	//if (mtcp_getlastpkt(mctx, msock, side, &p) < 0)
	//	EXIT_WITH_ERROR("Failed to get packet context!\n");

	//if (false) {
	//	// drop
	//	mtcp_setlastpkt(mctx, msock, side, 0, NULL, 0, MOS_DROP);
	//}
	//else {
	//	//stop monitoring
	//	/* no need to monitor this flow any more */
	//	opt = MOS_SIDE_BOTH;
	//	if (mtcp_setsockopt(mctx, msock, SOL_MONSOCKET,
	//		MOS_STOP_MON, &opt, sizeof(opt)) < 0)
	//	{
	//		EXIT_WITH_ERROR("Failed to stop monitoring conn with sockid: %d\n", msock);
	//	}
	//	else
	//	{
	//		printf("stop sock %d \n ", msock);
	//	}
	//}
}

static void
DumpFWRuleTable(mctx_t mctx, int sock, int side,
	uint64_t events, filter_arg_t *arg)
{
	printf("call DumpFWRuleTable, %d:%d\n", SYNnum, APPnum);
}

static void
CreateAndInitThreadContext(struct thread_context* ctx,
	int core, event_t  udeForSYN)
{
	struct timeval tv_1sec = { /* 5 second */
		.tv_sec = 5,
		.tv_usec = 0
	};

	ctx->mctx = mtcp_create_context(core);

	/* create socket  */
	ctx->mon_listener = mtcp_socket(ctx->mctx, AF_INET,
		MOS_SOCK_MONITOR_STREAM, 0);

	if (ctx->mon_listener < 0)
		EXIT_WITH_ERROR("Failed to create monitor listening socket!\n");

	/* register callback */
	if (mtcp_register_callback(ctx->mctx, ctx->mon_listener,
		udeForSYN,
		MOS_HK_RCV,
		ApplyActionPerFlow) == -1)
		EXIT_WITH_ERROR("Failed to register callback func!\n");

	/* CPU 0 is in charge of printing stats */
	if (ctx->mctx->cpu == 0 &&
		mtcp_settimer(ctx->mctx, ctx->mon_listener,
			&tv_1sec, DumpFWRuleTable))
		EXIT_WITH_ERROR("Failed to register timer callback func!\n");

}

static void
WaitAndCleanupThreadContext(struct thread_context* ctx)
{
	/* wait for the TCP thread to finish */
	mtcp_app_join(ctx->mctx);

	/* close the monitoring socket */
	mtcp_close(ctx->mctx, ctx->mon_listener);

	/* tear down */
	mtcp_destroy_context(ctx->mctx);
}


int mOsPrintPkt()
{
	char* fname = "./untrusted/mos.conf";

	int ret = mtcp_init(fname);
	if (ret)
		EXIT_WITH_ERROR("Failed to initialize mtcp.\n");

	struct mtcp_conf mcfg;
	mtcp_getconf(&mcfg);
	mcfg.num_cores = 1;
	mtcp_setconf(&mcfg);

	/* populate local mos-specific mcfg struct for later usage */
	mtcp_getconf(&mcfg);

	event_t initSYNEvent;
	initSYNEvent = mtcp_define_event(MOS_ON_PKT_IN, CatchInitSYN, NULL);

	if (initSYNEvent == MOS_NULL_EVENT)
		EXIT_WITH_ERROR("mtcp_define_event() failed!");

	struct thread_context ctx[1] = { { 0 } };

	/* initialize monitor threads */
	for (int i = 0; i < mcfg.num_cores; i++)
		CreateAndInitThreadContext(&ctx[i], i, initSYNEvent);

	/* wait until all threads finish */
	for (int i = 0; i < mcfg.num_cores; i++) {
		WaitAndCleanupThreadContext(&ctx[i]);
	}

	mtcp_destroy();

	return EXIT_SUCCESS;
}




