#include "include/sgx/sgxFunc.h"


#define __MOS_CORE_

#include <string.h>
#include <stdbool.h>

#include "ip_in.h"
#include "ip_out.h"
#include "tcp.h"
#include "mtcp_api.h"
#include "debug.h"
#include "mos_api.h"
#include "icmp.h"
#include "config.h"

#define ETH_P_IP_FRAG   0xF800
#define ETH_P_IPV6_FRAG 0xF6DD


/*----------------------------------------------------------------------------*/
inline void
FillInPacketIPContext (struct pkt_ctx *pctx, struct iphdr *iph, int ip_len)
{
	pctx->p.iph = iph;
	pctx->p.ip_len = ip_len;
	
	return;
}
/*----------------------------------------------------------------------------*/
int cnt_tcp = 0, cnt_icmp = 0, cnt_other = 0, err_drop_1 = 0, err_drop_2 = 0, err_drop_3 = 0, err_drop_4 = 0;
inline int 
ProcessInIPv4Packet(mtcp_manager_t mtcp, struct pkt_ctx *pctx)
{
	bool release = false;
	int ret;
	struct mon_listener *walk;
	/* check and process IPv4 packets */
	struct iphdr* iph =
#if CAIDA == 0
		(struct iphdr *)((char *)pctx->p.ethh + sizeof(struct ethhdr));
#else
		(struct iphdr *)((char *)pctx->p.ethh);
#endif
	int ip_len = ntohs(iph->tot_len);
    /*static bool ddd = false;
    if(!ddd){
    printf("iph %p tos %d len %d proto %d \n", iph, iph->tos, ip_len, iph->protocol);
    ddd = true;
    }*/
	/* drop the packet shorter than ip header */
	if (ip_len < sizeof(struct iphdr)) {
		ret = ERROR;
		// ip error 1
		++err_drop_1;
		goto __return;
	}
    //printf("error 1\n");

	if (iph->version != IPVERSION ) {
		release = true;
		ret = FALSE;
		// ip error 2
		++err_drop_2;
		goto __return;
	}

    //printf("error 2\n");

	FillInPacketIPContext(pctx, iph, ip_len);

    //printf("error 3\n");

	/* callback for monitor raw socket */
	TAILQ_FOREACH(walk, &mtcp->monitors, link)
		if (walk->socket->socktype == MOS_SOCK_MONITOR_RAW)
		{
#ifdef ALLOW_PKT_DROP
			printf("find row sock monitor.\n");
#else
			if (ISSET_BPFFILTER(walk->raw_pkt_fcode) &&
				EVAL_BPFFILTER(walk->raw_pkt_fcode, (uint8_t *)pctx->p.ethh,
					pctx->p.eth_len))
				HandleCallback(mtcp, MOS_NULL, walk->socket, MOS_SIDE_BOTH,
					pctx, MOS_ON_PKT_IN);
#endif
		}

    //printf("error 4\n");

	/* if there is no MOS_SOCK_STREAM or MOS_SOCK_MONITOR_STREAM socket,
	   forward IP packet before reaching upper (transport) layer */
	if (mtcp->num_msp == 0 && mtcp->num_esp == 0)
	{

#ifdef ALLOW_PKT_DROP
		printf("not find MONITOR\n.");
#else
		if (pctx->forward) {
			ForwardIPPacket(mtcp, pctx);
		}
		// ip error 3
		++err_drop_3;
		return TRUE;
#endif
	}		
	
    //printf("error 5\n");

	if (ip_fast_csum(iph, iph->ihl)) 
	{
#ifdef ALLOW_PKT_DROP
		printf("ip error 4.\n");
#else
		ret = ERROR;
		// ip error 4
		++err_drop_4;
		goto __return;
#endif

	}

    //printf("error 6\n");

	switch (iph->protocol) {
		case IPPROTO_TCP:
			// tcp
            //printf("tcp pkt!\n");
			++cnt_tcp;
			return ProcessInTCPPacket(mtcp, pctx);


#ifdef ALLOW_PKT_DROP
		default:
			printf("recv not tcp pkt.\n");
			return TRUE;
#else
		case IPPROTO_ICMP:
			// icmp
			++cnt_icmp;
			if (ProcessICMPPacket(mtcp, pctx))
				return TRUE;
		default:
			// ipelse
			++cnt_other;
			/* forward other protocols without any processing */
			if (!mtcp->num_msp || !pctx->forward)
				release = true;
			else
				ForwardIPPacket(mtcp, pctx);
			ret = FALSE;
			goto __return;
#endif


	}

__return:
	if (release && mtcp->iom->release_pkt)
		mtcp->iom->release_pkt(mtcp->ctx, pctx->p.in_ifidx,
				       (unsigned char *)pctx->p.ethh, pctx->p.eth_len);
	return ret;
}
/*----------------------------------------------------------------------------*/
