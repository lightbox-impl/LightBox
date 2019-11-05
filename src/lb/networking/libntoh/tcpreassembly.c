/********************************************************************************
 * Copyright (c) 2012, Chema Garcia * All rights reserved. *
 *                                                                              *
 * Redistribution and use in source and binary forms, with or * without
 *modification, are permitted provided that the following              *
 * conditions are met: *
 *                                                                              *
 *    * Redistributions of source code must retain the above * copyright notice,
 *this list of conditions and the following             * disclaimer. *
 *                                                                              *
 *    * Redistributions in binary form must reproduce the above * copyright
 *notice, this list of conditions and the following             * disclaimer in
 *the documentation and/or other materials provided         * with the
 *distribution.                                                  *
 *                                                                              *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" *
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE *
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE *
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE *
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR *
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF *
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS *
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN *
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) *
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE *
 * POSSIBILITY OF SUCH DAMAGE. *
 ********************************************************************************/

#include "../../../instances/lwids/common/lwids_type.h"

#include "../../core/enclave/cuckoo/cuckoo_hash.h"
#include "../../core/enclave/include/crypto_t.h"
#include "../../core/enclave/include/state_mgmt_t.h"
#include "../../core/enclave/include/lb_utils_t.h"
#include "../../core/enclave/lb_edge_t.h"

#include "linux_type_ports.h"

//#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
//#include <poll.h>
//#include <sys/time.h>
#include "libntoh.h"

//#include <netinet/ip6.h> // struct ip6_hdr

static ntoh_tcp_params_t params = {0, 0};

extern exp_data_t *exp_stats;

extern struct timeval wall_clock;

#define IS_TIMEWAIT(peer, side)                         \
	(peer.status == DEFAULT_TCP_TIMEWAIT_TIMEOUT || \
	 side.status == DEFAULT_TCP_TIMEWAIT_TIMEOUT)

static const char tcp_status[][1024] = {
    "Closed",      "Listen",   "SYN Sent",   "SYN Rcv",
    "Established", "Closing",  "Close Wait", "Fin Wait1",
    "Fin Wait2",   "Last ACK", "Time Wait"};

/** @brief API to get the string description associated to the given value
 * corresponding with a TCP status **/
const char *ntoh_tcp_get_status(unsigned int status) {
	if (status > NTOH_STATUS_TIMEWAIT) return 0;

	return tcp_status[status];
}

inline static void free_segment(pntoh_tcp_stream_t pstream,
				pntoh_tcp_segment_t psegment) {
	if (psegment->allocated) {
		memset(psegment, 0, sizeof(ntoh_tcp_segment_t));
		pstream->segment_used_size -= 1;
	}
}

/** @brief Returns the key for the stream identified by 'data' **/
inline static ntoh_tcp_key_t tcp_getkey(pntoh_tcp_session_t session,
					pntoh_tcp_tuple5_t data) {
#define ARRAY_SIZE (IP6_ADDR_LEN * 2) + 2
	unsigned int val[ARRAY_SIZE] = {0};
	size_t len = IPPROTO_IPV6;

	if (!data || !session) return 0;

	if (data->protocol != IPPROTO_IPV6) len = IP4_ADDR_LEN;

	val[0] = data->protocol;
	val[1] = data->sport | (data->dport << 16);
	memcpy((void *)(val + 2), (void *)data->source, len);
	memcpy((void *)((val + 2) + len), (void *)data->destination, len);
	len *= 2;
	return sfhash(val, len + 2 * sizeof(int), session->rand);

	//#define ARRAY_SIZE	(IP6_ADDR_LEN*2)+2
	// unsigned int	val[ARRAY_SIZE] = {0};
	// size_t		len = ARRAY_SIZE;

	// if ( !data || !session )
	//	return 0;

	// if ( data->protocol != IPPROTO_IPV6 )
	//	len -= (IP6_ADDR_LEN - IP4_ADDR_LEN) * 2;

	// memcpy ( (void*) val , (void*)data->source , len );
	// val[len] = data->protocol;
	// memcpy ( (void*) &val[len] , (void*)data->destination , IP6_ADDR_LEN
	// ); val[(len*2)+1] = data->sport | (data->dport << 16);

	// return sfhash ( val , len , session->rand );
	/*
		return (
				( ( ( data->sport | (data->protocol & 0x0F) ) &
	   0xFF ) | ( ( ( data->dport | (data->protocol & 0xF0) ) & 0xFF ) << 8
	   ) | ( ( data->source & 0xFF ) << 16 ) | ( ( data->destination & 0xFF
	   ) << 24 ) )
			);*/
}

/** @brief Sends the given segment to the user **/
inline static void send_single_segment(pntoh_tcp_session_t session,
				       pntoh_tcp_stream_t stream,
				       pntoh_tcp_peer_t origin,
				       pntoh_tcp_peer_t destination,
				       pntoh_tcp_segment_t segment, int reason,
				       int extra) {
	// send this segment
	if (extra != NTOH_REASON_OOO)
		origin->next_seq = segment->seq + segment->payload_len;

	origin->totalwin += segment->payload_len;

	if (segment->flags & (TH_FIN | TH_RST)) {
		origin->status = NTOH_STATUS_FINWAIT1;
		destination->status = NTOH_STATUS_CLOSEWAIT;
		stream->status = NTOH_STATUS_CLOSING;

		if (origin == &stream->client)
			stream->closedby = NTOH_CLOSEDBY_CLIENT;
		else if (origin == &stream->server)
			stream->closedby = NTOH_CLOSEDBY_SERVER;

		if (origin->final_seq == 0) origin->final_seq = segment->seq;

		origin->next_seq++;
	}

	if (origin->receive)
		((pntoh_tcp_callback_t)stream->function)(
		    stream, origin, destination, segment, reason, extra);

	// free ( segment );
	free_segment(stream, segment);

	return;
}

/** @brief Sends all segment stored in a peer queue **/
inline static void flush_peer_queues(pntoh_tcp_session_t session,
				     pntoh_tcp_stream_t stream,
				     unsigned short extra) {
	/*pntoh_tcp_peer_t	peers[2] = { &stream->client , &stream->server
	}; pntoh_tcp_segment_t	seg = 0; unsigned int		i = 0;

	for (i = 0; i < 2; i++)
		while (peers[i]->segments != 0)
		{
			seg = peers[i]->segments;
			if (i == 0)
				seg->origin = NTOH_SENT_BY_CLIENT;
			else
				seg->origin = NTOH_SENT_BY_SERVER;

			peers[i]->segments = seg->next;

			send_single_segment(session, stream, peers[i], peers[(i
	+ 1) % 2], seg, seg->payload_len > 0 ? NTOH_REASON_DATA :
	NTOH_REASON_SYNC, extra);
		}*/
}

/** @brief Remove the stream from the session streams hash table, and notify the
 * user **/
inline static void delete_stream(pntoh_tcp_session_t session,
				 pntoh_tcp_stream_t *stream, int reason,
				 int extra) {
	pntoh_tcp_stream_t item = 0;

	if (!stream || !(*stream)) return;

	item = *stream;

	if (session->streams != 0 &&
	    htable_find(session->streams, item->key, 0) != 0) {
		htable_remove(session->streams, item->key, 0);
		// sem_post(&session->max_streams);
		++session->max_streams;
	}

	if (session->timewait != 0 &&
	    htable_find(session->timewait, item->key, 0) != 0) {
		htable_remove(session->timewait, item->key, 0);
		// sem_post(&session->max_timewait);
		++session->max_timewait;
	}

	switch (extra) {
		case NTOH_MAX_SYN_RETRIES_REACHED:
			extra = NTOH_REASON_MAX_SYN_RETRIES_REACHED;
			break;

		case NTOH_MAX_SYNACK_RETRIES_REACHED:
			extra = NTOH_REASON_MAX_SYNACK_RETRIES_REACHED;
			break;

		case NTOH_HANDSHAKE_FAILED:
			extra = NTOH_REASON_HSFAILED;
			break;
	}

	// if (item->client.receive)
	//	((pntoh_tcp_callback_t)item->function)(item, &item->client,
	//&item->server, 0, reason, extra);

	free(item);
	*stream = 0;

	return;
}

/** @brief Frees a TCP stream **/
static unsigned int send_peer_segments(pntoh_tcp_session_t session,
				       pntoh_tcp_stream_t stream,
				       pntoh_tcp_peer_t origin,
				       pntoh_tcp_peer_t destination,
				       unsigned int ack, unsigned short first,
				       int extra, int who);
inline static void __tcp_free_stream(pntoh_tcp_session_t session,
				     pntoh_tcp_stream_t *stream, int reason,
				     int extra) {
	// flush_peer_queues(session, *stream, extra);

	send_peer_segments(session, *stream, &((*stream)->client), 0, 0, 0, 0,
			   0);
	delete_stream(session, stream, reason, extra);

	return;
}

/** @brief Frees a TCP session **/
inline static void __tcp_free_session(pntoh_tcp_session_t session) {
	pntoh_tcp_session_t ptr = 0;
	pntoh_tcp_stream_t item = 0;
	ntoh_tcp_key_t first = 0;

	if (params.sessions_list == session)
		params.sessions_list = session->next;
	else {
		for (ptr = params.sessions_list;
		     ptr != 0 && ptr->next != session; ptr = ptr->next)
			;
		if (ptr != 0) ptr->next = session->next;
	}

	while ((first = htable_first(session->timewait)) != 0) {
		item = (pntoh_tcp_stream_t)htable_remove(session->timewait,
							 first, 0);
		__tcp_free_stream(session, &item, NTOH_REASON_SYNC,
				  NTOH_REASON_EXIT);
	}

	while ((first = htable_first(session->streams)) != 0) {
		item = (pntoh_tcp_stream_t)htable_remove(session->streams,
							 first, 0);
		__tcp_free_stream(session, &item, NTOH_REASON_SYNC,
				  NTOH_REASON_EXIT);
	}

	htable_destroy(&session->streams);
	htable_destroy(&session->timewait);

	free(session);

	return;
}

#if LightBox == 0
void tcp_check_timeouts(pntoh_tcp_session_t session) {
#define IS_FINWAIT2(peer, side)                 \
	(peer.status == NTOH_STATUS_FINWAIT2 || \
	 side.status == NTOH_STATUS_FINWAIT2)

	struct timeval tv = {0, 0};
	unsigned int val = 0;
	unsigned int i = 0;
	unsigned short timedout = 0;
	pntoh_tcp_stream_t item;
	phtnode_t node = 0;
	phtnode_t prev = 0;

	/* iterating manually between flows */
	for (i = 0; i < session->streams->table_size; i++) {
		node = prev = session->streams->table[i];
		while (node != 0) {
			timedout = 0;
			// gettimeofday(&tv, 0);
			memcpy(&tv, &wall_clock, sizeof(wall_clock));
			item = (pntoh_tcp_stream_t)node->val;
			val = tv.tv_sec - item->last_activ.tv_sec;

			if (val > DEFAULT_TCP_ESTABLISHED_TIMEOUT) timedout = 1;

			/* timeout expired */
			if (timedout) {
				exp_stats->pm_time_out += 1;
				exp_stats->current_stream -= 1;
				__tcp_free_stream(session, &item,
						  NTOH_REASON_SYNC,
						  NTOH_REASON_TIMEDOUT);
				// @contrib: Eosis - https://github.com/Eosis
				if (node != prev)
					node = prev;
				else
					node = 0;
			} else {
				prev = node;
				node = node->next;
			}
		}
	}

	return;
}
#else
extern struct cuckoo_hash store_lkup_table;
void tcp_check_timeouts(pntoh_tcp_session_t session) {
	struct cuckoo_hash_item *it;
	for (cuckoo_hash_each(it, &store_lkup_table)) {
		state_entry_t *state = it->value;
		time_t state_time = state->last_access_time;
		if ((wall_clock.tv_sec - state_time) >
		    DEFAULT_TCP_ESTABLISHED_TIMEOUT) {
			// skip the processing
			/*send_peer_segments(session, stream, &stream->client,
			0, 0, 0, 0, 0);
			++session->max_streams;*/
			exp_stats->pm_time_out += 1;
			exp_stats->current_stream -= 1;
			// safe to remove while iterating
			cuckoo_hash_remove(&store_lkup_table, state->lkup);
			ocall_state_store_free(state);
		}
	}
}
#endif

/** @brief API to get a tuple5 **/
unsigned int ntoh_tcp_get_tuple5(void *ip, struct tcphdr *tcp,
				 pntoh_tcp_tuple5_t tuple) {
	struct ip6_hdr *ip6hdr = (struct ip6_hdr *)ip;
	struct ip *ip4hdr = (struct ip *)ip;

	if (!ip || !tcp || !tuple) return NTOH_ERROR_PARAMS;

	switch (ip4hdr->ip_v) {
		case 4:
			memset((void *)tuple->source, 0, sizeof(tuple->source));
			memset((void *)tuple->destination, 0,
			       sizeof(tuple->destination));
			/* pointer already set */
			// ip4hdr = (struct ip*)ip;
			tuple->protocol = 4;
			tuple->source[0] = ip4hdr->ip_src.s_addr;
			tuple->destination[0] = ip4hdr->ip_dst.s_addr;
			break;

		case 6:
			tuple->protocol = 6;
			memcpy((void *)tuple->source,
			       (void *)&(ip6hdr->ip6_src),
			       sizeof(tuple->source));
			memcpy((void *)tuple->destination,
			       (void *)&(ip6hdr->ip6_dst),
			       sizeof(tuple->destination));
			break;

		default:
			return NTOH_INCORRECT_IP_HEADER;
	}

	tuple->sport = tcp->th_sport;
	tuple->dport = tcp->th_dport;

	return NTOH_OK;
}

fid_t *lb_get_fid(struct ip *ip, struct tcphdr *tcp) {
	static fid_t fid;
	fid.proto = ip->ip_v;
	fid.src_ip = ip->ip_src.s_addr;
	fid.dst_ip = ip->ip_dst.s_addr;
	fid.src_port = tcp->th_sport;
	fid.dst_port = tcp->th_dport;

	return &fid;
}

unsigned short tcp_equal_tuple(void *a, void *b) {
	unsigned short ret = 0;

	if (!memcmp(a, (void *)&((pntoh_tcp_stream_t)b)->tuple,
		    sizeof(ntoh_tcp_tuple5_t)))
		ret++;

	return ret;
}

/** @brief API to get the size of the sessions table (max allowed streams) **/
unsigned int ntoh_tcp_get_size(pntoh_tcp_session_t session) {
	unsigned int ret = 0;

	if (!session) return ret;

	ret = session->streams->table_size;

	return ret;
}

/** @brief API to create a new session and add it to the global sessions list
 * **/
pntoh_tcp_session_t ntoh_tcp_new_session(unsigned int max_streams,
					 unsigned int max_timewait,
					 unsigned int *error) {
	pntoh_tcp_session_t session;

	if (!max_streams) max_streams = DEFAULT_TCP_MAX_STREAMS;

	if (!max_timewait)
		max_timewait = DEFAULT_TCP_MAX_TIMEWAIT_STREAMS(max_streams);

	if (!(session =
		  (pntoh_tcp_session_t)calloc(1, sizeof(ntoh_tcp_session_t)))) {
		if (error != 0) *error = NTOH_ERROR_NOMEM;
		return 0;
	}

	ntoh_tcp_init();

#if LightBox == 0
	session->streams = htable_map(max_streams, &tcp_equal_tuple);
	session->timewait = htable_map(max_timewait, &tcp_equal_tuple);
#endif

	session->max_streams = max_streams;
	session->max_timewait = max_timewait;
	// sem_init(&session->max_streams, 0, max_streams);
	// sem_init(&session->max_timewait, 0, max_timewait);

	// srand((int)time(NULL));

	// session->rand = rand();
	draw_rand(&session->rand, sizeof(session->rand));

	if (params.sessions_list != 0) session->next = params.sessions_list;
	params.sessions_list = session;

	if (error != 0) *error = NTOH_OK;

	// implement Check tcp fragment timeout
	// look all streams in session stream hash table and check if the stream
	// is timeout
	// pthread_create(&session->tID, 0, timeouts_thread, (void*)session);

	return session;
}

/** @brief API to free a TCP session (wrapper) **/
void ntoh_tcp_free_session(pntoh_tcp_session_t session) {
	if (!session) return;

	__tcp_free_session(session);

	return;
}

/** @brief API to free a TCP stream (wrapper) **/
void ntoh_tcp_free_stream(pntoh_tcp_session_t session,
			  pntoh_tcp_stream_t *stream, int reason, int extra) {
	if (!session || !stream || !(*stream)) return;

	__tcp_free_stream(session, stream, reason, extra);

	return;
}

/** @brief API to release all used TCP resources (sessions and streams) **/
void ntoh_tcp_exit(void) {
	if (!params.init) return;

	while (params.sessions_list != 0)
		__tcp_free_session(params.sessions_list);

	params.init = 0;

	return;
}

/** @brief API to initialize the global structure **/
void ntoh_tcp_init(void) {
	if (params.init) return;

	params.init = 1;

	return;
}

/** @brief API to look for a TCP stream identified by 'tuple5' **/
pntoh_tcp_stream_t ntoh_tcp_find_stream(pntoh_tcp_session_t session,
					pntoh_tcp_tuple5_t tuple5) {
	ntoh_tcp_key_t key = 0;
	// ntoh_tcp_tuple5_t	tuplerev = { {0},{0},0 };
	pntoh_tcp_stream_t ret = 0;
	// unsigned int		i;

	if (!session || !tuple5) return ret;

	key = tcp_getkey(session, tuple5);

	ret = (pntoh_tcp_stream_t)htable_find(session->streams, key, 0);

	// if ( ! ( ret = (pntoh_tcp_stream_t) htable_find ( session->streams ,
	// key , 0) ) )
	//{
	//	for ( i = 0 ; i < IP6_ADDR_LEN ; i++ )
	//	{
	//		tuplerev.destination[i] = tuple5->source[i];
	//		tuplerev.source[i] = tuple5->destination[i];
	//	}

	//	tuplerev.sport = tuple5->dport;
	//	tuplerev.dport = tuple5->sport;
	//	tuplerev.protocol = tuple5->protocol;

	//	key = tcp_getkey( session , &tuplerev );

	//	ret = (pntoh_tcp_stream_t) htable_find ( session->streams , key
	//, 0);
	//}

	return ret;
}

/** @brief API to create a new TCP stream and add it to the given session **/
pntoh_tcp_stream_t ntoh_tcp_new_stream(pntoh_tcp_stream_t new_stream_memory,
				       pntoh_tcp_session_t session,
				       pntoh_tcp_tuple5_t tuple5,
				       pntoh_tcp_callback_t function,
				       void *udata, unsigned int *error,
				       unsigned short enable_check_timeout,
				       unsigned short enable_check_nowindow) {
	pntoh_tcp_stream_t stream = 0;
	ntoh_tcp_key_t key = 0;
	unsigned int i;

	if (error != 0) *error = 0;

	if (!session) {
		if (error != 0) *error = NTOH_ERROR_PARAMS;
		return 0;
	}

	if (!(key = tcp_getkey(session, tuple5))) {
		if (error != 0) *error = NTOH_ERROR_NOKEY;
		return 0;
	}

	if (!function) {
		if (error != 0) *error = NTOH_ERROR_NOFUNCTION;
		return 0;
	}

	if (!tuple5->dport || !tuple5->sport || !tuple5->protocol) {
		if (error != 0) *error = NTOH_ERROR_INVALID_TUPLE5;
		return 0;
	}

	--session->max_streams;
	// if (--session->max_streams <= 0)
	////if (sem_trywait(&session->max_streams) != 0)
	//{
	//	++session->max_streams;
	//	if (error != 0)
	//		*error = NTOH_ERROR_NOSPACE;
	//	return 0;
	//}

	stream = new_stream_memory;
	// if (!(stream = (pntoh_tcp_stream_t)calloc(1,
	// sizeof(ntoh_tcp_stream_t))))
	//{

	//	if (error != 0)
	//		*error = NTOH_ERROR_NOMEM;
	//	return 0;
	//}

	memcpy((void *)&(stream->tuple), (void *)tuple5,
	       sizeof(ntoh_tcp_tuple5_t));
	stream->key = key;

	for (i = 0; i < IP6_ADDR_LEN; i++) {
		stream->client.addr[i] = stream->tuple.source[i];
		stream->server.addr[i] = stream->tuple.destination[i];
	}

	stream->client.port = stream->tuple.sport;
	stream->server.port = stream->tuple.dport;
	stream->client.receive = 1;
	stream->server.receive = 1;
	stream->client.first_segment = -1;
	stream->server.first_segment = -1;

	memcpy(&stream->last_activ, &wall_clock, sizeof(wall_clock));
	// gettimeofday(&stream->last_activ, 0);
	stream->status = stream->client.status = stream->server.status =
	    NTOH_STATUS_ESTABLISHED;
	// stream->status = stream->client.status = stream->server.status =
	// NTOH_STATUS_CLOSED;

	stream->function = (void *)function;
	stream->udata = udata;
	stream->enable_check_timeout =
	    enable_check_timeout;  // @contrib: di3online -
				   // https://github.com/di3online
	// stream->enable_check_nowindow = enable_check_nowindow;// @contrib:
	// di3online - https://github.com/di3online
	stream->enable_check_nowindow =
	    0;  // @contrib: di3online - https://github.com/di3online

	htable_insert(session->streams, key, stream);

	if (error != 0) *error = NTOH_OK;

	return stream;
}

/** @brief API to get the amount of streams stored in a session **/
unsigned int ntoh_tcp_count_streams(pntoh_tcp_session_t session) {
	unsigned int ret = 0;
	int count;

	if (!session) return ret;

	count = session->max_streams;
	// sem_getvalue(&session->max_streams, &count);
	ret = session->streams->table_size - count;
	// ret = htable_count ( session->streams );

	return ret;
}

/** @brief Gets the TCP options from a TCP header **/
inline static void get_tcp_options(pntoh_tcp_peer_t peer, struct tcphdr *tcp,
				   size_t tcp_len) {
	unsigned char *options = 0;
	unsigned int aux = 0;

	if (tcp_len == sizeof(struct tcphdr)) return;

	options = (unsigned char *)tcp + sizeof(struct tcphdr);
	peer->wsize = (unsigned int)ntohs(tcp->th_win);
	peer->wscale = 0;

	while (options < (unsigned char *)tcp + tcp_len) {
		switch (*options) {
			case TCPOPT_MAXSEG:
				memcpy(&aux, (options + 2), TCPOLEN_MAXSEG - 2);
				peer->mss = (unsigned short)ntohs(aux);
				options += TCPOLEN_MAXSEG;
				break;

			case TCPOPT_SACK_PERMITTED:
				if (*(options + 1) == TCPI_OPT_SACK)
					peer->sack = 1;

				options += TCPOLEN_SACK_PERMITTED;
				break;

			case TCPOPT_TIMESTAMP:
				options += TCPOLEN_TIMESTAMP;
				break;

			case TCPOPT_WINDOW:
				memcpy(&aux, (options + 2), TCPOLEN_WINDOW - 2);
				peer->wscale = (unsigned int)aux;
				options += TCPOLEN_WINDOW;
				break;

			case TCPOPT_EOL:
				/* exit */
				options = (unsigned char *)tcp + tcp_len;
				break;

			case TCPOPT_NOP:
			default:
				options++;
				break;
		}
	}

	return;
}

/** @brief Gets the TCP Timestamp from TCP Options header **/
inline static void get_timestamp(struct tcphdr *tcp, size_t tcp_len,
				 unsigned int *ts) {
	unsigned char *options = 0;
	unsigned int tmp = 0;

	if (tcp_len == sizeof(struct tcphdr)) return;

	options = (unsigned char *)tcp + sizeof(struct tcphdr);
	while (options < (unsigned char *)tcp + tcp_len) {
		switch (*options) {
			case TCPOPT_MAXSEG:
				options += TCPOLEN_MAXSEG;
				break;

			case TCPOPT_SACK_PERMITTED:
				options += TCPOLEN_SACK_PERMITTED;
				break;

			case TCPOPT_TIMESTAMP:
				memcpy((unsigned char *)&tmp, options + 2,
				       4);  // get TSval
				*ts = ntohl(tmp);
				options += TCPOLEN_TIMESTAMP;
				break;

			case TCPOPT_WINDOW:
				options += TCPOLEN_WINDOW;
				break;

			case TCPOPT_EOL:
				/* exit */
				options = (unsigned char *)tcp + tcp_len;
				break;

			case TCPOPT_NOP:
			default:
				options++;
				break;
		}
	}
}

/** @brief Adds a segment to the given peer queue **/
inline static int queue_segment(pntoh_tcp_stream_t stream,
				pntoh_tcp_peer_t peer,
				pntoh_tcp_segment_t segment) {
	pntoh_tcp_segment_t qu = 0;
	ppeer_info_t pdata = 0;

	pdata = (ppeer_info_t)segment->user_data;

	if (pdata && pdata->data_len < TCP_STREAM_DATA_MAX_LEN) {
		segment->data_loc = stream->data_len;
		segment->data_len = pdata->data_len;
		memcpy(stream->stream_data + segment->data_loc, pdata->data,
		       pdata->data_len);
		stream->data_len += pdata->data_len;

		if (peer->first_segment < 0) {
			peer->first_segment = segment->this_loc;
		} else {
			if (segment->seq <
			    stream->segments[peer->first_segment].seq) {
				// insert the new segmeng into first loc
				segment->next_loc =
				    stream->segments[peer->first_segment]
					.this_loc;
				peer->first_segment = segment->this_loc;
			} else {
				// insert the new segment into the list
				for (qu = &(
					 stream->segments[peer->first_segment]);
				     qu->next_loc >= 0 &&
				     (stream->segments[qu->next_loc]).seq <
					 segment->seq;
				     qu = &(stream->segments[qu->next_loc]))
					;
				segment->next_loc = qu->next_loc;
				qu->next_loc = segment->this_loc;
			}
		}
		return 1;
	}
	return -1;
}

/** @brief Creates a new segment **/
inline static pntoh_tcp_segment_t new_segment(
    pntoh_tcp_stream_t stream, unsigned long seq, unsigned long ack,
    unsigned long payload_len, unsigned char flags, void *udata) {
	pntoh_tcp_segment_t ret = 0;

	// allocates the new segment
	// ret = (pntoh_tcp_segment_t) c//alloc ( 1 , sizeof (
	// ntoh_tcp_segment_t ) );

	for (int i = 0; i < TCP_STREAM_SEGMENT_MAX_COUNT; i++) {
		if (!(stream->segments[i].allocated)) {
			stream->segment_used_size++;
			ret = &stream->segments[i];
			ret->allocated = 1;
			ret->this_loc = i;
			ret->next_loc = -1;
			break;
		}
	}

	if (ret) {
		ret->ack = ack;
		ret->seq = seq;
		ret->payload_len = payload_len;
		ret->flags = flags;
		ret->user_data = udata;
		// gettimeofday(&ret->tv, 0);
		ret->tv = wall_clock;
	}

	return ret;
}

char g_tcp_send_buffer[TCP_STREAM_DATA_MAX_LEN];

/** @brief Sends all possible segments to the user or only the first one **/
static unsigned int send_peer_segments(pntoh_tcp_session_t session,
				       pntoh_tcp_stream_t stream,
				       pntoh_tcp_peer_t origin,
				       pntoh_tcp_peer_t destination,
				       unsigned int ack, unsigned short first,
				       int extra, int who) {
	pntoh_tcp_segment_t segment = 0;
	unsigned int ret = 0;
	unsigned send_len = 0;

	if (origin->first_segment < 0) return ret;

	segment = &(stream->segments[origin->first_segment]);
	while (segment != 0) {
		memcpy(g_tcp_send_buffer + send_len,
		       stream->stream_data + segment->data_loc,
		       segment->data_len);
		send_len += segment->data_len;
		if (segment->next_loc >= 0)
			segment = &(stream->segments[segment->next_loc]);
		else
			segment = 0;
		ret++;
	}

	peer_info_t peer_info;
	peer_info.data = g_tcp_send_buffer;
	peer_info.data_len = send_len;

	segment = &(stream->segments[origin->first_segment]);
	segment->user_data = &peer_info;

	if (stream->function)
		((pntoh_tcp_callback_t)stream->function)(
		    stream, origin, destination, segment, 0, extra);

	while (origin->first_segment >= 0) {
		segment = &(stream->segments[origin->first_segment]);
		origin->first_segment = segment->next_loc;
		free_segment(stream, segment);
	}
	stream->data_len = 0;

	return ret;
}

/** @brief Handles the connection establishment **/
inline static int handle_new_connection(pntoh_tcp_stream_t stream,
					struct tcphdr *tcp,
					pntoh_tcp_peer_t origin,
					pntoh_tcp_peer_t destination,
					void *udata) {
	unsigned long seq = ntohl(tcp->th_seq);
	unsigned long ack = ntohl(tcp->th_ack);

	/* switch between possibles connection status */
	switch (stream->status) {
			// Client --- SYN ---> Server
		case NTOH_STATUS_CLOSED:

			if (tcp->th_flags != TH_SYN) {
				if (DEFAULT_TCP_SYN_RETRIES <
				    stream->syn_retries++)
					return NTOH_MAX_SYN_RETRIES_REACHED;

				return NTOH_OK;
			}

			/* as we have a SYN flag, get tcp options */
			get_tcp_options(origin, tcp, tcp->th_off * 4);
			origin->totalwin = origin->wsize << origin->wscale;

			/* store seq number as ISN */
			origin->isn = seq;
			origin->next_seq = (seq - origin->isn) + 1;
			destination->ian = origin->isn;

			origin->status = NTOH_STATUS_SYNSENT;
			destination->status = NTOH_STATUS_LISTEN;
			stream->status = NTOH_STATUS_SYNSENT;

			break;

			// Server --- SYN + ACK ---> Client
		case NTOH_STATUS_SYNSENT:
			if (tcp->th_flags != (TH_SYN | TH_ACK) ||
			    ((ack - origin->ian) != destination->next_seq)) {
				if (DEFAULT_TCP_SYNACK_RETRIES <
				    stream->synack_retries++)
					return NTOH_MAX_SYNACK_RETRIES_REACHED;

				return NTOH_OK;
			}

			/* as we have a SYN flag, get tcp options */
			get_tcp_options(origin, tcp, tcp->th_off * 4);
			origin->totalwin = origin->wsize << origin->wscale;

			/* store ack number as IAN */
			origin->isn = seq;
			origin->next_seq = (seq - origin->isn) + 1;
			destination->ian = origin->isn;

			origin->status = NTOH_STATUS_SYNRCV;
			stream->status = NTOH_STATUS_SYNRCV;
			break;

			// Client --- ACK ---> Server
		case NTOH_STATUS_SYNRCV:

			if (tcp->th_flags != TH_ACK)
				return NTOH_HANDSHAKE_FAILED;

			if (ntohl(tcp->th_seq) != destination->ian + 1)
				return NTOH_HANDSHAKE_FAILED;

			if (ntohl(tcp->th_ack) - origin->ian !=
			    destination->next_seq)
				return NTOH_HANDSHAKE_FAILED;

			origin->status = NTOH_STATUS_ESTABLISHED;
			destination->status = NTOH_STATUS_ESTABLISHED;
			stream->status = NTOH_STATUS_ESTABLISHED;

			break;
	}

	return NTOH_OK;
}

/** @brief What to do when an incoming segment arrives to a closing connection?
 * **/
inline static void handle_closing_connection(pntoh_tcp_session_t session,
					     pntoh_tcp_stream_t stream,
					     pntoh_tcp_peer_t origin,
					     pntoh_tcp_peer_t destination,
					     pntoh_tcp_segment_t segment,
					     int who) {
	// pntoh_tcp_peer_t	peer = origin;
	// pntoh_tcp_peer_t	side = destination;
	// pntoh_tcp_stream_t	twait = 0;
	// ntoh_tcp_key_t		key = 0;

	// send_peer_segments(session, stream, destination, origin,
	// origin->next_seq, 0, 0, who);

	// if (stream->status == NTOH_STATUS_CLOSING)
	//{
	//	if (stream->closedby == NTOH_CLOSEDBY_CLIENT)
	//	{
	//		peer = &stream->client;
	//		side = &stream->server;
	//	}
	//	else {
	//		peer = &stream->server;
	//		side = &stream->client;
	//	}
	//}

	///* check segment seq and ack */
	// if (!origin->segments)
	//	return;

	// if (origin->segments->seq == origin->next_seq &&
	// origin->segments->ack == destination->next_seq)
	//{
	//	/* unlink the first segment */
	//	segment = origin->segments;
	//	origin->segments = segment->next;
	//}
	// else
	//	return;

	///* TCP finite machine state */
	// switch (peer->status)
	//{
	// case NTOH_STATUS_ESTABLISHED:
	//	/*
	//	 * Expected: FIN
	//	 * Sender: Transits to FIN WAIT 1
	//	 * Receiver: Does not transits, sends ACK and transits to CLOSE
	//WAIT
	//	 * */
	//	if (segment->flags & TH_FIN)
	//		break;

	//	origin->status = NTOH_STATUS_FINWAIT1;
	//	destination->status = NTOH_STATUS_CLOSEWAIT;
	//	stream->status = NTOH_STATUS_CLOSING;

	//	if (origin == &stream->client)
	//		stream->closedby = NTOH_CLOSEDBY_CLIENT;
	//	else if (origin == &stream->server)
	//		stream->closedby = NTOH_CLOSEDBY_SERVER;

	//	break;

	// case NTOH_STATUS_FINWAIT1:
	//	/*
	//	 * Expected:
	//	 * 	1) ACK
	//	 * 	2) FIN
	//	 *
	//	 * Receives: ACK
	//	 * Sender: Transits to CLOSEWAIT
	//	 * Receiver: FINWAIT2
	//	 *
	//	 * Receives: FIN
	//	 * Sender: Transits to LASTACK
	//	 * Receiver: Sends ACK and transits to CLOSING
	//	 */
	//	if (segment->flags & TH_ACK)
	//	{
	//		// peer receives ACK
	//		if (peer == destination)
	//		{
	//			peer->status = NTOH_STATUS_FINWAIT2;
	//			side->status = NTOH_STATUS_CLOSEWAIT;
	//			// peer sends ACK (due to a previously received FIN
	//while being in FIN WAIT 1)
	//		}
	//		else
	//			peer->status = NTOH_STATUS_CLOSING;

	//	}
	//	else if (peer == destination && (segment->flags & TH_FIN))
	//	{
	//		peer->status = NTOH_STATUS_CLOSING;
	//		side->status = NTOH_STATUS_LASTACK;
	//	}

	//	break;

	// case NTOH_STATUS_CLOSING:
	//	break;

	// case NTOH_STATUS_FINWAIT2:
	//	/*
	//	 * Expected: FIN
	//	 * Sender: N/A
	//	 * Receiver: Sends ACK and transits to TIME WAIT
	//	 */
	//	if (peer == destination && (segment->flags & TH_FIN))
	//		peer->status = NTOH_STATUS_TIMEWAIT;
	//	else if (peer == origin)
	//	{
	//		if (segment->flags & TH_ACK)
	//		{
	//			peer->status = NTOH_STATUS_TIMEWAIT;
	//			side->status = NTOH_STATUS_CLOSED;
	//			stream->status = NTOH_STATUS_CLOSED;
	//		}
	//		else if (segment->flags & TH_FIN)
	//		{
	//			stream->status = NTOH_STATUS_CLOSED;
	//			side->status = NTOH_STATUS_CLOSED;
	//		}
	//	}

	//	break;

	// case NTOH_STATUS_TIMEWAIT:
	//	break;
	//}

	// if (segment->flags & (TH_FIN | TH_RST))
	//	origin->next_seq++;

	// if (stream->status != NTOH_STATUS_CLOSED && origin->receive)
	//	((pntoh_tcp_callback_t)stream->function) (stream, origin,
	//destination, segment, NTOH_REASON_SYNC, 0);

	///* should we add this stream to TIMEWAIT queue? */
	// if (stream->status == NTOH_STATUS_CLOSING &&
	// IS_TIMEWAIT(stream->client, stream->server))
	//{
	//	if (!htable_find(session->timewait, stream->key, 0))
	//	{
	//		htable_remove(session->streams, stream->key, 0);
	//		//sem_post(&session->max_streams);
	//		++session->max_streams;

	//		while (sem_trywait(&session->max_timewait) != 0)
	//		{
	//			key = htable_first(session->timewait);
	//			twait = htable_remove(session->timewait, key,
	//0);
	//			__tcp_free_stream(session, &twait, NTOH_REASON_SYNC,
	//NTOH_REASON_CLOSED);
	//		}

	//		htable_insert(session->timewait, stream->key, stream);
	//	}
	//}

	// send_peer_segments(session, stream, destination, origin,
	// origin->next_seq, 0, 0, who);

	////free ( segment );
	// free_segment(stream, segment);

	return;
}

/** @brief What to do when an incoming segment arrives to an established
 * connection? **/
inline static int handle_established_connection(
    pntoh_tcp_session_t session, pntoh_tcp_stream_t stream, struct tcphdr *tcp,
    size_t payload_len, pntoh_tcp_peer_t origin, pntoh_tcp_peer_t destination,
    void *udata, int who) {
	// int ret;
	// int queue_ret;
	// int send_ret;
	// pntoh_tcp_segment_t	segment = 0;
	// unsigned long 		seq = ntohl(tcp->th_seq) - origin->isn;
	// unsigned long 		ack = ntohl(tcp->th_ack) - origin->ian;

	///* only store segments with data */
	////if ( payload_len > 0 )
	////{
	////	if (stream->enable_check_nowindow) // @contrib: di3online -
	///https://github.com/di3online /	{ /		/* if we have no
	///space */ /		while ( origin->totalwin < payload_len && /
	///send_peer_segments ( session , stream , origin , /
	///destination , ack , 1 , /
	///NTOH_REASON_NOWINDOW, who ) > 0 /		);

	////		/* we're in trouble */
	////		if ( origin->totalwin < payload_len )
	////			return NTOH_NO_WINDOW_SPACE_LEFT;
	////	}
	////}

	///* creates a new segment and push it into the queue */
	// segment = new_segment(stream, seq, ack, payload_len, tcp->th_flags,
	// udata); if (!segment)
	//{
	//	delete_stream(session, &stream, NTOH_REASON_SYNC, ret);
	//	return NTOH_NOT_INITIALIZED;
	//}

	///* wants to close the connection ? */
	// if ((tcp->th_flags & (TH_FIN | TH_RST)))
	//{
	//	send_peer_segments(session, stream, destination, origin, ack, 0,
	//0, !who); 	free_segment(stream, segment);
	//}
	// else
	//{
	//	if (stream->data_len + payload_len < TCP_STREAM_DATA_MAX_LEN)
	//	{
	//		queue_ret = queue_segment(stream, origin, segment);
	//	}
	//	else
	//	{
	//		send_ret = send_peer_segments(session, stream,
	//destination, origin, ack, 0, 0, !who); 		queue_ret =
	//queue_segment(stream, origin, segment);
	//	}
	//	if (queue_ret < 0)
	//		free_segment(stream, segment);
	//}

	return NTOH_OK;
}

// extern int sgx_deleted_flow;
// extern int lb_deleted_flow;
/** @brief API for add an incoming segment **/
int ntoh_tcp_add_segment(pntoh_tcp_session_t session, pntoh_tcp_stream_t stream,
			 void *ip, size_t len, void *udata) {
	size_t iphdr_len = 0;
	size_t tcphdr_len = 0;
	size_t payload_len = 0;
	struct tcphdr *tcp = 0;
	pntoh_tcp_peer_t origin = 0;
	pntoh_tcp_peer_t destination = 0;
	unsigned int tstamp = 0;
	int queue_ret;
	// int send_ret;
	int ret = NTOH_OK;
	pntoh_tcp_segment_t segment = 0;
	struct ip *ip4hdr = (struct ip *)ip;
	struct ip6_hdr *ip6hdr = (struct ip6_hdr *)ip;
	int who;  // @contrib: di3online - https://github.com/di3online
	unsigned int saddr[IP6_ADDR_LEN] = {0};
	unsigned int daddr[IP6_ADDR_LEN] = {0};

	if (!stream || !session) return NTOH_ERROR_PARAMS;

	/* verify IP header */
	if (!ip)  // no ip header
		return NTOH_INCORRECT_IP_HEADER;

	if (ip4hdr->ip_v != 4 && ip4hdr->ip_v != 6)
		return NTOH_INCORRECT_IP_HEADER;

	if ((ip4hdr->ip_v == 4 && len <= sizeof(struct ip)) ||
	    (ip4hdr->ip_v == 6 && len <= sizeof(struct ip6_hdr))

		)  // no data
		return NTOH_INCORRECT_LENGTH;

	if ((ip4hdr->ip_v == 4 &&
	     (iphdr_len = 4 * (ip4hdr->ip_hl)) <
		 sizeof(struct ip)))  // incorrect ip header length
		return NTOH_INCORRECT_IP_HEADER_LENGTH;

	if (ip4hdr->ip_v == 6) iphdr_len = sizeof(struct ip6_hdr);

	if ((ip4hdr->ip_v == 4 && len < ntohs(ip4hdr->ip_len)) ||
	    (ip4hdr->ip_v == 6 &&
	     len < ntohs(ip6hdr->ip6_plen)))  // incorrect capture length
		return NTOH_NOT_ENOUGH_DATA;

	if (ip4hdr->ip_v == 4) {
		saddr[0] = ip4hdr->ip_src.s_addr;
		daddr[0] = ip4hdr->ip_dst.s_addr;
	} else {
		memcpy((void *)saddr, (void *)&(ip6hdr->ip6_src), IP6_ADDR_LEN);
		memcpy((void *)daddr, (void *)&(ip6hdr->ip6_dst), IP6_ADDR_LEN);
	}

	/* check IP addresses */
	// if ( ! (
	//	( !memcmp ( (void*)stream->client.addr , (void*)saddr ,
	//IP6_ADDR_LEN ) && !memcmp ( (void*)stream->server.addr , (void*)daddr
	//, IP6_ADDR_LEN ) ) || 	( !memcmp ( (void*)stream->client.addr ,
	//(void*)daddr , IP6_ADDR_LEN ) && !memcmp ( (void*)stream->server.addr
	//, (void*)saddr , IP6_ADDR_LEN ) ) ) ) 	return
	//NTOH_IP_ADDRESSES_MISMATCH;
	//

	// if (
	//	( ip4hdr->ip_v == 4 && ip4hdr->ip_p != IPPROTO_TCP ) ||
	//	( ip4hdr->ip_v == 6 && ip6hdr->ip6_nxt != IPPROTO_TCP )
	//)
	//	return NTOH_NOT_TCP;

	tcp = (struct tcphdr *)((unsigned char *)ip + iphdr_len);

	/* check TCP header */
	if ((tcphdr_len = tcp->th_off * 4) < sizeof(struct tcphdr))
		return NTOH_INCORRECT_TCP_HEADER_LENGTH;

	if (!tcp->th_flags || tcp->th_flags == 0xFF) return NTOH_INVALID_FLAGS;

	/* check TCP ports */
	// if (!(
	//	(tcp->th_dport == stream->tuple.dport && tcp->th_sport ==
	//stream->tuple.sport) || 	(tcp->th_dport == stream->tuple.sport &&
	//tcp->th_sport == stream->tuple.dport)
	//	))
	//{
	//	//printf("%d,%d,%d,%d\n", tcp->th_dport, tcp->th_sport,
	//stream->tuple.dport, stream->tuple.sport); 	ret =
	//NTOH_TCP_PORTS_MISMATCH; 	goto exitp;
	//}

	if (ip4hdr->ip_v == 4)
		payload_len = ntohs(ip4hdr->ip_len) - iphdr_len - tcphdr_len;
	else
		payload_len = ntohs(ip6hdr->ip6_plen) - tcphdr_len;

	/* get origin and destination */
	if (!memcmp((void *)stream->tuple.source, (void *)saddr,
		    IP6_ADDR_LEN) &&
	    stream->tuple.sport ==
		tcp->th_sport)  // @contrib: harjotgill -
				// https://github.com/harjotgill
	{
		origin = &stream->client;
		destination = &stream->server;
		who = NTOH_SENT_BY_CLIENT;  // @contrib: di3online -
					    // https://github.com/di3online
	} else {
		origin = &stream->server;
		destination = &stream->client;
		who = NTOH_SENT_BY_SERVER;  // @contrib: di3online -
					    // https://github.com/di3online
		goto exitp;
	}

	get_timestamp(tcp, tcphdr_len, &tstamp);

	///* PAWS check */
	// if (tstamp > 0 && origin->lastts > 0)
	//{
	//	if (tstamp < origin->lastts)
	//	{
	//		ret = NTOH_PAWS_FAILED;
	//		goto exitp;
	//	}

	//	if (ntohl(tcp->th_seq) <= origin->next_seq)
	//		origin->lastts = tstamp;

	//}
	// else if (tstamp > 0 && !(origin->lastts))
	//	origin->lastts = tstamp;

	origin->lastts = tstamp;

	// if ( origin->next_seq > 0 && (origin->isn - ntohl ( tcp->th_seq ) ) <
	// origin->next_seq )
	//{
	//	ret = NTOH_TOO_LOW_SEQ_NUMBER;
	//	goto exitp;
	//}

	// if ( destination->next_seq > 0 && (origin->ian - ntohl(tcp->th_ack) )
	// < destination->next_seq )
	//{
	//	ret = NTOH_TOO_LOW_ACK_NUMBER;
	//	goto exitp;
	//}

	/* @todo some TCP/IP stacks implementations overloads the MSS on certain
	 * segments */
	/*if ( origin->mss > 0 && payload_len > origin->mss )
		return NTOH_SEGMENT_EXCEEDS_MSS;*/

	// segment = new_segment(stream, ntohl(tcp->th_seq) - origin->isn,
	// ntohl(tcp->th_ack) - origin->ian, payload_len, tcp->th_flags, udata);
	segment = new_segment(stream, ntohl(tcp->th_seq), ntohl(tcp->th_ack),
			      payload_len, tcp->th_flags, udata);
	if (!segment) {
		exp_stats->pm_segment_count_overflow += 1;
		exp_stats->pm_ret_sum +=
		    send_peer_segments(session, stream, origin, origin,
				       ntohl(tcp->th_ack), 0, 0, !who);
		segment =
		    new_segment(stream, ntohl(tcp->th_seq), ntohl(tcp->th_ack),
				payload_len, tcp->th_flags, udata);
	}

	/* wants to close the connection ? */
	if ((tcp->th_flags & (TH_FIN | TH_RST))) {
		exp_stats->pm_in_fin += 1;
		exp_stats->pm_ret_sum +=
		    send_peer_segments(session, stream, origin, origin,
				       ntohl(tcp->th_ack), 0, 0, !who);
		free_segment(stream, segment);
		stream->status = NTOH_STATUS_CLOSED;
	} else {
		if (payload_len > 0)
			if (stream->data_len + payload_len <
			    TCP_STREAM_DATA_MAX_LEN) {
				queue_ret =
				    queue_segment(stream, origin, segment);
			} else {
				if (payload_len < TCP_STREAM_DATA_MAX_LEN) {
					exp_stats->pm_buffer_overflow += 1;
					exp_stats->pm_ret_sum +=
					    send_peer_segments(
						session, stream, origin, origin,
						ntohl(tcp->th_ack), 0, 0, !who);
					queue_ret = queue_segment(
					    stream, origin, segment);
				} else {
					queue_ret = -1;
				}
			}
		else {
			queue_ret = -1;
		}
		if (queue_ret < 0) {
			exp_stats->payload_total_size -= segment->payload_len;
			free_segment(stream, segment);
		}
	}

	if (stream->status == NTOH_STATUS_CLOSED) {
#if LightBox == 0
		__tcp_free_stream(session, &stream, NTOH_REASON_SYNC,
				  NTOH_REASON_CLOSED);
		//++sgx_deleted_flow;
#else
		send_peer_segments(session, stream, &stream->client, 0, 0, 0, 0,
				   0);
		++session->max_streams;
		fid_t *fid = lb_get_fid(ip4hdr, tcp);
		stop_tracking(fid);
		//++lb_deleted_flow;
#endif
		stream = 0;
		exp_stats->current_stream -= 1;
		return ret;
	}

	if (ret == NTOH_OK) {
		if (stream != 0) {
			// gettimeofday(&(stream->last_activ), 0);
			memcpy(&stream->last_activ, &wall_clock,
			       sizeof(wall_clock));
			// stream->last_activ = wall_clock;
		}

		if (payload_len == 0) ret = NTOH_SYNCHRONIZING;
	}

exitp:

	return ret;
}

/* @brief resizes the hash table of a given TCP session */
int ntoh_tcp_resize_session(pntoh_tcp_session_t session, unsigned short table,
			    size_t newsize) {
	ptcprs_streams_table_t newht = 0, curht = 0;
	pntoh_tcp_stream_t item = 0;
	int current = 0;

	if (!session) return NTOH_INCORRECT_SESSION;

	if (!newsize || newsize == session->streams->table_size) return NTOH_OK;

	switch (table) {
		case NTOH_RESIZE_STREAMS:
			curht = session->streams;
			break;

		case NTOH_RESIZE_TIMEWAIT:
			curht = session->timewait;
			break;

		default:
			return NTOH_ERROR_PARAMS;
	}

	// increase the size
	if (newsize > curht->table_size)
		newht = htable_map(newsize, &tcp_equal_tuple);
	// decrease the size
	else {
		// sem_getvalue(&session->max_streams, &current);
		current = session->max_streams;
		if (newsize < current) {
			return NTOH_ERROR_NOSPACE;
		}
	}

	// moves all the streams to the new sessions table
	while ((current = htable_first(curht)) != 0) {
		item = (pntoh_tcp_stream_t)htable_remove(curht, current, 0);
		htable_insert(newht, current, item);
	}
	htable_destroy(&curht);

	if (table == NTOH_RESIZE_TIMEWAIT) {
		session->max_timewait = newsize;
		// sem_init(&session->max_timewait, 0, newsize);
		session->streams = newht;
	} else {
		session->max_streams = newsize;
		// sem_init(&session->max_streams, 0, newsize);
		session->timewait = newht;
	}

	return NTOH_OK;
}
