#include "etap_u.h"

#include "lb_core_edge_u.h"
#include <lb_config.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pcap.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

etap_param_t etap_args;
int srv_fd;
int cli_fd;

int batch_size;
uint8_t *batch_buffer;
uint8_t *client_batch_buffer;
int num_batch;

uint64_t rtt = 0;
uint64_t rtt_flag_1 = 0xFFFFFFFFFFFFFFFF;
uint64_t rtt_flag_2 = 0xFFFFFFFFFFFFFFFE;

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa) {
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in *)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

/* all configuration assumed to be int */
int get_conf_from_peer() {
	int conf = 0;
	int ret = recv(srv_fd, &conf, sizeof(conf), 0);
	if (ret != sizeof(conf)) {
		printf(
		    "%s : no excuse for failing to receive such small piece %d "
		    "of data!\n",
		    __func__, ret);
		etap_network_deinit();
		exit(1);
	} else {
		return conf;
	}
}

void configure_etap() {
	/* get configurations from peer in order */
	etap_args.record_size = get_conf_from_peer();
	etap_args.record_per_batch = get_conf_from_peer();

	printf("record_size %d\n", etap_args.record_size);
	printf("record_per_batch %d\n", etap_args.record_per_batch);

	batch_size =
	    (etap_args.record_size + MAC_SIZE) * etap_args.record_per_batch;
	batch_buffer = (uint8_t *)malloc(batch_size);
	printf("batch_size %d\n", batch_size);
}

void etap_network_init() {
	/* Sample code modified from
	   Beej's guide http://beej.us/guide/bgnet/html/single/bgnet.html
	*/

	struct sockaddr_storage their_addr;
	socklen_t addr_size;
	struct addrinfo hints, *res, *p;
	int sockfd;
	char s[INET6_ADDRSTRLEN];
	int yes;

	// first, load up address structs with getaddrinfo():
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;  // use IPv4
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;  // fill in my IP for me

	int status;
	if ((status = getaddrinfo(NULL, SERV_PORT, &hints, &res)) != 0) {
		fprintf(stderr, "getaddrinfo error: %s\n",
			gai_strerror(status));
		exit(1);
	}

	// loop through all the results and bind to the first we can
	for (p = res; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				     p->ai_protocol)) == -1) {
			perror("server: socket");
			continue;
		}

		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
			       sizeof(int)) == -1) {
			perror("setsockopt");
			exit(1);
		}

		if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("server: bind");
			continue;
		}

		break;
	}

	freeaddrinfo(res);  // free the linked-list

	if (p == NULL) {
		fprintf(stderr, "server: failed to bind\n");
		exit(1);
	}

	if (listen(sockfd, BACKLOG) == -1) {
		perror("listen");
		exit(1);
	}

	printf("server: waiting for connections...\n");

	while (1) {  // main accept() loop
		addr_size = sizeof their_addr;
		srv_fd =
		    accept(sockfd, (struct sockaddr *)&their_addr, &addr_size);
		if (srv_fd == -1) {
			perror("accept");
			continue;
		}

		inet_ntop(their_addr.ss_family,
			  get_in_addr((struct sockaddr *)&their_addr), s,
			  sizeof s);
		printf("server: got connection from %s\n", s);

		close(sockfd);	// we don't need the listener anymore
		break;
	}
	configure_etap();
	// not to be used here, this is enclave related
	//ecall_etap_controller_init(0, 0);

	/* init the gateway client for next middlebox */
	// gateway_init(etap_args.record_size, etap_args.record_per_batch);
}

void send_conf_to_peer(int conf) {
	int ret = send(cli_fd, &conf, sizeof(conf), 0);
	if (ret != sizeof(conf)) {
		printf(
		    "%s : no excuse for failing to sending such small piece of "
		    "data!\n",
		    __func__);
		exit(1);
	}
}

void gateway_init(int rec_size, int rec_per_bat) {
	struct addrinfo hints, *servinfo, *p;
	int rv;
	char s[INET6_ADDRSTRLEN];

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((rv = getaddrinfo(SEND_ADDR, SEND_PORT, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return;
	}

	// loop through all the results and connect to the first we can
	for (p = servinfo; p != NULL; p = p->ai_next) {
		if ((cli_fd = socket(p->ai_family, p->ai_socktype,
				     p->ai_protocol)) == -1) {
			perror("client: socket");
			continue;
		}
		if (connect(cli_fd, p->ai_addr, p->ai_addrlen) == -1) {
			close(cli_fd);
			perror("client: connect");
			continue;
		}

		break;
	}

	if (p == NULL) {
		fprintf(stderr, "client: failed to connect\n");
		exit(1);
		return;
	}

	inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), s,
		  sizeof s);
	printf("client: connecting to %s\n", s);

	freeaddrinfo(servinfo);	 // all done with this structure

	/* send configurations to peer */
	printf("record_size %d\n", rec_size);
	printf("record_per_batch %d\n", rec_per_bat);

	send_conf_to_peer(rec_size);
	send_conf_to_peer(rec_per_bat);
	send_conf_to_peer(-1);

	// live mode
	/* send_conf_to_peer(-1); */

	batch_size = (rec_size + MAC_SIZE) * rec_per_bat;
	client_batch_buffer = malloc(batch_size);
	if (!client_batch_buffer) {
		printf("Failed to malloc mem to client_batch_buffer.");
		exit(-1);
	}
	printf("done with gateway init()\n");
}

void gateway_deinit() {
	if (close(cli_fd) != 0)
		perror(
		    "gateway fd for next middlebox is not closed correctly.");
	else
		printf("gateway fd for next middlebox is closed.");
	free(client_batch_buffer);
}

void etap_network_deinit() {
	if (close(srv_fd) != 0)
		perror("lb_net");
	else
		printf("lb_net closed!\n");
	free(batch_buffer);
}

int etap_testrun() {
	num_batch = get_conf_from_peer();
	// trick to check the end of test
	if (memcmp(&num_batch, "end", sizeof(num_batch)) == 0) {
		printf("Receive termination signal from peer!\n");
		return 0;
	} else if (num_batch == -1) {
		printf("live traffic mode enabled!\n");
		return 1;
	} else {
		//	printf("Expecting %d batches to receive in current
		// round!\n", num_batch);
		return 1;
	}
}

/* etap OCALL */
void ocall_lb_etap_in(uint8_t **batch) {
	/* static buffers */
	static int b_idx = 0;

	/* stop sign */
	if (unlikely(b_idx == num_batch)) {
		*batch = 0;
		//	printf("no more batch to receive after %d!\n", b_idx);
		b_idx = 0;
	} else {
		//		printf("to receive batch %d!\n", b_idx);

		uint64_t flag;
		int expect_rtt_byte;

		expect_rtt_byte = sizeof(uint64_t);
		while (expect_rtt_byte) {
				expect_rtt_byte -= recv(srv_fd, &flag, expect_rtt_byte, 0);
		 }
		/* printf("recv rtt flags, start to calculate rtt\n"); */
		// rtt_flag_1 or rtt_flag_2
		if (flag == rtt_flag_1) {
			// send some dummy byte back
			send(srv_fd, &flag, sizeof(flag), 0);

			expect_rtt_byte = sizeof(uint64_t);
			while (expect_rtt_byte) {
				expect_rtt_byte -=
					recv(srv_fd, &rtt, expect_rtt_byte, 0);
			}
			/* printf("Current rtt is %lu\n", rtt); */

		} 

		int expect = batch_size;
		while (expect) {
				int ret = recv(
				    srv_fd, batch_buffer + batch_size - expect,
				    expect, 0);
				if (likely(ret > 0)) {
					expect -= ret;
				} else if (ret == 0) {
					printf("client closed!\n");
					exit(1);
				} else {
					perror("recv");
				}
			}

			*batch = batch_buffer;
			++b_idx;

		/* *batch = batch_buffer; */

		/* ++b_idx; */

		//	printf("batch %d received!\n", b_idx);
	}
}

void ocall_get_rtt(uint64_t * rtt_enclave) {
		*rtt_enclave = rtt;
}

void ocall_lb_etap_out(uint8_t **batch) {
	int expect = batch_size;
	while (expect) {
		int ret = send(cli_fd, *batch + batch_size - expect, expect, 0);
		if (ret > 0)
			expect -= ret;
		else
			break;
	}
}
