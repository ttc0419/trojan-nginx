/* copyright (c) 2023, William Tang <galaxyking0419@gmail.com> */

#ifndef TROJAN_NGINX_DNS_H
#define TROJAN_NGINX_DNS_H

#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <netdb.h>
#include <netinet/in.h>
#include <sys/signalfd.h>

#include "server.h"

typedef struct {
	struct gaicb *gaicb;
	conn_t *client;
	in_port_t port;
	unsigned char *udp_payload;
	size_t udp_payload_size;
} dns_result_t;

static inline int create_resolver_fd() {
	sigset_t sigset;
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGRTMIN);
	pthread_sigmask(SIG_BLOCK, &sigset, NULL);
	return signalfd(-1, &sigset, SFD_NONBLOCK | SFD_CLOEXEC);
}

static inline void dns_lookup(conn_t *client, const char *const hostname, in_port_t port, unsigned char *udp_payload, size_t udp_payload_size) {
	struct gaicb *cb = calloc(1, sizeof(struct gaicb));
	cb->ar_name = hostname;

	struct addrinfo *request = calloc(1, sizeof(struct addrinfo));
	request->ai_socktype = SOCK_DGRAM;
	request->ai_protocol = IPPROTO_UDP;
	request->ai_family = AF_INET;
	request->ai_flags = AI_V4MAPPED;
	cb->ar_request = request;

	dns_result_t *dns_result = malloc(sizeof(dns_result_t));
	dns_result->client = client;
	dns_result->gaicb = cb;
	dns_result->port = port;
	dns_result->udp_payload = udp_payload;
	dns_result->udp_payload_size = udp_payload_size;

	/**
	 * We save the pointer in target connection buffer in case the client closed the connection
	 * and we need to ignore the dns result in resolver callback.
	 */
	if (socket_type(client->other->socket) == SOCK_STREAM)
		client->other->buffer = (unsigned char *)dns_result;

	struct sigevent sev;
	sev.sigev_notify = SIGEV_SIGNAL;
	sev.sigev_signo = SIGRTMIN;
	sev.sigev_value.sival_ptr = dns_result;

	getaddrinfo_a(GAI_NOWAIT, &cb, 1, &sev);
}

#endif //TROJAN_NGINX_DNS_H
