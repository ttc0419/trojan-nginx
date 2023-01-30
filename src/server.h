/* copyright (c) 2023, William Tang <galaxyking0419@gmail.com> */

#ifndef TROJAN_NGINX_SERVER_H
#define TROJAN_NGINX_SERVER_H

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <fcntl.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "rdns-table.h"

/* Only used by client connection */
#define CONN_STATE_ACCEPTED 0
#define CONN_STATE_PARSED 1
#define CONN_STATE_RESOLVED 2

/* Only used by target connection */
#define CONN_STATE_CONNECTING 3

/* Can be used by both types of connections */
#define CONN_STATE_STREAM 4

/* SOCKS5 CMD */
#define CMD_TCP 0x1
#define CMD_UDP 0x3

/* SOCKS5 ATYP */
#define ATYP_IPV4 0x1
#define ATYP_DOMAIN 0x3

/**
 * +-----------------------+------+-----+------+-----------+------+------+----------++-------+
 * | hex(SHA224(password)) | CRLF | CMD | ATYP | IPv4 ADDR | PORT | CRLF | Payload  || Total |
 * +-----------------------+------+-----+------+-----------+------+------+----------++-------+
 * |          56           |   2  |  1  |   1  |     4     |   2  |   2  |     0    ||   68  |
 * +-----------------------+------+-----+------+-----------+------+------+----------++-------+
 */
#define TCP_MINIMAL_INIT_REQUEST_SIZE 68

/**
 * +------+-----------+------+--------+------+----------++-------+
 * | ATYP | IPv4 ADDR | PORT | Length | CRLF | Payload  || Total |
 * +------+-----------+------+--------+------+----------++-------+
 * |   1  |     4     |   2  |    2   |   2  |     1    ||   12  |
 * +------+-----------+------+--------+------+----------++-------+
 */
#define MIN_UDP_PKT_SIZE 12

typedef struct conn_t {
	unsigned int state;
	int socket;
	struct conn_t *other;
	unsigned char *buffer;
	size_t buffer_size;
} conn_t;

static inline int setup_uds_server(char *path) {
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	assert(fd != -1);

	struct sockaddr_un addr;
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, path);

	unlink(path);

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		fprintf(stderr, "[FATAL] Cannot bind to the path!\n");
		exit(EXIT_FAILURE);
	}

	chmod(path, 0666);

	if (listen(fd, 65536) == -1) {
		fprintf(stderr, "[FATAL] Cannot listen to the path!\n");
		exit(EXIT_FAILURE);
	}

	return fd;
}

static inline int socket_type(int s) {
	int type;
	socklen_t length = sizeof(int);
	getsockopt(s, SOL_SOCKET, SO_TYPE, &type, &length);
	return type;
}

static inline void shutdown_connection(conn_t *c, int epoll_fd, conn_t **closed_list, size_t *closed_list_size) {
#ifdef TROJAN_NGINX_DEBUG
	printf("[%d - %d] Closing connection... closed_list_size: %zu\n", c->socket, c->other ? c->other->socket : -1, *closed_list_size);
#endif

	closed_list[(*closed_list_size)++] = c;
	if (c->other)
		closed_list[(*closed_list_size)++] = c->other;

	epoll_ctl(epoll_fd, EPOLL_CTL_DEL, c->socket, NULL);
	if (c->other)
		epoll_ctl(epoll_fd, EPOLL_CTL_DEL, c->other->socket, NULL);

	if (c->other) {
		if (c->other->buffer) {
			if (socket_type(c->other->socket) == SOCK_STREAM)
				free(c->other->buffer);
			else
				rdns_table_free((rdns_table_t *)c->other->buffer);
		}
		close(c->other->socket);
		free(c->other);
	}

	if (c->buffer) {
		if (socket_type(c->socket) == SOCK_STREAM)
			free(c->buffer);
		else
			rdns_table_free((rdns_table_t *)c->other->buffer);
	}
	close(c->socket);

	free(c);
}

static inline void epoll_connect(conn_t *c, struct sockaddr *addr, int epoll_fd) {
	/* Enable non-blocking on the connecting socket */
	int flags = fcntl(c->socket, F_GETFL, 0);
	fcntl(c->socket, F_SETFL, flags | O_NONBLOCK);

	/* Add connecting socket to epoll */
	struct epoll_event event;
	event.events = EPOLLOUT | EPOLLONESHOT;
	event.data.ptr = c;
	epoll_ctl(epoll_fd, EPOLL_CTL_ADD, c->socket, &event);

	/* We connect the target server using the address above */
	connect(c->socket, addr,
		addr->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_un));

	c->state = CONN_STATE_CONNECTING;
	c->other->state = CONN_STATE_RESOLVED;
}

static inline void connect_to_fallback_server(conn_t *c, struct sockaddr_un *addr, int epoll_fd) {
	c->other = calloc(1, sizeof(conn_t));
	c->other->socket = socket(AF_UNIX, SOCK_STREAM, 0);
	assert(c->other->socket != -1);
	c->other->other = c;

	epoll_connect(c->other, (struct sockaddr *)addr, epoll_fd);
}

static inline bool connection_closed(conn_t *c, conn_t **closed_list, size_t closed_list_size) {
	size_t i = 0;
	while (i < closed_list_size && closed_list[i] != c)
		++i;
	return i < closed_list_size;
}

static inline void append_buffer(conn_t *c, int available_data_size) {
	if (c->buffer) {
		c->buffer = realloc(c->buffer, c->buffer_size + available_data_size);
		assert(c->buffer != NULL);
		recv(c->socket, c->buffer + c->buffer_size, available_data_size, 0);
		c->buffer_size += available_data_size;
	} else {
		c->buffer = malloc(available_data_size);
		assert(c->buffer != NULL);
		recv(c->socket, c->buffer, available_data_size, 0);
		c->buffer_size = available_data_size;
	}
}

#endif //TROJAN_NGINX_SERVER_H
