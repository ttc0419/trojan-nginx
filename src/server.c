/* copyright (c) 2023, William Tang <galaxyking0419@gmail.com> */

#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/signalfd.h>
#include <sys/socket.h>

#ifdef TROJAN_NGINX_DEBUG
#include <arpa/inet.h>
#endif

#include "debug.h"
#include "dns.h"
#include "help.h"
#include "rdns-table.h"
#include "server.h"
#include "sha224hex.h"
#include "validate-fallback-server.h"

#define MAX_EVENT 64U
#define PIPE_SIZE (4 * 8 * 1024 * 1024)
#define DEFAULT_UDS_PATH "/tmp/trojan.sock"

#define REMAINING_SIZE(c, current_position) (c->buffer + c->buffer_size - current_position)

int main(int argc, char *argv[]) {
	/* Switch to line buffering for stdout logging */
	setvbuf(stdout, NULL, _IOLBF, 0);
	setvbuf(stderr, NULL, _IOLBF, 0);

	/* Password and fallback server unix domain socket are required */
	if (argc < 5) {
		SHOW_USAGE();
		return EXIT_FAILURE;
	}

	/* Parse command line options */
	int opt;
	char password_sha224_hex[SHA224HEX_SIZE];
	struct sockaddr_un fallback_server_address;
	while ((opt = getopt(argc, argv, ":p:f:")) != -1) {
		switch (opt) {
			case 'p':
				sha224hex(optarg, strlen(optarg), password_sha224_hex);
				break;
			case 'f':
				fallback_server_address.sun_family = AF_UNIX;
				strcpy(fallback_server_address.sun_path, optarg);
				validate_fallback_server(&fallback_server_address);
				break;
			default:
				SHOW_USAGE();
				return EXIT_FAILURE;
		}
	}

	signal(SIGPIPE, SIG_IGN);

	int server_socket = setup_uds_server(DEFAULT_UDS_PATH);
	int resolver_fd = create_resolver_fd();

	/* Pipe for splice() */
	int pipes[2];
	assert(pipe(pipes) != -1);
	fcntl(pipes[0], F_SETPIPE_SZ, PIPE_SIZE);

	int epoll_fd = epoll_create(MAX_EVENT);
	{
		struct epoll_event event;
		event.events = EPOLLIN;
		event.data.ptr = &server_socket;
		epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_socket, &event);

		event.data.ptr = &resolver_fd;
		epoll_ctl(epoll_fd, EPOLL_CTL_ADD, resolver_fd, &event);
	}

	struct epoll_event events[MAX_EVENT];
	size_t closed_list_size;
	conn_t *closed_list[MAX_EVENT << 1];

	printf("[INFO] Running trojan server on %s\n", DEFAULT_UDS_PATH);

	/* Server event loop using epoll() */
	while (true) {
		closed_list_size = 0;
		int count = epoll_wait(epoll_fd, events, MAX_EVENT, -1);

		for (int i = 0; i < count; ++i) {
			if (events[i].data.ptr == &server_socket) {
				/* Accept the connection and add it to epoll for further read polling */
				int client_socket = accept(server_socket, NULL, NULL);
				if (client_socket == -1) {
					fprintf(stderr, "[ERROR] Cannot accept client connection!\n");
					continue;
				}

#ifdef TROJAN_NGINX_DEBUG
				printf("Accepted client %d\n", client_socket);
#endif

				conn_t *c = calloc(1, sizeof(conn_t));
				assert(c != NULL);
				c->state = CONN_STATE_ACCEPTED;
				c->socket = client_socket;

				struct epoll_event event;
				event.events = EPOLLIN;
				event.data.ptr = c;
				epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_socket, &event);
			} else if (events[i].data.ptr == &resolver_fd) {
				/* Callback for domain name resolution using getaddrinfo_a() */
				bool free_domain = true;
				struct signalfd_siginfo ssi;
				read(resolver_fd, &ssi, sizeof(ssi));
				dns_result_t *dns_result = (dns_result_t *)ssi.ssi_ptr;

				/**
				 * Connect to target server using IPv6 address only when
				 * - Connection is not closed
				 * - Domain resolution is successful
				 */
				if (dns_result->client && !connection_closed(dns_result->client, closed_list, closed_list_size)) {
					/**
					 * We need to reset target connection buffer pointer
					 * to avoid it being double freed in shutdown_connection()
					 */
					if (socket_type(dns_result->client->other->socket) == SOCK_STREAM)
						dns_result->client->other->buffer = NULL;

					if (dns_result->gaicb->ar_result) {
						struct sockaddr_in addr = {
							.sin_family = AF_INET,
							.sin_port = dns_result->port,
							.sin_addr = ((struct sockaddr_in *)(dns_result->gaicb->ar_result->ai_addr))->sin_addr
						};

#ifdef TROJAN_NGINX_DEBUG
						char ip[INET_ADDRSTRLEN];
						inet_ntop(AF_INET, &(addr.sin_addr), ip, INET_ADDRSTRLEN);
						printf("[%d - %d] Domain resolution was successful, connecting %s:%hu...\n",
							   dns_result->client->socket, dns_result->client->other ? dns_result->client->other->socket : -1,
							   ip, ntohs(addr.sin_port));
#endif

						if (socket_type(dns_result->client->other->socket) == SOCK_STREAM) {
							/* TCP connection, connect to target using the resolved address using epoll first. */
							epoll_connect(dns_result->client->other, (struct sockaddr *)&addr, epoll_fd);
						} else {
							/* UDP connection, send the payload directly. */
							sendto(dns_result->client->other->socket, dns_result->udp_payload, dns_result->udp_payload_size,
								0, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
							free(dns_result->udp_payload);

							/* Add the packet to reverse dns list */
							if (rdns_table_insert((rdns_table_t *)dns_result->client->other->buffer, addr.sin_addr.s_addr, addr.sin_port, dns_result->gaicb->ar_name)) {
								free_domain = false;
							} else {
								fprintf(stderr, "[ERROR] Hash table insertion failed!");
								shutdown_connection(dns_result->client, epoll_fd, closed_list, &closed_list_size);
							}
						}
					} else {
						fprintf(stderr, "[ERROR] Cannot resolve %s or client closed the connection\n", dns_result->gaicb->ar_name);
						shutdown_connection(dns_result->client, epoll_fd, closed_list, &closed_list_size);
					}
				}

				freeaddrinfo(dns_result->gaicb->ar_result);
				free((void *)(dns_result->gaicb->ar_request));
				if (free_domain)
					free((void *)(dns_result->gaicb->ar_name));
				free(dns_result->gaicb);
				free(dns_result);
			} else {
				conn_t *c = (conn_t *)events[i].data.ptr;

				/* If the connection is closed previously, ignore them. */
				if (connection_closed(c, closed_list, closed_list_size)) {
#ifdef TROJAN_NGINX_DEBUG
					printf("Connection %p is closed, ignoring...\n", c);
#endif
					continue;
				}

				/* We handle connected events early since available size will be 0 */
				if (c->state == CONN_STATE_CONNECTING) {
#ifdef TROJAN_NGINX_DEBUG
					printf("[%d - %d] Target server is connected, sending %zu bytes of data\n",
						   c->socket, c->other ? c->other->socket : -1, c->other->buffer_size);
#endif

					if (events[i].events & EPOLLERR) {
						fprintf(stderr, "[ERROR] Failed to connect to target!\n");
						shutdown_connection(c, epoll_fd, closed_list, &closed_list_size);
						continue;
					}

					/* Both client and target is connected, start streaming. */
					c->state = CONN_STATE_STREAM;
					c->other->state = CONN_STATE_STREAM;

					/* We need to disable non-blocking flag on the target socket. */
					int flags = fcntl(c->socket, F_GETFL, 0);
					fcntl(c->socket, F_SETFL, flags & ~O_NONBLOCK);

					/* Add a new read event for the target server socket. */
					struct epoll_event event;
					event.events = EPOLLIN;
					event.data.ptr = c;
					epoll_ctl(epoll_fd, EPOLL_CTL_MOD, c->socket, &event);

					/* Send the initial payload and free the buffer if there are any */
					if (c->other->buffer && send(c->socket, c->other->buffer, c->other->buffer_size, 0) == -1) {
						fprintf(stderr, "[ERROR] Failed to send initial payload! (%s)\n", strerror(errno));
						shutdown_connection(c, epoll_fd, closed_list, &closed_list_size);
						continue;
					}

					/* Free the buffer and set in to NULL to prevent double free */
					free(c->other->buffer);
					c->other->buffer = NULL;

					continue;
				}

				int available_data_size;
				ioctl(c->socket, FIONREAD, &available_data_size);

				/* Connection is closed */
				if (available_data_size <= 0) {
					/**
					 * If the server is resolving domain, set client to NULL to indicate cancellation.
					 * This mechanism is only implemented for TCP connections for now,
					 * since UDP packets are sent over a TCP connection controlled by a Trojan client
					 * and will only be closed by the trojan client after idling for some time,
					 * which is almost certainly longer than the last domain resolution.
					 */
					if (c->state == CONN_STATE_PARSED && c->other->state == CONN_STATE_ACCEPTED) {
#ifdef TROJAN_NGINX_DEBUG
						printf("[%d - %d] Domain resolution is progress, canceling request...\n",
						       c->socket, c->other ? c->other->socket : -1);
#endif
						((dns_result_t *)(c->other->buffer))->client = NULL;
						c->other->buffer = NULL;
					}
					shutdown_connection(c, epoll_fd, closed_list, &closed_list_size);
					continue;
				}

				if (c->state == CONN_STATE_ACCEPTED) {
					/**
					 * The connection must be from a client, we check if the buffer is NULL.
					 *
					 * If the buffer is NULL, the connection is newly accepted.
					 * We allocate memory for it and append the received data.
					 *
					 * Otherwise, the additional data just arrived while the server is resolving a domain name.
					 * We just append the received data to the end of it and parse it again.
					 */
					c->state = CONN_STATE_PARSED;
					c->buffer = malloc(available_data_size);
					assert(c->buffer != NULL);
					recv(c->socket, c->buffer, available_data_size, 0);
					c->buffer_size = available_data_size;

					unsigned char *current_position = c->buffer;

					/* We assume the data is enough for SHA224 hex authentication. */
					if (available_data_size < SHA224HEX_SIZE ||
						memcmp(c->buffer, password_sha224_hex, SHA224HEX_SIZE) != 0) {
						/* Received size is less than hash size, it might be from the GFW. */
						fprintf(stderr, "[WARNING] Redirecting due to incorrect hash. Received payload: \n");
						pbin(c->buffer, c->buffer_size);
						connect_to_fallback_server(c, &fallback_server_address, epoll_fd);
						continue;
					} else if (available_data_size < TCP_MINIMAL_INIT_REQUEST_SIZE) {
						fprintf(stderr, "[ERROR] Connection closed due to insufficient received length.");
						shutdown_connection(c, epoll_fd, closed_list, &closed_list_size);
						continue;
					}

					current_position += SHA224HEX_SIZE + 2;

					/**
					 * From now on, we know the client is valid since the hash is correct.
					 * We can also safely close the connection if the data format is not correct.
					 */
					if ((current_position[0] != CMD_TCP && current_position[0] != CMD_UDP)
							|| (current_position[1] != ATYP_IPV4 && current_position[1] != ATYP_DOMAIN)) {
						fprintf(stderr, "[ERROR] Unsupported protocol, CMD: %hhu, ATYP: %hhu\n", current_position[0], current_position[1]);
						shutdown_connection(c, epoll_fd, closed_list, &closed_list_size);
						continue;
					}

					bool tcp = current_position[0] == CMD_TCP;

					/* We first create the socket for the remote host */
					c->other = calloc(1, sizeof(conn_t));
					assert(c->other != NULL);
					c->other->socket = socket(AF_INET, tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
					assert(c->other->socket != 1);
					c->other->other = c;

					/* The target connection buffer is a pointer to reverse DNS table for request domains */
					if (!tcp)
						c->other->buffer = calloc(1, sizeof(rdns_table_t));

					if (current_position[1] == ATYP_DOMAIN) {
						/* If the request type is domain we need to resolve the domain first. */
						unsigned char domain_length = current_position[2];

						if (available_data_size - SHA224HEX_SIZE - 5 < domain_length + 3) {
							fprintf(stderr, "[ERROR] Request size is too small\n");
							shutdown_connection(c, epoll_fd, closed_list, &closed_list_size);
							continue;
						}

						/* These fields are meaningless to UDP connection, just shift the offset. */
						if (tcp) {
							/* Copy domain string. */
							char *domain_name = malloc(domain_length + 1);
							assert(domain_name != NULL);
							memcpy(domain_name, &current_position[3], domain_length);
							domain_name[domain_length] = '\0';

#ifdef TROJAN_NGINX_DEBUG
							printf("[%d - %d] ATYP domain, resolving %s...\n", c->socket, c->other ? c->other->socket : -1, domain_name);
#endif

							in_port_t port;
							memcpy(&port, &current_position[3 + domain_length], sizeof(in_port_t));

							dns_lookup(c, domain_name, port, NULL, 0);
						}

						current_position += 7 + domain_length;
					} else if (current_position[1] == ATYP_IPV4) {
						if (tcp) {
							/**
							 * If the request type is IPv4, we can connect to the host directly.
							 * No additional length checks are required since minimal size is assumed using IPv4
							 */
							struct sockaddr_in addr = {.sin_family = AF_INET};
							memcpy(&addr.sin_addr.s_addr, &current_position[2], sizeof(in_addr_t));
							memcpy(&addr.sin_port, &current_position[2 + sizeof(in_addr_t)], sizeof(in_port_t));

#ifdef TROJAN_NGINX_DEBUG
							char ip[INET_ADDRSTRLEN];
							inet_ntop(AF_INET, &(addr.sin_addr), ip, INET_ADDRSTRLEN);
							printf("[%d - %d] ATYP IPv4, connecting %s:%hu...\n", c->socket, c->other ? c->other->socket : -1, ip, ntohs(addr.sin_port));
#endif

							epoll_connect(c->other, (struct sockaddr *)&addr, epoll_fd);
						}

						current_position += 10;
					}

					/* Since UDP packets are processed in the STREAM branch, update the state */
					if (!tcp) {
						c->state = CONN_STATE_STREAM;
						c->other->state = CONN_STATE_STREAM;

						struct epoll_event event;
						event.events = EPOLLIN;
						event.data.ptr = c->other;
						epoll_ctl(epoll_fd, EPOLL_CTL_ADD, c->other->socket, &event);
					}

					/**
					 * Move initial payload to the beginning of the data
					 * if there are any to send them after target server is connected.
					 */
					c->buffer_size = REMAINING_SIZE(c, current_position);
					if (c->buffer_size) {
						memmove(c->buffer, current_position, c->buffer_size);
						c->buffer = realloc(c->buffer, c->buffer_size);
						assert(c->buffer != NULL);

						/**
						 * If there are remaining payload and target connection type is UDP,
						 * we process them right way since we don't need to connect.
						 */
						if (!tcp)
							goto process_udp_packets;
					} else {
						free(c->buffer);
						c->buffer = NULL;
					}
				} else if (c->state == CONN_STATE_PARSED || c->state == CONN_STATE_RESOLVED) {
#ifdef TROJAN_NGINX_DEBUG
					printf("[%d - %d] Additional data arriving...\n", c->socket, c->other ? c->other->socket : -1);
#endif

					/**
					 * There might be more data coming when the server is connecting to the target server
					 * or resolving the domain name.  Append additional data to the buffer.
					 */
					append_buffer(c, available_data_size);
				} else if (c->state == CONN_STATE_STREAM) {
					if (socket_type(c->socket) == SOCK_STREAM && socket_type(c->other->socket) == SOCK_STREAM) {
						/**
						 * Since TCP connection just pass the the data between two sockets as is.
						 * Use splice() for TCP sockets for zero copy data transfer.
						 * We need to send data multiple times in case the data size exceeded the pipe maximum size.
						 * Otherwise, the pipe will block.
						 */
						while (available_data_size > 0) {
							int splice_size = available_data_size > PIPE_SIZE ? PIPE_SIZE : available_data_size;
							ssize_t s1 = splice(c->socket, NULL, pipes[1], NULL, splice_size, SPLICE_F_MOVE);
							ssize_t s2 = splice(pipes[0], NULL, c->other->socket, NULL, splice_size, SPLICE_F_MOVE);
							available_data_size -= splice_size;

							/* The splice() might be failed due to closed connection or reset. */
							if (s1 != s2) {
								fprintf(stderr, "[ERROR] splice() failed (%s)\n", strerror(errno));
								shutdown_connection(c, epoll_fd, closed_list, &closed_list_size);
								close(pipes[0]);
								close(pipes[1]);
								assert(pipe(pipes) != -1);
								break;
							}
						}
					} else if (socket_type(c->socket) == SOCK_STREAM && socket_type(c->other->socket) == SOCK_DGRAM) {
						/* New data came from client. For UDP we need to process the packets, zero copy is not possible */
						append_buffer(c, available_data_size);

#ifdef TROJAN_NGINX_DEBUG
						printf("Receiving UDP packets, data: ");
						pbin(c->buffer, c->buffer_size);
#endif

						/* Parse all UDP packets from the received buffer of client connection */
						process_udp_packets:
						while (c->buffer_size >= MIN_UDP_PKT_SIZE) {
							unsigned char *current_position = c->buffer;

							if (c->buffer[0] == ATYP_DOMAIN) {
								unsigned char domain_length = current_position[1];

								/* Wait for more data */
								if (REMAINING_SIZE(c, &current_position[2]) < domain_length + 7)
									break;

								char *domain_name = malloc(domain_length + 1);
								assert(domain_name != NULL);
								memcpy(domain_name, &current_position[2], domain_length);
								domain_name[domain_length] = '\0';

								current_position += domain_length + 2;

								in_port_t port;
								memcpy(&port, current_position, sizeof(in_port_t));
								current_position += 2;

								unsigned short payload_size;
								memcpy(&payload_size, current_position, sizeof(in_port_t));
								payload_size = ntohs(payload_size);
								current_position += 4;

								if (REMAINING_SIZE(c, current_position) < payload_size)
									break;

								unsigned char *udp_payload = malloc(payload_size);
								assert(udp_payload != NULL);
								memcpy(udp_payload, current_position, payload_size);

								dns_lookup(c, domain_name, port, udp_payload, payload_size);

								current_position += payload_size;
							} else if (c->buffer[0] == ATYP_IPV4) {
								struct sockaddr_in addr = {.sin_family = AF_INET};
								memcpy(&addr.sin_addr.s_addr, &current_position[1], 4);
								memcpy(&addr.sin_port, &current_position[5], 2);
								current_position += 7;

#ifdef TROJAN_NGINX_DEBUG
								char ip[INET_ADDRSTRLEN];
								inet_ntop(AF_INET, &(addr.sin_addr), ip, INET_ADDRSTRLEN);
								printf("[%d - %d] ATYP IPv4, sending UDP data to %s:%hu...\n", c->socket, c->other ? c->other->socket : -1, ip, ntohs(addr.sin_port));
#endif

								unsigned short payload_size;
								memcpy(&payload_size, current_position, sizeof(in_port_t));
								payload_size = ntohs(payload_size);
								current_position += 4;

								if (REMAINING_SIZE(c, current_position) < payload_size)
									break;

								sendto(c->other->socket, current_position, payload_size, 0,
									(struct sockaddr *)&addr, sizeof(struct sockaddr_in));

								current_position += payload_size;
							} else {
								fprintf(stderr, "[ERROR] Malformed UDP packet found, data: ");
								pbin(c->buffer, c->buffer_size);
								shutdown_connection(c, epoll_fd, closed_list, &closed_list_size);
								break;
							}

							/* Shift memory buffer */
							c->buffer_size = REMAINING_SIZE(c, current_position);
							if (c->buffer_size > 0) {
								memmove(c->buffer, current_position, c->buffer_size);
								c->buffer = realloc(c->buffer, c->buffer_size);
								assert(c->buffer != NULL);
							} else {
								free(c->buffer);
								c->buffer = NULL;
							}
						}
					} else if (socket_type(c->socket) == SOCK_DGRAM && socket_type(c->other->socket) == SOCK_STREAM) {
						/* UDP data received from some target server */
						struct sockaddr_in addr;
						socklen_t len = sizeof(struct sockaddr_in);
						unsigned char *payload = malloc(available_data_size);
						recvfrom(c->socket, payload, available_data_size, 0, (struct sockaddr *)&addr, &len);

						/**
						 * Check if the target server address and port was associated with a domain.
						 * If so, we need to construct the response using the domain instead of IPv4 address.
						 * Since the each address and port identifies a services on a host, it should be consistent
						 * about whether it uses IPv4 address or domain in the lifetime of the TCP connection.
						 */
						const char *domain = rdns_table_find((rdns_table_t *)c->buffer, addr.sin_addr.s_addr, addr.sin_port);

#ifdef TROJAN_NGINX_DEBUG
						char ip[INET_ADDRSTRLEN];
						inet_ntop(AF_INET, &(addr.sin_addr), ip, INET_ADDRSTRLEN);
						printf("[%d - %d] Received data from UDP target %s:%hu...\n", c->socket, c->other ? c->other->socket : -1, ip, ntohs(addr.sin_port));
#endif

						unsigned char *reply = malloc(11 + available_data_size);
						assert(reply != NULL);
						unsigned char *current_position = reply;

						/* Check the reverse dns table and construct the reply */
						if (domain) {
#ifdef TROJAN_NGINX_DEBUG
							puts("Domain found in the table, using domain for reply address");
#endif

							size_t domain_len = strlen(domain);
							reply = realloc(reply, 8 + domain_len + available_data_size);
							assert(reply != NULL);
							current_position = reply;

							reply[0] = ATYP_DOMAIN;
							reply[1] = domain_len;
							memcpy(&reply[2], domain, domain_len);
							free((void *)domain);

							current_position += 2 + domain_len;
						} else {
#ifdef TROJAN_NGINX_DEBUG
							puts("Domain not found in the table, using IPv4 for reply address");
#endif

							reply[0] = ATYP_IPV4;
							memcpy(&reply[1], &addr.sin_addr.s_addr, 4);
							current_position += 5;
						}

						/* Port */
						memcpy(current_position, &addr.sin_port, 2);

						/* Payload length */
						uint16_t length = htons(available_data_size);
						memcpy(&current_position[2], &length, 2);

						/* CRLF */
						current_position[4] = '\r';
						current_position[5] = '\n';
						current_position += 6;

						/* Payload */
						memcpy(current_position, payload, available_data_size);
						free(payload);

#ifdef TROJAN_NGINX_DEBUG
						printf("[%d - %d] Sending packet to client: ", c->socket, c->other ? c->other->socket : -1);
						pbin(reply, current_position - reply + available_data_size);
#endif

						if (send(c->other->socket, reply, current_position - reply + available_data_size, 0) == -1) {
							fprintf(stderr, "[ERROR] Failed to send UDP packet! (%s)\n", strerror(errno));
							shutdown_connection(c, epoll_fd, closed_list, &closed_list_size);
						}

						free(reply);
					}
				}
			}
		}
	}
}
