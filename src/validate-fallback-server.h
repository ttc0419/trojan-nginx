/* copyright (c) 2023, William Tang <galaxyking0419@gmail.com> */

#ifndef TROJAN_NGINX_VALIDATE_FALLBACK_SERVER_H
#define TROJAN_NGINX_VALIDATE_FALLBACK_SERVER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <sys/socket.h>

#define HTTP_VALIDATE_REQUEST "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
#define HTTP_VALIDATE_REQUEST_SIZE 54
#define HTTP_VALIDATE_RESPONSE "HTTP/1.1 200 OK\r\n"
#define HTTP_VALIDATE_RESPONSE_SIZE 17

static inline bool validate_fallback_server(struct sockaddr_un *address) {
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1) {
		fprintf(stderr,
			"[FATAL] Cannot create server file descriptor! Please check your server is running correctly!\n");
		exit(EXIT_FAILURE);
	}

	int ret = connect(fd, (struct sockaddr *)address, sizeof(struct sockaddr_un));
	if (ret == -1) {
		fprintf(stderr,
			"[FATAL] Cannot connect to fallback server! Please check your fallback server is running correctly!\n");
		exit(EXIT_FAILURE);
	}

	send(fd, HTTP_VALIDATE_REQUEST, HTTP_VALIDATE_REQUEST_SIZE, 0);

	char response[HTTP_VALIDATE_RESPONSE_SIZE];
	ssize_t received_size = recv(fd, response, HTTP_VALIDATE_RESPONSE_SIZE, 0);

	close(fd);

	return received_size == HTTP_VALIDATE_RESPONSE_SIZE &&
		memcmp(response, HTTP_VALIDATE_RESPONSE, HTTP_VALIDATE_RESPONSE_SIZE) == 0;
}

#endif //TROJAN_NGINX_VALIDATE_FALLBACK_SERVER_H
