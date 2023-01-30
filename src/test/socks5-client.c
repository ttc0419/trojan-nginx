/* copyright (c) 2023, William Tang <galaxyking0419@gmail.com> */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../debug.h"

static unsigned char ipv4_request[] = {
	5, 3, 0, 1,
	1, 13, 189, 2, 4, 210,
	'F', 'Y', 'G', 'F', 'W'
};

__attribute__((unused))
static unsigned char domain_request[] = {
	5, 3, 0, 3,
	7, 't', 't', 'c', '.', 'i', 'c', 'u', 4, 210,
	'F', 'Y', 'G', 'F', 'W'
};

int main(int argc, char *argv[]) {
	if (argc < 2) {
		printf("Usage: %s [t|u]\n", argv[0]);
		return EXIT_FAILURE;
	}

	int s;
	if (argv[1][0] == 't') {
		s = socket(AF_INET, SOCK_STREAM, 0);
	} else if (argv[1][0] == 'u') {
		s = socket(AF_INET, SOCK_DGRAM, 0);
	} else {
		printf("Usage: %s [t|u]\n", argv[0]);
		return EXIT_FAILURE;
	}

	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(1080)
	};
	inet_pton(AF_INET, "127.0.0.1", &(addr.sin_addr));

	if (connect(s, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1) {
		printf("[FATAL] Failed to connect to address! (%s)\n", strerror(errno));
		return EXIT_FAILURE;
	}

	if (send(s, ipv4_request, 15, 0) == -1) {
		printf("[FATAL] Failed to connect to send data! (%s)\n", strerror(errno));
		return EXIT_FAILURE;
	}

	unsigned char recv_buf[4096];
	ssize_t recv_size = recv(s, recv_buf, 4096, 0);
	if (recv_size == -1) {
		printf("[FATAL] Failed to receive echo data! (%s)\n", strerror(errno));
		return EXIT_FAILURE;
	}

	puts("Got data: ");
	pbin(recv_buf, recv_size);

	close(s);

	return 0;
}
