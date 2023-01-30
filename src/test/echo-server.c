/* copyright (c) 2023, William Tang <galaxyking0419@gmail.com> */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>

#define BUFFER_SIZE 256

int main(int argc, char *argv[]) {
	if (argc < 3) {
		printf("Usage: %s [t|u] [port]\n", argv[0]);
		return EXIT_FAILURE;
	}

	int s;
	if (argv[1][0] == 't') {
		puts("Using TCP socket");
		s = socket(AF_INET, SOCK_STREAM, 0);
	} else if (argv[1][0] == 'u') {
		puts("Using UDP socket");
		s = socket(AF_INET, SOCK_DGRAM, 0);
	} else {
		printf("Usage: %s [t|u] [address] [port]\n", argv[0]);
		return EXIT_FAILURE;
	}

	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(atoi(argv[2])),
		.sin_addr = {INADDR_ANY}
	};

	if (bind(s, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1) {
		printf("[FATAL] Failed to bind to address! (%s)\n", strerror(errno));
		return EXIT_FAILURE;
	}

	ssize_t recv_size;
	unsigned char buffer[BUFFER_SIZE];
	memset(buffer, 0, BUFFER_SIZE);

	if (argv[1][0] == 't') {
		int cs;
		if (listen(s, 4) == -1 || (cs = accept(s, NULL, NULL)) == -1) {
			printf("[FATAL] Failed to accept client! (%s)\n", strerror(errno));
			return EXIT_FAILURE;
		}

		if ((recv_size = recv(cs, buffer, BUFFER_SIZE, 0)) == -1) {
			printf("[FATAL] Failed to receive TCP echo data! (%s)\n", strerror(errno));
			return EXIT_FAILURE;
		}

		if (send(cs, buffer, recv_size, 0) != recv_size) {
			printf("[FATAL] Failed to send echo data! (%s)\n", strerror(errno));
			return EXIT_FAILURE;
		}

		close(cs);
	} else {
		struct sockaddr_in c_addr;
		socklen_t c_addr_len = sizeof(struct sockaddr_in);

		puts("Waiting UDP data...");
		if ((recv_size = recvfrom(s, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&c_addr, &c_addr_len)) == -1) {
			printf("[FATAL] Failed to receive UDP echo data! (%s)\n", strerror(errno));
			return EXIT_FAILURE;
		}
		printf("Got UDP data %s\n", buffer);

		puts("Sending UDP echo data...");
		if (sendto(s, buffer, recv_size, 0, (struct sockaddr *)&c_addr, c_addr_len) != recv_size) {
			printf("[FATAL] Failed to send UDP echo data! (%s)\n", strerror(errno));
			return EXIT_FAILURE;
		}
	}

	close(s);

	return 0;
}
