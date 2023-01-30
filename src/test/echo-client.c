/* copyright (c) 2023, William Tang <galaxyking0419@gmail.com> */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(int argc, char *argv[]) {
	if (argc < 5) {
		printf("Usage: %s [t|u] [address] [port] [payload]\n", argv[0]);
		return EXIT_FAILURE;
	}

	int s;
	if (argv[1][0] == 't') {
		s = socket(AF_INET, SOCK_STREAM, 0);
	} else if (argv[1][0] == 'u') {
		s = socket(AF_INET, SOCK_DGRAM, 0);
	} else {
		printf("Usage: %s [t|u] [address] [port] [payload]\n", argv[0]);
		return EXIT_FAILURE;
	}

	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(atoi(argv[3]))
	};
	inet_pton(AF_INET, argv[2], &(addr.sin_addr));

	if (connect(s, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1) {
		printf("[FATAL] Failed to connect to address! (%s)\n", strerror(errno));
		return EXIT_FAILURE;
	}

	size_t payload_size = strlen(argv[4]);

	if (send(s, argv[4], payload_size, 0) == -1) {
		printf("[FATAL] Failed to connect to send data! (%s)\n", strerror(errno));
		return EXIT_FAILURE;
	}

	char recv_buf[payload_size];
	if (recv(s, recv_buf, payload_size, 0) == -1) {
		printf("[FATAL] Failed to receive echo data! (%s)\n", strerror(errno));
		return EXIT_FAILURE;
	}

	if (memcmp(recv_buf, argv[4], payload_size) != 0)
		puts("[ERROR] Echo data is incorrect!");
	else
		puts("[INFO] Echo data is received and validated!");

	close(s);

	return 0;
}
