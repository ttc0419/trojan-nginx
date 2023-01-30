/* copyright (c) 2023, William Tang <galaxyking0419@gmail.com> */

#ifndef TROJAN_NGINX_DEBUG_H
#define TROJAN_NGINX_DEBUG_H

#include <stdio.h>
#include <stddef.h>
#include <ctype.h>

static inline void pbin(unsigned char *buffer, size_t size) {
	for (size_t i = 0; i < size; ++i) {
		if (isprint(buffer[i]))
			putchar(buffer[i]);
		else
			printf("\\%hhu", buffer[i]);
	}
	putchar('\n');
}

#endif //TROJAN_NGINX_DEBUG_H
