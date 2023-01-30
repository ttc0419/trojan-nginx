/* copyright (c) 2023, William Tang <galaxyking0419@gmail.com> */

#ifndef TROJAN_NGINX_SHA224HEX_H
#define TROJAN_NGINX_SHA224HEX_H

#include <openssl/evp.h>

#define SHA224_SIZE 28
#define SHA224HEX_SIZE 56

/* We use sha224 from openssl since NGINX use it as well */
static inline void sha224hex(void *data, size_t size, char *output) {
	const char hex[17] = "0123456789abcdef";
	unsigned char buffer[SHA224_SIZE];

	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	EVP_DigestInit(ctx, EVP_sha224());
	EVP_DigestUpdate(ctx, data, size);
	EVP_DigestFinal(ctx, buffer, NULL);
	EVP_MD_CTX_free(ctx);

	for (size_t i = 0; i < SHA224_SIZE; ++i) {
		output[i << 1] = hex[buffer[i] >> 4];
		output[(i << 1) + 1] = hex[buffer[i] & 0xf];
	}
}

#endif //TROJAN_NGINX_SHA224HEX_H
