/* copyright (c) 2023, William Tang <galaxyking0419@gmail.com> */

#ifndef TROJAN_NGINX_RNDS_TABLE_H
#define TROJAN_NGINX_RNDS_TABLE_H

#include <stdbool.h>
#include <stdint.h>

#include <netinet/in.h>

#define TABLE_SIZE 256

/**
 * Hash function of the hash table.
 * Since key is unique unsigned 64 bit integer, using module operation is good enough.
 */
#define TARGET_TO_KEY(ip, port) (((uint64_t)ip << 16) | port)
#define HASH(key) (key % TABLE_SIZE)

typedef struct {
	uint64_t key;
	const char *domain;
} rdns_rec_t;

/**
 * A hash table to store reverse dns records.
 * Key is the IPv4 address and port number, value is the domain string.
 */
typedef struct {
	size_t num_of_items;
	rdns_rec_t records[TABLE_SIZE];
} rdns_table_t;

static inline bool rdns_table_insert(rdns_table_t *table, in_addr_t ip, in_port_t port, const char *domain) {
	if (table->num_of_items >= TABLE_SIZE)
		return false;

	table->num_of_items += 1;
	uint64_t key = TARGET_TO_KEY(ip, port);
	size_t index = HASH(key);

	/* Resolve collision using linear probing */
	while (index < TABLE_SIZE && table->records[index].key != 0)
		++index;

	if (index == TABLE_SIZE) {
		return false;
	} else {
		table->records[index].key = key;
		table->records[index].domain = domain;
		return true;
	}
}

static inline const char *rdns_table_find(rdns_table_t *table, in_addr_t ip, in_port_t port) {
	uint64_t key = TARGET_TO_KEY(ip, port);
	size_t index = HASH(key);

	if (table->records[index].key == 0)
		return NULL;

	/* Use linear probing to find the correct record */
	while (index < TABLE_SIZE && table->records[index].key != key)
		++index;

	/**
	 * Since UDP packets are sent over a trojan client TCP connection
	 * and the life time of the connection is not very long.  We can assume
	 * all services are consistent about whether use IPv4 or domain.
	 */
	if (table->records[index].key == key)
		return table->records[index].domain;
	else
		return NULL;
}

static inline void rdns_table_free(rdns_table_t *table) {
	for (size_t i = 0; i < TABLE_SIZE; ++i) {
		if (table->records[i].domain)
			free((void *)table->records[i].domain);
	}
	free(table);
}

#endif //TROJAN_NGINX_RNDS_TABLE_H
