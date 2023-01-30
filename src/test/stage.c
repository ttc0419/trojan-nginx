/* copyright (c) 2023, William Tang <galaxyking0419@gmail.com> */

#include <stdio.h>
#include <stdlib.h>
#include "../rdns-table.h"

static inline void pt(rdns_table_t *table) {
	for (size_t i = 0; i < TABLE_SIZE; ++i) {
		printf("[%zu] %lu %p\n", i, table->records[i].key, table->records[i].domain);
	}
	putchar('\n');
}

int main(int argc, char *argv[]) {
	rdns_table_t *table = calloc(1, sizeof(rdns_table_t));

	rdns_table_insert(table, 23, 2, (char *)0x1111);
	pt(table);

	rdns_table_insert(table, 24, 2, (char *)0x1112);
	pt(table);

	printf("domain for 24: %p", rdns_table_find(table, 24, 2));
	pt(table);

	free(table);
}
