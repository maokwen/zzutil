#ifndef ZZUTIL_ZZCACHE_H
#define ZZUTIL_ZZCACHE_H

#include "basetype.h"

struct zzcache;
typedef struct zzcache zzcache;

/* Create table */
zzcache *zzcache_create_table();

/* Free table */
void zzcache_free_table(zzcache *table);

/* Insert value to table */
void zzcache_insert(zzcache *table, char *key, u8 *value);

/* Find all values in table, ordered by time added DESC */
u8 *zzcache_find(zzcache *table, char *key);

/* Remove value from table, not recommand to use this */
void zzcache_remove(zzcache *table, char *key);

#endif // ZZUTIL_ZZCACHE_H
