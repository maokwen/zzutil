#ifndef ZZUTIL_ZZCACHE_H
#define ZZUTIL_ZZCACHE_H

struct zzcache;
typedef struct zzcache zzcache;

/* Create table */
zzcache *zzcache_create_table();

/* Free table */
void zzcache_free_table(zzcache *table);

/* Insert value to table */
void zzcache_insert(zzcache *table, const char *key, const char *value);

/* Find all values in table, ordered by time added DESC */
char **zzcache_find(zzcache *table, const char *key);

/* Remove value from table, not recommand to use this */
void zzcache_remove(zzcache *table, const char *key);

#endif // ZZUTIL_ZZCACHE_H