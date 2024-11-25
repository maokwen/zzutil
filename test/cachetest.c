#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <zzutil/zzcache.h>

#include "testutil.h"

int main(int agrc, char *agrv[]) {
    int ret;
    char *s;

    // test insert and find

    zzcache *cache = zzcache_create_table();
    assert(cache != NULL);
    printf("Cache created\n");
    
    printf("Inserting %s\t%s\n", "key1", "value1");
    zzcache_insert(cache, "key1", "value1");

    printf("Finding %s\n", "key1");
    s = zzcache_find(cache, "key1");
    assert(s != NULL);
    assert(strcmp(s, "value1") == 0);
    free(s);

    printf("Inserting %s\t%s\n", "key2", "value2");
    zzcache_insert(cache, "key2", "value2");

    printf("Finding %s\n", "key2");
    s = zzcache_find(cache, "key2");
    assert(s != NULL);
    assert(strcmp(s, "value2") == 0);
    free(s);

    printf("Inserting %s\t%s\n", "key1", "value3");
    zzcache_insert(cache, "key1", "value3");
    s = zzcache_find(cache, "key1");
    assert(s != NULL);
    assert(strcmp(s, "value3") == 0);
    free(s);

    printf("== Insert and find test passed\n");

    // test not expire

    printf("Sleep 100\n");
    dosleep_timeofday(100);

    printf("Finding %s\n", "key1");
    s = zzcache_find(cache, "key1");
    assert(s != NULL);
    assert(strcmp(s, "value3") == 0);
    free(s);

    printf("== Not expire test passed\n");

    // test expire

    printf("Sleep 300\n");
    dosleep_timeofday(1000);

    printf("Finding %s\n", "key1");
    s = zzcache_find(cache, "key1");
    assert(s == NULL);

    printf("Finding %s\n", "key2");
    s = zzcache_find(cache, "key2");
    assert(s == NULL);

    printf("== Expire test passed\n");

    // test remove

    printf("Inserting %s\t%s\n", "key1", "value4");
    zzcache_insert(cache, "key1", "value4");

    s = zzcache_find(cache, "key1");
    assert(s != NULL);
    assert(strcmp(s, "value4") == 0);

    zzcache_remove(cache, "key1");
    
    s = zzcache_find(cache, "key1");
    assert(s == NULL);

    printf("== Remove test passed\n");

    printf("== All tests passed\n");

    pasue_on_exit();
    return 0;
}
