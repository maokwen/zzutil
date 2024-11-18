#include "zzcache.h"
#include "errmsg.h"

#include <stdlib.h>
#include <time.h>

#ifdef _WIN32
#elif _UNIX
#include <pthread.h>
#endif

#define TABLE_SIZE 100
#define TICKS_TO_EXPIRE (CLOCKS_PER_SEC / 1000 * 200) // 200 milliseconds
#define CLEANUP_INTERVAL_MILISEC 20                   // 20 milliseconds
#define MAXIMUM_DUP_KEY_NUMBER 10

typedef struct {
    char *key;
    char *value;
    clock_t expire;
    struct cache_entry *next;
} cache_entry;

struct zzcache {
    cache_entry *entries[TABLE_SIZE];
#ifdef _UNIX
    pthread_t thread;
    pthread_rwlock_t *rwlock;
    int start_thread;
#endif
};

/* calcu hash */
unsigned int hash(const char *key);

/* remove a node in entry node list */
cache_entry *inplace_remove_node(zzcache *table, int slot, cache_entry *curr, cache_entry *prev);

/* routine to clean up expired entry */
void *cleanup_routine(void *arg);

/* stop thread and free memory */
void cleanup(zzcache *table);

zzcache *zzcache_create_table() {
    zzcache *table = malloc(sizeof(zzcache));
    for (int i = 0; i < TABLE_SIZE; i++) {
        table->entries[i] = NULL;
    }
    table->thread = NULL;
    table->rwlock = NULL;

    // create a new thread to clean up expired entries
    int ret;
    pthread_t thread;
    ret = pthread_create(
        &table->thread,
        NULL,
        cleanup_routine,
        table);
    if (thread == 0) {
        printf("Failed to create thread");
        cleanup(table);
        return NULL;
    }
    // init rw lock
    table->rwlock = malloc(sizeof(pthread_rwlock_t));
    ret = pthread_rwlock_init(table->rwlock, NULL);
    if (ret != 0) {
        printf("Failed to init rwlock");
        cleanup(table);
        return NULL;
    }

    return table;
}

void zzcache_free_table(zzcache *table) {
    cleanup(table);
}

void zzcache_insert(zzcache *table, const char *key, const char *value) {
    unsigned int slot = hash(key);
    cache_entry *entry = malloc(sizeof(cache_entry));
    entry->key = strdup(key);
    entry->value = strdup(value);
    entry->next = NULL;

    pthread_rwlock_wrlock(table->rwlock);
    {
        entry->expire = clock() + TICKS_TO_EXPIRE;

        // if slot already has entry, insert to the HEAD of the list
        int flag = 0;
        cache_entry *parent = table->entries[slot];
        if (parent != NULL) {
            entry->next = parent;
            table->entries[slot] = entry;
            flag = 1;
        }
        // else insert to the slot
        if (!flag) {
            table->entries[slot] = entry;
        }
    }
    pthread_rwlock_wrlock(table->rwlock);
}

char **zzcache_find(zzcache *table, const char *key) {
    unsigned int slot = hash(key);
    char *buffer[MAXIMUM_DUP_KEY_NUMBER] = {};
    int total = 0;

    pthread_rwlock_rdlock(table->rwlock);
    {
        // find top MAXIMUM_DUP_KEY_NUMBER entries, ordered by time added DESC
        cache_entry *entry = table->entries[slot];
        while (entry != NULL && total <= MAXIMUM_DUP_KEY_NUMBER) {
            if (strcmp(entry->key, key) == 0) {
                buffer[total++] = entry->value;
            }
            entry = entry->next;
        }
    }
    pthread_rwlock_unlock(table->rwlock);

    char **string_list = (char **)malloc(sizeof(char *) * (total + 1));
    for (int i = 0; i < total; i++) {
        string_list[i] = buffer[i];
    }
    string_list[total] = NULL;

    return string_list;
}

void zzcache_remove(zzcache *table, const char *key) {
    unsigned int slot = hash(key);

    pthread_rwlock_wrlock(table->rwlock);
    {
        cache_entry *entry = table->entries[slot];
        cache_entry *prev = NULL;
        while (entry != NULL) {
            if (strcmp(entry->key, key) == 0) {
                prev = inplace_remove_node(table, slot, entry, prev);
                entry = prev->next;
                continue;
            }
            prev = entry;
            entry = entry->next;
        }
    }
    pthread_rwlock_unlock(table->rwlock);
}

/* SECTION implement */

unsigned int hash(const char *key) {
    unsigned int hash = 0;
    while (*key) {
        hash = (hash << 5) + *key++;
    }
    return hash % TABLE_SIZE;
}

cache_entry *inplace_remove_node(zzcache *table, int slot, cache_entry *curr, cache_entry *prev) {
    if (prev == NULL) {
        table->entries[slot] = curr->next;
    } else {
        prev->next = curr->next;
    }
    free(curr->key);
    free(curr->value);
    free(curr);
    return prev;
}

void *cleanup_routine(void *arg) {
    zzcache *table = (zzcache *)arg;
    // wait for cond to run
    // pthread_mutex_lock(&table->mutex);
    // while (!table->start_thread) {
    //     pthread_cond_wait(&table->cond, &table->mutex);
    // }
    // pthread_mutex_unlock(&table->mutex);

    printf("Thread started\n");

    clock_t now;
    while (1) {
        cache_entry *to_remove_list = malloc(sizeof(cache_entry));

        // record entries to remove
        pthread_rwlock_rdlock(table->rwlock);
        {
            now = clock();
            cache_entry *to_remove_tail = to_remove_list;
            for (int i = 0; i < TABLE_SIZE; i++) {
                cache_entry *entry = table->entries[i];
                int deep = 0;
                while (entry != NULL) {
                    // if is expired, add to remove list
                    if (entry->expire < now) {
                        to_remove_tail->next = entry;
                        to_remove_tail = entry;
                    }
                    // if is duplicated too many times, add to remove list
                    else if (++deep > MAXIMUM_DUP_KEY_NUMBER) {
                        to_remove_tail->next = entry;
                        to_remove_tail = entry;
                    }

                    entry = entry->next;
                }
            }
        }
        pthread_rwlock_unlock(table->rwlock);

        // remove entries
        pthread_rwlock_wrlock(table->rwlock);
        {
            // NOTE: optimize this
            for (cache_entry *entry = to_remove_list->next; entry != NULL; entry = entry->next) {
            }
        }
        pthread_rwlock_unlock(table->rwlock);

        nsleep(CLEANUP_INTERVAL_MILISEC * 1000);
    }
}

void cleanup(zzcache *table) {
    if (table == NULL) {
        return;
    }
    if (table->entries) {
        for (int i = 0; i < TABLE_SIZE; i++) {
            cache_entry *entry = table->entries[i];
            while (entry != NULL) {
                cache_entry *temp = entry;
                entry = entry->next;
                free(temp->key);
                free(temp->value);
                free(temp);
            }
        }
    }
    int ret;
    if (table->thread) {
        ret = pthread_cancel(table->thread);
        if (ret != 0) {
            printf("Failed to cancel thread");
        }
        table->thread = NULL;
    }
    if (table->rwlock) {
        ret = pthread_rwlock_destroy(table->rwlock);
        if (ret != 0) {
            printf("Failed to destroy rwlock");
        }
        table->rwlock = NULL;
    }
    free(table);
}

/* !SECTION implement */
