#include "zzcache.h"
#include "errmsg.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#elif _UNIX
#include <pthread.h>
#include <unistd.h>
#endif

#define TABLE_SIZE 100
#define TICKS_TO_EXPIRE (CLOCKS_PER_SEC / 1000 * 200) // 200 milliseconds
#define CLEANUP_INTERVAL_MILISEC 20                   // 20 milliseconds
#define MAXIMUM_DUP_KEY_NUMBER 10

typedef struct cache_entry_t {
    char *key;
    char *value;
    clock_t expire;
    struct cache_entry_t *next;
} cache_entry;

struct zzcache {
    cache_entry *entries[TABLE_SIZE];
#ifdef _UNIX
    pthread_t *thread;
    pthread_rwlock_t *rwlock;
    int on_exit;
#endif
};

/* calcu hash */
unsigned int hash(const char *key);

/* remove a node in entry node list */
cache_entry *inplace_remove_node(zzcache *table, int slot, cache_entry *curr, cache_entry *prev);

/* find and remove node */
cache_entry *find_and_remove_node_list(zzcache *table, cache_entry *curr);

/* routine to clean up expired entry */
void *expire_check_routine(void *arg);

/* routine to cleanup thread before kill a thread */
void *thread_cleanup_routine(void *arg);

/* stop thread and free memory */
void on_destory(zzcache *table);

zzcache *zzcache_create_table() {
    zzcache *table = malloc(sizeof(zzcache));
    table->on_exit = 0;
    for (int i = 0; i < TABLE_SIZE; i++) {
        table->entries[i] = NULL;
    }

    int ret;
    // create a new thread to clean up expired entries
    table->thread = (pthread_t *)malloc(sizeof(pthread_t));
    ret = pthread_create(
        table->thread,
        NULL,
        expire_check_routine,
        table);
    if (ret) {
        printf("Failed to create thread");
        on_destory(table);
        return NULL;
    }
    // pthread_cleanup_push(thread_cleanup_routine, table);

    // init rw lock
    table->rwlock = malloc(sizeof(pthread_rwlock_t));
    ret = pthread_rwlock_init(table->rwlock, NULL);
    if (ret) {
        printf("Failed to init rwlock");
        on_destory(table);
        return NULL;
    }

    return table;
}

void zzcache_free_table(zzcache *table) {
    table->on_exit = 1;
    // create a new thread to join the table thread
    pthread_t thread;
    int ret = pthread_create(
        &thread,
        NULL,
        thread_cleanup_routine,
        table);
    if (ret) {
        printf("Failed to create cleanup thread");
        return;
    }
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

cache_entry *find_and_remove_node_list(zzcache *table, cache_entry *curr) {
    cache_entry *next = curr->next;
    int slot = hash(curr->key);
    cache_entry *entry = table->entries[slot];
    cache_entry *prev = NULL;
    while (entry != NULL) {
        if (entry == curr) {
            prev = inplace_remove_node(table, slot, entry, prev);
            return next;
        }
        prev = entry;
        entry = entry->next;
    }
}

void *expire_check_routine(void *arg) {
    zzcache *table = (zzcache *)arg;

    printf("Thread started\n");

    clock_t now;
    while (1) {
        if (table->on_exit) {
            break;
        }

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
            while (to_remove_list->next != NULL) {
                to_remove_list->next = find_and_remove_node_list(table, to_remove_list->next);
            }
        }
        pthread_rwlock_unlock(table->rwlock);

        usleep(CLEANUP_INTERVAL_MILISEC * 1000);
    }
}

void *thread_cleanup_routine(void *arg) {
    zzcache *table = (zzcache *)arg;
    int ret = pthread_join(*(table->thread), NULL);
    if (ret) {
        printf("Failed to join thread");
    }
    printf("Thread joined\n");
    on_destory(table);
    return NULL;
}

void on_destory(zzcache *table) {
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
        ret = pthread_cancel(*(table->thread));
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
