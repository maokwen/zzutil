#include "zzutil/zzcache.h"
#include "zzutil/errmsg.h"

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
#define TICKS_PER_MILI_SEC (CLOCKS_PER_SEC / 1000)
#define TICKS_TO_EXPIRE TICKS_PER_MILI_SEC * 200 // 200 milliseconds
#define CLEANUP_INTERVAL_MILISEC 50              // 50 milliseconds

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
unsigned int hash(char *key);

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

void zzcache_insert(zzcache *table, char *key, u8 *value) {
    unsigned int slot = hash(key);

    pthread_rwlock_wrlock(table->rwlock);
    {
        clock_t expire = clock() + TICKS_TO_EXPIRE;
        cache_entry *curr = table->entries[slot];
        int updated = 0;
        while (curr != NULL) {
            // if found the same key, update the value
            if (strcmp(curr->key, key) == 0) {
                free(curr->value);
                curr->value = strdup(value);
                curr->expire = expire;
                updated = 1;
                break;
            }
        }
        // if not found. insert to the head of the list
        if (!updated) {
            cache_entry *entry = malloc(sizeof(cache_entry));
            entry->key = strdup(key);
            entry->value = strdup(value);
            entry->expire = expire;
            entry->next = table->entries[slot];
            table->entries[slot] = entry;
        }
    }
    pthread_rwlock_wrlock(table->rwlock);
}

u8 *zzcache_find(zzcache *table, char *key) {
    unsigned int slot = hash(key);
    char *value = NULL;

    pthread_rwlock_rdlock(table->rwlock);
    {
        cache_entry *entry = table->entries[slot];
        while (entry != NULL) {
            if (strcmp(entry->key, key) == 0) {
                value = strdup(entry->value);
                break;
            }
            entry = entry->next;
        }
    }
    pthread_rwlock_unlock(table->rwlock);

    return value;
}

void zzcache_remove(zzcache *table, char *key) {
    unsigned int slot = hash(key);

    pthread_rwlock_wrlock(table->rwlock);
    {
        cache_entry *entry = table->entries[slot];
        cache_entry *prev = NULL;
        while (entry != NULL) {
            if (strcmp(entry->key, key) == 0) {
                if (prev == NULL) {
                    table->entries[slot] = entry->next;
                } else {
                    prev->next = entry->next;
                }
                free(entry->key);
                free(entry->value);
                free(entry);
                break;
            }
            prev = entry;
            entry = entry->next;
        }
    }
    pthread_rwlock_unlock(table->rwlock);
}

/* SECTION implement */

unsigned int hash(char *key) {
    unsigned int hash = 0;
    while (*key) {
        hash = (hash << 5) + *key++;
    }
    return hash % TABLE_SIZE;
}

void *expire_check_routine(void *arg) {
    zzcache *table = (zzcache *)arg;

    printf("Expire check thread started.\n");

    while (1) {
        if (table->on_exit) {
            break;
        }

        pthread_rwlock_wrlock(table->rwlock);
        {
            clock_t now = clock();
            for (int i = 0; i < TABLE_SIZE; i++) {
                cache_entry *entry = table->entries[i];
                cache_entry *prev = NULL;
                while (entry != NULL) {
                    // if is expired, remove it
                    if (entry->expire < now) {
                        if (prev == NULL) {
                            table->entries[i] = entry->next;
                        } else {
                            prev->next = entry->next;
                        }
                        free(entry->key);
                        free(entry->value);
                        free(entry);
                    } else {
                        prev = entry;
                    }
                    prev = entry;
                    entry = entry->next;
                }
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
