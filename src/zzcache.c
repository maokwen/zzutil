#include "zzutil/zzcache.h"
#include "zzutil/errmsg.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <wtypes.h>
#include <winbase.h>
#include <processthreadsapi.h>
#include <synchapi.h>
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
#ifdef _WIN32
    HANDLE thread;
    DWORD dwThreadId;
    SRWLOCK rwlock;
#elif _UNIX
    pthread_t *thread;
    pthread_rwlock_t *rwlock;
#endif
    int on_exit;
};

/* routine to clean up expired entry */
#ifdef _WIN32
static DWORD WINAPI expire_check_routine(LPVOID lpParam);
static DWORD WINAPI thread_cleanup_routine(LPVOID lpParam);
#elif _UNIX
static void *thread_cleanup_routine(void *arg);
static void *expire_check_routine(void *arg);
#endif

/* calcu hash */
static unsigned int hash(char *key);
/* routine to cleanup thread before kill a thread */
/* stop thread and free memory */
static void on_destory(zzcache *table);
/* sleep */
static void dosleep(int ms);
/* write lock */
static void wrlock(zzcache *table, bool lock);
/* read lock */
static void rdlock(zzcache *table, bool lock);

zzcache *zzcache_create_table() {
    zzcache *table = malloc(sizeof(zzcache));
    table->on_exit = 0;
    for (int i = 0; i < TABLE_SIZE; i++) {
        table->entries[i] = NULL;
    }

    // create a new thread to clean up expired entries
#ifdef _WIN32
    table->thread = CreateThread(
        NULL,
        0,
        expire_check_routine,
        table,
        0,
        &table->dwThreadId);
    if (table->thread == NULL) {
        printf("Failed to create thread");
        on_destory(table);
        return NULL;
    }
#endif
#ifdef _UNIX
    int ret;
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
#endif

    // init rw lock
#ifdef _WIN32
    InitializeSRWLock(&table->rwlock);
#endif
#ifdef _UNIX
    table->rwlock = malloc(sizeof(pthread_rwlock_t));
    ret = pthread_rwlock_init(table->rwlock, NULL);
    if (ret) {
        printf("Failed to init rwlock");
        on_destory(table);
        return NULL;
    }
#endif

    return table;
}

void zzcache_free_table(zzcache *table) {
    table->on_exit = 1;
    // create a new thread to join the table thread
#ifdef _WIN32
    HANDLE thread = CreateThread(
        NULL,
        0,
        thread_cleanup_routine,
        table,
        0,
        NULL);
    if (thread == NULL) {
        printf("Failed to create cleanup thread");
        return;
    }
#endif
#ifdef _UNIX
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
#endif
}

void zzcache_insert(zzcache *table, char *key, u8 *value) {
    unsigned int slot = hash(key);

    wrlock(table, true);
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
    wrlock(table, false);
}

u8 *zzcache_find(zzcache *table, char *key) {
    unsigned int slot = hash(key);
    char *value = NULL;

    rdlock(table, true);
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
    rdlock(table, false);

    return value;
}

void zzcache_remove(zzcache *table, char *key) {
    unsigned int slot = hash(key);

    wrlock(table, true);
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
    wrlock(table, false);
}

/* SECTION implement */

unsigned int hash(char *key) {
    unsigned int hash = 0;
    while (*key) {
        hash = (hash << 5) + *key++;
    }
    return hash % TABLE_SIZE;
}

#ifdef _WIN32
DWORD WINAPI expire_check_routine(LPVOID lpParam) {
    zzcache *table = (zzcache *)lpParam;
#elif _UNIX
void *expire_check_routine(void *arg) {
    zzcache *table = (zzcache *)arg;
#endif

    printf("Expire check thread started.\n");

    while (1) {
        if (table->on_exit) {
            break;
        }

        wrlock(table, true);
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
        wrlock(table, false);

        dosleep(CLEANUP_INTERVAL_MILISEC);
    }
    return ZZECODE_OK;
}

#ifdef _WIN32
DWORD WINAPI thread_cleanup_routine(LPVOID lpParam) {
    zzcache *table = (zzcache *)lpParam;
    int ret = WaitForSingleObject(table->thread, INFINITE);
    if (ret == WAIT_FAILED) {
        printf("Failed to wait for thread");
    }
    CloseHandle(table->thread);
    on_destory(table);
    return 0;
}
#elif _UNIX
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
#endif

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
#ifdef _WIN32
// TODO -
#endif
#ifdef _UNIX
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
#endif
    free(table);
}

void wrlock(zzcache *table, bool lock) {
#ifdef _WIN32
    if (lock) {
        AcquireSRWLockExclusive(&table->rwlock);
    } else {
        ReleaseSRWLockExclusive(&table->rwlock);
    }
#endif
#ifdef _UNIX
    if (lock) {
        pthread_rwlock_wrlock(table->rwlock);
    } else {
        pthread_rwlock_unlock(table->rwlock);
    }
#endif
}

void rdlock(zzcache *table, bool lock) {
#ifdef _WIN32
    if (lock) {
        AcquireSRWLockShared(&table->rwlock);
    } else {
        ReleaseSRWLockShared(&table->rwlock);
    }
#endif
#ifdef _UNIX
    if (lock) {
        pthread_rwlock_rdlock(table->rwlock);
    } else {
        pthread_rwlock_unlock(table->rwlock);
    }
#endif
}

void dosleep(int ms) {
#ifdef _WIN32
    Sleep(ms);
#endif
#ifdef _UNIX
    usleep(ms * 1000);
#endif
}

/* !SECTION implement */
