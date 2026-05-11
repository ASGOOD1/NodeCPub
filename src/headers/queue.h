#ifndef QUEUE_H
#define QUEUE_H

#include <pthread.h>
#include <stddef.h>

#define TIMEOUT_SEC 1000
#define TIMEOUT_NSEC 1000000L
#define DEFAULT_TIMEOUT_NSEC 1000000000L

typedef struct queue_node {
    void             *data;
    struct queue_node *next;
} queue_node_t;

typedef struct {
    queue_node_t    *head;
    queue_node_t    *tail;
    int              count;
    pthread_mutex_t  lock;
    pthread_cond_t   not_empty;
} queue_t;

int  queue_init(queue_t *q);
void queue_destroy(queue_t *q);

int  queue_push(queue_t *q, void *data);

void *queue_pop(queue_t *q, int timeout_ms);

void *queue_try_pop(queue_t *q);

int  queue_count(queue_t *q);

#endif
