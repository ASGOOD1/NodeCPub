/*
    queue.c - Implementarea unei cozi thread-safe folosind mutex si conditii pentru sincronizare intre thread-uri.
    Aceasta coada este utilizata pentru a gestiona joburile de copiere in pool-ul de thread-uri din cp_worker.c, 
    permitand adaugarea si preluarea joburilor intr-un mod sigur din punct de vedere al concurentei, 
    asigurandu-se ca thread-urile pot adauga si prelua joburi fara a se bloca sau a cauza race conditions.


*/


#include <stdlib.h>
#include <errno.h>
#include <time.h> // Pentru struct timespec
#include "headers/queue.h"


// Initializarea queue-ului
int queue_init(queue_t *q) {
    q->head  = NULL;
    q->tail  = NULL;
    q->count = 0;
    if (pthread_mutex_init(&q->lock, NULL) != 0)       return -1;
    if (pthread_cond_init(&q->not_empty, NULL) != 0)   return -1;
    return 0;
}


// Distrugerea cozii si eliberarea memoriei.
void queue_destroy(queue_t *q) {
    queue_node_t *cur = q->head;
    while (cur) {
        queue_node_t *next = cur->next;
        free(cur);
        cur = next;
    }
    pthread_mutex_destroy(&q->lock);
    pthread_cond_destroy(&q->not_empty);
}

// Adaugarea unui nou element in coada
int queue_push(queue_t *q, void *data) {
    queue_node_t *node = malloc(sizeof(queue_node_t));
    if (!node) return -1;
    node->data = data;
    node->next = NULL;

    pthread_mutex_lock(&q->lock);
    if (q->tail)
        q->tail->next = node;   
    else
        q->head = node;        
    q->tail = node;
    q->count++;
    pthread_cond_signal(&q->not_empty);   
    pthread_mutex_unlock(&q->lock);
    return 0;
}

// Scoaterea / preluarea unui element din coada, cu timeout
void *queue_pop(queue_t *q, int timeout_ms) {
    pthread_mutex_lock(&q->lock);

    while (q->count == 0) {
        if (timeout_ms < 0) {
            pthread_cond_wait(&q->not_empty, &q->lock);
        } else {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec  += timeout_ms / TIMEOUT_SEC;
            ts.tv_nsec += (timeout_ms % TIMEOUT_SEC) * TIMEOUT_NSEC;
            if (ts.tv_nsec >= DEFAULT_TIMEOUT_NSEC) {
                ts.tv_sec++;
                ts.tv_nsec -= DEFAULT_TIMEOUT_NSEC;
            }
            int rc = pthread_cond_timedwait(&q->not_empty, &q->lock, &ts);
            if (rc == ETIMEDOUT) {
                pthread_mutex_unlock(&q->lock);
                return NULL;
            }
        }
    }

    queue_node_t *node = q->head;
    q->head = node->next;
    if (!q->head) q->tail = NULL;
    q->count--;

    pthread_mutex_unlock(&q->lock);

    void *data = node->data;
    free(node);
    return data;
}

// O varianta non-blocanta a functiei de pop, care returneaza imediat daca coada este goala
void *queue_try_pop(queue_t *q) {
    pthread_mutex_lock(&q->lock);
    if (q->count == 0) {
        pthread_mutex_unlock(&q->lock);
        return NULL;
    }
    queue_node_t *node = q->head;
    q->head = node->next;
    if (!q->head) q->tail = NULL;
    q->count--;
    pthread_mutex_unlock(&q->lock);

    void *data = node->data;
    free(node);
    return data;
}

// Functie pentru a obtine numarul de elemente din coada intr-un mod thread-safe
int queue_count(queue_t *q) {
    pthread_mutex_lock(&q->lock);
    int c = q->count;
    pthread_mutex_unlock(&q->lock);
    return c;
}
