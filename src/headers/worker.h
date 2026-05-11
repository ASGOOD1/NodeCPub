#ifndef WORKER_H
#define WORKER_H

#include "queue.h"

void worker_start(int num_threads);
void worker_stop(void);
int worker_cancel_job(const char *username, const char *filename);
int get_active_jobs(void);

extern queue_t g_queue;
extern int     g_nthreads;
#endif
