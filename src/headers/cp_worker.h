#ifndef CP_WORKER_H
#define CP_WORKER_H

#include "queue.h"
#ifndef HEX_LENGTH
#define HEX_LENGTH 64
#endif
#ifndef STR_LENGTH
#define STR_LENGTH 256
#endif
typedef struct {
    char username[HEX_LENGTH];
    char filename[STR_LENGTH];
} cp_job_t;

extern queue_t g_cp_queue;

void cp_worker_start(int num_threads);
void cp_worker_stop(void);
int  cp_enqueue_job(const char *username, const char *filename);

#endif
