/* cp_worker.c - Worker thread pentru copierea fisierelor
    Acest fisier creaza un pool de thread-uri care doar creaza copii ale fisiserelor si le muta in directurul de procesare
    Acest lucru permite evitarea problemelor de concurenta

*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/stat.h>

#include "headers/queue.h"
#include "headers/cp_worker.h"

#ifndef STR_LENGTH
#define STR_LENGTH 256
#endif
#ifndef HEX_LENGTH
#define HEX_LENGTH 64
#endif
#ifndef DIR_PERM
#define DIR_PERM 0777
#endif
#ifndef UPLOAD_PERM
#define UPLOAD_PERM 0666
#endif
#ifndef BUFFER_SIZE_WORKER
#define BUFFER_SIZE_WORKER 4096
#endif

#ifndef QUEUE_TIMEOUT_MS
#define QUEUE_TIMEOUT_MS 1000
#endif

#define DIR_FCE         "./fce"
#define DIR_PROCESSING  "./fce/processing"


// Variabile globale pentru gestionarea pool-ului de thread-uri si a cozii de joburi(de copiere)
queue_t      g_cp_queue;
static pthread_t    *g_cp_threads  = NULL;
static int           g_cp_nthreads = 0;
static volatile int  g_cp_running  = 0;

// Functia care se ocupa cu copierea si redenumirea fisierelor
static int cp_copy_file(const char *src, const char *dst)
{
    int fd_src = open(src, O_RDONLY);
    if (fd_src < 0) {
        perror("[cp_worker] open src");
        return -1;
    }

    struct stat st;
    if (fstat(fd_src, &st) < 0) {
        perror("[cp_worker] fstat");
        close(fd_src);
        return -1;
    }

    int fd_dst = open(dst, O_WRONLY | O_CREAT | O_TRUNC, st.st_mode & UPLOAD_PERM);
    if (fd_dst < 0) {
        perror("[cp_worker] open dst");
        close(fd_src);
        return -1;
    }

    char buf[BUFFER_SIZE_WORKER];
    ssize_t nr;
    while ((nr = read(fd_src, buf, sizeof(buf))) > 0) {
        char   *wptr = buf;
        ssize_t left = nr;
        while (left > 0) {
            ssize_t nw = write(fd_dst, wptr, left);
            if (nw < 0) {
                if (errno == EINTR) continue;
                perror("[cp_worker] write");
                close(fd_src);
                close(fd_dst);
                unlink(dst);
                return -1;
            }
            wptr += nw;
            left -= nw;
        }
    }

    close(fd_src);
    close(fd_dst);

    if (nr < 0) {
        perror("[cp_worker] read");
        unlink(dst);
        return -1;
    }
    unlink(src);

    return 0;
}
// Functia thread-ului care se ocupa cu preluarea joburilor din coada si procesarea lor
static void *cp_worker_thread(void *arg)
{
    (void)arg;
    // Cat timp workerul este activ, preia joburi din coada si le proceseaza
    while (g_cp_running) {
        cp_job_t *job = (cp_job_t *)queue_pop(&g_cp_queue, QUEUE_TIMEOUT_MS);
        if (!job) continue;

        char src[STR_LENGTH * 2];
        char tmp[STR_LENGTH * 2];
        char dst[STR_LENGTH * 2];
        char dst_dir[STR_LENGTH * 2];

        (void)snprintf(src,     sizeof(src),     "%s/%s/%s",
                 DIR_FCE, job->username, job->filename);
        (void)snprintf(tmp,     sizeof(tmp),     "%s/%s/%s.tmp",
                 DIR_FCE, job->username, job->filename);
        (void)snprintf(dst_dir, sizeof(dst_dir), "%s/%s",
                 DIR_PROCESSING, job->username);
        (void)snprintf(dst,     sizeof(dst),     "%s/%s/%s",
                 DIR_PROCESSING, job->username, job->filename);

        // Cream directorul de destinatie daca nu exista
        mkdir(dst_dir, DIR_PERM);

        // Copiem fisierul in locatia temporara
        if (cp_copy_file(src, tmp) != 0) {
            (void)fprintf(stderr, "[cp_worker] copy failed: %s\n", src);
            free(job);
            continue;
        }
        // Redenumim fisierul temporar in destinatia finala (Atomic)
        if (rename(tmp, dst) != 0) {
            perror("[cp_worker] rename");
            unlink(tmp);
            free(job);
            continue;
        }

        // Eliberam memoria alocata pentru job, am terminat procesarea lui
        free(job);
    }

    return NULL;
}
// Functia pentru a porni pool-ul de thread-uri si a initializa coada de joburi
void cp_worker_start(int num_threads)
{
    g_cp_running  = 1;
    g_cp_nthreads = num_threads;

    queue_init(&g_cp_queue);

    g_cp_threads = malloc(sizeof(pthread_t) * num_threads);
    for (int i = 0; i < num_threads; i++)
        pthread_create(&g_cp_threads[i], NULL, cp_worker_thread, NULL);

    (void)fprintf(stderr, "[cp_worker] %d threads started\n", num_threads);
}

// Functia pentru a opri pool-ul de thread-uri si a elibera resursele
void cp_worker_stop(void)
{
    g_cp_running = 0;

    for (int i = 0; i < g_cp_nthreads; i++)
        pthread_join(g_cp_threads[i], NULL);

    free(g_cp_threads);
    g_cp_threads  = NULL;
    g_cp_nthreads = 0;

    queue_destroy(&g_cp_queue);

    (void)fprintf(stderr, "[cp_worker] stopped\n");
}
// Aceasta functie permite adaugaurea unui job de copiere in coda
int cp_enqueue_job(const char *username, const char *filename)
{
    cp_job_t *job = malloc(sizeof(cp_job_t));
    if (!job) return -1;

    strncpy(job->username, username, sizeof(job->username) - 1);
    job->username[sizeof(job->username) - 1] = '\0';
    strncpy(job->filename, filename, sizeof(job->filename) - 1);
    job->filename[sizeof(job->filename) - 1] = '\0';

    // Escape de caractere pentru a preveni probleme de securitate sau de formatare in numele de fisiere

    if (queue_push(&g_cp_queue, job) < 0) { // Facem push job-ului in coada de copiere
        free(job);
        return -1;
    }

    (void)fprintf(stderr, "[cp_worker] enqueued: %s/%s\n", username, filename); // (logging pt debug)
    return 0;
}


