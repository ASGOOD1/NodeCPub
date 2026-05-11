/*
    worker.c - Implementarea worker-ului de procesare
    Acest modul se ocupa de procesarea fisierelor(scanarea acestora)

    Erori tratate:
    * Erori de citire / scriere
    * Erori la hashing
    * Erori de procesare
*/




#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <dirent.h>
#include <time.h>
#include <signal.h> // Activez sigpipe (daca inchid pipe-ul din procesul parinte sa iasa automat procesul copil)


#include "headers/queue.h"
#include "headers/worker.h"
#include "headers/watcher.h"
#include "headers/server.h"
#include "headers/pe_scanner.h"
#include "headers/sha256.h"

// Constante redefinite in caz ca nu exista deja
#ifndef STR_LENGTH
#define STR_LENGTH 256
#endif
#ifndef HEX_LENGTH
#define HEX_LENGTH 64
#endif

#ifndef UPLOAD_PERM
#define UPLOAD_PERM 0666
#endif

#ifndef DIR_PERM
#define DIR_PERM 0777
#endif

#ifndef BUFFER_SIZE_WORKER
#define BUFFER_SIZE_WORKER 4096
#endif

/* ── Directoare ── */
#define DIR_PROCESSING  "./fce/processing"
#define DIR_OUTGOING    "./fce/outgoing"

#define HUNDREDMS 100
#define MILMS 1000000
#ifndef BUF
#define BUF 4096
#endif

// Structura fiecarui job
typedef struct {
    char         username[HEX_LENGTH];
    char         filename[STR_LENGTH];
    char         signature[HEX_LENGTH+2];
    volatile int cancelled;
    pid_t        pids[4];
} job_t;


// Coada globala de procesare
queue_t      g_queue;
static pthread_t   *g_threads   = NULL;
int          g_nthreads  = 0;
static volatile int g_running   = 0;
static pthread_t    g_watcher_tid;


// Numarul maxim de workeri(thread-uri)
#define MAX_WORKERS 64

// Alte variabilile
static job_t          *g_active_jobs[MAX_WORKERS];
static pthread_mutex_t g_active_lock = PTHREAD_MUTEX_INITIALIZER;


// Functia care se ocupa cu procesarea efectiva a fisierelor
static int process_file(const char *src, const char *dst, job_t *job)
{
    // Pipe-uri pentru a comunica cu procesele copil
    int pipes[4][2];
    pid_t pids[4];

    char signature[HEX_LENGTH+2];
    if(compute_signature(src, signature) == EXIT_SUCCESS) {
        printf("Computed signature for %s/%s: %s\n", job->username, job->filename, signature);
        (void)fflush(stdout);
    }

    file_record_t record = find_file_by_minisig(signature);
    if(record.id != 0){
        unlink(src);
        int client = find_client_socket_by_username(job->username);
        if(client > 0) {
            int fd = open(record.result_path, O_RDONLY);
            if (fd < 0) {
                (void)safe_write(client, "\033[31mFile not found or couldn't be opened\033[0m\n", strlen("\033[31mFile not found or couldn't be opened\033[0m\n"));
                return -1;
            }

            struct stat st;
            if (fstat(fd, &st) != 0) {
                (void)safe_write(client, "\033[31mFile not found or couldn't be opened\033[0m\n", strlen("\033[31mFile not found or couldn't be opened\033[0m\n"));
                close(fd);
                return -1;
            }

            char header[STR_LENGTH];
            (void)snprintf(header, sizeof(header), "SIZE %lld\n", (long long)st.st_size);
            (void)safe_write(client, header, strlen(header));

            char buffer[BUF];
            ssize_t n;
            while ((n = read(fd, buffer, sizeof(buffer))) > 0) {
                if (write_all(client, buffer, n) < 0) {
                    close(fd);
                    return -1;
                }
            }

            close(fd);
            return -3;
        }


    }
    else {
        update_file_minisig(job->username, job->filename, signature);
        // Se creeaza cele 4 procese copil pentru a face cele 4 taskuri diferite}
        for (int i = 0; i < 4; i++) {
            if (pipe(pipes[i]) < 0) {
                perror("pipe");
                return -1;
            }
        }
        // Procesul care face hashing-ul fisierului (sha256 signature)
        if ((pids[0] = fork()) == 0) {
            (void)signal(SIGPIPE, SIG_DFL);
            close(pipes[0][0]);

            unsigned char hash[HEX_LENGTH/2];
            char hex[HEX_LENGTH+1];
            // Se face hashing-ul efectiv al fisierului
            if (sha256_file(src, hash) < 0) {
                ssize_t wlen = write(pipes[0][1], "ERR_SHA256", strlen("ERR_SHA256"));
                (void)wlen;
                exit(EXIT_FAILURE);// NOLINT safe here, child process ends
            }
            // Se transforma in hex
            for (int i = 0; i < HEX_LENGTH/2; i++)
                (void)sprintf(hex + i*2, "%02x", hash[i]);
            hex[HEX_LENGTH] = '\0';
            // Se scrie catre procesul parinte rezultatul
            ssize_t wlen = write(pipes[0][1], hex, strlen(hex));
            (void)wlen;
            exit(EXIT_SUCCESS); // NOLINT safe here, child process ends
        }
        // Procesul care se ocupa cu scanarea de tip text pattern match / base64 decode & pattern match
        if ((pids[1] = fork()) == 0) {
            (void)signal(SIGPIPE, SIG_DFL);
            close(pipes[1][0]);
            int r = scanner_scan_file_raw(g_scanner, src, pipes[1][1]); // Se scaneaza fisierul src, si se scrie rezultatul la procesul parinte
            if(r == SCAN_NO_MATCH) {
                ssize_t wlen = write(pipes[1][1], "PATTERN_CLEAN", strlen("PATTERN_CLEAN")); // Daca nu se gaseste niciun match sa scrie pattern clean la parinte
                (void)wlen;
            } 
            exit(EXIT_SUCCESS);// NOLINT safe here, child process ends
        }
        if ((pids[3] = fork()) == 0) {
            (void)signal(SIGPIPE, SIG_DFL);
            close(pipes[3][0]);
            int r = scanner_scan_file_decoded(g_scanner, src, pipes[3][1]); // Se scaneaza fisierul src, si se scrie rezultatul la procesul parinte
            if(r == SCAN_NO_MATCH) {
                ssize_t wlen = write(pipes[3][1], "PATTERN_CLEAN", strlen("PATTERN_CLEAN")); // Daca nu se gaseste niciun match sa scrie pattern clean la parinte
                (void)wlen;
            } 
            exit(EXIT_SUCCESS);// NOLINT safe here, child process ends
        }

        // Procesul care se ocupa cu PE Scanning (PE Heuristic Match)
        if ((pids[2] = fork()) == 0) {
            (void)signal(SIGPIPE, SIG_DFL);
            close(pipes[2][0]);

            ScanResult r = pe_scanner_scan(src); // Se creaza un scanner pe nou
            if (r.verdict == SCAN_MODERATE_RISK || r.verdict == SCAN_HIGH_RISK) // Daca verdictul e mai mare de low 
                pe_scanner_print(src, pipes[2][1], &r); // Scrie toate datele din r la parinte
            else{
                
                ssize_t wlen = write(pipes[2][1], "PE_LOW_RISK", strlen("PE_LOW_RISK")); // Daca nu se scrie low risk
                (void)wlen;
            }
            exit(EXIT_SUCCESS);// NOLINT safe here, child process ends
        }
        if (job) { // Asignam id-urile proceselor la job
            job->pids[0] = pids[0];
            job->pids[1] = pids[1];
            job->pids[2] = pids[2];
            job->pids[3] = pids[3];
        }

        // Variabile pentru rezultate
        char sha256_hex[STR_LENGTH] = {0};
        char pattern_res[STR_LENGTH] = {0};
        char pe_res[STR_LENGTH] = {0};
        char pattern_res_dec[STR_LENGTH] = {0};
        char STRING_BUFFER[BUFFER_SIZE_WORKER] = {0};

        close(pipes[0][1]); // Se inchid capetele de scriere (nu ne intereseaza in parinte)
        close(pipes[1][1]);
        close(pipes[2][1]);
        close(pipes[3][1]);

        waitpid(pids[0], NULL, 0);
        waitpid(pids[1], NULL, 0);
        waitpid(pids[2], NULL, 0);
        waitpid(pids[3], NULL, 0);
        ssize_t wr = 0;
        wr = read(pipes[0][0], sha256_hex, sizeof(sha256_hex)-1); // Se citesc valorile cu care a raspuns copilul
        (void)wr;    // Dam discard numarului de bytes citit (nu ne intereseaza daca a fost sau nu eroare)
        wr = read(pipes[1][0], pattern_res, sizeof(pattern_res)-1);
        (void)wr;
        wr = read(pipes[2][0], pe_res, sizeof(pe_res)-1);
        (void)wr;
        wr = read(pipes[3][0], pattern_res_dec, sizeof(pattern_res_dec)-1);
        (void)wr;

        virus_t v = find_virus_by_hash(sha256_hex); // Se verifica daca hash-ul exista deja

        int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, UPLOAD_PERM);
        if (out < 0) {
            perror(dst);
            return -1;
        }
        
        if (v.found) { // Daca exista deja scriem unde l-am gasit
            (void)sprintf(STRING_BUFFER, "Possible malware detected: %s (signature: %s, hash: %s)\n", v.knownfile, v.signature, sha256_hex);
            ssize_t wr = write(out, STRING_BUFFER, strlen(STRING_BUFFER));

            if(wr < 0) {
                perror("[worker] write");
            }
            goto finish; // Mergem direct la final(nu mai are rost sa facem matching-ul)
        } 
        if(!strstr(pattern_res, "PATTERN_CLEAN")) { // Daca nu e pattern_clean
            ssize_t wlen = write(out, pattern_res, strlen(pattern_res)); // Scriem in fisier primul buffer citit
            wr = read(pipes[1][0], pattern_res, sizeof(pattern_res)-1);  // continuam sa citim
            while(wr > 0) { // scriem cat timp inca mai avem de citit
                wlen = write(out, pattern_res, wr); 
                wr = read(pipes[1][0], pattern_res, sizeof(pattern_res)-1);
            }
            insert_virus(job->filename, "Pattern Match", sha256_hex); // Inseram virusul nou in db
            (void)wlen;
            goto finish; // Mergem la final (cleanup)
        }
        if(!strstr(pattern_res_dec, "PATTERN_CLEAN")) { // Daca nu e pattern_clean
            ssize_t wlen = write(out, pattern_res_dec, strlen(pattern_res_dec)); // Scriem in fisier primul buffer citit
            wr = read(pipes[3][0], pattern_res_dec, sizeof(pattern_res_dec)-1);  // continuam sa citim
            while(wr > 0) { // scriem cat timp inca mai avem de citit
                wlen = write(out, pattern_res_dec, wr); 
                wr = read(pipes[3][0], pattern_res_dec, sizeof(pattern_res_dec)-1);
            }
            insert_virus(job->filename, "Pattern Match Base64", sha256_hex); // Inseram virusul nou in db
            (void)wlen;
            goto finish; // Mergem la final (cleanup)
        }
        if(!strstr(pe_res, "PE_LOW_RISK")) { // Daca fisierul nu e low risk
            ssize_t wlen = write(out, pe_res, strlen(pe_res)); // La fel ca la Pattern Match
            wr = read(pipes[2][0], pe_res, sizeof(pe_res)-1);
            while(wr > 0) {
                wlen = write(out, pe_res, wr);
                wr = read(pipes[2][0], pe_res, sizeof(pe_res)-1);
            }
            (void)wlen;
            insert_virus(job->filename, "PE Heuristic Match", sha256_hex);
            goto finish;
        }
        // Daca se ajunge aici inseamna ca nu am gasit niciun virus
        (void)sprintf(STRING_BUFFER, "No known threats found. SHA256: %s\n", sha256_hex); 
        wr = write(out, STRING_BUFFER, strlen(STRING_BUFFER)); // Scriem ca n-am gasit niciun pattern de niciun fel
        if(wr < 0) {
            perror("[worker] write");
        }
        finish: 
        
        close(pipes[0][0]); // Facem cleanup
        close(pipes[1][0]);
        close(pipes[2][0]);
        close(pipes[3][0]);
        close(out);
        if(job && job->cancelled) {
            return -2; // indicate cancellation
        }
    }
    return 0;
}

// Worker thread-ul
static void *worker_thread(void *arg)
{
    (void)arg; // Nu ne intereseaza argumentul (e NULL)

    int slot = -1;
    pthread_mutex_lock(&g_active_lock); // Blocam arrayul si cautam slot-ul
    for (int i = 0; i < MAX_WORKERS; i++) {
        if (!g_active_jobs[i]) { slot = i; break; }
    }
    pthread_mutex_unlock(&g_active_lock);

    while (g_running) {
        job_t *job = queue_pop(&g_queue, TIMEOUT_SEC); // Scoatem un element din coada
        if (!job) continue;

        if (slot >= 0) { // Daca am gasit slot liber, il setam pe slot-ul respectiv (este job-ul activ)
            pthread_mutex_lock(&g_active_lock);
            g_active_jobs[slot] = job;
            pthread_mutex_unlock(&g_active_lock);
        }

        char src[STR_LENGTH * 2];
        char dst[STR_LENGTH * 2];
        char dst_dir[STR_LENGTH * 2];

        (void)snprintf(src, sizeof(src), "%s/%s/%s",
                 DIR_PROCESSING, job->username, job->filename);
        (void)snprintf(dst_dir, sizeof(dst_dir), "%s/%s",
                 DIR_OUTGOING, job->username);
        (void)snprintf(dst, sizeof(dst), "%s/%s/result_%s.txt",
                 DIR_OUTGOING, job->username, job->filename);

        mkdir(dst_dir, DIR_PERM); // Cream directorul destinatie (daca nu e)


        int rc = process_file(src, dst, job); // Procesam efectiv fisierul

        if (slot >= 0) { // Eliberam slot-ul
            pthread_mutex_lock(&g_active_lock);
            g_active_jobs[slot] = NULL;
            pthread_mutex_unlock(&g_active_lock);
        }

        if (rc == -2) { // Daca se returneaza -2 inseamna ca job-ul a fost anulat
            int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, UPLOAD_PERM);
            if (out >= 0) { // Scriem in fisier ca a fost anulat 
                ssize_t wr = write(out, "Job cancelled by an administrator!\n", strlen("Job cancelled by an administrator!\n")); 
                if(wr < 0) {
                    perror("[worker] write");
                }
                close(out);
            }
            unlink(src); // setrgem fisier-ul sursa(din processing)
        } else if (rc == 0) { // Daca rezultatul e 0
            char log_file_end[STR_LENGTH*2];
            (void)snprintf(log_file_end, sizeof(log_file_end), "\033[32mFile %s has been processed.\033[0m\n", job->filename);
            add_logs(job->username, log_file_end); // adaugam log-ul
            unlink(src); // stergem fiiserul sursa
            int client_socket = find_client_socket_by_username(job->username); // Cautam fd-ul clientului
            
            ssize_t wr = write(client_socket, log_file_end, strlen(log_file_end)); // Ii scriem ca am procesat(inotify nu e necesar)
            if(wr < 0) {
                perror("[worker] write");
            }
            struct timespec ts;
            ts.tv_sec = 0;
            ts.tv_nsec = HUNDREDMS * MILMS; // 100 ms = 100.000.000 ns

            nanosleep(&ts, NULL);

            if (download_file_result(client_socket, job->filename, job->username) != EXIT_FAILURE) {
                char log_string[STR_LENGTH*2];
                (void)snprintf(log_string, sizeof(log_string), "downloaded result file %255s", job->filename);
                add_logs(job->username, log_string);
            }

        }
        else if (rc == -3) {
            unlink(src);
        } 
        else {
            (void)fprintf(stderr, "[worker] error processing: %s\n", src);
        }

        free(job);
    }

    return NULL;
}
// Functia care se ocupa cu activarea efectiva a procesarii 
static void on_new_file(const char *path, const char *filename, int deleted)
{
    if (deleted) return;  

    const char *username = strrchr(path, '/');
    if (!username) return; // Daca nu gasim numele clar nu are job activ
    username++;  // sarim peste /

    pthread_mutex_lock(&g_active_lock);
    for (int i = 0; i < MAX_WORKERS; i++) {
        if (g_active_jobs[i] &&
            strcmp(g_active_jobs[i]->username, username) == 0 &&
            strcmp(g_active_jobs[i]->filename, filename) == 0) // Cautam daca job-ul deja e activ
        {
            pthread_mutex_unlock(&g_active_lock); // Daca e activ il ignoram
            (void)fprintf(stderr, "[watcher] already processing: %s/%s\n", 
                    username, filename);
            return;
        }
    }
    pthread_mutex_unlock(&g_active_lock);

    pthread_mutex_lock(&g_queue.lock);
    queue_node_t *cur = g_queue.head; // Initializam un nod la capatul cozii
    while (cur) {
        job_t *j = (job_t*)cur->data;
        if (strcmp(j->username, username) == 0 &&
            strcmp(j->filename, filename) == 0) // Mergem prin coada si daca gasim acest job inca odata il ignoram
        {
            pthread_mutex_unlock(&g_queue.lock);
            (void)fprintf(stderr, "[watcher] duplicate job ignored: %s/%s\n",
                    username, filename);
            return;
        }
        cur = cur->next;
    }
    pthread_mutex_unlock(&g_queue.lock);

    job_t *job = calloc(1, sizeof(job_t)); // Realocam
    if (!job) return;



    strncpy(job->username, username, sizeof(job->username) - 1);
    job->username[sizeof(job->username) - 1] = '\0';
    strncpy(job->filename, filename, sizeof(job->filename) - 1);
    job->filename[sizeof(job->filename) - 1] = '\0';
    
    if (queue_push(&g_queue, job) < 0) { // Il adaugam in coada
        (void)fprintf(stderr, "[watcher] queue_push failed\n");
        free(job);
    }
    
}

// Thread-ul de watch (inotify / kevent)
static void *watcher_thread(void *arg)
{
    (void)arg;

    
    mkdir(DIR_PROCESSING, DIR_PERM);

    DIR *root = opendir(DIR_PROCESSING); // Deschidem directorul de procesare
    if (root) {
        struct dirent *e;
        while ((e = readdir(root)) != NULL) { // NOLINT thread safe
            if (e->d_name[0] == '.') continue;
            char subdir[STR_LENGTH * 2];
            (void)snprintf(subdir, sizeof(subdir), "%s/%s",
                     DIR_PROCESSING, e->d_name);
            struct stat st;
            if (stat(subdir, &st) == 0 && S_ISDIR(st.st_mode))
                watcher_init(subdir, on_new_file); // Adaugam efectiv subfolder-ul in watcher
        }
        closedir(root);
    }

    watcher_loop();  // Incepem loop-ul pentru detectarea noilor foldere
    return NULL;
}

// Functie specifica pentru adaugarea unui utilizator la watcher(manual adaugam ambele foldere la watch)
void worker_watch_user(const char *username)
{
    char path[STR_LENGTH * 2];
    (void)snprintf(path, sizeof(path), "%s/%s", DIR_PROCESSING, username);
    mkdir(path, DIR_PERM);
    mkdir(DIR_OUTGOING, DIR_PERM);
    char out_path[STR_LENGTH * 2];
    (void)snprintf(out_path, sizeof(out_path), "%s/%s", DIR_OUTGOING, username);
    mkdir(out_path, DIR_PERM);
    watcher_init(path, on_new_file); // Cream directooarele si adaugam directorul de procesare in watcher
}

// Functia pentru a pornii workerii
void worker_start(int num_threads)
{
    g_running  = 1;
    g_nthreads = num_threads; // Numarul de workeri

    queue_init(&g_queue); // Initializam coada
    mkdir(DIR_PROCESSING, DIR_PERM); // Cream folder-ul de procesare
    mkdir(DIR_OUTGOING,   DIR_PERM); // Cream folder-ul de rezultate

    g_threads = malloc(sizeof(pthread_t) * num_threads); // Alocam un vector in care o sa tinem thread-urile
    for (int i = 0; i < num_threads; i++)
        pthread_create(&g_threads[i], NULL, worker_thread, NULL); // Cream efectiv worker thread-urile

    pthread_create(&g_watcher_tid, NULL, watcher_thread, NULL); // Cream watcher-ul

    (void)fprintf(stderr, "[worker] %d threads started\n", num_threads);
}
// Functie pentru a oprii workerii
void worker_stop(void)
{
    g_running = 0;
    watcher_stop(); // Oprim watcher-ul

    pthread_join(g_watcher_tid, NULL); // Asteptam thread-ul de watch
    for (int i = 0; i < g_nthreads; i++)
        pthread_join(g_threads[i], NULL); // Asteptam thread-urile de worker

    free(g_threads); // Eliberam memoria
    queue_destroy(&g_queue); // Distrugem coada
    (void)fprintf(stderr, "[worker] stopped\n");
}
int get_active_jobs(void) {
    int active = 0;
    
    pthread_mutex_lock(&g_active_lock);
    for (int i = 0; i < MAX_WORKERS; i++) {
        if (g_active_jobs[i]) {
            if(g_active_jobs[i]->pids[1] != 0) active++;
        }
    }
    pthread_mutex_unlock(&g_active_lock);
    return active;
}
// Functia pentru a da cancel unui job
int worker_cancel_job(const char *username, const char *filename)
{
    int found = 0;

    pthread_mutex_lock(&g_queue.lock);
    queue_node_t *prev = NULL;
    queue_node_t *cur  = g_queue.head;
    while (cur) { // Mergem pe fiecare elemnt din coada
        job_t *job = (job_t*)cur->data;
        if (strcmp(job->username, username) == 0 &&
            strcmp(job->filename, filename) == 0)
        {
            if (prev) prev->next = cur->next;
            else      g_queue.head = cur->next;
            if (g_queue.tail == cur) g_queue.tail = prev;
            g_queue.count--;
            
            free(job);
            free(cur);
            found = 1; // Daca il gasim il eliminam din coada si eliberam resursele
            break;
        }
        prev = cur;
        cur  = cur->next;
    }
    pthread_mutex_unlock(&g_queue.lock);

    if (!found) { // Daca nu era in coada (in asteptare)
        pthread_mutex_lock(&g_active_lock);
        for (int i = 0; i < MAX_WORKERS; i++) {
            if (g_active_jobs[i] &&
                strcmp(g_active_jobs[i]->username, username) == 0 &&
                strcmp(g_active_jobs[i]->filename, filename) == 0) // Verificam daca e in lista de active
            { 
                g_active_jobs[i]->cancelled = 1;
                if (g_active_jobs[i]->pids[0] > 0) { // Daca este in lista de active il setam pe canceled si terminam procesele copil
                    kill(g_active_jobs[i]->pids[0], SIGKILL);
                    kill(g_active_jobs[i]->pids[1], SIGKILL);
                    kill(g_active_jobs[i]->pids[2], SIGKILL);
                    kill(g_active_jobs[i]->pids[3], SIGKILL);
                    waitpid(g_active_jobs[i]->pids[0], NULL, 0);
                    waitpid(g_active_jobs[i]->pids[1], NULL, 0);
                    waitpid(g_active_jobs[i]->pids[2], NULL, 0);
                    waitpid(g_active_jobs[i]->pids[3], NULL, 0);
                }
                found = 1;
                break;
            }
        }
        pthread_mutex_unlock(&g_active_lock);
    }
    if(found) { // Daca este gasit la oricare din cei 2 pasi
        int client = find_client_socket_by_username(username); // Cautam utilizatorul
        if(client >= 0) {
            char msg[STR_LENGTH];
            (void)snprintf(msg, sizeof(msg), "\033[31mYour scanning for the file %s has been cancelled by an admin.\033[0m\n", filename);
            ssize_t wr = write(client, msg, strlen(msg)); // Ii trimitem mesajul ca job-ul lui a fost anulat
            if(wr < 0) {
                perror("[worker] write");
            }
        }
    }

    return found; // Returnam daca l-am gasit sau nu
}

