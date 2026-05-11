/*
    * watcher.c - Sistem-ul de watching pentru procesarea automata
    Acest modul se ocupa cu supravegherea folder-ului de procesare(processing) pentru a detecta cand sunt adaugate fisiere noi
    Acest modul este hibrid(pe macOS inotify nu e diponibil) asa ca sunt doua implementari diferite
    Ambele implementari sunt testate si facute in asa fel incat sa foloseasca wrappere 


*/




#if defined(__linux__)
#include <sys/inotify.h> // inotify pentru linux
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include "headers/watcher.h"

#define MAX_FILES 1024
#define WATCHER_BUFF 4096
#define ALIGNMENT 8

// Variabile globale pentru watcher
static int          g_fd      = -1;
static watcher_cb   g_cb      = NULL;
static char         g_path[MAX_FILES];   
static volatile int g_running_watcher = 0;


// Initializarea watcher-ului (folosim aceasta functie pentru a seta path-ul ce va fii supravegheat)
int watcher_init(const char *path, watcher_cb cb) {
    strncpy(g_path, path, sizeof(g_path) - 1);
    g_path[sizeof(g_path) - 1] = '\0';
    g_cb   = cb;

    g_fd = inotify_init();
    if (g_fd < 0) return -1;

    if (inotify_add_watch(g_fd, path,
            IN_CLOSE_WRITE | IN_DELETE |
            IN_MOVED_TO    | IN_MOVED_FROM) < 0)
        return -1;

    return 0;
}

// Watcher loop-ul, acesta se ocupa cu citirea evenimentelor de la inotify si apelarea callback-ului pentru fiecare eveniment detectat
void watcher_loop(void) {
    char buf[WATCHER_BUFF] __attribute__((aligned(ALIGNMENT))); // Buffer pentru citirea evenimentelor, aliniat pentru a evita problemele de performanta pe unele arhitecturi(inotify necesita ca buffer-ul sa fie aliniat la dimensiunea struct inotify_event pentru a functiona corect)
    g_running_watcher = 1;

    while (g_running_watcher) {
        ssize_t n = read(g_fd, buf, sizeof(buf)); // Citim evenimentele de la inotify
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }

        char *ptr = buf;
        while (ptr < buf + n) {
            struct inotify_event *ev = (struct inotify_event *)ptr; // Cast-uim buffer-ul ca o serie de structuri inotify_event

            if (ev->len > 0 && ev->name[0] != '.' && g_cb) { // Daca avem un nume valid si un callback setat
                // Verificam daca evenimentul e de stergere sau mutare
                int deleted = (ev->mask & IN_DELETE) || 
                              (ev->mask & IN_MOVED_FROM);
                g_cb(g_path, ev->name, deleted); // Apelam callback-ul extern
            }
            // Mergem la urmatorul eveniment
            ptr += sizeof(struct inotify_event) + ev->len;
        }
    }

    close(g_fd);
}
// Functia pentru oprirea watcher-ului
void watcher_stop(void) {
    g_running_watcher = 0;
}
#else

// Varianta pentru macos
#include <sys/event.h> // kqueue pentru macOS
#include <sys/stat.h> // stat pentru a verifica daca un fisier exista sau nu
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include "headers/watcher.h"

// Variabile, constante si structuri pentru watcher
#define MAX_FILES 1024
static int          g_kq       = -1;
static int          g_dirfd    = -1;
static watcher_cb   g_cb       = NULL;
static char         g_path[MAX_FILES];  
static volatile int g_running_watcher  = 0;

#ifndef STR_LENGTH
#define STR_LENGTH 256
#endif
#ifndef HEX_LENGTH
#define HEX_LENGTH 64
#endif
typedef struct {
    int  fd;
    char name[STR_LENGTH];
} watched_file_t;

static watched_file_t g_files[MAX_FILES];
static int            g_file_count = 0;



// Functia pentru a cauta un fisier in lista de fisiere supravegheate, returneaza index-ul daca il gaseste sau -1 daca nu
static int find_file(const char *name) {
    for (int i = 0; i < g_file_count; i++)
        if (strcmp(g_files[i].name, name) == 0)
            return i;
    return -1;
}
// Functia pentru a adauga un fisier in lista de fisiere supravegheate
static void add_watch(const char *name) {
    if (find_file(name) >= 0)   return;   
    if (g_file_count >= MAX_FILES) return;

    char full[STR_LENGTH * 2];
    (void)snprintf(full, sizeof(full), "%s/%s", g_path, name);

    int fd = open(full, O_RDONLY);
    if (fd < 0) return;

    struct kevent change; // kqueue event
    // Setam event-ul pentru a monitoriza fisierul adaugat, monitorizam stergerea, mutarea, scrierea si schimbarea atributelor
    EV_SET(&change, fd, EVFILT_VNODE, 
           EV_ADD | EV_CLEAR,
           NOTE_DELETE | NOTE_RENAME | NOTE_WRITE | NOTE_ATTRIB,
           0, (void *)(intptr_t)g_file_count); 
    // Adaugam event-ul in kqueue
    kevent(g_kq, &change, 1, NULL, 0, NULL);


    // Adaugam fisierul in lista de fisiere supravegheate
    g_files[g_file_count].fd = fd;
    strncpy(g_files[g_file_count].name, name, 255);
    g_file_count++;
}
// Functie pentru a sterge un fisier din lista
static void remove_watch(int idx) {
    close(g_files[idx].fd);
    
    g_files[idx] = g_files[g_file_count - 1];
    g_file_count--;
}

// Functie pentru a scana folder-ul si a adauga fisierele existente in lista de watch (startup)
static void scan_and_watch(void) {
    DIR *dir = opendir(g_path);
    if (!dir) return;
    struct dirent *e;
    while ((e = readdir(dir)) != NULL) { // NOLINT thread safe 
        if (e->d_name[0] == '.') continue;
        if (find_file(e->d_name) < 0) {
            
            add_watch(e->d_name);
            if (g_cb) g_cb(g_path, e->d_name, 0);
        }
    }
    closedir(dir);
}

// Initializarea watcher-ului
int watcher_init(const char *path, watcher_cb cb) {
    strncpy(g_path, path, sizeof(g_path) - 1);
    g_path[sizeof(g_path) - 1] = '\0';
    g_cb   = cb;
    g_kq   = kqueue();
    if (g_kq < 0) return -1;

    
    g_dirfd = open(path, O_RDONLY);
    if (g_dirfd < 0) return -1;

    struct kevent change;

    // Setam event-ul pentru a monitoriza fisierul adaugat, monitorizam stergerea, mutarea, scrierea si schimbarea atributelor
    EV_SET(&change, g_dirfd, EVFILT_VNODE,
           EV_ADD | EV_CLEAR,
           NOTE_WRITE | NOTE_DELETE | NOTE_RENAME,
           0, NULL);
    kevent(g_kq, &change, 1, NULL, 0, NULL);

    
    DIR *dir = opendir(path);
    if (dir) {
        struct dirent *e;
        while ((e = readdir(dir)) != NULL) { // NOLINT thread safe
            if (e->d_name[0] == '.') continue;
            // Adaugam in watch list
            add_watch(e->d_name);
        }
        closedir(dir);
    }

    return 0;
}
// Loop-ul principal al watcher-ului, acesta se ocupa cu citirea evenimentelor de la kqueue si apelarea callback-ului pentru fiecare eveniment detectat
void watcher_loop(void) {
    g_running_watcher = 1;

    while (g_running_watcher) {
        struct kevent events[HEX_LENGTH/2];
        struct timespec ts = { .tv_sec = 1, .tv_nsec = 0 }; // Timeout pentru kevent, pentru a putea verifica periodic daca trebuie sa oprim watcher-ul

        int n = kevent(g_kq, NULL, 0, events, HEX_LENGTH/2, &ts); // Citim evenimentele de la kqueue

        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) continue;   

        for (int i = 0; i < n; i++) {
            struct kevent *ev = &events[i]; // Evenimentul curent

            if ((int)ev->ident == g_dirfd) { // Daca evenimentul e pe directorul monitorizat, inseamna ca s-a adaugat sau s-a sters un fisier, deci trebuie sa scanam din nou folder-ul pentru a actualiza lista de fisiere supravegheate
                if (ev->fflags & (NOTE_WRITE | NOTE_RENAME)) {
                    
                    scan_and_watch(); // Scanam folder-ul pentru a adauga fisierele noi in lista de watch

                    
                    for (int j = g_file_count - 1; j >= 0; j--) { // Verificam daca fisierele din lista de watch inca exista, daca nu, atunci le stergem din lista si apelam callback-ul pentru a notifica stergerea
                        struct stat st;
                        char full[STR_LENGTH * 2];
                        (void)snprintf(full, sizeof(full), "%s/%s",
                                 g_path, g_files[j].name);
                        if (stat(full, &st) != 0) {
                            char name_copy[STR_LENGTH];
                            strncpy(name_copy, g_files[j].name, STR_LENGTH - 1);
                            name_copy[STR_LENGTH - 1] = '\0';
                            remove_watch(j);
                            if (g_cb) g_cb(g_path, name_copy, 1);
                        }
                    }
                }
                continue;
            }

            int idx = (int)(intptr_t)ev->udata; // Index-ul fisierului in lista de watch, stocat in campul udata al evenimentului
            if (idx < 0 || idx >= g_file_count) continue; // Verificam daca index-ul e valid

            if (ev->fflags & (NOTE_DELETE | NOTE_RENAME)) { // Daca evenimentul e de stergere sau mutare, atunci stergem fisierul din lista de watch si apelam callback-ul pentru a notifica stergerea
                char name_copy[STR_LENGTH];
                strncpy(name_copy, g_files[idx].name, STR_LENGTH - 1);
                name_copy[STR_LENGTH - 1] = '\0';
                remove_watch(idx);
                if (g_cb) g_cb(g_path, name_copy, 1); 
            } else if (ev->fflags & (NOTE_WRITE | NOTE_ATTRIB)) {
                if (g_cb) g_cb(g_path, g_files[idx].name, 0); 
            }
        }
    }

    for (int i = 0; i < g_file_count; i++)
        close(g_files[i].fd);
    close(g_dirfd);
    close(g_kq);
}
// Functia de oprire a watcher-ului, aceasta seteaza flag-ul pentru a opri loop-ul principal si a inchide resursele
void watcher_stop(void) {
    g_running_watcher = 0;
}
#endif


