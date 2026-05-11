/*
    * user_server.c
    * Implementarea pentru serverul care se ocupa de clientii obisnuiti, 
    * pot incarca fisiere pentru scanare, sa descarce rezultatele, sa vada statistici sau sa vada lista de fisiere.
    Erori tratate:
    * Erori de procesare are fisierelor
    * Erori de procesare ale comenzilor


*/


// Constante care pot fii predefinite in alte headere
#ifndef MIN_LENGTH
#define MIN_LENGTH 50
#endif
#ifndef STR_LENGTH
#define STR_LENGTH 256
#endif
#ifndef HEX_LENGTH
#define HEX_LENGTH 64
#endif
#ifndef BUF
#define BUF 4096
#endif
#ifndef MIN_OFFSET
#define MIN_OFFSET 5
#endif
#ifndef FULL_PERM
#define FULL_PERM 0777
#endif
#ifndef UPLOAD_PERM
#define UPLOAD_PERM 0666
#endif
#ifndef USER_PORT
#define USER_PORT 8080
#endif

#ifndef MAX_IP_SIZE
#define MAX_IP_SIZE 16
#endif
#define MAX_STAT_SIZE 500

// POLL Timeout
#define TIMEOUT 1000

#include <pthread.h> 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <poll.h>     
#include <sqlite3.h> 
#include <errno.h>
#include <ctype.h>

#include "headers/server.h"
#include "headers/cp_worker.h"
#include "headers/sha256.h"

extern int running; // Importam variabila globala pentru a verifica daca serverul este inca in functiune


// Enum pentru starea clientului (daca e in modul de comanda sau in modul de upload)
typedef enum {
    STATE_CMD    = 0,   
    STATE_UPLOAD = 1,   
} client_state_e;


// Enum pentru a reprezenta un state-ul unui user
typedef struct {
    int            fd;                      
    int            logged;
    char           user_logged[MIN_LENGTH];
    char           buf[BUF];               
    long long      buf_len;

    client_state_e state;

    int            upload_fd;             
    long long      upload_total;           
    long long      upload_recv;            
    char           upload_filename[HEX_LENGTH]; 
} user_state_t;


// Aceasta functie este interna si se ocupa de a scrie tot ce trebuie scris, pentru a nu avea probleme cu write partiale
int write_all(int sock, const char *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = write(sock, buf + sent, len - sent);
        if (n < 0) {
            if (errno == EINTR) continue;  
            return -1;                      
        }
        sent += n;
    }
    return 0;
}

// Aceasta functie permite descarcarea unui fisier (doar rezultatele)
int download_file_result(int sock, char *filename, char *username) {
    char path[STR_LENGTH];
    (void)snprintf(path, sizeof(path), "./fce/outgoing/%s/result_%s.txt", username, filename);
    // Validate no path traversal
    if (strchr(filename, '/') || strstr(filename, "..") ||
        strchr(username, '/') || strstr(username, "..")) {
        (void)safe_write(sock, "Invalid filename\n", strlen("Invalid filename\n"));
        return EXIT_FAILURE;
    }

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        (void)safe_write(sock, "\033[31mFile not found or couldn't be opened\033[0m\n", strlen("\033[31mFile not found or couldn't be opened\033[0m\n"));
        return EXIT_FAILURE;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        (void)safe_write(sock, "\033[31mFile not found or couldn't be opened\033[0m\n", strlen("\033[31mFile not found or couldn't be opened\033[0m\n"));
        close(fd);
        return EXIT_FAILURE;
    }

    char header[STR_LENGTH];
    (void)snprintf(header, sizeof(header), "SIZE %lld\n", (long long)st.st_size);
    (void)safe_write(sock, header, strlen(header));

    char buffer[BUF];
    ssize_t n;
    while ((n = read(fd, buffer, sizeof(buffer))) > 0) {
        if (write_all(sock, buffer, n) < 0) {
            close(fd);
            return EXIT_FAILURE;  
        }
    }

    close(fd);
    return EXIT_SUCCESS;
}

// Functia care se ocupa de adaugarea in coada a unui fisier pentru a fii scanat
void scan_file(int sock, char *filename, char *username) {
    char path[STR_LENGTH], diff_path[STR_LENGTH];
    (void)snprintf(path, sizeof(path), "./fce/%s/%s", username, filename);
    (void)snprintf(diff_path, sizeof(diff_path), "./fce/processing/%s/%s", username, filename);

    struct stat st;
    if (stat(path, &st) != 0) {
        (void)safe_write(sock, "\033[31mFile not found or couldn't be opened\033[0m\n", strlen("\033[31mFile not found or couldn't be opened\033[0m\n"));
        return;
    }
    if (stat(diff_path, &st) == 0) {
        (void)safe_write(sock, "\033[31mFile is already being scanned\033[0m\n", strlen("\033[31mFile is already being scanned\033[0m\n"));
        return;
    }

    (void)safe_write(sock, "\033[32mFile is queued for scanning\033[0m\n", strlen("\033[32mFile is queued for scanning\033[0m\n"));
    cp_enqueue_job(username, filename);
}

// Functia care se ocupa cu citirea rezultatelor si trimiterea inapoi catre client
void stats_file(int sock, char *filename, char* username) {
    char path[STR_LENGTH], result_path[STR_LENGTH];
    (void)snprintf(path, sizeof(path), "./fce/outgoing/%s/result_%s.txt", username, filename);

    (void)snprintf(result_path, sizeof(result_path), "./fce/processing/%s/%s", username, filename);
    struct stat st;
    if(stat(result_path, &st) == 0) {
        (void)safe_write(sock, "\033[32mYour file is queued for scanning\033[0m\n", strlen("\033[32mYour file is queued for scanning\033[0m\n"));
        return;
    }
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        char* resp = "\033[31mFile is not scanned yet or doesn't exist\033[0m\n";
        (void)safe_write(sock, resp, strlen(resp));
        return;
    }
    if(stat(path, &st) != 0) {
        char* resp = "\033[31mFile is not scanned yet or doesn't exist\033[0m\n";
        (void)safe_write(sock, resp, strlen(resp));
        close(fd);
        return;
    }
    else if(st.st_size > MAX_STAT_SIZE) {
        char* resp = "\033[31mThe report file is too large to display, please use download command.\033[0m\n";
        (void)safe_write(sock, resp, strlen(resp));
        close(fd);
        return;
    }
    char buffer[BUF];
    size_t n;

    while ((n = read(fd, buffer, BUF-1)) > 0) {
        buffer[n] = '\0';
        (void)safe_write(sock, buffer, strlen(buffer));
    }
    close(fd);

}


// Functia care se ocupa cu listarea fisierelor disponibile pentru scanare si a celor deja scanate
void list_files(int sock, char* username) {
    char path[STR_LENGTH];
    char buffer[STR_LENGTH+2];

    (void)safe_write(sock, "===== SCANNED FILES =====\n", strlen("===== SCANNED FILES =====\n"));
    (void)snprintf(path, sizeof(path), "./fce/outgoing/%s", username);
    DIR *dir = opendir(path);
    if (!dir) {
        char *resp = "Could not open directory\n";
        (void)safe_write(sock, resp, strlen(resp));
        return;
    }
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) { // NOLINT threadsafe
        buffer[0] = '\0';
        if(strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 || entry->d_name[0] == '.') {
            continue;
        }
        char stpath[STR_LENGTH*2];
        (void)snprintf(stpath, sizeof(stpath), "./fce/outgoing/%s/%s", username, entry->d_name);
        struct stat st;
        if(stat(stpath, &st) != 0 || st.st_size == 0 || S_ISDIR(st.st_mode)) {
            continue;
        }
        char* stripped = strdup(entry->d_name);
        if (!stripped) continue;
        if(strstr(stripped, "result_") == stripped) {
            memmove(stripped, stripped + strlen("result_"), strlen(stripped) - strlen("result_") + 1);
        }
        size_t len = strlen(stripped);
        if (len > 4 && strcmp(stripped + len - 4, ".txt") == 0) {
            stripped[len - 4] = '\0';
        }
        (void)snprintf(buffer, sizeof(buffer), "%s\n", stripped);
        (void)safe_write(sock, buffer, strlen(buffer));
        free(stripped);
    }
    (void)safe_write(sock, "END_OF_LIST", strlen("END_OF_LIST"));
    closedir(dir);
}

// Folosita in backend pentru a verifica daca user-ul si parola contin caractere invalide.
int isValidCharacter(char c) {
    return isalnum((unsigned char)c) || c == '_' || c == '-' || c == '.';
}

static ssize_t getFilesTotalSize(char* username) {
    char path[STR_LENGTH];
    (void)snprintf(path, sizeof(path), "./fce/outgoing/%s", username);
    DIR *dir = opendir(path);
    if (!dir) {
        return -1;
    }
    struct dirent *entry;
    ssize_t total_size = 0;
    while ((entry = readdir(dir)) != NULL) { // NOLINT threadsafe
        if(strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 || entry->d_name[0] == '.') {
            continue;
        }
        char stpath[STR_LENGTH*2];
        (void)snprintf(stpath, sizeof(stpath), "./fce/outgoing/%s/%s", username, entry->d_name);
        struct stat st;
        if(stat(stpath, &st) != 0 || st.st_size == 0 || S_ISDIR(st.st_mode)) {
            continue;
        }
        total_size += st.st_size;
    }
    closedir(dir);
    return total_size;
}


// Functia care se ocupa efectiv cu procesarea comenzilor primite
static int process_user_cmd(user_state_t *st)
{
    char *buffer = st->buf;

    if (strncasecmp(buffer, "LOGIN", MIN_OFFSET) == 0) {
        char u[MIN_LENGTH], p[HEX_LENGTH+1];
        (void)sscanf(buffer, "LOGIN %49s %64s", u, p);
        if (check_login(u, p, "user")) {
            st->logged = 1;
            st->user_logged[0] = '\0';
            (void)snprintf(st->user_logged, sizeof(st->user_logged), "%s", u);
            ensure_dir(st->user_logged); // Ne asigura ca directoarele pentru acest user exista, daca nu le creeaza
            add_client(st->fd, st->user_logged);
            (void)safe_write(st->fd, "OK\n", 3);
        } else {
            (void)safe_write(st->fd, "FAIL\n", MIN_OFFSET);
        }
        return 0;
    }
    else if (!st->logged && strncasecmp(buffer, "REGISTER", strlen("REGISTER")) == 0) {
        char u[MIN_LENGTH], p[HEX_LENGTH+1];
        (void)sscanf(buffer, "REGISTER %49s %64s", u, p);
        // Validari user si parola
        for(int c = 0; c<(int)strlen(u); c++) {
            if(!isValidCharacter(u[c])) {
                (void)safe_write(st->fd, "\033[31mInvalid character in username. Allowed: alphanumeric, '_', '-', '.'\033[0m\n", strlen("\033[31mInvalid character in username. Allowed: alphanumeric, '_', '-', '.'\033[0m\n"));
                return 0;
            }
        }
        for(int c = 0; c<(int)strlen(p); c++) {
            if(!isValidCharacter(p[c])) {
                (void)safe_write(st->fd, "\033[31mInvalid character in password. Allowed: alphanumeric, '_', '-', '.'\033[0m\n", strlen("\033[31mInvalid character in password. Allowed: alphanumeric, '_', '-', '.'\033[0m\n"));
                return 0;
            }
        }
        // Ne asiguram ca user-ul nu exista deja
        if (find_db_id(u) > 0) {
            (void)safe_write(st->fd, "\033[31mUsername already exists\033[0m\n", strlen("\033[31mUsername already exists\033[0m\n"));
            return 0;
        }
        // Adaugam si ii spunem clientului ca s-a inregistrat cu succes, acum se poate loga
        add_user_hash(u, p, "user");
        (void)safe_write(st->fd, "OK\n", 3);
        return 0;
    }

    if (!st->logged) {
        (void)safe_write(st->fd, "\033[31mUNAUTHORIZED\033[0m\n", strlen("\033[31mUNAUTHORIZED\033[0m\n"));
        return 0;
    }
    // UPLOAD (functia extrem de complicata pentru upload-uri si download-uri stabile)
    
    else if (strncasecmp(buffer, "DOWNLOAD", strlen("DOWNLOAD")) == 0) { // Nu necesita explicatii, doar parsare si apelare de functii
        char file[MIN_LENGTH];
        (void)sscanf(buffer, "DOWNLOAD %49s", file);
        if (download_file_result(st->fd, file, st->user_logged) != EXIT_FAILURE) {
            char log_string[STR_LENGTH];
            (void)snprintf(log_string, sizeof(log_string), "downloaded result file %49s", file);
            add_logs(st->user_logged, log_string);
        }
    }

    

    
    else if (strncasecmp(buffer, "STATS", MIN_OFFSET) == 0) {
        char file[STR_LENGTH];
        (void)sscanf(buffer, "STATS %255s", file);
        stats_file(st->fd, file, st->user_logged);
    }
    else if (strncasecmp(buffer, "BACKUP", MIN_OFFSET) == 0) {
        char file[MIN_LENGTH];
        (void)sscanf(buffer, "BACKUP %49s", file);
        int total_time = compute_time(file);
        char strtime[MIN_LENGTH];
        (void)snprintf(strtime, sizeof(strtime), "%d", total_time);
        update_user_column(st->user_logged, "backup", strtime);
        (void)safe_write(st->fd, "Backup time updated\n", strlen("Backup time updated\n"));
    }

    else if (strncasecmp(buffer, "CLEANUP", MIN_OFFSET) == 0) {
        char file[MIN_LENGTH];
        (void)sscanf(buffer, "CLEANUP %49s", file);
        int total_time = compute_time(file);
        char strtime[MIN_LENGTH];
        (void)snprintf(strtime, sizeof(strtime), "%d", total_time);
        update_user_column(st->user_logged, "cleanup", strtime);
        (void)safe_write(st->fd, "Cleanup time updated (files older than specified time will be deleted)\n", strlen("Cleanup time updated (files older than specified time will be deleted)\n"));
    }

    else if(strncasecmp(buffer, "SIZE", MIN_OFFSET-1) == 0) {
        char file[MIN_LENGTH];
        (void)sscanf(buffer, "SIZE %49s", file);
        ssize_t total_size = getFilesTotalSize(st->user_logged);
        if(total_size < 0) {
            (void)safe_write(st->fd, "\033[31mCould not access user files\033[0m\n", strlen("\033[31mCould not access user files\033[0m\n"));
            return 0;
        }
        char size_str[MIN_LENGTH];
        if(strncasecmp(file, "B", 1) == 0) {
            (void)snprintf(size_str, sizeof(size_str), "%lld B\n", (long long)total_size);
            (void)safe_write(st->fd, size_str, strlen(size_str));
            return 0;
        }
        else if(strncasecmp(file, "KB", 2) == 0) {
            (void)snprintf(size_str, sizeof(size_str), "%lld KB\n", (long long)(total_size/1024));
            (void)safe_write(st->fd, size_str, strlen(size_str));
            return 0;
        }
        else if(strncasecmp(file, "MB", 2) == 0) {
            (void)snprintf(size_str, sizeof(size_str), "%lld MB\n", (long long)(total_size/(1024*1024)));
            (void)safe_write(st->fd, size_str, strlen(size_str));
            return 0;
        }
        (void)snprintf(size_str, sizeof(size_str), "%lld\n", (long long)total_size);
        (void)safe_write(st->fd, size_str, strlen(size_str));
    }

    else if (strncasecmp(buffer, "SCAN", MIN_OFFSET-1) == 0) {
        char file[MIN_LENGTH]; long long size = 0;
        (void)sscanf(buffer, "SCAN %49s %lld", file, &size);

        if (size <= 0) {
            (void)safe_write(st->fd, "\033[31mERR_INVALID_SIZE\033[0m\n", strlen("\033[31mERR_INVALID_SIZE\033[0m\n"));
            return 0;
        }

        char path[STR_LENGTH];
        (void)snprintf(path, sizeof(path), "./fce/%s/%s", st->user_logged, file);
        int ufd = open(path, O_WRONLY | O_CREAT | O_TRUNC, UPLOAD_PERM);
        if (ufd < 0) {
            (void)safe_write(st->fd, "\033[31mERR_OPEN\033[0m\n", strlen("\033[31mERR_OPEN\033[0m\n"));
            return 0;
        }

        st->upload_fd    = ufd;
        st->upload_total = size;
        st->upload_recv  = 0;
        strncpy(st->upload_filename, file, HEX_LENGTH - 1);
        st->upload_filename[HEX_LENGTH - 1] = '\0';
        st->state = STATE_UPLOAD;  // Ii setam state-ul pe UPLOAD pentru a sti ca urmatoarele date care vin sunt parte din upload, pana cand upload-ul se termina sau se anuleaza
    }
    else if (strncasecmp(buffer, "LIST", MIN_OFFSET-1) == 0) {
        list_files(st->fd, st->user_logged);
    }
    else if (strncasecmp(buffer, "LOGOUT", MIN_OFFSET+1) == 0) {
        (void)safe_write(st->fd, "BYE\n", 4);
        return -1;
    }

    return 0;
}
// Functie pentru a abandona un upload in curs
static void upload_abort(user_state_t *st)
{
    if (st->upload_fd >= 0) { 
        close(st->upload_fd); // Inchide fd-ul
        st->upload_fd = -1; // il setam pe -1
        char path[STR_LENGTH];
        (void)snprintf(path, sizeof(path), "./fce/%s/%s",
                       st->user_logged, st->upload_filename);
        unlink(path); // stergem fisierul corupt
    }
    st->state        = STATE_CMD; // resetam state-ul
    st->upload_recv  = 0; // resetam tot ce tine de upload
    st->upload_total = 0;
}

// Functia de disconnect_user
static void disconnect_user(user_state_t *st, struct pollfd *pfd)
{
    if (st->state == STATE_UPLOAD) // Daca avea uplaod in curs ii dam abort
        upload_abort(st);
    update_user_column(st->user_logged, "loggedin", "0"); 
    remove_client(st->fd);
    add_logs(st->user_logged[0] ? st->user_logged : "?", "User disconnected.");
    close(st->fd);
    st->fd      = -1;
    st->logged  = 0;
    st->buf_len = 0;
    st->user_logged[0] = '\0';
    pfd->fd     = -1;
    pfd->events = 0; // Resetam toate variabilele)
}

// Main loop-ul pentru user_server
void *user_server(void *arg) {
    int sfd;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) { perror("socket"); return NULL; }

    int yes = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);

    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(USER_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Could not bind the server.");
        close(sfd);
        return NULL;
    }
    if (listen(sfd, SOMAXCONN) < 0) {
        perror("Could not listen on the server.");
        close(sfd);
        pthread_exit(NULL);
        return NULL;
    }

    int capacity = HEX_LENGTH;
    struct pollfd   *fds    = malloc(sizeof(struct pollfd)   * capacity); // Alocam array-urile pentru poll
    user_state_t    *states = malloc(sizeof(user_state_t)    * capacity); // Alocam array-urile pentru a tine state-ul userilor
    if (!fds || !states) { 
        free(fds); free(states);
        perror("malloc poll arrays"); 
        close(sfd); 
        return NULL; }

    for (int i = 0; i < capacity; i++) {
        fds[i].fd     = -1;
        fds[i].events = 0;
    }

    fds[0].fd     = sfd; // Adaugam server socket-ul in poll
    fds[0].events = POLLIN;  // Setam flag-ul pentru a primi evenimente de citire
    int nfds = 1;  

    (void)fprintf(stderr, "[user_server] Active on port %d\n", USER_PORT);

    while (running) {
        int ret = poll(fds, nfds, TIMEOUT); // Asteptam evenimente pe socket-uri

        if (ret < 0) {
            if (errno == EINTR) continue;  // Daca am primit un semnal de eroare, continuam sa asteptam
            perror("poll");
            break;
        }
        if (ret == 0) continue;   

        if (fds[0].revents & POLLIN) { // Daca avem un eveniment pe server socket, inseamna ca avem un client nou care vrea sa se conecteze
            struct sockaddr_in caddr; // Structura pentru a tine informatii despre clientul care se conecteaza
            socklen_t clen = sizeof caddr; // Variabila pentru lungimea structurii, necesara pentru accept
            int cfd = accept(sfd, (struct sockaddr*)&caddr, &clen); // Acceptam conexiunea
            
            if (cfd >= 0) {
                char client_ip[MAX_IP_SIZE];
                inet_ntop(AF_INET, &caddr.sin_addr, client_ip, sizeof(client_ip));
                int banned = find_ip_ban(client_ip); // Verificarea daca e banat

                if (banned) {
                    safe_write(cfd, "BANNED\n", strlen("BANNED\n"));
                    close(cfd);
                    goto next_events;
                }
                int slot = -1; // Cautam un slot liber in array-ul pentru poll
                for (int i = 1; i < nfds; i++) { // Incepem de la 1 pentru a nu lua in considerare server socket-ul
                    if (fds[i].fd == -1) { slot = i; break; }
                }

                if (slot == -1) { // Daca nu avem slot liber, dublam capacitatea array-urilor
                    if (nfds == capacity) {
                        int new_cap = capacity * 2;
                        struct pollfd  *nf = realloc(fds,    sizeof(struct pollfd)  * new_cap);
                        user_state_t   *ns = realloc(states, sizeof(user_state_t)   * new_cap);
                        if (!nf || !ns) {
                            (void)fprintf(stderr, "[user_server] realloc failed – client rejected\n");
                            close(cfd);
                            goto next_events;
                        }
                        fds    = nf;
                        states = ns;
                        for (int i = capacity; i < new_cap; i++) {
                            fds[i].fd     = -1;
                            fds[i].events = 0;
                        }
                        capacity = new_cap;
                    }
                    slot = nfds++;
                }

                fds[slot].fd      = cfd; // Adaugam clientul nou in array-ul pentru poll
                fds[slot].events  = POLLIN; // Setam flag-ul pentru a primi evenimente de citire de la acest client
                fds[slot].revents = 0; // Resetam campul pentru evenimentele primite
                memset(&states[slot], 0, sizeof(user_state_t));
                states[slot].fd        = cfd; // Setam fd-ul in state
                states[slot].state     = STATE_CMD; // Setam state-ul pe CMD, pentru ca atunci cand se conecteaza, clientul este in modul de comanda, nu in modul de upload
                states[slot].upload_fd = -1;

                (void)fprintf(stderr, "[user_server] New client fd=%d  slot=%d  total=%d\n",
                              cfd, slot, nfds - 1);
            }
        }
// Aici se ajunge automat dupa ce am procesat evenimentul pentru server socket, sau daca avem un eveniment pe un socket de client, 
// Atunci intram aici pentru a procesa acel eveniment, fie ca e comanda sau date pentru upload
next_events: 

        for (int i = 1; i < nfds; i++) {
            if (fds[i].fd < 0)          continue;
            if (fds[i].revents == 0)    continue;

            if (fds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) { // Daca avem o eroare, sau clientul s-a deconectat, sau fd-ul nu e valid, atunci ne deconectam si curatam tot ce tine de acel client
                disconnect_user(&states[i], &fds[i]);
                continue;
            }

            if (!(fds[i].revents & POLLIN)) continue; // Daca nu avem un eveniment de citire, continuam

            if (states[i].state == STATE_UPLOAD) { // Daca clientul e in modul de upload, atunci datele care vin sunt parte din upload, nu comenzi, deci le tratam diferit
                char ubuf[BUF];
                long long  remaining = states[i].upload_total - states[i].upload_recv;
                long long  to_read   = remaining < BUF ? remaining : BUF;

                ssize_t n = recv(fds[i].fd, ubuf, to_read, 0); // Citim datele pentru upload
                if (n <= 0) { // Daca avem o eroare sau clientul s-a deconectat, sau nu avem date de citit, atunci abandonam upload-ul si ne deconectam
                    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue; // Daca nu avem date de citit, continuam sa asteptam
                    disconnect_user(&states[i], &fds[i]); // Ne deconectam si curatam tot ce tine de acel client
                    continue;
                }

                (void)safe_write(states[i].upload_fd, ubuf, n); // Scriem datele primite in fisier
                states[i].upload_recv += (long long)n; // Salvam cat am primit pana acum pentru a sti cand se termina upload-ul

                if (states[i].upload_recv >= states[i].upload_total) { // Daca am primit tot ce trebuie pentru upload, atunci inchidem upload-ul, adaugam in log si ii spunem clientului ca upload-ul s-a terminat cu succes
                    close(states[i].upload_fd);
                    states[i].upload_fd = -1;
                    states[i].state     = STATE_CMD;   
                    char path[STR_LENGTH];
                    (void)snprintf(path, sizeof(path), "./fce/%s/%s",
                            states[i].user_logged, states[i].upload_filename);
                    char resultpath[STR_LENGTH];
                    (void)snprintf(resultpath, sizeof(resultpath), "./fce/outgoing/%s/result_%s.txt",
                            states[i].user_logged, states[i].upload_filename);
                   
                    (void)safe_write(fds[i].fd, "File uploaded!\n", strlen("File uploaded!\n"));
                    
                    char log_string[STR_LENGTH];
                    (void)snprintf(log_string, sizeof(log_string),
                                   "uploaded file %s", states[i].upload_filename);
                    add_file_if_not_exists(states[i].user_logged, states[i].upload_filename, path, resultpath);
                    add_logs(states[i].user_logged, log_string);

                    scan_file(states[i].fd, states[i].upload_filename, states[i].user_logged);
                }

            } else {// Da nu e upload (inseamna ca e comanda)
                ssize_t n = recv(fds[i].fd,
                                 states[i].buf + states[i].buf_len,
                                 BUF - 1 - states[i].buf_len, 0); // Citim datele in buffer

                if (n <= 0) {
                    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue; // Aceleasi ignorari ca la upload
                    disconnect_user(&states[i], &fds[i]);
                    continue;
                }

                states[i].buf_len += (long long)n;
                states[i].buf[states[i].buf_len] = '\0';

                char *newline;
                while ((newline = memchr(states[i].buf, '\n',
                                         states[i].buf_len)) != NULL) {
                    *newline = '\0';

                    int r = process_user_cmd(&states[i]); // Procesam comanda

                    long long processed = (long long)(newline - states[i].buf) + 1;
                    states[i].buf_len -= processed; // Stergem comanda procesata din buffer
                    memmove(states[i].buf, newline + 1, states[i].buf_len); // Mutam restul datelor ramase la inceputul buffer-ului
                    states[i].buf[states[i].buf_len] = '\0';

                    if (r < 0) { // Daca a esuat procesarea comenzii atunci ne deconectam
                        disconnect_user(&states[i], &fds[i]);
                        break;
                    }
                    // Daca clientul e in modul de upload, inseamna ca urmatoarele date care vin sunt parte din upload, deci iesim din loop-ul de procesare a comenzilor pentru a nu procesa datele de upload ca si comenzi
                    if (states[i].state == STATE_UPLOAD && states[i].buf_len > 0) {
                        long long to_write = states[i].buf_len;
                        if (to_write > states[i].upload_total - states[i].upload_recv)
                            to_write = states[i].upload_total - states[i].upload_recv;

                        (void)safe_write(states[i].upload_fd,
                                         states[i].buf, to_write); // Scriem in fisier datele care au venit impreuna cu comanda de upload, daca exista
                        states[i].upload_recv += to_write;
                        states[i].buf_len     -= to_write;
                        memmove(states[i].buf,
                                states[i].buf + to_write,
                                states[i].buf_len);

                        if (states[i].upload_recv >= states[i].upload_total) { // Daca am primit tot ce trebuie pentru upload, atunci inchidem upload-ul, adaugam in log si ii spunem clientului ca upload-ul s-a terminat cu succes
                            close(states[i].upload_fd);
                            states[i].upload_fd = -1;
                            states[i].state     = STATE_CMD;
                            char path[STR_LENGTH];
                            (void)snprintf(path, sizeof(path), "./fce/%s/%s",
                                        states[i].user_logged, states[i].upload_filename);
                            char resultpath[STR_LENGTH];
                            (void)snprintf(resultpath, sizeof(resultpath), "./fce/outgoing/%s/result_%s.txt",
                                        states[i].user_logged, states[i].upload_filename);
                            (void)safe_write(fds[i].fd, "File uploaded!\n", strlen("File uploaded!\n"));
                            char log_string[STR_LENGTH];
                            (void)snprintf(log_string, sizeof(log_string),
                                           "uploaded file %s",
                                           states[i].upload_filename);

                            add_file_if_not_exists(states[i].user_logged, states[i].upload_filename, path, resultpath);
                            add_logs(states[i].user_logged, log_string);

                            scan_file(states[i].fd, states[i].upload_filename, states[i].user_logged);
                        }
                        break; 
                    }
                }

                if (states[i].fd >= 0 && states[i].buf_len >= BUF - 1) { 
                    // Fallback pentru cazul in care clientul trimite o comanda foarte lunga care depaseste dimensiunea buffer-ului, 
                    // pentru a nu avea probleme de overflow sau alte probleme, atunci ii spunem clientului ca comanda e prea lunga si curatam buffer-ul
                    (void)safe_write(fds[i].fd, "ERR_CMD_TOO_LONG\n", strlen("ERR_CMD_TOO_LONG\n"));
                    states[i].buf_len = 0;
                }
            }
        }
        // Dupa ce am procesat toate evenimentele, verificam daca avem spatiu in array-ul pentru poll, daca nu, atunci curatam slot-urile care sunt libere (fd == -1) pentru a putea adauga noi clienti fara a fi nevoie sa dublam iar capacitatea
        while (nfds > 1 && fds[nfds - 1].fd == -1)
            nfds--;

    } 
    // In cazul in care serverul se inchide, atunci parcurgem toti clientii conectati si ii deconectam, pentru a curata toate resursele si a nu lasa fisiere deschise sau alte probleme
    for (int i = 1; i < nfds; i++) {
        if (fds[i].fd >= 0) {
            (void)safe_write(fds[i].fd, "SERVER_SHUTDOWN\n", strlen("SERVER_SHUTDOWN\n"));
            disconnect_user(&states[i], &fds[i]);
        }
    }

    // Eliberam resursele si inchide thread-ul
    free(fds);
    free(states);
    close(sfd);
    pthread_exit(NULL);
    return arg;
}



