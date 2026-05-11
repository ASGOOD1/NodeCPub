/* 
    * server.c - implementarea pentru aplicatia main, care deleaga tread-urile si etc
    In acest fisier se afla de asemenea si unele functii pt a interactiona cu db s.a.m.d
    Optiuni din linia de comanda:
    -u: foloseste socket unix pe webservice in loc de socket INET
    -c: sterge log-urile vechi
*/



#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h> // Socket-uri inet
#include <pthread.h> // Threaduri
#include <strings.h> // strcasecmp in user_server.c
#include <sqlite3.h> // Database
#include "jwt.c" // Generare (Necesar pt linker)
#include <getopt.h>  // Parsare optiuni linia de comanda (-u - perneste webserviceul cu unix socket)
#include <sys/stat.h> // stat si mkdir
#include <signal.h> // custom signal handling

#include <uuid/uuid.h>
#include "headers/server.h" 
#include "headers/base64.h"
#include "headers/cp_worker.h"


// Implementari pentru servere si altele
#include "user_server.c"
#include "admin_server.c"
#include "web_server.c"
#include "worker.c"
#include "watcher.c"
#include "queue.c"
#include "cp_worker.c"

// Daca avem strlcat definit il inlocuim cu aceasta varianta (pe mac nu vine definita, iar pe linux e posibil sa fie definita deferit in unele distributii))
#if defined strlcat
#undef strlcat
size_t strlcat(char *dst, const char *src, size_t siz) {
    size_t dlen = strnlen(dst, siz);
    size_t slen = strlen(src);
    if (dlen < siz - 1) {
        size_t copylen = (slen < siz - dlen - 1) ? slen : siz - dlen - 1;
        memcpy(dst + dlen, src, copylen);
        dst[dlen + copylen] = '\0';
    }
    return dlen + slen;
}
#endif



// Variabile globale

sqlite3 *db; // Database handle
pthread_mutex_t db_lock = PTHREAD_MUTEX_INITIALIZER; // Mutex database


// Constante

#define USER_PORT 8080
#define ADMIN_PORT 9000
#define WEB_PORT 8081
#define BUF 4096
#define FULL_PERM 0777
#define UPLOAD_PERM 0666
#define MIN_OFFSET 5
#define MIN_LENGTH 50
#define STR_LENGTH 256
#ifndef HEX_LENGTH
#define HEX_LENGTH 64
#endif

#define SECONDS_IN_MINUTE 60
#define SECONDS_IN_HOUR 3600
#define SECONDS_IN_DAY 86400
#define DAYS_IN_YEAR 365
time_t start_time; // Pt comanda uptime
int running = 1; // Flag pentru a opri serverul in caz de nevoie


// Aceasta functie asigura existenta directoarelor necesare(upload, scan, download)
void ensure_dir(char * username) {
    char path[STR_LENGTH];
    (void)snprintf(path, sizeof(path), "./fce/%s", username);
    struct stat st = {0};
    if (stat(path, &st) == -1) {
        mkdir(path, FULL_PERM);
    }
    (void)snprintf(path, sizeof(path), "./fce/processing/%s", username);
  
    if (stat(path, &st) == -1) {
        mkdir(path, FULL_PERM);
    }
    (void)snprintf(path, sizeof(path), "./fce/outgoing/%s", username);

    if (stat(path, &st) == -1) {
        mkdir(path, FULL_PERM);
    }
    worker_watch_user(username);
}
// Wrapper peste write pentru a nu pune (void) peste tot in cod
void safe_write(int fd, const char *buf, unsigned long len) {
    ssize_t n = write(fd, buf, len);
    (void)n; 
}


// Pipe pentru log-uri live (functia de logging)

void log_to_pipe(const char* user, const char* action) {
    char buffer[STR_LENGTH * 2];
    time_t acum = time(NULL);
    struct tm t_local; 
    if (localtime_r(&acum, &t_local) != NULL) {
        if(localtime_r(&acum, &t_local) != NULL) {
            (void)snprintf(buffer, sizeof(buffer), "[%02d:%02d:%02d] %s: %s",
                t_local.tm_hour, t_local.tm_min, t_local.tm_sec, user, action);

            (void)safe_write(log_pipe[1], buffer, strlen(buffer));
        }
        else  {
            (void)snprintf(buffer, sizeof(buffer), "[%02d:%02d:%02d] %s: %s",
                    t_local.tm_hour, t_local.tm_min, t_local.tm_sec, user, action);
            (void)safe_write(log_pipe[1], buffer, strlen(buffer));
        }
    }
}

// Functia pentru a adauga un client in lista
void add_client(int sock, const char *username) {
    pthread_mutex_lock(&clients_mutex);

    if (client_count == client_capacity) {
        int new_capacity = client_capacity == 0 ? 4 : client_capacity * 2; // Lista este dinamica
        client_t *new_clients = realloc(clients, sizeof(client_t) * new_capacity);
        if (!new_clients) {
            perror("realloc");
            pthread_mutex_unlock(&clients_mutex);
            return;
        }
        clients = new_clients;
        client_capacity = new_capacity;
    }
    
    clients[client_count].sock = sock;
    strncpy(clients[client_count].username, username, MIN_LENGTH-1);
    clients[client_count].username[MIN_LENGTH-1] = '\0';
    size_t ulen = strlen(clients[client_count].username);
    if (ulen > 0 && clients[client_count].username[ulen - 1] == '\n')
        clients[client_count].username[ulen - 1] = '\0';
    client_count++;

    pthread_mutex_unlock(&clients_mutex);
}

// Functia pentru a sterge un client din lista (dupa socket)
void remove_client(int sock) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < client_count; i++) {
        if (clients[i].sock == sock ) {
            clients[i] = clients[client_count - 1];
            clients[client_count - 1].sock = 0;
            clients[client_count - 1].username[0] = '\0';
            client_count--;
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);

}

// Functia pentru a sterge un client la un anumit index
void remove_client_at_index(int index) {
    if (index >= 0 && index < client_count) {
        clients[index] = clients[client_count - 1];
        clients[client_count - 1].sock = 0;
        clients[client_count - 1].username[0] = '\0';
        client_count--;
    }
}

// Functia pentru a gasi un client dupa socket, returneaza indexul sau in lista sau 0
int find_client(int sock) {
    for (int i = 0; i < client_count; i++) {
        if (clients[i].sock == sock) {
            return i;
            break;
        }
    }
    return 0;
}

// Functia pentru a gasi un client dupa username, returneaza socketul sau sau -1
int find_client_socket_by_username(const char *username) {
    int sock = -1;
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < client_count; i++) {
        if (strcmp(clients[i].username, username) == 0 && clients[i].sock > 0) {
            sock = clients[i].sock;
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);
    return sock;
}



// Functia pentru a adauga un user in baza de date (folosita la inregistrare)
void add_user_hash(char *username, char *hash, char *role) {
    sqlite3_stmt *stmt;
    pthread_mutex_lock(&db_lock);

    if (sqlite3_prepare_v2(db,
        "INSERT INTO users(username, password, role) VALUES (?, ?, ?)",
        -1, &stmt, NULL) == SQLITE_OK) {

        sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, hash, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, role, -1, SQLITE_STATIC);

        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    } else {
        (void)fprintf(stderr, "Failed to prepare insert statement\n");
    }

    pthread_mutex_unlock(&db_lock);
}

// Functie pentru a adauga logs in database.
void add_logs(char *user, char* action) {
    char* action_dup = strdup(action);
    if(action_dup == NULL) {
        (void)fprintf(stderr, "Failed to duplicate action string\n");
        return;
    }
    if(strchr(action_dup, '\n')) {
        *strchr(action_dup, '\n') = '\0';
    }
    if(action_dup[0] == '\033') {
        char* action_d2 = strdup(action_dup+MIN_OFFSET);
        char * end = strrchr(action_d2, '\033');
        if(end) {
            *end = '\0';
        }
        memcpy(action_dup, action_d2, strlen(action_d2)+1);
        free(action_d2);
    }
    
    sqlite3_stmt *stmt;
    pthread_mutex_lock(&db_lock);
    if (sqlite3_prepare_v2(db, "INSERT INTO logs(username, action) VALUES (?, ?)",  -1, &stmt, NULL) == SQLITE_OK) {

        sqlite3_bind_text(stmt, 1, user, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, action_dup, -1, SQLITE_STATIC);

        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    } else {
        (void)fprintf(stderr, "Failed to prepare insert statement\n");
        (void)fflush(stderr);
    }

    pthread_mutex_unlock(&db_lock);
    log_to_pipe(user, action_dup);
    free(action_dup);
}


// Functie pentru a actualiza o coloana a unui user (nu trebuie escaped, e o functie interna)
void update_user_column(char *user, char* column, char* value) {
    sqlite3_stmt *stmt;
    char sql[STR_LENGTH];
    (void)snprintf(sql, sizeof(sql),  "UPDATE users SET %s=? WHERE username=?", column);
    pthread_mutex_lock(&db_lock);
    if (sqlite3_prepare_v2(db, sql,  -1, &stmt, NULL) == SQLITE_OK) {

        sqlite3_bind_text(stmt, 1, value, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, user, -1, SQLITE_STATIC);

        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    } else {
        (void)fprintf(stderr, "Failed to prepare update statement\n");
        (void)fflush(stderr);
    }

    pthread_mutex_unlock(&db_lock);
}


// Functie pentru a verifica daca user-ul si parola sunt corecte( returneaza id-ul userului)
int check_login(char *user, char *pass, char *role) {

    if(strcasecmp(role, "admin") == 0) {
        pthread_mutex_lock(&admin_lock);
        if (adminLogged) {
            pthread_mutex_unlock(&admin_lock);
            return 0;
        }
        pthread_mutex_unlock(&admin_lock);
    }

    char log_string[HEX_LENGTH*2];
    log_string[0] = '\0';

    (void)snprintf(log_string, sizeof(log_string), "%s log in failed.", role);

    sqlite3_stmt *stmt;
    int res = 0;

    pthread_mutex_lock(&db_lock);

    if (sqlite3_prepare_v2(db,
        "SELECT password, id FROM users WHERE username=? AND role=?",
        -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&db_lock);
        return 0;
    }

    sqlite3_bind_text(stmt, 1, user, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, role, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *pwd = sqlite3_column_text(stmt, 0);
        if (strcmp((const char*)pwd, pass) == 0) {
            res = sqlite3_column_int(stmt, 1);
            (void)snprintf(log_string, sizeof(log_string), "%s log in succes.", role);
        }
    }

    sqlite3_finalize(stmt);

    pthread_mutex_unlock(&db_lock);

    
    update_user_column(user, "loggedin", res ? "1" : "0");
    add_logs(user, log_string);
    return res;
}


// Functie pentru a gasi username-ul unui user dupa id
char* find_db_username(char* userid) {
    sqlite3_stmt *stmt;
    static char username_buf[STR_LENGTH];
    char* result = NULL;

    pthread_mutex_lock(&db_lock);

    if (sqlite3_prepare_v2(db, "SELECT username FROM users WHERE id=?", -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&db_lock);
        return NULL;
    }

    sqlite3_bind_text(stmt, 1, userid, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char* text = sqlite3_column_text(stmt, 0);
        if (text) {
            strncpy(username_buf, (const char*)text, sizeof(username_buf) - 1);
            username_buf[sizeof(username_buf) - 1] = '\0';
            result = username_buf;
        }
    }

    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&db_lock); 

    return result;
}

// Functie pentru a gasi id-ul unui user dupa username
int find_db_id(char* username) {
    sqlite3_stmt *stmt;
    int result = 0;

    pthread_mutex_lock(&db_lock);

    if (sqlite3_prepare_v2(db, "SELECT id FROM users WHERE username=?", -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&db_lock);
        return 0;
    }

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        result = sqlite3_column_int(stmt, 0);

    }

    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&db_lock);

    return result;
}


// Functie pentru a gasi daca un ip este banat, returneaza id-ul banului sau 0
int find_ip_ban(const char* ip) {
    sqlite3_stmt *stmt;
    int banned = 0;

    pthread_mutex_lock(&db_lock);
    if (sqlite3_prepare_v2(db, "SELECT id FROM bans WHERE ip=?", -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, ip, -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            banned = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }
    pthread_mutex_unlock(&db_lock);

    return banned;
}

// Functie pentru a sterge un ip din lista de banari, returneaza 1 daca a fost sters sau 0 daca nu a fost gasit
int remove_ip_ban(const char* ip) {
    sqlite3_stmt *stmt;
    int removed = 0;

    pthread_mutex_lock(&db_lock);
    if (sqlite3_prepare_v2(db, "DELETE FROM bans WHERE ip=?", -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, ip, -1, SQLITE_STATIC);
        sqlite3_step(stmt);
        sqlite3_changes(db);
        removed = 1;
        sqlite3_finalize(stmt);
    }
    pthread_mutex_unlock(&db_lock);

    return removed;
}

// Functie pentru a adauga un ip in lista de banari, returneaza 1 daca a fost adaugat sau 0 daca era deja banat
int add_ip_ban(const char* ip, const char* banned_by) {
    sqlite3_stmt *stmt;
    int added = 0;
    pthread_mutex_lock(&db_lock);
    if (sqlite3_prepare_v2(db, "INSERT OR IGNORE INTO bans(ip, banned_by) VALUES (?, ?)", -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, ip, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, banned_by, -1, SQLITE_STATIC);
        sqlite3_step(stmt);
        added = sqlite3_changes(db);
        sqlite3_finalize(stmt);
    }
    pthread_mutex_unlock(&db_lock);
    return added;
}

char* find_file_uuid(char* user, char* filename) {
    sqlite3_stmt *stmtfind;
    static char found[STR_LENGTH] = {0};
    
    char* result = NULL;

    pthread_mutex_lock(&db_lock);
    if (sqlite3_prepare_v2(db, "SELECT uniqid FROM files WHERE user=? AND filename=?", -1, &stmtfind, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmtfind, 1, user, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmtfind, 2, filename, -1, SQLITE_STATIC);
        if (sqlite3_step(stmtfind) == SQLITE_ROW) {
            const unsigned char* text = sqlite3_column_text(stmtfind, 0);
            if (text) {
                strncpy(found, (const char*)text, sizeof(found) - 1);
                found[sizeof(found) - 1] = '\0';
                result = found;
            }
        }
        sqlite3_finalize(stmtfind);
    }
    pthread_mutex_unlock(&db_lock);
    return result;
}
char* find_file_scanpath(char* uuid) {
    sqlite3_stmt *stmtfind;
    static char username_buf[STR_LENGTH];
    char* result = NULL;

    pthread_mutex_lock(&db_lock);
    if (sqlite3_prepare_v2(db, "SELECT resultpath FROM files WHERE uniqid=?", -1, &stmtfind, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmtfind, 1, uuid, -1, SQLITE_STATIC);
        if (sqlite3_step(stmtfind) == SQLITE_ROW) {
            const unsigned char* text = sqlite3_column_text(stmtfind, 0);
            if (text) {
                strncpy(username_buf, (const char*)text, sizeof(username_buf) - 1);
                username_buf[sizeof(username_buf) - 1] = '\0';
                result = username_buf;
            }
        }
        sqlite3_finalize(stmtfind);
    }
    pthread_mutex_unlock(&db_lock);
    return result;
}

char* find_file_filename(char* uuid) {
    sqlite3_stmt *stmtfind;
    static char username_buf[STR_LENGTH];
    char* result = NULL;

    pthread_mutex_lock(&db_lock);
    if (sqlite3_prepare_v2(db, "SELECT filename FROM files WHERE uniqid=?", -1, &stmtfind, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmtfind, 1, uuid, -1, SQLITE_STATIC);
        if (sqlite3_step(stmtfind) == SQLITE_ROW) {
            const unsigned char* text = sqlite3_column_text(stmtfind, 0);
            if (text) {
                strncpy(username_buf, (const char*)text, sizeof(username_buf) - 1);
                username_buf[sizeof(username_buf) - 1] = '\0';
                result = username_buf;
            }
        }
        sqlite3_finalize(stmtfind);
    }
    pthread_mutex_unlock(&db_lock);
    return result;
}

file_record_t find_file_by_minisig(char* sig) {
    sqlite3_stmt *stmtfind;
    file_record_t record = {0};

    pthread_mutex_lock(&db_lock);
    if (sqlite3_prepare_v2(db, "SELECT id, user, filename, resultpath FROM files WHERE minisig=?", -1, &stmtfind, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmtfind, 1, sig, -1, SQLITE_STATIC);
        if (sqlite3_step(stmtfind) == SQLITE_ROW) {
            record.id = sqlite3_column_int(stmtfind, 0);
            const unsigned char* text = sqlite3_column_text(stmtfind, 1);
            if (text) {
                strncpy(record.username, (const char*)text, sizeof(record.username) - 1);
                record.username[sizeof(record.username) - 1] = '\0';
            }
            strncpy(record.filename, (const char*)sqlite3_column_text(stmtfind, 2), sizeof(record.filename) - 1);
            record.filename[sizeof(record.filename) - 1] = '\0';
            strncpy(record.result_path, (const char*)sqlite3_column_text(stmtfind, 3), sizeof(record.result_path) - 1);
            record.result_path[sizeof(record.result_path) - 1] = '\0';
        }
        sqlite3_finalize(stmtfind);
    }
    pthread_mutex_unlock(&db_lock);
    return record;
}
char* find_file_path(char* uuid) {
    sqlite3_stmt *stmtfind;
    static char username_buf[STR_LENGTH];
    char* result = NULL;

    pthread_mutex_lock(&db_lock);
    if (sqlite3_prepare_v2(db, "SELECT filepath FROM files WHERE uniqid=?", -1, &stmtfind, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmtfind, 1, uuid, -1, SQLITE_STATIC);
        if (sqlite3_step(stmtfind) == SQLITE_ROW) {
            const unsigned char* text = sqlite3_column_text(stmtfind, 0);
            if (text) {
                strncpy(username_buf, (const char*)text, sizeof(username_buf) - 1);
                username_buf[sizeof(username_buf) - 1] = '\0';
                result = username_buf;
            }
        }
        sqlite3_finalize(stmtfind);
    }
    pthread_mutex_unlock(&db_lock);
    return result;
}
#define UUID_STR_LEN 37
char* uuid(char out[UUID_STR_LEN]){
  uuid_t b;
  uuid_generate(b);
  uuid_unparse_lower(b, out);
  return out;
}
void update_file_minisig(char* user, char* filename, char* minisig) {
    sqlite3_stmt *stmt;
    pthread_mutex_lock(&db_lock);
    if (sqlite3_prepare_v2(db, "UPDATE files SET minisig=? WHERE user=? AND filename=?", -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, minisig, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, user, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, filename, -1, SQLITE_STATIC);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
    pthread_mutex_unlock(&db_lock);
}
void add_file_if_not_exists(char* user, char* filename, char* filepath, char* resultpath) {
    sqlite3_stmt *stmtfind;
    int found = 0;

    pthread_mutex_lock(&db_lock);
    if (sqlite3_prepare_v2(db, "SELECT id FROM files WHERE user=? AND filename=?", -1, &stmtfind, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmtfind, 1, user, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmtfind, 2, filename, -1, SQLITE_STATIC);
        if (sqlite3_step(stmtfind) == SQLITE_ROW) {
            found = sqlite3_column_int(stmtfind, 0);
        }
        sqlite3_finalize(stmtfind);
    }
    pthread_mutex_unlock(&db_lock);

    if(found == 0) {
        char out[UUID_STR_LEN]={0};
        char uuidv[UUID_STR_LEN+1];
        (void)snprintf(uuidv, sizeof uuidv, "%s", uuid(out));
        sqlite3_stmt *stmt;
        pthread_mutex_lock(&db_lock);
        if (sqlite3_prepare_v2(db, "INSERT OR IGNORE INTO files(user, filename, filepath, resultpath, uniqid) VALUES (?, ?, ?, ?, ?)", -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, user, -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, filename, -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 3, filepath, -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 4, resultpath, -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, MIN_OFFSET, uuidv, -1, SQLITE_STATIC);

            sqlite3_step(stmt);
            sqlite3_changes(db);
            sqlite3_finalize(stmt);
        }
        pthread_mutex_unlock(&db_lock);
    }
}

// Functie pentru a gasi un virus dupa hash
virus_t find_virus_by_hash(char* hash) {
    sqlite3_stmt *stmt;
    virus_t result = {0};
    result.found = 0;
    result.knownfile[0] = '\0';
    result.signature[0] = '\0';

    pthread_mutex_lock(&db_lock);

    if (sqlite3_prepare_v2(db, "SELECT original_name, signature FROM viruses WHERE hash=?", -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&db_lock);
        return result;
    }

    sqlite3_bind_text(stmt, 1, hash, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char* name = sqlite3_column_text(stmt, 0);
        const unsigned char* signature = sqlite3_column_text(stmt, 1);
        
        strncpy(result.knownfile, (const char*)name, sizeof(result.knownfile) - 1);
        strncpy(result.signature, (const char*)signature, sizeof(result.signature) - 1);
        if(result.knownfile[strlen(result.knownfile)-1] == '\n') {
            result.knownfile[strlen(result.knownfile)-1] = '\0';
        }
        if(result.signature[strlen(result.signature)-1] == '\n') {
            result.signature[strlen(result.signature)-1] = '\0';
        }
        result.found = 1;
    }

    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&db_lock); 

    return result;
}

// Functie pentru a adauga un virus in baza de date
void insert_virus(char* original_name, char* signature, char* hash) {
    sqlite3_stmt *stmt;
    pthread_mutex_lock(&db_lock);

    if (sqlite3_prepare_v2(db, "INSERT OR IGNORE INTO viruses(original_name, signature, hash) VALUES (?, ?, ?)", -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&db_lock);
        return;
    }
    sqlite3_bind_text(stmt, 1, original_name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, signature, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, hash, -1, SQLITE_STATIC);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&db_lock);
}


// Functie care initializeaza scanner-ul cu pattern-urile date
void scanner_init(void) {
    g_scanner = scanner_create();
    if (!g_scanner) {
        (void)fprintf(stderr, "[scanner] failed to create scanner\n");
        return;
    }

    scanner_add_pattern(g_scanner, "eval\\(base64_decode",              "php_obfuscation");
    scanner_add_pattern(g_scanner, "eval\\(gzinflate",                  "php_obfuscation");
    scanner_add_pattern(g_scanner, "eval\\(gzuncompress",               "php_obfuscation");
    scanner_add_pattern(g_scanner, "eval\\(str_rot13",                  "php_obfuscation");
    scanner_add_pattern(g_scanner, "eval\\(rawurldecode",               "php_obfuscation");
    scanner_add_pattern(g_scanner, "assert\\(base64_decode",            "php_obfuscation");
    scanner_add_pattern(g_scanner, "preg_replace.*\\/e",                "php_obfuscation");
    scanner_add_pattern(g_scanner, "create_function\\(",                "php_obfuscation");
    scanner_add_pattern(g_scanner, "call_user_func\\(base64",           "php_obfuscation");

    scanner_add_pattern(g_scanner, "eval\\(unescape",                   "js_obfuscation");
    scanner_add_pattern(g_scanner, "eval\\(atob",                       "js_obfuscation");
    scanner_add_pattern(g_scanner, "eval\\(String\\.fromCharCode",      "js_obfuscation");
    scanner_add_pattern(g_scanner, "document\\.write\\(unescape",       "js_obfuscation");
    scanner_add_pattern(g_scanner, "document\\.write\\(atob",           "js_obfuscation");
    scanner_add_pattern(g_scanner, "setTimeout\\(\"eval",               "js_obfuscation");
    scanner_add_pattern(g_scanner, "setInterval\\(\"eval",              "js_obfuscation");
    scanner_add_pattern(g_scanner, "window\\[\"eval\"\\]",              "js_obfuscation");

    scanner_add_pattern(g_scanner, "powershell\\s+-enc",                "powershell");
    scanner_add_pattern(g_scanner, "powershell\\s+-nop",                "powershell");
    scanner_add_pattern(g_scanner, "powershell\\s+-w\\s+hidden",        "powershell");
    scanner_add_pattern(g_scanner, "powershell\\s+-exec\\s+bypass",     "powershell");
    scanner_add_pattern(g_scanner, "IEX\\(New-Object",                  "powershell");
    scanner_add_pattern(g_scanner, "Invoke-Expression",                 "powershell");
    scanner_add_pattern(g_scanner, "Invoke-Mimikatz",                   "powershell");
    scanner_add_pattern(g_scanner, "Invoke-Shellcode",                  "powershell");
    scanner_add_pattern(g_scanner, "\\[Convert\\]::FromBase64String",   "powershell");
    scanner_add_pattern(g_scanner, "-EncodedCommand",                   "powershell");
    scanner_add_pattern(g_scanner, "DownloadString\\(",                 "powershell");
    scanner_add_pattern(g_scanner, "DownloadFile\\(",                   "powershell");

    scanner_add_pattern(g_scanner, "vssadmin delete shadows",           "ransomware");
    scanner_add_pattern(g_scanner, "bcdedit /set recoveryenabled",      "ransomware");
    scanner_add_pattern(g_scanner, "wbadmin delete catalog",            "ransomware");
    scanner_add_pattern(g_scanner, "shadowcopy delete",                 "ransomware");
    scanner_add_pattern(g_scanner, "YOUR_FILES_ARE_ENCRYPTED",          "ransomware");
    scanner_add_pattern(g_scanner, "HOW_TO_DECRYPT",                    "ransomware");
    scanner_add_pattern(g_scanner, "README_DECRYPT",                    "ransomware");
    scanner_add_pattern(g_scanner, "DECRYPT_INSTRUCTIONS",              "ransomware");
    scanner_add_pattern(g_scanner, "\\.locked$",                        "ransomware");
    scanner_add_pattern(g_scanner, "\\.encrypted$",                     "ransomware");
    scanner_add_pattern(g_scanner, "\\.crypted$",                       "ransomware");

    scanner_add_pattern(g_scanner, "CreateRemoteThread",                "injection");
    scanner_add_pattern(g_scanner, "WriteProcessMemory",                "injection");
    scanner_add_pattern(g_scanner, "VirtualAlloc",                      "injection");
    scanner_add_pattern(g_scanner, "VirtualAllocEx",                    "injection");
    scanner_add_pattern(g_scanner, "NtUnmapViewOfSection",              "injection");
    scanner_add_pattern(g_scanner, "ZwUnmapViewOfSection",              "injection");
    scanner_add_pattern(g_scanner, "QueueUserAPC",                      "injection");
    scanner_add_pattern(g_scanner, "SetThreadContext",                  "injection");
    scanner_add_pattern(g_scanner, "RtlCreateUserThread",               "injection");
    scanner_add_pattern(g_scanner, "NtCreateThreadEx",                  "injection");

    scanner_add_pattern(g_scanner, "/bin/bash\\s+-i\\s+>&",            "reverse_shell");
    scanner_add_pattern(g_scanner, "nc\\s+-e\\s+/bin/",                "reverse_shell");
    scanner_add_pattern(g_scanner, "ncat\\s+-e\\s+/bin/",              "reverse_shell");
    scanner_add_pattern(g_scanner, "0<&196;exec\\s+196<>/dev/tcp/",    "reverse_shell");
    scanner_add_pattern(g_scanner, "socat\\s+exec:bash",               "reverse_shell");
    scanner_add_pattern(g_scanner, "python.*import\\s+socket",         "reverse_shell");
    scanner_add_pattern(g_scanner, "perl.*use\\s+Socket",              "reverse_shell");
    scanner_add_pattern(g_scanner, "ruby.*require.*socket",            "reverse_shell");

    scanner_add_pattern(g_scanner, "wget\\s+http.*-O\\s+/tmp/",        "dropper");
    scanner_add_pattern(g_scanner, "curl\\s+-o\\s+/tmp/",              "dropper");
    scanner_add_pattern(g_scanner, "chmod\\s+\\+x\\s+/tmp/",           "dropper");
    scanner_add_pattern(g_scanner, "exec\\s+/tmp/",                    "dropper");
    scanner_add_pattern(g_scanner, "mv\\s+/tmp/.*&&",                  "dropper");
    scanner_add_pattern(g_scanner, "curl.*\\|\\s*bash",                "dropper");
    scanner_add_pattern(g_scanner, "wget.*\\|\\s*bash",                "dropper");

    scanner_add_pattern(g_scanner, "stratum\\+tcp://",                  "cryptominer");
    scanner_add_pattern(g_scanner, "stratum\\+ssl://",                  "cryptominer");
    scanner_add_pattern(g_scanner, "mining\\.subscribe",                "cryptominer");
    scanner_add_pattern(g_scanner, "xmrig",                             "cryptominer");
    scanner_add_pattern(g_scanner, "minerd",                            "cryptominer");
    scanner_add_pattern(g_scanner, "cryptonight",                       "cryptominer");
    scanner_add_pattern(g_scanner, "nicehash",                          "cryptominer");
    scanner_add_pattern(g_scanner, "coinhive",                          "cryptominer");

    scanner_add_pattern(g_scanner, "<\\?php\\s+eval\\(",                "webshell");
    scanner_add_pattern(g_scanner, "<\\?php\\s+system\\(",              "webshell");
    scanner_add_pattern(g_scanner, "<\\?php\\s+passthru\\(",            "webshell");
    scanner_add_pattern(g_scanner, "<\\?php\\s+shell_exec\\(",          "webshell");
    scanner_add_pattern(g_scanner, "<\\?php\\s+popen\\(",               "webshell");
    scanner_add_pattern(g_scanner, "<\\?php\\s+proc_open\\(",           "webshell");
    scanner_add_pattern(g_scanner, "c99shell",                          "webshell");
    scanner_add_pattern(g_scanner, "r57shell",                          "webshell");
    scanner_add_pattern(g_scanner, "b374k",                             "webshell");

    scanner_add_pattern(g_scanner, "mimikatz",                          "credential_steal");
    scanner_add_pattern(g_scanner, "sekurlsa::logonpasswords",          "credential_steal");
    scanner_add_pattern(g_scanner, "lsass\\.exe",                       "credential_steal");
    scanner_add_pattern(g_scanner, "SAM\\s+database",                   "credential_steal");
    scanner_add_pattern(g_scanner, "/etc/shadow",                       "credential_steal");
    scanner_add_pattern(g_scanner, "pass_the_hash",                     "credential_steal");
    scanner_add_pattern(g_scanner, "golden_ticket",                     "credential_steal");
    scanner_add_pattern(g_scanner, "DCSync",                            "credential_steal");
    scanner_add_pattern(g_scanner, "kerberoast",                        "credential_steal");

    scanner_add_pattern(g_scanner, "CurrentVersion\\\\Run",             "persistence");
    scanner_add_pattern(g_scanner, "CurrentVersion\\\\RunOnce",         "persistence");
    scanner_add_pattern(g_scanner, "Winlogon\\\\Shell",                 "persistence");
    scanner_add_pattern(g_scanner, "AppInit_DLLs",                      "persistence");
    scanner_add_pattern(g_scanner, "schtasks\\s+/create",               "persistence");
    scanner_add_pattern(g_scanner, "sc\\s+create",                      "persistence");
    scanner_add_pattern(g_scanner, "Image File Execution Options",       "persistence");

    scanner_add_pattern(g_scanner, "/etc/crontab",                      "persistence");
    scanner_add_pattern(g_scanner, "/etc/rc\\.local",                   "persistence");
    scanner_add_pattern(g_scanner, "~/.bashrc",                         "persistence");
    scanner_add_pattern(g_scanner, "LaunchAgents",                      "persistence");
    scanner_add_pattern(g_scanner, "LaunchDaemons",                     "persistence");
    scanner_add_pattern(g_scanner, "LD_PRELOAD",                        "persistence");
    scanner_add_pattern(g_scanner, "/etc/init\\.d/",                    "persistence");

    scanner_add_pattern(g_scanner, "IsDebuggerPresent",                 "evasion");
    scanner_add_pattern(g_scanner, "CheckRemoteDebuggerPresent",        "evasion");
    scanner_add_pattern(g_scanner, "NtQueryInformationProcess",         "evasion");
    scanner_add_pattern(g_scanner, "ZwQueryInformationProcess",         "evasion");
    scanner_add_pattern(g_scanner, "OutputDebugString",                 "evasion");
    scanner_add_pattern(g_scanner, "GetTickCount",                      "evasion");
    scanner_add_pattern(g_scanner, "timing_attack",                     "evasion");
    scanner_add_pattern(g_scanner, "anti_sandbox",                      "evasion");
    scanner_add_pattern(g_scanner, "anti_vm",                           "evasion");

    scanner_add_pattern(g_scanner, "regsvr32\\s+/s\\s+/n\\s+/u",       "fileless");
    scanner_add_pattern(g_scanner, "mshta\\s+http",                     "fileless");
    scanner_add_pattern(g_scanner, "wmic\\s+process\\s+call\\s+create", "fileless");
    scanner_add_pattern(g_scanner, "certutil\\s+-decode",               "fileless");
    scanner_add_pattern(g_scanner, "rundll32.*javascript",              "fileless");
    scanner_add_pattern(g_scanner, "pcalua\\.exe",                      "fileless");
    scanner_add_pattern(g_scanner, "cmstp\\.exe",                       "fileless");

    scanner_add_pattern(g_scanner, "dns_tunnel",                        "c2");
    scanner_add_pattern(g_scanner, "icmp_tunnel",                       "c2");
    scanner_add_pattern(g_scanner, "domain_fronting",                   "c2");
    scanner_add_pattern(g_scanner, "fast_flux",                         "c2");
    scanner_add_pattern(g_scanner, "ngrok\\.io",                        "c2");
    scanner_add_pattern(g_scanner, "cobalt\\s*strike",                  "c2");
    scanner_add_pattern(g_scanner, "meterpreter",                       "c2");
    scanner_add_pattern(g_scanner, "beacon\\s+sleep",                   "c2");

    scanner_add_pattern(g_scanner, "Auto_Open",                         "macro");
    scanner_add_pattern(g_scanner, "AutoOpen",                          "macro");
    scanner_add_pattern(g_scanner, "AutoExec",                          "macro");
    scanner_add_pattern(g_scanner, "Document_Open",                     "macro");
    scanner_add_pattern(g_scanner, "CreateObject\\(\"WScript",          "macro");
    scanner_add_pattern(g_scanner, "CreateObject\\(\"Shell",            "macro");
    scanner_add_pattern(g_scanner, "Shell\\(\"cmd\\.exe",               "macro");

    scanner_add_pattern(g_scanner, "heap_spray",                        "exploit");
    scanner_add_pattern(g_scanner, "use_after_free",                    "exploit");
    scanner_add_pattern(g_scanner, "buffer_overflow",                   "exploit");
    scanner_add_pattern(g_scanner, "ROP\\s+chain",                      "exploit");
    scanner_add_pattern(g_scanner, "ret2libc",                          "exploit");
    scanner_add_pattern(g_scanner, "format_string",                     "exploit");
    scanner_add_pattern(g_scanner, "EternalBlue",                       "exploit");
    scanner_add_pattern(g_scanner, "MS17-010",                          "exploit");
    scanner_add_pattern(g_scanner, "CVE-20",                            "exploit");
}

void scanner_cleanup(void) {
    scanner_destroy(g_scanner);
    g_scanner = NULL;
}

int compute_time(const char *str) {
    if(!str) {
        return 0;
    }
    int time = 0;
    int i = 0;
    while(i<(int)strlen(str)) {
        if(isdigit(str[i])) {
            time = time*MIN_OFFSET*2 + str[i] - '0';
        }
        else {
            switch(str[i]) {
                case 'm':
                    time *= SECONDS_IN_MINUTE;
                    return time; 
                    break;
                case 'h':
                    time *= SECONDS_IN_HOUR;
                    return time; 
                    break;
                case 'd':
                    time *= SECONDS_IN_DAY;
                    return time; 
                    break;
                case 'w':
                    time *= (MIN_OFFSET+2) * SECONDS_IN_DAY;
                    return time; 
                    break;
                case 'M':
                    time *= (MIN_OFFSET*MIN_OFFSET+MIN_OFFSET) * SECONDS_IN_DAY;
                    return time; 
                    break;
                case 'y':
                    time *= DAYS_IN_YEAR * SECONDS_IN_DAY;
                    return time; 
                    break;
                default:
                    return 0; // Invalid character
            }
        }
        i++;
    }
    return time;
    
}

void* backup_server(void* arg) {
    (void)arg;
    while(1) {
        sleep(1); // NOLINT - this is not a busy wait, we want to check every second if there are backups to be made
        char script_username[STR_LENGTH];
        char script_path[STR_LENGTH];
        time_t time_now = time(NULL);
        pthread_mutex_lock(&db_lock);
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(db, "SELECT username, backup FROM users WHERE backup!=0", -1, &stmt, NULL) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const unsigned char *username = sqlite3_column_text(stmt, 0);
                int backup = sqlite3_column_int(stmt, 1);
                if(time_now%backup == 0) {
                    (void)snprintf(script_username, sizeof(script_username), 
                    "for f in ./fce/outgoing/%s/*.txt; do "
                    "cp \"$f\" \"./fce/outgoing/%s/backup/$(basename \"$f\").bak\"; "
                    "done 2>/dev/null", username, username);

                    (void)snprintf(script_path, sizeof(script_path), "./fce/outgoing/%s/backup", username);
                    mkdir(script_path, FULL_PERM);
                    pid_t pid = fork();
                    if(pid == 0) {
                        execlp("sh", "sh", "-c",
                        script_username,
                        (char *)NULL);
                        perror("execlp failed");
                        exit(EXIT_FAILURE); // NOLINT - if execlp fails, we want to exit the child process
                    }
                    
                }
            }
            sqlite3_finalize(stmt);
        }
        pthread_mutex_unlock(&db_lock);
    }
    return NULL;
}

void *cleanup_server(void* arg) {
    (void)arg;
    while(1) {
        sleep(60); // NOLINT - this is not a busy wait, we want to check every second if there are files to be cleaned up
        char script_username[STR_LENGTH];
        time_t time_now = time(NULL);
        pthread_mutex_lock(&db_lock);
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(db, "SELECT username, cleanup FROM users WHERE cleanup!=0", -1, &stmt, NULL) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const unsigned char *username = sqlite3_column_text(stmt, 0);
                int cleanup = sqlite3_column_int(stmt, 1);
                (void)snprintf(script_username, sizeof(script_username), 
                "./fce/outgoing/%s", username);
                
                DIR* dir = opendir(script_username);
                if(dir) {
                    struct dirent* entry;
                    while((entry = readdir(dir)) != NULL) { // NOLINT safe 
                        if (strcmp(entry->d_name, ".") == 0 ||
                            strcmp(entry->d_name, "..") == 0 ||
                            entry->d_name[0] == '.') 
                            continue;
                        char filepath[STR_LENGTH*2];
                        (void)snprintf(filepath, sizeof(filepath), "%s/%s", script_username, entry->d_name);
                        struct stat st;
                        if (stat(filepath, &st) == 0 && S_ISREG(st.st_mode)) {
                            if (time_now - st.st_mtime > cleanup) {
                                unlink(filepath);
                            }
                        }
                        sqlite3_stmt *stmt_delete;
                        if (sqlite3_prepare_v2(db, "DELETE FROM files WHERE user=? AND filename=?", -1, &stmt_delete, NULL) == SQLITE_OK) {
                            sqlite3_bind_text(stmt_delete, 1, (const char*)username, -1, SQLITE_STATIC);
                            sqlite3_bind_text(stmt_delete, 2, entry->d_name, -1, SQLITE_STATIC);
                            sqlite3_step(stmt_delete);
                            sqlite3_finalize(stmt_delete);
                        }
                    }
                    
                }
            }
            sqlite3_finalize(stmt);
        }
        pthread_mutex_unlock(&db_lock);
    }
    return NULL;
}
// Functia principala a serverului
int main(int argc, char *argv[]) {
    // Ignoram SIGPIPE (crash daca incercam sa scriem pe un socket inchis)
    (void)signal(SIGPIPE, SIG_IGN);
    // Cream directoarele necesare pentru fisierele in asteptare si cele procesate
    mkdir("fce", FULL_PERM);
    mkdir("fce/processing", FULL_PERM);
    mkdir("fce/outgoing", FULL_PERM);

    // Initializam scanner-ul
    scanner_init();

    worker_start(4);  // Pornim workerii pt procesare

    cp_worker_start(3); // Pornim workerii pt copiere

    // Deschidem baza de date
    if (sqlite3_open("users.db", &db) != SQLITE_OK) {
        (void)fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        return 1;
    }
    // Cream tabelele necesare in baza de date daca nu exista deja
    char *sql_create_users = "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT UNIQUE NOT NULL,password TEXT NOT NULL,role TEXT NOT NULL, loggedin INTEGER DEFAULT 0, backup INTEGER DEFAULT 0, cleanup INTEGER DEFAULT 0);";

    char *sql_create_logs = "CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT NOT NULL, action TEXT NOT NULL, time DATETIME DEFAULT CURRENT_TIMESTAMP);";
    char *sql_create_bans = "CREATE TABLE IF NOT EXISTS bans (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT UNIQUE NOT NULL, banned_by TEXT NOT NULL, time DATETIME DEFAULT CURRENT_TIMESTAMP);";

    char *sql_clear_logs = "DELETE FROM logs; DELETE sqlite_sequence WHERE name='logs';";


    char *sql_create_viruses = "CREATE TABLE IF NOT EXISTS viruses(id INTEGER PRIMARY KEY AUTOINCREMENT, hash TEXT, original_name TEXT, signature TEXT);";

    char *sql_index = "CREATE INDEX IF NOT EXISTS idx_hash ON viruses(hash);";

    char *sql_create_files = "CREATE TABLE IF NOT EXISTS files(id INTEGER PRIMARY KEY AUTOINCREMENT, user TEXT, filename TEXT, uniqid TEXT UNIQUE, filepath TEXT, resultpath TEXT, minisig TEXT);";

    int opt;
    struct option long_options[] = { // Parsarea argumentelor din linia de comanda
        {"clearlogs", no_argument, 0, 'c'},
        {"unixsocket", no_argument, 0, 'u'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    int logs = 0;
    int unixsocket = 0;
    while((opt = getopt_long(argc, argv, "cuh", long_options, NULL)) != -1) { // NOLINT - getopt is not thread safe, but this is before any threads are created
        switch (opt) {
            case 'c':
                logs = 1;
                break;
            case 'u':
                unixsocket = 1;
                break;
            case 'h':
                (void)printf("Usage: %s [OPTIONS]\n\n"
                       "Options:\n"
                       "  --clear-logs           Clear all logs from the database\n"
                       "  --unixsocket           Use Unix domain sockets instead of TCP/IP\n"
                       "  --help                  Display this help message\n",
                       argv[0]);
                return 0;
            default:
                return 1;
        }
    }
    if(unixsocket) {
        unix_based_socket = 1;
    }

    char *errmsg;

    // Executam toate comenzile SQL
    pthread_mutex_lock(&db_lock);
    if(logs) {
        if (sqlite3_exec(db, sql_clear_logs, 0, 0, &errmsg) != SQLITE_OK) {
            (void)fprintf(stderr, "SQL error: %s\n", errmsg);
            sqlite3_free(errmsg);
        } else {
            (void)fprintf(stdout, "Logs cleared successfully.\n");
        }
    }
    if (sqlite3_exec(db, sql_create_bans, 0, 0, &errmsg) != SQLITE_OK) {
        (void)fprintf(stderr, "SQL error: %s\n", errmsg);
        sqlite3_free(errmsg);
    }

    if (sqlite3_exec(db, sql_create_files, 0, 0, &errmsg) != SQLITE_OK) {
        (void)fprintf(stderr, "SQL error: %s\n", errmsg);
        sqlite3_free(errmsg);
    }

    if (sqlite3_exec(db, sql_create_viruses, 0, 0, &errmsg) != SQLITE_OK) {
        (void)fprintf(stderr, "SQL error: %s\n", errmsg);
        sqlite3_free(errmsg);
    }

    
    if (sqlite3_exec(db, sql_index, 0, 0, &errmsg) != SQLITE_OK) {
        (void)fprintf(stderr, "SQL error: %s\n", errmsg);
        sqlite3_free(errmsg);
    }
    if (sqlite3_exec(db, sql_create_users, 0, 0, &errmsg) != SQLITE_OK) {
        (void)fprintf(stderr, "SQL error: %s\n", errmsg);
        sqlite3_free(errmsg);
    }
    if (sqlite3_exec(db, sql_create_logs, 0, 0, &errmsg) != SQLITE_OK) {
        (void)fprintf(stderr, "SQL error: %s\n", errmsg);
        sqlite3_free(errmsg);
    }
   

    pthread_mutex_unlock(&db_lock);
    (void)time(&start_time);

    // Cream pipe-ul pentru logger
    if (pipe(log_pipe) == -1) {
        perror("Pipe failed");
        return 1;
    }
    // Pornim thread-ul pentru logger
    pthread_t logger_tid;
    pthread_create(&logger_tid, NULL, logger_thread_func, NULL);
    pthread_detach(logger_tid);


    //Pornim thread-urile pentru servere si le detasam (Nu trebuie sa le asteptam)

    pthread_t t1, t2, t3, t4, t5;
    pthread_create(&t1, NULL, user_server, NULL);
    pthread_create(&t2, NULL, admin_server, NULL);
    pthread_create(&t3, NULL, web_server, NULL);
    pthread_create(&t4, NULL, cleanup_server, NULL);
    pthread_create(&t5, NULL, backup_server, NULL);

    pthread_detach(t1);
    pthread_detach(t2);
    pthread_detach(t3);
    pthread_detach(t4);
    pthread_detach(t5);

    //Mentinem main thread-ul in viata pana cand serverul este oprit
    while (running)
    {
        sleep(1); // NOLINT
    }
    pthread_kill(t4, SIGSTOP); // Oprim thread-ul pentru cleanup server
    pthread_kill(t5, SIGSTOP); // Oprim thread-ul pentru backup server
    // Apelam cleanup-ul pentru toate componentele
    worker_stop();
    cp_worker_stop();
    scanner_cleanup();
    sqlite3_close(db);
    return 0;
}




