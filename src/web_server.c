/*
    web_server.c - Implementarea serviciilor web
    Acest modul se ocupa cu toate http request-urile avand `celeasi capabilitati de procesare ca si thread-ul pentru utilizatori simpli
    Parsarea se face manual a fiecarui request

    Erori tratate:
    * Erori de creare/bind/linsten socket
    * Erori de procesare are fisier-ului
    * Erori de procesare ale request-ului
*/

// Constante redefinite in caz ca nu exista deja din alt header
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
#ifndef WEB_PORT
#define WEB_PORT 8081
#endif

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
#include <sys/un.h> // Pentru socket unix
#include <arpa/inet.h>
#include <poll.h>
#include <errno.h>
#include "headers/sha256.h"


// Constante pentru timeout-uri si cod-uri de eroare
#define WEB_TIMEOUT 2000   
#define BAD_RQ 400
#define NOT_FOUND 404
#define INTERNAL_ERR 500
#define UNAUTHORIZED 401
#define FORBIDDEN 403


#include "headers/server.h"
#include "headers/cp_worker.h"  




extern int running;



// Necesar pentru request-uri sa stie ce tip de date trimite
char *get_mime_type(char *filename) {
    char *ext = strrchr(filename, '.');
    if (!ext) return "application/octet-stream";

    if (strcmp(ext, ".html") == 0) return "text/html";
    if (strcmp(ext, ".js") == 0) return "application/javascript";
    if (strcmp(ext, ".css") == 0) return "text/css";
    if (strcmp(ext, ".json") == 0) return "application/json";
    if (strcmp(ext, ".png") == 0) return "image/png";
    if (strcmp(ext, ".jpg") == 0 || strcmp(ext, ".jpeg") == 0) return "image/jpeg";
    if (strcmp(ext, ".gif") == 0) return "image/gif";
    if (strcmp(ext, ".svg") == 0) return "image/svg+xml";
    if (strcmp(ext, ".txt") == 0) return "text/plain";

    return "application/octet-stream";
}


// Calculeaza unde e boundary-ul pentru form-urile multipart formdata
char *get_boundary(char *header_block) {
    char *start = strstr(header_block, "boundary=");
    if (!start) return NULL;
    start += MIN_OFFSET + 4;
    char *end = start + strcspn(start, "\r\n;");
    size_t boundary_len = (end - start) + 3;
    char *boundary = malloc(boundary_len);
    (void)snprintf(boundary, boundary_len, "--%.*s", (int)(end - start), start);
    return boundary;
}


// Returneaza marimea request-ului
size_t get_content_length(char *buffer) {
    char *ptr = strstr(buffer, "Content-Length: ");
    if (!ptr) return 0;
    ptr += MIN_OFFSET * 3 + 1;
    return (size_t)atol(ptr);
}


// Functie pentru a extrage token-ul din cookie
static char *extract_token(const char *buffer, int cfd) {
    char *cookie_header = strstr(buffer, "Cookie: "); // Daca nu gasim acest punct iesim pentru ca nu exista cookie
    if (!cookie_header) return NULL;

    char *t_ptr = NULL;

    if (strstr(cookie_header, "csrftoken")) { // Daca exista acest csrftoken cautam token-ul din nou
        t_ptr = strstr(cookie_header, "; token=");
        if (!t_ptr) { 
            const char *error_body = "{\"success\":false}"; // Daca nu se gaseste token-ul jwt (setat de noi) ii returnam eroare
            char response[BUF];
            (void)snprintf(response, sizeof(response),
                     "HTTP/1.1 401 Unauthorized\r\n"
                     "Content-Type: application/json\r\n"
                     "Content-Length: %zu\r\n\r\n%s",
                     strlen(error_body), error_body);
            (void)safe_write(cfd, response, strlen(response));
            return NULL;
        }
        t_ptr += MIN_OFFSET + 3; // Altfel sarim peste 8 caractere(; token=)
    } else { // Daca nu gasim csrftoken in cookie
        t_ptr = strstr(cookie_header, "token="); // Cautam direct token= 
        if (!t_ptr) { // Daca nu-l gasim e eroare
            const char *error_body = "{\"success\":false}";
            char response[BUF];
            (void)snprintf(response, sizeof(response),
                     "HTTP/1.1 401 Unauthorized\r\n"
                     "Content-Type: application/json\r\n"
                     "Content-Length: %zu\r\n\r\n%s",
                     strlen(error_body), error_body);
            (void)safe_write(cfd, response, strlen(response));
            return NULL;
        }
        t_ptr += MIN_OFFSET + 1; // Daca-l gasim sarim peste 6 caractere (token=)
    }

    static char t_val[STR_LENGTH * 2];
    (void)sscanf(t_ptr, "%[^;\r\n ]", t_val); // Salvam token-ul in t_var, daca gaseste oricare din caracterele listate se opreste
    return t_val;
}


// Functie pentru a trimite mesaj de eroare 401
static void send_unauthorized(int cfd) {
    const char *error_body = "{\"success\":false}";
    char response[BUF];
    (void)snprintf(response, sizeof(response),
             "HTTP/1.1 401 Unauthorized\r\n"
             "Content-Type: application/json\r\n"
             "Content-Length: %zu\r\n\r\n%s",
             strlen(error_body), error_body);
    (void)safe_write(cfd, response, strlen(response));
}

// Functie care trimite mesaj de eroare dat de noi prin cod
static void send_error(int cfd, int code) {
    const char *msg;
    switch (code) {
        case BAD_RQ: msg = "Bad Request";            break;
        case UNAUTHORIZED: msg = "Unauthorized";           break;
        case FORBIDDEN: msg = "Forbidden";              break;
        case NOT_FOUND: msg = "Not Found";              break;
        case INTERNAL_ERR: msg = "Internal Server Error";  break;
        default:  msg = "Unknown";                break;
    }

    char body[STR_LENGTH/2];
    int body_len = snprintf(body, sizeof(body),
        "{\"success\":false,\"message\":\"%s\"}", msg);

    char response[STR_LENGTH];
    int response_len = snprintf(response, sizeof(response),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Content-Length: %d\r\n\r\n%s",
        code, msg, body_len, body);

    (void)safe_write(cfd, response, response_len);
}

// Functie care face fetch la fisiere si returneaza status-ul
void get_file_status(const char* filename, const char* username, char *out, size_t out_size) {
    char path[STR_LENGTH];
    struct stat st;

    if (strchr(filename, '/') || strstr(filename, "..") ||
        strchr(username, '/') || strstr(username, "..")) {
        (void)snprintf(out, out_size, "invalid");
        return;
    }

    (void)snprintf(path, sizeof(path), "./fce/processing/%s/%s", username, filename); // Daca fisierul este in processing inseamna ca este in curs de procesare
    if (stat(path, &st) == 0) { (void)snprintf(out, out_size, "queued"); return; }

    
    (void)snprintf(path, sizeof(path), "./fce/%s/%s.tmp", username, filename); // Daca exista fisier-ul cu extensia tmp inseamna ca este in curs de copiere, tot ca si queued e
    if (stat(path, &st) == 0) { (void)snprintf(out, out_size, "queued"); return; }

    (void)snprintf(path, sizeof(path), "./fce/outgoing/%s/result_%s.txt", username, filename); // Daca se afla in outgoing inseamna ca a fost scanat
    if (stat(path, &st) == 0) {
        char read_buffer[STR_LENGTH/2+1];
        int fd = open(path, O_RDONLY);
        if(fd < 0)  {(void)snprintf(out, out_size, "scanned"); return; }
        ssize_t n = read(fd, read_buffer, STR_LENGTH/2-1);
        read_buffer[STR_LENGTH/2] = 0;
        if(n>0) {
            if(strstr(read_buffer, "Job cancelled by an administrator!") != NULL)
            { 
                close(fd);
                (void)snprintf(out, out_size, "cancelled"); return; 
            }
        }

        close(fd);
        (void)snprintf(out, out_size, "scanned"); return; 

    }

    (void)snprintf(out, out_size, "available"); // Daca nu, inseamna ca e available (nu e nioci in curs de procesare, nici scanat)
}

// Aceasta functie se ocupa de handling-ul efectiv al request-urilor
static void handle_web_request(int cfd, char *buffer, size_t n) {
    buffer[n] = 0;

    char method[MIN_OFFSET * 2], reqpath[STR_LENGTH];
    (void)sscanf(buffer, "%s %255s", method, reqpath); // Se citeste metoda si locatia de request


    /* ── POST /api/auth/login ── */
    if (strcmp(method, "POST") == 0 && strcmp(reqpath, "/api/auth/login") == 0) { // Daca e metoda post si locatia api/auth/login
        char *body = strstr(buffer, "\r\n\r\n"); // Cautam unde incepe body-ul
        if (body) {
            body += 4; // Sarim peste caracterele de mai sus

            char username[STR_LENGTH] = {0};
            char password[STR_LENGTH] = {0};

            char *user_key = strstr(body, "\"username\":\""); // Vedem daca exista in body field-ul username
            if (user_key) { // Daca exista
                user_key += MIN_OFFSET * 2 + 2;
                char *end = strchr(user_key, '"'); // Vedem unde se termina
                if (end) {
                    size_t len = end - user_key;
                    if (len < sizeof(username) - 1) {
                        strncpy(username, user_key, len); // Copiem pana la acea locatie
                        username[len] = '\0';
                    }
                }
            }

            char *pass_key = strstr(body, "\"pwd\":\""); // asemanator pentru parola
            if (pass_key) {
                pass_key += MIN_OFFSET + 2;
                char *end = strchr(pass_key, '"');
                if (end) {
                    size_t len = end - pass_key;
                    if (len < sizeof(password) - 1) {
                        strncpy(password, pass_key, len);
                        password[len] = '\0';
                    }
                }
            }

            char response[BUF / 2];

            if (user_key == NULL || pass_key == NULL) { // Daca una dintre ele nu este gasita, returnam eroare (puteam pune badrequest dar nu m-am gandit atunci)
                const char *b = "{\"success\":false,\"message\":\"Invalid credentials\"}";
                (void)snprintf(response, sizeof(response),
                            "HTTP/1.1 404 Not found\r\n"
                            "Content-Type: application/json\r\n"
                            "Content-Length: %zu\r\n"
                            "Connection: close\r\n\r\n%s",
                            strlen(b), b);
            } else { // Daca totul exista aplicam logica de login
                int user_id = check_login(username, password, "user");
                if (user_id > 0) { // Daca user-ul a fost gasit
                    const char *jwt = create_jwt(user_id, "secret_jwt"); // Generam jwt
                    ensure_dir(username);

                    char cookie[STR_LENGTH * 2];
                    (void)snprintf(cookie, sizeof(cookie),
                                "Set-Cookie: token=%s; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600\r\n",
                                jwt); // Cream stringul pentru cookie
                    char b[STR_LENGTH * 2];
                    (void)snprintf(b, sizeof(b),
                                "{\"success\":true,\"user\":{\"id\":%d,\"username\":\"%s\"},\"message\":\"Logged in\"}",
                                user_id, username); // Cream raspunsul cu id-ul si username-ul gasit
                    (void)snprintf(response, sizeof(response),
                                "HTTP/1.1 200 OK\r\n"
                                "Content-Type: application/json\r\n"
                                "Content-Length: %zu\r\n"
                                "%s"
                                "Connection: close\r\n\r\n%s",
                                strlen(b), cookie, b); // Cream raspunsul intreg
                } else { // Daca nu ii spunem cu 401 ca nu a introdus credentialele bune
                    const char *b = "{\"success\":false,\"message\":\"Invalid credentials\"}";
                    (void)snprintf(response, sizeof(response),
                                "HTTP/1.1 401 Unauthorized\r\n"
                                "Content-Type: application/json\r\n"
                                "Content-Length: %zu\r\n"
                                "Connection: close\r\n\r\n%s",
                                strlen(b), b);
                }
            }
            (void)safe_write(cfd, response, strlen(response)); // Scriem raspunsul catre socket
        }
    }

    /* ── POST /api/auth/register ── */
    else if (strcmp(method, "POST") == 0 && strcmp(reqpath, "/api/auth/register") == 0) { // La fel ca la login
        char *body = strstr(buffer, "\r\n\r\n");
        if (body) {
            body += 4;

            char username[STR_LENGTH] = {0};
            char password[STR_LENGTH] = {0};

            char *user_key = strstr(body, "\"username\":\"");
            if (user_key) {
                user_key += MIN_OFFSET * 2 + 2;
                char *end = strchr(user_key, '"');
                if (end) {
                    size_t len = end - user_key;
                    if (len < sizeof(username) - 1) {
                        strncpy(username, user_key, len);
                        username[len] = '\0';
                    }
                }
            }

            char *pass_key = strstr(body, "\"pwd\":\"");
            if (pass_key) {
                pass_key += MIN_OFFSET + 2;
                char *end = strchr(pass_key, '"');
                if (end) {
                    size_t len = end - pass_key;
                    if (len < sizeof(password) - 1) {
                        strncpy(password, pass_key, len);
                        password[len] = '\0';
                    }
                }
            }

            char response[BUF / 2];

            if (user_key == NULL || pass_key == NULL) {
                const char *b = "{\"success\":false,\"message\":\"Invalid credentials\"}";
                (void)snprintf(response, sizeof(response),
                            "HTTP/1.1 404 Not found\r\n"
                            "Content-Type: application/json\r\n"
                            "Content-Length: %zu\r\n"
                            "Connection: close\r\n\r\n%s",
                            strlen(b), b);
            } else {
                int user_id = find_db_id(username); // Vetificam daca user-ul exista
                if (user_id == 0) {
                    add_user_hash(username, password, "user");
                    const char *b = "{\"success\":true,\"message\":\"User created\"}";
                    (void)snprintf(response, sizeof(response),
                                "HTTP/1.1 200 OK\r\n"
                                "Content-Type: application/json\r\n"
                                "Content-Length: %zu\r\n"
                                "Connection: close\r\n\r\n%s",
                                strlen(b), b);
                } else { // Daca exista returnam eroare
                    const char *b = "{\"success\":false,\"message\":\"User already exists!\"}";
                    (void)snprintf(response, sizeof(response),
                                "HTTP/1.1 401 Unauthorized\r\n"
                                "Content-Type: application/json\r\n"
                                "Content-Length: %zu\r\n"
                                "Connection: close\r\n\r\n%s",
                                strlen(b), b);
                }
            }
            (void)safe_write(cfd, response, strlen(response));
        }
    }

    /* ── GET /api/auth/me ── */
    else if (strcmp(method, "GET") == 0 && strcmp(reqpath, "/api/auth/me") == 0) { // Aceast endpoint este folosit pentru persistent login
        char *token = extract_token(buffer, cfd);
        if (token && verify_jwt(token, "secret_jwt") != NULL) { // Verifica daca exista si este valid token-ul
            char *user_dbid   = verify_jwt(token, "secret_jwt"); // Preia id-ul din token
            char *user_dbname = find_db_username(user_dbid); // Cauta user-ul

            char body_tpl[STR_LENGTH];
            (void)snprintf(body_tpl, sizeof(body_tpl),
                     "{\"success\":true,\"user\":{\"id\":%s,\"username\":\"%s\"}}",
                     user_dbid, user_dbname); // Parseaza raspunsul (partea json)

            char response[BUF];
            (void)snprintf(response, sizeof(response),
                     "HTTP/1.1 200 OK\r\n"
                     "Content-Type: application/json\r\n"
                     "Content-Length: %zu\r\n\r\n%s",
                     strlen(body_tpl), body_tpl); // Parseaza raspunsul intreg
            (void)safe_write(cfd, response, strlen(response));  // Scrie raspunsul
        } else {
            send_unauthorized(cfd); // Daca nu exista token-ul inseamna ca nu e logat sau ca e expirat
            // Folosesc asta in front ca sa-i dau logout automat
        }
    }

    /* ── GET /api/file ── */
    else if (strcmp(method, "GET") == 0 && strncmp(reqpath, "/api/file/", strlen("/api/file/")) == 0) { // Folosit pentru a descarca fisiere
        
        char *fileid = strdup(reqpath + strlen("/api/scan/"));
        char *filename = find_file_scanpath(fileid);
        char *basename = find_file_filename(fileid);

        free(fileid);

        if (strlen(filename) == 0 || strchr(basename, '/') || strstr(basename, "..")) {
            send_error(cfd, BAD_RQ);
        } else {
            (void)printf("Attempting to serve file: %s\n", filename);
            int fd = open(filename, O_RDONLY);
            if (fd < 0) {
                
                send_error(cfd, NOT_FOUND);
            } else {
                struct stat st;
                fstat(fd, &st);

                char header[STR_LENGTH];
                int header_len = snprintf(header, sizeof(header),
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: application/octet-stream\r\n"
                    "Content-Disposition: attachment; filename=\"result_%s.txt\"\r\n"
                    "Access-Control-Allow-Origin: *\r\n"
                    "Content-Length: %lld\r\n\r\n",
                    basename, (long long)st.st_size);
                (void)safe_write(cfd, header, header_len);

                char buf[BUF];
                ssize_t n;
                while ((n = read(fd, buf, sizeof(buf))) > 0)
                    (void)safe_write(cfd, buf, n); // Cat exista lucruri de citit scriem in buffer (file-ul e mic)

                close(fd);
            }
        }
        
    }
    else if (strcmp(method, "GET") == 0 && strcmp(reqpath, "/api/file") == 0) { // Acest endpoint returneaza fisierele incarcate de utilizator si status-ul acestora
        char *token = extract_token(buffer, cfd);
        char *user_dbid = token ? verify_jwt(token, "secret_jwt") : NULL;
        if (!user_dbid) { send_unauthorized(cfd); }
        else {
            char *user_dbname = find_db_username(user_dbid);

            char path[STR_LENGTH];
            (void)snprintf(path, sizeof(path), "./fce/outgoing/%s", user_dbname);

            size_t body_size = BUF*MIN_OFFSET;
            size_t body_len  = 0;
            char  *body      = malloc(body_size);
            if (!body) { send_error(cfd, INTERNAL_ERR); goto done; }

            DIR *dir = opendir(path);
            if (!dir) {
                body_len = snprintf(body, body_size,
                    "{\"success\":false,\"message\":\"Could not open directory\"}");
            } else {
                body_len += snprintf(body + body_len, body_size - body_len,
                    "{\"success\":true,\"files\":[");

                int first = 1;
                struct dirent *entry; // O sa citim fiecare fisier
                while ((entry = readdir(dir)) != NULL) { // NOLINT thread safe
                    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 || strcmp(entry->d_name, ".DS_Store") == 0)
                        continue;

                    char full_path[STR_LENGTH*2];
                    (void)snprintf(full_path, sizeof(full_path),
                        "./fce/outgoing/%s/%s", user_dbname, entry->d_name);

                    struct stat st;
                    if (stat(full_path, &st) != 0 || S_ISDIR(st.st_mode))
                        continue;

                    char status[HEX_LENGTH/4];
                    char* filename_try=strdup(entry->d_name + strlen("result_"));
                    
                    size_t filename_try_len = strlen(filename_try);
                    const char *ext = ".txt";

                    if (filename_try_len > strlen(ext) &&
                        strcmp(filename_try + filename_try_len - strlen(ext), ext) == 0) {
                        filename_try[filename_try_len - strlen(ext)] = '\0';
                    }
                    char filename_tofind[HEX_LENGTH+1] = {0};
                    (void)snprintf(filename_tofind, sizeof(filename_tofind), "%s", filename_try);
                    free(filename_try);                    
                    get_file_status(filename_tofind, user_dbname, status, sizeof(status));

                    /* Escape ghilimele din numele fisierului */
                    char safe_name[STR_LENGTH * 2];
                    const char *src = filename_tofind;
                    char *dst = safe_name;
                    while (*src && dst - safe_name < (int)sizeof(safe_name) - 2) {
                        if (*src == '"' || *src == '\\') *dst++ = '\\';
                        *dst++ = *src++;
                    }
                    *dst = '\0';

                    char entry_buf[STR_LENGTH * 2];
                    char *fileid = find_file_uuid(user_dbname, filename_tofind);
                    int entry_len = snprintf(entry_buf, sizeof(entry_buf),
                        "%s{\"name\":\"%s\",\"size\":%ld,\"status\":\"%s\",\"id\":\"%s\"}",
                        first ? "" : ",", safe_name, (long)st.st_size, status, fileid); // Daca e primul fisier nu ii punem , in fata

                    /* Realloc daca nu mai incape */
                    if (body_len + entry_len + 4 >= body_size) {
                        body_size *= 2;
                        char *tmp = realloc(body, body_size);
                        if (!tmp) { free(body); closedir(dir); send_error(cfd, INTERNAL_ERR); goto done; }
                        body = tmp;
                    }

                    memcpy(body + body_len, entry_buf, entry_len);
                    body_len += entry_len;
                    first = 0;
                }
                closedir(dir);

                memcpy(body + body_len, "]}", 2); // Adaugam finalul
                body_len += 2;
                body[body_len] = '\0';
            }

            char header[STR_LENGTH];
            int header_len = snprintf(header, sizeof(header),
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/json\r\n"
                "Access-Control-Allow-Origin: *\r\n"
                "Content-Length: %zu\r\n\r\n", body_len);

            (void)safe_write(cfd, header, header_len); // Trimitem header-ul
            (void)safe_write(cfd, body, body_len); // Trimitem body-ul
            free(body);
            done:;
        }
    }

    

    
    else if (strcmp(method, "POST") == 0 && strcmp(reqpath, "/api/file/") == 0) {
        char *token = extract_token(buffer, cfd);
        if (!token || verify_jwt(token, "secret_jwt") == NULL) {
            send_unauthorized(cfd);
            return;
        }

        // Extrage nume fișier
        char *filename_ptr = strstr(buffer, "X-File-Name: ");
        if (!filename_ptr) {
            send_error(cfd, BAD_RQ);
            return;
        }
        filename_ptr += strlen("X-File-Name: ");
        char *filename_end = strchr(filename_ptr, '\r');
        if (!filename_end) {
            send_error(cfd, BAD_RQ);
            return;
        }

        size_t len = (size_t)(filename_end - filename_ptr);
        char filename[STR_LENGTH];
        strncpy(filename, filename_ptr, len < STR_LENGTH-1 ? len : STR_LENGTH-1);
        filename[len < STR_LENGTH-1 ? len : STR_LENGTH-1] = '\0';

        char *user_dbname = find_db_username(verify_jwt(token, "secret_jwt"));

        char path[STR_LENGTH * 2];
        (void)snprintf(path, sizeof(path), "./fce/%s/%s", user_dbname, filename);

        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, UPLOAD_PERM);
        if (fd < 0) {
            send_error(cfd, INTERNAL_ERR);
            return;
        }

        // Scrie ce a venit deja in primul buffer
        char *body_start = strstr(buffer, "\r\n\r\n");
        if (body_start) body_start += 4;

        size_t header_len = body_start ? (size_t)(body_start - buffer) : 0;
        size_t already_received = n - header_len;

        if (already_received > 0) {
            safe_write(fd, body_start, already_received);
        }
        char chunk[BUF];   
        ssize_t bytes_read;
        size_t content_length = get_content_length(buffer); 
        size_t remaining = content_length - already_received;

        // 2. Citeste doar cat a mai ramas
        while (remaining > 0) {
            size_t to_read = (remaining < (size_t)sizeof(chunk)) ? remaining : (size_t)sizeof(chunk);
            bytes_read = read(cfd, chunk, to_read);
            
            if (bytes_read <= 0) break; // Eroare 

            safe_write(fd, chunk, (size_t)bytes_read);
            remaining -= bytes_read;
        }
        

        close(fd);

        char resultpath[STR_LENGTH * 2];
        (void)snprintf(resultpath, sizeof(resultpath), "./fce/outgoing/%s/result_%s.txt", user_dbname, filename);
        add_file_if_not_exists(user_dbname, filename, path, resultpath);
        
        cp_enqueue_job(user_dbname, filename); 
        int found = 0;

        struct stat st;
        (void)stat(resultpath, &st);
        long long firstsize = st.st_size;
        while (!found) {
            if (stat(resultpath, &st) == 0 && st.st_size > 0 && st.st_size == firstsize) { // Asteptam pana cand fisierul rezultat exista si are continut, asta inseamna ca a fost procesat
                found = 1;
            } else {
                firstsize = st.st_size;
                continue;
            }
        }

        (void)stat(resultpath, &st);
        char res_header[STR_LENGTH];
        int res_header_len = snprintf(res_header, sizeof(res_header),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/octet-stream\r\n"
            "Content-Disposition: attachment; filename=\"result_%s.txt\"\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Content-Length: %lld\r\n\r\n",
            filename, (long long)st.st_size);
        (void)safe_write(cfd, res_header, res_header_len);

        fd = open(resultpath, O_RDONLY);
        char buf[BUF];
                ssize_t n;
                while ((n = read(fd, buf, sizeof(buf))) > 0)
                    (void)safe_write(cfd, buf, n); // Cat exista lucruri de citit scriem in buffer (file-ul e mic)
        close(fd);
       


    }

    else if (strcmp(method, "POST") == 0 && strcmp(reqpath, "/api/auth/logout") == 0) { // Endpoint pentru logout
        const char *body = "{\"success\":true,\"message\":\"Logged out\"}";
        char response[BUF];
        (void)snprintf(response, sizeof(response),
                 "HTTP/1.1 200 OK\r\n"
                 "Content-Type: application/json\r\n"
                 "Content-Length: %zu\r\n"
                 "Set-Cookie: token=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT\r\n" // Se reseteaza token-ul
                 "Connection: close\r\n\r\n%s",
                 strlen(body), body);
        (void)safe_write(cfd, response, strlen(response));
    }

    else { // Daca nu este niciun-ul din endpoint-urile mentionate mai sus, se servesc fisierele statice
        char filepath[STR_LENGTH] = "./src/dist";
        char path[STR_LENGTH]     = {0};
        (void)sscanf(buffer, "GET %255s HTTP", path);

        if (strstr(path, "api/") != NULL || strstr(path, "assets") != NULL) {
            (void)strlcat(filepath, path, sizeof(filepath)); // Daca se gaseste in request api/ sau assets se adauga la filepath si datele respective
        } else {
            (void)strlcat(filepath, "/index.html", sizeof(filepath)); // Daca nu se returneaza index.html (ok pentru React SPA)
        }

        struct stat st;
        int fd = open(filepath, O_RDONLY);
        if (fd < 0 || stat(filepath, &st) < 0) { // Se verifica daca ruta exista
            char err[] =
                "HTTP/1.1 404 Not Found\r\n"
                "Content-Type: text/html\r\n"
                "Content-Length: 29\r\n\r\n"
                "<html><body>404 Not Found</body></html>";
            (void)safe_write(cfd, err, strlen(err));
            if (fd >= 0) close(fd);
        } else {
            char *mime = get_mime_type(filepath);
            char header[STR_LENGTH];

#ifdef __APPLE__ 
            (void)snprintf(header, STR_LENGTH,
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: %s\r\n"
                "Content-Length: %lld\r\n\r\n", mime, st.st_size);

#else
                (void)snprintf(header, STR_LENGTH,
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: %s\r\n"
                "Content-Length: %ld\r\n\r\n", mime, st.st_size);

#endif
            (void)safe_write(cfd, header, strlen(header)); // Se trimite header-ul

            char fbuf[BUF];
            size_t nr;
            while ((nr = read(fd, fbuf, BUF - 1)) > 0) // Se trimite fisierul cerut
                (void)safe_write(cfd, fbuf, nr);
            close(fd);
        }
    }
}
// Structura pentru web_client
typedef struct {
    char  buf[BUF];
    size_t   buf_len;
} web_client_t;
// WebServer-ul efectiv
void *web_server(void *arg) {
    int sfd;


    if(unix_based_socket == 0) { // Daca nu se trimite flag-ul de unix, facem inet socket pe TCP

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        sfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sfd < 0) { perror("socket"); return NULL; }

        int yes = 1;
        setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);

        addr.sin_family      = AF_INET;
        addr.sin_port        = htons(WEB_PORT);
        addr.sin_addr.s_addr = INADDR_ANY;
        if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("Could not bind the web server.");
            close(sfd);
            return NULL;
        }
    }
    else { // Daca se trimite flag-ul de unix facem socket Unix, tot pe TCP

        struct sockaddr_un uaddr;
        memset(&uaddr, 0, sizeof(uaddr));
        sfd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sfd < 0) { perror("socket"); return NULL; }

        uaddr.sun_family = AF_UNIX;
        strncpy(uaddr.sun_path, "/tmp/websocket.sock", sizeof(uaddr.sun_path) - 1);

        unlink(uaddr.sun_path); 
        if (bind(sfd, (struct sockaddr *)&uaddr, sizeof(uaddr)) < 0) {
            perror("Could not bind the web server.");
            close(sfd);
            return NULL;
        }
    }

    
    if (listen(sfd, SOMAXCONN) < 0) {
        perror("Could not listen on the web server.");
        close(sfd);
        pthread_exit(NULL);
        return NULL;
    }
    // Ca la userserver, alocam memorie pentru fds si pentru state-uri(buffer pentru fiecare client)
    int capacity = HEX_LENGTH;
    struct pollfd  *fds    = malloc(sizeof(struct pollfd)  * capacity);
    web_client_t   *states = malloc(sizeof(web_client_t)   * capacity);
    if (!fds || !states) {
        free(fds); free(states);
        perror("malloc web poll arrays");
        close(sfd);
        return NULL;
    }

    for (int i = 0; i < capacity; i++) {
        fds[i].fd     = -1;
        fds[i].events = 0;
    }

    fds[0].fd     = sfd;
    fds[0].events = POLLIN;
    int nfds = 1;

    (void)fprintf(stderr, "[web_server] Active on port %d\n", WEB_PORT);
    // Loginca de aici este identica cu cea de la user_server
    while (running) {
        int ret = poll(fds, nfds, WEB_TIMEOUT);

        if (ret < 0) {
            if (errno == EINTR) continue;
            perror("poll web");
            break;
        }
        if (ret == 0) goto shrink;

        if (fds[0].revents & POLLIN) {
            struct sockaddr_in caddr;
            socklen_t clen = sizeof caddr;
            int cfd = accept(sfd, (struct sockaddr *)&caddr, &clen);

            if (cfd >= 0) {
                int slot = -1;
                for (int i = 1; i < nfds; i++) {
                    if (fds[i].fd == -1) { slot = i; break; }
                }
                if (slot == -1) {
                    if (nfds == capacity) {
                        int new_cap = capacity * 2;
                        struct pollfd  *nf = realloc(fds,    sizeof(struct pollfd)  * new_cap);
                        web_client_t   *ns = realloc(states, sizeof(web_client_t)   * new_cap);
                        if (!nf || !ns) {
                            (void)fprintf(stderr, "[web_server] realloc failed – client rejected\n");
                            close(cfd);
                            goto process_events;
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

                fds[slot].fd      = cfd;
                fds[slot].events  = POLLIN;
                fds[slot].revents = 0;
                memset(&states[slot], 0, sizeof(web_client_t));
            }
        }

process_events:
        for (int i = 1; i < nfds; i++) {
            if (fds[i].fd < 0)       continue;
            if (fds[i].revents == 0) continue;

            if (fds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                close(fds[i].fd);
                fds[i].fd     = -1;
                fds[i].events = 0;
                continue;
            }

            if (!(fds[i].revents & POLLIN)) continue;

            ssize_t n = recv(fds[i].fd,
                             states[i].buf + states[i].buf_len,
                             BUF - 1 - states[i].buf_len, 0);

            if (n <= 0) {
                if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
                close(fds[i].fd);
                fds[i].fd     = -1;
                fds[i].events = 0;
                states[i].buf_len = 0;
                continue;
            }

            states[i].buf_len += (int)n;
            states[i].buf[states[i].buf_len] = '\0';

            char *hdr_end = strstr(states[i].buf, "\r\n\r\n"); // Se cauta end-ul header-ului
            if (!hdr_end) { // Daca nu se gaseste se inchide conexiunea
                if (states[i].buf_len >= BUF - 1) {
                    close(fds[i].fd);
                    fds[i].fd     = -1;
                    fds[i].events = 0;
                    states[i].buf_len = 0;
                }
                continue;
            }

            char *cl_ptr = strstr(states[i].buf, "Content-Length: "); // Se cauta length-ul
            if (cl_ptr) {
                size_t content_length = (size_t)atol(cl_ptr + HEX_LENGTH/4);
                size_t header_len = (size_t)(hdr_end + 4 - states[i].buf);
                size_t body_in_buf = (states[i].buf_len > header_len) ?
                                     (states[i].buf_len - header_len) : 0; // Se calculeaza length-ul (body-ului)

                size_t needed = (content_length < STR_LENGTH*2) ? content_length : STR_LENGTH*2; // Failsafe in caz ca e prea mic
                if (body_in_buf < needed && states[i].buf_len < BUF - 1) {
                    continue;
                }
            }

            handle_web_request(fds[i].fd, states[i].buf, states[i].buf_len); // Apelam functia de mai sus care se ocupa cu handling-ul

            close(fds[i].fd);
            fds[i].fd     = -1;
            fds[i].events = 0;
            states[i].buf_len = 0;
        }

shrink:
        while (nfds > 1 && fds[nfds - 1].fd == -1)
            nfds--;
    }

    for (int i = 1; i < nfds; i++) {
        if (fds[i].fd >= 0) close(fds[i].fd);
    }
    free(fds);
    free(states);
    close(sfd);
    pthread_exit(NULL);
    return arg;
}

