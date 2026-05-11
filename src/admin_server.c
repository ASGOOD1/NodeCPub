/*
    * admin_server.c - Admin server thread, se ocupa cu interactiunea cu adminul.
    * Comunica prin socket UNIX de tip datagram cu clientul admin.
    * Comenzi suportate:
    * - LOGIN <username> <password>
    * - LOGOUT
    * - SHUTDOWN
    * - UPTIME
    * - KICK <username>
    * - LOGS [username] [page]
    * - PAGESLOGS [username]
    * - CLIENTS
    * - QSTATS
    * - CANCELJOB <username> <filename>
    * - BAN <ip>
    * - UNBAN <ip>
    * Adminul poate avea o singura sesiune activa. Dupa o perioada de inactivitate, sesiunea expira automat.
    * Acest server se ocupa si de trimiterea in timp real a logurilor catre admin, folosind acelasi socket UNIX.
    Erori tratate:
    * - Eroare la crearea socketului
    * - Eroare la bind
    * - Eroare la recvfrom
    * - Eroare la sendto
    * - Eroare la interactiunea cu baza de date


*/


/*
    Constante si structuri
    Unele sunt definite cu #ifndef pentru ca sunt definite si in alte fisiere, dar nu vrem erori de redefinire. 
    Acestea sunt doar valori implicite.
*/

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
#ifndef ADMIN_PORT
#define ADMIN_PORT 9000
#endif
#ifndef ADMIN_TIMEOUT_SEC
#define ADMIN_TIMEOUT_SEC 120  
#endif


#ifndef POLL_TIMEOUT
#define POLL_TIMEOUT 1000    
#endif

#include <pthread.h> // Folosit pentru thread-uri si mutex-uri
#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> // Aici folosit pentru formatare si manipulare stringuri
#include <unistd.h> // Pentru close, unlink, read, write
#include <sys/socket.h> // Pentru socket, bind, recvfrom, sendto
#include <arpa/inet.h>  // Pentru a comunica cu socketuri de tip inet(kick catre clienti)
#include <sqlite3.h> // Pentru interactiunea cu baza de date SQLite (loguri, autentificare admin)
#include <time.h> // Pentru a gestiona timpul de activitate al adminului si uptime-ul serverului
#include <errno.h> // Pentru a verifica erorile la functiile de sistem (la poll)
#include <poll.h> // Pentru a folosi poll pentru a astepta date pe socket cu timeout
#include <sys/un.h> // Pentru a folosi socketuri UNIX de tip datagram pentru comunicarea cu adminul
#include "headers/queue.h" // Pentru a verifica starea cozii de joburi si a permite cancelarea joburilor din coada
#include "headers/server.h" // Pentru structura client_t si functii legate de gestionarea clientilor
#include "headers/worker.h" // Pentru a permite cancelarea joburilor din coada si a obtine statistici despre worker threads
#define SOCKET_PATH "/tmp/admin_socket.sock" // Calea catre socketul UNIX folosit pentru comunicarea cu adminul

//Variabile globale partajate cu celelalte threaduri (web server, worker threads)
// sau cu functiile din server.c (pentru interactiunea cu baza de date si gestionarea clientilor)
extern int running; // Variabila globala care indica daca serverul este in functiune
extern time_t start_time;
extern sqlite3 *db;
extern pthread_mutex_t db_lock;
extern pthread_mutex_t admin_lock;
extern int adminLogged;
extern int adminSocket;
extern pthread_mutex_t clients_mutex;
extern client_t *clients;
extern int client_count;


// Variabila globala pentru a stoca adresa clientului admin conectat, folosita pentru a trimite loguri in timp real
struct sockaddr_un logged_addr;


// Functie pentru thread-ul de logare in timp real catre admin. Aceasta citeste dintr-un pipe si trimite mesajele catre admin daca este conectat.
int log_pipe[2];


// Constanta pentru dimensiunea ip-ului
#define MAX_IP_SIZE 16


// Thread separat care citeste mesajele din logpipe si le transmite catre admin.
void* logger_thread_func(void* arg) {
    char buffer[STR_LENGTH];
    while (running) {
        ssize_t bytes = read(log_pipe[0], buffer, sizeof(buffer) - 1);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            if (adminSocket >= 0) {
                char log_msg[STR_LENGTH*2];
                (void)snprintf(log_msg, sizeof(log_msg), "[LIVE] %255s", buffer);

                pthread_mutex_lock(&admin_lock);
                if (sendto(adminSocket, log_msg, strlen(log_msg), 0, (struct sockaddr*)&logged_addr, sizeof(logged_addr)) <= 0) {
                    adminSocket = -1;
                    adminLogged = 0;
                }
                pthread_mutex_unlock(&admin_lock);
            }
        }
    }
    return arg;
}

// Functia principala pentru thread-ul admin_server. Aceasta se ocupa cu mare parte din logica pentru clientul de admin.

void *admin_server(void *arg) {
    int sfd;
    struct sockaddr_un addr, client_addr;
    memset(&addr, 0, sizeof(addr));
    socklen_t client_len = sizeof(client_addr);

    sfd = socket(AF_UNIX, SOCK_DGRAM, 0);
    unlink(SOCKET_PATH); // stergem socket ul daca a ramas dintr-o rulare anterioara, ca sa nu pice bind ul
    if (sfd < 0) { perror("socket"); return NULL; }

    int yes = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)); //permitem refolosirea adresei socketului
    
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (bind(sfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Could not bind the admin server.");
        close(sfd);
        return NULL;
    }

    char buffer[BUF];
    char user_logged[MIN_LENGTH] = {0};
    int  logged = 0;
    time_t last_activity = 0; 

    memset(&logged_addr, 0, sizeof(logged_addr)); //resetam adresa clientului admin

    while (running) {
        memset(buffer, 0, BUF);
        memset(&client_addr, 0, sizeof(client_addr));
        client_len = sizeof(client_addr);

        struct pollfd pfd = { .fd = sfd, .events = POLLIN }; 
        int pr = poll(&pfd, 1, POLL_TIMEOUT); 

        if (pr < 0) { // Daca poll a fost intrerupt de un semnal, continuam sa asteptam. Altfel, iesim din loop in caz de eroare.
            if (errno == EINTR) continue; 
            break;
        }

        if (logged) {
            time_t now = time(NULL); 
            if (now - last_activity >= ADMIN_TIMEOUT_SEC) {  // Timeout admin pt incativitate
                const char *tmsg = "TIMEOUT: Timed out due to inactivity.\n";
                (void)sendto(sfd, tmsg, strlen(tmsg), 0,
                             (struct sockaddr*)&logged_addr, sizeof(logged_addr));
                

                update_user_column(user_logged, "loggedin", "0"); 

                pthread_mutex_lock(&admin_lock);
                adminLogged = 0;  
                adminSocket = -1; 
                pthread_mutex_unlock(&admin_lock);

                char log_msg[STR_LENGTH];
                (void)snprintf(log_msg, sizeof(log_msg),
                               "Admin %s has been disconnected (timeout %ds).",
                               user_logged, ADMIN_TIMEOUT_SEC); 
                add_logs(user_logged, log_msg);

                memset(user_logged, 0, sizeof(user_logged)); 
                memset(&logged_addr, 0, sizeof(logged_addr)); 
                logged = 0;       
                last_activity = 0; 
                continue;         
            }
        }

        if (pr == 0) continue;   // Timeout, nu s-au primit date, continuam sa asteptam

        ssize_t n = recvfrom(sfd, buffer, BUF - 1, 0,
                             (struct sockaddr*)&client_addr, &client_len); // Primim comanda si adresa expeditorului
        if (n <= 0) continue;
        buffer[n] = '\0';

        
        if (logged) last_activity = time(NULL); // Orice comanda valida de la adminul logat reseteaza timer ul de inactivitate

        if (logged) { // Daca exista deja un admin conectat, verificam daca noul client este acelasi. Daca nu, refuzam conexiunea.
            if (strcmp(client_addr.sun_path, logged_addr.sun_path) != 0) {
                (void)sendto(sfd, "BUSY\n", strlen("BUSY\n"), 0, (struct sockaddr*)&client_addr, client_len);
                continue;
            }
        }
       
        if (strncasecmp(buffer, "LOGIN", strlen("LOGIN")) == 0) { // Logica de login
            char u[MIN_LENGTH], p[HEX_LENGTH + 1];
            memset(u, 0, sizeof(u));
            memset(p, 0, sizeof(p));
            (void)sscanf(buffer, "LOGIN %49s %64s", u, p); // Parsare credeantiale din comanda LOGIN in buffere cu dimensiune fixa

            if (check_login(u, p, "admin")) {
                logged = 1;
                last_activity = time(NULL); 
                memset(user_logged, 0, sizeof(user_logged));
                (void)snprintf(user_logged, sizeof(user_logged), "%s", u);
                memcpy(&logged_addr, &client_addr, sizeof(logged_addr)); // Salvam adresa adminului logat ca sa trimitem live logs doar catre el

                pthread_mutex_lock(&admin_lock);
                adminSocket = sfd;   
                adminLogged = 1;
                pthread_mutex_unlock(&admin_lock);

                (void)sendto(sfd, "OK", 2, 0,
                             (struct sockaddr*)&client_addr, client_len);
                (void)fflush(stdout);
            } else {
                (void)sendto(sfd, "FAIL", strlen("FAIL"), 0,
                             (struct sockaddr*)&client_addr, client_len);
            }
        }

        else if (logged && strncasecmp(buffer, "UPTIME", strlen("UPTIME")) == 0) { // Logica pentru comanda UPTIME (comentariul acesta nu o sa-l mai pun)
            time_t now;
            (void)time(&now);
            char resp[MIN_LENGTH];
            (void)snprintf(resp, sizeof(resp), "UPTIME %ld sec\n", now - start_time);
            (void)sendto(sfd, resp, strlen(resp), 0,
                         (struct sockaddr*)&client_addr, client_len);
        }

        else if (logged && strncasecmp(buffer, "SHUTDOWN", strlen("SHUTDOWN")) == 0) {
            const char *resp = "SHUTTING DOWN SERVER\n";
            (void)sendto(sfd, resp, strlen(resp), 0,
                         (struct sockaddr*)&client_addr, client_len);
            running = 0; // setam variabila asta pe 0 (se comporta ca un flag), o sa opreasca automat server-ul
        }

        else if (logged && strncasecmp(buffer, "LOGOUT", strlen("LOGOUT")) == 0) {
            const char *resp = "BYE\n";
            (void)sendto(sfd, resp, strlen(resp), 0,
                         (struct sockaddr*)&client_addr, client_len); //Pentru a trimite mesajul de logout catre admin

            pthread_mutex_lock(&admin_lock);
            adminLogged = 0;
            adminSocket = -1;
            pthread_mutex_unlock(&admin_lock); 

            update_user_column(user_logged, "loggedin", "0");
            memset(user_logged, 0, sizeof(user_logged));
            memset(&logged_addr, 0, sizeof(logged_addr));
            last_activity = 0;
            logged = 0; // resetam toate datele legate de adminul conectat (de la lock pana aici)
        }

        /* ---- KICK <username> ---- */
        else if (logged && strncasecmp(buffer, "KICK", 4) == 0) {
            char usernamekick[MIN_LENGTH];
            memset(usernamekick, 0, sizeof(usernamekick));
            (void)sscanf(buffer, "KICK %49s", usernamekick);
            int found = 0;
            pthread_mutex_lock(&clients_mutex);
            for (int i = 0; i < client_count; i++) { // Ne uitam in toti clientii conectati
                if (clients[i].sock <= 0) continue; // Daca socketul e invalid, sarim peste client
                if (strcmp(usernamekick, clients[i].username) != 0) continue; // Daca nu are username-ul cautat, sarim peste client
                char resp[STR_LENGTH];
                (void)snprintf(resp, sizeof(resp),
                               "User %s has been kicked.\n", usernamekick);
                (void)sendto(sfd, resp, strlen(resp), 0,
                             (struct sockaddr*)&client_addr, client_len);
                found ++;
                add_logs(user_logged, resp);

                (void)snprintf(resp, sizeof(resp),
                               "You have been kicked by admin %s\n", user_logged);
                (void)safe_write(clients[i].sock, resp, strlen(resp));
                close(clients[i].sock);
                remove_client_at_index(i);
                i--; // II dam kick, insa remove client at index o sa mute ultimul client aici, so reverificam indexul din nou
            }

            client_count-= found; // Scadem numarul de clienti conectati cu numarul de clienti pe care i-am dat kick
            pthread_mutex_unlock(&clients_mutex);

            // Facem asta deoarece poate avea mai multe aplicatii de client(sesiuni) deschise pe acelasi cont
            if (!found) {
                char resp[STR_LENGTH];
                (void)snprintf(resp, sizeof(resp),
                               "User %s not found.\n", usernamekick);
                (void)sendto(sfd, resp, strlen(resp), 0,
                             (struct sockaddr*)&client_addr, client_len);
            }
        }

        else if (logged && strncasecmp(buffer, "LOGS", 4) == 0) {
            char usernamekick[MIN_LENGTH] = "";
            int page = 0;
            (void)sscanf(buffer, "LOGS %49s %d", usernamekick, &page);
            
            if (usernamekick[0] == '\0')
                (void)strncpy(usernamekick, "all", strlen("all") + 1);
            size_t ulen = strlen(usernamekick);
            if (ulen > 0 && usernamekick[ulen - 1] == '\n')
                usernamekick[ulen - 1] = '\0';

            sqlite3_stmt *stmt;
            char sql[STR_LENGTH];

            pthread_mutex_lock(&db_lock); // Blocam accesul la baza de date pentru a preveni probleme de concurenta
            if (strcasecmp(usernamekick, "all") == 0) {
                (void)snprintf(sql, sizeof(sql),
                    "SELECT time, username, action FROM logs ORDER BY time DESC LIMIT 5 OFFSET %d;", page * MIN_OFFSET);
                if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
                    pthread_mutex_unlock(&db_lock);
                    continue;
                } // Selectam doar numarul de loguri din pagina ceruta(all)
            } else {
                (void)snprintf(sql, sizeof(sql),
                    "SELECT time, username, action FROM logs WHERE username = ? ORDER BY time DESC LIMIT 5 OFFSET %d;", page * MIN_OFFSET);
                if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
                    pthread_mutex_unlock(&db_lock);
                    continue;
                }
                sqlite3_bind_text(stmt, 1, usernamekick, -1, SQLITE_TRANSIENT);
                //asemanator ca mai sus, doar ca pentru un user specificat
            }

            int found = 0;
            char resp[BUF] = "User | Time | Action\n";   // buffer curat

            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const unsigned char *ts  = sqlite3_column_text(stmt, 0);
                const unsigned char *usr = sqlite3_column_text(stmt, 1);
                const unsigned char *act = sqlite3_column_text(stmt, 2);
                found = 1;

                char line[STR_LENGTH];
                (void)snprintf(line, sizeof(line), "%s | %s | %s\n", usr, ts, act);
                (void)strncat(resp, line, sizeof(resp) - strlen(resp) - 1);
            } // Scriem toate logurile gasite in bufferul de raspuns

            if (found) {
                (void)sendto(sfd, resp, strlen(resp), 0,
                             (struct sockaddr*)&client_addr, client_len);
            } else {
                (void)sendto(sfd, "No logs found.\n", strlen("No logs found.\n"), 0,
                             (struct sockaddr*)&client_addr, client_len);
            } //Trimitem buffer-ul sau un mesaj de eroare daca nu s-au gasit loguri pentru pagina ceruta

            sqlite3_finalize(stmt); // Eliberam statement-ul SQL dupa ce terminam interogarea
            pthread_mutex_unlock(&db_lock);
        }
        else if (logged && strncasecmp(buffer, "PAGESLOGS", strlen("PAGESLOGS")) == 0) {
            char usernamekick[MIN_LENGTH] = "";
            (void)sscanf(buffer, "PAGESLOGS %49s", usernamekick);

            if (usernamekick[0] == '\0')
                (void)strncpy(usernamekick, "all", strlen("all") + 1);

            size_t ulen = strlen(usernamekick);
            if (ulen > 0 && usernamekick[ulen - 1] == '\n')
                usernamekick[ulen - 1] = '\0';

            sqlite3_stmt *stmt = NULL;
            char sql[STR_LENGTH];

            pthread_mutex_lock(&db_lock);

            if (strcasecmp(usernamekick, "all") == 0) {
                (void)snprintf(sql, sizeof(sql),
                    "SELECT COUNT(id) FROM logs ORDER BY time DESC;");
            } else {
                (void)snprintf(sql, sizeof(sql),
                    "SELECT COUNT(id) FROM logs WHERE username = ? ORDER BY time DESC;");
            }
            if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
                pthread_mutex_unlock(&db_lock);
                continue;
            }

            if (strcasecmp(usernamekick, "all") != 0) {
                sqlite3_bind_text(stmt, 1, usernamekick, -1, SQLITE_TRANSIENT);
            }
            // Contorizam numarul total de loguri
            int total_rows = 0;
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                total_rows = sqlite3_column_int(stmt, 0);
            }

            int page_limit = MIN_OFFSET;           // 5
            int num_pages  = (total_rows + page_limit - 1) / page_limit;
            if (num_pages == 0) num_pages = 1;
            //calculam numarul de pagini(5/pagina) si trimitem raspunsul catre admin
            char response[STR_LENGTH];
            (void)snprintf(response, sizeof(response), "PAGES %d\n", num_pages);

            (void)sendto(sfd, response, strlen(response), 0,
                         (struct sockaddr*)&client_addr, client_len);

            sqlite3_finalize(stmt);
            pthread_mutex_unlock(&db_lock);
        }
        else if (logged && strncasecmp(buffer, "CLIENTS", strlen("CLIENTS")) == 0) {// Construim raspunsul in batch-uri ca sa nu depasim bufferul
            char outbuf[BUF];
            int outpos = 0;

            pthread_mutex_lock(&clients_mutex);
            for (int i = 0; i < client_count; i++) { // Iteram toti clientii
                if (clients[i].sock <= 0) continue;
                char line[STR_LENGTH];
                int len = snprintf(line, sizeof(line), "fd=%-4d  user=%s\n",
                                clients[i].sock, clients[i].username); 
                if (outpos + len >= BUF) {
                    sendto(sfd, outbuf, outpos, 0,
                        (struct sockaddr*)&client_addr, client_len); //trimitem datele clientului
                    outpos = 0;// resetam pozitia pentru urmatorul batch de clienti
                }
                memcpy(outbuf + outpos, line, len); // adaugam linia curenta in bufferul de raspuns
                outpos += len;
            }
            if (client_count == 0) {
                outpos = snprintf(outbuf, sizeof(outbuf), "No clients connected.\n");
            }
            pthread_mutex_unlock(&clients_mutex);

            if (outpos > 0)
                sendto(sfd, outbuf, outpos, 0,
                    (struct sockaddr*)&client_addr, client_len); //Trimitem ultimul batch de clienti sau mesajul de eroare daca nu sunt clienti conectati
            
        }

        else if (logged && strncasecmp(buffer, "QSTATS", strlen("QSTATS")) == 0) {
            char resp[STR_LENGTH];
            
            (void)snprintf(resp, sizeof(resp),
                    "Queue jobs pending: %d\nWorker threads: %d\nActive jobs: %d\n",
                    queue_count(&g_queue), g_nthreads, get_active_jobs()); 
            sendto(sfd, resp, strlen(resp), 0,
                (struct sockaddr*)&client_addr, client_len); // Se obtine si se trimite numarul de job-uri in coada
        }
        else if (logged && strncasecmp(buffer, "CANCELJOB", strlen("CANCELJOB")) == 0) {
            char uname[MIN_LENGTH] = {0};
            char fname[STR_LENGTH] = {0};
            (void)sscanf(buffer, "CANCELJOB %49s %255s", uname, fname);

            char resp[STR_LENGTH];
            if (uname[0] == '\0' || fname[0] == '\0') {
                (void)snprintf(resp, sizeof(resp), "Usage: CANCELJOB <username> <filename>\n");
            } else if (worker_cancel_job(uname, fname)) { // Daca am reusit sa anulez jobul, trimit mesaj de confirmare catre admin si adaug in loguri
                (void)snprintf(resp, sizeof(resp), "Job %s/%s cancelled.\n", uname, fname);
                add_logs(user_logged, resp);
            } else {
                (void)snprintf(resp, sizeof(resp), "Job %s/%s not found in queue.\n", uname, fname);
            }

            sendto(sfd, resp, strlen(resp), 0,
                (struct sockaddr*)&client_addr, client_len); // Trimitem efectiv mesajul
        }
        else if (logged && strncasecmp(buffer, "UNBAN", strlen("UNBAN")) == 0) {
            char ip[MAX_IP_SIZE] = {0};
            (void)sscanf(buffer, "UNBAN %15s", ip);

            char resp[STR_LENGTH];
            int changed = remove_ip_ban(ip); // Fiunctie helper care sterge ip-ul din db
            if (changed > 0){
                (void)snprintf(resp, sizeof(resp), "IP %s unbanned.\n", ip);
                add_logs(user_logged, resp);
            }
            else
                (void)snprintf(resp, sizeof(resp), "IP %s not in ban list.\n", ip);
            

            sendto(sfd, resp, strlen(resp), 0, (struct sockaddr*)&client_addr, client_len);
        }
        else if (logged && strncasecmp(buffer, "BAN ", 4) == 0) {
            char ip[MAX_IP_SIZE] = {0};
            (void)sscanf(buffer, "BAN %15s", ip);

            char resp[STR_LENGTH];
            int changed = add_ip_ban(ip, user_logged);// Asemator cu functia de unban
            if (changed > 0) {
                (void)snprintf(resp, sizeof(resp), "IP %s banned.\n", ip);
                add_logs(user_logged, resp);
            }
            else                
                (void)snprintf(resp, sizeof(resp), "IP %s is already banned.\n", ip);
            int found = 0;
            pthread_mutex_lock(&clients_mutex);
            for (int i = 0; i < client_count; i++) { // Verificam daca este vreun client cu ip-ul banat si ii dam kick daca gasim vreunul
                if (clients[i].sock <= 0) continue;
                struct sockaddr_in addr;
                socklen_t len = sizeof(addr);
                if (getpeername(clients[i].sock,
                                (struct sockaddr*)&addr, &len) == 0) {
                    char cip[MAX_IP_SIZE];
                    inet_ntop(AF_INET, &addr.sin_addr, cip, sizeof(cip));
                    if (strcmp(cip, ip) == 0) {
                        safe_write(clients[i].sock,
                                "You have been banned.\n", strlen("You have been banned.\n"));
                        close(clients[i].sock);
                        found++;
                        remove_client_at_index(i);
                        i--;
                    }
                }
            }
            client_count -= found;
            pthread_mutex_unlock(&clients_mutex);

            sendto(sfd, resp, strlen(resp), 0,
                (struct sockaddr*)&client_addr, client_len);
        }
        else if (!logged) {
            (void)sendto(sfd, "NOT LOGGED IN\n", strlen("NOT LOGGED IN\n"), 0,
                         (struct sockaddr*)&client_addr, client_len);
        }
    }

    if (logged) {// daca adminul era logat, ii inchidem sesiunea corect
        update_user_column(user_logged, "loggedin", "0");
        pthread_mutex_lock(&admin_lock);
        adminLogged = 0;
        adminSocket = -1;
        pthread_mutex_unlock(&admin_lock);
    }

    close(sfd);
    pthread_exit(NULL);
    return arg;
}

