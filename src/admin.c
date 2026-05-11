/* admin.c - Implementarea clientului de admin.

    Clientul acesta are capabilitatea de a se conecta la server prin socket UNIX de tip datagram, 
    de a trimite comenzi si de a primi raspunsuri. De asemenea, primeste logurile in timp real de la server si le afiseaza.
    Functionalitati principale:
    * Conectare si autentificare cu username si parola.
    * Trimiterea de comenzi catre server si afisarea raspunsurilor.
    * Afisarea logurilor in timp real primite de la server.
    * Gestionarea sesiunii de admin, inclusiv timeout pentru inactivitate si deconectare.
    * Interfata simpla in terminal pentru a vizualiza statusul si raspunsurile serverului.
    Comenzi suportate:
    * LOGIN <username> <password>
    * LOGOUT
    * SHUTDOWN
    * UPTIME
    * KICK <username>
    * LOGS [username] [page]
    * PAGESLOGS [username]
    * CLIENTS
    * QSTATS
    * CANCELJOB <username> <filename>
    * BAN <ip>
    * UNBAN <ip>
    * Adminul poate avea o singura sesiune activa. Dupa o perioada de inactivitate, sesiunea expira automat.
    Erori tratate:
    * Eroare la crearea socketului
    * Eroare la bind
    * Eroare la recvfrom
    * Eroare la sendto
    Celelalte erori sunt tratate la nivel de server.
*/

// Include-urile sunt de baza si explicate in admin_server.c.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/un.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <pthread.h>
#include <strings.h>

#include <ncurses.h> // Folosit pentru interfata.

// Folosit pentru a face hashing parolelor inainte de a le trimite catre server pentru autentificare.
#include "headers/sha256.h"

// Constante necesare

//Specific (nu e predefinita pe MacOS)
#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT 0x40
#endif 


#define PORT        9000
#define BUFFER_SIZE 4096
#define HEX_LENGTH  64
#define STR_LENGTH  256
#define PAGE_LIMIT  5
#define SERVER_IP   "127.0.0.1"
#ifndef MIN_OFFSET
#define MIN_OFFSET 5
#endif

// Variabile globale pentru starea clientului de admin
static int  sock      = -1;
static int  running   = 1;

static int  connected      = 0;
static int  authenticated  = 0;
static int  login_failed   = 0;
static int  current_page   = 0;
static int  max_pages      = 1;

char status_msg   [STR_LENGTH]    = "Not connected";
char last_response[BUFFER_SIZE]   = "";
char current_user [STR_LENGTH]    = "";
char latest_live_log[STR_LENGTH * 2] = "[LIVE] (no logs yet)";
char user_searched[STR_LENGTH/2]    = "";


struct sockaddr_un server_addr;

// Constanta pentru socket-ul UNIX folosit pentru comunicarea cu serverul de admin
#define SERVER_SOCKET_PATH "/tmp/admin_socket.sock"
// Variabila pentru a stoca calea catre socketul UNIX al clientului, folosita pentru a curata socketul la inchidere
static char actual_client_path[STR_LENGTH/2-4*MIN_OFFSET-2];





// Functia pentru a crea socket-ul si a se "conecta" la server-ul admin.
 
int setup_socket(void) {
    if (sock >= 0) close(sock); //daca exista deja un socket deschis, il inchidem inainte sa il recream
 
    sock = socket(AF_UNIX, SOCK_DGRAM, 0); // Cream un socket UNIX de tip datagram
    if (sock < 0) return -1;
 
    struct sockaddr_un client_addr;
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sun_family = AF_UNIX;
 
    (void)snprintf(actual_client_path, sizeof(actual_client_path),
                   "/tmp/admin_cli_%d.sock", getpid());
    unlink(actual_client_path);// Stergem socket ul clientului daca a ramas in /tmp dintr-o rulare anterioara
    strncpy(client_addr.sun_path, actual_client_path,
            sizeof(client_addr.sun_path) - 1);
 
    if (bind(sock, (struct sockaddr*)&client_addr, sizeof(client_addr)) < 0)
        return -1;
 
 
    memset(&server_addr, 0, sizeof(server_addr));// Pregatim adresa serverului admin
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, SERVER_SOCKET_PATH,  sizeof(server_addr.sun_path) - 1);
 
    return 0;
}
 

// Functie pentru send de date( e un wrapper pentru ca socket-ul catre care trimit e mereu acelasi )
int udp_send(const char *msg) {
    if (sock < 0) return -1;
    ssize_t sent = sendto(sock, msg, strlen(msg), 0,
                          (struct sockaddr*)&server_addr, sizeof(server_addr));
    return (sent < 0) ? -1 : 0;
}

// Functie pentru recv de date (e un wrapper pentru recvfrom, dar nu intoarce adresa sursa pentru ca stim ca e mereu serverul)
int udp_recv(char *out, int outsz) {
    if (sock < 0) return -1;
    struct sockaddr_un from;
    socklen_t fromlen = sizeof(from);
    ssize_t n = recvfrom(sock, out, outsz - 1, 0,
                         (struct sockaddr*)&from, &fromlen); // Primim raspunsul de la server si il terminam cu \0
    if (n <= 0) return -1;
    out[n] = '\0';
    return (int)n;
}
// Automatizare pentru trimiterea comenzilor si primirea raspunsurilor, cu gestionarea erorilor si actualizarea statusului.
// Comunicarea e sincrona (din cerinta)
int udp_rpc(const char *msg) {
    if (udp_send(msg) < 0) {
        connected = 0;
        (void)snprintf(status_msg, sizeof(status_msg), "Send failed");
        return -1;
    }
    char buf[BUFFER_SIZE];
    int n = udp_recv(buf, sizeof(buf));

    if (n < 0) {
        (void)snprintf(status_msg, sizeof(status_msg), "No reply from server (timeout)");
        return -1;
    }
    last_response[0] = '\0';
    (void)strncpy(last_response, buf, sizeof(last_response) - 1); // Copiem raspunsul in bufferul global afisat in interfata
    last_response[sizeof(last_response) - 1] = '\0';
    return n;
}
//Thread separat care asculta pentru log-uri
void* poll_live_log(void* arg) {
    if (sock < 0) return NULL;
    (void)arg;
    char buf[BUFFER_SIZE];
    struct sockaddr_un from;
    socklen_t fromlen = sizeof(from);
    while (1) {
        ssize_t n = recvfrom(sock, buf, sizeof(buf) - 1, MSG_DONTWAIT | MSG_PEEK,
                                (struct sockaddr*)&from, &fromlen); // Citesc mesajul cu MSG_PEEK pentru a verifica daca e un mesaj de log in timp real fara a-l consuma din buffer

        if (n <= 0) continue;
        buf[n] = '\0';


        if (strncmp(buf, "[LIVE]", strlen("[LIVE]")) == 0) { // Daca e log live il consum efectiv din buffer
            n = recvfrom(sock, buf, sizeof(buf) - 1, MSG_DONTWAIT,
                            (struct sockaddr*)&from, &fromlen);
            buf[n] = '\0';
            char *p = buf + strlen("[LIVE]");
            while (*p == ' ') p++; // Eliminam spatiile de dupa prefix ul [LIVE] 
            (void)snprintf(latest_live_log, sizeof(latest_live_log), "[LIVE] %.490s", p);
            size_t ln = strlen(latest_live_log);
            if (ln > 0 && latest_live_log[ln - 1] == '\n')
                latest_live_log[--ln] = '\0';
            for (char *c = latest_live_log; *c; c++)
                if (*c == '\n' || *c == '\r' || *c == '\t') *c = ' ';// Curatam mesajul live pentru afisare
        }
        else if (strncmp(buf, "TIMEOUT: Timed out due to inactivity.", strlen("TIMEOUT: Timed out due to inactivity.")) == 0) { // La fel si pentru timeout
            n = recvfrom(sock, buf, sizeof(buf) - 1, MSG_DONTWAIT,
                            (struct sockaddr*)&from, &fromlen);
            buf[n] = '\0';
            (void)snprintf(last_response, sizeof(last_response), "%s", buf);
            continue; 
        }
    }
    return NULL;
}
static void handle_sigint(int sig) { // La primirea semnalului SIGINT, se deconecteaza si se curata socketul
    (void)sig;
    if (authenticated) udp_send("LOGOUT\n");
    running = 0;
    unlink(actual_client_path);
    if (sock >= 0) close(sock);
}
int main(void) {
    (void)signal(SIGPIPE, SIG_IGN); // Ignoram sigpipe pentru a evita ca programul sa se inchida daca serverul de admin se deconecteaza sau daca exista o problema la trimiterea datelor.
    (void)signal(SIGINT, handle_sigint); // Adaugam handle-ul custom pt sigint

    if (setup_socket() < 0) { // Incercam sa cream socket-ul si sa ne conectam la el
        (void)fprintf(stderr, "Failed to create UDP socket\n");
        return 1;
    }
    
    // Cream thread-ul pentru a asculta log-urile in timp real de la server
    pthread_t logger_tid;
    pthread_create(&logger_tid, NULL, poll_live_log, NULL); // Pornim thread ul care asculta loguri live
    pthread_detach(logger_tid);

    //Loginca pentru a primi comenzile de la admin si a le procesa(login, uptime, kick, canceljob, ban, unban etc)
    connected = 1;   
    (void)snprintf(status_msg, sizeof(status_msg), "Ready - please log in");


   
    initscr(); // Initializam ncurses pentru a putea folosi functiile de afisare in terminal
    cbreak();// Setam terminalul in mod cbreak pentru a putea citi input-ul caracter cu caracter
    noecho(); // Dezactivam echo-ul pentru a nu afisa caracterele introduse de admin (mai ales la parola)
    curs_set(0); // Ascundem cursorul pentru a avea o interfata mai curata
    timeout(200);    // Setam un timeout pentru getnstr, astfel incat sa putem actualiza interfata chiar si atunci cand adminul nu introduce nimic

    if (has_colors()) { // Daca terminalul suporta culori, initializam cateva perechi de culori pentru a face interfata mai atractiva
        start_color();// Initializam modul de culori
        init_pair(1, COLOR_CYAN,   COLOR_BLACK);
        init_pair(2, COLOR_YELLOW, COLOR_BLACK);
        init_pair(3, COLOR_GREEN,  COLOR_BLACK);
        init_pair(4, COLOR_WHITE,  COLOR_BLACK);
        init_pair(MIN_OFFSET, COLOR_RED,    COLOR_BLACK); // Pentru mesajele de eroare sau statusuri importante
    }

    char input   [STR_LENGTH / 2] = {0};
    char password[STR_LENGTH / 2] = {0};
    int  login_stage = 1;  

    while (running) { // Bucla principala pentru a procesa comenzile adminului si a actualiza interfata

        if (strcasecmp(last_response, "TIMEOUT: Timed out due to inactivity.\n") == 0) { // Verificare timedout pentru inactivitate, Fallback pentru thread.
            authenticated = 0;                              
            login_stage   = 1;                            
            memset(current_user, 0, sizeof(current_user)); 
            (void)snprintf(status_msg, sizeof(status_msg), "Disconnected due to inactivity"); 
            
        }

        clear(); // Curatam ecranul la fiecare iteratie pentru a reafisa interfata actualizata
        box(stdscr, 0, 0); // Desenam o cutie in jurul ecranului pentru a delimita zona de afisare

        if (has_colors()) attron(COLOR_PAIR(1) | A_BOLD); // Setam culoarea pentru titlu
        mvprintw(1, 2, "Admin Client - UDP");
        if (has_colors()) attroff(COLOR_PAIR(1) | A_BOLD); // Resetam culoarea dupa titlu

        if (has_colors()) attron(COLOR_PAIR(2)); // Setam culoarea pentru status
        mvprintw(2, 2, "Status: %s", status_msg);
        if (has_colors()) attroff(COLOR_PAIR(2)); // Resetam culoarea dupa status

        mvhline(3, 1, ACS_HLINE, COLS - 2); // Desenam o linie orizontala pentru a separa zona de status de restul interfetei

        if (!authenticated) { // Daca nu e autentificat

            mvprintw(MIN_OFFSET, 2, "Response: %s", last_response); // Afisam ultimul raspuns primit de la server (de obicei legat de login)

            if (login_failed) { // Daca incercarea de login a esuat, afisam un mesaj de eroare si resetam starea pentru a permite o noua incercare
                mvprintw(MIN_OFFSET + 1, 2, "Login failed! Try again.");
                login_failed = 0;
                login_stage  = 1;
                memset(input,    0, sizeof(input));
                memset(password, 0, sizeof(password));
            }

            if (login_stage == 1) { // Et introducere username
                if (has_colors()) attron(COLOR_PAIR(3)); // Setam culoarea pentru promptul de username
                mvprintw(MIN_OFFSET + 3, 2, "Username: "); // Afisam promptul pentru username
                if (has_colors()) attroff(COLOR_PAIR(3));
                refresh(); // Actualizam ecranul pentru a afisa promptul
                echo(); curs_set(1); timeout(-1); // Permitem afisarea caracterelor introduse de admin pentru username si dezactivam timeout-ul pentru a astepta input-ul
                getnstr(input, sizeof(input) - 1); // Citim username-ul introdus de admin
                noecho(); curs_set(0); timeout(200); // Dezactivam echo-ul pentru a nu afisa caracterele introduse de admin (mai ales la parola), ascundem cursorul si setam timeout pentru a putea actualiza interfata chiar si atunci cand adminul nu introduce nimic
                login_stage = 2; // Mergem la etapa urmatoare
            }

            if (login_stage == 2) { // Etapa introducere parola
                if (has_colors()) attron(COLOR_PAIR(3));
                mvprintw(MIN_OFFSET + 4, 2, "Password: ");
                if (has_colors()) attroff(COLOR_PAIR(3));
                refresh();
                echo(); curs_set(1); timeout(-1);
                getnstr(password, sizeof(password) - 1);
                noecho(); curs_set(0);

                strncpy(current_user, input, sizeof(current_user) - 1); // salvam user-ul
 
                char hash_hex[HEX_LENGTH + 1];
                sha256_hash(password, hash_hex); // Generam hash-ul

                char login_msg[STR_LENGTH];
                (void)snprintf(login_msg, sizeof(login_msg),
                         "LOGIN %s %s\n", input, hash_hex); //trimitem la server
                memset(password, 0, sizeof(password)); // resetam campul de parola( nu pastram parola )

                int n = udp_rpc(login_msg); // trimitem mesajul si asteptam raspunsul
                timeout(200);  
                if (n > 0 && strncmp(last_response, "OK", 2) == 0) { // Daca e ok modificam textele si il setam ca fiind autentificat
                    authenticated = 1;
                    login_stage   = 1;
                    (void)snprintf(status_msg, sizeof(status_msg),
                             "Authenticated as %.238s", current_user);
                    (void)snprintf(last_response, sizeof(last_response),
                             "Login successful!\n");
                } else if (n > 0 && strncmp(last_response, "BUSY", 4) == 0) { // Daca e busy, inseamna ca alt admin e deja conectat, deci afisam mesajul corespunzator
                    login_stage = 1;
                    (void)snprintf(last_response, sizeof(last_response),
                             "Another admin is already logged in.\n");
                } else { // Daca e alta eroare, presupunem ca login-ul a esuat din alte motive (ex: parola gresita) si afisam mesajul de eroare corespunzator
                    login_failed = 1;
                    login_stage  = 1;
                    (void)snprintf(last_response, sizeof(last_response),
                             n < 0 ? "No reply from server.\n" : "Login failed.\n");
                }
            }
        }

        else { // Autentificat
            if (has_colors()) attron(COLOR_PAIR(4)); // Setam culoarea pentru lista de comenzi disponibile
            mvprintw(MIN_OFFSET,  2, "Commands:"); 
            mvprintw(MIN_OFFSET + 1,  4, "u - UPTIME");
            mvprintw(MIN_OFFSET + 1,  PAGE_LIMIT*2+MIN_OFFSET+MIN_OFFSET, "c - CLIENTS");
            mvprintw(MIN_OFFSET + 2,  PAGE_LIMIT*2+MIN_OFFSET+MIN_OFFSET, "w - QUEUE STATS");
            mvprintw(MIN_OFFSET + 3,  PAGE_LIMIT*2+MIN_OFFSET+MIN_OFFSET, "x - CANCEL JOB");
            mvprintw(MIN_OFFSET + 4, PAGE_LIMIT*2+MIN_OFFSET+MIN_OFFSET, "b - BAN IP");
            mvprintw(MIN_OFFSET*2, PAGE_LIMIT*2+MIN_OFFSET+MIN_OFFSET, "n - UNBAN IP");
            
            mvprintw(MIN_OFFSET + 2,  4, "k - KICK user");
            mvprintw(MIN_OFFSET + 3,  4, "s - SHUTDOWN");
            mvprintw(MIN_OFFSET + 4,  4, "v - VIEW LOGS");
            mvprintw(MIN_OFFSET + MIN_OFFSET,  4, "o - LOGOUT");
            mvprintw(MIN_OFFSET + MIN_OFFSET + 1,  4, "q - Quit");
            if (has_colors()) attroff(COLOR_PAIR(4)); // Resetam culoarea dupa lista de comenzi

            
            if (current_page >= max_pages) current_page = max_pages - 1; // Daca pagina curenta depaseste numarul maxim de pagini, o setam la ultima pagina disponibila
            if (current_page <  0)        current_page = 0; // Daca pagina curenta e negativa, o setam la prima pagina

            if (has_colors()) attron(COLOR_PAIR(5) | A_BOLD);
            mvprintw(4, 2, "Latest activity: %s", latest_live_log); // Afisam ultimul log live primit de la server
            if (has_colors()) attroff(COLOR_PAIR(5) | A_BOLD);

            mvprintw(MIN_OFFSET*2+3, 2, "Last response (page %d/%d):", current_page + 1, max_pages); // Afisam ultimul raspuns primit de la server, care poate fi rezultatul unei comenzi sau un mesaj de log, impreuna cu informatii despre pagina curenta daca raspunsul e paginat
            {
                int yy = MIN_OFFSET*2 + 4; // Logica pentru a afisa raspunsul pe mai multe linii(log-uri si clienti conectati)
                const char *p = last_response;
                while (p && *p && yy < LINES - 3) {
                    int len = (int)strcspn(p, "\n");
                    mvprintw(yy++, 4, "%.*s", len, p);
                    p += len;
                    if (*p == '\n') p++;
                }
            }

            if (max_pages > 1)
                mvprintw(LINES - 2, 2, "a = prev page   d = next page");
        }

        refresh(); // Actualizam ecranul pentru a afisa toate modificarile facute in aceasta iteratie

        int ch = getch(); // Citim un caracter de la admin pentru a procesa comenzile sau pentru a naviga prin pagini

        if (ch == 'a' && current_page > 0) { // Daca adminul apasa 'a' si nu e deja pe prima pagina, mergem la pagina anterioara
            current_page--;
            char msg[STR_LENGTH];
            (void)snprintf(msg, sizeof(msg), "LOGS %s %d\n", user_searched, current_page);
            udp_rpc(msg);
            continue;
        }
        if (ch == 'd' && current_page < max_pages - 1) { // Daca adminul apasa 'd' si nu e deja pe ultima pagina, mergem la pagina urmatoare
            current_page++;

            char msg[STR_LENGTH];
            (void)snprintf(msg, sizeof(msg), "LOGS %s %d\n", user_searched, current_page);
            udp_rpc(msg);
            continue;
        }

        if (ch == 'q') { // Daca adminul apasa 'q', ne deconectam si inchidem programul
            if (authenticated) udp_send("LOGOUT\n");
            running = 0;
            break;
        }

        if (!authenticated) continue; // Daca nu e autentificat, ignoram orice alta tasta apasata in afara de cele pentru login

        if (ch == 'u') { // Daca adminul apasa 'u', trimitem comanda de uptime la server si asteptam raspunsul
            udp_rpc("UPTIME\n");
            current_page = 0;
        }
        else if (ch == 's') {
            udp_rpc("SHUTDOWN\n");
            current_page = 0;
        }
        else if (ch == 'o') { // Daca adminul apasa 'o', trimitem comanda de logout la server, resetam starea de autentificare si curatam informatiile despre user-ul curent
            udp_rpc("LOGOUT\n");
            authenticated = 0;
            login_stage   = 1;
            memset(current_user, 0, sizeof(current_user));
            (void)snprintf(status_msg, sizeof(status_msg), "Logged out");
            last_response[0] = '\0';
            current_page = 0;
        }
        else if (ch == 'k') { // Logica kick, asematoarea cu cea de login
            echo(); curs_set(1); timeout(-1);
            if (has_colors()) attron(COLOR_PAIR(3));
            mvprintw(MIN_OFFSET*2+2, 2, "Enter username to kick: ");
            if (has_colors()) attroff(COLOR_PAIR(3));
            getnstr(input, sizeof(input) - 1);
            timeout(200); noecho(); curs_set(0);

            char msg[STR_LENGTH];
            (void)snprintf(msg, sizeof(msg), "KICK %s\n", input);
            udp_rpc(msg);
            current_page = 0;
        }
        else if (ch == 'v') { // Logica de view logs(all time) asematoare cu cea de kick
            echo(); curs_set(1); timeout(-1);
            if (has_colors()) attron(COLOR_PAIR(3));
            
            mvprintw(MIN_OFFSET*2+2, 2, "Username for logs (or 'all'): ");
            if (has_colors()) attroff(COLOR_PAIR(3));
            getnstr(input, sizeof(input) - 1);
            timeout(200); noecho(); curs_set(0);
            current_page = 0;
            input[strcspn(input, "\n")] = '\0';
            strncpy(user_searched, input, sizeof(user_searched)); // Retinem userul cautat pentru navigarea intre pagini
            char msg[STR_LENGTH];
            char req_pages[STR_LENGTH];
            (void)snprintf(req_pages, sizeof(req_pages), "PAGESLOGS %s\n", input);
            udp_rpc(req_pages); // cerem numarul de pagini
            if (strncmp(last_response, "PAGES", strlen("PAGES")) == 0) { // Daca serverul intoarce "PAGES", actualizam limita maxima de paginare
                max_pages = atoi(last_response + strlen("PAGES")+1);
            }
            (void)snprintf(msg, sizeof(msg), "LOGS %s %d\n", input, current_page); // Cerem prima pagina
            udp_rpc(msg);
            current_page = 0;
        }
        else if (ch == 'c') { // Daca adminul apasa 'c', trimitem comanda de clients la server pentru a vedea clientii conectati si asteptam raspunsul
            udp_rpc("CLIENTS\n");
            current_page = 0;
        }
        else if (ch == 'w') { // Asemator pentru queue stats
            udp_rpc("QSTATS\n");
            current_page = 0;
        }
        else if (ch == 'x') { // Logica pentru cancel job, care necesita atat username-ul cat si numele fisierului pentru a putea anula jobul corespunzator, deci cerem ambele informatii adminului
            char user_input[STR_LENGTH] = {0};
            char file_input[STR_LENGTH] = {0};

            echo(); curs_set(1); timeout(-1);
            mvprintw(MIN_OFFSET*2+2, 2, "Username: ");
            getnstr(user_input, sizeof(user_input) - 1);
            mvprintw(MIN_OFFSET*2+2, PAGE_LIMIT*4+MIN_OFFSET*2, "Filename: ");
            getnstr(file_input, sizeof(file_input) - 1);
            timeout(200); noecho(); curs_set(0);

            char msg[STR_LENGTH];
            (void)snprintf(msg, sizeof(msg), "CANCELJOB %s %s\n", user_input, file_input);
            udp_rpc(msg);
            current_page = 0;
        }
        else if (ch == 'b') {
            echo(); curs_set(1); timeout(-1);
            mvprintw(MIN_OFFSET*2+2, 2, "IP to ban: ");
            getnstr(input, sizeof(input) - 1);
            timeout(200); noecho(); curs_set(0);

            char msg[STR_LENGTH];
            (void)snprintf(msg, sizeof(msg), "BAN %s\n", input);
            udp_rpc(msg);
            current_page = 0;
        }
        else if (ch == 'n') {
            echo(); curs_set(1); timeout(-1);
            mvprintw(MIN_OFFSET*2+2, 2, "IP to unban: ");
            getnstr(input, sizeof(input) - 1);
            timeout(200); noecho(); curs_set(0);

            char msg[STR_LENGTH];
            (void)snprintf(msg, sizeof(msg), "UNBAN %s\n", input);
            udp_rpc(msg);
            current_page = 0;
        }
    }

    endwin();
    unlink(actual_client_path); // Stergem socketul clientului pentru a curata resursele, astfel incat sa nu ramana socketi inutili in /tmp daca programul se inchide
    if (sock >= 0) close(sock);
    return 0;
}

