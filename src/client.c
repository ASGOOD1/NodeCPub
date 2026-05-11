/*  client.c - Aplicatia client simplu 
    Aceasta aplicatie permite conectarea la server si transmiterea de comenzi.
    Functionalitati:
    * Conectare la server folosind socket UNIX.
    * Trimiterea de comenzi catre server si afisarea raspunsurilor.
    * Comenzi suportate: register, login, upload, download, stats, scan, list, exit.
    Erori tratate:
    * Eroare la crearea socketului
    * Eroare la conectare
    * Eroare la trimiterea datelor
    * Eroare la primirea datelor
    * Eroare la interactiunea cu fisierele locale (pentru upload/download)
    Posibil si alte erori, dar acestea sunt tratate la nivel de server.


*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h> // Pentru a comunica cu socketuri de tip inet 
#include "headers/sha256.h" // Folosit pentru a face hashing parolelor inainte de a le trimite catre server pentru autentificare.
#include <ctype.h> // Pentru a verifica daca un caracter e alfanumeric (folosit la validarea inputului)
#include <sys/socket.h> // Pentru socket, bind, recv, send
#include <sys/stat.h> // Pentru a verifica existenta fisierelor si a obtine informatii despre ele
#include <strings.h> // strcasecmp pentru comparare case-insensitive a comenzilor
#include <fcntl.h> // Pentru a folosi open cu O_CREAT pentru download
#include <signal.h> // Pentru a gestiona semnalele (de exemplu, pentru a prinde SIGINT si a ne deconecta curat)
#include <poll.h> // Pentru a folosi poll pentru a astepta date pe socket cu timeout
#include <getopt.h> // Pentru a parsa argumentele din linia de comanda (de exemplu, pentru a specifica adresa serverului sau portul)
#include <libconfig.h> // Autologin 
#include <time.h>

//Constante pentru configurare
#define BUFFER_SIZE       4096
#define HEX_LENGTH        64
#define CLIENT_PORT       8080
#define STR_LENGTH        256
#define DOWNLOAD_PERM     0666
#define BUFFER_LIMIT      65536
#define TIMEOUT_MS        10000
#define POLL_INDEFINIT    -1
#define PROGRESS_INTERVAL (80LL * 1024 * 1024)
#define MB_CONVERSION     1048576.0
#ifndef MIN_LENGTH
#define MIN_LENGTH 50
#endif


char client_env_var[HEX_LENGTH/2]; // // Folosim un env var unic per socket ca flag de rulare pentru bucla principala

// Structura pentru bufferul de primire, care permite citirea liniilor si a fisierelor in mod eficient, gestionand datele ramase intre apeluri.
typedef struct {
    int  fd;
    char buf[BUFFER_LIMIT];
    int  start;
    int  end;
} RecvBuf;

// Functii pentru gestionarea bufferului de primire

// Aceste functii au fost generate dupa ce am creat o verisiune functionala dar instabila a acestora
// Acestea sunt acum optimizate pentru a reduce numarul de apeluri la recv, pentru a gestiona eficient datele ramase in buffer intre apeluri si pentru a permite citirea atat a liniilor cat si a fisierelor mari fara a depasi limitele de memorie sau a pierde date.
// rbuf_readline: Citeste o linie din buffer, asteptand date daca e necesar, si o stocheaza in out. Returneaza lungimea liniei sau -1 in caz de eroare.
static int rbuf_readline(RecvBuf *rb, char *out, size_t maxout, int timeout_ms) {
    size_t outlen = 0;

    for (;;) { // For infity, pentru ca vom iesi din bucla doar cand citim o linie completa sau cand apare o eroare
        for (int i = rb->start; i < rb->end; i++) { // Parcurgem bufferul de la pozitia start la end pentru a cauta o linie completa
            if (outlen >= maxout - 1) return -1; // Daca linia depaseste dimensiunea maxima permisa, returnam eroare
            out[outlen++] = rb->buf[i]; // Adaugam caracterul curent la output si incrementam lungimea liniei
            if (rb->buf[i] == '\n') { // Daca am gasit un newline, inseamna ca am citit o linie completa
                rb->start = i + 1; // Mutam startul bufferului dupa linia citita
                out[outlen] = '\0'; // Adaugam terminatorul de string la finalul liniei
                return (int)outlen; // Returnam lungimea liniei citite
            }
        }

        // Daca am ajuns aici, inseamna ca nu am gasit un newline in buffer, deci trebuie sa asteptam mai multe date de la socket
        int remaining = rb->end - rb->start; // Calculam cate date raman in buffer dupa pozitia start
        if (remaining > 0 && rb->start > 0) // Daca exista date ramase si startul nu este deja la inceputul bufferului, mutam datele ramase la inceputul bufferului pentru a face loc pentru noile date
            memmove(rb->buf, rb->buf + rb->start, remaining); // Mutam datele ramase la inceputul bufferului
        rb->start = 0; // Resetam startul la 0, deoarece am mutat datele ramase la inceputul bufferului
        rb->end   = remaining; // Setam endul la numarul de date ramase, deoarece acestea sunt acum la inceputul bufferului

        struct pollfd pfd = { .fd = rb->fd, .events = POLLIN }; // Pregatim structura pentru poll, specificand ca vrem sa asteptam date de la socketul rb->fd
        int r = poll(&pfd, 1, timeout_ms); // Asteptam pana cand exista date de citit pe socket sau pana cand expira timeoutul 
        if (r < 0)  { perror("poll"); return -1; }// daca r == 0, a expirat timeoutul, iar daca pfd.revents contine POLLHUP sau POLLERR, inseamna ca conexiunea a fost inchisa sau a aparut o eroare la socket.
        if (r == 0) { (void)fprintf(stderr, "Timeout waiting for header\n"); return -1; }// Daca r < 0, a aparut o eroare la poll
        if (pfd.revents & (POLLHUP | POLLERR)) return -1; // Ca la r < 0

        int n = (int)recv(rb->fd, rb->buf + rb->end,
                          sizeof(rb->buf) - rb->end, 0); // Citim efectiv datele de la socket
        if (n <= 0) return -1;
        rb->end += n; // Mutam sfarsitul bufferului in functie de cate date am citit
    }
}

/* Writes exactly file_size bytes to fd f — no upper size limit, pure chunked. */
// Functia aceasta este folosita la download in general(varianta mea dadea erori cateodata)
static int rbuf_recv_file(RecvBuf *rb, int f, long long file_size, int timeout_ms) {
    long long remaining  = file_size;
    long long last_print = 0;

    // Daca dupa citirea headerului au ramas bytes in buffer, ii scirem primii in fisier
    int buffered = rb->end - rb->start;
    if (buffered > 0) {
        long long take = (long long)buffered < remaining
                         ? (long long)buffered : remaining;
        ssize_t w = 0;
        while (w < (ssize_t)take) {
            ssize_t r2 = write(f, rb->buf + rb->start + w, (size_t)(take - w));
            if (r2 <= 0) { perror("write buffered"); return -1; }
            w += r2;
        }
        rb->start += (int)take;
        remaining -= take;
    }

    /* Reset cursor so the loop always recvs into index 0 */
    rb->start = 0;
    rb->end   = 0;

    while (remaining > 0) {
        struct pollfd pfd = { .fd = rb->fd, .events = POLLIN };
        int r = poll(&pfd, 1, timeout_ms);
        if (r < 0)  { perror("poll"); return -1; }
        if (r == 0) { (void)fprintf(stderr, "Timeout during download\n"); return -1; }
        if (pfd.revents & (POLLHUP | POLLERR)) {
            (void)fprintf(stderr, "Connection lost\n"); return -1;
        }

        // Cerem din socket minimul dintre bytes ramasi si dimensiunea bufferului
        size_t want = (remaining < (long long)sizeof(rb->buf))
                      ? (size_t)remaining : sizeof(rb->buf);

        ssize_t n = recv(rb->fd, rb->buf, want, 0);
        if (n < 0)  { perror("recv"); return -1; }
        if (n == 0) { (void)fprintf(stderr, "Connection closed early\n"); return -1; }

        ssize_t w = 0;
        while (w < n) {
            ssize_t r2 = write(f, rb->buf + w, (size_t)(n - w));
            if (r2 <= 0) { perror("write"); return -1; }
            w += r2;
        }

        remaining -= n;

        // Calculam progresul download-ului pentru afisare
        long long received = file_size - remaining;
        if (received - last_print >= PROGRESS_INTERVAL || remaining == 0) {
            printf("Downloaded: %.1f MB / %.1f MB (%.1f%%)                  \r",
                   (double)received  / MB_CONVERSION,
                   (double)file_size / MB_CONVERSION,
                   100.0 * (double)received / (double)file_size);
            (void)fflush(stdout);
            last_print = received;
        }
    }

    printf("\n");
    return 0;
}
// Aici incepe efectiv clientul
int sock;


//Functie care citeste o linie de la un fd dat, folosind poll pentru a astepta date cu timeout. Returneaza lungimea liniei citite sau -1 in caz de eroare.
static int poll_recv_line(int fd, char *buf, size_t maxlen, int timeout_ms) {
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    size_t received = 0;

    while (received < maxlen - 1) {
        int ret = poll(&pfd, 1, timeout_ms);
        if (ret < 0)  { perror("poll"); return -1; }
        if (ret == 0) { (void)fprintf(stderr, "Timeout waiting for response!\n"); return -1; }
        if (pfd.revents & (POLLHUP | POLLERR)) return -1;

        int chunk = (int)recv(fd, buf + received, maxlen - 1 - received, 0);
        if (chunk <= 0) return -1;
        received += chunk;

        if (memchr(buf, '\n', received) != NULL) break;
    }

    // Terminam explicit buffer ul ca string pentru parsari ulterioare
    buf[received] = '\0';
    return (int)received;
}

// Incercam logout la SIGINT pentru a inchide sesiunea curat pe server
void handle_sigint(int sig) {
    (void)sig;
    send(sock, "LOGOUT\n", strlen("LOGOUT\n"), 0);
    unsetenv(client_env_var); // NOLINT safe enough here
    close(sock);
    
}

// Validarea caracterelor(se mai face odata in server)
int isValidCharacter(char c) {
    return isalnum((unsigned char)c) || c == '_' || c == '-' || c == '.';
}
int main(const int argc, const char *argv[]) {
    // Instalare handler SIGINT inainte de operatii de retea
    const char *HOST = "127.0.0.1";
    const char* user_arg = NULL;
    const char* pass_arg = NULL;
    (void)signal(SIGINT, handle_sigint);  

    // Parsarea argumentelor (acasta aplicatie permite si inregistrarea
    // folosind -user username -password password, caz in care se va face register in loc de login, dar e optionala)
    struct option long_options[] = {
        {"server", required_argument, NULL, 's'},
        {"help", no_argument, NULL, 'h'},
        {"user", required_argument, NULL, 'u'},
        {"password", required_argument, NULL, 'p'},
        {0, 0, NULL, 0}
    };
    int opt;
    while ((opt = getopt_long(argc, (char * const *)argv, "s:u:p:h", long_options, NULL)) != -1) { // NOLINT not in thread
        switch (opt) {
            case 's':
                HOST = optarg;
                break;
            case 'u':
                user_arg = optarg;
                break;
            case 'p':
                pass_arg = optarg;
                break;
            case 'h':
            case '?':
            default:
                (void)printf("Usage: %s [OPTIONS]\n\n"
                       "Options:\n"
                       "  -s, --server <IP>       Server IP address to connect to (default: 127.0.0.1)\n"
                        "  -h, --help              Display this help message\n",
                argv[0]);
                exit(EXIT_SUCCESS); // NOLINT not in thread
                break;
        }
    }  

    //Verificari (daca exista user trb si pass si vice-versa)
    if(user_arg != NULL && pass_arg == NULL) {
        (void)fprintf(stderr, "Password is required when username is provided(registration mode).\n");
        return EXIT_FAILURE;
    }
    if(pass_arg != NULL && user_arg == NULL) {
        (void)fprintf(stderr, "Username is required when password is provided(registration mode).\n");
        return EXIT_FAILURE;
    }

    //Creare socket si conectare

    sock = socket(AF_INET, SOCK_STREAM, 0);
    client_env_var[0] = 0;
    (void)snprintf(client_env_var, sizeof(client_env_var) ,"client_%d_running", sock);
    setenv(client_env_var, "1", 1); // NOLINT not threaded
    if (sock < 0) { perror("socket"); return EXIT_FAILURE; }

    // Construim IP-ul textual in format binar pentru connect
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port   = htons(CLIENT_PORT);
    inet_pton(AF_INET, HOST, &server.sin_addr);

    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
        perror("connect"); return EXIT_FAILURE;
    }

    // Daca au fost date --user/--password, facem mai intai register
    if(user_arg != NULL && pass_arg != NULL) {
        char msg[STR_LENGTH] = {0};
        char hash_hex[HEX_LENGTH + 1];
        char *pwd_dup = strdup(pass_arg);
        if(!pwd_dup) {
            (void)fprintf(stderr, "Memory allocation failed\n");
            close(sock);
            return EXIT_FAILURE;
        }
        if(pwd_dup[strlen(pwd_dup) - 1] == '\n') {
            pwd_dup[strlen(pwd_dup) - 1] = '\0';
        } // Failsafe(stergem newline de la final daca exista)
        char* user_dup = strdup(user_arg);
        if(!user_dup) {
            (void)fprintf(stderr, "Memory allocation failed\n");
            free(user_dup);
            free(pwd_dup);
            close(sock);
            return EXIT_FAILURE;
        }
        if(user_dup[strlen(user_dup) - 1] == '\n') {
            user_dup[strlen(user_dup) - 1] = '\0';
        }
        if(strlen(user_dup) < 3 || strlen(pwd_dup) < 3) {
            (void)fprintf(stderr, "Username and password must be at least 3 characters long\n");
            free(user_dup);
            free(pwd_dup);
            close(sock);
            return EXIT_FAILURE;
        } // Verificare lungime minima nume si parola
        for(int c = 0; c<(int)strlen(user_dup); c++) {
            if(!isValidCharacter(user_dup[c])) {
                (void)fprintf(stderr, "Invalid character in username. Allowed: alphanumeric, '_', '-', '.'\n");
                free(user_dup);
                free(pwd_dup);
                close(sock);
                return EXIT_FAILURE;
            }
        } // Verificare caractere valide

        for(int c = 0; c<(int)strlen(pwd_dup); c++) {
            if(!isValidCharacter(pwd_dup[c])) {
                (void)fprintf(stderr, "Invalid character in password. Allowed: alphanumeric, '_', '-', '.'\n");
                free(user_dup);
                free(pwd_dup);
                close(sock);
                return EXIT_FAILURE;
            }
        }// Verificare caractere valide
        sha256_hash(pwd_dup, hash_hex); // generare hash
        free(pwd_dup); // eliberam parola
        (void)snprintf(msg, sizeof(msg), "REGISTER %s %s\n", user_dup, hash_hex);
        send(sock, msg, strlen(msg), 0); // transmitem comanda de register catre server
        free(user_dup); // eliberam memoria alocata pentru username, nu mai avem nevoie de ea
        char resp[BUFFER_SIZE];
        if (poll_recv_line(sock, resp, sizeof(resp), TIMEOUT_MS) < 0) { // asteptam raspunsul de la server pentru comanda de register, daca nu primim niciun raspuns in timeout, afisam eroare si inchidem conexiunea
            (void)fprintf(stderr, "No response received for registration.\n");
            close(sock); return EXIT_FAILURE;
        }
        if (strstr(resp, "OK") == NULL) { // daca raspunsul nu contine "OK", inseamna ca inregistrarea a esuat din diverse motive (ex: username deja folosit) si afisam mesajul de eroare corespunzator
            printf("Registration failed: %s\n", resp);
            close(sock); return EXIT_FAILURE;
        }
        printf("Registration successful!\n"); // Daca am ajuns aici, inregistrarea a fost un succes, deci putem continua cu login-ul normal folosind username-ul si parola deja introduse, fara a mai cere utilizatorului sa le introduca din nou
    }
    
     // Login automat din data.cfg, daca esueaza punem input manual
    char user[HEX_LENGTH], pw[HEX_LENGTH];
    char hash_hex[HEX_LENGTH + 1];
    config_t cfg;
    config_setting_t *setting;
    config_init(&cfg);
    if(!config_read_file(&cfg, "./data.cfg")) {printf("err read"); goto cfg_parse_error;}
    setting = config_lookup(&cfg, "logindata");
    if(setting == NULL)  {printf("err read setting"); goto cfg_parse_error;}
    const char *cfg_user;
    if(!config_setting_lookup_string(setting, "username", &cfg_user))  {printf("err user"); goto cfg_parse_error;}
    // Config citit cu succes
    const char *cfg_pwd;
    if(!config_setting_lookup_string(setting, "password", &cfg_pwd))  {printf("err pwd"); goto cfg_parse_error;}
    (void)snprintf(user, sizeof(user), "%s", cfg_user);
    (void)snprintf(pw, sizeof(pw), "%s", cfg_pwd);
    
    goto parsed_successfully;
    cfg_parse_error:
    user[0] = 0;
    pw[0] = 0;
    config_destroy(&cfg);
    printf("User: ");
    if (scanf("%63s", user) != 1) { (void)fprintf(stderr, "Error reading user\n"); return EXIT_FAILURE; }
    printf("Password: ");
    if (scanf("%63s", pw) != 1)   { (void)fprintf(stderr, "Error reading password\n"); return EXIT_FAILURE; }
    parsed_successfully:
    sha256_hash(pw, hash_hex); // Generam hash-ul

    char msg[STR_LENGTH] = {0};
    (void)snprintf(msg, sizeof(msg), "LOGIN %s %s\n", user, hash_hex); 
    send(sock, msg, strlen(msg), 0); // Trimitem mesajul de login catre server

    char resp[BUFFER_SIZE];
    if (poll_recv_line(sock, resp, sizeof(resp), TIMEOUT_MS) < 0) { // Asteptam raspunsul ca la register
        (void)fprintf(stderr, "No response received for login.\n");
        close(sock); return EXIT_FAILURE;
    }
    if (strstr(resp, "OK") == NULL) {
        printf("Login failed: %s\n", resp);
        close(sock); return EXIT_FAILURE;
    }
    printf("Login successful!\n");

    struct pollfd fds[2]; // Pregatim structura pentru poll, astfel incat sa putem astepta atat input de la utilizator cat si mesaje de la server in acelasi timp, fara a bloca programul
    fds[0].fd     = STDIN_FILENO; // Asteptam input de la utilizator pe stdin
    fds[0].events = POLLIN; // Asteptam sa fie disponibil de citit
    fds[1].fd     = sock; // Asteptam mesaje de la server pe socketul de comunicare
    fds[1].events = POLLIN; //  Asteptam sa fie disponibil de citit

    while (getenv(client_env_var)) { // NOLINT not in any thread
        printf("Commands (download/stats/scan/list/size/backup/cleanup/exit): "); // Afisam lista de comenzi
        (void)fflush(stdout);

        int ret = poll(fds, 2, POLL_INDEFINIT); // Asteptam pana cand exista input de la utilizator sau mesaje de la server, fara timeout (POLL_INDEFINIT)
        if (ret < 0) { perror("poll"); break; } // Daca ret == 0, nu se intampla nimic, dar cum am folosit POLL_INDEFINIT, acest caz nu ar trebui sa apara

        /* Unsolicited server message */
        if (fds[1].revents & POLLIN) { // Daca exista mesaje de la server, le citim si le afisam imediat, chiar daca utilizatorul nu a introdus nicio comanda, pentru a permite serverului sa trimita notificari sau mesaje importante in timp real
            char respbody[STR_LENGTH];
            int n = (int)recv(sock, respbody, sizeof(respbody) - 1, MSG_PEEK); // Citim mesajul de la server
            if (n <= 0) { printf("\nConnection closed by server.\n"); break; } // Daca n == 0, inseamna ca serverul a inchis conexiunea, deci afisam un mesaj si iesim din bucla
            respbody[n] = '\0';


            if(strncmp(respbody, "SIZE ", strlen("SIZE ")) != 0){
                printf("\n[Server]: %s\n", respbody); // Afisam mesajul de la server, precedat de o eticheta pentru a-l diferentia de alte mesaje
                n = (int)recv(sock, respbody, sizeof(respbody) - 1, 0);
                (void)n;
            }
            else {
                RecvBuf rb = { .fd = sock, .start = 0, .end = 0 };

                char header[STR_LENGTH];
                if (rbuf_readline(&rb, header, sizeof(header), TIMEOUT_MS) < 0) {
                    (void)fprintf(stderr, "Timeout on header\n"); continue;
                }
                if (strncmp(header, "SIZE ", strlen("SIZE ")) != 0) {
                    printf("Server error: %s\n", header); continue;
                }

                long long file_size = atoll(header + strlen("SIZE "));
                if (file_size <= 0) {
                    printf("Invalid file size: %lld\n", file_size); continue;
                }

                char local_file[STR_LENGTH];
                srand(time(NULL));
                int random = rand(); // NOLINT not in thread, but we just need a random number for the filename, so it's fine
                (void)snprintf(local_file, sizeof(local_file), "downloaded_result_%d.txt", random);

                int f = open(local_file, O_WRONLY | O_CREAT | O_TRUNC, DOWNLOAD_PERM);
                if (f < 0) { perror("open"); continue; }

                if (rbuf_recv_file(&rb, f, file_size, TIMEOUT_MS) == 0){
                    printf("\nDownload completed: %s (%lld bytes)\n", local_file, file_size);

                    close(f);
                }
                else {
                    printf("\nDownload failed\n");
                    close(f);
                    unlink(local_file);
                }
            }
            if (strstr(respbody, "You have been kicked") != NULL) break; // Daca mesajul e de tipul "You have been kicked", inseamna ca serverul ne-a deconectat fortat, deci afisam mesajul si iesim din bucla
            continue;
        }

        if (!(fds[0].revents & POLLIN)) continue; // Daca nu exista input de la utilizator, continuam sa asteptam(Fallback)

        char cmd[HEX_LENGTH] = {0}; 
        if (scanf("%63s", cmd) != 1) continue; // Citim comanda introdusa de utilizator, daca nu reusim sa citim nicio comanda, continuam sa asteptam input valid

        /* ── EXIT ── */
        if (strcasecmp(cmd, "exit") == 0) { // Daca comanda e exit trimitem mesajul de logout
            send(sock, "LOGOUT\n", strlen("LOGOUT\n"), 0);
            unsetenv(client_env_var); // NOLINT not in thread
            break;
        }

        
        else if(strcasecmp(cmd, "backup") == 0) {
            char file[MIN_LENGTH] = {0};
            printf("Backup time(1d = 1Day, 1h = 1Hour, 1m = 1Minute, M for month, any number not just 1): ");
            if (scanf("%49s", file) != 1) { (void)fprintf(stderr, "Error reading filename\n"); continue; }
            (void)snprintf(msg, sizeof(msg), "BACKUP %s\n", file);
            send(sock, msg, strlen(msg), 0);
            int n = poll_recv_line(sock, resp, sizeof(resp), TIMEOUT_MS);
            if (n > 0) {
                if (strstr(resp, "You have been kicked") != NULL) {
                    printf("\n%s", resp); unsetenv(client_env_var); break; // NOLINT not threaded
                }
                printf("%s\n", resp);
            }
        }
        else if(strcasecmp(cmd, "cleanup") == 0) {
            char file[MIN_LENGTH] = {0};
            printf("Files older than the cleanup time will be deleted!\n");
            printf("Cleanup time(1d = 1Day, 1h = 1Hour, 1m = 1Minute, M for month, any number not just 1): ");
            if (scanf("%49s", file) != 1) { (void)fprintf(stderr, "Error reading filename\n"); continue; }
            (void)snprintf(msg, sizeof(msg), "CLEANUP %s\n", file);
            send(sock, msg, strlen(msg), 0);
            int n = poll_recv_line(sock, resp, sizeof(resp), TIMEOUT_MS);
            if (n > 0) {
                if (strstr(resp, "You have been kicked") != NULL) {
                    printf("\n%s", resp); unsetenv(client_env_var); break; // NOLINT not threaded
                }
                printf("%s\n", resp);
            }
        }

        else if(strcasecmp(cmd, "size") == 0) {
            char file[MIN_LENGTH] = {0};
            printf("Size format (B, KB, MB): ");
            if (scanf("%49s", file) != 1) { (void)fprintf(stderr, "Error reading filename\n"); continue; }
            (void)snprintf(msg, sizeof(msg), "SIZE %s\n", file);
            send(sock, msg, strlen(msg), 0);
            int n = poll_recv_line(sock, resp, sizeof(resp), TIMEOUT_MS);
            if (n > 0) {
                if (strstr(resp, "You have been kicked") != NULL) {
                    printf("\n%s", resp); unsetenv(client_env_var); break; // NOLINT not threaded
                }
                printf("%s\n", resp);
            }
        }

        /* ── DOWNLOAD RESULT ── */
        else if (strcasecmp(cmd, "download") == 0) { // la fel ca la download
            char file[STR_LENGTH] = {0};
            printf("File: ");
            if (scanf("%255s", file) != 1) { (void)fprintf(stderr, "Error reading filename\n"); continue; }

            (void)snprintf(msg, sizeof(msg), "DOWNLOAD %s\n", file);
            send(sock, msg, strlen(msg), 0);

            RecvBuf rb = { .fd = sock, .start = 0, .end = 0 };

            char header[STR_LENGTH];
            if (rbuf_readline(&rb, header, sizeof(header), TIMEOUT_MS) < 0) {
                (void)fprintf(stderr, "Timeout on header\n"); continue;
            }
            if (strncmp(header, "SIZE ", strlen("SIZE ")) != 0) {
                printf("Server error: %s\n", header); continue;
            }

            long long file_size = atoll(header + strlen("SIZE "));
            if (file_size <= 0) {
                printf("Invalid file size: %lld\n", file_size); continue;
            }

            char local_file[STR_LENGTH];
            (void)snprintf(local_file, sizeof(local_file), "downloaded_result_%s.txt", file);

            int f = open(local_file, O_WRONLY | O_CREAT | O_TRUNC, DOWNLOAD_PERM);
            if (f < 0) { perror("open"); continue; }

            if (rbuf_recv_file(&rb, f, file_size, TIMEOUT_MS) == 0){
                printf("\nDownload completed: %s (%lld bytes)\n", local_file, file_size);

                close(f);
            }
            else {
                printf("\nDownload failed\n");
                close(f);
                unlink(local_file);
            }
        }

        /* ── STATS ── */
        else if (strcasecmp(cmd, "stats") == 0) { // Transmite comanda catre server
            char file[STR_LENGTH] = {0};
            printf("File: ");
            if (scanf("%127s", file) != 1) { (void)fprintf(stderr, "Error reading file\n"); continue; }

            (void)snprintf(msg, sizeof(msg), "STATS %s\n", file);
            send(sock, msg, strlen(msg), 0);

            int n = poll_recv_line(sock, resp, sizeof(resp), TIMEOUT_MS);
            if (n > 0) {
                if (strstr(resp, "You have been kicked") != NULL) {
                    printf("\n%s", resp); unsetenv(client_env_var); break; // NOLINT not threaded
                }
                printf("%s\n", resp);
            }
        }

        /* ── SCAN ── */
        else if (strcasecmp(cmd, "scan") == 0) { 
            char file[STR_LENGTH] = {0};
            printf("File: ");
            if (scanf("%255s", file) != 1) { (void)fprintf(stderr, "Error reading filename\n"); continue; }

            //Incercam sa-l deschidem
            int f = open(file, O_RDONLY);
            if (f == -1) { (void)fprintf(stderr, "Error opening file\n"); continue; }

            //Ii dam stat (pentru a lua size-ul)
            struct stat st;
            if (fstat(f, &st) != 0) { perror("fstat"); close(f); continue; }
            size_t size = (size_t)st.st_size;

            (void)snprintf(msg, sizeof(msg), "SCAN %s %zu\n", file, size);
            send(sock, msg, strlen(msg), 0);


            char buf[BUFFER_SIZE];
            ssize_t  bytes;
            size_t   sent       = 0;
            size_t   last_print = 0;

            while ((bytes = read(f, buf, sizeof(buf))) > 0) { //Cat timp mai avem ce citi din fisier, citim in buffer
                ssize_t w = 0;
                while (w < bytes) { // Asiguram ca trimitem tot ce am citit in buffer, chiar daca send trimite doar o parte din date
                    ssize_t s = send(sock, buf + w, (size_t)(bytes - w), 0);// Trimitem datele de la pozitia w in buffer, pentru restul de bytes ramasi
                    if (s <= 0) { perror("send"); goto upload_done; } // Daca send returneaza 0 sau o valoare negativa, inseamna ca a aparut o eroare la trimitere, deci afisam mesajul de eroare si iesim din bucla de upload
                    w += s; // Incrementam pozitia w cu numarul de bytes trimisi, pentru a continua trimiterea restului de date din buffer
                }
                sent += (size_t)bytes; // Incrementam numarul total de bytes trimisi cu numarul de bytes cititi in acest pas
                if (sent - last_print >= (size_t)PROGRESS_INTERVAL || sent == size) { // Daca am trimis suficient de multe date de la ultimul update sau daca am trimis tot fisierul, afisam progresul upload-ului
                    printf("Uploaded: %.1f MB / %.1f MB (%.1f%%)                  \r",
                           (double)sent / MB_CONVERSION,
                           (double)size / MB_CONVERSION,
                           100.0 * (double)sent / (double)size);
                    (void)fflush(stdout);
                    last_print = sent; // Actualizam last_print pentru a sti cand sa afisam urmatorul update de progres
                }
            }
            upload_done:
            printf("\nUpload completed: %s (%zu bytes)\n", file, size);
            close(f);

            
        }

        // Comanda LIST citeste in loop pana primeste markerul "END_OF_LIST"
        else if (strcasecmp(cmd, "list") == 0) { // Logica comanda list e putin diferita
            (void)snprintf(msg, sizeof(msg), "LIST\n");
            send(sock, msg, strlen(msg), 0);

            struct pollfd spfd = { .fd = sock, .events = POLLIN };
            for (;;) {
                int pr = poll(&spfd, 1, TIMEOUT_MS);
                if (pr <= 0) { if (pr == 0) (void)fprintf(stderr, "Timeout list.\n"); break; }
                if (spfd.revents & (POLLHUP | POLLERR)) break;

                int n = (int)recv(sock, resp, sizeof(resp) - 1, 0);
                if (n <= 0) break;
                resp[n] = '\0';

                char *end_marker = strstr(resp, "END_OF_LIST"); // Serverul va trimite "END_OF_LIST" la finalul listei pentru a indica ca nu mai sunt date de citit, astfel incat clientul sa stie cand sa se opreasca din citirea raspunsului
                if (end_marker != NULL) {
                    *end_marker = '\0';
                    printf("%s", resp);
                    break;
                }
                printf("%s", resp); // Afisam fiecare parte a listei pe masura ce o primim, pentru a permite afisarea in timp real a listei, chiar daca aceasta este foarte lunga
            }
        }
    }

    close(sock);
    return 0;
}


