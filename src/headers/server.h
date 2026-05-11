#ifndef _H_SERVER
#define _H_SERVER

#include <pthread.h>
#include <sqlite3.h>
#include "scanner.h"
#ifndef MIN_LENGTH
#define MIN_LENGTH 50
#endif
#ifndef HEX_LENGTH
#define HEX_LENGTH 65
#endif
#ifndef STR_LENGTH
#define STR_LENGTH 256
#endif

typedef struct {
    int found;
    char knownfile[MIN_LENGTH*2];
    char signature[MIN_LENGTH*2];
    
} virus_t;



typedef struct {
    int id;
    char filename[MIN_LENGTH];
    char result_path[STR_LENGTH];
    char username[MIN_LENGTH];
} file_record_t;

int check_login(char *username, char *password, char *role);
void add_client(int sock, const char *username);
void remove_client(int sock);
void remove_client_at_index(int index);
void ensure_dir(char *username);
void safe_write(int fd, const char *buf, unsigned long count);
void add_logs(char *username, char *action);
void update_user_column(char *username, char *column, char *value);
int find_client_socket_by_username(const char *username);
#ifndef strlcat
size_t strlcat(char *dst, const char *src, size_t siz);
#endif
void base64url_encode(const unsigned char *input, int length, char *output);
char* find_db_username(char* userid);
int find_db_id(char* username);
void add_user_hash(char *username, char *hash, char *role);
int base64url_decode(const char *input, unsigned char *output);
char* create_jwt(const int user_id, const char *secret);
char* verify_jwt(const char *token, const char *secret);
int find_ip_ban(const char* ip);
int remove_ip_ban(const char* ip);
int add_ip_ban(const char* ip, const char* user_logged);
virus_t find_virus_by_hash(char *hash);
void insert_virus(char *original_name, char *signature, char *hash);

char* find_file_uuid(char* user, char* filename);
char* find_file_scanpath(char* uuid);
char* find_file_path(char* uuid);
char* find_file_filename(char* uuid);
file_record_t find_file_by_minisig(char* minisig);
void add_file_if_not_exists(char* user, char* filename, char* filepath, char* resultpath);
int write_all(int sock, const char *buf, size_t len);

void update_file_minisig(char* user, char* filename, char* minisig);


int compute_time(const char* str);


pthread_mutex_t admin_lock = PTHREAD_MUTEX_INITIALIZER;
int adminLogged = 0;
int adminSocket = -1;

typedef struct {
    int sock;
    char username[MIN_LENGTH];
} client_t;

client_t *clients = NULL;
int client_count = 0;
int client_capacity = 0;
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;


int unix_based_socket = 0;

Scanner *g_scanner = NULL;
 

int download_file_result(int sock, char *filename, char *username);

#endif


