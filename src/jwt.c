/* jwt.c  - Implementarea token-urilor JWT pentru autentificare si autorizare
    Acest fisier contine functiile necesare pentru a crea, semna si verifica token-uri JWT folosind HMAC-SHA256.
    Functii principale:
    - create_jwt: Creeaza un token JWT pentru un user_id dat, semnat cu un secret specificat. Token-ul contine un payload cu sub (user_id) si exp (timp de expirare).
    - verify_jwt: Verifica un token JWT dat folosind secretul specificat. Returneaza user_id daca token-ul este valid si nu a expirat, sau NULL in caz contrar.
    - base64url_encode: Functie auxiliara pentru a codifica date in format Base64
    - base64url_decode: Functie auxiliara pentru a decodifica date din format Base64
*/



#include <openssl/hmac.h>  // Pentru a folosi functiile de HMAC pentru semnarea token-urilor JWT
#include <openssl/evp.h>// Pentru a folosi functiile de digest pentru a calcula hash-ul necesar semnarii JWT-urilor
#include <openssl/bio.h> // Pentru a folosi functiile de BIO pentru a codifica si decodifica date in format Base64, necesar pentru structura JWT-urilor
#include <openssl/buffer.h> // Pentru a folosi functiile de buffer pentru a gestiona datele in timpul codarii si decodarii Base64
#include <stdio.h>
#include <string.h>

#define JWT_LENGTH 1024 // Dimensiunea maxima a token-ului JWT generat sau verificat, asigurand spatiu suficient pentru header, payload si semnatura
#define PAYLOAD 256 // Dimensiunea maxima a payload-ului JWT, care contine informatiile despre subiect (user_id) si timpul de expirare (exp), asigurand spatiu suficient pentru aceste date si pentru eventuale extensii viitoare ale payload-ului
#define DECODE 64 // Dimensiunea maxima a user_id decodat din payload-ul JWT, asigurand spatiu suficient pentru a stoca un user_id valid si pentru a preveni depasirea bufferului in cazul unor payload-uri neasteptat de mari
#define HOUR 3600 // Constanta pentru a seta timpul de expirare al token-ului JWT la o ora de la momentul crearii, asigurand un echilibru intre securitate si comoditate pentru utilizatori, permitandu-le sa ramana autentificati pentru o perioada rezonabila fara a fi nevoiti sa se reautentifice prea frecvent.
#define OFFSET 7 // Constanta pentru a ajuta la extragerea user_id din payload-ul JWT, reprezentand lungimea sirului "\"sub\":\"" care precede user_id in payload, permitand functiei verify_jwt sa localizeze si sa extraga corect user_id din payload dupa ce a decodificat token-ul JWT



// Stackoverflow solution
void base64url_encode(const unsigned char *input, int length, char *output) {
    BIO *b64 = BIO_new(BIO_f_base64()); // Cream un obiect BIO pentru codificare Base64
    BIO *mem = BIO_new(BIO_s_mem()); // Cream un obiect BIO pentru a stoca rezultatul codificarii in memorie
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // Setam flag-ul pentru a elimina newline-urile din output-ul Base64, deoarece JWT-urile trebuie sa fie intr-un format compact fara spatii sau newline-uri
    BIO_push(b64, mem); // Legam obiectul BIO de codificare Base64 la obiectul BIO de memorie, astfel incat datele codificate sa fie scrise in memorie
    BIO_write(b64, input, length); // Scriem datele de intrare in obiectul BIO de codificare Base64, care le va codifica si le va stoca in obiectul BIO de memorie
    BIO_flush(b64); // Golim BIO-ul pentru a ne asigura ca toate datele au fost procesate si scrise in memorie

    BUF_MEM *ptr; // Structura pentru a obtine pointerul si lungimea datelor codificate stocate in BIO-ul de memorie
    BIO_get_mem_ptr(mem, &ptr); // Obtinem pointerul catre datele codificate si lungimea acestora din BIO-ul de memorie, astfel incat sa putem procesa rezultatul codificarii pentru a-l transforma in formatul Base64URL necesar pentru JWT-uri

    int j = 0;
    for (size_t i = 0; i < ptr->length; i++) {
        if (ptr->data[i] == '+') output[j++] = '-';
        else if (ptr->data[i] == '/') output[j++] = '_';
        else if (ptr->data[i] == '=') continue;
        else output[j++] = ptr->data[i];
    }
    output[j] = '\0';

    BIO_free_all(b64); // Eliberam resursele alocate pentru obiectele BIO, asigurandu-ne ca nu exista scurgeri de memorie dupa ce am terminat de codificat datele in format Base64URL pentru JWT-uri
}

//Functia pentru a crea un token JWT pentru un user_id dat, semnat cu un secret specificat. Token-ul contine un payload cu sub (user_id) si exp (timp de expirare).
char* create_jwt(const int user_id, const char *secret) {
    static char jwt_token[JWT_LENGTH];
    char header[] = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
    char payload[PAYLOAD];

    long exp = time(NULL) + HOUR;
    (void)snprintf(payload, sizeof(payload), "{\"sub\":\"%d\",\"exp\":%ld}", user_id, exp);

    char enc_header[PAYLOAD], enc_payload[PAYLOAD];
    base64url_encode((unsigned char*)header, (int)strlen(header), enc_header);
    base64url_encode((unsigned char*)payload, (int)strlen(payload), enc_payload);

    char unsigned_part[PAYLOAD*2];
    (void)snprintf(unsigned_part, sizeof(unsigned_part), "%s.%s", enc_header, enc_payload);

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int result_len;
    HMAC(EVP_sha256(), secret, (int)strlen(secret),
         (unsigned char*)unsigned_part, (int)strlen(unsigned_part),
         digest, &result_len);

    char enc_signature[PAYLOAD*2];
    base64url_encode(digest, (int)result_len, enc_signature);

    (void)snprintf(jwt_token, sizeof(jwt_token), "%s.%s", unsigned_part, enc_signature);

    return jwt_token;
}
int base64url_decode(const char *input, unsigned char *output) {
    int len = (int)strlen(input);

    char *temp = strdup(input);
    for (int i = 0; i < len; i++) {
        if (temp[i] == '-') temp[i] = '+';
        if (temp[i] == '_') temp[i] = '/';
    }

    int padding = (4 - (len % 4)) % 4;
    int full_len = len + padding;
    char *padded_temp = malloc(full_len + 1);
    strncpy(padded_temp, temp, full_len + 1);
    for (int i = 0; i < padding; i++) {
        padded_temp[len + i] = '=';
    }
    padded_temp[full_len] = '\0';

    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new_mem_buf(padded_temp, full_len);
    
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, mem);

    int decoded_len = BIO_read(b64, output, full_len);

    if (decoded_len > 0) {
        output[decoded_len] = '\0';
    }

    free(temp);
    free(padded_temp);
    BIO_free_all(b64);

    return decoded_len;
}
char* verify_jwt(const char *token, const char *secret) {
    static char user_id[DECODE] = {0};
    char header_payload[PAYLOAD*2];
    char payload_b64[PAYLOAD*2];
    unsigned char decoded_payload[PAYLOAD*2];

    char *first_dot = strchr(token, '.');
    char *second_dot = strrchr(token, '.');
    if (!first_dot || !second_dot || first_dot == second_dot) return NULL;

    //Sig verify
    size_t hp_len = second_dot - token;
    strncpy(header_payload, token, hp_len);
    header_payload[hp_len] = '\0';

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int result_len;
    HMAC(EVP_sha256(), secret, (int)strlen(secret), (unsigned char*)header_payload, strlen(header_payload), digest, &result_len);
    char sig_expected[PAYLOAD];
    base64url_encode(digest, (int)result_len, sig_expected);

    if (strcmp(second_dot + 1, sig_expected) != 0) return NULL;

    // Decode Payload
    size_t p_len = second_dot - (first_dot + 1);
    strncpy(payload_b64, first_dot + 1, p_len);
    payload_b64[p_len] = '\0';

    base64url_decode(payload_b64, decoded_payload);
    char *sub_key = strstr((char*)decoded_payload, "\"sub\":\"");
    if (sub_key) {
        sub_key += OFFSET; 
        char *end = strchr(sub_key, '"');
        if (end) {
            size_t id_len = end - sub_key;
            strncpy(user_id, sub_key, id_len);
            user_id[id_len] = '\0';
        }
    }
    char *exp_key = strstr((char*)decoded_payload, "\"exp\":");
    if (exp_key) {
        exp_key += OFFSET-1;
        long exp_val = atol(exp_key);

        time_t acum = time(NULL);
        if (acum > exp_val) {
            return NULL;
        }
    }

    return user_id;
}
