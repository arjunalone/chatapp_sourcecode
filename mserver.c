#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 8080
#define BUF_SIZE 1024
#define PASSWORD_FILE "client_password.txt"

// Secure password hashing parameters
#define SALT_SIZE 16
#define HASH_ITERATIONS 100000
#define HASH_SIZE 32

void handle_openssl_error() {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

void hash_password(const char *password, unsigned char *salt, unsigned char *hash) {
    if (!RAND_bytes(salt, SALT_SIZE)) {
        perror("Failed to generate salt");
        exit(EXIT_FAILURE);
    }
    if (!PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_SIZE, 
                           HASH_ITERATIONS, EVP_sha256(), HASH_SIZE, hash)) {
        handle_openssl_error();
    }
}

int verify_password(const char *password, unsigned char *stored_salt, unsigned char *stored_hash) {
    unsigned char hash[HASH_SIZE];
    if (!PKCS5_PBKDF2_HMAC(password, strlen(password), stored_salt, SALT_SIZE, 
                           HASH_ITERATIONS, EVP_sha256(), HASH_SIZE, hash)) {
        handle_openssl_error();
    }
    return memcmp(hash, stored_hash, HASH_SIZE) == 0;
}

void prompt_for_password(char *password, int is_new) {
    printf(is_new ? "Set a new client password: " : "Enter client password: ");
    fgets(password, BUF_SIZE, stdin);
    password[strcspn(password, "\n")] = 0;
}

int manage_password() {
    FILE *file = fopen(PASSWORD_FILE, "rb");
    unsigned char stored_salt[SALT_SIZE];
    unsigned char stored_hash[HASH_SIZE];

    if (!file) {
        char new_password[BUF_SIZE];
        prompt_for_password(new_password, 1);

        file = fopen(PASSWORD_FILE, "wb");
        if (!file) {
            perror("Failed to create password file");
            exit(EXIT_FAILURE);
        }

        unsigned char salt[SALT_SIZE], hash[HASH_SIZE];
        hash_password(new_password, salt, hash);
        fwrite(salt, 1, SALT_SIZE, file);
        fwrite(hash, 1, HASH_SIZE, file);
        fclose(file);

        printf("Password set successfully.\n");
        return 1;
    }

    fread(stored_salt, 1, SALT_SIZE, file);
    fread(stored_hash, 1, HASH_SIZE, file);
    fclose(file);

    char entered_password[BUF_SIZE];
    prompt_for_password(entered_password, 0);

    if (verify_password(entered_password, stored_salt, stored_hash)) {
        printf("Authentication successful.\n");
        return 1;
    } else {
        printf("Authentication failed.\n");
        return 0;
    }
}

void generate_session_key_iv(unsigned char *key, unsigned char *iv) {
    if (!RAND_bytes(key, 16) || !RAND_bytes(iv, 16)) {
        perror("Failed to generate key or IV");
        exit(EXIT_FAILURE);
    }
}

int main() {
    SSL_library_init();
    SSL_load_error_strings();
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);

    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        handle_openssl_error();
    }

    if (!manage_password()) {
        exit(EXIT_FAILURE);
    }

    int server_fd;
    struct sockaddr_in serv_addr;
    socklen_t addr_len = sizeof(serv_addr);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 1) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Waiting for a secure connection...\n");

    int client_fd = accept(server_fd, NULL, &addr_len);
    if (client_fd < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_fd);

    if (SSL_accept(ssl) <= 0) {
        handle_openssl_error();
    } else {
        printf("Secure connection established.\n");

        unsigned char key[16], iv[16];
        generate_session_key_iv(key, iv);
        SSL_write(ssl, key, 16);
        SSL_write(ssl, iv, 16);

        unsigned char buffer[BUF_SIZE] = {0};
        while (1) {
            int bytes_read = SSL_read(ssl, buffer, BUF_SIZE);
            if (bytes_read <= 0) {
                break;
            }
            printf("Client: %s\n", buffer);

            printf("Server: ");
            fgets((char *)buffer, BUF_SIZE, stdin);
            SSL_write(ssl, buffer, strlen((char *)buffer));
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_fd);
    close(server_fd);
    SSL_CTX_free(ctx);

    return 0;
}

