#include "pki.h"
#include <stdio.h>
#include <string.h>
#include <malloc.h>

void generateRSAKeypair(char* pri_key, char* pub_key) {
    size_t pri_len;
    size_t pub_len;
    printf("Generating RSA (%d bits) keypair...\n", KEY_LENGTH);
    RSA *keypair = RSA_generate_key(KEY_LENGTH, PUB_EXP, NULL, NULL);
    BIO *pri = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(pub, keypair);
    pri_len = BIO_pending(pri);
    pub_len = BIO_pending(pub);
    pri_key = malloc(pri_len + 1);
    pub_key = malloc(pub_len + 1);
    BIO_read(pri, pri_key, pri_len);
    BIO_read(pub, pub_key, pub_len);
    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';
    // public_BIO = pub_key;
    // private_BIO = pri_key;
}
RSA* read_public_key_file(const char* filename) {
    FILE *public_key_file = fopen(filename, "rb");
    fseek(public_key_file, 0, SEEK_END);
    long file_size_pub = ftell(public_key_file);
    fseek(public_key_file, 0, SEEK_SET);
    char *public_key_string = malloc(file_size_pub+1);
    fread(public_key_string, 1, file_size_pub, public_key_file);
    fclose(public_key_file);
    public_key_string[file_size_pub] = 0x0;
    BIO *bio_pub = BIO_new_mem_buf((void*)public_key_string, (int)strlen(public_key_string));
    RSA *rsa_pub_key = PEM_read_bio_RSA_PUBKEY(bio_pub, NULL, 0, NULL);
    printf("Successfully read the public key\n");
    return rsa_pub_key;
}
RSA* read_private_key_file(const char* filename) {
    FILE *private_key_file = fopen(filename, "rb");
    fseek(private_key_file, 0, SEEK_END);
    long file_size_pri = ftell(private_key_file);
    fseek(private_key_file, 0, SEEK_SET);
    char *private_key_string = malloc(file_size_pri+1);
    fread(private_key_string, 1, file_size_pri, private_key_file);
    fclose(private_key_file);
    private_key_string[file_size_pri] = 0x0;
    BIO *bio_pri = BIO_new_mem_buf((void*)private_key_string, (int)strlen(private_key_string));
    RSA *rsa_pri_key = PEM_read_bio_RSAPrivateKey(bio_pri, NULL, 0, NULL);
    printf("Successfully read the private key\n");
    return rsa_pri_key;
}
char* PKI_encrypt(const char* message, int* message_length, RSA* public_key_rsa_obj) {
    printf("Encrypting....\n");
    char *encrypt = malloc(RSA_size(public_key_rsa_obj));
    int encrypt_len = RSA_public_encrypt(strlen(message)+1, (unsigned char*)message, (unsigned char*)encrypt, public_key_rsa_obj, RSA_PKCS1_OAEP_PADDING);
    *message_length = encrypt_len;
    printf("Finished encrypting...\n");
    return encrypt;    
}
char* PKI_decrypt(const char* message, int message_length, RSA* private_key_rsa_obj) {
    printf("Decrypting....\n");
    char* decrypt = malloc(message_length);
    RSA_private_decrypt(message_length, (unsigned char*)message, (unsigned char*)decrypt, private_key_rsa_obj, RSA_PKCS1_OAEP_PADDING);
    printf("Finished decrypting...\n");
    return decrypt;
}
void saveToFile(const char* buffer, const char* filename, int RSA_obj_size) {
    FILE *f = fopen(filename, "w");
    fwrite(buffer, sizeof(*buffer), RSA_obj_size, f);
    fclose(f);
}
void loadFromFileToBuf(char* buffer, const char* filename, int RSA_obj_size) {
    free(buffer);
    buffer = malloc(RSA_obj_size);
    FILE *f = fopen(filename, "r");
    fread(buffer, sizeof(*buffer), RSA_obj_size, f);
    fclose(f);
}