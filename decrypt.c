#include "pki.h"
#include <string.h>

void createKeypairFiles();
void readWrite(char* username);

int main(int argc, char** argv) {
    // createKeypairFiles();
    readWrite(argv[1]);
    return 0;
}

void readWrite(char* username) {
    char message[KEY_LENGTH/8];
    char* encrypt = NULL;
    char* decrypt = NULL;
    char filename[100];
    char filename2[100];
    char filenameEnc[100];
    strcpy(message, "awoo was here h3h3 uwu---");
    strcat(message, username);
    int message_length = 0;
    printf("Message to be encrypted : %s\n", message);
    strcpy(filename, "public-");
    strcpy(filename2, "private-");
    strcpy(filenameEnc, "/etc/pam.d/babylon/enc-");
    strcat(filename, username);
    strcat(filename2, username);
    strcat(filenameEnc, username);
    strcat(filename, ".txt");
    strcat(filename2, ".txt");
    strcat(filenameEnc, ".txt");
    RSA* pub = read_public_key_file(filename);
    RSA* pri = read_private_key_file(filename2);
    encrypt = PKI_encrypt(message, &message_length, pub);
    printf("aaaaa\n");
    saveToFile(encrypt, filenameEnc, RSA_size(pub));
    loadFromFileToBuf(encrypt, filenameEnc, RSA_size(pub));
    decrypt = PKI_decrypt(encrypt, 256, pri);
    printf("encrypt_len : %d\n", message_length);
    printf("=====ENCRYPTED=====\n%s\n========\nDecrypted message : %s\n", encrypt, decrypt);
}



void createKeypairFiles() {
    printf("Begin creating keypair...\n");
    size_t pri_len;            // Length of private key
    size_t pub_len;            // Length of public key
    char   *pri_key;           // Private key
    char   *pub_key;           // Public key
    printf("Generating RSA (%d bits) keypair...", KEY_LENGTH);
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
    // printf("\n%s\n%s\n", pri_key, pub_key);
    saveToFile(pri_key, "privateKey.txt", pri_len);
    saveToFile(pub_key, "publicKey.txt", pub_len);
    printf("Finished creating keypair...\n");
}