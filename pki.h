#ifndef __PKI_AWOO__
#define __PKI_AWOO__

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#define KEY_LENGTH  2048
#define PUB_EXP     3
#define MAX_CHAR 8000

void generateRSAKeypair(char* pri_key, char* pub_key);
RSA* read_public_key_file(const char* filename);
RSA* read_private_key_file(const char* filename);
char* PKI_encrypt(const char* message, int* message_length, RSA* public_key_rsa_obj);
char* PKI_decrypt(const char* message, int message_length, RSA* private_key_rsa_obj);
void saveToFile(const char* buffer, const char* filename, int RSA_obj_size);
void loadFromFileToBuf(char* buffer, const char* filename, int RSA_obj_size);
#endif