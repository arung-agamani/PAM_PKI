#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#define KEY_LENGTH  2048
#define PUB_EXP     3
#define MAX_CHAR 8000

RSA* read_public_key_file(const char* filename);
RSA* read_private_key_file(const char* filename);
char* PKI_decrypt(const char* message, int message_length, RSA* private_key_rsa_obj);

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
    // printf("Successfully read the public key\n");
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
    // printf("Successfully read the private key\n");
    return rsa_pri_key;
}
char* PKI_decrypt(const char* message, int message_length, RSA* private_key_rsa_obj) {
    // printf("Decrypting....\n");
    char* decrypt = malloc(message_length);
    RSA_private_decrypt(message_length, (unsigned char*)message, (unsigned char*)decrypt, private_key_rsa_obj, RSA_PKCS1_OAEP_PADDING);
    // printf("Finished decrypting...\n");
    return decrypt;
}

PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	// printf("AWOOOOOOOOOOOASDKLFLJASFJKLSDFK\n");
	return PAM_SUCCESS;
}

/* expected hook, this is where custom stuff happens */
PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {
	int retval;
	unsigned char isUSBExist = 0, isFileExist = 0, isContentAsExpected = 0;
	struct dirent *de;
	DIR* dir;

	const char* pUsername;
	char *base = "/media/";
	char publicKeyFilename[100];
	char privateKeyPath[100];
	char credential[64];
	char str[64];
	retval = pam_get_user(pamh, &pUsername, "Username: ");
	printf("Awoo Gate of Babylon\nPlease enter your credential used on key generation : ");
	scanf("%s", credential);
	printf("Now please enter your current username : ");
	scanf("%s", pUsername);
	strcpy(str, base);
	strcat(str, pUsername);
	strcat(str, "/");
	strcpy(publicKeyFilename, "public-");
	strcat(publicKeyFilename, credential);
	strcat(publicKeyFilename, ".txt");
	strcpy(privateKeyPath, "/etc/pam.d/babylon/private-");
	strcat(privateKeyPath, credential);
	strcat(privateKeyPath, ".txt");
	printf("Target directory search : %s\n", str);
	dir = opendir(str);
	if (dir) {
		while ((de = readdir(dir)) != NULL) {
			printf("Folder found : %s\n", de->d_name);
			if (strcmp(de->d_name, ".") != 0 && strcmp(de->d_name, "..") != 0) {
				printf("External device found! \"%s\"\n", de->d_name);
				isUSBExist = 1;
				strcat(str, de->d_name);
				strcat(str, "/");
				dir = opendir(str);
				while((de = readdir(dir)) != NULL) {
					if (strcmp(de->d_name, publicKeyFilename) == 0) {
						printf("Credential file is exists! %s\n", publicKeyFilename);
						isFileExist = 1;
						char filePath[100];
						char fileContent[8196];
						char message[KEY_LENGTH/8];
						char* encrypt = NULL;
						char* decrypt = NULL;
						char filename[100];
						char filename2[100];
						char encryptedFilename[100];
						strcpy(message, "awoo was here h3h3 uwu---");
						strcat(message, credential);
						int message_length = 0;
						strcpy(filename, "public-");
						strcpy(filename2, "private-");
						strcpy(encryptedFilename, "/etc/pam.d/babylon/enc-");
						strcat(encryptedFilename, credential);
						strcat(filename, credential);
						strcat(filename2, credential);
						strcat(filename, ".txt");
						strcat(filename2, ".txt");
						strcat(encryptedFilename, ".txt");
						strcpy(filePath, str);
						strcat(filePath, de->d_name);
						printf("Keys gonna parsed: %s\n", filePath);
						// RSA* pub_key = read_public_key_file(filePath);
						FILE *public_key_file = fopen(filePath, "rb");
						printf("aaaaaa");
						fseek(public_key_file, 0, SEEK_END);
						long file_size_pub = ftell(public_key_file);
						fseek(public_key_file, 0, SEEK_SET);
						char *public_key_string = malloc(file_size_pub+1);
						fread(public_key_string, 1, file_size_pub, public_key_file);
						fclose(public_key_file);
						public_key_string[file_size_pub] = 0x0;
						
						BIO *bio_pub = BIO_new_mem_buf((void*)public_key_string, (int)strlen(public_key_string));
						RSA *rsa_pub_key = PEM_read_bio_RSA_PUBKEY(bio_pub, NULL, 0, NULL);
						
						RSA* pri_key = read_private_key_file(privateKeyPath);
						printf("Keys parsed\n");
						free(encrypt);
						encrypt = malloc(RSA_size(rsa_pub_key));
						FILE *f = fopen(encryptedFilename, "r");
						fread(encrypt, sizeof(*encrypt), RSA_size(rsa_pub_key), f);
						fclose(f);
						decrypt = PKI_decrypt(encrypt, 256, pri_key);
						if (strcmp(message, decrypt) == 0) {
							printf("Authenticated!!\n");
							return PAM_SUCCESS;
						}
						return PAM_AUTH_ERR;
					}
				}
				if (isFileExist == 0) {
					return PAM_AUTH_ERR;
					break;
				}
			}
		}
		if (isUSBExist == 0) {
			return PAM_AUTH_ERR;
		}
	} else if (ENOENT == errno) {
		printf("Directory doesnt exists\n");
	} else {
		printf("Opendir failed hmm\n");
	}
	
}