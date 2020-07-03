gcc -c awoo-pam.c -w -lcrypto
ld -x -lcrypto --shared -o /lib/security/awoo-pam.so awoo-pam.o
rm awoo-pam.o