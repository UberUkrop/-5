#include <openssl/conf.h>
#include <openssl/applink.c>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#define KEY_LENGTH 16
void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}
int main (int argc, char **argv)
{
    if (argc == 6)
    {
        unsigned char key[KEY_LENGTH] = {0};
        memcpy(key, argv[4], KEY_LENGTH);
        unsigned char iv[KEY_LENGTH] = {0};
        memcpy(iv, argv[5], KEY_LENGTH);
        //read in file to string
        FILE *file_in = fopen(argv[2], "rb");
        fseek(file_in, 0, SEEK_END);
        long fsize = ftell(file_in);
        fseek(file_in, 0, SEEK_SET);
        unsigned char *plaintext = malloc(fsize * sizeof(char) + 1);
        fread(plaintext, 1, fsize, file_in);
        fclose(file_in);
        printf("\nResult\n");
        if (argv[1][0] == 'd')
        {
            //decrypt
            unsigned char decryptedtext[fsize];
            decrypt(plaintext, fsize, key, iv, decryptedtext);
            printf(decryptedtext);
            printf("\n");
            FILE *file_out = fopen(argv[3], "w");
            fputs(decryptedtext, file_out);
            fclose(file_out);
        }
        if (argv[1][0] == 'e')
        {
            //encrypt
            unsigned char ciphertext[fsize*2];
            encrypt(plaintext, fsize, key, iv, ciphertext);
            printf(ciphertext);
            printf("\n");
            FILE *file_out = fopen(argv[3], "w");
            fputs(ciphertext, file_out);
            fclose(file_out);
        }

    }
    else printf("Wrong arguments!");
    return 0;
}