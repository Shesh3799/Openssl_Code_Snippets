#include<iostream>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/rand.h>
int main()
{
    // The plaintext message to be encrypted
    const char* secretMessage = "This is secret message";

    // The key and IV sizes for AES-256-CBC
    const int KEY_SIZE = 32;
    const int IV_SIZE = 16;

    //seed the random generator
    RAND_poll();

    //Check whether or not the random generator has been sufficiently seeded
    //If not, functions such as RAND_bytes() will fail
    if (RAND_status() != 1) {
        std::cerr << "Error: OpenSSL PRNG not seeded" << std::endl;
        exit(-1);
    }

    // Generate a random key and IV
    unsigned char key[KEY_SIZE], iv[IV_SIZE];
    if (RAND_bytes(key, KEY_SIZE) != 1 || RAND_bytes(iv, IV_SIZE) != 1) {
        std::cerr << "Error: Failed to generate random key/IV" << std::endl;
        exit(-1);
    }

    // Allocate a buffer for the ciphertext
    size_t max_ciphertext_len = EVP_MAX_BLOCK_LENGTH + strlen(secretMessage);
    unsigned char* ciphertext = new unsigned char[max_ciphertext_len];
    size_t ciphertext_len = 0;

    // Encrypt the message using AES-256-CBC
    //Allocates and returns a cipher context.
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    //Sets up cipher context ctx for encryption with cipher type
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    //Encrypts inl bytes from the buffer in and writes the encrypted version to out
    if (EVP_EncryptUpdate(ctx, ciphertext, (int*)&ciphertext_len, (const unsigned char*)secretMessage, strlen(secretMessage)) != 1) {
        std::cerr << "Error: Failed to encrypt message" << std::endl;
        exit(-1);
    }
    
    if (EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, (int*)&max_ciphertext_len - ciphertext_len) != 1) {
        std::cerr << "Error: Failed to finalize encryption" << std::endl;
        exit(-1);
    }
    ciphertext_len += max_ciphertext_len - ciphertext_len;

    
    std::cout << "Ciphertext: ";
    for (size_t i = 0; i < ciphertext_len; i++) {
        std::cout << std::hex << (int)ciphertext[i];
    }
    std::cout << std::endl;

    // Allocate a buffer for the decrypted message
    size_t max_plaintext_len = ciphertext_len;
    unsigned char* decryptedMessage = new unsigned char[max_plaintext_len];
    size_t decrypted_text_len = 0;

    // Decrypt the ciphertext using AES-256-CBC
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    if (EVP_DecryptUpdate(ctx, decryptedMessage, (int*)&decrypted_text_len, ciphertext, (int)ciphertext_len) != 1) {
        std::cerr << "Error: Failed to decrypt message" << std::endl;
        exit(-1);
    }
    if (EVP_DecryptFinal_ex(ctx, decryptedMessage + decrypted_text_len, (int*)&max_plaintext_len - decrypted_text_len) != 1) {
        std::cerr << "Error: Failed to finalize decryption" << std::endl;
        exit(-1);
    }
    decrypted_text_len += max_plaintext_len - decrypted_text_len;

    decryptedMessage[decrypted_text_len] = 0;

    // Print the decrypted plaintext
    std::cout << "Decrypted text message : " << decryptedMessage << std::endl;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    delete[] ciphertext;
    delete[] decryptedMessage;
    return 0;
}
