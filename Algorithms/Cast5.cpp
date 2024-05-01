#pragma warning(disable : 4996)

#include <openssl/cast.h>
#include <openssl/rand.h>
#include <iostream>
#include <iomanip>
#include <string>

void initialize_cast5_key(unsigned char key[CAST_KEY_LENGTH], unsigned char iv[CAST_BLOCK], int& key_len) {
    // Generate random Key
    RAND_bytes(key, CAST_KEY_LENGTH);
    key_len = CAST_KEY_LENGTH * 8;  // Set key len with bits

    // Generate random IV
    RAND_bytes(iv, CAST_BLOCK);
}

std::string cast5_encrypt(const std::string& plaintext, const unsigned char key[CAST_KEY_LENGTH], const unsigned char iv[CAST_BLOCK], int key_len) {
    CAST_KEY enc_key;
    CAST_set_key(&enc_key, key_len / 8, key);

    int padding_required = CAST_BLOCK - (plaintext.size() % CAST_BLOCK);
    std::string padded_text = plaintext + std::string(padding_required, char(padding_required));

    std::string ciphertext(padded_text.size(), '\0');
    unsigned char temp_iv[CAST_BLOCK];
    memcpy(temp_iv, iv, CAST_BLOCK);
    CAST_cbc_encrypt((unsigned char*)&padded_text[0], (unsigned char*)&ciphertext[0], padded_text.size(), &enc_key, temp_iv, CAST_ENCRYPT);

    return ciphertext;
}

std::string cast5_decrypt(const std::string& ciphertext, const unsigned char key[CAST_KEY_LENGTH], const unsigned char iv[CAST_BLOCK], int key_len) {
    CAST_KEY dec_key;
    CAST_set_key(&dec_key, key_len / 8, key);

    std::string decryptedtext(ciphertext.size(), '\0');
    unsigned char temp_iv[CAST_BLOCK];
    memcpy(temp_iv, iv, CAST_BLOCK);
    CAST_cbc_encrypt((unsigned char*)&ciphertext[0], (unsigned char*)&decryptedtext[0], ciphertext.size(), &dec_key, temp_iv, CAST_DECRYPT);

    // Remove Padding
    int padding_len = decryptedtext.back();
    decryptedtext.resize(decryptedtext.size() - padding_len);

    return decryptedtext;
}

int main() {
    unsigned char key[CAST_KEY_LENGTH];  // Key
    unsigned char iv[CAST_BLOCK];        // Beginning Vector
    int key_len;                         // Key Length

    initialize_cast5_key(key, iv, key_len);

    std::string plaintext = "Hidden text is here.";
    std::cout << "Original Text: " << plaintext << std::endl;

    std::string ciphertext = cast5_encrypt(plaintext, key, iv, key_len);
    std::cout << "Encrypted Text: ";
    for (unsigned char c : ciphertext) {
        std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)c;
    }
    std::cout << std::endl;

    std::string decryptedtext = cast5_decrypt(ciphertext, key, iv, key_len);
    std::cout << "Decrypted Text: " << decryptedtext << std::endl;

    return 0;
}