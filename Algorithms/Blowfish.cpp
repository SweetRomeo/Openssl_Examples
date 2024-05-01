// ConsoleApplication4.cpp : Bu dosya 'main' işlevi içeriyor. Program yürütme orada başlayıp biter.
//
#pragma warning(disable : 4996)

#include <openssl/rand.h>
#include <openssl/blowfish.h>
#include <iostream>
#include <map>
#include <string>
#include <iomanip>


void initialize_bf_key(unsigned char key[16], unsigned char iv[BF_BLOCK], int& key_len) {
    // Generate Random Key (For Example We are using 128 bit Key)
    RAND_bytes(key, 16);  // 128 bit = 16 bytes
    key_len = 128;  // Set the key length

    // Generate Random IV
    RAND_bytes(iv, BF_BLOCK);
}

std::string bf_encrypt(const std::string& plaintext, const unsigned char key[16], const unsigned char iv[BF_BLOCK], int key_len) {
    BF_KEY enc_key;
    BF_set_key(&enc_key, key_len / 8, key);

    int padding_required = BF_BLOCK - (plaintext.size() % BF_BLOCK);
    std::string padded_text = plaintext + std::string(padding_required, char(padding_required));

    std::string ciphertext(padded_text.size(), '\0');
    unsigned char temp_iv[BF_BLOCK];
    memcpy(temp_iv, iv, BF_BLOCK);
    BF_cbc_encrypt((unsigned char*)&padded_text[0], (unsigned char*)&ciphertext[0], padded_text.size(), &enc_key, temp_iv, BF_ENCRYPT);

    return ciphertext;
}

std::string bf_decrypt(const std::string& ciphertext, const unsigned char key[16], const unsigned char iv[BF_BLOCK], int key_len) {
    BF_KEY dec_key;
    BF_set_key(&dec_key, key_len / 8, key);

    std::string decryptedtext(ciphertext.size(), '\0');
    unsigned char temp_iv[BF_BLOCK];
    memcpy(temp_iv, iv, BF_BLOCK);
    BF_cbc_encrypt((unsigned char*)&ciphertext[0], (unsigned char*)&decryptedtext[0], ciphertext.size(), &dec_key, temp_iv, BF_DECRYPT);

    // Remove Padding
    int padding_len = decryptedtext.back();
    decryptedtext.resize(decryptedtext.size() - padding_len);

    return decryptedtext;
}

int main() {
    unsigned char key[16];  // Key
    unsigned char iv[BF_BLOCK];        // Beginning Vector
    int key_len;                       // Key Length

    initialize_bf_key(key, iv, key_len);

    std::string plaintext = "Hidden text is here";
    std::cout << "Original Text: " << plaintext << std::endl;

    std::string ciphertext = bf_encrypt(plaintext, key, iv, key_len);
    std::cout << "Encrypted Text: ";
    for (unsigned char c : ciphertext) {
        std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)c;
    }
    std::cout << std::endl;

    std::string decryptedtext = bf_decrypt(ciphertext, key, iv, key_len);
    std::cout << "Decrypted Text: " << decryptedtext << std::endl;

    return 0;
}
