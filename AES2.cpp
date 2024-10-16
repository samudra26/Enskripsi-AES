#include <iostream>
#include <string>
#include <openssl/aes.h>

class AESCipher {
public:
    AESCipher(const std::string& key) : key_(key) {}

    std::string encrypt(const std::string& plaintext) {
        unsigned char iv[AES_BLOCK_SIZE];
        RAND_bytes(iv, AES_BLOCK_SIZE);

        AES_KEY aes_key;
        AES_set_encrypt_key((const unsigned char*)key_.c_str(), key_.size() * 8, &aes_key);

        int len = plaintext.size(), written = 0;
        std::string ciphertext;
        ciphertext.resize(len + AES_BLOCK_SIZE);

        AES_cbc_encrypt((const unsigned char*)plaintext.c_str(), (unsigned char*)&ciphertext[0], len, &aes_key, iv, AES_ENCRYPT);

        ciphertext.resize(written + AES_BLOCK_SIZE);
        return std::string((char*)iv, AES_BLOCK_SIZE) + ciphertext;
    }

    std::string decrypt(const std::string& ciphertext) {
        unsigned char iv[AES_BLOCK_SIZE];
        std::copy(ciphertext.begin(), ciphertext.begin() + AES_BLOCK_SIZE, iv);

        AES_KEY aes_key;
        AES_set_decrypt_key((const unsigned char*)key_.c_str(), key_.size() * 8, &aes_key);

        int len = ciphertext.size() - AES_BLOCK_SIZE, written = 0;
        std::string plaintext;
        plaintext.resize(len);

        AES_cbc_encrypt((const unsigned char*)&ciphertext[AES_BLOCK_SIZE], (unsigned char*)&plaintext[0], len, &aes_key, iv, AES_DECRYPT);

return plaintext;
    }

private:
    std::string key_;
};

int main() {
    std::string key;
    std::cout << "masukan kunci: ";
    std::getline(std::cin, key);

    AESCipher cipher(key);

    while (true) {
        std::cout << "1. Enskripsi\n";
        std::cout << "2. Dekripsi\n";
        int choice;
        std::cin >> choice;

        if (choice == 1) {
            std::string plaintext;
            std::cout << "masukan data yang ingin di enskripsi: ";
            std::getline(std::cin, plaintext);
            std::string encrypted = cipher.encrypt(plaintext);
            std::cout << "data enskripsi: " << encrypted << std::endl;
        } else if (choice == 2) {
            std::string ciphertext;
            std::cout << "masukan data yang ingin di dekripsi: ";
            std::getline(std::cin, ciphertext);
            std::string decrypted = cipher.decrypt(ciphertext);
            std::cout << "data dekripsi: " << decrypted << std::endl;
        } else {
            std::cout << "opsi salah,coba lagi" << std::endl;
        }
    }

    return 0;
}
