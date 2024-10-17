#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <iostream>
#include <vector>
#include <cstring>

class AESCipher {
public:
    AESCipher(const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv)
        : key_(key), iv_(iv) {}

    // Encrypt plaintext with AES-CBC
    std::vector<unsigned char> encrypt(const std::vector<unsigned char>& plaintext) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("Failed to create context");

        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key_.data(), iv_.data())) {
            throw std::runtime_error("Encryption init failed");
        }

        std::vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
        int len = 0, ciphertext_len = 0;

        if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size())) {
            throw std::runtime_error("Encryption failed");
        }
        ciphertext_len = len;

        if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) {
            throw std::runtime_error("Encryption final step failed");
        }
        ciphertext_len += len;

        EVP_CIPHER_CTX_free(ctx);
        ciphertext.resize(ciphertext_len);
        return ciphertext;
    }

    // Decrypt ciphertext with AES-CBC
    std::vector<unsigned char> decrypt(const std::vector<unsigned char>& ciphertext) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("Failed to create context");

        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key_.data(), iv_.data())) {
            throw std::runtime_error("Decryption init failed");
        }

        std::vector<unsigned char> plaintext(ciphertext.size());
        int len = 0, plaintext_len = 0;

        if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size())) {
            throw std::runtime_error("Decryption failed");
        }
        plaintext_len = len;

        if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len)) {
            throw std::runtime_error("Decryption final step failed");
        }
        plaintext_len += len;

        EVP_CIPHER_CTX_free(ctx);
        plaintext.resize(plaintext_len);
        return plaintext;
    }

private:
    std::vector<unsigned char> key_;
    std::vector<unsigned char> iv_;
};

// Helper function to print binary data as hex
void printHex(const std::vector<unsigned char>& data) {
    for (unsigned char byte : data) {
        printf("%02x", byte);
    }
    printf("\n");
}

int main() {
    // 256-bit key (32 bytes) and 128-bit IV (16 bytes)
    std::vector<unsigned char> key = {'t', 'h', 'i', 's', 'i', 's', 'a', '2', '5', '6', 'b', 'i', 't', 'k', 'e', 'y',
                                      't', 'h', 'i', 's', 'i', 's', 'a', '2', '5', '6', 'b', 'i', 't', 'k', 'e', 'y'};
    std::vector<unsigned char> iv = {'t', 'h', 'i', 's', 'i', 's', 'a', '1', '2', '8', 'b', 'i', 't', 'i', 'v'};

    AESCipher aesCipher(key, iv);

    // Sample plaintext
    std::string plaintext = "Hello, this is a secret message!";
    std::vector<unsigned char> plaintextBytes(plaintext.begin(), plaintext.end());

    std::cout << "Plaintext: " << plaintext << std::endl;

    // Encrypt the plaintext
    std::vector<unsigned char> ciphertext = aesCipher.encrypt(plaintextBytes);
    std::cout << "Ciphertext (hex): ";
    printHex(ciphertext);

    // Decrypt the ciphertext
    std::vector<unsigned char> decryptedtext = aesCipher.decrypt(ciphertext);
    std::string decryptedString(decryptedtext.begin(), decryptedtext.end());
    std::cout << "Decrypted text: " << decryptedString << std::endl;

    return 0;
}
