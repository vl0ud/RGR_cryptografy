#include "../include/magma.h"
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <algorithm>

// S-box из RFC 8891 (id-tc26-gost-28147-param-Z)
const uint8_t MagmaCipher::SBOX[8][16] = {
    {12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1},
    {6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15},
    {11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0},
    {12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11},
    {7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12},
    {5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0},
    {8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7},
    {1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2}
};

std::array<uint32_t, 8> MagmaCipher::expandKey(const std::vector<uint8_t>& key) {
    std::array<uint32_t, 8> subkeys;
    
    for (int i = 0; i < 8; i++) {
        subkeys[i] = static_cast<uint32_t>(key[i * 4]) |
                     (static_cast<uint32_t>(key[i * 4 + 1]) << 8) |
                     (static_cast<uint32_t>(key[i * 4 + 2]) << 16) |
                     (static_cast<uint32_t>(key[i * 4 + 3]) << 24);
    }
    
    return subkeys;
}

uint32_t MagmaCipher::tTransform(uint32_t value) {
    uint32_t result = 0;
    
    for (int i = 0; i < 8; i++) {
        uint8_t byte = (value >> (i * 4)) & 0x0F;
        result |= static_cast<uint32_t>(SBOX[i][byte]) << (i * 4);
    }
    
    return result;
}

uint32_t MagmaCipher::gTransform(uint32_t half, uint32_t key) {
    uint32_t sum = (half + key) & 0xFFFFFFFF;
    uint32_t substituted = tTransform(sum);
    return (substituted << 11) | (substituted >> 21);
}

void MagmaCipher::encryptBlock(const uint8_t* input, uint8_t* output, const std::array<uint32_t, 8>& subkeys) {
    uint32_t left = static_cast<uint32_t>(input[0]) |
                    (static_cast<uint32_t>(input[1]) << 8) |
                    (static_cast<uint32_t>(input[2]) << 16) |
                    (static_cast<uint32_t>(input[3]) << 24);
    
    uint32_t right = static_cast<uint32_t>(input[4]) |
                     (static_cast<uint32_t>(input[5]) << 8) |
                     (static_cast<uint32_t>(input[6]) << 16) |
                     (static_cast<uint32_t>(input[7]) << 24);
    
    // 24 раунда с прямым порядком ключей
    for (int i = 0; i < 24; i++) {
        uint32_t temp = left ^ gTransform(right, subkeys[i % 8]);
        left = right;
        right = temp;
    }
    
    // 8 раундов с обратным порядком ключей
    for (int i = 0; i < 8; i++) {
        uint32_t temp = left ^ gTransform(right, subkeys[7 - i]);
        left = right;
        right = temp;
    }
    
    // Запись результата
    output[0] = right & 0xFF;
    output[1] = (right >> 8) & 0xFF;
    output[2] = (right >> 16) & 0xFF;
    output[3] = (right >> 24) & 0xFF;
    output[4] = left & 0xFF;
    output[5] = (left >> 8) & 0xFF;
    output[6] = (left >> 16) & 0xFF;
    output[7] = (left >> 24) & 0xFF;
}

void MagmaCipher::decryptBlock(const uint8_t* input, uint8_t* output, const std::array<uint32_t, 8>& subkeys) {
    uint32_t left = static_cast<uint32_t>(input[0]) |
                    (static_cast<uint32_t>(input[1]) << 8) |
                    (static_cast<uint32_t>(input[2]) << 16) |
                    (static_cast<uint32_t>(input[3]) << 24);
    
    uint32_t right = static_cast<uint32_t>(input[4]) |
                     (static_cast<uint32_t>(input[5]) << 8) |
                     (static_cast<uint32_t>(input[6]) << 16) |
                     (static_cast<uint32_t>(input[7]) << 24);
    
    // 8 раундов с прямым порядком ключей
    for (int i = 0; i < 8; i++) {
        uint32_t temp = left ^ gTransform(right, subkeys[i]);
        left = right;
        right = temp;
    }
    
    // 24 раунда с обратным порядком ключей
    for (int i = 0; i < 24; i++) {
        uint32_t temp = left ^ gTransform(right, subkeys[7 - (i % 8)]);
        left = right;
        right = temp;
    }
    
    // Запись результата
    output[0] = right & 0xFF;
    output[1] = (right >> 8) & 0xFF;
    output[2] = (right >> 16) & 0xFF;
    output[3] = (right >> 24) & 0xFF;
    output[4] = left & 0xFF;
    output[5] = (left >> 8) & 0xFF;
    output[6] = (left >> 16) & 0xFF;
    output[7] = (left >> 24) & 0xFF;
}

std::vector<uint8_t> MagmaCipher::keyToBytes(const std::string& key) {
    std::vector<uint8_t> bytes;
    
    for (size_t i = 0; i < key.length(); i += 2) {
        std::string byteString = key.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoul(byteString, nullptr, 16));
        bytes.push_back(byte);
    }
    
    return bytes;
}

bool MagmaCipher::validateKey(const std::string& key) const {
    if (key.length() != 64) return false;
    
    for (char c : key) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
    }
    
    return true;
}

std::vector<uint8_t> MagmaCipher::encryptBytes(const std::vector<uint8_t>& data, const std::string& key) {
    if (!validateKey(key)) {
        throw std::invalid_argument("Неверный формат ключа для Магма");
    }
    
    std::vector<uint8_t> keyBytes = keyToBytes(key);
    auto subkeys = expandKey(keyBytes);
    
    // Добавление padding (PKCS7)
    size_t paddingSize = BLOCK_SIZE - (data.size() % BLOCK_SIZE);
    std::vector<uint8_t> paddedData = data;
    for (size_t i = 0; i < paddingSize; i++) {
        paddedData.push_back(static_cast<uint8_t>(paddingSize));
    }
    
    std::vector<uint8_t> result;
    result.resize(paddedData.size());
    
    // Шифрование блоками
    for (size_t i = 0; i < paddedData.size(); i += BLOCK_SIZE) {
        encryptBlock(&paddedData[i], &result[i], subkeys);
    }
    
    return result;
}

std::vector<uint8_t> MagmaCipher::decryptBytes(const std::vector<uint8_t>& data, const std::string& key) {
    if (!validateKey(key)) {
        throw std::invalid_argument("Неверный формат ключа для Магма");
    }
    
    if (data.size() % BLOCK_SIZE != 0) {
        throw std::invalid_argument("Размер зашифрованных данных должен быть кратен 8 байтам");
    }
    
    std::vector<uint8_t> keyBytes = keyToBytes(key);
    auto subkeys = expandKey(keyBytes);
    
    std::vector<uint8_t> result;
    result.resize(data.size());
    
    // Дешифрование блоками
    for (size_t i = 0; i < data.size(); i += BLOCK_SIZE) {
        decryptBlock(&data[i], &result[i], subkeys);
    }
    
    // Удаление padding
    if (!result.empty()) {
        uint8_t paddingSize = result.back();
        if (paddingSize > 0 && paddingSize <= BLOCK_SIZE && paddingSize <= result.size()) {
            result.resize(result.size() - paddingSize);
        }
    }
    
    return result;
}

std::string MagmaCipher::encrypt(const std::string& plaintext, const std::string& key) {
    std::vector<uint8_t> data(plaintext.begin(), plaintext.end());
    std::vector<uint8_t> encrypted = encryptBytes(data, key);
    
    // Преобразование в hex строку
    std::ostringstream oss;
    for (uint8_t byte : encrypted) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    
    return oss.str();
}

std::string MagmaCipher::decrypt(const std::string& ciphertext, const std::string& key) {
    // Преобразование hex строки в байты
    std::vector<uint8_t> data;
    for (size_t i = 0; i < ciphertext.length(); i += 2) {
        std::string byteString = ciphertext.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoul(byteString, nullptr, 16));
        data.push_back(byte);
    }
    
    std::vector<uint8_t> decrypted = decryptBytes(data, key);
    return std::string(decrypted.begin(), decrypted.end());
}