#include "../include/chacha20.h"
#include <stdexcept>
#include <cstring>
#include <algorithm>

uint32_t ChaCha20Cipher::rotl32(uint32_t value, int shift) {
    return (value << shift) | (value >> (32 - shift));
}

void ChaCha20Cipher::quarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b; d ^= a; d = rotl32(d, 16);
    c += d; b ^= c; b = rotl32(b, 12);
    a += b; d ^= a; d = rotl32(d, 8);
    c += d; b ^= c; b = rotl32(b, 7);
}

ChaCha20Cipher::ChaChaKey ChaCha20Cipher::parseKey(const std::string& key) {
    if (key.length() != 88) {
        throw std::invalid_argument("Ключ ChaCha20 должен содержать 88 hex символов");
    }
    
    // Проверка на hex символы
    for (char c : key) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) {
            throw std::invalid_argument("Ключ должен содержать только hex символы");
        }
    }
    
    ChaChaKey result;
    
    // Парсинг ключа (64 hex символа = 32 байта)
    for (int i = 0; i < KEY_SIZE; i++) {
        std::string byteStr = key.substr(i * 2, 2);
        result.key[i] = static_cast<uint8_t>(std::stoul(byteStr, nullptr, 16));
    }
    
    // Парсинг nonce (24 hex символа = 12 байт)
    for (int i = 0; i < NONCE_SIZE; i++) {
        std::string byteStr = key.substr(64 + i * 2, 2);
        result.nonce[i] = static_cast<uint8_t>(std::stoul(byteStr, nullptr, 16));
    }
    
    return result;
}

void ChaCha20Cipher::initState(std::array<uint32_t, STATE_SIZE>& state, const ChaChaKey& key, uint32_t counter) {
    // Константы "expand 32-byte k" в little-endian формате
    // "expa" = 0x61707865
    // "nd 3" = 0x3320646e
    // "2-by" = 0x79622d32
    // "te k" = 0x6b206574
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    
    // Ключ (little-endian)
    for (int i = 0; i < 8; i++) {
        state[4 + i] = static_cast<uint32_t>(key.key[i * 4]) |
                       (static_cast<uint32_t>(key.key[i * 4 + 1]) << 8) |
                       (static_cast<uint32_t>(key.key[i * 4 + 2]) << 16) |
                       (static_cast<uint32_t>(key.key[i * 4 + 3]) << 24);
    }
    
    // Счетчик блока
    state[12] = counter;
    
    // Nonce (little-endian)
    state[13] = static_cast<uint32_t>(key.nonce[0]) |
                (static_cast<uint32_t>(key.nonce[1]) << 8) |
                (static_cast<uint32_t>(key.nonce[2]) << 16) |
                (static_cast<uint32_t>(key.nonce[3]) << 24);
    
    state[14] = static_cast<uint32_t>(key.nonce[4]) |
                (static_cast<uint32_t>(key.nonce[5]) << 8) |
                (static_cast<uint32_t>(key.nonce[6]) << 16) |
                (static_cast<uint32_t>(key.nonce[7]) << 24);
    
    state[15] = static_cast<uint32_t>(key.nonce[8]) |
                (static_cast<uint32_t>(key.nonce[9]) << 8) |
                (static_cast<uint32_t>(key.nonce[10]) << 16) |
                (static_cast<uint32_t>(key.nonce[11]) << 24);
}

void ChaCha20Cipher::chachaBlock(const std::array<uint32_t, STATE_SIZE>& input, std::array<uint32_t, STATE_SIZE>& output) {
    output = input;
    
    // 20 раундов (10 двойных раундов)
    for (int i = 0; i < 10; i++) {
        // Нечетные раунды - колонны
        quarterRound(output[0], output[4], output[8], output[12]);
        quarterRound(output[1], output[5], output[9], output[13]);
        quarterRound(output[2], output[6], output[10], output[14]);
        quarterRound(output[3], output[7], output[11], output[15]);
        
        // Четные раунды - диагонали
        quarterRound(output[0], output[5], output[10], output[15]);
        quarterRound(output[1], output[6], output[11], output[12]);
        quarterRound(output[2], output[7], output[8], output[13]);
        quarterRound(output[3], output[4], output[9], output[14]);
    }
    
    // Добавление начального состояния
    for (int i = 0; i < STATE_SIZE; i++) {
        output[i] += input[i];
    }
}

void ChaCha20Cipher::processData(std::vector<uint8_t>& data, const ChaChaKey& key) {
    std::array<uint32_t, STATE_SIZE> state;
    std::array<uint32_t, STATE_SIZE> keystream;
    
    size_t blockCount = (data.size() + 63) / 64;
    
    for (size_t block = 0; block < blockCount; block++) {
        initState(state, key, static_cast<uint32_t>(block));
        chachaBlock(state, keystream);
        
        // XOR данных с keystream
        for (size_t i = 0; i < 64 && (block * 64 + i) < data.size(); i++) {
            uint8_t keystreamByte = (keystream[i / 4] >> ((i % 4) * 8)) & 0xFF;
            data[block * 64 + i] ^= keystreamByte;
        }
    }
}

bool ChaCha20Cipher::validateKey(const std::string& key) const {
    if (key.length() != 88) return false;
    
    for (char c : key) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
    }
    
    return true;
}

std::vector<uint8_t> ChaCha20Cipher::encryptBytes(const std::vector<uint8_t>& data, const std::string& key) {
    if (!validateKey(key)) {
        throw std::invalid_argument("Неверный формат ключа для ChaCha20");
    }
    
    ChaChaKey chachaKey = parseKey(key);
    std::vector<uint8_t> result = data;
    processData(result, chachaKey);
    
    return result;
}

std::vector<uint8_t> ChaCha20Cipher::decryptBytes(const std::vector<uint8_t>& data, const std::string& key) {
    // ChaCha20 симметричен - шифрование = дешифрование
    return encryptBytes(data, key);
}

std::string ChaCha20Cipher::encrypt(const std::string& plaintext, const std::string& key) {
    std::vector<uint8_t> data(plaintext.begin(), plaintext.end());
    std::vector<uint8_t> encrypted = encryptBytes(data, key);
    return std::string(encrypted.begin(), encrypted.end());
}

std::string ChaCha20Cipher::decrypt(const std::string& ciphertext, const std::string& key) {
    std::vector<uint8_t> data(ciphertext.begin(), ciphertext.end());
    std::vector<uint8_t> decrypted = decryptBytes(data, key);
    return std::string(decrypted.begin(), decrypted.end());
}