#include "../include/trithemius.h"
#include <stdexcept>
#include <sstream>

TrithemiusCipher::ProgressiveKey TrithemiusCipher::parseKey(const std::string& key) const {
    ProgressiveKey pk;
    std::istringstream iss(key);
    std::string temp;
    
    // Чтение первого числа
    if (!std::getline(iss, temp, ',')) {
        throw std::invalid_argument("Неверный формат ключа для Тритемиуса");
    }
    try {
        pk.a = std::stoi(temp);
    } catch (...) {
        throw std::invalid_argument("Неверный формат ключа для Тритемиуса");
    }
    
    // Чтение второго числа
    if (!std::getline(iss, temp, ',')) {
        throw std::invalid_argument("Неверный формат ключа для Тритемиуса");
    }
    try {
        pk.b = std::stoi(temp);
    } catch (...) {
        throw std::invalid_argument("Неверный формат ключа для Тритемиуса");
    }
    
    // Чтение третьего числа
    if (!std::getline(iss, temp)) {
        throw std::invalid_argument("Неверный формат ключа для Тритемиуса");
    }
    try {
        pk.c = std::stoi(temp);
    } catch (...) {
        throw std::invalid_argument("Неверный формат ключа для Тритемиуса");
    }
    
    return pk;
}

uint8_t TrithemiusCipher::encryptByte(uint8_t byte, int position, const ProgressiveKey& pk) const {
    // Вычисление сдвига по формуле k(p) = ap + b + c
    int shift = (pk.a * position + pk.b + pk.c) % 256;
    
    // Приведение shift к положительному значению
    if (shift < 0) {
        shift += 256;
    }
    
    // Шифрование с циклическим сдвигом
    int encrypted = (static_cast<int>(byte) + shift) % 256;
    
    return static_cast<uint8_t>(encrypted);
}

uint8_t TrithemiusCipher::decryptByte(uint8_t byte, int position, const ProgressiveKey& pk) const {
    // Вычисление сдвига по формуле k(p) = ap + b + c
    int shift = (pk.a * position + pk.b + pk.c) % 256;
    
    // Приведение shift к положительному значению
    if (shift < 0) {
        shift += 256;
    }
    
    // Дешифрование с циклическим сдвигом
    int decrypted = (static_cast<int>(byte) - shift + 256) % 256;
    
    return static_cast<uint8_t>(decrypted);
}

bool TrithemiusCipher::validateKey(const std::string& key) const {
    try {
        parseKey(key);
        return true;
    } catch (...) {
        return false;
    }
}

std::vector<uint8_t> TrithemiusCipher::encryptBytes(const std::vector<uint8_t>& data, const std::string& key) {
    ProgressiveKey pk = parseKey(key);
    std::vector<uint8_t> result;
    result.reserve(data.size());
    
    for (size_t i = 0; i < data.size(); i++) {
        result.push_back(encryptByte(data[i], static_cast<int>(i), pk));
    }
    
    return result;
}

std::vector<uint8_t> TrithemiusCipher::decryptBytes(const std::vector<uint8_t>& data, const std::string& key) {
    ProgressiveKey pk = parseKey(key);
    std::vector<uint8_t> result;
    result.reserve(data.size());
    
    for (size_t i = 0; i < data.size(); i++) {
        result.push_back(decryptByte(data[i], static_cast<int>(i), pk));
    }
    
    return result;
}

std::string TrithemiusCipher::encrypt(const std::string& plaintext, const std::string& key) {
    std::vector<uint8_t> data(plaintext.begin(), plaintext.end());
    std::vector<uint8_t> encrypted = encryptBytes(data, key);
    return std::string(encrypted.begin(), encrypted.end());
}

std::string TrithemiusCipher::decrypt(const std::string& ciphertext, const std::string& key) {
    std::vector<uint8_t> data(ciphertext.begin(), ciphertext.end());
    std::vector<uint8_t> decrypted = decryptBytes(data, key);
    return std::string(decrypted.begin(), decrypted.end());
}