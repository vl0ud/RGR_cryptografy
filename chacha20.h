#ifndef CHACHA20_H
#define CHACHA20_H

#include "cipher_interface.h"
#include <array>

// Реализация алгоритма ChaCha20
class ChaCha20Cipher : public ICipher {
private:
    // Размер блока состояния
    static const int STATE_SIZE = 16;
    
    // Размер ключа в байтах
    static const int KEY_SIZE = 32;
    
    // Размер nonce в байтах
    static const int NONCE_SIZE = 12;
    
    // Структура ключа: ключ + nonce
    struct ChaChaKey {
        std::array<uint8_t, KEY_SIZE> key;
        std::array<uint8_t, NONCE_SIZE> nonce;
    };
    
    // Парсинг ключа из hex-строки
    ChaChaKey parseKey(const std::string& key);
    
    // Инициализация состояния
    void initState(std::array<uint32_t, STATE_SIZE>& state, const ChaChaKey& key, uint32_t counter);
    
    // Quarter round функция
    void quarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d);
    
    // Циклический сдвиг влево
    uint32_t rotl32(uint32_t value, int shift);
    
    // Генерация блока keystream
    void chachaBlock(const std::array<uint32_t, STATE_SIZE>& input, std::array<uint32_t, STATE_SIZE>& output);
    
    // XOR данных с keystream
    void processData(std::vector<uint8_t>& data, const ChaChaKey& key);

public:
    std::string encrypt(const std::string& plaintext, const std::string& key) override;
    std::string decrypt(const std::string& ciphertext, const std::string& key) override;
    std::vector<uint8_t> encryptBytes(const std::vector<uint8_t>& data, const std::string& key) override;
    std::vector<uint8_t> decryptBytes(const std::vector<uint8_t>& data, const std::string& key) override;
    std::string getName() const override { return "ChaCha20"; }
    std::string getKeyFormat() const override { return "88 hex символов: 64 для ключа + 24 для nonce"; }
    bool validateKey(const std::string& key) const override;
};

#endif