#ifndef MAGMA_H
#define MAGMA_H

#include "cipher_interface.h"
#include <array>

// Реализация алгоритма шифрования ГОСТ 28147-89 (Магма)
class MagmaCipher : public ICipher {
private:
    // Таблица замен S-box (по умолчанию используется id-tc26-gost-28147-param-Z)
    static const uint8_t SBOX[8][16];
    
    // Количество раундов
    static const int ROUNDS = 32;
    
    // Размер блока в байтах
    static const int BLOCK_SIZE = 8;
    
    // Размер ключа в байтах
    static const int KEY_SIZE = 32;
    
    // Преобразование ключа в подключи
    std::array<uint32_t, 8> expandKey(const std::vector<uint8_t>& key);
    
    // Функция t (подстановка через S-box)
    uint32_t tTransform(uint32_t value);
    
    // Функция g (основная функция раунда)
    uint32_t gTransform(uint32_t half, uint32_t key);
    
    // Шифрование одного блока
    void encryptBlock(const uint8_t* input, uint8_t* output, const std::array<uint32_t, 8>& subkeys);
    
    // Дешифрование одного блока
    void decryptBlock(const uint8_t* input, uint8_t* output, const std::array<uint32_t, 8>& subkeys);
    
    // Преобразование строки ключа в байты
    std::vector<uint8_t> keyToBytes(const std::string& key);

public:
    std::string encrypt(const std::string& plaintext, const std::string& key) override;
    std::string decrypt(const std::string& ciphertext, const std::string& key) override;
    std::vector<uint8_t> encryptBytes(const std::vector<uint8_t>& data, const std::string& key) override;
    std::vector<uint8_t> decryptBytes(const std::vector<uint8_t>& data, const std::string& key) override;
    std::string getName() const override { return "Магма (ГОСТ 28147-89)"; }
    std::string getKeyFormat() const override { return "64 шестнадцатеричных символа (32 байта)"; }
    bool validateKey(const std::string& key) const override;
};

#endif