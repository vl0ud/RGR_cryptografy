#ifndef TRITHEMIUS_H
#define TRITHEMIUS_H

#include "cipher_interface.h"

// Реализация шифра Тритемиуса с прогрессивным ключом
class TrithemiusCipher : public ICipher {
private:
    // Параметры линейной функции k(p) = ap + b + c
    struct ProgressiveKey {
        int a;
        int b;
        int c;
    };
    
    // Парсинг ключа из строки формата "a,b,c"
    ProgressiveKey parseKey(const std::string& key) const;
    
    // Шифрование одного байта с позицией
    uint8_t encryptByte(uint8_t byte, int position, const ProgressiveKey& pk) const;
    
    // Дешифрование одного байта с позицией
    uint8_t decryptByte(uint8_t byte, int position, const ProgressiveKey& pk) const;

public:
    std::string encrypt(const std::string& plaintext, const std::string& key) override;
    std::string decrypt(const std::string& ciphertext, const std::string& key) override;
    std::vector<uint8_t> encryptBytes(const std::vector<uint8_t>& data, const std::string& key) override;
    std::vector<uint8_t> decryptBytes(const std::vector<uint8_t>& data, const std::string& key) override;
    std::string getName() const override { return "Шифр Тритемиуса"; }
    std::string getKeyFormat() const override { return "Три числа через запятую: a,b,c (например: 1,2,3)"; }
    bool validateKey(const std::string& key) const override;
};

#endif