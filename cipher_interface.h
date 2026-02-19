#ifndef CIPHER_INTERFACE_H
#define CIPHER_INTERFACE_H

#include <string>
#include <vector>
#include <cstdint>

// Базовый интерфейс для всех алгоритмов шифрования
class ICipher {
public:
    virtual ~ICipher() = default;
    
    // Шифрование текста
    virtual std::string encrypt(const std::string& plaintext, const std::string& key) = 0;
    
    // Дешифрование текста
    virtual std::string decrypt(const std::string& ciphertext, const std::string& key) = 0;
    
    // Шифрование данных в байтах
    virtual std::vector<uint8_t> encryptBytes(const std::vector<uint8_t>& data, const std::string& key) = 0;
    
    // Дешифрование данных в байтах
    virtual std::vector<uint8_t> decryptBytes(const std::vector<uint8_t>& data, const std::string& key) = 0;
    
    // Получение имени алгоритма
    virtual std::string getName() const = 0;
    
    // Получение описания формата ключа
    virtual std::string getKeyFormat() const = 0;
    
    // Валидация ключа
    virtual bool validateKey(const std::string& key) const = 0;
};

#endif