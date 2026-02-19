#ifndef KEY_GENERATOR_H
#define KEY_GENERATOR_H

#include <string>

// Класс для генерации ключей для различных алгоритмов
class KeyGenerator {
public:
    // Генерация ключа для Магма (64 hex символа)
    static std::string generateMagmaKey();
    
    // Генерация ключа для Тритемиуса (a,b,c)
    static std::string generateTrithemiusKey();
    
    // Генерация ключа для ChaCha20 (88 hex символов)
    static std::string generateChaCha20Key();
    
private:
    // Генерация случайного hex символа
    static char randomHexChar();
    
    // Генерация случайного числа в диапазоне
    static int randomInt(int min, int max);
};

#endif