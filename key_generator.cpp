#include "../include/key_generator.h"
#include <random>
#include <sstream>
#include <iomanip>

char KeyGenerator::randomHexChar() {
    static const char hexChars[] = "0123456789abcdef";
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 15);
    
    return hexChars[dis(gen)];
}

int KeyGenerator::randomInt(int min, int max) {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(min, max);
    
    return dis(gen);
}

std::string KeyGenerator::generateMagmaKey() {
    std::ostringstream oss;
    
    // Генерация 64 hex символов (32 байта)
    for (int i = 0; i < 64; i++) {
        oss << randomHexChar();
    }
    
    return oss.str();
}

std::string KeyGenerator::generateTrithemiusKey() {
    // Генерация трех случайных чисел
    int a = randomInt(1, 10);
    int b = randomInt(0, 50);
    int c = randomInt(0, 50);
    
    std::ostringstream oss;
    oss << a << "," << b << "," << c;
    
    return oss.str();
}

std::string KeyGenerator::generateChaCha20Key() {
    std::ostringstream oss;
    
    // Генерация 88 hex символов (32 байта ключ + 12 байт nonce)
    for (int i = 0; i < 88; i++) {
        oss << randomHexChar();
    }
    
    return oss.str();
}