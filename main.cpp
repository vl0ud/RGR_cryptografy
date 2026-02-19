#include <iostream>
#include <memory>
#include <vector>
#include <limits>
#include <clocale>
#include "../include/cipher_interface.h"
#include "../include/magma.h"
#include "../include/trithemius.h"
#include "../include/chacha20.h"
#include "../include/key_generator.h"
#include "../include/file_handler.h"

// Очистка буфера ввода
void clearInput() {
    std::cin.clear();
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

// Отображение главного меню
void displayMainMenu() {
    std::cout << "\n========================================\n";
    std::cout << "  Система шифрования данных (РГР)\n";
    std::cout << "========================================\n";
    std::cout << "1. Шифрование/дешифрование текста\n";
    std::cout << "2. Шифрование/дешифрование файла\n";
    std::cout << "3. Генератор ключей\n";
    std::cout << "0. Выход\n";
    std::cout << "========================================\n";
    std::cout << "Выберите действие: ";
}

// Отображение меню выбора алгоритма
int selectCipher(std::unique_ptr<ICipher>& cipher) {
    std::cout << "\n--- Выбор алгоритма шифрования ---\n";
    std::cout << "1. Магма (ГОСТ 28147-89)\n";
    std::cout << "2. Шифр Тритемиуса\n";
    std::cout << "3. ChaCha20\n";
    std::cout << "0. Назад\n";
    std::cout << "Выберите алгоритм: ";
    
    int choice;
    std::cin >> choice;
    clearInput();
    
    switch (choice) {
        case 1:
            cipher = std::make_unique<MagmaCipher>();
            break;
        case 2:
            cipher = std::make_unique<TrithemiusCipher>();
            break;
        case 3:
            cipher = std::make_unique<ChaCha20Cipher>();
            break;
        case 0:
            return 0;
        default:
            std::cout << "Неверный выбор!\n";
            return -1;
    }
    
    std::cout << "\nВыбран алгоритм: " << cipher->getName() << "\n";
    std::cout << "Формат ключа: " << cipher->getKeyFormat() << "\n";
    
    return choice;
}

// Ввод ключа с валидацией
std::string inputKey(const std::unique_ptr<ICipher>& cipher) {
    std::string key;
    
    while (true) {
        std::cout << "\nВведите ключ: ";
        std::getline(std::cin, key);
        
        if (cipher->validateKey(key)) {
            return key;
        } else {
            std::cout << "Ошибка: неверный формат ключа!\n";
            std::cout << "Требуемый формат: " << cipher->getKeyFormat() << "\n";
            
            std::cout << "Попробовать снова? (да/нет): ";
            std::string retry;
            std::getline(std::cin, retry);
            
            if (retry != "да" && retry != "yes" && retry != "y") {
                return "";
            }
        }
    }
}

// Обработка шифрования/дешифрования текста
void processText() {
    std::unique_ptr<ICipher> cipher;
    
    // Выбор алгоритма
    if (selectCipher(cipher) <= 0) {
        return;
    }
    
    // Выбор операции
    std::cout << "\n--- Выбор операции ---\n";
    std::cout << "1. Шифрование\n";
    std::cout << "2. Дешифрование\n";
    std::cout << "Выберите операцию: ";
    
    int operation;
    std::cin >> operation;
    clearInput();
    
    if (operation != 1 && operation != 2) {
        std::cout << "Неверный выбор операции!\n";
        return;
    }
    
    // Ввод ключа
    std::string key = inputKey(cipher);
    if (key.empty()) {
        std::cout << "Операция отменена.\n";
        return;
    }
    
    // Ввод текста
    std::cout << "\nВведите текст для " << (operation == 1 ? "шифрования" : "дешифрования") << ":\n";
    std::string inputText;
    std::getline(std::cin, inputText);
    
    if (inputText.empty()) {
        std::cout << "Текст не может быть пустым!\n";
        return;
    }
    
    // Выполнение операции
    try {
        std::string result;
        
        if (operation == 1) {
            std::cout << "\nВыполняется шифрование...\n";
            result = cipher->encrypt(inputText, key);
            std::cout << "\n--- Результат шифрования ---\n";
        } else {
            std::cout << "\nВыполняется дешифрование...\n";
            result = cipher->decrypt(inputText, key);
            std::cout << "\n--- Результат дешифрования ---\n";
        }
        
        std::cout << result << "\n";
        
        // Сохранение результата в файл (опционально)
        std::cout << "\nСохранить результат в файл? (да/нет): ";
        std::string saveChoice;
        std::getline(std::cin, saveChoice);
        
        if (saveChoice == "да" || saveChoice == "yes" || saveChoice == "y") {
            std::cout << "Введите путь к файлу: ";
            std::string filepath;
            std::getline(std::cin, filepath);
            
            std::vector<uint8_t> data(result.begin(), result.end());
            
            if (FileHandler::writeFile(filepath, data)) {
                std::cout << "Результат успешно сохранен в файл: " << filepath << "\n";
            } else {
                std::cout << "Ошибка при сохранении файла!\n";
            }
        }
        
    } catch (const std::exception& e) {
        std::cout << "\nОшибка при выполнении операции: " << e.what() << "\n";
    }
}

// Обработка шифрования/дешифрования файла
void processFile() {
    std::unique_ptr<ICipher> cipher;
    
    // Выбор алгоритма
    if (selectCipher(cipher) <= 0) {
        return;
    }
    
    // Выбор операции
    std::cout << "\n--- Выбор операции ---\n";
    std::cout << "1. Шифрование файла\n";
    std::cout << "2. Дешифрование файла\n";
    std::cout << "Выберите операцию: ";
    
    int operation;
    std::cin >> operation;
    clearInput();
    
    if (operation != 1 && operation != 2) {
        std::cout << "Неверный выбор операции!\n";
        return;
    }
    
    // Ввод ключа
    std::string key = inputKey(cipher);
    if (key.empty()) {
        std::cout << "Операция отменена.\n";
        return;
    }
    
    // Ввод пути к входному файлу
    std::cout << "\nВведите путь к исходному файлу: ";
    std::string inputPath;
    std::getline(std::cin, inputPath);
    
    if (!FileHandler::fileExists(inputPath)) {
        std::cout << "Ошибка: файл не существует!\n";
        return;
    }
    
    // Ввод пути к выходному файлу
    std::cout << "Введите путь к результирующему файлу: ";
    std::string outputPath;
    std::getline(std::cin, outputPath);
    
    // Проверка существования выходного файла
    if (FileHandler::fileExists(outputPath)) {
        std::cout << "Файл уже существует. Перезаписать? (да/нет): ";
        std::string overwrite;
        std::getline(std::cin, overwrite);
        
        if (overwrite != "да" && overwrite != "yes" && overwrite != "y") {
            std::cout << "Операция отменена.\n";
            return;
        }
    } else {
        // Попытка создать директории если нужно
        FileHandler::createDirectories(outputPath);
    }
    
    // Выполнение операции
    try {
        std::cout << "\nЧтение файла...\n";
        std::vector<uint8_t> data = FileHandler::readFile(inputPath);
        
        std::cout << "Размер файла: " << data.size() << " байт\n";
        
        std::vector<uint8_t> result;
        
        if (operation == 1) {
            std::cout << "Выполняется шифрование...\n";
            result = cipher->encryptBytes(data, key);
        } else {
            std::cout << "Выполняется дешифрование...\n";
            result = cipher->decryptBytes(data, key);
        }
        
        std::cout << "Запись результата в файл...\n";
        
        if (FileHandler::writeFile(outputPath, result)) {
            std::cout << "\nУспешно завершено!\n";
            std::cout << "Результат сохранен в: " << outputPath << "\n";
            std::cout << "Размер результата: " << result.size() << " байт\n";
        } else {
            std::cout << "\nОшибка при записи файла!\n";
        }
        
    } catch (const std::exception& e) {
        std::cout << "\nОшибка при обработке файла: " << e.what() << "\n";
    }
}

// Генератор ключей
void keyGenerator() {
    std::cout << "\n========================================\n";
    std::cout << "        Генератор ключей\n";
    std::cout << "========================================\n";
    std::cout << "1. Сгенерировать ключ для Магма\n";
    std::cout << "2. Сгенерировать ключ для Тритемиуса\n";
    std::cout << "3. Сгенерировать ключ для ChaCha20\n";
    std::cout << "0. Назад\n";
    std::cout << "Выберите действие: ";
    
    int choice;
    std::cin >> choice;
    clearInput();
    
    std::string key;
    
    switch (choice) {
        case 1:
            key = KeyGenerator::generateMagmaKey();
            std::cout << "\n--- Ключ для Магма ---\n";
            std::cout << key << "\n";
            std::cout << "\nФормат: 64 шестнадцатеричных символа (32 байта)\n";
            break;
            
        case 2:
            key = KeyGenerator::generateTrithemiusKey();
            std::cout << "\n--- Ключ для Тритемиуса ---\n";
            std::cout << key << "\n";
            std::cout << "\nФормат: a,b,c где a,b,c - коэффициенты функции k(p) = ap + b + c\n";
            break;
            
        case 3:
            key = KeyGenerator::generateChaCha20Key();
            std::cout << "\n--- Ключ для ChaCha20 ---\n";
            std::cout << key << "\n";
            std::cout << "\nФормат: 88 hex символов (64 для ключа + 24 для nonce)\n";
            break;
            
        case 0:
            return;
            
        default:
            std::cout << "Неверный выбор!\n";
            return;
    }
    
    // Предложение сохранить ключ
    std::cout << "\nСохранить ключ в файл? (да/нет): ";
    std::string saveChoice;
    std::getline(std::cin, saveChoice);
    
    if (saveChoice == "да" || saveChoice == "yes" || saveChoice == "y") {
        std::cout << "Введите путь к файлу: ";
        std::string filepath;
        std::getline(std::cin, filepath);
        
        std::vector<uint8_t> data(key.begin(), key.end());
        
        if (FileHandler::writeFile(filepath, data)) {
            std::cout << "Ключ успешно сохранен в файл: " << filepath << "\n";
        } else {
            std::cout << "Ошибка при сохранении файла!\n";
        }
    }
}

// Главная функция
int main() {
    // Установка локали для корректного отображения кириллицы
    std::setlocale(LC_ALL, "ru_RU.UTF-8");
    
    std::cout << "Добро пожаловать в систему шифрования!\n";
    std::cout << "Программа разработана в соответствии с ГОСТ 19.201-78\n";
    
    bool running = true;
    
    while (running) {
        displayMainMenu();
        
        int choice;
        std::cin >> choice;
        clearInput();
        
        try {
            switch (choice) {
                case 1:
                    processText();
                    break;
                    
                case 2:
                    processFile();
                    break;
                    
                case 3:
                    keyGenerator();
                    break;
                    
                case 0:
                    std::cout << "\nЗавершение работы программы...\n";
                    std::cout << "До свидания!\n";
                    running = false;
                    break;
                    
                default:
                    std::cout << "\nОшибка: неверный выбор! Пожалуйста, выберите пункт от 0 до 3.\n";
            }
        } catch (const std::exception& e) {
            std::cout << "\nКритическая ошибка: " << e.what() << "\n";
            std::cout << "Программа будет перезапущена...\n";
        }
    }
    
    return 0;
}