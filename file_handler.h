#ifndef FILE_HANDLER_H
#define FILE_HANDLER_H

#include <string>
#include <vector>
#include <cstdint>

// Класс для работы с файлами
class FileHandler {
public:
    // Чтение файла в байты
    static std::vector<uint8_t> readFile(const std::string& filepath);
    
    // Запись байтов в файл
    static bool writeFile(const std::string& filepath, const std::vector<uint8_t>& data);
    
    // Проверка существования файла
    static bool fileExists(const std::string& filepath);
    
    // Создание директорий для пути
    static bool createDirectories(const std::string& filepath);
};

#endif