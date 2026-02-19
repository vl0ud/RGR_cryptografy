#include "../include/file_handler.h"
#include <fstream>
#include <stdexcept>
#include <sys/stat.h>

#ifdef _WIN32
    #include <direct.h>
    #define mkdir _mkdir
#else
    #include <sys/types.h>
#endif

std::vector<uint8_t> FileHandler::readFile(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    
    if (!file) {
        throw std::runtime_error("Не удалось открыть файл для чтения: " + filepath);
    }
    
    // Определение размера файла
    file.seekg(0, std::ios::end);
    std::streamsize fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    
    // Чтение содержимого файла
    std::vector<uint8_t> buffer(static_cast<size_t>(fileSize));
    file.read(reinterpret_cast<char*>(buffer.data()), fileSize);
    
    if (!file) {
        throw std::runtime_error("Ошибка при чтении файла: " + filepath);
    }
    
    file.close();
    return buffer;
}

bool FileHandler::writeFile(const std::string& filepath, const std::vector<uint8_t>& data) {
    std::ofstream file(filepath, std::ios::binary);
    
    if (!file) {
        return false;
    }
    
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    
    if (!file) {
        return false;
    }
    
    file.close();
    return true;
}

bool FileHandler::fileExists(const std::string& filepath) {
    struct stat buffer;
    return (stat(filepath.c_str(), &buffer) == 0);
}

bool FileHandler::createDirectories(const std::string& filepath) {
    // Упрощенная реализация - создание только одного уровня директории
    size_t pos = filepath.find_last_of("/\\");
    
    if (pos == std::string::npos) {
        return true;
    }
    
    std::string directory = filepath.substr(0, pos);
    
    #ifdef _WIN32
        return mkdir(directory.c_str()) == 0 || errno == EEXIST;
    #else
        return mkdir(directory.c_str(), 0755) == 0 || errno == EEXIST;
    #endif
}