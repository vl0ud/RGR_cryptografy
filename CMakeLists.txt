cmake_minimum_required(VERSION 3.10)
project(EncryptionRGR)

# Установка стандарта C++
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Включение всех предупреждений компилятора
if(MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra -pedantic)
endif()

# Включение директорий заголовочных файлов
include_directories(${PROJECT_SOURCE_DIR}/include)

# Сборка исполняемого файла
add_executable(encryption_rgr
    src/main.cpp
    src/magma.cpp
    src/trithemius.cpp
    src/chacha20.cpp
    src/key_generator.cpp
    src/file_handler.cpp
)

# Опциональная сборка в режиме отладки
if(CMAKE_BUILD_TYPE MATCHES Debug)
    add_definitions(-DDEBUG)
endif()