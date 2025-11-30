/**
 * @file modTableCipher.h
 * @brief Заголовочный файл для класса Table
 * @details Реализация табличной маршрутной перестановки для русского алфавита
 * @author Искоркин Андрей
 * @version 1.0
 * @date 30.11.2025
 */

#pragma once
#include <string>
#include <vector>
#include <stdexcept>

/**
 * @brief Класс исключений для ошибок шифрования
 * @details Наследуется от std::invalid_argument
 */
class cipher_error: public std::invalid_argument {
public:
    /**
     * @brief Конструктор с строковым параметром
     * @param [in] what_arg Сообщение об ошибке
     */
    explicit cipher_error (const std::string& what_arg):
        std::invalid_argument(what_arg) {}
    /**
     * @brief Конструктор с C-строкой
     * @param [in] what_arg Сообщение об ошибке
     */
    explicit cipher_error (const char* what_arg):
        std::invalid_argument(what_arg) {}
};

/**
 * @brief Класс для шифрования методом табличной маршрутной перестановки
 * @details Реализует шифрование и дешифрование текста на русском языке
 */
class Table
{
private:
    int cols; /**< Количество столбцов таблицы */
    
    /**
     * @brief Валидация ключа шифрования
     * @param [in] key Ключ для проверки
     * @return Валидный ключ
     * @throw cipher_error Если ключ невалиден
     */
    int getValidKey(const int key);
    
    /**
     * @brief Валидация открытого текста
     * @param [in] s Текст для проверки
     * @return Валидный текст только с русскими буквами в верхнем регистре
     * @throw cipher_error Если текст не содержит валидных русских букв
     */
    std::wstring getValidOpenText(const std::wstring& s);
    
    /**
     * @brief Валидация зашифрованного текста
     * @param [in] s Зашифрованный текст для проверки
     * @return Валидный зашифрованный текст
     * @throw cipher_error Если текст пустой или содержит не-прописные русские буквы
     */
    std::wstring getValidCipherText(const std::wstring& s);
    
public:
    /**
     * @brief Конструктор класса Table
     * @param [in] key Ключ шифрования (количество столбцов)
     * @throw cipher_error Если ключ невалиден
     */
    explicit Table(int key);
    
    /**
     * @brief Шифрование открытого текста
     * @param [in] plain Открытый текст для шифрования
     * @return Зашифрованный текст
     * @throw cipher_error Если текст невалиден
     */
    std::wstring encrypt(const std::wstring& plain);
    
    /**
     * @brief Дешифрование зашифрованного текста
     * @param [in] cipher Зашифрованный текст для дешифрования
     * @return Расшифрованный текст
     * @throw cipher_error Если текст невалиден
     */
    std::wstring decrypt(const std::wstring& cipher);
};
